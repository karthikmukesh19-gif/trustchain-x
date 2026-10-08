"""Test fixtures.

The application is built through its public factory with in-memory stand-ins
for its three external systems:

* MongoDB  -> mongomock (same PyMongo API, including unique indexes)
* Redis    -> a minimal in-memory object exposing the calls the app makes
* GitHub   -> httpx.MockTransport, so the real HTTP client code runs but no
              network request leaves the process
"""

from __future__ import annotations

import base64
import hashlib
import time
from pathlib import Path

import httpx
import mongomock
import pytest
from fastapi.testclient import TestClient

from app.config.settings import load_settings
from app.main import create_app
from tests import mongomock_compat

# PyMongo >= 4.11 and mongomock <= 4.3.0 disagree about bulk_write; see the module for details.
mongomock_compat.apply()

TEST_ENV = {
    "APP_ENV": "test",
    "JWT_SECRET": "test-secret-that-is-long-enough-for-hs256-signing",
    "MONGODB_DB": "trustchain_x_test",
    "AUTH_RATE_LIMIT": "1000",
    "CORS_ORIGINS": "http://localhost:5173",
}

GITHUB_REPO_PAYLOAD = {
    "id": 4164482,
    "full_name": "django/django",
    "description": "The Web framework for perfectionists with deadlines.",
    "default_branch": "main",
    "language": "Python",
    "stargazers_count": 80000,
    "forks_count": 31000,
    "open_issues_count": 300,
    "size": 250000,
    "archived": False,
    "fork": False,
    "visibility": "public",
    "license": {"spdx_id": "BSD-3-Clause"},
    "created_at": "2012-04-28T02:47:18Z",
    "pushed_at": "2026-01-01T10:00:00Z",
}


class FakeRedis:
    """In-memory subset of the Redis client used by the application."""

    def __init__(self) -> None:
        self.store: dict[str, tuple[bytes, float | None]] = {}
        self.queues: dict[str, list[str]] = {}
        self.available = True

    def _check(self) -> None:
        if not self.available:
            raise ConnectionError("redis unavailable")

    def ping(self) -> bool:
        self._check()
        return True

    def set(self, key: str, value: str, ex: int | None = None) -> bool:
        self._check()
        self.store[key] = (str(value).encode(), time.monotonic() + ex if ex else None)
        return True

    def get(self, key: str) -> bytes | None:
        self._check()
        item = self.store.get(key)
        if item is None:
            return None
        value, expires = item
        if expires is not None and time.monotonic() >= expires:
            del self.store[key]
            return None
        return value

    def lpush(self, key: str, value: str) -> int:
        self._check()
        self.queues.setdefault(key, []).insert(0, value)
        return len(self.queues[key])

    def brpop(self, key: str, timeout: int = 0):
        self._check()
        queue = self.queues.get(key) or []
        return (key.encode(), queue.pop().encode()) if queue else None

    def close(self) -> None:
        pass


class FakeRepository:
    """An in-memory git repository served through the GitHub REST endpoints the analyser uses."""

    def __init__(self, files: dict[str, bytes | str], branch: str = "main") -> None:
        self.files = {path: content.encode() if isinstance(content, str) else content for path, content in files.items()}
        self.branch = branch
        self.extra_entries: list[dict] = []     # raw tree entries appended as-is (hostile paths, symlinks, ...)
        self.listed_sizes: dict[str, int] = {}  # size to report for a path without storing that much content
        self.truncated = False
        self.tamper: set[str] = set()           # paths whose content is served corrupted
        self.size_kb: int | None = None

    def blob_id(self, path: str) -> str:
        from app.collectors.github import git_blob_id

        return git_blob_id(self.files[path])

    @property
    def commit_sha(self) -> str:
        digest = hashlib.sha1()
        for path in sorted(self.files):
            digest.update(path.encode() + b"\0" + self.blob_id(path).encode())
        return digest.hexdigest()

    @property
    def tree_sha(self) -> str:
        return hashlib.sha1(b"tree" + self.commit_sha.encode()).hexdigest()

    def respond(self, path: str) -> httpx.Response | None:
        parts = path.strip("/").split("/")
        if len(parts) < 3 or parts[0] != "repos":
            return None
        rest = parts[3:]
        if not rest:
            size = self.size_kb if self.size_kb is not None else sum(len(c) for c in self.files.values()) // 1024
            return httpx.Response(200, json={**GITHUB_REPO_PAYLOAD, "default_branch": self.branch, "size": size})
        if rest[0] == "commits":
            return httpx.Response(200, json={"sha": self.commit_sha, "commit": {
                "message": "Fixture commit\n\nbody", "tree": {"sha": self.tree_sha},
                "committer": {"date": "2026-01-02T03:04:05Z"}}})
        if rest[:2] == ["git", "trees"]:
            entries = [{"path": p, "mode": "100644", "type": "blob", "sha": self.blob_id(p),
                        "size": self.listed_sizes.get(p, len(c))} for p, c in sorted(self.files.items())]
            return httpx.Response(200, json={"sha": rest[2], "tree": entries + self.extra_entries, "truncated": self.truncated})
        if rest[:2] == ["git", "blobs"]:
            for p, content in self.files.items():
                if self.blob_id(p) == rest[2]:
                    body = content + b"tampered" if p in self.tamper else content
                    return httpx.Response(200, json={"encoding": "base64", "size": len(body),
                                                     "content": base64.encodebytes(body).decode()})
            return httpx.Response(404, json={"message": "Not Found"})
        return None


class GitHubStub:
    """Programmable GitHub API. Records every request it receives."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.status = 200
        self.payload: object = dict(GITHUB_REPO_PAYLOAD)
        self.headers: dict[str, str] = {}
        self.error: Exception | None = None
        self.repo: FakeRepository | None = None
        self.fail_paths: dict[str, tuple[int, dict[str, str]]] = {}   # path fragment -> (status, headers)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        for fragment, (status, headers) in self.fail_paths.items():
            if fragment in request.url.path:
                return httpx.Response(status, json={"message": "simulated"}, headers=headers)
        if self.repo is not None and self.status == 200:
            response = self.repo.respond(request.url.path)
            if response is not None:
                return response
        return httpx.Response(self.status, json=self.payload, headers=self.headers)


@pytest.fixture
def settings():
    return load_settings(TEST_ENV)


@pytest.fixture
def mongo():
    return mongomock.MongoClient(tz_aware=True)


@pytest.fixture
def db(mongo, settings):
    return mongo[settings.mongodb_db]


@pytest.fixture
def fake_redis():
    return FakeRedis()


@pytest.fixture
def github():
    return GitHubStub()


@pytest.fixture
def app(settings, mongo, fake_redis, github):
    application = create_app(
        settings,
        mongo_client=mongo,
        redis_client=fake_redis,
        github_transport=httpx.MockTransport(github.handler),
    )
    application.state.github.sleep = lambda _seconds: None  # no real back-off waits in tests
    return application


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client


VALID_USER = {"email": "alice@example.com", "password": "correct-horse-42", "full_name": "Alice Example"}


def register(client, **overrides):
    return client.post("/api/auth/register", json={**VALID_USER, **overrides})


@pytest.fixture
def auth_headers(client):
    response = register(client)
    assert response.status_code == 201, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture
def other_headers(client):
    response = register(client, email="bob@example.com", full_name="Bob Example")
    assert response.status_code == 201, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


FIXTURES = Path(__file__).parent / "fixtures"


def load_tree(name: str) -> dict[str, bytes]:
    """Every file under tests/fixtures/<name>, keyed by repository-relative path."""
    root = FIXTURES / name
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*"))
            if p.is_file() and p.name not in {"README.md", "FILES.tsv"}}


def run_worker(app) -> int:
    """Run the worker's job loop once against the application's own database and GitHub client."""
    from app.workers.worker import process_available_jobs

    return process_available_jobs(app.state.settings, app.state.db, app.state.github)
