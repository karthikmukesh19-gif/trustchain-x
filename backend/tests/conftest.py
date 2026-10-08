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
import json
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


class OsvStub:
    """A programmable OSV API (POST /v1/querybatch, GET /v1/vulns/{id}). Records every request.

    `records` holds advisory records by id. `reports` says which ids OSV
    reports for a package version; tests state that explicitly, exactly as
    they would observe it from the real service.
    """

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.records: dict[str, dict] = {}
        self.reports: dict[tuple[str, str, str], list[str]] = {}
        self.fail: dict[str, list[tuple[int, dict[str, str]]]] = {}   # path fragment -> queued (status, headers) failures
        self.always_fail: dict[str, tuple[int, dict[str, str]]] = {}
        self.error: Exception | None = None
        self.raw_bodies: dict[str, bytes] = {}                        # id -> body served instead of the record
        self.page_size: int | None = None                              # ids per query page (None: all at once)
        self.modified_override: dict[str, str] = {}

    def add(self, *records: dict) -> None:
        for record in records:
            self.records[record["id"]] = record

    def report(self, ecosystem: str, name: str, version: str, *ids: str) -> None:
        self.reports[(ecosystem, name, version)] = list(ids)

    def load(self, *names: str) -> list[dict]:
        """Add real advisory records from tests/fixtures/osv by id."""
        loaded = [json.loads((FIXTURES / "osv" / f"{name}.json").read_text()) for name in names]
        self.add(*loaded)
        return loaded

    def calls(self, fragment: str) -> list[httpx.Request]:
        return [r for r in self.requests if fragment in r.url.path]

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        path = request.url.path
        for fragment, (status, headers) in self.always_fail.items():
            if fragment in path:
                return httpx.Response(status, json={"message": "simulated"}, headers=headers)
        for fragment, queue in self.fail.items():
            if fragment in path and queue:
                status, headers = queue.pop(0)
                return httpx.Response(status, json={"message": "simulated"}, headers=headers)
        if request.method == "POST" and path.endswith("/v1/querybatch"):
            results = []
            for query in json.loads(request.content)["queries"]:
                package = query["package"]
                ids = self.reports.get((package["ecosystem"], package["name"], query["version"]), [])
                start = int(query.get("page_token") or 0)
                page = ids[start:start + self.page_size] if self.page_size else ids
                answer: dict = {}
                if page:
                    answer["vulns"] = [{"id": i, "modified": self.modified_override.get(i, self.records.get(i, {}).get("modified", ""))}
                                       for i in page]
                if self.page_size and start + self.page_size < len(ids):
                    answer["next_page_token"] = str(start + self.page_size)
                results.append(answer)
            return httpx.Response(200, json={"results": results})
        if request.method == "GET" and "/v1/vulns/" in path:
            identifier = path.rsplit("/", 1)[1]
            if identifier in self.raw_bodies:
                return httpx.Response(200, content=self.raw_bodies[identifier], headers={"content-type": "application/json"})
            if identifier in self.records:
                return httpx.Response(200, json=self.records[identifier])
            return httpx.Response(404, json={"code": 5, "message": "Bug not found."})
        return httpx.Response(404, json={"message": "not found"})


class RegistryStub:
    """Programmable PyPI and npm registries. Records every request.

    `packages` maps (ecosystem, name) to {"latest": version, "releases": {version: ISO date or None},
    "yanked": [versions], "deprecated": [versions]}. The contents are test data, not a copy of the real registries.
    """

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.packages: dict[tuple[str, str], dict] = {}
        self.fail: dict[str, int] = {}                # name fragment -> HTTP status
        self.error: Exception | None = None
        self.raw: dict[str, bytes] = {}               # name fragment -> body served as-is

    def add(self, ecosystem: str, name: str, latest: str | None, releases: dict[str, str | None], **extra) -> None:
        self.packages[(ecosystem, name)] = {"latest": latest, "releases": releases, **extra}

    def calls(self, host: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.host == host]

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        path = request.url.path
        for fragment, status in self.fail.items():
            if fragment in path:
                return httpx.Response(status, json={"message": "simulated"})
        for fragment, body in self.raw.items():
            if fragment in path:
                return httpx.Response(200, content=body, headers={"content-type": "application/json"})
        if request.url.host == "pypi.org":
            name = path.removeprefix("/pypi/").removesuffix("/json")
            package = self.packages.get(("pypi", name))
            if package is None:
                return httpx.Response(404, json={"message": "Not Found"})
            yanked = set(package.get("yanked", []))
            releases = {version: ([] if moment is None else [{"upload_time_iso_8601": moment, "yanked": version in yanked},
                                                             {"upload_time_iso_8601": moment.replace("T", "T") , "yanked": version in yanked}])
                        for version, moment in package["releases"].items()}
            return httpx.Response(200, json={"info": {"name": name, "version": package["latest"]}, "releases": releases})
        name = request.url.raw_path.decode().lstrip("/").replace("%2F", "/").replace("%2f", "/")
        package = self.packages.get(("npm", name))
        if package is None:
            return httpx.Response(404, json={"error": "Not found"})
        compact = "vnd.npm.install-v1" in request.headers.get("accept", "")
        deprecated = set(package.get("deprecated", []))
        body: dict = {"name": name, "dist-tags": {"latest": package["latest"]} if package["latest"] else {},
                      "versions": {version: ({"deprecated": "no longer supported"} if version in deprecated else {})
                                   for version in package["releases"]}}
        if not compact:
            body["time"] = {"created": "2010-01-01T00:00:00.000Z", **{v: m for v, m in package["releases"].items() if m}}
        return httpx.Response(200, json=body)


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
def osv():
    return OsvStub()


@pytest.fixture
def registry():
    return RegistryStub()


@pytest.fixture
def app(settings, mongo, fake_redis, github, osv, registry):
    application = create_app(
        settings,
        mongo_client=mongo,
        redis_client=fake_redis,
        github_transport=httpx.MockTransport(github.handler),
        provider_transport=httpx.MockTransport(osv.handler),
        registry_transport=httpx.MockTransport(registry.handler),
    )
    for client in application.state.registries.values():
        client.sleep = lambda _seconds: None
    application.state.github.sleep = lambda _seconds: None  # no real back-off waits in tests
    for provider in application.state.providers.values():
        provider.sleep = lambda _seconds: None
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

    return process_available_jobs(app.state.settings, app.state.db, app.state.github, providers=app.state.providers,
                                  registries=app.state.registries)
