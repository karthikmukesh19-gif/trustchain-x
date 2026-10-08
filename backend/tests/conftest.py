"""Test fixtures.

The application is built through its public factory with in-memory stand-ins
for its three external systems:

* MongoDB  -> mongomock (same PyMongo API, including unique indexes)
* Redis    -> a minimal in-memory object exposing the calls the app makes
* GitHub   -> httpx.MockTransport, so the real HTTP client code runs but no
              network request leaves the process
"""

from __future__ import annotations

import time

import httpx
import mongomock
import pytest
from fastapi.testclient import TestClient

from app.config.settings import load_settings
from app.main import create_app

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

    def close(self) -> None:
        pass


class GitHubStub:
    """Programmable GitHub API. Records every request it receives."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.status = 200
        self.payload: object = dict(GITHUB_REPO_PAYLOAD)
        self.headers: dict[str, str] = {}
        self.error: Exception | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
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
    return create_app(
        settings,
        mongo_client=mongo,
        redis_client=fake_redis,
        github_transport=httpx.MockTransport(github.handler),
    )


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
