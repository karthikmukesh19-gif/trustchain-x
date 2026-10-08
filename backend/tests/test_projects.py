import httpx
import pytest
from bson import ObjectId

from tests.conftest import GITHUB_REPO_PAYLOAD

PROJECT = {"name": "Django", "repository_url": "https://github.com/django/django", "description": "Web framework"}


def create(client, headers, **overrides):
    return client.post("/api/projects", json={**PROJECT, **overrides}, headers=headers)


def test_projects_require_authentication(client):
    assert client.get("/api/projects").status_code == 401
    assert client.post("/api/projects", json=PROJECT).status_code == 401
    assert client.get(f"/api/projects/{ObjectId()}").status_code == 401
    assert client.delete(f"/api/projects/{ObjectId()}").status_code == 401


def test_create_project_registers_repository_and_fetches_metadata(client, auth_headers, github, db):
    response = create(client, auth_headers)
    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "Django"
    assert body["repository_url"] == "https://github.com/django/django"
    assert body["status"] == "ACTIVE"
    assert body["last_analysis"] is None
    assert body["languages"] == []
    assert body["repository"]["full_name"] == "django/django"

    # The metadata fetch runs after the response; by now it has completed.
    assert len(github.requests) == 1
    request = github.requests[0]
    assert str(request.url) == "https://api.github.com/repos/django/django"
    assert "authorization" not in request.headers

    fetched = client.get(f"/api/projects/{body['id']}", headers=auth_headers).json()
    assert fetched["default_branch"] == "main"
    repo = fetched["repository"]
    assert repo["metadata_status"] == "FETCHED"
    assert repo["metadata_error"] is None
    assert repo["metadata"]["stars"] == GITHUB_REPO_PAYLOAD["stargazers_count"]
    assert repo["metadata"]["primary_language"] == "Python"
    assert repo["metadata"]["license"] == "BSD-3-Clause"
    assert db.repositories.count_documents({}) == 1


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/django/django/",
        "https://github.com/django/django.git",
        "https://www.github.com/django/django",
        "  https://github.com/django/django  ",
    ],
)
def test_repository_url_is_canonicalised(client, auth_headers, url):
    response = create(client, auth_headers, repository_url=url)
    assert response.status_code == 201
    assert response.json()["repository_url"] == "https://github.com/django/django"


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/django/django",
        "https://gitlab.com/django/django",
        "https://github.com.evil.example/django/django",
        "https://evil.example/github.com/django/django",
        "https://user:pass@github.com/django/django",
        "https://github.com@evil.example/django/django",
        "https://github.com:8443/django/django",
        "https://github.com/django",
        "https://github.com/django/django/tree/main",
        "https://github.com/django/django?tab=readme",
        "https://github.com/django/django#readme",
        "https://github.com/django/..",
        "https://github.com/../django",
        "https://github.com/django/dj%2Fango",
        "https://github.com/-bad/django",
        "https://169.254.169.254/latest/meta-data",
        "https://localhost/a/b",
        "file:///etc/passwd",
        "git@github.com:django/django.git",
        "javascript:alert(1)",
        "https://github.com/django/dja ngo",
        "https://github.com\\@evil.example/a/b",
    ],
)
def test_unsafe_or_unsupported_repository_urls_are_rejected(client, auth_headers, github, url):
    response = create(client, auth_headers, repository_url=url)
    assert response.status_code == 422
    assert github.requests == []


def test_same_repository_cannot_be_registered_twice_by_one_user(client, auth_headers):
    assert create(client, auth_headers).status_code == 201
    duplicate = create(client, auth_headers, name="Again", repository_url="https://github.com/Django/DJANGO.git")
    assert duplicate.status_code == 409


def test_two_users_can_register_the_same_repository(client, auth_headers, other_headers, db, github):
    assert create(client, auth_headers).status_code == 201
    assert create(client, other_headers).status_code == 201
    assert db.projects.count_documents({}) == 2
    assert db.repositories.count_documents({}) == 1
    # Fresh metadata is reused instead of calling GitHub again.
    assert len(github.requests) == 1


def test_users_only_see_their_own_projects(client, auth_headers, other_headers):
    mine = create(client, auth_headers).json()
    theirs = create(client, other_headers, repository_url="https://github.com/pallets/flask", name="Flask").json()

    listing = client.get("/api/projects", headers=auth_headers).json()
    assert listing["total"] == 1
    assert [p["id"] for p in listing["items"]] == [mine["id"]]

    assert client.get(f"/api/projects/{theirs['id']}", headers=auth_headers).status_code == 404
    assert client.delete(f"/api/projects/{theirs['id']}", headers=auth_headers).status_code == 404
    assert client.post(f"/api/projects/{theirs['id']}/refresh-metadata", headers=auth_headers).status_code == 404
    assert client.get(f"/api/projects/{theirs['id']}", headers=other_headers).status_code == 200


def test_list_is_newest_first_and_paginated(client, auth_headers):
    names = ["one", "two", "three"]
    for name in names:
        assert create(client, auth_headers, name=name, repository_url=f"https://github.com/org/{name}").status_code == 201
    page = client.get("/api/projects?limit=2", headers=auth_headers).json()
    assert page["total"] == 3
    assert [p["name"] for p in page["items"]] == ["three", "two"]
    rest = client.get("/api/projects?limit=2&skip=2", headers=auth_headers).json()
    assert [p["name"] for p in rest["items"]] == ["one"]


@pytest.mark.parametrize("query", ["limit=0", "limit=101", "skip=-1", "limit=abc"])
def test_list_rejects_bad_pagination(client, auth_headers, query):
    assert client.get(f"/api/projects?{query}", headers=auth_headers).status_code == 422


@pytest.mark.parametrize("project_id", ["nope", "123", str(ObjectId()), "../../etc/passwd", "{'$ne': 1}"])
def test_unknown_or_malformed_project_ids_return_404(client, auth_headers, project_id):
    assert client.get(f"/api/projects/{project_id}", headers=auth_headers).status_code == 404


@pytest.mark.parametrize(
    "overrides",
    [{"name": ""}, {"name": "   "}, {"name": "x" * 121}, {"description": "y" * 1001}, {"name": "bad\x00name"}],
)
def test_create_validates_fields(client, auth_headers, overrides):
    assert create(client, auth_headers, **overrides).status_code == 422


def test_create_rejects_unknown_fields(client, auth_headers):
    response = client.post("/api/projects", json={**PROJECT, "owner_id": str(ObjectId())}, headers=auth_headers)
    assert response.status_code == 422


def test_query_operators_in_body_are_not_accepted(client, auth_headers):
    response = client.post(
        "/api/projects", json={**PROJECT, "name": {"$gt": ""}}, headers=auth_headers
    )
    assert response.status_code == 422


def test_delete_project(client, auth_headers, db):
    project = create(client, auth_headers).json()
    assert client.delete(f"/api/projects/{project['id']}", headers=auth_headers).status_code == 204
    assert client.get(f"/api/projects/{project['id']}", headers=auth_headers).status_code == 404
    assert client.delete(f"/api/projects/{project['id']}", headers=auth_headers).status_code == 404
    actions = [e["action"] for e in db.audit_logs.find({})]
    assert actions.count("project.create") == 1 and actions.count("project.delete") == 1


@pytest.mark.parametrize(
    "status,headers,expected",
    [
        (404, {}, "not found"),
        (301, {}, "moved or renamed"),
        (403, {"x-ratelimit-remaining": "0"}, "rate limit"),
        (429, {}, "rate limit"),
        (403, {}, "denied"),
        (401, {}, "token"),
        (500, {}, "HTTP 500"),
    ],
)
def test_github_failures_are_recorded_not_raised(client, auth_headers, github, status, headers, expected):
    github.status, github.headers, github.payload = status, headers, {"message": "x"}
    created = create(client, auth_headers)
    assert created.status_code == 201
    repo = client.get(f"/api/projects/{created.json()['id']}", headers=auth_headers).json()["repository"]
    assert repo["metadata_status"] == "UNAVAILABLE"
    assert expected.lower() in repo["metadata_error"].lower()
    assert repo["metadata"] is None


@pytest.mark.parametrize(
    "error,expected",
    [(httpx.ConnectTimeout("slow"), "in time"), (httpx.ConnectError("down"), "could not be reached")],
)
def test_github_network_errors_are_recorded(client, auth_headers, github, error, expected):
    github.error = error
    created = create(client, auth_headers).json()
    repo = client.get(f"/api/projects/{created['id']}", headers=auth_headers).json()["repository"]
    assert repo["metadata_status"] == "UNAVAILABLE"
    assert expected in repo["metadata_error"]


def test_malformed_github_payload_is_handled(client, auth_headers, github):
    github.payload = ["not", "an", "object"]
    created = create(client, auth_headers).json()
    repo = client.get(f"/api/projects/{created['id']}", headers=auth_headers).json()["repository"]
    assert repo["metadata_status"] == "UNAVAILABLE"


def test_untrusted_github_fields_are_type_checked(client, auth_headers, github):
    github.payload = {
        **GITHUB_REPO_PAYLOAD,
        "stargazers_count": "lots",
        "archived": "yes",
        "description": "d" * 5000,
        "license": "MIT",
        "pushed_at": "yesterday",
        "default_branch": {"$where": "1"},
    }
    created = create(client, auth_headers).json()
    fetched = client.get(f"/api/projects/{created['id']}", headers=auth_headers).json()
    meta = fetched["repository"]["metadata"]
    assert meta["stars"] is None and meta["archived"] is None and meta["license"] is None
    assert meta["pushed_at"] is None and meta["default_branch"] is None
    assert len(meta["description"]) == 1000
    assert fetched["default_branch"] is None


def test_refresh_metadata_recovers_after_failure(client, auth_headers, github):
    github.status = 500
    created = create(client, auth_headers).json()
    github.status = 200
    refreshed = client.post(f"/api/projects/{created['id']}/refresh-metadata", headers=auth_headers)
    assert refreshed.status_code == 200
    assert refreshed.json()["repository"]["metadata_status"] == "FETCHED"
    assert refreshed.json()["default_branch"] == "main"
    assert len(github.requests) == 4  # the failing request was retried twice before giving up


def test_failed_refresh_keeps_previously_fetched_metadata(client, auth_headers, github):
    created = create(client, auth_headers).json()
    github.status = 500
    refreshed = client.post(f"/api/projects/{created['id']}/refresh-metadata", headers=auth_headers).json()
    assert refreshed["repository"]["metadata_status"] == "UNAVAILABLE"
    assert refreshed["repository"]["metadata"]["stars"] == GITHUB_REPO_PAYLOAD["stargazers_count"]


def test_github_token_is_sent_only_to_the_configured_api(mongo, fake_redis, github):
    from fastapi.testclient import TestClient

    from app.config.settings import load_settings
    from app.main import create_app
    from tests.conftest import TEST_ENV, register

    settings = load_settings({**TEST_ENV, "GITHUB_TOKEN": "ghp_example"})
    app = create_app(settings, mongo_client=mongo, redis_client=fake_redis, github_transport=httpx.MockTransport(github.handler))
    with TestClient(app) as c:
        headers = {"Authorization": f"Bearer {register(c).json()['access_token']}"}
        assert create(c, headers).status_code == 201
    assert github.requests[0].url.host == "api.github.com"
    assert github.requests[0].headers["authorization"] == "Bearer ghp_example"
    assert "ghp_example" not in repr(settings)
