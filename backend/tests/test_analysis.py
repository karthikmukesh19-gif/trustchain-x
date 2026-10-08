"""Dependency analysis end to end: API -> job -> worker -> snapshot -> extraction -> graph -> MongoDB -> API."""

import json
import threading
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from bson import ObjectId
from fastapi.testclient import TestClient

from app.config.settings import load_settings
from app.main import create_app
from app.services import analysis
from app.workers import worker
from tests.conftest import FIXTURES, TEST_ENV, FakeRepository, load_tree, register, run_worker

REPO_URL = "https://github.com/octo/demo"
ENDPOINTS = [
    ("get", "/dependencies/paths?to=npm:b@2.5.0"),
    ("post", "/analysis/dependencies"), ("get", "/analysis/status"), ("get", "/snapshot"), ("get", "/snapshot/files"),
    ("get", "/dependencies"), ("get", "/dependencies/graph"),
]

MIXED_REPO = {
    "README.md": "# demo\n",
    "backend/app.py": "import flask\n" * 200,
    "backend/util.py": "x = 1\n",
    "backend/models.py": "y = 2\n",
    "backend/requirements.txt": "flask==3.0.0\nrequests>=2.31\n-r extra/more.txt\n-r ../../outside.txt\n",
    "backend/extra/more.txt": "pyyaml==6.0.1\n",
    "web/package.json": json.dumps({"name": "web", "dependencies": {"a": "^1.0.0"}, "devDependencies": {"d": "^1.0.0"}}),
    "web/package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "web", "dependencies": {"a": "^1.0.0"}, "devDependencies": {"d": "^1.0.0"}},
        "node_modules/a": {"version": "1.2.0", "integrity": "sha512-AAAA", "dependencies": {"b": "^2.0.0"}},
        "node_modules/b": {"version": "2.5.0"},
        "node_modules/d": {"version": "1.0.0", "dev": True}}}),
    "web/src/index.ts": "export {}\n" * 100,
    "svc/go.mod": "module example.com/svc\n\ngo 1.22\n\nrequire (\n\tgithub.com/a/b v1.0.0\n\tgithub.com/c/d v0.2.0 // indirect\n)\n",
    "svc/main.go": "package main\n",
    "Gemfile": "gem 'rails'\n",
    "setup.py": "import os; os.system('echo this must never run')\n",
    "node_modules/evil/package.json": json.dumps({"dependencies": {"should-not-appear": "1.0.0"}}),
}


def make_app(mongo, fake_redis, github, **env):
    settings = load_settings({**TEST_ENV, **{k: str(v) for k, v in env.items()}})
    application = create_app(settings, mongo_client=mongo, redis_client=fake_redis, github_transport=httpx.MockTransport(github.handler))
    application.state.github.sleep = lambda _s: None
    return application


@pytest.fixture
def repo(github):
    github.repo = FakeRepository(MIXED_REPO)
    return github.repo


@pytest.fixture
def project(client, auth_headers, repo):
    response = client.post("/api/projects", json={"name": "Demo", "repository_url": REPO_URL}, headers=auth_headers)
    assert response.status_code == 201
    return response.json()


def start(client, headers, project):
    return client.post(f"/api/projects/{project['id']}/analysis/dependencies", headers=headers)


def analyse(client, app, headers, project):
    assert start(client, headers, project).status_code == 202
    assert run_worker(app) == 1
    return client.get(f"/api/projects/{project['id']}/analysis/status", headers=headers).json()["job"]


def get(client, headers, project, path, **params):
    return client.get(f"/api/projects/{project['id']}{path}", headers=headers, params=params)


# --- authentication and authorisation ---------------------------------------

@pytest.mark.parametrize("method,path", ENDPOINTS)
def test_analysis_endpoints_require_authentication(client, method, path):
    assert getattr(client, method)(f"/api/projects/{ObjectId()}{path}").status_code == 401


@pytest.mark.parametrize("method,path", ENDPOINTS)
def test_only_the_owner_can_reach_a_projects_analysis(client, app, auth_headers, other_headers, project, method, path):
    analyse(client, app, auth_headers, project)
    url = f"/api/projects/{project['id']}{path}"
    assert getattr(client, method)(url, headers=other_headers).status_code == 404
    assert getattr(client, method)(url, headers=auth_headers).status_code in (200, 202)


@pytest.mark.parametrize("project_id", ["nope", "../x", str(ObjectId())])
def test_unknown_projects_are_404(client, auth_headers, project_id):
    assert client.post(f"/api/projects/{project_id}/analysis/dependencies", headers=auth_headers).status_code == 404
    assert client.get(f"/api/projects/{project_id}/dependencies", headers=auth_headers).status_code == 404


# --- job lifecycle ----------------------------------------------------------

def test_nothing_is_reported_before_an_analysis_runs(client, auth_headers, project):
    status = get(client, auth_headers, project, "/analysis/status").json()
    assert status == {"job": None, "has_results": False, "last_analysis": None}
    for path in ("/snapshot", "/snapshot/files", "/dependencies", "/dependencies/graph"):
        response = get(client, auth_headers, project, path)
        assert response.status_code == 404 and "not been analysed" in response.json()["detail"]


def test_request_queues_a_job_and_does_not_claim_completion(client, app, auth_headers, project, fake_redis, db):
    response = start(client, auth_headers, project)
    assert response.status_code == 202
    job = response.json()["job"]
    assert job["state"] == "queued" and job["stage"] == "QUEUED" and job["snapshot_id"] is None and job["finished_at"] is None
    assert "owner_id" not in job
    assert fake_redis.queues[analysis.QUEUE_KEY] == [job["id"]]

    status = get(client, auth_headers, project, "/analysis/status").json()
    assert status["job"]["state"] == "queued" and status["has_results"] is False
    assert get(client, auth_headers, project, "/dependencies").status_code == 404
    assert client.get(f"/api/projects/{project['id']}", headers=auth_headers).json()["last_analysis"] is None
    assert db.repository_snapshots.count_documents({}) == 0


def test_only_one_analysis_per_project_at_a_time(client, app, auth_headers, project, db):
    assert start(client, auth_headers, project).status_code == 202
    again = start(client, auth_headers, project)
    assert again.status_code == 409 and db.analysis_jobs.count_documents({}) == 1
    run_worker(app)
    assert start(client, auth_headers, project).status_code == 202       # allowed again once finished


def test_worker_completes_the_job_and_records_progress(client, app, auth_headers, project, db):
    job = analyse(client, app, auth_headers, project)
    assert job["state"] == "completed" and job["stage"] == "COMPLETED" and job["stage_index"] == job["stage_count"] == 5
    assert job["error"] is None and job["started_at"] and job["finished_at"] and job["snapshot_id"]
    assert job["summary"]["dependencies"] == 8 and job["summary"]["ecosystems"] == ["golang", "npm", "pypi"]
    stored = client.get(f"/api/projects/{project['id']}", headers=auth_headers).json()
    assert stored["last_analysis"] is not None and stored["latest_snapshot_id"] == job["snapshot_id"]
    assert stored["languages"] == ["Python", "TypeScript", "Go"]
    assert db.projects.find_one({})["active_job_id"] is None
    assert client.get("/api/dashboard/summary", headers=auth_headers).json()["projects_analysed"] == 1


def test_jobs_run_oldest_first_and_each_is_claimed_once(client, app, auth_headers, other_headers, project, db):
    second = client.post("/api/projects", json={"name": "Second", "repository_url": REPO_URL}, headers=other_headers).json()
    start(client, auth_headers, project)
    start(client, other_headers, second)
    first_claim = analysis.claim_next_job(db)
    assert str(first_claim["project_id"]) == project["id"] and first_claim["state"] == "running"
    assert str(analysis.claim_next_job(db)["project_id"]) == second["id"]
    assert analysis.claim_next_job(db) is None


def test_job_survives_redis_being_down_when_requested(client, app, auth_headers, project, fake_redis):
    fake_redis.available = False
    assert start(client, auth_headers, project).status_code == 202
    assert run_worker(app) == 1                                           # found by polling MongoDB
    assert get(client, auth_headers, project, "/analysis/status").json()["job"]["state"] == "completed"


def test_stale_running_jobs_are_failed_so_the_project_is_not_stuck(client, app, auth_headers, project, db, settings):
    start(client, auth_headers, project)
    analysis.claim_next_job(db)                                           # a worker took it, then died
    db.analysis_jobs.update_one({}, {"$set": {"started_at": datetime.now(timezone.utc) - timedelta(hours=1)}})
    assert analysis.fail_stale_jobs(db, settings) == 1
    job = get(client, auth_headers, project, "/analysis/status").json()["job"]
    assert job["state"] == "failed" and job["error"]["code"] == "WORKER_INTERRUPTED"
    assert start(client, auth_headers, project).status_code == 202


def test_recent_running_jobs_are_left_alone(client, auth_headers, project, db, settings):
    start(client, auth_headers, project)
    analysis.claim_next_job(db)
    assert analysis.fail_stale_jobs(db, settings) == 0


def test_requests_and_outcomes_are_audited(client, app, auth_headers, project, db):
    analyse(client, app, auth_headers, project)
    actions = [(e["action"], e["outcome"]) for e in db.audit_logs.find({"action": {"$regex": "^analysis"}})]
    assert actions == [("analysis.dependencies.request", "success"), ("analysis.dependencies.finish", "success")]


def test_worker_loop_processes_jobs_and_stops(client, app, auth_headers, project, fake_redis):
    start(client, auth_headers, project)
    stop = threading.Event()
    original = worker.wait_for_work

    def wait_then_stop(redis_client, timeout, stop_event):
        original(redis_client, timeout, stop_event)
        stop_event.set()

    worker.wait_for_work = wait_then_stop
    try:
        worker.run(app.state.settings, fake_redis, app.state.db, app.state.github, stop)
    finally:
        worker.wait_for_work = original
    assert get(client, auth_headers, project, "/analysis/status").json()["job"]["state"] == "completed"


def test_wait_for_work_falls_back_to_polling_without_redis(fake_redis):
    fake_redis.available = False
    stop = threading.Event()
    stop.set()
    worker.wait_for_work(fake_redis, 5, stop)                             # returns instead of raising


# --- integration: snapshot -> extraction -> graph -> API --------------------

def test_snapshot_is_recorded_with_evidence(client, app, auth_headers, project, repo):
    analyse(client, app, auth_headers, project)
    snapshot = get(client, auth_headers, project, "/snapshot").json()
    assert snapshot["repository_url"] == REPO_URL and snapshot["branch"] == "main"
    assert snapshot["commit_sha"] == repo.commit_sha and snapshot["tree_sha"] == repo.tree_sha
    assert snapshot["status"] == "COMPLETE" and snapshot["collected_at"] and snapshot["analyzer_version"] == analysis.ANALYZER_VERSION
    assert snapshot["file_count"] == len(MIXED_REPO) and "no repository code executed" in snapshot["collection_method"]
    assert "files" not in snapshot

    files = {f["path"]: f for f in snapshot["dependency_files"]}
    assert set(files) == {"Gemfile", "setup.py", "backend/requirements.txt", "backend/extra/more.txt", "web/package.json",
                          "web/package-lock.json", "svc/go.mod"}
    assert "node_modules/evil/package.json" not in files
    requirements = files["backend/requirements.txt"]
    assert requirements["status"] == "PARSED" and requirements["dependencies_found"] == 2
    assert requirements["git_blob_sha"] == repo.blob_id("backend/requirements.txt") and len(requirements["sha256"]) == 64
    assert any("outside.txt" in note and "ignored" in note for note in requirements["notes"])
    assert files["backend/extra/more.txt"]["referenced_by"] == "backend/requirements.txt"
    assert files["Gemfile"]["status"] == "UNSUPPORTED" and files["Gemfile"]["sha256"] is None       # recognised, never fetched
    assert files["setup.py"]["status"] == "NOT_EVALUATED" and "never run" in files["setup.py"]["detail"]

    languages = {l["language"]: l for l in snapshot["languages"]["languages"]}
    assert snapshot["languages"]["primary_language"] == "Python" and set(languages) == {"Python", "TypeScript", "Go"}
    assert languages["Python"]["evidence_files"][0] == "backend/app.py"
    assert snapshot["github_primary_language"] == "Python"
    managers = {p["package_manager"]: p for p in snapshot["package_managers"]}
    assert set(managers) == {"pip", "npm", "go", "bundler"} and managers["bundler"]["supported"] is False


def test_snapshot_files_are_listed_with_hashes(client, app, auth_headers, project, repo):
    analyse(client, app, auth_headers, project)
    page = get(client, auth_headers, project, "/snapshot/files", limit=5).json()
    assert page["total"] == len(MIXED_REPO) and len(page["items"]) == 5
    hit = get(client, auth_headers, project, "/snapshot/files", q="GO.MOD").json()
    assert hit["items"] == [{"path": "svc/go.mod", "size": len(MIXED_REPO["svc/go.mod"]), "git_blob_sha": repo.blob_id("svc/go.mod")}]


def test_dependencies_are_normalised_classified_and_evidenced(client, app, auth_headers, project, repo):
    analyse(client, app, auth_headers, project)
    body = get(client, auth_headers, project, "/dependencies").json()
    deps = {d["node_id"]: d for d in body["items"]}
    assert set(deps) == {"pypi:flask@3.0.0", "pypi:requests@unresolved", "pypi:pyyaml@6.0.1", "npm:a@1.2.0", "npm:b@2.5.0",
                         "npm:d@1.0.0", "golang:github.com/a/b@v1.0.0", "golang:github.com/c/d@v0.2.0"}
    assert "should-not-appear" not in json.dumps(body)
    assert body["total"] == 8 and body["snapshot"]["commit_sha"] == repo.commit_sha
    assert body["summary"]["direct"] == 6 and body["summary"]["transitive"] == 2 and body["summary"]["unresolved_versions"] == 1
    assert body["summary"]["max_depth"] == 2 and body["summary"]["by_ecosystem"] == {"pypi": 3, "npm": 3, "golang": 2}

    flask = deps["pypi:flask@3.0.0"]
    assert flask["purl"] == "pkg:pypi/flask@3.0.0" and flask["version_basis"] == "OBSERVED"
    assert (flask["relationship"], flask["relationship_basis"]) == ("DIRECT", "INFERRED")
    assert flask["evidence"] == [{
        "source_file": "backend/requirements.txt", "file_kind": "manifest", "package_manager": "pip", "line": 1,
        "declaration": "flask==3.0.0", "constraint": "==3.0.0", "scope": "runtime", "evidence_type": "repository_file",
        "extras": [], "marker": None, "git_blob_sha": repo.blob_id("backend/requirements.txt")}]
    requests_dep = deps["pypi:requests@unresolved"]
    assert requests_dep["version"] is None and requests_dep["version_status"] == "UNRESOLVED" and requests_dep["constraints"] == [">=2.31"]
    assert deps["npm:b@2.5.0"]["relationship"] == "TRANSITIVE" and deps["npm:b@2.5.0"]["parents"] == ["npm:a@1.2.0"]
    assert deps["npm:a@1.2.0"]["integrity"] == [{"algorithm": "sha512", "value": "AAAA"}]
    assert deps["golang:github.com/c/d@v0.2.0"]["relationship"] == "TRANSITIVE" and deps["golang:github.com/c/d@v0.2.0"]["depth"] is None
    assert "project_id" not in flask and "_id" not in flask


def test_dependency_filters(client, app, auth_headers, project):
    analyse(client, app, auth_headers, project)

    def ids(**params):
        return [d["node_id"] for d in get(client, auth_headers, project, "/dependencies", **params).json()["items"]]

    assert ids(ecosystem="npm") == ["npm:a@1.2.0", "npm:b@2.5.0", "npm:d@1.0.0"]
    assert ids(relationship="transitive") == ["golang:github.com/c/d@v0.2.0", "npm:b@2.5.0"]
    assert ids(version_status="UNRESOLVED") == ["pypi:requests@unresolved"]
    assert ids(q="YAML") == ["pypi:pyyaml@6.0.1"]
    assert ids(q=".*") == [] and ids(q="$where") == []                     # search text is literal, never a pattern
    assert ids(limit=2, skip=6) == ["pypi:pyyaml@6.0.1", "pypi:requests@unresolved"]
    for bad in ({"relationship": "sideways"}, {"version_status": "MAYBE"}, {"ecosystem": "np m"}, {"limit": 0}, {"limit": 501}, {"skip": -1}):
        assert get(client, auth_headers, project, "/dependencies", **bad).status_code == 422


def test_graph_is_stored_and_served(client, app, auth_headers, project, db):
    analyse(client, app, auth_headers, project)
    graph = get(client, auth_headers, project, "/dependencies/graph").json()
    assert graph["root"] == {"id": "root", "type": "application", "label": "octo/demo"}
    assert len(graph["nodes"]) == 8 and graph["stats"]["edges"] == len(graph["edges"]) == 7
    node_ids = {n["node_id"] for n in graph["nodes"]} | {"root"}
    assert all(e["source"] in node_ids and e["target"] in node_ids and e["evidence_files"] for e in graph["edges"])
    assert {"source": "npm:a@1.2.0", "target": "npm:b@2.5.0"}.items() <= next(e for e in graph["edges"] if e["target"] == "npm:b@2.5.0").items()
    assert "evidence" not in graph["nodes"][0] and "paths" not in graph
    assert db.dependency_graphs.count_documents({}) == 1 and db.dependencies.count_documents({}) == 8

    paths = get(client, auth_headers, project, "/dependencies/graph", paths_to="npm:b@2.5.0").json()["paths"]
    assert paths == [["root", "npm:a@1.2.0", "npm:b@2.5.0"]]
    assert get(client, auth_headers, project, "/dependencies/graph", paths_to="npm:ghost@1").status_code == 404
    assert get(client, auth_headers, project, "/dependencies/paths", to="npm:b@2.5.0").json() == {
        "to": "npm:b@2.5.0", "paths": [["root", "npm:a@1.2.0", "npm:b@2.5.0"]]}
    assert get(client, auth_headers, project, "/dependencies/paths", to="npm:ghost@1").status_code == 404
    assert get(client, auth_headers, project, "/dependencies/paths").status_code == 422


def test_resolved_versions_are_catalogued_once(client, app, auth_headers, other_headers, project, db):
    analyse(client, app, auth_headers, project)
    assert db.dependency_versions.count_documents({}) == 7                 # the unresolved one is not catalogued
    record = db.dependency_versions.find_one({"package_name": "flask"})
    assert record["version"] == "3.0.0" and record["purl"] == "pkg:pypi/flask@3.0.0"
    second = client.post("/api/projects", json={"name": "Again", "repository_url": REPO_URL}, headers=other_headers).json()
    analyse(client, app, other_headers, second)
    assert db.dependency_versions.count_documents({}) == 7


def test_repository_code_is_never_executed(client, app, auth_headers, project, github, repo):
    analyse(client, app, auth_headers, project)
    fetched = [r.url.path.rsplit("/", 1)[-1] for r in github.requests if "/git/blobs/" in r.url.path]
    assert repo.blob_id("setup.py") not in fetched and repo.blob_id("Gemfile") not in fetched
    assert repo.blob_id("backend/app.py") not in fetched                    # only dependency files are read
    assert len(fetched) == 5


# --- real repository content: ShadowWatch -----------------------------------

@pytest.fixture
def shadowwatch(github):
    files = load_tree("shadowwatch")
    sizes = {}
    for line in (FIXTURES / "shadowwatch" / "FILES.tsv").read_text().splitlines():
        size, path = line.split("\t", 1)
        sizes[path] = int(size)
        files.setdefault(path, b"")
    github.repo = FakeRepository(files)
    github.repo.listed_sizes = {p: s for p, s in sizes.items() if not files[p]}
    return github.repo


def test_shadowwatch_content_end_to_end(client, app, auth_headers, shadowwatch):
    project = client.post("/api/projects", json={"name": "ShadowWatch", "repository_url": "https://github.com/karthikmukesh19-gif/ShadowWatch"},
                          headers=auth_headers).json()
    job = analyse(client, app, auth_headers, project)
    assert job["state"] == "completed", job
    summary = job["summary"]
    assert summary["files"] == 104 and summary["dependency_files"] == 6
    assert summary["languages"] == ["JavaScript", "Python"] and summary["primary_language"] == "JavaScript"
    assert summary["package_managers"] == ["npm", "pip"] and summary["ecosystems"] == ["npm", "pypi"]
    assert summary["dependencies"] == 320 and summary["direct"] == 51 and summary["transitive"] == 269
    assert summary["unresolved_versions"] == 0 and summary["relationship_unknown"] == 0 and summary["max_depth"] == 6

    snapshot = get(client, auth_headers, project, "/snapshot").json()
    assert {f["path"]: f["status"] for f in snapshot["dependency_files"]} == {
        "package-lock.json": "PARSED", "package.json": "PARSED", "requirements.txt": "PARSED",
        "backend/requirements.txt": "PARSED", "frontend/package-lock.json": "PARSED", "frontend/package.json": "PARSED"}

    react = [d for d in get(client, auth_headers, project, "/dependencies", q="react-dom").json()["items"] if d["name"] == "react-dom"]
    assert [(d["name"], d["relationship"], d["relationship_basis"], d["constraints"]) for d in react] == [
        ("react-dom", "DIRECT", "OBSERVED", ["^19.2.7"])]
    assert react[0]["version"] and react[0]["version_basis"] == "OBSERVED" and react[0]["integrity"][0]["algorithm"] == "sha512"
    # The same version is also installed for the root package, so the root lockfile is evidence too.
    assert {e["source_file"] for e in react[0]["evidence"]} == {"frontend/package.json", "frontend/package-lock.json", "package-lock.json"}

    fastapi = get(client, auth_headers, project, "/dependencies", q="fastapi").json()["items"][0]
    assert fastapi["version"] == "0.139.2" and (fastapi["relationship"], fastapi["relationship_basis"]) == ("DIRECT", "INFERRED")
    by_basis = get(client, auth_headers, project, "/dependencies/graph").json()["stats"]["by_relationship_basis"]
    assert by_basis == {"OBSERVED": 293, "INFERRED": 27}                    # npm from lockfiles; pip from requirements files


# --- re-analysis ------------------------------------------------------------

def test_unchanged_repository_reuses_the_snapshot(client, app, auth_headers, project, github, db):
    first = analyse(client, app, auth_headers, project)
    before = len(github.requests)
    second = analyse(client, app, auth_headers, project)
    assert second["state"] == "completed" and second["reused_snapshot"] is True and second["snapshot_id"] == first["snapshot_id"]
    assert "unchanged" in second["message"] and second["summary"] == first["summary"]
    assert len(github.requests) - before == 2                               # metadata + head commit only
    assert db.repository_snapshots.count_documents({}) == 1 and db.dependencies.count_documents({}) == 8


def test_changed_repository_gets_a_new_snapshot_and_the_old_one_is_kept(client, app, auth_headers, project, repo, db):
    first = analyse(client, app, auth_headers, project)
    old_commit = repo.commit_sha
    repo.files["backend/requirements.txt"] = b"flask==3.0.3\n"
    second = analyse(client, app, auth_headers, project)
    assert second["reused_snapshot"] is False and second["snapshot_id"] != first["snapshot_id"]
    assert get(client, auth_headers, project, "/snapshot").json()["commit_sha"] == repo.commit_sha != old_commit
    ids = [d["node_id"] for d in get(client, auth_headers, project, "/dependencies", ecosystem="pypi").json()["items"]]
    assert ids == ["pypi:flask@3.0.3"]
    assert db.repository_snapshots.count_documents({}) == 2                 # history is immutable
    old = db.repository_snapshots.find_one({"commit_sha": old_commit})
    assert old["status"] == "COMPLETE" and db.dependencies.count_documents({"snapshot_id": old["_id"]}) == 8


def test_interrupted_snapshot_is_rebuilt_not_reused(client, app, auth_headers, project, db):
    analyse(client, app, auth_headers, project)
    db.repository_snapshots.update_one({}, {"$set": {"status": "COLLECTED"}})
    job = analyse(client, app, auth_headers, project)
    assert job["reused_snapshot"] is False and db.repository_snapshots.count_documents({}) == 1
    assert db.repository_snapshots.find_one({})["status"] == "COMPLETE" and db.dependencies.count_documents({}) == 8


# --- failures and limits ----------------------------------------------------

def failed(client, app, headers, project):
    job = analyse(client, app, headers, project)
    assert job["state"] == "failed" and job["finished_at"] and job["snapshot_id"] is None
    return job


def assert_nothing_stored(client, headers, project, db):
    assert db.repository_snapshots.count_documents({}) == 0 and db.dependencies.count_documents({}) == 0
    assert db.dependency_graphs.count_documents({}) == 0
    assert get(client, headers, project, "/dependencies").status_code == 404
    assert client.get(f"/api/projects/{project['id']}", headers=headers).json()["last_analysis"] is None


@pytest.mark.parametrize("fragment,status,headers,code", [
    ("/commits/", 403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1893456000"}, "RATE_LIMITED"),
    ("/git/trees/", 429, {"retry-after": "60"}, "RATE_LIMITED"),
    ("/git/blobs/", 403, {"x-ratelimit-remaining": "0"}, "RATE_LIMITED"),
    ("/commits/", 409, {}, "EMPTY_REPOSITORY"),
    ("/git/trees/", 404, {}, "NOT_FOUND"),
    ("/git/blobs/", 500, {}, "GITHUB_ERROR"),
])
def test_github_failures_fail_the_job_with_a_structured_error(client, app, auth_headers, project, github, db, fragment, status, headers, code):
    github.fail_paths[fragment] = (status, headers)
    job = failed(client, app, auth_headers, project)
    assert job["error"]["code"] == code and job["error"]["message"] == job["message"]
    if "x-ratelimit-reset" in headers:
        assert job["error"]["retry_at"].startswith("2030-01-01")
    assert_nothing_stored(client, auth_headers, project, db)
    github.fail_paths.clear()
    assert analyse(client, app, auth_headers, project)["state"] == "completed"      # recovers on the next run


def test_repository_size_limit(mongo, fake_redis, github, repo, db):
    repo.size_kb = 5000
    app = make_app(mongo, fake_redis, github, ANALYSIS_MAX_REPO_KB=4999)
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {register(client).json()['access_token']}"}
        project = client.post("/api/projects", json={"name": "Big", "repository_url": REPO_URL}, headers=headers).json()
        before = len(github.requests)
        job = failed(client, app, headers, project)
        assert job["error"]["code"] == "REPOSITORY_TOO_LARGE" and "5000 KB" in job["message"]
        assert len(github.requests) - before == 1                           # stopped before listing or reading anything
        assert_nothing_stored(client, headers, project, db)


@pytest.mark.parametrize("env,truncated", [({"ANALYSIS_MAX_FILES": 5}, False), ({}, True)])
def test_file_count_limit_and_truncated_listings(mongo, fake_redis, github, repo, db, env, truncated):
    repo.truncated = truncated
    app = make_app(mongo, fake_redis, github, **env)
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {register(client).json()['access_token']}"}
        project = client.post("/api/projects", json={"name": "Many", "repository_url": REPO_URL}, headers=headers).json()
        assert failed(client, app, headers, project)["error"]["code"] == "TOO_MANY_FILES"
        assert not any("/git/blobs/" in r.url.path for r in github.requests)
        assert_nothing_stored(client, headers, project, db)


def test_dependency_count_limit(mongo, fake_redis, github, repo, db):
    app = make_app(mongo, fake_redis, github, ANALYSIS_MAX_DEPENDENCIES=3)
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {register(client).json()['access_token']}"}
        project = client.post("/api/projects", json={"name": "Deps", "repository_url": REPO_URL}, headers=headers).json()
        assert failed(client, app, headers, project)["error"]["code"] == "TOO_MANY_DEPENDENCIES"
        assert_nothing_stored(client, headers, project, db)


def test_oversized_and_excess_dependency_files_are_skipped_and_reported(mongo, fake_redis, github, repo):
    repo.listed_sizes["web/package-lock.json"] = 50_000_000
    app = make_app(mongo, fake_redis, github, ANALYSIS_MAX_MANIFESTS=3)
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {register(client).json()['access_token']}"}
        project = client.post("/api/projects", json={"name": "Limits", "repository_url": REPO_URL}, headers=headers).json()
        assert analyse(client, app, headers, project)["state"] == "completed"
        files = {f["path"]: f for f in get(client, headers, project, "/snapshot").json()["dependency_files"]}
        assert files["web/package-lock.json"]["status"] == "SKIPPED" and "per-file limit" in files["web/package-lock.json"]["detail"]
        skipped = [f for f in files.values() if f["status"] == "SKIPPED" and "More than 3" in (f["detail"] or "")]
        assert len(skipped) == 1 and sum(1 for f in files.values() if f["status"] == "PARSED") == 3
        assert not any(github.repo.blob_id("web/package-lock.json") in r.url.path for r in github.requests)


def test_time_limit(mongo, fake_redis, github, repo, db, monkeypatch):
    app = make_app(mongo, fake_redis, github, ANALYSIS_TIMEOUT_SECONDS=5)
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {register(client).json()['access_token']}"}
        project = client.post("/api/projects", json={"name": "Slow", "repository_url": REPO_URL}, headers=headers).json()
        clock = iter(range(0, 10_000, 4))
        monkeypatch.setattr(analysis.time, "monotonic", lambda: next(clock))
        assert failed(client, app, headers, project)["error"]["code"] == "TIMEOUT"
        assert_nothing_stored(client, headers, project, db)


def test_tampered_file_content_fails_the_analysis(client, app, auth_headers, project, repo, db):
    repo.tamper.add("svc/go.mod")
    assert failed(client, app, auth_headers, project)["error"]["code"] == "INTEGRITY_MISMATCH"
    assert_nothing_stored(client, auth_headers, project, db)


def test_hostile_paths_in_the_listing_are_dropped_and_counted(client, app, auth_headers, project, repo):
    repo.extra_entries = [
        {"path": "../../etc/requirements.txt", "mode": "100644", "type": "blob", "sha": "a" * 40, "size": 10},
        {"path": "/abs/package.json", "mode": "100644", "type": "blob", "sha": "b" * 40, "size": 10},
        {"path": "link/requirements.txt", "mode": "120000", "type": "blob", "sha": "c" * 40, "size": 10},
    ]
    assert analyse(client, app, auth_headers, project)["state"] == "completed"
    snapshot = get(client, auth_headers, project, "/snapshot").json()
    assert snapshot["rejected_paths"] == 2 and snapshot["symlinks_skipped"] == 1 and snapshot["file_count"] == len(MIXED_REPO)
    assert not any(".." in f["path"] or f["path"].startswith("/") for f in snapshot["dependency_files"])
    assert get(client, auth_headers, project, "/snapshot/files", q="etc").json()["total"] == 0


def test_malformed_dependency_files_are_reported_and_do_not_stop_the_analysis(client, app, auth_headers, project, repo):
    repo.files["web/package.json"] = b"{ this is not json"
    repo.files["svc/Cargo.toml"] = b"[dependencies\n"
    repo.files["bin/package-lock.json"] = b"\x00\x01\x02binary"
    job = analyse(client, app, auth_headers, project)
    assert job["state"] == "completed"
    files = {f["path"]: f for f in get(client, auth_headers, project, "/snapshot").json()["dependency_files"]}
    assert files["web/package.json"]["status"] == "ERROR" and "JSON" in files["web/package.json"]["detail"]
    assert files["svc/Cargo.toml"]["status"] == "ERROR" and files["bin/package-lock.json"]["detail"] == "The file is binary, not text"
    assert files["backend/requirements.txt"]["status"] == "PARSED"
    ids = {d["node_id"] for d in get(client, auth_headers, project, "/dependencies").json()["items"]}
    # Without the manifest the lockfile still lists its roots, so npm packages stay classified.
    assert {"npm:a@1.2.0", "pypi:flask@3.0.0"} <= ids


def test_hostile_names_and_broken_unicode_cannot_break_storage(client, app, auth_headers, project, repo):
    repo.files["web/package.json"] = json.dumps({"dependencies": {"ok-package": "1.0.0"}}).encode()
    repo.files["web/package-lock.json"] = (
        b'{"lockfileVersion": 3, "packages": {"": {"dependencies": {"ok-package": "1.0.0"}}, '
        b'"node_modules/ok-package": {"version": "1.0.0", "resolved": "https://x.example/\\ud800broken"}}}')
    repo.files["py/Pipfile.lock"] = json.dumps({"default": {
        "x" * 5000: {"version": "==1.0"}, "has space": {"version": "==1.0"}, "fine": {"version": "==" + "9" * 500},
        "bad\u0000name": {"version": "==1.0"}, "good": {"version": "==2.0"}}}).encode()
    assert analyse(client, app, auth_headers, project)["state"] == "completed"
    items = get(client, auth_headers, project, "/dependencies", limit=500).json()["items"]
    names = {d["name"] for d in items}
    assert {"ok-package", "good"} <= names and not any(len(n) > 300 or " " in n or "\x00" in n for n in names)
    assert "fine" not in names                                              # its version was implausible
    assert any("implausible" in note for note in get(client, auth_headers, project, "/snapshot").json()["notes"])


def test_parser_crash_is_contained(client, app, auth_headers, project, monkeypatch):
    from app.analyzers import detect

    def explode(path, text):
        raise RuntimeError("secret internal detail")

    crashing = detect.FileType("go.mod", "go", "golang", "manifest", explode)
    monkeypatch.setattr(detect, "FILE_TYPES", tuple(crashing if t.pattern == "go.mod" else t for t in detect.FILE_TYPES))
    assert analyse(client, app, auth_headers, project)["state"] == "completed"
    entry = next(f for f in get(client, auth_headers, project, "/snapshot").json()["dependency_files"] if f["path"] == "svc/go.mod")
    assert entry["status"] == "ERROR" and "secret" not in json.dumps(entry)


def test_repository_without_dependency_files(client, app, auth_headers, github):
    github.repo = FakeRepository({"README.md": "# docs only\n", "notes.txt": "hello\n"})
    project = client.post("/api/projects", json={"name": "Docs", "repository_url": "https://github.com/octo/docs"}, headers=auth_headers).json()
    job = analyse(client, app, auth_headers, project)
    assert job["state"] == "completed" and job["summary"]["dependencies"] == 0 and job["summary"]["languages"] == []
    assert get(client, auth_headers, project, "/dependencies").json() | {"snapshot": None} == {
        "snapshot": None, "summary": get(client, auth_headers, project, "/dependencies/graph").json()["stats"],
        "total": 0, "skip": 0, "limit": 100, "items": []}
    graph = get(client, auth_headers, project, "/dependencies/graph").json()
    assert graph["nodes"] == [] and graph["edges"] == []
    snapshot = get(client, auth_headers, project, "/snapshot").json()
    assert snapshot["dependency_files"] == [] and snapshot["package_managers"] == [] and snapshot["languages"]["primary_language"] is None


def test_internal_errors_fail_the_job_without_leaking_details(client, app, auth_headers, project, db, monkeypatch):
    monkeypatch.setattr(analysis, "resolve", lambda _files: (_ for _ in ()).throw(RuntimeError("secret internal detail")))
    job = failed(client, app, auth_headers, project)
    assert job["error"] == {"code": "INTERNAL_ERROR", "message": "The analysis stopped because of an internal error."}
    assert "secret" not in json.dumps(job)
    assert_nothing_stored(client, auth_headers, project, db)


def test_project_deleted_while_queued(client, app, auth_headers, project, db):
    start(client, auth_headers, project)
    assert client.delete(f"/api/projects/{project['id']}", headers=auth_headers).status_code == 204
    assert db.analysis_jobs.count_documents({}) == 0 and run_worker(app) == 0


def test_deleting_a_project_removes_its_analysis_data(client, app, auth_headers, other_headers, project, db):
    other = client.post("/api/projects", json={"name": "Other", "repository_url": REPO_URL}, headers=other_headers).json()
    analyse(client, app, auth_headers, project)
    analyse(client, app, other_headers, other)
    assert client.delete(f"/api/projects/{project['id']}", headers=auth_headers).status_code == 204
    for collection in ("repository_snapshots", "dependencies", "dependency_graphs", "analysis_jobs"):
        remaining = {str(d["project_id"]) for d in db[collection].find({})}
        assert remaining == {other["id"]}, collection
    assert get(client, other_headers, other, "/dependencies").json()["total"] == 8


def test_no_trust_or_risk_or_vulnerability_figures_are_produced(client, app, auth_headers, project):
    analyse(client, app, auth_headers, project)
    text = "".join(get(client, auth_headers, project, path).text for path in ("/snapshot", "/dependencies", "/dependencies/graph", "/analysis/status")).lower()
    for term in ("trust_score", "risk_score", "vulnerab", "cve-", "severity"):
        assert term not in text


def test_every_classification_carries_an_epistemic_label(client, app, auth_headers, project):
    analyse(client, app, auth_headers, project)
    labels = {"OBSERVED", "INFERRED", "UNKNOWN"}
    for dep in get(client, auth_headers, project, "/dependencies").json()["items"]:
        assert dep["relationship_basis"] in labels and dep["version_basis"] in labels and dep["relationship_reason"]
        assert dep["evidence"] and all(e["evidence_type"] == "repository_file" and e["source_file"] for e in dep["evidence"])
        assert (dep["version"] is None) == (dep["version_status"] == "UNRESOLVED") == (dep["version_basis"] == "UNKNOWN")
    assert all(e["basis"] in labels for e in get(client, auth_headers, project, "/dependencies/graph").json()["edges"])


# --- indexes ----------------------------------------------------------------

def test_obsolete_indexes_from_phase_one_are_replaced(mongo, fake_redis, github, settings):
    db = mongo[settings.mongodb_db]
    db.dependencies.create_index([("snapshot_id", 1), ("purl", 1)], unique=True)          # the Phase 1 definition
    db.repository_snapshots.create_index([("repository_id", 1), ("commit_sha", 1)], unique=True)
    with TestClient(make_app(mongo, fake_redis, github)):
        pass
    keys = lambda name: {tuple(v["key"]) for k, v in db[name].index_information().items() if k != "_id_"}  # noqa: E731
    assert (("snapshot_id", 1), ("purl", 1)) not in keys("dependencies")
    assert (("snapshot_id", 1), ("node_id", 1)) in keys("dependencies")
    assert (("repository_id", 1), ("commit_sha", 1)) not in keys("repository_snapshots")
    assert (("email", 1),) in keys("users")                                               # unrelated indexes untouched
