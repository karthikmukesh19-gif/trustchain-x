"""Dependency intelligence end to end: API -> job -> worker -> graph metrics -> registries -> scores -> API.

GitHub, OSV and the package registries are in-memory stand-ins. GHSA-* records
are real public advisories from tests/fixtures/osv; TEST-* records are
synthetic. Registry contents (versions and dates) are test data chosen to
exercise the models, not a copy of the real registries. Nothing contacts the
network and no repository code is executed.
"""

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from bson import ObjectId
from fastapi.testclient import TestClient

from app.config.settings import load_settings
from app.main import create_app
from tests.conftest import TEST_ENV, FakeRepository, register, run_worker

REPO_URL = "https://github.com/octo/intelligence-demo"
LOCK = {"lockfileVersion": 3, "packages": {
    "": {"name": "web", "dependencies": {"express": "4.17.1", "morgan": "1.10.0", "lodash": "4.17.20"}},
    "node_modules/express": {"version": "4.17.1", "dependencies": {"body-parser": "1.19.0", "debug": "2.6.9", "qs": "6.7.0"}},
    "node_modules/morgan": {"version": "1.10.0", "dependencies": {"debug": "2.6.9"}},
    "node_modules/lodash": {"version": "4.17.20"},
    "node_modules/body-parser": {"version": "1.19.0", "dependencies": {"debug": "2.6.9", "qs": "6.7.0"}},
    "node_modules/debug": {"version": "2.6.9", "dependencies": {"ms": "2.0.0"}},
    "node_modules/qs": {"version": "6.7.0"},
    "node_modules/ms": {"version": "2.0.0"},
}}
REPO = {
    "requirements.txt": "requests==2.19.1\nPyYAML==5.1\n",
    "app/__init__.py": "",
    "app/client.py": "import requests\n\n\ndef fetch(url):\n    return requests.get(url)\n",
    "web/package.json": json.dumps({"name": "web", "dependencies": {"express": "4.17.1", "morgan": "1.10.0", "lodash": "4.17.20"}}),
    "web/package-lock.json": json.dumps(LOCK),
}
EVERYTHING = {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "99.0"}]}


def advisory(identifier, ecosystem, package, **specific):
    return {"id": identifier, "modified": "2024-01-01T00:00:00Z", "summary": f"Synthetic advisory {identifier}",
            "affected": [{"package": {"ecosystem": ecosystem, "name": package}, "ranges": [EVERYTHING], "ecosystem_specific": specific}]}


@pytest.fixture
def settings(request):
    return load_settings({**TEST_ENV, **getattr(request, "param", {})})


@pytest.fixture
def repo(github):
    github.repo = FakeRepository(REPO)
    return github.repo


def load_advisories(osv):
    osv.load("GHSA-x84v-xcm2-53pg", "GHSA-35jh-r3h4-6jhm")
    osv.add(advisory("TEST-REQ-GET", "PyPI", "requests", affected_functions=["requests.get"]),
            advisory("TEST-MS-1", "npm", "ms"),
            *(advisory(f"TEST-QS-{n}", "npm", "qs") for n in (1, 2, 3)))
    osv.report("PyPI", "requests", "2.19.1", "GHSA-x84v-xcm2-53pg", "TEST-REQ-GET")
    osv.report("npm", "lodash", "4.17.20", "GHSA-35jh-r3h4-6jhm")
    osv.report("npm", "ms", "2.0.0", "TEST-MS-1")
    osv.report("npm", "qs", "6.7.0", "TEST-QS-1", "TEST-QS-2", "TEST-QS-3")
    return osv


@pytest.fixture
def advisories(osv):
    return load_advisories(osv)


def days_ago(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")


def load_packages(registry):
    registry.add("pypi", "requests", "2.32.3", {"2.19.1": days_ago(2900), "2.20.0": days_ago(2800), "2.31.0": days_ago(900),
                                                "2.32.3": days_ago(500)})
    registry.add("pypi", "pyyaml", "5.1", {"5.1": days_ago(30), "5.0": days_ago(200)})
    registry.add("npm", "express", "4.19.2", {"4.17.1": days_ago(2000), "4.18.0": days_ago(1000), "4.19.2": days_ago(40)})
    registry.add("npm", "morgan", "1.10.0", {"1.10.0": days_ago(1500)})
    registry.add("npm", "lodash", "4.17.21", {"4.17.20": days_ago(1900), "4.17.21": days_ago(1700)})
    registry.add("npm", "body-parser", "1.20.2", {"1.19.0": days_ago(2000), "1.20.2": days_ago(600)})
    registry.add("npm", "debug", "4.3.4", {"2.6.9": days_ago(2500), "3.0.0": days_ago(2400), "4.3.4": days_ago(800)})
    registry.add("npm", "qs", "6.12.0", {"6.7.0": days_ago(2300), "6.12.0": days_ago(200)})
    # "ms" is deliberately absent: the registry answers 404 for it.
    return registry


@pytest.fixture
def packages(registry):
    return load_packages(registry)


def url(project, path=""):
    return f"/api/projects/{project['id']}{path}"


def start(client, app, headers, project, path, body=None):
    response = client.post(url(project, path), headers=headers, json=body)
    assert response.status_code == 202, response.text
    assert run_worker(app) == 1
    return client.get(url(project, "/jobs"), headers=headers).json()["items"][0]


def get(client, headers, project, path, **params):
    response = client.get(url(project, path), headers=headers, params=params)
    assert response.status_code == 200, response.text
    return response.json()


@pytest.fixture
def analysed(client, app, auth_headers, repo):
    """A project with a dependency inventory and graph, and nothing else."""
    created = client.post("/api/projects", json={"name": "Demo", "repository_url": REPO_URL}, headers=auth_headers).json()
    assert start(client, app, auth_headers, created, "/analysis/dependencies")["state"] == "completed"
    return created


@pytest.fixture
def project(client, app, auth_headers, analysed, advisories, packages):
    """A project with an inventory and a completed vulnerability check."""
    assert start(client, app, auth_headers, analysed, "/vulnerabilities/sync")["state"] == "completed"
    return analysed



def make_app(env, mongo, fake_redis, github, osv, registry):
    application = create_app(load_settings({**TEST_ENV, **env}), mongo_client=mongo, redis_client=fake_redis,
                             github_transport=httpx.MockTransport(github.handler), provider_transport=httpx.MockTransport(osv.handler),
                             registry_transport=httpx.MockTransport(registry.handler))
    for client in application.state.registries.values():
        client.sleep = lambda _seconds: None
    return application


def prepared(client, app, scan=True):
    """Register, create the project, build its inventory and (optionally) run the vulnerability check."""
    headers = {"Authorization": f"Bearer {register(client).json()['access_token']}"}
    created = client.post("/api/projects", json={"name": "Demo", "repository_url": REPO_URL}, headers=headers).json()
    assert start(client, app, headers, created, "/analysis/dependencies")["state"] == "completed"
    if scan:
        assert start(client, app, headers, created, "/vulnerabilities/sync")["state"] == "completed"
    return headers, created


def predictive(client, app, headers, project):
    return start(client, app, headers, project, "/predictive-risk/analyze")


def rows(client, headers, project, path="/predictive-risk", **params):
    return {item["normalized_name"]: item for item in get(client, headers, project, path, **params)["items"]}


def detail(client, headers, project, name, path="/predictive-risk"):
    return get(client, headers, project, f"{path}/{rows(client, headers, project, path)[name]['dependency_id']}")


def factors(row):
    return {factor["name"]: factor for factor in row["factors"]}


ANALYZE = ["/fragility/analyze", "/graph-risk/analyze", "/predictive-risk/analyze"]
READS = ["/fragility", "/fragility/summary", f"/fragility/{ObjectId()}", "/graph-risk", f"/graph-risk/{ObjectId()}", "/predictive-risk",
         "/predictive-risk/history", f"/predictive-risk/compare?base={ObjectId()}&target={ObjectId()}", "/predictive-risk/graph",
         f"/predictive-risk/{ObjectId()}"]
ENDPOINTS = [("post", path) for path in ANALYZE] + [("get", path) for path in READS]
REGISTRY_HOSTS = {"pypi.org", "registry.npmjs.org"}


# --- access control -------------------------------------------------------------------------

@pytest.mark.parametrize("method,path", ENDPOINTS)
def test_endpoints_require_authentication(client, method, path):
    assert getattr(client, method)(f"/api/projects/{ObjectId()}{path}").status_code == 401


@pytest.mark.parametrize("method,path", ENDPOINTS)
def test_another_users_project_is_not_found(client, auth_headers, other_headers, project, method, path):
    assert getattr(client, method)(url(project, path), headers=other_headers).status_code == 404


@pytest.mark.parametrize("method,path", ENDPOINTS)
@pytest.mark.parametrize("project_id", ["nope", str(ObjectId())])
def test_unknown_projects_are_404(client, auth_headers, method, path, project_id):
    assert getattr(client, method)(f"/api/projects/{project_id}{path}", headers=auth_headers).status_code == 404


def test_results_cannot_be_read_through_another_project(client, app, auth_headers, other_headers, project, db):
    predictive(client, app, auth_headers, project)
    dependency = rows(client, auth_headers, project)["requests"]["dependency_id"]
    analysis_id = get(client, auth_headers, project, "/predictive-risk")["analysis"]["id"]
    other = client.post("/api/projects", json={"name": "Mine", "repository_url": "https://github.com/octo/other"}, headers=other_headers).json()
    for owner_project, headers in ((project, other_headers), (other, other_headers)):
        for path in (f"/fragility/{dependency}", f"/graph-risk/{dependency}", f"/predictive-risk/{dependency}",
                     f"/predictive-risk/compare?base={analysis_id}&target={analysis_id}"):
            assert client.get(url(owner_project, path), headers=headers).status_code == 404
    assert get(client, other_headers, other, "/predictive-risk")["items"] == []
    assert get(client, other_headers, other, "/predictive-risk/history")["items"] == []
    assert client.get(url(other, "/predictive-risk/graph"), headers=other_headers).status_code == 404


@pytest.mark.parametrize("identifier", ["nope", "123", str(ObjectId()), "..%2Fx", "$ne", "a" * 500])
def test_unknown_or_malformed_dependency_ids_are_404(client, app, auth_headers, project, identifier):
    predictive(client, app, auth_headers, project)
    for base in ("/fragility", "/graph-risk", "/predictive-risk"):
        assert client.get(url(project, f"{base}/{identifier}"), headers=auth_headers).status_code == 404


def test_responses_carry_no_owner_or_internal_fields(client, app, auth_headers, project):
    predictive(client, app, auth_headers, project)
    name = "requests"
    blob = json.dumps([get(client, auth_headers, project, path) for path in
                       ("/fragility", "/fragility/summary", "/graph-risk", "/predictive-risk", "/predictive-risk/history", "/predictive-risk/graph")]
                      + [detail(client, auth_headers, project, name)])
    for hidden in ("owner_id", "input_digest", "password", "repository_id", TEST_ENV["JWT_SECRET"]):
        assert hidden not in blob


# --- validation -----------------------------------------------------------------------------

@pytest.mark.parametrize("path", ANALYZE)
@pytest.mark.parametrize("body", [{"url": "https://evil.example"}, {"registry_url": "http://169.254.169.254"}, {"model_version": "x"},
                                  {"weights": {"fragility": 100}}, {"score": 0}, {"snapshot_id": "abc"}])
def test_analysis_requests_take_no_parameters(client, auth_headers, project, registry, path, body):
    assert client.post(url(project, path), headers=auth_headers, json=body).status_code == 422
    assert registry.requests == []


@pytest.mark.parametrize("path,params", [
    ("/fragility", {"limit": 0}), ("/fragility", {"limit": 501}), ("/fragility", {"skip": -1}), ("/fragility", {"sort": "$where"}),
    ("/fragility", {"level": "EXTREME"}), ("/fragility", {"ecosystem": "npm;drop"}), ("/fragility", {"q": "x" * 101}),
    ("/fragility", {"relationship": "SIDEWAYS"}), ("/graph-risk", {"classification": "VULNERABLE"}), ("/graph-risk", {"limit": 9999}),
    ("/predictive-risk", {"indicator": "ZERO_DAY"}), ("/predictive-risk", {"level": "low"}), ("/predictive-risk", {"vulnerable": "maybe"}),
    ("/predictive-risk", {"sort": "score desc"}), ("/predictive-risk/history", {"kind": "trust"}), ("/predictive-risk/history", {"limit": 101}),
    ("/predictive-risk/compare", {"base": "x" * 25, "target": "y"}), ("/predictive-risk/compare", {}),
])
def test_invalid_query_parameters_are_rejected(client, app, auth_headers, project, path, params):
    predictive(client, app, auth_headers, project)
    assert client.get(url(project, path), headers=auth_headers, params=params).status_code == 422


def test_search_text_is_matched_literally(client, app, auth_headers, project):
    predictive(client, app, auth_headers, project)
    assert rows(client, auth_headers, project, q=".*") == {}
    assert rows(client, auth_headers, project, q="(") == {}
    assert set(rows(client, auth_headers, project, q="body-")) == {"body-parser"}
    assert set(rows(client, auth_headers, project, "/fragility", q="REQ")) == {"requests"}


# --- before anything has been analysed ------------------------------------------------------

@pytest.mark.parametrize("path", ANALYZE)
def test_analysis_needs_a_dependency_inventory(client, auth_headers, github, path):
    created = client.post("/api/projects", json={"name": "Demo", "repository_url": REPO_URL}, headers=auth_headers).json()
    response = client.post(url(created, path), headers=auth_headers)
    assert response.status_code == 409 and "dependency analysis first" in response.json()["detail"]


@pytest.mark.parametrize("path", ["/graph-risk/analyze", "/predictive-risk/analyze"])
def test_risk_analysis_needs_a_vulnerability_check(client, auth_headers, analysed, path):
    response = client.post(url(analysed, path), headers=auth_headers)
    assert response.status_code == 409 and "vulnerability check" in response.json()["detail"]


def test_nothing_is_reported_before_an_analysis(client, auth_headers, project):
    """No analysis means no figures at all: not zeros, not a LOW level."""
    for path in ("/fragility", "/graph-risk", "/predictive-risk"):
        body = get(client, auth_headers, project, path)
        assert body["analysis"] is None and body["items"] == [] and body["total"] == 0 and body["job"] is None
        assert body["snapshot"]["commit_sha"] and body["has_vulnerability_scan"] is True
    summary = get(client, auth_headers, project, "/fragility/summary")
    assert summary["available"] is False and summary["fragility"] is None and summary["graph"] is None and summary["metadata"] is None
    assert client.get(url(project, "/predictive-risk/graph"), headers=auth_headers).status_code == 404
    assert get(client, auth_headers, project, "/predictive-risk/history") == {"items": []}


def test_a_fragility_analysis_alone_does_not_produce_risk_results(client, app, auth_headers, project, db):
    assert start(client, app, auth_headers, project, "/fragility/analyze")["state"] == "completed"
    assert get(client, auth_headers, project, "/fragility")["total"] == 9
    assert get(client, auth_headers, project, "/graph-risk")["analysis"] is None
    assert get(client, auth_headers, project, "/predictive-risk")["analysis"] is None
    assert db.graph_risk_analysis.count_documents({}) == 0 and db.predictions.count_documents({}) == 0
    assert db.predictive_indicators.count_documents({}) == 0


# --- jobs -----------------------------------------------------------------------------------

@pytest.mark.parametrize("path,job_type,stages", [
    ("/fragility/analyze", "dependency_fragility_analysis", ["GRAPH_METRICS", "PACKAGE_METADATA", "FRAGILITY"]),
    ("/graph-risk/analyze", "graph_risk_analysis", ["GRAPH_METRICS", "RISK_PROPAGATION"]),
    ("/predictive-risk/analyze", "predictive_dependency_analysis", ["GRAPH_METRICS", "PACKAGE_METADATA", "FRAGILITY", "RISK_PROPAGATION", "PREDICTION"]),
])
def test_each_job_is_queued_then_run_by_the_worker(client, app, auth_headers, project, db, path, job_type, stages):
    response = client.post(url(project, path), headers=auth_headers)
    assert response.status_code == 202
    queued = response.json()["job"]
    assert queued["type"] == job_type and queued["state"] == "queued" and queued["stages"] == stages
    assert db.dependency_analyses.count_documents({}) == 0                       # nothing is computed in the request
    assert get(client, auth_headers, project, "/jobs")["active"]["id"] == queued["id"]
    assert run_worker(app) == 1
    job = get(client, auth_headers, project, "/jobs")["items"][0]
    assert job["id"] == queued["id"] and job["state"] == "completed" and job["stage"] == "COMPLETED" and job["error"] is None
    assert job["started_at"] and job["finished_at"] and job["summary"]["analysis_id"] == job["analysis_id"]
    assert get(client, auth_headers, project, "/jobs")["active"] is None
    record = db.dependency_analyses.find_one({"_id": ObjectId(job["analysis_id"])})
    assert record["state"] == "COMPLETE" and record["job_id"] == ObjectId(job["id"]) and record["completed_at"]


def test_graph_risk_job_contacts_no_registry(client, app, auth_headers, project, registry, db):
    assert start(client, app, auth_headers, project, "/graph-risk/analyze")["state"] == "completed"
    assert registry.requests == [] and db.package_metadata.count_documents({}) == 0
    assert db.dependency_fragility.count_documents({}) == 0 and db.graph_risk_analysis.count_documents({}) == 9


def test_one_job_at_a_time_per_project(client, app, auth_headers, project):
    assert client.post(url(project, "/predictive-risk/analyze"), headers=auth_headers).status_code == 202
    for path in (*ANALYZE, "/vulnerabilities/sync", "/analysis/dependencies", "/code-reachability/analyze"):
        response = client.post(url(project, path), headers=auth_headers)
        assert response.status_code == 409 and "already queued or running" in response.json()["detail"]
    assert run_worker(app) == 1
    assert client.post(url(project, "/fragility/analyze"), headers=auth_headers).status_code == 202


def test_job_requests_are_rate_limited(mongo, fake_redis, github, osv, registry, repo):
    app = make_app({"JOB_RATE_LIMIT": "3"}, mongo, fake_redis, github, osv, registry)
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {register(client).json()['access_token']}"}
        created = client.post("/api/projects", json={"name": "Demo", "repository_url": REPO_URL}, headers=headers).json()
        codes = [client.post(url(created, path), headers=headers).status_code for path in ANALYZE + ANALYZE]
        assert codes == [409, 409, 409, 429, 429, 429]
        assert int(client.post(url(created, ANALYZE[0]), headers=headers).headers["retry-after"]) >= 1


def test_requests_and_outcomes_are_audited(client, app, auth_headers, project, db):
    predictive(client, app, auth_headers, project)
    entries = [(e["action"], e["outcome"]) for e in db.audit_logs.find({"action": {"$regex": "^job.predictive_dependency_analysis"}})]
    assert ("job.predictive_dependency_analysis.request", "success") in entries
    assert ("job.predictive_dependency_analysis.finish", "success") in entries


def test_a_crash_inside_a_job_is_failed_and_leaks_nothing(client, app, auth_headers, project, db, monkeypatch):
    from app.services import intelligence

    def boom(*_a, **_k):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(intelligence.risk_propagation, "propagate", boom)
    job = predictive(client, app, auth_headers, project)
    assert job["state"] == "failed" and job["error"]["code"] == "INTERNAL_ERROR" and "secret internal detail" not in json.dumps(job)
    assert get(client, auth_headers, project, "/jobs")["active"] is None
    # A run that did not finish leaves no results behind.
    assert get(client, auth_headers, project, "/predictive-risk")["analysis"] is None
    assert db.dependency_fragility.count_documents({}) == 0 and db.dependency_analyses.count_documents({}) == 0


def test_project_deleted_while_a_job_is_queued(client, app, auth_headers, project, db):
    client.post(url(project, "/predictive-risk/analyze"), headers=auth_headers)
    job_id = db.analysis_jobs.find_one({"type": "predictive_dependency_analysis"})["_id"]
    db.projects.delete_many({})
    assert run_worker(app) == 1
    job = db.analysis_jobs.find_one({"_id": job_id})
    assert job["state"] == "failed" and job["error"]["code"] == "PROJECT_NOT_FOUND"


def test_the_worker_rechecks_the_vulnerability_scan(client, app, auth_headers, project, db):
    client.post(url(project, "/predictive-risk/analyze"), headers=auth_headers)
    db.projects.update_one({}, {"$set": {"latest_vulnerability_scan": None}})
    assert run_worker(app) == 1
    job = get(client, auth_headers, project, "/jobs")["items"][0]
    assert job["state"] == "failed" and job["error"]["code"] == "NOT_SCANNED"
    assert db.dependency_analyses.count_documents({}) == 0


def test_time_limit(client, app, auth_headers, project, db, monkeypatch):
    from app.services import jobs

    clock = iter(range(0, 100_000, 400))
    monkeypatch.setattr(jobs.time, "monotonic", lambda: next(clock))
    job = predictive(client, app, auth_headers, project)
    assert job["state"] == "failed" and job["error"]["code"] == "TIMEOUT"
    assert db.dependency_analyses.count_documents({}) == 0 and db.predictions.count_documents({}) == 0


@pytest.mark.parametrize("settings", [{"INTELLIGENCE_MAX_EDGES": "10"}], indirect=True)
def test_a_graph_over_the_edge_limit_is_refused(client, app, auth_headers, project, db, registry):
    job = predictive(client, app, auth_headers, project)
    assert job["state"] == "failed" and job["error"]["code"] == "GRAPH_TOO_LARGE" and "limit is 10" in job["error"]["message"]
    assert registry.requests == [] and db.dependency_analyses.count_documents({}) == 0


def test_a_graph_over_the_node_limit_is_refused(client, app, auth_headers, project, db, monkeypatch):
    from app.services import intelligence

    monkeypatch.setattr(intelligence, "GraphLimits", lambda _nodes, edges: intelligence.analyse_structure.__globals__["GraphLimits"](5, edges))
    job = start(client, app, auth_headers, project, "/fragility/analyze")
    assert job["state"] == "failed" and job["error"]["code"] == "GRAPH_TOO_LARGE" and "9 packages" in job["error"]["message"]


# --- what is stored --------------------------------------------------------------------------

def test_every_stored_row_is_scoped_and_versioned(client, app, auth_headers, project, db):
    job = predictive(client, app, auth_headers, project)
    analysis_id = ObjectId(job["analysis_id"])
    stored_project = db.projects.find_one({})
    expected = {"dependency_fragility": ("fragility-v1", 9), "dependency_health": ("fragility-v1", 9), "graph_risk_analysis": ("graph-risk-v1", 9),
                "predictions": ("dependency-risk-v1", 9), "predictive_indicators": ("indicators-v1", None)}
    for collection, (model, count) in expected.items():
        documents = list(db[collection].find({}))
        assert documents and (count is None or len(documents) == count), collection
        for document in documents:
            assert document["analysis_id"] == analysis_id and document["project_id"] == stored_project["_id"]
            assert document["repository_id"] == stored_project["repository_id"]
            assert document["snapshot_id"] == stored_project["latest_snapshot_id"]
            assert document["model_version"] == model and isinstance(document["created_at"], datetime)
            assert db.dependencies.find_one({"_id": document["dependency_id"], "node_id": document["node_id"]}) is not None
    record = db.dependency_analyses.find_one({"_id": analysis_id})
    assert record["model_versions"] == {"fragility": "fragility-v1", "graph_risk": "graph-risk-v1", "predictive": "dependency-risk-v1",
                                        "indicators": "indicators-v1"}
    assert record["layers"] == ["fragility", "health", "graph_risk", "indicators", "predictive"] and record["kind"] == "predictive"
    assert record["commit_sha"] == db.repository_snapshots.find_one({})["commit_sha"]


def test_required_output_fields(client, app, auth_headers, project):
    predictive(client, app, auth_headers, project)
    for item in get(client, auth_headers, project, "/fragility")["items"]:
        for field in ("dependency_id", "package_name", "ecosystem", "version", "fragility_score", "confidence", "factors",
                      "observed_metrics", "inferred_metrics", "model_version"):
            assert field in item, field
        assert 0 <= item["fragility_score"] <= 100 and 0 <= item["confidence"] <= 1
    body = detail(client, auth_headers, project, "requests")
    assert set(body) == {"prediction", "indicators", "fragility", "health", "graph_risk"}
    prediction = body["prediction"]
    assert prediction["model_version"] == "dependency-risk-v1" and set(prediction["evidence"]) == {"OBSERVED", "DERIVED", "PREDICTED", "RECOMMENDED"}
    assert "Not a probability" in prediction["meaning"] and 0 <= prediction["score"] <= 100
    for indicator in body["indicators"]:
        assert indicator["type"] and indicator["severity"] in ("LOW", "MEDIUM", "HIGH") and 0 < indicator["confidence"] <= 1
        assert indicator["evidence"] and all(isinstance(line, str) and line for line in indicator["evidence"])


def test_scores_are_the_sum_of_their_visible_factors(client, app, auth_headers, project):
    predictive(client, app, auth_headers, project)
    for name in rows(client, auth_headers, project):
        body = detail(client, auth_headers, project, name)
        fragility, prediction = body["fragility"], body["prediction"]
        assert sum(f["weight"] for f in fragility["factors"]) == 100 and sum(f["weight"] for f in prediction["factors"]) == 100
        assert fragility["fragility_score"] == pytest.approx(sum(f["contribution"] for f in fragility["factors"]), abs=0.11)
        assert prediction["score"] == pytest.approx(sum(f["contribution"] for f in prediction["factors"]), abs=0.11)
        for factor in fragility["factors"] + prediction["factors"]:
            if factor["status"] == "UNKNOWN":
                assert factor["value"] is None and factor["contribution"] == 0
            else:
                assert factor["contribution"] == pytest.approx(factor["weight"] * factor["value"], abs=0.06)
        known = sum(f["weight"] for f in fragility["factors"] if f["status"] != "UNKNOWN")
        assert fragility["confidence"] <= known / 100 + 0.001
        risk = body["graph_risk"]
        assert risk["graph_risk"] == max(risk["own_risk"], risk["propagated_risk"])


# --- fragility and health --------------------------------------------------------------------

def test_graph_metrics_match_the_lockfile(client, app, auth_headers, project):
    start(client, app, auth_headers, project, "/fragility/analyze")
    observed = {name: row["observed_metrics"] for name, row in rows(client, auth_headers, project, "/fragility").items()}
    expected = {  # name: (depth, fan_in, fan_out, dependents, introduced)
        "express": (1, 0, 3, 0, 4), "morgan": (1, 0, 1, 0, 2), "lodash": (1, 0, 0, 0, 0), "requests": (1, 0, 0, 0, 0), "pyyaml": (1, 0, 0, 0, 0),
        "body-parser": (2, 1, 2, 1, 3), "debug": (2, 3, 1, 3, 1), "qs": (2, 2, 0, 2, 0), "ms": (3, 1, 0, 4, 0)}
    assert {name: (m["depth"], m["fan_in"], m["fan_out"], m["dependents"], m["introduced"]) for name, m in observed.items()} == expected
    assert observed["ms"]["reached_by_direct"] == 2 and observed["ms"]["direct"] is False and observed["express"]["direct"] is True
    summary = get(client, auth_headers, project, "/fragility/summary")
    assert summary["available"] is True and summary["graph"]["packages"] == 9 and summary["graph"]["relationships"] == 7
    assert summary["graph"]["direct_dependencies"] == 5 and summary["graph"]["max_depth"] == 3
    assert summary["fragility"]["dependencies"] == 9 and sum(summary["fragility"]["by_level"].values()) == 9
    assert "not vulnerability severity" in summary["meaning"]


def test_the_most_depended_on_package_is_the_most_fragile(client, app, auth_headers, project):
    start(client, app, auth_headers, project, "/fragility/analyze")
    items = get(client, auth_headers, project, "/fragility")["items"]
    assert items[0]["normalized_name"] == "debug"
    assert [i["fragility_score"] for i in items] == sorted((i["fragility_score"] for i in items), reverse=True)
    by_name = {i["normalized_name"]: i for i in items}
    assert by_name["pyyaml"]["fragility_score"] == 0.0 and by_name["pyyaml"]["confidence"] == 1.0   # current, direct, nothing depends on it


def test_version_position_uses_registry_data_and_ecosystem_rules(client, app, auth_headers, project):
    predictive(client, app, auth_headers, project)
    health = detail(client, auth_headers, project, "requests")["health"]
    version = health["version"]
    assert version["comparison_status"] == "COMPARED" and version["position"] == "BEHIND" and version["comparator"] == "pep440"
    assert (version["major_distance"], version["minor_distance"], version["releases_behind"]) == (0, 13, 3)
    assert version["installed_age_days"] == 2900 and version["latest_age_days"] == 500 and version["lag_days"] == 2400
    assert health["latest_release"] == "2.32.3" and health["installed_version"] == "2.19.1"
    assert health["metadata_source"] == {"registry": "pypi", "status": "COLLECTED", "detail": "FULL",
                                         "fetched_at": health["metadata_source"]["fetched_at"], "url": "https://pypi.org/pypi/requests/json", "stale": False}
    assert health["known_vulnerability_count"] == 2 and health["metadata_confidence"] == "HIGH"
    current = detail(client, auth_headers, project, "pyyaml")["health"]["version"]
    assert current["position"] == "UP_TO_DATE" and current["releases_behind"] == 0 and current["lag_days"] == 0
    major = detail(client, auth_headers, project, "debug")["health"]["version"]
    assert major["major_distance"] == 2 and major["comparator"] == "semver" and major["position"] == "BEHIND"


def test_transitive_npm_packages_have_versions_but_no_invented_dates(client, app, auth_headers, project, registry):
    predictive(client, app, auth_headers, project)
    accepts = {r.url.raw_path.decode(): r.headers["accept"] for r in registry.calls("registry.npmjs.org")}
    assert accepts["/express"] == "application/json" and "vnd.npm.install-v1" in accepts["/debug"]
    body = detail(client, auth_headers, project, "debug")
    health = body["health"]
    assert health["latest_release"] == "4.3.4" and health["version"]["comparison_status"] == "COMPARED"
    for field in ("latest_release_at", "installed_release_at", "release_age_days", "latest_release_age_days", "release_frequency"):
        assert health[field] is None, field
    assert health["metadata_source"]["detail"] == "COMPACT" and health["metadata_confidence"] != "HIGH"
    unknown = {entry["field"] for entry in health["unknown"]}
    assert {"latest_release_at", "release_age_days"} <= unknown
    staleness = factors(body["fragility"])["release_staleness"]
    assert staleness["status"] == "UNKNOWN" and staleness["value"] is None and staleness["contribution"] == 0
    assert "release_staleness" in body["fragility"]["unknown_factors"] and body["fragility"]["confidence"] < 1


def test_a_package_the_registry_does_not_know_is_unknown_not_guessed(client, app, auth_headers, project):
    job = predictive(client, app, auth_headers, project)
    assert job["state"] == "completed" and job["summary"]["metadata"]["not_found"] == 1
    body = detail(client, auth_headers, project, "ms")
    version = body["health"]["version"]
    assert version["comparison_status"] == "UNKNOWN" and version["position"] is None and version["latest_version"] is None
    assert version["metadata_status"] == "NOT_FOUND" and version["reason"]
    assert body["health"]["latest_release"] is None and body["health"]["metadata_confidence"] == "NONE"
    for name in ("version_lag", "release_staleness"):
        factor = factors(body["fragility"])[name]
        assert factor["status"] == "UNKNOWN" and factor["value"] is None and factor["contribution"] == 0
    assert body["fragility"]["confidence"] == pytest.approx(0.7, abs=0.01)
    types = {i["type"]: i for i in body["indicators"]}
    assert "INSUFFICIENT_METADATA" in types and "OUTDATED_DEPENDENCY" not in types
    assert any("NOT_FOUND" in line or "no such package" in line.lower() or "not found" in line.lower() for line in types["INSUFFICIENT_METADATA"]["evidence"])
    assert factors(body["prediction"])["version_indicators"]["status"] == "UNKNOWN" and body["prediction"]["confidence"] < 1


@pytest.mark.parametrize("settings", [{"PACKAGE_METADATA_PROVIDERS": ""}], indirect=True)
def test_with_registries_disabled_version_facts_are_unknown_and_the_rest_is_analysed(client, app, auth_headers, project, registry, db):
    job = predictive(client, app, auth_headers, project)
    assert job["state"] == "completed" and registry.requests == [] and db.package_metadata.count_documents({}) == 0
    assert job["summary"]["metadata"]["unsupported_ecosystem"] == 9 and job["summary"]["metadata"]["providers"] == []
    assert job["summary"]["fragility"]["version_comparison"] == {"UNKNOWN": 9}
    for name, row in rows(client, auth_headers, project).items():
        assert "INSUFFICIENT_METADATA" in row["indicator_types"] and "OUTDATED_DEPENDENCY" not in row["indicator_types"], name
    body = detail(client, auth_headers, project, "debug")
    assert body["health"]["latest_release"] is None and body["health"]["version"]["metadata_status"] is None
    assert body["fragility"]["fragility_score"] > 0 and factors(body["fragility"])["downstream_impact"]["status"] == "KNOWN"
    assert rows(client, auth_headers, project)["requests"]["vulnerability_count"] == 2


def test_ecosystems_without_a_registry_client_are_unknown(client, app, auth_headers, project, db, registry):
    db.dependencies.update_one({"normalized_name": "lodash"}, {"$set": {"ecosystem": "cargo"}})
    predictive(client, app, auth_headers, project)
    assert "/lodash" not in {r.url.raw_path.decode() for r in registry.requests}
    health = detail(client, auth_headers, project, "lodash")["health"]
    assert health["version"]["comparison_status"] == "UNKNOWN" and health["latest_release"] is None and health["metadata_source"]["registry"] is None


def test_a_version_that_cannot_be_ordered_safely_is_unsupported(client, app, auth_headers, project, registry):
    registry.add("npm", "qs", "not-a-version", {"6.7.0": days_ago(2300), "not-a-version": days_ago(10)})
    predictive(client, app, auth_headers, project)
    body = detail(client, auth_headers, project, "qs")
    version = body["health"]["version"]
    assert version["comparison_status"] == "UNSUPPORTED" and version["position"] is None and version["major_distance"] is None
    assert version["latest_version"] == "not-a-version"                                   # what the registry said is still shown
    assert factors(body["fragility"])["version_lag"]["status"] == "UNKNOWN"
    assert "OUTDATED_DEPENDENCY" not in {i["type"] for i in body["indicators"]}


def test_fragility_without_a_vulnerability_check_says_the_count_is_unknown(client, app, auth_headers, analysed, packages):
    job = start(client, app, auth_headers, analysed, "/fragility/analyze")
    assert job["state"] == "completed" and job["summary"]["vulnerability_scan"] is False
    body = detail(client, auth_headers, analysed, "requests", "/fragility")
    assert body["health"]["known_vulnerability_count"] is None
    assert {"field": "known_vulnerability_count", "status": "UNKNOWN",
            "reason": "No vulnerability check has been run for this snapshot."} in body["health"]["unknown"]
    assert get(client, auth_headers, analysed, "/fragility")["has_vulnerability_scan"] is False


# --- registry failures -----------------------------------------------------------------------

def test_a_registry_error_makes_the_job_partial_and_keeps_the_results(client, app, auth_headers, project, registry, db):
    registry.fail["/express"] = 503
    job = predictive(client, app, auth_headers, project)
    assert job["state"] == "partial" and job["stage"] == "COMPLETED" and job["finished_at"]
    assert job["error"]["code"] == "METADATA_INCOMPLETE" and "1 of 9 package(s)" in job["error"]["message"]
    assert "unknown, not estimated" in job["error"]["message"]
    assert job["summary"]["metadata"]["errors"] == 1 and job["summary"]["metadata"]["error_codes"] == {"HTTP_ERROR": 1}
    assert get(client, auth_headers, project, "/jobs")["active"] is None
    assert get(client, auth_headers, project, "/predictive-risk")["total"] == 9
    express = detail(client, auth_headers, project, "express")
    assert express["health"]["version"]["comparison_status"] == "UNKNOWN" and express["health"]["version"]["metadata_status"] == "ERROR"
    assert express["health"]["latest_release"] is None and "INSUFFICIENT_METADATA" in {i["type"] for i in express["indicators"]}
    assert detail(client, auth_headers, project, "requests")["health"]["latest_release"] == "2.32.3"
    assert db.package_metadata.find_one({"normalized_name": "express"}) is None            # a failure is not cached as an answer
    entry = db.audit_logs.find_one({"action": "job.predictive_dependency_analysis.finish"})
    assert entry["outcome"] == "partial"


def test_recovery_after_a_registry_error(client, app, auth_headers, project, registry):
    registry.fail["/express"] = 503
    first = predictive(client, app, auth_headers, project)
    registry.fail.clear()
    registry.requests.clear()
    second = predictive(client, app, auth_headers, project)
    assert second["state"] == "completed" and second["analysis_id"] != first["analysis_id"]
    assert [r.url.raw_path.decode() for r in registry.requests] == ["/express"]            # everything else came from the cache
    assert detail(client, auth_headers, project, "express")["health"]["latest_release"] == "4.19.2"


@pytest.mark.parametrize("error", [httpx.ConnectError("down"), httpx.ReadTimeout("slow"), 503, 500, 429, 403])
def test_an_unreachable_registry_is_not_asked_about_every_package(client, app, auth_headers, project, registry, error):
    if isinstance(error, int):
        registry.fail = {"/": error}                 # the registry answers, but only with an error status
    else:
        registry.error = error
    job = predictive(client, app, auth_headers, project)
    assert job["state"] == "partial" and job["error"]["code"] == "METADATA_INCOMPLETE"
    stats = job["summary"]["metadata"]
    assert stats["errors"] + stats["skipped_after_failures"] == 9 and stats["skipped_after_failures"] >= 2
    attempts = 1 if error == 403 else 2                                                  # a refusal is not retried
    assert len(registry.calls("registry.npmjs.org")) == 5 * attempts                      # five packages, then it stops asking
    assert job["summary"]["fragility"]["version_comparison"] == {"UNKNOWN": 9}
    assert rows(client, auth_headers, project)["requests"]["vulnerability_count"] == 2     # the rest of the analysis is intact
    assert detail(client, auth_headers, project, "ms")["health"]["version"]["metadata_status"] == "ERROR"


@pytest.mark.parametrize("settings", [{"PACKAGE_METADATA_MAX_PACKAGES": "5"}], indirect=True)
def test_the_lookup_limit_covers_direct_dependencies_first(client, app, auth_headers, project, registry):
    job = predictive(client, app, auth_headers, project)
    assert job["state"] == "partial" and job["summary"]["metadata"]["skipped_by_limit"] == 4 and len(registry.requests) == 5
    looked_up = {r.url.raw_path.decode().rsplit("/", 2)[-2] if r.url.host == "pypi.org" else r.url.raw_path.decode().lstrip("/")
                 for r in registry.requests}
    assert looked_up == {"requests", "pyyaml", "express", "morgan", "lodash"}
    assert detail(client, auth_headers, project, "qs")["health"]["version"]["comparison_status"] == "UNKNOWN"


def test_every_registry_request_goes_to_a_configured_host_and_carries_no_credentials(client, app, auth_headers, project, registry):
    predictive(client, app, auth_headers, project)
    assert len(registry.requests) == 9 and {r.url.host for r in registry.requests} <= REGISTRY_HOSTS
    for request in registry.requests:
        assert request.method == "GET" and request.url.scheme == "https" and "authorization" not in request.headers
        assert "cookie" not in request.headers and request.content == b""


def test_a_hostile_package_name_is_never_sent_to_a_registry(client, app, auth_headers, project, registry, db):
    db.dependencies.update_one({"normalized_name": "qs"}, {"$set": {"name": "../../-/user/token"}})         # npm is asked by its exact name
    db.dependencies.update_one({"normalized_name": "pyyaml"}, {"$set": {"normalized_name": "x/../../simple?redirect=http://evil.example"}})
    job = predictive(client, app, auth_headers, project)
    assert job["state"] == "completed" and job["summary"]["metadata"]["invalid_name"] == 2
    paths = [r.url.raw_path.decode() for r in registry.requests]
    assert len(paths) == 7 and not any(".." in path or "evil" in path or "token" in path for path in paths)


# --- the metadata cache ------------------------------------------------------------------------

def test_registry_answers_are_cached_and_reused(client, app, auth_headers, project, registry, db):
    first = predictive(client, app, auth_headers, project)
    assert first["summary"]["metadata"]["fetched"] == 9 and first["summary"]["metadata"]["from_cache"] == 0
    assert db.package_metadata.count_documents({}) == 9
    cached = db.package_metadata.find_one({"ecosystem": "npm", "normalized_name": "ms"})
    assert cached["status"] == "NOT_FOUND"                                                # "no such package" is an answer too
    registry.requests.clear()
    second = start(client, app, auth_headers, project, "/fragility/analyze")
    assert registry.requests == [] and second["summary"]["metadata"]["from_cache"] == 9 and second["summary"]["metadata"]["fetched"] == 0
    assert second["summary"]["metadata"]["not_found"] == 1          # counted from the answer, whether cached or fresh


@pytest.mark.parametrize("settings", [{"PACKAGE_METADATA_TTL_HOURS": "0"}], indirect=True)
def test_expired_answers_are_fetched_again_and_a_stale_one_is_marked(client, app, auth_headers, project, registry, db):
    predictive(client, app, auth_headers, project)
    registry.requests.clear()
    registry.fail["/pypi/requests/"] = 500
    job = start(client, app, auth_headers, project, "/fragility/analyze")
    assert len(registry.requests) == 10 and job["state"] == "partial"
    health = detail(client, auth_headers, project, "requests", "/fragility")["health"]
    # The previous answer is used, and shown as what it is.
    assert health["latest_release"] == "2.32.3" and health["metadata_source"]["stale"] is True


def test_a_compact_answer_is_upgraded_when_dates_are_needed(client, app, auth_headers, project, registry, db):
    predictive(client, app, auth_headers, project)
    assert db.package_metadata.find_one({"normalized_name": "debug"})["detail"] == "COMPACT"
    db.dependencies.update_one({"normalized_name": "debug"}, {"$set": {"relationship": "DIRECT"}})
    registry.requests.clear()
    start(client, app, auth_headers, project, "/fragility/analyze")
    assert [(r.url.raw_path.decode(), r.headers["accept"]) for r in registry.requests] == [("/debug", "application/json")]
    assert db.package_metadata.find_one({"normalized_name": "debug"})["detail"] == "FULL"


# --- graph risk ------------------------------------------------------------------------------

def test_exposure_classification_follows_the_dependency_edges(client, app, auth_headers, project):
    start(client, app, auth_headers, project, "/graph-risk/analyze")
    body = get(client, auth_headers, project, "/graph-risk")
    classes = {item["normalized_name"]: item["classification"] for item in body["items"]}
    assert classes == {
        "requests": "DIRECT_VULNERABILITY", "lodash": "DIRECT_VULNERABILITY", "ms": "DIRECT_VULNERABILITY", "qs": "DIRECT_VULNERABILITY",
        "debug": "DEPENDENCY_PROPAGATION",         # requires ms directly
        "express": "DEPENDENCY_PROPAGATION",       # requires qs directly
        "body-parser": "DEPENDENCY_PROPAGATION",   # requires qs directly
        "morgan": "INDIRECT_EXPOSURE",             # reaches ms only through debug
        "pyyaml": "NO_OBSERVED_PROPAGATION"}
    assert body["analysis"]["summary"]["graph_risk"]["by_classification"] == {
        "DIRECT_VULNERABILITY": 4, "DEPENDENCY_PROPAGATION": 3, "INDIRECT_EXPOSURE": 1, "NO_OBSERVED_PROPAGATION": 1}
    assert body["classifications"] == ["DIRECT_VULNERABILITY", "DEPENDENCY_PROPAGATION", "INDIRECT_EXPOSURE", "NO_OBSERVED_PROPAGATION"]


def test_packages_that_only_lead_to_a_vulnerable_one_are_not_called_vulnerable(client, app, auth_headers, project):
    start(client, app, auth_headers, project, "/graph-risk/analyze")
    items = rows(client, auth_headers, project, "/graph-risk")
    for name in ("express", "body-parser", "debug", "morgan"):
        item = items[name]
        assert item["vulnerability_count"] == 0 and item["own_risk"] == 0 and item["severity"] is None, name
        assert item["components"]["vulnerability_signal"] == 0 and item["propagated_risk"] > 0 and item["exposure_sources"]
    # Risk does not flow from a package to what it depends on.
    assert items["pyyaml"]["graph_risk"] == 0 and items["pyyaml"]["exposure_sources"] == []
    assert items["ms"]["exposure_sources"] == [] and items["ms"]["exposes"] == 4 and items["qs"]["exposes"] == 2


def test_propagated_risk_halves_with_each_step(client, app, auth_headers, project):
    start(client, app, auth_headers, project, "/graph-risk/analyze")
    items = rows(client, auth_headers, project, "/graph-risk")
    ms, qs = items["ms"]["own_risk"], items["qs"]["own_risk"]
    assert items["debug"]["propagated_risk"] == pytest.approx(ms * 0.5, abs=0.06)
    assert items["morgan"]["propagated_risk"] == pytest.approx(ms * 0.25, abs=0.06)
    assert items["express"]["propagated_risk"] == pytest.approx(max(qs * 0.5, ms * 0.25), abs=0.06)
    assert items["morgan"]["exposure_sources"] == [{"node_id": "npm:ms@2.0.0", "distance": 2, "source_risk": ms,
                                                    "influence": items["morgan"]["propagated_risk"]}]
    components = items["ms"]["components"]
    assert ms == pytest.approx(components["vulnerability_signal"] * components["reachability_signal"] * components["centrality_signal"]
                               * components["downstream_impact"] * components["confidence"], abs=0.06)
    assert components["vulnerability_signal"] == 50 and items["ms"]["severity"] == "UNKNOWN"   # the source publishes no severity


def test_paths_from_the_project_to_each_vulnerable_package(client, app, auth_headers, project):
    job = start(client, app, auth_headers, project, "/graph-risk/analyze")
    risk = job["summary"]["graph_risk"]
    paths = {entry["node_id"]: entry["path"] for entry in risk["paths"]}
    assert paths["pypi:requests@2.19.1"] == ["root", "pypi:requests@2.19.1"]
    assert paths["npm:qs@6.7.0"] == ["root", "npm:express@4.17.1", "npm:qs@6.7.0"]
    assert paths["npm:ms@2.0.0"][0] == "root" and paths["npm:ms@2.0.0"][-2:] == ["npm:debug@2.6.9", "npm:ms@2.0.0"] and len(paths["npm:ms@2.0.0"]) == 4
    assert risk["project"] == {"classification": "DEPENDENCY_PROPAGATION", "vulnerable_packages": 4, "reachable_from_project": 4,
                               "highest_graph_risk": max(e["own_risk"] for e in risk["paths"])}
    assert risk["parameters"]["decay"] == 0.5 and job["summary"]["kind"] == "graph_risk"


def test_reachability_changes_the_weight_but_never_removes_a_vulnerability(client, app, auth_headers, project):
    start(client, app, auth_headers, project, "/graph-risk/analyze")
    before = rows(client, auth_headers, project, "/graph-risk")["requests"]
    assert before["reachability_state"] == "NOT_ANALYSED" and before["components"]["reachability_signal"] == 0.7
    assert start(client, app, auth_headers, project, "/code-reachability/analyze")["state"] == "completed"
    start(client, app, auth_headers, project, "/graph-risk/analyze")
    after = rows(client, auth_headers, project, "/graph-risk")
    assert after["requests"]["reachability_state"] == "REACHABLE" and after["requests"]["components"]["reachability_signal"] == 1.0
    assert after["requests"]["own_risk"] > before["own_risk"]
    # npm is not analysed for reachability: that is "unsupported", and it does not lower the package to safe.
    assert after["lodash"]["reachability_state"] == "UNSUPPORTED" and after["lodash"]["components"]["reachability_signal"] == 0.7
    assert after["lodash"]["classification"] == "DIRECT_VULNERABILITY" and after["lodash"]["own_risk"] > 0


def test_a_project_with_no_matches_has_no_observed_propagation(client, app, auth_headers, analysed, osv, packages):
    assert start(client, app, auth_headers, analysed, "/vulnerabilities/sync")["state"] == "completed"
    job = predictive(client, app, auth_headers, analysed)
    assert job["summary"]["graph_risk"]["by_classification"]["NO_OBSERVED_PROPAGATION"] == 9
    assert job["summary"]["graph_risk"]["project"]["classification"] == "NO_OBSERVED_PROPAGATION" and job["summary"]["graph_risk"]["paths"] == []
    for name, row in rows(client, auth_headers, analysed).items():
        assert row["graph_risk"] == 0 and row["vulnerability_count"] == 0 and row["max_severity"] is None, name
        assert not {"REACHABLE_VULNERABLE_DEPENDENCY", "VULNERABILITY_CLUSTER"} & set(row["indicator_types"])
    exposure = factors(detail(client, auth_headers, analysed, "debug")["prediction"])["vulnerability_exposure"]
    assert exposure["status"] == "KNOWN" and exposure["value"] == 0


def test_graph_risk_filters(client, app, auth_headers, project):
    start(client, app, auth_headers, project, "/graph-risk/analyze")
    assert set(rows(client, auth_headers, project, "/graph-risk", classification="INDIRECT_EXPOSURE")) == {"morgan"}
    assert set(rows(client, auth_headers, project, "/graph-risk", ecosystem="pypi")) == {"requests", "pyyaml"}
    page = get(client, auth_headers, project, "/graph-risk", limit=2, skip=1)
    assert page["total"] == 9 and len(page["items"]) == 2
    everything = get(client, auth_headers, project, "/graph-risk")["items"]
    assert [i["graph_risk"] for i in everything] == sorted((i["graph_risk"] for i in everything), reverse=True)
    assert page["items"] == everything[1:3]
    one = get(client, auth_headers, project, f"/graph-risk/{everything[0]['dependency_id']}")
    assert one["node_id"] == everything[0]["node_id"] and one["model_version"] == "graph-risk-v1"


# --- indicators and predictive dependency risk -------------------------------------------------

def test_indicators_follow_from_the_evidence(client, app, auth_headers, project):
    assert start(client, app, auth_headers, project, "/code-reachability/analyze")["state"] == "completed"
    job = predictive(client, app, auth_headers, project)
    items = rows(client, auth_headers, project)
    assert set(items["requests"]["indicator_types"]) == {"REACHABLE_VULNERABLE_DEPENDENCY", "OUTDATED_DEPENDENCY"}
    assert items["qs"]["indicator_types"] == ["VULNERABILITY_CLUSTER"] and items["ms"]["indicator_types"] == ["INSUFFICIENT_METADATA"]
    assert items["pyyaml"]["indicator_types"] == [] and items["lodash"]["indicator_types"] == []
    # lodash is vulnerable, but nothing shows it is reached: no reachability indicator is produced for it.
    assert items["lodash"]["vulnerability_count"] == 1 and items["lodash"]["reachability_state"] == "UNSUPPORTED"
    assert job["summary"]["predictive"]["indicators"] == {"INSUFFICIENT_METADATA": 1, "OUTDATED_DEPENDENCY": 3,
                                                           "REACHABLE_VULNERABLE_DEPENDENCY": 1, "VULNERABILITY_CLUSTER": 1}
    reached = {i["type"]: i for i in detail(client, auth_headers, project, "requests")["indicators"]}["REACHABLE_VULNERABLE_DEPENDENCY"]
    assert reached["basis"] == "OBSERVED" and "TEST-REQ-GET" in reached["evidence"][0] and "app/client.py:5" in reached["evidence"][1]
    assert "not of exploitability" in reached["evidence"][2]
    cluster = detail(client, auth_headers, project, "qs")["indicators"][0]
    assert "3 distinct known vulnerabilities" in cluster["evidence"][0] and "TEST-QS-1" in cluster["evidence"][1]


def test_a_vulnerable_dependency_is_not_reported_as_reachable_without_a_path(client, app, auth_headers, project):
    predictive(client, app, auth_headers, project)                                         # no reachability analysis has run
    items = rows(client, auth_headers, project)
    assert all("REACHABLE_VULNERABLE_DEPENDENCY" not in row["indicator_types"] for row in items.values())
    assert items["requests"]["reachable_vulnerability_count"] is None and items["requests"]["reachability_state"] == "NOT_ANALYSED"
    reachability = factors(detail(client, auth_headers, project, "requests")["prediction"])["reachability"]
    # Not established either way: the model's neutral value, labelled as assumed, with the confidence lowered. Never zero ("safe").
    assert reachability["status"] == "ASSUMED" and reachability["value"] == 0.5 and reachability["basis"] == "DERIVED"
    assert "not established either way" in reachability["detail"]
    assert detail(client, auth_headers, project, "requests")["prediction"]["confidence"] == 0.95
    assert set(rows(client, auth_headers, project, reachable="true")) == set()
    assert set(rows(client, auth_headers, project, vulnerable="true")) == {"requests", "lodash", "ms", "qs"}


def test_zero_reachable_is_reported_only_when_it_was_established(client, app, auth_headers, project, osv):
    osv.add(advisory("TEST-YAML-LOAD", "PyPI", "PyYAML", imports=[{"path": "yaml", "symbols": ["load"]}]))
    osv.report("PyPI", "pyyaml", "5.1", "TEST-YAML-LOAD")
    assert start(client, app, auth_headers, project, "/vulnerabilities/sync")["state"] == "completed"
    predictive(client, app, auth_headers, project)
    before = detail(client, auth_headers, project, "requests")["health"]
    assert before["reachable_vulnerability_count"] is None
    assert {"field": "reachable_vulnerability_count", "status": "UNKNOWN",
            "reason": "No code reachability analysis exists for this snapshot."} in before["unknown"]

    assert start(client, app, auth_headers, project, "/code-reachability/analyze")["state"] == "completed"
    predictive(client, app, auth_headers, project)
    items = rows(client, auth_headers, project)
    health = lambda name: detail(client, auth_headers, project, name)["health"]  # noqa: E731
    # requests: one finding is reachable.
    assert items["requests"]["reachable_vulnerability_count"] == 1 and health("requests")["reachable_vulnerability_count"] == 1
    # debug has no known vulnerability: zero is a fact.
    assert items["debug"]["reachable_vulnerability_count"] == 0 and health("debug")["reachable_vulnerability_count"] == 0
    assert "reachable_vulnerability_count" not in {entry["field"] for entry in health("debug")["unknown"]}
    # pyyaml: its only finding was decided and no path exists (yaml.load is never imported): zero was established.
    assert items["pyyaml"]["reachability_state"] == "NOT_CONFIRMED_REACHABLE" and items["pyyaml"]["reachable_vulnerability_count"] == 0
    # lodash is npm, which is not analysed: "not reachable" was never established, so the count is unknown, not zero.
    assert items["lodash"]["reachability_state"] == "UNSUPPORTED" and items["lodash"]["reachable_vulnerability_count"] is None
    unknown = {entry["field"]: entry["reason"] for entry in health("lodash")["unknown"]}
    assert health("lodash")["reachable_vulnerability_count"] is None and "could not be decided" in unknown["reachable_vulnerability_count"]


def test_predictive_risk_orders_dependencies_and_is_not_a_trust_score(client, app, auth_headers, project):
    assert start(client, app, auth_headers, project, "/code-reachability/analyze")["state"] == "completed"
    predictive(client, app, auth_headers, project)
    body = get(client, auth_headers, project, "/predictive-risk")
    items = body["items"]
    assert items[0]["normalized_name"] == "requests" and items[-1]["normalized_name"] == "pyyaml" and items[-1]["score"] == 0
    assert [i["monitoring_rank"] for i in items] == list(range(1, 10))
    assert [i["score"] for i in items] == sorted((i["score"] for i in items), reverse=True)
    assert all(i["model_version"] == "dependency-risk-v1" and i["classification"] == "PREDICTED" for i in items)
    assert all(i["level"] == ("HIGH" if i["score"] >= 67 else "MEDIUM" if i["score"] >= 34 else "LOW") for i in items)
    assert "trust_score" not in json.dumps(body) and "probability" not in json.dumps([{k: v for k, v in i.items() if k != "meaning"} for i in items])
    assert body["indicator_types"][0] == "REACHABLE_VULNERABLE_DEPENDENCY" and len(body["indicator_types"]) == 10
    assert "evidence" not in items[0] and "factors" not in items[0]                        # the list is compact; detail has them


def test_evidence_is_labelled_by_how_it_was_obtained(client, app, auth_headers, project):
    assert start(client, app, auth_headers, project, "/code-reachability/analyze")["state"] == "completed"
    predictive(client, app, auth_headers, project)
    evidence = detail(client, auth_headers, project, "requests")["prediction"]["evidence"]
    assert "Installed version: 2.19.1." in evidence["OBSERVED"] and "Registry's latest version: 2.32.3." in evidence["OBSERVED"]
    assert any("GHSA-x84v-xcm2-53pg" in line for line in evidence["OBSERVED"])
    assert any(line.startswith("Exposure classification: DIRECT_VULNERABILITY") for line in evidence["DERIVED"])
    assert any("dependency-risk-v1" in line for line in evidence["PREDICTED"])
    assert evidence["RECOMMENDED"] and all("guarantee" not in line.lower() for group in evidence.values() for line in group)
    quiet = detail(client, auth_headers, project, "pyyaml")["prediction"]["evidence"]
    assert quiet["OBSERVED"] and not any("vulnerab" in line.lower() and "0 known" not in line.lower() for line in quiet["RECOMMENDED"])


def test_predictive_filters_sorting_and_paging(client, app, auth_headers, project):
    assert start(client, app, auth_headers, project, "/code-reachability/analyze")["state"] == "completed"
    predictive(client, app, auth_headers, project)
    names = lambda **params: set(rows(client, auth_headers, project, **params))  # noqa: E731
    assert names(level="MEDIUM") == {"requests"} and names(level="HIGH") == set()
    assert names(indicator="OUTDATED_DEPENDENCY") == {"requests", "debug", "express"}
    assert names(reachable="true") == {"requests"} and "requests" not in names(reachable="false")
    assert names(vulnerable="false") == {"express", "morgan", "body-parser", "debug", "pyyaml"}
    assert names(relationship="TRANSITIVE") == {"body-parser", "debug", "qs", "ms"}
    assert names(ecosystem="pypi", relationship="DIRECT") == {"requests", "pyyaml"}
    assert names(ecosystem="npm", vulnerable="true", relationship="TRANSITIVE") == {"qs", "ms"}
    order = lambda sort: [i["normalized_name"] for i in get(client, auth_headers, project, "/predictive-risk", sort=sort)["items"]]  # noqa: E731
    assert order("name") == sorted(order("name")) and order("fragility")[0] == "debug" and order("dependents")[0] == "ms"
    page = get(client, auth_headers, project, "/predictive-risk", limit=3, skip=3)
    assert page["total"] == 9 and [i["normalized_name"] for i in page["items"]] == order("risk")[3:6]
    assert get(client, auth_headers, project, "/predictive-risk", skip=50)["items"] == []
    fragile = lambda **params: set(rows(client, auth_headers, project, "/fragility", **params))  # noqa: E731
    assert fragile(level="MEDIUM") == {"debug"} and fragile(relationship="DIRECT", ecosystem="npm") == {"express", "morgan", "lodash"}


def test_the_risk_graph_contains_exactly_the_observed_packages_and_edges(client, app, auth_headers, project, db):
    predictive(client, app, auth_headers, project)
    graph = get(client, auth_headers, project, "/predictive-risk/graph")
    inventory = {d["node_id"] for d in db.dependencies.find({})}
    assert {node["node_id"] for node in graph["nodes"]} == inventory and len(graph["nodes"]) == 9
    stored = {(e["source"], e["target"]) for e in db.dependency_graphs.find_one({})["edges"]}
    edges = {(e["source"], e["target"]) for e in graph["edges"]}
    assert edges <= stored and len(edges) == 12 and ("npm:debug@2.6.9", "npm:ms@2.0.0") in edges
    assert ("root", "npm:ms@2.0.0") not in edges and all(source in inventory | {"root"} and target in inventory for source, target in edges)
    scores = {row["node_id"]: row["score"] for row in get(client, auth_headers, project, "/predictive-risk")["items"]}
    for node in graph["nodes"]:
        assert node["score"] == scores[node["node_id"]] and node["exposure_classification"] and node["dependency_id"]
    assert graph["analysis"]["model_versions"]["predictive"] == "dependency-risk-v1"


# --- history ---------------------------------------------------------------------------------

def test_an_unchanged_rerun_keeps_the_previous_analysis(client, app, auth_headers, project, db):
    first = predictive(client, app, auth_headers, project)
    second = predictive(client, app, auth_headers, project)
    assert second["state"] == "completed" and second["analysis_id"] == first["analysis_id"] and second["summary"]["reused"] is True
    assert "kept" in second["message"] and first["summary"]["reused"] is False
    assert db.dependency_analyses.count_documents({}) == 1 and db.predictions.count_documents({}) == 9


def test_analyses_are_kept_as_history_and_can_be_compared(client, app, auth_headers, project, osv, db):
    first = predictive(client, app, auth_headers, project)
    # A new advisory for a package that had none, and two withdrawn for another: the next check sees different facts.
    osv.add(advisory("TEST-DEBUG-1", "npm", "debug"))
    osv.report("npm", "debug", "2.6.9", "TEST-DEBUG-1")
    for identifier in ("TEST-QS-2", "TEST-QS-3"):
        osv.add({**osv.records[identifier], "modified": "2025-01-01T00:00:00Z", "withdrawn": "2025-01-01T00:00:00Z"})
    assert start(client, app, auth_headers, project, "/vulnerabilities/sync")["state"] == "completed"
    second = predictive(client, app, auth_headers, project)
    assert second["analysis_id"] != first["analysis_id"] and second["summary"]["reused"] is False
    assert db.dependency_analyses.count_documents({"kind": "predictive"}) == 2
    assert db.predictions.count_documents({"analysis_id": ObjectId(first["analysis_id"])}) == 9      # the earlier run is intact
    history = get(client, auth_headers, project, "/predictive-risk/history")["items"]
    assert [h["id"] for h in history] == [second["analysis_id"], first["analysis_id"]]
    assert all(h["kind"] == "predictive" and h["state"] == "COMPLETE" and h["model_versions"] and h["commit_sha"] for h in history)
    # The list endpoints read the newest analysis.
    assert get(client, auth_headers, project, "/predictive-risk")["analysis"]["id"] == second["analysis_id"]
    assert rows(client, auth_headers, project)["debug"]["exposure_classification"] == "DIRECT_VULNERABILITY"

    diff = get(client, auth_headers, project, "/predictive-risk/compare", base=first["analysis_id"], target=second["analysis_id"])
    assert diff["base"]["analysis_id"] == first["analysis_id"] and diff["target"]["analysis_id"] == second["analysis_id"] and diff["comparable"]
    changed = {item["normalized_name"]: item for item in diff["items"]}
    assert changed["debug"]["change"] == "CHANGED" and changed["debug"]["deltas"]["predictive_risk"] > 0
    assert changed["debug"]["before"]["classification"] == "DEPENDENCY_PROPAGATION" and changed["debug"]["after"]["classification"] == "DIRECT_VULNERABILITY"
    assert changed["qs"]["indicators_removed"] == ["VULNERABILITY_CLUSTER"] and changed["qs"]["deltas"]["predictive_risk"] < 0
    assert "pyyaml" not in changed and "lodash" not in changed
    assert diff["summary"]["added"] == 0 and diff["summary"]["removed"] == 0
    assert diff["summary"]["changed"] == len(diff["items"]) and diff["summary"]["unchanged"] == 9 - len(diff["items"])
    same = get(client, auth_headers, project, "/predictive-risk/compare", base=first["analysis_id"], target=first["analysis_id"])
    assert same["items"] == [] and same["summary"]["unchanged"] == 9


def test_a_reader_can_tell_when_the_inputs_are_newer_than_the_analysis(client, app, auth_headers, project):
    predictive(client, app, auth_headers, project)
    body = get(client, auth_headers, project, "/predictive-risk")
    assert body["current_inputs"] == {"vulnerability_scan_matched_at": body["analysis"]["inputs"]["vulnerability_scan_matched_at"],
                                      "reachability_completed_at": None}
    assert body["analysis"]["inputs"]["reachability"] is None
    assert start(client, app, auth_headers, project, "/code-reachability/analyze")["state"] == "completed"
    assert start(client, app, auth_headers, project, "/vulnerabilities/analyze")["state"] == "completed"
    later = get(client, auth_headers, project, "/predictive-risk")
    assert later["analysis"]["id"] == body["analysis"]["id"]
    assert later["current_inputs"]["reachability_completed_at"] is not None
    assert later["current_inputs"]["vulnerability_scan_matched_at"] > later["analysis"]["inputs"]["vulnerability_scan_matched_at"]
    predictive(client, app, auth_headers, project)
    fresh = get(client, auth_headers, project, "/predictive-risk")
    assert fresh["analysis"]["id"] != body["analysis"]["id"]
    assert fresh["analysis"]["inputs"]["vulnerability_scan_matched_at"] == fresh["current_inputs"]["vulnerability_scan_matched_at"]
    assert fresh["analysis"]["inputs"]["reachability"]["completed_at"] == fresh["current_inputs"]["reachability_completed_at"]


def test_history_can_be_filtered_by_kind(client, app, auth_headers, project):
    start(client, app, auth_headers, project, "/fragility/analyze")
    start(client, app, auth_headers, project, "/graph-risk/analyze")
    predictive(client, app, auth_headers, project)
    kinds = [h["kind"] for h in get(client, auth_headers, project, "/predictive-risk/history")["items"]]
    assert kinds == ["predictive", "graph_risk", "fragility"]
    assert [h["kind"] for h in get(client, auth_headers, project, "/predictive-risk/history", kind="fragility")["items"]] == ["fragility"]
    assert len(get(client, auth_headers, project, "/predictive-risk/history", limit=1)["items"]) == 1
    # Each read endpoint uses the newest analysis that contains its layer.
    newest = get(client, auth_headers, project, "/predictive-risk")["analysis"]["id"]
    assert get(client, auth_headers, project, "/fragility")["analysis"]["id"] == newest
    assert get(client, auth_headers, project, "/graph-risk")["analysis"]["id"] == newest


@pytest.mark.parametrize("base,target", [("nope", "nope"), (str(ObjectId()), str(ObjectId()))])
def test_comparing_unknown_analyses_is_404(client, app, auth_headers, project, base, target):
    predictive(client, app, auth_headers, project)
    assert client.get(url(project, "/predictive-risk/compare"), headers=auth_headers, params={"base": base, "target": target}).status_code == 404


@pytest.mark.parametrize("settings", [{"INTELLIGENCE_HISTORY_LIMIT": "2"}], indirect=True)
def test_history_is_bounded(client, app, auth_headers, project, osv, db):
    identifiers = []
    for round_number in range(4):
        osv.add(advisory(f"TEST-ROUND-{round_number}", "npm", "morgan"))
        osv.report("npm", "morgan", "1.10.0", *(f"TEST-ROUND-{n}" for n in range(round_number + 1)))
        assert start(client, app, auth_headers, project, "/vulnerabilities/sync")["state"] == "completed"
        identifiers.append(start(client, app, auth_headers, project, "/graph-risk/analyze")["analysis_id"])
    assert len(set(identifiers)) == 4
    kept = [h["id"] for h in get(client, auth_headers, project, "/predictive-risk/history")["items"]]
    assert kept == identifiers[:1:-1]                                                      # the two newest
    assert db.graph_risk_analysis.count_documents({}) == 18
    assert set(map(str, db.graph_risk_analysis.distinct("analysis_id"))) == set(kept)


def test_a_new_snapshot_starts_without_results_and_keeps_the_old_ones_in_history(client, app, auth_headers, project, repo, db):
    first = predictive(client, app, auth_headers, project)
    repo.files["requirements.txt"] = b"requests==2.31.0\nPyYAML==5.1\n"
    assert start(client, app, auth_headers, project, "/analysis/dependencies")["state"] == "completed"
    # Results of the previous commit are not shown as if they described this one.
    for path in ("/fragility", "/graph-risk", "/predictive-risk"):
        body = get(client, auth_headers, project, path)
        assert body["analysis"] is None and body["items"] == [] and body["has_vulnerability_scan"] is False
    assert client.post(url(project, "/predictive-risk/analyze"), headers=auth_headers).status_code == 409
    assert [h["id"] for h in get(client, auth_headers, project, "/predictive-risk/history")["items"]] == [first["analysis_id"]]

    assert start(client, app, auth_headers, project, "/vulnerabilities/sync")["state"] == "completed"
    second = predictive(client, app, auth_headers, project)
    diff = get(client, auth_headers, project, "/predictive-risk/compare", base=first["analysis_id"], target=second["analysis_id"])
    upgraded = {item["normalized_name"]: item for item in diff["items"]}["requests"]
    assert upgraded["version_changed"] is True and upgraded["before"]["version"] == "2.19.1" and upgraded["after"]["version"] == "2.31.0"
    assert diff["base"]["commit_sha"] != diff["target"]["commit_sha"] and upgraded["deltas"]["fragility_score"] < 0


def test_deleting_a_project_removes_its_results_but_not_the_shared_registry_cache(client, app, auth_headers, project, db):
    predictive(client, app, auth_headers, project)
    assert client.delete(url(project), headers=auth_headers).status_code in (200, 204)
    for collection in ("dependency_analyses", "dependency_fragility", "dependency_health", "graph_risk_analysis", "predictive_indicators", "predictions"):
        assert db[collection].count_documents({}) == 0, collection
    assert db.package_metadata.count_documents({}) == 9          # public registry facts, tied to no project or user
    assert all("project_id" not in doc and "owner_id" not in doc for doc in db.package_metadata.find({}))


# --- earlier phases are read, not changed ------------------------------------------------------

def test_the_analysis_does_not_modify_earlier_phases_data(client, app, auth_headers, project, db, github, osv):
    assert start(client, app, auth_headers, project, "/code-reachability/analyze")["state"] == "completed"
    watched = ("dependencies", "dependency_graphs", "vulnerability_matches", "vulnerabilities", "code_reachability", "repository_snapshots",
               "reachability_analyses", "source_symbols", "code_edges")
    before = {name: sorted(json.dumps(doc, sort_keys=True, default=str) for doc in db[name].find({})) for name in watched}
    github_requests, osv_requests = len(github.requests), len(osv.requests)
    predictive(client, app, auth_headers, project)
    assert {name: sorted(json.dumps(doc, sort_keys=True, default=str) for doc in db[name].find({})) for name in watched} == before
    # It reads stored results only: no repository content is fetched again and no advisory source is contacted.
    assert len(github.requests) == github_requests and len(osv.requests) == osv_requests


def test_vulnerability_counts_are_exactly_phase_three_matches(client, app, auth_headers, project, db):
    predictive(client, app, auth_headers, project)
    matched = {}
    for match in db.vulnerability_matches.find({"match_status": "AFFECTED"}):
        matched.setdefault(match["dependency_node_id"], set()).add(match.get("group_key") or match["source_id"])
    for row in get(client, auth_headers, project, "/predictive-risk")["items"]:
        assert row["vulnerability_count"] == len(matched.get(row["node_id"], ())), row["node_id"]


# --- regression tests from the independent review ----------------------------------------------

def one_package_project(client, app, headers, github, name, version, repository="upper"):
    lock = {"lockfileVersion": 3, "packages": {"": {"name": "web", "dependencies": {name: version}}, f"node_modules/{name}": {"version": version}}}
    github.repo = FakeRepository({"package.json": json.dumps({"name": "web", "dependencies": {name: version}}), "package-lock.json": json.dumps(lock)})
    created = client.post("/api/projects", json={"name": "One", "repository_url": f"https://github.com/octo/{repository}"}, headers=headers).json()
    assert start(client, app, headers, created, "/analysis/dependencies")["state"] == "completed"
    return created


def test_a_mixed_case_npm_name_is_never_answered_with_another_packages_data(client, app, auth_headers, github, registry, db):
    registry.add("npm", "jsonstream", "9.9.9", {"1.3.5": days_ago(100), "9.9.9": days_ago(1)})       # the lowercase name is a different package
    created = one_package_project(client, app, auth_headers, github, "JSONStream", "1.3.5")
    assert start(client, app, auth_headers, created, "/fragility/analyze")["state"] == "completed"
    assert [r.url.raw_path.decode() for r in registry.requests] == ["/JSONStream"]
    version = get(client, auth_headers, created, "/fragility")["items"][0]["inferred_metrics"]["version"]
    assert version["comparison_status"] == "UNKNOWN" and version["latest_version"] is None and version["position"] is None
    assert db.package_metadata.find_one({"ecosystem": "npm"})["normalized_name"] == "JSONStream"     # cached under the name that was asked

    registry.add("npm", "JSONStream", "1.3.5", {"1.3.5": days_ago(100)})
    db.package_metadata.delete_many({})
    start(client, app, auth_headers, created, "/fragility/analyze")
    assert get(client, auth_headers, created, "/fragility")["items"][0]["inferred_metrics"]["version"]["position"] == "UP_TO_DATE"


def test_an_absurd_registry_version_cannot_break_the_analysis_or_the_shared_cache(client, app, auth_headers, project, registry, db):
    registry.add("pypi", "requests", "99999999999999999999.0", {"2.19.1": days_ago(2900), "99999999999999999999.0": days_ago(1)})
    job = predictive(client, app, auth_headers, project)
    assert job["state"] == "completed"
    version = detail(client, auth_headers, project, "requests")["health"]["version"]
    assert version["comparison_status"] == "UNSUPPORTED" and version["major_distance"] is None and "too large" in version["reason"]
    assert db.dependency_analyses.count_documents({"state": "COMPLETE"}) == 1
    assert start(client, app, auth_headers, project, "/fragility/analyze")["state"] == "completed"   # and again, from the cache


def test_a_failure_while_storing_results_leaves_nothing_behind(client, app, auth_headers, project, db, monkeypatch):
    from app.services import intelligence

    real, calls = intelligence._insert, []

    def failing(database, collection, rows):
        calls.append(collection)
        if len(calls) == 3:
            raise OverflowError("simulated storage failure")
        real(database, collection, rows)

    monkeypatch.setattr(intelligence, "_insert", failing)
    job = predictive(client, app, auth_headers, project)
    assert job["state"] == "failed" and job["error"]["code"] == "INTERNAL_ERROR" and len(calls) == 3
    for collection in ("dependency_analyses", "dependency_fragility", "dependency_health", "graph_risk_analysis", "predictive_indicators", "predictions"):
        assert db[collection].count_documents({}) == 0, collection
    assert get(client, auth_headers, project, "/predictive-risk")["analysis"] is None
    monkeypatch.undo()
    assert predictive(client, app, auth_headers, project)["state"] == "completed"


def test_reuse_survives_the_cache_round_trip_but_not_a_changed_registry_answer(client, app, auth_headers, project, registry, db):
    stamp = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.175627Z")      # PyPI publishes microseconds
    registry.add("pypi", "pyyaml", "5.1", {"5.1": stamp, "5.0": days_ago(200)})
    first = start(client, app, auth_headers, project, "/fragility/analyze")
    second = start(client, app, auth_headers, project, "/fragility/analyze")                            # read back from the cache
    assert second["analysis_id"] == first["analysis_id"] and second["summary"]["reused"] is True
    assert db.dependency_analyses.count_documents({}) == 1

    # The installed version is withdrawn at the registry. Latest version and dates are unchanged; the analysis is not the same.
    registry.add("pypi", "pyyaml", "5.1", {"5.1": stamp, "5.0": days_ago(200)}, yanked=["5.1"])
    db.package_metadata.update_many({}, {"$set": {"fetched_at": datetime(2020, 1, 1, tzinfo=timezone.utc)}})
    third = start(client, app, auth_headers, project, "/fragility/analyze")
    assert third["analysis_id"] != first["analysis_id"] and third["summary"]["reused"] is False
    assert detail(client, auth_headers, project, "pyyaml", "/fragility")["fragility"]["inferred_metrics"]["version"]["installed_withdrawn"] is True


def test_reachable_false_means_established_not_unknown(client, app, auth_headers, project):
    predictive(client, app, auth_headers, project)                                         # no reachability analysis yet
    assert rows(client, auth_headers, project, reachable="false") == {} and rows(client, auth_headers, project, reachable="true") == {}
    assert start(client, app, auth_headers, project, "/code-reachability/analyze")["state"] == "completed"
    predictive(client, app, auth_headers, project)
    established = rows(client, auth_headers, project, reachable="false")
    # Packages without a known vulnerability have nothing to reach. Undecided ones (npm: unsupported) are in neither answer.
    assert set(established) == {"express", "morgan", "body-parser", "debug", "pyyaml"}
    assert set(rows(client, auth_headers, project, reachable="true")) == {"requests"}
    assert rows(client, auth_headers, project, reachable="false", vulnerable="true") == {}
    assert all(row["reachable_vulnerability_count"] is None for name, row in rows(client, auth_headers, project).items() if name in ("lodash", "qs", "ms"))


def test_comparison_keeps_two_versions_of_one_package_apart(client, app, auth_headers, github, osv, registry):
    lock = {"lockfileVersion": 3, "packages": {
        "": {"name": "web", "dependencies": {"a": "1.0.0", "b": "1.0.0"}},
        "node_modules/a": {"version": "1.0.0", "dependencies": {"debug": "2.6.9"}},
        "node_modules/b": {"version": "1.0.0", "dependencies": {"debug": "4.3.4"}},
        "node_modules/debug": {"version": "2.6.9"}, "node_modules/b/node_modules/debug": {"version": "4.3.4"}}}
    github.repo = FakeRepository({"package.json": json.dumps({"name": "web", "dependencies": {"a": "1.0.0", "b": "1.0.0"}}),
                                  "package-lock.json": json.dumps(lock)})
    created = client.post("/api/projects", json={"name": "Two", "repository_url": "https://github.com/octo/multi"}, headers=auth_headers).json()
    assert start(client, app, auth_headers, created, "/analysis/dependencies")["state"] == "completed"
    assert start(client, app, auth_headers, created, "/vulnerabilities/sync")["state"] == "completed"
    first = start(client, app, auth_headers, created, "/graph-risk/analyze")
    older = advisory("TEST-DBG", "npm", "debug")
    older["affected"][0]["ranges"] = [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "3.0.0"}]}]   # only the older version is affected
    osv.add(older)
    osv.report("npm", "debug", "2.6.9", "TEST-DBG")
    assert start(client, app, auth_headers, created, "/vulnerabilities/sync")["state"] == "completed"
    second = start(client, app, auth_headers, created, "/graph-risk/analyze")
    diff = get(client, auth_headers, created, "/predictive-risk/compare", base=first["analysis_id"], target=second["analysis_id"])
    changed = {item["after"]["node_id"]: item for item in diff["items"]}
    assert set(changed) == {"npm:debug@2.6.9", "npm:a@1.0.0"}                               # a requires the affected version; b and debug 4.3.4 do not
    assert changed["npm:debug@2.6.9"]["after"]["classification"] == "DIRECT_VULNERABILITY" and changed["npm:debug@2.6.9"]["version_changed"] is False
    assert changed["npm:a@1.0.0"]["after"]["classification"] == "DEPENDENCY_PROPAGATION"
    assert diff["summary"] == {"added": 0, "removed": 0, "changed": 2, "unchanged": 2}


def test_a_stale_answer_is_used_and_described_as_such_not_as_missing(client, app, auth_headers, project, registry, db):
    predictive(client, app, auth_headers, project)
    db.package_metadata.update_many({}, {"$set": {"fetched_at": datetime(2020, 1, 1, tzinfo=timezone.utc)}})
    registry.fail = {"/": 503}
    job = start(client, app, auth_headers, project, "/fragility/analyze")
    stats = job["summary"]["metadata"]
    # Eight packages had an earlier answer; "ms" never had one (the registry said it does not exist, which is re-asked and now fails).
    assert job["state"] == "partial" and stats["stale_used"] == 8 and stats["errors"] + stats["skipped_after_failures"] == 9
    assert "could not be collected for 1 of 9 package(s)" in job["error"]["message"]
    assert "for 8 more package(s) the registry could not be asked again and an earlier answer was used" in job["error"]["message"]
    health = detail(client, auth_headers, project, "express", "/fragility")["health"]
    assert health["latest_release"] == "4.19.2" and health["metadata_source"]["stale"] is True       # also for those skipped after the failures
    assert detail(client, auth_headers, project, "ms", "/fragility")["health"]["version"]["comparison_status"] == "UNKNOWN"


@pytest.mark.parametrize("partial", [{"message": "only a message"}, {}, "not a dict", {"code": None, "message": None}])
def test_a_malformed_partial_report_cannot_leave_the_project_locked(client, app, auth_headers, project, db, monkeypatch, partial):
    from app.services import jobs

    monkeypatch.setitem(jobs._HANDLERS, "predictive_dependency_analysis", lambda _context, _job: ("done", {"partial": partial} if partial != {} else {"partial": {"x": 1}}))
    job = predictive(client, app, auth_headers, project)
    assert job["state"] == "partial" and job["error"]["code"] == "PARTIAL" and job["error"]["message"]
    assert get(client, auth_headers, project, "/jobs")["active"] is None and db.projects.find_one({})["active_job_id"] is None


@pytest.mark.parametrize("settings", [{"PACKAGE_METADATA_MAX_BYTES": "4096"}], indirect=True)
def test_an_oversized_npm_document_falls_back_to_the_compact_answer(client, app, auth_headers, project, registry):
    releases = {f"4.{n}.0": days_ago(3000 - n) for n in range(120)}                       # the full document exceeds the limit; the compact one does not
    registry.add("npm", "express", "4.119.0", {"4.17.1": days_ago(2000), **releases})
    job = predictive(client, app, auth_headers, project)
    assert job["state"] == "completed" and job["summary"]["metadata"]["errors"] == 0
    asked = [r.headers["accept"] for r in registry.requests if r.url.raw_path == b"/express"]
    assert asked[0] == "application/json" and "vnd.npm.install-v1" in asked[1] and len(asked) == 2
    health = detail(client, auth_headers, project, "express")["health"]
    assert health["latest_release"] == "4.119.0" and health["metadata_source"]["detail"] == "COMPACT"
    assert health["latest_release_at"] is None and health["release_age_days"] is None      # versions are known, dates are not, none invented
