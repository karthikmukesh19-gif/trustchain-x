"""Code reachability end to end: API -> job -> worker -> GitHub blobs -> AST -> graph -> findings -> API.

The repository is served by an in-memory stand-in for the GitHub API and the
advisories by a stand-in for OSV. GHSA-* records are real public advisories
from tests/fixtures/osv; TEST-* records are synthetic and exist only because
real Python advisories do not publish affected functions. Nothing contacts
the network and no repository code is executed.
"""

import json

import pytest
from bson import ObjectId

from app.config.settings import load_settings
from tests.conftest import TEST_ENV, FakeRepository, run_worker

REPO_URL = "https://github.com/octo/reachability-demo"
MAIN = "from app.client import fetch\n\n\ndef handle_request(url):\n    return fetch(url)\n"
CLIENT = "import requests\n\n\ndef fetch(url):\n    return requests.get(url)\n"
CONFIG = "import yaml\n\n\ndef load(text):\n    return yaml.safe_load(text)\n"
REPO = {
    "requirements.txt": "requests==2.19.1\nPyYAML==5.1\n",
    "app/__init__.py": "",
    "app/main.py": MAIN,
    "app/client.py": CLIENT,
    "app/config.py": CONFIG,
    "tests/test_client.py": "from app.client import fetch\n\n\ndef test_fetch():\n    assert fetch('u')\n",
    "web/package.json": json.dumps({"name": "web", "dependencies": {"lodash": "4.17.20"}}),
    "web/package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "web", "dependencies": {"lodash": "4.17.20"}}, "node_modules/lodash": {"version": "4.17.20"}}}),
    "web/index.js": "const _ = require('lodash');\n",
}
EVERYTHING = {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "99.0"}]}


def advisory(identifier, package, **specific):
    return {"id": identifier, "modified": "2024-01-01T00:00:00Z", "summary": f"Synthetic advisory {identifier}",
            "affected": [{"package": {"ecosystem": "PyPI", "name": package}, "ranges": [EVERYTHING], "ecosystem_specific": specific}]}


GET = advisory("TEST-REQ-GET", "requests", affected_functions=["requests.get"])
SEND = advisory("TEST-REQ-SEND", "requests", affected_functions=["requests.sessions.Session.send"])
YAML_LOAD = advisory("TEST-YAML-LOAD", "PyYAML", imports=[{"path": "yaml", "symbols": ["load"]}])
BASE = "/code-reachability"
ENDPOINTS = [("post", f"{BASE}/analyze"), ("get", BASE), ("get", f"{BASE}/{ObjectId()}"), ("get", f"{BASE}/{ObjectId()}/path"),
             ("get", f"{BASE}/source/{ObjectId()}")]


@pytest.fixture
def settings(request):
    return load_settings({**TEST_ENV, **getattr(request, "param", {})})


@pytest.fixture
def repo(github):
    github.repo = FakeRepository(REPO)
    return github.repo


@pytest.fixture
def intelligence(osv):
    osv.load("GHSA-x84v-xcm2-53pg", "GHSA-35jh-r3h4-6jhm")
    osv.add(GET, SEND, YAML_LOAD)
    osv.report("PyPI", "requests", "2.19.1", "GHSA-x84v-xcm2-53pg", "TEST-REQ-GET", "TEST-REQ-SEND")
    osv.report("PyPI", "pyyaml", "5.1", "TEST-YAML-LOAD")
    osv.report("npm", "lodash", "4.17.20", "GHSA-35jh-r3h4-6jhm")
    return osv


def url(project, path=""):
    return f"/api/projects/{project['id']}{path}"


def start(client, app, headers, project, path, body=None):
    response = client.post(url(project, path), headers=headers, json=body)
    assert response.status_code == 202, response.text
    assert run_worker(app) == 1
    return client.get(url(project, "/jobs"), headers=headers).json()["items"][0]


@pytest.fixture
def analysed(client, app, auth_headers, repo):
    """A project with a dependency inventory."""
    created = client.post("/api/projects", json={"name": "Demo", "repository_url": REPO_URL}, headers=auth_headers).json()
    assert start(client, app, auth_headers, created, "/analysis/dependencies")["state"] == "completed"
    return created


@pytest.fixture
def project(client, app, auth_headers, analysed, intelligence):
    """A project with a dependency inventory and a completed vulnerability check."""
    assert start(client, app, auth_headers, analysed, "/vulnerabilities/sync")["state"] == "completed"
    return analysed


def analyse(client, app, headers, project, body=None):
    return start(client, app, headers, project, f"{BASE}/analyze", body)


def findings(client, headers, project, **params):
    response = client.get(url(project, BASE), headers=headers, params=params)
    assert response.status_code == 200, response.text
    return response.json()


def by_advisory(body):
    return {item["advisory_id"]: item for item in body["items"]}


def blob_requests(github):
    return [r for r in github.requests if "/git/blobs/" in r.url.path]


# --- access control -------------------------------------------------------------------------

@pytest.mark.parametrize("method,path", ENDPOINTS)
def test_endpoints_require_authentication(client, method, path):
    assert getattr(client, method)(f"/api/projects/{ObjectId()}{path}").status_code == 401


@pytest.mark.parametrize("method,path", ENDPOINTS)
def test_another_users_project_is_not_found(client, auth_headers, other_headers, project, method, path):
    assert getattr(client, method)(url(project, path), headers=other_headers).status_code == 404


def test_another_users_findings_cannot_be_read_by_id(client, app, auth_headers, other_headers, project, db):
    analyse(client, app, auth_headers, project)
    finding = findings(client, auth_headers, project)["items"][0]
    snapshot = findings(client, auth_headers, project)["snapshot"]["id"]
    for path in (f"{BASE}/{finding['id']}", f"{BASE}/{finding['id']}/path", f"{BASE}/source/{snapshot}"):
        assert client.get(url(project, path), headers=other_headers).status_code == 404
    # Nor through a project the other user owns.
    other = client.post("/api/projects", json={"name": "Mine", "repository_url": "https://github.com/octo/other"}, headers=other_headers).json()
    for path in (f"{BASE}/{finding['id']}", f"{BASE}/{finding['id']}/path", f"{BASE}/source/{snapshot}"):
        assert client.get(url(other, path), headers=other_headers).status_code == 404
    assert findings(client, other_headers, other)["items"] == []


@pytest.mark.parametrize("identifier", ["nope", "123", str(ObjectId()), "../x", "$ne"])
def test_unknown_or_malformed_ids_are_404(client, app, auth_headers, project, identifier):
    analyse(client, app, auth_headers, project)
    assert client.get(url(project, f"{BASE}/{identifier}"), headers=auth_headers).status_code == 404
    assert client.get(url(project, f"{BASE}/{identifier}/path"), headers=auth_headers).status_code == 404
    assert client.get(url(project, f"{BASE}/source/{identifier}"), headers=auth_headers).status_code == 404


def test_unknown_request_fields_and_bad_filters_are_rejected(client, app, auth_headers, project):
    assert client.post(url(project, f"{BASE}/analyze"), headers=auth_headers, json={"repository_url": "https://evil.example"}).status_code == 422
    analyse(client, app, auth_headers, project)
    for params in ({"status": "SAFE"}, {"confidence": "CERTAIN"}, {"ecosystem": "py pi"}, {"limit": 0}, {"limit": 501}, {"skip": -1}):
        assert client.get(url(project, BASE), headers=auth_headers, params=params).status_code == 422, params


# --- preconditions --------------------------------------------------------------------------

def test_analysis_needs_a_snapshot_and_a_vulnerability_check(client, app, auth_headers, github, intelligence):
    github.repo = FakeRepository(REPO)
    created = client.post("/api/projects", json={"name": "Demo", "repository_url": REPO_URL}, headers=auth_headers).json()
    response = client.post(url(created, f"{BASE}/analyze"), headers=auth_headers)
    assert response.status_code == 409 and "dependency analysis first" in response.json()["detail"]
    start(client, app, auth_headers, created, "/analysis/dependencies")
    response = client.post(url(created, f"{BASE}/analyze"), headers=auth_headers)
    assert response.status_code == 409 and "vulnerability check" in response.json()["detail"]
    body = findings(client, auth_headers, created)
    assert body["analysis"] is None and body["items"] == [] and body["has_vulnerability_scan"] is False and body["job"] is None


def test_only_one_job_runs_per_project(client, auth_headers, project):
    assert client.post(url(project, f"{BASE}/analyze"), headers=auth_headers).status_code == 202
    assert client.post(url(project, f"{BASE}/analyze"), headers=auth_headers).status_code == 409
    assert client.post(url(project, "/sbom/generate"), headers=auth_headers).status_code == 409


@pytest.mark.parametrize("settings", [{"JOB_RATE_LIMIT": "2"}], indirect=True)
def test_starting_analyses_is_rate_limited(client, auth_headers, github, repo):
    created = client.post("/api/projects", json={"name": "Demo", "repository_url": REPO_URL}, headers=auth_headers).json()
    codes = [client.post(url(created, f"{BASE}/analyze"), headers=auth_headers).status_code for _ in range(3)]
    assert codes == [409, 409, 429]


# --- the job --------------------------------------------------------------------------------

def test_job_runs_in_the_worker_through_its_stages(client, app, auth_headers, project, db):
    response = client.post(url(project, f"{BASE}/analyze"), headers=auth_headers)
    queued = response.json()["job"]
    assert (queued["type"], queued["state"], queued["stage"]) == ("code_reachability_analysis", "queued", "QUEUED")
    assert queued["stages"] == ["SOURCE_INVENTORY", "SOURCE_PARSING", "GRAPH_BUILDING", "SYMBOL_MAPPING", "REACHABILITY"]
    assert findings(client, auth_headers, project)["job"]["state"] == "queued"
    assert run_worker(app) == 1
    body = findings(client, auth_headers, project)
    job = body["job"]
    assert (job["state"], job["stage"], job["error"]) == ("completed", "COMPLETED", None)
    assert job["message"] == "5 finding(s) analysed: 1 reachable, 2 not confirmed, 1 unknown, 1 unsupported"
    summary = job["summary"]
    assert summary["by_status"] == {"REACHABLE": 1, "NOT_CONFIRMED_REACHABLE": 2, "UNKNOWN": 1, "UNSUPPORTED": 1}
    assert summary["source"]["files_found"] == 5 and summary["source"]["files_parsed"] == 5 and summary["source"]["test_files"] == 1
    assert summary["source"]["other_languages"] == {"JavaScript": 1} and summary["source_complete"] is True
    assert summary["with_symbol_mapping"] == 3 and summary["analyzer_version"] == "4.0.0"
    assert db.projects.find_one({})["active_job_id"] is None


def test_requests_and_outcomes_are_audited(client, app, auth_headers, project, db):
    analyse(client, app, auth_headers, project)
    entries = [(e["action"], e["outcome"]) for e in db.audit_logs.find({"action": {"$regex": "^job.code_reachability_analysis"}})]
    assert entries == [("job.code_reachability_analysis.request", "success"), ("job.code_reachability_analysis.finish", "success")]


def test_only_source_files_are_fetched_and_each_by_its_blob_id(client, app, auth_headers, project, github, repo):
    before = len(blob_requests(github))
    analyse(client, app, auth_headers, project)
    fetched = {r.url.path.rsplit("/", 1)[-1] for r in blob_requests(github)[before:]}
    python_files = [p for p in REPO if p.endswith(".py")]
    assert fetched == {repo.blob_id(p) for p in python_files} and len(blob_requests(github)) - before == len(set(fetched))
    assert all(r.url.host == "api.github.com" and r.method == "GET" for r in github.requests)


# --- findings -------------------------------------------------------------------------------

def test_each_finding_gets_the_status_the_source_establishes(client, app, auth_headers, project):
    analyse(client, app, auth_headers, project)
    body = findings(client, auth_headers, project)
    found = {k: (v["status"], v["confidence"], v["reason"]) for k, v in by_advisory(body).items()}
    assert found == {
        "TEST-REQ-GET": ("REACHABLE", "HIGH", "PATH_FOUND"),                              # requests.get is called
        "TEST-REQ-SEND": ("NOT_CONFIRMED_REACHABLE", "MEDIUM", "NO_PATH_FOUND"),          # Session.send is never used
        "TEST-YAML-LOAD": ("NOT_CONFIRMED_REACHABLE", "MEDIUM", "NO_PATH_FOUND"),         # yaml.safe_load is used, yaml.load is not
        "GHSA-x84v-xcm2-53pg": ("UNKNOWN", None, "SYMBOL_MAPPING_UNKNOWN"),               # the real advisory names no function
        "GHSA-35jh-r3h4-6jhm": ("UNSUPPORTED", None, "LANGUAGE_NOT_SUPPORTED"),           # an npm package
    }
    assert [i["status"] for i in body["items"]] == ["REACHABLE", "UNKNOWN", "NOT_CONFIRMED_REACHABLE", "NOT_CONFIRMED_REACHABLE", "UNSUPPORTED"]
    assert body["total"] == 5 and body["supported_ecosystems"] == ["pypi"] and body["has_vulnerability_scan"] is True
    assert body["statuses"] == ["REACHABLE", "NOT_CONFIRMED_REACHABLE", "UNKNOWN", "UNSUPPORTED"]


def test_reachable_finding_carries_the_required_evidence(client, app, auth_headers, project, db):
    analyse(client, app, auth_headers, project)
    listed = by_advisory(findings(client, auth_headers, project))["TEST-REQ-GET"]
    assert listed["evidence"] == {"source_file": "app/client.py", "line": 5, "symbol": "app.client:fetch", "text": "return requests.get(url)",
                                  "path": ["app.main:handle_request", "app.client:fetch", "requests.get"]}
    assert (listed["dependency"], listed["ecosystem"], listed["resolved_version"], listed["usage_level"]) == ("requests", "pypi", "2.19.1", "CALLED")
    detail = client.get(url(project, f"{BASE}/{listed['id']}"), headers=auth_headers).json()
    snapshot = db.repository_snapshots.find_one({})
    assert detail["snapshot_id"] == str(snapshot["_id"]) and detail["match_id"] and detail["vulnerability_id"] and detail["analysis_id"]
    assert detail["analyzer_version"] == "4.0.0" and detail["analyzed_at"] and detail["relationship"] == "DIRECT"
    assert detail["matched_symbol"]["symbol"] == "requests.get" and detail["matched_symbol"]["source"] == "ADVISORY"
    assert detail["matched_symbol"]["origin"] == "affected[].ecosystem_specific.affected_functions"
    assert "not a likelihood of exploitation" in detail["confidence_meaning"] and "exploited" in detail["explanation"]
    path = detail["observed"]["path"]
    assert [(e["evidence"]["source_file"], e["evidence"]["line"], e["confidence"]) for e in path["edges"]] == [
        ("app/main.py", 5, "HIGH"), ("app/client.py", 5, "HIGH")]
    usage = detail["observed"]["dependency_usage"]
    assert usage["import_sites"][0]["text"] == "import requests" and usage["import_sites"][0]["source_file"] == "app/client.py"
    assert detail["inferred"]["status"] == "REACHABLE" and len(detail["inferred"]["notes"]) == 2
    stored = db.code_reachability.find_one({"advisory_id": "TEST-REQ-GET"})
    assert stored["project_id"] == ObjectId(project["id"]) and stored["repository_id"] == snapshot["repository_id"]
    assert "project_id" not in detail and "status_rank" not in detail


def test_path_endpoint_returns_the_path_or_the_usage_path_and_says_which(client, app, auth_headers, project):
    analyse(client, app, auth_headers, project)
    items = by_advisory(findings(client, auth_headers, project))
    reached = client.get(url(project, f"{BASE}/{items['TEST-REQ-GET']['id']}/path"), headers=auth_headers).json()
    assert reached["path_kind"] == "AFFECTED_SYMBOL" and reached["status"] == "REACHABLE" and reached["path"]["length"] == 2
    assert [n["label"] for n in reached["path"]["nodes"]] == ["app.main:handle_request", "app.client:fetch", "requests.get"]
    assert reached["path"]["nodes"][0] == {"id": "app.main:handle_request", "kind": "function", "label": "app.main:handle_request",
                                           "path": "app/main.py", "line": 4, "is_test": False}
    assert "not proof of exploitability" in reached["meaning"]
    unknown = client.get(url(project, f"{BASE}/{items['GHSA-x84v-xcm2-53pg']['id']}/path"), headers=auth_headers).json()
    assert unknown["path_kind"] == "DEPENDENCY_USAGE" and unknown["status"] == "UNKNOWN" and unknown["path"]["length"] == 2
    absent = client.get(url(project, f"{BASE}/{items['TEST-REQ-SEND']['id']}/path"), headers=auth_headers).json()
    assert absent["path_kind"] is None and absent["path"] is None
    unsupported = client.get(url(project, f"{BASE}/{items['GHSA-35jh-r3h4-6jhm']['id']}/path"), headers=auth_headers).json()
    assert unsupported["path"] is None and unsupported["status"] == "UNSUPPORTED"


def test_unknown_is_never_presented_as_safe_or_exploitable(client, app, auth_headers, project):
    analyse(client, app, auth_headers, project)
    body = findings(client, auth_headers, project)
    details = [client.get(url(project, f"{BASE}/{i['id']}"), headers=auth_headers).json() for i in body["items"]]
    text = json.dumps([body, details]).lower()
    for word in ('"safe"', "not_affected", "exploitable\"", "risk_score", "trust_score", "exploitability_score", "likelihood\":"):
        assert word not in text, word
    unknown = next(d for d in details if d["advisory_id"] == "GHSA-x84v-xcm2-53pg")
    assert unknown["confidence"] is None and unknown["affected_symbols"] == [] and unknown["matched_symbol"] is None
    assert "cannot be decided" in unknown["explanation"] and unknown["observed"]["dependency_usage"]["level"] == "CALLED"
    not_confirmed = next(d for d in details if d["advisory_id"] == "TEST-REQ-SEND")
    assert "not a statement that the application is safe" in not_confirmed["explanation"]


def test_filters_search_and_paging(client, app, auth_headers, project):
    analyse(client, app, auth_headers, project)
    assert sorted(by_advisory(findings(client, auth_headers, project, status="NOT_CONFIRMED_REACHABLE"))) == ["TEST-REQ-SEND", "TEST-YAML-LOAD"]
    assert list(by_advisory(findings(client, auth_headers, project, confidence="HIGH"))) == ["TEST-REQ-GET"]
    assert sorted(by_advisory(findings(client, auth_headers, project, confidence="NONE"))) == ["GHSA-35jh-r3h4-6jhm", "GHSA-x84v-xcm2-53pg"]
    assert list(by_advisory(findings(client, auth_headers, project, ecosystem="npm"))) == ["GHSA-35jh-r3h4-6jhm"]
    assert list(by_advisory(findings(client, auth_headers, project, q="pyyaml"))) == ["TEST-YAML-LOAD"]
    assert list(by_advisory(findings(client, auth_headers, project, q="cve-2018-18074"))) == ["GHSA-x84v-xcm2-53pg"]
    assert findings(client, auth_headers, project, q=".*")["total"] == 0                       # the text is not a pattern
    page = findings(client, auth_headers, project, skip=1, limit=2)
    assert page["total"] == 5 and len(page["items"]) == 2 and page["items"][0]["status"] == "UNKNOWN"


def test_source_inventory_lists_every_candidate_file_and_its_imports(client, app, auth_headers, project):
    analyse(client, app, auth_headers, project)
    snapshot = findings(client, auth_headers, project)["snapshot"]["id"]
    body = client.get(url(project, f"{BASE}/source/{snapshot}"), headers=auth_headers).json()
    assert body["total"] == 5 and body["source_available"] is True and body["analysis"]["snapshot_id"] == snapshot
    files = {f["path"]: f for f in body["items"]}
    client_file = files["app/client.py"]
    assert (client_file["language"], client_file["parse_status"], client_file["parse_error"], client_file["file_size"], client_file["is_test"]) == (
        "python", "PARSED", None, len(CLIENT), False)
    assert client_file["discovered_symbols_count"] == 2 and client_file["discovered_imports_count"] == 1 and client_file["git_blob_sha"]
    assert client_file["snapshot_id"] == snapshot and client_file["module"] == "app.client"
    mapped = client_file["imports"][0]
    assert (mapped["statement"], mapped["line"], mapped["resolution"], mapped["dependency"], mapped["resolved_version"]) == (
        "import requests", 1, "DEPENDENCY", "requests", "2.19.1")
    assert files["tests/test_client.py"]["is_test"] is True and files["app/main.py"]["imports"][0]["resolution"] == "LOCAL"
    assert client.get(url(project, f"{BASE}/source/{snapshot}"), headers=auth_headers, params={"q": "client"}).json()["total"] == 2
    assert client.get(url(project, f"{BASE}/source/{snapshot}"), headers=auth_headers, params={"parse_status": "SYNTAX_ERROR"}).json()["total"] == 0


def test_symbols_and_edges_are_stored_scoped_to_the_snapshot(client, app, auth_headers, project, db):
    analyse(client, app, auth_headers, project)
    snapshot = db.repository_snapshots.find_one({})
    scope = {"project_id": ObjectId(project["id"]), "repository_id": snapshot["repository_id"], "snapshot_id": snapshot["_id"]}
    for collection in (db.source_files, db.source_symbols, db.code_edges, db.code_reachability, db.reachability_analyses):
        assert collection.count_documents({}) > 0 and collection.count_documents(scope) == collection.count_documents({})
    symbol = db.source_symbols.find_one({"symbol_id": "app.client:fetch"})
    assert (symbol["kind"], symbol["path"], symbol["line"], symbol["end_line"]) == ("function", "app/client.py", 4, 5)
    edge = db.code_edges.find_one({"source": "app.client:fetch", "target": "ext:requests.get"})
    assert edge["kind"] == "calls" and edge["confidence"] == "HIGH" and edge["evidence"]["line"] == 5
    assert db.source_symbols.find_one({"symbol_id": "ext:requests.get"})["dependency_node_ids"] == ["pypi:requests@2.19.1"]


# --- untrusted and incomplete source --------------------------------------------------------

def test_a_file_that_does_not_parse_does_not_fail_the_analysis_but_makes_absence_unknown(client, app, auth_headers, github, intelligence):
    github.repo = FakeRepository({**REPO, "app/broken.py": "def broken(:\n    pass\n", "app/blob.py": b"\x7fELF\x00\x01\x02"})
    created = client.post("/api/projects", json={"name": "Demo", "repository_url": REPO_URL}, headers=auth_headers).json()
    start(client, app, auth_headers, created, "/analysis/dependencies")
    start(client, app, auth_headers, created, "/vulnerabilities/sync")
    job = analyse(client, app, auth_headers, created)
    assert job["state"] == "completed" and job["summary"]["source_complete"] is False
    assert job["summary"]["incomplete_reasons"] == [{"reason": "NOT_TEXT", "files": 1}, {"reason": "SYNTAX_ERROR", "files": 1}]
    body = findings(client, auth_headers, created)
    found = {k: (v["status"], v["reason"]) for k, v in by_advisory(body).items()}
    assert found["TEST-REQ-GET"] == ("REACHABLE", "PATH_FOUND")                               # what was found still stands
    assert found["TEST-REQ-SEND"] == ("UNKNOWN", "INCOMPLETE_SOURCE") and found["TEST-YAML-LOAD"] == ("UNKNOWN", "INCOMPLETE_SOURCE")
    files = {f["path"]: f for f in client.get(url(created, f"{BASE}/source/{body['snapshot']['id']}"), headers=auth_headers).json()["items"]}
    assert files["app/broken.py"]["parse_status"] == "SYNTAX_ERROR" and "line 1" in files["app/broken.py"]["parse_error"]
    assert files["app/blob.py"]["parse_status"] == "NOT_TEXT" and files["app/blob.py"]["discovered_symbols_count"] == 0


@pytest.mark.parametrize("settings", [{"REACHABILITY_MAX_FILE_BYTES": "2048"}], indirect=True)
def test_a_source_file_above_the_size_limit_is_not_fetched(client, app, auth_headers, github, intelligence):
    github.repo = FakeRepository({**REPO, "app/huge.py": "x = 1\n" * 1000})
    created = client.post("/api/projects", json={"name": "Demo", "repository_url": REPO_URL}, headers=auth_headers).json()
    start(client, app, auth_headers, created, "/analysis/dependencies")
    start(client, app, auth_headers, created, "/vulnerabilities/sync")
    before = len(blob_requests(github))
    job = analyse(client, app, auth_headers, created)
    assert job["state"] == "completed" and job["summary"]["incomplete_reasons"] == [{"reason": "SKIPPED_TOO_LARGE", "files": 1}]
    assert github.repo.blob_id("app/huge.py") not in {r.url.path.rsplit("/", 1)[-1] for r in blob_requests(github)[before:]}
    assert by_advisory(findings(client, auth_headers, created))["TEST-REQ-SEND"]["status"] == "UNKNOWN"


@pytest.mark.parametrize("settings", [{"REACHABILITY_MAX_FILE_BYTES": "2048"}], indirect=True)
def test_a_file_larger_than_the_listing_claimed_is_cut_off_at_the_limit(client, app, auth_headers, github, intelligence):
    github.repo = FakeRepository({**REPO, "app/liar.py": "x = 1\n" * 1000})
    github.repo.listed_sizes["app/liar.py"] = 10
    created = client.post("/api/projects", json={"name": "Demo", "repository_url": REPO_URL}, headers=auth_headers).json()
    start(client, app, auth_headers, created, "/analysis/dependencies")
    start(client, app, auth_headers, created, "/vulnerabilities/sync")
    job = analyse(client, app, auth_headers, created)
    assert job["state"] == "completed" and job["summary"]["incomplete_reasons"] == [{"reason": "SKIPPED_TOO_LARGE", "files": 1}]


@pytest.mark.parametrize("settings", [{"REACHABILITY_MAX_FILES": "2"}, {"REACHABILITY_MAX_TOTAL_BYTES": "1024", "REACHABILITY_MAX_FILE_BYTES": "1024"}],
                         indirect=True)
def test_file_count_and_total_size_limits_bound_the_work_and_are_reported(client, app, auth_headers, github, intelligence, settings):
    filler = {f"app/extra{i}.py": "value = 1\n" * 30 for i in range(6)}
    github.repo = FakeRepository({**REPO, **filler})
    created = client.post("/api/projects", json={"name": "Demo", "repository_url": REPO_URL}, headers=auth_headers).json()
    start(client, app, auth_headers, created, "/analysis/dependencies")
    start(client, app, auth_headers, created, "/vulnerabilities/sync")
    before = len(blob_requests(github))
    job = analyse(client, app, auth_headers, created)
    reason = "SKIPPED_FILE_LIMIT" if settings.reachability_max_files == 2 else "SKIPPED_SIZE_LIMIT"
    assert job["state"] == "completed" and [r["reason"] for r in job["summary"]["incomplete_reasons"]] == [reason]
    fetched = len(blob_requests(github)) - before
    assert fetched == job["summary"]["source"]["files_analysed"] and (fetched == 2 if reason == "SKIPPED_FILE_LIMIT" else fetched < 11)
    assert job["summary"]["source_complete"] is False


def test_paths_outside_the_repository_never_reach_the_analyser(client, app, auth_headers, github, intelligence, db):
    github.repo = FakeRepository(REPO)
    sha = github.repo.blob_id("app/client.py")
    github.repo.extra_entries = [{"path": p, "mode": "100644", "type": "blob", "sha": sha, "size": 10}
                                 for p in ("../../etc/shadow.py", "/abs/x.py", "app/../../y.py", "app\\z.py")]
    github.repo.extra_entries.append({"path": "link.py", "mode": "120000", "type": "blob", "sha": sha, "size": 10})
    created = client.post("/api/projects", json={"name": "Demo", "repository_url": REPO_URL}, headers=auth_headers).json()
    start(client, app, auth_headers, created, "/analysis/dependencies")
    start(client, app, auth_headers, created, "/vulnerabilities/sync")
    assert analyse(client, app, auth_headers, created)["state"] == "completed"
    paths = {f["path"] for f in db.source_files.find({})}
    assert paths == {p for p in REPO if p.endswith(".py")}
    assert all(not r.url.path.count("..") for r in github.requests)


def test_hostile_source_is_parsed_not_run(client, app, auth_headers, github, intelligence, tmp_path, monkeypatch):
    marker = tmp_path / "executed"
    monkeypatch.chdir(tmp_path)
    hostile = f"import os, subprocess\nopen({str(marker)!r}, 'w').write('x')\nos.system('touch {marker}')\nsubprocess.run(['touch', {str(marker)!r}])\n"
    github.repo = FakeRepository({**REPO, "setup.py": hostile, "app/__init__.py": hostile, "conftest.py": hostile})
    created = client.post("/api/projects", json={"name": "Demo", "repository_url": REPO_URL}, headers=auth_headers).json()
    start(client, app, auth_headers, created, "/analysis/dependencies")
    start(client, app, auth_headers, created, "/vulnerabilities/sync")
    assert analyse(client, app, auth_headers, created)["state"] == "completed"
    assert not marker.exists()


def test_hostile_strings_in_source_are_stored_bounded_and_as_text(client, app, auth_headers, github, intelligence, db):
    nasty = "import requests\n\n\ndef f():\n    return requests.get('<script>alert(1)</script>" + "A" * 9000 + "')\n"
    github.repo = FakeRepository({**REPO, "app/nasty.py": nasty})
    created = client.post("/api/projects", json={"name": "Demo", "repository_url": REPO_URL}, headers=auth_headers).json()
    start(client, app, auth_headers, created, "/analysis/dependencies")
    start(client, app, auth_headers, created, "/vulnerabilities/sync")
    assert analyse(client, app, auth_headers, created)["state"] == "completed"
    edge = db.code_edges.find_one({"source": "app.nasty:f", "kind": "calls"})
    assert len(edge["evidence"]["text"]) == 200 and edge["evidence"]["text"].startswith("return requests.get('<script>")


# --- idempotency ----------------------------------------------------------------------------

def test_running_again_replaces_the_results_and_reuses_the_parsed_source(client, app, auth_headers, project, github, db):
    first = analyse(client, app, auth_headers, project)
    counts = {name: db[name].count_documents({}) for name in ("source_files", "source_symbols", "code_edges", "code_reachability", "reachability_analyses")}
    ids = sorted(str(f["match_id"]) for f in db.code_reachability.find({}))
    requests_before = len(github.requests)
    second = analyse(client, app, auth_headers, project)
    assert second["state"] == "completed" and second["summary"]["source_reused"] is True and first["summary"]["source_reused"] is False
    assert len(github.requests) == requests_before                                             # no GitHub request at all
    assert {name: db[name].count_documents({}) for name in counts} == counts
    assert sorted(str(f["match_id"]) for f in db.code_reachability.find({})) == ids
    assert second["summary"]["by_status"] == first["summary"]["by_status"] and second["summary"]["graph"] == first["summary"]["graph"]
    assert second["summary"]["analysis_id"] == first["summary"]["analysis_id"]


def test_refresh_reads_the_source_again(client, app, auth_headers, project, github, db):
    analyse(client, app, auth_headers, project)
    before = len(blob_requests(github))
    job = analyse(client, app, auth_headers, project, {"refresh_source": True})
    assert job["summary"]["source_reused"] is False and len(blob_requests(github)) - before == 5
    assert db.reachability_analyses.count_documents({}) == 1 and db.source_files.count_documents({}) == 5


def test_findings_follow_a_new_vulnerability_check(client, app, auth_headers, project, intelligence):
    analyse(client, app, auth_headers, project)
    intelligence.add(advisory("TEST-REQ-POST", "requests", affected_functions=["requests.post"]))
    intelligence.report("PyPI", "requests", "2.19.1", "GHSA-x84v-xcm2-53pg", "TEST-REQ-GET", "TEST-REQ-SEND", "TEST-REQ-POST")
    assert start(client, app, auth_headers, project, "/vulnerabilities/sync")["state"] == "completed"
    stale = findings(client, auth_headers, project)
    assert "TEST-REQ-POST" not in by_advisory(stale)                                           # not analysed until the job runs again
    job = analyse(client, app, auth_headers, project)
    assert job["summary"]["source_reused"] is True and job["summary"]["findings"] == 6
    found = by_advisory(findings(client, auth_headers, project))
    assert sorted(found) == ["GHSA-35jh-r3h4-6jhm", "GHSA-x84v-xcm2-53pg", "TEST-REQ-GET", "TEST-REQ-POST", "TEST-REQ-SEND", "TEST-YAML-LOAD"]
    assert found["TEST-REQ-POST"]["status"] == "NOT_CONFIRMED_REACHABLE" and found["TEST-REQ-GET"]["status"] == "REACHABLE"


def test_a_new_commit_gets_its_own_analysis_and_old_parsed_source_is_removed(client, app, auth_headers, project, github, intelligence, db):
    analyse(client, app, auth_headers, project)
    old = db.reachability_analyses.find_one({})
    github.repo = FakeRepository({**REPO, "app/client.py": "import requests\n\n\ndef fetch(url):\n    return requests.post(url)\n"})
    assert start(client, app, auth_headers, project, "/analysis/dependencies")["state"] == "completed"
    assert findings(client, auth_headers, project)["items"] == []                              # nothing analysed for the new snapshot yet
    assert client.post(url(project, f"{BASE}/analyze"), headers=auth_headers).status_code == 409   # needs a vulnerability check first
    start(client, app, auth_headers, project, "/vulnerabilities/sync")
    job = analyse(client, app, auth_headers, project)
    assert job["summary"]["source_reused"] is False and job["summary"]["analysis_id"] != str(old["_id"])
    assert by_advisory(findings(client, auth_headers, project))["TEST-REQ-GET"]["status"] == "NOT_CONFIRMED_REACHABLE"
    assert db.source_files.count_documents({"analysis_id": old["_id"]}) == 0 and db.code_edges.count_documents({"analysis_id": old["_id"]}) == 0
    assert db.reachability_analyses.find_one({"_id": old["_id"]})["source_state"] == "REMOVED"
    assert db.code_reachability.count_documents({"analysis_id": old["_id"]}) == 5              # earlier findings are kept
    old_source = client.get(url(project, f"{BASE}/source/{old['snapshot_id']}"), headers=auth_headers).json()
    assert old_source["source_available"] is False and old_source["items"] == []


# --- operator mappings ----------------------------------------------------------------------

def test_an_operator_mapping_supplies_symbols_the_advisory_does_not_publish(client, auth_headers, github, osv, mongo, fake_redis, tmp_path):
    import httpx
    from fastapi.testclient import TestClient
    from app.main import create_app

    mapping = tmp_path / "symbols.json"
    mapping.write_text(json.dumps({"mappings": [{
        "advisory_id": "GHSA-x84v-xcm2-53pg", "ecosystem": "PyPI", "package": "requests", "symbols": ["requests.get"],
        "source_url": "https://github.com/psf/requests/pull/4718"}, {"advisory_id": "bad id", "symbols": []}]}))
    settings = load_settings({**TEST_ENV, "REACHABILITY_SYMBOL_MAPPINGS_FILE": str(mapping)})
    app = create_app(settings, mongo_client=mongo, redis_client=fake_redis, github_transport=httpx.MockTransport(github.handler),
                     provider_transport=httpx.MockTransport(osv.handler))
    github.repo = FakeRepository(REPO)
    osv.load("GHSA-x84v-xcm2-53pg")
    osv.report("PyPI", "requests", "2.19.1", "GHSA-x84v-xcm2-53pg")
    with TestClient(app) as local:
        created = local.post("/api/projects", json={"name": "Demo", "repository_url": REPO_URL}, headers=auth_headers).json()
        start(local, app, auth_headers, created, "/analysis/dependencies")
        start(local, app, auth_headers, created, "/vulnerabilities/sync")
        job = analyse(local, app, auth_headers, created)
        assert job["summary"]["operator_mappings"] == 1 and len(job["summary"]["operator_mapping_problems"]) == 1
        item = findings(local, auth_headers, created)["items"][0]
        # Reached, but never above MEDIUM: the mapping is the operator's, not the advisory's.
        assert (item["status"], item["confidence"], item["symbol_mapping"]) == ("REACHABLE", "MEDIUM", "OPERATOR_SUPPLIED")
        detail = local.get(url(created, f"{BASE}/{item['id']}"), headers=auth_headers).json()
        assert detail["matched_symbol"]["origin"] == "https://github.com/psf/requests/pull/4718" and detail["matched_symbol"]["match"] == "EXACT"
        assert any("operator-supplied" in note for note in detail["inferred"]["notes"])


# --- failures -------------------------------------------------------------------------------

def test_github_rate_limit_fails_the_job_with_the_reset_time_and_can_be_retried(client, app, auth_headers, project, github, db):
    github.fail_paths["/git/blobs/"] = (403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1893456000"})
    job = analyse(client, app, auth_headers, project)
    assert job["state"] == "failed" and job["error"]["code"] == "RATE_LIMITED" and job["error"]["retry_at"].startswith("2030-01-01")
    body = findings(client, auth_headers, project)
    assert body["analysis"] is None and body["items"] == [] and db.code_reachability.count_documents({}) == 0
    assert db.projects.find_one({})["active_job_id"] is None
    entry = db.audit_logs.find_one({"action": "job.code_reachability_analysis.finish"})
    assert entry["outcome"] == "failure" and entry["details"]["error_code"] == "RATE_LIMITED"
    github.fail_paths.clear()
    assert analyse(client, app, auth_headers, project)["state"] == "completed"
    assert findings(client, auth_headers, project)["total"] == 5


def test_tampered_file_content_fails_the_job(client, app, auth_headers, project, github):
    github.repo.tamper.add("app/client.py")
    job = analyse(client, app, auth_headers, project)
    assert job["state"] == "failed" and job["error"]["code"] == "INTEGRITY_MISMATCH"
    assert findings(client, auth_headers, project)["items"] == []


def test_the_time_limit_stops_the_job(client, app, auth_headers, project, monkeypatch):
    from app.services import jobs
    clock = iter(range(0, 10_000_000, 1000))
    monkeypatch.setattr(jobs.time, "monotonic", lambda: next(clock))
    job = analyse(client, app, auth_headers, project)
    assert job["state"] == "failed" and job["error"]["code"] == "TIMEOUT" and "600 seconds" in job["error"]["message"]
    monkeypatch.undo()
    assert findings(client, auth_headers, project)["items"] == []


def test_an_internal_error_is_reported_without_details_and_releases_the_project(client, app, auth_headers, project, db, monkeypatch):
    from app.services import reachability

    def explode(*_args, **_kwargs):
        raise RuntimeError("secret internal detail")
    monkeypatch.setattr(reachability, "build_graph", explode)
    job = analyse(client, app, auth_headers, project)
    assert job["state"] == "failed" and job["error"]["code"] == "INTERNAL_ERROR" and "secret" not in json.dumps(job)
    assert db.projects.find_one({})["active_job_id"] is None and findings(client, auth_headers, project)["items"] == []
    monkeypatch.undo()
    assert analyse(client, app, auth_headers, project)["state"] == "completed"


def test_a_project_deleted_before_the_job_runs_fails_cleanly(client, app, auth_headers, project, db):
    assert client.post(url(project, f"{BASE}/analyze"), headers=auth_headers).status_code == 202
    db.projects.delete_one({})
    assert run_worker(app) == 1
    assert db.analysis_jobs.find_one({"type": "code_reachability_analysis"})["error"]["code"] == "PROJECT_NOT_FOUND"


def test_deleting_a_project_removes_its_reachability_data(client, app, auth_headers, project, db):
    analyse(client, app, auth_headers, project)
    assert client.delete(url(project), headers=auth_headers).status_code in (200, 204)
    for name in ("source_files", "source_symbols", "code_edges", "code_reachability", "reachability_analyses"):
        assert db[name].count_documents({}) == 0, name
    assert db.vulnerabilities.count_documents({}) > 0                                           # shared advisory data is kept


def test_jobs_endpoint_lists_the_new_job_type(client, app, auth_headers, project):
    analyse(client, app, auth_headers, project)
    body = client.get(url(project, "/jobs"), headers=auth_headers, params={"type": "code_reachability_analysis"}).json()
    assert [j["type"] for j in body["items"]] == ["code_reachability_analysis"] and body["active"] is None


# --- review findings ------------------------------------------------------------------------

def test_a_failed_refresh_leaves_the_previous_results_in_place(client, app, auth_headers, project, github, db):
    analyse(client, app, auth_headers, project)
    before = {name: db[name].count_documents({}) for name in ("source_files", "source_symbols", "code_edges", "code_reachability")}
    github.fail_paths["/git/blobs/"] = (403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1893456000"})
    job = analyse(client, app, auth_headers, project, {"refresh_source": True})
    assert job["state"] == "failed" and job["error"]["code"] == "RATE_LIMITED"
    record = db.reachability_analyses.find_one({})
    assert (record["state"], record["source_state"]) == ("COMPLETE", "COMPLETE")
    body = findings(client, auth_headers, project)
    assert body["analysis"] is not None and body["total"] == 5 and body["job"]["state"] == "failed"
    assert {name: db[name].count_documents({}) for name in before} == before
    github.fail_paths.clear()
    assert analyse(client, app, auth_headers, project)["summary"]["source_reused"] is True


def test_an_interrupted_replacement_of_stored_source_is_rebuilt_not_reused(client, app, auth_headers, project, github, db, monkeypatch):
    from app.services import reachability
    analyse(client, app, auth_headers, project)
    original = reachability._store_source

    def interrupted(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("worker died")
    monkeypatch.setattr(reachability, "_store_source", interrupted)
    assert analyse(client, app, auth_headers, project, {"refresh_source": True})["state"] == "failed"
    assert db.reachability_analyses.find_one({})["source_state"] == "REBUILDING"
    monkeypatch.undo()
    before = len(blob_requests(github))
    job = analyse(client, app, auth_headers, project)
    assert job["state"] == "completed" and job["summary"]["source_reused"] is False and len(blob_requests(github)) - before == 5
    assert db.reachability_analyses.find_one({})["source_state"] == "COMPLETE"


def test_a_notebook_in_the_repository_makes_absence_unknown(client, app, auth_headers, github, intelligence):
    github.repo = FakeRepository({**REPO, "notebooks/explore.ipynb": '{"cells": []}'})
    created = client.post("/api/projects", json={"name": "Demo", "repository_url": REPO_URL}, headers=auth_headers).json()
    start(client, app, auth_headers, created, "/analysis/dependencies")
    start(client, app, auth_headers, created, "/vulnerabilities/sync")
    job = analyse(client, app, auth_headers, created)
    assert job["summary"]["incomplete_reasons"] == [{"reason": "SKIPPED_UNSUPPORTED_FORMAT", "files": 1}]
    found = by_advisory(findings(client, auth_headers, created))
    assert found["TEST-REQ-SEND"]["status"] == "UNKNOWN" and found["TEST-REQ-GET"]["status"] == "REACHABLE"


def test_a_reused_graph_gives_exactly_the_same_findings(client, app, auth_headers, project, db):
    analyse(client, app, auth_headers, project)
    strip = lambda doc: {k: v for k, v in doc.items() if k not in ("_id", "job_id", "analyzed_at")}  # noqa: E731
    first = [strip(d) for d in db.code_reachability.find({}).sort("advisory_id", 1)]
    analyse(client, app, auth_headers, project)
    assert [strip(d) for d in db.code_reachability.find({}).sort("advisory_id", 1)] == first
