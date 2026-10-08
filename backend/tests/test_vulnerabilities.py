"""Vulnerability intelligence end to end: API -> job -> worker -> provider -> storage -> matching -> API.

Advisory records are real public advisories from tests/fixtures/osv, served by
a local stand-in for the OSV API; ids starting with TEST- are synthetic records
written for a specific edge case. No test contacts the network.
"""

import json

import httpx
import pytest
from bson import ObjectId
from fastapi.testclient import TestClient

from app.config.settings import load_settings
from app.main import create_app
from tests.conftest import TEST_ENV, FakeRepository, load_tree, register, run_worker

REPO_URL = "https://github.com/octo/vulnerable-demo"
POM = """<project><modelVersion>4.0.0</modelVersion><groupId>demo</groupId><artifactId>svc</artifactId><version>1</version>
<dependencies>
  <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>
  <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>31.1-jre</version></dependency>
</dependencies></project>"""
REPO = {
    "api/requirements.txt": "requests==2.19.1\npython-jose==3.5.0\nflask>=2.0\n",
    "api/app.py": "import requests\n" * 50,
    "web/package.json": json.dumps({"name": "web", "dependencies": {"xlsx": "^0.18.5", "left": "^1.0.0"}}),
    "web/package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "web", "dependencies": {"xlsx": "^0.18.5", "left": "^1.0.0"}},
        "node_modules/xlsx": {"version": "0.18.5", "integrity": "sha512-dmg3LCjBPHZnQp5/F/+nnTa+miPJxUXB6vtk42YjBBKayDNagxGEeIdWApkYPOf3Z3pm3k62Knjzp7lMeTEtFQ=="},
        "node_modules/left": {"version": "1.0.0", "dependencies": {"lodash": "^4.17.0"}},
        "node_modules/lodash": {"version": "4.17.20"}}}),
    "svc/go.mod": "module example.com/svc\n\ngo 1.22\n\nrequire golang.org/x/crypto v0.30.0\n",
    "java/pom.xml": POM,
    "native/vcpkg.json": json.dumps({"name": "native", "dependencies": ["zlib"], "overrides": [{"name": "zlib", "version": "1.3.1"}]}),
}
GUAVA_ADVISORY = {
    "id": "TEST-GUAVA-0001", "modified": "2024-01-01T00:00:00Z", "summary": "Synthetic advisory for an unorderable version",
    "affected": [{"package": {"ecosystem": "Maven", "name": "com.google.guava:guava"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "32.0.0-android"}]}]}],
}
REAL = ["GHSA-x84v-xcm2-53pg", "PYSEC-2018-28", "GHSA-4r6h-8v6p-xvw6", "GHSA-5pgg-2g8v-p4x9", "GHSA-35jh-r3h4-6jhm",
        "GHSA-v778-237x-gjrc", "GHSA-jfh8-c2jp-5v3q"]
BASE = "/vulnerabilities"
ENDPOINTS = [("post", "/vulnerabilities/sync"), ("post", "/vulnerabilities/analyze"), ("get", "/vulnerabilities"),
             ("get", f"/vulnerabilities/{ObjectId()}"), ("get", "/jobs")]


@pytest.fixture
def repo(github):
    github.repo = FakeRepository(REPO)
    return github.repo


@pytest.fixture
def intelligence(osv):
    """What the provider reports for this repository's package versions."""
    osv.load(*REAL)
    osv.add(GUAVA_ADVISORY)
    osv.report("PyPI", "requests", "2.19.1", "GHSA-x84v-xcm2-53pg", "PYSEC-2018-28")
    osv.report("npm", "xlsx", "0.18.5", "GHSA-4r6h-8v6p-xvw6", "GHSA-5pgg-2g8v-p4x9")
    osv.report("npm", "lodash", "4.17.20", "GHSA-35jh-r3h4-6jhm")
    osv.report("Go", "golang.org/x/crypto", "0.30.0", "GHSA-v778-237x-gjrc")
    osv.report("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", "GHSA-jfh8-c2jp-5v3q")
    osv.report("Maven", "com.google.guava:guava", "31.1-jre", "TEST-GUAVA-0001")
    return osv


@pytest.fixture
def project(client, app, auth_headers, repo):
    created = client.post("/api/projects", json={"name": "Demo", "repository_url": REPO_URL}, headers=auth_headers).json()
    assert client.post(f"/api/projects/{created['id']}/analysis/dependencies", headers=auth_headers).status_code == 202
    assert run_worker(app) == 1
    return created


def url(project, path=""):
    return f"/api/projects/{project['id']}{path}"


def run(client, app, headers, project, action="sync", body=None):
    response = client.post(url(project, f"{BASE}/{action}"), headers=headers, json=body)
    assert response.status_code == 202, response.text
    assert run_worker(app) == 1
    return client.get(url(project, "/jobs"), headers=headers).json()["items"][0]


def matches(client, headers, project, **params):
    response = client.get(url(project, BASE), headers=headers, params=params)
    assert response.status_code == 200, response.text
    return response.json()


def pairs(body, status="AFFECTED"):
    return sorted((m["dependency_node_id"], m["source_id"]) for m in body["items"] if m["match_status"] == status)


# --- access control -------------------------------------------------------------------------

@pytest.mark.parametrize("method,path", ENDPOINTS)
def test_endpoints_require_authentication(client, method, path):
    assert getattr(client, method)(f"/api/projects/{ObjectId()}{path}").status_code == 401


@pytest.mark.parametrize("method,path", ENDPOINTS)
def test_another_users_project_is_not_found(client, auth_headers, other_headers, project, method, path):
    assert getattr(client, method)(url(project, path), headers=other_headers).status_code == 404


@pytest.mark.parametrize("project_id", ["nope", "../x", str(ObjectId())])
def test_unknown_projects_are_404(client, auth_headers, project_id):
    assert client.post(f"/api/projects/{project_id}/vulnerabilities/sync", headers=auth_headers).status_code == 404
    assert client.get(f"/api/projects/{project_id}/vulnerabilities", headers=auth_headers).status_code == 404


@pytest.mark.parametrize("match_id", ["nope", "../x", str(ObjectId()), "{'$ne': 1}"])
def test_unknown_or_malformed_match_ids_are_404(client, auth_headers, project, match_id):
    assert client.get(url(project, f"{BASE}/{match_id}"), headers=auth_headers).status_code == 404


def test_a_match_cannot_be_read_through_another_project(client, app, auth_headers, other_headers, project, intelligence):
    run(client, app, auth_headers, project)
    match_id = matches(client, auth_headers, project)["items"][0]["id"]
    theirs = client.post("/api/projects", json={"name": "Other", "repository_url": REPO_URL}, headers=other_headers).json()
    assert client.get(url(theirs, f"{BASE}/{match_id}"), headers=other_headers).status_code == 404
    assert client.get(url(project, f"{BASE}/{match_id}"), headers=auth_headers).status_code == 200


def test_provider_endpoints_require_authentication(client):
    assert client.get("/api/vulnerability-providers").status_code == 401
    assert client.post("/api/vulnerability-providers/osv/health-check").status_code == 401


# --- before anything has run ------------------------------------------------------------------

def test_jobs_need_a_dependency_inventory(client, auth_headers, github):
    github.repo = FakeRepository(REPO)
    fresh = client.post("/api/projects", json={"name": "Fresh", "repository_url": REPO_URL}, headers=auth_headers).json()
    for action in ("sync", "analyze"):
        response = client.post(url(fresh, f"{BASE}/{action}"), headers=auth_headers)
        assert response.status_code == 409 and "dependency analysis first" in response.json()["detail"]
    body = matches(client, auth_headers, fresh)
    assert body["items"] == [] and body["total"] == 0 and body["snapshot"] is None and body["scan"] is None and body["job"] is None


def test_no_findings_are_shown_before_a_scan(client, auth_headers, project):
    body = matches(client, auth_headers, project)
    assert body["items"] == [] and body["scan"] is None and body["sync"] is None and body["job"] is None
    assert body["snapshot"]["commit_sha"]


# --- synchronisation and matching ---------------------------------------------------------------

def test_sync_job_runs_in_the_worker_and_reports_progress(client, app, auth_headers, project, intelligence, db):
    response = client.post(url(project, f"{BASE}/sync"), headers=auth_headers)
    assert response.status_code == 202
    queued = response.json()["job"]
    assert (queued["type"], queued["state"], queued["stage"]) == ("vulnerability_sync", "queued", "QUEUED")
    assert queued["stages"] == ["PROVIDER_QUERY", "RECORD_INGESTION", "MATCHING"] and queued["started_at"] is None
    assert matches(client, auth_headers, project)["items"] == []           # nothing exists until the worker has run
    assert client.get(url(project, "/jobs"), headers=auth_headers).json()["active"]["id"] == queued["id"]

    assert run_worker(app) == 1
    listing = client.get(url(project, "/jobs"), headers=auth_headers).json()
    job = listing["items"][0]
    assert listing["active"] is None
    assert (job["state"], job["stage"], job["stage_index"], job["stage_count"]) == ("completed", "COMPLETED", 4, 4)
    assert job["started_at"] and job["finished_at"] and job["error"] is None
    assert job["summary"]["affected_matches"] == 7 and job["sync_id"]

    sync = db.vulnerability_syncs.find_one({})
    assert (sync["provider"], sync["status"]) == ("osv", "completed")
    assert sync["started_at"] <= sync["completed_at"]
    assert (sync["records_seen"], sync["records_inserted"], sync["records_updated"], sync["records_failed"]) == (8, 8, 0, 0)
    assert sync["dependencies_total"] == 10 and sync["packages_queried"] == 8
    assert sync["packages_unresolved"] == 1 and sync["packages_unsupported"] == 1          # flask>=2.0; vcpkg zlib
    assert sync["error_summary"] is None and sync["provider_requests"] == 1
    source = db.vulnerability_sources.find_one({"name": "osv"})
    assert source["last_sync_status"] == "completed" and source["base_url"] == "https://api.osv.dev"


def test_matches_are_exactly_the_versions_inside_published_ranges(client, app, auth_headers, project, intelligence):
    run(client, app, auth_headers, project)
    body = matches(client, auth_headers, project)
    assert pairs(body) == [
        ("golang:golang.org/x/crypto@v0.30.0", "GHSA-v778-237x-gjrc"),
        ("maven:org.apache.logging.log4j:log4j-core@2.14.1", "GHSA-jfh8-c2jp-5v3q"),
        ("npm:lodash@4.17.20", "GHSA-35jh-r3h4-6jhm"),
        ("npm:xlsx@0.18.5", "GHSA-4r6h-8v6p-xvw6"),
        ("npm:xlsx@0.18.5", "GHSA-5pgg-2g8v-p4x9"),
        ("pypi:requests@2.19.1", "GHSA-x84v-xcm2-53pg"),
        ("pypi:requests@2.19.1", "PYSEC-2018-28"),
    ]
    assert pairs(body, "UNSUPPORTED") == [("maven:com.google.guava:guava@31.1-jre", "TEST-GUAVA-0001")]
    scan = body["scan"]
    assert scan["affected_matches"] == 7 and scan["affected_dependencies"] == 5
    assert scan["distinct_vulnerabilities"] == 6                           # the GHSA and PYSEC records share CVE-2018-18074
    assert scan["unsupported_matches"] == 1 and scan["conflict_matches"] == 0
    assert scan["by_severity"] == {"CRITICAL": 2, "HIGH": 4, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 1}
    assert scan["dependencies_total"] == 10 and scan["dependencies_unresolved"] == 1
    assert scan["dependencies_unsupported_ecosystem"] == 1 and scan["unsupported_ecosystems"] == {"vcpkg": 1}
    assert scan["dependencies_checked"] == 8 and scan["advisories_considered"] == 8
    assert scan["intelligence"]["status"] == "completed" and scan["intelligence"]["provider"] == "osv"
    assert scan["reported_but_not_stored_count"] == 0
    # Most severe first.
    assert [m["severity"] for m in body["items"]][:2] == ["CRITICAL", "CRITICAL"] and body["items"][-1]["severity"] == "UNKNOWN"


def test_every_match_answers_source_observed_match_and_evidence(client, app, auth_headers, project, intelligence):
    run(client, app, auth_headers, project)
    for item in matches(client, auth_headers, project)["items"]:
        detail = client.get(url(project, f"{BASE}/{item['id']}"), headers=auth_headers).json()
        match, advisory = detail["match"], detail["vulnerability"]
        evidence = match["evidence"]
        # SOURCE: where the information came from
        assert evidence["source"]["provider"] == "osv" and evidence["source"]["source_id"] == match["source_id"] == advisory["source_id"]
        assert evidence["source"]["url"] == f"https://osv.dev/vulnerability/{match['source_id']}"
        assert len(evidence["source"]["record_sha256"]) == 64 and evidence["source"]["retrieved_at"]
        # OBSERVED: what was found in the repository
        observed = evidence["observed"]
        assert observed["installed_version"] == match["matched_version"] and observed["ecosystem"] == match["ecosystem"]
        assert observed["declared_in"] and all(d["source_file"] for d in observed["declared_in"])
        assert observed["version_basis"] == "OBSERVED"
        # MATCH: why the dependency matches (or why that could not be decided)
        assert evidence["match"]["explanation"] and evidence["match"]["provider_reported"] is True
        assert match["confidence_meaning"] and match["matcher_version"] and match["matched_at"]
        if match["match_status"] == "AFFECTED":
            assert match["classification"] == "OBSERVED" and match["confidence"] == "HIGH"
            assert evidence["evidence_type"] in ("version_range_match", "version_listed_by_source")
            assert match["affected_range"] and evidence["match"]["comparator"]
        else:
            assert match["confidence"] == "UNDETERMINED"
        assert "raw" not in advisory and advisory["affected"]


def test_range_evidence_names_the_boundaries_and_the_fixed_version(client, app, auth_headers, project, intelligence):
    run(client, app, auth_headers, project)
    item = next(m for m in matches(client, auth_headers, project, q="GHSA-x84v")["items"] if m["source_id"] == "GHSA-x84v-xcm2-53pg")
    assert (item["package_name"], item["matched_version"], item["affected_range"], item["fixed_version"]) == \
        ("requests", "2.19.1", "< 2.20.0", "2.20.0")
    assert item["severity"] == "HIGH" and item["severity_source"] == "source_label" and item["cvss"][0]["base_score"] == 7.5
    assert item["aliases"] == ["CVE-2018-18074"] and item["group_key"] == "CVE-2018-18074"
    evidence = client.get(url(project, f"{BASE}/{item['id']}"), headers=auth_headers).json()["match"]["evidence"]
    assert evidence["evidence_type"] == "version_range_match"
    assert evidence["match"] | {"explanation": None} == {
        "comparator": "pep440", "range_type": "ECOSYSTEM", "affected_range": "< 2.20.0", "introduced": "0", "fixed": "2.20.0",
        "last_affected": None, "limit": None, "events": [{"introduced": "0"}, {"fixed": "2.20.0"}],
        "version_listed_by_source": False, "provider_reported": True, "explanation": None, "source_range_note": "<= 2.19.1"}
    assert evidence["observed"]["declared_in"] == [
        {"source_file": "api/requirements.txt", "line": 1, "declaration": "requests==2.19.1", "file_kind": "manifest",
         "git_blob_sha": evidence["observed"]["declared_in"][0]["git_blob_sha"]}]
    assert len(evidence["observed"]["declared_in"][0]["git_blob_sha"]) == 40
    assert "2.19.1" in evidence["match"]["explanation"] and "< 2.20.0" in evidence["match"]["explanation"]


def test_missing_severity_is_shown_as_unknown_never_invented(client, app, auth_headers, project, intelligence):
    run(client, app, auth_headers, project)
    item, = matches(client, auth_headers, project, q="PYSEC-2018-28")["items"]
    assert (item["severity"], item["severity_source"], item["cvss"]) == ("UNKNOWN", None, None)
    assert item["match_status"] == "AFFECTED" and item["fixed_version"] == "2.20.0"
    evidence = client.get(url(project, f"{BASE}/{item['id']}"), headers=auth_headers).json()["match"]["evidence"]
    assert evidence["match"]["version_listed_by_source"] is True           # the record also lists 2.19.1 explicitly


def test_open_ended_range_has_no_fixed_version_and_keeps_the_sources_note(client, app, auth_headers, project, intelligence):
    run(client, app, auth_headers, project)
    item, = matches(client, auth_headers, project, q="GHSA-4r6h")["items"]
    assert item["fixed_version"] is None and item["fixed_versions"] == []
    assert item["affected_range"] == "all versions (no fixed version published)"
    evidence = client.get(url(project, f"{BASE}/{item['id']}"), headers=auth_headers).json()["match"]["evidence"]
    assert evidence["match"]["source_range_note"] == "< 0.19.3"


def test_transitive_dependencies_are_matched_with_their_depth(client, app, auth_headers, project, intelligence):
    run(client, app, auth_headers, project)
    item, = matches(client, auth_headers, project, q="lodash")["items"]
    assert (item["relationship"], item["depth"], item["matched_version"], item["fixed_version"]) == ("TRANSITIVE", 2, "4.17.20", "4.17.21")


def test_go_versions_are_compared_without_their_v_prefix(client, app, auth_headers, project, intelligence):
    run(client, app, auth_headers, project)
    item, = matches(client, auth_headers, project, ecosystem="golang")["items"]
    assert (item["matched_version"], item["fixed_version"], item["match_status"]) == ("v0.30.0", "0.31.0", "AFFECTED")


def test_unorderable_version_is_unsupported_not_reported_as_affected(client, app, auth_headers, project, intelligence):
    run(client, app, auth_headers, project)
    item, = matches(client, auth_headers, project, match_status="UNSUPPORTED")["items"]
    assert (item["package_name"], item["matched_version"], item["source_id"]) == ("com.google.guava:guava", "31.1-jre", "TEST-GUAVA-0001")
    assert item["confidence"] == "UNDETERMINED" and item["affected_range"] is None and item["fixed_version"] is None
    detail = client.get(url(project, f"{BASE}/{item['id']}"), headers=auth_headers).json()["match"]
    assert detail["evidence"]["evidence_type"] == "provider_report_only"
    assert "cannot be ordered" in detail["evidence"]["match"]["explanation"]


def test_unaffected_versions_produce_no_match(client, app, auth_headers, project, intelligence, db):
    # Advisories for python-jose are in the database (another project could have fetched them) ...
    intelligence.load("GHSA-6c5p-j8vq-pqhj", "GHSA-cjwg-qfpm-7377")
    intelligence.report("PyPI", "python-jose", "3.3.0", "GHSA-6c5p-j8vq-pqhj", "GHSA-cjwg-qfpm-7377")
    from app.collectors.providers.osv import normalize_osv
    for name in ("GHSA-6c5p-j8vq-pqhj", "GHSA-cjwg-qfpm-7377"):
        db.vulnerabilities.insert_one(normalize_osv(intelligence.records[name]))
    run(client, app, auth_headers, project)
    # ... but 3.5.0 is past the fixed version 3.4.0, so nothing is reported for it.
    assert matches(client, auth_headers, project, q="python-jose")["items"] == []
    assert db.vulnerabilities.count_documents({"affected.package_name": "python-jose"}) == 2


def test_provider_claim_that_local_evaluation_does_not_confirm_is_a_conflict(client, app, auth_headers, project, intelligence):
    intelligence.load("GHSA-6c5p-j8vq-pqhj")
    intelligence.report("PyPI", "python-jose", "3.5.0", "GHSA-6c5p-j8vq-pqhj")       # contradicts the record's own range
    job = run(client, app, auth_headers, project)
    assert job["summary"]["conflict_matches"] == 1 and job["summary"]["affected_matches"] == 7
    item, = matches(client, auth_headers, project, match_status="CONFLICT")["items"]
    assert (item["confidence"], item["matched_version"], item["affected_range"]) == ("LOW", "3.5.0", None)
    detail = client.get(url(project, f"{BASE}/{item['id']}"), headers=auth_headers).json()["match"]
    assert "outside the ranges published" in detail["evidence"]["match"]["explanation"]


def test_withdrawn_advisories_are_not_matched(client, app, auth_headers, project, intelligence):
    intelligence.records["GHSA-35jh-r3h4-6jhm"] = {**intelligence.records["GHSA-35jh-r3h4-6jhm"], "withdrawn": "2025-01-01T00:00:00Z"}
    job = run(client, app, auth_headers, project)
    assert job["summary"]["advisories_withdrawn_skipped"] == 1 and job["summary"]["affected_matches"] == 6
    assert matches(client, auth_headers, project, q="lodash")["items"] == []


def test_filters_search_and_paging(client, app, auth_headers, project, intelligence):
    run(client, app, auth_headers, project)
    assert pairs(matches(client, auth_headers, project, severity="critical")) == [
        ("golang:golang.org/x/crypto@v0.30.0", "GHSA-v778-237x-gjrc"), ("maven:org.apache.logging.log4j:log4j-core@2.14.1", "GHSA-jfh8-c2jp-5v3q")]
    assert matches(client, auth_headers, project, severity="LOW")["total"] == 0
    assert matches(client, auth_headers, project, ecosystem="npm")["total"] == 3
    assert matches(client, auth_headers, project, match_status="AFFECTED")["total"] == 7
    assert matches(client, auth_headers, project, q="CVE-2018-18074")["total"] == 2            # found through aliases
    assert matches(client, auth_headers, project, q="XLSX")["total"] == 2
    assert matches(client, auth_headers, project, q=".*")["total"] == 0                        # literal text, not a pattern
    first = matches(client, auth_headers, project, limit=3)
    rest = matches(client, auth_headers, project, limit=3, skip=3)
    assert first["total"] == 8 and len(first["items"]) == 3 and len(rest["items"]) == 3
    assert not {m["id"] for m in first["items"]} & {m["id"] for m in rest["items"]}
    assert "evidence" not in first["items"][0]                                                 # the list stays light
    for params in ({"severity": "terrible"}, {"match_status": "MAYBE"}, {"ecosystem": "N P M"}, {"limit": 0}, {"limit": 501}, {"skip": -1}):
        assert client.get(url(project, BASE), headers=auth_headers, params=params).status_code == 422


def test_raw_source_record_is_available_on_request(client, app, auth_headers, project, intelligence):
    run(client, app, auth_headers, project)
    item = next(m for m in matches(client, auth_headers, project, q="GHSA-x84v")["items"] if m["source_id"] == "GHSA-x84v-xcm2-53pg")
    detail = client.get(url(project, f"{BASE}/{item['id']}"), headers=auth_headers, params={"include_raw": "true"}).json()
    assert detail["vulnerability"]["raw"] == intelligence.records["GHSA-x84v-xcm2-53pg"]
    assert detail["vulnerability"]["first_seen_at"] and detail["vulnerability"]["ingested_at"] and detail["vulnerability"]["normalized_at"]


# --- idempotency -------------------------------------------------------------------------------

def test_repeating_a_sync_creates_no_duplicates_and_keeps_first_seen(client, app, auth_headers, project, intelligence, db):
    run(client, app, auth_headers, project)
    before = {v["source_id"]: v for v in db.vulnerabilities.find({})}
    fetches = len(intelligence.calls("/v1/vulns/"))
    match_ids = {m["id"] for m in matches(client, auth_headers, project)["items"]}

    job = run(client, app, auth_headers, project)
    assert job["state"] == "completed"
    after = {v["source_id"]: v for v in db.vulnerabilities.find({})}
    assert set(after) == set(before) and db.vulnerabilities.count_documents({}) == 8
    assert all(after[k]["_id"] == before[k]["_id"] and after[k]["first_seen_at"] == before[k]["first_seen_at"] for k in before)
    assert all(after[k]["last_seen_at"] >= before[k]["last_seen_at"] for k in before)
    assert all(after[k]["published_at"] == before[k]["published_at"] and after[k]["modified_at"] == before[k]["modified_at"] for k in before)
    assert len(intelligence.calls("/v1/vulns/")) == fetches                # unchanged records are not downloaded again
    latest = db.vulnerability_syncs.find_one(sort=[("started_at", -1), ("_id", -1)])
    assert (latest["records_seen"], latest["records_unchanged"], latest["records_inserted"], latest["records_updated"]) == (8, 8, 0, 0)
    assert db.vulnerability_syncs.count_documents({}) == 2                 # history of syncs is kept
    assert {m["id"] for m in matches(client, auth_headers, project)["items"]} == match_ids
    assert db.vulnerability_matches.count_documents({}) == 8


def test_a_record_modified_at_the_source_is_updated_in_place(client, app, auth_headers, project, intelligence, db):
    run(client, app, auth_headers, project)
    original = db.vulnerabilities.find_one({"source_id": "GHSA-x84v-xcm2-53pg"})
    intelligence.records["GHSA-x84v-xcm2-53pg"] = {**intelligence.records["GHSA-x84v-xcm2-53pg"],
                                                   "modified": "2026-01-01T00:00:00Z", "summary": "Updated summary"}
    run(client, app, auth_headers, project)
    updated = db.vulnerabilities.find_one({"source_id": "GHSA-x84v-xcm2-53pg"})
    assert updated["_id"] == original["_id"] and updated["first_seen_at"] == original["first_seen_at"]
    assert updated["summary"] == "Updated summary" and updated["source_modified"] == "2026-01-01T00:00:00Z"
    assert updated["raw_sha256"] != original["raw_sha256"] and updated["ingested_at"] > original["ingested_at"]
    latest = db.vulnerability_syncs.find_one(sort=[("started_at", -1), ("_id", -1)])
    assert (latest["records_updated"], latest["records_unchanged"], latest["records_inserted"]) == (1, 7, 0)


def test_matches_keep_their_first_matched_time_across_scans(client, app, auth_headers, project, intelligence, db):
    run(client, app, auth_headers, project)
    first = {m["_id"]: m["first_matched_at"] for m in db.vulnerability_matches.find({})}
    run(client, app, auth_headers, project, "analyze")
    again = {m["_id"]: (m["first_matched_at"], m["matched_at"]) for m in db.vulnerability_matches.find({})}
    assert set(again) == set(first)
    assert all(again[k][0] == first[k] and again[k][1] >= first[k] for k in first)


def test_matches_that_no_longer_hold_are_removed_on_the_next_scan(client, app, auth_headers, project, intelligence, db):
    run(client, app, auth_headers, project)
    assert matches(client, auth_headers, project, q="lodash")["total"] == 1
    intelligence.records["GHSA-35jh-r3h4-6jhm"] = {**intelligence.records["GHSA-35jh-r3h4-6jhm"],
                                                   "modified": "2026-02-02T00:00:00Z", "withdrawn": "2026-02-02T00:00:00Z"}
    run(client, app, auth_headers, project)
    assert matches(client, auth_headers, project, q="lodash")["total"] == 0
    assert db.vulnerabilities.find_one({"source_id": "GHSA-35jh-r3h4-6jhm"})["withdrawn_at"] is not None   # the record is kept


# --- matching without the network ----------------------------------------------------------------

def test_analyze_uses_stored_advisories_and_makes_no_provider_request(client, app, auth_headers, project, intelligence):
    run(client, app, auth_headers, project)
    requests_before = len(intelligence.requests)
    job = run(client, app, auth_headers, project, "analyze")
    assert (job["type"], job["state"], job["stages"]) == ("vulnerability_analysis", "completed", ["MATCHING"])
    assert job["summary"]["affected_matches"] == 7 and len(intelligence.requests) == requests_before


def test_analyze_without_any_stored_intelligence_finds_nothing_and_says_so(client, app, auth_headers, project, osv):
    job = run(client, app, auth_headers, project, "analyze")
    assert job["state"] == "completed" and job["summary"]["affected_matches"] == 0
    assert job["summary"]["intelligence"] is None and job["summary"]["advisories_considered"] == 0
    assert osv.requests == []
    assert matches(client, auth_headers, project)["sync"] is None


# --- provider failures ---------------------------------------------------------------------------

def test_provider_outage_fails_the_job_and_stores_no_findings(client, app, auth_headers, project, intelligence, db):
    intelligence.always_fail["/v1/querybatch"] = (503, {})
    job = run(client, app, auth_headers, project)
    assert job["state"] == "failed" and job["stage"] == "PROVIDER_QUERY"
    assert job["error"] == {"code": "PROVIDER_ERROR", "message": "OSV returned HTTP 503."}
    assert len(intelligence.calls("/v1/querybatch")) == 3                  # bounded retries
    sync = db.vulnerability_syncs.find_one({})
    assert sync["status"] == "failed" and sync["completed_at"] and sync["error_summary"] == "OSV returned HTTP 503."
    assert db.vulnerability_matches.count_documents({}) == 0 and db.vulnerabilities.count_documents({}) == 0
    body = matches(client, auth_headers, project)
    assert body["scan"] is None and body["sync"]["status"] == "failed" and body["items"] == []
    assert db.projects.find_one({})["active_job_id"] is None               # the project is free for another attempt


@pytest.mark.parametrize("failure,code", [((429, {"retry-after": "900"}), "PROVIDER_RATE_LIMITED"), ((500, {}), "PROVIDER_ERROR")])
def test_outage_while_fetching_records_fails_the_sync_but_keeps_what_was_fetched(client, app, auth_headers, project, intelligence, db, failure, code):
    original = intelligence.handler
    served = []

    def flaky(request):
        if "/v1/vulns/" in request.url.path:
            served.append(request.url.path)
            if len(served) > 3:
                intelligence.requests.append(request)
                return httpx.Response(failure[0], json={}, headers=failure[1])
        return original(request)

    app.state.providers["osv"].transport = httpx.MockTransport(flaky)
    job = run(client, app, auth_headers, project)
    assert job["state"] == "failed" and job["error"]["code"] == code
    assert ("retry_at" in job["error"]) == (code == "PROVIDER_RATE_LIMITED")
    sync = db.vulnerability_syncs.find_one({})
    assert sync["status"] == "failed" and sync["records_inserted"] == 3
    assert db.vulnerabilities.count_documents({}) == 3                     # nothing fetched is thrown away
    assert db.vulnerability_matches.count_documents({}) == 0               # but no findings are presented from a failed sync


def test_recovery_after_an_outage(client, app, auth_headers, project, intelligence, db):
    intelligence.fail["/v1/querybatch"] = [(503, {})] * 3
    assert run(client, app, auth_headers, project)["state"] == "failed"
    job = run(client, app, auth_headers, project)
    assert job["state"] == "completed" and job["summary"]["affected_matches"] == 7
    assert [s["status"] for s in db.vulnerability_syncs.find({}).sort([("started_at", 1), ("_id", 1)])] == ["failed", "completed"]


def test_transient_errors_within_the_retry_budget_do_not_fail_the_job(client, app, auth_headers, project, intelligence):
    intelligence.fail["/v1/querybatch"] = [(503, {}), (502, {})]
    intelligence.fail["/v1/vulns/"] = [(500, {})]
    assert run(client, app, auth_headers, project)["state"] == "completed"


def test_a_record_that_cannot_be_fetched_makes_the_sync_partial_not_successful(client, app, auth_headers, project, intelligence, db):
    del intelligence.records["GHSA-jfh8-c2jp-5v3q"]                        # reported by the provider, then 404
    job = run(client, app, auth_headers, project)
    assert job["state"] == "failed" and job["error"]["code"] == "SYNC_INCOMPLETE"
    assert "1 of 8" in job["error"]["message"] and "incomplete" in job["error"]["message"]
    sync = db.vulnerability_syncs.find_one({})
    assert sync["status"] == "partial" and (sync["records_seen"], sync["records_inserted"], sync["records_failed"]) == (8, 7, 1)
    assert sync["errors"] == [{"source_id": "GHSA-jfh8-c2jp-5v3q", "code": "NOT_FOUND", "message": "OSV has no record with that id."}]
    assert db.vulnerabilities.count_documents({}) == 7 and db.vulnerability_matches.count_documents({}) == 0

    # Matching can still be run on what is stored; the result states that the intelligence is incomplete.
    job = run(client, app, auth_headers, project, "analyze")
    summary = job["summary"]
    assert job["state"] == "completed" and summary["affected_matches"] == 6
    assert summary["intelligence"]["status"] == "partial" and summary["intelligence"]["records_failed"] == 1
    assert summary["reported_but_not_stored"] == [{"dependency": "maven:org.apache.logging.log4j:log4j-core@2.14.1",
                                                   "source_id": "GHSA-jfh8-c2jp-5v3q"}]
    assert matches(client, auth_headers, project)["sync"]["status"] == "partial"


@pytest.mark.parametrize("body,code", [
    (b'{"id": "SOMETHING-ELSE", "affected": []}', "MALFORMED_RECORD"),      # answers with a different record
    (b'{"id": "GHSA-x84v-xcm2-53pg", "affected": "all"}', "MALFORMED_RECORD"),
    (b"not json at all", "PROVIDER_BAD_RESPONSE"),
])
def test_malformed_records_are_counted_as_failures_not_stored(client, app, auth_headers, project, intelligence, db, body, code):
    intelligence.raw_bodies["GHSA-x84v-xcm2-53pg"] = body
    job = run(client, app, auth_headers, project)
    assert job["state"] == "failed" and job["error"]["code"] == "SYNC_INCOMPLETE"
    sync = db.vulnerability_syncs.find_one({})
    assert sync["status"] == "partial" and sync["errors"][0]["code"] == code and sync["errors"][0]["source_id"] == "GHSA-x84v-xcm2-53pg"
    assert db.vulnerabilities.count_documents({"source_id": {"$in": ["GHSA-x84v-xcm2-53pg", "SOMETHING-ELSE"]}}) == 0


def test_record_limit_is_enforced_and_reported(mongo, fake_redis, github, osv, repo, intelligence):
    settings = load_settings({**TEST_ENV, "VULNERABILITY_MAX_RECORDS": "3"})
    app = create_app(settings, mongo_client=mongo, redis_client=fake_redis, github_transport=httpx.MockTransport(github.handler),
                     provider_transport=httpx.MockTransport(osv.handler))
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {register(client).json()['access_token']}"}
        project = client.post("/api/projects", json={"name": "Demo", "repository_url": REPO_URL}, headers=headers).json()
        client.post(url(project, "/analysis/dependencies"), headers=headers)
        run_worker(app)
        job = run(client, app, headers, project)
    assert job["state"] == "failed" and job["error"]["code"] == "TOO_MANY_ADVISORIES"
    sync = mongo[settings.mongodb_db].vulnerability_syncs.find_one({})
    assert sync["status"] == "partial" and sync["records_seen"] == 8 and sync["records_inserted"] == 3


def test_no_provider_enabled(mongo, fake_redis, github, repo):
    settings = load_settings({**TEST_ENV, "VULNERABILITY_PROVIDERS": ""})
    app = create_app(settings, mongo_client=mongo, redis_client=fake_redis, github_transport=httpx.MockTransport(github.handler))
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {register(client).json()['access_token']}"}
        project = client.post("/api/projects", json={"name": "Demo", "repository_url": REPO_URL}, headers=headers).json()
        client.post(url(project, "/analysis/dependencies"), headers=headers)
        run_worker(app)
        response = client.post(url(project, f"{BASE}/sync"), headers=headers)
        assert response.status_code == 409 and "No vulnerability provider" in response.json()["detail"]
        assert client.get("/api/vulnerability-providers", headers=headers).json() == {"items": []}


# --- jobs ---------------------------------------------------------------------------------------

def test_one_job_at_a_time_per_project(client, app, auth_headers, project, intelligence):
    assert client.post(url(project, f"{BASE}/sync"), headers=auth_headers).status_code == 202
    for path in (f"{BASE}/sync", f"{BASE}/analyze", "/analysis/dependencies", "/sbom/generate"):
        response = client.post(url(project, path), headers=auth_headers)
        assert response.status_code == 409 and "already queued or running" in response.json()["detail"]
    assert run_worker(app) == 1
    assert client.post(url(project, f"{BASE}/analyze"), headers=auth_headers).status_code == 202


def test_jobs_listing_filters_by_type(client, app, auth_headers, project, intelligence):
    run(client, app, auth_headers, project)
    run(client, app, auth_headers, project, "analyze")
    everything = client.get(url(project, "/jobs"), headers=auth_headers).json()["items"]
    assert [j["type"] for j in everything] == ["vulnerability_analysis", "vulnerability_sync", "dependencies"]
    only = client.get(url(project, "/jobs"), headers=auth_headers, params={"type": "vulnerability_sync,dependencies"}).json()["items"]
    assert [j["type"] for j in only] == ["vulnerability_sync", "dependencies"]
    assert client.get(url(project, "/jobs"), headers=auth_headers, params={"limit": 1}).json()["items"][0]["type"] == "vulnerability_analysis"
    assert client.get(url(project, "/jobs"), headers=auth_headers, params={"type": "rm -rf"}).status_code == 422
    assert "owner_id" not in everything[0]


def test_a_crash_inside_a_job_is_recorded_as_failed_never_completed(client, app, auth_headers, project, intelligence, monkeypatch):
    from app.services import vulnerabilities

    def boom(*_a, **_k):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(vulnerabilities, "match_snapshot", boom)
    job = run(client, app, auth_headers, project)
    assert job["state"] == "failed" and job["error"]["code"] == "INTERNAL_ERROR"
    assert "secret internal detail" not in json.dumps(job)
    assert job["finished_at"] and client.get(url(project, "/jobs"), headers=auth_headers).json()["active"] is None


def test_project_deleted_while_a_job_is_queued(client, app, auth_headers, project, intelligence, db):
    client.post(url(project, f"{BASE}/sync"), headers=auth_headers)
    job_id = db.analysis_jobs.find_one({"type": "vulnerability_sync"})["_id"]
    db.projects.delete_many({})
    assert run_worker(app) == 1
    job = db.analysis_jobs.find_one({"_id": job_id})
    assert job["state"] == "failed" and job["error"]["code"] == "PROJECT_NOT_FOUND"


def test_job_requests_are_rate_limited(mongo, fake_redis, github, osv, repo):
    settings = load_settings({**TEST_ENV, "JOB_RATE_LIMIT": "2"})
    app = create_app(settings, mongo_client=mongo, redis_client=fake_redis, github_transport=httpx.MockTransport(github.handler),
                     provider_transport=httpx.MockTransport(osv.handler))
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {register(client).json()['access_token']}"}
        project = client.post("/api/projects", json={"name": "Demo", "repository_url": REPO_URL}, headers=headers).json()
        codes = [client.post(url(project, f"{BASE}/sync"), headers=headers).status_code for _ in range(4)]
        assert codes == [409, 409, 429, 429]                               # the first two are refused for lack of an inventory
        limited = client.post("/api/vulnerability-providers/osv/health-check", headers=headers)
        assert limited.status_code == 429 and int(limited.headers["retry-after"]) >= 1


# --- a request cannot choose where the platform connects -------------------------------------------

@pytest.mark.parametrize("body", [
    {"url": "https://evil.example"}, {"provider": "osv", "base_url": "http://169.254.169.254"}, {"api_url": "file:///etc/passwd"},
    {"provider": "osv", "endpoint": "https://evil.example/v1"},
])
def test_requests_cannot_supply_a_provider_url(client, auth_headers, project, osv, body):
    response = client.post(url(project, f"{BASE}/sync"), headers=auth_headers, json=body)
    assert response.status_code == 422 and osv.requests == []


@pytest.mark.parametrize("name", ["https://evil.example", "nvd", "../osv", "osv?x=1", "169.254.169.254"])
def test_unknown_provider_names_are_rejected(client, auth_headers, project, osv, name):
    response = client.post(url(project, f"{BASE}/sync"), headers=auth_headers, json={"provider": name})
    assert response.status_code == 422 and osv.requests == []
    assert client.post(f"/api/vulnerability-providers/{name}/health-check", headers=auth_headers).status_code in (404, 405)


def test_every_provider_request_goes_to_the_configured_host(client, app, auth_headers, project, intelligence):
    run(client, app, auth_headers, project, body={"provider": "OSV"})
    assert intelligence.requests and {r.url.host for r in intelligence.requests} == {"api.osv.dev"}
    assert {r.url.scheme for r in intelligence.requests} == {"https"}
    assert all(r.url.path == "/v1/querybatch" or r.url.path.startswith("/v1/vulns/") for r in intelligence.requests)


def test_oversized_request_body_is_rejected(client, auth_headers, project):
    response = client.post(url(project, f"{BASE}/sync"), headers={**auth_headers, "Content-Type": "application/json"},
                           content=b'{"provider": "' + b"x" * 1_100_000 + b'"}')
    assert response.status_code == 413


# --- providers ---------------------------------------------------------------------------------

def test_provider_listing_and_health_check(client, app, auth_headers, project, intelligence, db):
    listing = client.get("/api/vulnerability-providers", headers=auth_headers).json()["items"]
    assert [(p["name"], p["enabled"], p["base_url"], p["last_sync_status"]) for p in listing] == [("osv", True, "https://api.osv.dev", None)]
    health = client.post("/api/vulnerability-providers/osv/health-check", headers=auth_headers)
    assert health.status_code == 200 and health.json()["ok"] is True and health.json()["provider"] == "osv"
    run(client, app, auth_headers, project)
    after = client.get("/api/vulnerability-providers", headers=auth_headers).json()["items"][0]
    assert after["last_sync_status"] == "completed" and after["last_health"]["ok"] is True
    intelligence.error = httpx.ConnectError("down")
    down = client.post("/api/vulnerability-providers/osv/health-check", headers=auth_headers).json()
    assert down["ok"] is False and down["code"] == "PROVIDER_UNREACHABLE"
    assert db.audit_logs.count_documents({"action": "vulnerability_provider.health_check"}) == 2


# --- housekeeping ---------------------------------------------------------------------------------

def test_requests_and_outcomes_are_audited(client, app, auth_headers, project, intelligence, db):
    run(client, app, auth_headers, project)
    intelligence.always_fail["/v1/querybatch"] = (503, {})
    run(client, app, auth_headers, project)
    entries = [(e["action"], e["outcome"]) for e in db.audit_logs.find({"action": {"$regex": "^job.vulnerability"}})]
    assert entries == [("job.vulnerability_sync.request", "success"), ("job.vulnerability_sync.finish", "success"),
                       ("job.vulnerability_sync.request", "success"), ("job.vulnerability_sync.finish", "failure")]
    failed = db.audit_logs.find_one({"action": "job.vulnerability_sync.finish", "outcome": "failure"})
    assert failed["details"]["error_code"] == "PROVIDER_ERROR"


def test_deleting_a_project_removes_its_findings_but_keeps_shared_advisories(client, app, auth_headers, project, intelligence, db):
    run(client, app, auth_headers, project)
    assert db.vulnerability_matches.count_documents({}) == 8
    assert client.delete(url(project), headers=auth_headers).status_code == 204
    assert db.vulnerability_matches.count_documents({}) == 0 and db.vulnerability_syncs.count_documents({}) == 0
    assert db.vulnerabilities.count_documents({}) == 8 and db.vulnerability_sources.count_documents({}) == 1


def test_results_follow_the_snapshot_being_served(client, app, auth_headers, project, intelligence, repo, db):
    run(client, app, auth_headers, project)
    assert matches(client, auth_headers, project)["total"] == 8
    repo.files["api/requirements.txt"] = b"requests==2.32.0\n"             # the repository moves to a fixed version
    client.post(url(project, "/analysis/dependencies"), headers=auth_headers)
    run_worker(app)
    stale = matches(client, auth_headers, project)
    assert stale["total"] == 0 and stale["scan"] is None                    # the old scan is not presented for the new snapshot
    run(client, app, auth_headers, project)
    assert matches(client, auth_headers, project, q="requests")["total"] == 0
    assert matches(client, auth_headers, project)["total"] == 6
    assert db.vulnerability_matches.count_documents({}) == 14               # findings of the earlier snapshot remain as history


def test_no_scores_or_predictions_are_produced(client, app, auth_headers, project, intelligence):
    run(client, app, auth_headers, project)
    body = matches(client, auth_headers, project)
    item = client.get(url(project, f"{BASE}/{body['items'][0]['id']}"), headers=auth_headers).json()
    text = json.dumps([body["scan"], body["items"], item["match"]]).lower()
    for term in ("trust_score", "risk_score", "exploit_prob", "epss", "predicted", "reachab"):
        assert term not in text
    assert {m["classification"] for m in body["items"]} == {"OBSERVED"}


def test_shadowwatch_dependencies_against_real_advisories(client, app, auth_headers, github, osv, db):
    """The real ShadowWatch dependency files with real advisories for two of its packages."""
    github.repo = FakeRepository(load_tree("shadowwatch"))
    project = client.post("/api/projects", json={"name": "ShadowWatch", "repository_url": "https://github.com/karthikmukesh19-gif/ShadowWatch"},
                          headers=auth_headers).json()
    client.post(url(project, "/analysis/dependencies"), headers=auth_headers)
    run_worker(app)
    osv.load("GHSA-4r6h-8v6p-xvw6", "GHSA-5pgg-2g8v-p4x9", "GHSA-6c5p-j8vq-pqhj", "GHSA-cjwg-qfpm-7377", "PYSEC-2024-232", "PYSEC-2024-233")
    osv.report("npm", "xlsx", "0.18.5", "GHSA-4r6h-8v6p-xvw6", "GHSA-5pgg-2g8v-p4x9")
    job = run(client, app, auth_headers, project)
    assert job["state"] == "completed"
    summary = job["summary"]
    assert summary["dependencies_total"] == 320 and summary["dependencies_checked"] == 320 and summary["dependencies_unresolved"] == 0
    body = matches(client, auth_headers, project)
    assert pairs(body) == [("npm:xlsx@0.18.5", "GHSA-4r6h-8v6p-xvw6"), ("npm:xlsx@0.18.5", "GHSA-5pgg-2g8v-p4x9")]
    assert {m["severity"] for m in body["items"]} == {"HIGH"} and {m["relationship"] for m in body["items"]} == {"DIRECT"}
    query = json.loads(osv.calls("/v1/querybatch")[0].content)["queries"]
    assert len(query) == 320 and {"package": {"name": "python-jose", "ecosystem": "PyPI"}, "version": "3.5.0"} in query
    # python-jose 3.5.0 is newer than the fixed version 3.4.0 of its advisories: stored or not, they do not match.
    from app.collectors.providers.osv import normalize_osv
    for name in ("GHSA-6c5p-j8vq-pqhj", "PYSEC-2024-232"):
        db.vulnerabilities.insert_one(normalize_osv(osv.records[name]))
    assert run(client, app, auth_headers, project, "analyze")["summary"]["affected_matches"] == 2


# --- regression -----------------------------------------------------------------------------

def test_an_invalid_id_reported_by_the_provider_makes_the_sync_partial(client, app, auth_headers, project, intelligence, db):
    intelligence.report("PyPI", "requests", "2.19.1", "GHSA-x84v-xcm2-53pg", "BAD ID/with space")
    job = run(client, app, auth_headers, project)
    assert job["state"] == "failed" and job["error"]["code"] == "SYNC_INCOMPLETE"
    sync = db.vulnerability_syncs.find_one({})
    assert sync["status"] == "partial" and sync["records_failed"] == 1
    assert [e["code"] for e in sync["errors"]] == ["INVALID_ID"]
    assert not any("BAD" in r.url.path for r in intelligence.requests)                 # it was never placed in a URL


def test_an_unexpected_error_does_not_leave_the_sync_marked_running(client, app, auth_headers, project, intelligence, db, monkeypatch):
    def explode(*_args, **_kwargs):
        raise RuntimeError("storage failure")
    monkeypatch.setattr(app.state.providers["osv"], "normalize", explode)
    job = run(client, app, auth_headers, project)
    assert job["state"] == "failed" and job["error"]["code"] == "INTERNAL_ERROR"
    assert "storage failure" not in json.dumps(job)                                    # internals are not shown
    sync = db.vulnerability_syncs.find_one({})
    assert sync["status"] == "failed" and sync["completed_at"] is not None
    assert matches(client, auth_headers, project)["items"] == []


def test_the_stored_raw_record_always_corresponds_to_its_recorded_hash(client, app, auth_headers, project, intelligence, db):
    import hashlib
    long_record = {**intelligence.records["GHSA-x84v-xcm2-53pg"], "database_specific": {"note": "x" * 30000}}
    intelligence.records["GHSA-x84v-xcm2-53pg"] = long_record
    assert run(client, app, auth_headers, project)["state"] == "completed"
    stored = db.vulnerabilities.find_one({"source_id": "GHSA-x84v-xcm2-53pg"})
    assert stored["raw_stored"] is True and stored["raw"] == long_record                # kept whole, not shortened
    served = next(r for r in intelligence.requests if r.url.path.endswith("GHSA-x84v-xcm2-53pg"))
    assert stored["raw_sha256"] == hashlib.sha256(intelligence.handler(served).content).hexdigest()


def test_a_job_that_was_already_failed_cannot_later_be_recorded_as_completed(client, app, auth_headers, project, intelligence, db):
    from app.services import jobs
    assert client.post(url(project, f"{BASE}/sync"), headers=auth_headers).status_code == 202
    job = jobs.claim_next_job(db)
    db.analysis_jobs.update_one({"_id": job["_id"]}, {"$set": {"state": "failed", "error": {"code": "STALE", "message": "x"}}})
    jobs._finish(db, job, "completed", "late result")
    stored = db.analysis_jobs.find_one({"_id": job["_id"]})
    assert stored["state"] == "failed" and stored["error"]["code"] == "STALE"
    assert db.projects.find_one({})["active_job_id"] is None                          # the project is released either way


def test_a_job_that_cannot_be_created_does_not_lock_the_project(client, app, auth_headers, project, db, monkeypatch):
    from app.services import jobs
    stored = db.projects.find_one({})

    class Broken:
        def insert_one(self, _document):
            raise RuntimeError("write failed")

    real = db.__class__.__getitem__
    monkeypatch.setattr(db.__class__, "__getitem__", lambda self, name: Broken() if name == "analysis_jobs" else real(self, name))
    with pytest.raises(RuntimeError):
        jobs.request_job(db, app.state.redis, stored, jobs.SBOM_GENERATION)
    monkeypatch.undo()
    assert db.projects.find_one({})["active_job_id"] is None
