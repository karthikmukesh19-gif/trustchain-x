"""SBOM generation, integrity verification, history and comparison."""

import base64
import copy
import hashlib
import json
import zlib
from datetime import datetime, timedelta, timezone

import pytest
from bson import ObjectId
from bson.binary import Binary

from app.sbom import canonical, cyclonedx
from app.sbom import diff as sbom_diff
from app.services import sbom as sbom_service
from tests.conftest import FakeRepository, load_tree, run_worker
from tests.test_vulnerabilities import REAL, REPO, REPO_URL

ENDPOINTS = [("get", "/sbom"), ("post", "/sbom/generate"), ("get", f"/sbom/{ObjectId()}"), ("get", f"/sbom/{ObjectId()}/document"),
             ("get", f"/sbom/{ObjectId()}/components"), ("post", f"/sbom/{ObjectId()}/verify"),
             ("get", f"/sbom/{ObjectId()}/diff/{ObjectId()}")]
XLSX_SRI = "dmg3LCjBPHZnQp5/F/+nnTa+miPJxUXB6vtk42YjBBKayDNagxGEeIdWApkYPOf3Z3pm3k62Knjzp7lMeTEtFQ=="


@pytest.fixture
def repo(github):
    github.repo = FakeRepository(REPO)
    return github.repo


@pytest.fixture
def project(client, app, auth_headers, repo):
    created = client.post("/api/projects", json={"name": "Demo", "repository_url": REPO_URL}, headers=auth_headers).json()
    analyse(client, app, auth_headers, created)
    return created


def url(project, path=""):
    return f"/api/projects/{project['id']}{path}"


def analyse(client, app, headers, project):
    assert client.post(url(project, "/analysis/dependencies"), headers=headers).status_code == 202
    assert run_worker(app) == 1


def generate(client, app, headers, project):
    response = client.post(url(project, "/sbom/generate"), headers=headers)
    assert response.status_code == 202, response.text
    assert run_worker(app) == 1
    job = client.get(url(project, "/jobs"), headers=headers, params={"type": "sbom_generation"}).json()["items"][0]
    assert job["state"] == "completed", job
    return job


def document(client, headers, project, sbom_id):
    response = client.get(url(project, f"/sbom/{sbom_id}/document"), headers=headers)
    assert response.status_code == 200
    return json.loads(response.content), response


def verify(client, headers, project, sbom_id):
    response = client.post(url(project, f"/sbom/{sbom_id}/verify"), headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def failed(result):
    return sorted(c["name"] for c in result["checks"] if not c["ok"])


def rewrite(db, sbom_id, change, fix_digests=False):
    """Alter the stored document the way someone with database access could."""
    stored = db.sboms.find_one({"_id": ObjectId(sbom_id)})
    doc = json.loads(zlib.decompress(bytes(stored["document_zlib"])))
    change(doc)
    payload = canonical.canonical_bytes(doc)
    update = {"document_zlib": Binary(zlib.compress(payload))}
    if fix_digests:
        update.update(document_digest=hashlib.sha256(payload).hexdigest(), content_digest=canonical.content_digest(doc))
    db.sboms.update_one({"_id": stored["_id"]}, {"$set": update})


def component(doc, ref):
    return next(c for c in doc["components"] if c["bom-ref"] == ref)


# --- access control -------------------------------------------------------------------------

@pytest.mark.parametrize("method,path", ENDPOINTS)
def test_endpoints_require_authentication(client, method, path):
    assert getattr(client, method)(f"/api/projects/{ObjectId()}{path}").status_code == 401


@pytest.mark.parametrize("method,path", ENDPOINTS)
def test_another_users_project_is_not_found(client, auth_headers, other_headers, project, method, path):
    assert getattr(client, method)(url(project, path), headers=other_headers).status_code == 404


@pytest.mark.parametrize("sbom_id", ["nope", "../x", str(ObjectId()), "{'$gt': ''}"])
def test_unknown_or_malformed_sbom_ids_are_404(client, auth_headers, project, sbom_id):
    for method, path in (("get", ""), ("get", "/document"), ("get", "/components"), ("post", "/verify")):
        assert getattr(client, method)(url(project, f"/sbom/{sbom_id}{path}"), headers=auth_headers).status_code == 404


def test_an_sbom_cannot_be_reached_through_another_project(client, app, auth_headers, other_headers, project, github):
    mine = generate(client, app, auth_headers, project)["sbom_id"]
    theirs = client.post("/api/projects", json={"name": "Other", "repository_url": REPO_URL}, headers=other_headers).json()
    analyse(client, app, other_headers, theirs)
    other = generate(client, app, other_headers, theirs)["sbom_id"]
    for path in (f"/sbom/{mine}", f"/sbom/{mine}/document", f"/sbom/{mine}/components", f"/sbom/{other}/diff/{mine}", f"/sbom/{mine}/diff/{other}"):
        assert client.get(url(theirs, path), headers=other_headers).status_code == 404
    assert client.post(url(theirs, f"/sbom/{mine}/verify"), headers=other_headers).status_code == 404


def test_generation_needs_a_dependency_inventory(client, auth_headers, github):
    github.repo = FakeRepository(REPO)
    fresh = client.post("/api/projects", json={"name": "Fresh", "repository_url": REPO_URL}, headers=auth_headers).json()
    response = client.post(url(fresh, "/sbom/generate"), headers=auth_headers)
    assert response.status_code == 409 and "dependency analysis first" in response.json()["detail"]
    listing = client.get(url(fresh, "/sbom"), headers=auth_headers).json()
    assert listing == {"job": None, "latest": None, "history": [], "has_inventory": False, "latest_snapshot_id": None}


# --- generation -------------------------------------------------------------------------------

def test_generation_runs_as_a_job_and_records_the_sbom(client, app, auth_headers, project, db):
    response = client.post(url(project, "/sbom/generate"), headers=auth_headers)
    queued = response.json()["job"]
    assert (response.status_code, queued["type"], queued["state"]) == (202, "sbom_generation", "queued")
    assert client.get(url(project, "/sbom"), headers=auth_headers).json()["latest"] is None      # nothing until the worker runs
    assert run_worker(app) == 1
    listing = client.get(url(project, "/sbom"), headers=auth_headers).json()
    job, latest = listing["job"], listing["latest"]
    assert job["state"] == "completed" and job["summary"]["reused"] is False and job["summary"]["changes_from_previous"] is None
    snapshot = db.repository_snapshots.find_one({})
    assert latest["id"] == job["sbom_id"] and latest["snapshot_id"] == str(snapshot["_id"]) and latest["commit_sha"] == snapshot["commit_sha"]
    assert (latest["format"], latest["spec_version"], latest["media_type"]) == ("CycloneDX", "1.5", "application/vnd.cyclonedx+json")
    assert latest["version"] == 1 and latest["previous_sbom_id"] is None
    assert latest["generator"] == {"name": "TrustChain-X", "version": cyclonedx.GENERATOR_VERSION}
    assert latest["component_count"] == 10 and latest["relationship_count"] == 10
    assert latest["unresolved_components"] == 1 and latest["components_with_hashes"] == 1
    assert latest["digest_algorithm"] == "SHA-256" and len(latest["content_digest"]) == 64 and len(latest["document_digest"]) == 64
    assert latest["generated_at"] and latest["last_verification"] is None and latest["completeness"] == "incomplete"
    assert "document_zlib" not in latest
    assert listing["history"][0]["id"] == latest["id"] and listing["has_inventory"] is True
    assert db.sbom_components.count_documents({"sbom_id": ObjectId(latest["id"])}) == 10


def test_document_is_cyclonedx_json_describing_the_snapshot(client, app, auth_headers, project, db):
    sbom_id = generate(client, app, auth_headers, project)["sbom_id"]
    doc, response = document(client, auth_headers, project, sbom_id)
    snapshot = db.repository_snapshots.find_one({})
    assert response.headers["content-type"].startswith("application/vnd.cyclonedx+json")
    assert response.headers["content-disposition"] == f'attachment; filename="sbom-v1-{snapshot["commit_sha"][:10]}.cdx.json"'
    assert (doc["bomFormat"], doc["specVersion"], doc["version"]) == ("CycloneDX", "1.5", 1)
    assert doc["serialNumber"].startswith("urn:uuid:") and len(doc["serialNumber"]) == 45
    metadata = doc["metadata"]
    assert metadata["component"] == {"type": "application", "bom-ref": "root", "name": "octo/vulnerable-demo",
                                     "version": snapshot["commit_sha"], "externalReferences": [{"type": "vcs", "url": REPO_URL}]}
    assert metadata["tools"] == {"components": [{"type": "application", "name": "TrustChain-X", "version": cyclonedx.GENERATOR_VERSION}]}
    properties = {p["name"]: p["value"] for p in metadata["properties"]}
    assert properties["trustchain:snapshot_id"] == str(snapshot["_id"]) and properties["trustchain:commit_sha"] == snapshot["commit_sha"]
    assert properties["trustchain:project_id"] == project["id"] and properties["trustchain:unresolved_versions"] == "1"
    assert "no repository code executed" in properties["trustchain:collection_method"]
    assert datetime.fromisoformat(metadata["timestamp"].replace("Z", "+00:00")).tzinfo is not None


def test_components_carry_only_what_the_repository_establishes(client, app, auth_headers, project):
    doc, _ = document(client, auth_headers, project, generate(client, app, auth_headers, project)["sbom_id"])
    refs = [c["bom-ref"] for c in doc["components"]]
    assert refs == sorted(refs) and len(refs) == len(set(refs)) == 10

    xlsx = component(doc, "npm:xlsx@0.18.5")
    assert (xlsx["type"], xlsx["name"], xlsx["version"], xlsx["purl"], xlsx["scope"]) == ("library", "xlsx", "0.18.5", "pkg:npm/xlsx@0.18.5", "required")
    # The lockfile's base64 SHA-512 is the same digest re-encoded as hex, not a new value.
    assert xlsx["hashes"] == [{"alg": "SHA-512", "content": base64.b64decode(XLSX_SRI).hex()}]
    properties = {p["name"]: p["value"] for p in xlsx["properties"]}
    assert properties["trustchain:relationship"] == "DIRECT" and properties["trustchain:relationship_basis"] == "OBSERVED"
    assert properties["trustchain:source_files"] == "web/package-lock.json, web/package.json"
    assert properties["trustchain:version_status"] == "RESOLVED" and properties["trustchain:depth"] == "1"

    flask = component(doc, "pypi:flask@unresolved")
    assert "version" not in flask and "hashes" not in flask and flask["purl"] == "pkg:pypi/flask"
    assert {p["name"]: p["value"] for p in flask["properties"]}["trustchain:constraints"] == ">=2.0"

    log4j = component(doc, "maven:org.apache.logging.log4j:log4j-core@2.14.1")
    assert (log4j["group"], log4j["name"], log4j["purl"]) == ("org.apache.logging.log4j", "log4j-core",
                                                              "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
    # Nothing that the inventory does not contain is written.
    text = json.dumps(doc)
    assert '"licenses"' not in text and '"license"' not in text and '"supplier"' not in text and '"author"' not in text
    assert sum(1 for c in doc["components"] if "hashes" in c) == 1
    assert doc["compositions"] == [{"aggregate": "incomplete", "assemblies": ["root"]}]


def test_dependency_relationships_come_from_the_graph(client, app, auth_headers, project):
    doc, _ = document(client, auth_headers, project, generate(client, app, auth_headers, project)["sbom_id"])
    depends = {d["ref"]: d["dependsOn"] for d in doc["dependencies"]}
    assert set(depends) == {c["bom-ref"] for c in doc["components"]} | {"root"}
    assert depends["npm:left@1.0.0"] == ["npm:lodash@4.17.20"] and depends["npm:lodash@4.17.20"] == []
    assert "npm:lodash@4.17.20" not in depends["root"]                      # transitive: reached through left, not from the project
    assert {"npm:xlsx@0.18.5", "npm:left@1.0.0", "pypi:requests@2.19.1", "golang:golang.org/x/crypto@v0.30.0"} <= set(depends["root"])
    assert all(value == sorted(value) for value in depends.values())


def test_downloaded_bytes_are_canonical_and_match_the_recorded_digest(client, app, auth_headers, project):
    sbom_id = generate(client, app, auth_headers, project)["sbom_id"]
    doc, response = document(client, auth_headers, project, sbom_id)
    record = client.get(url(project, f"/sbom/{sbom_id}"), headers=auth_headers).json()
    assert hashlib.sha256(response.content).hexdigest() == record["document_digest"]
    assert response.headers["x-content-digest"] == f"sha-256={record['document_digest']}"
    assert response.content == canonical.canonical_bytes(doc) and record["document_size"] == len(response.content)
    assert canonical.content_digest(doc) == record["content_digest"] != record["document_digest"]


def test_same_inventory_gives_the_same_content_digest_whenever_it_is_generated(db, client, app, auth_headers, project):
    snapshot = db.repository_snapshots.find_one({}, {"files": 0})
    project_id = ObjectId(project["id"])
    first = sbom_service.build_document(db, project_id, snapshot, datetime(2026, 1, 1, tzinfo=timezone.utc))
    later = sbom_service.build_document(db, project_id, snapshot, datetime(2026, 6, 1, 12, 30, tzinfo=timezone.utc))
    assert first["metadata"]["timestamp"] != later["metadata"]["timestamp"]
    assert canonical.content_digest(first) == canonical.content_digest(later)
    assert first["serialNumber"] == later["serialNumber"]                   # derived from project, snapshot and content
    assert canonical.digest(first) != canonical.digest(later)               # the whole document includes the timestamp
    assert canonical.content_view(first) == canonical.content_view(later)


def test_generating_again_from_an_unchanged_inventory_reuses_the_sbom(client, app, auth_headers, project, db):
    first = generate(client, app, auth_headers, project)
    second = generate(client, app, auth_headers, project)
    assert second["sbom_id"] == first["sbom_id"] and second["summary"]["reused"] is True and "unchanged" in second["message"]
    assert db.sboms.count_documents({}) == 1 and db.sbom_components.count_documents({}) == 10
    assert len(client.get(url(project, "/sbom"), headers=auth_headers).json()["history"]) == 1


def test_canonical_form_is_independent_of_key_order_and_whitespace():
    a = {"b": [1, {"y": "é", "x": None}], "a": True}
    b = json.loads('{ "a": true,\n "b": [1, {"x": null, "y": "\\u00e9"}] }')
    assert canonical.canonical_bytes(a) == canonical.canonical_bytes(b) == '{"a":true,"b":[1,{"x":null,"y":"é"}]}'.encode()
    assert canonical.digest(a) == canonical.digest(b) and canonical.digest(a) != canonical.digest({**a, "a": False})
    assert canonical.digest({"l": [1, 2]}) != canonical.digest({"l": [2, 1]})   # list order is significant
    with pytest.raises(ValueError):
        canonical.canonical_bytes({"n": float("nan")})


@pytest.mark.parametrize("algorithm,value,expected", [
    ("sha512", XLSX_SRI, {"alg": "SHA-512", "content": base64.b64decode(XLSX_SRI).hex()}),
    ("sha256", "A" * 64, {"alg": "SHA-256", "content": "a" * 64}),
    ("SHA-1", base64.b64encode(bytes(20)).decode(), {"alg": "SHA-1", "content": "00" * 20}),
    ("sha256", "abc", None),                    # wrong length: not presented as a hash
    ("sha512", "!!!not base64!!!", None),
    ("h1", "kV0Yy1Jd0mZ4Dc0Mj4Y8Ew==", None),    # Go module hash: not a file digest
    ("md4", "0" * 32, None), (None, "x", None), ("sha256", None, None),
])
def test_recorded_digests_are_converted_or_left_out_never_invented(algorithm, value, expected):
    assert cyclonedx.convert_hash(algorithm, value) == expected


def test_shadowwatch_sbom(client, app, auth_headers, github, db):
    github.repo = FakeRepository(load_tree("shadowwatch"))
    project = client.post("/api/projects", json={"name": "ShadowWatch", "repository_url": "https://github.com/karthikmukesh19-gif/ShadowWatch"},
                          headers=auth_headers).json()
    analyse(client, app, auth_headers, project)
    job = generate(client, app, auth_headers, project)
    assert job["summary"]["component_count"] == 320 and job["summary"]["relationship_count"] == 459
    doc, _ = document(client, auth_headers, project, job["sbom_id"])
    assert len(doc["components"]) == 320 and all(c.get("version") and c.get("purl") for c in doc["components"])
    npm = [c for c in doc["components"] if c["purl"].startswith("pkg:npm/")]
    assert len(npm) == 293 and all(c["hashes"][0]["alg"] == "SHA-512" and len(c["hashes"][0]["content"]) == 128 for c in npm)
    assert all("hashes" not in c for c in doc["components"] if c["purl"].startswith("pkg:pypi/"))   # requirements.txt records none
    assert verify(client, auth_headers, project, job["sbom_id"])["valid"] is True
    assert doc["compositions"][0]["aggregate"] == "unknown"                 # nothing unparsed or unresolved, yet completeness is not claimed


# --- integrity verification ----------------------------------------------------------------------

def test_untouched_sbom_verifies(client, app, auth_headers, project, db):
    sbom_id = generate(client, app, auth_headers, project)["sbom_id"]
    result = verify(client, auth_headers, project, sbom_id)
    assert result["valid"] is True and result["sbom_id"] == sbom_id
    assert [c["name"] for c in result["checks"]] == ["stored_document_digest", "canonical_form", "content_digest", "component_records", "regeneration"]
    assert all(c["ok"] and c["detail"] for c in result["checks"])
    assert result["difference_from_regenerated"] is None and result["digest_algorithm"] == "SHA-256"
    assert "not cryptographically signed" in result["meaning"] and "tamper-proof" not in json.dumps(result).lower()
    stored = client.get(url(project, f"/sbom/{sbom_id}"), headers=auth_headers).json()["last_verification"]
    assert stored["valid"] is True and stored["failed_checks"] == [] and stored["verified_at"]
    assert db.audit_logs.find_one({"action": "sbom.verify"})["outcome"] == "success"


def bump_version(doc):
    component(doc, "pypi:requests@2.19.1")["version"] = "2.32.0"


def rename_component(doc):
    component(doc, "npm:xlsx@0.18.5")["name"] = "xlsx-patched"


def drop_component(doc):
    doc["components"] = [c for c in doc["components"] if c["bom-ref"] != "npm:lodash@4.17.20"]


def add_component(doc):
    doc["components"].append({"type": "library", "bom-ref": "npm:injected@9.9.9", "name": "injected", "version": "9.9.9"})


def cut_relationship(doc):
    next(d for d in doc["dependencies"] if d["ref"] == "npm:left@1.0.0")["dependsOn"] = []


def add_relationship(doc):
    next(d for d in doc["dependencies"] if d["ref"] == "npm:xlsx@0.18.5")["dependsOn"] = ["npm:lodash@4.17.20"]


def swap_hash(doc):
    component(doc, "npm:xlsx@0.18.5")["hashes"][0]["content"] = "0" * 128


def retarget_repository(doc):
    doc["metadata"]["component"]["name"] = "someone/else"


TAMPERINGS = [bump_version, rename_component, drop_component, add_component, cut_relationship, add_relationship, swap_hash, retarget_repository]


@pytest.mark.parametrize("change", TAMPERINGS, ids=lambda f: f.__name__)
def test_modified_document_fails_verification(client, app, auth_headers, project, db, change):
    sbom_id = generate(client, app, auth_headers, project)["sbom_id"]
    rewrite(db, sbom_id, change)
    result = verify(client, auth_headers, project, sbom_id)
    assert result["valid"] is False
    assert {"stored_document_digest", "content_digest"} <= set(failed(result))
    check = next(c for c in result["checks"] if c["name"] == "stored_document_digest")
    assert check["expected"] != check["actual"] and len(check["actual"]) == 64
    assert client.get(url(project, f"/sbom/{sbom_id}"), headers=auth_headers).json()["last_verification"]["valid"] is False
    assert db.audit_logs.find_one({"action": "sbom.verify"})["outcome"] == "failure"


@pytest.mark.parametrize("change", TAMPERINGS, ids=lambda f: f.__name__)
def test_modification_is_detected_even_when_the_stored_digests_are_rewritten_to_match(client, app, auth_headers, project, db, change):
    sbom_id = generate(client, app, auth_headers, project)["sbom_id"]
    rewrite(db, sbom_id, change, fix_digests=True)
    result = verify(client, auth_headers, project, sbom_id)
    assert result["valid"] is False and "regeneration" in failed(result)
    assert "stored_document_digest" not in failed(result)                   # the forged digests agree with the forged document
    summary = result["difference_from_regenerated"]["summary"]
    assert summary["identical"] is False
    if change in (rename_component, retarget_repository):
        assert result["difference_from_regenerated"]["items"] or result["difference_from_regenerated"]["document_changes"]


def test_what_was_changed_is_reported(client, app, auth_headers, project, db):
    sbom_id = generate(client, app, auth_headers, project)["sbom_id"]
    rewrite(db, sbom_id, lambda doc: (bump_version(doc), cut_relationship(doc), add_component(doc)), fix_digests=True)
    difference = verify(client, auth_headers, project, sbom_id)["difference_from_regenerated"]
    changes = {(i["name"], i["change"]): i for i in difference["items"]}
    assert changes[("requests", "CHANGED")]["old_version"] == "2.19.1" and changes[("requests", "CHANGED")]["new_version"] == "2.32.0"
    assert ("injected", "ADDED") in changes
    assert difference["relationships_removed"] == [{"from": "npm:left@1.0.0", "to": "npm:lodash@4.17.20"}]
    assert difference["summary"]["changed"] == 1 and difference["summary"]["added"] == 1


def test_modified_component_record_fails_verification(client, app, auth_headers, project, db):
    sbom_id = generate(client, app, auth_headers, project)["sbom_id"]
    db.sbom_components.update_one({"bom_ref": "npm:xlsx@0.18.5"}, {"$set": {"component_digest": "0" * 64}})
    db.sbom_components.delete_one({"bom_ref": "npm:left@1.0.0"})
    result = verify(client, auth_headers, project, sbom_id)
    assert failed(result) == ["component_records"]
    assert next(c for c in result["checks"] if c["name"] == "component_records")["differing"] == ["npm:left@1.0.0", "npm:xlsx@0.18.5"]


def test_whitespace_or_reordered_keys_are_not_canonical(client, app, auth_headers, project, db):
    sbom_id = generate(client, app, auth_headers, project)["sbom_id"]
    stored = db.sboms.find_one({})
    pretty = json.dumps(json.loads(zlib.decompress(bytes(stored["document_zlib"]))), indent=2).encode()
    db.sboms.update_one({"_id": stored["_id"]}, {"$set": {"document_zlib": Binary(zlib.compress(pretty))}})
    result = verify(client, auth_headers, project, sbom_id)
    assert failed(result) == ["canonical_form", "stored_document_digest"]     # same content, different bytes


@pytest.mark.parametrize("blob", [b"not zlib data", zlib.compress(b"not json"), zlib.compress(b"[1, 2]")])
def test_unreadable_document_fails_verification_and_cannot_be_downloaded(client, app, auth_headers, project, db, blob):
    sbom_id = generate(client, app, auth_headers, project)["sbom_id"]
    db.sboms.update_one({}, {"$set": {"document_zlib": Binary(blob)}})
    result = verify(client, auth_headers, project, sbom_id)
    assert result["valid"] is False and "stored_document_readable" in failed(result)
    assert client.get(url(project, f"/sbom/{sbom_id}/document"), headers=auth_headers).status_code == 409


def test_sbom_that_no_longer_reflects_the_inventory_fails_regeneration(client, app, auth_headers, project, db):
    sbom_id = generate(client, app, auth_headers, project)["sbom_id"]
    db.dependencies.update_one({"node_id": "pypi:requests@2.19.1"}, {"$set": {"version": "2.19.2"}})   # the inventory is altered
    result = verify(client, auth_headers, project, sbom_id)
    assert failed(result) == ["regeneration"]
    item, = result["difference_from_regenerated"]["items"]
    assert (item["name"], item["change"], item["old_version"], item["new_version"]) == ("requests", "CHANGED", "2.19.2", "2.19.1")


def test_missing_snapshot_makes_regeneration_impossible_and_says_so(client, app, auth_headers, project, db):
    sbom_id = generate(client, app, auth_headers, project)["sbom_id"]
    db.repository_snapshots.delete_many({})
    result = verify(client, auth_headers, project, sbom_id)
    assert failed(result) == ["regeneration"] and "no longer available" in result["checks"][-1]["detail"]


# --- history and comparison ---------------------------------------------------------------------

@pytest.fixture
def two_versions(client, app, auth_headers, project, repo):
    first = generate(client, app, auth_headers, project)["sbom_id"]
    lock = json.loads(REPO["web/package-lock.json"])
    lock["packages"][""]["dependencies"] = {"xlsx": "^0.18.5", "left": "^1.0.0", "right": "^2.0.0"}
    lock["packages"]["node_modules/lodash"]["version"] = "4.17.21"
    lock["packages"]["node_modules/right"] = {"version": "2.0.0", "dependencies": {"lodash": "^4.17.0"}}
    lock["packages"]["node_modules/xlsx"]["integrity"] = "sha512-" + base64.b64encode(bytes(range(64))).decode()
    repo.files["web/package-lock.json"] = json.dumps(lock).encode()
    repo.files["web/package.json"] = json.dumps({"name": "web", "dependencies": lock["packages"][""]["dependencies"]}).encode()
    repo.files["api/requirements.txt"] = b"requests==2.32.0\npython-jose==3.5.0\nflask>=2.0\n"
    del repo.files["svc/go.mod"]
    analyse(client, app, auth_headers, project)
    job = generate(client, app, auth_headers, project)
    return first, job["sbom_id"], job


def test_each_new_snapshot_gets_a_new_sbom_version_and_the_old_one_is_kept(client, auth_headers, project, two_versions, db):
    first, second, job = two_versions
    listing = client.get(url(project, "/sbom"), headers=auth_headers).json()
    assert [(s["id"], s["version"]) for s in listing["history"]] == [(second, 2), (first, 1)]
    assert listing["latest"]["id"] == second and listing["latest"]["previous_sbom_id"] == first
    assert listing["history"][0]["snapshot_id"] != listing["history"][1]["snapshot_id"]
    assert listing["history"][0]["content_digest"] != listing["history"][1]["content_digest"]
    assert db.projects.find_one({})["latest_sbom_id"] == ObjectId(second)
    # Both remain verifiable against their own snapshots.
    assert verify(client, auth_headers, project, first)["valid"] and verify(client, auth_headers, project, second)["valid"]
    assert job["summary"]["changes_from_previous"]["changed"] == 3 and job["stage"] == "COMPLETED"


def test_difference_between_two_sboms(client, auth_headers, project, two_versions, db):
    first, second, _ = two_versions
    response = client.get(url(project, f"/sbom/{first}/diff/{second}"), headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert (body["base_sbom_id"], body["target_sbom_id"], body["base_version"], body["target_version"]) == (first, second, 1, 2)
    assert body["base_snapshot_id"] != body["target_snapshot_id"] and body["base_commit_sha"] != body["target_commit_sha"]
    fields = [c["field"] for c in body["document_changes"]]
    assert body["summary"] == {
        "added": 1, "removed": 1, "changed": 3, "version_changes": 2, "metadata_changes": 1, "ecosystem_changes": 0,
        "relationships_added": 4, "relationships_removed": 3, "components_before": 10, "components_after": 10,
        "document_changes": len(fields), "identical": False}
    # A different snapshot: the commit the SBOM describes and the snapshot properties differ, and are reported as such.
    # (The collection time is also listed whenever the two snapshots were collected in different seconds.)
    assert set(fields) - {"metadata.snapshot_collected_at"} == {
        "metadata.component", "metadata.commit_sha", "metadata.dependency_files", "metadata.snapshot_id", "metadata.tree_sha"}
    items = {(i["ecosystem"], i["name"]): i for i in body["items"]}
    assert items[("npm", "right")]["change"] == "ADDED" and items[("npm", "right")]["new_versions"] == ["2.0.0"]
    assert items[("golang", "golang.org/x/crypto")]["change"] == "REMOVED" and items[("golang", "golang.org/x/crypto")]["old_versions"] == ["v0.30.0"]
    requests = items[("pypi", "requests")]
    assert (requests["change"], requests["change_type"], requests["old_version"], requests["new_version"]) == ("CHANGED", "version", "2.19.1", "2.32.0")
    assert (items[("npm", "lodash")]["old_version"], items[("npm", "lodash")]["new_version"]) == ("4.17.20", "4.17.21")
    xlsx = items[("npm", "xlsx")]
    assert (xlsx["change"], xlsx["change_type"]) == ("CHANGED", "metadata") and [f["field"] for f in xlsx["fields"]] == ["hashes"]
    assert ("npm", "left") not in items and ("pypi", "flask") not in items       # unchanged components are not listed
    assert {"from": "npm:right@2.0.0", "to": "npm:lodash@4.17.21"} in body["relationships_added"]
    assert {"from": "root", "to": "golang:golang.org/x/crypto@v0.30.0"} in body["relationships_removed"]


def test_difference_is_directional_stored_once_and_empty_for_identical_sboms(client, auth_headers, project, two_versions, db):
    first, second, _ = two_versions
    assert db.sbom_differences.count_documents({}) == 1                     # recorded when version 2 was generated
    forward = client.get(url(project, f"/sbom/{first}/diff/{second}"), headers=auth_headers).json()
    again = client.get(url(project, f"/sbom/{first}/diff/{second}"), headers=auth_headers).json()
    assert forward["id"] == again["id"] and db.sbom_differences.count_documents({}) == 1
    backward = client.get(url(project, f"/sbom/{second}/diff/{first}"), headers=auth_headers).json()
    assert (backward["summary"]["added"], backward["summary"]["removed"]) == (forward["summary"]["removed"], forward["summary"]["added"])
    back = {(i["ecosystem"], i["name"]): i for i in backward["items"]}
    assert (back[("pypi", "requests")]["old_version"], back[("pypi", "requests")]["new_version"]) == ("2.32.0", "2.19.1")
    same = client.get(url(project, f"/sbom/{first}/diff/{first}"), headers=auth_headers).json()
    assert same["summary"]["identical"] is True and same["items"] == [] and same["relationships_added"] == []
    stored = db.sbom_differences.find_one({"base_sbom_id": ObjectId(first), "target_sbom_id": ObjectId(second)})
    assert stored["base_snapshot_id"] != stored["target_snapshot_id"] and stored["project_id"] == ObjectId(project["id"])


def test_diff_with_unknown_sbom_is_404(client, auth_headers, project, two_versions):
    first, _, _ = two_versions
    for a, b in ((first, str(ObjectId())), (str(ObjectId()), first), (first, "nope")):
        assert client.get(url(project, f"/sbom/{a}/diff/{b}"), headers=auth_headers).status_code == 404


def test_diff_refuses_an_unreadable_document(client, auth_headers, project, two_versions, db):
    first, second, _ = two_versions
    db.sbom_differences.delete_many({})
    db.sboms.update_one({"_id": ObjectId(first)}, {"$set": {"document_zlib": Binary(b"garbage")}})
    response = client.get(url(project, f"/sbom/{first}/diff/{second}"), headers=auth_headers)
    assert response.status_code == 409 and "cannot be read" in response.json()["detail"]


def lib(ecosystem, name, version, **extra):
    properties = [{"name": "trustchain:ecosystem", "value": ecosystem}, {"name": "trustchain:normalized_name", "value": name}]
    item = {"type": "library", "bom-ref": f"{ecosystem}:{name}@{version}", "name": name, "properties": properties, **extra}
    if version:
        item["version"] = version
    return item


def bom(components, dependencies=()):
    return {"components": components, "dependencies": [{"ref": a, "dependsOn": list(b)} for a, b in dependencies]}


def test_compare_added_removed_changed():
    result = sbom_diff.compare(bom([lib("pypi", "requests", "2.19.1"), lib("pypi", "old", "1.0")]),
                               bom([lib("pypi", "requests", "2.32.0"), lib("pypi", "new", "1.0")]))
    assert [(i["name"], i["change"]) for i in result["items"]] == [("new", "ADDED"), ("old", "REMOVED"), ("requests", "CHANGED")]
    changed = result["items"][2]
    assert (changed["old_version"], changed["new_version"], changed["change_type"]) == ("2.19.1", "2.32.0", "version")
    assert result["summary"]["added"] == result["summary"]["removed"] == result["summary"]["changed"] == 1


def test_compare_treats_several_installed_versions_as_a_set():
    result = sbom_diff.compare(bom([lib("npm", "ms", "2.0.0"), lib("npm", "ms", "2.1.2")]),
                               bom([lib("npm", "ms", "2.1.2"), lib("npm", "ms", "2.1.3")]))
    item, = result["items"]
    assert (item["change"], item["old_versions"], item["new_versions"]) == ("CHANGED", ["2.0.0", "2.1.2"], ["2.1.2", "2.1.3"])
    assert "old_version" not in item
    assert sbom_diff.compare(bom([lib("npm", "ms", "2.0.0"), lib("npm", "ms", "2.1.2")]),
                             bom([lib("npm", "ms", "2.1.2"), lib("npm", "ms", "2.0.0")]))["summary"]["identical"] is True


def test_compare_resolved_against_unresolved_version():
    item, = sbom_diff.compare(bom([lib("pypi", "flask", None)]), bom([lib("pypi", "flask", "3.0.0")]))["items"]
    assert (item["change"], item["old_version"], item["new_version"]) == ("CHANGED", None, "3.0.0")


def test_compare_reports_metadata_changes_field_by_field():
    old = lib("npm", "a", "1.0.0", scope="required", purl="pkg:npm/a@1.0.0", hashes=[{"alg": "SHA-512", "content": "aa"}])
    new = copy.deepcopy(old)
    new["scope"] = "optional"
    new["hashes"] = [{"alg": "SHA-512", "content": "bb"}]
    new["properties"].append({"name": "trustchain:relationship", "value": "TRANSITIVE"})
    item, = sbom_diff.compare(bom([old]), bom([new]))["items"]
    assert (item["change"], item["change_type"]) == ("CHANGED", "metadata")
    assert {f["field"]: (f["old"], f["new"]) for f in item["fields"]} == {
        "scope": ("required", "optional"), "hashes": ([{"alg": "SHA-512", "content": "aa"}], [{"alg": "SHA-512", "content": "bb"}]),
        "relationship": (None, "TRANSITIVE")}


def test_compare_flags_a_name_moving_between_ecosystems_as_inferred():
    result = sbom_diff.compare(bom([lib("pypi", "colors", "1.0")]), bom([lib("npm", "colors", "1.4.0")]))
    assert [(i["ecosystem"], i["change"]) for i in result["items"]] == [("npm", "ADDED"), ("pypi", "REMOVED")]
    change, = result["ecosystem_changes"]
    assert (change["name"], change["old_ecosystem"], change["new_ecosystem"], change["basis"]) == ("colors", "pypi", "npm", "INFERRED")
    assert result["summary"]["ecosystem_changes"] == 1


def test_compare_relationships():
    a, b, c = lib("npm", "a", "1"), lib("npm", "b", "1"), lib("npm", "c", "1")
    result = sbom_diff.compare(bom([a, b, c], [("root", ["npm:a@1"]), ("npm:a@1", ["npm:b@1"])]),
                               bom([a, b, c], [("root", ["npm:a@1"]), ("npm:a@1", ["npm:c@1"])]))
    assert result["items"] == [] and result["summary"]["identical"] is False and result["document_changes"] == []
    assert result["relationships_added"] == [{"from": "npm:a@1", "to": "npm:c@1"}]
    assert result["relationships_removed"] == [{"from": "npm:a@1", "to": "npm:b@1"}]


# --- components and vulnerability linkage ----------------------------------------------------------

def test_components_listing_paging_and_search(client, app, auth_headers, project):
    sbom_id = generate(client, app, auth_headers, project)["sbom_id"]
    body = client.get(url(project, f"/sbom/{sbom_id}/components"), headers=auth_headers, params={"limit": 4}).json()
    assert body["total"] == 10 and len(body["items"]) == 4 and body["sbom_id"] == sbom_id
    assert [i["ecosystem"] for i in body["items"]] == sorted(i["ecosystem"] for i in body["items"])
    found = client.get(url(project, f"/sbom/{sbom_id}/components"), headers=auth_headers, params={"q": "LOG4J"}).json()["items"]
    assert [(i["bom_ref"], i["name"], i["version"]) for i in found] == [
        ("maven:org.apache.logging.log4j:log4j-core@2.14.1", "org.apache.logging.log4j:log4j-core", "2.14.1")]
    assert len(found[0]["component_digest"]) == 64 and found[0]["vulnerabilities"] == []
    left = client.get(url(project, f"/sbom/{sbom_id}/components"), headers=auth_headers, params={"q": "left"}).json()["items"][0]
    assert left["depends_on"] == ["npm:lodash@4.17.20"]
    assert client.get(url(project, f"/sbom/{sbom_id}/components"), headers=auth_headers, params={"q": ".*"}).json()["total"] == 0
    for params in ({"limit": 0}, {"limit": 501}, {"skip": -1}):
        assert client.get(url(project, f"/sbom/{sbom_id}/components"), headers=auth_headers, params=params).status_code == 422


def test_components_are_linked_to_stored_vulnerability_matches(client, app, auth_headers, project, osv):
    sbom_id = generate(client, app, auth_headers, project)["sbom_id"]
    before = client.get(url(project, f"/sbom/{sbom_id}"), headers=auth_headers).json()["vulnerability_linkage"]
    assert before == {"components_with_matches": 0, "affected_matches": 0, "latest_match_at": None}

    osv.load(*REAL)
    osv.report("npm", "xlsx", "0.18.5", "GHSA-4r6h-8v6p-xvw6", "GHSA-5pgg-2g8v-p4x9")
    osv.report("PyPI", "requests", "2.19.1", "GHSA-x84v-xcm2-53pg")
    client.post(url(project, "/vulnerabilities/sync"), headers=auth_headers)
    assert run_worker(app) == 1

    record = client.get(url(project, f"/sbom/{sbom_id}"), headers=auth_headers).json()
    assert record["vulnerability_linkage"]["components_with_matches"] == 2 and record["vulnerability_linkage"]["affected_matches"] == 3
    assert record["vulnerability_linkage"]["latest_match_at"]
    vulnerable = client.get(url(project, f"/sbom/{sbom_id}/components"), headers=auth_headers, params={"only_vulnerable": "true"}).json()
    assert [i["bom_ref"] for i in vulnerable["items"]] == ["npm:xlsx@0.18.5", "pypi:requests@2.19.1"]
    xlsx = vulnerable["items"][0]["vulnerabilities"]
    assert sorted(v["source_id"] for v in xlsx) == ["GHSA-4r6h-8v6p-xvw6", "GHSA-5pgg-2g8v-p4x9"] and {v["severity"] for v in xlsx} == {"HIGH"}
    match = client.get(url(project, f"/vulnerabilities/{xlsx[0]['match_id']}"), headers=auth_headers)
    assert match.status_code == 200 and match.json()["match"]["dependency_node_id"] == "npm:xlsx@0.18.5"
    # Linking findings does not alter the SBOM: it still verifies and its digest is unchanged.
    assert verify(client, auth_headers, project, sbom_id)["valid"] is True
    assert record["content_digest"] == client.get(url(project, "/sbom"), headers=auth_headers).json()["latest"]["content_digest"]


# --- housekeeping ---------------------------------------------------------------------------------

def test_deleting_a_project_removes_its_sboms(client, auth_headers, project, two_versions, db):
    assert db.sboms.count_documents({}) == 2 and db.sbom_components.count_documents({}) == 20 and db.sbom_differences.count_documents({}) == 1
    assert client.delete(url(project), headers=auth_headers).status_code == 204
    assert db.sboms.count_documents({}) == 0 and db.sbom_components.count_documents({}) == 0 and db.sbom_differences.count_documents({}) == 0


def test_generation_and_verification_are_audited(client, app, auth_headers, project, db):
    sbom_id = generate(client, app, auth_headers, project)["sbom_id"]
    verify(client, auth_headers, project, sbom_id)
    actions = [(e["action"], e["outcome"]) for e in db.audit_logs.find({"action": {"$regex": "sbom"}})]
    assert actions == [("job.sbom_generation.request", "success"), ("job.sbom_generation.finish", "success"), ("sbom.verify", "success")]


def test_job_fails_cleanly_when_the_project_disappears(client, app, auth_headers, project, db):
    client.post(url(project, "/sbom/generate"), headers=auth_headers)
    db.projects.delete_many({})
    assert run_worker(app) == 1
    job = db.analysis_jobs.find_one({"type": "sbom_generation"})
    assert job["state"] == "failed" and job["error"]["code"] == "PROJECT_NOT_FOUND" and db.sboms.count_documents({}) == 0


def test_sbom_timestamp_is_the_generation_time(client, app, auth_headers, project):
    before = datetime.now(timezone.utc) - timedelta(seconds=2)
    doc, _ = document(client, auth_headers, project, generate(client, app, auth_headers, project)["sbom_id"])
    stamp = datetime.fromisoformat(doc["metadata"]["timestamp"].replace("Z", "+00:00"))
    assert before <= stamp <= datetime.now(timezone.utc) + timedelta(seconds=2)


def test_compare_reports_changes_outside_the_component_list():
    old = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {
        "timestamp": "2026-01-01T00:00:00Z", "component": {"name": "octo/demo", "version": "aaa"},
        "properties": [{"name": "trustchain:commit_sha", "value": "aaa"}, {"name": "trustchain:branch", "value": "main"}]},
        "components": [lib("npm", "a", "1")], "serialNumber": "urn:uuid:1"}
    new = copy.deepcopy(old)
    new["metadata"].update(timestamp="2026-02-02T00:00:00Z", component={"name": "someone/else", "version": "bbb"})
    new["metadata"]["properties"][0]["value"] = "bbb"
    new["serialNumber"] = "urn:uuid:2"
    result = sbom_diff.compare(old, new)
    assert [(c["field"], c["old"], c["new"]) for c in result["document_changes"]] == [
        ("metadata.component", {"name": "octo/demo", "version": "aaa"}, {"name": "someone/else", "version": "bbb"}),
        ("metadata.commit_sha", "aaa", "bbb")]
    assert result["summary"]["document_changes"] == 2 and result["summary"]["identical"] is False and result["items"] == []
    # The timestamp and serial number alone never count as a change.
    only_volatile = copy.deepcopy(old)
    only_volatile["metadata"]["timestamp"] = "2027-01-01T00:00:00Z"
    only_volatile["serialNumber"] = "urn:uuid:3"
    assert sbom_diff.compare(old, only_volatile)["summary"]["identical"] is True


def test_compare_detects_a_renamed_component():
    old, new = lib("npm", "xlsx", "0.18.5"), lib("npm", "xlsx", "0.18.5")
    new["name"] = "xlsx-patched"
    item, = sbom_diff.compare(bom([old]), bom([new]))["items"]
    assert (item["change_type"], item["fields"]) == ("metadata", [{"field": "name", "old": "xlsx", "new": "xlsx-patched", "version": "0.18.5"}])


# --- regression: documents that are valid JSON but not a usable SBOM ------------------------

def _not_a_list(doc):
    doc["components"] = 5


def _component_not_an_object(doc):
    doc["components"][0] = "not a component"


def _property_without_value(doc):
    doc["components"][0]["properties"][0] = {"name": doc["components"][0]["properties"][0]["name"]}


def _dependencies_not_a_list(doc):
    doc["dependencies"] = {"ref": "root"}


@pytest.mark.parametrize("fix_digests", [False, True])
@pytest.mark.parametrize("change", [_not_a_list, _component_not_an_object, _property_without_value, _dependencies_not_a_list])
def test_a_structurally_damaged_document_fails_verification_instead_of_crashing(client, app, auth_headers, project, db, change, fix_digests):
    sbom_id = generate(client, app, auth_headers, project)["summary"]["sbom_id"]
    rewrite(db, sbom_id, change, fix_digests=fix_digests)
    result = verify(client, auth_headers, project, sbom_id)
    # With the recorded digests left alone the digest checks catch it; with the digests rewritten to
    # match, the regeneration from the snapshot does.
    assert result["valid"] is False and ("regeneration" if fix_digests else "content_digest") in failed(result)
    assert db.sboms.find_one({"_id": ObjectId(sbom_id)})["last_verification"]["valid"] is False
