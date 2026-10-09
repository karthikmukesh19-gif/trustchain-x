"""Self-validating security dataset: hashing, each quality check, the status rules, versioning and the API end to end.

Records in the unit tests are built by hand. The end-to-end tests build the
dataset from the dependency-intelligence fixture project. The tests also pin
down the limits of the feature: tampering is detected, missing layers are
gaps rather than zeros, and nothing claims the data is free of manipulation.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.analyzers.dataset import balance, duplicates, integrity, provenance, quality, validate
from app.analyzers.dataset.validation import LIMITATION, WEIGHTS
from app.models.collections import DATASET_QUALITY, DATASET_RECORDS, DATASETS
from tests.test_intelligence import (  # noqa: F401 - fixtures
    advisories, analysed, get, packages, project, repo, settings, start, url,
)

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)
LAYERS = {layer: {"collection": f"c_{layer}", "reference": f"ref-{layer}", "collected_at": NOW - timedelta(hours=1), "basis": "OBSERVED",
                  "model_version": "1"} for layer in provenance.LAYERS}
OVERCLAIMS = ("poison-free", "poison free", "free of poison", "guaranteed", "is clean", "tamper-proof", "cannot be manipulated")


def record(n, vulnerable=False, **changes):
    features = {"relationship": "DIRECT" if n % 2 else "TRANSITIVE", "depth": 1 if n % 2 else 2, "dependents": n, "dependencies": n % 3,
                "version_resolved": True, "vulnerability_count": 1 if vulnerable else 0, "max_severity": "HIGH" if vulnerable else "NOT_APPLICABLE",
                "reachability_state": "REACHABLE" if vulnerable else "NOT_APPLICABLE", "fragility_score": float(n % 100), "graph_risk": float(n % 50),
                "predictive_risk": float(n % 70), "attack_path_count": 1 if vulnerable else 0, "max_attack_path_score": 40.0 if vulnerable else 0.0}
    labels = {"vulnerable": vulnerable, "reachable_vulnerability": vulnerable, "risk_level": "HIGH" if vulnerable else "LOW"}
    item = {"record_id": f"npm:pkg{n}@1.0.{n}", "identity": {"ecosystem": "npm", "name": f"pkg{n}", "version": f"1.0.{n}"},
            "features": features, "labels": labels, "provenance": [{"layer": layer, **entry} for layer, entry in LAYERS.items()]}
    for path, value in changes.items():
        group, _, name = path.partition("__")
        if name:
            item[group] = {**item[group], name: value}
        else:
            item[group] = value
    item["record_hash"] = integrity.record_hash(item)
    return item


def dataset(count=40, vulnerable_every=4):
    return [record(n, vulnerable=n % vulnerable_every == 0) for n in range(count)]


def check(records, **overrides):
    arguments = dict(expected_dataset_hash=integrity.dataset_hash(records), expected_count=len(records), layers_available=LAYERS, now=NOW,
                     snapshot_committed_at=NOW - timedelta(days=1), chain_intact=True)
    return validate(records, **{**arguments, **overrides})


def factor(result, name):
    return next(f for f in result["factors"] if f["name"] == name)


# --- hashing ----------------------------------------------------------------------------

def test_record_hash_is_sha256_over_a_canonical_form():
    item = record(1)
    assert len(item["record_hash"]) == 64 and integrity.ALGORITHM == "SHA-256"
    reordered = {key: item[key] for key in reversed(list(item))}
    reordered["features"] = dict(reversed(list(item["features"].items())))
    assert integrity.record_hash(reordered) == item["record_hash"]


def test_any_change_to_a_hashed_field_changes_the_hash():
    item = record(1)
    for path, value in (("features__dependents", 99), ("labels__vulnerable", True), ("identity__version", "9.9.9"), ("record_id", "other")):
        assert record(1, **{path: value})["record_hash"] != item["record_hash"]
    assert integrity.record_hash({**item, "note": "not part of the hash"}) == item["record_hash"]


def test_timestamps_hash_the_same_before_and_after_storage_precision_loss():
    precise = NOW.replace(microsecond=123456)
    stored = NOW.replace(microsecond=123000)
    naive = stored.replace(tzinfo=None)
    assert integrity.canonical({"t": precise}) == integrity.canonical({"t": stored}) == integrity.canonical({"t": naive})
    assert b'"2026-03-01T12:00:00.123Z"' in integrity.canonical({"t": precise})
    assert integrity.canonical({"t": NOW.astimezone(timezone(timedelta(hours=5, minutes=30)))}) == integrity.canonical({"t": NOW})


def test_dataset_hash_ignores_order_and_detects_added_removed_and_swapped_records():
    records = dataset(10)
    base = integrity.dataset_hash(records)
    assert integrity.dataset_hash(list(reversed(records))) == base
    assert integrity.dataset_hash(records[:-1]) != base and integrity.dataset_hash(records + [record(99)]) != base
    assert integrity.dataset_hash([{**records[0], "record_hash": "0" * 64}, *records[1:]]) != base


def test_chain_hash_links_versions():
    first = integrity.chain_hash(None, "a" * 64)
    assert integrity.chain_hash(first, "b" * 64) != integrity.chain_hash(None, "b" * 64) and len(first) == 64


def test_verification_names_altered_records():
    records = dataset(10)
    expected = integrity.dataset_hash(records)
    assert integrity.verify(records, expected, 10)["status"] == "VERIFIED"
    records[3]["features"]["dependents"] = 12345
    outcome = integrity.verify(records, expected, 10)
    assert outcome["status"] == "MISMATCH" and outcome["altered_records"] == ["npm:pkg3@1.0.3"] and outcome["dataset_hash_matches"] is False


def test_verification_catches_a_removed_record_and_a_recomputed_hash():
    records = dataset(10)
    expected = integrity.dataset_hash(records)
    removed = integrity.verify(records[1:], expected, 10)
    assert removed["status"] == "MISMATCH" and removed["altered_count"] == 0 and removed["record_count_matches"] is False
    forged = dict(records[0], labels={**records[0]["labels"], "vulnerable": False})
    forged["record_hash"] = integrity.record_hash(forged)                # the record is self-consistent again...
    assert integrity.verify([forged, *records[1:]], expected, 10)["status"] == "MISMATCH"   # ...but the dataset hash gives it away


# --- individual checks ------------------------------------------------------------------

def test_completeness_counts_missing_cells_by_field():
    records = dataset(10)
    for item in records[:4]:
        item["features"]["fragility_score"] = None
    for item in records:
        item["labels"]["risk_level"] = None
    result = quality.completeness(records)
    assert result["missing_by_field"] == {"fragility_score": 4, "risk_level": 10} and result["fields_fully_missing"] == ["risk_level"]
    assert result["cells"] == 160 and result["filled"] == 146 and result["value"] == 0.9125 and result["records_complete"] == 0


@pytest.mark.parametrize("path,value,rule,kind", [
    ("features__fragility_score", 140, "range.fragility_score", "INVALID"), ("features__graph_risk", -1, "range.graph_risk", "INVALID"),
    ("features__predictive_risk", "high", "range.predictive_risk", "INVALID"), ("features__depth", -2, "range.depth", "INVALID"),
    ("features__dependents", 1.5, "range.dependents", "INVALID"), ("features__relationship", "SIDEWAYS", "enum.relationship", "INVALID"),
    ("features__max_severity", "SEVERE", "enum.max_severity", "INVALID"), ("labels__risk_level", "EXTREME", "enum.risk_level", "INVALID"),
    ("labels__vulnerable", "yes", "type.vulnerable", "INVALID"), ("features__fragility_score", True, "range.fragility_score", "INVALID"),
    ("labels__vulnerable", True, "label.vulnerable", "INCONSISTENT"),
    ("labels__reachable_vulnerability", True, "label.reachable_without_vulnerability", "INCONSISTENT"),
    ("features__max_severity", "HIGH", "severity_without_vulnerability", "INCONSISTENT"),
    ("features__reachability_state", "REACHABLE", "reachability_without_vulnerability", "INCONSISTENT"),
    ("features__attack_path_count", 2, "attack_path_without_vulnerability", "INCONSISTENT"),
    ("features__max_attack_path_score", 55.0, "attack_path_score_without_path", "INCONSISTENT"),
    ("features__depth", 0, "zero_depth", "INCONSISTENT")])
def test_record_problems(path, value, rule, kind):
    problems = quality.record_problems(record(2, **{path: value}))
    assert (kind, rule) in [(p["kind"], p["rule"]) for p in problems]


def test_more_record_problems_and_what_is_not_a_problem():
    assert quality.record_problems(record(3)) == [] and quality.record_problems(record(4, vulnerable=True)) == []
    assert ("INCONSISTENT", "direct_depth") in [(p["kind"], p["rule"]) for p in quality.record_problems(record(1, features__depth=3))]
    assert ("INCONSISTENT", "vulnerability_without_severity") in [
        (p["kind"], p["rule"]) for p in quality.record_problems(record(4, vulnerable=True, features__max_severity="NOT_APPLICABLE"))]
    assert ("INCONSISTENT", "label.reachable_state") in [
        (p["kind"], p["rule"]) for p in quality.record_problems(record(4, vulnerable=True, features__reachability_state="UNKNOWN"))]
    rules = {p["rule"] for p in quality.record_problems({"record_id": "", "identity": {}, "features": {}, "labels": {}})}
    assert rules == {"record_id", "identity.ecosystem", "identity.name"}
    gaps = record(5, features__fragility_score=None, labels__vulnerable=None, features__vulnerability_count=None)
    assert quality.record_problems(gaps) == []                               # unknown values are gaps, not errors


def test_consistency_lists_suspicious_records():
    records = dataset(20) + [record(100, features__fragility_score=500), record(101, labels__vulnerable=True)]
    result = quality.consistency(records)
    assert result["invalid_records"] == 1 and result["inconsistent_records"] == 1 and result["value"] == round(1 - 2 / 22, 4)
    assert [item["record_id"] for item in result["suspicious"]] == ["npm:pkg100@1.0.100", "npm:pkg101@1.0.101"]


def test_duplicates_identities_near_duplicates_and_label_conflicts():
    base = dataset(10)
    copy = {**base[1], "record_id": "npm:copy@1"}                                           # same content under another id
    twin = record(50)
    alike = {**twin, "record_id": "npm:alike@2.0.0", "identity": {"ecosystem": "npm", "name": "alike", "version": "2.0.0"}}
    conflict = {**alike, "record_id": "npm:conflict@3.0.0", "identity": {"ecosystem": "npm", "name": "conflict", "version": "3.0.0"},
                "labels": {**twin["labels"], "risk_level": "HIGH"}}
    result = duplicates.find(base + [copy, twin, alike, conflict])
    assert result["exact_duplicate_records"] == 1 and result["exact_duplicate_groups"] == [["npm:copy@1", "npm:pkg1@1.0.1"]]
    assert result["repeated_identity_records"] == 1
    assert result["near_duplicate_groups"] == 2 and result["label_conflict_records"] == 3
    assert result["value"] == round(1 - 4 / 14, 4) and "not penalised" in result["note"]
    assert duplicates.find(base)["value"] == 1.0 and duplicates.find([])["value"] is None


def test_class_balance():
    balanced = balance.evaluate(dataset(40, vulnerable_every=4))
    assert balanced["classes"] == {"true": 10, "false": 30} and balanced["minority_share"] == 0.25 and balanced["value"] == 1.0 and balanced["note"] is None
    skewed = balance.evaluate(dataset(40, vulnerable_every=20))
    assert skewed["minority_share"] == 0.05 and skewed["value"] == 0.25 and "typical of dependency data" in skewed["note"]
    single = balance.evaluate([record(n) for n in range(10)])
    assert single["value"] == 0.0 and "same class" in single["note"]
    unlabelled = balance.evaluate([record(n, labels__vulnerable=None) for n in range(5)])
    assert unlabelled["value"] is None and unlabelled["unlabelled"] == 5
    assert balanced["distributions"]["ecosystem"] == {"npm": 40} and balanced["distributions"]["relationship"] == {"DIRECT": 20, "TRANSITIVE": 20}


def test_provenance_completeness_and_source_coverage():
    full = provenance.evaluate(dataset(10), LAYERS)
    assert full["field_provenance_completeness"] == 1.0 and full["source_coverage"] == 1.0 and full["value"] == 1.0 and full["source_diversity"] == 7
    two_layers = {name: LAYERS[name] for name in ("inventory", "vulnerabilities")}
    records = [dict(item, provenance=[{"layer": name, **entry} for name, entry in two_layers.items()]) for item in dataset(10)]
    partial = provenance.evaluate(records, two_layers)
    assert partial["source_layers_missing"] == ["reachability", "fragility", "graph_risk", "predictive", "attack_paths"]
    assert partial["untraced_fields"]["fragility_score"] == 10 and partial["source_coverage"] == round(2 / 7, 4) and partial["value"] < 0.5
    untimed = [dict(item, provenance=[{**entry, "collected_at": None} for entry in item["provenance"]]) for item in dataset(3)]
    assert provenance.evaluate(untimed, LAYERS)["field_provenance_completeness"] == 0.0


# --- score and status -------------------------------------------------------------------

def test_weights_sum_to_one_hundred_and_all_factors_are_visible():
    result = check(dataset())
    assert sum(WEIGHTS.values()) == 100 and [f["name"] for f in result["factors"]] == list(WEIGHTS)
    assert round(sum(f["contribution"] for f in result["factors"]), 1) == result["quality_score"]


def test_a_sound_dataset_is_valid():
    result = check(dataset())
    assert result["status"] == "VALID" and result["quality_score"] == 100.0 and result["confidence"] == 1.0 and result["warnings"] == []


def test_an_empty_dataset_is_unknown():
    result = check([])
    assert result["status"] == "UNKNOWN" and result["quality_score"] is None and result["confidence"] == 0.0


def test_tampering_makes_the_dataset_invalid():
    records = dataset()
    expected = integrity.dataset_hash(records)
    records[5]["labels"]["vulnerable"] = True
    result = check(records, expected_dataset_hash=expected)
    assert result["status"] == "INVALID" and factor(result, "integrity")["value"] == 0.0 and result["integrity"]["altered_records"] == ["npm:pkg5@1.0.5"]
    assert "Integrity verification failed" in result["reasons"][0]


def test_a_broken_version_chain_makes_the_dataset_invalid():
    result = check(dataset(), chain_intact=False)
    assert result["status"] == "INVALID" and "version chain is broken" in " ".join(result["warnings"])


def test_schema_breaking_records_make_the_dataset_invalid():
    result = check(dataset() + [record(200, features__fragility_score=999)])
    assert result["status"] == "INVALID" and result["suspicious_records"][0]["record_id"] == "npm:pkg200@1.0.200"


def test_a_tiny_dataset_is_low_confidence():
    result = check(dataset(6, vulnerable_every=2))
    assert result["status"] == "LOW_CONFIDENCE" and result["confidence"] == 0.2 and "Only 6 record(s)" in result["reasons"][0]


def test_weaknesses_give_a_warning_not_a_pass():
    skewed = check(dataset(40, vulnerable_every=40))
    assert skewed["status"] == "WARNING" and 80 <= skewed["quality_score"] < 100 and any("typical of dependency data" in w for w in skewed["warnings"])
    contradictory = check(dataset() + [record(300, labels__vulnerable=True)])
    assert contradictory["status"] == "WARNING" and "1 suspicious record(s) need review." in contradictory["warnings"]
    assert check(dataset(), truncated=True)["status"] == "WARNING"


def test_missing_layers_lower_the_score_and_are_named():
    two_layers = {name: LAYERS[name] for name in ("inventory", "vulnerabilities")}
    records = []
    for item in dataset():
        for name in ("reachability_state", "fragility_score", "graph_risk", "predictive_risk", "attack_path_count", "max_attack_path_score"):
            item["features"][name] = None
        item["labels"].update(reachable_vulnerability=None, risk_level=None)
        item["provenance"] = [{"layer": name, **entry} for name, entry in two_layers.items()]
        item["record_hash"] = integrity.record_hash(item)
        records.append(item)
    result = check(records, layers_available=two_layers)
    assert result["status"] == "WARNING" and result["quality_score"] < 90
    assert any("No data from: reachability" in warning for warning in result["warnings"])
    assert factor(result, "completeness")["value"] == 0.5


def test_an_unlabelled_dataset_has_unknown_balance_and_lower_confidence():
    records = [record(n, labels__vulnerable=None, features__vulnerability_count=None) for n in range(40)]
    result = check(records)
    assert factor(result, "balance")["status"] == "UNKNOWN" and factor(result, "balance")["contribution"] is None and result["confidence"] == 0.9


def test_timestamps_in_the_future_or_before_the_commit_are_flagged():
    future = [dict(item, provenance=[{**entry, "collected_at": NOW + timedelta(days=2)} for entry in item["provenance"]]) for item in dataset(40)]
    for item in future:
        item["record_hash"] = integrity.record_hash(item)
    result = check(future)
    assert factor(result, "timestamps")["value"] == 0.0 and result["timestamps"]["in_future"] == 280 and result["status"] == "WARNING"
    old = check(dataset(12), snapshot_committed_at=NOW + timedelta(hours=3))
    assert old["timestamps"]["before_commit"] == 84


def test_validation_is_deterministic_and_states_its_limit():
    first, second = check(dataset()), check(dataset())
    assert first == second and "cannot establish that the data is free of deliberate manipulation" in LIMITATION
    assert not any(phrase in str(first).lower() for phrase in OVERCLAIMS)


# --- end to end -------------------------------------------------------------------------

@pytest.fixture
def validated(client, app, auth_headers, project):
    job = start(client, app, auth_headers, project, "/datasets/validate")
    assert job["state"] == "completed", job
    return project


def test_validation_needs_a_snapshot(client, auth_headers):
    created = client.post("/api/projects", json={"name": "Empty", "repository_url": "https://github.com/octo/empty"}, headers=auth_headers).json()
    assert client.post(url(created, "/datasets/validate"), headers=auth_headers).status_code == 409
    body = get(client, auth_headers, created, "/datasets")
    assert body["items"] == [] and body["current"] is None and body["chain_intact"] is None


def test_a_dataset_version_is_built_from_the_stored_layers(client, auth_headers, validated, db):
    body = get(client, auth_headers, validated, "/datasets")
    current = body["current"]
    assert body["total"] == 1 and current["version"] == 1 and current["record_count"] == 9 == db[DATASET_RECORDS].count_documents({})
    assert current["hash_algorithm"] == "SHA-256" and len(current["dataset_hash"]) == 64 and current["previous_dataset_id"] is None
    assert [source["layer"] for source in current["sources"]] == ["inventory", "vulnerabilities"]
    assert "owner_id" not in current and "project_id" not in current
    # Nine records are too few to rely on, and five layers have not been analysed: the status says so.
    assert current["latest_quality"]["status"] == "LOW_CONFIDENCE" and body["chain_intact"] is True
    assert "cannot establish that the data is free of deliberate manipulation" in body["limitation"]


def test_records_carry_features_labels_provenance_and_a_hash(client, auth_headers, validated):
    dataset_id = get(client, auth_headers, validated, "/datasets")["current"]["id"]
    body = get(client, auth_headers, validated, f"/datasets/{dataset_id}")
    assert body["records"]["total"] == 9
    by_id = {item["record_id"]: item for item in body["records"]["items"]}
    vulnerable = by_id["npm:qs@6.7.0"]
    assert vulnerable["labels"]["vulnerable"] is True and vulnerable["features"]["vulnerability_count"] == 3
    assert vulnerable["features"]["fragility_score"] is None and vulnerable["labels"]["risk_level"] is None      # layer not analysed: a gap
    assert vulnerable["features"]["reachability_state"] is None and len(vulnerable["record_hash"]) == 64
    assert {entry["layer"] for entry in vulnerable["provenance"]} == {"inventory", "vulnerabilities"}
    clean = by_id["npm:express@4.17.1"]
    assert clean["labels"]["vulnerable"] is False and clean["features"]["max_severity"] == "NOT_APPLICABLE"
    assert get(client, auth_headers, validated, f"/datasets/{dataset_id}", vulnerable="true")["records"]["total"] == 4
    assert get(client, auth_headers, validated, f"/datasets/{dataset_id}", limit=2, skip=8)["records"]["items"].__len__() == 1
    assert get(client, auth_headers, validated, f"/datasets/{dataset_id}", suspicious="true")["records"]["total"] == 0


def test_quality_shows_every_factor_and_verifies_integrity_now(client, auth_headers, validated):
    dataset_id = get(client, auth_headers, validated, "/datasets")["current"]["id"]
    body = get(client, auth_headers, validated, f"/datasets/{dataset_id}/quality")
    quality_row = body["quality"]
    assert [f["name"] for f in quality_row["factors"]] == list(WEIGHTS) and quality_row["integrity"]["status"] == "VERIFIED"
    assert body["integrity_now"]["status"] == "VERIFIED" and body["integrity_now"]["chain_intact"] is True
    assert quality_row["provenance"]["source_layers_missing"] == ["reachability", "fragility", "graph_risk", "predictive", "attack_paths"]
    assert quality_row["balance"]["classes"] == {"true": 4, "false": 5} and len(body["history"]) == 1


def test_more_layers_give_a_new_version_with_fewer_gaps(client, app, auth_headers, validated, db):
    for path in ("/code-reachability/analyze", "/predictive-risk/analyze", "/attack-paths/analyze"):
        assert start(client, app, auth_headers, validated, path)["state"] == "completed"
    job = start(client, app, auth_headers, validated, "/datasets/validate")
    assert job["summary"]["new_version"] is True and job["summary"]["version"] == 2
    listing = get(client, auth_headers, validated, "/datasets")
    current, first = listing["items"][0], listing["items"][1]
    assert current["previous_dataset_id"] == first["id"] and current["previous_dataset_hash"] == first["dataset_hash"]
    assert current["changes"] == {"comparable": True, "added": 0, "removed": 0, "changed": 9, "unchanged": 0, "added_examples": [],
                                  "removed_examples": [], "changed_examples": current["changes"]["changed_examples"]}
    assert current["latest_quality"]["quality_score"] > first["latest_quality"]["quality_score"] and listing["chain_intact"] is True
    record_ = next(item for item in get(client, auth_headers, validated, f"/datasets/{current['id']}")["records"]["items"]
                   if item["record_id"] == "pypi:requests@2.19.1")
    assert record_["features"]["reachability_state"] == "REACHABLE" and record_["labels"]["reachable_vulnerability"] is True
    assert record_["features"]["attack_path_count"] == 2 and record_["features"]["fragility_score"] is not None
    assert len(record_["provenance"]) == 7
    quality_row = get(client, auth_headers, validated, f"/datasets/{current['id']}/quality")["quality"]
    assert quality_row["provenance"]["source_layers_missing"] == [] and quality_row["completeness"]["value"] > 0.9


def test_an_unchanged_dataset_is_validated_again_without_a_new_version(client, app, auth_headers, validated, db):
    job = start(client, app, auth_headers, validated, "/datasets/validate")
    assert job["summary"]["new_version"] is False and job["summary"]["version"] == 1 and "validated again" in job["message"]
    assert db[DATASETS].count_documents({}) == 1 and db[DATASET_QUALITY].count_documents({}) == 2
    dataset_id = get(client, auth_headers, validated, "/datasets")["current"]["id"]
    assert len(get(client, auth_headers, validated, f"/datasets/{dataset_id}/quality")["history"]) == 2
    assert get(client, auth_headers, validated, "/datasets")["current"]["validations"] == 2


def test_tampering_with_a_stored_record_is_detected_on_read_and_on_validation(client, app, auth_headers, validated, db):
    dataset_id = get(client, auth_headers, validated, "/datasets")["current"]["id"]
    db[DATASET_RECORDS].update_one({"record_id": "npm:qs@6.7.0"}, {"$set": {"labels.vulnerable": False, "features.vulnerability_count": 0}})
    now = get(client, auth_headers, validated, f"/datasets/{dataset_id}/quality")["integrity_now"]
    assert now["status"] == "MISMATCH" and now["altered_records"] == ["npm:qs@6.7.0"]
    job = start(client, app, auth_headers, validated, "/datasets/validate")
    # The stored version no longer matches the results, so a new version is written; validating the old one now fails.
    assert job["summary"]["version"] == 1 and job["summary"]["status"] == "INVALID"
    latest_quality = get(client, auth_headers, validated, f"/datasets/{dataset_id}/quality")["quality"]
    assert latest_quality["status"] == "INVALID" and latest_quality["integrity"]["altered_count"] == 1


def test_a_deleted_record_and_a_deleted_version_are_detected(client, app, auth_headers, validated, db):
    assert start(client, app, auth_headers, validated, "/code-reachability/analyze")["state"] == "completed"
    assert start(client, app, auth_headers, validated, "/datasets/validate")["summary"]["version"] == 2
    listing = get(client, auth_headers, validated, "/datasets")
    newest, oldest = listing["items"][0]["id"], listing["items"][1]["id"]
    db[DATASET_RECORDS].delete_one({"record_id": "npm:ms@2.0.0", "dataset_id": db[DATASETS].find_one({"version": 2})["_id"]})
    assert get(client, auth_headers, validated, f"/datasets/{newest}/quality")["integrity_now"]["record_count_matches"] is False
    db[DATASETS].delete_one({"version": 1})
    assert get(client, auth_headers, validated, "/datasets")["chain_intact"] is False
    assert client.get(url(validated, f"/datasets/{oldest}"), headers=auth_headers).status_code == 404


def test_a_new_snapshot_starts_a_new_version_and_keeps_the_old_one(client, app, auth_headers, validated, repo):
    repo.files["requirements.txt"] = b"requests==2.19.1\nPyYAML==5.1\nflask==3.0.0\n"
    assert start(client, app, auth_headers, validated, "/analysis/dependencies")["state"] == "completed"
    assert get(client, auth_headers, validated, "/datasets")["current"] is None          # nothing describes the new snapshot yet
    job = start(client, app, auth_headers, validated, "/datasets/validate")
    assert job["summary"]["version"] == 2 and job["summary"]["records"] == 10
    listing = get(client, auth_headers, validated, "/datasets")
    assert listing["current"]["version"] == 2 and listing["current"]["changes"]["added"] == 1 and listing["total"] == 2
    record_ = get(client, auth_headers, validated, f"/datasets/{listing['current']['id']}")["records"]["items"][0]
    assert record_["labels"]["vulnerable"] is None                                       # the new snapshot has not been checked: unknown, not False


@pytest.mark.parametrize("settings", [{"DATASET_MAX_RECORDS": "5"}], indirect=True)
def test_the_record_limit_is_applied_and_reported(client, auth_headers, validated):
    current = get(client, auth_headers, validated, "/datasets")["current"]
    assert current["record_count"] == 5 and current["truncated"] is True
    quality_row = get(client, auth_headers, validated, f"/datasets/{current['id']}/quality")["quality"]
    assert any("record limit" in warning for warning in quality_row["warnings"])


@pytest.mark.parametrize("settings", [{"INTELLIGENCE_HISTORY_LIMIT": "2"}], indirect=True)
def test_old_versions_keep_their_hashes_when_their_records_are_pruned(client, app, auth_headers, validated, repo, db):
    for extra in ("flask==3.0.0", "flask==3.0.1"):
        repo.files["requirements.txt"] = f"requests==2.19.1\nPyYAML==5.1\n{extra}\n".encode()
        assert start(client, app, auth_headers, validated, "/analysis/dependencies")["state"] == "completed"
        assert start(client, app, auth_headers, validated, "/datasets/validate")["state"] == "completed"
    listing = get(client, auth_headers, validated, "/datasets")
    assert [item["version"] for item in listing["items"]] == [3, 2, 1] and listing["chain_intact"] is True
    assert [item["records_pruned"] for item in listing["items"]] == [False, False, True]
    oldest = listing["items"][2]["id"]
    assert get(client, auth_headers, validated, f"/datasets/{oldest}")["records"]["total"] == 0
    assert get(client, auth_headers, validated, f"/datasets/{oldest}/quality")["integrity_now"]["status"] == "NOT_AVAILABLE"


def test_ids_are_validated_and_other_users_see_nothing(client, auth_headers, other_headers, validated):
    dataset_id = get(client, auth_headers, validated, "/datasets")["current"]["id"]
    for bad in ("abc", "0" * 24, "{$ne:1}", "z" * 24):
        assert client.get(url(validated, f"/datasets/{bad}"), headers=auth_headers).status_code == 404
        assert client.get(url(validated, f"/datasets/{bad}/quality"), headers=auth_headers).status_code == 404
    for method, path in (("post", "/datasets/validate"), ("get", "/datasets"), ("get", f"/datasets/{dataset_id}"), ("get", f"/datasets/{dataset_id}/quality")):
        assert getattr(client, method)(url(validated, path), headers=other_headers).status_code == 404
        assert getattr(client, method)(url(validated, path)).status_code == 401
    assert client.post(url(validated, "/datasets/validate"), headers=auth_headers, json={"force": True}).status_code == 422
    assert client.get(url(validated, f"/datasets/{dataset_id}"), headers=auth_headers, params={"limit": 0}).status_code == 422


def test_no_response_claims_the_data_is_free_of_manipulation(client, auth_headers, validated):
    dataset_id = get(client, auth_headers, validated, "/datasets")["current"]["id"]
    text = (client.get(url(validated, "/datasets"), headers=auth_headers).text
            + client.get(url(validated, f"/datasets/{dataset_id}/quality"), headers=auth_headers).text).lower()
    assert not any(phrase in text for phrase in OVERCLAIMS)


def test_deleting_the_project_removes_its_datasets(client, auth_headers, validated, db):
    assert client.delete(f"/api/projects/{validated['id']}", headers=auth_headers).status_code == 204
    for collection in (DATASETS, DATASET_RECORDS, DATASET_QUALITY):
        assert db[collection].count_documents({}) == 0
