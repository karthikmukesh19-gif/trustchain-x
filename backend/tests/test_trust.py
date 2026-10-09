"""The trust engine: every component's normalisation, the handling of unknowns, explanations, history and the API.

The property that matters most is that missing evidence never improves the
score: an unknown component has no value, widens the bounds, lowers the
confidence, and below the coverage threshold no score is given at all.
"""

import pytest

from app.models.collections import SBOMS, TRUST_SCORES
from app.services.trust import WEIGHTS, WEIGHTS_STATEMENT, compute, history
from app.services.trust import normalization as N
from app.services.trust.explanation import explain
from tests.pipeline import (  # noqa: F401 - fixtures
    advisories, created, evidence_layers, packages, repo, run_layers,
)
from tests.test_intelligence import get, settings, start, url  # noqa: F401

OVERCLAIMS = ("guaranteed", "certified", "is safe", "is secure", "no risk", "zero-day", "malicious")


def layer(status="ANALYSED", **data):
    return {"status": status, "available": status == "ANALYSED", "reference": {"collection": "c", "id": "1"} if status == "ANALYSED" else None,
            "as_of": None, **data}


def analysed(**overrides):
    """Every layer analysed with unremarkable results."""
    state = {
        "inventory": layer(stats={"total": 100, "unresolved_versions": 0, "relationship_unknown": 0, "without_path": 0,
                                  "by_relationship_basis": {"OBSERVED": 100}}),
        "sbom": layer(verified=True, component_count=100, unresolved_components=0, verification={"valid": True, "failed_checks": []}),
        "vulnerabilities": layer(by_severity={}, dependencies_total=100, dependencies_checked=100, affected_matches=0, affected_dependencies=0),
        "reachability": layer(by_status={}, source_complete=True),
        "fragility": layer(summary={"mean": 10.0, "highest": 30.0, "mean_confidence": 0.9}),
        "graph_risk": layer(summary={}),
        "predictive": layer(summary={"top": [{"score": 20.0}, {"score": 10.0}]}),
        "attack_paths": layer(summary={"paths": 0, "highest_score": None, "by_status": {}}),
        "maintainers": layer(attention_score=10.0, confidence=0.8, indicators=[]),
        "commits": layer(analysed_total=30, window=30, highest_anomaly=20.0, mean_anomaly=5.0, mean_confidence=0.9, security_events=0),
        "dataset": layer(quality_status="VALID", quality_score=95.0, quality_confidence=1.0, version=1),
    }
    state.update(overrides)
    return state


def none_analysed():
    return {name: layer("NOT_ANALYSED") for name in analysed()}


def component(result, name):
    return next(item for item in result["components"] if item["name"] == name)


# --- weights ----------------------------------------------------------------------------

def test_the_weights_are_the_documented_ones_and_carry_their_caveat():
    assert WEIGHTS == {"dependency_risk": 15, "sbom_integrity": 15, "vulnerability_exposure": 15, "code_reachability": 10,
                       "dependency_fragility": 10, "attack_path_risk": 10, "maintainer_behaviour": 10, "commit_behaviour": 5,
                       "dataset_confidence": 5, "predictive_risk": 5}
    assert WEIGHTS_STATEMENT == "These weights are expert-defined initial weights and are not statistically trained."
    result = compute(analysed())
    assert result["weights_statement"] == WEIGHTS_STATEMENT and [c["name"] for c in result["components"]] == list(WEIGHTS)


# --- components -------------------------------------------------------------------------

def test_dependency_risk_measures_what_cannot_be_pinned_down():
    clean = N.dependency_risk(analysed())
    assert clean["risk"] == 0.0 and clean["status"] == "KNOWN" and clean["confidence"] == 1.0
    loose = N.dependency_risk(analysed(inventory=layer(stats={"total": 10, "unresolved_versions": 5, "relationship_unknown": 2, "without_path": 1,
                                                              "by_relationship_basis": {"OBSERVED": 4, "INFERRED": 4, "UNKNOWN": 2}})))
    assert loose["risk"] == round(100 * (0.4 * 0.5 + 0.2 * 0.2 + 0.2 * 0.6 + 0.2 * 0.1), 1) == 38.0
    assert N.dependency_risk(analysed(inventory=layer(stats={"total": 0})))["risk"] == 0.0
    assert N.dependency_risk(none_analysed())["status"] == "UNKNOWN"


def test_sbom_integrity_distinguishes_verified_failed_unverified_and_missing():
    assert N.sbom_integrity(analysed())["risk"] == 0.0
    partial = N.sbom_integrity(analysed(sbom=layer(verified=True, component_count=10, unresolved_components=5)))
    assert partial["risk"] == 15.0
    failed = N.sbom_integrity(analysed(sbom=layer(verified=False, verification={"failed_checks": ["content_digest"]})))
    assert failed["risk"] == 100.0 and "content_digest" in failed["detail"]
    unverified = N.sbom_integrity(analysed(sbom=layer(verified=None)))
    assert unverified["status"] == "UNKNOWN" and unverified["risk"] is None and "Unverified is not the same as intact" in unverified["detail"]
    assert N.sbom_integrity(analysed(sbom=layer("STALE")))["status"] == "UNKNOWN"
    assert "No SBOM exists" in N.sbom_integrity(none_analysed())["detail"]


@pytest.mark.parametrize("counts,expected", [({}, 0.0), ({"LOW": 1}, 5.0), ({"HIGH": 1}, 30.0), ({"CRITICAL": 1}, 50.0),
                                             ({"CRITICAL": 1, "HIGH": 1}, 65.0), ({"UNKNOWN": 2}, 27.8), ({"CRITICAL": 10}, 99.9)])
def test_vulnerability_exposure_saturates(counts, expected):
    result = N.vulnerability_exposure(analysed(vulnerabilities=layer(by_severity=counts, dependencies_total=10, dependencies_checked=10,
                                                                     affected_matches=sum(counts.values()), affected_dependencies=1)))
    assert result["risk"] == expected


def test_vulnerability_exposure_confidence_follows_what_could_be_checked():
    result = N.vulnerability_exposure(analysed(vulnerabilities=layer(by_severity={}, dependencies_total=10, dependencies_checked=6, affected_matches=0)))
    assert result["risk"] == 0.0 and result["confidence"] == 0.6 and "4 package(s) could not be checked" in result["detail"]
    assert N.vulnerability_exposure(none_analysed())["status"] == "UNKNOWN"
    assert N.vulnerability_exposure(analysed(vulnerabilities=layer("STALE")))["status"] == "UNKNOWN"


def test_code_reachability_counts_undecided_findings_half():
    vulnerable = layer(by_severity={"HIGH": 4}, dependencies_total=10, dependencies_checked=10, affected_matches=4)
    reach = lambda **by_status: analysed(vulnerabilities=vulnerable, reachability=layer(by_status=by_status, source_complete=True))   # noqa: E731
    assert N.code_reachability(reach(REACHABLE=4))["risk"] == 100.0
    assert N.code_reachability(reach(NOT_CONFIRMED_REACHABLE=4))["risk"] == 10.0
    mixed = N.code_reachability(reach(REACHABLE=1, UNKNOWN=1, UNSUPPORTED=1, NOT_CONFIRMED_REACHABLE=1))
    assert mixed["risk"] == round(100 * (1 + 0.5 + 0.5 + 0.1) / 4, 1) and mixed["confidence"] == 0.5
    undecided = N.code_reachability(reach(UNSUPPORTED=4))
    assert undecided["risk"] == 50.0 and undecided["confidence"] == 0.1 and "not cleared" in undecided["detail"]


def test_code_reachability_without_vulnerabilities_or_without_analysis():
    nothing = N.code_reachability(analysed(reachability=layer("NOT_ANALYSED")))
    assert nothing["status"] == "KNOWN" and nothing["risk"] == 0.0 and "no vulnerable functionality" in nothing["detail"]
    vulnerable = layer(by_severity={"HIGH": 1}, dependencies_total=1, dependencies_checked=1, affected_matches=1)
    assert N.code_reachability(analysed(vulnerabilities=vulnerable, reachability=layer("NOT_ANALYSED")))["status"] == "UNKNOWN"
    assert N.code_reachability(analysed(vulnerabilities=vulnerable, reachability=layer(by_status={})))["status"] == "UNKNOWN"
    assert N.code_reachability(none_analysed())["status"] == "UNKNOWN"


def test_the_remaining_components():
    state = analysed(attack_paths=layer(summary={"paths": 4, "highest_score": 56.0, "by_status": {"SUPPORTED_PATH": 1, "UNKNOWN_PATH": 2}}),
                     maintainers=layer(attention_score=62.5, confidence=0.6, indicators=[{"type": "CONTRIBUTOR_CONCENTRATION", "status": "OBSERVED"}]),
                     dataset=layer(quality_status="WARNING", quality_score=70.0, quality_confidence=0.9, version=2))
    assert N.dependency_fragility(state)["risk"] == 20.0 and N.dependency_fragility(state)["confidence"] == 0.9
    paths = N.attack_path_risk(state)
    assert paths["risk"] == 56.0 and paths["confidence"] == 0.75
    assert N.attack_path_risk(analysed())["risk"] == 0.0 and "no attack path" in N.attack_path_risk(analysed())["detail"]
    people = N.maintainer_behaviour(state)
    assert people["risk"] == 62.5 and "CONTRIBUTOR_CONCENTRATION" in people["detail"] and "not any person" in people["detail"]
    assert N.commit_behaviour(state)["risk"] == round(0.6 * 20 + 0.4 * 5, 1)
    assert N.dataset_confidence(state)["risk"] == 37.0            # 100 − 70 × 0.9: the score counts only as far as it is trusted
    assert N.dataset_confidence(analysed(dataset=layer(quality_status="LOW_CONFIDENCE", quality_score=99.0, quality_confidence=0.3, version=1)))["risk"] == 70.3
    assert N.dataset_confidence(analysed(dataset=layer(quality_status="INVALID", quality_score=10.0)))["risk"] == 100.0
    predicted = N.predictive_risk(state)
    assert predicted["risk"] == 15.0 and predicted["basis"] == "PREDICTED" and "not a forecast of an event" in predicted["detail"]


@pytest.mark.parametrize("override,name", [
    ({"fragility": layer(summary={})}, "dependency_fragility"), ({"maintainers": layer(attention_score=None)}, "maintainer_behaviour"),
    ({"maintainers": layer("UNAVAILABLE")}, "maintainer_behaviour"), ({"commits": layer(analysed_total=0)}, "commit_behaviour"),
    ({"dataset": layer(quality_status="UNKNOWN")}, "dataset_confidence"), ({"predictive": layer(summary={"top": []})}, "predictive_risk"),
    ({"attack_paths": layer("NOT_ANALYSED")}, "attack_path_risk")])
def test_components_without_usable_data_are_unknown_with_no_value(override, name):
    found = component(compute(analysed(**override)), name)
    assert found["status"] == "UNKNOWN" and found["risk"] is None and found["contribution"] is None and found["confidence"] == 0.0


# --- the score --------------------------------------------------------------------------

def test_the_score_is_the_documented_weighted_average():
    result = compute(analysed())
    risks = {c["name"]: c["risk"] for c in result["components"]}
    expected = sum(WEIGHTS[name] * risks[name] for name in WEIGHTS) / 100
    assert result["status"] == "SCORED" and result["risk_score"] == round(expected, 1) and result["trust_score"] == round(100 - expected, 1)
    assert result["coverage"] == 1.0 and result["risk_low"] == result["risk_high"] == result["risk_score"] and result["unknown_components"] == []
    assert round(sum(c["contribution"] for c in result["components"]), 1) == result["risk_score"]
    assert result["band"] == "LOW_RISK" and compute(analysed()) == result


def test_an_unknown_component_never_improves_the_score():
    bad_sbom = analysed(sbom=layer(verified=False, verification={"failed_checks": ["x"]}))
    with_failure = compute(bad_sbom)
    hidden = compute(analysed(sbom=layer("NOT_ANALYSED")))
    full = compute(analysed())
    # Not analysing the SBOM does not earn the score a verified SBOM would: the bounds and confidence show the gap.
    assert hidden["confidence"] < full["confidence"] and hidden["coverage"] == 0.85
    assert hidden["risk_high"] == round(hidden["risk_low"] + 15.0, 1) and hidden["risk_low"] < hidden["risk_score"] < hidden["risk_high"]
    assert with_failure["risk_score"] > full["risk_score"]
    assert component(hidden, "sbom_integrity")["risk"] is None


def test_renormalisation_keeps_the_average_over_what_is_known():
    state = none_analysed()
    state["inventory"] = analysed()["inventory"]
    state["vulnerabilities"] = layer(by_severity={"CRITICAL": 1}, dependencies_total=10, dependencies_checked=10, affected_matches=1)
    result = compute(state, min_coverage=0.2)
    assert result["known_weight"] == 30 and result["risk_score"] == 25.0          # (15 × 0 + 15 × 50) / 30
    assert component(result, "vulnerability_exposure")["effective_weight"] == 50.0
    assert result["risk_low"] == 7.5 and result["risk_high"] == 77.5 and result["confidence"] == 0.3


def test_below_the_coverage_threshold_there_is_no_score():
    state = none_analysed()
    state["inventory"] = analysed()["inventory"]
    result = compute(state)
    assert result["status"] == "INSUFFICIENT_DATA" and result["trust_score"] is None and result["risk_score"] is None and result["band"] is None
    assert result["coverage"] == 0.15 and "at least 60% is required" in result["insufficient_reason"]
    assert result["risk_low"] == 0.0 and result["risk_high"] == 85.0
    nothing = compute(none_analysed(), min_coverage=0.0)
    assert nothing["status"] == "INSUFFICIENT_DATA" and nothing["trust_score"] is None and nothing["confidence"] == 0.0


def test_the_threshold_is_inclusive_and_configurable():
    state = analysed(**{name: layer("NOT_ANALYSED") for name in ("sbom", "attack_paths", "maintainers", "commits")})   # 60 of 100 known
    assert compute(state)["status"] == "SCORED" and compute(state, min_coverage=0.61)["status"] == "INSUFFICIENT_DATA"


@pytest.mark.parametrize("trust,expected", [(100, "LOW_RISK"), (80, "LOW_RISK"), (79.9, "MODERATE_RISK"), (60, "MODERATE_RISK"),
                                            (59.9, "ELEVATED_RISK"), (40, "ELEVATED_RISK"), (39.9, "HIGH_RISK"), (0, "HIGH_RISK")])
def test_bands(trust, expected):
    from app.services.trust.engine import band

    assert band(trust) == expected


def test_scores_stay_within_bounds_for_extreme_inputs():
    worst = analysed(
        inventory=layer(stats={"total": 5, "unresolved_versions": 5, "relationship_unknown": 5, "without_path": 5, "by_relationship_basis": {}}),
        sbom=layer(verified=False), vulnerabilities=layer(by_severity={"CRITICAL": 50}, dependencies_total=5, dependencies_checked=5, affected_matches=50),
        reachability=layer(by_status={"REACHABLE": 50}, source_complete=True), fragility=layer(summary={"mean": 100, "highest": 100, "mean_confidence": 1}),
        attack_paths=layer(summary={"paths": 50, "highest_score": 100, "by_status": {"SUPPORTED_PATH": 50}}),
        maintainers=layer(attention_score=100, confidence=1, indicators=[]),
        commits=layer(analysed_total=1, window=1, highest_anomaly=100, mean_anomaly=100, mean_confidence=1, security_events=9),
        dataset=layer(quality_status="INVALID", quality_score=0), predictive=layer(summary={"top": [{"score": 100}] * 5}))
    result = compute(worst)
    assert result["risk_score"] == 100.0 and result["trust_score"] == 0.0 and result["band"] == "HIGH_RISK"
    assert all(0 <= c["risk"] <= 100 for c in result["components"])


# --- explanation ------------------------------------------------------------------------

def test_the_explanation_shows_the_calculation_the_drivers_and_the_unknowns():
    state = analysed(vulnerabilities=layer(by_severity={"CRITICAL": 1, "HIGH": 2}, dependencies_total=100, dependencies_checked=100, affected_matches=3,
                                           affected_dependencies=2),
                     reachability=layer(by_status={"REACHABLE": 1, "UNSUPPORTED": 2}, source_complete=True), maintainers=layer("NOT_ANALYSED"))
    result = compute(state)
    told = explain(result)
    assert told["headline"].startswith(f"Trust score {result['trust_score']} of 100")
    assert f"/ {result['known_weight']} = {result['risk_score']}" in told["calculation"]["worked"]
    assert told["calculation"]["weights_statement"] == WEIGHTS_STATEMENT and "carry 10 of 100 weight points" in told["calculation"]["bounds"]
    assert [item["name"] for item in told["top_risks"]][:2] == ["vulnerability_exposure", "code_reachability"]
    assert [item["name"] for item in told["unknown"]] == ["maintainer_behaviour"]
    texts = [item["text"] for item in told["recommendations"]]
    assert texts[0].startswith("Upgrade the affected packages") and "Run the maintainer behaviour analysis." in texts[-1]
    assert all(item["basis"] == "RECOMMENDED" for item in told["recommendations"])
    assert [item["priority"] for item in told["recommendations"]] == list(range(1, len(texts) + 1))


def test_the_explanation_of_insufficient_data_gives_no_number():
    told = explain(compute(none_analysed()))
    assert told["headline"].startswith("INSUFFICIENT DATA") and told["calculation"]["worked"] is None and told["top_risks"] == []
    assert len(told["recommendations"]) == 10 and told["recommendations"][0]["text"].startswith("Run the dependency analysis.")


# --- comparison -------------------------------------------------------------------------

def test_comparing_two_results():
    before = {"_id": "a", **compute(analysed(sbom=layer("NOT_ANALYSED"))), "snapshot_id": "s1"}
    after = {"_id": "b", **compute(analysed(vulnerabilities=layer(by_severity={"HIGH": 1}, dependencies_total=100, dependencies_checked=100,
                                                                 affected_matches=1), reachability=layer(by_status={"REACHABLE": 1}))), "snapshot_id": "s1"}
    diff = history.compare(before, after)
    changes = {item["name"]: item["change"] for item in diff["components"]}
    assert changes["sbom_integrity"] == "BECAME_KNOWN" and changes["vulnerability_exposure"] == "RISK_UP" and changes["dependency_risk"] == "UNCHANGED"
    assert diff["trust_delta"] == round(after["trust_score"] - before["trust_score"], 1) and diff["coverage_delta"] == 0.15 and diff["same_snapshot"]
    assert set(diff["changed"]) == {"sbom_integrity", "vulnerability_exposure", "code_reachability"}
    insufficient = {"_id": "c", **compute(none_analysed()), "snapshot_id": "s2"}
    gone = history.compare(after, insufficient)
    assert gone["trust_delta"] is None and "no score difference" in gone["note"] and gone["same_snapshot"] is False
    assert {item["change"] for item in gone["components"]} == {"BECAME_UNKNOWN"}


# --- end to end -------------------------------------------------------------------------

@pytest.fixture
def scored(client, app, auth_headers, evidence_layers):
    job = start(client, app, auth_headers, evidence_layers, "/trust/analyze")
    assert job["state"] == "completed", job
    return evidence_layers


def test_no_score_exists_until_one_is_calculated(client, auth_headers, evidence_layers):
    body = get(client, auth_headers, evidence_layers, "/trust")
    assert body["trust"] is None and body["up_to_date"] is None and body["weights"] == WEIGHTS and body["weights_statement"] == WEIGHTS_STATEMENT
    assert client.get(url(evidence_layers, "/trust/explanation"), headers=auth_headers).status_code == 404
    assert get(client, auth_headers, evidence_layers, "/trust/history")["items"] == []


def test_a_project_without_a_snapshot_cannot_be_scored(client, auth_headers):
    made = client.post("/api/projects", json={"name": "Empty", "repository_url": "https://github.com/octo/none"}, headers=auth_headers).json()
    assert client.post(url(made, "/trust/analyze"), headers=auth_headers).status_code == 409


def test_with_every_layer_analysed_a_score_is_given_with_all_its_parts(client, auth_headers, scored, db):
    body = get(client, auth_headers, scored, "/trust")
    trust = body["trust"]
    assert trust["status"] == "SCORED" and trust["coverage"] == 1.0 and trust["unknown_components"] == [] and body["up_to_date"] is True
    assert trust["trust_score"] == round(100 - trust["risk_score"], 1) and 0 < trust["risk_score"] < 100 and 0 < trust["confidence"] <= 1
    assert [c["name"] for c in trust["components"]] == list(WEIGHTS) and all(c["status"] == "KNOWN" for c in trust["components"])
    assert round(sum(c["contribution"] for c in trust["components"]), 1) == trust["risk_score"]
    assert {item["layer"] for item in trust["evidence"]} >= {"inventory", "sbom", "vulnerabilities", "attack_paths", "maintainers", "dataset"}
    assert all(item["reference"] for item in trust["evidence"]) and trust["model_version"] == "trust-v1"
    for name in ("project_id", "snapshot_id", "risk_score", "trust_score", "confidence", "component_scores", "evidence", "model_version", "created_at"):
        assert name in db[TRUST_SCORES].find_one({})
    assert "input_digest" not in trust and "project_id" not in trust
    exposure = component(trust, "vulnerability_exposure")
    assert exposure["inputs"]["by_severity"] == {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 5}


def test_with_only_an_inventory_the_answer_is_insufficient_data(client, app, auth_headers, created):
    run_layers(client, app, auth_headers, created, only=("dependencies",))
    job = start(client, app, auth_headers, created, "/trust/analyze")
    assert job["state"] == "completed" and job["message"].startswith("Insufficient data") and job["summary"]["trust_score"] is None
    trust = get(client, auth_headers, created, "/trust")["trust"]
    assert trust["status"] == "INSUFFICIENT_DATA" and trust["trust_score"] is None and trust["risk_score"] is None and trust["coverage"] == 0.15
    assert trust["risk_high"] == round(trust["risk_low"] + 85.0, 1) and len(trust["unknown_components"]) == 9
    told = get(client, auth_headers, created, "/trust/explanation")
    assert told["headline"].startswith("INSUFFICIENT DATA") and told["trust_score"] is None and len(told["recommendations"]) == 9


def test_more_evidence_moves_the_result_from_insufficient_to_scored(client, app, auth_headers, created):
    run_layers(client, app, auth_headers, created, only=("dependencies", "vulnerabilities", "trust"))
    first = get(client, auth_headers, created, "/trust")["trust"]
    assert first["status"] == "INSUFFICIENT_DATA" and first["coverage"] == 0.3
    run_layers(client, app, auth_headers, created, only=("sbom", "reachability", "predictive", "attack_paths"))
    assert get(client, auth_headers, created, "/trust")["up_to_date"] is False            # layers changed after the score
    assert start(client, app, auth_headers, created, "/trust/analyze")["state"] == "completed"
    second = get(client, auth_headers, created, "/trust")["trust"]
    assert second["status"] == "SCORED" and second["coverage"] == 0.8 and second["unknown_components"] == ["maintainer_behaviour", "commit_behaviour",
                                                                                                             "dataset_confidence"]
    items = get(client, auth_headers, created, "/trust/history")["items"]
    assert [item["status"] for item in items] == ["SCORED", "INSUFFICIENT_DATA"] and "components" not in items[0]
    diff = get(client, auth_headers, created, "/trust/compare", base=items[1]["id"], target=items[0]["id"])
    assert diff["trust_delta"] is None and diff["coverage_delta"] == 0.5 and "sbom_integrity" in diff["changed"]


def test_a_failed_sbom_verification_lowers_trust(client, app, auth_headers, scored, db):
    before = get(client, auth_headers, scored, "/trust")["trust"]
    db[SBOMS].update_one({}, {"$set": {"last_verification": {"valid": False, "verified_at": None, "failed_checks": ["stored_document_digest"]}}})
    assert get(client, auth_headers, scored, "/trust")["up_to_date"] is False
    assert start(client, app, auth_headers, scored, "/trust/analyze")["summary"]["reused"] is False
    after = get(client, auth_headers, scored, "/trust")["trust"]
    assert after["trust_score"] < before["trust_score"] and component(after, "sbom_integrity")["risk"] == 100.0
    diff = get(client, auth_headers, scored, "/trust/compare", base=before["id"], target=after["id"])
    assert diff["trust_delta"] == round(after["trust_score"] - before["trust_score"], 1) and diff["changed"] == ["sbom_integrity"]


def test_an_unchanged_state_is_not_stored_twice(client, app, auth_headers, scored, db):
    again = start(client, app, auth_headers, scored, "/trust/analyze")
    assert again["summary"]["reused"] is True and db[TRUST_SCORES].count_documents({}) == 1


def test_a_new_snapshot_has_no_score_until_it_is_analysed(client, app, auth_headers, scored, repo):
    repo.files["requirements.txt"] = b"requests==2.19.1\nPyYAML==5.1\nflask==3.0.0\n"
    assert start(client, app, auth_headers, scored, "/analysis/dependencies")["state"] == "completed"
    assert get(client, auth_headers, scored, "/trust")["trust"] is None                      # the old score is history, not the present
    assert len(get(client, auth_headers, scored, "/trust/history")["items"]) == 1
    assert start(client, app, auth_headers, scored, "/trust/analyze")["state"] == "completed"
    trust = get(client, auth_headers, scored, "/trust")["trust"]
    # Repository-level layers (maintainers, commits) still apply; snapshot-level ones must be redone.
    assert trust["status"] == "INSUFFICIENT_DATA" and set(trust["unknown_components"]) >= {"sbom_integrity", "vulnerability_exposure"}
    assert component(trust, "maintainer_behaviour")["status"] == "KNOWN"


@pytest.mark.parametrize("settings", [{"TRUST_MIN_COVERAGE": "0.1"}], indirect=True)
def test_the_coverage_threshold_setting_is_applied(client, app, auth_headers, created):
    run_layers(client, app, auth_headers, created, only=("dependencies", "trust"))
    trust = get(client, auth_headers, created, "/trust")["trust"]
    assert trust["status"] == "SCORED" and trust["min_coverage"] == 0.1 and trust["confidence"] == 0.15
    assert trust["risk_high"] == round(trust["risk_low"] + 85.0, 1) and trust["trust_low"] < trust["trust_score"] <= trust["trust_high"]


def test_explanation_endpoint(client, auth_headers, scored):
    told = get(client, auth_headers, scored, "/trust/explanation")
    assert told["status"] == "SCORED" and told["calculation"]["worked"] and told["top_risks"] and told["recommendations"]
    assert told["calculation"]["weights_statement"] == WEIGHTS_STATEMENT and len(told["evidence"]) == 11


def test_validation_isolation_and_wording(client, auth_headers, other_headers, scored):
    score_id = get(client, auth_headers, scored, "/trust")["trust"]["id"]
    for params in ({"base": "abc", "target": score_id}, {"base": score_id, "target": "0" * 24}):
        assert client.get(url(scored, "/trust/compare"), headers=auth_headers, params=params).status_code == 404
    assert client.get(url(scored, "/trust/compare"), headers=auth_headers).status_code == 422
    assert client.get(url(scored, "/trust/history"), headers=auth_headers, params={"limit": 0}).status_code == 422
    assert client.post(url(scored, "/trust/analyze"), headers=auth_headers, json={"score": 100}).status_code == 422
    for method, path in (("post", "/trust/analyze"), ("get", "/trust"), ("get", "/trust/history"), ("get", "/trust/explanation"),
                         ("get", f"/trust/compare?base={score_id}&target={score_id}")):
        assert getattr(client, method)(url(scored, path), headers=other_headers).status_code == 404
        assert getattr(client, method)(url(scored, path)).status_code == 401
    text = (client.get(url(scored, "/trust"), headers=auth_headers).text + client.get(url(scored, "/trust/explanation"), headers=auth_headers).text).lower()
    assert not any(phrase in text for phrase in OVERCLAIMS), [phrase for phrase in OVERCLAIMS if phrase in text]
    assert "not a certification" in text


def test_deleting_the_project_removes_its_scores(client, auth_headers, scored, db):
    assert client.delete(f"/api/projects/{scored['id']}", headers=auth_headers).status_code == 204
    assert db[TRUST_SCORES].count_documents({}) == 0
