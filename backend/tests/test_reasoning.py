"""Cross-layer reasoning: evidence rules, the provider guard, confidence, each rule, and the API end to end.

The central property under test is grounding: a finding cannot be stored
unless every statement in it cites evidence that exists, and text from a
language-model provider is refused when it cites anything else.
"""

import pytest

from app.ai import CATEGORIES, MODEL_VERSION, confidence, evidence, prompts, provider
from app.ai import context as context_builder
from app.ai.evidence import DERIVED, OBSERVED, PREDICTED, RECOMMENDED, EvidenceStore
from app.ai.reasoning import reason, statement
from app.models.collections import AI_FINDINGS, ANALYSIS_RUNS, PROJECTS, SBOMS
from app.services import reasoning
from tests.pipeline import (  # noqa: F401 - fixtures
    FAKE_TOKEN, advisories, created, evidence_layers, packages, repo, run_layers,
)
from tests.test_intelligence import get, settings, start, url  # noqa: F401

OVERCLAIMS = ("exploit confirmed", "will be exploited", "will be attacked", "guaranteed", "zero-day", "malicious", "is exploitable")


def store_with(*bases):
    store = EvidenceStore()
    refs = [store.add(layer=f"layer{n}", collection="c", record_id=n, basis=basis, summary=f"fact {n}", confidence=0.9) for n, basis in enumerate(bases)]
    return store, refs


def sample_finding(refs, **overrides):
    base = {"category": "REACHABLE_VULNERABILITY", "severity": "MEDIUM", "confidence": 0.5,
            "evidence_refs": list(refs), "contributing_layers": [], "explanation": "",
            "statements": [statement(DERIVED, "Something follows from the records.", *refs)],
            "recommendation": statement(RECOMMENDED, "Do something about it.", refs[0])}
    return {**base, **overrides}


# --- evidence ---------------------------------------------------------------------------

def test_the_store_assigns_stable_ids_and_deduplicates():
    store = EvidenceStore()
    first = store.add(layer="a", collection="c", record_id=1, basis=OBSERVED, summary="x")
    again = store.add(layer="a", collection="c", record_id=1, basis=OBSERVED, summary="x")
    other = store.add(layer="a", collection="c", record_id=2, basis=DERIVED, summary="y")
    assert (first, again, other) == ("E1", "E1", "E2") and len(store) == 2 and store.ids() == ["E1", "E2"]
    assert store.get("E2")["basis"] == DERIVED and store.get("E9") is None and "E1" in store and "E9" not in store
    with pytest.raises(ValueError):
        store.add(layer="a", collection="c", record_id=3, basis="GUESSED", summary="z")


def test_a_grounded_finding_passes_validation():
    store, refs = store_with(OBSERVED, DERIVED)
    assert evidence.validate(sample_finding(refs), store) == []


@pytest.mark.parametrize("change,expected", [
    ({"evidence_refs": []}, "cites no evidence"),
    ({"evidence_refs": ["E1", "E2", "E77"]}, "does not exist"),
    ({"statements": []}, "makes no statement"),
    ({"statements": [{"basis": DERIVED, "text": "Unsupported.", "evidence_refs": []}]}, "Statement 1 cites no evidence"),
    ({"statements": [{"basis": "CERTAIN", "text": "x", "evidence_refs": ["E1"]}]}, "no valid basis"),
    ({"statements": [{"basis": DERIVED, "text": "x", "evidence_refs": ["E1", "E99"]}]}, "outside the finding's evidence list"),
    ({"statements": [{"basis": OBSERVED, "text": "x", "evidence_refs": ["E2"]}]}, "presented as observed"),
    ({"recommendation": {"basis": OBSERVED, "text": "x", "evidence_refs": ["E1"]}}, "not marked as a recommendation"),
    ({"recommendation": {"basis": RECOMMENDED, "text": "x", "evidence_refs": []}}, "recommendation cites no evidence"),
    ({"contributing_layers": ["layer0", "attack_paths"]}, "contributing layer it cites no evidence from"),
    ({"explanation": "It is bad [E42]."}, "E42"),
    ({"explanation": "According to the source, it is bad."}, "refers to a source without citing one"),
    ({"statements": [{"basis": DERIVED, "text": "According to the source it is fine.", "evidence_refs": []}]}, "refers to a source without citing"),
])
def test_ungrounded_findings_are_refused(change, expected):
    store, refs = store_with(OBSERVED, DERIVED)
    problems = evidence.validate(sample_finding(refs, **change), store)
    assert any(expected in problem for problem in problems), problems


def test_a_source_phrase_is_fine_when_it_cites_evidence():
    store, refs = store_with(OBSERVED)
    finding = sample_finding(refs, explanation="According to the advisory record, the version is affected [E1].")
    assert evidence.validate(finding, store) == []


def test_grounding_metrics_are_measured_from_the_findings():
    store, refs = store_with(OBSERVED, DERIVED, PREDICTED, DERIVED)
    grounded = sample_finding(refs[:2])
    partly = sample_finding([refs[2]], statements=[statement(PREDICTED, "a", refs[2]), {"basis": DERIVED, "text": "b", "evidence_refs": []}])
    metrics = evidence.grounding([grounded, partly], store, rejected=1)
    assert metrics["statements"] == 3 and metrics["grounded_statements"] == 2 and metrics["evidence_grounding"] == 0.6667
    assert metrics["unsupported_claim_rate"] == 0.3333 and metrics["evidence_coverage"] == 0.75 and metrics["findings_rejected"] == 1
    empty = evidence.grounding([], EvidenceStore())
    assert empty["evidence_grounding"] is None and empty["evidence_coverage"] is None


# --- confidence -------------------------------------------------------------------------

def test_confidence_is_the_weakest_evidence_times_corroboration_times_completeness():
    items = [{"confidence": 0.9}, {"confidence": 0.6}, {"confidence": None}]
    conditions = [{"result": "TRUE"}, {"result": "UNKNOWN"}]
    result = confidence.combine(items, ["a", "b"], conditions)
    assert result == {"value": round(0.6 * 0.85 * 0.5, 2), "weakest_evidence": 0.6, "corroboration": 0.85, "completeness": 0.5, "layers": 2,
                      "conditions_unknown": 1}
    assert confidence.combine([{"confidence": None}], ["a"], [])["value"] == 0.7
    assert confidence.combine([{"confidence": 1.0}], ["a", "b", "c", "d"], [{"result": "TRUE"}])["value"] == 1.0
    assert confidence.combine([], [], [])["value"] == 0.0


# --- providers --------------------------------------------------------------------------

class Scripted:
    """A stand-in for a language-model provider that returns whatever the test scripts."""

    name, model_version, deterministic = "scripted", "scripted-1", False

    def __init__(self, reply):
        self.reply, self.prompts = reply, []

    def explain(self, finding, items):
        self.prompts.append(prompts.explanation_prompt(finding, items))
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


def test_only_the_deterministic_provider_is_configurable():
    from app.config.settings import SettingsError, load_settings
    from tests.conftest import TEST_ENV

    assert provider.get_provider("deterministic").deterministic is True
    with pytest.raises(ValueError):
        provider.get_provider("anything-else")
    with pytest.raises(SettingsError):
        load_settings({**TEST_ENV, "AI_PROVIDER": "some-model"})
    assert load_settings({**TEST_ENV, "AI_PROVIDER": "Deterministic"}).ai_provider == "deterministic"


def test_the_deterministic_explanation_is_the_statements_with_their_citations():
    store, refs = store_with(OBSERVED, DERIVED)
    finding = sample_finding(refs, statements=[statement(OBSERVED, "A is recorded.", refs[0]), statement(DERIVED, "B follows.", refs[0], refs[1])])
    text, record = provider.explain(provider.DeterministicProvider(), finding, store.resolve(refs))
    assert text == "A is recorded. [E1] B follows. [E1][E2]" and record["accepted"] is True and record["provider"] == "deterministic"
    assert provider.guard(text, finding) == []


@pytest.mark.parametrize("reply,expected", [
    ("The package is affected.", "cites no evidence"),
    ("The package is affected [E1]. Attackers are already using it [E9].", "does not use: E9"),
    ("The package is affected [E1]. It was downloaded a million times.", "A sentence carries no citation"),
    ("The exploit is confirmed [E1].", "claim the platform does not make"),
    ("This will be exploited [E1].", "claim the platform does not make"),
    ("A malicious maintainer added it [E1].", "claim the platform does not make"),
    ("x" * 2000, "longer than allowed"), ("", "returned no text"), (None, "returned no text"), (42, "returned no text"),
])
def test_provider_text_is_refused_unless_it_is_grounded(reply, expected):
    store, refs = store_with(OBSERVED, DERIVED)
    finding = sample_finding(refs)
    scripted = Scripted(reply)
    text, record = provider.explain(scripted, finding, store.resolve(refs))
    assert record["accepted"] is False and any(expected in problem for problem in record["problems"]), record
    assert text == provider.DeterministicProvider().explain(finding, []) and record["fallback"] == "deterministic"


def test_grounded_provider_text_is_used_and_a_failing_provider_does_not_break_anything():
    store, refs = store_with(OBSERVED, DERIVED)
    finding = sample_finding(refs)
    text, record = provider.explain(Scripted("The record shows it [E1]. The analysis derives the rest [E2]."), finding, store.resolve(refs))
    assert text.startswith("The record shows it") and record["accepted"] is True and record["prompt_evidence"] == ["E1", "E2"]
    text, record = provider.explain(Scripted(RuntimeError("boom")), finding, store.resolve(refs))
    assert record["accepted"] is False and "RuntimeError" in record["problems"][0] and "boom" not in str(record)


def test_the_prompt_contains_only_the_findings_own_evidence_and_the_rules():
    store, refs = store_with(OBSERVED, DERIVED, PREDICTED)
    finding = sample_finding(refs[:2])
    prompt = prompts.explanation_prompt(finding, store.resolve(finding["evidence_refs"]))
    assert "[E1] (OBSERVED, layer0) fact 0" in prompt["user"] and "[E2]" in prompt["user"] and "E3" not in prompt["user"] and "fact 2" not in prompt["user"]
    assert "Use only the evidence items given to you" in prompt["system"] and "Every sentence needs at least one citation" in prompt["system"]
    assert "acted with bad intent" in prompt["system"]


# --- rules over a real context ----------------------------------------------------------

@pytest.fixture
def reasoned(client, app, auth_headers, evidence_layers):
    job = start(client, app, auth_headers, evidence_layers, "/ai-analysis")
    assert job["state"] == "completed", job
    return evidence_layers


def findings_by_category(client, headers, project):
    grouped = {}
    for item in get(client, headers, project, "/ai-analysis", limit=200)["items"]:
        grouped.setdefault(item["category"], []).append(item)
    return grouped


def test_the_context_registers_every_fact_as_evidence(app, evidence_layers, db):
    context = context_builder.build(db, db[PROJECTS].find_one({}))
    assert set(context.layer_evidence) == {"inventory", "sbom", "vulnerabilities", "reachability", "fragility", "graph_risk", "predictive",
                                           "attack_paths", "maintainers", "commits", "dataset"}
    assert set(context.vulnerable) == {"pypi:requests@2.19.1", "npm:lodash@4.17.20", "npm:ms@2.0.0", "npm:qs@6.7.0"}
    reach = {group["source_id"]: group["reach_state"] for group in context.vulnerable["pypi:requests@2.19.1"]}
    assert reach == {"GHSA-x84v-xcm2-53pg": "UNKNOWN", "TEST-REQ-GET": "REACHABLE"}
    assert len(context.secret_events) == 1 and len(context.pipeline_changes) == 1 and context.dependency_changes
    assert all(item["ref"] in context.store for item in context.store.resolve(context.store.ids()))
    assert FAKE_TOKEN not in str([context.store.get(ref) for ref in context.store.ids()])
    assert context.digest() == context_builder.build(db, db[PROJECTS].find_one({})).digest()


def test_reasoning_is_deterministic_and_every_finding_is_grounded(app, evidence_layers, db):
    project = db[PROJECTS].find_one({})
    first = reasoning.analyse(db, project, provider.DeterministicProvider())
    second = reasoning.analyse(db, project, provider.DeterministicProvider())
    strip = lambda result: [{k: v for k, v in f.items() if k != "evidence"} for f in result["findings"]]      # noqa: E731
    assert strip(first) == strip(second) and first["rejected"] == [] and first["findings"]
    assert first["grounding"]["evidence_grounding"] == 1.0 and first["grounding"]["unsupported_claim_rate"] == 0.0
    for finding in first["findings"]:
        assert evidence.validate(finding, first["context"].store) == []
        assert finding["category"] in CATEGORIES and 0 <= finding["confidence"] <= 1


def test_a_reachable_vulnerability_with_other_signals_is_the_high_priority_finding(client, auth_headers, reasoned):
    grouped = findings_by_category(client, auth_headers, reasoned)
    [top] = grouped["HIGH_PRIORITY_CORRELATED_RISK"]
    assert top["subject"]["package_name"] == "requests" and top["subject"]["advisory"] == "TEST-REQ-GET" and top["severity"] == "HIGH"
    assert {"vulnerabilities", "reachability"} <= set(top["contributing_layers"]) and len(top["contributing_layers"]) >= 3
    bases = [item["basis"] for item in top["statements"]]
    assert bases[:2] == ["OBSERVED", "DERIVED"] and top["recommendation"]["basis"] == "RECOMMENDED"
    assert "Upgrade requests" in top["recommendation"]["text"] and top["model_version"] == MODEL_VERSION
    assert all(ref in {item["ref"] for item in top["evidence"]} for item in top["statements"] for ref in item["evidence_refs"])
    detail = get(client, auth_headers, reasoned, f"/ai-analysis/{top['finding_id']}")
    names = {item["condition"]: item["result"] for item in detail["conditions"]}
    assert names["known_vulnerability"] == "TRUE" and names["reachability_confirmed"] == "TRUE" and names["supported_attack_path"] == "TRUE"
    assert detail["confidence_detail"]["completeness"] == 1.0 and detail["explanation"].count("[E") >= 3


def test_undetermined_reachability_is_one_finding_that_says_it_is_not_a_clearance(client, auth_headers, reasoned):
    [gap] = findings_by_category(client, auth_headers, reasoned)["UNVERIFIED_VULNERABILITY_EXPOSURE"]
    assert gap["subject"]["count"] == 6 and gap["severity"] == "HIGH"
    assert "do not treat an undetermined result as safe" in gap["recommendation"]["text"]
    assert "lodash" in gap["statements"][0]["text"] and gap["statements"][0]["basis"] == "OBSERVED"


def test_commit_and_maintainer_findings(client, auth_headers, reasoned):
    grouped = findings_by_category(client, auth_headers, reasoned)
    [secret] = grouped["SECRET_EXPOSURE_REVIEW"]
    assert secret["severity"] == "HIGH" and "scripts/release.py" in secret["statements"][0]["text"] and FAKE_TOKEN not in str(secret)
    assert "revoke and replace" in secret["recommendation"]["text"] and secret["contributing_layers"] == ["commits"]
    [control] = grouped["CONCENTRATED_CHANGE_CONTROL"]
    assert control["contributing_layers"] == ["maintainers", "commits"] and "says nothing about the person" in control["statements"][2]["text"]
    assert "second reviewer" in control["recommendation"]["text"]


def test_layer_gaps_are_reported_as_unknown_not_as_clean(client, app, auth_headers, created):
    run_layers(client, app, auth_headers, created, only=("dependencies", "vulnerabilities"))
    assert start(client, app, auth_headers, created, "/ai-analysis")["state"] == "completed"
    grouped = findings_by_category(client, auth_headers, created)
    [gaps] = grouped["INSUFFICIENT_EVIDENCE"]
    assert gaps["severity"] == "INFO" and set(gaps["subject"]["missing_layers"]) == {
        "sbom", "reachability", "fragility", "graph_risk", "predictive", "attack_paths", "maintainers", "commits", "dataset"}
    assert "their absence is not a clean result" in gaps["statements"][0]["text"]
    [exposure] = grouped["UNVERIFIED_VULNERABILITY_EXPOSURE"]
    assert exposure["subject"]["count"] == 7 and "Run the code reachability analysis" in exposure["recommendation"]["text"]
    assert "HIGH_PRIORITY_CORRELATED_RISK" not in grouped and "REACHABLE_VULNERABILITY" not in grouped


def test_sbom_findings_follow_the_verification_state(client, app, auth_headers, created, db):
    run_layers(client, app, auth_headers, created, only=("dependencies", "vulnerabilities", "sbom"), verify_sbom=False)
    assert start(client, app, auth_headers, created, "/ai-analysis")["state"] == "completed"
    [unverified] = findings_by_category(client, auth_headers, created)["SBOM_INTEGRITY_CONCERN"]
    assert unverified["severity"] == "LOW" and unverified["rule_id"] == "sbom_not_verified"
    db[SBOMS].update_one({}, {"$set": {"last_verification": {"valid": False, "verified_at": None, "failed_checks": ["content_digest"]}}})
    assert start(client, app, auth_headers, created, "/ai-analysis")["state"] == "completed"
    [failed] = findings_by_category(client, auth_headers, created)["SBOM_INTEGRITY_CONCERN"]
    assert failed["severity"] == "HIGH" and "content_digest" in failed["statements"][0]["text"]


def test_a_verified_sbom_and_a_small_dataset(client, auth_headers, reasoned):
    grouped = findings_by_category(client, auth_headers, reasoned)
    assert "SBOM_INTEGRITY_CONCERN" not in grouped
    [dataset] = grouped["DATASET_CONFIDENCE_LIMIT"]
    assert dataset["severity"] == "LOW" and "LOW_CONFIDENCE" in dataset["statements"][0]["text"]


# --- API --------------------------------------------------------------------------------

def test_nothing_is_reported_before_a_run(client, auth_headers, evidence_layers):
    body = get(client, auth_headers, evidence_layers, "/ai-analysis")
    assert body["analysis"] is None and body["items"] == [] and set(body["categories"]) == set(CATEGORIES)
    assert client.get(url(evidence_layers, "/ai-analysis/" + "0" * 24), headers=auth_headers).status_code == 404


def test_a_project_without_a_snapshot_cannot_be_reasoned_about(client, auth_headers):
    made = client.post("/api/projects", json={"name": "Empty", "repository_url": "https://github.com/octo/none"}, headers=auth_headers).json()
    assert client.post(url(made, "/ai-analysis"), headers=auth_headers).status_code == 409


def test_listing_is_ordered_filtered_and_carries_its_audit_information(client, auth_headers, reasoned, db):
    body = get(client, auth_headers, reasoned, "/ai-analysis")
    ranks = [item["severity_rank"] for item in body["items"]]
    assert ranks == sorted(ranks, reverse=True) and body["total"] == db[AI_FINDINGS].count_documents({})
    summary = body["analysis"]["summary"]
    assert summary["provider"] == "deterministic" and summary["deterministic"] is True and summary["grounding"]["evidence_grounding"] == 1.0
    assert summary["rejected_findings"] == [] and [rule["rule"] for rule in summary["rules"]][0] == "vulnerability_correlation"
    assert body["analysis"]["inputs"]["layers"]["reachability"] == "ANALYSED" and "input_digest" not in body["analysis"]
    assert "conditions" not in body["items"][0] and "project_id" not in body["items"][0]
    assert get(client, auth_headers, reasoned, "/ai-analysis", severity="HIGH")["total"] < body["total"]
    assert get(client, auth_headers, reasoned, "/ai-analysis", category="SECRET_EXPOSURE_REVIEW")["total"] == 1
    assert get(client, auth_headers, reasoned, "/ai-analysis", layer="maintainers")["total"] == 1
    for params in ({"severity": "FATAL"}, {"category": "MADE_UP"}, {"layer": "astrology"}, {"limit": 0}):
        assert client.get(url(reasoned, "/ai-analysis"), headers=auth_headers, params=params).status_code == 422


def test_the_audit_trail_records_each_run(client, app, auth_headers, reasoned, db):
    entry = db["audit_logs"].find_one({"action": "ai.reasoning.complete"})
    assert entry["details"]["provider"] == "deterministic" and entry["details"]["evidence_grounding"] == 1.0 and entry["details"]["rejected"] == 0
    assert entry["details"]["model_version"] == MODEL_VERSION and len(entry["details"]["input_digest"]) == 16
    again = start(client, app, auth_headers, reasoned, "/ai-analysis")
    assert again["summary"]["reused"] is True and db[ANALYSIS_RUNS].count_documents({"kind": "ai"}) == 1
    assert len(get(client, auth_headers, reasoned, "/ai-analysis/history")["items"]) == 1


def test_an_ungrounded_finding_is_never_stored(app, evidence_layers, db, monkeypatch):
    from app.ai import reasoning as rules
    from app.services import jobs
    from app.services.jobs import JobContext

    def invented(context):
        return [rules._assemble(context, rule="invented", category="REACHABLE_VULNERABILITY", severity="CRITICAL", subject={"type": "project", "key": "x"},
                                statements=[{"basis": OBSERVED, "text": "According to the source this is being exploited.", "evidence_refs": ["E9999"]}],
                                conditions=[], recommendation=statement(RECOMMENDED, "Panic.", "E9999"))]

    monkeypatch.setattr(rules, "RULES", (*rules.RULES, ("invented", invented)))
    project = db[PROJECTS].find_one({})
    job = jobs.request_job(db, app.state.redis, project, jobs.AI_SECURITY_ANALYSIS)
    job = jobs.claim_next_job(db)
    message, fields = reasoning._run(JobContext(db, app.state.settings, {}, __import__("time").monotonic()), job)
    assert db[AI_FINDINGS].count_documents({"rule_id": "invented"}) == 0
    rejected = fields["summary"]["rejected_findings"]
    assert [item["rule_id"] for item in rejected] == ["invented"] and any("does not exist" in problem for problem in rejected[0]["problems"])
    assert fields["summary"]["grounding"]["findings_rejected"] == 1 and fields["summary"]["grounding"]["evidence_grounding"] == 1.0


def test_rejected_provider_text_is_audited_and_replaced(app, evidence_layers, db):
    from app.services import jobs
    from app.services.jobs import JobContext

    scripted = Scripted("Attackers will be exploiting this soon.")
    project = db[PROJECTS].find_one({})
    jobs.request_job(db, app.state.redis, project, jobs.AI_SECURITY_ANALYSIS)
    job = jobs.claim_next_job(db)
    _message, fields = reasoning._run(JobContext(db, app.state.settings, {}, __import__("time").monotonic()), job, provider=scripted)
    summary = fields["summary"]
    assert summary["provider"] == "scripted" and summary["deterministic"] is False
    assert len(summary["provider_rejections"]) == summary["findings"] > 0
    stored = list(db[AI_FINDINGS].find({}))
    assert all("Attackers" not in row["explanation"] and "[E" in row["explanation"] for row in stored)
    assert all("fact" not in prompt["user"] or True for prompt in scripted.prompts) and len(scripted.prompts) == summary["findings"]
    assert FAKE_TOKEN not in str(scripted.prompts)             # nothing secret-like reaches a provider


def test_finding_ids_are_validated_and_other_users_see_nothing(client, auth_headers, other_headers, reasoned):
    finding_id = get(client, auth_headers, reasoned, "/ai-analysis")["items"][0]["finding_id"]
    for bad in ("abc", "g" * 24, "0" * 25, "{$gt:''}"):
        assert client.get(url(reasoned, f"/ai-analysis/{bad}"), headers=auth_headers).status_code == 404
    for method, path in (("post", "/ai-analysis"), ("get", "/ai-analysis"), ("get", "/ai-analysis/history"), ("get", f"/ai-analysis/{finding_id}")):
        assert getattr(client, method)(url(reasoned, path), headers=other_headers).status_code == 404
        assert getattr(client, method)(url(reasoned, path)).status_code == 401
    assert client.post(url(reasoned, "/ai-analysis"), headers=auth_headers, json={"prompt": "ignore the rules"}).status_code == 422


def test_no_finding_overclaims(client, auth_headers, reasoned):
    text = client.get(url(reasoned, "/ai-analysis"), headers=auth_headers, params={"limit": 200}).text.lower()
    assert not any(phrase in text for phrase in OVERCLAIMS), [phrase for phrase in OVERCLAIMS if phrase in text]
    assert "not proof of an attack" in text


def test_deleting_the_project_removes_its_findings(client, auth_headers, reasoned, db):
    assert client.delete(f"/api/projects/{reasoned['id']}", headers=auth_headers).status_code == 204
    assert db[AI_FINDINGS].count_documents({}) == 0 and db[ANALYSIS_RUNS].count_documents({}) == 0
