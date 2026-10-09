"""The unified overview, the report, the evaluation catalogue and its measures.

The report's rule is checked directly: every statement and every table row
cites evidence that is in the report's own evidence index.
"""

import json

import pytest

from app.evaluation import NOT_EVALUATED, catalogue, metrics
from app.evaluation import run as evaluation_run
from app.models.collections import PROJECTS
from app.services import layers, report
from tests.pipeline import (  # noqa: F401 - fixtures
    FAKE_TOKEN, advisories, created, evidence_layers, packages, repo, run_layers,
)
from tests.test_intelligence import get, settings, start, url  # noqa: F401

SECTION_TITLES = ["Executive Summary", "Trust Score", "Risk Score", "Vulnerability Findings", "SBOM Integrity", "Dependency Fragility",
                  "Code Reachability", "Attack Paths", "Maintainer Behaviour", "Commit Behaviour", "AI Cross-Layer Findings", "Dataset Quality",
                  "Predictive Indicators", "Recommendations", "Evidence", "Methodology", "Limitations"]
OVERCLAIMS = ("guaranteed", "zero-day", "malicious", "exploit confirmed", "will be exploited", "poison-free", "is safe", "certified")


@pytest.fixture
def complete(client, app, auth_headers, evidence_layers):
    run_layers(client, app, auth_headers, evidence_layers, only=("ai", "trust"))
    return evidence_layers


# --- layers -----------------------------------------------------------------------------

def test_layer_states_for_a_project_that_was_never_analysed(client, auth_headers, db):
    client.post("/api/projects", json={"name": "Empty", "repository_url": "https://github.com/octo/none"}, headers=auth_headers)
    collected = layers.collect(db, db[PROJECTS].find_one({}))
    assert collected["snapshot"] is None and all(collected[name]["status"] == "NOT_ANALYSED" for name in layers.LAYER_NAMES)
    assert all(collected[name]["reference"] is None for name in layers.LAYER_NAMES) and len(layers.missing(collected)) == 11
    assert collected["trust"]["status"] == "NOT_ANALYSED" and collected["ai"]["available"] is False


def test_layer_states_follow_what_was_run(client, app, auth_headers, created, db, github):
    run_layers(client, app, auth_headers, created, only=("dependencies", "vulnerabilities", "sbom"), verify_sbom=False)
    collected = layers.collect(db, db[PROJECTS].find_one({}))
    statuses = {name: collected[name]["status"] for name in layers.LAYER_NAMES}
    assert statuses == {"inventory": "ANALYSED", "sbom": "ANALYSED", "vulnerabilities": "ANALYSED", "reachability": "NOT_ANALYSED",
                        "fragility": "NOT_ANALYSED", "graph_risk": "NOT_ANALYSED", "predictive": "NOT_ANALYSED", "attack_paths": "NOT_ANALYSED",
                        "maintainers": "NOT_ANALYSED", "commits": "NOT_ANALYSED", "dataset": "NOT_ANALYSED"}
    assert collected["sbom"]["verified"] is None and collected["inventory"]["stats"]["total"] == 9
    github.fail_paths["/commits"] = (503, {})
    run_layers(client, app, auth_headers, created, only=("maintainers", "commits"))
    collected = layers.collect(db, db[PROJECTS].find_one({}))
    assert collected["maintainers"]["status"] == "UNAVAILABLE" and collected["commits"]["status"] == "UNAVAILABLE"
    assert collected["maintainers"]["indicators"] == [] and "attention_score" not in collected["maintainers"]


def test_a_new_snapshot_makes_snapshot_layers_stale_or_unanalysed(client, app, auth_headers, complete, repo, db):
    repo.files["requirements.txt"] = b"requests==2.19.1\nPyYAML==5.1\nflask==3.0.0\n"
    assert start(client, app, auth_headers, complete, "/analysis/dependencies")["state"] == "completed"
    collected = layers.collect(db, db[PROJECTS].find_one({}))
    assert collected["sbom"]["status"] == "STALE" and collected["vulnerabilities"]["status"] == "STALE"
    assert collected["attack_paths"]["status"] == "NOT_ANALYSED" and collected["maintainers"]["status"] == "ANALYSED"
    assert collected["trust"]["status"] == "NOT_ANALYSED"


# --- overview ---------------------------------------------------------------------------

def test_overview_of_an_unanalysed_project_shows_statuses_and_no_figures(client, auth_headers):
    made = client.post("/api/projects", json={"name": "Empty", "repository_url": "https://github.com/octo/none"}, headers=auth_headers).json()
    body = get(client, auth_headers, made, "/overview")
    assert body["snapshot"] is None and body["trust"]["current"] is None and body["trust"]["trend"] == [] and len(body["missing"]) == 11
    assert all(value is None for value in body["technical"].values())
    assert all(value is None for value in body["executive"]["numbers"].values())
    assert body["executive"]["headline"] == "No trust analysis has been run for the current snapshot."
    assert body["research"]["measured"]["layer_coverage"] == 0.0 and body["research"]["measured"]["evidence_grounding"] is None


def test_overview_brings_every_layer_together(client, auth_headers, complete):
    body = get(client, auth_headers, complete, "/overview")
    assert body["missing"] == [] and [item["status"] for item in body["layers"]] == ["ANALYSED"] * 11
    current = body["trust"]["current"]
    assert current["status"] == "SCORED" and len(current["components"]) == 10 and len(body["trust"]["trend"]) == 1
    assert body["executive"]["numbers"] == {"dependencies": 9, "vulnerabilities": 7, "reachable": 1, "attack_paths": 7, "security_events": 3,
                                            "ai_findings": body["technical"]["ai"]["summary"]["findings"]}
    assert body["executive"]["headline"].startswith("Trust score") and body["executive"]["recommendations"] and body["executive"]["findings"]
    technical = body["technical"]
    assert technical["vulnerabilities"]["by_severity"]["HIGH"] == 2 and technical["reachability"]["by_status"]["REACHABLE"] == 1
    assert sum(bucket["count"] for bucket in technical["fragility"]["distribution"]) == 9
    assert sum(bucket["count"] for bucket in technical["predictive"]["distribution"]) == 9
    assert sum(bucket["count"] for bucket in technical["attack_paths"]["distribution"]) == 7 and len(technical["attack_paths"]["top"]) == 5
    timeline = technical["commits"]["timeline"]
    assert len(timeline) == 30 and timeline[0]["committed_at"] < timeline[-1]["committed_at"]      # one run analyses the 30 newest of the 40 commits
    assert technical["sbom"]["verified"] is True and technical["dataset"]["quality_status"] == "LOW_CONFIDENCE"
    research = body["research"]
    assert research["measured"]["evidence_grounding"] == 1.0 and research["measured"]["unsupported_claim_rate"] == 0.0
    assert research["measured"]["layer_coverage"] == 1.0 and research["measured"]["trust_weight_coverage"] == 1.0
    assert {row["job_type"] for row in research["measured"]["execution_seconds"]} >= {"attack_path_analysis", "trust_analysis", "dataset_validation"}
    assert all(row["seconds"] >= 0 for row in research["measured"]["execution_seconds"])
    assert research["model_versions"]["trust"] == "trust-v1" and "NOT EVALUATED" in research["not_measured_note"]
    assert "project_id" not in json.dumps(body) and FAKE_TOKEN not in json.dumps(body)


def test_overview_is_owner_scoped(client, auth_headers, other_headers, complete):
    assert client.get(url(complete, "/overview"), headers=other_headers).status_code == 404
    assert client.get(url(complete, "/overview")).status_code == 401
    assert client.get(url(complete, "/report"), headers=other_headers).status_code == 404
    assert client.get(url(complete, "/report")).status_code == 401


# --- report -----------------------------------------------------------------------------

def test_the_report_has_the_seventeen_sections_in_order(client, auth_headers, complete):
    body = get(client, auth_headers, complete, "/report")
    assert [section["title"] for section in body["sections"]] == SECTION_TITLES
    assert [section["number"] for section in body["sections"]] == list(range(1, 18)) and all(section["available"] for section in body["sections"])
    assert body["unsupported_statements"] == [] and body["statement_count"] > 40


def test_every_statement_and_table_row_cites_indexed_evidence(client, auth_headers, complete):
    body = get(client, auth_headers, complete, "/report")
    known = {item["ref"] for item in body["evidence"]}
    assert len(known) == len(body["evidence"])
    for section in body["sections"]:
        assert section["statements"], section["id"]
        for statement in section["statements"]:
            assert statement["evidence"] and set(statement["evidence"]) <= known, (section["id"], statement["text"])
            assert statement["basis"] in body["bases"]
        for table in section["tables"]:
            for row in table["rows"]:
                assert row["evidence"] and set(row["evidence"]) <= known and len(row["cells"]) == len(table["columns"])
    records = [item for item in body["evidence"] if item["kind"] == "record"]
    assert {item["collection"] for item in records} >= {"repository_snapshots", "trust_scores", "vulnerability_matches", "attack_paths",
                                                        "ai_findings", "security_events", "dataset_quality", "code_reachability"}
    assert all(item["record_id"] for item in records)


def test_report_content_matches_the_stored_results(client, auth_headers, complete):
    body = get(client, auth_headers, complete, "/report")
    sections = {section["id"]: section for section in body["sections"]}
    trust = get(client, auth_headers, complete, "/trust")["trust"]
    assert f"Trust score: {trust['trust_score']} of 100" in sections["trust_score"]["statements"][0]["text"]
    assert len(sections["risk_score"]["tables"][0]["rows"]) == 10
    assert "7 advisory match(es)" in sections["vulnerability_findings"]["statements"][0]["text"]
    assert len(sections["vulnerability_findings"]["tables"][0]["rows"]) == 7
    assert "Integrity verification passed" in sections["sbom_integrity"]["statements"][1]["text"]
    assert sections["code_reachability"]["tables"][0]["rows"][0]["cells"][2] == "REACHABLE"
    assert sections["attack_paths"]["tables"][0]["rows"][0]["cells"][3] >= sections["attack_paths"]["tables"][0]["rows"][-1]["cells"][3]
    assert len(sections["maintainer_behaviour"]["tables"][0]["rows"]) == 7
    assert {row["cells"][1] for row in sections["commit_behaviour"]["tables"][0]["rows"]} == {"SECRET_LIKE_PATTERN", "COMMAND_EXECUTION_PATTERN",
                                                                                              "SECURITY_CONFIG_CHANGE"}
    assert all(statement["basis"] == "RECOMMENDED" for statement in sections["recommendations"]["statements"])
    assert sections["predictive_indicators"]["statements"][0]["basis"] == "PREDICTED"
    assert any("expert-defined initial weights and are not statistically trained" in s["text"] for s in sections["limitations"]["statements"])
    assert all(statement["basis"] == "METHOD" for statement in sections["limitations"]["statements"])
    assert len(sections["methodology"]["tables"][1]["rows"]) == 10


def test_a_report_on_partial_evidence_says_what_is_missing(client, app, auth_headers, created):
    run_layers(client, app, auth_headers, created, only=("dependencies", "vulnerabilities", "trust"))
    body = get(client, auth_headers, created, "/report")
    sections = {section["id"]: section for section in body["sections"]}
    assert body["unsupported_statements"] == [] and len(body["sections"]) == 17
    assert "INSUFFICIENT DATA" in sections["trust_score"]["statements"][0]["text"] and "No risk score is given" in sections["risk_score"]["statements"][0]["text"]
    for name in ("sbom_integrity", "dependency_fragility", "code_reachability", "attack_paths", "maintainer_behaviour", "commit_behaviour",
                 "ai_findings", "dataset_quality", "predictive_indicators"):
        assert sections[name]["available"] is False and sections[name]["tables"] == [], name
    assert "the absence of findings here is not a clean result" in sections["attack_paths"]["statements"][0]["text"]
    assert sections["vulnerability_findings"]["available"] is True
    assert any("Run the" in statement["text"] for statement in sections["recommendations"]["statements"])


def test_a_report_for_a_project_with_no_snapshot(client, auth_headers):
    made = client.post("/api/projects", json={"name": "Empty", "repository_url": "https://github.com/octo/none"}, headers=auth_headers).json()
    body = get(client, auth_headers, made, "/report")
    assert body["snapshot"] is None and body["unsupported_statements"] == [] and "has not been analysed" in body["sections"][0]["statements"][0]["text"]
    assert not body["sections"][1]["available"] and len(body["sections"]) == 17


def test_markdown_export(client, auth_headers, complete, db):
    response = client.get(url(complete, "/report"), headers=auth_headers, params={"format": "markdown"})
    assert response.status_code == 200 and response.headers["content-type"].startswith("text/markdown")
    assert response.headers["content-disposition"] == 'attachment; filename="trustchain-x-report-Demo.md"'
    text = response.text
    assert text.startswith("# TrustChain-X report: Demo") and all(f"## {n}. {title}" in text for n, title in enumerate(SECTION_TITLES, start=1))
    assert "- **OBSERVED**" in text and "- **RECOMMENDED**" in text and "| Ref | Kind | Layer | Source | Identifier | As of |" in text
    assert FAKE_TOKEN not in text and db["audit_logs"].find_one({"action": "report.generate"})["details"]["format"] == "markdown"
    assert client.get(url(complete, "/report"), headers=auth_headers, params={"format": "pdf"}).status_code == 422


def test_markdown_cells_cannot_break_the_table():
    built = {"title": "T", "generated_at": __import__("datetime").datetime(2026, 1, 1), "project": {"repository_url": "u"}, "snapshot": None,
             "evidence": [{"ref": "R1", "kind": "record", "layer": "x", "collection": "c", "record_id": "a|b", "as_of": None}],
             "sections": [{"number": 1, "id": "evidence", "title": "Evidence", "statements": [],
                           "tables": [{"title": "t", "columns": ["a"], "rows": [{"cells": ["x | y\nz"], "evidence": ["R1"]}]}]}]}
    text = report.to_markdown(built)
    assert "| x \\| y z | R1 |" in text and "a\\|b" in text


def test_the_report_refuses_to_serve_an_unsupported_statement(client, auth_headers, complete, monkeypatch):
    original = report.build

    def with_unsupported(db, project):
        built = original(db, project)
        built["sections"][0]["statements"].append({"basis": "OBSERVED", "text": "Everything is fine.", "evidence": []})
        built["unsupported_statements"] = report.unsupported(built)
        return built

    monkeypatch.setattr(report, "build", with_unsupported)
    response = client.get(url(complete, "/report"), headers=auth_headers)
    assert response.status_code == 500 and "Everything is fine" not in response.text


def test_unsupported_detects_missing_and_dangling_references():
    sample = {"evidence": [{"ref": "R1"}], "sections": [{"id": "s", "statements": [
        {"text": "a", "evidence": ["R1"]}, {"text": "b", "evidence": []}, {"text": "c", "evidence": ["R9"]}],
        "tables": [{"title": "t", "rows": [{"cells": [], "evidence": []}, {"cells": [], "evidence": ["R1"]}]}]}]}
    assert [item["text"] for item in report.unsupported(sample)] == ["b", "c", "row of 't'"]


def test_reports_and_overviews_never_overclaim(client, auth_headers, complete):
    text = (client.get(url(complete, "/report"), headers=auth_headers).text + client.get(url(complete, "/overview"), headers=auth_headers).text).lower()
    assert not any(phrase in text for phrase in OVERCLAIMS), [phrase for phrase in OVERCLAIMS if phrase in text]


# --- dashboard summary ------------------------------------------------------------------

def test_the_dashboard_lists_each_projects_current_trust(client, app, auth_headers, complete):
    other = client.post("/api/projects", json={"name": "Second", "repository_url": "https://github.com/octo/second"}, headers=auth_headers).json()
    body = client.get("/api/dashboard/summary", headers=auth_headers).json()
    by_name = {item["name"]: item for item in body["trust"]}
    assert by_name["Demo"]["status"] == "SCORED" and by_name["Demo"]["trust_score"] is not None and by_name["Demo"]["analysed"] is True
    # A project without a score carries no score fields at all: there is no placeholder to mistake for a result.
    assert by_name["Second"] == {"project_id": other["id"], "name": "Second", "analysed": False, "status": "NOT_ANALYSED"}


def test_the_dashboard_shows_only_the_callers_projects(client, auth_headers, other_headers, complete):
    assert client.get("/api/dashboard/summary", headers=other_headers).json()["trust"] == []


# --- evaluation -------------------------------------------------------------------------

def test_nothing_is_reported_as_evaluated_without_a_benchmark(client, auth_headers):
    rows = catalogue()
    assert rows and all(row["status"] == NOT_EVALUATED and row["value"] is None and row["benchmark"] is None for row in rows)
    assert {row["display"] for row in rows} == {"NOT EVALUATED", "Measured per run"}
    components = {row["component"] for row in rows}
    assert components >= {"vulnerability_matching", "code_reachability", "attack_paths", "commit_behaviour", "predictive_risk", "ai_reasoning", "dataset"}
    body = client.get("/api/dashboard/evaluation", headers=auth_headers).json()
    assert body["not_evaluated"] == body["total"] == len(rows) and "none of them is estimated" in body["note"]
    assert client.get("/api/dashboard/evaluation").status_code == 401


def test_a_supplied_benchmark_result_is_shown_with_its_source():
    rows = catalogue({"vulnerability_matching.precision": {"value": 0.97, "benchmark": "hand-labelled-2026-01", "n": 400},
                      "vulnerability_matching.recall": {"value": 0.9}, "code_reachability.precision": {"value": None, "benchmark": "x"}})
    by_key = {(row["component"], row["measure"]): row for row in rows}
    evaluated = by_key[("vulnerability_matching", "precision")]
    assert evaluated["status"] == "EVALUATED" and evaluated["value"] == 0.97 and evaluated["benchmark"] == "hand-labelled-2026-01"
    assert by_key[("vulnerability_matching", "recall")]["status"] == NOT_EVALUATED          # a value without a named benchmark is not accepted
    assert by_key[("code_reachability", "precision")]["status"] == NOT_EVALUATED


def test_classification_measures():
    predicted = [True, True, True, False, False, False, True, False]
    actual = [True, True, False, False, False, True, True, False]
    result = metrics.classification(predicted, actual)
    assert (result["tp"], result["fp"], result["tn"], result["fn"]) == (3, 1, 3, 1)
    assert result["precision"] == 0.75 and result["recall"] == 0.75 and result["false_positive_rate"] == 0.25 and result["false_negative_rate"] == 0.25
    assert result["f1"] == 0.75 and result["accuracy"] == 0.75


def test_undefined_measures_are_none_not_zero():
    empty = metrics.classification([], [])
    assert empty["precision"] is None and empty["recall"] is None and empty["accuracy"] is None and empty["f1"] is None
    no_positive = metrics.classification([False, False], [False, False])
    assert no_positive["precision"] is None and no_positive["recall"] is None and no_positive["false_positive_rate"] == 0.0
    assert metrics.coverage(0, 0) is None and metrics.coverage(3, 4) == 0.75
    assert metrics.precision_at_k([], 3) is None and metrics.precision_at_k([True], 0) is None
    assert metrics.ndcg([0, 0, 0]) is None and metrics.spearman([1, 2], [1, 2]) is None and metrics.spearman([1, 1, 1], [1, 2, 3]) is None
    assert metrics.brier([], []) is None and metrics.expected_calibration_error([], []) is None
    with pytest.raises(ValueError):
        metrics.confusion([True], [])


def test_ranking_correlation_and_calibration_measures():
    assert metrics.precision_at_k([True, False, True, False], 2) == 0.5 and metrics.precision_at_k([True, True], 5) == 1.0
    assert metrics.ndcg([3, 2, 1]) == 1.0 and metrics.ndcg([1, 2, 3]) < 1.0 and metrics.ndcg([0, 1], k=1) == 0.0
    assert metrics.spearman([1, 2, 3, 4], [10, 20, 30, 40]) == 1.0 and metrics.spearman([1, 2, 3, 4], [4, 3, 2, 1]) == -1.0
    assert metrics.spearman([1, 2, 2, 3], [1, 2, 2, 3]) == 1.0
    assert metrics.brier([1.0, 0.0], [True, False]) == 0.0 and metrics.brier([0.5, 0.5], [True, False]) == 0.25
    perfect = metrics.expected_calibration_error([0.95, 0.95, 0.05, 0.05], [True, True, False, False])
    assert perfect["ece"] == 0.05 and len(perfect["bins"]) == 2
    overconfident = metrics.expected_calibration_error([0.9] * 10, [True] * 5 + [False] * 5)
    assert overconfident["ece"] == 0.4 and overconfident["bins"][0]["accuracy"] == 0.5
    for function in (metrics.spearman, metrics.brier, metrics.expected_calibration_error):
        with pytest.raises(ValueError):
            function([0.1], [])


def test_timing_helpers_measure_and_return_results():
    measured = metrics.timed(lambda: sum(range(1000)), repeats=2)
    assert measured["result"] == 499500 and measured["repeats"] == 2 and 0 <= measured["best_seconds"] <= measured["mean_seconds"]
    points = metrics.scalability(lambda size: list(range(size)), [10, 100])
    assert [point["size"] for point in points] == [10, 100]


def test_benchmark_files_are_validated_and_scored(tmp_path, capsys):
    good = {"benchmark": "labelled-set", "component": "vulnerability_matching",
            "cases": [{"predicted": True, "actual": True}, {"predicted": True, "actual": False}, {"predicted": False, "actual": False}]}
    result = evaluation_run.from_benchmark(good)
    assert result["precision"] == 0.5 and result["recall"] == 1.0 and result["benchmark"] == "labelled-set"
    for bad in ({}, {"benchmark": "x", "cases": []}, {"benchmark": "", "cases": [{"predicted": True, "actual": True}]},
                {"benchmark": "x", "cases": [{"predicted": 1, "actual": True}]}, {"benchmark": "x", "cases": ["nope"]}):
        with pytest.raises(ValueError):
            evaluation_run.from_benchmark(bad)
    path = tmp_path / "labels.json"
    path.write_text(json.dumps(good))
    assert evaluation_run.main(["--benchmark", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["benchmark"]["n"] == 3
    with pytest.raises(SystemExit):
        evaluation_run.main([])


def test_scalability_run_on_generated_graphs(capsys):
    nodes, edges = evaluation_run.synthetic_graph(50)
    assert len(nodes) == 50 and evaluation_run.synthetic_graph(50) == (nodes, edges)          # reproducible
    assert evaluation_run.main(["--scalability", "--sizes", "30,60"]) == 0
    output = json.loads(capsys.readouterr().out)["scalability"]
    assert [point["size"] for point in output["points"]] == [30, 60] and "timing only" in output["note"]
