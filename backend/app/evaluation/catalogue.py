"""Which evaluation measures exist for which component, and whether each has been evaluated.

A measure is EVALUATED only when a benchmark result for it has been supplied
(see `app.evaluation.run`). Otherwise it is NOT_EVALUATED, with the kind of
data that would be needed. No default or illustrative value is ever given.
"""

from __future__ import annotations

from typing import Any

NOT_EVALUATED, EVALUATED = "NOT_EVALUATED", "EVALUATED"

# (component, measure, what it would be measured against)
MEASURES: tuple[tuple[str, str, str], ...] = (
    ("vulnerability_matching", "precision", "package versions labelled affected or not affected by hand or by a second, independent source"),
    ("vulnerability_matching", "recall", "the same labelled set"),
    ("vulnerability_matching", "false_positive_rate", "the same labelled set"),
    ("vulnerability_matching", "false_negative_rate", "the same labelled set"),
    ("code_reachability", "precision", "vulnerable functions labelled reachable or not by manual review or by dynamic traces"),
    ("code_reachability", "recall", "the same labelled set"),
    ("code_reachability", "coverage", "share of findings the analysis decides (measured per project; see the project's research dashboard)"),
    ("attack_paths", "precision", "paths labelled valid or invalid by security review"),
    ("attack_paths", "graph_processing_scalability", "timings over dependency graphs of increasing size (run `python -m app.evaluation.run --scalability`)"),
    ("commit_behaviour", "precision", "commits labelled security-relevant or not by reviewers"),
    ("commit_behaviour", "recall", "the same labelled set"),
    ("commit_behaviour", "false_positive_rate", "the same labelled set"),
    ("maintainer_behaviour", "precision", "repositories with independently documented maintenance events"),
    ("predictive_risk", "ranking_quality", "later-published advisories for the ranked dependencies (precision@k, NDCG)"),
    ("predictive_risk", "correlation_with_historical_findings", "advisory history of the same packages (Spearman rank correlation)"),
    ("predictive_risk", "calibration", "outcomes observed after the prediction date (expected calibration error, Brier score)"),
    ("fragility", "correlation_with_historical_findings", "advisory and breakage history of the same packages"),
    ("trust_score", "confidence_quality", "outcomes for projects scored earlier, to compare stated confidence with what happened"),
    ("ai_reasoning", "evidence_grounding", "measured on every run from the findings themselves (see the project's research dashboard)"),
    ("ai_reasoning", "unsupported_claim_rate", "measured on every run from the findings themselves"),
    ("ai_reasoning", "evidence_coverage", "measured on every run from the findings themselves"),
    ("dataset", "duplicate_detection_accuracy", "a dataset with duplicates planted at known positions"),
    ("dataset", "label_consistency", "measured on every validation from the records themselves"),
    ("dataset", "provenance_completeness", "measured on every validation from the records themselves"),
    ("platform", "execution_time", "measured per job on this installation (see the project's research dashboard)"),
)
MEASURED_PER_RUN = {("ai_reasoning", "evidence_grounding"), ("ai_reasoning", "unsupported_claim_rate"), ("ai_reasoning", "evidence_coverage"),
                    ("dataset", "label_consistency"), ("dataset", "provenance_completeness"), ("platform", "execution_time"),
                    ("code_reachability", "coverage")}


def catalogue(results: dict[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Every measure with its status. `results` maps "component.measure" to a benchmark result {"value", "benchmark", "n", "evaluated_at"}."""
    results = results or {}
    rows = []
    for component, measure, needs in MEASURES:
        result = results.get(f"{component}.{measure}")
        per_run = (component, measure) in MEASURED_PER_RUN
        if result is not None and result.get("value") is not None and result.get("benchmark"):
            rows.append({"component": component, "measure": measure, "status": EVALUATED, "value": result["value"],
                         "benchmark": result["benchmark"], "n": result.get("n"), "evaluated_at": result.get("evaluated_at"), "needs": needs,
                         "measured_per_run": per_run})
        else:
            rows.append({"component": component, "measure": measure, "status": NOT_EVALUATED, "value": None, "benchmark": None, "n": None,
                         "evaluated_at": None, "needs": needs, "measured_per_run": per_run,
                         "display": "Measured per run" if per_run else "NOT EVALUATED"})
    return rows
