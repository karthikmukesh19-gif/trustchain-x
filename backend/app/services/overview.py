"""The unified project overview behind the executive, technical and research dashboards.

Everything here is read from stored results through `layers.collect`. A layer
without results appears with its status and no figures, so a dashboard can
show "not analysed" instead of an empty chart that looks like a clean one.
"""

from __future__ import annotations

from typing import Any

from pymongo.database import Database

from app.models.collections import AI_FINDINGS, ANALYSIS_JOBS, ATTACK_PATHS, DEPENDENCY_FRAGILITY, PREDICTIONS, SECURITY_EVENTS
from app.services import layers, runs
from app.services.trust import history as trust_history
from app.services.trust.weights import WEIGHTS_STATEMENT

TREND_POINTS = 60
SCORE_BUCKETS = ((0, 20), (20, 40), (40, 60), (60, 80), (80, 100.01))


def _distribution(db: Database, collection: str, analysis_id: Any, field: str) -> list[dict[str, Any]]:
    """How many rows fall in each fifth of a 0-100 score."""
    counts = [0] * len(SCORE_BUCKETS)
    for row in db[collection].find({"analysis_id": analysis_id}, {field: 1}):
        value = row.get(field)
        if isinstance(value, (int, float)):
            for index, (low, high) in enumerate(SCORE_BUCKETS):
                if low <= value < high:
                    counts[index] += 1
                    break
    return [{"range": f"{low}-{min(int(high), 100)}", "count": count} for (low, high), count in zip(SCORE_BUCKETS, counts)]


def job_timings(db: Database, project_id: Any) -> list[dict[str, Any]]:
    """Measured duration of the latest finished job of each type. A measurement of this installation, not a benchmark."""
    latest: dict[str, dict[str, Any]] = {}
    for job in db[ANALYSIS_JOBS].find({"project_id": project_id, "finished_at": {"$ne": None}, "started_at": {"$ne": None}},
                                      {"type": 1, "state": 1, "started_at": 1, "finished_at": 1}).sort([("finished_at", -1)]).limit(500):
        latest.setdefault(job.get("type") or "dependencies", job)
    return [{"job_type": name, "state": job["state"], "seconds": round((job["finished_at"] - job["started_at"]).total_seconds(), 3),
             "finished_at": job["finished_at"]} for name, job in sorted(latest.items())]


def build(db: Database, project: dict[str, Any]) -> dict[str, Any]:
    collected = layers.collect(db, project)
    project_id = project["_id"]
    trust = trust_history.latest(db, project)
    trend = [{"created_at": item["created_at"], "status": item["status"], "trust_score": item.get("trust_score"),
              "risk_score": item.get("risk_score"), "confidence": item.get("confidence"), "coverage": item.get("coverage"),
              "commit_sha": item.get("commit_sha")} for item in reversed(trust_history.series(db, project_id, TREND_POINTS))]

    def available(name: str) -> bool:
        return bool(collected[name]["available"])

    ai_findings: list[dict[str, Any]] = []
    if available("ai"):
        ai_findings = list(db[AI_FINDINGS].find(
            {"analysis_id": collected["ai"]["reference"]["id"]},
            {"_id": 0, "finding_id": 1, "category": 1, "severity": 1, "confidence": 1, "explanation": 1, "contributing_layers": 1,
             "recommendation.text": 1, "subject.package_name": 1, "subject.advisory": 1})
            .sort([("severity_rank", -1), ("confidence", -1), ("finding_id", 1)]).limit(5))
    top_paths: list[dict[str, Any]] = []
    path_scores: list[dict[str, Any]] = []
    if available("attack_paths"):
        reference = collected["attack_paths"]["reference"]["id"]
        top_paths = list(db[ATTACK_PATHS].find({"analysis_id": reference}, {
            "_id": 0, "attack_path_id": 1, "score": 1, "level": 1, "status": 1, "confidence": 1, "target.package_name": 1, "target.version": 1,
            "advisory.source_id": 1, "advisory.severity": 1}).sort([("score", -1), ("attack_path_id", 1)]).limit(5))
        path_scores = _distribution(db, ATTACK_PATHS, reference, "score")
    events_recent = list(db[SECURITY_EVENTS].find({"project_id": project_id}, {
        "_id": 0, "commit_sha": 1, "event_type": 1, "severity": 1, "occurred_at": 1, "summary": 1}).sort([("occurred_at", -1), ("event_type", 1)]).limit(8))

    technical = {
        "inventory": collected["inventory"].get("stats"),
        "vulnerabilities": {"by_severity": collected["vulnerabilities"].get("by_severity"),
                            "affected_dependencies": collected["vulnerabilities"].get("affected_dependencies"),
                            "distinct": collected["vulnerabilities"].get("distinct_vulnerabilities")} if available("vulnerabilities") else None,
        "sbom": {k: collected["sbom"].get(k) for k in ("version", "component_count", "verified", "content_digest")} if available("sbom") else None,
        "reachability": {"by_status": collected["reachability"].get("by_status"), "findings": collected["reachability"].get("findings"),
                         "source_complete": collected["reachability"].get("source_complete")} if available("reachability") else None,
        "fragility": {"summary": {k: collected["fragility"]["summary"].get(k) for k in ("dependencies", "by_level", "highest", "mean", "single_points")},
                      "distribution": _distribution(db, DEPENDENCY_FRAGILITY, collected["fragility"]["reference"]["id"], "fragility_score")}
        if available("fragility") else None,
        "predictive": {"summary": {k: collected["predictive"]["summary"].get(k) for k in ("dependencies", "by_level", "indicators", "indicator_total", "highest")},
                       "distribution": _distribution(db, PREDICTIONS, collected["predictive"]["reference"]["id"], "score")}
        if available("predictive") else None,
        "attack_paths": {"summary": {k: collected["attack_paths"]["summary"].get(k) for k in ("paths", "by_status", "by_level", "by_severity", "highest_score")},
                         "distribution": path_scores, "top": top_paths} if available("attack_paths") else None,
        "maintainers": {k: collected["maintainers"].get(k) for k in ("attention_score", "attention_level", "confidence", "contributor_count",
                                                                     "top_share", "commits_observed", "indicators", "data_status")}
        if available("maintainers") else None,
        "commits": {**{k: collected["commits"].get(k) for k in ("analysed_total", "by_level", "security_events", "security_events_by_type",
                                                                "highest_anomaly", "mean_anomaly")},
                    "timeline": [{k: row.get(k) for k in ("commit_sha", "committed_at", "anomaly_score", "level", "indicator_types", "message")}
                                 for row in reversed(collected["commits"].get("recent") or [])],
                    "recent_events": events_recent} if available("commits") else None,
        "dataset": {k: collected["dataset"].get(k) for k in ("version", "record_count", "quality_status", "quality_score", "quality_confidence")}
        if available("dataset") else None,
        "ai": {"summary": {k: (collected["ai"].get("summary") or {}).get(k) for k in ("findings", "by_severity", "by_category", "grounding")},
               "top": ai_findings} if available("ai") else None,
    }

    components = (trust or {}).get("components") or []
    grounding = ((collected["ai"].get("summary") or {}).get("grounding") or {}) if available("ai") else {}
    research = {
        "model_versions": {name: collected[name].get("model_version") for name in ("fragility", "graph_risk", "predictive", "attack_paths", "ai")
                           if available(name)} | ({"trust": trust.get("model_version")} if trust else {}),
        "weights_statement": WEIGHTS_STATEMENT,
        "component_confidence": [{"name": c["name"], "label": c["label"], "status": c["status"], "confidence": c["confidence"], "basis": c["basis"]}
                                 for c in components],
        # Quantities this installation actually measured for this project. Anything not listed here was not measured.
        "measured": {
            "evidence_grounding": grounding.get("evidence_grounding"), "unsupported_claim_rate": grounding.get("unsupported_claim_rate"),
            "evidence_coverage": grounding.get("evidence_coverage"), "layer_coverage": round(
                sum(1 for name in layers.LAYER_NAMES if available(name)) / len(layers.LAYER_NAMES), 2),
            "trust_weight_coverage": (trust or {}).get("coverage"),
            "dataset_quality_score": collected["dataset"].get("quality_score") if available("dataset") else None,
            "execution_seconds": job_timings(db, project_id),
        },
        "not_measured_note": "Accuracy figures (precision, recall, calibration, ranking quality) need labelled benchmark data, which this "
                             "installation does not have. They are reported as NOT EVALUATED rather than estimated.",
    }

    current = None
    if trust is not None:
        current = {k: trust.get(k) for k in ("status", "trust_score", "risk_score", "confidence", "coverage", "risk_low", "risk_high", "trust_low",
                                             "trust_high", "band", "unknown_components", "created_at", "model_version", "insufficient_reason")}
        current["id"] = trust["_id"]
        current["components"] = [{k: c.get(k) for k in ("name", "label", "weight", "status", "risk", "contribution", "confidence", "basis", "detail")}
                                 for c in components]
    explanation = (trust or {}).get("explanation") or {}
    executive = {
        "headline": explanation.get("headline") or "No trust analysis has been run for the current snapshot.",
        "top_risks": explanation.get("top_risks") or [], "recommendations": (explanation.get("recommendations") or [])[:5],
        "findings": ai_findings, "attack_paths": top_paths,
        "numbers": {
            "dependencies": (collected["inventory"].get("stats") or {}).get("total") if available("inventory") else None,
            "vulnerabilities": collected["vulnerabilities"].get("distinct_vulnerabilities") if available("vulnerabilities") else None,
            "reachable": (collected["reachability"].get("by_status") or {}).get("REACHABLE") if available("reachability") else None,
            "attack_paths": (collected["attack_paths"]["summary"].get("paths")) if available("attack_paths") else None,
            "security_events": collected["commits"].get("security_events") if available("commits") else None,
            "ai_findings": (collected["ai"].get("summary") or {}).get("findings") if available("ai") else None,
        },
    }
    return {
        "generated_at": runs.now(), "project": {"id": project_id, "name": project.get("name"), "repository_url": project.get("repository_url")},
        "snapshot": collected["snapshot"],
        "layers": [{"name": name, "label": layers.LAYER_LABELS[name], "status": collected[name]["status"], "as_of": collected[name]["as_of"]}
                   for name in layers.LAYER_NAMES],
        "missing": layers.missing(collected),
        "trust": {"current": current, "trend": trend, "weights_statement": WEIGHTS_STATEMENT},
        "executive": executive, "technical": technical, "research": research,
    }
