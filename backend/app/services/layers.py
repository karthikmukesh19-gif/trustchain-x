"""One read of every analysis layer's latest state for a project.

The cross-layer reasoning, the trust engine, the dashboards and the report
all need the same answer to "what do we know, from which analysis, and how
current is it". This module gives that answer once, from stored results
only, so the consumers cannot drift apart.

Every layer is returned with a `status`:

  ANALYSED       results exist for the project's latest snapshot (or, for repository-level layers, for the repository)
  NOT_ANALYSED   the layer has not been run
  STALE          results exist only for an earlier snapshot
  UNAVAILABLE    the layer ran but could not collect its data

and a `reference` to the stored record it was read from. A layer that is not
ANALYSED carries no figures: nothing is filled in for it.
"""

from __future__ import annotations

from typing import Any

from pymongo.database import Database

from app.models.collections import (
    COMMIT_ANALYSIS, DEPENDENCIES, DEPENDENCY_GRAPHS, MAINTAINER_PROFILES, REACHABILITY_ANALYSES, SBOMS, SECURITY_EVENTS, TRUST_SCORES,
)
from app.services import analysis, attack_paths, behaviour, datasets, intelligence, maintainers, runs

ANALYSED, NOT_ANALYSED, STALE, UNAVAILABLE = "ANALYSED", "NOT_ANALYSED", "STALE", "UNAVAILABLE"
LAYER_NAMES = ("inventory", "sbom", "vulnerabilities", "reachability", "fragility", "graph_risk", "predictive", "attack_paths", "maintainers",
               "commits", "dataset")
LAYER_LABELS = {
    "inventory": "Dependency inventory", "sbom": "SBOM", "vulnerabilities": "Vulnerability intelligence", "reachability": "Code reachability",
    "fragility": "Dependency fragility", "graph_risk": "Graph risk", "predictive": "Predictive dependency risk",
    "attack_paths": "Attack paths", "maintainers": "Maintainer behaviour", "commits": "Commit behaviour", "dataset": "Dataset quality",
}
HOW_TO_RUN = {
    "inventory": "Run the dependency analysis.", "sbom": "Generate an SBOM and verify it.", "vulnerabilities": "Run the vulnerability check.",
    "reachability": "Run the code reachability analysis.", "fragility": "Run the dependency intelligence analysis.",
    "graph_risk": "Run the dependency intelligence analysis.", "predictive": "Run the dependency intelligence analysis.",
    "attack_paths": "Run the attack-path simulation.", "maintainers": "Run the maintainer behaviour analysis.",
    "commits": "Run the commit behaviour analysis.", "dataset": "Build and validate the dataset.",
}


def _layer(status: str, reference: dict[str, Any] | None = None, as_of: Any = None, **data: Any) -> dict[str, Any]:
    return {"status": status, "available": status == ANALYSED, "reference": reference, "as_of": as_of, **data}


def _ref(collection: str, identifier: Any) -> dict[str, Any]:
    return {"collection": collection, "id": identifier}


def collect(db: Database, project: dict[str, Any]) -> dict[str, Any]:
    """The latest state of every layer. Reads only; never starts an analysis."""
    project_id = project["_id"]
    snapshot = analysis.latest_snapshot(db, project)
    out: dict[str, Any] = {
        "project": {"id": project_id, "name": project.get("name"), "repository_url": project.get("repository_url")},
        "snapshot": None if snapshot is None else {"id": snapshot["_id"], "commit_sha": snapshot.get("commit_sha"), "branch": snapshot.get("branch"),
                                                   "collected_at": snapshot.get("collected_at"), "committed_at": snapshot.get("committed_at")},
    }

    # --- snapshot-bound layers ---------------------------------------------------------
    if snapshot is None:
        for name in ("inventory", "sbom", "vulnerabilities", "reachability", "fragility", "graph_risk", "predictive", "attack_paths", "dataset"):
            out[name] = _layer(NOT_ANALYSED)
    else:
        snapshot_id = snapshot["_id"]
        graph = db[DEPENDENCY_GRAPHS].find_one({"snapshot_id": snapshot_id, "project_id": project_id}, {"stats": 1}) or {}
        stats = graph.get("stats") or {}
        total = stats.get("total", db[DEPENDENCIES].count_documents({"snapshot_id": snapshot_id, "project_id": project_id}))
        out["inventory"] = _layer(ANALYSED, _ref("repository_snapshots", snapshot_id), snapshot.get("collected_at"), stats={
            "total": total, "direct": stats.get("direct"), "transitive": stats.get("transitive"),
            "relationship_unknown": stats.get("relationship_unknown"), "unresolved_versions": stats.get("unresolved_versions"),
            "max_depth": stats.get("max_depth"), "edges": stats.get("edges"), "without_path": stats.get("without_path"),
            "by_ecosystem": stats.get("by_ecosystem") or {}, "by_relationship_basis": stats.get("by_relationship_basis") or {}})

        fields = {"document_zlib": 0}
        sbom = db[SBOMS].find_one({"project_id": project_id, "snapshot_id": snapshot_id}, fields, sort=[("version", -1)])
        if sbom is None:
            older = db[SBOMS].find_one({"project_id": project_id}, {"version": 1, "generated_at": 1}, sort=[("version", -1)])
            out["sbom"] = _layer(STALE if older else NOT_ANALYSED, _ref(SBOMS, older["_id"]) if older else None, (older or {}).get("generated_at"))
        else:
            verification = sbom.get("last_verification")
            out["sbom"] = _layer(ANALYSED, _ref(SBOMS, sbom["_id"]), sbom.get("generated_at"), sbom_id=sbom["_id"], version=sbom.get("version"),
                                 component_count=sbom.get("component_count"), unresolved_components=sbom.get("unresolved_components"),
                                 components_with_hashes=sbom.get("components_with_hashes"), content_digest=sbom.get("content_digest"),
                                 verified=None if verification is None else bool(verification.get("valid")), verification=verification)

        scan = project.get("latest_vulnerability_scan") or {}
        if scan.get("snapshot_id") == snapshot_id:
            out["vulnerabilities"] = _layer(ANALYSED, _ref("analysis_jobs", scan.get("job_id")), scan.get("matched_at"), **{
                key: scan.get(key) for key in ("dependencies_total", "dependencies_checked", "dependencies_unresolved",
                                               "dependencies_unsupported_ecosystem", "affected_matches", "affected_dependencies",
                                               "distinct_vulnerabilities", "unsupported_matches", "conflict_matches", "by_severity")},
                provider_status=(scan.get("intelligence") or {}).get("status"))
        else:
            out["vulnerabilities"] = _layer(STALE if scan else NOT_ANALYSED, None, scan.get("matched_at"))

        reach = db[REACHABILITY_ANALYSES].find_one({"project_id": project_id, "snapshot_id": snapshot_id, "state": "COMPLETE"},
                                                  sort=[("completed_at", -1)])
        if reach is None:
            out["reachability"] = _layer(NOT_ANALYSED)
        else:
            findings = reach.get("findings") or {}
            out["reachability"] = _layer(ANALYSED, _ref(REACHABILITY_ANALYSES, reach["_id"]), reach.get("completed_at"),
                                         findings=findings.get("findings"), by_status=findings.get("by_status") or {},
                                         source_complete=reach.get("source_complete"), languages=(reach.get("source") or {}).get("languages") or [],
                                         analyzer_version=reach.get("analyzer_version"))

        for name in ("fragility", "graph_risk", "predictive"):
            record = intelligence.latest_analysis(db, project, name)
            if record is None:
                out[name] = _layer(NOT_ANALYSED)
            else:
                out[name] = _layer(ANALYSED, _ref("dependency_analyses", record["_id"]), record.get("created_at"),
                                   summary=(record.get("summary") or {}).get(name) or {}, model_version=(record.get("model_versions") or {}).get(name),
                                   graph=(record.get("summary") or {}).get("graph") or {})

        run = attack_paths.latest(db, project)
        out["attack_paths"] = _layer(NOT_ANALYSED) if run is None else _layer(
            ANALYSED, _ref("analysis_runs", run["_id"]), run.get("created_at"), summary=run.get("summary") or {}, model_version=run.get("model_version"))

        dataset = datasets.latest(db, project)
        if dataset is None:
            out["dataset"] = _layer(NOT_ANALYSED)
        else:
            quality = dataset.get("latest_quality") or {}
            out["dataset"] = _layer(ANALYSED, _ref("datasets", dataset["_id"]), quality.get("validated_at") or dataset.get("created_at"),
                                    dataset_id=dataset["_id"], version=dataset.get("version"), record_count=dataset.get("record_count"),
                                    quality_status=quality.get("status"), quality_score=quality.get("quality_score"),
                                    quality_confidence=quality.get("confidence"), dataset_hash=dataset.get("dataset_hash"))

    # --- repository-level layers -------------------------------------------------------
    run = maintainers.latest(db, project)
    if run is None:
        out["maintainers"] = _layer(NOT_ANALYSED)
    else:
        profile = db[MAINTAINER_PROFILES].find_one({"analysis_id": run["_id"]}, {
            "data_status": 1, "attention_score": 1, "attention_level": 1, "confidence": 1, "contributor_count": 1,
            "anomaly_indicators.type": 1, "anomaly_indicators.status": 1, "anomaly_indicators.detail": 1, "anomaly_indicators.strength": 1,
            "contributor_concentration.top_share": 1, "commit_frequency.total": 1, "commit_frequency.days_since_last": 1}) or {}
        usable = profile.get("data_status") in ("COLLECTED", "PARTIAL")
        out["maintainers"] = _layer(ANALYSED if usable else UNAVAILABLE, _ref(MAINTAINER_PROFILES, profile.get("_id")), run.get("created_at"),
                                    **({k: profile.get(k) for k in ("data_status", "attention_score", "attention_level", "confidence",
                                                                    "contributor_count")} if usable else {"data_status": profile.get("data_status")}),
                                    indicators=profile.get("anomaly_indicators") or [] if usable else [],
                                    top_share=(profile.get("contributor_concentration") or {}).get("top_share") if usable else None,
                                    commits_observed=(profile.get("commit_frequency") or {}).get("total") if usable else None)

    run = behaviour.latest(db, project)
    analysed_total = db[COMMIT_ANALYSIS].count_documents({"project_id": project_id})
    if run is None:
        out["commits"] = _layer(NOT_ANALYSED)
    elif analysed_total == 0:
        status = UNAVAILABLE if (run.get("summary") or {}).get("data_status") == "UNAVAILABLE" else ANALYSED
        out["commits"] = _layer(status, _ref("analysis_runs", run["_id"]), run.get("created_at"), analysed_total=0, by_level={}, events={},
                                security_events=0, highest_anomaly=None, mean_anomaly=None, recent=[])
    else:
        recent = list(db[COMMIT_ANALYSIS].find({"project_id": project_id}, {
            "_id": 0, "commit_sha": 1, "committed_at": 1, "anomaly_score": 1, "level": 1, "confidence": 1, "indicator_types": 1, "message": 1,
            "author_login": 1, "author_name": 1}).sort([("committed_at", -1), ("commit_sha", 1)]).limit(50))
        scores = [row["anomaly_score"] for row in recent]
        levels: dict[str, int] = {}
        for row in recent:
            levels[row["level"]] = levels.get(row["level"], 0) + 1
        events: dict[str, int] = {}
        for row in db[SECURITY_EVENTS].find({"project_id": project_id}, {"event_type": 1}):
            events[row["event_type"]] = events.get(row["event_type"], 0) + 1
        out["commits"] = _layer(ANALYSED, _ref("analysis_runs", run["_id"]), run.get("created_at"), analysed_total=analysed_total,
                                window=len(recent), by_level=levels, security_events=sum(events.values()), security_events_by_type=events,
                                highest_anomaly=max(scores), mean_anomaly=round(sum(scores) / len(scores), 1),
                                mean_confidence=round(sum(row.get("confidence") or 0 for row in recent) / len(recent), 2), recent=recent,
                                data_status=(run.get("summary") or {}).get("data_status"))

    ai_run = runs.latest(db, project, "ai")
    out["ai"] = _layer(NOT_ANALYSED) if ai_run is None else _layer(ANALYSED, _ref("analysis_runs", ai_run["_id"]), ai_run.get("created_at"),
                                                                    summary=ai_run.get("summary") or {}, model_version=ai_run.get("model_version"))
    trust = db[TRUST_SCORES].find_one({"project_id": project_id, **({"snapshot_id": snapshot["_id"]} if snapshot else {})},
                                      {"components": 0, "evidence": 0}, sort=[("created_at", -1), ("_id", -1)])
    out["trust"] = _layer(NOT_ANALYSED) if trust is None else _layer(
        ANALYSED, _ref(TRUST_SCORES, trust["_id"]), trust.get("created_at"),
        score_status=trust.get("status"),
        **{k: trust.get(k) for k in ("trust_score", "risk_score", "confidence", "coverage", "risk_low", "risk_high", "band", "model_version")})
    return out


def missing(layers: dict[str, Any]) -> list[dict[str, str]]:
    """Layers without usable results, each with what to do about it."""
    return [{"layer": name, "label": LAYER_LABELS[name], "status": layers[name]["status"], "action": HOW_TO_RUN[name]}
            for name in LAYER_NAMES if not layers[name]["available"]]
