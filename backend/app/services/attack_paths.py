"""Attack-path simulation for a snapshot: job, storage and reads.

Inputs are what earlier phases stored: the dependency graph (Phase 2),
advisory matches (Phase 3), reachability findings (Phase 4) and, where they
exist, dependency-intelligence scores (Phase 5). Nothing is fetched, and no
repository code is read or run.
"""

from __future__ import annotations

from typing import Any

from bson import ObjectId
from pymongo.database import Database

from app.analyzers.attack_paths import Inputs, Limits, risk, simulate
from app.analyzers.graph.graph_metrics import GraphLimits, GraphTooLarge, analyse_structure
from app.models.collections import (
    ATTACK_PATHS, CODE_REACHABILITY, DEPENDENCIES, DEPENDENCY_GRAPHS, PREDICTIONS, PROJECTS, REACHABILITY_ANALYSES, REPOSITORY_SNAPSHOTS,
    VULNERABILITY_MATCHES,
)
from app.services import intelligence, jobs, runs
from app.services.jobs import JobContext, JobError

KIND = "attack_paths"
ROW_COLLECTIONS = (ATTACK_PATHS,)


def _snapshot(db: Database, job: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    project = db[PROJECTS].find_one({"_id": job["project_id"]})
    if project is None:
        raise JobError("PROJECT_NOT_FOUND", "The project was deleted before the job started.")
    snapshot = db[REPOSITORY_SNAPSHOTS].find_one(
        {"_id": project.get("latest_snapshot_id"), "project_id": project["_id"], "status": "COMPLETE"}, {"files": 0}) \
        if project.get("latest_snapshot_id") else None
    if snapshot is None:
        raise JobError("NOT_ANALYSED", "Run a dependency analysis first: there is no dependency graph to analyse.")
    return project, snapshot


def advisory_groups(db: Database, project_id: ObjectId, snapshot_id: ObjectId) -> tuple[dict[str, list[dict[str, Any]]], dict[ObjectId, tuple[str, str]]]:
    """Distinct vulnerabilities per package, from the stored AFFECTED matches, and which group each match belongs to."""
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    of_match: dict[ObjectId, tuple[str, str]] = {}
    for match in db[VULNERABILITY_MATCHES].find(
            {"project_id": project_id, "snapshot_id": snapshot_id, "match_status": "AFFECTED"},
            {"dependency_node_id": 1, "source_id": 1, "group_key": 1, "aliases": 1, "severity": 1, "severity_rank": 1, "summary": 1,
             "fixed_versions": 1, "confidence": 1, "evidence.match.explanation": 1}).sort([("severity_rank", -1), ("source_id", 1)]):
        key = (match["dependency_node_id"], match.get("group_key") or match["source_id"])
        of_match[match["_id"]] = key
        entry = grouped.get(key)
        if entry is None:
            # The cursor is ordered, so the first match of a group is its most severe record.
            entry = grouped[key] = {
                "group_key": key[1], "source_id": match["source_id"], "aliases": list(match.get("aliases") or []),
                "severity": match.get("severity") or "UNKNOWN", "severity_rank": match.get("severity_rank") or 0,
                "summary": match.get("summary"), "confidence": match.get("confidence"), "fixed_versions": [], "match_ids": [], "match_count": 0,
                "match_explanation": ((match.get("evidence") or {}).get("match") or {}).get("explanation"),
            }
        entry["match_ids"].append(match["_id"])
        entry["match_count"] += 1
        for version in match.get("fixed_versions") or []:
            if isinstance(version, str) and version not in entry["fixed_versions"]:
                entry["fixed_versions"].append(version)
    by_node: dict[str, list[dict[str, Any]]] = {}
    for (node_id, _group), entry in grouped.items():
        by_node.setdefault(node_id, []).append(entry)
    return by_node, of_match


def _run(context: JobContext, job: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    db, settings = context.db, context.settings
    project, snapshot = _snapshot(db, job)
    scan = project.get("latest_vulnerability_scan") or {}
    if scan.get("snapshot_id") != snapshot["_id"]:
        raise JobError("NOT_SCANNED", "Run a vulnerability check for this snapshot first: attack paths start from matched advisories.")
    deadline = lambda: context.check_deadline(settings.intelligence_timeout_seconds)  # noqa: E731

    jobs.progress(db, job, "GRAPH_BUILDING", "Reading the dependency graph and the stored findings")
    graph = db[DEPENDENCY_GRAPHS].find_one({"snapshot_id": snapshot["_id"], "project_id": project["_id"]}, {"nodes": 1, "edges": 1})
    if graph is None:
        raise JobError("NOT_ANALYSED", "The snapshot has no dependency graph. Run the dependency analysis again.")
    try:
        structure = analyse_structure(graph.get("nodes") or [], graph.get("edges") or [],
                                      GraphLimits(settings.intelligence_max_nodes, settings.intelligence_max_edges))
    except GraphTooLarge as exc:
        raise JobError("GRAPH_TOO_LARGE", str(exc)) from exc
    dependencies = {doc["node_id"]: doc for doc in db[DEPENDENCIES].find(
        {"snapshot_id": snapshot["_id"], "project_id": project["_id"]},
        {"node_id": 1, "name": 1, "normalized_name": 1, "ecosystem": 1, "version": 1, "relationship": 1, "relationship_basis": 1,
         "relationship_reason": 1, "evidence": {"$slice": 3}})}
    advisories, of_match = advisory_groups(db, project["_id"], snapshot["_id"])
    reach = db[REACHABILITY_ANALYSES].find_one({"project_id": project["_id"], "snapshot_id": snapshot["_id"], "state": "COMPLETE"},
                                              sort=[("completed_at", -1)])
    findings: dict[tuple[str, str], list[dict[str, Any]]] = {}
    if reach is not None:
        for finding in db[CODE_REACHABILITY].find(
                {"project_id": project["_id"], "snapshot_id": snapshot["_id"], "analysis_id": reach["_id"]},
                {"match_id": 1, "status": 1, "confidence": 1, "reason": 1, "evidence.source_file": 1, "evidence.line": 1, "evidence.symbol": 1}):
            key = of_match.get(finding.get("match_id"))
            if key is not None:
                findings.setdefault(key, []).append(finding)
    predictive = intelligence.latest_analysis(db, project, "predictive")
    annotations: dict[str, dict[str, Any]] = {}
    if predictive is not None:
        for row in db[PREDICTIONS].find({"analysis_id": predictive["_id"], "node_id": {"$in": list(advisories)}},
                                        {"node_id": 1, "score": 1, "level": 1, "fragility_score": 1, "graph_risk": 1}):
            annotations[row["node_id"]] = {"predictive_risk": row.get("score"), "predictive_level": row.get("level"),
                                           "fragility_score": row.get("fragility_score"), "graph_risk": row.get("graph_risk"),
                                           "analysis_id": predictive["_id"], "basis": "PREDICTED"}
    deadline()

    limits = Limits(settings.attack_path_max_depth, settings.attack_path_max_paths, settings.attack_path_max_routes,
                    settings.attack_path_max_expansions)
    input_digest = runs.digest({
        "snapshot": snapshot["_id"], "scan": scan.get("matched_at"), "reachability": (reach or {}).get("_id"),
        "reachability_at": (reach or {}).get("completed_at"), "predictive": (predictive or {}).get("_id"), "model": risk.MODEL_VERSION,
        "limits": [limits.max_depth, limits.max_paths, limits.max_routes, limits.max_expansions]})
    existing = runs.reusable(db, project["_id"], KIND, input_digest)
    if existing is not None:
        return ("Nothing has changed since the previous analysis; it was kept",
                {"summary": {**(existing.get("summary") or {}), "analysis_id": existing["_id"], "reused": True},
                 "analysis_id": existing["_id"], "snapshot_id": snapshot["_id"]})

    jobs.progress(db, job, "PATH_SEARCH", f"Searching paths to {len(advisories)} vulnerable package(s)")
    result = simulate(Inputs(project_name=project.get("name") or "Project", snapshot_id=str(snapshot["_id"]), structure=structure,
                             dependencies=dependencies, advisories=advisories, findings=findings, reachability_analysed=reach is not None,
                             annotations=annotations), limits)
    deadline()

    jobs.progress(db, job, "SCORING", f"Storing {len(result['paths'])} path(s)")
    run = runs.begin(db, project=project, snapshot=snapshot, kind=KIND, job=job, model_version=risk.MODEL_VERSION, input_digest=input_digest,
                     inputs={"vulnerability_scan_matched_at": scan.get("matched_at"),
                             "reachability_analysis_id": (reach or {}).get("_id"), "reachability_completed_at": (reach or {}).get("completed_at"),
                             "predictive_analysis_id": (predictive or {}).get("_id"),
                             "limits": {"max_depth": limits.max_depth, "max_paths": limits.max_paths, "max_routes": limits.max_routes}})
    scope = {"analysis_id": run["_id"], "project_id": project["_id"], "repository_id": project["repository_id"],
             "snapshot_id": snapshot["_id"], "created_at": run["created_at"]}
    try:
        runs.insert_rows(db, ATTACK_PATHS, [{**scope, **path} for path in result["paths"]])
    except Exception:
        runs.discard(db, run, ROW_COLLECTIONS)
        raise
    summary = {**result["summary"], "packages": structure.model.size, "reachability_analysed": reach is not None, "reused": False}
    runs.complete(db, run, summary)
    runs.prune(db, project["_id"], KIND, settings.intelligence_history_limit, ROW_COLLECTIONS)
    by_status = summary["by_status"]
    message = (f"{summary['paths']} attack path(s): {by_status[risk.SUPPORTED_PATH]} supported, {by_status[risk.POTENTIAL_PATH]} potential, "
               f"{by_status[risk.UNKNOWN_PATH]} unknown")
    return message, {"summary": {**summary, "analysis_id": run["_id"]}, "analysis_id": run["_id"], "snapshot_id": snapshot["_id"]}


jobs.handler(jobs.ATTACK_PATH_ANALYSIS)(_run)


def latest(db: Database, project: dict[str, Any]) -> dict[str, Any] | None:
    return runs.latest(db, project, KIND)


def delete_project_data(db: Database, project_id: ObjectId) -> None:
    for collection in ROW_COLLECTIONS:
        db[collection].delete_many({"project_id": project_id})
