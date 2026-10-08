"""Dependency intelligence: fragility, graph risk and predictive indicators for a snapshot.

Three jobs share one pipeline and differ in how far they go:

  dependency_fragility_analysis    graph metrics -> registry metadata -> fragility and health
  graph_risk_analysis              graph metrics -> risk propagation
  predictive_dependency_analysis   all of the above -> indicators and predictive dependency risk

Inputs are what earlier phases stored: the dependency inventory and graph
(Phase 2), vulnerability matches (Phase 3) and reachability findings (Phase 4).
Their logic is not repeated here. The only new data is release metadata from
the configured package registries, cached in `package_metadata`.

Every run is stored under its own analysis id and kept, so runs can be
compared. A run whose inputs are identical to an earlier one returns that
earlier analysis instead of storing a copy.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from bson import ObjectId
from pymongo.database import Database

from app.analyzers.fragility import fragility as fragility_model
from app.analyzers.fragility.fragility import DependencyFragilityAnalyzer, FragilityInputs
from app.analyzers.fragility.metrics import reachable_count
from app.analyzers.graph import prediction, risk_propagation
from app.analyzers.graph.graph_metrics import GraphLimits, GraphTooLarge, Structure, analyse_structure
from app.analyzers.vulnerabilities.versions import UnsupportedVersion, parse
from app.collectors.registries import base as registry_base
from app.models.collections import (
    CODE_EDGES, CODE_REACHABILITY, DEPENDENCIES, DEPENDENCY_ANALYSES, DEPENDENCY_FRAGILITY, DEPENDENCY_GRAPHS, DEPENDENCY_HEALTH,
    GRAPH_RISK_ANALYSIS, PACKAGE_METADATA, PREDICTIONS, PREDICTIVE_INDICATORS, PROJECTS, REACHABILITY_ANALYSES, REPOSITORY_SNAPSHOTS,
    SOURCE_SYMBOLS, VULNERABILITY_MATCHES,
)
from app.services import jobs
from app.services.analysis import storable
from app.services.jobs import JobContext, JobError

logger = logging.getLogger(__name__)

FRAGILITY, GRAPH_RISK, PREDICTIVE = "fragility", "graph_risk", "predictive"
KIND_OF_JOB = {jobs.DEPENDENCY_FRAGILITY_ANALYSIS: FRAGILITY, jobs.GRAPH_RISK_ANALYSIS: GRAPH_RISK,
               jobs.PREDICTIVE_DEPENDENCY_ANALYSIS: PREDICTIVE}
LAYERS = {FRAGILITY: ("fragility", "health"), GRAPH_RISK: ("graph_risk",),
          PREDICTIVE: ("fragility", "health", "graph_risk", "indicators", "predictive")}
ROW_COLLECTIONS = (DEPENDENCY_FRAGILITY, DEPENDENCY_HEALTH, GRAPH_RISK_ANALYSIS, PREDICTIVE_INDICATORS, PREDICTIONS)
MAX_CONSECUTIVE_REGISTRY_ERRORS = 5
_BATCH = 1000


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _insert(db: Database, collection: str, rows: list[dict[str, Any]]) -> None:
    for start in range(0, len(rows), _BATCH):
        db[collection].insert_many(rows[start:start + _BATCH], ordered=False)


# --- inputs from earlier phases ---------------------------------------------------------

def vulnerability_summaries(db: Database, project_id: ObjectId, snapshot_id: ObjectId) -> dict[str, dict[str, Any]]:
    """Per dependency: what Phase 3 matched. Only AFFECTED matches count; nothing is re-evaluated."""
    grouped: dict[str, dict[str, Any]] = {}
    for match in db[VULNERABILITY_MATCHES].find(
            {"project_id": project_id, "snapshot_id": snapshot_id, "match_status": "AFFECTED"},
            {"dependency_node_id": 1, "source_id": 1, "group_key": 1, "severity": 1, "severity_rank": 1, "fixed_versions": 1, "ecosystem": 1}):
        entry = grouped.setdefault(match["dependency_node_id"], {
            "matches": 0, "groups": set(), "advisories": [], "by_severity": Counter(), "rank": -1, "max_severity": "UNKNOWN",
            "fixed": set(), "fixed_groups": set(), "ecosystem": match.get("ecosystem")})
        entry["matches"] += 1
        entry["groups"].add(match.get("group_key") or match["source_id"])
        entry["advisories"].append((-(match.get("severity_rank") or 0), match["source_id"]))
        entry["by_severity"][match.get("severity") or "UNKNOWN"] += 1
        if (match.get("severity_rank") or 0) > entry["rank"]:
            entry["rank"], entry["max_severity"] = match.get("severity_rank") or 0, match.get("severity") or "UNKNOWN"
        fixed = [v for v in match.get("fixed_versions") or [] if isinstance(v, str)]
        entry["fixed"].update(fixed)
        if fixed:
            entry["fixed_groups"].add(match.get("group_key") or match["source_id"])
    result = {}
    for node_id, entry in grouped.items():
        result[node_id] = {
            "matches": entry["matches"], "distinct": len(entry["groups"]), "max_severity": entry["max_severity"],
            "by_severity": dict(entry["by_severity"]), "advisories": [identifier for _rank, identifier in sorted(entry["advisories"])][:20],
            "fixed_versions": _ordered_versions(entry["ecosystem"], entry["fixed"]), "with_fix": len(entry["fixed_groups"]),
        }
    return result


def _ordered_versions(ecosystem: str | None, versions: set[str]) -> list[str]:
    """Fixed versions lowest to highest by the ecosystem's rules; those that cannot be ordered are left out."""
    keyed = []
    for version in versions:
        try:
            keyed.append((parse(ecosystem or "", version), version))
        except UnsupportedVersion:
            continue
    try:
        return [version for _key, version in sorted(keyed)][-10:]
    except TypeError:
        return []


def reachability_summaries(db: Database, project_id: ObjectId, snapshot_id: ObjectId) -> tuple[dict[str, dict[str, Any]], bool, int | None, dict[str, Any] | None]:
    """Per dependency: what Phase 4 found. Returns (summaries, analysed, application modules, analysis reference)."""
    analysis = db[REACHABILITY_ANALYSES].find_one({"project_id": project_id, "snapshot_id": snapshot_id, "state": "COMPLETE"},
                                                 sort=[("completed_at", -1)])
    if analysis is None:
        return {}, False, None, None
    summaries: dict[str, dict[str, Any]] = {}

    def entry(node_id: str) -> dict[str, Any]:
        return summaries.setdefault(node_id, {"findings": 0, "reachable": 0, "not_confirmed": 0, "unknown": 0, "unsupported": 0,
                                              "reachable_findings": [], "importing_modules": None, "use_sites": None})
    keys = {"REACHABLE": "reachable", "NOT_CONFIRMED_REACHABLE": "not_confirmed", "UNKNOWN": "unknown", "UNSUPPORTED": "unsupported"}
    for finding in db[CODE_REACHABILITY].find(
            {"project_id": project_id, "snapshot_id": snapshot_id, "analysis_id": analysis["_id"]},
            {"dependency_node_id": 1, "status": 1, "confidence": 1, "advisory_id": 1, "evidence.source_file": 1, "evidence.line": 1}):
        item = entry(finding["dependency_node_id"])
        item["findings"] += 1
        item[keys.get(finding["status"], "unknown")] += 1
        if finding["status"] == "REACHABLE" and len(item["reachable_findings"]) < 20:
            evidence = finding.get("evidence") or {}
            item["reachable_findings"].append({"advisory_id": finding["advisory_id"], "confidence": finding.get("confidence"),
                                               "source_file": evidence.get("source_file"), "line": evidence.get("line")})
    modules = None
    if analysis.get("source_state") == "COMPLETE":
        # How the application's own modules use each dependency, from the stored code graph.
        modules = db[SOURCE_SYMBOLS].count_documents({"analysis_id": analysis["_id"], "kind": "module"})
        externals = {doc["symbol_id"]: doc.get("dependency_node_ids") or []
                     for doc in db[SOURCE_SYMBOLS].find({"analysis_id": analysis["_id"], "kind": "external"},
                                                        {"symbol_id": 1, "dependency_node_ids": 1})}
        importing: dict[str, set[str]] = {}
        uses: Counter[str] = Counter()
        for edge in db[CODE_EDGES].find({"analysis_id": analysis["_id"], "target": {"$in": list(externals)}},
                                        {"kind": 1, "source": 1, "target": 1}):
            for node_id in externals.get(edge["target"], []):
                if edge["kind"] == "imports":
                    importing.setdefault(node_id, set()).add(str(edge["source"]).split(":", 1)[0])
                elif edge["kind"] in ("calls", "references"):
                    uses[node_id] += 1
        for node_id in set(importing) | set(uses):
            item = entry(node_id)
            item["importing_modules"], item["use_sites"] = len(importing.get(node_id, ())), uses.get(node_id, 0)
    reference = {"analysis_id": analysis["_id"], "completed_at": analysis.get("completed_at"), "analyzer_version": analysis.get("analyzer_version"),
                 "source_complete": analysis.get("source_complete")}
    return summaries, True, modules, reference


# --- registry metadata ------------------------------------------------------------------

def _from_cache(document: dict[str, Any]) -> dict[str, Any]:
    versions = {item["v"]: item.get("at") for item in document.get("releases") or [] if isinstance(item, dict) and isinstance(item.get("v"), str)}
    return {**{k: v for k, v in document.items() if k not in ("_id", "releases")}, "versions": versions}


def _to_cache(metadata: dict[str, Any], fetched_at: datetime) -> dict[str, Any]:
    document = {k: v for k, v in metadata.items() if k != "versions"}
    document["releases"] = [{"v": version, "at": moment} for version, moment in metadata.get("versions", {}).items()]
    document["fetched_at"] = fetched_at
    return document


# Registry problems that say nothing about the registry as a whole: this one answer was unusable.
_PACKAGE_SPECIFIC_ERRORS = ("BAD_RESPONSE", "RESPONSE_TOO_LARGE")


def collect_metadata(context: JobContext, job: dict[str, Any], dependencies: list[dict[str, Any]]) -> tuple[dict[tuple[str, str], dict[str, Any]], dict[str, Any]]:
    """Release metadata for the snapshot's packages, from the cache where it is fresh and the registries otherwise.

    Returns the metadata keyed by (ecosystem, normalized name) and what happened.
    Direct dependencies are looked up in full (with release dates); transitive
    npm packages use the registry's compact answer, which has no dates. A
    registry that keeps failing is not asked about every remaining package.
    When an answer cannot be refreshed, an earlier one is used and marked stale.
    """
    db, settings = context.db, context.settings
    registries = context.registries or {}
    # One lookup per (ecosystem, name as the registry spells it). The cache is keyed the same way.
    wanted: dict[tuple[str, str], bool] = {}
    asked_as: dict[tuple[str, str], tuple[str, str]] = {}
    for dependency in dependencies:
        ecosystem = dependency["ecosystem"]
        registry = registries.get(ecosystem)
        name = registry.lookup_name(dependency) if registry is not None else dependency["normalized_name"]
        key = (ecosystem, name if isinstance(name, str) else "")
        asked_as.setdefault((ecosystem, dependency["normalized_name"]), key)
        key = asked_as[(ecosystem, dependency["normalized_name"])]
        wanted[key] = wanted.get(key, False) or dependency.get("relationship") == "DIRECT"
    stats = {"packages": len(wanted), "from_cache": 0, "fetched": 0, "not_found": 0, "errors": 0, "unsupported_ecosystem": 0, "invalid_name": 0,
             "skipped_by_limit": 0, "skipped_after_failures": 0, "stale_used": 0, "error_codes": Counter(), "requests": 0}
    found: dict[tuple[str, str], dict[str, Any]] = {}
    fresh_after = _now() - timedelta(hours=settings.package_metadata_ttl_hours)
    cached = {}
    by_ecosystem: dict[str, list[str]] = {}
    for ecosystem, name in wanted:
        by_ecosystem.setdefault(ecosystem, []).append(name)
    for ecosystem, names in by_ecosystem.items():
        for start in range(0, len(names), _BATCH):
            for document in db[PACKAGE_METADATA].find({"ecosystem": ecosystem, "normalized_name": {"$in": names[start:start + _BATCH]}}):
                cached[(ecosystem, document["normalized_name"])] = document

    def unavailable(key: tuple[str, str], registry_name: str, code: str, counter: str) -> None:
        """No fresh answer for this package: reuse an earlier one, marked stale, or record why there is none."""
        stats[counter] += 1
        document = cached.get(key)
        if document is not None and document.get("status") == registry_base.COLLECTED:
            stats["stale_used"] += 1
            found[key] = {**_from_cache(document), "stale": True}
        else:
            found[key] = {"status": registry_base.ERROR, "error_code": code, "registry": registry_name}

    failures: Counter[str] = Counter()
    lookups = 0
    position = 0
    # Direct dependencies first: if a limit is reached, the packages the project chose itself are covered.
    for key in sorted(wanted, key=lambda item: (not wanted[item], item)):
        position += 1
        ecosystem, name = key
        registry = registries.get(ecosystem)
        if registry is None:
            stats["unsupported_ecosystem"] += 1
            continue
        detail = registry_base.FULL if wanted[key] or registry.name == "pypi" else registry_base.COMPACT
        document = cached.get(key)
        if document is not None and document.get("fetched_at") is not None and document["fetched_at"] >= fresh_after \
                and (document.get("status") != registry_base.COLLECTED or detail == registry_base.COMPACT or document.get("detail") == registry_base.FULL):
            found[key] = _from_cache(document)
            stats["from_cache"] += 1
            continue
        if failures[ecosystem] >= MAX_CONSECUTIVE_REGISTRY_ERRORS:
            unavailable(key, registry.name, "REGISTRY_UNAVAILABLE", "skipped_after_failures")
            continue
        if lookups >= settings.package_metadata_max_packages:
            unavailable(key, registry.name, "LOOKUP_LIMIT", "skipped_by_limit")
            continue
        context.check_deadline(settings.intelligence_timeout_seconds)
        lookups += 1
        before = registry.requests_made
        result = registry.lookup(name, detail)
        if result.get("error_code") == "RESPONSE_TOO_LARGE" and detail == registry_base.FULL and registry.name == "npm":
            # Some npm packages publish a full document larger than the limit. The compact form still has the versions;
            # the release dates stay unknown.
            result = registry.lookup(name, registry_base.COMPACT)
        stats["requests"] += registry.requests_made - before
        fetched_at = _now()
        result["fetched_at"] = fetched_at
        if result["status"] == registry_base.ERROR:
            code = result.get("error_code") or "ERROR"
            stats["error_codes"][code] += 1
            # Timeouts, refused connections and error statuses all count towards giving up on the registry for this run.
            if code not in _PACKAGE_SPECIFIC_ERRORS:
                failures[ecosystem] += 1
            unavailable(key, registry.name, code, "errors")
            if found[key].get("stale") is not True:
                found[key] = result
        else:
            failures[ecosystem] = 0
            if result["status"] != registry_base.INVALID_NAME:
                stats["fetched"] += 1                       # an answer from the registry, including "no such package"
            db[PACKAGE_METADATA].update_one({"ecosystem": ecosystem, "normalized_name": name},
                                            {"$set": storable(_to_cache(result, fetched_at), 500)}, upsert=True)
            found[key] = result
        if lookups % 25 == 0:
            jobs.progress(db, job, "PACKAGE_METADATA", f"Looked up {position} of {len(wanted)} package(s) in their registries")
    # What the registries say, wherever the answer came from (cache or network).
    stats["not_found"] = sum(1 for item in found.values() if item.get("status") == registry_base.NOT_FOUND)
    stats["invalid_name"] = sum(1 for item in found.values() if item.get("status") == registry_base.INVALID_NAME)
    stats["error_codes"] = dict(stats["error_codes"])
    stats["incomplete"] = bool(stats["errors"] or stats["skipped_by_limit"] or stats["skipped_after_failures"])
    stats["providers"] = sorted(registry.name for registry in registries.values())
    metadata = {package: found[key] for package, key in asked_as.items() if key in found}
    return metadata, stats


def _fingerprint(metadata: dict[str, Any]) -> str:
    """Everything of a registry answer that can change a result, so a changed answer is never mistaken for the same input."""
    return _digest({
        "status": metadata.get("status"), "detail": metadata.get("detail"), "latest": metadata.get("latest_version"),
        "latest_at": metadata.get("latest_published_at"), "stale": bool(metadata.get("stale")), "truncated": bool(metadata.get("versions_truncated")),
        "versions": sorted((version, str(moment)) for version, moment in (metadata.get("versions") or {}).items()),
        "withdrawn": sorted(metadata.get("withdrawn_versions") or []), "deprecated": sorted(metadata.get("deprecated_versions") or []),
    })


# --- the run ----------------------------------------------------------------------------

def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()


def _snapshot_for(db: Database, job: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    project = db[PROJECTS].find_one({"_id": job["project_id"]})
    if project is None:
        raise JobError("PROJECT_NOT_FOUND", "The project was deleted before the job started.")
    snapshot = db[REPOSITORY_SNAPSHOTS].find_one(
        {"_id": project.get("latest_snapshot_id"), "project_id": project["_id"], "status": "COMPLETE"}, {"files": 0}) \
        if project.get("latest_snapshot_id") else None
    if snapshot is None:
        raise JobError("NOT_ANALYSED", "Run a dependency analysis first: there is no dependency graph to analyse.")
    return project, snapshot


def _run(context: JobContext, job: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    db, settings = context.db, context.settings
    kind = KIND_OF_JOB[job["type"]]
    project, snapshot = _snapshot_for(db, job)
    scan = project.get("latest_vulnerability_scan") or {}
    scanned = scan.get("snapshot_id") == snapshot["_id"]
    if kind != FRAGILITY and not scanned:
        raise JobError("NOT_SCANNED", "Run a vulnerability check for this snapshot first: risk cannot be traced without it.")
    deadline = lambda: context.check_deadline(settings.intelligence_timeout_seconds)  # noqa: E731

    jobs.progress(db, job, "GRAPH_METRICS", "Measuring the dependency graph")
    graph = db[DEPENDENCY_GRAPHS].find_one({"snapshot_id": snapshot["_id"], "project_id": project["_id"]}, {"nodes": 1, "edges": 1})
    if graph is None:
        raise JobError("NOT_ANALYSED", "The snapshot has no dependency graph. Run the dependency analysis again.")
    try:
        structure = analyse_structure(graph.get("nodes") or [], graph.get("edges") or [],
                                      GraphLimits(settings.intelligence_max_nodes, settings.intelligence_max_edges))
    except GraphTooLarge as exc:
        raise JobError("GRAPH_TOO_LARGE", str(exc)) from exc
    deadline()
    dependencies = list(db[DEPENDENCIES].find(
        {"snapshot_id": snapshot["_id"], "project_id": project["_id"]},
        {"node_id": 1, "name": 1, "normalized_name": 1, "ecosystem": 1, "version": 1, "relationship": 1}))
    vulnerabilities = vulnerability_summaries(db, project["_id"], snapshot["_id"]) if scanned else {}
    reachability, reach_analysed, modules, reach_reference = reachability_summaries(db, project["_id"], snapshot["_id"])
    as_of = _now()

    metadata: dict[tuple[str, str], dict[str, Any]] = {}
    metadata_stats: dict[str, Any] | None = None
    if kind != GRAPH_RISK:
        jobs.progress(db, job, "PACKAGE_METADATA", "Collecting release metadata from the package registries")
        metadata, metadata_stats = collect_metadata(context, job, dependencies)
        deadline()

    digest = _digest({
        "kind": kind, "snapshot": snapshot["_id"], "scan": scan.get("matched_at") if scanned else None,
        "reachability": reach_reference, "day": as_of.date().isoformat(),
        "models": [fragility_model.MODEL_VERSION, risk_propagation.MODEL_VERSION, prediction.MODEL_VERSION, prediction.INDICATOR_VERSION],
        "metadata": sorted((eco, name, _fingerprint(m)) for (eco, name), m in metadata.items()),
    })
    existing = db[DEPENDENCY_ANALYSES].find_one({"project_id": project["_id"], "kind": kind, "input_digest": digest, "state": "COMPLETE"})
    if existing is not None:
        message = "Nothing has changed since the previous analysis; it was kept"
        return message, {"summary": {**(existing.get("summary") or {}), "analysis_id": existing["_id"], "reused": True},
                         "analysis_id": existing["_id"], "snapshot_id": snapshot["_id"], **_partial(metadata_stats)}

    analysis_id = ObjectId()
    scope = {"analysis_id": analysis_id, "project_id": project["_id"], "repository_id": project["repository_id"],
             "snapshot_id": snapshot["_id"], "created_at": as_of}
    models = {"fragility": fragility_model.MODEL_VERSION, "graph_risk": risk_propagation.MODEL_VERSION,
              "predictive": prediction.MODEL_VERSION, "indicators": prediction.INDICATOR_VERSION}
    summary: dict[str, Any] = {"kind": kind, "packages": structure.model.size, "graph": structure.concentration,
                               "graph_issues": structure.model.issues, "betweenness_computed": structure.betweenness_computed,
                               "vulnerability_scan": scanned, "reachability_analysed": reach_analysed, "reused": False}
    rows: dict[str, list[dict[str, Any]]] = {name: [] for name in ROW_COLLECTIONS}
    fragility_rows: list[dict[str, Any]] = []

    if kind != GRAPH_RISK:
        jobs.progress(db, job, "FRAGILITY", "Scoring dependency fragility")
        fragility_rows = DependencyFragilityAnalyzer().analyze(FragilityInputs(
            dependencies=dependencies, structure=structure, metadata=metadata, vulnerabilities=vulnerabilities, reachability=reachability,
            reachability_analysed=reach_analysed, application_modules=modules, as_of=as_of))
        for row in fragility_rows:
            health = row.pop("health")
            if not scanned:
                health["known_vulnerability_count"] = None
                health["unknown"].append({"field": "known_vulnerability_count", "status": "UNKNOWN",
                                          "reason": "No vulnerability check has been run for this snapshot."})
            identity = {**scope, "model_version": fragility_model.MODEL_VERSION, "dependency_id": row["dependency_id"], "node_id": row["node_id"],
                        "package_name": row["package_name"], "normalized_name": row["normalized_name"], "ecosystem": row["ecosystem"],
                        "version": row["version"]}
            rows[DEPENDENCY_FRAGILITY].append({**scope, "model_version": fragility_model.MODEL_VERSION, **row})
            rows[DEPENDENCY_HEALTH].append({**identity, **health})
        scores = [row["fragility_score"] for row in fragility_rows]
        summary["fragility"] = {
            "dependencies": len(fragility_rows), "by_level": dict(Counter(row["fragility_level"] for row in fragility_rows)),
            "highest": max(scores, default=None), "mean": round(sum(scores) / len(scores), 1) if scores else None,
            "mean_confidence": round(sum(row["confidence"] for row in fragility_rows) / len(fragility_rows), 2) if fragility_rows else None,
            "single_points": sum(1 for row in fragility_rows if row["inferred_metrics"]["single_point"]),
            "version_comparison": dict(Counter(row["inferred_metrics"]["version"]["comparison_status"] for row in fragility_rows)),
            "top": [{"node_id": row["node_id"], "score": row["fragility_score"]} for row in
                    sorted(fragility_rows, key=lambda r: (-r["fragility_score"], r["node_id"]))[:5]],
        }
        summary["metadata"] = metadata_stats
        deadline()

    propagation: dict[str, Any] | None = None
    if kind != FRAGILITY:
        jobs.progress(db, job, "RISK_PROPAGATION", "Tracing vulnerable packages through the graph")
        propagation = risk_propagation.propagate(structure, vulnerabilities, reachability, reach_analysed)
        by_node = {d["node_id"]: d for d in dependencies}
        for node_id, entry in propagation["nodes"].items():
            dependency = by_node.get(node_id, {})
            structural = structure.rows[node_id]
            rows[GRAPH_RISK_ANALYSIS].append({
                **scope, "model_version": risk_propagation.MODEL_VERSION, "dependency_id": dependency.get("_id"),
                "package_name": dependency.get("name"), "normalized_name": dependency.get("normalized_name"),
                "ecosystem": dependency.get("ecosystem"), "version": dependency.get("version"), "relationship": dependency.get("relationship"),
                **entry,
                "metrics": {key: structural[key] for key in ("depth", "fan_in", "fan_out", "dependents", "dependents_share", "introduced",
                                                             "degree_centrality", "betweenness_centrality", "relative_centrality")},
            })
        summary["graph_risk"] = {
            "by_classification": propagation["by_classification"], "project": propagation["project"], "paths": propagation["paths"],
            "paths_truncated": propagation["paths_truncated"],
            "parameters": propagation["parameters"],
            "top": [{"node_id": e["node_id"], "graph_risk": e["graph_risk"], "classification": e["classification"]} for e in
                    sorted(propagation["nodes"].values(), key=lambda e: (-e["graph_risk"], e["node_id"]))[:5] if e["graph_risk"] > 0],
        }
        deadline()

    if kind == PREDICTIVE and propagation is not None:
        jobs.progress(db, job, "PREDICTION", "Deriving indicators and predictive dependency risk")
        types: Counter[str] = Counter()
        levels: Counter[str] = Counter()
        predictions = []
        for row in fragility_rows:
            node_id = row["node_id"]
            risk = propagation["nodes"][node_id]
            vulnerable = vulnerabilities.get(node_id, {})
            reach = reachability.get(node_id, {})
            found = prediction.indicators(row, risk, vulnerable, reach, structure.model.size, structure.betweenness_computed)
            predicted = prediction.predictive_risk(row, risk, structure.model.size)
            identity = {**scope, "dependency_id": row["dependency_id"], "node_id": node_id, "package_name": row["package_name"],
                        "normalized_name": row["normalized_name"], "ecosystem": row["ecosystem"], "version": row["version"]}
            for indicator in found:
                types[indicator["type"]] += 1
                rows[PREDICTIVE_INDICATORS].append({**identity, "model_version": prediction.INDICATOR_VERSION, **indicator})
            levels[predicted["level"]] += 1
            predictions.append({
                **identity, "subject_type": "dependency", "subject_id": node_id, "relationship": row["relationship"],
                "predicted_risk": predicted["score"], **predicted,
                "fragility_score": row["fragility_score"], "fragility_confidence": row["confidence"],
                "graph_risk": risk["graph_risk"], "exposure_classification": risk["classification"],
                "vulnerability_count": vulnerable.get("distinct", 0), "max_severity": vulnerable.get("max_severity") if vulnerable else None,
                "reachable_vulnerability_count": reachable_count(vulnerable.get("distinct", 0), reach, reach_analysed)[0],
                "reachability_state": risk["reachability_state"],
                "dependents": row["observed_metrics"]["dependents"], "depth": row["observed_metrics"]["depth"],
                "relative_centrality": row["inferred_metrics"]["relative_centrality"],
                "betweenness_centrality": row["inferred_metrics"]["betweenness_centrality"],
                "degree_centrality": row["inferred_metrics"]["degree_centrality"],
                "indicator_types": [indicator["type"] for indicator in found], "indicator_count": len(found),
                "evidence": prediction.evidence(row, risk, predicted, found, vulnerable, reach),
            })
        predictions.sort(key=lambda p: (-p["score"], p["node_id"]))
        for rank, item in enumerate(predictions, start=1):
            item["monitoring_rank"] = rank
        rows[PREDICTIONS] = predictions
        summary["predictive"] = {
            "dependencies": len(predictions), "by_level": dict(levels), "indicators": dict(sorted(types.items())),
            "indicator_total": sum(types.values()), "highest": predictions[0]["score"] if predictions else None,
            "top": [{"node_id": p["node_id"], "score": p["score"], "level": p["level"]} for p in predictions[:10]],
        }

    db[DEPENDENCY_ANALYSES].insert_one({
        "_id": analysis_id, **{k: v for k, v in scope.items() if k != "analysis_id"}, "job_id": job["_id"], "kind": kind,
        "layers": list(LAYERS[kind]), "state": "RUNNING", "commit_sha": snapshot["commit_sha"], "branch": snapshot.get("branch"),
        "model_versions": models, "model_version": models[kind], "input_digest": digest, "as_of": as_of,
        "inputs": {"vulnerability_scan_matched_at": scan.get("matched_at") if scanned else None, "reachability": reach_reference,
                   "metadata_providers": (metadata_stats or {}).get("providers", [])},
        "summary": storable(summary),
    })
    try:
        for collection, items in rows.items():
            _insert(db, collection, storable(items, 2000))
    except Exception:
        # A run that could not be stored completely leaves nothing behind. (It was never visible: reads need COMPLETE.)
        for collection in ROW_COLLECTIONS:
            db[collection].delete_many({"analysis_id": analysis_id})
        db[DEPENDENCY_ANALYSES].delete_one({"_id": analysis_id})
        raise
    db[DEPENDENCY_ANALYSES].update_one({"_id": analysis_id}, {"$set": {"state": "COMPLETE", "completed_at": _now()}})
    _prune(db, project["_id"], kind, settings.intelligence_history_limit)

    counted = {FRAGILITY: f"{len(fragility_rows)} dependencies scored for fragility",
               GRAPH_RISK: f"{(propagation or {}).get('project', {}).get('vulnerable_packages', 0)} vulnerable package(s) traced through the graph",
               PREDICTIVE: f"{len(rows[PREDICTIONS])} dependencies assessed; {len(rows[PREDICTIVE_INDICATORS])} indicator(s)"}[kind]
    return counted, {"summary": {**summary, "analysis_id": analysis_id}, "analysis_id": analysis_id, "snapshot_id": snapshot["_id"],
                     **_partial(metadata_stats)}


def _partial(stats: dict[str, Any] | None) -> dict[str, Any]:
    """The job is PARTIAL when registry metadata could not be collected, or refreshed, for some packages."""
    if not stats or not stats.get("incomplete"):
        return {}
    failed = stats["errors"] + stats["skipped_by_limit"] + stats["skipped_after_failures"]
    stale, missing = stats.get("stale_used", 0), failed - stats.get("stale_used", 0)
    parts = []
    if missing:
        parts.append(f"Release metadata could not be collected for {missing} of {stats['packages']} package(s). Their version and "
                     "release-age factors are unknown, not estimated")
    if stale:
        parts.append(f"{'For' if not missing else 'for'} {stale} {'more ' if missing else ''}package(s) the registry could not be asked again and an "
                     "earlier answer was used, marked as such")
    return {"partial": {"code": "METADATA_INCOMPLETE", "message": "; ".join(parts) + ". Everything else was analysed."}}


def _prune(db: Database, project_id: ObjectId, kind: str, keep: int) -> None:
    """Keep the most recent analyses of a kind; remove the rows of older ones."""
    old = [doc["_id"] for doc in db[DEPENDENCY_ANALYSES].find({"project_id": project_id, "kind": kind}, {"_id": 1}).sort(
        [("created_at", -1), ("_id", -1)]).skip(keep)]
    # Runs that never completed (a worker stopped mid-write) are removed too.
    cutoff = _now() - timedelta(hours=1)
    old.extend(doc["_id"] for doc in db[DEPENDENCY_ANALYSES].find(
        {"project_id": project_id, "kind": kind, "state": "RUNNING", "created_at": {"$lt": cutoff}}, {"_id": 1}))
    if old:
        for collection in ROW_COLLECTIONS:
            db[collection].delete_many({"analysis_id": {"$in": old}})
        db[DEPENDENCY_ANALYSES].delete_many({"_id": {"$in": old}})


for _job_type in KIND_OF_JOB:
    jobs.handler(_job_type)(_run)


# --- reads ------------------------------------------------------------------------------

def latest_analysis(db: Database, project: dict[str, Any], layer: str) -> dict[str, Any] | None:
    """The newest completed analysis of the project's latest snapshot that contains the given layer."""
    snapshot_id = project.get("latest_snapshot_id")
    if snapshot_id is None:
        return None
    return db[DEPENDENCY_ANALYSES].find_one(
        {"project_id": project["_id"], "snapshot_id": snapshot_id, "layers": layer, "state": "COMPLETE"},
        sort=[("created_at", -1), ("_id", -1)])


def current_inputs(db: Database, project: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    """When the snapshot's vulnerability check and reachability analysis last completed (None: never)."""
    scan = project.get("latest_vulnerability_scan") or {}
    reachability = db[REACHABILITY_ANALYSES].find_one({"project_id": project["_id"], "snapshot_id": snapshot["_id"], "state": "COMPLETE"},
                                                     {"completed_at": 1}, sort=[("completed_at", -1)])
    return {"vulnerability_scan_matched_at": scan.get("matched_at") if scan.get("snapshot_id") == snapshot["_id"] else None,
            "reachability_completed_at": (reachability or {}).get("completed_at")}


def get_analysis(db: Database, project_id: ObjectId, analysis_id: str) -> dict[str, Any] | None:
    if not ObjectId.is_valid(analysis_id):
        return None
    return db[DEPENDENCY_ANALYSES].find_one({"_id": ObjectId(analysis_id), "project_id": project_id, "state": "COMPLETE"})


def history(db: Database, project_id: ObjectId, kind: str | None, limit: int) -> list[dict[str, Any]]:
    query: dict[str, Any] = {"project_id": project_id, "state": "COMPLETE"}
    if kind:
        query["kind"] = kind
    return list(db[DEPENDENCY_ANALYSES].find(query, {"summary.graph_risk.paths": 0}).sort([("created_at", -1), ("_id", -1)]).limit(limit))


def compare(db: Database, base: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    """What changed between two analyses of a project.

    A package present once in each analysis is matched by ecosystem and name,
    so a version change shows as one changed entry. A package present in
    several versions is matched version by version.
    """
    def load(analysis: dict[str, Any]) -> dict[str, dict[str, Any]]:
        merged: dict[str, dict[str, Any]] = {}
        sources = ((DEPENDENCY_FRAGILITY, {"fragility_score": "fragility_score"}),
                   (PREDICTIONS, {"score": "predictive_risk", "indicator_types": "indicators"}),
                   (GRAPH_RISK_ANALYSIS, {"graph_risk": "graph_risk", "classification": "classification"}))
        for collection, fields in sources:
            projection = {"ecosystem": 1, "normalized_name": 1, "version": 1, "node_id": 1, **{name: 1 for name in fields}}
            for row in db[collection].find({"analysis_id": analysis["_id"]}, projection):
                if not row.get("ecosystem") or not row.get("normalized_name"):
                    continue
                entry = merged.setdefault(row["node_id"], {"node_id": row["node_id"], "ecosystem": row["ecosystem"],
                                                           "normalized_name": row["normalized_name"], "version": row.get("version")})
                for source, name in fields.items():
                    if source in row:
                        entry[name] = row[source]
        return merged

    def by_package(nodes: dict[str, dict[str, Any]]) -> dict[tuple[str, str], list[dict[str, Any]]]:
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for entry in nodes.values():
            grouped.setdefault((entry["ecosystem"], entry["normalized_name"]), []).append(entry)
        return grouped

    before_nodes, after_nodes = load(base), load(target)
    before, after = by_package(before_nodes), by_package(after_nodes)
    pairs: list[tuple[dict[str, Any] | None, dict[str, Any] | None]] = []
    for key in sorted(set(before) | set(after)):
        old_versions, new_versions = before.get(key, []), after.get(key, [])
        if len(old_versions) <= 1 and len(new_versions) <= 1:
            pairs.append((old_versions[0] if old_versions else None, new_versions[0] if new_versions else None))
            continue
        old_by_node = {entry["node_id"]: entry for entry in old_versions}
        new_by_node = {entry["node_id"]: entry for entry in new_versions}
        pairs.extend((old_by_node.get(node_id), new_by_node.get(node_id)) for node_id in sorted(set(old_by_node) | set(new_by_node)))

    public = lambda entry: {k: v for k, v in entry.items() if k not in ("ecosystem", "normalized_name")}  # noqa: E731
    items, unchanged = [], 0
    for old, new in pairs:
        present = new or old
        entry: dict[str, Any] = {"ecosystem": present["ecosystem"], "normalized_name": present["normalized_name"]}  # type: ignore[index]
        if old is None:
            entry.update(change="ADDED", after=public(new))  # type: ignore[arg-type]
        elif new is None:
            entry.update(change="REMOVED", before=public(old))
        else:
            deltas = {}
            for name in ("fragility_score", "predictive_risk", "graph_risk"):
                if old.get(name) is not None and new.get(name) is not None and abs(new[name] - old[name]) >= 0.05:
                    deltas[name] = round(new[name] - old[name], 1)
            added = sorted(set(new.get("indicators") or []) - set(old.get("indicators") or []))
            removed = sorted(set(old.get("indicators") or []) - set(new.get("indicators") or []))
            version_changed = old.get("version") != new.get("version")
            reclassified = old.get("classification") != new.get("classification") and old.get("classification") and new.get("classification")
            if not (deltas or added or removed or version_changed or reclassified):
                unchanged += 1
                continue
            entry.update(change="CHANGED", before=public(old), after=public(new), deltas=deltas, indicators_added=added,
                         indicators_removed=removed, version_changed=version_changed)
        items.append(entry)
    counts = Counter(item["change"] for item in items)
    return {
        "base": {"analysis_id": base["_id"], "kind": base["kind"], "created_at": base["created_at"], "snapshot_id": base["snapshot_id"],
                 "commit_sha": base.get("commit_sha")},
        "target": {"analysis_id": target["_id"], "kind": target["kind"], "created_at": target["created_at"], "snapshot_id": target["snapshot_id"],
                   "commit_sha": target.get("commit_sha")},
        "comparable": bool(set(base.get("layers") or []) & set(target.get("layers") or [])),
        "summary": {"added": counts.get("ADDED", 0), "removed": counts.get("REMOVED", 0), "changed": counts.get("CHANGED", 0),
                    "unchanged": unchanged},
        "items": items[:2000], "items_truncated": len(items) > 2000,
    }


def delete_project_data(db: Database, project_id: ObjectId) -> None:
    for collection in (*ROW_COLLECTIONS, DEPENDENCY_ANALYSES):
        db[collection].delete_many({"project_id": project_id})


__all__ = ["FRAGILITY", "GRAPH_RISK", "PREDICTIVE", "Structure", "collect_metadata", "compare", "current_inputs", "delete_project_data", "get_analysis",
           "history", "latest_analysis"]
