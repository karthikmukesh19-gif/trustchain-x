"""Code reachability: read a snapshot's source, build the code graph, and evaluate every vulnerability match.

The job reads source files through the GitHub API by git blob id (the ids
recorded in the immutable snapshot, so the content is exactly that commit's),
parses them as data, and stores:

  reachability_analyses   one document per (project, snapshot, analyzer version)
  source_files            every candidate source file with how it was handled
  source_symbols          modules, classes, functions, methods, and the dependency names referred to
  code_edges              imports, calls, references, and unresolved uses with their reasons
  code_reachability       one finding per vulnerability match

Running it again for the same snapshot replaces these records. The parsed
source of a snapshot is reused, so a re-run after a new vulnerability check
makes no GitHub requests.

A finding says what the source text establishes. It never says a
vulnerability is exploitable, and "no path found" is never reported as safe.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from bson import ObjectId
from pymongo.database import Database

from app.analyzers.reachability import engine, symbols
from app.analyzers.reachability.callgraph import CodeGraph, build_graph
from app.analyzers.reachability.imports import DependencyIndex
from app.analyzers.source import ANALYZERS, SourceLimits, base, inventory
from app.collectors.github import GitHubUnavailable
from app.models.collections import (
    CODE_EDGES, CODE_REACHABILITY, DEPENDENCIES, PROJECTS, REACHABILITY_ANALYSES, REPOSITORIES, REPOSITORY_SNAPSHOTS,
    SOURCE_FILES, SOURCE_SYMBOLS, VULNERABILITIES, VULNERABILITY_MATCHES,
)
from app.security.url_validation import RepositoryRef
from app.services import jobs
from app.services.analysis import storable
from app.services.jobs import JobContext, JobError

logger = logging.getLogger(__name__)

ANALYZER_VERSION = "4.0.0"
# Which dependency ecosystem each analysed language can say something about.
ECOSYSTEM_LANGUAGE = {"pypi": "python"}
STATUS_RANK = {engine.REACHABLE: 4, engine.UNKNOWN: 3, engine.NOT_CONFIRMED_REACHABLE: 2, engine.UNSUPPORTED: 1}
FETCH_FAILED = "FETCH_FAILED"
DEFAULT_MAPPINGS = Path(__file__).resolve().parent.parent / "data" / "symbol_mappings.json"
_BATCH = 1000
MAX_IMPORTS_PER_FILE = 500


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _insert(db: Database, collection: str, rows: list[dict[str, Any]]) -> None:
    for start in range(0, len(rows), _BATCH):
        db[collection].insert_many(rows[start:start + _BATCH], ordered=False)


def supported_ecosystems() -> set[str]:
    return {ecosystem for ecosystem, language in ECOSYSTEM_LANGUAGE.items() if language in ANALYZERS}


# --- source ---------------------------------------------------------------------------

def _read_source(context: JobContext, job: dict[str, Any], repository: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    """Select, fetch and parse the snapshot's source files. Returns the parsed files and per-file records."""
    db, settings = context.db, context.settings
    limits = inventory.InventoryLimits(settings.reachability_max_files, settings.reachability_max_file_bytes,
                                       settings.reachability_max_total_bytes)
    selected = inventory.select(snapshot.get("files") or [], ANALYZERS, limits)
    entries = selected["entries"]
    wanted = [entry for entry in entries if entry["selection"] == inventory.SELECTED]
    jobs.progress(db, job, "SOURCE_INVENTORY", f"{len(wanted)} of {len(entries)} source file(s) selected for analysis")

    ref = RepositoryRef(host=repository["host"], owner=repository["owner"], name=repository["name"])
    source_limits = SourceLimits(max_nodes=settings.reachability_max_nodes_per_file)
    parsed: list[base.ParsedFile] = []
    requests_made = 0
    if wanted and context.github is None:
        raise JobError("INTERNAL_ERROR", "The worker has no GitHub client for reading source files.")
    try:
        if wanted:
            with context.github.session() as session:
                for position, entry in enumerate(wanted, start=1):
                    context.check_deadline(settings.reachability_timeout_seconds)
                    try:
                        content = session.blob(ref, entry["git_blob_sha"], settings.reachability_max_file_bytes)
                    except GitHubUnavailable as exc:
                        if exc.code == "RESPONSE_TOO_LARGE":
                            entry["selection"] = inventory.SKIPPED_TOO_LARGE
                            continue
                        if exc.code == "NOT_FOUND":
                            entry.update(selection=FETCH_FAILED, parse_error="The file is no longer available from GitHub.")
                            continue
                        raise
                    result = ANALYZERS[entry["language"]].parse(entry["path"], content, source_limits)
                    entry["parsed"] = result
                    parsed.append(result)
                    if position % 25 == 0:
                        jobs.progress(db, job, "SOURCE_PARSING", f"Read and parsed {position} of {len(wanted)} source file(s)")
                requests_made = session.requests_made
    except GitHubUnavailable as exc:
        raise JobError(exc.code, exc.reason, exc.retry_at) from exc
    jobs.progress(db, job, "SOURCE_PARSING", f"Parsed {len(parsed)} source file(s)")
    return {"entries": entries, "parsed": parsed, "other_languages": selected["other_languages"], "github_requests": requests_made}


def _file_rows(scope: dict[str, Any], entries: list[dict[str, Any]], graph: CodeGraph) -> list[dict[str, Any]]:
    imports_by_file: dict[str, list[dict[str, Any]]] = {}
    for record in graph.imports:
        imports_by_file.setdefault(record["source_file"], []).append(record)
    rows = []
    for entry in entries:
        result: base.ParsedFile | None = entry.get("parsed")
        analysed = result is not None
        status = result.status if result is not None else entry["selection"]
        imports = imports_by_file.get(entry["path"], [])
        rows.append({
            **scope, "path": entry["path"], "language": entry["language"], "file_size": entry["size"],
            "git_blob_sha": entry["git_blob_sha"], "is_test": entry["is_test"], "analysed": analysed,
            "parse_status": status, "parse_error": (result.error if result is not None else entry.get("parse_error")),
            "module": result.module if result is not None else None,
            "discovered_symbols_count": len(result.symbols) if result is not None else 0,
            "discovered_imports_count": len(result.imports) if result is not None else 0,
            "discovered_usages_count": len(result.usages) if result is not None else 0,
            "records_truncated": bool(result and result.truncated),
            "imports": [{k: v for k, v in record.items() if k != "source_file"} for record in imports[:MAX_IMPORTS_PER_FILE]],
        })
    return rows


def _completeness(entries: list[dict[str, Any]], graph: CodeGraph) -> tuple[bool, list[dict[str, Any]]]:
    """Whether all application source was analysed, and if not, why not."""
    counts: Counter[str] = Counter()
    for entry in entries:
        result: base.ParsedFile | None = entry.get("parsed")
        if result is not None:
            if result.status != base.PARSED:
                counts[result.status] += 1
            elif result.truncated:
                counts["RECORDS_TRUNCATED"] += 1
        elif entry["selection"] in (*inventory.INCOMPLETE_REASONS, FETCH_FAILED):
            counts[entry["selection"]] += 1
    if graph.truncated:
        counts["GRAPH_TRUNCATED"] += 1
    reasons = [{"reason": reason, "files": count} for reason, count in sorted(counts.items())]
    return not reasons, reasons


def _store_source(db: Database, scope: dict[str, Any], source: dict[str, Any], graph: CodeGraph) -> None:
    analysis_id = scope["analysis_id"]
    for collection in (SOURCE_FILES, SOURCE_SYMBOLS, CODE_EDGES):
        db[collection].delete_many({"analysis_id": analysis_id})
    _insert(db, SOURCE_FILES, storable(_file_rows(scope, source["entries"], graph)))
    _insert(db, SOURCE_SYMBOLS, storable([{**scope, "symbol_id": identity, **{k: v for k, v in node.items() if k != "id"}}
                                          for identity, node in graph.nodes.items()]))
    edges = [{**scope, **edge} for edge in graph.edges]
    edges.extend({**scope, "kind": "unresolved", "target": None, **item} for item in graph.unresolved)
    _insert(db, CODE_EDGES, storable(edges))


def _load_graph(db: Database, analysis_id: ObjectId) -> CodeGraph:
    graph = CodeGraph()
    hidden = {"_id": 0, "analysis_id": 0, "project_id": 0, "repository_id": 0, "snapshot_id": 0}
    for node in db[SOURCE_SYMBOLS].find({"analysis_id": analysis_id}, hidden):
        identity = node.pop("symbol_id")
        graph.nodes[identity] = {"id": identity, **node}
    for edge in db[CODE_EDGES].find({"analysis_id": analysis_id}, hidden):
        if edge["kind"] == "unresolved":
            edge.pop("kind"), edge.pop("target", None)
            graph.unresolved.append(edge)
        else:
            graph.edges.append(edge)
    # The same order the builder produces, so a reused graph gives the same paths as a fresh one.
    location = lambda item: ((item.get("evidence") or {}).get("line") or 0, (item.get("evidence") or {}).get("col") or 0)  # noqa: E731
    graph.edges.sort(key=lambda e: (e["source"], e["target"], e["kind"], *location(e)))
    graph.unresolved.sort(key=lambda u: (u["source"], (u.get("evidence") or {}).get("source_file") or "", *location(u)))
    return graph


# --- findings -------------------------------------------------------------------------

def _affected_symbols(db: Database, match: dict[str, Any], mappings: list[dict[str, Any]],
                      cache: dict[ObjectId, Any]) -> list[symbols.AffectedSymbol]:
    """Affected symbols for a match: what the advisory publishes, otherwise an operator mapping, otherwise none."""
    vulnerability_id = match["vulnerability_id"]
    if vulnerability_id not in cache:
        record = db[VULNERABILITIES].find_one({"_id": vulnerability_id}, {"raw": 1})
        cache[vulnerability_id] = (record or {}).get("raw")
    published = symbols.from_advisory(cache[vulnerability_id], match["ecosystem"], match["normalized_name"])
    if published:
        return published
    identifiers = [match["source_id"], *match.get("aliases", [])]
    return symbols.from_operator(mappings, identifiers, match["ecosystem"], match["normalized_name"])


def _finding(scope: dict[str, Any], job: dict[str, Any], match: dict[str, Any], outcome: dict[str, Any], now: datetime) -> dict[str, Any]:
    path = outcome.get("path")
    last = path["edges"][-1] if path and path["edges"] else None
    site = (last or {}).get("evidence") or {}
    usage = outcome.get("usage") or {}
    observed_site = site or next(iter(usage.get("use_sites") or usage.get("import_sites") or []), {})
    return {
        **scope, "job_id": job["_id"], "match_id": match["_id"], "vulnerability_id": match["vulnerability_id"],
        "dependency_id": match.get("dependency_id"), "dependency_node_id": match["dependency_node_id"],
        "advisory_source": match["source"], "advisory_id": match["source_id"], "aliases": match.get("aliases", []),
        "summary": match.get("summary"), "severity": match.get("severity"), "severity_rank": match.get("severity_rank", 0),
        "ecosystem": match["ecosystem"], "dependency": match["package_name"], "normalized_name": match["normalized_name"],
        "resolved_version": match["matched_version"], "relationship": match.get("relationship"),
        "status": outcome["status"], "status_rank": STATUS_RANK[outcome["status"]], "confidence": outcome["confidence"],
        "confidence_meaning": "How directly the source text establishes the result. It is not a likelihood of exploitation.",
        "reason": outcome["reason"], "explanation": outcome["explanation"],
        "usage_level": usage.get("level"),
        "symbol_mapping": outcome["symbol_mapping"], "affected_symbols": outcome["affected_symbols"],
        "matched_symbol": outcome["matched_symbol"],
        # The location and path that carry the conclusion, in the flat form used for listing.
        "evidence": {
            "source_file": observed_site.get("source_file"), "line": observed_site.get("line"),
            "symbol": (last or {}).get("source") or observed_site.get("symbol"),
            "text": observed_site.get("text"),
            "path": [node["label"] for node in path["nodes"]] if path else [],
        },
        "observed": {"dependency_usage": usage or None, "path": path, "usage_path": outcome.get("usage_path"),
                     "dynamic_sites": outcome.get("dynamic_sites")},
        "inferred": {
            "status": outcome["status"], "reason": outcome["reason"],
            "notes": [note for note in (
                "The import name was mapped to the dependency by name, not by reading the installed package." if usage.get("imported") else None,
                "Functions that nothing in the analysed source calls are treated as possible entry points." if path else None,
                "The affected name was matched by its trailing name; the module path differs (possibly a re-export)."
                if (outcome.get("matched_symbol") or {}).get("match") == symbols.NAME else None,
                "The affected names come from an operator-supplied mapping, not from the advisory."
                if outcome["symbol_mapping"] == symbols.OPERATOR_SUPPLIED else None,
            ) if note],
        },
        "analyzed_at": now, "analyzer_version": ANALYZER_VERSION,
    }


def evaluate_matches(db: Database, scope: dict[str, Any], job: dict[str, Any], snapshot: dict[str, Any], graph: CodeGraph,
                     complete: bool, incomplete: list[dict[str, Any]], mappings: list[dict[str, Any]],
                     check: Any = None) -> dict[str, Any]:
    """Evaluate every AFFECTED vulnerability match of the snapshot and replace the stored findings."""
    index = engine.ReachabilityIndex(graph)
    note = ", ".join(f"{item['files']} × {item['reason']}" for item in incomplete) or None
    now = _now()
    findings = []
    raw_cache: dict[ObjectId, Any] = {}
    skipped: Counter[str] = Counter()
    for match in db[VULNERABILITY_MATCHES].find({"project_id": scope["project_id"], "snapshot_id": snapshot["_id"]}).sort(
            [("severity_rank", -1), ("normalized_name", 1), ("source_id", 1)]):
        if check is not None:
            check()
        if match.get("match_status") != "AFFECTED":
            skipped[match.get("match_status") or "UNKNOWN"] += 1     # not established as affected: nothing to reach
            continue
        supported = match["ecosystem"] in supported_ecosystems()
        affected = _affected_symbols(db, match, mappings, raw_cache) if supported else []
        outcome = engine.evaluate(
            index if supported else None, ecosystem=match["ecosystem"], supported_ecosystems=supported_ecosystems(),
            dependency_node_id=match["dependency_node_id"], relationship=match.get("relationship"), affected=affected,
            source_complete=complete, incomplete_note=note)
        findings.append(_finding(scope, job, match, outcome, now))
    db[CODE_REACHABILITY].delete_many({"project_id": scope["project_id"], "snapshot_id": snapshot["_id"]})
    _insert(db, CODE_REACHABILITY, storable(findings))
    by_status = Counter(f["status"] for f in findings)
    return {
        "findings": len(findings), "by_status": {status: by_status.get(status, 0) for status in engine.STATUSES},
        "by_reason": dict(sorted(Counter(f["reason"] for f in findings).items())),
        "with_symbol_mapping": sum(1 for f in findings if f["symbol_mapping"] != symbols.SYMBOL_MAPPING_UNKNOWN),
        "dependencies_used": len({f["dependency_node_id"] for f in findings
                                  if f["usage_level"] in (engine.USAGE_CALLED, engine.USAGE_REFERENCED)}),
        "matches_not_evaluated": dict(skipped),
    }


# --- job ------------------------------------------------------------------------------

@jobs.handler(jobs.CODE_REACHABILITY_ANALYSIS)
def run_analysis(context: JobContext, job: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    db, settings = context.db, context.settings
    project = db[PROJECTS].find_one({"_id": job["project_id"]})
    repository = db[REPOSITORIES].find_one({"_id": job.get("repository_id")}) if project else None
    if project is None or repository is None:
        raise JobError("PROJECT_NOT_FOUND", "The project was deleted before the job started.")
    snapshot = db[REPOSITORY_SNAPSHOTS].find_one(
        {"_id": project.get("latest_snapshot_id"), "project_id": project["_id"], "status": "COMPLETE"}) \
        if project.get("latest_snapshot_id") else None
    if snapshot is None:
        raise JobError("NOT_ANALYSED", "Run a dependency analysis first: there is no repository snapshot to read.")
    scan = project.get("latest_vulnerability_scan") or {}
    if scan.get("snapshot_id") != snapshot["_id"]:
        raise JobError("NOT_SCANNED", "Run a vulnerability check for this snapshot first: there are no findings to analyse.")

    identity = {"project_id": project["_id"], "snapshot_id": snapshot["_id"], "analyzer_version": ANALYZER_VERSION}
    existing = db[REACHABILITY_ANALYSES].find_one(identity)
    analysis_id = existing["_id"] if existing else ObjectId()
    scope = {"analysis_id": analysis_id, "project_id": project["_id"], "repository_id": repository["_id"], "snapshot_id": snapshot["_id"]}
    started_at = _now()
    refresh = bool(job.get("parameters", {}).get("refresh_source"))
    reuse = existing is not None and existing.get("source_state") == "COMPLETE" and not refresh

    deadline = lambda: context.check_deadline(settings.reachability_timeout_seconds)  # noqa: E731
    if reuse:
        jobs.progress(db, job, "GRAPH_BUILDING", "Reusing the source analysis already stored for this snapshot")
        graph = _load_graph(db, analysis_id)
        graph.stats = existing.get("graph") or {}
        complete, incomplete = existing.get("source_complete", False), existing.get("incomplete_reasons", [])
        source_summary = existing.get("source") or {}
        github_requests = 0
    else:
        # Everything is read and built in memory first. Nothing stored is touched until the new source
        # analysis is complete, so a run that fails leaves the previous results exactly as they were.
        source = _read_source(context, job, repository, snapshot)
        deadline()
        jobs.progress(db, job, "GRAPH_BUILDING", "Mapping imports to dependencies and building the call graph")
        dependencies = list(db[DEPENDENCIES].find(
            {"snapshot_id": snapshot["_id"], "project_id": project["_id"]},
            {"ecosystem": 1, "node_id": 1, "name": 1, "normalized_name": 1, "version": 1, "relationship": 1}))
        test_paths = {entry["path"] for entry in source["entries"] if entry["is_test"]}
        graph = build_graph(source["parsed"], DependencyIndex(dependencies), test_paths, settings.reachability_max_edges, deadline)
        complete, incomplete = _completeness(source["entries"], graph)
        deadline()
        # From here the stored source is being replaced. The marker makes an interrupted replacement visible:
        # such a snapshot is rebuilt on the next run instead of being reused.
        db[REACHABILITY_ANALYSES].update_one(identity, {
            "$set": {**{k: v for k, v in scope.items() if k != "analysis_id"}, "source_state": "REBUILDING",
                     "commit_sha": snapshot["commit_sha"]},
            "$setOnInsert": {"state": "RUNNING", "started_at": started_at}}, upsert=True)
        analysis_id = db[REACHABILITY_ANALYSES].find_one(identity, {"_id": 1})["_id"]
        scope["analysis_id"] = analysis_id
        _store_source(db, scope, source, graph)
        statuses = Counter((entry["parsed"].status if entry.get("parsed") is not None else entry["selection"]) for entry in source["entries"])
        source_summary = {
            "languages": sorted(ANALYZERS), "files_found": len(source["entries"]), "files_analysed": len(source["parsed"]),
            "files_parsed": statuses.get(base.PARSED, 0), "by_status": dict(sorted(statuses.items())),
            "test_files": len(test_paths), "bytes_analysed": sum(e["size"] for e in source["entries"] if e.get("parsed") is not None),
            "other_languages": source["other_languages"],
        }
        github_requests = source["github_requests"]
        db[REACHABILITY_ANALYSES].update_one({"_id": analysis_id}, {"$set": {
            "source_state": "COMPLETE", "source_complete": complete, "incomplete_reasons": incomplete, "source": source_summary,
            "graph": graph.stats, "source_analysed_at": _now(), "github_requests": github_requests}})

    jobs.progress(db, job, "SYMBOL_MAPPING", "Looking up the functions each advisory names as affected")
    mappings, problems = symbols.load_operator_mappings(settings.reachability_symbol_mappings_file or DEFAULT_MAPPINGS)
    for problem in problems:
        logger.warning("Symbol mapping file: %s", problem)
    jobs.progress(db, job, "REACHABILITY", "Searching the code graph for paths to affected functionality")
    findings = evaluate_matches(db, scope, job, snapshot, graph, complete, incomplete, mappings, deadline)

    completed_at = _now()
    summary = {
        "analysis_id": analysis_id, "snapshot_id": snapshot["_id"], "commit_sha": snapshot["commit_sha"],
        "analyzer_version": ANALYZER_VERSION, "source_reused": reuse, "source_complete": complete, "incomplete_reasons": incomplete,
        "source": source_summary, "graph": graph.stats, **findings,
        "operator_mappings": len(mappings), "operator_mapping_problems": problems,
        "vulnerability_scan_matched_at": scan.get("matched_at"),
    }
    db[REACHABILITY_ANALYSES].update_one({"_id": analysis_id}, {"$set": {
        "state": "COMPLETE", "source_state": "COMPLETE", "job_id": job["_id"], "commit_sha": snapshot["commit_sha"],
        "branch": snapshot.get("branch"), "completed_at": completed_at, "source_complete": complete,
        "incomplete_reasons": incomplete, "source": source_summary, "graph": graph.stats, "findings": findings,
        "operator_mappings": len(mappings), "operator_mapping_problems": problems,
        "vulnerability_scan_matched_at": scan.get("matched_at"), "source_reused": reuse,
        "collection_method": "GitHub REST API (git/blobs by id); parsed with Python's ast module; no repository code executed",
    }})
    # Parsed source is kept for the project's current analysis only; findings of earlier snapshots stay.
    stale = [doc["_id"] for doc in db[REACHABILITY_ANALYSES].find({"project_id": project["_id"], "_id": {"$ne": analysis_id}}, {"_id": 1})]
    if stale:
        for collection in (SOURCE_FILES, SOURCE_SYMBOLS, CODE_EDGES):
            db[collection].delete_many({"analysis_id": {"$in": stale}})
        db[REACHABILITY_ANALYSES].update_many({"_id": {"$in": stale}}, {"$set": {"source_state": "REMOVED"}})
    db[PROJECTS].update_one({"_id": project["_id"]}, {"$set": {"latest_reachability_analysis_id": analysis_id, "updated_at": completed_at}})
    by_status = findings["by_status"]
    message = (f"{findings['findings']} finding(s) analysed: {by_status[engine.REACHABLE]} reachable, "
               f"{by_status[engine.NOT_CONFIRMED_REACHABLE]} not confirmed, {by_status[engine.UNKNOWN]} unknown, "
               f"{by_status[engine.UNSUPPORTED]} unsupported")
    return message, {"summary": summary, "analysis_id": analysis_id, "snapshot_id": snapshot["_id"]}


# --- reads ----------------------------------------------------------------------------

def latest_analysis(db: Database, project: dict[str, Any], snapshot_id: ObjectId | None = None) -> dict[str, Any] | None:
    """The completed analysis for a snapshot (the project's latest snapshot by default)."""
    snapshot_id = snapshot_id or project.get("latest_snapshot_id")
    if snapshot_id is None:
        return None
    return db[REACHABILITY_ANALYSES].find_one({"project_id": project["_id"], "snapshot_id": snapshot_id, "state": "COMPLETE"},
                                              sort=[("completed_at", -1)])


def get_finding(db: Database, project_id: ObjectId, finding_id: str) -> dict[str, Any] | None:
    if not ObjectId.is_valid(finding_id):
        return None
    return db[CODE_REACHABILITY].find_one({"_id": ObjectId(finding_id), "project_id": project_id})


def delete_project_data(db: Database, project_id: ObjectId) -> None:
    for collection in (CODE_REACHABILITY, CODE_EDGES, SOURCE_SYMBOLS, SOURCE_FILES, REACHABILITY_ANALYSES):
        db[collection].delete_many({"project_id": project_id})
