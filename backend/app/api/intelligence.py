"""Dependency intelligence endpoints: fragility, graph risk and predictive dependency risk.

Every route is scoped to the project's owner. Scores are returned with the
factors behind them. None of them is a probability, a vulnerability severity
or the platform's trust score, and nothing is returned for a snapshot that
has not been analysed.
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.analyzers.graph import prediction, risk_propagation
from app.auth.dependencies import CurrentUser, DbDep
from app.models.collections import (
    DEPENDENCY_FRAGILITY, DEPENDENCY_GRAPHS, DEPENDENCY_HEALTH, GRAPH_RISK_ANALYSIS, PREDICTIONS, PREDICTIVE_INDICATORS,
)
from app.schemas.common import StrictModel
from app.security.rate_limit import job_rate_limit
from app.services import analysis, audit, intelligence, jobs
from app.services import projects as project_service

router = APIRouter(prefix="/api/projects/{project_id}", tags=["dependency-intelligence"])

LEVELS = ("LOW", "MEDIUM", "HIGH")
HIDDEN = {"_id": 0, "project_id": 0, "repository_id": 0}
Skip = Annotated[int, Query(ge=0, le=1_000_000)]
Limit = Annotated[int, Query(ge=1, le=500)]
Search = Annotated[str | None, Query(max_length=100)]
Ecosystem = Annotated[str | None, Query(max_length=30, pattern=r"^[a-z0-9_-]+$")]
Level = Annotated[str | None, Query(max_length=10)]


class AnalyzeRequest(StrictModel):
    pass


def _project(db, user, project_id: str) -> dict[str, Any]:
    project = project_service.get_project(db, user["_id"], project_id)
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")
    return project


def _public_analysis(record: dict[str, Any] | None) -> dict[str, Any] | None:
    if record is None:
        return None
    return analysis.public({k: v for k, v in record.items() if k not in ("project_id", "repository_id", "input_digest")})


def _start(request: Request, db, user, project_id: str, job_type: str, needs_scan: bool) -> dict[str, Any]:
    project = _project(db, user, project_id)
    if analysis.latest_snapshot(db, project) is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Run a dependency analysis first: there is no dependency graph to analyse")
    scan = project.get("latest_vulnerability_scan") or {}
    if needs_scan and scan.get("snapshot_id") != project.get("latest_snapshot_id"):
        raise HTTPException(status.HTTP_409_CONFLICT, "Run a vulnerability check for this snapshot first: risk cannot be traced without it")
    try:
        job = jobs.request_job(db, request.app.state.redis, project, job_type)
    except analysis.AnalysisAlreadyRunning:
        raise HTTPException(status.HTTP_409_CONFLICT, "Another job is already queued or running for this project") from None
    audit.record(db, f"job.{job_type}.request", request=request, actor_id=user["_id"], resource_type="project",
                 resource_id=project["_id"], details={"job_id": str(job["_id"])})
    return {"job": analysis.public_job(job)}


def _context(db, project: dict[str, Any], layer: str, job_type: str) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """The response envelope shared by the list endpoints, and the analysis they read from."""
    snapshot = analysis.latest_snapshot(db, project)
    record = intelligence.latest_analysis(db, project, layer) if snapshot is not None else None
    scan = project.get("latest_vulnerability_scan") or {}
    body = {
        "job": analysis.public_job(jobs.latest_job(db, project["_id"], job_type)),
        "snapshot": None if snapshot is None else {"id": str(snapshot["_id"]), "commit_sha": snapshot["commit_sha"], "branch": snapshot.get("branch")},
        "has_vulnerability_scan": snapshot is not None and scan.get("snapshot_id") == snapshot["_id"],
        # What the inputs look like now, so a reader can tell when the analysis on screen predates a newer check.
        "current_inputs": None if snapshot is None else intelligence.current_inputs(db, project, snapshot),
        "analysis": _public_analysis(record), "total": 0, "items": [],
    }
    return body, record


def _filters(record: dict[str, Any], q: str | None, ecosystem: str | None, relationship: str | None = None) -> dict[str, Any]:
    query: dict[str, Any] = {"analysis_id": record["_id"]}
    if ecosystem:
        query["ecosystem"] = ecosystem
    if relationship:
        if relationship not in ("DIRECT", "TRANSITIVE", "UNKNOWN"):
            raise HTTPException(422, "relationship must be DIRECT, TRANSITIVE or UNKNOWN")
        query["relationship"] = relationship
    if q:
        query["normalized_name"] = {"$regex": re.escape(q.strip().lower()), "$options": "i"}
    return query


def _level(value: str | None) -> str | None:
    if value is not None and value not in LEVELS:
        raise HTTPException(422, "level must be LOW, MEDIUM or HIGH")
    return value


def _row(db, collection: str, record: dict[str, Any] | None, project: dict[str, Any], dependency_id: str) -> dict[str, Any]:
    row = None
    if record is not None and ObjectId.is_valid(dependency_id):
        row = db[collection].find_one({"analysis_id": record["_id"], "project_id": project["_id"], "dependency_id": ObjectId(dependency_id)}, HIDDEN)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No analysis result exists for that dependency")
    return row


# --- fragility --------------------------------------------------------------------------

@router.post("/fragility/analyze", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(job_rate_limit)])
def analyze_fragility(project_id: str, request: Request, db: DbDep, user: CurrentUser, body: AnalyzeRequest | None = None) -> dict[str, Any]:
    """Queue a dependency fragility analysis of the latest snapshot."""
    return _start(request, db, user, project_id, jobs.DEPENDENCY_FRAGILITY_ANALYSIS, needs_scan=False)


@router.get("/fragility")
def list_fragility(project_id: str, db: DbDep, user: CurrentUser, skip: Skip = 0, limit: Limit = 100, q: Search = None,
                   ecosystem: Ecosystem = None, level: Level = None,
                   relationship: Annotated[str | None, Query(max_length=12)] = None,
                   sort: Annotated[str, Query(pattern=r"^(fragility|confidence|name)$")] = "fragility") -> dict[str, Any]:
    """Fragility of every dependency of the latest snapshot, most fragile first."""
    project = _project(db, user, project_id)
    body, record = _context(db, project, "fragility", jobs.DEPENDENCY_FRAGILITY_ANALYSIS)
    body.update(skip=skip, limit=limit)
    if record is None:
        return body
    query = _filters(record, q, ecosystem, relationship)
    if _level(level):
        query["fragility_level"] = level
    order = {"fragility": [("fragility_score", -1), ("node_id", 1)], "confidence": [("confidence", 1), ("node_id", 1)],
             "name": [("normalized_name", 1), ("node_id", 1)]}[sort]
    body["total"] = db[DEPENDENCY_FRAGILITY].count_documents(query)
    cursor = db[DEPENDENCY_FRAGILITY].find(query, {**HIDDEN, "factors.inputs": 0}).sort(order).skip(skip).limit(limit)
    body["items"] = [analysis.public(row) for row in cursor]
    return body


@router.get("/fragility/summary")
def fragility_summary(project_id: str, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    """Project-level fragility: score distribution, graph concentration, and what metadata was available."""
    project = _project(db, user, project_id)
    body, record = _context(db, project, "fragility", jobs.DEPENDENCY_FRAGILITY_ANALYSIS)
    summary = (record or {}).get("summary") or {}
    return {"job": body["job"], "snapshot": body["snapshot"], "available": record is not None,
            "analysis": None if record is None else {"id": str(record["_id"]), "kind": record["kind"], "created_at": record["created_at"],
                                                     "model_versions": record["model_versions"], "as_of": record["as_of"]},
            "fragility": analysis.public(summary.get("fragility")), "graph": analysis.public(summary.get("graph")),
            "metadata": analysis.public(summary.get("metadata")), "graph_issues": summary.get("graph_issues") or {},
            "meaning": "Fragility describes structure and upkeep on a 0-100 scale. It is not vulnerability severity and predicts no specific event."}


@router.get("/fragility/{dependency_id}")
def get_fragility(project_id: str, dependency_id: str, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    """One dependency's fragility with every factor, and its health profile."""
    project = _project(db, user, project_id)
    record = intelligence.latest_analysis(db, project, "fragility")
    row = _row(db, DEPENDENCY_FRAGILITY, record, project, dependency_id)
    health = db[DEPENDENCY_HEALTH].find_one({"analysis_id": record["_id"], "dependency_id": ObjectId(dependency_id)}, HIDDEN)  # type: ignore[index]
    return analysis.public({"fragility": row, "health": health})


# --- graph risk -------------------------------------------------------------------------

@router.post("/graph-risk/analyze", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(job_rate_limit)])
def analyze_graph_risk(project_id: str, request: Request, db: DbDep, user: CurrentUser, body: AnalyzeRequest | None = None) -> dict[str, Any]:
    """Queue a graph risk analysis: trace known-vulnerable packages through the dependency graph."""
    return _start(request, db, user, project_id, jobs.GRAPH_RISK_ANALYSIS, needs_scan=True)


@router.get("/graph-risk")
def list_graph_risk(project_id: str, db: DbDep, user: CurrentUser, skip: Skip = 0, limit: Limit = 100, q: Search = None,
                    ecosystem: Ecosystem = None,
                    classification: Annotated[str | None, Query(max_length=30)] = None) -> dict[str, Any]:
    """Exposure classification and graph risk of every package, highest first, with the paths from the project."""
    project = _project(db, user, project_id)
    body, record = _context(db, project, "graph_risk", jobs.GRAPH_RISK_ANALYSIS)
    body.update(skip=skip, limit=limit, classifications=list(risk_propagation.CLASSIFICATIONS))
    if record is None:
        return body
    query = _filters(record, q, ecosystem)
    if classification:
        if classification not in risk_propagation.CLASSIFICATIONS:
            raise HTTPException(422, f"classification must be one of: {', '.join(risk_propagation.CLASSIFICATIONS)}")
        query["classification"] = classification
    body["total"] = db[GRAPH_RISK_ANALYSIS].count_documents(query)
    cursor = db[GRAPH_RISK_ANALYSIS].find(query, HIDDEN).sort([("graph_risk", -1), ("node_id", 1)]).skip(skip).limit(limit)
    body["items"] = [analysis.public(row) for row in cursor]
    return body


@router.get("/graph-risk/{dependency_id}")
def get_graph_risk(project_id: str, dependency_id: str, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    project = _project(db, user, project_id)
    record = intelligence.latest_analysis(db, project, "graph_risk")
    return analysis.public(_row(db, GRAPH_RISK_ANALYSIS, record, project, dependency_id))


# --- predictive dependency risk ---------------------------------------------------------

@router.post("/predictive-risk/analyze", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(job_rate_limit)])
def analyze_predictive_risk(project_id: str, request: Request, db: DbDep, user: CurrentUser, body: AnalyzeRequest | None = None) -> dict[str, Any]:
    """Queue the full analysis: fragility, graph risk, indicators and predictive dependency risk."""
    return _start(request, db, user, project_id, jobs.PREDICTIVE_DEPENDENCY_ANALYSIS, needs_scan=True)


@router.get("/predictive-risk")
def list_predictive_risk(project_id: str, db: DbDep, user: CurrentUser, skip: Skip = 0, limit: Limit = 100, q: Search = None,
                         ecosystem: Ecosystem = None, level: Level = None,
                         relationship: Annotated[str | None, Query(max_length=12)] = None,
                         indicator: Annotated[str | None, Query(max_length=40)] = None,
                         vulnerable: Annotated[bool | None, Query()] = None,
                         reachable: Annotated[bool | None, Query()] = None,
                         sort: Annotated[str, Query(pattern=r"^(risk|fragility|centrality|dependents|name)$")] = "risk") -> dict[str, Any]:
    """Predictive dependency risk of every dependency of the latest snapshot, highest first."""
    project = _project(db, user, project_id)
    body, record = _context(db, project, "predictive", jobs.PREDICTIVE_DEPENDENCY_ANALYSIS)
    body.update(skip=skip, limit=limit, indicator_types=list(prediction.INDICATOR_TYPES))
    if record is None:
        return body
    query = _filters(record, q, ecosystem, relationship)
    if _level(level):
        query["level"] = level
    if indicator:
        if indicator not in prediction.INDICATOR_TYPES:
            raise HTTPException(422, "Unknown indicator type")
        query["indicator_types"] = indicator
    if vulnerable is not None:
        query["vulnerability_count"] = {"$gt": 0} if vulnerable else 0
    if reachable is not None:
        # false means "established as none reachable". A count that is unknown (not analysed, undecided) matches neither value.
        query["reachable_vulnerability_count"] = {"$gt": 0} if reachable else 0
    order = {"risk": [("score", -1), ("node_id", 1)], "fragility": [("fragility_score", -1), ("node_id", 1)],
             "centrality": [("relative_centrality", -1), ("node_id", 1)], "dependents": [("dependents", -1), ("node_id", 1)],
             "name": [("normalized_name", 1), ("node_id", 1)]}[sort]
    body["total"] = db[PREDICTIONS].count_documents(query)
    cursor = db[PREDICTIONS].find(query, {**HIDDEN, "evidence": 0, "factors": 0}).sort(order).skip(skip).limit(limit)
    body["items"] = [analysis.public(row) for row in cursor]
    return body


@router.get("/predictive-risk/history")
def predictive_history(project_id: str, db: DbDep, user: CurrentUser,
                       kind: Annotated[str | None, Query(pattern=r"^(fragility|graph_risk|predictive)$")] = None,
                       limit: Annotated[int, Query(ge=1, le=100)] = 20) -> dict[str, Any]:
    """Earlier analyses of the project, newest first. Analyses are kept, not overwritten."""
    project = _project(db, user, project_id)
    return {"items": [_public_analysis(record) for record in intelligence.history(db, project["_id"], kind, limit)]}


@router.get("/predictive-risk/compare")
def compare_analyses(project_id: str, db: DbDep, user: CurrentUser,
                     base: Annotated[str, Query(max_length=24)], target: Annotated[str, Query(max_length=24)]) -> dict[str, Any]:
    """What changed between two analyses of this project, package by package."""
    project = _project(db, user, project_id)
    first, second = intelligence.get_analysis(db, project["_id"], base), intelligence.get_analysis(db, project["_id"], target)
    if first is None or second is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis not found")
    return analysis.public(intelligence.compare(db, first, second))


@router.get("/predictive-risk/graph")
def predictive_graph(project_id: str, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    """The dependency graph with each package's scores, for visualisation. Only packages and edges that were observed."""
    project = _project(db, user, project_id)
    record = intelligence.latest_analysis(db, project, "predictive")
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No predictive analysis exists for the latest snapshot")
    graph = db[DEPENDENCY_GRAPHS].find_one({"snapshot_id": record["snapshot_id"], "project_id": project["_id"]}, {"edges": 1, "root": 1}) or {}
    fields = {"_id": 0, "node_id": 1, "dependency_id": 1, "package_name": 1, "normalized_name": 1, "ecosystem": 1, "version": 1,
              "relationship": 1, "depth": 1, "score": 1, "level": 1, "confidence": 1, "fragility_score": 1, "graph_risk": 1,
              "exposure_classification": 1, "vulnerability_count": 1, "reachable_vulnerability_count": 1, "relative_centrality": 1,
              "betweenness_centrality": 1, "degree_centrality": 1, "dependents": 1, "indicator_types": 1}
    nodes = [analysis.public(row) for row in db[PREDICTIONS].find({"analysis_id": record["_id"]}, fields).sort("node_id", 1)]
    known = {node["node_id"] for node in nodes} | {"root"}
    edges = sorted({(e.get("source"), e.get("target")) for e in graph.get("edges") or []
                    if e.get("source") in known and e.get("target") in known and e.get("source") != e.get("target")})
    return {"analysis": {"id": str(record["_id"]), "created_at": record["created_at"], "model_versions": record["model_versions"]},
            "root": graph.get("root") or {"id": "root"}, "nodes": nodes,
            "edges": [{"source": source, "target": target} for source, target in edges]}


@router.get("/predictive-risk/{dependency_id}")
def get_predictive_risk(project_id: str, dependency_id: str, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    """Everything about one dependency: predictive risk and its factors, indicators, evidence, fragility, health and graph risk."""
    project = _project(db, user, project_id)
    record = intelligence.latest_analysis(db, project, "predictive")
    row = _row(db, PREDICTIONS, record, project, dependency_id)
    key = {"analysis_id": record["_id"], "dependency_id": ObjectId(dependency_id)}  # type: ignore[index]
    return analysis.public({
        "prediction": row,
        "indicators": list(db[PREDICTIVE_INDICATORS].find(key, {**HIDDEN, "analysis_id": 0, "snapshot_id": 0}).sort("type", 1)),
        "fragility": db[DEPENDENCY_FRAGILITY].find_one(key, HIDDEN),
        "health": db[DEPENDENCY_HEALTH].find_one(key, HIDDEN),
        "graph_risk": db[GRAPH_RISK_ANALYSIS].find_one(key, HIDDEN),
    })
