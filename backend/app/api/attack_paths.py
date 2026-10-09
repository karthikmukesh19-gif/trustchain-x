"""Attack-path endpoints. Every route is scoped to the project's owner.

A path is a static reading of stored evidence. Responses never state that an
exploit exists or was confirmed: `exploit_confirmed` is always false because
the platform does not test exploitability.
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.analyzers.attack_paths import risk
from app.analyzers.attack_paths.graph import combine
from app.analyzers.attack_paths.simulation import choke_points, without
from app.api.common import HIDDEN, AnalyzeRequest, Limit, Search, Skip, owned_project, snapshot_reference, start_job
from app.auth.dependencies import CurrentUser, DbDep
from app.models.collections import ATTACK_PATHS
from app.security.rate_limit import job_rate_limit
from app.services import analysis, attack_paths, intelligence, jobs, runs

router = APIRouter(prefix="/api/projects/{project_id}/attack-paths", tags=["attack-paths"])

PATH_ID = re.compile(r"^[0-9a-f]{24}$")
LIST_FIELDS = {**HIDDEN, "nodes": 0, "edges": 0, "evidence": 0, "explanation": 0, "break_points": 0, "components.confidence_lowered_by": 0}
MEANING = ("Attack paths are built from stored static evidence: dependency declarations, graph edges, advisory matches and reachability "
           "findings. No path was exercised. A score orders paths for review; it is not a probability and does not show exploitability.")


def _envelope(db, project: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    run = attack_paths.latest(db, project)
    snapshot = analysis.latest_snapshot(db, project)
    scan = project.get("latest_vulnerability_scan") or {}
    body = {
        "job": analysis.public_job(jobs.latest_job(db, project["_id"], jobs.ATTACK_PATH_ANALYSIS)),
        "snapshot": snapshot_reference(db, project),
        "has_vulnerability_scan": snapshot is not None and scan.get("snapshot_id") == snapshot["_id"],
        "current_inputs": None if snapshot is None else intelligence.current_inputs(db, project, snapshot),
        "analysis": runs.public(run), "statuses": list(risk.STATUSES), "status_meaning": risk.STATUS_MEANING, "meaning": MEANING,
    }
    return body, run


@router.post("/analyze", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(job_rate_limit)])
def analyze(project_id: str, request: Request, db: DbDep, user: CurrentUser, body: AnalyzeRequest | None = None) -> dict[str, Any]:
    """Queue an attack-path simulation of the latest snapshot."""
    return start_job(request, db, user, owned_project(db, user, project_id), jobs.ATTACK_PATH_ANALYSIS, needs_scan=True)


@router.get("")
def list_paths(project_id: str, db: DbDep, user: CurrentUser, skip: Skip = 0, limit: Limit = 100, q: Search = None,
               path_status: Annotated[str | None, Query(alias="status", max_length=30)] = None,
               level: Annotated[str | None, Query(max_length=10)] = None,
               severity: Annotated[str | None, Query(max_length=10)] = None) -> dict[str, Any]:
    """Attack paths of the latest snapshot, highest score first."""
    project = owned_project(db, user, project_id)
    body, run = _envelope(db, project)
    body.update(skip=skip, limit=limit, total=0, items=[])
    if run is None:
        return body
    query: dict[str, Any] = {"analysis_id": run["_id"]}
    if path_status:
        if path_status not in risk.STATUSES:
            raise HTTPException(422, f"status must be one of: {', '.join(risk.STATUSES)}")
        query["status"] = path_status
    if level:
        if level not in risk.LEVELS:
            raise HTTPException(422, "level must be LOW, MEDIUM or HIGH")
        query["level"] = level
    if severity:
        if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
            raise HTTPException(422, "severity must be CRITICAL, HIGH, MEDIUM, LOW or UNKNOWN")
        query["advisory.severity"] = severity
    if q:
        pattern = {"$regex": re.escape(q.strip()), "$options": "i"}
        query["$or"] = [{"target.normalized_name": pattern}, {"advisory.source_id": pattern}, {"advisory.aliases": pattern}]
    body["total"] = db[ATTACK_PATHS].count_documents(query)
    cursor = db[ATTACK_PATHS].find(query, LIST_FIELDS).sort([("score", -1), ("status_rank", -1), ("attack_path_id", 1)]).skip(skip).limit(limit)
    body["items"] = [analysis.public(row) for row in cursor]
    return body


@router.get("/graph")
def graph(project_id: str, request: Request, db: DbDep, user: CurrentUser,
          without_node: Annotated[str | None, Query(alias="without", max_length=400)] = None) -> dict[str, Any]:
    """All paths merged into one graph for display, the packages most paths pass through, and an optional what-if.

    `without=<node id>` reports which stored paths would no longer exist if
    that package were fixed or removed. It is computed from the stored paths.
    """
    project = owned_project(db, user, project_id)
    run = attack_paths.latest(db, project)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No attack-path analysis exists for the latest snapshot")
    fields = {"_id": 0, "attack_path_id": 1, "score": 1, "status": 1, "nodes": 1, "edges": 1, "route": 1, "alternative_routes": 1,
              "routes_truncated": 1, "target.node_id": 1}
    paths = list(db[ATTACK_PATHS].find({"analysis_id": run["_id"]}, fields))
    merged = combine(paths, request.app.state.settings.attack_path_graph_max_nodes)
    body = {"analysis": {"id": str(run["_id"]), "created_at": run["created_at"], "model_version": run["model_version"]},
            **analysis.public(merged), "choke_points": choke_points(paths)[:20], "meaning": MEANING, "what_if": None}
    if without_node:
        body["what_if"] = without(paths, without_node)
    return body


@router.get("/history")
def history(project_id: str, db: DbDep, user: CurrentUser, limit: Annotated[int, Query(ge=1, le=100)] = 20) -> dict[str, Any]:
    """Earlier attack-path analyses of the project, newest first."""
    project = owned_project(db, user, project_id)
    return {"items": [runs.public(run) for run in runs.history(db, project["_id"], attack_paths.KIND, limit)]}


@router.get("/{path_id}")
def get_path(project_id: str, path_id: str, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    """One path with its nodes, edges, evidence, score components and explanation."""
    project = owned_project(db, user, project_id)
    run = attack_paths.latest(db, project)
    row = None
    if run is not None and PATH_ID.match(path_id):
        row = db[ATTACK_PATHS].find_one({"analysis_id": run["_id"], "project_id": project["_id"], "attack_path_id": path_id}, HIDDEN)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Attack path not found")
    return analysis.public(row)
