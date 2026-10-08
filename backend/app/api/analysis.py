"""Dependency analysis: start a job, follow it, and read its results.

All routes resolve the project through the caller's ownership first, so one
user's analysis is never visible to another (a foreign project is a 404).
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, status

from app.auth.dependencies import CurrentUser, DbDep
from app.graph.builder import find_paths
from app.models.collections import DEPENDENCIES, DEPENDENCY_GRAPHS, REPOSITORY_SNAPSHOTS
from app.services import analysis, audit
from app.services import projects as project_service

router = APIRouter(prefix="/api/projects/{project_id}", tags=["analysis"])

RELATIONSHIPS = {"DIRECT", "TRANSITIVE", "UNKNOWN"}
SNAPSHOT_FIELDS = (
    "id", "repository_url", "repository_full_name", "branch", "commit_sha", "tree_sha", "committed_at", "commit_message",
    "collected_at", "status", "analyzer_version", "collection_method", "file_count", "total_bytes", "rejected_paths",
    "symlinks_skipped", "submodules_skipped", "languages", "github_primary_language", "package_managers",
    "dependency_files", "notes", "summary",
)


def _project(db, user, project_id: str) -> dict[str, Any]:
    project = project_service.get_project(db, user["_id"], project_id)
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")
    return project


def _snapshot(db, project, include_files: bool = False) -> dict[str, Any]:
    snapshot = analysis.latest_snapshot(db, project, include_files)
    if snapshot is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "This project has not been analysed yet")
    return snapshot


def _snapshot_ref(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {"id": str(snapshot["_id"]), "commit_sha": snapshot["commit_sha"], "branch": snapshot["branch"],
            "collected_at": snapshot["collected_at"], "analyzer_version": snapshot["analyzer_version"]}


@router.post("/analysis/dependencies", status_code=status.HTTP_202_ACCEPTED)
def start_dependency_analysis(project_id: str, request: Request, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    """Queue a dependency analysis. The work happens in the background worker."""
    project = _project(db, user, project_id)
    try:
        job = analysis.request_analysis(db, request.app.state.redis, project)
    except analysis.AnalysisAlreadyRunning:
        raise HTTPException(status.HTTP_409_CONFLICT, "An analysis is already queued or running for this project") from None
    audit.record(db, "analysis.dependencies.request", request=request, actor_id=user["_id"], resource_type="project",
                 resource_id=project["_id"], details={"job_id": str(job["_id"])})
    return {"job": analysis.public_job(job)}


@router.get("/analysis/status")
def analysis_status(project_id: str, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    project = _project(db, user, project_id)
    return {
        "job": analysis.public_job(analysis.latest_job(db, project["_id"])),
        "has_results": project.get("latest_snapshot_id") is not None,
        "last_analysis": project.get("last_analysis"),
    }


@router.get("/snapshot")
def get_snapshot(project_id: str, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    snapshot = analysis.public(_snapshot(db, _project(db, user, project_id)))
    return {key: snapshot.get(key) for key in SNAPSHOT_FIELDS}


@router.get("/snapshot/files")
def list_snapshot_files(
    project_id: str, db: DbDep, user: CurrentUser,
    skip: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    q: Annotated[str | None, Query(max_length=200)] = None,
) -> dict[str, Any]:
    """Files discovered in the snapshot, with their git blob ids."""
    snapshot = _snapshot(db, _project(db, user, project_id), include_files=True)
    files = snapshot.get("files", [])
    if q:
        needle = q.lower()
        files = [f for f in files if needle in f["path"].lower()]
    return {"snapshot": _snapshot_ref(snapshot), "total": len(files), "skip": skip, "limit": limit,
            "items": [{"path": f["path"], "size": f["size"], "git_blob_sha": f["sha"]} for f in files[skip:skip + limit]]}


@router.get("/dependencies")
def list_dependencies(
    project_id: str, db: DbDep, user: CurrentUser,
    skip: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ecosystem: Annotated[str | None, Query(max_length=30, pattern=r"^[a-z0-9_-]+$")] = None,
    relationship: Annotated[str | None, Query(max_length=12)] = None,
    version_status: Annotated[str | None, Query(pattern=r"^(RESOLVED|UNRESOLVED)$")] = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
) -> dict[str, Any]:
    project = _project(db, user, project_id)
    snapshot = _snapshot(db, project)
    query: dict[str, Any] = {"project_id": project["_id"], "snapshot_id": snapshot["_id"]}
    if ecosystem:
        query["ecosystem"] = ecosystem
    if relationship:
        if relationship.upper() not in RELATIONSHIPS:
            raise HTTPException(422, "relationship must be DIRECT, TRANSITIVE or UNKNOWN")
        query["relationship"] = relationship.upper()
    if version_status:
        query["version_status"] = version_status
    if q:
        # The search text is escaped, so it is matched literally and cannot act as a pattern.
        query["normalized_name"] = {"$regex": re.escape(q.strip().lower()), "$options": "i"}
    total = db[DEPENDENCIES].count_documents(query)
    cursor = db[DEPENDENCIES].find(query, {"_id": 0, "project_id": 0, "snapshot_id": 0}).sort(
        [("ecosystem", 1), ("normalized_name", 1), ("version", 1)]).skip(skip).limit(limit)
    graph = db[DEPENDENCY_GRAPHS].find_one({"snapshot_id": snapshot["_id"]}, {"stats": 1}) or {}
    return {"snapshot": _snapshot_ref(snapshot), "summary": graph.get("stats", {}), "total": total, "skip": skip,
            "limit": limit, "items": analysis.public(list(cursor))}


@router.get("/dependencies/graph")
def dependency_graph(
    project_id: str, db: DbDep, user: CurrentUser,
    paths_to: Annotated[str | None, Query(max_length=400)] = None,
) -> dict[str, Any]:
    """The stored dependency graph. With `paths_to=<node id>`, also returns paths from the project to that package."""
    project = _project(db, user, project_id)
    snapshot = _snapshot(db, project)
    graph = db[DEPENDENCY_GRAPHS].find_one({"snapshot_id": snapshot["_id"], "project_id": project["_id"]})
    if graph is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No dependency graph is stored for this analysis")
    body = {"snapshot": _snapshot_ref(snapshot), "root": graph["root"], "nodes": graph["nodes"], "edges": graph["edges"],
            "stats": graph["stats"]}
    if paths_to:
        if not any(node["node_id"] == paths_to for node in graph["nodes"]):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "That package is not in this dependency graph")
        body["paths"] = find_paths(graph["edges"], paths_to)
    return analysis.public(body)


@router.get("/dependencies/paths")
def dependency_paths(project_id: str, db: DbDep, user: CurrentUser, to: Annotated[str, Query(min_length=1, max_length=400)]) -> dict[str, Any]:
    """Up to 20 paths from the project to one package, shortest first."""
    project = _project(db, user, project_id)
    snapshot = _snapshot(db, project)
    graph = db[DEPENDENCY_GRAPHS].find_one({"snapshot_id": snapshot["_id"], "project_id": project["_id"]}, {"edges": 1, "nodes.node_id": 1})
    if graph is None or not any(node["node_id"] == to for node in graph["nodes"]):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "That package is not in this dependency graph")
    return {"to": to, "paths": find_paths(graph["edges"], to)}
