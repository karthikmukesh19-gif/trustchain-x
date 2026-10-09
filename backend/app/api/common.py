"""Helpers shared by the project-scoped analysis endpoints."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import HTTPException, Query, Request, status

from app.schemas.common import StrictModel
from app.services import analysis, audit, jobs
from app.services import projects as project_service

HIDDEN = {"_id": 0, "project_id": 0, "repository_id": 0}
Skip = Annotated[int, Query(ge=0, le=1_000_000)]
Limit = Annotated[int, Query(ge=1, le=500)]
Search = Annotated[str | None, Query(max_length=100)]


class AnalyzeRequest(StrictModel):
    """Analysis requests take no parameters; unknown fields are rejected."""


def owned_project(db, user, project_id: str) -> dict[str, Any]:
    """The caller's project, or 404. Another user's project is indistinguishable from one that does not exist."""
    project = project_service.get_project(db, user["_id"], project_id)
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")
    return project


def snapshot_reference(db, project: dict[str, Any]) -> dict[str, Any] | None:
    snapshot = analysis.latest_snapshot(db, project)
    return None if snapshot is None else {"id": str(snapshot["_id"]), "commit_sha": snapshot["commit_sha"], "branch": snapshot.get("branch")}


def start_job(request: Request, db, user, project: dict[str, Any], job_type: str, *, needs_snapshot: bool = True,
              needs_scan: bool = False, parameters: dict[str, Any] | None = None) -> dict[str, Any]:
    """Queue a job for the project after checking what it needs exists. The caller has already been authorised."""
    if needs_snapshot and analysis.latest_snapshot(db, project) is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Run a dependency analysis first: there is no snapshot to analyse")
    scan = project.get("latest_vulnerability_scan") or {}
    if needs_scan and scan.get("snapshot_id") != project.get("latest_snapshot_id"):
        raise HTTPException(status.HTTP_409_CONFLICT, "Run a vulnerability check for this snapshot first")
    try:
        job = jobs.request_job(db, request.app.state.redis, project, job_type, parameters)
    except analysis.AnalysisAlreadyRunning:
        raise HTTPException(status.HTTP_409_CONFLICT, "Another job is already queued or running for this project") from None
    audit.record(db, f"job.{job_type}.request", request=request, actor_id=user["_id"], resource_type="project",
                 resource_id=project["_id"], details={"job_id": str(job["_id"])})
    return {"job": analysis.public_job(job)}
