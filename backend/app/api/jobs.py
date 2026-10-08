"""Job status for a project (all job types)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, status

from app.auth.dependencies import CurrentUser, DbDep
from app.models.collections import ANALYSIS_JOBS
from app.services import analysis, jobs
from app.services import projects as project_service

router = APIRouter(prefix="/api/projects/{project_id}/jobs", tags=["jobs"])

KNOWN_TYPES = (analysis.JOB_TYPE, *jobs.JOB_TYPES)


@router.get("")
def list_jobs(
    project_id: str, db: DbDep, user: CurrentUser,
    type: Annotated[str | None, Query(max_length=200, description="Comma-separated job types")] = None,
    limit: Annotated[int, Query(ge=1, le=50)] = 10,
) -> dict[str, Any]:
    """Recent jobs, newest first, and the job that is queued or running now (if any)."""
    project = project_service.get_project(db, user["_id"], project_id)
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")
    query: dict[str, Any] = {"project_id": project["_id"]}
    if type:
        wanted = [t.strip() for t in type.split(",") if t.strip()]
        if any(t not in KNOWN_TYPES for t in wanted):
            raise HTTPException(422, f"type must be one of: {', '.join(KNOWN_TYPES)}")
        query["type"] = {"$in": wanted}
    recent = list(db[ANALYSIS_JOBS].find(query).sort([("created_at", -1), ("_id", -1)]).limit(limit))
    return {"active": analysis.public_job(jobs.active_job(db, project["_id"])),
            "items": [analysis.public_job(job) for job in recent]}
