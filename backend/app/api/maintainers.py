"""Maintainer behaviour endpoints. Every route is scoped to the project's owner.

Responses describe patterns in public repository metadata. They never
classify a person: there is no "malicious", "suspicious" or "trusted" label
anywhere in this API.
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.analyzers.maintainers import INDICATOR_TYPES, anomaly
from app.api.common import HIDDEN, AnalyzeRequest, Limit, Search, Skip, owned_project, start_job
from app.auth.dependencies import CurrentUser, DbDep
from app.models.collections import MAINTAINER_PROFILES, MAINTAINERS
from app.security.rate_limit import job_rate_limit
from app.services import analysis, jobs, maintainers, runs

router = APIRouter(prefix="/api/projects/{project_id}/maintainers", tags=["maintainers"])
MAINTAINER_ID = re.compile(r"^[0-9a-f]{24}$")


@router.post("/analyze", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(job_rate_limit)])
def analyze(project_id: str, request: Request, db: DbDep, user: CurrentUser, body: AnalyzeRequest | None = None) -> dict[str, Any]:
    """Queue a maintainer behaviour analysis of the project's repository."""
    return start_job(request, db, user, owned_project(db, user, project_id), jobs.MAINTAINER_ANALYSIS, needs_snapshot=False)


@router.get("")
def list_maintainers(project_id: str, db: DbDep, user: CurrentUser, skip: Skip = 0, limit: Limit = 100, q: Search = None) -> dict[str, Any]:
    """The repository's behaviour profile with its indicators, and the contributors observed, most commits first."""
    project = owned_project(db, user, project_id)
    run = maintainers.latest(db, project)
    body: dict[str, Any] = {
        "job": analysis.public_job(jobs.latest_job(db, project["_id"], jobs.MAINTAINER_ANALYSIS)), "analysis": runs.public(run),
        "profile": None, "indicator_types": list(INDICATOR_TYPES), "meaning": anomaly.MEANING, "total": 0, "skip": skip, "limit": limit,
        "items": [],
    }
    if run is None:
        return body
    body["profile"] = analysis.public(db[MAINTAINER_PROFILES].find_one({"analysis_id": run["_id"]}, HIDDEN))
    query: dict[str, Any] = {"analysis_id": run["_id"]}
    if q:
        query["display_name"] = {"$regex": re.escape(q.strip()), "$options": "i"}
    body["total"] = db[MAINTAINERS].count_documents(query)
    cursor = db[MAINTAINERS].find(query, {**HIDDEN, "sample_commits": 0}).sort([("commits", -1), ("maintainer_id", 1)]).skip(skip).limit(limit)
    body["items"] = [analysis.public(row) for row in cursor]
    return body


@router.get("/history")
def history(project_id: str, db: DbDep, user: CurrentUser, limit: Annotated[int, Query(ge=1, le=100)] = 20) -> dict[str, Any]:
    """Earlier maintainer analyses, newest first: how the indicators changed over time."""
    project = owned_project(db, user, project_id)
    return {"items": [runs.public(run) for run in runs.history(db, project["_id"], maintainers.KIND, limit)]}


@router.get("/{maintainer_id}")
def get_maintainer(project_id: str, maintainer_id: str, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    """One contributor's activity in this repository, with the repository indicators whose evidence names them."""
    project = owned_project(db, user, project_id)
    run = maintainers.latest(db, project)
    row = None
    if run is not None and MAINTAINER_ID.match(maintainer_id):
        row = db[MAINTAINERS].find_one({"analysis_id": run["_id"], "project_id": project["_id"], "maintainer_id": maintainer_id}, HIDDEN)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Contributor not found")
    profile = db[MAINTAINER_PROFILES].find_one({"analysis_id": run["_id"]}, {"_id": 0, "repository": 1, "data_status": 1, "confidence": 1,   # type: ignore[index]
                                                                              "contributor_count": 1, "as_of": 1})
    return analysis.public({"maintainer": row, "repository": profile, "meaning": anomaly.MEANING})
