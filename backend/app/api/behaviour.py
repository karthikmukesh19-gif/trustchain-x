"""Commit behaviour endpoints. Every route is scoped to the project's owner.

Events are things to review. Nothing here calls a commit or its author
harmful, and secret-like values found in diffs are never returned: excerpts
are masked before they are stored.
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.analyzers.behavior import INDICATOR_TYPES, anomaly
from app.analyzers.behavior.security_changes import SEVERITIES, SEVERITY_RANK
from app.api.common import HIDDEN, AnalyzeRequest, Limit, Search, Skip, owned_project, start_job
from app.auth.dependencies import CurrentUser, DbDep
from app.models.collections import BEHAVIOUR_EVENTS, COMMIT_ANALYSIS, SECURITY_EVENTS
from app.schemas.common import StrictModel
from app.security.rate_limit import job_rate_limit
from app.services import analysis, audit, behaviour, jobs, runs

router = APIRouter(prefix="/api/projects/{project_id}", tags=["commit-behaviour"])
SHA = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
LIST_HIDDEN = {**HIDDEN, "findings": 0, "files": 0, "factors": 0, "author_email_tag": 0, "author_key": 0}
DETAIL_HIDDEN = {**HIDDEN, "author_email_tag": 0, "author_key": 0}
LEVELS = ("LOW", "MEDIUM", "HIGH")


class MonitoringRequest(StrictModel):
    enabled: bool


def _event_filters(event_type: str | None, severity: str | None) -> dict[str, Any]:
    query: dict[str, Any] = {}
    if event_type:
        if event_type not in INDICATOR_TYPES:
            raise HTTPException(422, f"type must be one of: {', '.join(INDICATOR_TYPES)}")
        query["event_type"] = event_type
    if severity:
        if severity not in SEVERITIES:
            raise HTTPException(422, f"severity must be one of: {', '.join(SEVERITIES)}")
        query["severity_rank"] = {"$gte": SEVERITY_RANK[severity]}
    return query


def _events(db, collection: str, project: dict[str, Any], skip: int, limit: int, event_type: str | None, severity: str | None,
            sha: str | None) -> dict[str, Any]:
    query = {"project_id": project["_id"], **_event_filters(event_type, severity)}
    if sha:
        if not SHA.match(sha):
            raise HTTPException(422, "sha must be a full commit id")
        query["commit_sha"] = sha
    cursor = db[collection].find(query, HIDDEN).sort([("occurred_at", -1), ("severity_rank", -1), ("event_type", 1)]).skip(skip).limit(limit)
    return {"total": db[collection].count_documents(query), "skip": skip, "limit": limit, "items": [analysis.public(row) for row in cursor],
            "event_types": list(INDICATOR_TYPES), "severities": list(SEVERITIES), "meaning": anomaly.MEANING}


@router.post("/commits/analyze", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(job_rate_limit)])
def analyze(project_id: str, request: Request, db: DbDep, user: CurrentUser, body: AnalyzeRequest | None = None) -> dict[str, Any]:
    """Queue a check for new commits and an analysis of their diffs."""
    return start_job(request, db, user, owned_project(db, user, project_id), jobs.COMMIT_BEHAVIOUR_ANALYSIS, needs_snapshot=False,
                     parameters={"trigger": "manual"})


@router.post("/commits/monitoring")
def set_monitoring(project_id: str, body: MonitoringRequest, request: Request, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    """Turn periodic commit checks for this project on or off. Checks happen by polling; no webhook is registered anywhere."""
    project = owned_project(db, user, project_id)
    behaviour.set_monitoring(db, project, body.enabled)
    audit.record(db, "commits.monitoring.set", request=request, actor_id=user["_id"], resource_type="project", resource_id=project["_id"],
                 details={"enabled": body.enabled})
    return {"monitoring": behaviour.monitoring(owned_project(db, user, project_id), request.app.state.settings)}


@router.get("/commits")
def list_commits(project_id: str, request: Request, db: DbDep, user: CurrentUser, skip: Skip = 0, limit: Limit = 100, q: Search = None,
                 level: Annotated[str | None, Query(max_length=10)] = None,
                 indicator: Annotated[str | None, Query(max_length=40)] = None,
                 sort: Annotated[str, Query(pattern=r"^(time|anomaly)$")] = "time") -> dict[str, Any]:
    """Analysed commits, newest first (or highest anomaly first), with their scores and indicator types."""
    project = owned_project(db, user, project_id)
    run = behaviour.latest(db, project)
    query: dict[str, Any] = {"project_id": project["_id"]}
    if level:
        if level not in LEVELS:
            raise HTTPException(422, "level must be LOW, MEDIUM or HIGH")
        query["level"] = level
    if indicator:
        if indicator not in INDICATOR_TYPES:
            raise HTTPException(422, "Unknown indicator type")
        query["indicator_types"] = indicator
    if q:
        text = q.strip()
        pattern = {"$regex": re.escape(text), "$options": "i"}
        query["$or"] = [{"commit_sha": {"$regex": f"^{re.escape(text.lower())}"}}, {"message": pattern}, {"author_login": pattern},
                        {"author_name": pattern}]
    order = [("committed_at", -1), ("commit_sha", 1)] if sort == "time" else [("anomaly_score", -1), ("committed_at", -1), ("commit_sha", 1)]
    cursor = db[COMMIT_ANALYSIS].find(query, LIST_HIDDEN).sort(order).skip(skip).limit(limit)
    return {
        "job": analysis.public_job(jobs.latest_job(db, project["_id"], jobs.COMMIT_BEHAVIOUR_ANALYSIS)), "analysis": runs.public(run),
        "monitoring": analysis.public(behaviour.monitoring(project, request.app.state.settings)),
        "indicator_types": list(INDICATOR_TYPES), "meaning": anomaly.MEANING, "weights": anomaly.WEIGHTS,
        "total": db[COMMIT_ANALYSIS].count_documents(query), "analysed_total": db[COMMIT_ANALYSIS].count_documents({"project_id": project["_id"]}),
        "skip": skip, "limit": limit, "items": [analysis.public(row) for row in cursor],
    }


@router.get("/commits/{sha}")
def get_commit(project_id: str, sha: str, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    """One analysed commit: changed files, findings with masked excerpts, score factors and the baseline it was compared with."""
    project = owned_project(db, user, project_id)
    row = db[COMMIT_ANALYSIS].find_one({"project_id": project["_id"], "commit_sha": sha}, DETAIL_HIDDEN) if SHA.match(sha) else None
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No analysis exists for that commit")
    events = db[BEHAVIOUR_EVENTS].find({"project_id": project["_id"], "commit_sha": sha}, HIDDEN).sort([("severity_rank", -1), ("event_type", 1)])
    return analysis.public({"commit": row, "events": list(events)})


@router.get("/security-events")
def list_security_events(project_id: str, db: DbDep, user: CurrentUser, skip: Skip = 0, limit: Limit = 100,
                         event_type: Annotated[str | None, Query(alias="type", max_length=40)] = None,
                         severity: Annotated[str | None, Query(max_length=10)] = None,
                         sha: Annotated[str | None, Query(max_length=64)] = None) -> dict[str, Any]:
    """Behaviour events of severity MEDIUM or higher: the ones listed for security review. Newest first."""
    return _events(db, SECURITY_EVENTS, owned_project(db, user, project_id), skip, limit, event_type, severity, sha)


@router.get("/behaviour-events")
def list_behaviour_events(project_id: str, db: DbDep, user: CurrentUser, skip: Skip = 0, limit: Limit = 100,
                          event_type: Annotated[str | None, Query(alias="type", max_length=40)] = None,
                          severity: Annotated[str | None, Query(max_length=10)] = None,
                          sha: Annotated[str | None, Query(max_length=64)] = None) -> dict[str, Any]:
    """Every behaviour event, of any severity. Newest first."""
    return _events(db, BEHAVIOUR_EVENTS, owned_project(db, user, project_id), skip, limit, event_type, severity, sha)
