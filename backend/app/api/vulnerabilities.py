"""Vulnerability intelligence for a project: synchronise, match and read results.

Every route resolves the project through the caller's ownership first, so a
project that belongs to someone else is indistinguishable from one that does
not exist (404). Provider endpoints are fixed by configuration; nothing in a
request can name a URL to contact.
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.auth.dependencies import CurrentUser, DbDep
from app.collectors.providers.base import SEVERITIES
from app.models.collections import VULNERABILITIES, VULNERABILITY_MATCHES, VULNERABILITY_SOURCES, VULNERABILITY_SYNCS
from app.schemas.common import StrictModel
from app.security.rate_limit import job_rate_limit
from app.services import analysis, audit, jobs, vulnerabilities
from app.services import projects as project_service

router = APIRouter(prefix="/api/projects/{project_id}/vulnerabilities", tags=["vulnerabilities"])
providers_router = APIRouter(prefix="/api/vulnerability-providers", tags=["vulnerabilities"])

VULNERABILITY_JOBS = (jobs.VULNERABILITY_SYNC, jobs.VULNERABILITY_ANALYSIS)
SYNC_FIELDS = ("id", "provider", "status", "started_at", "completed_at", "packages_queried", "packages_unsupported",
               "packages_unresolved", "provider_requests", "records_seen", "records_inserted", "records_updated",
               "records_unchanged", "records_failed", "errors", "error_summary")


class SyncRequest(StrictModel):
    provider: str | None = None


def _project(db, user, project_id: str) -> dict[str, Any]:
    project = project_service.get_project(db, user["_id"], project_id)
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")
    return project


def _require_snapshot(db, project) -> dict[str, Any]:
    snapshot = analysis.latest_snapshot(db, project)
    if snapshot is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Run a dependency analysis first: there is no dependency inventory to check")
    return snapshot


def _start(request: Request, db, user, project, job_type: str, parameters: dict[str, Any] | None = None) -> dict[str, Any]:
    try:
        job = jobs.request_job(db, request.app.state.redis, project, job_type, parameters)
    except analysis.AnalysisAlreadyRunning:
        raise HTTPException(status.HTTP_409_CONFLICT, "Another job is already queued or running for this project") from None
    audit.record(db, f"job.{job_type}.request", request=request, actor_id=user["_id"], resource_type="project",
                 resource_id=project["_id"], details={"job_id": str(job["_id"]), **(parameters or {})})
    return {"job": analysis.public_job(job)}


def _public_sync(sync: dict[str, Any] | None) -> dict[str, Any] | None:
    if sync is None:
        return None
    converted = analysis.public(sync)
    return {key: converted.get(key) for key in SYNC_FIELDS}


@router.post("/sync", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(job_rate_limit)])
def start_sync(project_id: str, request: Request, db: DbDep, user: CurrentUser, body: SyncRequest | None = None) -> dict[str, Any]:
    """Queue a job that fetches advisories for the project's resolved dependencies and then matches them."""
    project = _project(db, user, project_id)
    _require_snapshot(db, project)
    providers = request.app.state.providers
    if not providers:
        raise HTTPException(status.HTTP_409_CONFLICT, "No vulnerability provider is enabled on this installation")
    # The provider is chosen by name from the configured set; a request can never supply a URL.
    name = body.provider.lower() if body and body.provider else next(iter(providers))
    if name not in providers:
        raise HTTPException(422, "Unknown vulnerability provider")
    return _start(request, db, user, project, jobs.VULNERABILITY_SYNC, {"provider": name})


@router.post("/analyze", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(job_rate_limit)])
def start_matching(project_id: str, request: Request, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    """Queue a job that re-matches the dependency inventory against advisories already stored (no network)."""
    project = _project(db, user, project_id)
    _require_snapshot(db, project)
    return _start(request, db, user, project, jobs.VULNERABILITY_ANALYSIS)


@router.get("")
def list_matches(
    project_id: str, db: DbDep, user: CurrentUser,
    skip: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    severity: Annotated[str | None, Query(max_length=10)] = None,
    match_status: Annotated[str | None, Query(max_length=12)] = None,
    ecosystem: Annotated[str | None, Query(max_length=30, pattern=r"^[a-z0-9_-]+$")] = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
) -> dict[str, Any]:
    project = _project(db, user, project_id)
    snapshot = analysis.latest_snapshot(db, project)
    latest_job = None
    for job_type in VULNERABILITY_JOBS:
        candidate = jobs.latest_job(db, project["_id"], job_type)
        if candidate and (latest_job is None or candidate["created_at"] > latest_job["created_at"]):
            latest_job = candidate
    base = {"job": analysis.public_job(latest_job), "providers": sorted(_provider_names(db))}
    if snapshot is None:
        return {**base, "snapshot": None, "scan": None, "sync": None, "total": 0, "skip": skip, "limit": limit, "items": []}

    query: dict[str, Any] = {"project_id": project["_id"], "snapshot_id": snapshot["_id"]}
    if severity:
        if severity.upper() not in SEVERITIES:
            raise HTTPException(422, "severity must be CRITICAL, HIGH, MEDIUM, LOW or UNKNOWN")
        query["severity"] = severity.upper()
    if match_status:
        if match_status.upper() not in vulnerabilities.MATCH_STATUSES:
            raise HTTPException(422, "match_status must be AFFECTED, UNSUPPORTED or CONFLICT")
        query["match_status"] = match_status.upper()
    if ecosystem:
        query["ecosystem"] = ecosystem
    if q:
        # Escaped, so the text is matched literally and cannot act as a pattern.
        needle = {"$regex": re.escape(q.strip()), "$options": "i"}
        query["$or"] = [{"normalized_name": needle}, {"source_id": needle}, {"aliases": needle}]
    total = db[VULNERABILITY_MATCHES].count_documents(query)
    cursor = db[VULNERABILITY_MATCHES].find(query, {"evidence": 0}).sort(
        [("severity_rank", -1), ("normalized_name", 1), ("source_id", 1)]).skip(skip).limit(limit)
    sync = db[VULNERABILITY_SYNCS].find_one({"project_id": project["_id"], "snapshot_id": snapshot["_id"]},
                                            {"reported": 0}, sort=[("started_at", -1), ("_id", -1)])
    return {
        **base,
        "snapshot": {"id": str(snapshot["_id"]), "commit_sha": snapshot["commit_sha"], "branch": snapshot["branch"],
                     "collected_at": snapshot["collected_at"]},
        "scan": analysis.public(vulnerabilities.scan_for(project, snapshot)),
        "sync": _public_sync(sync),
        "total": total, "skip": skip, "limit": limit, "items": analysis.public(list(cursor)),
    }


def _provider_names(db) -> set[str]:
    return {source["name"] for source in db[VULNERABILITY_SOURCES].find({}, {"name": 1})}


@router.get("/{match_id}")
def get_match(project_id: str, match_id: str, db: DbDep, user: CurrentUser,
              include_raw: Annotated[bool, Query()] = False) -> dict[str, Any]:
    """One match with its full evidence and the normalised advisory it refers to."""
    project = _project(db, user, project_id)
    match = None
    if ObjectId.is_valid(match_id):
        match = db[VULNERABILITY_MATCHES].find_one({"_id": ObjectId(match_id), "project_id": project["_id"]})
    if match is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Vulnerability match not found")
    advisory = db[VULNERABILITIES].find_one({"_id": match["vulnerability_id"]}, None if include_raw else {"raw": 0})
    return {"match": analysis.public(match), "vulnerability": analysis.public(advisory)}


# --- providers (not project-specific) ---------------------------------------------------

@providers_router.get("")
def list_providers(request: Request, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    """Providers enabled by configuration, with the outcome of their most recent synchronisation."""
    stored = {s["name"]: s for s in db[VULNERABILITY_SOURCES].find({})}
    items = []
    for name, provider in request.app.state.providers.items():
        record = stored.get(name, {})
        items.append({**provider.describe(), "enabled": True,
                      "last_sync_at": record.get("last_sync_at"), "last_sync_status": record.get("last_sync_status"),
                      "last_health": record.get("last_health")})
    return {"items": items}


@providers_router.post("/{name}/health-check", dependencies=[Depends(job_rate_limit)])
def check_provider(name: str, request: Request, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    """Contact a configured provider and report whether it answers. This makes one outbound request."""
    provider = request.app.state.providers.get(name.lower())
    if provider is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown vulnerability provider")
    health = provider.health_check()
    db[VULNERABILITY_SOURCES].update_one({"name": provider.name}, {
        "$set": {**provider.describe(), "last_health": health, "updated_at": health["checked_at"]},
        "$setOnInsert": {"created_at": health["checked_at"]}}, upsert=True)
    audit.record(db, "vulnerability_provider.health_check", request=request, actor_id=user["_id"],
                 outcome="success" if health["ok"] else "failure", details={"provider": provider.name})
    return {"provider": provider.name, **health}
