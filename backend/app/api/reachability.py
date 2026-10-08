"""Code reachability endpoints. Every route is scoped to the project's owner.

A finding states what the analysed source text establishes about a known
vulnerable dependency. No response contains an exploitability, risk or trust figure.
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.analyzers.reachability import engine
from app.auth.dependencies import CurrentUser, DbDep
from app.models.collections import CODE_REACHABILITY, SOURCE_FILES
from app.schemas.common import StrictModel
from app.security.rate_limit import job_rate_limit
from app.services import analysis, audit, jobs, reachability
from app.services import projects as project_service

router = APIRouter(prefix="/api/projects/{project_id}/code-reachability", tags=["code-reachability"])

LIST_FIELDS = ("id", "match_id", "advisory_source", "advisory_id", "aliases", "summary", "severity", "ecosystem", "dependency",
               "normalized_name", "resolved_version", "relationship", "status", "confidence", "reason", "symbol_mapping",
               "matched_symbol", "evidence", "usage_level", "analyzed_at", "analyzer_version")
ANALYSIS_HIDDEN = {"project_id", "repository_id"}


class AnalyzeRequest(StrictModel):
    refresh_source: bool = False


def _project(db, user, project_id: str) -> dict[str, Any]:
    project = project_service.get_project(db, user["_id"], project_id)
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")
    return project


def _public_analysis(record: dict[str, Any] | None) -> dict[str, Any] | None:
    if record is None:
        return None
    return analysis.public({k: v for k, v in record.items() if k not in ANALYSIS_HIDDEN})


def _finding(db, project, finding_id: str) -> dict[str, Any]:
    finding = reachability.get_finding(db, project["_id"], finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Reachability finding not found")
    return finding


def _public_finding(finding: dict[str, Any]) -> dict[str, Any]:
    return analysis.public({k: v for k, v in finding.items() if k not in ("project_id", "repository_id", "status_rank", "severity_rank")})


@router.post("/analyze", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(job_rate_limit)])
def analyze(project_id: str, request: Request, db: DbDep, user: CurrentUser, body: AnalyzeRequest | None = None) -> dict[str, Any]:
    """Queue a code reachability analysis of the latest snapshot's vulnerability findings."""
    project = _project(db, user, project_id)
    if analysis.latest_snapshot(db, project) is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Run a dependency analysis first: there is no repository snapshot to read")
    scan = project.get("latest_vulnerability_scan") or {}
    if scan.get("snapshot_id") != project.get("latest_snapshot_id"):
        raise HTTPException(status.HTTP_409_CONFLICT, "Run a vulnerability check for this snapshot first: there are no findings to analyse")
    parameters = {"refresh_source": True} if body is not None and body.refresh_source else {}
    try:
        job = jobs.request_job(db, request.app.state.redis, project, jobs.CODE_REACHABILITY_ANALYSIS, parameters)
    except analysis.AnalysisAlreadyRunning:
        raise HTTPException(status.HTTP_409_CONFLICT, "Another job is already queued or running for this project") from None
    audit.record(db, f"job.{jobs.CODE_REACHABILITY_ANALYSIS}.request", request=request, actor_id=user["_id"],
                 resource_type="project", resource_id=project["_id"], details={"job_id": str(job["_id"]), **parameters})
    return {"job": analysis.public_job(job)}


@router.get("")
def list_findings(
    project_id: str, db: DbDep, user: CurrentUser,
    skip: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    reachability_status: Annotated[str | None, Query(alias="status", max_length=30)] = None,
    confidence: Annotated[str | None, Query(max_length=10)] = None,
    ecosystem: Annotated[str | None, Query(max_length=30, pattern=r"^[a-z0-9_-]+$")] = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
) -> dict[str, Any]:
    """Reachability findings for the project's latest snapshot, most significant first."""
    project = _project(db, user, project_id)
    snapshot = analysis.latest_snapshot(db, project)
    record = reachability.latest_analysis(db, project) if snapshot is not None else None
    scan = project.get("latest_vulnerability_scan") or {}
    body: dict[str, Any] = {
        "job": analysis.public_job(jobs.latest_job(db, project["_id"], jobs.CODE_REACHABILITY_ANALYSIS)),
        "snapshot": None if snapshot is None else {"id": str(snapshot["_id"]), "commit_sha": snapshot["commit_sha"],
                                                   "branch": snapshot.get("branch")},
        "has_vulnerability_scan": snapshot is not None and scan.get("snapshot_id") == snapshot["_id"],
        "vulnerability_scan_matched_at": scan.get("matched_at") if snapshot is not None and scan.get("snapshot_id") == snapshot["_id"] else None,
        "analysis": _public_analysis(record), "supported_ecosystems": sorted(reachability.supported_ecosystems()),
        "statuses": list(engine.STATUSES), "total": 0, "skip": skip, "limit": limit, "items": [],
    }
    if record is None:
        return body
    query: dict[str, Any] = {"project_id": project["_id"], "snapshot_id": record["snapshot_id"], "analysis_id": record["_id"]}
    if reachability_status:
        if reachability_status not in engine.STATUSES:
            raise HTTPException(422, f"status must be one of: {', '.join(engine.STATUSES)}")
        query["status"] = reachability_status
    if confidence:
        if confidence not in ("HIGH", "MEDIUM", "LOW", "NONE"):
            raise HTTPException(422, "confidence must be HIGH, MEDIUM, LOW or NONE")
        query["confidence"] = None if confidence == "NONE" else confidence
    if ecosystem:
        query["ecosystem"] = ecosystem
    if q:
        pattern = {"$regex": re.escape(q.strip()), "$options": "i"}
        query["$or"] = [{"normalized_name": pattern}, {"advisory_id": pattern}, {"aliases": pattern}]
    body["total"] = db[CODE_REACHABILITY].count_documents(query)
    cursor = db[CODE_REACHABILITY].find(query, {"observed": 0, "inferred": 0, "affected_symbols": 0, "explanation": 0}).sort(
        [("status_rank", -1), ("severity_rank", -1), ("normalized_name", 1), ("advisory_id", 1)]).skip(skip).limit(limit)
    items = []
    for finding in cursor:
        converted = analysis.public(finding)
        items.append({key: converted.get(key) for key in LIST_FIELDS})
    body["items"] = items
    return body


@router.get("/source/{snapshot_id}")
def source_inventory(
    project_id: str, snapshot_id: str, db: DbDep, user: CurrentUser,
    skip: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    parse_status: Annotated[str | None, Query(max_length=40, pattern=r"^[A-Z_]+$")] = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
) -> dict[str, Any]:
    """The source files considered for a snapshot and how each was handled."""
    project = _project(db, user, project_id)
    record = reachability.latest_analysis(db, project, ObjectId(snapshot_id)) if ObjectId.is_valid(snapshot_id) else None
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No code reachability analysis exists for that snapshot")
    query: dict[str, Any] = {"analysis_id": record["_id"], "project_id": project["_id"]}
    if parse_status:
        query["parse_status"] = parse_status
    if q:
        query["path"] = {"$regex": re.escape(q.strip()), "$options": "i"}
    hidden = {"_id": 0, "analysis_id": 0, "project_id": 0, "repository_id": 0}
    items = [analysis.public(doc) for doc in db[SOURCE_FILES].find(query, hidden).sort("path", 1).skip(skip).limit(limit)]
    return {"analysis": _public_analysis(record), "source_available": record.get("source_state") == "COMPLETE",
            "total": db[SOURCE_FILES].count_documents(query), "skip": skip, "limit": limit, "items": items}


@router.get("/{finding_id}")
def get_finding(project_id: str, finding_id: str, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    """One finding with its full evidence."""
    project = _project(db, user, project_id)
    return _public_finding(_finding(db, project, finding_id))


@router.get("/{finding_id}/path")
def get_path(project_id: str, finding_id: str, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    """The path behind a finding: to the affected name when one was reached, otherwise to the package's use."""
    project = _project(db, user, project_id)
    finding = _finding(db, project, finding_id)
    observed = finding.get("observed") or {}
    path = observed.get("path")
    kind = "AFFECTED_SYMBOL" if path else "DEPENDENCY_USAGE" if observed.get("usage_path") else None
    return analysis.public({
        "finding_id": finding["_id"], "status": finding["status"], "confidence": finding["confidence"],
        "dependency": finding["dependency"], "resolved_version": finding["resolved_version"], "advisory_id": finding["advisory_id"],
        "path_kind": kind, "path": path or observed.get("usage_path"),
        "meaning": "A path in a conservative static graph is evidence of possible reachability, not proof of exploitability.",
    })
