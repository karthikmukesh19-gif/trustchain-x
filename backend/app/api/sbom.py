"""SBOMs for a project: generate, list, download, verify and compare. Owner-only."""

from __future__ import annotations

import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status

from app.auth.dependencies import CurrentUser, DbDep
from app.models.collections import SBOM_COMPONENTS
from app.security.rate_limit import job_rate_limit
from app.services import analysis, audit, jobs, sbom
from app.services import projects as project_service
from app.services.jobs import JobError

router = APIRouter(prefix="/api/projects/{project_id}/sbom", tags=["sbom"])


def _project(db, user, project_id: str) -> dict[str, Any]:
    project = project_service.get_project(db, user["_id"], project_id)
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")
    return project


def _sbom(db, project, sbom_id: str, with_document: bool = False) -> dict[str, Any]:
    record = sbom.get(db, project["_id"], sbom_id, with_document)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SBOM not found")
    return record


def _public(db, record: dict[str, Any], linkage: bool = True) -> dict[str, Any]:
    body = analysis.public({k: v for k, v in record.items() if k != "document_zlib"})
    if linkage:
        links = sbom.vulnerability_linkage(db, record)
        body["vulnerability_linkage"] = {
            "components_with_matches": links["components_with_matches"], "affected_matches": links["affected_matches"],
            "latest_match_at": links["latest_match_at"]}
    return body


@router.get("")
def list_sboms(project_id: str, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    """SBOM history for the project, newest first."""
    project = _project(db, user, project_id)
    records = sbom.history(db, project["_id"])
    return {
        "job": analysis.public_job(jobs.latest_job(db, project["_id"], jobs.SBOM_GENERATION)),
        "latest": _public(db, records[0]) if records else None,
        "history": [_public(db, record, linkage=False) for record in records],
        "has_inventory": project.get("latest_snapshot_id") is not None,
        "latest_snapshot_id": str(project["latest_snapshot_id"]) if project.get("latest_snapshot_id") else None,
    }


@router.post("/generate", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(job_rate_limit)])
def generate_sbom(project_id: str, request: Request, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    """Queue SBOM generation from the latest snapshot's dependency inventory."""
    project = _project(db, user, project_id)
    if analysis.latest_snapshot(db, project) is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Run a dependency analysis first: an SBOM is generated from the dependency inventory")
    try:
        job = jobs.request_job(db, request.app.state.redis, project, jobs.SBOM_GENERATION)
    except analysis.AnalysisAlreadyRunning:
        raise HTTPException(status.HTTP_409_CONFLICT, "Another job is already queued or running for this project") from None
    audit.record(db, "job.sbom_generation.request", request=request, actor_id=user["_id"], resource_type="project",
                 resource_id=project["_id"], details={"job_id": str(job["_id"])})
    return {"job": analysis.public_job(job)}


@router.get("/{sbom_id}")
def get_sbom(project_id: str, sbom_id: str, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    project = _project(db, user, project_id)
    return _public(db, _sbom(db, project, sbom_id))


@router.get("/{sbom_id}/document")
def download_sbom(project_id: str, sbom_id: str, db: DbDep, user: CurrentUser) -> Response:
    """The CycloneDX JSON document exactly as stored (canonical form)."""
    project = _project(db, user, project_id)
    record = _sbom(db, project, sbom_id, with_document=True)
    document, payload = sbom.load_document(record)
    if document is None or payload is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "The stored SBOM document cannot be read. Verify it to see what is wrong")
    filename = f"sbom-v{record['version']}-{record['commit_sha'][:10]}.cdx.json"
    return Response(content=payload, media_type=record["media_type"], headers={
        "Content-Disposition": f'attachment; filename="{filename}"', "X-Content-Digest": f"sha-256={record['document_digest']}"})


@router.get("/{sbom_id}/components")
def list_components(
    project_id: str, sbom_id: str, db: DbDep, user: CurrentUser,
    skip: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    q: Annotated[str | None, Query(max_length=100)] = None,
    only_vulnerable: Annotated[bool, Query()] = False,
) -> dict[str, Any]:
    """Components of an SBOM, each with the vulnerability matches currently stored for it."""
    project = _project(db, user, project_id)
    record = _sbom(db, project, sbom_id)
    links = sbom.vulnerability_linkage(db, record)
    query: dict[str, Any] = {"sbom_id": record["_id"]}
    if q:
        query["normalized_name"] = {"$regex": re.escape(q.strip().lower()), "$options": "i"}
    if only_vulnerable:
        query["bom_ref"] = {"$in": sorted(links["by_component"])}
    total = db[SBOM_COMPONENTS].count_documents(query)
    cursor = db[SBOM_COMPONENTS].find(query, {"_id": 0, "sbom_id": 0, "project_id": 0, "snapshot_id": 0}).sort(
        [("ecosystem", 1), ("normalized_name", 1), ("version", 1)]).skip(skip).limit(limit)
    items = []
    for row in cursor:
        row["vulnerabilities"] = links["by_component"].get(row["bom_ref"], [])
        items.append(row)
    return {"sbom_id": str(record["_id"]), "total": total, "skip": skip, "limit": limit, "items": analysis.public(items),
            "vulnerability_linkage": {"components_with_matches": links["components_with_matches"],
                                      "affected_matches": links["affected_matches"], "latest_match_at": links["latest_match_at"]}}


@router.post("/{sbom_id}/verify")
def verify_sbom(project_id: str, sbom_id: str, request: Request, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    """Check the stored SBOM against its recorded digests and against a regeneration from its snapshot."""
    project = _project(db, user, project_id)
    record = _sbom(db, project, sbom_id, with_document=True)
    result = sbom.verify(db, project, record)
    audit.record(db, "sbom.verify", request=request, actor_id=user["_id"], outcome="success" if result["valid"] else "failure",
                 resource_type="sbom", resource_id=record["_id"],
                 details={"failed_checks": [c["name"] for c in result["checks"] if not c["ok"]]})
    return {"sbom_id": str(record["_id"]), **analysis.public(result)}


@router.get("/{sbom_id}/diff/{other_id}")
def diff_sboms(project_id: str, sbom_id: str, other_id: str, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    """Changes going from SBOM `sbom_id` (base) to SBOM `other_id` (target). Both must belong to the project."""
    project = _project(db, user, project_id)
    base = _sbom(db, project, sbom_id, with_document=True)
    target = _sbom(db, project, other_id, with_document=True)
    try:
        difference = sbom.difference_between(db, project["_id"], base, target)
    except JobError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, exc.message) from None
    return analysis.public(difference)
