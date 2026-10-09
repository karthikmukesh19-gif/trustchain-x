"""Dataset trust endpoints. Every route is scoped to the project's owner.

A validation status describes the checks that were run. No response states
that a dataset is free of manipulation.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.analyzers.dataset import STATUSES
from app.analyzers.dataset.validation import LIMITATION, WEIGHTS
from app.api.common import HIDDEN, AnalyzeRequest, Limit, Skip, owned_project, snapshot_reference, start_job
from app.auth.dependencies import CurrentUser, DbDep
from app.models.collections import DATASET_QUALITY, DATASET_RECORDS, DATASETS
from app.security.rate_limit import job_rate_limit
from app.services import analysis, datasets, jobs

router = APIRouter(prefix="/api/projects/{project_id}/datasets", tags=["datasets"])
DATASET_HIDDEN = {"project_id": 0, "repository_id": 0, "owner_id": 0}


def _dataset(db, project: dict[str, Any], dataset_id: str) -> dict[str, Any]:
    dataset = datasets.get(db, project["_id"], dataset_id)
    if dataset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Dataset not found")
    return dataset


def _public(dataset: dict[str, Any]) -> dict[str, Any]:
    return analysis.public({k: v for k, v in dataset.items() if k not in ("project_id", "repository_id", "owner_id")})


@router.post("/validate", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(job_rate_limit)])
def validate_dataset(project_id: str, request: Request, db: DbDep, user: CurrentUser, body: AnalyzeRequest | None = None) -> dict[str, Any]:
    """Queue a build of the dataset from the latest snapshot's stored results, followed by its validation."""
    return start_job(request, db, user, owned_project(db, user, project_id), jobs.DATASET_VALIDATION)


@router.get("")
def list_datasets(project_id: str, db: DbDep, user: CurrentUser, skip: Skip = 0, limit: Limit = 50) -> dict[str, Any]:
    """Dataset versions of the project, newest first, each with its latest validation result."""
    project = owned_project(db, user, project_id)
    query = {"project_id": project["_id"]}
    cursor = db[DATASETS].find(query, {**DATASET_HIDDEN, "sources": 0}).sort("version", -1).skip(skip).limit(limit)
    current = datasets.latest(db, project)
    return {
        "job": analysis.public_job(jobs.latest_job(db, project["_id"], jobs.DATASET_VALIDATION)), "snapshot": snapshot_reference(db, project),
        "current": None if current is None else _public(current), "statuses": list(STATUSES), "weights": WEIGHTS, "limitation": LIMITATION,
        "chain_intact": datasets.chain_intact(db, project["_id"]),
        "total": db[DATASETS].count_documents(query), "skip": skip, "limit": limit, "items": [analysis.public(row) for row in cursor],
    }


@router.get("/{dataset_id}")
def get_dataset(project_id: str, dataset_id: str, db: DbDep, user: CurrentUser, skip: Skip = 0, limit: Limit = 100,
                suspicious: Annotated[bool, Query()] = False,
                vulnerable: Annotated[bool | None, Query()] = None) -> dict[str, Any]:
    """One dataset version with a page of its records. `suspicious=true` lists only the records the last validation flagged."""
    project = owned_project(db, user, project_id)
    dataset = _dataset(db, project, dataset_id)
    query: dict[str, Any] = {"dataset_id": dataset["_id"]}
    if suspicious:
        quality = db[DATASET_QUALITY].find_one({"dataset_id": dataset["_id"]}, {"suspicious_records.record_id": 1}, sort=[("created_at", -1)])
        query["record_id"] = {"$in": [item["record_id"] for item in (quality or {}).get("suspicious_records") or []]}
    if vulnerable is not None:
        query["labels.vulnerable"] = vulnerable
    cursor = db[DATASET_RECORDS].find(query, {"_id": 0, "dataset_id": 0, "project_id": 0}).sort("record_id", 1).skip(skip).limit(limit)
    return {"dataset": _public(dataset), "records": {"total": db[DATASET_RECORDS].count_documents(query), "skip": skip, "limit": limit,
                                                     "items": [analysis.public(row) for row in cursor]},
            "limitation": LIMITATION}


@router.get("/{dataset_id}/quality")
def get_quality(project_id: str, dataset_id: str, db: DbDep, user: CurrentUser,
                history: Annotated[int, Query(ge=1, le=100)] = 20) -> dict[str, Any]:
    """The latest validation of a dataset version with every factor, earlier validations, and an integrity check made now."""
    project = owned_project(db, user, project_id)
    dataset = _dataset(db, project, dataset_id)
    rows = list(db[DATASET_QUALITY].find({"dataset_id": dataset["_id"]}, HIDDEN).sort([("created_at", -1), ("_id", -1)]).limit(history))
    summary_fields = ("created_at", "status", "quality_score", "confidence", "records")
    return {
        "dataset": {"id": str(dataset["_id"]), "version": dataset["version"], "record_count": dataset["record_count"],
                    "dataset_hash": dataset["dataset_hash"], "chain_hash": dataset["chain_hash"], "hash_algorithm": dataset["hash_algorithm"],
                    "created_at": dataset["created_at"]},
        "quality": analysis.public(rows[0]) if rows else None,
        "history": [analysis.public({name: row.get(name) for name in summary_fields}) for row in rows],
        "integrity_now": analysis.public(datasets.verify_now(db, dataset)), "weights": WEIGHTS, "statuses": list(STATUSES), "limitation": LIMITATION,
    }
