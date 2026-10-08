"""Background jobs for Phase 3 (vulnerability sync, matching, SBOM generation).

These jobs share Phase 2's mechanics: a document in `analysis_jobs` is the
source of truth, Redis only wakes the worker, and a project runs one job at a
time (`projects.active_job_id`, claimed atomically). The dependency-analysis
job keeps its own module; this one adds the job types that build on its
results.

States: queued -> running -> completed | failed. A job is marked completed
only by its handler returning normally.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from bson import ObjectId
from pymongo import ReturnDocument
from pymongo.database import Database

from app.config.settings import Settings
from app.models.collections import ANALYSIS_JOBS, PROJECTS
from app.services import audit
from app.services.analysis import ACTIVE_STATES, COMPLETED, FAILED, QUEUE_KEY, QUEUED, RUNNING, AnalysisAlreadyRunning

logger = logging.getLogger(__name__)

VULNERABILITY_SYNC = "vulnerability_sync"
VULNERABILITY_ANALYSIS = "vulnerability_analysis"
SBOM_GENERATION = "sbom_generation"

STAGES: dict[str, tuple[str, ...]] = {
    VULNERABILITY_SYNC: ("QUEUED", "PROVIDER_QUERY", "RECORD_INGESTION", "MATCHING", "COMPLETED"),
    VULNERABILITY_ANALYSIS: ("QUEUED", "MATCHING", "COMPLETED"),
    SBOM_GENERATION: ("QUEUED", "SBOM_GENERATION", "SBOM_COMPARISON", "COMPLETED"),
}
JOB_TYPES = tuple(STAGES)


class JobError(Exception):
    """A structured, user-presentable job failure."""

    def __init__(self, code: str, message: str, retry_at: datetime | None = None, extra: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retry_at = retry_at
        self.extra = extra or {}


@dataclass
class JobContext:
    db: Database
    settings: Settings
    providers: dict[str, Any]
    started: float

    def check_deadline(self, limit_seconds: int) -> None:
        if time.monotonic() - self.started > limit_seconds:
            raise JobError("TIMEOUT", f"The job exceeded its time limit of {limit_seconds} seconds.")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def request_job(db: Database, redis_client: Any, project: dict[str, Any], job_type: str,
                parameters: dict[str, Any] | None = None) -> dict[str, Any]:
    """Create a queued job. Raises AnalysisAlreadyRunning if the project already has an active job."""
    if job_type not in STAGES:
        raise ValueError(f"unknown job type {job_type!r}")
    now = _now()
    job_id = ObjectId()
    claimed = db[PROJECTS].find_one_and_update(
        {"_id": project["_id"], "active_job_id": None}, {"$set": {"active_job_id": job_id, "updated_at": now}})
    if claimed is None:
        raise AnalysisAlreadyRunning(db[ANALYSIS_JOBS].find_one({"_id": project.get("active_job_id")}))
    stages = STAGES[job_type]
    job = {
        "_id": job_id, "project_id": project["_id"], "owner_id": project["owner_id"], "repository_id": project["repository_id"],
        "type": job_type, "state": QUEUED, "stage": "QUEUED", "stage_index": 0, "stage_count": len(stages) - 1,
        "stages": list(stages[1:-1]), "message": "Waiting for the background worker", "error": None,
        "snapshot_id": project.get("latest_snapshot_id"), "parameters": parameters or {}, "summary": None,
        "created_at": now, "started_at": None, "finished_at": None, "updated_at": now,
    }
    try:
        db[ANALYSIS_JOBS].insert_one(job)
    except Exception:
        # Without a job document nothing would ever release the project again.
        db[PROJECTS].update_one({"_id": project["_id"], "active_job_id": job_id}, {"$set": {"active_job_id": None}})
        raise
    try:
        redis_client.lpush(QUEUE_KEY, str(job_id))
    except Exception:  # noqa: BLE001 - the worker also polls MongoDB, so the job is not lost
        logger.warning("Could not signal the worker through Redis; job %s will be picked up by polling", job_id)
    return job


def latest_job(db: Database, project_id: ObjectId, job_type: str | None = None) -> dict[str, Any] | None:
    query: dict[str, Any] = {"project_id": project_id}
    if job_type:
        query["type"] = job_type
    return db[ANALYSIS_JOBS].find_one(query, sort=[("created_at", -1), ("_id", -1)])


def active_job(db: Database, project_id: ObjectId) -> dict[str, Any] | None:
    return db[ANALYSIS_JOBS].find_one({"project_id": project_id, "state": {"$in": list(ACTIVE_STATES)}},
                                      sort=[("created_at", -1), ("_id", -1)])


def claim_next_job(db: Database) -> dict[str, Any] | None:
    """Atomically move the oldest queued Phase 3 job to running."""
    now = _now()
    return db[ANALYSIS_JOBS].find_one_and_update(
        {"state": QUEUED, "type": {"$in": list(JOB_TYPES)}},
        {"$set": {"state": RUNNING, "started_at": now, "updated_at": now, "message": "Starting"}},
        sort=[("created_at", 1), ("_id", 1)], return_document=ReturnDocument.AFTER,
    )


def progress(db: Database, job: dict[str, Any], stage: str, message: str) -> None:
    index = STAGES[job["type"]].index(stage)
    job.update(stage=stage, stage_index=index, message=message)
    db[ANALYSIS_JOBS].update_one({"_id": job["_id"]}, {"$set": {
        "stage": stage, "stage_index": index, "message": message, "updated_at": _now()}})


def _finish(db: Database, job: dict[str, Any], state: str, message: str, *, error: dict[str, Any] | None = None,
            extra: dict[str, Any] | None = None) -> None:
    now = _now()
    update = {"state": state, "message": message, "error": error, "finished_at": now, "updated_at": now, **(extra or {})}
    if state == COMPLETED:
        update.update(stage="COMPLETED", stage_index=job["stage_count"])
    # Only a job that is still active can finish: one already failed (for example as stale) keeps that outcome.
    outcome = db[ANALYSIS_JOBS].update_one({"_id": job["_id"], "state": {"$in": list(ACTIVE_STATES)}}, {"$set": update})
    db[PROJECTS].update_one({"_id": job["project_id"], "active_job_id": job["_id"]}, {"$set": {"active_job_id": None}})
    if outcome.matched_count:
        job.update(update)
    else:
        logger.warning("Job %s had already ended; its late result (%s) was not recorded", job["_id"], state)


Handler = Callable[[JobContext, dict[str, Any]], tuple[str, dict[str, Any]]]
_HANDLERS: dict[str, Handler] = {}


def handler(job_type: str) -> Callable[[Handler], Handler]:
    """Register the function that executes one job type. It returns (message, fields to store on the job)."""
    def register(function: Handler) -> Handler:
        _HANDLERS[job_type] = function
        return function
    return register


def run_job(db: Database, settings: Settings, providers: dict[str, Any], job: dict[str, Any]) -> dict[str, Any]:
    """Execute one claimed job. Never raises: every outcome is recorded on the job."""
    # Imported here so that the service modules can register their handlers without an import cycle.
    from app.services import sbom, vulnerabilities  # noqa: F401

    context = JobContext(db=db, settings=settings, providers=providers, started=time.monotonic())
    try:
        message, fields = _HANDLERS[job["type"]](context, job)
    except JobError as exc:
        error: dict[str, Any] = {"code": exc.code, "message": exc.message}
        if exc.retry_at is not None:
            error["retry_at"] = exc.retry_at
        _finish(db, job, FAILED, exc.message, error=error, extra=exc.extra)
    except Exception:  # noqa: BLE001 - last line of defence for the worker loop
        logger.exception("Job %s (%s) crashed", job["_id"], job["type"])
        _finish(db, job, FAILED, "The job stopped because of an internal error.",
                error={"code": "INTERNAL_ERROR", "message": "The job stopped because of an internal error."})
    else:
        _finish(db, job, COMPLETED, message, extra=fields)
    audit.record(db, f"job.{job['type']}.finish", actor_id=job.get("owner_id"),
                 outcome="success" if job["state"] == COMPLETED else "failure",
                 resource_type="project", resource_id=job["project_id"],
                 details={"job_id": str(job["_id"]), "error_code": (job.get("error") or {}).get("code"),
                          "seconds": round(time.monotonic() - context.started, 2)})
    return job
