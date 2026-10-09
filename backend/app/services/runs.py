"""Analysis run records shared by the layers added after dependency intelligence.

One document in `analysis_runs` describes one execution of a layer (attack
paths, maintainer behaviour, commit behaviour, cross-layer reasoning): what it
analysed, with which model version, from which inputs, and a summary. The
layer's own rows carry the run's id as `analysis_id`. Runs are kept so results
can be compared over time; a run only becomes visible once it is COMPLETE.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from bson import ObjectId
from pymongo.database import Database

from app.models.collections import ANALYSIS_RUNS
from app.services.analysis import storable

RUNNING, COMPLETE = "RUNNING", "COMPLETE"
_BATCH = 1000


def now() -> datetime:
    return datetime.now(timezone.utc)


def digest(value: Any) -> str:
    """A stable SHA-256 over JSON-serialisable input, used to recognise an unchanged input."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()


def reusable(db: Database, project_id: ObjectId, kind: str, input_digest: str) -> dict[str, Any] | None:
    return db[ANALYSIS_RUNS].find_one({"project_id": project_id, "kind": kind, "input_digest": input_digest, "state": COMPLETE},
                                      sort=[("created_at", -1), ("_id", -1)])


def begin(db: Database, *, project: dict[str, Any], kind: str, job: dict[str, Any], model_version: str, input_digest: str,
          snapshot: dict[str, Any] | None = None, inputs: dict[str, Any] | None = None, created_at: datetime | None = None) -> dict[str, Any]:
    """Insert a RUNNING run and return it. Rows are written next; `complete` makes the run visible."""
    run = {
        "_id": ObjectId(), "project_id": project["_id"], "repository_id": project.get("repository_id"), "kind": kind,
        "snapshot_id": snapshot["_id"] if snapshot else None, "commit_sha": snapshot.get("commit_sha") if snapshot else None,
        "branch": snapshot.get("branch") if snapshot else None, "job_id": job["_id"], "state": RUNNING, "model_version": model_version,
        "input_digest": input_digest, "inputs": storable(inputs or {}), "summary": {}, "created_at": created_at or now(),
    }
    db[ANALYSIS_RUNS].insert_one(run)
    return run


def insert_rows(db: Database, collection: str, rows: list[dict[str, Any]], limit: int = 2000) -> None:
    for start in range(0, len(rows), _BATCH):
        db[collection].insert_many(storable(rows[start:start + _BATCH], limit), ordered=False)


def complete(db: Database, run: dict[str, Any], summary: dict[str, Any]) -> dict[str, Any]:
    finished = now()
    db[ANALYSIS_RUNS].update_one({"_id": run["_id"]}, {"$set": {"state": COMPLETE, "summary": storable(summary), "completed_at": finished}})
    run.update(state=COMPLETE, summary=summary, completed_at=finished)
    return run


def discard(db: Database, run: dict[str, Any], row_collections: Iterable[str]) -> None:
    """Remove a run that could not be stored completely. It was never visible."""
    for collection in row_collections:
        db[collection].delete_many({"analysis_id": run["_id"]})
    db[ANALYSIS_RUNS].delete_one({"_id": run["_id"]})


def latest(db: Database, project: dict[str, Any], kind: str, *, snapshot_bound: bool = True) -> dict[str, Any] | None:
    """The newest completed run of a kind; for snapshot-bound layers, only one of the project's latest snapshot."""
    query: dict[str, Any] = {"project_id": project["_id"], "kind": kind, "state": COMPLETE}
    if snapshot_bound:
        if project.get("latest_snapshot_id") is None:
            return None
        query["snapshot_id"] = project["latest_snapshot_id"]
    return db[ANALYSIS_RUNS].find_one(query, sort=[("created_at", -1), ("_id", -1)])


def get(db: Database, project_id: ObjectId, run_id: str, kind: str | None = None) -> dict[str, Any] | None:
    if not ObjectId.is_valid(run_id):
        return None
    query: dict[str, Any] = {"_id": ObjectId(run_id), "project_id": project_id, "state": COMPLETE}
    if kind:
        query["kind"] = kind
    return db[ANALYSIS_RUNS].find_one(query)


def history(db: Database, project_id: ObjectId, kind: str, limit: int) -> list[dict[str, Any]]:
    return list(db[ANALYSIS_RUNS].find({"project_id": project_id, "kind": kind, "state": COMPLETE})
                .sort([("created_at", -1), ("_id", -1)]).limit(limit))


def prune(db: Database, project_id: ObjectId, kind: str, keep: int, row_collections: Iterable[str]) -> None:
    """Keep the most recent runs of a kind; remove older ones and runs that never completed, with their rows."""
    old = [doc["_id"] for doc in db[ANALYSIS_RUNS].find({"project_id": project_id, "kind": kind}, {"_id": 1})
           .sort([("created_at", -1), ("_id", -1)]).skip(keep)]
    cutoff = now() - timedelta(hours=1)
    old.extend(doc["_id"] for doc in db[ANALYSIS_RUNS].find(
        {"project_id": project_id, "kind": kind, "state": RUNNING, "created_at": {"$lt": cutoff}}, {"_id": 1}))
    if old:
        for collection in row_collections:
            db[collection].delete_many({"analysis_id": {"$in": old}})
        db[ANALYSIS_RUNS].delete_many({"_id": {"$in": old}})


def public(run: dict[str, Any] | None) -> dict[str, Any] | None:
    """A run as the API returns it: no owner-internal ids, no input digest."""
    if run is None:
        return None
    from app.services.analysis import public as to_public

    return to_public({k: v for k, v in run.items() if k not in ("project_id", "repository_id", "input_digest")})


def delete_project_data(db: Database, project_id: ObjectId, row_collections: Iterable[str]) -> None:
    for collection in (*row_collections, ANALYSIS_RUNS):
        db[collection].delete_many({"project_id": project_id})
