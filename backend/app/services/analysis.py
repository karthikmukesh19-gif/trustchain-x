"""Dependency analysis: job lifecycle and the analysis pipeline.

Flow:  API request -> job document (QUEUED) -> Redis wake-up -> worker claims
the job (RUNNING) -> repository snapshot -> detection -> dependency extraction
-> graph -> MongoDB -> COMPLETED or FAILED.

MongoDB is the source of truth for job state; Redis only wakes the worker, so
a lost queue message delays a job but never loses it.
"""

from __future__ import annotations

import hashlib
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from bson import ObjectId
from pymongo import ReturnDocument, UpdateOne
from pymongo.database import Database
from pymongo.errors import BulkWriteError

from app.analyzers import detect
from app.analyzers.model import PARSE_ERROR, PARSED, SKIPPED, ParsedFile, ParseFailure, clean
from app.analyzers.resolve import resolve
from app.collectors.github import GitHubClient, GitHubSession, GitHubUnavailable
from app.config.settings import Settings
from app.graph.builder import build_graph
from app.models.collections import (
    ANALYSIS_JOBS, DEPENDENCIES, DEPENDENCY_GRAPHS, DEPENDENCY_VERSIONS, PROJECTS, REPOSITORIES, REPOSITORY_SNAPSHOTS,
)
from app.security.url_validation import RepositoryRef
from app.services import audit

logger = logging.getLogger(__name__)

ANALYZER_VERSION = "2.0.0"
JOB_TYPE = "dependencies"
QUEUE_KEY = "trustchain:jobs:analysis"

QUEUED, RUNNING, COMPLETED, FAILED = "queued", "running", "completed", "failed"
ACTIVE_STATES = (QUEUED, RUNNING)
STAGES = ("QUEUED", "REPOSITORY_SNAPSHOT", "REPOSITORY_DISCOVERY", "DEPENDENCY_DISCOVERY", "GRAPH_BUILDING", "COMPLETED")


class AnalysisError(Exception):
    """A structured, user-presentable analysis failure."""

    def __init__(self, code: str, message: str, retry_at: datetime | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retry_at = retry_at


class AnalysisAlreadyRunning(Exception):
    def __init__(self, job: dict[str, Any] | None) -> None:
        super().__init__("analysis already running")
        self.job = job


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --- jobs ---------------------------------------------------------------------

def request_analysis(db: Database, redis_client: Any, project: dict[str, Any]) -> dict[str, Any]:
    """Create a queued job. Only one job per project may be queued or running."""
    now = _now()
    job_id = ObjectId()
    # Atomic claim on the project document: two simultaneous requests cannot both succeed.
    claimed = db[PROJECTS].find_one_and_update(
        {"_id": project["_id"], "active_job_id": None}, {"$set": {"active_job_id": job_id, "updated_at": now}})
    if claimed is None:
        raise AnalysisAlreadyRunning(db[ANALYSIS_JOBS].find_one({"_id": project.get("active_job_id")}) or latest_job(db, project["_id"]))
    job = {
        "_id": job_id, "project_id": project["_id"], "owner_id": project["owner_id"], "repository_id": project["repository_id"],
        "type": JOB_TYPE, "state": QUEUED, "stage": "QUEUED", "stage_index": 0, "stage_count": len(STAGES) - 1,
        "message": "Waiting for the background worker", "error": None, "snapshot_id": None, "summary": None,
        "reused_snapshot": False, "analyzer_version": ANALYZER_VERSION,
        "created_at": now, "started_at": None, "finished_at": None, "updated_at": now,
    }
    db[ANALYSIS_JOBS].insert_one(job)
    try:
        redis_client.lpush(QUEUE_KEY, str(job_id))
    except Exception:  # noqa: BLE001 - the worker also polls MongoDB, so the job is not lost
        logger.warning("Could not signal the worker through Redis; job %s will be picked up by polling", job_id)
    return job


def latest_job(db: Database, project_id: ObjectId) -> dict[str, Any] | None:
    return db[ANALYSIS_JOBS].find_one({"project_id": project_id, "type": JOB_TYPE}, sort=[("created_at", -1), ("_id", -1)])


def claim_next_job(db: Database) -> dict[str, Any] | None:
    """Atomically move the oldest queued job to RUNNING."""
    now = _now()
    return db[ANALYSIS_JOBS].find_one_and_update(
        {"state": QUEUED, "type": JOB_TYPE},
        {"$set": {"state": RUNNING, "started_at": now, "updated_at": now, "message": "Starting"}},
        sort=[("created_at", 1), ("_id", 1)], return_document=ReturnDocument.AFTER,
    )


def fail_stale_jobs(db: Database, settings: Settings) -> int:
    """Fail jobs left RUNNING by a worker that died, so the project can be analysed again."""
    cutoff = _now() - timedelta(seconds=settings.analysis_stale_job_seconds)
    count = 0
    for job in db[ANALYSIS_JOBS].find({"state": RUNNING, "started_at": {"$lt": cutoff}}):
        _finish(db, job, FAILED, "The analysis did not finish (the worker stopped). Run it again.",
                error={"code": "WORKER_INTERRUPTED", "message": "The worker stopped before the analysis finished."})
        count += 1
    return count


def _progress(db: Database, job: dict[str, Any], stage: str, message: str) -> None:
    job.update(stage=stage, stage_index=STAGES.index(stage), message=message)
    db[ANALYSIS_JOBS].update_one({"_id": job["_id"]}, {"$set": {
        "stage": stage, "stage_index": STAGES.index(stage), "message": message, "updated_at": _now()}})


def _finish(db: Database, job: dict[str, Any], state: str, message: str, *, error: dict[str, Any] | None = None,
            extra: dict[str, Any] | None = None) -> None:
    now = _now()
    update = {"state": state, "message": message, "error": error, "finished_at": now, "updated_at": now, **(extra or {})}
    if state == COMPLETED:
        update.update(stage="COMPLETED", stage_index=len(STAGES) - 1)
    db[ANALYSIS_JOBS].update_one({"_id": job["_id"]}, {"$set": update})
    db[PROJECTS].update_one({"_id": job["project_id"], "active_job_id": job["_id"]}, {"$set": {"active_job_id": None}})
    job.update(update)


# --- pipeline -----------------------------------------------------------------

def run_job(db: Database, github: GitHubClient, settings: Settings, job: dict[str, Any]) -> dict[str, Any]:
    """Execute one claimed job. Never raises: every outcome is recorded on the job."""
    started = time.monotonic()
    try:
        summary, snapshot_id, reused = _analyse(db, github, settings, job, started)
    except AnalysisError as exc:
        error = {"code": exc.code, "message": exc.message}
        if exc.retry_at is not None:
            error["retry_at"] = exc.retry_at
        _finish(db, job, FAILED, exc.message, error=error)
    except Exception:  # noqa: BLE001 - last line of defence for the worker loop
        logger.exception("Analysis job %s crashed", job["_id"])
        _finish(db, job, FAILED, "The analysis stopped because of an internal error.",
                error={"code": "INTERNAL_ERROR", "message": "The analysis stopped because of an internal error."})
    else:
        message = "Repository unchanged since the last analysis; existing results kept" if reused else "Analysis complete"
        _finish(db, job, COMPLETED, message, extra={"snapshot_id": snapshot_id, "summary": summary, "reused_snapshot": reused})
    audit.record(db, "analysis.dependencies.finish", actor_id=job.get("owner_id"), outcome="success" if job["state"] == COMPLETED else "failure",
                 resource_type="project", resource_id=job["project_id"],
                 details={"job_id": str(job["_id"]), "error_code": (job.get("error") or {}).get("code"),
                          "seconds": round(time.monotonic() - started, 2)})
    return job


def _check_deadline(started: float, settings: Settings) -> None:
    if time.monotonic() - started > settings.analysis_timeout_seconds:
        raise AnalysisError("TIMEOUT", f"The analysis exceeded its time limit of {settings.analysis_timeout_seconds} seconds.")


def _analyse(db: Database, github: GitHubClient, settings: Settings, job: dict[str, Any], started: float) -> tuple[dict[str, Any], ObjectId, bool]:
    project = db[PROJECTS].find_one({"_id": job["project_id"]})
    repository = db[REPOSITORIES].find_one({"_id": job["repository_id"]})
    if project is None or repository is None:
        raise AnalysisError("PROJECT_NOT_FOUND", "The project was deleted before the analysis started.")
    ref = RepositoryRef(host=repository["host"], owner=repository["owner"], name=repository["name"])

    try:
        with github.session() as session:
            _progress(db, job, "REPOSITORY_SNAPSHOT", "Reading repository metadata and the latest commit")
            metadata = session.repository(ref)
            if (metadata.get("size_kb") or 0) > settings.analysis_max_repo_kb:
                raise AnalysisError("REPOSITORY_TOO_LARGE",
                                    f"The repository is {metadata['size_kb']} KB; the limit is {settings.analysis_max_repo_kb} KB.")
            branch = metadata.get("default_branch")
            if not branch:
                raise AnalysisError("NO_DEFAULT_BRANCH", "GitHub did not report a default branch for this repository.")
            head = session.head_commit(ref, branch)

            existing = db[REPOSITORY_SNAPSHOTS].find_one({
                "project_id": project["_id"], "commit_sha": head["commit_sha"], "analyzer_version": ANALYZER_VERSION})
            if existing is not None and existing.get("status") == "COMPLETE":
                db[PROJECTS].update_one({"_id": project["_id"]}, {"$set": {"latest_snapshot_id": existing["_id"], "updated_at": _now()}})
                return existing.get("summary") or {}, existing["_id"], True
            if existing is not None:
                _delete_snapshot(db, existing["_id"])   # left incomplete by an interrupted run

            _progress(db, job, "REPOSITORY_SNAPSHOT", f"Listing files at commit {head['commit_sha'][:10]}")
            listing = session.tree(ref, head["tree_sha"])
            if listing["truncated"] or len(listing["files"]) > settings.analysis_max_files:
                raise AnalysisError("TOO_MANY_FILES",
                                    f"The repository has more files than the limit of {settings.analysis_max_files}.")
            _check_deadline(started, settings)

            _progress(db, job, "REPOSITORY_DISCOVERY", "Detecting languages and package managers")
            files = listing["files"]
            manifests = detect.detect_manifests(files)
            languages = detect.detect_languages(files, manifests)
            package_managers = detect.detect_package_managers(manifests)

            _progress(db, job, "DEPENDENCY_DISCOVERY", f"Reading {len(manifests)} dependency file(s)")
            parsed_files, manifest_records = _read_manifests(session, ref, files, manifests, settings, started)
            requests_made, rate_remaining = session.requests_made, session.rate_remaining
    except GitHubUnavailable as exc:
        raise AnalysisError(exc.code, exc.reason, exc.retry_at) from exc

    _progress(db, job, "GRAPH_BUILDING", "Resolving dependencies and building the graph")
    resolution = resolve(parsed_files)
    manifest_records = storable(manifest_records)
    if len(resolution.packages) > settings.analysis_max_dependencies:
        raise AnalysisError("TOO_MANY_DEPENDENCIES",
                            f"{len(resolution.packages)} dependencies were found; the limit is {settings.analysis_max_dependencies}.")
    graph = storable(build_graph(resolution, repository["full_name"]))
    blob_ids = {m["path"]: m.get("git_blob_sha") for m in manifest_records}
    for node in graph["nodes"]:
        for item in node["evidence"]:
            item["git_blob_sha"] = blob_ids.get(item["source_file"])

    now = _now()
    stats = graph["stats"]
    summary = {
        "dependencies": stats["total"], "direct": stats["direct"], "transitive": stats["transitive"],
        "relationship_unknown": stats["relationship_unknown"], "unresolved_versions": stats["unresolved_versions"],
        "edges": stats["edges"], "max_depth": stats["max_depth"], "ecosystems": sorted(stats["by_ecosystem"]),
        "package_managers": [p["package_manager"] for p in package_managers],
        "languages": [l["language"] for l in languages["languages"]], "primary_language": languages["primary_language"],
        "dependency_files": len(manifest_records), "files": len(files),
    }
    snapshot_id = ObjectId()
    db[REPOSITORY_SNAPSHOTS].insert_one({
        "_id": snapshot_id, "project_id": project["_id"], "repository_id": repository["_id"], "job_id": job["_id"],
        "repository_url": repository["url"], "repository_full_name": repository["full_name"],
        "branch": branch, "commit_sha": head["commit_sha"], "tree_sha": head["tree_sha"],
        "committed_at": head["committed_at"], "commit_message": head["message"],
        "collected_at": now, "status": "COLLECTED", "analyzer_version": ANALYZER_VERSION,
        "collection_method": "GitHub REST API (commits, git/trees, git/blobs); no repository code executed",
        "file_count": len(files), "total_bytes": sum(f["size"] for f in files),
        "rejected_paths": listing["rejected_paths"], "symlinks_skipped": listing["symlinks"], "submodules_skipped": listing["submodules"],
        "files": files, "languages": languages, "github_primary_language": metadata.get("primary_language"),
        "package_managers": package_managers, "dependency_files": manifest_records,
        "notes": storable(resolution.notes[:200]), "summary": summary,
        "github_requests": requests_made, "github_rate_remaining": rate_remaining,
    })
    records = [{**node, "project_id": project["_id"], "snapshot_id": snapshot_id} for node in graph["nodes"]]
    if records:
        db[DEPENDENCIES].insert_many(records, ordered=False)
    slim_nodes = [{k: v for k, v in node.items() if k not in {"evidence", "integrity"}} for node in graph["nodes"]]
    db[DEPENDENCY_GRAPHS].insert_one({
        "project_id": project["_id"], "snapshot_id": snapshot_id, "created_at": now, "root": graph["root"],
        "nodes": slim_nodes, "edges": graph["edges"], "stats": stats,
    })
    _record_versions(db, graph["nodes"], now)
    db[REPOSITORY_SNAPSHOTS].update_one({"_id": snapshot_id}, {"$set": {"status": "COMPLETE"}})
    db[PROJECTS].update_one({"_id": project["_id"]}, {"$set": {
        "last_analysis": now, "latest_snapshot_id": snapshot_id, "default_branch": branch,
        "languages": summary["languages"], "updated_at": now}})
    return summary, snapshot_id, False


def _read_manifests(session: GitHubSession, ref: RepositoryRef, files: list[dict[str, Any]], manifests: list[dict[str, Any]],
                    settings: Settings, started: float) -> tuple[list[ParsedFile], list[dict[str, Any]]]:
    """Fetch and parse every dependency file within the limits. A file that fails is recorded, not fatal."""
    index = {f["path"]: f for f in files}
    queue = list(manifests)
    seen = {m["path"] for m in queue}
    parsed_files: list[ParsedFile] = []
    records: list[dict[str, Any]] = []
    total_bytes = fetched = 0

    while queue:
        manifest = queue.pop(0)
        record = {k: manifest.get(k) for k in ("path", "size", "git_blob_sha", "package_manager", "ecosystem", "kind", "matched_pattern")}
        record.update(status=manifest.get("status") or PARSED, detail=manifest.get("reason"), sha256=None,
                      dependencies_found=0, notes=[], evidence_type="repository_file", referenced_by=manifest.get("referenced_by"))
        records.append(record)
        if not manifest["parseable"]:
            continue
        size = manifest.get("size") or 0
        if fetched >= settings.analysis_max_manifests:
            record.update(status=SKIPPED, detail=f"More than {settings.analysis_max_manifests} dependency files; this one was not read")
            continue
        if size > settings.analysis_max_manifest_bytes:
            record.update(status=SKIPPED, detail=f"File is {size} bytes; the per-file limit is {settings.analysis_max_manifest_bytes}")
            continue
        if total_bytes + size > settings.analysis_max_total_bytes:
            record.update(status=SKIPPED, detail="The total size limit for dependency files was reached")
            continue
        _check_deadline(started, settings)
        content = session.blob(ref, manifest["git_blob_sha"], settings.analysis_max_manifest_bytes)
        fetched += 1
        total_bytes += len(content)
        record["sha256"] = hashlib.sha256(content).hexdigest()
        if b"\x00" in content[:8192]:
            record.update(status=PARSE_ERROR, detail="The file is binary, not text")
            continue
        text = content.decode("utf-8", errors="replace")
        file_type = detect.classify_file(manifest["path"]) if not manifest.get("forced_parser") else detect.REQUIREMENTS_FILE
        try:
            parsed = file_type.parser(manifest["path"], text)
        except ParseFailure as exc:
            record.update(status=PARSE_ERROR, detail=clean(str(exc), 300))
            continue
        except Exception:  # noqa: BLE001 - hostile input must not stop the analysis
            logger.exception("Parser crashed on %s", manifest["path"])
            record.update(status=PARSE_ERROR, detail="The file could not be parsed")
            continue
        parsed_files.append(parsed)
        record.update(kind=parsed.kind, package_manager=parsed.package_manager,
                      dependencies_found=len(parsed.declared) + len([l for l in parsed.locked if not l.local]),
                      notes=parsed.notes[:20])
        # Files pulled in with "-r other.txt": follow them only if they exist in this snapshot.
        for target in parsed.includes:
            if target in seen:
                continue
            seen.add(target)
            entry = index.get(target)
            if entry is None or detect.is_ignored(target):
                parsed.note(f"Referenced file {target} is not in the repository")
                record["notes"] = parsed.notes[:20]
                continue
            queue.append({"path": target, "size": entry["size"], "git_blob_sha": entry["sha"], "package_manager": "pip",
                          "ecosystem": "pypi", "kind": "manifest", "parseable": True, "status": None, "reason": None,
                          "matched_pattern": "-r include", "forced_parser": True, "referenced_by": manifest["path"]})
    return parsed_files, records


def _record_versions(db: Database, nodes: list[dict[str, Any]], now: datetime) -> None:
    """Catalogue every resolved package version seen, for later phases to attach registry facts to."""
    operations = []
    for node in nodes:
        if not node["version"]:
            continue
        operations.append(UpdateOne(
            {"ecosystem": node["ecosystem"], "package_name": node["normalized_name"], "version": node["version"]},
            {"$setOnInsert": {"purl": node["purl"], "first_seen_at": now, "source": "repository_analysis"},
             "$set": {"last_seen_at": now}},
            upsert=True))
    for start in range(0, len(operations), 1000):
        try:
            db[DEPENDENCY_VERSIONS].bulk_write(operations[start:start + 1000], ordered=False)
        except BulkWriteError as exc:
            # Two workers cataloguing the same version at once: the other one's insert is equally good.
            if any(error.get("code") != 11000 for error in exc.details.get("writeErrors", [])):
                raise


def _delete_snapshot(db: Database, snapshot_id: ObjectId) -> None:
    db[DEPENDENCIES].delete_many({"snapshot_id": snapshot_id})
    db[DEPENDENCY_GRAPHS].delete_many({"snapshot_id": snapshot_id})
    db[REPOSITORY_SNAPSHOTS].delete_one({"_id": snapshot_id})


def delete_project_analysis(db: Database, project_id: ObjectId) -> None:
    """Remove everything derived from a project when the project is deleted."""
    db[DEPENDENCIES].delete_many({"project_id": project_id})
    db[DEPENDENCY_GRAPHS].delete_many({"project_id": project_id})
    db[REPOSITORY_SNAPSHOTS].delete_many({"project_id": project_id})
    db[ANALYSIS_JOBS].delete_many({"project_id": project_id})


def storable(value: Any, limit: int = 4000) -> Any:
    """Make repository-derived data safe to store: valid UTF-8, bounded strings, no NUL bytes."""
    if isinstance(value, str):
        return value.encode("utf-8", "replace").decode("utf-8").replace("\x00", "")[:limit]
    if isinstance(value, dict):
        return {key: storable(item, limit) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [storable(item, limit) for item in value]
    return value


# --- reads --------------------------------------------------------------------

def latest_snapshot(db: Database, project: dict[str, Any], include_files: bool = False) -> dict[str, Any] | None:
    snapshot_id = project.get("latest_snapshot_id")
    if snapshot_id is None:
        return None
    projection = None if include_files else {"files": 0}
    return db[REPOSITORY_SNAPSHOTS].find_one({"_id": snapshot_id, "project_id": project["_id"], "status": "COMPLETE"}, projection)


def public(value: Any) -> Any:
    """Convert a stored document into JSON-serialisable data (ObjectIds become strings)."""
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, dict):
        return {("id" if key == "_id" else key): public(item) for key, item in value.items()}
    if isinstance(value, list):
        return [public(item) for item in value]
    return value


def public_job(job: dict[str, Any] | None) -> dict[str, Any] | None:
    if job is None:
        return None
    hidden = {"owner_id", "repository_id"}
    return public({k: v for k, v in job.items() if k not in hidden})


