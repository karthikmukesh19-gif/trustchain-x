"""Projects and their registered repositories.

A repository is stored once (collection `repositories`) and referenced by
every project that registers it. Each project belongs to exactly one user,
and every query here is scoped to that owner.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from bson import ObjectId
from pymongo.database import Database
from pymongo.errors import DuplicateKeyError

from app.collectors.github import GitHubClient, GitHubUnavailable
from app.models.collections import PROJECTS, REPOSITORIES
from app.security.url_validation import RepositoryRef, parse_github_url

logger = logging.getLogger(__name__)

STATUS_ACTIVE = "ACTIVE"
METADATA_PENDING = "PENDING"
METADATA_FETCHED = "FETCHED"
METADATA_UNAVAILABLE = "UNAVAILABLE"

METADATA_FRESH_FOR = timedelta(hours=1)


class ProjectAlreadyExists(Exception):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _get_or_create_repository(db: Database, ref: RepositoryRef) -> dict[str, Any]:
    existing = db[REPOSITORIES].find_one({"key": ref.key})
    if existing is not None:
        return existing
    now = _now()
    repository = {
        "key": ref.key,
        "host": ref.host,
        "owner": ref.owner,
        "name": ref.name,
        "full_name": ref.full_name,
        "url": ref.url,
        "metadata_status": METADATA_PENDING,
        "metadata_error": None,
        "metadata": None,
        "metadata_fetched_at": None,
        "created_at": now,
        "updated_at": now,
    }
    try:
        repository["_id"] = db[REPOSITORIES].insert_one(repository).inserted_id
        return repository
    except DuplicateKeyError:
        # Another request registered the same repository at the same moment.
        return db[REPOSITORIES].find_one({"key": ref.key})


def create_project(
    db: Database, owner_id: ObjectId, name: str, repository_url: str, description: str
) -> dict[str, Any]:
    ref = parse_github_url(repository_url)
    repository = _get_or_create_repository(db, ref)
    now = _now()
    metadata = repository.get("metadata") or {}
    project = {
        "owner_id": owner_id,
        "name": name,
        "description": description,
        "repository_id": repository["_id"],
        "repository_key": ref.key,
        "repository_url": ref.url,
        "default_branch": metadata.get("default_branch"),
        "languages": [],
        "status": STATUS_ACTIVE,
        "created_at": now,
        "updated_at": now,
        "last_analysis": None,
        "latest_snapshot_id": None,
        "active_job_id": None,
    }
    try:
        project["_id"] = db[PROJECTS].insert_one(project).inserted_id
    except DuplicateKeyError as exc:
        raise ProjectAlreadyExists(ref.full_name) from exc
    return project


def metadata_is_fresh(repository: dict[str, Any]) -> bool:
    fetched_at = repository.get("metadata_fetched_at")
    if repository.get("metadata_status") != METADATA_FETCHED or fetched_at is None:
        return False
    if fetched_at.tzinfo is None:
        fetched_at = fetched_at.replace(tzinfo=timezone.utc)
    return _now() - fetched_at < METADATA_FRESH_FOR


def refresh_repository_metadata(
    db: Database, github: GitHubClient, repository_id: ObjectId, *, force: bool = False
) -> dict[str, Any] | None:
    """Fetch public metadata from GitHub and store the outcome.

    A failure is recorded as UNAVAILABLE with the reason; previously fetched
    metadata is kept so earlier evidence is not lost.
    """
    repository = db[REPOSITORIES].find_one({"_id": repository_id})
    if repository is None:
        return None
    if not force and metadata_is_fresh(repository):
        return repository

    ref = RepositoryRef(host=repository["host"], owner=repository["owner"], name=repository["name"])
    now = _now()
    try:
        metadata = github.fetch_repository(ref)
    except GitHubUnavailable as exc:
        update = {"metadata_status": METADATA_UNAVAILABLE, "metadata_error": exc.reason, "updated_at": now}
    except Exception:  # noqa: BLE001 - runs as a background task; nothing above us can report it
        logger.exception("Unexpected error fetching metadata for %s", repository["full_name"])
        update = {
            "metadata_status": METADATA_UNAVAILABLE,
            "metadata_error": "Unexpected error while contacting GitHub",
            "updated_at": now,
        }
    else:
        update = {
            "metadata_status": METADATA_FETCHED,
            "metadata_error": None,
            "metadata": metadata,
            "metadata_fetched_at": now,
            "updated_at": now,
        }
        if metadata.get("default_branch"):
            db[PROJECTS].update_many(
                {"repository_id": repository_id},
                {"$set": {"default_branch": metadata["default_branch"], "updated_at": now}},
            )
    db[REPOSITORIES].update_one({"_id": repository_id}, {"$set": update})
    repository.update(update)
    return repository


def list_projects(db: Database, owner_id: ObjectId, skip: int, limit: int) -> tuple[list[dict[str, Any]], int]:
    query = {"owner_id": owner_id}
    total = db[PROJECTS].count_documents(query)
    cursor = db[PROJECTS].find(query).sort([("created_at", -1), ("_id", -1)]).skip(skip).limit(limit)
    return list(cursor), total


def get_project(db: Database, owner_id: ObjectId, project_id: str) -> dict[str, Any] | None:
    if not ObjectId.is_valid(project_id):
        return None
    return db[PROJECTS].find_one({"_id": ObjectId(project_id), "owner_id": owner_id})


def delete_project(db: Database, owner_id: ObjectId, project_id: str) -> bool:
    if not ObjectId.is_valid(project_id):
        return False
    result = db[PROJECTS].delete_one({"_id": ObjectId(project_id), "owner_id": owner_id})
    if result.deleted_count == 1:
        # Local import: the analysis service depends on this module.
        from app.services import sbom, vulnerabilities
        from app.services.analysis import delete_project_analysis

        delete_project_analysis(db, ObjectId(project_id))
        vulnerabilities.delete_project_data(db, ObjectId(project_id))
        sbom.delete_project_data(db, ObjectId(project_id))
    return result.deleted_count == 1


def load_repositories(db: Database, projects: list[dict[str, Any]]) -> dict[ObjectId, dict[str, Any]]:
    ids = list({p["repository_id"] for p in projects if p.get("repository_id") is not None})
    if not ids:
        return {}
    return {r["_id"]: r for r in db[REPOSITORIES].find({"_id": {"$in": ids}})}


def to_public(project: dict[str, Any], repository: dict[str, Any] | None) -> dict[str, Any]:
    repo_out = None
    if repository is not None:
        repo_out = {
            "host": repository["host"],
            "owner": repository["owner"],
            "name": repository["name"],
            "full_name": repository["full_name"],
            "url": repository["url"],
            "metadata_status": repository["metadata_status"],
            "metadata_error": repository.get("metadata_error"),
            "metadata_fetched_at": repository.get("metadata_fetched_at"),
            "metadata": repository.get("metadata"),
        }
    return {
        "id": str(project["_id"]),
        "name": project["name"],
        "description": project.get("description", ""),
        "repository_url": project["repository_url"],
        "status": project["status"],
        "default_branch": project.get("default_branch"),
        "languages": project.get("languages", []),
        "created_at": project["created_at"],
        "updated_at": project["updated_at"],
        "last_analysis": project.get("last_analysis"),
        "latest_snapshot_id": str(project["latest_snapshot_id"]) if project.get("latest_snapshot_id") else None,
        "repository": repo_out,
    }
