"""Project management and GitHub repository registration."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request, Response, status

from app.auth.dependencies import CurrentUser, DbDep
from app.collectors.github import GitHubClient
from app.models.collections import REPOSITORIES
from app.schemas.projects import ProjectCreate, ProjectList, ProjectOut
from app.services import audit
from app.services import projects as service

router = APIRouter(prefix="/api/projects", tags=["projects"])


def _github(request: Request) -> GitHubClient:
    return request.app.state.github


def _not_found() -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")


def _public(db, project) -> ProjectOut:
    repository = db[REPOSITORIES].find_one({"_id": project["repository_id"]})
    return ProjectOut(**service.to_public(project, repository))


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project(
    body: ProjectCreate, request: Request, background: BackgroundTasks, db: DbDep, user: CurrentUser
) -> ProjectOut:
    try:
        project = service.create_project(db, user["_id"], body.name, body.repository_url, body.description)
    except service.ProjectAlreadyExists:
        raise HTTPException(status.HTTP_409_CONFLICT, "You have already registered this repository") from None
    audit.record(
        db,
        "project.create",
        request=request,
        actor_id=user["_id"],
        resource_type="project",
        resource_id=project["_id"],
        details={"repository": project["repository_url"]},
    )
    # Metadata is fetched after the response is sent; the project reports
    # PENDING until the outcome is stored.
    background.add_task(service.refresh_repository_metadata, db, _github(request), project["repository_id"])
    return _public(db, project)


@router.get("", response_model=ProjectList)
def list_projects(
    db: DbDep,
    user: CurrentUser,
    skip: Annotated[int, Query(ge=0, le=100_000)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> ProjectList:
    projects, total = service.list_projects(db, user["_id"], skip, limit)
    repositories = service.load_repositories(db, projects)
    items = [ProjectOut(**service.to_public(p, repositories.get(p["repository_id"]))) for p in projects]
    return ProjectList(items=items, total=total, skip=skip, limit=limit)


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(project_id: str, db: DbDep, user: CurrentUser) -> ProjectOut:
    project = service.get_project(db, user["_id"], project_id)
    if project is None:
        raise _not_found()
    return _public(db, project)


@router.post("/{project_id}/refresh-metadata", response_model=ProjectOut)
def refresh_metadata(project_id: str, request: Request, db: DbDep, user: CurrentUser) -> ProjectOut:
    """Fetch the repository's public GitHub metadata again, now."""
    project = service.get_project(db, user["_id"], project_id)
    if project is None:
        raise _not_found()
    service.refresh_repository_metadata(db, _github(request), project["repository_id"], force=True)
    audit.record(
        db,
        "project.refresh_metadata",
        request=request,
        actor_id=user["_id"],
        resource_type="project",
        resource_id=project["_id"],
    )
    return _public(db, service.get_project(db, user["_id"], project_id))


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(project_id: str, request: Request, db: DbDep, user: CurrentUser) -> Response:
    project = service.get_project(db, user["_id"], project_id)
    if project is None or not service.delete_project(db, user["_id"], project_id):
        raise _not_found()
    audit.record(
        db,
        "project.delete",
        request=request,
        actor_id=user["_id"],
        resource_type="project",
        resource_id=project["_id"],
        details={"repository": project["repository_url"], "name": project["name"]},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
