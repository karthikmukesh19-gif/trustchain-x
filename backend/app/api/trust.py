"""Trust engine endpoints. Every route is scoped to the project's owner.

When too little has been analysed the response says INSUFFICIENT_DATA and
carries no score. A score is never estimated, defaulted or carried over from
an earlier snapshot.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.api.common import AnalyzeRequest, owned_project, snapshot_reference, start_job
from app.auth.dependencies import CurrentUser, DbDep
from app.security.rate_limit import job_rate_limit
from app.services import analysis, jobs, trust_service
from app.services.trust import MODEL_VERSION, WEIGHTS, WEIGHTS_STATEMENT, history
from app.services.trust.engine import MEANING
from app.services.trust.weights import LABELS

router = APIRouter(prefix="/api/projects/{project_id}/trust", tags=["trust"])
HIDDEN = ("project_id", "repository_id", "input_digest", "job_id")


def _public(document: dict[str, Any] | None) -> dict[str, Any] | None:
    return None if document is None else analysis.public({k: v for k, v in document.items() if k not in HIDDEN})


def _model() -> dict[str, Any]:
    return {"model_version": MODEL_VERSION, "weights": WEIGHTS, "labels": LABELS, "weights_statement": WEIGHTS_STATEMENT, "meaning": MEANING}


@router.post("/analyze", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(job_rate_limit)])
def analyze(project_id: str, request: Request, db: DbDep, user: CurrentUser, body: AnalyzeRequest | None = None) -> dict[str, Any]:
    """Queue a trust analysis: combine whatever the layers have stored for the latest snapshot."""
    return start_job(request, db, user, owned_project(db, user, project_id), jobs.TRUST_ANALYSIS)


@router.get("")
def current(project_id: str, request: Request, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    """The current trust result with every component, or `trust: null` when none has been calculated for the latest snapshot."""
    project = owned_project(db, user, project_id)
    score = history.latest(db, project)
    return {
        "job": analysis.public_job(jobs.latest_job(db, project["_id"], jobs.TRUST_ANALYSIS)), "snapshot": snapshot_reference(db, project),
        "trust": _public(score), **_model(),
        # False when a layer was analysed, re-analysed or changed after the score was calculated.
        "up_to_date": None if score is None else trust_service.is_current(db, project, score, request.app.state.settings.trust_min_coverage),
    }


@router.get("/history")
def score_history(project_id: str, db: DbDep, user: CurrentUser, limit: Annotated[int, Query(ge=1, le=200)] = 50) -> dict[str, Any]:
    """Earlier trust results, newest first, across snapshots: the trend."""
    project = owned_project(db, user, project_id)
    return {"items": [analysis.public(item) for item in history.series(db, project["_id"], limit)], **_model()}


@router.get("/compare")
def compare(project_id: str, db: DbDep, user: CurrentUser, base: Annotated[str, Query(max_length=24)],
            target: Annotated[str, Query(max_length=24)]) -> dict[str, Any]:
    """What changed between two stored trust results, component by component."""
    project = owned_project(db, user, project_id)
    first, second = history.get(db, project["_id"], base), history.get(db, project["_id"], target)
    if first is None or second is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Trust result not found")
    return analysis.public(history.compare(first, second))


@router.get("/explanation")
def explanation(project_id: str, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    """How the current result was calculated, what drives it, what is unknown and what is recommended."""
    project = owned_project(db, user, project_id)
    score = history.latest(db, project)
    if score is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No trust analysis exists for the latest snapshot")
    return analysis.public({"trust_score_id": score["_id"], "created_at": score["created_at"], "status": score["status"],
                            "trust_score": score["trust_score"], "risk_score": score["risk_score"], **score["explanation"],
                            "evidence": score["evidence"], "model_version": score["model_version"]})
