"""Cross-layer reasoning endpoints. Every route is scoped to the project's owner.

Every finding is returned with the evidence it cites, resolved to the stored
records. There is no finding without evidence, and none states that an
attack happened or would succeed.
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.ai import CATEGORIES, SEVERITIES
from app.ai.reasoning import SEVERITY_RANK
from app.api.common import HIDDEN, AnalyzeRequest, Limit, Skip, owned_project, snapshot_reference, start_job
from app.auth.dependencies import CurrentUser, DbDep
from app.models.collections import AI_FINDINGS
from app.security.rate_limit import job_rate_limit
from app.services import analysis, jobs, layers, reasoning, runs

router = APIRouter(prefix="/api/projects/{project_id}/ai-analysis", tags=["ai-analysis"])
FINDING_ID = re.compile(r"^[0-9a-f]{24}$")
MEANING = ("Findings are produced by fixed rules over stored analysis results. Each statement cites the records it rests on and is "
           "labelled as observed, derived, predicted or recommended. A finding is a reason to act or to look; it is not proof of an attack.")


@router.post("", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(job_rate_limit)])
def analyze(project_id: str, request: Request, db: DbDep, user: CurrentUser, body: AnalyzeRequest | None = None) -> dict[str, Any]:
    """Queue a cross-layer reasoning run over whatever the other layers have stored."""
    return start_job(request, db, user, owned_project(db, user, project_id), jobs.AI_SECURITY_ANALYSIS)


@router.get("")
def list_findings(project_id: str, db: DbDep, user: CurrentUser, skip: Skip = 0, limit: Limit = 100,
                  severity: Annotated[str | None, Query(max_length=10)] = None,
                  category: Annotated[str | None, Query(max_length=60)] = None,
                  layer: Annotated[str | None, Query(max_length=30)] = None) -> dict[str, Any]:
    """Findings of the latest reasoning run, most severe first, with the audit information of that run."""
    project = owned_project(db, user, project_id)
    run = reasoning.latest(db, project)
    body: dict[str, Any] = {
        "job": analysis.public_job(jobs.latest_job(db, project["_id"], jobs.AI_SECURITY_ANALYSIS)), "snapshot": snapshot_reference(db, project),
        "analysis": runs.public(run), "categories": CATEGORIES, "severities": list(SEVERITIES), "meaning": MEANING,
        "total": 0, "skip": skip, "limit": limit, "items": [],
    }
    if run is None:
        return body
    query: dict[str, Any] = {"analysis_id": run["_id"]}
    if severity:
        if severity not in SEVERITIES:
            raise HTTPException(422, f"severity must be one of: {', '.join(SEVERITIES)}")
        query["severity_rank"] = {"$gte": SEVERITY_RANK[severity]}
    if category:
        if category not in CATEGORIES:
            raise HTTPException(422, "Unknown category")
        query["category"] = category
    if layer:
        if layer not in layers.LAYER_NAMES:
            raise HTTPException(422, "Unknown layer")
        query["contributing_layers"] = layer
    body["total"] = db[AI_FINDINGS].count_documents(query)
    cursor = db[AI_FINDINGS].find(query, {**HIDDEN, "conditions": 0, "confidence_detail": 0}).sort(
        [("severity_rank", -1), ("confidence", -1), ("category", 1), ("finding_id", 1)]).skip(skip).limit(limit)
    body["items"] = [analysis.public(row) for row in cursor]
    return body


@router.get("/history")
def history(project_id: str, db: DbDep, user: CurrentUser, limit: Annotated[int, Query(ge=1, le=100)] = 20) -> dict[str, Any]:
    """Earlier reasoning runs, newest first: the audit trail of what was concluded, from what, by which model version."""
    project = owned_project(db, user, project_id)
    return {"items": [runs.public(run) for run in runs.history(db, project["_id"], reasoning.KIND, limit)]}


@router.get("/{finding_id}")
def get_finding(project_id: str, finding_id: str, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    """One finding with its statements, resolved evidence, the conditions the rule evaluated, and how its confidence was formed."""
    project = owned_project(db, user, project_id)
    run = reasoning.latest(db, project)
    row = None
    if run is not None and FINDING_ID.match(finding_id):
        row = db[AI_FINDINGS].find_one({"analysis_id": run["_id"], "project_id": project["_id"], "finding_id": finding_id}, HIDDEN)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    return analysis.public(row)
