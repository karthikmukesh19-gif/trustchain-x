"""The unified overview and the report. Every route is scoped to the project's owner."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import PlainTextResponse

from app.api.common import owned_project
from app.auth.dependencies import CurrentUser, DbDep
from app.services import analysis, audit, overview, report

router = APIRouter(prefix="/api/projects/{project_id}", tags=["overview"])


@router.get("/overview")
def get_overview(project_id: str, db: DbDep, user: CurrentUser) -> dict[str, Any]:
    """Everything the executive, technical and research dashboards show, in one read of the stored results."""
    return analysis.public(overview.build(db, owned_project(db, user, project_id)))


@router.get("/report", response_model=None)
def get_report(project_id: str, request: Request, db: DbDep, user: CurrentUser,
               report_format: Annotated[str, Query(alias="format", pattern=r"^(json|markdown)$")] = "json") -> Any:
    """The seventeen-section report of the project's current state. `format=markdown` returns it as a document to download."""
    project = owned_project(db, user, project_id)
    built = report.build(db, project)
    if built["unsupported_statements"]:
        # A report with a statement that cites nothing is a defect, not something to hand out.
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "The report could not be generated with complete evidence")
    audit.record(db, "report.generate", request=request, actor_id=user["_id"], resource_type="project", resource_id=project["_id"],
                 details={"format": report_format, "statements": built["statement_count"], "evidence": len(built["evidence"])})
    if report_format == "markdown":
        name = "".join(c if c.isalnum() or c in "-_" else "-" for c in str(project.get("name") or "project"))[:60] or "project"
        return PlainTextResponse(report.to_markdown(built), media_type="text/markdown; charset=utf-8",
                                 headers={"Content-Disposition": f'attachment; filename="trustchain-x-report-{name}.md"'})
    return analysis.public(built)
