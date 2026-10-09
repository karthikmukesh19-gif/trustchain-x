"""Dashboard summary."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from app.auth.dependencies import CurrentUser, DbDep
from app.services import dashboard

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/summary")
def summary(db: DbDep, user: CurrentUser) -> dict[str, Any]:
    return dashboard.build_summary(db, user["_id"])


@router.get("/evaluation")
def evaluation(user: CurrentUser) -> dict[str, Any]:
    """The evaluation measures defined for each component and whether each has been evaluated. Unevaluated measures have no value."""
    from app.evaluation import NOT_EVALUATED, catalogue

    rows = catalogue()
    return {"items": rows, "not_evaluated": sum(1 for row in rows if row["status"] == NOT_EVALUATED), "total": len(rows),
            "note": "No benchmark results are bundled with the platform. Measures marked NOT EVALUATED have never been computed; "
                    "none of them is estimated."}
