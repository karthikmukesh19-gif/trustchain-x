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
