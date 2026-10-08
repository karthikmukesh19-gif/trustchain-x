"""Audit log of security-relevant actions."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import Request
from pymongo.database import Database

from app.models.collections import AUDIT_LOGS
from app.security.rate_limit import client_address

logger = logging.getLogger(__name__)


def record(
    db: Database,
    action: str,
    *,
    request: Request | None = None,
    actor_id: Any = None,
    outcome: str = "success",
    resource_type: str | None = None,
    resource_id: Any = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Write one audit entry. Never include secrets or passwords in `details`."""
    entry = {
        "timestamp": datetime.now(timezone.utc),
        "action": action,
        "outcome": outcome,
        "actor_id": actor_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "ip": client_address(request) if request is not None else None,
        "user_agent": (request.headers.get("user-agent") or "")[:300] if request is not None else None,
        "details": details or {},
    }
    try:
        db[AUDIT_LOGS].insert_one(entry)
    except Exception:  # noqa: BLE001 - an audit failure must not hide the original outcome
        logger.error("Failed to write audit log entry for action %s", action, exc_info=True)
