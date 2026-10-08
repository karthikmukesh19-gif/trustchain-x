"""Liveness and readiness."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Request, Response, status

from app import __version__
from app.models.database import ping
from app.workers.heartbeat import HEARTBEAT_KEY

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/health", tags=["health"])


@router.get("")
def live(request: Request) -> dict[str, Any]:
    """The process is up. Does not touch any dependency."""
    return {
        "status": "ok",
        "service": request.app.state.settings.app_name,
        "version": __version__,
        "time": datetime.now(timezone.utc),
    }


def _redis_state(redis_client: Any) -> tuple[bool, str | None]:
    """Return (redis reachable, last worker heartbeat or None)."""
    if redis_client is None:
        return False, None
    try:
        redis_client.ping()
        beat = redis_client.get(HEARTBEAT_KEY)
    except Exception:  # noqa: BLE001 - any failure means "not reachable"
        logger.warning("Redis check failed", exc_info=True)
        return False, None
    if isinstance(beat, bytes):
        beat = beat.decode("utf-8", "replace")
    return True, beat


@router.get("/ready")
def ready(request: Request, response: Response) -> dict[str, Any]:
    """Dependency status.

    MongoDB is required: without it the response is 503. Redis and the worker
    are needed only for background analysis, so their absence is reported as
    `degraded` with a 200.
    """
    mongo_ok = ping(request.app.state.db)
    redis_ok, heartbeat = _redis_state(request.app.state.redis)
    worker_ok = heartbeat is not None

    if not mongo_ok:
        overall = "unavailable"
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    elif redis_ok and worker_ok:
        overall = "ok"
    else:
        overall = "degraded"

    return {
        "status": overall,
        "checks": {
            "mongodb": {"ok": mongo_ok},
            "redis": {"ok": redis_ok},
            "worker": {"ok": worker_ok, "last_heartbeat": heartbeat},
        },
        "time": datetime.now(timezone.utc),
    }
