"""Worker liveness signal shared by the worker and the health endpoint."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

HEARTBEAT_KEY = "trustchain:worker:heartbeat"


def beat(redis_client: Any, interval_seconds: int) -> str:
    """Publish a heartbeat that expires after three missed intervals."""
    stamp = datetime.now(timezone.utc).isoformat()
    redis_client.set(HEARTBEAT_KEY, stamp, ex=interval_seconds * 3)
    return stamp
