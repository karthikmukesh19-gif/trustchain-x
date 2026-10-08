"""Sliding-window rate limiter.

Counters live in process memory, so each backend process counts on its own.
That is sufficient for a single-process deployment; Redis-backed counters are
scheduled for Phase 14 (see docs/architecture.md, known limitations).
"""

from __future__ import annotations

import math
import threading
import time
from collections import deque
from typing import Callable

from fastapi import HTTPException, Request, status

MAX_TRACKED_KEYS = 50_000


class RateLimiter:
    def __init__(self, limit: int, window_seconds: float, clock: Callable[[], float] = time.monotonic):
        self.limit = limit
        self.window = float(window_seconds)
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, float]:
        """Record a hit. Returns (allowed, seconds until the next slot frees)."""
        now = self._clock()
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                if len(self._hits) >= MAX_TRACKED_KEYS:
                    self._prune(now)
                hits = self._hits[key] = deque()
            while hits and now - hits[0] >= self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False, max(0.0, self.window - (now - hits[0]))
            hits.append(now)
            return True, 0.0

    def _prune(self, now: float) -> None:
        stale = [k for k, v in self._hits.items() if not v or now - v[-1] >= self.window]
        for k in stale:
            del self._hits[k]
        if len(self._hits) >= MAX_TRACKED_KEYS:
            # Still full of live keys: drop the oldest half rather than grow without bound.
            for k in list(self._hits)[: MAX_TRACKED_KEYS // 2]:
                del self._hits[k]

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


def client_address(request: Request) -> str:
    """The peer address. Forwarding headers are ignored because they are client-controlled."""
    return request.client.host if request.client else "unknown"


def auth_rate_limit(request: Request) -> None:
    """FastAPI dependency: limit authentication attempts per client address."""
    limiter: RateLimiter = request.app.state.auth_limiter
    allowed, retry_after = limiter.check(client_address(request))
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many attempts. Try again later.",
            headers={"Retry-After": str(max(1, math.ceil(retry_after)))},
        )


def job_rate_limit(request: Request) -> None:
    """FastAPI dependency: limit how often one client may start background jobs or provider checks.

    These requests cause outbound calls to GitHub or a vulnerability provider,
    so they are bounded to protect the platform's quota with those services.
    """
    limiter: RateLimiter = request.app.state.job_limiter
    allowed, retry_after = limiter.check(client_address(request))
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many jobs requested. Try again later.",
            headers={"Retry-After": str(max(1, math.ceil(retry_after)))},
        )
