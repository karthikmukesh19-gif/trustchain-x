"""JWT access tokens."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

import jwt

from app.config.settings import Settings

TOKEN_TYPE = "access"


class InvalidToken(Exception):
    """The token is missing, malformed, expired or not signed by us."""


def create_access_token(settings: Settings, user_id: str, now: datetime | None = None) -> tuple[str, int]:
    """Return (token, lifetime in seconds)."""
    now = now or datetime.now(timezone.utc)
    lifetime = timedelta(minutes=settings.jwt_expire_minutes)
    payload = {
        "sub": user_id,
        "type": TOKEN_TYPE,
        "iat": now,
        "exp": now + lifetime,
        "jti": secrets.token_urlsafe(12),
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, int(lifetime.total_seconds())


def decode_access_token(settings: Settings, token: str) -> str:
    """Validate a token and return the user id it was issued to."""
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["sub", "exp", "iat", "type"]},
        )
    except jwt.PyJWTError as exc:
        raise InvalidToken(str(exc)) from exc
    if payload.get("type") != TOKEN_TYPE or not isinstance(payload.get("sub"), str):
        raise InvalidToken("wrong token type")
    return payload["sub"]
