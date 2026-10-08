"""Request-scoped dependencies: settings, database, current user."""

from __future__ import annotations

from typing import Annotated, Any

from bson import ObjectId
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pymongo.database import Database

from app.auth.tokens import InvalidToken, decode_access_token
from app.config.settings import Settings
from app.models.collections import USERS

_bearer = HTTPBearer(auto_error=False)


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


def get_db(request: Request) -> Database:
    return request.app.state.db


SettingsDep = Annotated[Settings, Depends(get_settings_dep)]
DbDep = Annotated[Database, Depends(get_db)]


def _unauthorised() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    settings: SettingsDep,
    db: DbDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> dict[str, Any]:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _unauthorised()
    try:
        user_id = decode_access_token(settings, credentials.credentials)
    except InvalidToken:
        raise _unauthorised() from None
    if not ObjectId.is_valid(user_id):
        raise _unauthorised()
    user = db[USERS].find_one({"_id": ObjectId(user_id)})
    if user is None or not user.get("is_active", False):
        raise _unauthorised()
    return user


CurrentUser = Annotated[dict[str, Any], Depends(get_current_user)]
