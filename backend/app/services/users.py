"""User accounts."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pymongo.database import Database
from pymongo.errors import DuplicateKeyError

from app.models.collections import USERS
from app.security.passwords import DUMMY_HASH, hash_password, needs_rehash, verify_password


class EmailAlreadyRegistered(Exception):
    pass


def create_user(db: Database, email: str, password: str, full_name: str) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    user = {
        "email": email,
        "full_name": full_name,
        "password_hash": hash_password(password),
        "role": "user",
        "is_active": True,
        "created_at": now,
        "last_login_at": None,
    }
    try:
        user["_id"] = db[USERS].insert_one(user).inserted_id
    except DuplicateKeyError as exc:
        raise EmailAlreadyRegistered(email) from exc
    return user


def authenticate(db: Database, email: str, password: str) -> dict[str, Any] | None:
    """Return the user for valid credentials, otherwise None.

    An unknown address costs the same hash computation as a known one.
    """
    user = db[USERS].find_one({"email": email})
    if user is None:
        verify_password(password, DUMMY_HASH)
        return None
    if not verify_password(password, user["password_hash"]) or not user.get("is_active", False):
        return None
    update: dict[str, Any] = {"last_login_at": datetime.now(timezone.utc)}
    if needs_rehash(user["password_hash"]):
        update["password_hash"] = hash_password(password)
    db[USERS].update_one({"_id": user["_id"]}, {"$set": update})
    return user


def to_public(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(user["_id"]),
        "email": user["email"],
        "full_name": user["full_name"],
        "role": user.get("role", "user"),
        "created_at": user["created_at"],
    }
