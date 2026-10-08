"""MongoDB connection and index management."""

from __future__ import annotations

import logging

from pymongo import MongoClient
from pymongo.database import Database
from pymongo.errors import OperationFailure

from app.config.settings import Settings
from app.models.collections import INDEXES

logger = logging.getLogger(__name__)


def create_client(settings: Settings) -> MongoClient:
    return MongoClient(
        settings.mongodb_uri,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=5000,
        tz_aware=True,
        appname=settings.app_name,
    )


def ensure_indexes(db: Database) -> None:
    """Make each collection's indexes match the declaration. Safe to call repeatedly.

    Indexes that an earlier version declared and this one no longer does are
    dropped: a stale unique index would otherwise reject valid documents.
    """
    for collection, indexes in INDEXES.items():
        declared = {tuple(index.keys) for index in indexes}
        try:
            existing = db[collection].index_information()
        except Exception:  # noqa: BLE001 - the collection may not exist yet
            existing = {}
        for name, info in existing.items():
            keys = tuple((key, int(direction)) for key, direction in info.get("key", []) if isinstance(direction, (int, float)))
            if name != "_id_" and keys not in declared:
                try:
                    db[collection].drop_index(name)
                    logger.info("Dropped obsolete index %s on %s", name, collection)
                except OperationFailure:
                    # The API and the worker start together and both migrate;
                    # the other process has already dropped this index.
                    logger.info("Obsolete index %s on %s was already dropped", name, collection)
        for index in indexes:
            db[collection].create_index(list(index.keys), **index.options)
    logger.info("MongoDB indexes ensured for %d collections", len(INDEXES))


def ping(db: Database) -> bool:
    try:
        return db.command("ping").get("ok") == 1
    except Exception as exc:  # noqa: BLE001 - any failure means "not reachable"
        logger.warning("MongoDB ping failed: %s", type(exc).__name__)
        return False
