"""MongoDB connection and index management."""

from __future__ import annotations

import logging

from pymongo import MongoClient
from pymongo.database import Database

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
    """Create every declared index. Safe to call repeatedly."""
    for collection, indexes in INDEXES.items():
        for index in indexes:
            db[collection].create_index(list(index.keys), **index.options)
    logger.info("MongoDB indexes ensured for %d collections", len(INDEXES))


def ping(db: Database) -> bool:
    try:
        return db.command("ping").get("ok") == 1
    except Exception as exc:  # noqa: BLE001 - any failure means "not reachable"
        logger.warning("MongoDB ping failed: %s", type(exc).__name__)
        return False
