"""Background worker process.

Today the worker verifies its connections and publishes a heartbeat so the
platform can report whether background processing is available. The analysis
pipeline (job queue and stage execution) is added in Phase 2; until then the
worker performs no analysis and writes no analysis data.

Run with:  python -m app.workers.worker
"""

from __future__ import annotations

import logging
import signal
import threading

import redis

from app.config.settings import Settings, get_settings
from app.models.database import create_client, ping
from app.workers.heartbeat import beat

logger = logging.getLogger("trustchain.worker")


def run(settings: Settings, redis_client, db, stop: threading.Event) -> int:
    """Heartbeat loop. Returns the number of heartbeats published."""
    beats = 0
    while not stop.is_set():
        try:
            if not ping(db):
                logger.warning("MongoDB is not reachable")
            beat(redis_client, settings.worker_heartbeat_seconds)
            beats += 1
        except redis.RedisError:
            logger.warning("Redis is not reachable; heartbeat skipped", exc_info=True)
        stop.wait(settings.worker_heartbeat_seconds)
    return beats


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = get_settings()
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())

    mongo = create_client(settings)
    redis_client = redis.Redis.from_url(settings.redis_url, socket_timeout=3, socket_connect_timeout=3)
    logger.info("Worker started (heartbeat every %ss)", settings.worker_heartbeat_seconds)
    try:
        run(settings, redis_client, mongo[settings.mongodb_db], stop)
    finally:
        mongo.close()
        redis_client.close()
        logger.info("Worker stopped")


if __name__ == "__main__":
    main()
