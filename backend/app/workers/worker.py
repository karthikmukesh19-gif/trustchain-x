"""Background worker process.

Runs every background job type and, when polling is configured, queues periodic commit checks. A heartbeat thread reports liveness
independently of the job loop, so a long analysis does not make the worker
look dead.

Run with:  python -m app.workers.worker
"""

from __future__ import annotations

import logging
import signal
import threading
from typing import Any

import redis

from app.collectors.github import GitHubClient
from app.collectors.providers import build_providers
from app.collectors.registries import build_registries
from app.config.settings import Settings, get_settings
from app.models.database import create_client, ensure_indexes, ping
from app.services import analysis, behaviour, jobs
from app.workers.heartbeat import beat

logger = logging.getLogger("trustchain.worker")


def heartbeat_loop(settings: Settings, redis_client: Any, stop: threading.Event) -> int:
    """Publish a heartbeat until stopped. Returns the number published."""
    beats = 0
    while not stop.is_set():
        try:
            beat(redis_client, settings.worker_heartbeat_seconds)
            beats += 1
        except Exception:  # noqa: BLE001 - Redis being down must not stop the worker
            logger.warning("Redis is not reachable; heartbeat skipped")
        stop.wait(settings.worker_heartbeat_seconds)
    return beats


def process_available_jobs(settings: Settings, db: Any, github: GitHubClient, stop: threading.Event | None = None,
                           providers: dict[str, Any] | None = None, registries: dict[str, Any] | None = None) -> int:
    """Run queued jobs until none are left. Returns how many were run."""
    processed = 0
    if providers is None:
        providers = build_providers(settings)
    if registries is None:
        registries = build_registries(settings)
    analysis.fail_stale_jobs(db, settings)
    while stop is None or not stop.is_set():
        job = analysis.claim_next_job(db)
        if job is not None:
            logger.info("Running analysis job %s for project %s", job["_id"], job["project_id"])
            finished = analysis.run_job(db, github, settings, job)
        else:
            job = jobs.claim_next_job(db)
            if job is None:
                break
            logger.info("Running %s job %s for project %s", job["type"], job["_id"], job["project_id"])
            finished = jobs.run_job(db, settings, providers, job, github, registries)
        logger.info("Job %s finished: %s", job["_id"], finished["state"])
        processed += 1
    return processed


def wait_for_work(redis_client: Any, timeout: int, stop: threading.Event) -> None:
    """Block until a job is announced or the timeout passes. MongoDB is re-checked either way."""
    try:
        redis_client.brpop(analysis.QUEUE_KEY, timeout=timeout)
    except Exception:  # noqa: BLE001 - fall back to plain polling when Redis is unavailable
        stop.wait(timeout)


def run(settings: Settings, redis_client: Any, db: Any, github: GitHubClient, stop: threading.Event,
        providers: dict[str, Any] | None = None, registries: dict[str, Any] | None = None) -> None:
    poll = max(1, min(settings.worker_heartbeat_seconds, 5))
    if providers is None:
        providers = build_providers(settings)
    if registries is None:
        registries = build_registries(settings)
    while not stop.is_set():
        try:
            if ping(db):
                behaviour.poll_due(db, redis_client, settings)      # queues commit checks for monitored projects, when polling is on
                process_available_jobs(settings, db, github, stop, providers, registries)
            else:
                logger.warning("MongoDB is not reachable")
        except Exception:  # noqa: BLE001 - keep the worker alive; the job itself records failures
            logger.exception("Worker loop error")
        if not stop.is_set():
            wait_for_work(redis_client, poll, stop)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = get_settings()
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())

    mongo = create_client(settings)
    db = mongo[settings.mongodb_db]
    # Blocking pops wait up to `poll` seconds, so the socket timeout must be longer than that.
    redis_client = redis.Redis.from_url(settings.redis_url, socket_timeout=15, socket_connect_timeout=3)
    heartbeat_redis = redis.Redis.from_url(settings.redis_url, socket_timeout=3, socket_connect_timeout=3)
    github = GitHubClient(settings)
    try:
        ensure_indexes(db)
    except Exception:  # noqa: BLE001 - the API also ensures indexes; retry happens on the next start
        logger.warning("Could not ensure MongoDB indexes at start-up")
    threading.Thread(target=heartbeat_loop, args=(settings, heartbeat_redis, stop), name="heartbeat", daemon=True).start()
    logger.info("Worker started (analyzer %s)", analysis.ANALYZER_VERSION)
    try:
        run(settings, redis_client, db, github, stop)
    finally:
        stop.set()
        mongo.close()
        redis_client.close()
        heartbeat_redis.close()
        logger.info("Worker stopped")


if __name__ == "__main__":
    main()
