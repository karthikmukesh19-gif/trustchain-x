"""FastAPI application factory."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any

import httpx
import redis
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import __version__
from app.api import analysis, auth, dashboard, health, jobs, projects, sbom, vulnerabilities
from app.collectors.github import GitHubClient
from app.collectors.providers import build_providers
from app.config.settings import Settings, get_settings
from app.models.database import create_client, ensure_indexes
from app.security.headers import BodySizeLimitMiddleware, SecurityHeadersMiddleware
from app.security.rate_limit import RateLimiter

logger = logging.getLogger(__name__)


def create_app(
    settings: Settings | None = None,
    *,
    mongo_client: Any = None,
    redis_client: Any = None,
    github_transport: httpx.BaseTransport | None = None,
    provider_transport: httpx.BaseTransport | None = None,
) -> FastAPI:
    """Build the application.

    The clients are parameters so that callers decide what the application
    talks to. With none supplied, real clients are created from settings.
    """
    settings = settings or get_settings()
    owns_mongo = mongo_client is None
    owns_redis = redis_client is None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        client = mongo_client if mongo_client is not None else create_client(settings)
        app.state.mongo = client
        app.state.db = client[settings.mongodb_db]
        ensure_indexes(app.state.db)
        app.state.redis = (
            redis_client
            if redis_client is not None
            else redis.Redis.from_url(settings.redis_url, socket_timeout=2, socket_connect_timeout=2)
        )
        try:
            yield
        finally:
            if owns_mongo:
                client.close()
            if owns_redis:
                app.state.redis.close()

    docs = None if settings.is_production else "/docs"
    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description="Predictive and Self-Verifying Software Supply Chain Security Platform",
        lifespan=lifespan,
        docs_url=docs,
        redoc_url=None,
        openapi_url=None if settings.is_production else "/openapi.json",
    )
    app.state.settings = settings
    app.state.auth_limiter = RateLimiter(settings.auth_rate_limit, settings.auth_rate_window_seconds)
    app.state.github = GitHubClient(settings, transport=github_transport)
    app.state.providers = build_providers(settings, transport=provider_transport)
    app.state.job_limiter = RateLimiter(settings.job_rate_limit, settings.job_rate_window_seconds)

    # Outermost first: headers on every response, then the size cap, then CORS.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
        max_age=600,
    )
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes)
    app.add_middleware(SecurityHeadersMiddleware)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        # The default handler echoes the rejected input back, which would
        # return a submitted password in the response. Report location and
        # message only.
        errors = [
            {"loc": [str(part) for part in error.get("loc", ())], "msg": error.get("msg", "Invalid value")}
            for error in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": errors})

    @app.exception_handler(Exception)
    async def unhandled_error(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(projects.router)
    app.include_router(analysis.router)
    app.include_router(jobs.router)
    app.include_router(vulnerabilities.providers_router)
    app.include_router(vulnerabilities.router)
    app.include_router(sbom.router)
    app.include_router(dashboard.router)
    return app


def app_factory() -> FastAPI:
    """Entry point for `uvicorn app.main:app_factory --factory`."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    return create_app()
