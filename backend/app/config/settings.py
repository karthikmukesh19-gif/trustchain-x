"""Application settings, read from environment variables.

No secret has a usable default. In production the application refuses to
start unless JWT_SECRET is set and long enough. Outside production a missing
secret is replaced by a random one generated for the lifetime of the process,
so tokens stop working on restart but nothing is ever hard-coded.
"""

from __future__ import annotations

import logging
import os
import secrets
from functools import lru_cache
from typing import Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator

logger = logging.getLogger(__name__)

MIN_SECRET_LENGTH = 32


class SettingsError(RuntimeError):
    """Raised when the configuration is unsafe or invalid."""


class Settings(BaseModel):
    model_config = ConfigDict(frozen=True)

    app_env: str = "development"
    app_name: str = "TrustChain-X"

    mongodb_uri: str = "mongodb://localhost:27017"
    mongodb_db: str = "trustchain_x"
    redis_url: str = "redis://localhost:6379/0"

    jwt_secret: str = Field(repr=False)
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = Field(default=60, ge=1, le=24 * 60)

    cors_origins: tuple[str, ...] = ("http://localhost:5173",)

    auth_rate_limit: int = Field(default=10, ge=1)
    auth_rate_window_seconds: int = Field(default=60, ge=1)

    max_request_bytes: int = Field(default=1_048_576, ge=1024)

    github_api_url: str = "https://api.github.com"
    github_token: str | None = Field(default=None, repr=False)
    github_timeout_seconds: float = Field(default=8.0, gt=0, le=60)

    worker_heartbeat_seconds: int = Field(default=10, ge=1)

    # Repository analysis limits. A repository beyond any of them is refused
    # with a structured error instead of being partially analysed.
    analysis_max_repo_kb: int = Field(default=2_097_152, ge=1)          # size reported by GitHub (2 GiB)
    analysis_max_files: int = Field(default=25_000, ge=1)               # entries in the file listing
    analysis_max_manifests: int = Field(default=300, ge=1)              # dependency files read per analysis
    analysis_max_manifest_bytes: int = Field(default=8_388_608, ge=1024)  # one dependency file (8 MiB)
    analysis_max_total_bytes: int = Field(default=67_108_864, ge=1024)    # all dependency files together (64 MiB)
    analysis_max_dependencies: int = Field(default=30_000, ge=1)
    analysis_timeout_seconds: int = Field(default=300, ge=5)
    analysis_stale_job_seconds: int = Field(default=900, ge=30)

    @field_validator("app_env")
    @classmethod
    def _known_env(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in {"development", "test", "production"}:
            raise ValueError("APP_ENV must be development, test or production")
        return value

    @field_validator("jwt_algorithm")
    @classmethod
    def _allowed_algorithm(cls, value: str) -> str:
        if value not in {"HS256", "HS384", "HS512"}:
            raise ValueError("JWT_ALGORITHM must be HS256, HS384 or HS512")
        return value

    @field_validator("cors_origins")
    @classmethod
    def _no_wildcard(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(origin == "*" for origin in value):
            raise ValueError("CORS_ORIGINS must list explicit origins, not '*'")
        return value

    @field_validator("github_api_url")
    @classmethod
    def _https_only(cls, value: str) -> str:
        value = value.rstrip("/")
        if not value.startswith("https://"):
            raise ValueError("GITHUB_API_URL must use https")
        return value

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


def _split(value: str) -> tuple[str, ...]:
    return tuple(part.strip().rstrip("/") for part in value.split(",") if part.strip())


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    """Build Settings from an environment mapping (os.environ by default)."""
    env = os.environ if env is None else env
    app_env = env.get("APP_ENV", "development").strip().lower()

    secret = env.get("JWT_SECRET", "").strip()
    if app_env == "production":
        if len(secret) < MIN_SECRET_LENGTH:
            raise SettingsError(
                f"JWT_SECRET must be set to at least {MIN_SECRET_LENGTH} characters in production"
            )
    elif not secret:
        secret = secrets.token_urlsafe(48)
        logger.warning(
            "JWT_SECRET is not set; using a random secret for this process. "
            "Tokens will be invalid after a restart."
        )
    elif len(secret) < MIN_SECRET_LENGTH:
        raise SettingsError(f"JWT_SECRET must be at least {MIN_SECRET_LENGTH} characters")

    values: dict[str, object] = {"app_env": app_env, "jwt_secret": secret}
    simple = {
        "MONGODB_URI": "mongodb_uri",
        "MONGODB_DB": "mongodb_db",
        "REDIS_URL": "redis_url",
        "JWT_ALGORITHM": "jwt_algorithm",
        "JWT_EXPIRE_MINUTES": "jwt_expire_minutes",
        "AUTH_RATE_LIMIT": "auth_rate_limit",
        "AUTH_RATE_WINDOW_SECONDS": "auth_rate_window_seconds",
        "MAX_REQUEST_BYTES": "max_request_bytes",
        "GITHUB_API_URL": "github_api_url",
        "GITHUB_TIMEOUT_SECONDS": "github_timeout_seconds",
        "WORKER_HEARTBEAT_SECONDS": "worker_heartbeat_seconds",
        "ANALYSIS_MAX_REPO_KB": "analysis_max_repo_kb",
        "ANALYSIS_MAX_FILES": "analysis_max_files",
        "ANALYSIS_MAX_MANIFESTS": "analysis_max_manifests",
        "ANALYSIS_MAX_MANIFEST_BYTES": "analysis_max_manifest_bytes",
        "ANALYSIS_MAX_TOTAL_BYTES": "analysis_max_total_bytes",
        "ANALYSIS_MAX_DEPENDENCIES": "analysis_max_dependencies",
        "ANALYSIS_TIMEOUT_SECONDS": "analysis_timeout_seconds",
        "ANALYSIS_STALE_JOB_SECONDS": "analysis_stale_job_seconds",
    }
    for key, field in simple.items():
        raw = env.get(key, "").strip()
        if raw:
            values[field] = raw
    if env.get("CORS_ORIGINS", "").strip():
        values["cors_origins"] = _split(env["CORS_ORIGINS"])
    if env.get("GITHUB_TOKEN", "").strip():
        values["github_token"] = env["GITHUB_TOKEN"].strip()

    try:
        return Settings(**values)
    except ValueError as exc:
        raise SettingsError(str(exc)) from exc


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return load_settings()
