"""Application settings, read from environment variables.

No secret has a usable default. In production the application refuses to
start unless JWT_SECRET is set and long enough. Outside production a missing
secret is replaced by a random one generated for the lifetime of the process,
so tokens stop working on restart but nothing is ever hard-coded.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import secrets
from functools import lru_cache
from typing import Mapping
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

logger = logging.getLogger(__name__)

MIN_SECRET_LENGTH = 32


KNOWN_VULNERABILITY_PROVIDERS = ("osv",)
KNOWN_METADATA_PROVIDERS = ("pypi", "npm")


def validate_provider_url(setting: str, value: str, allowed_hosts: tuple[str, ...],
                          allow_list: str = "VULNERABILITY_ALLOWED_HOSTS") -> str:
    """Accept only a plain https base URL whose host is in the allow-list."""
    value = (value or "").strip().rstrip("/")
    if any(ch.isspace() or ord(ch) < 0x20 for ch in value) or "\\" in value:
        raise ValueError(f"{setting} contains forbidden characters")
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"{setting} is not a valid URL") from exc
    if parts.scheme != "https":
        raise ValueError(f"{setting} must use https")
    if parts.username is not None or parts.password is not None:
        raise ValueError(f"{setting} must not contain credentials")
    if parts.query or parts.fragment:
        raise ValueError(f"{setting} must not contain a query or fragment")
    if port not in (None, 443):
        raise ValueError(f"{setting} must use the default https port")
    host = (parts.hostname or "").lower()
    if not host or host not in allowed_hosts:
        raise ValueError(f"{setting} host {host or '(none)'!r} is not in {allow_list}")
    if internal_host(host):
        # Refused even when listed: an outbound data source is a public service, never an address inside the deployment.
        raise ValueError(f"{setting} host {host!r} is an IP address or an internal name; a public host name is required")
    return f"https://{host}{parts.path.rstrip('/')}"


_INTERNAL_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home", ".corp", ".intranet", ".svc", ".cluster.local")


def internal_host(host: str) -> bool:
    """Whether a host is an IP literal (of any range), a single-label name, or a name reserved for internal use.

    Outbound sources are named public services. This check is on the name only: it does not resolve it, so it does
    not defend against a public name that resolves to a private address. Redirects are refused separately.
    """
    host = host.strip("[]").rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if host.replace(".", "").isdigit() or host.startswith("0x"):          # decimal, dotted-short or hexadecimal address forms
        return True
    return "." not in host or host == "localhost" or host.endswith(_INTERNAL_SUFFIXES)


GITHUB_TOKEN_PLACEHOLDERS = frozenset({"your_github_token_here", "changeme", "<your-token>", "your-token-here"})
AI_PROVIDERS = ("deterministic",)


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

    # Background jobs and provider checks one client may start per window.
    job_rate_limit: int = Field(default=30, ge=1)
    job_rate_window_seconds: int = Field(default=60, ge=1)

    github_api_url: str = "https://api.github.com"
    # The GitHub API host must be listed here, like every other outbound host. Only GitHub Enterprise installations change it.
    github_allowed_hosts: tuple[str, ...] = ("api.github.com",)
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

    # Vulnerability intelligence. Provider endpoints come from configuration
    # only; no request can supply or alter them. The host of every provider URL
    # must also appear in the allow-list, so a mistyped or injected setting
    # cannot point the platform at an arbitrary server.
    vulnerability_providers: tuple[str, ...] = ("osv",)
    vulnerability_allowed_hosts: tuple[str, ...] = ("api.osv.dev",)
    osv_api_url: str = "https://api.osv.dev"
    vulnerability_timeout_seconds: float = Field(default=15.0, gt=0, le=120)
    vulnerability_batch_size: int = Field(default=500, ge=1, le=1000)          # packages per provider query
    vulnerability_max_records: int = Field(default=5000, ge=1)                 # advisories fetched per sync
    vulnerability_max_record_bytes: int = Field(default=2_097_152, ge=1024)    # one advisory (2 MiB)
    vulnerability_sync_timeout_seconds: int = Field(default=600, ge=5)

    # Code reachability. Source files are fetched by git blob id and parsed as data; nothing is executed.
    reachability_max_files: int = Field(default=2000, ge=1)                    # source files analysed per run
    reachability_max_file_bytes: int = Field(default=524_288, ge=1024)         # one source file (512 KiB)
    reachability_max_total_bytes: int = Field(default=33_554_432, ge=1024)     # all source files together (32 MiB)
    reachability_max_nodes_per_file: int = Field(default=200_000, ge=1000)     # syntax-tree nodes visited per file
    reachability_max_edges: int = Field(default=300_000, ge=1000)              # edges kept in the code graph
    reachability_timeout_seconds: int = Field(default=600, ge=5)
    # Operator-maintained mapping of advisories to affected functions. Empty by default; never a URL.
    reachability_symbol_mappings_file: str = ""

    # Dependency intelligence (fragility, graph risk, predictive indicators). Release metadata comes from package
    # registries whose URLs are fixed here and whose hosts must be in the allow-list; an empty provider list turns
    # the lookups off, and version and release-age factors are then reported as unknown.
    package_metadata_providers: tuple[str, ...] = ("pypi", "npm")
    package_metadata_allowed_hosts: tuple[str, ...] = ("pypi.org", "registry.npmjs.org")
    pypi_api_url: str = "https://pypi.org"
    npm_registry_url: str = "https://registry.npmjs.org"
    package_metadata_timeout_seconds: float = Field(default=15.0, gt=0, le=120)
    package_metadata_max_bytes: int = Field(default=16_777_216, ge=1024)        # one registry answer (16 MiB)
    package_metadata_ttl_hours: int = Field(default=24, ge=0)                    # how long a cached answer is reused
    package_metadata_max_packages: int = Field(default=2000, ge=0)               # registry lookups per analysis
    intelligence_max_nodes: int = Field(default=5000, ge=10)                     # packages in an analysed graph
    intelligence_max_edges: int = Field(default=50_000, ge=10)
    intelligence_timeout_seconds: int = Field(default=600, ge=5)
    intelligence_history_limit: int = Field(default=50, ge=2)                    # analyses kept per project and kind

    # Attack-path simulation. A static search over stored evidence; every bound below keeps it finite.
    attack_path_max_depth: int = Field(default=12, ge=1, le=64)                  # dependency steps in one path
    attack_path_max_paths: int = Field(default=500, ge=1, le=5000)               # paths stored per analysis
    attack_path_max_routes: int = Field(default=3, ge=1, le=10)                  # dependency chains listed per path
    attack_path_max_expansions: int = Field(default=20_000, ge=100)              # search steps per vulnerable package
    attack_path_graph_max_nodes: int = Field(default=400, ge=10, le=5000)        # nodes in the combined graph view

    # Maintainer behaviour and commit behaviour. Both read public GitHub metadata through the configured API host;
    # commit content is analysed as text and never executed.
    maintainer_max_commits: int = Field(default=500, ge=1, le=5000)              # commits read per maintainer analysis
    maintainer_max_releases: int = Field(default=100, ge=0, le=1000)
    commit_analysis_max_commits: int = Field(default=30, ge=1, le=200)           # commits analysed per run
    commit_baseline_commits: int = Field(default=100, ge=5, le=1000)             # earlier commits a baseline is built from
    commit_max_files: int = Field(default=300, ge=1, le=3000)                    # changed files inspected per commit
    commit_max_patch_bytes: int = Field(default=200_000, ge=1024)                # diff text inspected per file
    commit_poll_interval_minutes: int = Field(default=0, ge=0, le=10_080)        # 0: no automatic polling
    behaviour_timeout_seconds: int = Field(default=300, ge=5)

    # Cross-layer reasoning. "deterministic" is the built-in rule engine; it needs no external service.
    ai_provider: str = "deterministic"
    # Dataset validation and the trust engine.
    dataset_max_records: int = Field(default=30_000, ge=1)
    trust_min_coverage: float = Field(default=0.6, ge=0.0, le=1.0)               # share of weight that must be known

    @field_validator("ai_provider")
    @classmethod
    def _known_ai_provider(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in AI_PROVIDERS:
            raise ValueError(f"AI_PROVIDER must be one of: {', '.join(AI_PROVIDERS)}")
        return value

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

    @field_validator("vulnerability_providers")
    @classmethod
    def _known_providers(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        value = tuple(v.lower() for v in value)
        unknown = [v for v in value if v not in KNOWN_VULNERABILITY_PROVIDERS]
        if unknown:
            raise ValueError(f"VULNERABILITY_PROVIDERS contains unknown provider(s): {', '.join(unknown)}")
        return value

    @field_validator("vulnerability_allowed_hosts", "package_metadata_allowed_hosts", "github_allowed_hosts")
    @classmethod
    def _lower_hosts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(v.lower() for v in value)

    @field_validator("package_metadata_providers")
    @classmethod
    def _known_metadata_providers(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        value = tuple(v.lower() for v in value)
        unknown = [v for v in value if v not in KNOWN_METADATA_PROVIDERS]
        if unknown:
            raise ValueError(f"PACKAGE_METADATA_PROVIDERS contains unknown provider(s): {', '.join(unknown)}")
        return value

    @model_validator(mode="after")
    def _provider_urls_are_safe(self) -> "Settings":
        object.__setattr__(self, "github_api_url", validate_provider_url(
            "GITHUB_API_URL", self.github_api_url, self.github_allowed_hosts, "GITHUB_ALLOWED_HOSTS"))
        if "osv" in self.vulnerability_providers:
            object.__setattr__(self, "osv_api_url", validate_provider_url("OSV_API_URL", self.osv_api_url, self.vulnerability_allowed_hosts))
        for provider, field_name, setting in (("pypi", "pypi_api_url", "PYPI_API_URL"), ("npm", "npm_registry_url", "NPM_REGISTRY_URL")):
            if provider in self.package_metadata_providers:
                object.__setattr__(self, field_name, validate_provider_url(
                    setting, getattr(self, field_name), self.package_metadata_allowed_hosts, "PACKAGE_METADATA_ALLOWED_HOSTS"))
        return self

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
        "JOB_RATE_LIMIT": "job_rate_limit",
        "JOB_RATE_WINDOW_SECONDS": "job_rate_window_seconds",
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
        "REACHABILITY_MAX_FILES": "reachability_max_files",
        "REACHABILITY_MAX_FILE_BYTES": "reachability_max_file_bytes",
        "REACHABILITY_MAX_TOTAL_BYTES": "reachability_max_total_bytes",
        "REACHABILITY_MAX_NODES_PER_FILE": "reachability_max_nodes_per_file",
        "REACHABILITY_MAX_EDGES": "reachability_max_edges",
        "REACHABILITY_TIMEOUT_SECONDS": "reachability_timeout_seconds",
        "REACHABILITY_SYMBOL_MAPPINGS_FILE": "reachability_symbol_mappings_file",
        "PYPI_API_URL": "pypi_api_url",
        "NPM_REGISTRY_URL": "npm_registry_url",
        "PACKAGE_METADATA_TIMEOUT_SECONDS": "package_metadata_timeout_seconds",
        "PACKAGE_METADATA_MAX_BYTES": "package_metadata_max_bytes",
        "PACKAGE_METADATA_TTL_HOURS": "package_metadata_ttl_hours",
        "PACKAGE_METADATA_MAX_PACKAGES": "package_metadata_max_packages",
        "INTELLIGENCE_MAX_NODES": "intelligence_max_nodes",
        "INTELLIGENCE_MAX_EDGES": "intelligence_max_edges",
        "INTELLIGENCE_TIMEOUT_SECONDS": "intelligence_timeout_seconds",
        "INTELLIGENCE_HISTORY_LIMIT": "intelligence_history_limit",
        "ATTACK_PATH_MAX_DEPTH": "attack_path_max_depth",
        "ATTACK_PATH_MAX_PATHS": "attack_path_max_paths",
        "ATTACK_PATH_MAX_ROUTES": "attack_path_max_routes",
        "ATTACK_PATH_MAX_EXPANSIONS": "attack_path_max_expansions",
        "ATTACK_PATH_GRAPH_MAX_NODES": "attack_path_graph_max_nodes",
        "MAINTAINER_MAX_COMMITS": "maintainer_max_commits",
        "MAINTAINER_MAX_RELEASES": "maintainer_max_releases",
        "COMMIT_ANALYSIS_MAX_COMMITS": "commit_analysis_max_commits",
        "COMMIT_BASELINE_COMMITS": "commit_baseline_commits",
        "COMMIT_MAX_FILES": "commit_max_files",
        "COMMIT_MAX_PATCH_BYTES": "commit_max_patch_bytes",
        "COMMIT_POLL_INTERVAL_MINUTES": "commit_poll_interval_minutes",
        "BEHAVIOUR_TIMEOUT_SECONDS": "behaviour_timeout_seconds",
        "AI_PROVIDER": "ai_provider",
        "DATASET_MAX_RECORDS": "dataset_max_records",
        "TRUST_MIN_COVERAGE": "trust_min_coverage",
        "OSV_API_URL": "osv_api_url",
        "VULNERABILITY_TIMEOUT_SECONDS": "vulnerability_timeout_seconds",
        "VULNERABILITY_BATCH_SIZE": "vulnerability_batch_size",
        "VULNERABILITY_MAX_RECORDS": "vulnerability_max_records",
        "VULNERABILITY_MAX_RECORD_BYTES": "vulnerability_max_record_bytes",
        "VULNERABILITY_SYNC_TIMEOUT_SECONDS": "vulnerability_sync_timeout_seconds",
    }
    for key, field in simple.items():
        raw = env.get(key, "").strip()
        if raw:
            values[field] = raw
    if env.get("CORS_ORIGINS", "").strip():
        values["cors_origins"] = _split(env["CORS_ORIGINS"])
    if "VULNERABILITY_PROVIDERS" in env:
        # An explicitly empty value disables vulnerability intelligence.
        values["vulnerability_providers"] = _split(env["VULNERABILITY_PROVIDERS"])
    if "PACKAGE_METADATA_PROVIDERS" in env:
        # An explicitly empty value turns registry lookups off.
        values["package_metadata_providers"] = _split(env["PACKAGE_METADATA_PROVIDERS"])
    if env.get("PACKAGE_METADATA_ALLOWED_HOSTS", "").strip():
        values["package_metadata_allowed_hosts"] = _split(env["PACKAGE_METADATA_ALLOWED_HOSTS"])
    if env.get("GITHUB_ALLOWED_HOSTS", "").strip():
        values["github_allowed_hosts"] = _split(env["GITHUB_ALLOWED_HOSTS"])
    if env.get("VULNERABILITY_ALLOWED_HOSTS", "").strip():
        values["vulnerability_allowed_hosts"] = _split(env["VULNERABILITY_ALLOWED_HOSTS"])
    token = env.get("GITHUB_TOKEN", "").strip()
    # The placeholder from .env.example is not a token: sending it would make GitHub reject every request.
    if token and token.lower() not in GITHUB_TOKEN_PLACEHOLDERS:
        values["github_token"] = token

    try:
        return Settings(**values)
    except ValueError as exc:
        raise SettingsError(str(exc)) from exc


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return load_settings()
