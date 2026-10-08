"""Package registries as a source of release metadata (latest version, release dates).

A registry client answers one question: what does the registry publish about
this package? It never guesses. A value the registry does not give is None,
and a package that cannot be looked up gets a status that says why.
"""

from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Callable

import httpx

from app.config.settings import Settings

COLLECTED = "COLLECTED"
NOT_FOUND = "NOT_FOUND"                    # the registry has no such package
ERROR = "ERROR"                            # the registry could not be read; see error_code
INVALID_NAME = "INVALID_NAME"              # the name is not one the registry could hold; no request was made

FULL = "FULL"                              # every version with its release date
COMPACT = "COMPACT"                        # latest version and version list, no release dates

USER_AGENT = "TrustChain-X/5.0 (+package metadata)"
MAX_VERSIONS = 5000
RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_ATTEMPTS = 2


class RegistryError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    # Milliseconds, the precision the database keeps: a value reads back from the cache exactly as it was fetched.
    parsed = parsed.replace(microsecond=parsed.microsecond // 1000 * 1000)
    return parsed if 1990 <= parsed.year <= 2100 else None


def newest(items: list[tuple[str, Any]], latest: Any, limit: int) -> list[tuple[str, Any]]:
    """At most `limit` entries of a registry's version list: the most recently listed, and always the latest version."""
    if len(items) <= limit:
        return items
    kept = items[-limit:]
    if isinstance(latest, str) and all(version != latest for version, _ in kept):
        kept = [item for item in items[:-limit] if item[0] == latest][:1] + kept[1:]
    return kept


class PackageRegistry(ABC):
    """One registry. Subclasses build the request and normalise the answer."""

    name: str                              # registry name, e.g. "pypi"
    ecosystem: str                         # platform ecosystem it serves
    display_name: str

    def __init__(self, settings: Settings, base_url: str, transport: httpx.BaseTransport | None = None) -> None:
        self.settings = settings
        self.base_url = base_url
        self.transport = transport
        self.sleep: Callable[[float], None] = time.sleep
        self.requests_made = 0

    @abstractmethod
    def valid_name(self, normalized_name: str) -> bool: ...

    def lookup_name(self, dependency: dict[str, Any]) -> str:
        """The name to ask this registry for. Registries whose names are case-sensitive override this."""
        return dependency["normalized_name"]

    @abstractmethod
    def lookup(self, normalized_name: str, detail: str = FULL) -> dict[str, Any]:
        """Normalised metadata for one package. Never raises for a registry problem: the status says what happened."""

    def describe(self) -> dict[str, Any]:
        return {"name": self.name, "display_name": self.display_name, "ecosystem": self.ecosystem, "base_url": self.base_url}

    def result(self, normalized_name: str, status: str, **fields: Any) -> dict[str, Any]:
        return {"ecosystem": self.ecosystem, "normalized_name": normalized_name, "registry": self.name, "status": status,
                "detail": None, "latest_version": None, "latest_published_at": None, "versions": {}, "versions_truncated": False,
                "withdrawn_versions": [], "deprecated_versions": [], "deprecated": None, "error_code": None, "source_url": None, **fields}

    def get_json(self, path: str, accept: str = "application/json") -> Any:
        """GET base_url + path. The host is fixed by configuration; redirects are not followed; the size is capped."""
        url = f"{self.base_url}{path}"
        limit = self.settings.package_metadata_max_bytes
        last: RegistryError | None = None
        with httpx.Client(transport=self.transport, timeout=self.settings.package_metadata_timeout_seconds, follow_redirects=False,
                          headers={"Accept": accept, "User-Agent": USER_AGENT}) as client:
            for attempt in range(MAX_ATTEMPTS):
                self.requests_made += 1
                try:
                    with client.stream("GET", url) as response:
                        status = response.status_code
                        chunks, received = [], 0
                        for chunk in response.iter_bytes():
                            received += len(chunk)
                            if received > limit:
                                raise RegistryError("RESPONSE_TOO_LARGE", f"{self.display_name} returned more data than the configured limit allows.")
                            chunks.append(chunk)
                except httpx.TimeoutException:
                    last = RegistryError("TIMEOUT", f"{self.display_name} did not respond in time.")
                except httpx.HTTPError:
                    last = RegistryError("UNREACHABLE", f"{self.display_name} could not be reached.")
                else:
                    if status == 200:
                        try:
                            return json.loads(b"".join(chunks))
                        except (ValueError, RecursionError):
                            raise RegistryError("BAD_RESPONSE", f"{self.display_name} returned a response that is not valid JSON.") from None
                    if status in (404, 410):
                        raise RegistryError(NOT_FOUND, f"{self.display_name} has no such package.")
                    if status not in RETRY_STATUS:
                        raise RegistryError("HTTP_ERROR", f"{self.display_name} returned HTTP {status}.")
                    last = RegistryError("RATE_LIMITED" if status == 429 else "HTTP_ERROR", f"{self.display_name} returned HTTP {status}.")
                if attempt < MAX_ATTEMPTS - 1:
                    self.sleep(0.5)
        assert last is not None
        raise last
