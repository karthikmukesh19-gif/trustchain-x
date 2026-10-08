"""Provider contract and the normalised vulnerability shape.

A provider answers two questions about packages the platform has observed -
"which advisories mention this package version?" and "what does advisory X
say?" - and converts its own record format into the normalised form below.
Nothing outside a provider module knows a provider's wire format.

Normalised vulnerability (what `normalize` returns)

    source              provider name, e.g. "osv"
    source_id           the provider's id for the record
    source_url          human-readable page for the record, or None
    aliases, related    other identifiers the source gives (CVE, GHSA, ...)
    summary, details    text as published (None when absent)
    severity            CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
    severity_source     where the label came from, or None when UNKNOWN
    cvss                list of published CVSS vectors, or None
    cwe_ids             as published
    affected            [{ecosystem, source_ecosystem, package_name,
                          source_package_name, purl, versions, ranges,
                          fixed_versions, severity, cvss}]
    references          [{type, url}]
    published_at, modified_at, withdrawn_at   source timestamps (None when absent)
    raw                 the source record as received (None if over the size cap)
    raw_sha256          digest of the source record

Fields a source does not provide stay None / empty / UNKNOWN. Nothing is
filled in by estimation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterable

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


class ProviderError(Exception):
    """A provider request failed. `message` is safe to show to the user."""

    def __init__(self, code: str, message: str, retry_at: datetime | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retry_at = retry_at


class MalformedRecord(ValueError):
    """A source record cannot be normalised. The message says why."""


@dataclass(frozen=True)
class PackageQuery:
    """One observed package version to ask a provider about."""

    ecosystem: str          # platform ecosystem id (pypi, npm, maven, golang, cargo, ...)
    name: str               # name as written in the repository
    normalized_name: str
    version: str


@dataclass
class QueryResult:
    """Advisory ids a provider reports for each queried package, keyed by the query."""

    reported: dict[PackageQuery, list[str]] = field(default_factory=dict)
    unsupported: list[PackageQuery] = field(default_factory=list)   # ecosystems the provider does not cover
    modified: dict[str, str | None] = field(default_factory=dict)    # advisory id -> source "modified" stamp
    rejected: list[str] = field(default_factory=list)                # reported ids that are not valid ids
    requests: int = 0


class VulnerabilityProvider(ABC):
    name: str
    display_name: str

    @abstractmethod
    def supports(self, ecosystem: str) -> bool:
        """Whether the provider covers this platform ecosystem."""

    @abstractmethod
    def query(self, packages: Iterable[PackageQuery], progress: Callable[[int, int], None] | None = None) -> QueryResult:
        """Ask which advisories the provider reports for each package version."""

    @abstractmethod
    def fetch(self, source_id: str) -> tuple[dict[str, Any], bytes]:
        """Fetch one advisory. Returns (parsed record, raw bytes)."""

    @abstractmethod
    def normalize(self, record: dict[str, Any], raw: bytes | None = None) -> dict[str, Any]:
        """Convert a source record to the normalised form. Raises MalformedRecord."""

    @abstractmethod
    def health_check(self) -> dict[str, Any]:
        """Return {"ok": bool, "detail": str, "checked_at": datetime}. Never raises."""

    def describe(self) -> dict[str, Any]:
        """Static facts about the provider, stored in vulnerability_sources."""
        return {"name": self.name, "display_name": self.display_name}
