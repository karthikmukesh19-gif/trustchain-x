"""OSV (https://osv.dev) vulnerability provider.

Two endpoints are used, both on the configured base URL:

    POST /v1/querybatch    which advisories does OSV report for these package versions?
    GET  /v1/vulns/{id}    the full advisory record

The base URL comes from configuration and is validated at start-up (https,
allow-listed host). Advisory ids are checked against a strict pattern before
they are placed in a path, redirects are not followed, and every response is
size-capped, so neither user input nor a provider response can steer a
request elsewhere.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

import httpx

from app.analyzers.normalize import normalize_name
from app.analyzers.vulnerabilities import cvss as cvss_module
from app.collectors.providers.base import MalformedRecord, PackageQuery, ProviderError, QueryResult, VulnerabilityProvider
from app.config.settings import Settings

USER_AGENT = "TrustChain-X/0.3 (vulnerability intelligence)"
NORMALIZER_VERSION = "osv-1"

# Platform ecosystem id -> OSV ecosystem name.
ECOSYSTEMS = {"pypi": "PyPI", "npm": "npm", "maven": "Maven", "golang": "Go", "cargo": "crates.io", "conan": "ConanCenter"}
FROM_OSV = {value.lower(): key for key, value in ECOSYSTEMS.items()}

ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}")   # always used with fullmatch
MAX_EVENTS = 400
MAX_RANGES = 50
RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_ATTEMPTS = 3
MAX_RETRY_AFTER = 30.0
MAX_QUERY_BYTES = 32 * 1024 * 1024
MAX_PAGES = 20
MAX_RAW_STORED = 512 * 1024
MAX_AFFECTED = 500
MAX_VERSIONS = 5000
MAX_REFERENCES = 100
EVENT_KINDS = ("introduced", "fixed", "last_affected", "limit")
SOURCE_LABELS = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "LOW"}
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _text(value: Any, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    value = _CONTROL.sub("", value.encode("utf-8", "replace").decode("utf-8")).strip()
    return value[:limit] or None


def _strings(value: Any, limit: int, each: int = 200) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        text = _text(item, each)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _cvss_list(value: Any) -> list[dict[str, Any]]:
    out = []
    if isinstance(value, list):
        for item in value[:10]:
            if isinstance(item, dict):
                record = cvss_module.describe(item.get("type"), item.get("score"))
                if record:
                    out.append(record)
    return out


def _severity(label_sources: list[Any], vectors: list[dict[str, Any]]) -> tuple[str, str | None]:
    """Severity label and where it came from. UNKNOWN when the source gives nothing usable."""
    for candidate in label_sources:
        if isinstance(candidate, str) and candidate.strip().upper() in SOURCE_LABELS:
            return SOURCE_LABELS[candidate.strip().upper()], "source_label"
    for vector in vectors:
        label = cvss_module.rating(vector.get("base_score"))
        if label:
            return label, "cvss_v3_base_score"
    return "UNKNOWN", None


def _ecosystem(value: Any) -> tuple[str | None, str | None]:
    """(platform ecosystem or None, ecosystem name as published)."""
    published = _text(value, 100)
    if not published:
        return None, None
    return FROM_OSV.get(published.split(":", 1)[0].lower()), published


def _affected(entry: Any) -> dict[str, Any] | None:
    if not isinstance(entry, dict) or not isinstance(entry.get("package"), dict):
        return None
    package = entry["package"]
    source_name = _text(package.get("name"), 300)
    ecosystem, source_ecosystem = _ecosystem(package.get("ecosystem"))
    if not source_name or not source_ecosystem:
        return None

    ranges, fixed = [], []
    ranges_truncated = False
    for item in entry.get("ranges") if isinstance(entry.get("ranges"), list) else []:
        if not isinstance(item, dict):
            continue
        kind = _text(item.get("type"), 20)
        events = []
        for event in item.get("events") if isinstance(item.get("events"), list) else []:
            if isinstance(event, dict):
                for name in EVENT_KINDS:
                    value = _text(event.get(name), 200)
                    if value:
                        events.append({name: value})
                        if name == "fixed" and kind in ("ECOSYSTEM", "SEMVER") and value not in fixed:
                            fixed.append(value)
        if len(events) > MAX_EVENTS:
            # Cutting an event list could turn a closed interval into an open one; drop the range and say so.
            ranges_truncated = True
            continue
        if kind and events:
            record = {"type": kind, "events": events}
            repo = _text(item.get("repo"), 500)
            if repo:
                record["repo"] = repo
            ranges.append(record)

    specific = [entry.get(key) for key in ("ecosystem_specific", "database_specific") if isinstance(entry.get(key), dict)]
    vectors = _cvss_list(entry.get("severity"))
    label, label_source = _severity([s.get("severity") for s in specific], vectors)
    versions = _strings(entry.get("versions"), MAX_VERSIONS)
    return {
        "ecosystem": ecosystem,
        "source_ecosystem": source_ecosystem,
        "package_name": normalize_name(ecosystem, source_name) if ecosystem else source_name,
        "source_package_name": source_name,
        "purl": _text(package.get("purl"), 500),
        "versions": versions,
        "versions_truncated": isinstance(entry.get("versions"), list) and len(entry["versions"]) > len(versions),
        "ranges": ranges[:MAX_RANGES],
        "ranges_truncated": ranges_truncated or len(ranges) > MAX_RANGES,
        "fixed_versions": fixed[:50],
        # GitHub-reviewed records sometimes add a free-text range here; kept verbatim, never evaluated.
        "source_range_note": next((_text(s.get("last_known_affected_version_range"), 200) for s in specific
                                   if s.get("last_known_affected_version_range")), None),
        "severity": label if label_source else None,
        "severity_source": label_source,
        "cvss": vectors or None,
    }


def normalize_osv(record: Any, raw: bytes | None = None) -> dict[str, Any]:
    """Convert one OSV-schema record into the normalised vulnerability form."""
    if not isinstance(record, dict):
        raise MalformedRecord("the record is not a JSON object")
    source_id = record.get("id")
    if not isinstance(source_id, str) or not ID_PATTERN.fullmatch(source_id):
        raise MalformedRecord("the record has no valid id")
    if "affected" in record and not isinstance(record["affected"], list):
        raise MalformedRecord("'affected' is not a list")

    entries = record.get("affected") or []
    affected = [a for a in (_affected(e) for e in entries[:MAX_AFFECTED]) if a is not None]
    vectors = _cvss_list(record.get("severity"))
    database_specific = record.get("database_specific") if isinstance(record.get("database_specific"), dict) else {}
    label, label_source = _severity([database_specific.get("severity")], vectors)
    if label_source is None:
        # No record-level severity: use what the source publishes per affected package, if anything.
        for entry in affected:
            if entry["severity_source"]:
                label, label_source = entry["severity"], entry["severity_source"] + "_per_package"
                break

    references = []
    for item in record.get("references") if isinstance(record.get("references"), list) else []:
        url = _text(item.get("url"), 2000) if isinstance(item, dict) else None
        if url and url.lower().startswith(("https://", "http://")):
            references.append({"type": _text(item.get("type"), 30), "url": url})
        if len(references) >= MAX_REFERENCES:
            break

    raw_bytes = raw if raw is not None else json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    return {
        "source": "osv",
        "source_id": source_id,
        "source_url": f"https://osv.dev/vulnerability/{source_id}",
        "schema_version": _text(record.get("schema_version"), 20),
        "aliases": [a for a in _strings(record.get("aliases"), 50) if a != source_id],
        "related": _strings(record.get("related"), 50),
        "summary": _text(record.get("summary"), 1000),
        "details": _text(record.get("details"), 20000),
        "severity": label,
        "severity_source": label_source,
        "cvss": vectors or None,
        "cwe_ids": _strings(database_specific.get("cwe_ids"), 30, 30),
        "affected": affected,
        "affected_truncated": len(entries) > MAX_AFFECTED,
        "references": references,
        "published_at": _timestamp(record.get("published")),
        "modified_at": _timestamp(record.get("modified")),
        "withdrawn_at": _timestamp(record.get("withdrawn")),
        "source_modified": _text(record.get("modified"), 40),
        "raw": record if len(raw_bytes) <= MAX_RAW_STORED else None,
        "raw_stored": len(raw_bytes) <= MAX_RAW_STORED,
        "raw_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "normalizer_version": NORMALIZER_VERSION,
    }


@dataclass
class OsvProvider(VulnerabilityProvider):
    settings: Settings
    transport: httpx.BaseTransport | None = None
    sleep: Callable[[float], None] = field(default=time.sleep)
    name: str = "osv"
    display_name: str = "OSV"

    # -- contract ---------------------------------------------------------------

    def supports(self, ecosystem: str) -> bool:
        return ecosystem in ECOSYSTEMS

    def describe(self) -> dict[str, Any]:
        return {"name": self.name, "display_name": self.display_name, "base_url": self.settings.osv_api_url,
                "website": "https://osv.dev", "ecosystems": sorted(ECOSYSTEMS), "normalizer_version": NORMALIZER_VERSION}

    def normalize(self, record: dict[str, Any], raw: bytes | None = None) -> dict[str, Any]:
        return normalize_osv(record, raw)

    def health_check(self) -> dict[str, Any]:
        checked_at = datetime.now(timezone.utc)
        try:
            body, _ = self._request("POST", "/v1/querybatch", {"queries": [
                {"package": {"name": "pip", "ecosystem": "PyPI"}, "version": "0.0.0"}]}, max_bytes=1_048_576, attempts=1)
        except ProviderError as exc:
            return {"ok": False, "detail": exc.message, "code": exc.code, "checked_at": checked_at}
        ok = isinstance(body, dict) and isinstance(body.get("results"), list)
        return {"ok": ok, "detail": "OSV answered a query" if ok else "OSV answered in an unexpected format",
                "code": None if ok else "PROVIDER_BAD_RESPONSE", "checked_at": checked_at}

    def query(self, packages: Iterable[PackageQuery], progress: Callable[[int, int], None] | None = None) -> QueryResult:
        result = QueryResult()
        supported: list[PackageQuery] = []
        for package in dict.fromkeys(packages):
            (supported if self.supports(package.ecosystem) else result.unsupported).append(package)
        size = self.settings.vulnerability_batch_size
        for start in range(0, len(supported), size):
            batch = supported[start:start + size]
            pending: list[tuple[PackageQuery, str | None]] = [(package, None) for package in batch]
            for _page in range(MAX_PAGES):
                if not pending:
                    break
                body, _ = self._request("POST", "/v1/querybatch", {"queries": [self._query(p, token) for p, token in pending]},
                                        max_bytes=MAX_QUERY_BYTES)
                result.requests += 1
                answers = body.get("results") if isinstance(body, dict) else None
                if not isinstance(answers, list) or len(answers) != len(pending):
                    raise ProviderError("PROVIDER_BAD_RESPONSE", "OSV returned an unexpected answer to a batch query.")
                following: list[tuple[PackageQuery, str | None]] = []
                for (package, _token), answer in zip(pending, answers):
                    answer = answer if isinstance(answer, dict) else {}
                    ids = result.reported.setdefault(package, [])
                    for item in answer.get("vulns") if isinstance(answer.get("vulns"), list) else []:
                        identifier = item.get("id") if isinstance(item, dict) else None
                        if isinstance(identifier, str) and ID_PATTERN.fullmatch(identifier):
                            if identifier not in ids:
                                ids.append(identifier)
                            modified = item.get("modified")
                            result.modified[identifier] = modified if isinstance(modified, str) else None
                        else:
                            # Reported, but not something that can be fetched safely. It must count as a failure.
                            result.rejected.append(repr(identifier)[:120])
                    token = answer.get("next_page_token")
                    if isinstance(token, str) and token:
                        following.append((package, token[:2000]))
                pending = following
            if pending:
                raise ProviderError("PROVIDER_BAD_RESPONSE", "OSV kept returning more result pages than the configured limit.")
            if progress:
                progress(min(start + size, len(supported)), len(supported))
        return result

    def fetch(self, source_id: str) -> tuple[dict[str, Any], bytes]:
        if not isinstance(source_id, str) or not ID_PATTERN.fullmatch(source_id):
            raise ProviderError("INVALID_ID", "The advisory id is not valid.")
        body, raw = self._request("GET", f"/v1/vulns/{source_id}", None, max_bytes=self.settings.vulnerability_max_record_bytes)
        if not isinstance(body, dict):
            raise ProviderError("PROVIDER_BAD_RESPONSE", f"OSV returned an unexpected record for {source_id}.")
        return body, raw

    # -- transport --------------------------------------------------------------

    @staticmethod
    def _query(package: PackageQuery, token: str | None) -> dict[str, Any]:
        # OSV names: PEP 503-normalised on PyPI; as published elsewhere. Go versions carry no "v" prefix.
        name = package.normalized_name if package.ecosystem in ("pypi", "npm", "maven") else package.name
        version = package.version.removeprefix("v") if package.ecosystem == "golang" else package.version
        query: dict[str, Any] = {"package": {"name": name, "ecosystem": ECOSYSTEMS[package.ecosystem]}, "version": version}
        if token:
            query["page_token"] = token
        return query

    def _request(self, method: str, path: str, payload: Any, *, max_bytes: int, attempts: int = MAX_ATTEMPTS) -> tuple[Any, bytes]:
        url = f"{self.settings.osv_api_url}{path}"
        headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
        last: ProviderError | None = None
        with httpx.Client(transport=self.transport, timeout=self.settings.vulnerability_timeout_seconds,
                          follow_redirects=False, headers=headers) as client:
            for attempt in range(attempts):
                wait = 0.5 * (attempt + 1)
                try:
                    with client.stream(method, url, json=payload) as response:
                        status, response_headers = response.status_code, response.headers
                        chunks, received = [], 0
                        for chunk in response.iter_bytes():
                            received += len(chunk)
                            if received > max_bytes:
                                raise ProviderError("PROVIDER_RESPONSE_TOO_LARGE", "OSV returned more data than the configured limit allows.")
                            chunks.append(chunk)
                        body = b"".join(chunks)
                except httpx.TimeoutException:
                    last = ProviderError("PROVIDER_TIMEOUT", "OSV did not respond in time.")
                except httpx.HTTPError:
                    last = ProviderError("PROVIDER_UNREACHABLE", "OSV could not be reached.")
                else:
                    if status == 200:
                        try:
                            return json.loads(body), body
                        except (ValueError, RecursionError):
                            raise ProviderError("PROVIDER_BAD_RESPONSE", "OSV returned a response that is not valid JSON.") from None
                    if status == 404:
                        raise ProviderError("NOT_FOUND", "OSV has no record with that id.")
                    if status not in RETRY_STATUS:
                        raise ProviderError("PROVIDER_ERROR", f"OSV returned HTTP {status}.")
                    retry_after = response_headers.get("retry-after", "")
                    if status == 429:
                        seconds = float(retry_after) if retry_after.isdigit() and len(retry_after) <= 6 else None
                        retry_at = datetime.fromtimestamp(time.time() + seconds, tz=timezone.utc) if seconds is not None else None
                        last = ProviderError("PROVIDER_RATE_LIMITED", "OSV is rate limiting requests. Try again later.", retry_at)
                        if seconds is not None and seconds > MAX_RETRY_AFTER:
                            raise last
                        wait = max(wait, seconds or 0.0)
                    else:
                        last = ProviderError("PROVIDER_ERROR", f"OSV returned HTTP {status}.")
                if attempt < attempts - 1:
                    self.sleep(wait)
        assert last is not None
        raise last
