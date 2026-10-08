"""How far the installed version of a package is behind what its registry publishes.

Versions are ordered with the ecosystem rules of Phase 3 (PEP 440, SemVer).
Nothing is compared as text. When the ecosystem has no safe ordering, or a
version does not parse, the comparison is UNSUPPORTED; when the registry data
is missing it is UNKNOWN. Dates come only from the registry.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from app.analyzers.vulnerabilities.versions import UnsupportedVersion, parse, release_components, scheme_name

COMPARED = "COMPARED"
UNSUPPORTED = "UNSUPPORTED"          # the versions cannot be ordered safely
UNKNOWN = "UNKNOWN"                  # there is nothing to compare with

UP_TO_DATE, BEHIND, AHEAD = "UP_TO_DATE", "BEHIND", "AHEAD_OF_LATEST"


MAX_COMPONENT = 10 ** 9              # a version component larger than this is not a real release number; nothing is measured from it


def _aware(moment: Any) -> datetime | None:
    """A registry date as an aware datetime (stored values may come back without a zone); anything else is None."""
    if not isinstance(moment, datetime):
        return None
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc)


def _days(later: datetime | None, earlier: datetime | None) -> int | None:
    """Whole days from `earlier` to `later`; None when either is missing or the order is impossible (a date in the future)."""
    if later is None or earlier is None or later < earlier:
        return None
    return (later - earlier).days


def _same_version(ecosystem: str, wanted: str, candidates: Any) -> str | None:
    """The spelling under which `candidates` holds `wanted` ("1.0" and "1.0.0" are one PEP 440 version), or None."""
    if wanted in candidates:
        return wanted
    try:
        key = parse(ecosystem, wanted)
    except UnsupportedVersion:
        return None
    for candidate in candidates:
        try:
            if parse(ecosystem, candidate) == key:
                return candidate
        except UnsupportedVersion:
            continue
    return None


def assess(ecosystem: str, installed: str | None, metadata: dict[str, Any] | None, as_of: datetime) -> dict[str, Any]:
    """Compare an installed version with registry metadata. Pure: `as_of` is the only clock."""
    result: dict[str, Any] = {
        "comparison_status": UNKNOWN, "reason": None, "position": None, "comparator": scheme_name(ecosystem),
        "installed_version": installed, "latest_version": None, "major_distance": None, "minor_distance": None, "patch_distance": None,
        "releases_behind": None, "versions_not_comparable": None, "installed_published_at": None, "latest_published_at": None,
        "installed_age_days": None, "latest_age_days": None, "lag_days": None, "releases_last_365_days": None,
        "installed_withdrawn": None, "installed_deprecated": None, "metadata_status": (metadata or {}).get("status"), "metadata_detail": (metadata or {}).get("detail"),
    }
    if not installed:
        result["reason"] = "The repository does not determine an installed version."
        return result
    if metadata is None or metadata.get("status") != "COLLECTED":
        code = (metadata or {}).get("error_code") or (metadata or {}).get("status")
        result["reason"] = f"No registry metadata is available for this package ({code})." if code else \
            "No registry metadata was collected for this ecosystem."
        return result

    versions: dict[str, Any] = {name: _aware(moment) for name, moment in (metadata.get("versions") or {}).items()}
    latest = metadata.get("latest_version")
    as_of = _aware(as_of) or as_of
    listed = _same_version(ecosystem, installed, versions)              # the registry's spelling of the installed version, if it lists it
    withdrawn = set(metadata.get("withdrawn_versions") or [])
    deprecated = set(metadata.get("deprecated_versions") or [])
    result.update(latest_version=latest, installed_published_at=versions.get(listed) if listed else None,
                  latest_published_at=_aware(metadata.get("latest_published_at")) or (versions.get(latest) if latest else None),
                  # Whether the registry lists the installed version at all decides if "not withdrawn" is known.
                  installed_withdrawn=(listed in withdrawn) if listed else None,
                  installed_deprecated=(listed in deprecated) if listed else None)
    result["installed_age_days"] = _days(as_of, result["installed_published_at"])
    result["latest_age_days"] = _days(as_of, result["latest_published_at"])
    result["lag_days"] = _days(result["latest_published_at"], result["installed_published_at"])
    dated = [moment for moment in versions.values() if moment is not None]
    if dated:
        result["releases_last_365_days"] = sum(1 for moment in dated if as_of - timedelta(days=365) <= moment <= as_of)
    if not latest:
        result["reason"] = "The registry does not name a latest version."
        return result
    if result["comparator"] is None:
        result.update(comparison_status=UNSUPPORTED, reason=f"No version ordering is implemented for the {ecosystem} ecosystem.")
        return result
    try:
        installed_key, latest_key = parse(ecosystem, installed), parse(ecosystem, latest)
        installed_parts, _ = release_components(ecosystem, installed)
        latest_parts, _ = release_components(ecosystem, latest)
    except UnsupportedVersion as exc:
        result.update(comparison_status=UNSUPPORTED, reason=f"The versions cannot be ordered safely ({exc}).")
        return result

    if any(component > MAX_COMPONENT for component in (*installed_parts, *latest_parts)):
        result.update(comparison_status=UNSUPPORTED, reason="A version component is too large to be a release number; nothing is measured from it.")
        return result

    result["comparison_status"] = COMPARED
    if installed_key == latest_key:
        result.update(position=UP_TO_DATE, major_distance=0, minor_distance=0, patch_distance=0, releases_behind=0)
        return result
    if installed_key > latest_key:
        # A pre-release, or a version newer than the one the registry marks as latest.
        result.update(position=AHEAD, major_distance=0, minor_distance=0, patch_distance=0, releases_behind=0)
        return result
    width = max(len(installed_parts), len(latest_parts), 3)
    old = installed_parts + (0,) * (width - len(installed_parts))
    new = latest_parts + (0,) * (width - len(latest_parts))
    major = new[0] - old[0]
    minor = new[1] - old[1] if major == 0 else None               # only meaningful within the same major line
    patch = new[2] - old[2] if major == 0 and minor == 0 else None
    behind, skipped = 0, 0
    for candidate in versions:
        if candidate in withdrawn:
            continue
        try:
            key = parse(ecosystem, candidate)
            _parts, prerelease = release_components(ecosystem, candidate)
        except UnsupportedVersion:
            skipped += 1
            continue
        if not prerelease and installed_key < key <= latest_key:
            behind += 1
    result.update(position=BEHIND, major_distance=major, minor_distance=minor, patch_distance=patch,
                  releases_behind=None if metadata.get("versions_truncated") else behind, versions_not_comparable=skipped)
    return result
