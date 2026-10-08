"""A dependency's health profile: the facts collected about one package, each with where it came from.

A field the platform could not collect reliably is None and listed under
`unknown`; it is never estimated.
"""

from __future__ import annotations

from typing import Any

from app.analyzers.fragility.metrics import reachable_count

HIGH, MEDIUM, LOW, NONE = "HIGH", "MEDIUM", "LOW", "NONE"


def metadata_confidence(version: dict[str, Any]) -> tuple[str, float]:
    """How much of the release metadata is available: (label, 0-1)."""
    if version.get("metadata_status") != "COLLECTED":
        return NONE, 0.0
    if version.get("comparison_status") != "COMPARED":
        return LOW, 0.3
    if version.get("installed_published_at") is not None and version.get("latest_published_at") is not None:
        return HIGH, 1.0
    return MEDIUM, 0.6                    # versions known, release dates not


def profile(dependency: dict[str, Any], structure: dict[str, Any], version: dict[str, Any], vulnerabilities: dict[str, Any],
            reachability: dict[str, Any]) -> dict[str, Any]:
    label, value = metadata_confidence(version)
    reachable, reachable_reason = reachable_count(vulnerabilities.get("distinct", 0), reachability, bool(reachability.get("analysed")))
    fields = {
        "installed_version": dependency.get("version"),
        "latest_release": version.get("latest_version"),
        "latest_release_at": version.get("latest_published_at"),
        "installed_release_at": version.get("installed_published_at"),
        "release_age_days": version.get("installed_age_days"),
        "latest_release_age_days": version.get("latest_age_days"),
        "release_frequency": version.get("releases_last_365_days"),          # releases in the 365 days before the analysis
        "known_vulnerability_count": vulnerabilities.get("distinct", 0),
        "reachable_vulnerability_count": reachable,
        "dependency_count": structure.get("fan_out"),
        "downstream_dependents": structure.get("dependents"),
        "repository_activity": None,                                          # not collected in this version
    }
    reasons = {
        "latest_release": version.get("reason"), "latest_release_at": version.get("reason") or "The registry answer used carries no release dates.",
        "installed_release_at": version.get("reason") or "The registry answer used carries no release date for this version.",
        "release_age_days": version.get("reason") or "No release date is available for the installed version.",
        "latest_release_age_days": version.get("reason") or "No release date is available for the latest version.",
        "release_frequency": version.get("reason") or "No release dates are available.",
        "reachable_vulnerability_count": reachable_reason,
        "repository_activity": "Source repository activity is not collected.",
        "installed_version": "The repository does not determine a version.",
    }
    unknown = [{"field": name, "status": "UNKNOWN", "reason": reasons.get(name) or "Not available."}
               for name, item in fields.items() if item is None]
    return {**fields, "metadata_confidence": label, "metadata_confidence_value": value,
            "metadata_source": {"registry": version.get("registry"), "status": version.get("metadata_status"),
                                "detail": version.get("metadata_detail"), "fetched_at": version.get("metadata_fetched_at"),
                                "url": version.get("metadata_url"), "stale": bool(version.get("metadata_stale"))},
            "version": version, "unknown": unknown}
