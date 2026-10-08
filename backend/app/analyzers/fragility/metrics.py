"""The factors of the fragility score. Each maps a measurement to a value between 0 and 1.

The thresholds are stated here and in docs/phase5.md. They are modelling
choices, not measurements; changing one changes MODEL_VERSION.
"""

from __future__ import annotations

import math
from typing import Any

OBSERVED, DERIVED = "OBSERVED", "DERIVED"
KNOWN, UNKNOWN = "KNOWN", "UNKNOWN"


def _factor(name: str, weight: int, value: float | None, basis: str, detail: str, inputs: dict[str, Any]) -> dict[str, Any]:
    known = value is not None
    bounded = max(0.0, min(1.0, value)) if known else None
    return {"name": name, "weight": weight, "value": round(bounded, 4) if known else None, "status": KNOWN if known else UNKNOWN,
            "contribution": round(weight * bounded, 2) if known else 0.0, "basis": basis, "detail": detail, "inputs": inputs}


def reachable_count(vulnerabilities: int, reachability: dict[str, Any] | None, analysed: bool) -> tuple[int | None, str | None]:
    """How many of a dependency's known vulnerabilities Phase 4 found reachable, or None with the reason it is not known.

    Zero is only reported when it was established: the package has no known
    vulnerability, or every finding was decided and none is reachable. An
    undecided or unsupported finding is never counted as "not reachable".
    """
    if not analysed:
        return None, "No code reachability analysis exists for this snapshot."
    if not vulnerabilities:
        return 0, None
    reach = reachability or {}
    if reach.get("reachable"):
        return reach["reachable"], None
    if not reach.get("findings"):
        return None, "The code reachability analysis does not cover this package's vulnerabilities; it predates the latest vulnerability check."
    if reach.get("unknown") or reach.get("unsupported"):
        return None, "Reachability of this package's vulnerabilities could not be decided (unknown, or the ecosystem is not analysed)."
    return 0, None


def downstream_impact_value(dependents: int, packages: int) -> float:
    """1.0 when a quarter of the project's packages (at least 10) depend on it."""
    return min(1.0, dependents / max(10.0, 0.25 * packages))


def downstream_impact(row: dict[str, Any], packages: int, weight: int) -> dict[str, Any]:
    value = downstream_impact_value(row["dependents"], packages)
    return _factor("downstream_impact", weight, value, OBSERVED,
                   f"{row['dependents']} of {max(packages - 1, 0)} other packages depend on it directly or through others.",
                   {"dependents": row["dependents"], "dependents_share": row["dependents_share"], "packages": packages})


def fan_in(row: dict[str, Any], weight: int) -> dict[str, Any]:
    value = math.log2(1 + row["fan_in"]) / math.log2(1 + 16)                # 16 direct dependents -> 1.0
    return _factor("fan_in", weight, value, OBSERVED,
                   f"{row['fan_in']} package(s) depend on it directly" + ("; the project requires it itself." if row["direct"] else "."),
                   {"fan_in": row["fan_in"], "required_by_project": row["direct"]})


def introduced(row: dict[str, Any], weight: int) -> dict[str, Any]:
    value = math.log2(1 + row["introduced"]) / math.log2(1 + 64)            # 64 packages brought in -> 1.0
    return _factor("introduced_dependencies", weight, value, OBSERVED,
                   f"It requires {row['fan_out']} package(s) directly and brings in {row['introduced']} in total "
                   f"({row['exclusive']} only through it).",
                   {"fan_out": row["fan_out"], "introduced": row["introduced"], "exclusive": row["exclusive"]})


def depth(row: dict[str, Any], weight: int) -> dict[str, Any]:
    level = row["depth"]
    if level is None:
        return _factor("transitive_depth", weight, None, OBSERVED, "No path from the project to this package is established.", {"depth": None})
    return _factor("transitive_depth", weight, (min(level, 5) - 1) / 4, OBSERVED,                      # depth 5 or more -> 1.0
                   "Required by the project itself." if level == 1 else f"{level - 1} package(s) lie between the project and it.",
                   {"depth": level})


def centrality(row: dict[str, Any], weight: int) -> dict[str, Any]:
    measure = row["centrality_measure"]
    figure = row["betweenness_centrality"] if measure == "betweenness" else row["degree_centrality"]
    return _factor("graph_centrality", weight, row["relative_centrality"], DERIVED,
                   f"{measure.capitalize()} centrality {figure}, {round(row['relative_centrality'] * 100)}% of the highest in this graph.",
                   {"measure": measure, "betweenness_centrality": row["betweenness_centrality"], "degree_centrality": row["degree_centrality"],
                    "relative_centrality": row["relative_centrality"]})


def version_lag_value(version: dict[str, Any]) -> float | None:
    if version.get("comparison_status") != "COMPARED":
        return None
    major, minor, behind = version.get("major_distance") or 0, version.get("minor_distance") or 0, version.get("releases_behind")
    by_major = min(1.0, major / 3)                                          # three major versions behind -> 1.0
    by_minor = min(0.6, minor / 10 * 0.6) if major == 0 else 0.0            # ten minor versions behind -> 0.6
    by_count = min(1.0, behind / 20) if behind is not None else 0.0         # twenty releases behind -> 1.0
    return max(by_major, by_minor, by_count)


def version_lag(version: dict[str, Any], weight: int) -> dict[str, Any]:
    value = version_lag_value(version)
    inputs = {key: version.get(key) for key in ("comparison_status", "position", "installed_version", "latest_version", "major_distance",
                                                "minor_distance", "patch_distance", "releases_behind", "lag_days")}
    if value is None:
        return _factor("version_lag", weight, None, DERIVED, version.get("reason") or "The installed and latest versions were not compared.", inputs)
    if version["position"] != "BEHIND":
        detail = f"Installed {version['installed_version']} is the latest release." if version["position"] == "UP_TO_DATE" \
            else f"Installed {version['installed_version']} is newer than the registry's latest ({version['latest_version']})."
    else:
        distance = f"{version['major_distance']} major version(s)" if version["major_distance"] else \
            f"{version['minor_distance']} minor version(s)" if version["minor_distance"] else \
            f"{version['patch_distance']} patch version(s)" if version["patch_distance"] else "an earlier release of the same version number"
        count = f", {version['releases_behind']} release(s)" if version.get("releases_behind") else ""       # zero or unknown: not stated
        detail = f"Installed {version['installed_version']} is {distance}{count} behind the latest ({version['latest_version']})."
    return _factor("version_lag", weight, value, DERIVED, detail, inputs)


def release_staleness(version: dict[str, Any], weight: int) -> dict[str, Any]:
    age = version.get("latest_age_days")
    inputs = {"latest_version": version.get("latest_version"), "latest_published_at": version.get("latest_published_at"), "latest_age_days": age}
    if age is None:
        return _factor("release_staleness", weight, None, DERIVED,
                       version.get("reason") or "No release date is available for the latest version.", inputs)
    value = (age - 365) / (1095 - 365)                                      # no release for a year -> 0; for three years -> 1.0
    return _factor("release_staleness", weight, value, DERIVED, f"The latest release was published {age} day(s) before the analysis.", inputs)
