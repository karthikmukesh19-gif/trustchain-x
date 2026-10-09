"""Completeness, validity and internal consistency of records."""

from __future__ import annotations

from typing import Any

FEATURES = ("relationship", "depth", "dependents", "dependencies", "version_resolved", "vulnerability_count", "max_severity",
            "reachability_state", "fragility_score", "graph_risk", "predictive_risk", "attack_path_count", "max_attack_path_score")
LABELS = ("vulnerable", "reachable_vulnerability", "risk_level")
SCORES = ("fragility_score", "graph_risk", "predictive_risk", "max_attack_path_score")
COUNTS = ("depth", "dependents", "dependencies", "vulnerability_count", "attack_path_count")
ENUMS = {
    "relationship": {"DIRECT", "TRANSITIVE", "UNKNOWN"}, "max_severity": {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "NOT_APPLICABLE"},
    "reachability_state": {"REACHABLE", "NOT_CONFIRMED_REACHABLE", "UNKNOWN", "UNSUPPORTED", "NOT_ANALYSED", "NOT_APPLICABLE"},
    "risk_level": {"LOW", "MEDIUM", "HIGH"},
}
MAX_LISTED = 200


def completeness(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Share of feature and label cells that hold a value. A cell is missing when its layer has not been analysed."""
    missing: dict[str, int] = {}
    cells = filled = 0
    for record in records:
        for group, names in (("features", FEATURES), ("labels", LABELS)):
            values = record.get(group) or {}
            for name in names:
                cells += 1
                if values.get(name) is None:
                    missing[name] = missing.get(name, 0) + 1
                else:
                    filled += 1
    return {"cells": cells, "filled": filled, "value": round(filled / cells, 4) if cells else None,
            "missing_by_field": dict(sorted(missing.items())), "fields_fully_missing": sorted(n for n, c in missing.items() if c == len(records)),
            "records_complete": sum(1 for record in records if _complete(record))}


def _complete(record: dict[str, Any]) -> bool:
    return all((record.get("features") or {}).get(name) is not None for name in FEATURES) \
        and all((record.get("labels") or {}).get(name) is not None for name in LABELS)


def record_problems(record: dict[str, Any]) -> list[dict[str, str]]:
    """Schema, range and cross-field problems of one record. Unknown (None) values are not problems: they are gaps."""
    problems: list[dict[str, str]] = []
    identity, features, labels = record.get("identity") or {}, record.get("features") or {}, record.get("labels") or {}

    def add(kind: str, rule: str, detail: str) -> None:
        problems.append({"kind": kind, "rule": rule, "detail": detail})

    if not isinstance(record.get("record_id"), str) or not record.get("record_id"):
        add("INVALID", "record_id", "The record has no identifier.")
    for name in ("ecosystem", "name"):
        if not isinstance(identity.get(name), str) or not identity.get(name):
            add("INVALID", f"identity.{name}", f"The record has no {name}.")
    for name in SCORES:
        value = features.get(name)
        if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 100):
            add("INVALID", f"range.{name}", f"{name} is {value!r}; it must be a number from 0 to 100.")
    for name in COUNTS:
        value = features.get(name)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
            add("INVALID", f"range.{name}", f"{name} is {value!r}; it must be a whole number of 0 or more.")
    for name, allowed in ENUMS.items():
        value = features.get(name, labels.get(name))
        if value is not None and value not in allowed:
            add("INVALID", f"enum.{name}", f"{name} is {value!r}, which is not one of the defined values.")
    for name in ("vulnerable", "reachable_vulnerability"):
        if labels.get(name) is not None and not isinstance(labels.get(name), bool):
            add("INVALID", f"type.{name}", f"{name} must be true, false or unknown.")

    count, vulnerable = features.get("vulnerability_count"), labels.get("vulnerable")
    if isinstance(count, int) and isinstance(vulnerable, bool) and (count > 0) != vulnerable:
        add("INCONSISTENT", "label.vulnerable", f"The label 'vulnerable' is {vulnerable} but {count} advisory match(es) are recorded.")
    if labels.get("reachable_vulnerability") is True and vulnerable is False:
        add("INCONSISTENT", "label.reachable_without_vulnerability", "A reachable vulnerability is labelled on a package labelled not vulnerable.")
    if labels.get("reachable_vulnerability") is True and features.get("reachability_state") not in (None, "REACHABLE"):
        add("INCONSISTENT", "label.reachable_state", "The label says reachable but the reachability state is not REACHABLE.")
    if isinstance(count, int) and count == 0 and features.get("max_severity") not in (None, "NOT_APPLICABLE"):
        add("INCONSISTENT", "severity_without_vulnerability", "A severity is recorded although no advisory matches.")
    if isinstance(count, int) and count > 0 and features.get("max_severity") in (None, "NOT_APPLICABLE"):
        add("INCONSISTENT", "vulnerability_without_severity", "Advisory matches are recorded without a severity value (UNKNOWN is a value).")
    if isinstance(count, int) and count == 0 and features.get("reachability_state") not in (None, "NOT_APPLICABLE"):
        add("INCONSISTENT", "reachability_without_vulnerability", "A reachability state is recorded although no advisory matches.")
    depth, relationship = features.get("depth"), features.get("relationship")
    if isinstance(depth, int) and relationship == "DIRECT" and depth != 1:
        add("INCONSISTENT", "direct_depth", f"A direct dependency has depth {depth}.")
    if isinstance(depth, int) and depth == 0:
        add("INCONSISTENT", "zero_depth", "Depth 0 is the project itself, not a dependency.")
    paths = features.get("attack_path_count")
    if isinstance(paths, int) and paths > 0 and vulnerable is False:
        add("INCONSISTENT", "attack_path_without_vulnerability", "Attack paths are recorded for a package labelled not vulnerable.")
    if isinstance(paths, int) and paths == 0 and features.get("max_attack_path_score") not in (None, 0, 0.0):
        add("INCONSISTENT", "attack_path_score_without_path", "An attack-path score is recorded without any path.")
    return problems


def consistency(records: list[dict[str, Any]]) -> dict[str, Any]:
    invalid = inconsistent = 0
    by_rule: dict[str, int] = {}
    suspicious = []
    for record in records:
        problems = record_problems(record)
        if not problems:
            continue
        kinds = {problem["kind"] for problem in problems}
        invalid += "INVALID" in kinds
        inconsistent += "INCONSISTENT" in kinds and "INVALID" not in kinds
        for problem in problems:
            by_rule[problem["rule"]] = by_rule.get(problem["rule"], 0) + 1
        if len(suspicious) < MAX_LISTED:
            suspicious.append({"record_id": str(record.get("record_id")), "problems": problems[:10]})
    total = len(records)
    return {"records": total, "invalid_records": invalid, "inconsistent_records": inconsistent, "by_rule": dict(sorted(by_rule.items())),
            "value": round(1 - (invalid + inconsistent) / total, 4) if total else None, "suspicious": suspicious,
            "suspicious_truncated": invalid + inconsistent > len(suspicious)}
