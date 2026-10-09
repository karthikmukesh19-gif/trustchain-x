"""What kinds of change the analysed commits contained, per contributor.

This reads the results of commit behaviour analysis (Phase 8) when they
exist. Without them nothing is assumed: the summary says the data is missing.
"""

from __future__ import annotations

from typing import Any

from app.analyzers.maintainers.contributors import identity, maintainer_id

SECURITY_TYPES = ("SECURITY_CONFIG_CHANGE", "AUTH_CHANGE", "SECRET_LIKE_PATTERN", "COMMAND_EXECUTION_PATTERN", "NETWORK_BEHAVIOUR_CHANGE")


def summarise(analysed: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts over commit-analysis rows: {available, commits, security_sensitive, dependency_changes, large_changesets, by_contributor}."""
    if not analysed:
        return {"available": False, "commits": 0, "security_sensitive": 0, "dependency_changes": 0, "large_changesets": 0,
                "by_contributor": {}, "security_commits": [],
                "reason": "No commit behaviour analysis exists for this project. Run it to evaluate what the commits changed."}
    by_person: dict[str, dict[str, Any]] = {}
    security_commits = []
    totals = {"security_sensitive": 0, "dependency_changes": 0, "large_changesets": 0}
    for row in analysed:
        types = set(row.get("indicator_types") or [])
        key, label, _login = identity(row)
        entry = by_person.setdefault(maintainer_id(key), {"display_name": label, "commits": 0, "security_sensitive": 0,
                                                          "dependency_changes": 0, "large_changesets": 0})
        entry["commits"] += 1
        flags = {"security_sensitive": bool(types & set(SECURITY_TYPES)), "dependency_changes": "DEPENDENCY_CHANGE" in types,
                 "large_changesets": "LARGE_CHANGESET" in types}
        for name, flag in flags.items():
            entry[name] += flag
            totals[name] += flag
        if flags["security_sensitive"]:
            security_commits.append({"sha": row.get("sha") or row.get("commit_sha"), "committed_at": row.get("committed_at"),
                                     "types": sorted(types & set(SECURITY_TYPES)), "maintainer_id": maintainer_id(key)})
    return {"available": True, "commits": len(analysed), **totals, "by_contributor": by_person,
            "security_commits": security_commits[:50], "reason": None}
