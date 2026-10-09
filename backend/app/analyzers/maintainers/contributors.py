"""Who contributes, and how concentrated the work is. Identities are public GitHub logins; e-mail addresses are never used as text."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from typing import Any

from app.analyzers.maintainers.activity import dated


def identity(commit: dict[str, Any]) -> tuple[str, str, str | None]:
    """(grouping key, label, login) for the author of a commit.

    A GitHub login identifies the account. Without one (the commit's e-mail is
    not linked to an account) commits are grouped by the e-mail tag, or by the
    author name as a last resort; such a group may be one person or several.
    """
    login = commit.get("author_login")
    if login:
        return f"login:{login.lower()}", login, login
    name = commit.get("author_name") or "unknown author"
    tag = commit.get("author_email_tag")
    return (f"email:{tag}" if tag else f"name:{name.lower()}"), name, None


def maintainer_id(key: str) -> str:
    return hashlib.sha256(f"github|{key}".encode()).hexdigest()[:24]


def profiles(commits: list[dict[str, Any]], as_of: datetime, recent_days: int = 90) -> list[dict[str, Any]]:
    """One profile per contributor in the observed commits, most commits first."""
    history = dated(commits)
    grouped: dict[str, dict[str, Any]] = {}
    recent_after = as_of - timedelta(days=recent_days)
    for commit in history:
        key, label, login = identity(commit)
        entry = grouped.setdefault(key, {
            "maintainer_id": maintainer_id(key), "key": key, "login": login, "display_name": label, "identified_by": key.split(":", 1)[0],
            "account_type": commit.get("author_type"), "commits": 0, "first_commit_at": commit["at"], "last_commit_at": commit["at"],
            "days": set(), "recent_commits": 0, "verified_commits": 0, "merge_commits": 0, "shas": []})
        entry["commits"] += 1
        entry["last_commit_at"] = commit["at"]
        entry["display_name"], entry["login"] = label, login or entry["login"]      # as spelled on the newest commit
        entry["days"].add(commit["at"].date())
        entry["recent_commits"] += commit["at"] >= recent_after
        entry["verified_commits"] += commit.get("verified") is True
        entry["merge_commits"] += (commit.get("parent_count") or 0) > 1
        if len(entry["shas"]) < 20:
            entry["shas"].append(commit["sha"])
    total = len(history)
    result = []
    for entry in grouped.values():
        days = entry.pop("days")
        entry.pop("key")
        result.append({**entry, "share": round(entry["commits"] / total, 4) if total else 0.0, "active_days": len(days),
                       "recent_share": None, "sample_commits": entry.pop("shas")})
    recent_total = sum(item["recent_commits"] for item in result)
    for item in result:
        item["recent_share"] = round(item["recent_commits"] / recent_total, 4) if recent_total else None
    result.sort(key=lambda item: (-item["commits"], item["display_name"].lower(), item["maintainer_id"]))
    for rank, item in enumerate(result, start=1):
        item["rank"] = rank
    return result


def concentration(people: list[dict[str, Any]]) -> dict[str, Any]:
    """How unevenly the observed commits are spread over contributors."""
    total = sum(person["commits"] for person in people)
    if not total:
        return {"contributors": 0, "commits": 0, "top_share": None, "top_contributor": None, "hhi": None, "effective_contributors": None,
                "half_of_commits_by": None}
    shares = [person["commits"] / total for person in people]
    hhi = sum(share * share for share in shares)
    covered, needed = 0.0, 0
    for share in shares:
        covered += share
        needed += 1
        if covered >= 0.5:
            break
    return {"contributors": len(people), "commits": total, "top_share": round(shares[0], 4),
            "top_contributor": {"maintainer_id": people[0]["maintainer_id"], "display_name": people[0]["display_name"]},
            "hhi": round(hhi, 4), "effective_contributors": round(1 / hhi, 2), "half_of_commits_by": needed}
