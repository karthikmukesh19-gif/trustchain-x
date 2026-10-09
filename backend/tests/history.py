"""Builders for GitHub history payloads used by the maintainer and commit behaviour tests.

The payloads have the shape of the GitHub REST API. Their contents (people,
dates, diffs) are invented for the tests; none is copied from a real project.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

NOW = datetime.now(timezone.utc).replace(microsecond=0)


def sha_of(label: object) -> str:
    return hashlib.sha1(f"commit-{label}".encode()).hexdigest()


def stamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ago(days: float = 0, hours: float = 0, minutes: float = 0) -> datetime:
    return NOW - timedelta(days=days, hours=hours, minutes=minutes)


def raw_commit(label: object, when: datetime, login: str | None = "alice", *, name: str | None = None, email: str | None = None,
               message: str = "Update", files: list[dict] | None = None, parents: int = 1, verified: bool = False) -> dict:
    """One commit as the GitHub API returns it. `files` (with patches) is only served by the single-commit endpoint."""
    name = name or (login.title() if login else "Someone")
    email = email or f"{(login or name).lower().replace(' ', '.')}@example.com"
    files = files or []
    return {
        "sha": sha_of(label),
        "commit": {"author": {"name": name, "email": email, "date": stamp(when)}, "committer": {"name": name, "email": email, "date": stamp(when)},
                   "message": message, "verification": {"verified": verified}},
        "author": {"login": login, "type": "User"} if login else None, "committer": {"login": login, "type": "User"} if login else None,
        "parents": [{"sha": sha_of(f"{label}-p{i}")} for i in range(parents)],
        "stats": {"additions": sum(f.get("additions", 0) for f in files), "deletions": sum(f.get("deletions", 0) for f in files)},
        "files": files,
    }


def changed(path: str, added: list[str] | None = None, removed: list[str] | None = None, status: str = "modified", **extra) -> dict:
    """A changed file with a unified-diff patch built from added and removed lines."""
    added, removed = added or [], removed or []
    patch = None
    if added or removed:
        patch = "\n".join([f"@@ -1,{len(removed)} +1,{len(added)} @@", *(f"-{line}" for line in removed), *(f"+{line}" for line in added)])
    return {"filename": path, "status": status, "additions": len(added), "deletions": len(removed), "changes": len(added) + len(removed),
            **({"patch": patch} if patch is not None else {}), **extra}


def release(tag: str, when: datetime, login: str | None = "alice", prerelease: bool = False, draft: bool = False) -> dict:
    return {"tag_name": tag, "name": tag, "published_at": stamp(when), "created_at": stamp(when), "prerelease": prerelease, "draft": draft,
            "author": {"login": login} if login else None}


def steady(count: int, every_days: float = 3.0, login: str = "alice", start_label: int = 0, newest_days_ago: float = 1.0) -> list[dict]:
    """`count` commits by one person at a regular interval, newest first."""
    return [raw_commit(start_label + index, ago(days=newest_days_ago + index * every_days), login) for index in range(count)]
