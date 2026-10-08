"""Dashboard summary built only from stored data.

Trust, risk and vulnerability figures are produced by the analysis pipeline
(Phase 2 onward). Until a project has been analysed there is nothing to
report for them, and this module does not invent placeholders.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from bson import ObjectId
from pymongo.database import Database

from app.models.collections import AUDIT_LOGS, PROJECTS
from app.services import projects as project_service

ACTIVITY_DAYS = 14
RECENT_PROJECTS = 5
RECENT_EVENTS = 10


def build_summary(db: Database, owner_id: ObjectId, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    projects = list(db[PROJECTS].find({"owner_id": owner_id}).sort([("created_at", -1), ("_id", -1)]))
    repositories = project_service.load_repositories(db, projects)

    by_status = Counter(p["status"] for p in projects)
    metadata = Counter(
        repositories[p["repository_id"]]["metadata_status"]
        for p in projects
        if p.get("repository_id") in repositories
    )
    analysed = sum(1 for p in projects if p.get("last_analysis") is not None)

    today = now.date()
    days = [today - timedelta(days=offset) for offset in range(ACTIVITY_DAYS - 1, -1, -1)]
    per_day = Counter()
    for p in projects:
        created = p["created_at"]
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        per_day[created.astimezone(timezone.utc).date()] += 1
    registrations = [{"date": d.isoformat(), "projects": per_day.get(d, 0)} for d in days]

    events = db[AUDIT_LOGS].find({"actor_id": owner_id}).sort([("timestamp", -1)]).limit(RECENT_EVENTS)
    activity = [
        {
            "timestamp": e["timestamp"],
            "action": e["action"],
            "outcome": e["outcome"],
            "resource_type": e.get("resource_type"),
            "resource_id": str(e["resource_id"]) if e.get("resource_id") is not None else None,
            "details": e.get("details") or {},
        }
        for e in events
    ]

    return {
        "generated_at": now,
        "projects_total": len(projects),
        "projects_analysed": analysed,
        "projects_by_status": dict(by_status),
        "repository_metadata": dict(metadata),
        "registrations_by_day": registrations,
        "recent_projects": [
            project_service.to_public(p, repositories.get(p.get("repository_id")))
            for p in projects[:RECENT_PROJECTS]
        ],
        "recent_activity": activity,
    }
