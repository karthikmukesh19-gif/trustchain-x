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

from app.models.collections import AUDIT_LOGS, PROJECTS, TRUST_SCORES
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

    # The current trust result of each project: only one calculated for its latest snapshot counts as current.
    trust = []
    for p in projects[:50]:
        score = None
        if p.get("latest_snapshot_id") is not None:
            score = db[TRUST_SCORES].find_one({"project_id": p["_id"], "snapshot_id": p["latest_snapshot_id"]},
                                              {"status": 1, "trust_score": 1, "risk_score": 1, "confidence": 1, "coverage": 1, "created_at": 1,
                                               "band": 1}, sort=[("created_at", -1), ("_id", -1)])
        entry = {"project_id": str(p["_id"]), "name": p["name"], "analysed": p.get("latest_snapshot_id") is not None,
                 "status": score["status"] if score else "NOT_ANALYSED"}
        if score:
            # Score fields exist only when a score was calculated: a project without one carries no placeholder figures.
            entry.update({key: score.get(key) for key in ("trust_score", "risk_score", "confidence", "coverage", "band", "created_at")})
        trust.append(entry)

    return {
        "generated_at": now,
        "trust": trust,
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
