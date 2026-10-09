"""Commit behaviour analysis of a project's repository: job, polling, storage and reads.

New commits are found by polling GitHub's commit list (no webhook is
needed). Each new commit's diff is read as text and checked against the
rules; its anomaly score compares it with the earlier commits already
analysed for the project. Commits are never checked out or executed.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timedelta
from typing import Any

from bson import ObjectId
from pymongo.database import Database

from app.analyzers.behavior import MODEL_VERSION, analyse_commit, assess, build_baseline
from app.analyzers.behavior.security_changes import INDICATOR_TYPES, SEVERITY_RANK
from app.analyzers.maintainers.contributors import identity
from app.collectors.github import GitHubUnavailable
from app.config.settings import Settings
from app.models.collections import BEHAVIOUR_EVENTS, COMMIT_ANALYSIS, COMMITS, PROJECTS, SECURITY_EVENTS
from app.services import jobs, runs
from app.services.analysis import AnalysisAlreadyRunning, storable
from app.services.jobs import JobContext
from app.services.maintainers import repository_of

logger = logging.getLogger(__name__)

KIND = "commits"
ROW_COLLECTIONS = (COMMIT_ANALYSIS, BEHAVIOUR_EVENTS, SECURITY_EVENTS)
SECURITY_EVENT_MIN_SEVERITY = "MEDIUM"      # events at or above this severity are also listed as security events
MAX_POLLED_PROJECTS = 20
_BASELINE_FIELDS = {"_id": 0, "commit_sha": 1, "stats": 1, "committed_at": 1, "author_key": 1, "sensitive": 1, "is_merge": 1}


def events_for(row: dict[str, Any], scope: dict[str, Any]) -> list[dict[str, Any]]:
    """One event per indicator type raised by a commit, carrying the findings behind it."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for finding in row["findings"]:
        grouped.setdefault(finding["type"], []).append(finding)
    events = []
    for kind in INDICATOR_TYPES:
        findings = grouped.get(kind)
        if not findings:
            continue
        strongest = max(findings, key=lambda item: (SEVERITY_RANK[item["severity"]], item["confidence"]))
        observed = any(item["basis"] == "OBSERVED" for item in findings)
        events.append({
            **scope, "commit_sha": row["commit_sha"], "repository": row["repository"], "occurred_at": row["committed_at"] or row["analysed_at"],
            "event_type": kind, "severity": strongest["severity"], "severity_rank": SEVERITY_RANK[strongest["severity"]],
            "confidence": max(item["confidence"] for item in findings),
            "observed_or_inferred": "OBSERVED" if observed and all(item["basis"] == "OBSERVED" for item in findings) else
                                    "OBSERVED_AND_INFERRED" if observed else "INFERRED",
            "changed_files": sorted({item["file"] for item in findings if item["file"]})[:50],
            "evidence": [{k: item[k] for k in ("rule", "file", "line", "side", "basis", "severity", "confidence", "detail", "excerpt")}
                         for item in findings[:20]],
            "finding_count": len(findings), "summary": strongest["detail"], "author": row.get("author_login") or row.get("author_name"),
            "anomaly_score": row["anomaly_score"], "model_version": MODEL_VERSION,
            "review_note": "Listed for review. This is not a confirmed incident.",
        })
    return events


def _store(db: Database, row: dict[str, Any], scope: dict[str, Any]) -> list[dict[str, Any]]:
    key = {"project_id": row["project_id"], "commit_sha": row["commit_sha"]}
    db[COMMIT_ANALYSIS].replace_one(key, storable(row, 2000), upsert=True)
    events = storable(events_for(row, scope), 2000)
    for collection in (BEHAVIOUR_EVENTS, SECURITY_EVENTS):
        db[collection].delete_many(key)
    if events:
        db[BEHAVIOUR_EVENTS].insert_many([dict(event) for event in events])
        serious = [dict(event) for event in events if event["severity_rank"] >= SEVERITY_RANK[SECURITY_EVENT_MIN_SEVERITY]]
        if serious:
            db[SECURITY_EVENTS].insert_many(serious)
    return events


def _run(context: JobContext, job: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    db, settings = context.db, context.settings
    project, repository, ref = repository_of(db, job)
    started = runs.now()
    trigger = (job.get("parameters") or {}).get("trigger") or "manual"
    db[PROJECTS].update_one({"_id": project["_id"]}, {"$set": {"commit_monitoring.last_checked_at": started}})

    jobs.progress(db, job, "COLLECTION", "Reading the newest commits from GitHub")
    problem: dict[str, Any] | None = None
    listing: list[dict[str, Any]] = []
    analysed: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    todo: list[dict[str, Any]] = []
    remaining = 0
    if context.github is None:
        problem = {"code": "UNAVAILABLE", "reason": "No GitHub client is configured.", "retry_at": None}
    else:
        with context.github.session() as session:
            try:
                listing = session.commits(ref, settings.commit_baseline_commits)["commits"]
            except GitHubUnavailable as exc:
                if exc.code != "EMPTY_REPOSITORY":
                    problem = {"code": exc.code, "reason": exc.reason, "retry_at": exc.retry_at}
            known = {doc["commit_sha"] for doc in db[COMMIT_ANALYSIS].find(
                {"project_id": project["_id"], "model_version": MODEL_VERSION}, {"commit_sha": 1})}
            new = [commit for commit in listing if commit["sha"] not in known]
            todo = list(reversed(new[:settings.commit_analysis_max_commits]))          # oldest first: each builds on the ones before
            remaining = len(new) - len(todo)
            jobs.progress(db, job, "DIFF_ANALYSIS", f"Inspecting the diff of {len(todo)} new commit(s)")
            for position, summary in enumerate(todo, start=1):
                context.check_deadline(settings.behaviour_timeout_seconds)
                try:
                    detail = session.commit_detail(ref, summary["sha"], settings.commit_max_files, settings.commit_max_patch_bytes)
                except GitHubUnavailable as exc:
                    if exc.code in ("RATE_LIMITED", "UNREACHABLE", "TIMEOUT", "BAD_TOKEN"):
                        # Nothing further can be collected now. What was analysed so far is kept.
                        problem = {"code": exc.code, "reason": exc.reason, "retry_at": exc.retry_at}
                        remaining += len(todo) - position + 1
                        break
                    skipped.append({"sha": summary["sha"], "code": exc.code, "reason": exc.reason})
                    continue
                result = analyse_commit(detail)
                key, _label, _login = identity(detail)
                db[COMMITS].update_one({"repository_id": repository["_id"], "sha": detail["sha"]}, {"$set": storable({
                    **{k: detail[k] for k in ("author_login", "committer_login", "author_name", "author_email_tag", "authored_at", "committed_at",
                                              "message", "parent_count", "verified", "additions", "deletions")},
                    "files": [{k: f[k] for k in ("path", "status", "additions", "deletions")} for f in result["files"]],
                    "files_listed": result["stats"]["files"], "fetched_at": runs.now()}, 1000)}, upsert=True)
                analysed.append({"detail": detail, "result": result, "author_key": key})
                if position % 10 == 0:
                    jobs.progress(db, job, "DIFF_ANALYSIS", f"Inspected {position} of {len(todo)} commit(s)")

    if not analysed and problem is None and not skipped:
        latest_run = latest(db, project)
        message = "No new commits since the last check" if listing else "The repository has no commits to analyse"
        if latest_run is not None:
            return message, {"summary": {**(latest_run.get("summary") or {}), "analysis_id": latest_run["_id"], "new_commits": 0, "reused": True,
                                         "checked_at": started, "trigger": trigger}, "analysis_id": latest_run["_id"]}

    jobs.progress(db, job, "BASELINE", "Comparing with earlier commits")
    run = runs.begin(db, project=project, kind=KIND, job=job, model_version=MODEL_VERSION, created_at=started,
                     input_digest=runs.digest({"job": job["_id"]}),
                     inputs={"repository": repository.get("full_name"), "trigger": trigger, "commit_limit": settings.commit_analysis_max_commits,
                             "baseline_limit": settings.commit_baseline_commits})
    scope = {"analysis_id": run["_id"], "project_id": project["_id"], "repository_id": repository["_id"], "created_at": started}
    earlier = list(db[COMMIT_ANALYSIS].find({"project_id": project["_id"]}, _BASELINE_FIELDS))
    events_by_type: Counter[str] = Counter()
    security_events = 0
    levels: Counter[str] = Counter()
    scores: list[tuple[float, str]] = []
    jobs.progress(db, job, "SCORING", f"Scoring {len(analysed)} commit(s)")
    far_past = datetime.min.replace(tzinfo=started.tzinfo)
    for item in analysed:
        detail, result = item["detail"], item["result"]
        committed = detail.get("committed_at") or detail.get("authored_at")
        is_merge = (detail.get("parent_count") or 0) > 1
        before = [row for row in earlier if not row.get("is_merge") and (row.get("committed_at") or far_past) < (committed or started)]
        before.sort(key=lambda row: row.get("committed_at") or far_past, reverse=True)
        assessment = assess(result, {"author_key": item["author_key"], "committed_at": committed, "is_merge": is_merge},
                            build_baseline(before[:settings.commit_baseline_commits]))
        row = {
            **scope, "repository": repository.get("full_name"), "commit_sha": detail["sha"], "author_login": detail.get("author_login"),
            "author_name": detail.get("author_name"), "author_email_tag": detail.get("author_email_tag"), "author_key": item["author_key"],
            "committed_at": committed, "authored_at": detail.get("authored_at"), "message": detail.get("message"),
            "verified": detail.get("verified"), "parent_count": detail.get("parent_count"), "is_merge": is_merge,
            "stats": result["stats"], "files": result["files"], "coverage": result["coverage"], "findings_dropped": result["findings_dropped"],
            **assessment, "analysed_at": runs.now(),
        }
        for event in _store(db, row, scope):
            events_by_type[event["event_type"]] += 1
            security_events += event["severity_rank"] >= SEVERITY_RANK[SECURITY_EVENT_MIN_SEVERITY]
        earlier.append({k: row.get(k) for k in ("commit_sha", "stats", "committed_at", "author_key", "sensitive", "is_merge")})
        levels[row["level"]] += 1
        scores.append((row["anomaly_score"], row["commit_sha"]))

    data_status = "UNAVAILABLE" if problem and not analysed and not listing else "PARTIAL" if problem or skipped else "COLLECTED"
    head = listing[0]["sha"] if listing else None
    if head:
        db[PROJECTS].update_one({"_id": project["_id"]}, {"$set": {"commit_monitoring.last_head_sha": head}})
    summary = {
        "data_status": data_status, "trigger": trigger, "head_sha": head, "commits_listed": len(listing), "new_commits": len(todo) + remaining,
        "analysed": len(analysed), "skipped": skipped[:20], "not_yet_analysed": remaining, "events": dict(events_by_type),
        "event_total": sum(events_by_type.values()), "security_events": security_events, "by_level": dict(levels),
        "highest_anomaly": max(scores)[0] if scores else None, "highest_anomaly_commit": max(scores)[1] if scores else None,
        "commits_analysed_total": db[COMMIT_ANALYSIS].count_documents({"project_id": project["_id"]}),
        "unavailable": {k: v for k, v in problem.items() if k != "retry_at"} if problem else None, "checked_at": started, "reused": False,
    }
    runs.complete(db, run, summary)
    runs.prune(db, project["_id"], KIND, settings.intelligence_history_limit, ())      # commit rows outlive the run that wrote them
    fields: dict[str, Any] = {"summary": {**summary, "analysis_id": run["_id"]}, "analysis_id": run["_id"]}
    if problem or skipped or remaining:
        parts = []
        if problem:
            parts.append(f"GitHub could not be read ({problem['code']}): {problem['reason']}")
            if problem.get("retry_at") is not None:
                parts.append(f"Retry after {problem['retry_at']:%Y-%m-%d %H:%M} UTC")
        if skipped:
            parts.append(f"{len(skipped)} commit(s) could not be read and were skipped")
        if remaining:
            parts.append(f"{remaining} more new commit(s) are waiting; run the analysis again to continue")
        fields["partial"] = {"code": "GITHUB_DATA_UNAVAILABLE" if data_status == "UNAVAILABLE" else "COMMITS_INCOMPLETE",
                             "message": ". ".join(parts) + ". Commits that were not analysed have no result; they are not assumed to be unremarkable."}
    message = ("Commit data is unavailable" if data_status == "UNAVAILABLE" else
               f"{len(analysed)} commit(s) analysed; {sum(events_by_type.values())} behaviour event(s), {security_events} listed for security review")
    return message, fields


jobs.handler(jobs.COMMIT_BEHAVIOUR_ANALYSIS)(_run)


def poll_due(db: Database, redis_client: Any, settings: Settings, now: datetime | None = None) -> int:
    """Queue a commit check for monitored projects whose last check is older than the polling interval. Returns how many were queued.

    Polling is off unless COMMIT_POLL_INTERVAL_MINUTES is set. A project that
    already has a job queued or running is left for the next round.
    """
    if settings.commit_poll_interval_minutes <= 0:
        return 0
    now = now or runs.now()
    due_before = now - timedelta(minutes=settings.commit_poll_interval_minutes)
    query = {"commit_monitoring.enabled": True, "active_job_id": None,
             "$or": [{"commit_monitoring.last_checked_at": None}, {"commit_monitoring.last_checked_at": {"$lte": due_before}}]}
    queued = 0
    for project in db[PROJECTS].find(query).sort([("commit_monitoring.last_checked_at", 1), ("_id", 1)]).limit(MAX_POLLED_PROJECTS):
        try:
            jobs.request_job(db, redis_client, project, jobs.COMMIT_BEHAVIOUR_ANALYSIS, {"trigger": "poll"})
        except AnalysisAlreadyRunning:
            continue
        db[PROJECTS].update_one({"_id": project["_id"]}, {"$set": {"commit_monitoring.last_checked_at": now}})
        queued += 1
    if queued:
        logger.info("Queued %d commit check(s) for monitored projects", queued)
    return queued


def set_monitoring(db: Database, project: dict[str, Any], enabled: bool) -> dict[str, Any]:
    now = runs.now()
    current = project.get("commit_monitoring") or {}
    update = {"commit_monitoring.enabled": enabled, "commit_monitoring.changed_at": now}
    if enabled and not current.get("enabled"):
        update["commit_monitoring.last_checked_at"] = current.get("last_checked_at")
    db[PROJECTS].update_one({"_id": project["_id"]}, {"$set": update})
    return {**current, "enabled": enabled, "changed_at": now}


def monitoring(project: dict[str, Any], settings: Settings) -> dict[str, Any]:
    state = project.get("commit_monitoring") or {}
    interval = settings.commit_poll_interval_minutes
    return {"enabled": bool(state.get("enabled")), "method": "polling", "interval_minutes": interval or None,
            "polling_active": bool(state.get("enabled")) and interval > 0, "last_checked_at": state.get("last_checked_at"),
            "last_head_sha": state.get("last_head_sha"),
            "note": None if interval > 0 else "Automatic polling is switched off on this installation (COMMIT_POLL_INTERVAL_MINUTES=0). "
                                              "Commits are checked when an analysis is started."}


def latest(db: Database, project: dict[str, Any]) -> dict[str, Any] | None:
    return runs.latest(db, project, KIND, snapshot_bound=False)


def delete_project_data(db: Database, project_id: ObjectId) -> None:
    for collection in ROW_COLLECTIONS:
        db[collection].delete_many({"project_id": project_id})
