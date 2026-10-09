"""Maintainer behaviour analysis of a project's repository: job, storage and reads.

The job reads public metadata from GitHub (commits, contributors, releases)
through the configured API host and, where it exists, the project's commit
behaviour analysis. When GitHub cannot be reached, or only part of the data
can be collected, the affected indicators are stored as UNKNOWN and the job
ends as partial; nothing is estimated in their place.
"""

from __future__ import annotations

from typing import Any

from bson import ObjectId
from pymongo.database import Database

from app.analyzers.maintainers import MODEL_VERSION, anomaly, build_profile
from app.collectors.github import GitHubUnavailable
from app.models.collections import COMMIT_ANALYSIS, MAINTAINER_PROFILES, MAINTAINERS, PROJECTS, REPOSITORIES
from app.security.url_validation import RepositoryRef
from app.services import jobs, runs
from app.services.jobs import JobContext, JobError

KIND = "maintainers"
ROW_COLLECTIONS = (MAINTAINERS, MAINTAINER_PROFILES)


def repository_of(db: Database, job: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], RepositoryRef]:
    project = db[PROJECTS].find_one({"_id": job["project_id"]})
    repository = db[REPOSITORIES].find_one({"_id": job["repository_id"]}) if project is not None else None
    if project is None or repository is None:
        raise JobError("PROJECT_NOT_FOUND", "The project was deleted before the job started.")
    return project, repository, RepositoryRef(host=repository["host"], owner=repository["owner"], name=repository["name"])


def _run(context: JobContext, job: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    db, settings = context.db, context.settings
    project, repository, ref = repository_of(db, job)
    as_of = runs.now()
    missing: list[dict[str, Any]] = []
    commits: list[dict[str, Any]] | None = None
    releases: list[dict[str, Any]] | None = None
    listed: list[dict[str, Any]] | None = None
    truncated = False
    retry_at = None

    jobs.progress(db, job, "COLLECTION", "Reading commit history, contributors and releases from GitHub")
    if context.github is None:
        missing.append({"source": "commits", "code": "UNAVAILABLE", "reason": "No GitHub client is configured."})
    else:
        try:
            with context.github.session() as session:
                try:
                    collected = session.commits(ref, settings.maintainer_max_commits)
                    commits, truncated = collected["commits"], collected["truncated"]
                except GitHubUnavailable as exc:
                    if exc.code == "EMPTY_REPOSITORY":
                        commits = []
                    else:
                        missing.append({"source": "commits", "code": exc.code, "reason": exc.reason})
                        retry_at = exc.retry_at
                if commits is not None:
                    # The history is the basis of everything; the other two only refine it, so their failure is not fatal.
                    for name, fetch in (("releases", lambda: session.releases(ref, settings.maintainer_max_releases)["releases"]),
                                        ("contributors", lambda: session.contributors(ref)["contributors"])):
                        context.check_deadline(settings.behaviour_timeout_seconds)
                        try:
                            value = fetch()
                        except GitHubUnavailable as exc:
                            missing.append({"source": name, "code": exc.code, "reason": exc.reason})
                            retry_at = retry_at or exc.retry_at
                            continue
                        if name == "releases":
                            releases = value
                        else:
                            listed = value
        except GitHubUnavailable as exc:   # pragma: no cover - session set-up itself does not make requests
            missing.append({"source": "commits", "code": exc.code, "reason": exc.reason})

    analysed = list(db[COMMIT_ANALYSIS].find(
        {"project_id": project["_id"]},
        {"_id": 0, "commit_sha": 1, "author_login": 1, "author_name": 1, "author_email_tag": 1, "committed_at": 1, "indicator_types": 1}))
    for row in analysed:
        row["sha"] = row.get("commit_sha")

    jobs.progress(db, job, "PROFILING", "Profiling contributors and activity")
    if commits is None:
        reason = f"The commit history could not be collected from GitHub ({missing[0]['code']}): {missing[0]['reason']}"
        profile = {"maintainer_id": None, "contributor_count": None, "commit_frequency": None, "contributor_concentration": None,
                   "release_frequency": None, "activity_pattern": None, "weekly_activity": [], "anomaly_indicators": anomaly.unavailable(reason),
                   "attention_score": None, "attention_level": "UNKNOWN", "confidence": 0.0,
                   "score_detail": anomaly.score(anomaly.unavailable(reason), 0),
                   "evidence": {"commits_observed": None, "sources": []}, "meaning": anomaly.MEANING, "model_version": MODEL_VERSION}
        people: list[dict[str, Any]] = []
        data_status = "UNAVAILABLE"
    else:
        built = build_profile(commits=commits, releases=releases, listed_contributors=listed, analysed_commits=analysed, as_of=as_of,
                              commits_truncated=truncated)
        profile, people = built["profile"], built["contributors"]
        data_status = "PARTIAL" if missing else "COLLECTED"

    jobs.progress(db, job, "INDICATORS", "Storing the profile and its indicators")
    input_digest = runs.digest({
        "repository": repository["_id"], "model": MODEL_VERSION, "day": as_of.date().isoformat(), "status": data_status,
        "head": commits[0]["sha"] if commits else None, "commits": len(commits or []), "releases": [r["tag"] for r in releases or []],
        "listed": len(listed or []), "missing": [m["source"] for m in missing],
        "analysed": sorted(str(row.get("commit_sha")) + ",".join(sorted(row.get("indicator_types") or [])) for row in analysed)})
    existing = runs.reusable(db, project["_id"], KIND, input_digest) if data_status != "UNAVAILABLE" else None
    if existing is not None:
        return ("Nothing has changed since the previous analysis; it was kept",
                {"summary": {**(existing.get("summary") or {}), "analysis_id": existing["_id"], "reused": True}, "analysis_id": existing["_id"],
                 **_partial(missing, retry_at, data_status)})

    run = runs.begin(db, project=project, kind=KIND, job=job, model_version=MODEL_VERSION, input_digest=input_digest, created_at=as_of,
                     inputs={"repository": repository.get("full_name"), "commit_limit": settings.maintainer_max_commits,
                             "commit_analysis_rows": len(analysed)})
    scope = {"analysis_id": run["_id"], "project_id": project["_id"], "repository_id": repository["_id"], "created_at": as_of}
    try:
        db[MAINTAINER_PROFILES].insert_one(runs.storable({**scope, "repository": repository.get("full_name"), "data_status": data_status,
                                                          "unavailable": missing, "as_of": as_of, **profile}, 2000))
        runs.insert_rows(db, MAINTAINERS, [{**scope, **person} for person in people])
    except Exception:
        runs.discard(db, run, ROW_COLLECTIONS)
        raise
    indicators = profile["anomaly_indicators"]
    summary = {
        "data_status": data_status, "contributors": len(people), "commits_observed": len(commits or []) if commits is not None else None,
        "attention_score": profile["attention_score"], "attention_level": profile["attention_level"], "confidence": profile["confidence"],
        "indicators": {item["type"]: item["status"] for item in indicators},
        "observed": [item["type"] for item in indicators if item["status"] == anomaly.OBSERVED],
        "unknown": [item["type"] for item in indicators if item["status"] == anomaly.UNKNOWN],
        "unavailable": missing, "reused": False,
    }
    runs.complete(db, run, summary)
    runs.prune(db, project["_id"], KIND, settings.intelligence_history_limit, ROW_COLLECTIONS)
    message = ("Maintainer data is unavailable; every indicator is unknown" if data_status == "UNAVAILABLE" else
               f"{len(people)} contributor(s) profiled from {len(commits or [])} commit(s); {len(summary['observed'])} indicator(s) observed, "
               f"{len(summary['unknown'])} unknown")
    return message, {"summary": {**summary, "analysis_id": run["_id"]}, "analysis_id": run["_id"], **_partial(missing, retry_at, data_status)}


def _partial(missing: list[dict[str, Any]], retry_at: Any, data_status: str) -> dict[str, Any]:
    if not missing:
        return {}
    sources = ", ".join(sorted({item["source"] for item in missing}))
    detail = {"code": "GITHUB_DATA_UNAVAILABLE" if data_status == "UNAVAILABLE" else "GITHUB_DATA_INCOMPLETE",
              "message": f"GitHub data could not be collected for: {sources} ({missing[0]['code']}: {missing[0]['reason']}). "
                         "The indicators that need it are reported as unknown."}
    if retry_at is not None:
        detail["message"] += f" Retry after {retry_at:%Y-%m-%d %H:%M} UTC."
    return {"partial": detail}


jobs.handler(jobs.MAINTAINER_ANALYSIS)(_run)


def latest(db: Database, project: dict[str, Any]) -> dict[str, Any] | None:
    return runs.latest(db, project, KIND, snapshot_bound=False)


def delete_project_data(db: Database, project_id: ObjectId) -> None:
    for collection in ROW_COLLECTIONS:
        db[collection].delete_many({"project_id": project_id})
