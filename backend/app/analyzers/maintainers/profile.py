"""Assembles the repository's maintainer behaviour profile from collected history."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from app.analyzers.maintainers import activity, anomaly, change_patterns, contributors


def build_profile(*, commits: list[dict[str, Any]], releases: list[dict[str, Any]] | None, listed_contributors: list[dict[str, Any]] | None,
                  analysed_commits: list[dict[str, Any]], as_of: datetime, commits_truncated: bool = False) -> dict[str, Any]:
    """The profile, its indicators and the contributor rows. Pure and deterministic for the same inputs and `as_of`.

    `releases` or `listed_contributors` being None means that data could not be
    collected; indicators that need it are UNKNOWN.
    """
    people = contributors.profiles(commits, as_of)
    cutoff = as_of - timedelta(days=anomaly.NEW_CONTRIBUTOR_DAYS)
    recent: dict[str, int] = {}
    for commit in activity.dated(commits):
        if commit["at"] >= cutoff:
            key = contributors.maintainer_id(contributors.identity(commit)[0])
            recent[key] = recent.get(key, 0) + 1
    for person in people:
        person["recent_30d"] = recent.get(person["maintainer_id"], 0)
    spread = contributors.concentration(people)
    frequency = activity.commit_frequency(commits, as_of)
    series = activity.weekly_series(commits, as_of)
    release_stats = activity.release_frequency(releases or [], as_of)
    gaps = activity.inactivity_gaps(commits, anomaly.INACTIVITY_DAYS)
    clusters = activity.rapid_clusters(commits, anomaly.CLUSTER_WINDOW_MINUTES, anomaly.CLUSTER_MIN_COMMITS)
    changes = change_patterns.summarise(analysed_commits)

    indicators = [
        anomaly.contributor_concentration(spread),
        anomaly.ownership_concentration(releases or [], changes, spread["contributors"]),
        anomaly.sudden_activity_change(series, people, as_of),
        anomaly.unusual_release_pattern(release_stats, releases is not None),
        anomaly.security_sensitive_change(changes),
        anomaly.long_inactivity(frequency, gaps, as_of),
        anomaly.rapid_change_cluster(clusters, frequency["dated"]),
    ]
    scored = anomaly.score(indicators, frequency["dated"])

    by_person = changes.get("by_contributor") or {}
    for person in people:
        person["change_patterns"] = by_person.get(person["maintainer_id"])
        person["indicators"] = _personal(person, indicators)
    listed = listed_contributors or []
    profile = {
        "maintainer_id": people[0]["maintainer_id"] if people else None,     # the most active contributor in the observed history
        "contributor_count": len(people),
        "contributor_count_listed_by_github": len(listed) if listed_contributors is not None else None,
        "commit_frequency": frequency, "contributor_concentration": spread, "release_frequency": release_stats,
        "activity_pattern": activity.activity_pattern(commits), "weekly_activity": series[-104:],
        "inactivity_gaps": gaps[:10], "rapid_clusters": clusters[:10],
        "change_patterns": {k: v for k, v in changes.items() if k != "by_contributor"},
        "anomaly_indicators": indicators, "attention_score": scored["score"], "attention_level": scored["level"],
        "confidence": scored["confidence"], "score_detail": scored,
        "evidence": {
            "commits_observed": len(commits), "commits_truncated": commits_truncated,
            "newest_commit": commits[0]["sha"] if commits else None, "oldest_commit": commits[-1]["sha"] if commits else None,
            "releases_observed": len(releases) if releases is not None else None,
            "commit_analysis_rows": len(analysed_commits),
            "sources": ["GitHub REST API: commits, contributors, releases (public metadata)"],
        },
        "meaning": anomaly.MEANING, "model_version": anomaly.MODEL_VERSION,
    }
    return {"profile": profile, "contributors": people}


def _personal(person: dict[str, Any], indicators: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Indicators whose evidence names this contributor. They describe the repository's pattern, not the person's character."""
    mine = []
    for item in indicators:
        if item["status"] != anomaly.OBSERVED:
            continue
        evidence = item["evidence"]
        named = (evidence.get("top_contributor") or {}).get("maintainer_id") == person["maintainer_id"] \
            or any(entry.get("maintainer_id") == person["maintainer_id"] for entry in evidence.get("new_contributors") or []) \
            or any(entry.get("maintainer_id") == person["maintainer_id"] for entry in evidence.get("security_commits") or [])
        if named:
            mine.append({"type": item["type"], "detail": item["detail"]})
    return mine
