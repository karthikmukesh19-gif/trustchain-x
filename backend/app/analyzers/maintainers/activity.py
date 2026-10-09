"""Activity measures of a repository's commit and release history. Pure functions over normalised records."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Any

WEEK = timedelta(days=7)


def _aware(moment: datetime) -> datetime:
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc)


def dated(commits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Commits that carry a usable time, oldest first. The time used is when the commit was authored."""
    usable = []
    for commit in commits:
        moment = commit.get("authored_at") or commit.get("committed_at")
        if isinstance(moment, datetime):
            usable.append({**commit, "at": _aware(moment)})
    return sorted(usable, key=lambda item: (item["at"], item["sha"]))


def commit_frequency(commits: list[dict[str, Any]], as_of: datetime) -> dict[str, Any]:
    history = dated(commits)
    if not history:
        return {"total": len(commits), "dated": 0, "first_at": None, "last_at": None, "span_days": None, "per_week_mean": None,
                "per_week_median": None, "active_weeks": 0, "weeks": 0, "days_since_last": None}
    first, last = history[0]["at"], history[-1]["at"]
    series = weekly_series(commits, as_of)
    counts = [week["commits"] for week in series]
    return {
        "total": len(commits), "dated": len(history), "first_at": first, "last_at": last, "span_days": max(0, (last - first).days),
        "per_week_mean": round(sum(counts) / len(counts), 2) if counts else None,
        "per_week_median": float(median(counts)) if counts else None,
        "active_weeks": sum(1 for count in counts if count), "weeks": len(counts),
        "days_since_last": max(0, (as_of - last).days),
    }


def weekly_series(commits: list[dict[str, Any]], as_of: datetime, max_weeks: int = 104) -> list[dict[str, Any]]:
    """Commits and distinct contributors per week, from the first observed commit to `as_of`. Weeks end at `as_of`."""
    history = dated(commits)
    if not history:
        return []
    weeks = min(max_weeks, max(1, ((as_of - history[0]["at"]).days // 7) + 1))
    start = as_of - weeks * WEEK
    buckets: list[dict[str, Any]] = [{"week_start": start + index * WEEK, "commits": 0, "people": set()} for index in range(weeks)]
    for commit in history:
        index = int((commit["at"] - start) / WEEK)
        if 0 <= index < weeks:
            buckets[index]["commits"] += 1
            buckets[index]["people"].add(commit.get("author_login") or commit.get("author_email_tag") or commit.get("author_name"))
    return [{"week_start": bucket["week_start"], "commits": bucket["commits"], "contributors": len(bucket["people"] - {None})}
            for bucket in buckets]


def inactivity_gaps(commits: list[dict[str, Any]], min_days: int) -> list[dict[str, Any]]:
    """Periods of at least `min_days` between two consecutive commits, longest first."""
    history = dated(commits)
    gaps = [{"from": before["at"], "to": after["at"], "days": (after["at"] - before["at"]).days}
            for before, after in zip(history, history[1:]) if (after["at"] - before["at"]).days >= min_days]
    return sorted(gaps, key=lambda gap: (-gap["days"], gap["from"]))


def rapid_clusters(commits: list[dict[str, Any]], window_minutes: int, min_commits: int) -> list[dict[str, Any]]:
    """Non-overlapping runs of at least `min_commits` commits inside `window_minutes`, largest first."""
    history = dated(commits)
    window = timedelta(minutes=window_minutes)
    clusters = []
    start = 0
    while start < len(history):
        end = start
        while end + 1 < len(history) and history[end + 1]["at"] - history[start]["at"] <= window:
            end += 1
        size = end - start + 1
        if size >= min_commits:
            members = history[start:end + 1]
            people = {m.get("author_login") or m.get("author_email_tag") or m.get("author_name") for m in members} - {None}
            clusters.append({"start": members[0]["at"], "end": members[-1]["at"], "commits": size, "contributors": len(people),
                             "first_sha": members[0]["sha"], "last_sha": members[-1]["sha"]})
            start = end + 1
        else:
            start += 1
    return sorted(clusters, key=lambda cluster: (-cluster["commits"], cluster["start"]))


def release_frequency(releases: list[dict[str, Any]], as_of: datetime) -> dict[str, Any]:
    moments = sorted(_aware(r["published_at"]) for r in releases if isinstance(r.get("published_at"), datetime))
    intervals = [round((after - before).total_seconds() / 86400, 2) for before, after in zip(moments, moments[1:])]
    return {
        "total": len(moments), "first_at": moments[0] if moments else None, "last_at": moments[-1] if moments else None,
        "median_interval_days": round(float(median(intervals)), 2) if intervals else None,
        "latest_interval_days": intervals[-1] if intervals else None,
        "days_since_last": max(0, (as_of - moments[-1]).days) if moments else None,
        "prereleases": sum(1 for r in releases if r.get("prerelease")),
        "intervals": intervals[-50:],
    }


def activity_pattern(commits: list[dict[str, Any]]) -> dict[str, Any]:
    """When work happens, in UTC. A description only: time zones and habits differ between people."""
    by_weekday, by_hour = [0] * 7, [0] * 24
    for commit in dated(commits):
        moment = commit["at"].astimezone(timezone.utc)
        by_weekday[moment.weekday()] += 1
        by_hour[moment.hour] += 1
    return {"by_weekday": by_weekday, "by_hour_utc": by_hour, "timezone": "UTC"}
