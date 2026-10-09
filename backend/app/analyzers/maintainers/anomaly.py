"""Behavioural indicators and the attention score built from them (model "maintainer-behaviour-v1").

Each indicator is OBSERVED, NOT_OBSERVED or UNKNOWN. UNKNOWN means the data
needed to evaluate it was not available; it is never counted as "fine".

    attention_score = 100 × Σ(weight × strength of observed indicators) / Σ(weight of evaluated indicators)
    confidence      = Σ(weight of evaluated indicators) / Σ(all weights) × history sufficiency

The score says how much of the maintenance pattern deserves a look. It is not
a measure of trustworthiness of any person and no indicator means that
anyone did something wrong.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

MODEL_VERSION = "maintainer-behaviour-v1"

OBSERVED, NOT_OBSERVED, UNKNOWN = "OBSERVED", "NOT_OBSERVED", "UNKNOWN"
INDICATOR_WEIGHTS = {
    "CONTRIBUTOR_CONCENTRATION": 20, "OWNERSHIP_CONCENTRATION": 15, "SUDDEN_ACTIVITY_CHANGE": 15, "UNUSUAL_RELEASE_PATTERN": 10,
    "SECURITY_SENSITIVE_CHANGE": 15, "LONG_INACTIVITY": 15, "RAPID_CHANGE_CLUSTER": 10,
}
INDICATOR_TYPES = tuple(INDICATOR_WEIGHTS)

MIN_COMMITS = 10                    # fewer observed commits than this say too little about concentration
CONCENTRATION_SHARE = 0.6           # one contributor with at least this share of the commits
MIN_WEEKS = 8                       # history needed before a change in activity can be called a change
ACTIVITY_FACTOR = 3.0               # recent four weeks vs. what the earlier weeks would predict
MIN_RECENT_COMMITS = 10
NEW_CONTRIBUTOR_DAYS = 30
NEW_CONTRIBUTOR_SHARE = 0.3
MIN_RELEASES = 4
INACTIVITY_DAYS = 180
CLUSTER_WINDOW_MINUTES, CLUSTER_MIN_COMMITS = 60, 10
SUFFICIENT_COMMITS = 30             # history at which confidence is no longer reduced for being short
MEANING = ("A behavioural indicator describes a pattern in public repository metadata. It is not evidence of intent or wrongdoing, "
           "and no indicator is a judgement about a person.")


def _indicator(kind: str, status: str, strength: float, detail: str, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"type": kind, "status": status, "strength": round(max(0.0, min(1.0, strength)), 2) if status == OBSERVED else 0.0,
            "weight": INDICATOR_WEIGHTS[kind], "detail": detail, "evidence": evidence or {}, "basis": "DERIVED" if status != UNKNOWN else "UNKNOWN"}


def contributor_concentration(concentration: dict[str, Any]) -> dict[str, Any]:
    kind = "CONTRIBUTOR_CONCENTRATION"
    if not concentration.get("commits") or concentration["commits"] < MIN_COMMITS:
        return _indicator(kind, UNKNOWN, 0, f"Fewer than {MIN_COMMITS} commits were observed; concentration is not evaluated on so little history.",
                          {"commits": concentration.get("commits", 0)})
    share, top = concentration["top_share"], concentration["top_contributor"]
    evidence = {"top_share": share, "top_contributor": top, "contributors": concentration["contributors"], "commits": concentration["commits"],
                "threshold": CONCENTRATION_SHARE}
    if share >= CONCENTRATION_SHARE:
        return _indicator(kind, OBSERVED, 0.5 + (share - CONCENTRATION_SHARE) / (2 * (1 - CONCENTRATION_SHARE)),
                          f"{top['display_name']} authored {share:.0%} of the {concentration['commits']} observed commits "
                          f"({concentration['contributors']} contributor(s) in total). The project depends heavily on one contributor.", evidence)
    return _indicator(kind, NOT_OBSERVED, 0, f"The most active contributor authored {share:.0%} of the observed commits.", evidence)


def ownership_concentration(releases: list[dict[str, Any]], changes: dict[str, Any], contributors: int) -> dict[str, Any]:
    kind = "OWNERSHIP_CONCENTRATION"
    authored = [r["author_login"] for r in releases if r.get("author_login")]
    sensitive = {key: value["security_sensitive"] for key, value in (changes.get("by_contributor") or {}).items() if value["security_sensitive"]}
    sensitive_total = sum(sensitive.values())
    evidence: dict[str, Any] = {"releases_with_author": len(authored), "release_publishers": len(set(authored)),
                                "security_sensitive_commits": sensitive_total, "contributors_making_them": len(sensitive)}
    reasons = []
    strength = 0.0
    if len(authored) >= 3 and len(set(authored)) == 1:
        reasons.append(f"all {len(authored)} releases with a known publisher were published by one account ({authored[0]})")
        strength = max(strength, 0.6 if contributors <= 1 else 0.8)
    if sensitive_total >= 5 and len(sensitive) == 1:
        reasons.append(f"all {sensitive_total} analysed security-sensitive commits were made by one contributor")
        strength = max(strength, 0.6 if contributors <= 1 else 0.8)
    if reasons:
        return _indicator(kind, OBSERVED, strength, "Control is concentrated: " + "; ".join(reasons) + ".", evidence)
    if len(authored) < 3 and not changes.get("available"):
        return _indicator(kind, UNKNOWN, 0, "Fewer than three releases have a known publisher and no commit behaviour analysis exists, "
                          "so who controls releases and security-sensitive files is not established.", evidence)
    return _indicator(kind, NOT_OBSERVED, 0, "Releases and security-sensitive changes are not confined to a single account in the analysed data.",
                      evidence)


def sudden_activity_change(series: list[dict[str, Any]], people: list[dict[str, Any]], as_of: datetime) -> dict[str, Any]:
    kind = "SUDDEN_ACTIVITY_CHANGE"
    if len(series) < MIN_WEEKS:
        return _indicator(kind, UNKNOWN, 0, f"Fewer than {MIN_WEEKS} weeks of history were observed; a change in activity cannot be told from normal variation.",
                          {"weeks": len(series)})
    recent = sum(week["commits"] for week in series[-4:])
    earlier = [week["commits"] for week in series[:-4]]
    expected = 4 * sum(earlier) / len(earlier)
    evidence: dict[str, Any] = {"recent_4_weeks": recent, "expected_from_earlier_weeks": round(expected, 1), "weeks": len(series),
                                "factor": ACTIVITY_FACTOR}
    reasons, strength = [], 0.0
    if recent >= MIN_RECENT_COMMITS and recent >= ACTIVITY_FACTOR * max(expected, 1.0):
        reasons.append(f"{recent} commits in the last four weeks against about {expected:.1f} expected from the earlier weeks")
        strength = max(strength, min(1.0, recent / (2 * ACTIVITY_FACTOR * max(expected, 1.0)) + 0.25))
    if expected >= MIN_RECENT_COMMITS and recent * ACTIVITY_FACTOR <= expected:
        reasons.append(f"only {recent} commits in the last four weeks against about {expected:.1f} expected from the earlier weeks")
        strength = max(strength, 0.6)
    cutoff = as_of - timedelta(days=NEW_CONTRIBUTOR_DAYS)
    recent_total = sum(person.get("recent_30d", 0) for person in people)
    for person in people:
        if person["first_commit_at"] >= cutoff and recent_total >= 5 and person.get("recent_30d", 0) / recent_total >= NEW_CONTRIBUTOR_SHARE \
                and len(people) > 1:
            share = person["recent_30d"] / recent_total
            reasons.append(f"{person['display_name']} first appears within the last {NEW_CONTRIBUTOR_DAYS} days and authored {share:.0%} of the "
                           "commits in that period")
            evidence.setdefault("new_contributors", []).append({"maintainer_id": person["maintainer_id"], "share_of_recent": round(share, 2)})
            strength = max(strength, min(1.0, 0.4 + share / 2))
    if reasons:
        return _indicator(kind, OBSERVED, strength, "Activity changed: " + "; ".join(reasons) + ".", evidence)
    return _indicator(kind, NOT_OBSERVED, 0, "Recent activity is in line with the earlier history.", evidence)


def unusual_release_pattern(frequency: dict[str, Any], releases_available: bool) -> dict[str, Any]:
    kind = "UNUSUAL_RELEASE_PATTERN"
    if not releases_available:
        return _indicator(kind, UNKNOWN, 0, "Release data could not be collected from GitHub.")
    if frequency["total"] < MIN_RELEASES:
        return _indicator(kind, UNKNOWN, 0, f"{frequency['total']} release(s) are published on GitHub; at least {MIN_RELEASES} are needed to "
                          "describe a release pattern. (Projects may publish elsewhere, for example straight to a package registry.)",
                          {"releases": frequency["total"]})
    intervals, median_days, latest = frequency["intervals"], frequency["median_interval_days"], frequency["latest_interval_days"]
    evidence = {"releases": frequency["total"], "median_interval_days": median_days, "latest_interval_days": latest}
    reasons, strength = [], 0.0
    if median_days >= 7 and latest < 0.1 * median_days:
        reasons.append(f"the latest release followed the previous one after {latest} day(s); the median interval is {median_days} days")
        strength = max(strength, 0.6)
    if len(intervals) >= 2 and sum(1 for value in intervals[-3:] if value < 1) >= 2 and median_days >= 7:
        reasons.append("several of the latest releases were published within a day of each other")
        strength = max(strength, 0.7)
    if median_days > 0 and latest > 5 * median_days and latest >= 90:
        reasons.append(f"the latest release came {latest:.0f} days after the previous one; the median interval is {median_days} days")
        strength = max(strength, 0.5)
    if reasons:
        return _indicator(kind, OBSERVED, strength, "Release timing departs from the project's own history: " + "; ".join(reasons) + ".", evidence)
    return _indicator(kind, NOT_OBSERVED, 0, "Release timing is in line with the project's own history.", evidence)


def security_sensitive_change(changes: dict[str, Any]) -> dict[str, Any]:
    kind = "SECURITY_SENSITIVE_CHANGE"
    if not changes.get("available"):
        return _indicator(kind, UNKNOWN, 0, changes.get("reason") or "No commit behaviour analysis exists.")
    evidence = {"analysed_commits": changes["commits"], "security_sensitive_commits": changes["security_sensitive"],
                "security_commits": changes["security_commits"][:10]}
    if changes["security_sensitive"]:
        share = changes["security_sensitive"] / changes["commits"]
        return _indicator(kind, OBSERVED, min(1.0, 0.3 + share),
                          f"{changes['security_sensitive']} of {changes['commits']} analysed commits changed security-sensitive files or code "
                          "(authentication, security configuration, command execution, network use or secret-like values). "
                          "Such changes are routine; they are listed because they deserve review.", evidence)
    return _indicator(kind, NOT_OBSERVED, 0, f"None of the {changes['commits']} analysed commits changed security-sensitive files or code.", evidence)


def long_inactivity(frequency: dict[str, Any], gaps: list[dict[str, Any]], as_of: datetime) -> dict[str, Any]:
    kind = "LONG_INACTIVITY"
    if frequency["days_since_last"] is None:
        return _indicator(kind, UNKNOWN, 0, "No dated commit was observed.")
    since = frequency["days_since_last"]
    evidence = {"days_since_last_commit": since, "last_commit_at": frequency["last_at"], "threshold_days": INACTIVITY_DAYS,
                "gaps": gaps[:5]}
    if since >= INACTIVITY_DAYS:
        return _indicator(kind, OBSERVED, min(1.0, since / 730), f"The newest observed commit is {since} days old.", evidence)
    resumed = [gap for gap in gaps if (as_of - gap["to"]).days <= 90]
    if resumed:
        gap = resumed[0]
        return _indicator(kind, OBSERVED, min(1.0, 0.3 + gap["days"] / 1460),
                          f"Activity resumed within the last 90 days after a pause of {gap['days']} days.", evidence)
    return _indicator(kind, NOT_OBSERVED, 0, f"The newest observed commit is {since} day(s) old and no long pause ended recently.", evidence)


def rapid_change_cluster(clusters: list[dict[str, Any]], commits: int) -> dict[str, Any]:
    kind = "RAPID_CHANGE_CLUSTER"
    if commits < CLUSTER_MIN_COMMITS:
        return _indicator(kind, UNKNOWN, 0, f"Fewer than {CLUSTER_MIN_COMMITS} commits were observed.", {"commits": commits})
    evidence = {"window_minutes": CLUSTER_WINDOW_MINUTES, "min_commits": CLUSTER_MIN_COMMITS, "clusters": clusters[:5]}
    if clusters:
        largest = clusters[0]
        return _indicator(kind, OBSERVED, min(1.0, 0.4 + largest["commits"] / (5 * CLUSTER_MIN_COMMITS)),
                          f"{len(clusters)} burst(s) of at least {CLUSTER_MIN_COMMITS} commits within {CLUSTER_WINDOW_MINUTES} minutes; the "
                          f"largest has {largest['commits']} commits. (Rebases, imports and squashed work also look like this.)", evidence)
    return _indicator(kind, NOT_OBSERVED, 0, f"No {CLUSTER_WINDOW_MINUTES}-minute window holds {CLUSTER_MIN_COMMITS} or more commits.", evidence)


def unavailable(reason: str) -> list[dict[str, Any]]:
    """Every indicator as UNKNOWN: the history could not be collected."""
    return [_indicator(kind, UNKNOWN, 0, reason) for kind in INDICATOR_TYPES]


def score(indicators: list[dict[str, Any]], observed_commits: int) -> dict[str, Any]:
    evaluated = [item for item in indicators if item["status"] != UNKNOWN]
    weight = sum(item["weight"] for item in evaluated)
    total_weight = sum(INDICATOR_WEIGHTS.values())
    sufficiency = min(1.0, observed_commits / SUFFICIENT_COMMITS) if observed_commits else 0.0
    confidence = round(weight / total_weight * sufficiency, 2)
    if not weight:
        return {"score": None, "level": "UNKNOWN", "confidence": 0.0, "evaluated_weight": 0, "total_weight": total_weight,
                "observed": 0, "unknown": len(indicators), "history_sufficiency": round(sufficiency, 2)}
    value = round(100 * sum(item["weight"] * item["strength"] for item in evaluated) / weight, 1)
    return {"score": value, "level": "HIGH" if value >= 50 else "MEDIUM" if value >= 20 else "LOW", "confidence": confidence,
            "evaluated_weight": weight, "total_weight": total_weight,
            "observed": sum(1 for item in indicators if item["status"] == OBSERVED),
            "unknown": sum(1 for item in indicators if item["status"] == UNKNOWN), "history_sufficiency": round(sufficiency, 2)}
