"""Anomaly score of a commit against the repository's baseline (model "commit-behaviour-v1").

    anomaly_score = 100 × Σ(weight × value of evaluated factors) / Σ(weight of evaluated factors)

  security_signals        40   strength of the security-relevant findings in the diff
  size_deviation          25   lines changed, against the median of earlier commits
  breadth_deviation       10   files changed, against the median of earlier commits
  new_author              10   the author has no earlier commit in the baseline
  sensitive_first_touch   10   the author's first change to security-sensitive or dependency files
  unusual_hour             5   committed at an hour (UTC) in which no earlier commit was made

A factor that cannot be evaluated (too few earlier commits) is UNKNOWN and
left out of both sums; confidence falls accordingly. The score says how far
the commit departs from what is usual here. It is not a verdict on the
commit, and a low score is not a clearance.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.analyzers.behavior import baseline as B
from app.analyzers.behavior.security_changes import INFERRED, SEVERITY_RANK, _finding

MODEL_VERSION = "commit-behaviour-v1"
WEIGHTS = {"security_signals": 40, "size_deviation": 25, "breadth_deviation": 10, "new_author": 10, "sensitive_first_touch": 10,
           "unusual_hour": 5}
SEVERITY_VALUE = {"INFO": 0.1, "LOW": 0.25, "MEDIUM": 0.55, "HIGH": 0.85}
SECURITY_TYPES = ("SECURITY_CONFIG_CHANGE", "AUTH_CHANGE", "NETWORK_BEHAVIOUR_CHANGE", "COMMAND_EXECUTION_PATTERN", "SECRET_LIKE_PATTERN",
                  "DEPENDENCY_CHANGE")
OUTLIER_Z = 3.5
MEANING = ("An anomaly is a departure from this repository's usual commits. It is a reason to review a change, not a verdict on the "
           "change or on its author.")


def _factor(name: str, value: float | None, detail: str, inputs: dict[str, Any] | None = None) -> dict[str, Any]:
    known = value is not None
    return {"name": name, "weight": WEIGHTS[name], "status": "KNOWN" if known else "UNKNOWN",
            "value": round(max(0.0, min(1.0, value)), 3) if known else None,
            "contribution": None, "detail": detail, "inputs": inputs or {}}


def security_value(findings: list[dict[str, Any]]) -> tuple[float, dict[str, str]]:
    """Combined strength of the security-relevant findings: the strongest finding of each type, combined so that more types add up without exceeding 1."""
    strongest: dict[str, float] = {}
    severities: dict[str, str] = {}
    for item in findings:
        if item["type"] not in SECURITY_TYPES:
            continue
        value = SEVERITY_VALUE[item["severity"]] * item["confidence"]
        if value > strongest.get(item["type"], 0.0):
            strongest[item["type"]] = value
        if SEVERITY_RANK[item["severity"]] > SEVERITY_RANK.get(severities.get(item["type"], "INFO"), 0) or item["type"] not in severities:
            severities[item["type"]] = item["severity"]
    remaining = 1.0
    for value in strongest.values():
        remaining *= 1 - value
    return 1 - remaining, severities


def assess(result: dict[str, Any], commit: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    """Score one analysed commit against a baseline. Adds UNUSUAL_CHANGE_PATTERN findings that only a baseline can show.

    `result` is the output of analyse_commit; `commit` carries author_key and
    committed_at; `baseline` comes from build_baseline over earlier commits.
    """
    findings = list(result["findings"])
    stats = result["stats"]
    security, severities = security_value(findings)
    factors = [_factor("security_signals", security,
                       f"{len(severities)} kind(s) of security-relevant change in the diff." if severities else "No security-relevant pattern in the diff.",
                       {"by_type": severities})]

    is_merge = bool(commit.get("is_merge"))
    sufficient = baseline["sufficient"] and not is_merge
    line_z = B.deviation(stats["lines"], baseline["median_lines"], baseline["mad_lines"]) if sufficient else None
    file_z = B.deviation(stats["files"], baseline["median_files"], baseline["mad_files"]) if sufficient else None
    short = ("A merge commit's diff combines the commits it merges, so its size is not compared with ordinary commits." if is_merge else
             f"Only {baseline['commits']} earlier commit(s) are known; at least {B.MIN_COMMITS} are needed for a baseline.")
    factors.append(_factor("size_deviation", None if line_z is None else (line_z - 2) / 6,
                           short if line_z is None else f"{stats['lines']} lines changed; the median of {baseline['commits']} earlier commits is "
                           f"{baseline['median_lines']:.0f} (robust z {line_z}).", {"z": line_z, "lines": stats["lines"]}))
    factors.append(_factor("breadth_deviation", None if file_z is None else (file_z - 2) / 6,
                           short if file_z is None else f"{stats['files']} files changed; the median is {baseline['median_files']:.0f} (robust z {file_z}).",
                           {"z": file_z, "files": stats["files"]}))

    key = commit.get("author_key")
    people_known = baseline["commits"] >= B.MIN_COMMITS_FOR_PEOPLE and key is not None
    earlier = baseline["authors"].get(key) if key else None
    is_new = people_known and earlier is None
    factors.append(_factor("new_author", (1.0 if is_new else 0.0) if people_known else None,
                           ("The author has no commit among the earlier ones." if is_new else "The author has earlier commits here.") if people_known
                           else f"Fewer than {B.MIN_COMMITS_FOR_PEOPLE} earlier commits are known, or the author could not be identified.",
                           {"earlier_commits_by_author": (earlier or {}).get("commits", 0) if people_known else None}))
    sensitive_now = bool(severities)
    first_touch = people_known and sensitive_now and not (earlier or {}).get("sensitive")
    factors.append(_factor("sensitive_first_touch", (1.0 if first_touch else 0.0) if people_known else None,
                           ("This is the author's first change here to security-sensitive or dependency files." if first_touch else
                            "Not a first change to security-sensitive or dependency files by this author.") if people_known
                           else "Not evaluated without enough earlier commits.", {}))
    moment = commit.get("committed_at")
    hour = (moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).hour if isinstance(moment, datetime) else None
    hours_known = baseline["commits"] >= B.MIN_COMMITS_FOR_HOURS and hour is not None
    odd_hour = hours_known and baseline["hours_utc"][hour] == 0
    factors.append(_factor("unusual_hour", (1.0 if odd_hour else 0.0) if hours_known else None,
                           (f"No earlier commit was made at {hour:02d}:00 UTC." if odd_hour else f"Earlier commits were also made at {hour:02d}:00 UTC.")
                           if hours_known else f"Fewer than {B.MIN_COMMITS_FOR_HOURS} earlier commits are known.", {"hour_utc": hour}))

    reasons = []
    if line_z is not None and line_z >= OUTLIER_Z:
        reasons.append(f"it changes {stats['lines']} lines, far more than the usual {baseline['median_lines']:.0f}")
    if file_z is not None and file_z >= OUTLIER_Z:
        reasons.append(f"it changes {stats['files']} files, far more than the usual {baseline['median_files']:.0f}")
    if is_new and sensitive_now:
        reasons.append("an author with no earlier commit here changes security-sensitive or dependency files")
    if reasons:
        findings.append(_finding("UNUSUAL_CHANGE_PATTERN", "departs_from_baseline", "MEDIUM" if len(reasons) > 1 or (is_new and sensitive_now) else "LOW",
                                 INFERRED, 0.6, "", "Compared with earlier commits: " + "; ".join(reasons) + "."))

    evaluated = [factor for factor in factors if factor["status"] == "KNOWN"]
    weight = sum(factor["weight"] for factor in evaluated)
    for factor in evaluated:
        factor["contribution"] = round(100 * factor["weight"] * factor["value"] / weight, 1)
    score = round(sum(factor["contribution"] for factor in evaluated), 1)
    coverage = 1.0 if result["coverage"]["complete"] else 0.7
    confidence = round(weight / sum(WEIGHTS.values()) * coverage, 2)
    findings.sort(key=lambda item: (-SEVERITY_RANK[item["severity"]], item["type"], item["file"], item["line"] or 0, item["rule"]))
    return {
        "anomaly_score": score, "level": "HIGH" if score >= 50 else "MEDIUM" if score >= 20 else "LOW", "confidence": confidence,
        "factors": factors, "findings": findings, "indicator_types": sorted({item["type"] for item in findings}),
        "baseline": B.public(baseline), "sensitive": sensitive_now, "meaning": MEANING, "model_version": MODEL_VERSION,
    }
