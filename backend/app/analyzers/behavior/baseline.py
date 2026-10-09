"""The repository's own earlier commits as a baseline for judging a new one."""

from __future__ import annotations

from datetime import datetime, timezone
from statistics import median
from typing import Any

MIN_COMMITS = 5              # fewer earlier commits than this are not a baseline
MIN_COMMITS_FOR_PEOPLE = 10  # needed before "this author is new here" means anything
MIN_COMMITS_FOR_HOURS = 30


def _mad(values: list[float], centre: float) -> float:
    return float(median(abs(value - centre) for value in values)) if values else 0.0


def build_baseline(previous: list[dict[str, Any]]) -> dict[str, Any]:
    """Typical size, authors and hours of earlier commits. `previous` holds stored commit analyses, in any order."""
    lines = [float((row.get("stats") or {}).get("lines") or 0) for row in previous]
    files = [float((row.get("stats") or {}).get("files") or 0) for row in previous]
    hours = [0] * 24
    authors: dict[str, dict[str, Any]] = {}
    for row in previous:
        moment = row.get("committed_at")
        if isinstance(moment, datetime):
            hours[(moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).hour] += 1
        key = row.get("author_key")
        if key:
            entry = authors.setdefault(key, {"commits": 0, "sensitive": False})
            entry["commits"] += 1
            entry["sensitive"] = entry["sensitive"] or bool(row.get("sensitive"))
    count = len(previous)
    median_lines, median_files = (float(median(lines)), float(median(files))) if count else (0.0, 0.0)
    return {
        "commits": count, "sufficient": count >= MIN_COMMITS,
        "median_lines": median_lines, "mad_lines": _mad(lines, median_lines), "median_files": median_files, "mad_files": _mad(files, median_files),
        "max_lines": max(lines, default=0.0), "max_files": max(files, default=0.0), "hours_utc": hours, "authors": authors,
    }


def deviation(value: float, centre: float, spread: float) -> float:
    """A robust z-score: how many scaled median absolute deviations `value` lies above the median.

    When the earlier commits barely vary (spread 0) the median itself, or 1,
    is used as the scale, so a repository of tiny uniform commits does not turn
    every slightly larger one into an outlier.
    """
    scale = 1.4826 * spread if spread > 0 else max(centre, 1.0)
    return round((value - centre) / scale, 2)


def public(baseline: dict[str, Any]) -> dict[str, Any]:
    """The baseline without per-author detail, for storing beside a commit's assessment."""
    return {key: baseline[key] for key in ("commits", "sufficient", "median_lines", "mad_lines", "median_files", "mad_files", "max_lines",
                                           "max_files")} | {"authors": len(baseline["authors"])}
