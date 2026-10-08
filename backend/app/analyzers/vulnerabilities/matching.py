"""Decide whether one observed package version is covered by one advisory.

Implements the evaluation described by the OSV schema: a version is affected
by an `affected` entry if the entry lists it explicitly, or if it falls inside
one of the entry's ranges. Ranges are sequences of events; `introduced` opens
an interval and `fixed` (exclusive), `last_affected` (inclusive) or `limit`
(exclusive) closes it.

Outcomes
  AFFECTED       the version is listed, or lies inside a range that could be
                 evaluated with the ecosystem's version ordering
  NOT_AFFECTED   every applicable range was evaluated and none contains it
  UNSUPPORTED    the question could not be answered safely: the version or a
                 range boundary is outside what the ordering scheme supports,
                 or only git-commit ranges are published. Never a guess.
"""

from __future__ import annotations

from itertools import groupby

from dataclasses import dataclass, field
from typing import Any

from app.analyzers.vulnerabilities.versions import LOWEST, UnsupportedVersion, parse, parse_event, same_version, scheme_name

AFFECTED = "AFFECTED"
NOT_AFFECTED = "NOT_AFFECTED"
UNSUPPORTED = "UNSUPPORTED"

VERSION_LISTED = "version_listed_by_source"
VERSION_RANGE = "version_range_match"

COMPARABLE_RANGE_TYPES = {"ECOSYSTEM", "SEMVER"}


@dataclass
class Evaluation:
    status: str
    evidence_type: str | None = None
    range_type: str | None = None
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    limit: str | None = None
    events: list[dict[str, str]] = field(default_factory=list)
    comparator: str | None = None
    reason: str = ""
    listed: bool = False        # the source also names this exact version

    @property
    def affected_range(self) -> str | None:
        """Human-readable form of the interval that matched."""
        if self.evidence_type == VERSION_LISTED:
            return "listed explicitly by the source"
        if self.evidence_type != VERSION_RANGE:
            return None
        lower = "all versions" if self.introduced in (None, "0") else f">= {self.introduced}"
        if self.fixed:
            upper = f"< {self.fixed}"
        elif self.last_affected:
            upper = f"<= {self.last_affected}"
        elif self.limit:
            upper = f"< {self.limit}"
        else:
            return f"{lower} (no fixed version published)" if lower != "all versions" else "all versions (no fixed version published)"
        return upper if lower == "all versions" else f"{lower}, {upper}"


def _intervals(ecosystem: str, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Turn a range's events into intervals. Raises UnsupportedVersion if a boundary cannot be ordered."""
    keyed = []
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            raise UnsupportedVersion("malformed range event")
        (kind, value), = event.items()
        if kind not in ("introduced", "fixed", "last_affected", "limit") or not isinstance(value, str):
            raise UnsupportedVersion("malformed range event")
        keyed.append((parse_event(ecosystem, value), kind, value))
    # Stable sort by version only, so events at the same version keep the order the source lists them in
    # ("fixed 2.0" then "introduced 2.0" closes one interval and opens the next).
    keyed.sort(key=lambda item: item[0])

    intervals: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for _key, members in groupby(keyed, key=lambda item: item[0]):
        group = list(members)
        if current is None:
            # Nothing is open, so an interval introduced at this version starts before anything at this version
            # ends it: "introduced X, last_affected X" is exactly X, "introduced X, fixed X" is empty.
            group.sort(key=lambda item: item[1] != "introduced")
        for key, kind, value in group:
            if kind == "introduced":
                if current is None:
                    current = {"introduced": value, "low": key, "high": None, "inclusive": False, "end_kind": None, "end": None}
            elif current is not None:
                current.update(high=key, inclusive=kind == "last_affected", end_kind=kind, end=value)
                intervals.append(current)
                current = None
    if current is not None:
        intervals.append(current)
    return intervals


def evaluate(ecosystem: str, version: str, affected: dict[str, Any]) -> Evaluation:
    """Evaluate one normalised `affected` entry (same ecosystem and package) against `version`."""
    listed = affected.get("versions") or []
    if any(same_version(ecosystem, version, candidate) for candidate in listed):
        # The explicit listing settles that the version is affected. If a range also contains it, report the
        # range instead: it carries the boundaries, including the fixed version, that explain the match.
        by_range = evaluate(ecosystem, version, {"ranges": affected.get("ranges")})
        if by_range.status == AFFECTED:
            by_range.listed = True
            by_range.reason += " The source also lists this version explicitly."
            return by_range
        return Evaluation(AFFECTED, VERSION_LISTED, comparator=scheme_name(ecosystem) or "exact", listed=True,
                          reason=f"The source lists version {version} as affected.")

    if affected.get("versions_truncated") or affected.get("ranges_truncated"):
        # Part of what the source publishes was not kept, so "not affected" cannot be concluded from what was.
        outcome = evaluate(ecosystem, version, {"versions": [], "ranges": affected.get("ranges")}) if affected.get("ranges") else None
        if outcome is not None and outcome.status == AFFECTED:
            return outcome
        return Evaluation(UNSUPPORTED, comparator=scheme_name(ecosystem),
                          reason="The source publishes more versions or ranges for this package than are stored, "
                                 "so the comparison is incomplete.")

    ranges = [r for r in affected.get("ranges") or [] if isinstance(r, dict)]
    comparable = [r for r in ranges if r.get("type") in COMPARABLE_RANGE_TYPES]
    scheme = scheme_name(ecosystem)

    if not comparable:
        if listed and not ranges:
            # The source enumerates affected versions and this one is not among them.
            return Evaluation(NOT_AFFECTED, comparator="exact", reason="The source lists affected versions and this one is not among them.")
        if ranges:
            return Evaluation(UNSUPPORTED, reason="The source describes this advisory only with source-code (git) ranges, "
                                                  "which cannot be compared with a package version.")
        return Evaluation(UNSUPPORTED, reason="The source publishes no versions or ranges for this package.")

    if scheme is None:
        return Evaluation(UNSUPPORTED, reason=f"No version ordering is implemented for ecosystem {ecosystem!r}, "
                                              "and the source does not list this version explicitly.")
    try:
        installed = parse(ecosystem, version)
    except UnsupportedVersion as exc:
        return Evaluation(UNSUPPORTED, comparator=scheme, reason=f"The installed version cannot be ordered ({exc}).")

    undecided: str | None = None
    for item in comparable:
        events = [e for e in item.get("events") or []]
        try:
            intervals = _intervals(ecosystem, events)
        except UnsupportedVersion as exc:
            undecided = f"A range boundary published by the source cannot be ordered ({exc})."
            continue
        for interval in intervals:
            low, high = interval["low"], interval["high"]
            above = low is LOWEST or installed >= low
            below = high is None or (installed <= high if interval["inclusive"] else installed < high)
            if above and below:
                result = Evaluation(AFFECTED, VERSION_RANGE, range_type=item.get("type"), introduced=interval["introduced"],
                                    events=events, comparator=scheme)
                if interval["end_kind"]:
                    setattr(result, interval["end_kind"], interval["end"])
                result.reason = f"Version {version} is inside the affected range ({result.affected_range})."
                return result
    if undecided:
        return Evaluation(UNSUPPORTED, comparator=scheme, reason=undecided)
    return Evaluation(NOT_AFFECTED, comparator=scheme, reason=f"Version {version} is outside every affected range published by the source.")
