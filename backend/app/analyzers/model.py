"""Data model shared by parsers and the resolver.

Epistemic labels used throughout Phase 2:

OBSERVED  read directly from a repository file
INFERRED  derived by a documented rule from observed facts
UNKNOWN   the repository evidence cannot establish it
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

OBSERVED = "OBSERVED"
INFERRED = "INFERRED"
UNKNOWN = "UNKNOWN"

DIRECT = "DIRECT"
TRANSITIVE = "TRANSITIVE"

MANIFEST = "manifest"
LOCKFILE = "lockfile"

PARSED = "PARSED"
PARSE_ERROR = "ERROR"
NOT_EVALUATED = "NOT_EVALUATED"   # executable build script, deliberately not run
UNSUPPORTED = "UNSUPPORTED"       # package manager recognised, extraction not implemented
SKIPPED = "SKIPPED"               # over a size or count limit

MAX_RAW = 300
MAX_INTEGRITY = 20
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean(text: Any, limit: int = MAX_RAW) -> str:
    """Make repository-provided text safe to store and display."""
    if not isinstance(text, str):
        text = str(text)
    return _CONTROL.sub("", text).strip()[:limit]


@dataclass
class Declared:
    """A dependency declared in a manifest."""

    ecosystem: str
    package_manager: str
    name: str
    source_file: str
    line: int | None = None
    raw: str = ""
    constraint: str | None = None
    exact_version: str | None = None
    scope: str = "runtime"
    optional: bool = False
    extras: tuple[str, ...] = ()
    marker: str | None = None
    source: dict[str, str] | None = None
    integrity: list[dict[str, str]] = field(default_factory=list)
    relationship: str = DIRECT
    basis: str = OBSERVED
    reason: str = ""


@dataclass
class Locked:
    """A resolved package recorded in a lockfile."""

    ecosystem: str
    package_manager: str
    name: str
    version: str | None
    source_file: str
    key: str                                   # unique within the lockfile
    line: int | None = None
    dev: bool = False
    scope_known: bool = False                  # the lockfile distinguishes dev-only packages
    optional: bool = False
    integrity: list[dict[str, str]] = field(default_factory=list)
    source: dict[str, str] | None = None
    direct: bool | None = None                 # None: the lockfile does not say
    local: bool = False                        # the project itself / a workspace member
    deps: list[tuple[str, str | None, str | None]] = field(default_factory=list)  # (name, spec, resolved key)


@dataclass
class ParsedFile:
    path: str
    kind: str
    package_manager: str
    ecosystem: str
    status: str = PARSED
    error: str | None = None
    declared: list[Declared] = field(default_factory=list)
    locked: list[Locked] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    includes: list[str] = field(default_factory=list)       # other repository files this one references
    spec_index: dict[str, str] = field(default_factory=dict)  # "name@range" -> lock key (yarn)
    integrity_index: dict[tuple[str, str], dict[str, str]] = field(default_factory=dict)  # go.sum
    records_edges: bool = False     # the lockfile records which package requires which
    records_roots: bool = False     # the lockfile records which packages are direct
    reliable_manifest: bool = True  # False for pattern-matched build scripts

    def note(self, text: str) -> None:
        text = clean(text, 400)
        if text and text not in self.notes and len(self.notes) < 50:
            self.notes.append(text)


class ParseFailure(Exception):
    """The file could not be parsed. The message is safe to show to the user."""


def find_line(text: str, needle: str) -> int | None:
    """1-based line of the first line mentioning `needle` as a whole token (best effort)."""
    if not needle:
        return None
    pattern = re.compile(r"(?<![A-Za-z0-9_.-])" + re.escape(needle) + r"(?![A-Za-z0-9_-])")
    for number, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            return number
    return None


def sri(value: Any) -> list[dict[str, str]]:
    """Split Subresource-Integrity strings ("sha512-abc sha1-def") into records."""
    out: list[dict[str, str]] = []
    if isinstance(value, str):
        for part in value.split():
            algorithm, sep, digest = part.partition("-")
            if sep and algorithm.isalnum() and digest:
                out.append({"algorithm": algorithm.lower(), "value": clean(digest, 200)})
    return out[:MAX_INTEGRITY]
