"""Ecosystem-aware version ordering.

Each ecosystem orders versions by its own rules, so versions are parsed into
comparable keys by an ecosystem-specific scheme. A version the scheme cannot
parse raises UnsupportedVersion: callers must record "cannot be compared"
rather than fall back to string comparison, which would get 1.0.9 < 1.0.10
wrong and could invent or hide a match.

Schemes
  pep440   PyPI, through `packaging` (the reference implementation)
  semver   npm, crates.io and Go modules: SemVer 2.0.0 precedence, including
           pre-release ordering; build metadata is ignored; a leading "v" is
           accepted (Go); missing minor/patch parts are read as 0
  maven    a deliberately restricted subset of Maven ordering: dotted numbers
           with an optional well-known qualifier (alpha, beta, milestone, rc,
           snapshot, ga/final/release, sp). Anything else is unsupported.

Ecosystems with no scheme (conan, vcpkg, cmake, ...) can still be matched
against versions a source lists explicitly, never against ranges.
"""

from __future__ import annotations

import re
from functools import total_ordering
from typing import Any, Callable

from packaging.version import InvalidVersion, Version

MAX_VERSION_LENGTH = 200


class UnsupportedVersion(ValueError):
    """The version cannot be ordered safely under the ecosystem's scheme."""


@total_ordering
class _Lowest:
    """OSV's "0" event: sorts before every real version."""

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _Lowest)

    def __lt__(self, other: object) -> bool:
        return not isinstance(other, _Lowest)

    def __hash__(self) -> int:
        return 0

    def __repr__(self) -> str:
        return "<lowest>"


LOWEST = _Lowest()


def _check(text: Any) -> str:
    if not isinstance(text, str) or not text.strip() or len(text) > MAX_VERSION_LENGTH:
        raise UnsupportedVersion("not a version string")
    return text.strip()


# --- PEP 440 -------------------------------------------------------------------

def _pep440(text: str) -> Version:
    try:
        return Version(_check(text))
    except InvalidVersion as exc:
        raise UnsupportedVersion(f"not a PEP 440 version: {text[:60]!r}") from exc


# --- SemVer --------------------------------------------------------------------

_SEMVER = re.compile(
    r"^v?(0|[1-9]\d*)(?:\.(0|[1-9]\d*))?(?:\.(0|[1-9]\d*))?"
    r"(?:-((?:[0-9A-Za-z-]+)(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z.-]+)?$"
)


def _semver(text: str) -> tuple:
    match = _SEMVER.match(_check(text))
    if match is None:
        raise UnsupportedVersion(f"not a semantic version: {text[:60]!r}")
    major, minor, patch, pre = match.groups()
    release = (int(major), int(minor or 0), int(patch or 0))
    if pre is None:
        # A release sorts after every pre-release of the same version.
        return (release, 1, ())
    identifiers = []
    for part in pre.split("."):
        # Numeric identifiers sort numerically and before alphanumeric ones.
        identifiers.append((0, int(part), "") if part.isdigit() else (1, 0, part))
    return (release, 0, tuple(identifiers))


# --- Maven (restricted) ----------------------------------------------------------

_MAVEN = re.compile(
    r"^(\d+(?:\.\d+)*)(?:[-.]?(alpha|a|beta|b|milestone|m|rc|cr|snapshot|ga|final|release|sp)[-.]?(\d*))?$",
    re.IGNORECASE,
)
_MAVEN_QUALIFIER = {
    "alpha": 1, "a": 1, "beta": 2, "b": 2, "milestone": 3, "m": 3, "rc": 4, "cr": 4, "snapshot": 5,
    "": 6, "ga": 6, "final": 6, "release": 6, "sp": 7,
}


def _maven(text: str) -> tuple:
    match = _MAVEN.match(_check(text))
    if match is None:
        raise UnsupportedVersion(f"Maven version outside the supported subset: {text[:60]!r}")
    numbers, qualifier, qualifier_number = match.groups()
    parts = [int(n) for n in numbers.split(".")]
    while len(parts) > 1 and parts[-1] == 0:   # 1.0 == 1.0.0 == 1
        parts.pop()
    return (tuple(parts), _MAVEN_QUALIFIER[(qualifier or "").lower()], int(qualifier_number or 0))


SCHEMES: dict[str, tuple[str, Callable[[str], Any]]] = {
    "pypi": ("pep440", _pep440),
    "npm": ("semver", _semver),
    "cargo": ("semver", _semver),
    "golang": ("semver", _semver),
    "maven": ("maven-subset", _maven),
}


def scheme_name(ecosystem: str) -> str | None:
    entry = SCHEMES.get(ecosystem)
    return entry[0] if entry else None


def parse(ecosystem: str, text: Any) -> Any:
    """Return a comparable key for `text`, or raise UnsupportedVersion."""
    entry = SCHEMES.get(ecosystem)
    if entry is None:
        raise UnsupportedVersion(f"no version ordering is implemented for ecosystem {ecosystem!r}")
    return entry[1](text)


def parse_event(ecosystem: str, text: Any) -> Any:
    """Like parse, but understands OSV's "0" ("before any version")."""
    if isinstance(text, str) and text.strip() == "0":
        return LOWEST
    return parse(ecosystem, text)


def same_version(ecosystem: str, left: Any, right: Any) -> bool:
    """Equality for versions a source lists explicitly.

    Uses the ecosystem's scheme when both sides parse (so 1.0 equals 1.0.0
    on PyPI); otherwise falls back to exact text, ignoring Go's "v" prefix.
    """
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        return parse(ecosystem, left) == parse(ecosystem, right)
    except UnsupportedVersion:
        a, b = left.strip(), right.strip()
        if ecosystem == "golang":
            a, b = a.removeprefix("v"), b.removeprefix("v")
        return a == b


def release_components(ecosystem: str, text: Any) -> tuple[tuple[int, ...], bool]:
    """(numeric release components, is a pre-release) for measuring how far apart two versions are.

    Raises UnsupportedVersion when the ecosystem has no ordering, the version does not
    parse, or its components are not comparable position by position (a PEP 440 epoch).
    """
    scheme = scheme_name(ecosystem)
    key = parse(ecosystem, text)
    if scheme == "pep440":
        if key.epoch:
            raise UnsupportedVersion("version uses an epoch; component distances are not meaningful")
        return tuple(key.release), bool(key.is_prerelease or key.is_devrelease)
    if scheme == "semver":
        return tuple(key[0]), key[1] == 0
    if scheme == "maven-subset":
        return tuple(key[0]), key[1] < 6
    raise UnsupportedVersion(f"no version ordering for ecosystem {ecosystem!r}")

