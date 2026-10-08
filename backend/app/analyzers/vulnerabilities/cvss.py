"""CVSS vectors: parsing, and the base score for CVSS v3.0 / v3.1.

A source usually publishes a vector, not a number. For v3.x the base score is
a fixed function of the vector (FIRST CVSS v3.1 specification, section 7), so
computing it reproduces a published fact rather than estimating anything; the
result is stored as `base_score` with `score_origin: "computed_from_vector"`.

CVSS v2 and v4 vectors are preserved as published and not scored here
(`base_score: null`): v4 scoring needs the specification's lookup tables,
which are not implemented.
"""

from __future__ import annotations

from decimal import ROUND_CEILING, Decimal
from typing import Any

_V3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_V3_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_V3_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

TYPE_VERSIONS = {"CVSS_V2": "2.0", "CVSS_V3": "3", "CVSS_V4": "4.0"}


def _roundup(value: float) -> float:
    """CVSS "round up to one decimal", done in decimal arithmetic to avoid float artefacts."""
    return float((Decimal(repr(round(value, 10))) * 10).to_integral_value(rounding=ROUND_CEILING) / 10)


def v3_base_score(vector: str) -> float | None:
    """Base score for a CVSS v3.0/v3.1 vector, or None if the vector is not valid."""
    if not isinstance(vector, str) or len(vector) > 300:
        return None
    parts = vector.strip().split("/")
    if not parts or parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        return None
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, sep, value = part.partition(":")
        if not sep or key in metrics:
            return None
        metrics[key] = value
    if any(key not in metrics for key in _V3_REQUIRED) or metrics["S"] not in ("U", "C"):
        return None
    try:
        scope_changed = metrics["S"] == "C"
        av, ac, ui = (_V3_WEIGHTS[k][metrics[k]] for k in ("AV", "AC", "UI"))
        pr = _V3_PR[metrics["S"]][metrics["PR"]]
        c, i, a = (_V3_WEIGHTS[k][metrics[k]] for k in ("C", "I", "A"))
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    total = 1.08 * (impact + exploitability) if scope_changed else impact + exploitability
    return _roundup(min(total, 10.0))


def rating(score: float | None) -> str | None:
    """CVSS v3 qualitative severity rating for a base score (None for no score or 0.0)."""
    if score is None or score <= 0:
        return None
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def describe(kind: Any, vector: Any) -> dict[str, Any] | None:
    """Normalise one published severity entry ({type, score}) into a stored CVSS record."""
    if not isinstance(kind, str) or not isinstance(vector, str) or not vector.strip() or len(vector) > 300:
        return None
    vector = vector.strip()
    record: dict[str, Any] = {"type": kind[:30], "vector": vector, "version": None, "base_score": None, "score_origin": None}
    if kind == "CVSS_V3":
        record["version"] = vector[5:8] if vector.startswith("CVSS:3.") else "3"
        score = v3_base_score(vector)
        if score is not None:
            record.update(base_score=score, score_origin="computed_from_vector")
    elif kind in TYPE_VERSIONS:
        record["version"] = TYPE_VERSIONS[kind]
    return record
