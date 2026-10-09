"""Edge types of an attack path and how confidence travels along them.

Every edge has a confidence in [0, 1]: how well the step it stands for is
established by stored evidence. A path's confidence is the product of its
edges' confidences, so one weak step lowers the whole path and no step can
raise it.
"""

from __future__ import annotations

from typing import Any

from app.analyzers.attack_paths.attack_nodes import DERIVED, INFERRED, OBSERVED

DECLARES = "DECLARES"                 # project -> a dependency it requires itself
REQUIRES = "REQUIRES"                 # dependency -> a dependency it requires
AFFECTED_BY = "AFFECTED_BY"           # dependency -> advisory that matches its version
ASSESSED_AS = "ASSESSED_AS"           # advisory -> what static reachability analysis found
USED_IN = "USED_IN"                   # reachability finding -> application code
PROPAGATES_TO = "PROPAGATES_TO"       # application -> packages that depend on the affected one
MAY_RESULT_IN = "MAY_RESULT_IN"       # -> potential impact
KINDS = (DECLARES, REQUIRES, AFFECTED_BY, ASSESSED_AS, USED_IN, PROPAGATES_TO, MAY_RESULT_IN)

RELATIONSHIP_BASIS_CONFIDENCE = {"OBSERVED": 1.0, "INFERRED": 0.8}
UNKNOWN_BASIS_CONFIDENCE = 0.6
LABEL_CONFIDENCE = {"HIGH": 1.0, "MEDIUM": 0.8, "LOW": 0.6}
# How well the reachability step is established, by what the analysis could say.
UNDECIDED_REACHABILITY_CONFIDENCE = 0.5      # UNKNOWN, UNSUPPORTED, not analysed: the step is a possibility only
DEFAULT_FINDING_CONFIDENCE = 0.7             # a finding without a stated confidence


def edge(source: str, target: str, kind: str, basis: str, confidence: float, reason: str) -> dict[str, Any]:
    return {"source": source, "target": target, "kind": kind, "basis": basis, "confidence": round(max(0.0, min(1.0, confidence)), 2),
            "reason": reason}


def declaration_confidence(dependency: dict[str, Any]) -> float:
    return RELATIONSHIP_BASIS_CONFIDENCE.get(dependency.get("relationship_basis") or "", UNKNOWN_BASIS_CONFIDENCE)


def match_confidence(advisory: dict[str, Any]) -> float:
    return LABEL_CONFIDENCE.get(advisory.get("confidence") or "", LABEL_CONFIDENCE["LOW"])


def reachability_confidence(finding: dict[str, Any] | None, state: str) -> float:
    if finding is None or state not in ("REACHABLE", "NOT_CONFIRMED_REACHABLE"):
        return UNDECIDED_REACHABILITY_CONFIDENCE
    return LABEL_CONFIDENCE.get(finding.get("confidence") or "", DEFAULT_FINDING_CONFIDENCE)


def propagate(edges: list[dict[str, Any]]) -> tuple[float, list[dict[str, Any]]]:
    """Path confidence (product of edge confidences) and the steps that lowered it."""
    value = 1.0
    lowered = []
    for item in edges:
        value *= item["confidence"]
        if item["confidence"] < 1.0:
            lowered.append({"edge": item["kind"], "source": item["source"], "target": item["target"], "confidence": item["confidence"],
                            "reason": item["reason"]})
    return round(value, 3), lowered


__all__ = ["AFFECTED_BY", "ASSESSED_AS", "DECLARES", "DERIVED", "INFERRED", "KINDS", "MAY_RESULT_IN", "OBSERVED", "PROPAGATES_TO", "REQUIRES",
           "USED_IN", "declaration_confidence", "edge", "match_confidence", "propagate", "reachability_confidence"]
