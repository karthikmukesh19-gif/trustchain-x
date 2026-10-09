"""Confidence of a cross-layer finding.

    confidence = weakest cited evidence × corroboration × completeness

  weakest evidence   the lowest confidence among the cited evidence items (1.0 where an item states none: it is a stored record)
  corroboration      0.7 for one contributing layer, 0.85 for two, 1.0 for three or more
  completeness       share of the conditions the rule looked at that could be evaluated (were not UNKNOWN)

It is the confidence that the finding follows from the stored evidence. It is
not the likelihood of an attack.
"""

from __future__ import annotations

from typing import Any

CORROBORATION = {0: 0.0, 1: 0.7, 2: 0.85}


def combine(evidence: list[dict[str, Any]], contributing_layers: list[str], conditions: list[dict[str, Any]]) -> dict[str, Any]:
    weakest = min((item["confidence"] for item in evidence if item.get("confidence") is not None), default=1.0)
    corroboration = CORROBORATION.get(len(set(contributing_layers)), 1.0)
    evaluated = [condition for condition in conditions if condition.get("result") != "UNKNOWN"]
    completeness = len(evaluated) / len(conditions) if conditions else 1.0
    value = round(max(0.0, min(1.0, weakest * corroboration * completeness)), 2)
    return {"value": value, "weakest_evidence": round(weakest, 2), "corroboration": corroboration, "completeness": round(completeness, 2),
            "layers": len(set(contributing_layers)), "conditions_unknown": len(conditions) - len(evaluated)}
