"""Attack-path status and score (model "attack-path-v1"). Deterministic: the same inputs give the same result.

    attack_path_score = vulnerability_signal × reachability_signal × graph_impact × confidence        (0-100)

  vulnerability_signal   0-100   severity published by the advisory source (UNKNOWN is the midpoint, not zero)
  reachability_signal    0-1     what static reachability analysis established (never zero: "not confirmed" is not "safe")
  graph_impact           0-1     how close the package is to the project and how much of the graph depends on it
  confidence             0-1     product of the confidences of the path's steps

The score orders paths for review. It is not a probability of attack and not
a statement that the weakness can be exploited.
"""

from __future__ import annotations

from typing import Any

from app.analyzers.fragility.metrics import downstream_impact_value
from app.analyzers.graph.risk_propagation import REACHABILITY_SIGNAL, SEVERITY_SIGNAL

MODEL_VERSION = "attack-path-v1"

SUPPORTED_PATH = "SUPPORTED_PATH"            # every step rests on stored evidence, including a static reachability finding
POTENTIAL_PATH = "POTENTIAL_PATH"            # the dependency chain and advisory are observed; no code reaching it was found
UNKNOWN_PATH = "UNKNOWN_PATH"                # the chain is observed; whether the code is reached could not be determined
OBSERVED_COMPONENT = "OBSERVED_COMPONENT"    # the affected package is in the inventory but no chain from the project is known
STATUSES = (SUPPORTED_PATH, POTENTIAL_PATH, UNKNOWN_PATH, OBSERVED_COMPONENT)
STATUS_RANK = {SUPPORTED_PATH: 3, UNKNOWN_PATH: 2, POTENTIAL_PATH: 1, OBSERVED_COMPONENT: 0}
STATUS_MEANING = {
    SUPPORTED_PATH: "Each step is backed by stored evidence, including static evidence that application code refers to the affected "
                    "functionality. Exploitability was not tested.",
    POTENTIAL_PATH: "The dependency chain and the advisory match were observed, but static analysis found no application code that reaches "
                    "the affected functionality.",
    UNKNOWN_PATH: "The dependency chain and the advisory match were observed; whether application code reaches the affected functionality "
                  "is unknown.",
    OBSERVED_COMPONENT: "The affected package is part of the inventory, but no chain of dependencies from the project to it is known.",
}
LEVELS = ("LOW", "MEDIUM", "HIGH")
GRAPH_IMPACT_BASE, PROXIMITY_WEIGHT, DOWNSTREAM_WEIGHT = 0.4, 0.3, 0.3


def status_for(has_route: bool, reachability_state: str) -> str:
    if not has_route:
        return OBSERVED_COMPONENT
    if reachability_state == "REACHABLE":
        return SUPPORTED_PATH
    if reachability_state == "NOT_CONFIRMED_REACHABLE":
        return POTENTIAL_PATH
    return UNKNOWN_PATH


def graph_impact(chain_length: int | None, dependents: int, packages: int) -> dict[str, Any]:
    """0.4 for being in the graph at all, up to 0.3 for closeness to the project, up to 0.3 for what depends on it."""
    proximity = 0.0 if not chain_length else 1.0 / chain_length
    downstream = downstream_impact_value(dependents, packages)
    value = GRAPH_IMPACT_BASE + PROXIMITY_WEIGHT * proximity + DOWNSTREAM_WEIGHT * downstream
    return {"value": round(value, 4), "proximity": round(proximity, 4), "downstream": round(downstream, 4), "chain_length": chain_length,
            "dependents": dependents}


def components(severity: str, reachability_state: str, impact: dict[str, Any], confidence: float) -> dict[str, Any]:
    severity = severity if severity in SEVERITY_SIGNAL else "UNKNOWN"
    return {"vulnerability_signal": SEVERITY_SIGNAL[severity], "severity": severity,
            "reachability_signal": REACHABILITY_SIGNAL[reachability_state], "reachability_state": reachability_state,
            "graph_impact": impact["value"], "graph_impact_detail": impact, "confidence": confidence}


def score(parts: dict[str, Any]) -> float:
    return round(parts["vulnerability_signal"] * parts["reachability_signal"] * parts["graph_impact"] * parts["confidence"], 1)


def level(value: float) -> str:
    return "HIGH" if value >= 50 else "MEDIUM" if value >= 20 else "LOW"
