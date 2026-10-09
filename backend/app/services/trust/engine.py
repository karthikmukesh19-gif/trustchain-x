"""The trust calculation.

    risk_score  = Σ(weight × component risk) / Σ(weight)        over the components that are KNOWN
    trust_score = 100 − risk_score
    coverage    = Σ(weight of KNOWN components) / 100
    confidence  = coverage × Σ(weight × component confidence) / Σ(weight)   over the KNOWN components

Missing components are handled in three ways at once, so that an unknown is
never mistaken for a good result:

  * The score is an average over what is known. An unknown component neither lowers nor raises it.
  * Bounds are reported beside it: `risk_low` assumes every unknown component is at 0 and `risk_high`
    assumes each is at 100. The distance between them is the room the unknowns leave.
  * When coverage is below the configured minimum, no score is given at all: the status is
    INSUFFICIENT_DATA and trust_score is null.
"""

from __future__ import annotations

from typing import Any

from app.services.trust.normalization import KNOWN, NORMALISERS
from app.services.trust.weights import MODEL_VERSION, WEIGHTS, WEIGHTS_STATEMENT

SCORED, INSUFFICIENT_DATA = "SCORED", "INSUFFICIENT_DATA"
BANDS = ((80.0, "LOW_RISK"), (60.0, "MODERATE_RISK"), (40.0, "ELEVATED_RISK"), (0.0, "HIGH_RISK"))
MEANING = ("The trust score summarises the stored evidence about this snapshot under stated weights. It is not a certification, and a "
           "high score is not a clean bill of health: it reflects only what was analysed.")


def band(trust_score: float) -> str:
    return next(name for threshold, name in BANDS if trust_score >= threshold)


def compute(layers: dict[str, Any], min_coverage: float = 0.6) -> dict[str, Any]:
    """Component risks, the scores, their bounds and the status. Pure: the same layer state gives the same result."""
    components = [normalise(layers) for normalise in NORMALISERS]
    known = [component for component in components if component["status"] == KNOWN]
    known_weight = sum(component["weight"] for component in known)
    total_weight = sum(WEIGHTS.values())
    coverage = known_weight / total_weight
    weighted = sum(component["weight"] * component["risk"] for component in known)
    for component in components:
        # Points of the risk score this component accounts for, on the renormalised scale. None when it is unknown.
        component["contribution"] = round(component["weight"] * component["risk"] / known_weight, 2) if component["status"] == KNOWN else None
        component["effective_weight"] = round(100 * component["weight"] / known_weight, 2) if component["status"] == KNOWN else None
    risk = weighted / known_weight if known_weight else None
    risk_low = weighted / total_weight
    risk_high = (weighted + 100 * (total_weight - known_weight)) / total_weight
    confidence = coverage * sum(component["weight"] * component["confidence"] for component in known) / known_weight if known_weight else 0.0
    sufficient = known_weight > 0 and coverage >= min_coverage
    result: dict[str, Any] = {
        "status": SCORED if sufficient else INSUFFICIENT_DATA,
        "risk_score": round(risk, 1) if sufficient and risk is not None else None,
        "trust_score": round(100 - risk, 1) if sufficient and risk is not None else None,
        "band": band(100 - risk) if sufficient and risk is not None else None,
        "confidence": round(confidence, 2), "coverage": round(coverage, 2), "min_coverage": min_coverage,
        "risk_low": round(risk_low, 1), "risk_high": round(risk_high, 1),
        "trust_low": round(100 - risk_high, 1), "trust_high": round(100 - risk_low, 1),
        "known_weight": known_weight, "unknown_weight": total_weight - known_weight,
        "components": components, "component_scores": [{"name": c["name"], "risk": c["risk"], "status": c["status"], "weight": c["weight"]}
                                                        for c in components],
        "unknown_components": [component["name"] for component in components if component["status"] != KNOWN],
        "weights": dict(WEIGHTS), "weights_statement": WEIGHTS_STATEMENT, "meaning": MEANING, "model_version": MODEL_VERSION,
    }
    if not sufficient:
        result["insufficient_reason"] = (
            f"Only {coverage:.0%} of the model's weight rests on analysed layers; at least {min_coverage:.0%} is required before a score is "
            "given. Showing a score now would present missing evidence as if it were good news.")
    return result
