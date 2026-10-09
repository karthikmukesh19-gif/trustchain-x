"""Explains a trust result in words: how it was calculated, what drives it, what is missing, and what would change it."""

from __future__ import annotations

from typing import Any

from app.services.layers import HOW_TO_RUN
from app.services.trust.normalization import KNOWN
from app.services.trust.weights import SOURCE_LAYER, WEIGHTS_STATEMENT

# What to do about a component that carries risk. A recommendation: a suggestion that follows from the evidence, not a finding.
ACTIONS = {
    "dependency_risk": "Pin versions with a lockfile and remove packages that nothing requires, so every dependency can be identified and checked.",
    "sbom_integrity": "Regenerate the SBOM and verify it; investigate any difference between the stored and the regenerated document.",
    "vulnerability_exposure": "Upgrade the affected packages to versions outside the published ranges, starting with the highest severity.",
    "code_reachability": "Fix the vulnerabilities that application code reaches first, and review the undecided ones by hand.",
    "dependency_fragility": "Review the most fragile packages: update those that lag behind, and reduce reliance on single points of failure.",
    "attack_path_risk": "Break the highest-scoring attack paths by upgrading the packages they end in.",
    "maintainer_behaviour": "Review the observed indicators; where maintenance is concentrated, add reviewers for release and security changes.",
    "commit_behaviour": "Review the commits and events listed for security review, starting with the highest anomaly score.",
    "dataset_confidence": "Resolve the weaknesses the dataset validation lists, and run the layers it reports as missing.",
    "predictive_risk": "Monitor the dependencies ranked highest and plan their updates.",
}
ACTION_THRESHOLD = 20.0        # component risk at or above which an action is suggested


def explain(result: dict[str, Any]) -> dict[str, Any]:
    components = result["components"]
    known = [component for component in components if component["status"] == KNOWN]
    unknown = [component for component in components if component["status"] != KNOWN]
    drivers = sorted(known, key=lambda component: (-(component["contribution"] or 0), component["name"]))
    scored = result["status"] == "SCORED"

    if scored:
        headline = (f"Trust score {result['trust_score']} of 100 (risk {result['risk_score']}), with confidence {result['confidence']}. "
                    f"{len(known)} of {len(components)} components are known, carrying {result['coverage']:.0%} of the weight.")
    else:
        headline = f"INSUFFICIENT DATA. {result.get('insufficient_reason', '')}"
    terms = " + ".join(f"{component['weight']} × {component['risk']}" for component in known)
    calculation = {
        "formula": "risk = Σ(weight × component risk) / Σ(weight of known components); trust = 100 − risk",
        "worked": (f"risk = ({terms}) / {result['known_weight']} = {result['risk_score']}; trust = 100 − {result['risk_score']} = {result['trust_score']}"
                   if scored and known else None),
        "bounds": (f"If every unknown component were at 0 the risk would be {result['risk_low']}; if each were at 100 it would be "
                   f"{result['risk_high']}. The unknown components carry {result['unknown_weight']} of 100 weight points."),
        "confidence": "confidence = coverage × weighted mean of the known components' confidence",
        "weights_statement": WEIGHTS_STATEMENT,
    }
    top_risks = [{"name": component["name"], "label": component["label"], "risk": component["risk"], "contribution": component["contribution"],
                  "weight": component["weight"], "detail": component["detail"], "basis": component["basis"]}
                 for component in drivers if (component["risk"] or 0) > 0][:5]
    recommendations = []
    for component in drivers:
        if (component["risk"] or 0) >= ACTION_THRESHOLD:
            recommendations.append({"basis": "RECOMMENDED", "component": component["name"], "priority": len(recommendations) + 1,
                                    "text": ACTIONS[component["name"]], "because": component["detail"],
                                    "evidence": component["reference"]})
    for component in sorted(unknown, key=lambda item: (-item["weight"], item["name"])):
        recommendations.append({"basis": "RECOMMENDED", "component": component["name"], "priority": len(recommendations) + 1,
                                "text": f"{HOW_TO_RUN[SOURCE_LAYER[component['name']]]} Until then {component['label'].lower()} is unknown.",
                                "because": component["detail"], "evidence": None})
    return {
        "headline": headline, "status": result["status"], "calculation": calculation, "top_risks": top_risks,
        "unknown": [{"name": component["name"], "label": component["label"], "weight": component["weight"], "reason": component["detail"],
                     "layer_status": component["layer_status"]} for component in unknown],
        "recommendations": recommendations, "meaning": result["meaning"],
    }
