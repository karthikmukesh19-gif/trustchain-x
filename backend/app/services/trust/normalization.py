"""Turns each layer's stored result into a component risk on a common 0-100 scale, or into UNKNOWN.

Every function returns a component:

  {name, label, weight, status, risk, confidence, basis, detail, inputs, layer, layer_status, reference}

`status` is KNOWN or UNKNOWN. A component is UNKNOWN when its layer has not
been analysed, is stale, or could not collect its data. An UNKNOWN component
has no risk value: it is never given 0, and never a default.
"""

from __future__ import annotations

from typing import Any

from app.services.trust.weights import LABELS, SOURCE_LAYER, WEIGHTS

KNOWN, UNKNOWN = "KNOWN", "UNKNOWN"
# Contribution of one advisory of a given severity to exposure. Combined as 1 - Π(1 - w), so many advisories saturate at 100.
SEVERITY_EXPOSURE = {"CRITICAL": 0.5, "HIGH": 0.3, "MEDIUM": 0.15, "LOW": 0.05, "UNKNOWN": 0.15}
# How much a vulnerability with a given reachability result counts. Undecided results count half: they are neither reached nor cleared.
REACHABILITY_WEIGHT = {"REACHABLE": 1.0, "UNKNOWN": 0.5, "UNSUPPORTED": 0.5, "NOT_CONFIRMED_REACHABLE": 0.1}
_WHY_UNKNOWN = {
    "NOT_ANALYSED": "This layer has not been analysed for the project.",
    "STALE": "Results exist only for an earlier snapshot; they say nothing certain about the current one.",
    "UNAVAILABLE": "The layer ran but could not collect its data.",
}


def _component(name: str, layer: dict[str, Any], *, risk: float | None, confidence: float, basis: str, detail: str,
               inputs: dict[str, Any] | None = None) -> dict[str, Any]:
    known = risk is not None
    return {
        "name": name, "label": LABELS[name], "weight": WEIGHTS[name], "status": KNOWN if known else UNKNOWN,
        "risk": round(max(0.0, min(100.0, risk)), 1) if known else None, "confidence": round(max(0.0, min(1.0, confidence)), 2) if known else 0.0,
        "basis": basis if known else "UNKNOWN", "detail": detail, "inputs": inputs or {}, "layer": SOURCE_LAYER[name],
        "layer_status": layer["status"], "reference": layer.get("reference"), "as_of": layer.get("as_of"),
    }


def _unknown(name: str, layer: dict[str, Any], detail: str | None = None) -> dict[str, Any]:
    return _component(name, layer, risk=None, confidence=0.0, basis="UNKNOWN",
                      detail=detail or _WHY_UNKNOWN.get(layer["status"], "No usable result exists for this layer."))


def dependency_risk(layers: dict[str, Any]) -> dict[str, Any]:
    """How much of the inventory cannot be pinned down: unresolved versions, unknown or inferred relationships, packages with no path."""
    layer = layers["inventory"]
    if not layer["available"]:
        return _unknown("dependency_risk", layer)
    stats = layer["stats"]
    total = stats.get("total") or 0
    if total == 0:
        return _component("dependency_risk", layer, risk=0.0, confidence=1.0, basis="OBSERVED",
                          detail="The snapshot declares no third-party dependencies.", inputs={"total": 0})
    observed = (stats.get("by_relationship_basis") or {}).get("OBSERVED", 0)
    shares = {
        "unresolved_versions": (stats.get("unresolved_versions") or 0) / total,
        "relationship_unknown": (stats.get("relationship_unknown") or 0) / total,
        "relationship_not_observed": max(0.0, 1 - observed / total),
        "without_path": (stats.get("without_path") or 0) / total,
    }
    risk = 100 * (0.4 * shares["unresolved_versions"] + 0.2 * shares["relationship_unknown"] + 0.2 * shares["relationship_not_observed"]
                  + 0.2 * shares["without_path"])
    return _component(
        "dependency_risk", layer, risk=risk, confidence=1.0, basis="DERIVED",
        detail=(f"Of {total} packages, {shares['unresolved_versions']:.0%} have no resolved version, "
                f"{shares['relationship_not_observed']:.0%} have a relationship that is inferred or unknown, and "
                f"{shares['without_path']:.0%} have no recorded path from the project. What cannot be pinned down cannot be checked."),
        inputs={"total": total, **{key: round(value, 4) for key, value in shares.items()},
                "formula": "100 × (0.4 × unresolved + 0.2 × relationship unknown + 0.2 × relationship not observed + 0.2 × without path)"})


def sbom_integrity(layers: dict[str, Any]) -> dict[str, Any]:
    layer = layers["sbom"]
    if not layer["available"]:
        return _unknown("sbom_integrity", layer, "No SBOM exists for the current snapshot." if layer["status"] != "STALE" else None)
    if layer["verified"] is None:
        return _unknown("sbom_integrity", layer, "An SBOM exists but its integrity has not been verified. Unverified is not the same as intact.")
    if layer["verified"] is False:
        failed = ", ".join((layer.get("verification") or {}).get("failed_checks") or []) or "unspecified checks"
        return _component("sbom_integrity", layer, risk=100.0, confidence=1.0, basis="OBSERVED",
                          detail=f"The SBOM failed its integrity verification ({failed}).", inputs={"verified": False})
    components = layer.get("component_count") or 0
    unresolved = (layer.get("unresolved_components") or 0) / components if components else 0.0
    return _component("sbom_integrity", layer, risk=30 * unresolved, confidence=1.0, basis="OBSERVED",
                      detail=f"The SBOM passed its integrity verification. {unresolved:.0%} of its {components} components have no resolved version.",
                      inputs={"verified": True, "components": components, "unresolved_share": round(unresolved, 4),
                              "formula": "0 when verified, plus up to 30 for components without a resolved version; 100 when verification fails"})


def vulnerability_exposure(layers: dict[str, Any]) -> dict[str, Any]:
    layer = layers["vulnerabilities"]
    if not layer["available"]:
        return _unknown("vulnerability_exposure", layer)
    counts = {severity: int((layer.get("by_severity") or {}).get(severity) or 0) for severity in SEVERITY_EXPOSURE}
    remaining = 1.0
    for severity, count in counts.items():
        remaining *= (1 - SEVERITY_EXPOSURE[severity]) ** count
    total = layer.get("dependencies_total") or 0
    checked = layer.get("dependencies_checked")
    coverage = (checked / total) if total and checked is not None else 1.0
    matched = sum(counts.values())
    return _component(
        "vulnerability_exposure", layer, risk=100 * (1 - remaining), confidence=coverage, basis="OBSERVED",
        detail=(f"{matched} advisory match(es) affect {layer.get('affected_dependencies') or 0} package(s): " +
                ", ".join(f"{count} {severity.lower()}" for severity, count in counts.items() if count) + "." if matched else
                f"No advisory matches the {checked if checked is not None else total} package version(s) that could be checked.")
        + (f" {total - checked} package(s) could not be checked." if total and checked is not None and checked < total else ""),
        inputs={"by_severity": counts, "dependencies_checked": checked, "dependencies_total": total, "severity_weights": SEVERITY_EXPOSURE,
                "formula": "100 × (1 − Π(1 − severity weight) over advisory matches)"})


def code_reachability(layers: dict[str, Any]) -> dict[str, Any]:
    layer, scan = layers["reachability"], layers["vulnerabilities"]
    if scan["available"] and not (scan.get("affected_matches") or 0):
        return _component("code_reachability", scan, risk=0.0, confidence=1.0, basis="DERIVED",
                          detail="No advisory matches this snapshot, so there is no vulnerable functionality to reach.", inputs={"findings": 0})
    if not layer["available"]:
        return _unknown("code_reachability", layer)
    by_status = {status: int((layer.get("by_status") or {}).get(status) or 0) for status in REACHABILITY_WEIGHT}
    total = sum(by_status.values())
    if total == 0:
        return _unknown("code_reachability", layer, "The reachability analysis evaluated no findings.")
    risk = 100 * sum(REACHABILITY_WEIGHT[status] * count for status, count in by_status.items()) / total
    decided = (by_status["REACHABLE"] + by_status["NOT_CONFIRMED_REACHABLE"]) / total
    confidence = decided * (1.0 if layer.get("source_complete") else 0.8)
    return _component(
        "code_reachability", layer, risk=risk, confidence=max(confidence, 0.1), basis="DERIVED",
        detail=(f"Of {total} vulnerability finding(s): {by_status['REACHABLE']} reachable, {by_status['NOT_CONFIRMED_REACHABLE']} not confirmed "
                f"reachable, {by_status['UNKNOWN'] + by_status['UNSUPPORTED']} undecided. Undecided findings count half; they are not cleared."),
        inputs={"by_status": by_status, "status_weights": REACHABILITY_WEIGHT, "decided_share": round(decided, 4),
                "formula": "100 × Σ(status weight × findings) / findings"})


def dependency_fragility(layers: dict[str, Any]) -> dict[str, Any]:
    layer = layers["fragility"]
    summary = layer.get("summary") or {}
    if not layer["available"] or summary.get("mean") is None:
        return _unknown("dependency_fragility", layer)
    mean, highest = float(summary["mean"]), float(summary.get("highest") or 0)
    return _component("dependency_fragility", layer, risk=0.5 * mean + 0.5 * highest, confidence=float(summary.get("mean_confidence") or 0.5),
                      basis="DERIVED", detail=f"Mean fragility is {mean} and the most fragile package scores {highest} (of 100).",
                      inputs={"mean": mean, "highest": highest, "formula": "0.5 × mean fragility + 0.5 × highest fragility"})


def attack_path_risk(layers: dict[str, Any]) -> dict[str, Any]:
    layer = layers["attack_paths"]
    if not layer["available"]:
        return _unknown("attack_path_risk", layer)
    summary = layer["summary"]
    paths = summary.get("paths") or 0
    highest = float(summary.get("highest_score") or 0)
    by_status = summary.get("by_status") or {}
    undetermined = by_status.get("UNKNOWN_PATH", 0)
    confidence = 1.0 if not paths else max(0.3, 1 - 0.5 * undetermined / paths)
    return _component(
        "attack_path_risk", layer, risk=highest, confidence=confidence, basis="DERIVED",
        detail=(f"{paths} attack path(s); the highest scores {highest}. {by_status.get('SUPPORTED_PATH', 0)} are supported by evidence at every "
                f"step and {undetermined} have undetermined reachability." if paths else "The simulation found no attack path."),
        inputs={"paths": paths, "highest_score": highest, "by_status": by_status, "formula": "the highest attack-path score"})


def maintainer_behaviour(layers: dict[str, Any]) -> dict[str, Any]:
    layer = layers["maintainers"]
    if not layer["available"] or layer.get("attention_score") is None:
        return _unknown("maintainer_behaviour", layer, None if not layer["available"] else "No behavioural indicator could be evaluated.")
    observed = [item["type"] for item in layer.get("indicators") or [] if item.get("status") == "OBSERVED"]
    return _component(
        "maintainer_behaviour", layer, risk=float(layer["attention_score"]), confidence=float(layer.get("confidence") or 0.0), basis="DERIVED",
        detail=(f"Attention score {layer['attention_score']} from {len(observed)} observed behavioural indicator(s)"
                + (f": {', '.join(observed)}." if observed else ".") + " Indicators describe how the repository is maintained, not any person."),
        inputs={"attention_score": layer["attention_score"], "observed_indicators": observed, "formula": "the maintainer attention score"})


def commit_behaviour(layers: dict[str, Any]) -> dict[str, Any]:
    layer = layers["commits"]
    if not layer["available"] or not layer.get("analysed_total"):
        return _unknown("commit_behaviour", layer, None if not layer["available"] else "No commit has been analysed.")
    highest, mean = float(layer["highest_anomaly"]), float(layer["mean_anomaly"])
    return _component(
        "commit_behaviour", layer, risk=0.6 * highest + 0.4 * mean, confidence=float(layer.get("mean_confidence") or 0.5), basis="DERIVED",
        detail=(f"Over the {layer['window']} most recent analysed commits the highest anomaly score is {highest} and the mean {mean}; "
                f"{layer['security_events']} event(s) are listed for review."),
        inputs={"highest_anomaly": highest, "mean_anomaly": mean, "commits": layer["window"], "security_events": layer["security_events"],
                "formula": "0.6 × highest anomaly + 0.4 × mean anomaly"})


def dataset_confidence(layers: dict[str, Any]) -> dict[str, Any]:
    layer = layers["dataset"]
    if not layer["available"] or layer.get("quality_status") in (None, "UNKNOWN"):
        return _unknown("dataset_confidence", layer, None if not layer["available"] else "The dataset could not be validated.")
    if layer["quality_status"] == "INVALID":
        return _component("dataset_confidence", layer, risk=100.0, confidence=1.0, basis="DERIVED",
                          detail="The dataset failed validation: stored records do not match their hashes, or break the schema.",
                          inputs={"status": "INVALID"})
    score, confidence = float(layer["quality_score"]), float(layer.get("quality_confidence") or 0.0)
    # A high score on a dataset too small or too incomplete to rely on is not reliability: the score counts only as far as it is trusted.
    return _component("dataset_confidence", layer, risk=100 - score * confidence, confidence=max(confidence, 0.1), basis="DERIVED",
                      detail=f"Dataset version {layer['version']} has quality score {score} with confidence {confidence} (status {layer['quality_status']}).",
                      inputs={"quality_score": score, "quality_confidence": confidence, "status": layer["quality_status"],
                              "formula": "100 − dataset quality score × validation confidence"})


def predictive_risk(layers: dict[str, Any]) -> dict[str, Any]:
    layer = layers["predictive"]
    summary = layer.get("summary") or {}
    top = [item["score"] for item in summary.get("top") or [] if isinstance(item.get("score"), (int, float))][:5]
    if not layer["available"] or not top:
        return _unknown("predictive_risk", layer, None if not layer["available"] else "The predictive analysis assessed no dependency.")
    mean_top = sum(top) / len(top)
    return _component("predictive_risk", layer, risk=mean_top, confidence=0.8, basis="PREDICTED",
                      detail=f"The {len(top)} dependencies with the highest predictive risk average {mean_top:.1f} of 100. This is a model's "
                             "estimate of where to look, not a forecast of an event.",
                      inputs={"top_scores": top, "formula": "mean predictive risk of the five highest-ranked dependencies"})


NORMALISERS = (dependency_risk, sbom_integrity, vulnerability_exposure, code_reachability, dependency_fragility, attack_path_risk,
               maintainer_behaviour, commit_behaviour, dataset_confidence, predictive_risk)
