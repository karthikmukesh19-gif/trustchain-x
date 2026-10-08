"""Predictive indicators and the predictive dependency risk score (model "dependency-risk-v1").

An indicator is a named, evidence-backed reason to watch a dependency more
closely. It is not a prediction of a specific vulnerability or attack, and
none is produced without evidence.

    predictive_dependency_risk = Σ weight_i × value_i        (0-100)
    confidence                 = Σ weight_i of the factors with data / 100

The score orders dependencies for attention. It is not a probability, and it
is not the platform's trust score.
"""

from __future__ import annotations

from typing import Any

from app.analyzers.fragility.metrics import downstream_impact_value, version_lag_value
from app.analyzers.graph import risk_propagation
from app.analyzers.graph.risk_propagation import DECAY, DIRECT_VULNERABILITY, SEVERITY_SIGNAL

MODEL_VERSION = "dependency-risk-v1"
INDICATOR_VERSION = "indicators-v1"
WEIGHTS = {"vulnerability_exposure": 30, "reachability": 10, "fragility": 20, "downstream_impact": 15, "graph_centrality": 10,
           "dependency_concentration": 5, "version_indicators": 10}
LOW, MEDIUM, HIGH = "LOW", "MEDIUM", "HIGH"
REACHABILITY_VALUE = {"REACHABLE": 1.0, "UNKNOWN": 0.5, "UNSUPPORTED": 0.5, "NOT_ANALYSED": 0.5, "NOT_CONFIRMED_REACHABLE": 0.2}
FINDING_CONFIDENCE = {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5}

INDICATOR_TYPES = (
    "REACHABLE_VULNERABLE_DEPENDENCY", "VULNERABILITY_CLUSTER", "SINGLE_POINT_DEPENDENCY", "HIGH_DOWNSTREAM_IMPACT",
    "HIGH_DEPENDENCY_CONCENTRATION", "HIGH_GRAPH_CENTRALITY", "HIGH_TRANSITIVE_DEPTH", "OUTDATED_DEPENDENCY", "RAPID_VERSION_GAP",
    "INSUFFICIENT_METADATA",
)


def level(score: float) -> str:
    return HIGH if score >= 67 else MEDIUM if score >= 34 else LOW


def _indicator(kind: str, severity: str, confidence: float, evidence: list[str], basis: str) -> dict[str, Any] | None:
    evidence = [item for item in evidence if item]
    if not evidence:
        return None                                   # never an indicator without evidence
    return {"type": kind, "severity": severity, "confidence": round(confidence, 2), "evidence": evidence, "basis": basis,
            "indicator_version": INDICATOR_VERSION}


def indicators(fragility: dict[str, Any], risk: dict[str, Any], vulnerabilities: dict[str, Any], reachability: dict[str, Any],
               packages: int, betweenness_computed: bool) -> list[dict[str, Any]]:
    """Every indicator that the evidence for one dependency supports."""
    observed, inferred = fragility["observed_metrics"], fragility["inferred_metrics"]
    version = inferred["version"]
    name = fragility["package_name"] or fragility["normalized_name"]
    found: list[dict[str, Any] | None] = []

    reachable = reachability.get("reachable_findings") or []
    if reachable:
        best = max(reachable, key=lambda f: FINDING_CONFIDENCE.get(f.get("confidence") or "", 0))
        found.append(_indicator("REACHABLE_VULNERABLE_DEPENDENCY", HIGH, FINDING_CONFIDENCE.get(best.get("confidence") or "", 0.5), [
            f"{len(reachable)} vulnerability finding(s) for {name} have a static path from application code to the affected functionality "
            f"({', '.join(f['advisory_id'] for f in reachable[:3])}).",
            f"Reached at {best['source_file']}:{best['line']}." if best.get("source_file") else "",
            "Static reachability is evidence of use, not of exploitability.",
        ], "OBSERVED"))

    distinct = vulnerabilities.get("distinct", 0)
    if distinct >= 3:
        found.append(_indicator("VULNERABILITY_CLUSTER", HIGH if distinct >= 5 else MEDIUM, 0.9, [
            f"{distinct} distinct known vulnerabilities match the installed version {fragility['version']}.",
            f"Advisories: {', '.join(vulnerabilities.get('advisories', [])[:5])}.",
        ], "OBSERVED"))

    if inferred["single_point"]:
        share = observed["reached_by_direct_share"] or 0
        found.append(_indicator("SINGLE_POINT_DEPENDENCY", HIGH if share >= 0.75 else MEDIUM, 0.9, [
            f"{observed['reached_by_direct']} of the project's direct dependencies ({round(share * 100)}%) lead to {name}.",
            "The project does not require it directly, so its version is chosen by other packages.",
        ], "DERIVED"))

    if observed["dependents"] >= 10:
        found.append(_indicator("HIGH_DOWNSTREAM_IMPACT", HIGH if observed["dependents"] >= 25 else MEDIUM, 0.95, [
            f"{observed['dependents']} packages depend on {name} directly or through others.",
            f"{observed['fan_in']} of them depend on it directly.",
        ], "OBSERVED"))

    if observed["dependents_share"] >= 0.25 and observed["dependents"] >= 5:
        found.append(_indicator("HIGH_DEPENDENCY_CONCENTRATION", HIGH if observed["dependents_share"] >= 0.5 else MEDIUM, 0.95, [
            f"{round(observed['dependents_share'] * 100)}% of the project's {packages} packages depend on {name}.",
        ], "OBSERVED"))

    if packages >= 10 and inferred["relative_centrality"] >= 0.5 and (inferred["betweenness_centrality"] or inferred["degree_centrality"]) > 0:
        measure = inferred["centrality_measure"]
        figure = inferred["betweenness_centrality"] if measure == "betweenness" else inferred["degree_centrality"]
        found.append(_indicator("HIGH_GRAPH_CENTRALITY", HIGH if inferred["relative_centrality"] >= 0.999 else MEDIUM,
                                0.85 if betweenness_computed else 0.6, [
            f"{measure.capitalize()} centrality {figure}: {round(inferred['relative_centrality'] * 100)}% of the highest in this graph.",
            "Betweenness counts the shortest dependency chains between other packages that pass through it." if measure == "betweenness" else
            "Betweenness was not computed for a graph of this size; the figure is degree centrality.",
        ], "DERIVED"))

    if observed["depth"] is not None and observed["depth"] >= 5:
        found.append(_indicator("HIGH_TRANSITIVE_DEPTH", HIGH if observed["depth"] >= 8 else MEDIUM, 0.95, [
            f"{name} is {observed['depth'] - 1} package(s) away from the project (depth {observed['depth']}).",
            "Its version is decided several layers below anything the project declares.",
        ], "OBSERVED"))

    if version["comparison_status"] == "COMPARED" and version["position"] == "BEHIND":
        major, lag = version["major_distance"] or 0, version["lag_days"]
        if major >= 1 or (lag is not None and lag >= 365):
            found.append(_indicator("OUTDATED_DEPENDENCY", HIGH if major >= 2 or (lag is not None and lag >= 730) else MEDIUM,
                                    0.9 if lag is not None else 0.75, [
                f"Installed {fragility['version']}; the registry's latest is {version['latest_version']}"
                + (f" ({major} major version(s) ahead)." if major else "."),
                f"The latest release is {lag} day(s) newer than the installed one." if lag is not None else "",
                f"{version['releases_behind']} release(s) have been published since." if version["releases_behind"] else "",
            ], "DERIVED"))
        behind, age = version["releases_behind"], version["installed_age_days"]
        if behind is not None and behind >= 6 and age is not None and age > 0 and behind / (age / 365) >= 12:
            found.append(_indicator("RAPID_VERSION_GAP", HIGH if behind >= 24 else MEDIUM, 0.85, [
                f"{behind} release(s) were published in the {age} day(s) since the installed version {fragility['version']}.",
                f"That is about {round(behind / (age / 365))} releases a year over that period.",
            ], "DERIVED"))

    if version["comparison_status"] != "COMPARED":
        found.append(_indicator("INSUFFICIENT_METADATA", LOW, 1.0, [
            version.get("reason") or "Release metadata for this package is not available.",
            "Version and release-age factors are unknown for this dependency and are not estimated.",
        ], "OBSERVED"))
    return [item for item in found if item is not None]


def predictive_risk(fragility: dict[str, Any], risk: dict[str, Any], packages: int) -> dict[str, Any]:
    """The predictive dependency risk of one dependency, with every factor's contribution."""
    observed, inferred = fragility["observed_metrics"], fragility["inferred_metrics"]
    vulnerable = risk["classification"] == DIRECT_VULNERABILITY
    factors: list[dict[str, Any]] = []

    def add(name: str, value: float | None, detail: str, basis: str, assumed: bool = False) -> None:
        # KNOWN: measured. UNKNOWN: no data, adds nothing. ASSUMED: the fact is not established and the model uses a
        # stated neutral value, because leaving it out would rank an undecided vulnerability below a decided one.
        known = value is not None
        bounded = max(0.0, min(1.0, value)) if known else None
        factors.append({"name": name, "weight": WEIGHTS[name], "value": round(bounded, 4) if known else None,
                        "contribution": round(WEIGHTS[name] * bounded, 1) if known else 0.0,
                        "status": "ASSUMED" if known and assumed else "KNOWN" if known else "UNKNOWN", "basis": basis, "detail": detail})

    if vulnerable:
        cluster = 1 + 0.1 * (min(risk["vulnerability_count"], 5) - 1)
        unrated = risk["severity"] not in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        add("vulnerability_exposure", SEVERITY_SIGNAL.get(risk["severity"], SEVERITY_SIGNAL["UNKNOWN"]) / 100 * cluster,
            f"{risk['vulnerability_count']} known vulnerability match(es); " + (
                "the source publishes no severity, so the model's neutral value is used." if unrated
                else f"highest published severity {risk['severity']}."), "DERIVED" if unrated else "OBSERVED", assumed=unrated)
        state = risk["reachability_state"]
        decided = state in ("REACHABLE", "NOT_CONFIRMED_REACHABLE")
        add("reachability", REACHABILITY_VALUE.get(state, REACHABILITY_VALUE["NOT_ANALYSED"]),
            {"REACHABLE": "Affected functionality is statically reached from application code.",
             "NOT_CONFIRMED_REACHABLE": "No static path to the affected functionality was established (not a statement of safety)."}.get(
                state, "Reachability of the affected functionality is not established either way; the model's neutral value is used."),
            "OBSERVED" if decided else "DERIVED", assumed=not decided)
    else:
        sources = risk["exposure_sources"]
        if sources:
            nearest = max(sources, key=lambda s: s["influence"])
            add("vulnerability_exposure", nearest["influence"] / 100,
                f"No advisory matches this package. It depends on {risk['exposure_source_count']} package(s) with known vulnerabilities; "
                f"the nearest influence is {nearest['node_id']} at {nearest['distance']} step(s), reduced by {DECAY} per step.", "DERIVED")
        else:
            add("vulnerability_exposure", 0.0, "No known vulnerability matches this package or anything it depends on.", "OBSERVED")
        add("reachability", 0.0, "Not applicable: no advisory matches this package.", "OBSERVED")
    add("fragility", fragility["fragility_score"] / 100, f"Fragility score {fragility['fragility_score']} ({fragility['model_version']}).", "DERIVED")
    add("downstream_impact", downstream_impact_value(observed["dependents"], packages),
        f"{observed['dependents']} package(s) depend on it directly or through others.", "OBSERVED")
    add("graph_centrality", inferred["relative_centrality"],
        f"{round(inferred['relative_centrality'] * 100)}% of the highest {inferred['centrality_measure']} centrality in this graph.", "DERIVED")
    add("dependency_concentration", observed["dependents_share"],
        f"{round(observed['dependents_share'] * 100)}% of the project's packages depend on it.", "OBSERVED")
    lag = version_lag_value(inferred["version"])
    add("version_indicators", lag, "Distance between the installed and the latest version." if lag is not None
        else (inferred["version"].get("reason") or "The installed and latest versions were not compared."), "DERIVED")

    score = round(sum(f["contribution"] for f in factors), 1)
    # An assumed factor counts for half its weight: the vulnerability is real, one of its properties is not known.
    known = sum(f["weight"] * (1.0 if f["status"] == "KNOWN" else 0.5) for f in factors if f["status"] != "UNKNOWN")
    # The fragility factor carries its own gaps: scale its weight by the fragility confidence.
    known -= WEIGHTS["fragility"] * (1 - fragility["confidence"])
    return {"score": score, "level": level(score), "confidence": round(known / 100, 2), "model_version": MODEL_VERSION,
            "factors": factors, "classification": "PREDICTED",
            "meaning": "A relative priority for monitoring and review. Not a probability, and not a prediction of a specific vulnerability or attack."}


def evidence(fragility: dict[str, Any], risk: dict[str, Any], prediction: dict[str, Any], found: list[dict[str, Any]],
             vulnerabilities: dict[str, Any], reachability: dict[str, Any]) -> dict[str, list[str]]:
    """The reasons behind a dependency's scores, grouped by how each is known."""
    observed, inferred = fragility["observed_metrics"], fragility["inferred_metrics"]
    version = inferred["version"]
    name = fragility["package_name"] or fragility["normalized_name"]
    seen = [
        f"Installed version: {fragility['version']}." if fragility["version"] else "The repository does not determine an installed version.",
        "Required by the project itself (depth 1)." if observed["direct"] else
        (f"Depth {observed['depth']} in the dependency graph." if observed["depth"] is not None else "No path from the project is established."),
        f"{observed['fan_in']} direct and {observed['dependents']} total dependent package(s).",
        f"Requires {observed['fan_out']} package(s) directly; brings in {observed['introduced']} in total.",
        f"{vulnerabilities.get('distinct', 0)} known vulnerability match(es)" + (
            f" ({', '.join(vulnerabilities.get('advisories', [])[:3])})." if vulnerabilities.get("distinct") else "."),
    ]
    if vulnerabilities.get("distinct"):
        if reachability.get("findings"):
            seen.append(f"Code reachability: {reachability.get('reachable', 0)} reachable, {reachability.get('not_confirmed', 0)} not confirmed, "
                        f"{reachability.get('unknown', 0) + reachability.get('unsupported', 0)} unknown or unsupported finding(s).")
        else:
            seen.append("Code reachability has not been analysed for these vulnerabilities.")
    if reachability.get("importing_modules") is not None:
        seen.append(f"Imported by {reachability['importing_modules']} application module(s); {reachability.get('use_sites') or 0} use site(s).")
    if version["latest_version"]:
        seen.append(f"Registry's latest version: {version['latest_version']}.")

    derived = [f"{f['name'].replace('_', ' ')}: {f['detail']}" for f in fragility["factors"] if f["status"] == "KNOWN" and f["value"] >= 0.5]
    derived.append(f"Exposure classification: {risk['classification']}.")
    derived.extend(f"{item['type']} ({item['severity']}): {item['evidence'][0]}" for item in found if item["type"] != "INSUFFICIENT_METADATA")

    predicted = [f"Predictive dependency risk {prediction['score']} of 100 ({prediction['level']}), confidence {prediction['confidence']}; "
                 f"model {prediction['model_version']}."]
    predicted.append("Elevated relative to the scale: a candidate for closer monitoring." if prediction["score"] >= 34
                     else "Low on the scale; this is not a statement that the dependency is safe.")

    recommended = []
    fixed = vulnerabilities.get("fixed_versions") or []
    if vulnerabilities.get("distinct"):
        total, with_fix = vulnerabilities["distinct"], vulnerabilities.get("with_fix")
        if not fixed:
            recommended.append(f"No fixed version that can be ordered is published for the matched advisories; review how {name} is used "
                               "and whether it can be replaced.")
        elif with_fix is not None and with_fix < total:
            recommended.append(f"{with_fix} of {total} matched advisories list a fixed version (highest: {fixed[-1]}). Assess that upgrade; "
                               "it is not known to address the others.")
        else:
            recommended.append(f"Assess upgrading {name} to {fixed[-1]} or later: the highest version the matched advisories list as fixed.")
    if any(item["type"] == "REACHABLE_VULNERABLE_DEPENDENCY" for item in found):
        recommended.append("Give this priority: affected functionality is statically reached from application code.")
    if any(item["type"] == "OUTDATED_DEPENDENCY" for item in found):
        recommended.append(f"Review the changes between {fragility['version']} and {version['latest_version']} before planning an update.")
    if any(item["type"] in ("SINGLE_POINT_DEPENDENCY", "HIGH_DOWNSTREAM_IMPACT", "HIGH_DEPENDENCY_CONCENTRATION") for item in found):
        recommended.append(f"Put {name} on the monitoring list: {observed['dependents']} other package(s) depend on it.")
    if any(item["type"] == "INSUFFICIENT_METADATA" for item in found):
        recommended.append("Check this package's release status by hand; the platform could not collect it.")
    return {"OBSERVED": seen, "DERIVED": derived, "PREDICTED": predicted, "RECOMMENDED": recommended}


__all__ = ["MODEL_VERSION", "INDICATOR_TYPES", "evidence", "indicators", "level", "predictive_risk", "risk_propagation"]
