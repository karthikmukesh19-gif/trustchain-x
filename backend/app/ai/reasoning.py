"""The rules that correlate layers into findings (model "cross-layer-reasoning-v1").

Each rule looks at conditions over the context, records which held, which
did not and which could not be evaluated, and emits a finding only when its
required conditions held. A condition that could not be evaluated is
UNKNOWN; it never counts as "did not hold" and never as "held".

Statements inside a finding are labelled:

  OBSERVED      read from the repository or an advisory source
  DERIVED       computed from observed data by a documented analysis
  PREDICTED     a model's forward-looking estimate
  RECOMMENDED   a suggested action; a judgement, not a fact
"""

from __future__ import annotations

import hashlib
from typing import Any, Callable, Iterable

from app.ai import confidence as confidence_model
from app.ai.context import Context
from app.ai.evidence import DERIVED, OBSERVED, PREDICTED, RECOMMENDED
from app.analyzers.fragility.metrics import downstream_impact_value
from app.services import layers

MODEL_VERSION = "cross-layer-reasoning-v1"
SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}
TRUE, FALSE, UNKNOWN = "TRUE", "FALSE", "UNKNOWN"
HIGH_IMPACT = 0.5            # downstream impact (0-1) at or above which a package counts as widely depended on
MAX_LISTED = 10

CATEGORIES = {
    "HIGH_PRIORITY_CORRELATED_RISK": "A known vulnerability that static analysis shows is reached by application code, amplified by at least one other layer.",
    "REACHABLE_VULNERABILITY": "A known vulnerability that static analysis shows is reached by application code.",
    "FRAGILE_VULNERABLE_DEPENDENCY": "A known vulnerability in a package that is also structurally fragile or hard to keep up to date.",
    "UNVERIFIED_VULNERABILITY_EXPOSURE": "Known vulnerabilities whose reachability could not be determined.",
    "SECRET_EXPOSURE_REVIEW": "A commit added a value that looks like a credential.",
    "CONCENTRATED_CHANGE_CONTROL": "Release or pipeline changes rest with one account.",
    "ANOMALOUS_COMMIT_REVIEW": "Commits that depart strongly from the repository's usual pattern.",
    "SBOM_INTEGRITY_CONCERN": "The SBOM failed verification, or has not been verified.",
    "DATASET_CONFIDENCE_LIMIT": "The dataset built from these results has known weaknesses.",
    "INSUFFICIENT_EVIDENCE": "Analysis layers that have not been run, so their part of the picture is unknown.",
}


def finding_id(snapshot_id: Any, rule: str, subject: str) -> str:
    return hashlib.sha256(f"{snapshot_id}|{rule}|{subject}".encode()).hexdigest()[:24]


def condition(name: str, result: str, refs: Iterable[str | None] = (), note: str | None = None) -> dict[str, Any]:
    return {"condition": name, "result": result, "evidence_refs": [ref for ref in refs if ref], "note": note}


def statement(basis: str, text: str, *refs: str | None) -> dict[str, Any]:
    return {"basis": basis, "text": text, "evidence_refs": [ref for ref in refs if ref]}


def _assemble(context: Context, *, rule: str, category: str, severity: str, subject: dict[str, Any], statements: list[dict[str, Any]],
              conditions: list[dict[str, Any]], recommendation: dict[str, Any]) -> dict[str, Any]:
    refs: list[str] = []
    for item in (*statements, recommendation, *conditions):
        for ref in item.get("evidence_refs") or []:
            if ref not in refs:
                refs.append(ref)
    statement_refs = [ref for item in (*statements, recommendation) for ref in item["evidence_refs"]]
    refs = [ref for ref in refs if ref in statement_refs]             # a finding cites what its statements use
    evidence = context.store.resolve(refs)
    contributing = sorted({item["layer"] for item in evidence}, key=lambda layer: layers.LAYER_NAMES.index(layer))
    confidence = confidence_model.combine(evidence, contributing, conditions)
    return {
        "finding_id": finding_id(context.snapshot["id"] if context.snapshot else context.project["_id"], rule, subject.get("key") or "project"),
        "rule_id": rule, "category": category, "category_meaning": CATEGORIES[category], "severity": severity,
        "severity_rank": SEVERITY_RANK[severity], "confidence": confidence["value"], "confidence_detail": confidence,
        "subject": subject, "statements": statements, "evidence_refs": refs, "contributing_layers": contributing,
        "recommendation": recommendation, "conditions": conditions, "model_version": MODEL_VERSION,
    }


def _amplifiers(context: Context, node_id: str, group: dict[str, Any]) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    """Other layers that make a reachable vulnerability matter more: (name, statement, condition)."""
    found = []
    dependency = context.dependencies[node_id]
    impact = downstream_impact_value(dependency["dependents"], context.package_count)
    if impact >= HIGH_IMPACT:
        found.append(("high_downstream_impact",
                      statement(OBSERVED, f"{dependency['dependents']} other package(s) depend directly on {dependency['name']}.", dependency["ev"]),
                      condition("high_downstream_impact", TRUE, [dependency["ev"]])))
    path = context.paths.get((node_id, group["group_key"]))
    if path and path["status"] == "SUPPORTED_PATH":
        found.append(("supported_attack_path",
                      statement(DERIVED, f"The attack-path simulation finds a path supported by evidence at every step (score {path['score']}).", path["ev"]),
                      condition("supported_attack_path", TRUE, [path["ev"]])))
    fragile = context.fragility.get(node_id)
    if fragile and fragile.get("fragility_level") == "HIGH":
        found.append(("high_fragility", statement(DERIVED, f"The package's fragility is {fragile['fragility_score']} of 100 (HIGH).", fragile["ev"]),
                      condition("high_fragility", TRUE, [fragile["ev"]])))
    predicted = context.predictive.get(node_id)
    if predicted and predicted.get("level") == "HIGH":
        found.append(("high_predictive_risk",
                      statement(PREDICTED, f"Its predictive dependency risk is {predicted['score']} of 100 (HIGH).", predicted["ev"]),
                      condition("high_predictive_risk", TRUE, [predicted["ev"]])))
    if context.dependency_changes:
        event = context.dependency_changes[0]
        found.append(("recent_dependency_change",
                      statement(DERIVED, f"Dependency files were changed recently (commit {event['commit_sha'][:10]}, "
                                         f"{len(context.dependency_changes)} such commit(s) in the last 30 days).", event["ev"]),
                      condition("recent_dependency_change", TRUE, [event["ev"]])))
    return found


def _unknown_amplifiers(context: Context) -> list[dict[str, Any]]:
    names = {"attack_paths": "supported_attack_path", "fragility": "high_fragility", "predictive": "high_predictive_risk",
             "commits": "recent_dependency_change"}
    return [condition(name, UNKNOWN, note=f"{layers.LAYER_LABELS[layer]} has not been analysed.") for layer, name in names.items()
            if not context.available(layer)]


def _fix(group: dict[str, Any], name: str) -> str:
    fixed = group["fixed_versions"]
    return (f"Upgrade {name} to a version outside the affected range (the advisory lists: {', '.join(fixed[:5])})." if fixed
            else f"The advisory lists no fixed version of {name}; review whether the affected functionality can be avoided or the package replaced.")


def vulnerability_rules(context: Context) -> list[dict[str, Any]]:
    """Per vulnerable package and vulnerability: correlated, reachable, or fragile-and-vulnerable."""
    findings = []
    for node_id in sorted(context.vulnerable):
        dependency = context.dependencies[node_id]
        name = dependency["name"]
        for group in context.vulnerable[node_id]:
            subject = {"type": "dependency", "key": f"{node_id}|{group['group_key']}", "node_id": node_id, "package_name": name,
                       "version": dependency["version"], "advisory": group["source_id"]}
            observed = statement(OBSERVED, f"{group['source_id']} lists {name} {dependency['version'] or '(unresolved version)'} as affected "
                                           f"(severity {group['severity']}).", group["ev"])
            base = [condition("known_vulnerability", TRUE, [group["ev"]])]
            reachable = group["reach_state"] == "REACHABLE"
            if reachable:
                reached = statement(DERIVED, "Static analysis finds application code that refers to the affected functionality.", group["reach_ev"])
                amplifiers = _amplifiers(context, node_id, group)
                conditions = [*base, condition("reachability_confirmed", TRUE, [group["reach_ev"]]), *(c for _n, _s, c in amplifiers),
                              *_unknown_amplifiers(context)]
                serious = group["severity"] in ("CRITICAL", "HIGH")
                if amplifiers:
                    severity = "CRITICAL" if serious and len(amplifiers) >= 2 else "HIGH"
                    findings.append(_assemble(
                        context, rule="correlated_reachable_vulnerability", category="HIGH_PRIORITY_CORRELATED_RISK", severity=severity,
                        subject=subject, statements=[observed, reached, *(s for _n, s, _c in amplifiers)], conditions=conditions,
                        recommendation=statement(RECOMMENDED, "Treat this as the first item to fix. " + _fix(group, name), group["ev"], group["reach_ev"])))
                else:
                    findings.append(_assemble(
                        context, rule="reachable_vulnerability", category="REACHABLE_VULNERABILITY", severity="HIGH" if serious else "MEDIUM",
                        subject=subject, statements=[observed, reached], conditions=conditions,
                        recommendation=statement(RECOMMENDED, _fix(group, name), group["ev"], group["reach_ev"])))
                continue
            fragile = context.fragility.get(node_id)
            if fragile and fragile.get("fragility_level") == "HIGH":
                state_condition = condition("reachability_confirmed", FALSE if group["reach_state"] == "NOT_CONFIRMED_REACHABLE" else UNKNOWN,
                                            [group["reach_ev"]], None if group["reach_ev"] else "Reachability was not determined.")
                findings.append(_assemble(
                    context, rule="fragile_vulnerable_dependency", category="FRAGILE_VULNERABLE_DEPENDENCY",
                    severity="HIGH" if group["severity"] in ("CRITICAL", "HIGH") else "MEDIUM", subject=subject,
                    statements=[observed, statement(DERIVED, f"The package's fragility is {fragile['fragility_score']} of 100 (HIGH): "
                                                             "it is structurally exposed or hard to keep current.", fragile["ev"])],
                    conditions=[*base, state_condition, condition("high_fragility", TRUE, [fragile["ev"]])],
                    recommendation=statement(RECOMMENDED, _fix(group, name) + " Its fragility makes delaying the change more costly.",
                                             group["ev"], fragile["ev"])))
    return findings


def unverified_exposure(context: Context) -> list[dict[str, Any]]:
    """One finding for all vulnerabilities whose reachability is undetermined: it is a gap, not a clearance."""
    undetermined = [(node_id, group) for node_id in sorted(context.vulnerable) for group in context.vulnerable[node_id]
                    if group["reach_state"] in ("UNKNOWN", "UNSUPPORTED", "NOT_ANALYSED")]
    if not undetermined:
        return []
    serious = [item for item in undetermined if item[1]["severity"] in ("CRITICAL", "HIGH")]
    listed = (serious + [item for item in undetermined if item not in serious])[:MAX_LISTED]
    names = ", ".join(f"{context.dependencies[node_id]['name']} ({group['source_id']})" for node_id, group in listed)
    analysed = context.available("reachability")
    statements = [statement(OBSERVED, f"{len(undetermined)} known vulnerabilit(ies) affect packages of this snapshot without a determined "
                                      f"reachability, including: {names}.", *(group["ev"] for _n, group in listed))]
    reach_refs = [group["reach_ev"] for _n, group in listed if group["reach_ev"]]
    if analysed and reach_refs:
        statements.append(statement(DERIVED, "The reachability analysis could not decide these: the package's language is not supported, or "
                                             "the code could not be followed statically.", *reach_refs))
    return [_assemble(
        context, rule="unverified_vulnerability_exposure", category="UNVERIFIED_VULNERABILITY_EXPOSURE", severity="HIGH" if serious else "MEDIUM",
        subject={"type": "project", "key": "unverified-exposure", "count": len(undetermined)}, statements=statements,
        conditions=[condition("known_vulnerability", TRUE, [group["ev"] for _n, group in listed]),
                    condition("reachability_confirmed", UNKNOWN, reach_refs, "Undetermined is not the same as unreachable.")],
        recommendation=statement(RECOMMENDED, ("Review these by hand or fix them by upgrading; " if analysed else "Run the code reachability analysis, then review what remains; ")
                                 + "do not treat an undetermined result as safe.", *(group["ev"] for _n, group in listed[:3])))]


def secret_exposure(context: Context) -> list[dict[str, Any]]:
    if not context.secret_events:
        return []
    events = context.secret_events[:MAX_LISTED]
    files = sorted({path for event in events for path in event["files"]})[:MAX_LISTED]
    return [_assemble(
        context, rule="secret_like_value_committed", category="SECRET_EXPOSURE_REVIEW",
        severity="HIGH" if any(event["severity"] == "HIGH" for event in events) else "MEDIUM",
        subject={"type": "project", "key": "secret-exposure", "commits": [event["commit_sha"] for event in events]},
        statements=[statement(DERIVED, f"{len(context.secret_events)} commit(s) added a value with the format of a credential"
                                       + (f" (in {', '.join(files)})." if files else "."), *(event["ev"] for event in events)),
                    statement(DERIVED, "The match is on the value's format. Whether it is a working credential cannot be told from the diff, "
                                       "and the value itself is not stored.", events[0]["ev"])],
        conditions=[condition("secret_like_value_in_diff", TRUE, [event["ev"] for event in events])],
        recommendation=statement(RECOMMENDED, "Check each one. If it is real, revoke and replace it: removing it in a later commit does not "
                                              "remove it from the history.", events[0]["ev"]))]


def concentrated_change_control(context: Context) -> list[dict[str, Any]]:
    """Concentrated maintenance together with pipeline or dependency-source changes: who reviews those changes?"""
    observed = {item["type"]: item for item in context.maintainer_indicators if item["status"] == "OBSERVED"}
    concentration = observed.get("CONTRIBUTOR_CONCENTRATION") or observed.get("OWNERSHIP_CONCENTRATION")
    changes = context.pipeline_changes or [event for event in context.dependency_changes
                                           if {"package_source_changed", "package_source_config_changed"} & set(event["rules"])]
    conditions = [
        condition("maintenance_concentrated", TRUE if concentration else UNKNOWN if not context.available("maintainers") else FALSE,
                  [concentration["ev"]] if concentration else []),
        condition("pipeline_or_package_source_changed", TRUE if changes else UNKNOWN if not context.available("commits") else FALSE,
                  [event["ev"] for event in changes[:MAX_LISTED]]),
    ]
    if not concentration or not changes:
        return []
    return [_assemble(
        context, rule="concentrated_change_control", category="CONCENTRATED_CHANGE_CONTROL", severity="MEDIUM",
        subject={"type": "project", "key": "change-control"},
        statements=[statement(DERIVED, concentration["detail"], concentration["ev"]),
                    statement(DERIVED, f"{len(changes)} analysed commit(s) changed the build pipeline or where packages are fetched from.",
                              *(event["ev"] for event in changes[:MAX_LISTED])),
                    statement(DERIVED, "Together these mean that changes to how the software is built and what goes into it can be made "
                                       "by one account. This describes the process; it says nothing about the person.", concentration["ev"], changes[0]["ev"])],
        conditions=conditions,
        recommendation=statement(RECOMMENDED, "Require a second reviewer for pipeline and dependency-source changes (branch protection, "
                                              "CODEOWNERS).", concentration["ev"], changes[0]["ev"]))]


def anomalous_commits(context: Context) -> list[dict[str, Any]]:
    if not context.anomalous_commits:
        return []
    commits = context.anomalous_commits[:MAX_LISTED]
    listed = ", ".join(f"{commit['commit_sha'][:10]} ({commit['anomaly_score']})" for commit in commits)
    return [_assemble(
        context, rule="anomalous_commits", category="ANOMALOUS_COMMIT_REVIEW", severity="MEDIUM",
        subject={"type": "project", "key": "anomalous-commits", "commits": [commit["commit_sha"] for commit in commits]},
        statements=[statement(DERIVED, f"{len(context.anomalous_commits)} commit(s) have a HIGH anomaly score against the repository's own "
                                       f"earlier commits: {listed}.", *(commit["ev"] for commit in commits)),
                    statement(DERIVED, "A high score marks a departure from the usual pattern. It is a reason to look, not a conclusion "
                                       "about the change.", commits[0]["ev"])],
        conditions=[condition("high_anomaly_commit", TRUE, [commit["ev"] for commit in commits])],
        recommendation=statement(RECOMMENDED, "Review these commits, starting with the highest score.", commits[0]["ev"]))]


def sbom_integrity(context: Context) -> list[dict[str, Any]]:
    layer = context.layers["sbom"]
    if not layer["available"]:
        return []
    ev = context.layer_evidence["sbom"]
    if layer["verified"] is False:
        failed = ", ".join((layer.get("verification") or {}).get("failed_checks") or []) or "unspecified checks"
        return [_assemble(
            context, rule="sbom_verification_failed", category="SBOM_INTEGRITY_CONCERN", severity="HIGH", subject={"type": "project", "key": "sbom"},
            statements=[statement(OBSERVED, f"The SBOM of this snapshot failed its integrity verification ({failed}).", ev)],
            conditions=[condition("sbom_verified", FALSE, [ev])],
            recommendation=statement(RECOMMENDED, "Do not rely on this SBOM. Generate a new one and find out why the stored one changed.", ev))]
    if layer["verified"] is None:
        return [_assemble(
            context, rule="sbom_not_verified", category="SBOM_INTEGRITY_CONCERN", severity="LOW", subject={"type": "project", "key": "sbom"},
            statements=[statement(OBSERVED, "An SBOM exists for this snapshot, but its integrity has not been verified.", ev)],
            conditions=[condition("sbom_verified", UNKNOWN, [ev], "Verification has not been run.")],
            recommendation=statement(RECOMMENDED, "Run the SBOM verification before relying on it.", ev))]
    return []


def dataset_confidence(context: Context) -> list[dict[str, Any]]:
    layer = context.layers["dataset"]
    if not layer["available"] or layer["quality_status"] in (None, "VALID"):
        return []
    ev = context.layer_evidence["dataset"]
    status = layer["quality_status"]
    severity = {"INVALID": "HIGH", "LOW_CONFIDENCE": "LOW", "WARNING": "LOW", "UNKNOWN": "INFO"}.get(status, "LOW")
    return [_assemble(
        context, rule="dataset_confidence_limit", category="DATASET_CONFIDENCE_LIMIT", severity=severity, subject={"type": "project", "key": "dataset"},
        statements=[statement(DERIVED, f"Validation of dataset version {layer['version']} ended with status {status}"
                                       + (f" and a quality score of {layer['quality_score']}." if layer["quality_score"] is not None else "."), ev)],
        conditions=[condition("dataset_valid", FALSE, [ev])],
        recommendation=statement(RECOMMENDED, "Open the dataset's validation result and resolve what it lists before using the dataset for "
                                              "evaluation or training." if status != "INVALID" else
                                 "The stored dataset no longer matches its hashes. Rebuild it and find out what changed it.", ev))]


def insufficient_evidence(context: Context) -> list[dict[str, Any]]:
    gaps = layers.missing(context.layers)
    if not gaps or not context.layer_evidence:
        return []
    anchor = next(iter(context.layer_evidence.values()))
    names = ", ".join(gap["label"] for gap in gaps)
    return [_assemble(
        context, rule="insufficient_evidence", category="INSUFFICIENT_EVIDENCE", severity="INFO",
        subject={"type": "project", "key": "coverage", "missing_layers": [gap["layer"] for gap in gaps]},
        statements=[statement(DERIVED, f"{len(gaps)} of {len(layers.LAYER_NAMES)} analysis layers have no usable result for this snapshot: {names}. "
                                       "What they would show is unknown; their absence is not a clean result.", anchor)],
        conditions=[condition(f"{gap['layer']}_analysed", UNKNOWN, note=gap["status"]) for gap in gaps],
        recommendation=statement(RECOMMENDED, " ".join(dict.fromkeys(gap["action"] for gap in gaps)), anchor))]


RULES: tuple[tuple[str, Callable[[Context], list[dict[str, Any]]]], ...] = (
    ("vulnerability_correlation", vulnerability_rules), ("unverified_vulnerability_exposure", unverified_exposure),
    ("secret_like_value_committed", secret_exposure), ("concentrated_change_control", concentrated_change_control),
    ("anomalous_commits", anomalous_commits), ("sbom_integrity", sbom_integrity), ("dataset_confidence_limit", dataset_confidence),
    ("insufficient_evidence", insufficient_evidence),
)


def reason(context: Context) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Run every rule. Returns (findings ordered by severity, per-rule trace). Deterministic for the same context."""
    findings: list[dict[str, Any]] = []
    trace = []
    for name, rule in RULES:
        produced = rule(context)
        findings += produced
        trace.append({"rule": name, "findings": len(produced)})
    findings.sort(key=lambda item: (-item["severity_rank"], -item["confidence"], item["category"], item["finding_id"]))
    return findings, trace
