"""Gathers what the analysis layers stored into one context for reasoning, registering every fact as evidence.

Nothing is analysed here and nothing is fetched from outside: the context is
a read of stored results. A layer that has not been analysed contributes no
facts, and the rules see it as unknown.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from pymongo.database import Database

from app.ai.evidence import DERIVED, OBSERVED, PREDICTED, EvidenceStore
from app.models.collections import (
    ATTACK_PATHS, BEHAVIOUR_EVENTS, CODE_REACHABILITY, COMMIT_ANALYSIS, DEPENDENCIES, DEPENDENCY_FRAGILITY, GRAPH_RISK_ANALYSIS, PREDICTIONS,
    SECURITY_EVENTS,
)
from app.services import attack_paths, layers, runs

LABEL_CONFIDENCE = {"HIGH": 1.0, "MEDIUM": 0.8, "LOW": 0.6}
REACHABILITY_ORDER = ("REACHABLE", "UNKNOWN", "UNSUPPORTED", "NOT_CONFIRMED_REACHABLE")
RECENT_DAYS = 30
MAX_EVENTS = 50


@dataclass
class Context:
    project: dict[str, Any]
    snapshot: dict[str, Any] | None
    layers: dict[str, Any]
    store: EvidenceStore
    now: Any
    layer_evidence: dict[str, str] = field(default_factory=dict)
    dependencies: dict[str, dict[str, Any]] = field(default_factory=dict)
    package_count: int = 0
    vulnerable: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    fragility: dict[str, dict[str, Any]] = field(default_factory=dict)
    predictive: dict[str, dict[str, Any]] = field(default_factory=dict)
    graph_risk: dict[str, dict[str, Any]] = field(default_factory=dict)
    paths: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    maintainer_indicators: list[dict[str, Any]] = field(default_factory=list)
    secret_events: list[dict[str, Any]] = field(default_factory=list)
    dependency_changes: list[dict[str, Any]] = field(default_factory=list)
    pipeline_changes: list[dict[str, Any]] = field(default_factory=list)
    anomalous_commits: list[dict[str, Any]] = field(default_factory=list)

    def available(self, layer: str) -> bool:
        return bool(self.layers[layer]["available"])

    def digest(self) -> str:
        """Identifies the stored inputs, so an unchanged context is recognised."""
        return runs.digest({name: [self.layers[name]["status"], self.layers[name]["reference"], self.layers[name]["as_of"]]
                            for name in (*layers.LAYER_NAMES,)} | {"events": [len(self.secret_events), len(self.dependency_changes),
                                                                            len(self.pipeline_changes), len(self.anomalous_commits)]})


def _layer_summary(name: str, layer: dict[str, Any]) -> str:
    if name == "inventory":
        return f"Dependency inventory of the snapshot: {layer['stats']['total']} package(s)."
    if name == "sbom":
        state = "not verified yet" if layer["verified"] is None else "verification passed" if layer["verified"] else "verification failed"
        return f"SBOM version {layer['version']} with {layer['component_count']} component(s); {state}."
    if name == "vulnerabilities":
        return (f"Vulnerability check of the snapshot: {layer['distinct_vulnerabilities']} distinct vulnerabilit(ies) affecting "
                f"{layer['affected_dependencies']} package(s).")
    if name == "reachability":
        return f"Code reachability analysis: {layer['findings']} finding(s), by status {layer['by_status']}."
    if name == "attack_paths":
        return f"Attack-path simulation: {layer['summary'].get('paths', 0)} path(s), by status {layer['summary'].get('by_status', {})}."
    if name == "maintainers":
        return f"Maintainer behaviour profile: attention score {layer['attention_score']} (confidence {layer['confidence']})."
    if name == "commits":
        return f"Commit behaviour analysis: {layer['analysed_total']} commit(s) analysed, {layer['security_events']} event(s) listed for review."
    if name == "dataset":
        return f"Dataset version {layer['version']}: {layer['record_count']} record(s), validation status {layer['quality_status']}."
    return f"{layers.LAYER_LABELS[name]} analysis of the snapshot."


def build(db: Database, project: dict[str, Any]) -> Context:
    collected = layers.collect(db, project)
    store = EvidenceStore()
    now = runs.now()
    context = Context(project=project, snapshot=collected["snapshot"], layers=collected, store=store, now=now)
    for name in layers.LAYER_NAMES:
        layer = collected[name]
        if layer["available"] and layer["reference"]:
            basis = OBSERVED if name in ("inventory", "sbom", "vulnerabilities") else PREDICTED if name == "predictive" else DERIVED
            context.layer_evidence[name] = store.add(layer=name, collection=layer["reference"]["collection"], record_id=layer["reference"]["id"],
                                                     basis=basis, summary=_layer_summary(name, layer), as_of=layer["as_of"])
    snapshot = collected["snapshot"]
    project_id = project["_id"]

    if snapshot is not None:
        snapshot_id = snapshot["id"]
        context.package_count = collected["inventory"]["stats"]["total"] or 0
        advisories: dict[str, list[dict[str, Any]]] = {}
        of_match: dict[Any, tuple[str, str]] = {}
        if context.available("vulnerabilities"):
            advisories, of_match = attack_paths.advisory_groups(db, project_id, snapshot_id)
        wanted = list(advisories)
        for document in db[DEPENDENCIES].find({"snapshot_id": snapshot_id, "project_id": project_id, "node_id": {"$in": wanted}},
                                              {"node_id": 1, "name": 1, "version": 1, "relationship": 1, "dependents_count": 1, "depth": 1}):
            version = document.get("version") or "unresolved version"
            context.dependencies[document["node_id"]] = {
                "name": document.get("name"), "version": document.get("version"), "relationship": document.get("relationship"),
                "dependents": document.get("dependents_count") or 0, "depth": document.get("depth"),
                "ev": store.add(layer="inventory", collection=DEPENDENCIES, record_id=document["_id"], basis=OBSERVED, subject=document["node_id"],
                                summary=f"{document.get('name')} {version} is a {str(document.get('relationship') or 'unknown').lower()} dependency "
                                        f"(depth {document.get('depth')}); {document.get('dependents_count') or 0} package(s) depend on it directly."),
            }
        findings: dict[tuple[str, str], list[dict[str, Any]]] = {}
        if context.available("reachability"):
            for finding in db[CODE_REACHABILITY].find(
                    {"project_id": project_id, "snapshot_id": snapshot_id, "analysis_id": collected["reachability"]["reference"]["id"]},
                    {"match_id": 1, "status": 1, "confidence": 1, "evidence.source_file": 1, "evidence.line": 1, "advisory_id": 1}):
                key = of_match.get(finding.get("match_id"))
                if key is not None:
                    findings.setdefault(key, []).append(finding)
        for node_id, groups in advisories.items():
            if node_id not in context.dependencies:
                continue
            name = context.dependencies[node_id]["name"]
            for group in groups:
                entry = {
                    "group_key": group["group_key"], "source_id": group["source_id"], "severity": group["severity"], "summary": group.get("summary"),
                    "fixed_versions": group.get("fixed_versions") or [], "reach_state": "NOT_ANALYSED", "reach_ev": None,
                    "ev": store.add(layer="vulnerabilities", collection="vulnerability_matches", record_id=group["match_ids"][0], basis=OBSERVED,
                                    subject=node_id, confidence=LABEL_CONFIDENCE.get(group.get("confidence") or "", 0.6),
                                    summary=f"{group['source_id']} lists {name} {context.dependencies[node_id]['version'] or ''} as affected "
                                            f"(severity {group['severity']})."),
                }
                available = findings.get((node_id, group["group_key"])) or []
                for state in REACHABILITY_ORDER:
                    chosen = sorted((f for f in available if f.get("status") == state), key=lambda f: str(f["_id"]))
                    if chosen:
                        finding = chosen[0]
                        located = finding.get("evidence") or {}
                        where = f" at {located['source_file']}:{located.get('line')}" if state == "REACHABLE" and located.get("source_file") else ""
                        entry["reach_state"] = state
                        entry["reach_ev"] = store.add(
                            layer="reachability", collection=CODE_REACHABILITY, record_id=finding["_id"], basis=DERIVED, subject=node_id,
                            confidence=LABEL_CONFIDENCE.get(finding.get("confidence") or "", 0.7 if state == "REACHABLE" else None),
                            summary=f"Static reachability of {group['source_id']} in {name}: {state}{where}.")
                        break
                context.vulnerable.setdefault(node_id, []).append(entry)

        def scores(layer: str, collection: str, fields: dict[str, int], basis: str, describe) -> dict[str, dict[str, Any]]:
            if not context.available(layer) or not wanted:
                return {}
            reference = collected[layer]["reference"]["id"]
            result = {}
            for row in db[collection].find({"analysis_id": reference, "node_id": {"$in": wanted}}, {"node_id": 1, "confidence": 1, **fields}):
                result[row["node_id"]] = {**{k: row.get(k) for k in fields}, "ev": store.add(
                    layer=layer, collection=collection, record_id=row["_id"], basis=basis, subject=row["node_id"],
                    confidence=row.get("confidence") if isinstance(row.get("confidence"), (int, float)) else None, summary=describe(row))}
            return result

        context.fragility = scores("fragility", DEPENDENCY_FRAGILITY, {"fragility_score": 1, "fragility_level": 1, "package_name": 1}, DERIVED,
                                   lambda r: f"Fragility of {r.get('package_name')}: {r.get('fragility_score')} of 100 ({r.get('fragility_level')}).")
        context.predictive = scores("predictive", PREDICTIONS, {"score": 1, "level": 1, "package_name": 1}, PREDICTED,
                                    lambda r: f"Predictive dependency risk of {r.get('package_name')}: {r.get('score')} of 100 ({r.get('level')}).")
        context.graph_risk = scores("graph_risk", GRAPH_RISK_ANALYSIS, {"graph_risk": 1, "classification": 1, "package_name": 1}, DERIVED,
                                    lambda r: f"Graph risk of {r.get('package_name')}: {r.get('graph_risk')} of 100.")
        if context.available("attack_paths"):
            for row in db[ATTACK_PATHS].find({"analysis_id": collected["attack_paths"]["reference"]["id"]},
                                             {"attack_path_id": 1, "status": 1, "score": 1, "level": 1, "confidence": 1, "target": 1,
                                              "advisory.group_key": 1, "advisory.source_id": 1}):
                node_id, group_key = row["target"]["node_id"], row["advisory"]["group_key"]
                context.paths[(node_id, group_key)] = {
                    "attack_path_id": row["attack_path_id"], "status": row["status"], "score": row["score"], "level": row["level"],
                    "ev": store.add(layer="attack_paths", collection=ATTACK_PATHS, record_id=row["attack_path_id"], basis=DERIVED, subject=node_id,
                                    confidence=row.get("confidence"),
                                    summary=f"Attack path to {row['target'].get('package_name')} via {row['advisory']['source_id']}: "
                                            f"{row['status']}, score {row['score']}.")}

    if context.available("maintainers"):
        reference = collected["maintainers"]["reference"]
        for item in collected["maintainers"]["indicators"]:
            context.maintainer_indicators.append({**item, "ev": store.add(
                layer="maintainers", collection=reference["collection"], record_id=reference["id"], basis=DERIVED, subject=item["type"],
                confidence=collected["maintainers"].get("confidence"), summary=f"{item['type']}: {item['status']}. {item.get('detail') or ''}"[:400])
                if item["status"] == "OBSERVED" else None})

    if context.available("commits") and collected["commits"]["analysed_total"]:
        recent_after = now - timedelta(days=RECENT_DAYS)

        def events(collection: str, query: dict[str, Any]) -> list[dict[str, Any]]:
            found = []
            for event in db[collection].find({"project_id": project_id, **query}).sort([("occurred_at", -1), ("event_type", 1)]).limit(MAX_EVENTS):
                found.append({
                    "commit_sha": event["commit_sha"], "event_type": event["event_type"], "severity": event["severity"],
                    "occurred_at": event.get("occurred_at"), "files": event.get("changed_files") or [],
                    "rules": sorted({item.get("rule") for item in event.get("evidence") or [] if item.get("rule")}),
                    "ev": store.add(layer="commits", collection=collection, record_id=event["_id"], basis=DERIVED, subject=event["commit_sha"],
                                    confidence=event.get("confidence"), as_of=event.get("occurred_at"),
                                    summary=f"Commit {event['commit_sha'][:10]}: {event['event_type']} ({event['severity']}). {event.get('summary') or ''}")})
            return found

        context.secret_events = events(SECURITY_EVENTS, {"event_type": "SECRET_LIKE_PATTERN"})
        context.dependency_changes = events(BEHAVIOUR_EVENTS, {"event_type": "DEPENDENCY_CHANGE", "occurred_at": {"$gte": recent_after}})
        context.pipeline_changes = events(BEHAVIOUR_EVENTS, {"event_type": "SECURITY_CONFIG_CHANGE", "evidence.rule": "ci_pipeline_changed"})
        for row in db[COMMIT_ANALYSIS].find({"project_id": project_id, "level": "HIGH"},
                                            {"commit_sha": 1, "anomaly_score": 1, "confidence": 1, "committed_at": 1, "indicator_types": 1})\
                .sort([("anomaly_score", -1), ("commit_sha", 1)]).limit(20):
            context.anomalous_commits.append({
                "commit_sha": row["commit_sha"], "anomaly_score": row["anomaly_score"], "indicator_types": row.get("indicator_types") or [],
                "ev": store.add(layer="commits", collection=COMMIT_ANALYSIS, record_id=row["_id"], basis=DERIVED, subject=row["commit_sha"],
                                confidence=row.get("confidence"), as_of=row.get("committed_at"),
                                summary=f"Commit {row['commit_sha'][:10]} has anomaly score {row['anomaly_score']} of 100.")})
    return context
