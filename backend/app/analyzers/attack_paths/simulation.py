"""Builds attack paths from stored evidence and answers "what if this package were fixed".

For every vulnerable package and every distinct vulnerability matched to it,
one path is produced:

    ENTRY -> DEPENDENCY ... -> VULNERABILITY -> REACHABILITY -> APPLICATION -> DOWNSTREAM_COMPONENT -> IMPACT

The dependency part is the shortest chain from the project (breadth-first);
other chains are listed as alternatives (depth-first, bounded). The search
runs over the stored dependency graph only.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from app.analyzers.attack_paths import attack_edges as E
from app.analyzers.attack_paths import attack_nodes as N
from app.analyzers.attack_paths import risk
from app.analyzers.attack_paths.path_engine import shortest_path, simple_paths
from app.analyzers.graph.graph_metrics import Structure

REACHABILITY_ORDER = ("REACHABLE", "UNKNOWN", "UNSUPPORTED", "NOT_CONFIRMED_REACHABLE")
NOT_ANALYSED = "NOT_ANALYSED"


@dataclass(frozen=True)
class Limits:
    max_depth: int = 12
    max_paths: int = 500
    max_routes: int = 3
    max_expansions: int = 20_000


@dataclass
class Inputs:
    project_name: str
    snapshot_id: str
    structure: Structure
    dependencies: dict[str, dict[str, Any]]                          # node id -> dependency document
    advisories: dict[str, list[dict[str, Any]]]                      # node id -> distinct vulnerabilities matched to it
    findings: dict[tuple[str, str], list[dict[str, Any]]] = field(default_factory=dict)   # (node id, group key) -> reachability findings
    reachability_analysed: bool = False
    annotations: dict[str, dict[str, Any]] = field(default_factory=dict)   # node id -> scores from dependency intelligence


def path_id(snapshot_id: str, node_id: str, group_key: str) -> str:
    return hashlib.sha256(f"{snapshot_id}|{node_id}|{group_key}".encode()).hexdigest()[:24]


def strongest_finding(findings: list[dict[str, Any]], analysed: bool) -> tuple[dict[str, Any] | None, str]:
    """The finding that says most about reachability, and its state. Without an analysis the state is NOT_ANALYSED."""
    if not analysed or not findings:
        return None, NOT_ANALYSED
    for state in REACHABILITY_ORDER:
        matching = sorted((f for f in findings if f.get("status") == state), key=lambda f: str(f.get("_id")))
        if matching:
            return matching[0], state
    return None, NOT_ANALYSED


def _routes(inputs: Inputs, position: int, limits: Limits) -> tuple[list[str] | None, list[list[str]], bool, int]:
    """Dependency chains from the project to a package: (shortest, alternatives, truncated, packages left out).

    Chains start at a direct dependency. The shortest chain is always found
    when one exists; one longer than the depth limit is shortened in the
    middle, and the number of packages left out is returned.
    """
    model = inputs.structure.model
    parents = lambda node: model.parents[node]          # noqa: E731 - walk towards the project
    is_direct = lambda node: model.direct[node]         # noqa: E731
    shortest = shortest_path(parents, position, is_direct, max_depth=model.size)
    if shortest is None:
        return None, [], False, 0
    primary = [model.ids[node] for node in reversed(shortest)]
    omitted = 0
    if len(primary) > limits.max_depth:
        head = max(1, limits.max_depth // 2)
        tail = max(1, limits.max_depth - head)
        omitted = len(primary) - head - tail
        return [*primary[:head], *primary[-tail:]], [], True, omitted
    alternatives: list[list[str]] = []
    truncated = False
    if limits.max_routes > 1:
        found, truncated = simple_paths(parents, position, is_direct, max_depth=limits.max_depth - 1,
                                        max_paths=limits.max_routes * 4 + 1, max_expansions=limits.max_expansions)
        chains = sorted(([model.ids[node] for node in reversed(chain)] for chain in found), key=lambda chain: (len(chain), chain))
        alternatives = [chain for chain in chains if chain != primary][:limits.max_routes - 1]
        truncated = truncated or len(chains) - 1 > len(alternatives)
    return primary, alternatives, truncated, omitted


def _explain(status: str, chain: list[str] | None, target: dict[str, Any], advisory: dict[str, Any], state: str, finding: dict[str, Any] | None,
             dependents: int, parts: dict[str, Any], value: float) -> list[dict[str, str]]:
    name = f"{target.get('name')} {target.get('version') or '(unresolved version)'}"
    lines = []
    if chain is None:
        lines.append({"basis": N.OBSERVED, "text": f"{name} is in the dependency inventory, but no chain of dependencies from the project to it is recorded."})
    elif len(chain) == 1:
        lines.append({"basis": N.OBSERVED, "text": f"The project requires {name} directly."})
    else:
        lines.append({"basis": N.OBSERVED, "text": f"The project reaches {name} through {len(chain) - 1} other package(s): {' -> '.join(chain)}."})
    lines.append({"basis": N.OBSERVED, "text": f"{advisory['source_id']} lists this version as affected"
                  + (f" (severity {advisory['severity']})." if advisory.get("severity") not in (None, "UNKNOWN") else " (no severity is published).")})
    located = (finding or {}).get("evidence") or {}
    if state == "REACHABLE" and located.get("source_file"):
        lines.append({"basis": N.DERIVED, "text": f"Static analysis found a reference to the affected functionality at {located['source_file']}"
                      + (f":{located['line']}." if located.get("line") else ".")})
    else:
        lines.append({"basis": N.DERIVED if finding is not None else N.INFERRED, "text": N._REACHABILITY_TEXT[state]})
    lines.append({"basis": N.DERIVED, "text": f"{dependents} other package(s) depend on {target.get('name')}; a problem in it can affect them."})
    lines.append({"basis": N.DERIVED, "text": (
        f"Score {value} = {parts['vulnerability_signal']} (severity {parts['severity']}) × {parts['reachability_signal']} (reachability) × "
        f"{parts['graph_impact']} (graph impact) × {parts['confidence']} (confidence).")})
    lines.append({"basis": N.INFERRED, "text": risk.STATUS_MEANING[status] + " No exploit was attempted."})
    return lines


def _break_points(chain: list[str] | None, target: dict[str, Any], advisory: dict[str, Any]) -> list[dict[str, Any]]:
    """Changes that would remove this path. RECOMMENDED: they follow from the evidence but are a suggestion, not a finding."""
    points = []
    fixed = advisory.get("fixed_versions") or []
    points.append({"basis": "RECOMMENDED", "action": "UPGRADE" if fixed else "REVIEW", "node_id": target["node_id"],
                   "detail": (f"The advisory lists fixed version(s): {', '.join(fixed[:5])}. A version outside the affected range removes this path."
                              if fixed else "The advisory lists no fixed version. Review whether the package can be replaced or the affected "
                              "functionality avoided.")})
    if chain and len(chain) > 1:
        points.append({"basis": "RECOMMENDED", "action": "REVIEW_PARENT", "node_id": chain[0],
                       "detail": f"The package arrives through {chain[0]}; a release of it that requires a fixed version also removes this path."})
    return points


def simulate(inputs: Inputs, limits: Limits = Limits()) -> dict[str, Any]:
    """All attack paths of a snapshot, scored and ordered, with a summary. Pure and deterministic."""
    model = inputs.structure.model
    packages = model.size
    paths: list[dict[str, Any]] = []
    truncated_routes = 0
    considered = 0
    for node_id in sorted(inputs.advisories):
        if node_id not in model.index or node_id not in inputs.dependencies:
            continue                                   # an advisory for a package that is not in this graph is not a path
        position = model.index[node_id]
        target = inputs.dependencies[node_id]
        chain, alternatives, truncated, omitted = _routes(inputs, position, limits)
        truncated_routes += truncated
        dependents = inputs.structure.rows[node_id]["dependents"]
        exposed = [model.ids[index] for index in range(packages) if model.ancestors[position] >> index & 1][:5]
        for advisory in sorted(inputs.advisories[node_id], key=lambda item: (-(item.get("severity_rank") or 0), item["group_key"])):
            considered += 1
            finding, state = strongest_finding(inputs.findings.get((node_id, advisory["group_key"]), []), inputs.reachability_analysed)
            nodes: list[dict[str, Any]] = []
            edges: list[dict[str, Any]] = []
            first = inputs.dependencies.get(chain[0], target) if chain else target
            entry = N.entry(inputs.project_name, (first.get("evidence") or []) if chain else [])
            vulnerable = N.dependency(target, vulnerable=True)
            if chain:
                nodes.append(entry)
                previous = entry
                for step in chain:
                    document = inputs.dependencies.get(step) or {"node_id": step, "name": step}
                    current = vulnerable if step == node_id else N.dependency(document)
                    if previous is entry:
                        edges.append(E.edge(entry["id"], current["id"], E.DECLARES, N.OBSERVED, E.declaration_confidence(document),
                                            document.get("relationship_reason") or "Declared by the project."))
                    elif omitted and step == chain[max(1, limits.max_depth // 2)]:
                        edges.append(E.edge(previous["id"], current["id"], E.REQUIRES, N.DERIVED, 1.0,
                                            f"{omitted} intermediate package(s) of this chain are left out of the display."))
                    else:
                        edges.append(E.edge(previous["id"], current["id"], E.REQUIRES, N.OBSERVED, 1.0,
                                            "Recorded in the dependency graph of the snapshot."))
                    nodes.append(current)
                    previous = current
            else:
                nodes.append(vulnerable)
            weakness = N.vulnerability(node_id, advisory)
            assessed = N.reachability(node_id, advisory["group_key"], finding, state)
            application = N.application(finding, state)
            below = N.downstream(node_id, dependents, packages, exposed)
            outcome = N.impact(node_id, advisory, state)
            nodes += [weakness, assessed, application, below, outcome]
            edges += [
                E.edge(vulnerable["id"], weakness["id"], E.AFFECTED_BY, N.OBSERVED, E.match_confidence(advisory),
                       advisory.get("match_explanation") or "The installed version is inside the range the advisory publishes."),
                E.edge(weakness["id"], assessed["id"], E.ASSESSED_AS, N.DERIVED if finding is not None else N.INFERRED,
                       E.reachability_confidence(finding, state), N._REACHABILITY_TEXT[state]),
                E.edge(assessed["id"], application["id"], E.USED_IN, N.OBSERVED if application["located"] else N.INFERRED, 1.0,
                       "Source location recorded by the reachability analysis." if application["located"]
                       else "The application contains the package; no use site is tied to this path."),
                E.edge(application["id"], below["id"], E.PROPAGATES_TO, N.DERIVED, 1.0, "Counted from the dependency graph."),
                E.edge(below["id"], outcome["id"], E.MAY_RESULT_IN, N.INFERRED, 1.0, "Consequence as described by the advisory; not tested."),
            ]
            confidence, lowered = E.propagate(edges)
            impact = risk.graph_impact(len(chain) + omitted if chain else None, dependents, packages)
            parts = risk.components(advisory.get("severity") or "UNKNOWN", state, impact, confidence)
            value = risk.score(parts)
            status = risk.status_for(chain is not None, state)
            evidence = [item | {"node": entry_node["id"], "stage": entry_node["stage"]} for entry_node in nodes for item in entry_node["evidence"]]
            paths.append({
                "attack_path_id": path_id(inputs.snapshot_id, node_id, advisory["group_key"]),
                "status": status, "status_rank": risk.STATUS_RANK[status], "status_meaning": risk.STATUS_MEANING[status],
                "score": value, "level": risk.level(value), "confidence": confidence, "components": {**parts, "confidence_lowered_by": lowered},
                "target": {"node_id": node_id, "dependency_id": target.get("_id"), "package_name": target.get("name"),
                           "normalized_name": target.get("normalized_name"), "ecosystem": target.get("ecosystem"),
                           "version": target.get("version"), "relationship": target.get("relationship")},
                "advisory": {"source_id": advisory["source_id"], "group_key": advisory["group_key"], "aliases": advisory.get("aliases", [])[:10],
                             "severity": advisory.get("severity") or "UNKNOWN", "summary": advisory.get("summary"),
                             "fixed_versions": advisory.get("fixed_versions", [])[:10], "match_count": advisory.get("match_count", 1)},
                "reachability": {"state": state, "finding_id": (finding or {}).get("_id"),
                                 "source_file": ((finding or {}).get("evidence") or {}).get("source_file") if state == "REACHABLE" else None,
                                 "line": ((finding or {}).get("evidence") or {}).get("line") if state == "REACHABLE" else None},
                "route": chain, "route_length": len(chain) + omitted if chain else None, "route_omitted": omitted,
                "alternative_routes": alternatives, "routes_truncated": truncated, "downstream": {"dependents": dependents, "examples": exposed},
                "related": inputs.annotations.get(node_id) or None,
                "nodes": nodes, "edges": edges, "evidence": evidence,
                "explanation": _explain(status, chain, target, advisory, state, finding, dependents, parts, value),
                "break_points": _break_points(chain, target, advisory),
                "exploit_confirmed": False, "model_version": risk.MODEL_VERSION,
            })
    paths.sort(key=lambda item: (-item["score"], -item["status_rank"], item["attack_path_id"]))
    kept = paths[:limits.max_paths]
    for rank, item in enumerate(kept, start=1):
        item["rank"] = rank
    return {"paths": kept, "summary": summarise(kept, considered, len(paths) > len(kept), truncated_routes), "model_version": risk.MODEL_VERSION}


def summarise(paths: list[dict[str, Any]], considered: int, truncated: bool, truncated_routes: int) -> dict[str, Any]:
    return {
        "paths": len(paths), "candidates": considered, "paths_truncated": truncated, "routes_truncated": truncated_routes,
        "by_status": {status: sum(1 for item in paths if item["status"] == status) for status in risk.STATUSES},
        "by_level": dict(Counter(item["level"] for item in paths)),
        "by_severity": dict(Counter(item["advisory"]["severity"] for item in paths)),
        "highest_score": max((item["score"] for item in paths), default=None),
        "vulnerable_packages": len({item["target"]["node_id"] for item in paths}),
        "top": [{"attack_path_id": item["attack_path_id"], "score": item["score"], "status": item["status"],
                 "node_id": item["target"]["node_id"], "advisory": item["advisory"]["source_id"]} for item in paths[:5]],
        "choke_points": choke_points(paths)[:10],
        "exploit_confirmed": 0,
        "meaning": "Paths are built from stored static evidence. None was exercised, and none shows that an attack would succeed.",
    }


def choke_points(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Packages that most paths pass through: where one change removes the most paths."""
    through: dict[str, dict[str, Any]] = {}
    for item in paths:
        for node_id in item["route"] or [item["target"]["node_id"]]:
            entry = through.setdefault(node_id, {"node_id": node_id, "paths": 0, "score_sum": 0.0, "max_score": 0.0, "is_target": False})
            entry["paths"] += 1
            entry["score_sum"] = round(entry["score_sum"] + item["score"], 1)
            entry["max_score"] = max(entry["max_score"], item["score"])
            entry["is_target"] = entry["is_target"] or node_id == item["target"]["node_id"]
    return sorted(through.values(), key=lambda entry: (-entry["paths"], -entry["score_sum"], entry["node_id"]))


def without(paths: list[dict[str, Any]], node_id: str) -> dict[str, Any]:
    """What would remain if a package no longer carried a path (fixed or removed). A static what-if, not a prediction.

    A path is removed when the package is its target, or when it lies on the
    path's chain and on every alternative chain that was found. If the
    alternatives were truncated, removal cannot be concluded and the path is
    reported as undetermined.
    """
    removed, undetermined, remaining = [], [], []
    for item in paths:
        if item["target"]["node_id"] == node_id:
            removed.append(item)
            continue
        chains = ([item["route"]] if item["route"] else []) + list(item.get("alternative_routes") or [])
        if not chains or not any(node_id in chain for chain in chains):
            remaining.append(item)
        elif all(node_id in chain for chain in chains):
            (undetermined if item.get("routes_truncated") else removed).append(item)
        else:
            remaining.append(item)
    return {
        "node_id": node_id, "paths_before": len(paths), "paths_removed": len(removed), "paths_undetermined": len(undetermined),
        "paths_remaining": len(remaining) + len(undetermined),
        "highest_score_before": max((item["score"] for item in paths), default=None),
        "highest_score_after": max((item["score"] for item in remaining + undetermined), default=None),
        "removed": [item["attack_path_id"] for item in removed][:200],
        "basis": "DERIVED",
        "note": "Computed from the stored paths. It assumes the change introduces nothing new, which only a new analysis can show.",
    }
