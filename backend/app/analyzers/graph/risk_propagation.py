"""How an observed vulnerability in one package relates to the rest of the dependency graph (model "graph-risk-v1").

Classification of every package:

  DIRECT_VULNERABILITY       an advisory matches this package's own version (Phase 3)
  DEPENDENCY_PROPAGATION     it directly requires a package with a direct vulnerability
  INDIRECT_EXPOSURE          it requires one through other packages
  NO_OBSERVED_PROPAGATION    none of the above was observed

Only the first is a statement that the package is vulnerable. The others say
that a vulnerable package lies in what this one depends on; whether that
matters depends on how it is used, which is not analysed here. A package that
a vulnerable package depends on is not exposed by it.

Node risk, every component kept visible:

    own_risk        = vulnerability_signal × reachability_signal × centrality_signal × downstream_impact × confidence
    propagated_risk = max over vulnerable packages it depends on of  own_risk(source) × DECAY ^ distance
    graph_risk      = max(own_risk, propagated_risk)                                        (0-100)
"""

from __future__ import annotations

import heapq
from collections import deque
from typing import Any

from app.analyzers.fragility.metrics import downstream_impact_value
from app.analyzers.graph.graph_metrics import Structure

MODEL_VERSION = "graph-risk-v1"

DIRECT_VULNERABILITY = "DIRECT_VULNERABILITY"
DEPENDENCY_PROPAGATION = "DEPENDENCY_PROPAGATION"
INDIRECT_EXPOSURE = "INDIRECT_EXPOSURE"
NO_OBSERVED_PROPAGATION = "NO_OBSERVED_PROPAGATION"
CLASSIFICATIONS = (DIRECT_VULNERABILITY, DEPENDENCY_PROPAGATION, INDIRECT_EXPOSURE, NO_OBSERVED_PROPAGATION)

# Severity as published by the advisory source, as a 0-100 signal. UNKNOWN is the midpoint: the source gives no
# severity, and nothing is assumed about it either way.
SEVERITY_SIGNAL = {"CRITICAL": 100, "HIGH": 80, "MEDIUM": 55, "LOW": 30, "UNKNOWN": 50}
# What Phase 4 established. A missing path is never treated as zero: "not confirmed" is not "safe".
REACHABILITY_SIGNAL = {"REACHABLE": 1.0, "UNKNOWN": 0.7, "UNSUPPORTED": 0.7, "NOT_ANALYSED": 0.7, "NOT_CONFIRMED_REACHABLE": 0.4}
DECAY = 0.5                      # per dependency step between a package and the vulnerable package it relies on
MAX_LISTED = 5                   # strongest vulnerable packages listed for each package that depends on them
MAX_PATHS = 50                   # paths from the project that are stored
MAX_PATH_NODES = 12              # packages shown of one path; the middle of a longer path is left out


def reachability_state(reach: dict[str, Any] | None, analysed: bool) -> str:
    """The strongest thing Phase 4 says about a package's vulnerabilities."""
    if not analysed or not reach or not reach.get("findings"):
        return "NOT_ANALYSED"
    for state in ("REACHABLE", "UNKNOWN", "UNSUPPORTED", "NOT_CONFIRMED_REACHABLE"):
        if reach.get(state.lower() if state != "NOT_CONFIRMED_REACHABLE" else "not_confirmed"):
            return state
    return "NOT_ANALYSED"


def propagate(structure: Structure, vulnerabilities: dict[str, dict[str, Any]], reachability: dict[str, dict[str, Any]],
              reachability_analysed: bool) -> dict[str, Any]:
    """Risk components and exposure classification for every package. Pure and deterministic."""
    model = structure.model
    packages = model.size
    results: dict[str, dict[str, Any]] = {}
    own: dict[int, float] = {}
    for identifier in model.ids:
        row = structure.rows[identifier]
        summary = vulnerabilities.get(identifier) or {}
        vulnerable = bool(summary.get("distinct"))
        state = reachability_state(reachability.get(identifier), reachability_analysed) if vulnerable else None
        severity = summary.get("max_severity") or "UNKNOWN"
        components: dict[str, Any] = {
            "vulnerability_signal": SEVERITY_SIGNAL.get(severity, SEVERITY_SIGNAL["UNKNOWN"]) if vulnerable else 0,
            "reachability_signal": REACHABILITY_SIGNAL[state] if state else None,
            "centrality_signal": round(0.6 + 0.4 * row["relative_centrality"], 4),
            "downstream_impact": round(0.6 + 0.4 * downstream_impact_value(row["dependents"], packages), 4),
            "confidence": None,
        }
        risk = 0.0
        if vulnerable:
            confidence = 1.0
            if severity == "UNKNOWN":
                confidence -= 0.1                 # the source publishes no severity
            if state != "REACHABLE" and state != "NOT_CONFIRMED_REACHABLE":
                confidence -= 0.15                # reachability was not established either way
            if not structure.betweenness_computed:
                confidence -= 0.1                 # centrality rests on degree only
            components["confidence"] = round(confidence, 2)
            risk = round(components["vulnerability_signal"] * components["reachability_signal"] * components["centrality_signal"]
                         * components["downstream_impact"] * confidence, 1)
            own[model.index[identifier]] = risk
        results[identifier] = {
            "node_id": identifier, "classification": DIRECT_VULNERABILITY if vulnerable else NO_OBSERVED_PROPAGATION,
            "components": components, "own_risk": risk, "propagated_risk": 0.0, "graph_risk": risk,
            "severity": severity if vulnerable else None, "reachability_state": state,
            "vulnerability_count": summary.get("distinct", 0), "exposure_sources": [], "exposure_source_count": 0,
            "exposes": 0, "model_version": MODEL_VERSION,
        }

    # Every vulnerable package's influence on everything that depends on it, strongest first (a Dijkstra search over
    # "depends on" edges, where each step multiplies by DECAY). A package keeps its strongest few sources, so the work
    # and the memory do not grow with the number of vulnerable packages.
    vulnerable_mask = 0
    for position in own:
        vulnerable_mask |= 1 << position
    arrivals: list[list[tuple[float, int, int]]] = [[] for _ in model.ids]          # per package: (influence, source, steps)
    heap = [(-risk, 0, model.ids[position], position, position) for position, risk in own.items()]
    heapq.heapify(heap)
    while heap:
        negative, steps, _source_id, source, node = heapq.heappop(heap)
        kept = arrivals[node]
        if len(kept) > MAX_LISTED or any(entry[1] == source for entry in kept):
            continue
        kept.append((-negative, source, steps))
        for parent in model.parents[node]:
            if len(arrivals[parent]) <= MAX_LISTED:
                heapq.heappush(heap, (negative * DECAY, steps + 1, model.ids[source], source, parent))
    for position, identifier in enumerate(model.ids):
        entry = results[identifier]
        sources = [item for item in arrivals[position] if item[1] != position][:MAX_LISTED]
        entry["exposure_sources"] = [{"node_id": model.ids[source], "distance": steps, "source_risk": own[source],
                                      "influence": round(influence, 1)} for influence, source, steps in sources]
        # Counted from the graph itself, so it is exact however many vulnerable packages there are.
        entry["exposure_source_count"] = (model.descendants[position] & vulnerable_mask).bit_count()
        entry["propagated_risk"] = entry["exposure_sources"][0]["influence"] if sources else 0.0
        entry["graph_risk"] = max(entry["own_risk"], entry["propagated_risk"])
        if position in own:
            entry["exposes"] = model.ancestors[position].bit_count()
        elif entry["exposure_source_count"]:
            entry["classification"] = DEPENDENCY_PROPAGATION if any(child in own for child in model.children[position]) else INDIRECT_EXPOSURE

    # How the project itself reaches each vulnerable package: one shortest chain of dependencies.
    previous: dict[int, int | None] = {}
    queue: deque[int] = deque()
    for position, flag in enumerate(model.direct):
        if flag:
            previous[position] = None
            queue.append(position)
    while queue:
        node = queue.popleft()
        for target in model.children[node]:
            if target not in previous:
                previous[target] = node
                queue.append(target)
    ranked = sorted(own, key=lambda position: (-own[position], model.ids[position]))
    paths = []
    reachable_from_project = direct_paths = 0
    for position in ranked:
        if position not in previous:
            if len(paths) < MAX_PATHS:
                paths.append({"node_id": model.ids[position], "path": None, "length": None, "own_risk": own[position], "path_truncated": False})
            continue
        chain, cursor = [], position
        while cursor is not None:
            chain.append(model.ids[cursor])
            cursor = previous[cursor]
        chain.reverse()
        reachable_from_project += 1
        direct_paths += len(chain) == 1
        if len(paths) < MAX_PATHS:
            shown = chain if len(chain) <= MAX_PATH_NODES else [*chain[:MAX_PATH_NODES // 2], "…", *chain[-(MAX_PATH_NODES // 2):]]
            paths.append({"node_id": model.ids[position], "path": ["root", *shown], "length": len(chain), "own_risk": own[position],
                          "path_truncated": len(chain) > MAX_PATH_NODES})

    counts = {name: 0 for name in CLASSIFICATIONS}
    for entry in results.values():
        counts[entry["classification"]] += 1
    project = {
        # The project is a dependent like any other: it is exposed through what it requires, never "vulnerable" itself.
        "classification": DEPENDENCY_PROPAGATION if direct_paths else INDIRECT_EXPOSURE if reachable_from_project else NO_OBSERVED_PROPAGATION,
        "vulnerable_packages": len(own), "reachable_from_project": reachable_from_project,
        "highest_graph_risk": max((entry["graph_risk"] for entry in results.values()), default=0.0),
    }
    return {"nodes": results, "paths": paths, "paths_truncated": len(own) > len(paths), "by_classification": counts, "project": project,
            "model_version": MODEL_VERSION,
            "parameters": {"severity_signal": SEVERITY_SIGNAL, "reachability_signal": REACHABILITY_SIGNAL, "decay": DECAY}}
