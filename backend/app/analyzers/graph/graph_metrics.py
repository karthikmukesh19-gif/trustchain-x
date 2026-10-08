"""Structure of a snapshot's dependency graph.

The graph is the one Phase 2 stored: a project node ("root"), package nodes,
and "depends_on" edges from a dependent to what it requires. Terms used here:

  fan_in            packages that directly depend on this one (the project is reported separately)
  fan_out           packages this one directly requires
  dependents        packages that depend on it directly or through others: what a problem in it can affect
  introduced        packages it brings in directly or through others
  exclusive         introduced packages that are in the project *only* through this one
  reached_by_direct the project's direct dependencies that lead to it

Duplicate edges count once, self-loops are ignored, cycles are handled, and a
package with no path from the project keeps a depth of None.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

ROOT = "root"


class GraphTooLarge(ValueError):
    """The graph exceeds the configured analysis limits."""


@dataclass(frozen=True)
class GraphLimits:
    max_nodes: int = 5000
    max_edges: int = 50_000


@dataclass
class GraphModel:
    """A validated, de-duplicated view of the stored graph, with reachability sets as bit masks."""

    ids: list[str]                                   # package node ids, sorted
    index: dict[str, int]
    children: list[list[int]]
    parents: list[list[int]]
    direct: list[bool]                               # required by the project itself
    depth: list[int | None]
    descendants: list[int]                           # bit masks over `ids`
    ancestors: list[int]
    issues: dict[str, int] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return len(self.ids)

    @property
    def edge_count(self) -> int:
        return sum(len(targets) for targets in self.children)


def build_model(nodes: list[dict[str, Any]], edges: list[dict[str, Any]], limits: GraphLimits = GraphLimits()) -> GraphModel:
    """Validate the stored graph and precompute what the metrics need.

    Malformed input is counted, not trusted: nodes without an id, edges whose
    ends are not nodes, self-loops and repeated edges are left out.
    """
    issues = {"nodes_without_id": 0, "duplicate_nodes": 0, "edges_malformed": 0, "edges_unknown_endpoint": 0,
              "self_loops": 0, "duplicate_edges": 0}
    identifiers: set[str] = set()
    for node in nodes if isinstance(nodes, list) else []:
        identifier = node.get("node_id") if isinstance(node, dict) else None
        if not isinstance(identifier, str) or not identifier or identifier == ROOT:
            issues["nodes_without_id"] += 1
        elif identifier in identifiers:
            issues["duplicate_nodes"] += 1
        else:
            identifiers.add(identifier)
    if len(identifiers) > limits.max_nodes:
        raise GraphTooLarge(f"The dependency graph has {len(identifiers)} packages; the limit is {limits.max_nodes}.")
    if isinstance(edges, list) and len(edges) > limits.max_edges * 4:
        raise GraphTooLarge(f"The dependency graph has more than {limits.max_edges} relationships.")
    ids = sorted(identifiers)
    index = {identifier: position for position, identifier in enumerate(ids)}
    child_sets: list[set[int]] = [set() for _ in ids]
    direct = [False] * len(ids)
    seen: set[tuple[str, str]] = set()
    for edge in edges if isinstance(edges, list) else []:
        source, target = (edge.get("source"), edge.get("target")) if isinstance(edge, dict) else (None, None)
        if not isinstance(source, str) or not isinstance(target, str):
            issues["edges_malformed"] += 1
            continue
        if (source != ROOT and source not in index) or target not in index:
            issues["edges_unknown_endpoint"] += 1
            continue
        if source == target:
            issues["self_loops"] += 1
            continue
        if (source, target) in seen:
            issues["duplicate_edges"] += 1
            continue
        seen.add((source, target))
        if source == ROOT:
            direct[index[target]] = True
        else:
            child_sets[index[source]].add(index[target])
    if len(seen) > limits.max_edges:
        raise GraphTooLarge(f"The dependency graph has {len(seen)} relationships; the limit is {limits.max_edges}.")
    children = [sorted(items) for items in child_sets]
    parents: list[list[int]] = [[] for _ in ids]
    for source, targets in enumerate(children):
        for target in targets:
            parents[target].append(source)

    depth: list[int | None] = [None] * len(ids)
    frontier = [position for position, flag in enumerate(direct) if flag]
    for position in frontier:
        depth[position] = 1
    level = 1
    while frontier:
        level += 1
        following = []
        for node in frontier:
            for target in children[node]:
                if depth[target] is None:
                    depth[target] = level
                    following.append(target)
        frontier = following

    descendants = _closure(children)
    ancestors = _closure(parents)
    return GraphModel(ids, index, children, parents, direct, depth, descendants, ancestors, {k: v for k, v in issues.items() if v})


def _closure(adjacency: list[list[int]]) -> list[int]:
    """For every node, the set of nodes reachable from it (itself excluded), as a bit mask.

    Strongly connected components are collapsed first (iteratively, so depth is
    not limited by the interpreter's recursion), then the sets are combined in
    reverse topological order. Members of a cycle reach each other.
    """
    count = len(adjacency)
    order: list[int] = [-1] * count
    low = [0] * count
    on_stack = [False] * count
    component = [-1] * count
    stack: list[int] = []
    components: list[list[int]] = []
    counter = 0
    for start in range(count):
        if order[start] != -1:
            continue
        work = [(start, 0)]
        while work:
            node, position = work[-1]
            if position == 0:
                order[node] = low[node] = counter
                counter += 1
                stack.append(node)
                on_stack[node] = True
            advanced = False
            neighbours = adjacency[node]
            while position < len(neighbours):
                target = neighbours[position]
                position += 1
                if order[target] == -1:
                    work[-1] = (node, position)
                    work.append((target, 0))
                    advanced = True
                    break
                if on_stack[target]:
                    low[node] = min(low[node], order[target])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == order[node]:
                members = []
                while True:
                    member = stack.pop()
                    on_stack[member] = False
                    component[member] = len(components)
                    members.append(member)
                    if member == node:
                        break
                components.append(members)
    # Tarjan emits components in reverse topological order: everything a component reaches is already done.
    reach: list[int] = [0] * len(components)
    own: list[int] = [0] * len(components)         # the members of each component, as one mask
    for identifier, members in enumerate(components):
        for member in members:
            own[identifier] |= 1 << member
        mask = 0
        merged: set[int] = set()
        for member in members:
            for target in adjacency[member]:
                other = component[target]
                if other != identifier and other not in merged:
                    merged.add(other)
                    mask |= reach[other] | own[other]
        if len(members) > 1:
            mask |= own[identifier]
        reach[identifier] = mask
    result = []
    for node in range(count):
        mask = reach[component[node]]
        result.append(mask & ~(1 << node))
    return result


def _exclusive(model: GraphModel) -> list[int]:
    """For each package, how many others are in the project only through it (its dominated set).

    Uses the iterative dominator algorithm of Cooper, Harvey and Kennedy on the
    part of the graph reachable from the project.
    """
    count = model.size
    root = count                                   # a virtual node for the project
    successors = [*model.children, [position for position, flag in enumerate(model.direct) if flag]]
    predecessors: list[list[int]] = [[] for _ in range(count + 1)]
    for source, targets in enumerate(successors):
        for target in targets:
            predecessors[target].append(source)
    postorder: list[int] = []
    visited = [False] * (count + 1)
    work = [(root, 0)]
    visited[root] = True
    while work:
        node, position = work[-1]
        if position < len(successors[node]):
            work[-1] = (node, position + 1)
            target = successors[node][position]
            if not visited[target]:
                visited[target] = True
                work.append((target, 0))
        else:
            work.pop()
            postorder.append(node)
    number = {node: position for position, node in enumerate(postorder)}
    idom: dict[int, int] = {root: root}
    changed = True
    while changed:
        changed = False
        for node in reversed(postorder[:-1]):
            candidates = [p for p in predecessors[node] if p in idom]
            new = candidates[0]
            for other in candidates[1:]:
                a, b = other, new
                while a != b:
                    while number[a] < number[b]:
                        a = idom[a]
                    while number[b] < number[a]:
                        b = idom[b]
                new = a
            if idom.get(node) != new:
                idom[node] = new
                changed = True
    dominated = [0] * (count + 1)
    for node in postorder:                         # children before parents in the dominator tree
        if node != root:
            dominated[idom[node]] += dominated[node] + 1
    return dominated[:count]


def node_metrics(model: GraphModel) -> list[dict[str, Any]]:
    """Structural measurements for every package, in the order of model.ids."""
    exclusive = _exclusive(model)
    direct_mask = 0
    for position, flag in enumerate(model.direct):
        if flag:
            direct_mask |= 1 << position
    direct_total = direct_mask.bit_count()
    others = max(model.size - 1, 1)
    rows = []
    for position, identifier in enumerate(model.ids):
        dependents = model.ancestors[position].bit_count()
        introduced = model.descendants[position].bit_count()
        reached_by = ((model.ancestors[position] | (1 << position)) & direct_mask).bit_count()
        rows.append({
            "node_id": identifier, "direct": model.direct[position], "depth": model.depth[position],
            "fan_in": len(model.parents[position]), "fan_out": len(model.children[position]),
            "dependents": dependents, "dependents_share": round(dependents / others, 4) if model.size > 1 else 0.0,
            "introduced": introduced, "exclusive": exclusive[position],
            "reached_by_direct": reached_by,
            "reached_by_direct_share": round(reached_by / direct_total, 4) if direct_total else None,
            "in_cycle": bool(model.descendants[position] & model.ancestors[position]),
            "connected_to_project": model.depth[position] is not None,
        })
    return rows


def concentration(model: GraphModel, metrics: list[dict[str, Any]]) -> dict[str, Any]:
    """How much of the project's dependency structure rests on few packages.

    hhi                  Herfindahl index of the fan-in distribution (1/n: evenly spread; 1: everything depends on one package)
    top_dependents       the packages most others depend on, with the share of packages that do
    largest_subtrees     the direct dependencies that bring in the most packages, with the share of all packages
    """
    total_in = sum(row["fan_in"] for row in metrics)
    hhi = round(sum((row["fan_in"] / total_in) ** 2 for row in metrics), 4) if total_in else None
    by_dependents = sorted(metrics, key=lambda row: (-row["dependents"], row["node_id"]))
    subtrees = sorted((row for row in metrics if row["direct"]), key=lambda row: (-row["introduced"], row["node_id"]))
    size = model.size
    covered = 0
    for row in subtrees[:3]:
        covered |= model.descendants[model.index[row["node_id"]]] | (1 << model.index[row["node_id"]])
    return {
        "packages": size, "relationships": model.edge_count, "direct_dependencies": sum(1 for row in metrics if row["direct"]),
        "unconnected_packages": sum(1 for row in metrics if not row["connected_to_project"]),
        "max_depth": max((row["depth"] for row in metrics if row["depth"] is not None), default=None),
        "packages_in_cycles": sum(1 for row in metrics if row["in_cycle"]),
        "fan_in_hhi": hhi, "effective_packages": round(1 / hhi, 1) if hhi else None,
        "top_dependents": [{"node_id": row["node_id"], "dependents": row["dependents"], "share": row["dependents_share"]}
                           for row in by_dependents[:5] if row["dependents"] > 0],
        "largest_subtrees": [{"node_id": row["node_id"], "introduced": row["introduced"],
                              "share": round((row["introduced"] + 1) / size, 4) if size else 0.0}
                             for row in subtrees[:5] if row["introduced"] > 0],
        "top3_subtree_share": round(covered.bit_count() / size, 4) if size and subtrees else None,
    }


@dataclass
class Structure:
    """Everything derived from the graph alone, computed once and shared by the analyzers."""

    model: GraphModel
    rows: dict[str, dict[str, Any]]                # node id -> structural metrics, including centrality
    concentration: dict[str, Any]
    betweenness_computed: bool
    max_betweenness: float
    max_degree: float


def analyse_structure(nodes: list[dict[str, Any]], edges: list[dict[str, Any]], limits: GraphLimits = GraphLimits()) -> Structure:
    from app.analyzers.graph import centrality

    model = build_model(nodes, edges, limits)
    metrics = node_metrics(model)
    degree = centrality.degree(model)
    between = centrality.betweenness(model)
    max_between = max(between, default=0.0) if between is not None else 0.0
    max_degree = max(degree, default=0.0)
    for position, row in enumerate(metrics):
        row["degree_centrality"] = degree[position]
        row["betweenness_centrality"] = between[position] if between is not None else None
        # Centrality relative to the most central package of this graph (0-1); betweenness when it was computed.
        if between is not None and max_between > 0:
            row["relative_centrality"], row["centrality_measure"] = round(between[position] / max_between, 4), "betweenness"
        elif max_degree > 0:
            row["relative_centrality"], row["centrality_measure"] = round(degree[position] / max_degree, 4), "degree"
        else:
            row["relative_centrality"], row["centrality_measure"] = 0.0, "degree"
    return Structure(model, {row["node_id"]: row for row in metrics}, concentration(model, metrics), between is not None, max_between, max_degree)
