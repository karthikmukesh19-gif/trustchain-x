"""Dependency graph: depth, parents, path counts and bounded path search."""

from __future__ import annotations

from collections import Counter
from typing import Any

from app.analyzers.model import DIRECT, TRANSITIVE, UNKNOWN
from app.analyzers.resolve import ROOT, Resolution, to_record

MAX_PARENTS = 25


def build_graph(resolution: Resolution, root_label: str) -> dict[str, Any]:
    """Return {"root", "nodes", "edges", "stats"} ready to store.

    depth                 length of the shortest path from the project (1 = direct);
                          None when no path is established by the evidence
    shortest_path_count   how many distinct shortest paths lead to the package
    parents               packages (or the project) that require it
    """
    edges = list(resolution.edges.values())
    children: dict[str, list[str]] = {}
    parents: dict[str, list[str]] = {}
    for edge in edges:
        children.setdefault(edge["source"], []).append(edge["target"])
        parents.setdefault(edge["target"], []).append(edge["source"])

    depth: dict[str, int] = {ROOT: 0}
    paths: dict[str, int] = {ROOT: 1}
    frontier = [ROOT]
    while frontier:
        following: list[str] = []
        for node in frontier:
            for target in children.get(node, []):
                if target not in depth:
                    depth[target] = depth[node] + 1
                    paths[target] = 0
                    following.append(target)
                if depth[target] == depth[node] + 1:
                    paths[target] += paths[node]
        frontier = following

    nodes = []
    for package in resolution.packages.values():
        record = to_record(package)
        record["depth"] = depth.get(package.node_id)
        record["shortest_path_count"] = paths.get(package.node_id, 0)
        all_parents = sorted(parents.get(package.node_id, []))
        record["parents"] = all_parents[:MAX_PARENTS]
        record["parent_count"] = len(all_parents)
        record["dependents_count"] = len([p for p in all_parents if p != ROOT])
        record["dependency_count"] = len(children.get(package.node_id, []))
        nodes.append(record)
    nodes.sort(key=lambda n: (n["depth"] if n["depth"] is not None else 10**6, n["ecosystem"], n["normalized_name"], n["version"] or ""))

    reachable = [n["depth"] for n in nodes if n["depth"] is not None]
    stats = {
        "total": len(nodes),
        "direct": sum(1 for n in nodes if n["relationship"] == DIRECT),
        "transitive": sum(1 for n in nodes if n["relationship"] == TRANSITIVE),
        "relationship_unknown": sum(1 for n in nodes if n["relationship"] == UNKNOWN),
        "unresolved_versions": sum(1 for n in nodes if n["version_status"] == "UNRESOLVED"),
        "edges": len(edges),
        "max_depth": max(reachable, default=0),
        "without_path": sum(1 for n in nodes if n["depth"] is None),
        "unresolved_edges": resolution.unresolved_edges,
        "by_ecosystem": dict(Counter(n["ecosystem"] for n in nodes)),
        "by_package_manager": dict(Counter(pm for n in nodes for pm in n["package_managers"])),
        "by_depth": {str(k): v for k, v in sorted(Counter(reachable).items())},
        "by_relationship_basis": dict(Counter(n["relationship_basis"] for n in nodes)),
        "by_scope": dict(Counter(scope for n in nodes for scope in n["scopes"])),
    }
    return {"root": {"id": ROOT, "type": "application", "label": root_label}, "nodes": nodes, "edges": edges, "stats": stats}


def find_paths(edges: list[dict[str, Any]], target: str, limit: int = 20, max_length: int = 12) -> list[list[str]]:
    """Up to `limit` simple paths from the project to `target`, shortest first (bounded search)."""
    parents: dict[str, list[str]] = {}
    for edge in edges:
        parents.setdefault(edge["target"], []).append(edge["source"])
    found: list[list[str]] = []
    budget = [20_000]

    def walk(node: str, trail: list[str]) -> None:
        if len(found) >= limit or budget[0] <= 0:
            return
        budget[0] -= 1
        if node == ROOT:
            found.append([ROOT] + trail)
            return
        if len(trail) >= max_length:
            return
        for parent in sorted(parents.get(node, [])):
            if parent not in trail and parent != node:
                walk(parent, [node] + trail)

    walk(target, [])
    found.sort(key=len)
    return found
