"""The combined attack graph: the union of the stored paths, bounded for display."""

from __future__ import annotations

from typing import Any

from app.analyzers.attack_paths.attack_nodes import STAGES


class AttackGraph:
    """Nodes and edges merged from paths, with hard limits. Adding beyond a limit is refused and recorded."""

    def __init__(self, max_nodes: int, max_edges: int) -> None:
        self.max_nodes, self.max_edges = max_nodes, max_edges
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.truncated = False
        self.paths_included = 0

    def add_path(self, path: dict[str, Any]) -> bool:
        """Add a whole path or nothing: a partly drawn path would misrepresent it."""
        new_nodes = [item for item in path["nodes"] if item["id"] not in self.nodes]
        new_edges = [item for item in path["edges"] if (item["source"], item["target"], item["kind"]) not in self.edges]
        if len(self.nodes) + len(new_nodes) > self.max_nodes or len(self.edges) + len(new_edges) > self.max_edges:
            self.truncated = True
            return False
        for item in path["nodes"]:
            known = self.nodes.get(item["id"])
            if known is None:
                known = self.nodes[item["id"]] = {**{k: v for k, v in item.items() if k != "evidence"}, "paths": 0, "max_score": 0.0}
            known["paths"] += 1
            known["max_score"] = max(known["max_score"], path["score"])
            if item.get("vulnerable"):
                known["vulnerable"] = True
        for item in path["edges"]:
            key = (item["source"], item["target"], item["kind"])
            known_edge = self.edges.get(key)
            if known_edge is None:
                known_edge = self.edges[key] = {**item, "paths": 0, "max_score": 0.0}
            known_edge["paths"] += 1
            known_edge["confidence"] = min(known_edge["confidence"], item["confidence"])
            known_edge["max_score"] = max(known_edge["max_score"], path["score"])
        self.paths_included += 1
        return True

    def to_dict(self) -> dict[str, Any]:
        order = {stage: position for position, stage in enumerate(STAGES)}
        nodes = sorted(self.nodes.values(), key=lambda item: (order[item["stage"]], item["id"]))
        edges = sorted(self.edges.values(), key=lambda item: (item["source"], item["target"], item["kind"]))
        return {"nodes": nodes, "edges": edges, "stages": list(STAGES), "truncated": self.truncated, "paths_included": self.paths_included}


def combine(paths: list[dict[str, Any]], max_nodes: int, max_edges: int | None = None) -> dict[str, Any]:
    """Merge paths into one graph, highest score first, until a limit is reached."""
    graph = AttackGraph(max_nodes, max_edges if max_edges is not None else max_nodes * 4)
    for path in sorted(paths, key=lambda item: (-item["score"], item["attack_path_id"])):
        graph.add_path(path)
    result = graph.to_dict()
    result["paths_total"] = len(paths)
    return result
