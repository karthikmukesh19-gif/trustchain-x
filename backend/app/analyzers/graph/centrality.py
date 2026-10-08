"""Centrality of packages in the dependency graph.

degree        (fan_in + fan_out) / (n - 1)
betweenness   Brandes' algorithm on the directed, unweighted graph, normalised by (n - 1)(n - 2):
              the share of shortest dependency chains between other packages that pass through this one

Betweenness costs O(nodes × edges). Above the work limit it is not computed
and is reported as None, never approximated silently.
"""

from __future__ import annotations

from collections import deque

from app.analyzers.graph.graph_metrics import GraphModel

MAX_BETWEENNESS_WORK = 20_000_000        # nodes × (nodes + edges)


def degree(model: GraphModel) -> list[float]:
    others = model.size - 1
    if others <= 0:
        return [0.0] * model.size
    return [round((len(model.parents[i]) + len(model.children[i])) / others, 6) for i in range(model.size)]


def betweenness(model: GraphModel, max_work: int = MAX_BETWEENNESS_WORK) -> list[float] | None:
    count = model.size
    if count * (count + model.edge_count) > max_work:
        return None
    scores = [0.0] * count
    for source in range(count):
        order: list[int] = []
        predecessors: list[list[int]] = [[] for _ in range(count)]
        paths = [0] * count
        distance = [-1] * count
        paths[source], distance[source] = 1, 0
        queue = deque([source])
        while queue:
            node = queue.popleft()
            order.append(node)
            for target in model.children[node]:
                if distance[target] < 0:
                    distance[target] = distance[node] + 1
                    queue.append(target)
                if distance[target] == distance[node] + 1:
                    paths[target] += paths[node]
                    predecessors[target].append(node)
        dependency = [0.0] * count
        for node in reversed(order):
            for previous in predecessors[node]:
                dependency[previous] += paths[previous] / paths[node] * (1 + dependency[node])
            if node != source:
                scores[node] += dependency[node]
    scale = (count - 1) * (count - 2)
    return [round(score / scale, 6) if scale > 0 else 0.0 for score in scores]
