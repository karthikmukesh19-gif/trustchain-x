"""Run evaluation measures from the command line.

    python -m app.evaluation.run --benchmark labels.json     precision/recall/... from a labelled file
    python -m app.evaluation.run --scalability               time the graph algorithms on generated graphs of growing size

A benchmark file is JSON: {"benchmark": "name", "component": "vulnerability_matching",
"cases": [{"predicted": true, "actual": false}, ...]}. The labels must come from
a source independent of the platform; the tool only does the arithmetic.

The scalability mode generates synthetic dependency graphs. Their only use is
to measure processing time: they say nothing about accuracy, and the timings
describe the machine they were taken on.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from typing import Any

from app.analyzers.attack_paths import Inputs, Limits, simulate
from app.analyzers.graph.graph_metrics import analyse_structure
from app.evaluation import metrics


def from_benchmark(document: dict[str, Any]) -> dict[str, Any]:
    cases = document.get("cases")
    if not isinstance(cases, list) or not cases or not isinstance(document.get("benchmark"), str) or not document["benchmark"].strip():
        raise ValueError("a benchmark needs a name and a non-empty list of cases")
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("predicted"), bool) or not isinstance(case.get("actual"), bool):
            raise ValueError("every case needs boolean 'predicted' and 'actual'")
    measured = metrics.classification([case["predicted"] for case in cases], [case["actual"] for case in cases])
    return {"benchmark": document["benchmark"], "component": document.get("component"), **measured}


def synthetic_graph(packages: int, seed: int = 7) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """A layered random dependency graph: generated input for timing only."""
    generator = random.Random(seed)
    ids = [f"npm:p{index}@1.0.0" for index in range(packages)]
    edges = [{"source": "root", "target": ids[index]} for index in range(min(packages, max(1, packages // 20)))]
    for index in range(1, packages):
        for _ in range(generator.randint(1, 3)):
            edges.append({"source": ids[generator.randrange(0, index)], "target": ids[index]})
    return [{"node_id": identifier} for identifier in ids], edges


def scalability(sizes: list[int]) -> list[dict[str, Any]]:
    def run(size: int) -> int:
        nodes, edges = synthetic_graph(size)
        structure = analyse_structure(nodes, edges)
        vulnerable = [node["node_id"] for node in nodes[::max(1, size // 50)]]
        dependencies = {node["node_id"]: {"node_id": node["node_id"], "name": node["node_id"], "relationship_basis": "OBSERVED"} for node in nodes}
        advisories = {node_id: [{"group_key": "SYNTHETIC", "source_id": "SYNTHETIC", "severity": "HIGH", "severity_rank": 3, "confidence": "HIGH",
                                 "match_ids": []}] for node_id in vulnerable}
        return len(simulate(Inputs("timing", "timing", structure, dependencies, advisories), Limits())["paths"])

    return metrics.scalability(run, sizes)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="TrustChain-X evaluation measures")
    parser.add_argument("--benchmark", help="path to a labelled benchmark file (JSON)")
    parser.add_argument("--scalability", action="store_true", help="time graph analysis and attack-path search on generated graphs")
    parser.add_argument("--sizes", default="100,500,1000,2000", help="graph sizes for --scalability")
    arguments = parser.parse_args(argv)
    if not arguments.benchmark and not arguments.scalability:
        parser.error("nothing to do: give --benchmark FILE or --scalability")
    output: dict[str, Any] = {}
    if arguments.benchmark:
        with open(arguments.benchmark, encoding="utf-8") as handle:
            output["benchmark"] = from_benchmark(json.load(handle))
    if arguments.scalability:
        output["scalability"] = {"note": "Synthetic graphs, used for timing only. Timings describe this machine.",
                                 "points": scalability([int(part) for part in arguments.sizes.split(",") if part.strip()])}
    json.dump(output, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
