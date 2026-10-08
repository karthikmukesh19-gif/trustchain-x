"""Decide, for one vulnerable dependency, what the code graph establishes.

Statuses
  REACHABLE                 a path of statically bound edges leads from application code to a name the
                            advisory (or an operator mapping) identifies as affected
  NOT_CONFIRMED_REACHABLE   the affected names are known, the analysed source is complete, and no such path exists
  UNKNOWN                   it cannot be decided: no affected name is published; a use only resembles an
                            affected name; the package's import name is unknown or shared with something
                            else; the dependency is only pulled in by other packages (whose source is not
                            analysed); part of the source was not analysed; or dynamic code could reach it
  UNSUPPORTED               the dependency's ecosystem has no source analyzer

UNKNOWN is never reported as anything else. REACHABLE describes source text, not exploitability.

Confidence (evidence quality, not likelihood)
  for REACHABLE: the weakest edge on the path, limited by where the mapping came from
  (OPERATOR_SUPPLIED -> at most MEDIUM). Only an exact match of the affected name counts as reaching it.
  for NOT_CONFIRMED_REACHABLE: HIGH when the package is never imported; MEDIUM when it is imported and
  every use of it was bound directly; LOW when some uses go through call results or unresolved receivers
  for UNKNOWN and UNSUPPORTED: none
"""

from __future__ import annotations

from collections import deque
from typing import Any

from app.analyzers.reachability import symbols as symbol_mapping
from app.analyzers.reachability.callgraph import CALLS, CONFIDENCE_RANK, HIGH, IMPORTS, LOW, MEDIUM, REFERENCES, CodeGraph, weakest
from app.analyzers.reachability.symbols import AffectedSymbol
from app.analyzers.source import base

REACHABLE = "REACHABLE"
NOT_CONFIRMED_REACHABLE = "NOT_CONFIRMED_REACHABLE"
UNKNOWN = "UNKNOWN"
UNSUPPORTED = "UNSUPPORTED"
STATUSES = (REACHABLE, NOT_CONFIRMED_REACHABLE, UNKNOWN, UNSUPPORTED)

# Reasons
PATH_FOUND = "PATH_FOUND"
NO_PATH_FOUND = "NO_PATH_FOUND"
SYMBOL_MAPPING_UNKNOWN = symbol_mapping.SYMBOL_MAPPING_UNKNOWN
DEPENDENCY_SOURCE_NOT_ANALYSED = "DEPENDENCY_SOURCE_NOT_ANALYSED"
INCOMPLETE_SOURCE = "INCOMPLETE_SOURCE"
DYNAMIC_CODE = "DYNAMIC_CODE"
AMBIGUOUS_DEPENDENCY = "AMBIGUOUS_DEPENDENCY"            # the import name could belong to this or another package, or to a local module
IMPORT_MAPPING_UNKNOWN = "IMPORT_MAPPING_UNKNOWN"        # the package's import name is not known, and unexplained imports exist
SYMBOL_MATCH_UNCERTAIN = "SYMBOL_MATCH_UNCERTAIN"        # a use resembles an affected name but is not provably the same thing
LANGUAGE_NOT_SUPPORTED = "LANGUAGE_NOT_SUPPORTED"

USAGE_CALLED, USAGE_REFERENCED, USAGE_IMPORTED, USAGE_NOT_OBSERVED = "CALLED", "REFERENCED", "IMPORTED_ONLY", "NOT_OBSERVED"
MAX_SITES = 20
MAX_PATH = 64


class ReachabilityIndex:
    """A code graph prepared for path queries."""

    def __init__(self, graph: CodeGraph) -> None:
        self.graph = graph
        self.nodes = graph.nodes
        self.incoming: dict[str, list[dict[str, Any]]] = {}
        callers: dict[str, set[str]] = {}
        for edge in graph.edges:
            self.incoming.setdefault(edge["target"], []).append(edge)
            if edge["kind"] in (CALLS, REFERENCES) and edge["source"] != edge["target"]:
                callers.setdefault(edge["target"], set()).add(edge["source"])
        # Where a path may start: module code (it runs when the module is imported or executed) and any function or
        # method nothing else in the analysed source calls or references - a possible entry point (a request
        # handler, a command, a public function). Which of them really are entry points is not known statically.
        self.entries = {identity for identity, node in self.nodes.items()
                        if node["kind"] == "module" or (node["kind"] in ("function", "method") and not callers.get(identity))}
        self.by_dependency: dict[str, list[str]] = {}
        for identity, node in self.nodes.items():
            if node["kind"] == "external":
                for dependency in node.get("dependency_node_ids", []):
                    self.by_dependency.setdefault(dependency, []).append(identity)
        self.dynamic = [item for item in graph.unresolved if item["reason"] in base.DYNAMIC_REASONS]
        mapping = (graph.stats or {}).get("mapping") or {}
        self.unmapped_imports: list[str] = list(mapping.get("unmapped_imports") or [])
        self.ambiguous_dependencies = set(mapping.get("ambiguous_dependency_node_ids") or [])
        self.shadowed_dependencies = set(mapping.get("shadowed_dependency_node_ids") or [])
        self.unbound_files = {item["evidence"].get("source_file") for item in graph.unresolved
                              if item["reason"] in (base.UNKNOWN_RECEIVER, base.CALL_RESULT, base.SELF_ATTRIBUTE, base.DYNAMIC_GETATTR)}

    def path_to(self, targets: set[str], minimum: str) -> dict[str, Any] | None:
        """The shortest path from an entry to any target using edges of at least `minimum` confidence.

        Searched breadth-first backwards from the targets. An entry in application code is
        preferred over one in test code. Returns None when no edge reaches a target.
        """
        floor = CONFIDENCE_RANK[minimum]
        parent: dict[str, tuple[str, dict[str, Any]] | None] = {target: None for target in sorted(targets)}
        queue = deque(sorted(targets))
        best: str | None = None
        fallback: str | None = None
        last: str | None = None
        while queue:
            current = queue.popleft()
            if current not in targets:
                last = current
                if current in self.entries:
                    if not self.nodes[current].get("is_test"):
                        best = current
                        break
                    fallback = fallback or current
            for edge in self.incoming.get(current, []):
                source = edge["source"]
                if CONFIDENCE_RANK[edge["confidence"]] < floor or source in parent or source not in self.nodes:
                    continue
                parent[source] = (current, edge)
                queue.append(source)
        start = best or fallback or last
        if start is None:
            return None
        nodes, edges = [start], []
        current = start
        while parent[current] is not None:
            following, edge = parent[current]  # type: ignore[misc]
            edges.append(edge)
            nodes.append(following)
            current = following
        return {"nodes": nodes, "edges": edges, "start_is_entry": start in self.entries,
                "through_tests_only": bool(self.nodes[start].get("is_test")),
                "confidence": weakest(*(edge["confidence"] for edge in edges)) if edges else HIGH}

    def best_path(self, targets: set[str]) -> dict[str, Any] | None:
        """Prefer a path made only of HIGH edges, then HIGH and MEDIUM, then any."""
        from_tests: dict[str, Any] | None = None
        for minimum in (HIGH, MEDIUM, LOW):
            path = self.path_to(targets, minimum)
            if path is None:
                continue
            if not path["through_tests_only"]:
                return path
            from_tests = from_tests or path          # keep looking for one that starts in application code
        return from_tests

    def describe_path(self, path: dict[str, Any]) -> dict[str, Any]:
        """A path in stored form: node summaries and, per step, the evidence of the edge taken."""
        truncated = len(path["edges"]) > MAX_PATH
        if truncated:                                # keep the part nearest the affected name
            path = {**path, "edges": path["edges"][-MAX_PATH:], "nodes": path["nodes"][-(MAX_PATH + 1):]}
        steps = []
        for edge in path["edges"]:
            steps.append({"kind": edge["kind"], "source": edge["source"], "target": edge["target"], "confidence": edge["confidence"],
                          "basis": edge["basis"], "via": edge.get("via"), "hops": edge.get("hops"), "evidence": edge.get("evidence")})
        summaries = []
        for identity in path["nodes"]:
            node = self.nodes[identity]
            summaries.append({"id": identity, "kind": node["kind"], "label": node.get("qualified") or identity,
                              "path": node.get("path"), "line": node.get("line"), "is_test": bool(node.get("is_test"))})
        return {"nodes": summaries, "edges": steps, "length": len(steps), "truncated": truncated,
                "start_is_entry": path["start_is_entry"] and not truncated,
                "through_tests_only": path["through_tests_only"], "confidence": path["confidence"]}

    def usage(self, dependency_node_id: str) -> dict[str, Any]:
        """What the analysed source shows about one dependency, regardless of any vulnerability."""
        externals = sorted(self.by_dependency.get(dependency_node_id, []))
        imports, uses = [], []
        indirect = False
        for identity in externals:
            for edge in self.incoming.get(identity, []):
                site = {"symbol": edge["source"], "used": self.nodes[identity]["qualified"], "kind": edge["kind"],
                        "confidence": edge["confidence"], "basis": edge["basis"], **(edge.get("evidence") or {}),
                        "is_test": bool(self.nodes.get(edge["source"], {}).get("is_test"))}
                if edge["kind"] == IMPORTS:
                    imports.append(site)
                else:
                    uses.append(site)
                    indirect = indirect or edge.get("via") == "instance"
        order = lambda site: (site["is_test"], site.get("source_file") or "", site.get("line") or 0, site["used"])  # noqa: E731
        imports.sort(key=order)
        uses.sort(key=order)
        called = any(site["kind"] == CALLS for site in uses)
        level = USAGE_CALLED if called else USAGE_REFERENCED if uses else USAGE_IMPORTED if imports else USAGE_NOT_OBSERVED
        return {"level": level, "imported": bool(imports), "import_sites": imports[:MAX_SITES], "import_site_count": len(imports),
                "use_sites": uses[:MAX_SITES], "use_site_count": len(uses), "used_names": sorted({s["used"] for s in uses})[:100],
                "externals": externals, "indirect_uses": indirect}


def evaluate(index: ReachabilityIndex | None, *, ecosystem: str, supported_ecosystems: set[str], dependency_node_id: str,
             relationship: str | None, affected: list[AffectedSymbol], source_complete: bool,
             incomplete_note: str | None = None) -> dict[str, Any]:
    """The reachability result for one (dependency, advisory) pair. Pure: reads the graph, stores nothing."""
    result: dict[str, Any] = {"status": UNKNOWN, "confidence": None, "reason": None, "explanation": "", "path": None,
                              "matched_symbol": None, "usage": None, "usage_path": None,
                              "affected_symbols": [s.as_dict() for s in affected],
                              "symbol_mapping": affected[0].source if affected else SYMBOL_MAPPING_UNKNOWN}
    if ecosystem not in supported_ecosystems or index is None:
        result.update(status=UNSUPPORTED, reason=LANGUAGE_NOT_SUPPORTED,
                      explanation=f"Source analysis is not implemented for the {ecosystem} ecosystem, so nothing is concluded.")
        return result

    usage = index.usage(dependency_node_id)
    externals = set(usage.pop("externals"))
    indirect = usage.pop("indirect_uses")
    result["usage"] = usage

    if not affected:
        result.update(reason=SYMBOL_MAPPING_UNKNOWN, explanation=(
            "The advisory does not publish which functions or classes are affected, and no operator mapping exists, so "
            "reachability of the affected functionality cannot be decided. What the source shows about the package as a "
            "whole is listed as dependency usage."))
        used = {identity for identity in externals if any(e["kind"] != IMPORTS for e in index.incoming.get(identity, []))}
        if used:
            path = index.best_path(used)
            if path is not None:
                result["usage_path"] = index.describe_path(path)
        return result

    matches: dict[str, tuple[str, AffectedSymbol]] = {}
    for identity in sorted(externals):
        if not any(edge["kind"] != IMPORTS for edge in index.incoming.get(identity, [])):
            continue                                  # importing a module is not using a function in it
        for symbol in affected:
            quality = symbol_mapping.match(symbol, index.nodes[identity]["qualified"])
            if quality and (identity not in matches or (quality == symbol_mapping.EXACT and matches[identity][0] != symbol_mapping.EXACT)):
                matches[identity] = (quality, symbol)
    exact = {identity for identity, (found, _symbol) in matches.items() if found == symbol_mapping.EXACT}
    path = index.best_path(exact) if exact else None
    if path is not None:
        end = path["nodes"][-1]
        symbol = matches[end][1]
        confidence = weakest(path["confidence"], MEDIUM if symbol.source == symbol_mapping.OPERATOR_SUPPLIED else HIGH)
        result.update(
            status=REACHABLE, reason=PATH_FOUND, confidence=confidence, path=index.describe_path(path),
            matched_symbol={**symbol.as_dict(), "observed": index.nodes[end]["qualified"], "match": symbol_mapping.EXACT},
            explanation=("Application code statically refers to a name identified as affected. This is evidence that the "
                         "affected functionality is used; it does not show that the vulnerability can be exploited."
                         + (" The only path found starts in test code." if path["through_tests_only"] else "")))
        return result

    # A use with the same trailing name but a different module path may be the affected function re-exported
    # (requests.get is requests.api.get) or a different function altogether (torch.load is not torch.jit.load).
    similar = {identity for identity, (found, _symbol) in matches.items() if found == symbol_mapping.NAME}
    path = index.best_path(similar) if similar else None
    if path is not None:
        end = path["nodes"][-1]
        symbol = matches[end][1]
        result.update(
            reason=SYMBOL_MATCH_UNCERTAIN, usage_path=index.describe_path(path),
            matched_symbol={**symbol.as_dict(), "observed": index.nodes[end]["qualified"], "match": symbol_mapping.NAME},
            explanation=(f"The source uses {index.nodes[end]['qualified']}, which has the same name as the affected "
                         f"{symbol.symbol} but a different module path. It may be the same function re-exported or a different "
                         "one; that cannot be told without the package's source, so nothing is concluded."))
        return result

    tops = {index.nodes[identity]["top_level"] for identity in externals}
    if tops and not any(symbol.symbol.split(".", 1)[0] in tops for symbol in affected):
        result.update(reason=SYMBOL_MATCH_UNCERTAIN, explanation=(
            "The affected names are not written in terms of the name this package is imported by "
            f"({', '.join(sorted(tops))}), so they cannot be compared with what the source uses."))
        return result
    if dependency_node_id in index.shadowed_dependencies or dependency_node_id in index.ambiguous_dependencies:
        result.update(reason=AMBIGUOUS_DEPENDENCY, explanation=(
            "The name this package is imported by also belongs to a local module or to another package in the inventory, "
            "so the source's use of that name cannot be attributed, and its absence cannot be concluded."))
        return result
    if not usage["imported"] and relationship == "DIRECT" and index.unmapped_imports:
        result.update(reason=IMPORT_MAPPING_UNKNOWN, unmapped_imports=index.unmapped_imports[:20], explanation=(
            "No import in the source was mapped to this package, but the source imports names that could not be mapped to any "
            f"dependency ({', '.join(index.unmapped_imports[:8])}{', …' if len(index.unmapped_imports) > 8 else ''}). "
            "A package can be imported under a different name, so its absence cannot be concluded."))
        return result

    if not usage["imported"] and relationship != "DIRECT":
        result.update(reason=DEPENDENCY_SOURCE_NOT_ANALYSED, explanation=(
            "The application does not import this package itself; it is installed because another package needs it. "
            "Whether those packages reach the affected functionality is not known, because dependency source code is not analysed."))
        return result
    if not source_complete:
        result.update(reason=INCOMPLETE_SOURCE, explanation=(
            "No path to the affected functionality was found, but part of the source was not analysed"
            + (f" ({incomplete_note})" if incomplete_note else "") + ", so its absence cannot be concluded."))
        return result
    dynamic = _relevant_dynamic(index, externals, dependency_node_id)
    if dynamic:
        result.update(reason=DYNAMIC_CODE, explanation=(
            "No path to the affected functionality was found, but the source uses constructs whose targets are decided at "
            f"run time ({', '.join(sorted({d['reason'] for d in dynamic}))}), which could reach it."),
            dynamic_sites=[{"reason": d["reason"], "expr": d["expr"], **d["evidence"]} for d in dynamic[:MAX_SITES]])
        return result
    confidence = HIGH if not usage["imported"] else LOW if indirect or _unbound_receivers(index, usage) else MEDIUM
    result.update(status=NOT_CONFIRMED_REACHABLE, reason=NO_PATH_FOUND, confidence=confidence, explanation=(
        "The package is present, but the analysed source does not establish a path to the functionality identified as "
        "affected. This is not a statement that the application is safe."))
    return result


def _relevant_dynamic(index: ReachabilityIndex, externals: set[str], dependency_node_id: str) -> list[dict[str, Any]]:
    """Dynamic constructs that could reach this package without a statically bound edge:
    eval/exec, an import whose module name is computed, getattr with a computed name on something
    that belongs to the package, and a star import of the package."""
    packages = {index.nodes[identity].get("package") for identity in externals} - {None}
    relevant = []
    for item in index.dynamic:
        if item["reason"] in (base.DYNAMIC_EVAL, base.DYNAMIC_IMPORT):
            relevant.append(item)
        elif item["reason"] == base.DYNAMIC_GETATTR and item.get("subject_package") in packages:
            relevant.append(item)
    for identity in sorted(externals):
        for edge in index.incoming.get(identity, []):
            if edge["kind"] == IMPORTS and edge.get("star"):
                relevant.append({"reason": base.STAR_IMPORT, "expr": (edge.get("evidence") or {}).get("text") or "",
                                 "evidence": edge.get("evidence") or {}})
    return relevant


def _unbound_receivers(index: ReachabilityIndex, usage: dict[str, Any]) -> bool:
    """Whether a file that imports or uses the package also makes calls on objects whose type is not known."""
    return any(site.get("source_file") in index.unbound_files for site in (*usage["import_sites"], *usage["use_sites"]))
