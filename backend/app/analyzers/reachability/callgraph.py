"""Build a conservative code graph from the per-file analysis results.

Nodes   application modules, classes, functions and methods; and "external"
        nodes for the names of a dependency that application code refers to
        (for example requests.get). Dependency source code is not analysed, so
        an external node has no outgoing edges.
Edges   imports     a scope imports a local module or a dependency
        calls       a call whose callee was bound statically
        references  a name used without being called (passed as a callback, assigned)
        constructs  a class to its own __init__

Every edge carries the source location and text it was read from, and a
confidence that describes how the callee was bound:

  HIGH    the name is bound by an explicit import or definition and used directly
  MEDIUM  one inference was needed: a method called on self, a name re-exported
          through another local module, a simple alias, a literal dynamic import,
          a method of a local class called on an instance of it
  LOW     the use is an attribute of a call result (an "instance" of something
          external, whose type is not known), or a reference that is not a call

A use that could not be bound is kept as an unresolved record with its reason.
It never becomes an edge.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from typing import Any, Callable

from app.analyzers.reachability import imports as import_mapping
from app.analyzers.reachability.imports import DependencyIndex
from app.analyzers.source import base
from app.analyzers.source.base import ParsedFile

HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"
CONFIDENCE_RANK = {LOW: 1, MEDIUM: 2, HIGH: 3}

IMPORTS, CALLS, REFERENCES, CONSTRUCTS = "imports", "calls", "references", "constructs"

LOCAL, NOT_FOUND = "LOCAL", "LOCAL_MODULE_NOT_FOUND"
LOCAL_SYMBOL_NOT_FOUND = "LOCAL_SYMBOL_NOT_FOUND"      # the module exists, the name is not a definition in it
AMBIGUOUS_LOCAL_MODULE = "AMBIGUOUS_LOCAL_MODULE"
EXTERNAL_NOT_ANALYSED = "EXTERNAL_NOT_ANALYSED"        # standard library or an unmapped third-party name
_MAX_HOPS = 8
_MAX_MODULE_PARTS = 12          # components of a dotted name tried as a module path
RESOLUTION_BUDGET = "RESOLUTION_BUDGET"                # the graph's resolution step budget was used up


def weakest(*levels: str) -> str:
    return min(levels, key=lambda level: CONFIDENCE_RANK[level])


def external_id(qualified: str) -> str:
    return f"ext:{qualified}"


@dataclass
class CodeGraph:
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: list[dict[str, Any]] = field(default_factory=list)
    unresolved: list[dict[str, Any]] = field(default_factory=list)
    imports: list[dict[str, Any]] = field(default_factory=list)       # one record per import statement, with its mapping
    stats: dict[str, Any] = field(default_factory=dict)
    truncated: bool = False


class _Module:
    def __init__(self, parsed: ParsedFile) -> None:
        self.parsed = parsed
        self.id = parsed.module
        self.path = parsed.path
        self.definitions: dict[str, dict[str, Any]] = {}       # module-level name -> symbol
        self.members: dict[str, set[str]] = {}                 # class id -> names defined directly in it
        self.bindings: dict[str, dict[str, Any]] = {}          # module-level name bound by an import
        self.stars: list[dict[str, Any]] = []
        kinds = {symbol["id"]: symbol["kind"] for symbol in parsed.symbols}
        for symbol in parsed.symbols:
            if symbol["parent"] == self.id and symbol["kind"] != "module":
                self.definitions[symbol["name"]] = symbol
            elif kinds.get(symbol["parent"]) == "class":
                self.members.setdefault(symbol["parent"], set()).add(symbol["name"])
        for record in parsed.imports:
            if record["scope"] != self.id or record["dynamic"]:
                continue
            if record["star"]:
                self.stars.append(record)
            elif record["bound"]:
                # "import a.b" binds "a" to the package a; "import a.b as c" binds c to a.b.
                module = record["module"] if record["name"] is not None or record["bound"] != record["module"].split(".", 1)[0] \
                    else record["module"].split(".", 1)[0]
                self.bindings[record["bound"]] = {"module": module, "name": record["name"], "level": record["level"]}


class GraphBuilder:
    def __init__(self, files: list[ParsedFile], dependencies: DependencyIndex, max_edges: int = 500_000,
                 check: Callable[[], None] | None = None) -> None:
        self.dependencies = dependencies
        self.max_edges = max_edges
        self.check = check                                  # called between modules; raises to stop (deadline)
        self.steps = 0
        self.max_steps = max(200_000, max_edges * 20)       # module lookups allowed for the whole graph
        self._star_cache: dict[tuple[str, str], dict[str, Any] | None] = {}
        self._star_active: set[tuple[str, str]] = set()
        self.unmapped: set[str] = set()                     # third-party import names no dependency was found for
        self.ambiguous: set[str] = set()                    # dependencies an ambiguous import name could belong to
        self.shadowed: set[str] = set()                     # dependencies whose import name a local module also has
        self.graph = CodeGraph()
        self.modules: dict[str, _Module] = {}
        self.by_path: dict[str, _Module] = {}
        for parsed in files:
            if parsed.status != base.PARSED:
                continue
            module = _Module(parsed)
            self.modules[module.id] = module
            self.by_path[parsed.path] = module
        self.directories = {posixpath.dirname(path) for path in self.by_path}
        self._edge_keys: set[tuple] = set()
        self._test_modules: set[str] = set()

    # -- module lookup -----------------------------------------------------------------

    def _module_at(self, directory: str, parts: list[str]) -> _Module | None:
        stem = posixpath.join(directory, *parts) if parts else directory
        return self.by_path.get(f"{stem}.py") or self.by_path.get(f"{stem}/__init__.py")

    def _roots(self, importer: _Module) -> list[str]:
        """Directories an absolute import in this file may be resolved from: every ancestor directory, nearest first."""
        directory = posixpath.dirname(importer.path)
        roots = [directory]
        while directory:
            directory = posixpath.dirname(directory)
            roots.append(directory)
        return roots

    def _local(self, importer: _Module, parts: list[str], level: int) -> tuple[_Module | None, list[str], str | None]:
        """Find the deepest local module named by a prefix of `parts`. Returns (module, remaining parts, problem)."""
        self.steps += 1
        if self.steps > self.max_steps:
            self.graph.truncated = True
            return None, parts, RESOLUTION_BUDGET
        depth = min(len(parts), _MAX_MODULE_PARTS)
        if level:
            directory = posixpath.dirname(importer.path)
            for _ in range(level - 1):
                if not directory:
                    return None, parts, NOT_FOUND
                directory = posixpath.dirname(directory)
            for length in range(depth, 0, -1):
                found = self._module_at(directory, parts[:length])
                if found is not None:
                    return found, parts[length:], None
            package = self.by_path.get(posixpath.join(directory, "__init__.py"))
            return (package, parts, None) if package is not None else (None, parts, NOT_FOUND)
        roots = self._roots(importer)
        for length in range(depth, 0, -1):
            matches: dict[str, _Module] = {}
            for root in roots:
                found = self._module_at(root, parts[:length])
                # A module never satisfies its own absolute import (proj/celery.py doing "from celery import Celery").
                if found is not None and found is not importer:
                    matches.setdefault(found.id, found)
            if len(matches) == 1:
                return next(iter(matches.values())), parts[length:], None
            if len(matches) > 1:
                return None, parts, AMBIGUOUS_LOCAL_MODULE      # which one Python would import depends on how it is run
        return None, parts, None

    # -- target resolution -------------------------------------------------------------

    def resolve(self, importer: _Module, module: str, name: str | None, level: int, attrs: list[str]) -> dict[str, Any]:
        """Resolve an imported name (plus attribute path) to an application symbol or an external name."""
        hops: list[str] = []
        seen: set[tuple] = set()
        current, parts = importer, [*(module.split(".") if module else []), *([name] if name else []), *attrs]
        for _ in range(_MAX_HOPS):
            key = (current.id, tuple(parts), level)
            if key in seen:
                break
            seen.add(key)
            found, rest, problem = self._local(current, parts, level)
            if found is None:
                if problem or level:
                    return {"kind": "unresolved", "reason": problem or NOT_FOUND, "hops": hops}
                return self._external(parts, hops)
            if not rest:
                return {"kind": "module", "id": found.id, "hops": hops}
            definition = found.definitions.get(rest[0])
            if definition is not None:
                return self._member(found, definition, rest[1:], hops)
            binding = found.bindings.get(rest[0])
            if binding is None:
                through = self._through_star(found, rest[0])
                if through is not None and through["kind"] == "symbol":
                    owner = self.modules[through["module"]]
                    return self._member(owner, owner.definitions[rest[0]], rest[1:], [*hops, found.id, *through["hops"]])
                if through is not None:
                    return {**through, "hops": hops}
                return {"kind": "unresolved", "reason": LOCAL_SYMBOL_NOT_FOUND, "hops": hops, "module": found.id}
            # The name is re-exported: the module imported it from somewhere else.
            hops.append(found.id)
            current, level = found, binding["level"]
            parts = [*(binding["module"].split(".") if binding["module"] else []), *([binding["name"]] if binding["name"] else []), *rest[1:]]
        return {"kind": "unresolved", "reason": LOCAL_SYMBOL_NOT_FOUND, "hops": hops}

    def _through_star(self, module: _Module, name: str) -> dict[str, Any] | None:
        """Where `name` comes from if one of the module's star imports supplies it. Each (module, name) is
        worked out once, and a chain of star imports that loops back is treated as not supplying the name."""
        key = (module.id, name)
        if key in self._star_cache:
            return self._star_cache[key]
        if key in self._star_active or not module.stars:
            return None
        self._star_active.add(key)
        result: dict[str, Any] | None = None
        external = False
        try:
            for star in module.stars:
                source, rest, problem = self._local(module, star["module"].split(".") if star["module"] else [], star["level"])
                if problem == RESOLUTION_BUDGET:
                    result = {"kind": "unresolved", "reason": RESOLUTION_BUDGET}
                    break
                if source is None or rest:
                    external = external or (source is None and not problem and not star["level"])
                    continue
                definition = source.definitions.get(name)
                if definition is not None:
                    result = {"kind": "symbol", "module": source.id, "hops": []}
                    break
                inner = self._through_star(source, name)
                if inner is not None and inner["kind"] == "symbol":
                    result = {**inner, "hops": [source.id, *inner["hops"]]}
                    break
                if inner is not None and inner.get("reason") == base.STAR_IMPORT:
                    external = True
            if result is None and external:
                result = {"kind": "unresolved", "reason": base.STAR_IMPORT}
        finally:
            self._star_active.discard(key)
        self._star_cache[key] = result
        return result

    def _member(self, module: _Module, definition: dict[str, Any], rest: list[str], hops: list[str]) -> dict[str, Any]:
        if not rest:
            return {"kind": "symbol", "id": definition["id"], "symbol_kind": definition["kind"], "hops": hops}
        if definition["kind"] == "class" and len(rest) == 1 and rest[0] in module.members.get(definition["id"], ()):
            return {"kind": "symbol", "id": f"{definition['id']}.{rest[0]}", "symbol_kind": "method", "hops": hops, "member": True}
        return {"kind": "unresolved", "reason": LOCAL_SYMBOL_NOT_FOUND, "hops": hops, "module": module.id}

    def _external(self, parts: list[str], hops: list[str]) -> dict[str, Any]:
        qualified = ".".join(parts)
        mapping = self.dependencies.classify(qualified)
        return {"kind": "external", "qualified": qualified, "mapping": mapping, "hops": hops}

    # -- graph construction ------------------------------------------------------------

    def _node(self, identity: str, **fields: Any) -> None:
        if identity not in self.graph.nodes:
            self.graph.nodes[identity] = {"id": identity, **fields}

    def _external_node(self, qualified: str, mapping: import_mapping.ImportMapping) -> str:
        identity = external_id(qualified)
        self._node(identity, kind="external", qualified=qualified, top_level=mapping.top_level,
                   ecosystem=self.dependencies.ecosystem,
                   dependency_node_ids=[d["node_id"] for d in mapping.dependencies],
                   package=mapping.dependencies[0]["normalized_name"] if mapping.dependencies else None,
                   mapping_basis=mapping.basis, mapping_resolution=mapping.resolution)
        return identity

    def _edge(self, kind: str, source: str, target: str, confidence: str, basis: str, module: _Module | None,
              record: dict[str, Any] | None, **extra: Any) -> None:
        line = record.get("line") if record else None
        key = (kind, source, target, line, record.get("col") if record else None)
        if key in self._edge_keys:
            return
        if len(self.graph.edges) >= self.max_edges:
            self.graph.truncated = True
            return
        self._edge_keys.add(key)
        self.graph.edges.append({
            "kind": kind, "source": source, "target": target, "confidence": confidence, "basis": basis,
            "evidence": None if record is None or module is None else {
                "source_file": module.path, "line": line, "col": record.get("col"), "end_line": record.get("end_line"),
                "text": record.get("text") or record.get("statement")},
            **{k: v for k, v in extra.items() if v},
        })

    def _unresolved(self, module: _Module, record: dict[str, Any], reason: str, **extra: Any) -> None:
        if len(self.graph.unresolved) >= self.max_edges:
            self.graph.truncated = True
            return
        self.graph.unresolved.append({
            "source": record["caller"], "usage": record["usage"], "reason": reason,
            "expr": (record["target"].get("expr") or record.get("text") or "")[:200],
            "evidence": {"source_file": module.path, "line": record.get("line"), "col": record.get("col"), "text": record.get("text")},
            **{k: v for k, v in extra.items() if v},
        })

    def _add_imports(self, module: _Module) -> None:
        for record in module.parsed.imports:
            entry: dict[str, Any] = {
                "source_file": module.path, "scope": record["scope"], "line": record["line"], "col": record["col"],
                "statement": record["statement"], "module": record["module"], "name": record["name"], "bound": record["bound"],
                "level": record["level"], "star": record["star"], "dynamic": record["dynamic"],
                "resolution": None, "target": None, "dependency_node_ids": [], "dependency": None, "resolved_version": None,
                "mapping_basis": None, "note": None,
            }
            parts = record["module"].split(".") if record["module"] else []
            found, rest, problem = self._local(module, [*parts, *([record["name"]] if record["name"] else [])], record["level"])
            if found is None and record["name"] and not problem:
                found, rest, problem = self._local(module, parts, record["level"])
            confidence = MEDIUM if record["dynamic"] else HIGH
            basis = "literal dynamic import" if record["dynamic"] else "import statement"
            if found is not None:
                entry.update(resolution=LOCAL, target=found.id)
                self._edge(IMPORTS, record["scope"], found.id, confidence, basis, module, record)
                if not record["level"]:
                    same_name = self.dependencies.classify(record["module"] or (record["name"] or ""))
                    if same_name.dependencies:
                        # A local module has the import name of a dependency. Which one Python loads depends on how
                        # the program is started, so nothing can be concluded about that dependency from its absence.
                        self.shadowed.update(d["node_id"] for d in same_name.dependencies)
                        entry.update(shadows_dependency=True, note="A local module has the same import name as a dependency.")
            elif problem or record["level"]:
                entry.update(resolution=problem or NOT_FOUND, note="No module of the analysed source matches this import.")
            else:
                mapping = self.dependencies.classify(record["module"] or (record["name"] or ""))
                entry.update(resolution=mapping.resolution, mapping_basis=mapping.basis, note=mapping.note,
                             dependency_node_ids=[d["node_id"] for d in mapping.dependencies])
                if mapping.resolution == import_mapping.UNMAPPED:
                    self.unmapped.add(mapping.top_level)
                elif mapping.resolution == import_mapping.AMBIGUOUS:
                    self.ambiguous.update(d["node_id"] for d in mapping.dependencies)
                if mapping.resolution == import_mapping.DEPENDENCY:
                    first = mapping.dependencies[0]
                    entry.update(dependency=first["normalized_name"], resolved_version=first["version"] if len(mapping.dependencies) == 1 else None)
                    qualified = record["module"]
                    target = self._external_node(qualified, mapping)
                    self._edge(IMPORTS, record["scope"], target, confidence, basis, module, record,
                               star=record["star"] or None, imported_name=record["name"])
            self.graph.imports.append(entry)

    def _add_usages(self, module: _Module) -> None:
        for record in module.parsed.usages:
            target = record["target"]
            kind = target["kind"]
            if kind == "builtin":
                continue
            if kind == "unresolved":
                subject = target.get("subject")
                package = None
                if subject and subject.get("kind") == "import":
                    resolved = self.resolve(module, subject["module"], subject.get("name"), subject.get("level", 0), [])
                    if resolved["kind"] == "external" and resolved["mapping"].resolution == import_mapping.DEPENDENCY:
                        package = resolved["mapping"].dependencies[0]["normalized_name"]
                self._unresolved(module, record, target["reason"], subject_package=package)
                continue
            via = target.get("via")
            edge_kind = CALLS if record["usage"] in ("call", "decorator") else REFERENCES
            confidence = HIGH if edge_kind == CALLS else LOW
            if kind == "local":
                self._local_usage(module, record, target, edge_kind, confidence, via)
                continue
            resolved = self.resolve(module, target["module"], target.get("name"), target.get("level", 0), target.get("attrs", []))
            hops = resolved.get("hops") or []
            if hops:
                confidence = weakest(confidence, MEDIUM)
            if via in ("alias", "conditional"):
                confidence = weakest(confidence, MEDIUM)
            if resolved["kind"] == "external":
                mapping = resolved["mapping"]
                if mapping.resolution != import_mapping.DEPENDENCY:
                    if mapping.resolution == import_mapping.AMBIGUOUS:
                        self._unresolved(module, record, import_mapping.AMBIGUOUS)
                    continue                      # standard library and unmapped names are outside the graph
                if via == "instance":
                    confidence = LOW
                self._edge(edge_kind, record["caller"], self._external_node(resolved["qualified"], mapping), confidence,
                           self._basis(edge_kind, via, hops, external=True), module, record, via=via, hops=hops)
            elif resolved["kind"] == "symbol":
                if via == "instance" and not resolved.get("member"):
                    self._unresolved(module, record, base.CALL_RESULT)
                    continue
                if via == "instance":
                    confidence = weakest(confidence, MEDIUM)
                self._edge(edge_kind, record["caller"], resolved["id"], confidence,
                           self._basis(edge_kind, via, hops, external=False), module, record, via=via, hops=hops)
            elif resolved["kind"] == "module":
                if edge_kind == REFERENCES:
                    continue                      # a bare reference to a module adds nothing beyond its import edge
                self._unresolved(module, record, LOCAL_SYMBOL_NOT_FOUND)
            else:
                # An attribute of a call result that is not a known member is a call-result problem, whatever the lookup said.
                reason = base.CALL_RESULT if via == "instance" and resolved["reason"] == LOCAL_SYMBOL_NOT_FOUND else resolved["reason"]
                self._unresolved(module, record, reason)

    def _local_usage(self, module: _Module, record: dict[str, Any], target: dict[str, Any], edge_kind: str, confidence: str,
                     via: str | None) -> None:
        symbol = target["symbol"]
        attrs = target.get("attrs", [])
        node = self.graph.nodes.get(symbol)
        if node is None:
            self._unresolved(module, record, LOCAL_SYMBOL_NOT_FOUND)
            return
        if attrs:
            if node["kind"] == "class" and len(attrs) == 1 and attrs[0] in module.members.get(symbol, ()):
                symbol = f"{symbol}.{attrs[0]}"
                if via == "instance":
                    confidence = weakest(confidence, MEDIUM)
            else:
                self._unresolved(module, record, base.CALL_RESULT if via == "instance" else LOCAL_SYMBOL_NOT_FOUND)
                return
        elif via == "instance":
            self._unresolved(module, record, base.CALL_RESULT)
            return
        if via in ("self", "alias"):
            confidence = weakest(confidence, MEDIUM)
        if symbol == record["caller"] and edge_kind == REFERENCES:
            return
        self._edge(edge_kind, record["caller"], symbol, confidence, self._basis(edge_kind, via, [], external=False), module, record, via=via)

    @staticmethod
    def _basis(edge_kind: str, via: str | None, hops: list[str], external: bool) -> str:
        what = "call" if edge_kind == CALLS else "reference (not a call)"
        if via == "self":
            return f"{what} to a method of the same class through self"
        if via == "instance":
            return f"{what} on the result of calling {'an imported name' if external else 'a local class'}"
        if via == "alias":
            return f"{what} through a name assigned from {'an imported name' if external else 'a local definition'}"
        if via == "conditional":
            return f"{what} to a name that is bound in more than one way in its file; this is one of the possibilities"
        if hops:
            return f"{what} to a name re-exported through {', '.join(hops[:3])}"
        return f"{what} to {'an explicitly imported name' if external else 'a definition in the analysed source'}"

    def build(self, test_paths: set[str] | None = None) -> CodeGraph:
        test_paths = test_paths or set()
        for module in self.modules.values():
            for symbol in module.parsed.symbols:
                self._node(symbol["id"], kind=symbol["kind"], name=symbol["name"], qualname=symbol["qualname"], module=symbol["module"],
                           path=symbol["path"], line=symbol["line"], end_line=symbol["end_line"], parent=symbol["parent"],
                           is_test=module.path in test_paths)
        for module in self.modules.values():
            for class_id, members in module.members.items():
                if "__init__" in members:
                    self._edge(CONSTRUCTS, class_id, f"{class_id}.__init__", HIGH, "instantiating a class runs its __init__", None, None)
            if self.check is not None:
                self.check()
            self._add_imports(module)
            self._add_usages(module)
        graph = self.graph
        graph.edges.sort(key=lambda e: (e["source"], e["target"], e["kind"], (e["evidence"] or {}).get("line") or 0,
                                        (e["evidence"] or {}).get("col") or 0))
        reasons: dict[str, int] = {}
        for item in graph.unresolved:
            reasons[item["reason"]] = reasons.get(item["reason"], 0) + 1
        by_kind: dict[str, int] = {}
        for edge in graph.edges:
            by_kind[edge["kind"]] = by_kind.get(edge["kind"], 0) + 1
        resolutions: dict[str, int] = {}
        for item in graph.imports:
            resolutions[item["resolution"]] = resolutions.get(item["resolution"], 0) + 1
        graph.stats = {
            "modules": sum(1 for n in graph.nodes.values() if n["kind"] == "module"),
            "classes": sum(1 for n in graph.nodes.values() if n["kind"] == "class"),
            "functions": sum(1 for n in graph.nodes.values() if n["kind"] in ("function", "method")),
            "external_symbols": sum(1 for n in graph.nodes.values() if n["kind"] == "external"),
            "edges": len(graph.edges), "edges_by_kind": dict(sorted(by_kind.items())),
            "unresolved": len(graph.unresolved), "unresolved_by_reason": dict(sorted(reasons.items())),
            "imports": len(graph.imports), "imports_by_resolution": dict(sorted(resolutions.items())),
            "truncated": graph.truncated,
            # What limits the import-to-dependency mapping, for the conclusions drawn from an absent import.
            "mapping": {"unmapped_imports": sorted(self.unmapped)[:200], "unmapped_import_count": len(self.unmapped),
                        "ambiguous_dependency_node_ids": sorted(self.ambiguous)[:500],
                        "shadowed_dependency_node_ids": sorted(self.shadowed)[:500]},
        }
        return graph


def build_graph(files: list[ParsedFile], dependencies: DependencyIndex, test_paths: set[str] | None = None,
                max_edges: int = 500_000, check: Callable[[], None] | None = None) -> CodeGraph:
    return GraphBuilder(files, dependencies, max_edges, check).build(test_paths)
