"""Merge parsed dependency files into one package inventory and edge list.

Rules, in the order they are applied:

1. Every package in a lockfile becomes a node with its locked version
   (version OBSERVED). Requirements recorded by the lockfile become edges
   (OBSERVED).
2. Every manifest declaration is matched to the lockfile next to it (or, for
   npm and Cargo workspaces, the nearest lockfile above it). A match gives the
   declared dependency its locked version. Without a match the version is the
   exact pin if the manifest has one, otherwise UNRESOLVED - never guessed.
3. Direct / transitive:
   - declared in a manifest, or listed as a root by the lockfile -> DIRECT
   - reachable only through lockfile edges                        -> TRANSITIVE, OBSERVED
   - marked indirect by the manifest itself (go.mod)              -> TRANSITIVE, OBSERVED
   - in a lockfile that records no edges, and absent from the
     reliable manifest beside it                                  -> TRANSITIVE, INFERRED
   - anything else                                                -> UNKNOWN
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from typing import Any

from app.analyzers.model import (
    DIRECT, INFERRED, LOCKFILE, MANIFEST, MAX_INTEGRITY, OBSERVED, PARSED, TRANSITIVE, UNKNOWN, Declared, Locked, ParsedFile,
)
from app.analyzers.normalize import make_purl, node_id, normalize_name
from app.analyzers.parsers.javascript import _resolve_up

ROOT = "root"
MAX_EVIDENCE = 20
MAX_NAME = 300
MAX_VERSION = 120
COMPATIBLE_LOCKS = {
    "npm": {"npm", "yarn", "pnpm"},
    "pipenv": {"pipenv"},
    "poetry": {"poetry", "pip-compile"},
    "pip": {"pip-compile", "poetry"},
    "uv": {"pip-compile"},
    "pdm": {"pip-compile"},
    "cargo": {"cargo"},
    "gradle": {"gradle"},
    "go": {"go"},
}
LOCK_PREFERENCE = {"npm": 0, "pnpm": 1, "yarn": 2, "poetry": 0, "pipenv": 0, "pip-compile": 1, "cargo": 0, "gradle": 0, "go": 0}
WORKSPACE_ECOSYSTEMS = {"npm", "cargo"}
_RANK = {(DIRECT, OBSERVED): 5, (DIRECT, INFERRED): 4, (TRANSITIVE, OBSERVED): 3, (TRANSITIVE, INFERRED): 2, (UNKNOWN, UNKNOWN): 1}


@dataclass
class Package:
    node_id: str
    ecosystem: str
    name: str
    normalized_name: str
    version: str | None
    version_basis: str = UNKNOWN
    version_reason: str = "No lockfile entry or exact pin establishes the version"
    constraints: list[str] = field(default_factory=list)
    package_managers: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    optional: bool = False
    integrity: list[dict[str, str]] = field(default_factory=list)
    source: dict[str, str] | None = None
    evidence: list[dict[str, Any]] = field(default_factory=list)
    evidence_count: int = 0
    claims: list[tuple[str, str, str]] = field(default_factory=list)
    pending: list[str] = field(default_factory=list)        # lockfiles that list the package without saying direct
    lock_dev: bool | None = None
    relationship: str = UNKNOWN
    relationship_basis: str = UNKNOWN
    relationship_reason: str = ""

    def add_evidence(self, item: dict[str, Any]) -> None:
        self.evidence_count += 1
        if len(self.evidence) < MAX_EVIDENCE:
            self.evidence.append(item)

    def add_unique(self, attribute: str, value: str | None) -> None:
        values: list[str] = getattr(self, attribute)
        if value and value not in values:
            values.append(value)

    def add_integrity(self, items: list[dict[str, str]]) -> None:
        for item in items:
            if item not in self.integrity and len(self.integrity) < MAX_INTEGRITY:
                self.integrity.append(item)


@dataclass
class Resolution:
    packages: dict[str, Package] = field(default_factory=dict)
    edges: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    unresolved_edges: int = 0
    skipped_entries: int = 0

    def edge(self, source: str, target: str, basis: str, relation: str, evidence_file: str, spec: str | None = None) -> None:
        if source == target:
            return
        item = self.edges.setdefault((source, target), {
            "source": source, "target": target, "type": "depends_on", "relation": relation, "basis": basis,
            "evidence_files": [], "requirement": spec,
        })
        if basis == OBSERVED:
            item["basis"] = OBSERVED
        if evidence_file not in item["evidence_files"] and len(item["evidence_files"]) < 5:
            item["evidence_files"].append(evidence_file)


def storable(name: object, version: object) -> bool:
    """Names and versions come from repository files; refuse ones that are not plausible identifiers."""
    if not isinstance(name, str) or not name.strip() or len(name) > MAX_NAME or any(c.isspace() or ord(c) < 32 for c in name):
        return False
    return version is None or (isinstance(version, str) and 0 < len(version) <= MAX_VERSION and not any(ord(c) < 32 for c in version))


def _dir(path: str) -> str:
    return posixpath.dirname(path)


def _is_within(child_dir: str, ancestor_dir: str) -> bool:
    return ancestor_dir == "" or child_dir == ancestor_dir or child_dir.startswith(ancestor_dir + "/")


def _pair_locks(manifest: ParsedFile, locks: list[ParsedFile]) -> list[ParsedFile]:
    """Lockfiles that resolve this manifest: same directory first, then the nearest workspace root above."""
    compatible = COMPATIBLE_LOCKS.get(manifest.package_manager, set())
    candidates = [l for l in locks if l.ecosystem == manifest.ecosystem and l.package_manager in compatible]
    here = [l for l in candidates if _dir(l.path) == _dir(manifest.path)]
    if not here and manifest.ecosystem in WORKSPACE_ECOSYSTEMS:
        above = [l for l in candidates if _is_within(_dir(manifest.path), _dir(l.path))]
        if above:
            nearest = max(len(_dir(l.path)) for l in above)
            here = [l for l in above if len(_dir(l.path)) == nearest]
    return sorted(here, key=lambda l: (LOCK_PREFERENCE.get(l.package_manager, 9), l.path))


def resolve(parsed_files: list[ParsedFile]) -> Resolution:
    result = Resolution()
    usable = [p for p in parsed_files if p.status == PARSED]
    locks = [p for p in usable if p.kind == LOCKFILE and not p.integrity_index]
    manifests = [p for p in usable if p.kind == MANIFEST]
    checksum_files = [p for p in usable if p.integrity_index]

    lock_nodes: dict[tuple[str, str], str] = {}          # (lock path, lock key) -> node id
    lock_names: dict[str, dict[str, list[Locked]]] = {}  # lock path -> normalised name -> entries
    lock_by_path = {l.path: l for l in locks}

    def package_for(ecosystem: str, name: str, version: str | None) -> Package:
        normalized = normalize_name(ecosystem, name)
        identifier = node_id(ecosystem, normalized, version)
        package = result.packages.get(identifier)
        if package is None:
            package = result.packages[identifier] = Package(
                node_id=identifier, ecosystem=ecosystem, name=name, normalized_name=normalized, version=version)
        return package

    # 1. lockfiles ------------------------------------------------------------
    for lock in locks:
        names = lock_names.setdefault(lock.path, {})
        for item in lock.locked:
            if item.local:
                continue
            if not storable(item.name, item.version):
                result.skipped_entries += 1
                continue
            package = package_for(item.ecosystem, item.name, item.version)
            lock_nodes[(lock.path, item.key)] = package.node_id
            names.setdefault(package.normalized_name, []).append(item)
            if item.version:
                package.version_basis = OBSERVED
                package.version_reason = f"Locked in {lock.path}"
            package.add_unique("package_managers", item.package_manager)
            package.add_integrity(item.integrity)
            package.source = package.source or item.source
            package.optional = package.optional or item.optional
            if item.scope_known:
                package.lock_dev = item.dev if package.lock_dev is None else (package.lock_dev and item.dev)
            package.add_evidence({
                "source_file": lock.path, "file_kind": LOCKFILE, "package_manager": item.package_manager, "line": item.line,
                "declaration": f"{item.name} {item.version or '(no version)'}", "constraint": None,
                "scope": ("dev" if item.dev else "runtime") if item.scope_known else None, "evidence_type": "repository_file",
            })
            if item.direct is True:
                package.claims.append((DIRECT, OBSERVED, f"Listed as a direct dependency in {lock.path}"))
                result.edge(ROOT, package.node_id, OBSERVED, "direct", lock.path)
            else:
                package.pending.append(lock.path)
        for item in lock.locked:
            source = ROOT if item.local else lock_nodes.get((lock.path, item.key))
            if source is None:
                continue
            for dep_name, spec, key in item.deps:
                target = lock_nodes.get((lock.path, key)) if key else None
                if target is None:
                    result.unresolved_edges += 1
                    continue
                result.edge(source, target, OBSERVED, "direct" if item.local else "requires", lock.path, spec)
                if item.local:
                    claim = (DIRECT, OBSERVED, f"Required by the project itself in {lock.path}")
                    if claim not in result.packages[target].claims:
                        result.packages[target].claims.append(claim)

    # 2. manifests ------------------------------------------------------------
    lock_has_manifest: dict[str, list[str]] = {}
    for manifest in manifests:
        paired = _pair_locks(manifest, locks)
        if manifest.reliable_manifest:
            for lock in paired:
                lock_has_manifest.setdefault(lock.path, []).append(manifest.path)
        for declared in manifest.declared:
            if not storable(declared.name, declared.exact_version):
                result.skipped_entries += 1
                continue
            package, lock_path, ambiguous = _match(declared, manifest, paired, lock_nodes, lock_names, result)
            if package is None:
                package = package_for(declared.ecosystem, declared.name, declared.exact_version)
                if declared.exact_version:
                    package.version_basis = OBSERVED
                    package.version_reason = f"Exact version declared in {manifest.path}"
                elif ambiguous:
                    package.version_reason = f"{paired[0].path} locks several versions of this package and the manifest does not say which applies"
                elif paired:
                    package.version_reason = f"Declared in {manifest.path} but not present in {paired[0].path}"
            package.add_unique("package_managers", declared.package_manager)
            package.add_unique("constraints", declared.constraint)
            package.add_unique("scopes", declared.scope)
            package.add_integrity(declared.integrity)
            package.source = package.source or declared.source
            package.optional = package.optional or declared.optional
            package.add_evidence({
                "source_file": manifest.path, "file_kind": MANIFEST, "package_manager": declared.package_manager,
                "line": declared.line, "declaration": declared.raw, "constraint": declared.constraint,
                "scope": declared.scope, "evidence_type": "repository_file",
                "extras": list(declared.extras), "marker": declared.marker,
            })
            package.claims.append((declared.relationship, declared.basis, declared.reason))
            if declared.relationship == DIRECT:
                result.edge(ROOT, package.node_id, declared.basis, "direct", manifest.path, declared.constraint)
        for checksums in checksum_files:
            if _dir(checksums.path) != _dir(manifest.path) or checksums.ecosystem != manifest.ecosystem:
                continue
            for declared in manifest.declared:
                digest = checksums.integrity_index.get((declared.name, declared.exact_version or ""))
                package = result.packages.get(node_id(declared.ecosystem, normalize_name(declared.ecosystem, declared.name), declared.exact_version))
                if digest and package:
                    package.add_integrity([digest])

    # 3. direct / transitive --------------------------------------------------
    depths = shortest_depths(result)
    parents: dict[str, list[str]] = {}
    for source, target in result.edges:
        parents.setdefault(target, []).append(source)
    for package in result.packages.values():
        best = max(package.claims, key=lambda c: _RANK.get((c[0], c[1]), 0), default=None)
        if best is not None and best[0] == DIRECT:
            package.relationship, package.relationship_basis, package.relationship_reason = best
        elif best is not None and best[0] == TRANSITIVE:
            package.relationship, package.relationship_basis, package.relationship_reason = best
        elif (depths.get(package.node_id) or 0) >= 2:
            names = sorted({result.packages[p].name for p in parents.get(package.node_id, []) if p in result.packages})
            shown = ", ".join(names[:3]) + (f" and {len(names) - 3} more" if len(names) > 3 else "")
            package.relationship, package.relationship_basis = TRANSITIVE, OBSERVED
            package.relationship_reason = f"Required by {shown} according to {package.pending[0] if package.pending else 'the lockfile'}"
        else:
            package.relationship, package.relationship_basis, package.relationship_reason = _fallback(package, lock_by_path, lock_has_manifest)
        if not package.scopes and package.lock_dev is not None:
            package.scopes.append("dev" if package.lock_dev else "runtime")
    for parsed in usable:
        for note in parsed.notes:
            result.notes.append(f"{parsed.path}: {note}")
    if result.skipped_entries:
        result.notes.append(f"{result.skipped_entries} entries had an implausible package name or version and were ignored")
    return result


def _match(declared: Declared, manifest: ParsedFile, paired: list[ParsedFile], lock_nodes: dict[tuple[str, str], str],
           lock_names: dict[str, dict[str, list[Locked]]], result: Resolution) -> tuple[Package | None, str | None, bool]:
    """Find the lockfile entry that resolves a manifest declaration."""
    normalized = normalize_name(declared.ecosystem, declared.name)
    ambiguous = False
    for lock in paired:
        key: str | None = None
        if lock.package_manager == "npm" and lock.records_roots:
            keys = {item.key: item for item in lock.locked}
            relative = posixpath.relpath(_dir(manifest.path) or ".", _dir(lock.path) or ".")
            key = _resolve_up(keys, "" if relative == "." else relative, declared.name)
        elif lock.spec_index:
            key = lock.spec_index.get(f"{declared.name}@{declared.constraint}")
        if key is None:
            candidates = lock_names.get(lock.path, {}).get(normalized, [])
            if len(candidates) > 1 and declared.exact_version:
                candidates = [c for c in candidates if c.version == declared.exact_version] or candidates
            if len(candidates) > 1:
                candidates = [c for c in candidates if c.direct is True] or candidates
            if len(candidates) == 1:
                key = candidates[0].key
            elif len(candidates) > 1:
                ambiguous = True
        identifier = lock_nodes.get((lock.path, key)) if key else None
        if identifier:
            return result.packages[identifier], lock.path, False
    return None, None, ambiguous


def _fallback(package: Package, lock_by_path: dict[str, ParsedFile], lock_has_manifest: dict[str, list[str]]) -> tuple[str, str, str]:
    for path in package.pending:
        lock = lock_by_path[path]
        manifests = lock_has_manifest.get(path, [])
        if manifests and not lock.records_roots and not lock.records_edges:
            return (TRANSITIVE, INFERRED,
                    f"Present in {path} but not declared in {manifests[0]}. The lockfile does not record which package requires it.")
    if package.pending:
        path = package.pending[0]
        lock = lock_by_path[path]
        if lock.records_roots or lock_has_manifest.get(path):
            return (UNKNOWN, UNKNOWN, f"Listed in {path} but not connected to any direct dependency there")
        return (UNKNOWN, UNKNOWN, f"{path} does not record which packages are direct, and no manifest beside it declares them")
    return (UNKNOWN, UNKNOWN, "The repository evidence does not establish whether this is direct or transitive")


def shortest_depths(result: Resolution) -> dict[str, int]:
    adjacency: dict[str, list[str]] = {}
    for source, target in result.edges:
        adjacency.setdefault(source, []).append(target)
    depths = {ROOT: 0}
    frontier = [ROOT]
    while frontier:
        following = []
        for node in frontier:
            for target in adjacency.get(node, []):
                if target not in depths:
                    depths[target] = depths[node] + 1
                    following.append(target)
        frontier = following
    return depths


def to_record(package: Package) -> dict[str, Any]:
    return {
        "node_id": package.node_id,
        "ecosystem": package.ecosystem,
        "name": package.name,
        "normalized_name": package.normalized_name,
        "version": package.version,
        "version_status": "RESOLVED" if package.version else "UNRESOLVED",
        "version_basis": package.version_basis if package.version else UNKNOWN,
        "version_reason": package.version_reason,
        "purl": make_purl(package.ecosystem, package.normalized_name, package.version),
        "constraints": package.constraints,
        "package_managers": package.package_managers,
        "relationship": package.relationship,
        "relationship_basis": package.relationship_basis,
        "relationship_reason": package.relationship_reason,
        "scopes": package.scopes or ["unknown"],
        "optional": package.optional,
        "integrity": package.integrity,
        "source": package.source,
        "evidence": package.evidence,
        "evidence_count": package.evidence_count,
    }
