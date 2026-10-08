"""Rust dependency files: Cargo.toml and Cargo.lock."""

from __future__ import annotations

import json
import re
import tomllib
from typing import Any

from app.analyzers.model import LOCKFILE, MANIFEST, Declared, Locked, ParsedFile, ParseFailure, clean, find_line

ECOSYSTEM = "cargo"
_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_EXACT = re.compile(r"^=\s*(\d+(?:\.\d+){0,2}[A-Za-z0-9.+-]*)$")
_CREDENTIALS = re.compile(r"(?<=://)[^/@\s]+@")


def _load(text: str) -> dict[str, Any]:
    try:
        return tomllib.loads(text.lstrip("﻿"))
    except (tomllib.TOMLDecodeError, RecursionError) as exc:
        raise ParseFailure(f"Not valid TOML: {clean(str(exc), 160)}") from exc


def _table(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def parse_cargo_toml(path: str, text: str) -> ParsedFile:
    data = _load(text)
    parsed = ParsedFile(path=path, kind=MANIFEST, package_manager="cargo", ecosystem=ECOSYSTEM)
    workspace = _table(data.get("workspace"))
    shared = _table(workspace.get("dependencies"))
    if workspace.get("members"):
        parsed.note("Cargo workspace root; each member crate's Cargo.toml is analysed separately")

    def add(table: Any, scope: str, label: str) -> None:
        for key, spec in _table(table).items():
            inherited = False
            if isinstance(spec, dict) and spec.get("workspace") is True:
                inherited = True
                base = shared.get(key)
                merged = dict(base) if isinstance(base, dict) else ({"version": base} if isinstance(base, str) else {})
                merged.update({k: v for k, v in spec.items() if k != "workspace"})
                spec_resolved: Any = merged
            else:
                spec_resolved = spec
            body = spec_resolved if isinstance(spec_resolved, dict) else {"version": spec_resolved}
            name = body.get("package") if isinstance(body.get("package"), str) else key
            if not _NAME.match(str(name)):
                parsed.note(f"{label}: '{clean(name, 80)}' is not a valid crate name and was ignored")
                continue
            constraint = body.get("version") if isinstance(body.get("version"), str) else None
            source = None
            for kind in ("git", "path", "registry"):
                if isinstance(body.get(kind), str):
                    source = {"type": kind, "location": clean(_CREDENTIALS.sub("***@", body[kind]), 300)}
                    break
            reason = f"Declared in {label}"
            if inherited and constraint is None and source is None:
                reason += "; inherited from the workspace root, whose definition is not in this file"
            exact = _EXACT.match(constraint) if constraint else None
            parsed.declared.append(Declared(
                ecosystem=ECOSYSTEM, package_manager="cargo", name=str(name), source_file=path, line=find_line(text, str(key)),
                raw=clean(f"{key} = {json.dumps(spec, default=str)}"), constraint=constraint,
                exact_version=exact.group(1) if exact else None, scope=scope, optional=body.get("optional") is True,
                source=source, reason=reason,
            ))

    for section, scope in (("dependencies", "runtime"), ("dev-dependencies", "dev"), ("build-dependencies", "build")):
        add(data.get(section), scope, f"[{section}]")
        for target, body in _table(data.get("target")).items():
            add(_table(body).get(section), scope, f"[target.{clean(target, 60)}.{section}]")
    return parsed


def parse_cargo_lock(path: str, text: str) -> ParsedFile:
    data = _load(text)
    parsed = ParsedFile(path=path, kind=LOCKFILE, package_manager="cargo", ecosystem=ECOSYSTEM, records_edges=True, records_roots=True)
    packages = data.get("package")
    if not isinstance(packages, list):
        return parsed
    by_name: dict[str, list[Locked]] = {}
    raw_deps: list[tuple[Locked, list[str]]] = []
    for entry in packages:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str) or not isinstance(entry.get("version"), str):
            continue
        name, version = entry["name"], entry["version"]
        if not _NAME.match(name):
            continue
        source = entry.get("source") if isinstance(entry.get("source"), str) else None
        kind = "registry" if source and source.startswith(("registry+", "sparse+")) else "git" if source and source.startswith("git+") else "url"
        checksum = entry.get("checksum")
        key = f"{name} {version}" + (f" ({source})" if source and any(o.version == version and o.name == name for o in by_name.get(name, [])) else "")
        item = Locked(
            ecosystem=ECOSYSTEM, package_manager="cargo", name=name, version=clean(version, 100), source_file=path, key=key,
            line=find_line(text, f'name = "{name}"'), direct=False, local=source is None,
            integrity=[{"algorithm": "sha256", "value": clean(checksum, 100)}] if isinstance(checksum, str) else [],
            source={"type": kind, "location": clean(_CREDENTIALS.sub("***@", source), 300)} if source else None,
        )
        parsed.locked.append(item)
        by_name.setdefault(name, []).append(item)
        raw_deps.append((item, [d for d in entry.get("dependencies") or [] if isinstance(d, str)]))
    for item, deps in raw_deps:
        for dep in deps:
            parts = dep.split(" ")
            candidates = by_name.get(parts[0], [])
            if len(parts) >= 2:
                candidates = [c for c in candidates if c.version == parts[1]]
            target = candidates[0] if len(candidates) == 1 else None
            item.deps.append((parts[0], parts[1] if len(parts) >= 2 else None, target.key if target else None))
            if item.local and target is not None and not target.local:
                target.direct = True
    return parsed
