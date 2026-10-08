"""JavaScript / TypeScript dependency files: package.json, package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml."""

from __future__ import annotations

import json
import re
from typing import Any

import yaml

from app.analyzers.model import LOCKFILE, MANIFEST, Declared, Locked, ParsedFile, ParseFailure, clean, find_line, sri

ECOSYSTEM = "npm"
_NAME = re.compile(r"^(@[a-z0-9~][a-z0-9._~-]*/)?[a-z0-9~][a-z0-9._~-]*$", re.I)
_EXACT = re.compile(r"^v?=?\s*(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$")
_CREDENTIALS = re.compile(r"(?<=://)[^/@\s]+@")
SECTIONS = (
    ("dependencies", "runtime", False),
    ("devDependencies", "dev", False),
    ("peerDependencies", "peer", False),
    ("optionalDependencies", "optional", True),
)
MAX_DEPTH = 60


def _json(text: str, what: str) -> dict[str, Any]:
    try:
        data = json.loads(text.lstrip("﻿"))
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ParseFailure(f"Not valid JSON: {clean(str(exc), 160)}") from exc
    if not isinstance(data, dict):
        raise ParseFailure(f"{what} must contain a JSON object")
    return data


def _table(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def valid_name(name: Any) -> bool:
    return isinstance(name, str) and len(name) <= 214 and bool(_NAME.match(name))


def classify_spec(spec: str) -> tuple[str | None, str | None, dict[str, str] | None, str | None]:
    """Return (constraint, exact version, source, real name for npm: aliases)."""
    spec = spec.strip()
    alias = None
    if spec.startswith("npm:"):
        target = spec[4:]
        at = target.rfind("@")
        if at > 0:
            alias, spec = target[:at], target[at + 1:]
        else:
            alias, spec = target, "*"
    for prefix, kind in (("git+", "git"), ("git://", "git"), ("github:", "git"), ("http://", "url"), ("https://", "url"),
                         ("file:", "path"), ("link:", "path"), ("workspace:", "workspace"), ("catalog:", "catalog")):
        if spec.startswith(prefix):
            return clean(_CREDENTIALS.sub("***@", spec), 200), None, {"type": kind, "location": clean(_CREDENTIALS.sub("***@", spec), 300)}, alias
    if re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(#.+)?$", spec):  # "user/repo" GitHub shorthand
        return clean(spec, 200), None, {"type": "git", "location": f"github:{clean(spec, 200)}"}, alias
    exact = _EXACT.match(spec)
    return clean(spec, 200) or None, exact.group(1) if exact else None, None, alias


def parse_package_json(path: str, text: str) -> ParsedFile:
    data = _json(text, "package.json")
    parsed = ParsedFile(path=path, kind=MANIFEST, package_manager="npm", ecosystem=ECOSYSTEM)
    for section, scope, optional in SECTIONS:
        for name, spec in _table(data.get(section)).items():
            if not isinstance(spec, str):
                parsed.note(f"{section}.{clean(name, 80)}: non-string version ignored")
                continue
            constraint, exact, source, alias = classify_spec(spec)
            real = alias or name
            if not valid_name(real):
                parsed.note(f"{section}: '{clean(real, 80)}' is not a valid npm package name and was ignored")
                continue
            meta = _table(_table(data.get("peerDependenciesMeta")).get(name)) if scope == "peer" else {}
            parsed.declared.append(Declared(
                ecosystem=ECOSYSTEM, package_manager="npm", name=real, source_file=path, line=find_line(text, f'"{name}"'),
                raw=clean(f'"{name}": "{spec}"'), constraint=constraint, exact_version=exact, scope=scope,
                optional=optional or meta.get("optional") is True, source=source,
                reason=f"Declared in {section}" + (f" (alias '{clean(name, 80)}')" if alias else ""),
            ))
    if data.get("workspaces"):
        parsed.note("This package declares npm workspaces; member packages are analysed from their own package.json files")
    if isinstance(data.get("packageManager"), str):
        parsed.note(f"packageManager: {clean(data['packageManager'], 80)}")
    return parsed


def _resolve_up(packages: dict[str, Any], start: str, dep: str) -> str | None:
    """Node's module resolution over lockfile paths: look in node_modules here, then in each ancestor."""
    current = start
    for _ in range(MAX_DEPTH):
        candidate = f"{current}/node_modules/{dep}" if current else f"node_modules/{dep}"
        if candidate in packages:
            return candidate
        if not current:
            return None
        cut = current.rfind("/node_modules/")
        if cut >= 0:
            current = current[:cut]
        elif current.startswith("node_modules/"):
            current = ""
        else:
            current = ""  # a workspace directory: fall back to the root node_modules
    return None


def _name_from_path(path: str) -> str:
    return path.rsplit("node_modules/", 1)[-1]


def parse_package_lock(path: str, text: str) -> ParsedFile:
    data = _json(text, "The lockfile")
    manager = "npm"
    parsed = ParsedFile(path=path, kind=LOCKFILE, package_manager=manager, ecosystem=ECOSYSTEM, records_edges=True)
    version = data.get("lockfileVersion")
    parsed.note(f"lockfileVersion {clean(version, 10)}")

    packages = data.get("packages")
    if isinstance(packages, dict) and packages:
        parsed.records_roots = True
        locked: dict[str, Locked] = {}
        for key, entry in packages.items():
            if not isinstance(key, str) or not isinstance(entry, dict) or entry.get("link") is True:
                continue
            local = "node_modules/" not in key
            name = entry.get("name") if isinstance(entry.get("name"), str) else (_name_from_path(key) if not local else key or "(root)")
            if not local and not valid_name(name):
                parsed.note(f"Entry '{clean(key, 120)}' has an invalid package name and was ignored")
                continue
            resolved = entry.get("resolved") if isinstance(entry.get("resolved"), str) else None
            locked[key] = Locked(
                ecosystem=ECOSYSTEM, package_manager=manager, name=name,
                version=entry.get("version") if isinstance(entry.get("version"), str) else None,
                source_file=path, key=key, dev=entry.get("dev") is True, scope_known=True, optional=entry.get("optional") is True or entry.get("devOptional") is True,
                integrity=sri(entry.get("integrity")), direct=False, local=local,
                source={"type": "registry" if resolved.startswith("https://registry.") else "url", "location": clean(_CREDENTIALS.sub("***@", resolved), 300)} if resolved else None,
            )
        for key, item in locked.items():
            entry = packages[key]
            wanted: dict[str, str | None] = {}
            for section in ("dependencies", "optionalDependencies", "peerDependencies") + (("devDependencies",) if item.local else ()):
                for dep, spec in _table(entry.get(section)).items():
                    wanted.setdefault(str(dep), spec if isinstance(spec, str) else None)
            for dep, spec in wanted.items():
                target = _resolve_up(packages, key, dep)
                if target in locked:
                    item.deps.append((dep, spec, target))
                    if item.local:
                        locked[target].direct = True
                elif dep not in _table(entry.get("peerDependencies")) and dep not in _table(entry.get("optionalDependencies")):
                    item.deps.append((dep, spec, None))
        parsed.locked = list(locked.values())
        return parsed

    # lockfileVersion 1: a nested "dependencies" tree with "requires" maps.
    tree = data.get("dependencies")
    flat: dict[str, dict[str, Any]] = {}

    def walk(node: dict[str, Any], prefix: str, depth: int) -> None:
        if depth > MAX_DEPTH:
            return
        for name, entry in node.items():
            if isinstance(entry, dict) and valid_name(name):
                key = f"{prefix}node_modules/{name}"
                flat[key] = entry
                walk(_table(entry.get("dependencies")), key + "/", depth + 1)

    walk(_table(tree), "", 0)
    locked = {}
    for key, entry in flat.items():
        resolved = entry.get("resolved") if isinstance(entry.get("resolved"), str) else None
        locked[key] = Locked(
            ecosystem=ECOSYSTEM, package_manager=manager, name=_name_from_path(key),
            version=entry.get("version") if isinstance(entry.get("version"), str) else None, source_file=path, key=key,
            dev=entry.get("dev") is True, scope_known=True, optional=entry.get("optional") is True, integrity=sri(entry.get("integrity")),
            source={"type": "registry" if resolved.startswith("https://registry.") else "url", "location": clean(_CREDENTIALS.sub("***@", resolved), 300)} if resolved else None,
        )
    for key, item in locked.items():
        for dep, spec in _table(flat[key].get("requires")).items():
            target = _resolve_up(flat, key, str(dep))
            item.deps.append((str(dep), spec if isinstance(spec, str) else None, target))
    parsed.locked = list(locked.values())
    return parsed


# --- yarn -------------------------------------------------------------------

_YARN_HEADER = re.compile(r"^(?P<specs>\S.*):\s*$")
_YARN_FIELD = re.compile(r'^  (?P<key>[A-Za-z]+)\s+"?(?P<value>.*?)"?\s*$')
_YARN_DEP = re.compile(r'^    "?(?P<name>[^"\s]+)"?\s+"?(?P<spec>[^"]*)"?\s*$')


def _split_spec(spec: str) -> tuple[str, str]:
    at = spec.rfind("@")
    return (spec[:at], spec[at + 1:]) if at > 0 else (spec, "")


def parse_yarn_lock(path: str, text: str) -> ParsedFile:
    if "__metadata:" in text[:2000]:
        return _parse_yarn_berry(path, text)
    parsed = ParsedFile(path=path, kind=LOCKFILE, package_manager="yarn", ecosystem=ECOSYSTEM, records_edges=True)
    current: Locked | None = None
    section: str | None = None
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        header = _YARN_HEADER.match(line) if not line.startswith(" ") else None
        if header:
            specs = [s.strip().strip('"') for s in header.group("specs").split(",") if s.strip()]
            name = _split_spec(specs[0])[0] if specs else ""
            section = None
            if not specs or not valid_name(name):
                current = None
                continue
            current = Locked(ecosystem=ECOSYSTEM, package_manager="yarn", name=name, version=None, source_file=path,
                             key=specs[0], line=number)
            parsed.locked.append(current)
            for spec in specs:
                parsed.spec_index[spec] = current.key
            continue
        if current is None:
            continue
        if line.startswith("    "):
            dep = _YARN_DEP.match(line)
            if dep and section in {"dependencies", "optionalDependencies"}:
                current.deps.append((dep.group("name"), dep.group("spec"), f'{dep.group("name")}@{dep.group("spec")}'))
            continue
        if line.rstrip().endswith(":") and line.startswith("  "):
            section = line.strip().rstrip(":")
            continue
        field = _YARN_FIELD.match(line)
        if field:
            section = None
            key, value = field.group("key"), field.group("value")
            if key == "version":
                current.version = clean(value, 100)
            elif key == "integrity":
                current.integrity = sri(value)
            elif key == "resolved":
                current.source = {"type": "registry" if "registry." in value else "url", "location": clean(_CREDENTIALS.sub("***@", value), 300)}
    for item in parsed.locked:
        item.deps = [(n, s, parsed.spec_index.get(k)) for n, s, k in item.deps]
    return parsed


def _parse_yarn_berry(path: str, text: str) -> ParsedFile:
    data = _yaml(text)
    parsed = ParsedFile(path=path, kind=LOCKFILE, package_manager="yarn", ecosystem=ECOSYSTEM, records_edges=True)
    raw_deps: dict[str, dict[str, Any]] = {}
    for header, entry in data.items():
        if header == "__metadata" or not isinstance(header, str) or not isinstance(entry, dict):
            continue
        specs = [s.strip() for s in header.split(",") if s.strip()]
        name, first_range = _split_spec(specs[0])
        if not valid_name(name):
            continue
        local = entry.get("linkType") == "soft" or "@workspace:" in specs[0]
        checksum = entry.get("checksum")
        item = Locked(
            ecosystem=ECOSYSTEM, package_manager="yarn", name=name, version=str(entry.get("version")) if entry.get("version") is not None else None,
            source_file=path, key=specs[0], line=find_line(text, f'"{specs[0]}'), local=local,
            integrity=[{"algorithm": "yarn-checksum", "value": clean(checksum, 200)}] if isinstance(checksum, str) else [],
            source={"type": "registry", "location": clean(entry.get("resolution", ""), 300)} if isinstance(entry.get("resolution"), str) else None,
        )
        parsed.locked.append(item)
        for spec in specs:
            parsed.spec_index[spec] = item.key
            dep_name, dep_range = _split_spec(spec)
            if dep_range.startswith("npm:"):
                parsed.spec_index[f"{dep_name}@{dep_range[4:]}"] = item.key
        raw_deps[item.key] = {**_table(entry.get("dependencies")), **_table(entry.get("optionalDependencies"))}
    for item in parsed.locked:
        for dep, spec in raw_deps.get(item.key, {}).items():
            spec = str(spec)
            target = parsed.spec_index.get(f"{dep}@{spec}") or parsed.spec_index.get(f"{dep}@npm:{spec}")
            item.deps.append((str(dep), spec, target))
    return parsed


# --- pnpm -------------------------------------------------------------------

def _yaml(text: str) -> dict[str, Any]:
    try:
        data = yaml.safe_load(text.lstrip("﻿"))
    except (yaml.YAMLError, RecursionError) as exc:
        raise ParseFailure(f"Not valid YAML: {clean(str(exc), 160)}") from exc
    if not isinstance(data, dict):
        raise ParseFailure("The lockfile must contain a YAML mapping")
    return data


def _pnpm_key(key: str) -> tuple[str, str] | None:
    """Split a pnpm package key into (name, version) across lockfile versions 5, 6 and 9."""
    key = key.strip()
    if key.startswith("/"):
        key = key[1:]
    key = key.split("(", 1)[0]
    at = key.rfind("@")
    if at > 0:
        name, version = key[:at], key[at + 1:]
    elif "/" in key:
        name, _, version = key.rpartition("/")
    else:
        return None
    version = version.split("_", 1)[0]
    return (name, version) if valid_name(name) and version else None


def _pnpm_ref(dep: str, ref: Any) -> tuple[str, str] | None:
    """A dependency reference is either a version of `dep` or a full key of another package."""
    if not isinstance(ref, (str, int, float)):
        return None
    ref = str(ref)
    if ref.startswith(("link:", "file:", "workspace:")):
        return None
    if ref.startswith("/") or (ref.rfind("@") > 0 and not ref[0].isdigit()):
        return _pnpm_key(ref)
    version = ref.split("(", 1)[0].split("_", 1)[0]
    return (dep, version) if version else None


def parse_pnpm_lock(path: str, text: str) -> ParsedFile:
    data = _yaml(text)
    parsed = ParsedFile(path=path, kind=LOCKFILE, package_manager="pnpm", ecosystem=ECOSYSTEM, records_edges=True, records_roots=True)
    parsed.note(f"lockfileVersion {clean(data.get('lockfileVersion'), 10)}")
    index: dict[tuple[str, str], Locked] = {}

    def ensure(name: str, version: str) -> Locked:
        item = index.get((name, version))
        if item is None:
            item = index[(name, version)] = Locked(
                ecosystem=ECOSYSTEM, package_manager="pnpm", name=name, version=version, source_file=path,
                key=f"{name}@{version}", direct=False,
            )
        return item

    for key, entry in _table(data.get("packages")).items():
        parts = _pnpm_key(str(key))
        if parts is None:
            continue
        item = ensure(*parts)
        entry = _table(entry)
        item.integrity = sri(_table(entry.get("resolution")).get("integrity")) or item.integrity
        item.dev = item.dev or entry.get("dev") is True
        item.optional = item.optional or entry.get("optional") is True
        tarball = _table(entry.get("resolution")).get("tarball")
        if isinstance(tarball, str):
            item.source = {"type": "url", "location": clean(_CREDENTIALS.sub("***@", tarball), 300)}

    # v9 keeps each package's dependencies under "snapshots"; earlier versions keep them on the package.
    for section in ("packages", "snapshots"):
        for key, entry in _table(data.get(section)).items():
            parts = _pnpm_key(str(key))
            if parts is None:
                continue
            item = ensure(*parts)
            seen = {d[2] for d in item.deps}
            for group in ("dependencies", "optionalDependencies"):
                for dep, ref in _table(_table(entry).get(group)).items():
                    target = _pnpm_ref(str(dep), ref)
                    target_key = f"{target[0]}@{target[1]}" if target and target in index else None
                    if target_key is None and target is not None:
                        target_key = ensure(*target).key
                    if target_key not in seen:
                        seen.add(target_key)
                        item.deps.append((str(dep), str(ref), target_key))

    importers = _table(data.get("importers")) or {".": data}
    for importer in importers.values():
        for group, dev in (("dependencies", False), ("devDependencies", True), ("optionalDependencies", False)):
            for dep, value in _table(_table(importer).get(group)).items():
                ref = value.get("version") if isinstance(value, dict) else value
                target = _pnpm_ref(str(dep), ref)
                if target is not None:
                    item = ensure(*target)
                    item.direct = True
                    item.dev = item.dev or dev
    parsed.locked = list(index.values())
    return parsed
