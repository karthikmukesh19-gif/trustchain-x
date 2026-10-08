"""Python dependency files: requirements, pyproject.toml, setup.cfg, Pipfile, Pipfile.lock, poetry.lock."""

from __future__ import annotations

import configparser
import json
import posixpath
import re
import tomllib
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement

from app.analyzers.model import (
    DIRECT, INFERRED, LOCKFILE, MANIFEST, MAX_INTEGRITY, OBSERVED, Declared, Locked, ParsedFile, ParseFailure, clean, find_line,
)
from app.analyzers.normalize import normalize_name

ECOSYSTEM = "pypi"
_EXACT = re.compile(r"^={2,3}\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)$")
_PLAIN_VERSION = re.compile(r"^v?\d+(\.\d+)*([.-]?[A-Za-z0-9]+)*(\+[A-Za-z0-9.]+)?$")
_HASH = re.compile(r"--hash[=\s]+([A-Za-z0-9]+):([A-Fa-f0-9]+)")
_EGG = re.compile(r"[#&]egg=([A-Za-z0-9._-]+)")
_URL_CREDENTIALS = re.compile(r"(?<=://)[^/@\s]+@")
_DEV_HINT = re.compile(r"(^|[-_./])(dev|develop|development|lint|docs?|ci|tools?)([-_.]|$)", re.I)
_TEST_HINT = re.compile(r"(^|[-_./])(tests?|testing)([-_.]|$)", re.I)

REQUIREMENTS_REASON = (
    "Listed in a requirements file. Such a file can also list transitive packages "
    "(for example pip freeze output), so 'direct' is inferred rather than observed."
)


def _redact(url: str) -> str:
    return _URL_CREDENTIALS.sub("***@", url)


def exact_from_specifier(spec: str | None) -> str | None:
    if not spec:
        return None
    match = _EXACT.match(spec.strip())
    return match.group(1) if match and "*" not in match.group(1) else None


def scope_from_filename(path: str) -> str:
    name = posixpath.basename(path)
    parent = posixpath.basename(posixpath.dirname(path))
    hint = f"{parent}/{name}" if parent in {"requirements", "reqs"} else name
    if _TEST_HINT.search(hint):
        return "test"
    if _DEV_HINT.search(hint):
        return "dev"
    return "runtime"


def parse_pep508(text: str) -> dict[str, Any] | None:
    """Parse one PEP 508 requirement string. Returns None when it is not one."""
    try:
        req = Requirement(text)
    except InvalidRequirement:
        return None
    constraint = str(req.specifier) or None
    source = {"type": "url", "location": clean(_redact(req.url), 300)} if req.url else None
    return {
        "name": req.name,
        "constraint": constraint,
        "exact_version": exact_from_specifier(constraint) if constraint and "," not in constraint else None,
        "extras": tuple(sorted(req.extras)),
        "marker": clean(str(req.marker), 200) if req.marker else None,
        "source": source,
    }


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Join backslash continuations; keep the first physical line number."""
    out: list[tuple[int, str]] = []
    buffer, start = "", 0
    for number, line in enumerate(text.splitlines(), start=1):
        if not buffer:
            start = number
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        out.append((start, buffer + line))
        buffer = ""
    if buffer:
        out.append((start, buffer))
    return out


def _safe_include(base: str, target: str) -> str | None:
    """Resolve a file referenced from a requirements file, refusing to leave the repository."""
    target = target.strip().strip("'\"")
    if not target or "://" in target or target.startswith(("/", "~")) or "\\" in target or "\x00" in target:
        return None
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(base), target))
    if resolved.startswith("../") or resolved in {"..", "."} or resolved.startswith("/"):
        return None
    return resolved


def parse_requirements(path: str, text: str) -> ParsedFile:
    parsed = ParsedFile(path=path, kind=MANIFEST, package_manager="pip", ecosystem=ECOSYSTEM)
    scope = scope_from_filename(path)
    entries: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    for number, line in _logical_lines(text.lstrip("﻿")):
        stripped = line.strip()
        if not stripped:
            current = None
            continue
        if stripped.startswith("#"):
            # pip-compile annotates each pin with the packages that require it.
            if current is not None and line[:1] in " \t":
                body = stripped.lstrip("#").strip()
                if body.lower().startswith("via"):
                    body = body[3:].strip()
                    current["annotated"] = True
                if body and current.get("annotated"):
                    current["via"].append(body)
            continue
        current = None
        inline_via = None
        if " #" in stripped:
            stripped, _, comment = stripped.partition(" #")
            stripped = stripped.strip()
            comment = comment.strip()
            if comment.lower().startswith("via "):
                inline_via = comment[4:].strip()

        if stripped.startswith("-"):
            option, _, value = stripped.partition(" ")
            if "=" in option and not value:
                option, _, value = option.partition("=")
            value = value.strip()
            if option in {"-r", "--requirement", "-c", "--constraint"}:
                target = _safe_include(path, value)
                if target is None:
                    parsed.note(f"Line {number}: reference to '{clean(value, 120)}' ignored (outside the repository or not a relative path)")
                elif option in {"-r", "--requirement"}:
                    parsed.includes.append(target)
                else:
                    parsed.note(f"Line {number}: constraints file {target} referenced (constraints are not dependencies)")
                continue
            if option in {"-e", "--editable"}:
                stripped = value
            else:
                if option in {"-i", "--index-url", "--extra-index-url", "-f", "--find-links"}:
                    parsed.note(f"Line {number}: {option} {clean(_redact(value), 200)} (recorded, never contacted)")
                continue

        hashes = [{"algorithm": a.lower(), "value": v.lower()} for a, v in _HASH.findall(stripped)][:MAX_INTEGRITY]
        requirement_text = re.split(r"\s--[a-z]", stripped, maxsplit=1)[0].strip().rstrip(";").strip()
        fields = parse_pep508(requirement_text)
        if fields is None:
            egg = _EGG.search(requirement_text)
            location = clean(_redact(requirement_text), 300)
            if egg:
                kind = "git" if requirement_text.startswith(("git+", "hg+", "svn+", "bzr+")) else "url"
                fields = {"name": egg.group(1), "constraint": None, "exact_version": None, "extras": (), "marker": None,
                          "source": {"type": kind, "location": location}}
            else:
                parsed.note(f"Line {number}: could not identify a package name in '{clean(requirement_text, 120)}'")
                continue
        entry = {**fields, "line": number, "raw": clean(line), "integrity": hashes, "via": [], "annotated": False}
        if inline_via:
            entry["via"].append(inline_via)
            entry["annotated"] = True
        entries.append(entry)
        current = entry

    if any(e["annotated"] for e in entries):
        return _compiled_requirements(parsed, entries, scope)

    for e in entries:
        parsed.declared.append(Declared(
            ecosystem=ECOSYSTEM, package_manager="pip", name=e["name"], source_file=path, line=e["line"], raw=e["raw"],
            constraint=e["constraint"], exact_version=e["exact_version"], scope=scope, extras=e["extras"], marker=e["marker"],
            source=e["source"], integrity=e["integrity"], relationship=DIRECT, basis=INFERRED, reason=REQUIREMENTS_REASON,
        ))
    return parsed


def _compiled_requirements(parsed: ParsedFile, entries: list[dict[str, Any]], scope: str) -> ParsedFile:
    """pip-compile output: a lockfile whose '# via' comments record what requires each pin."""
    parsed.kind = LOCKFILE
    parsed.package_manager = "pip-compile"
    parsed.records_edges = True
    parsed.records_roots = True
    by_name: dict[str, Locked] = {}
    for e in entries:
        key = normalize_name(ECOSYSTEM, e["name"])
        by_name[key] = Locked(
            ecosystem=ECOSYSTEM, package_manager="pip-compile", name=e["name"], version=e["exact_version"],
            source_file=parsed.path, key=key, line=e["line"], dev=scope in {"dev", "test"}, integrity=e["integrity"],
            source=e["source"], direct=None,
        )
    for e in entries:
        child = by_name[normalize_name(ECOSYSTEM, e["name"])]
        for via in e["via"]:
            via = via.strip()
            # "-r requirements.in", "-c ...", "project (pyproject.toml)", "project (setup.py)" mark a top-level request.
            if via.startswith(("-r ", "-c ")) or re.search(r"\((pyproject\.toml|setup\.(py|cfg))\)$", via):
                if not via.startswith("-c "):
                    child.direct = True
                continue
            parent = by_name.get(normalize_name(ECOSYSTEM, via.split(" ")[0]))
            if parent is not None and parent is not child:
                parent.deps.append((child.name, None, child.key))
                if child.direct is None:
                    child.direct = False
    parsed.locked = list(by_name.values())
    parsed.note("pip-compile annotations ('# via') were used to tell direct pins from transitive ones")
    return parsed


# --- pyproject.toml ---------------------------------------------------------

def _load_toml(text: str) -> dict[str, Any]:
    try:
        return tomllib.loads(text.lstrip("﻿"))
    except (tomllib.TOMLDecodeError, RecursionError) as exc:
        raise ParseFailure(f"Not valid TOML: {clean(str(exc), 160)}") from exc


def _table(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _pep508_list(parsed: ParsedFile, text: str, items: Any, manager: str, scope: str, optional: bool = False, label: str = "") -> None:
    if not isinstance(items, list):
        return
    for item in items:
        if not isinstance(item, str):
            if isinstance(item, dict) and "include-group" in item:
                continue
            parsed.note(f"{label}: non-string entry ignored")
            continue
        fields = parse_pep508(item)
        if fields is None:
            parsed.note(f"{label}: '{clean(item, 120)}' is not a valid requirement")
            continue
        parsed.declared.append(Declared(
            ecosystem=ECOSYSTEM, package_manager=manager, name=fields["name"], source_file=parsed.path,
            line=find_line(text, fields["name"]), raw=clean(item), constraint=fields["constraint"],
            exact_version=fields["exact_version"], scope=scope, optional=optional, extras=fields["extras"],
            marker=fields["marker"], source=fields["source"], reason=f"Declared in {label}",
        ))


def _poetry_table(parsed: ParsedFile, text: str, table: Any, scope: str, label: str) -> None:
    for name, spec in _table(table).items():
        if not isinstance(name, str) or name.lower() == "python":
            continue
        variants = spec if isinstance(spec, list) else [spec]
        constraints: list[str] = []
        optional, source, extras = False, None, ()
        for variant in variants:
            if isinstance(variant, str):
                constraints.append(variant)
            elif isinstance(variant, dict):
                if isinstance(variant.get("version"), str):
                    constraints.append(variant["version"])
                optional = optional or variant.get("optional") is True
                if isinstance(variant.get("extras"), list):
                    extras = tuple(sorted(str(x) for x in variant["extras"]))
                for kind in ("git", "path", "url"):
                    if isinstance(variant.get(kind), str):
                        source = {"type": kind, "location": clean(_redact(variant[kind]), 300)}
        constraint = " || ".join(dict.fromkeys(constraints)) or None
        exact = None
        if constraint and len(constraints) == 1:
            exact = exact_from_specifier(constraint) or (constraint if _PLAIN_VERSION.match(constraint) and constraint[0].isdigit() else None)
        parsed.declared.append(Declared(
            ecosystem=ECOSYSTEM, package_manager="poetry", name=name, source_file=parsed.path, line=find_line(text, name),
            raw=clean(f"{name} = {json.dumps(spec, default=str)}"), constraint=constraint, exact_version=exact, scope=scope,
            optional=optional, extras=extras, source=source, reason=f"Declared in {label}",
        ))


def parse_pyproject(path: str, text: str) -> ParsedFile:
    data = _load_toml(text)
    tool = _table(data.get("tool"))
    poetry = _table(tool.get("poetry"))
    manager = "poetry" if poetry else "pip"
    parsed = ParsedFile(path=path, kind=MANIFEST, package_manager=manager, ecosystem=ECOSYSTEM)

    project = _table(data.get("project"))
    _pep508_list(parsed, text, project.get("dependencies"), "pip", "runtime", label="[project].dependencies")
    for extra, items in _table(project.get("optional-dependencies")).items():
        _pep508_list(parsed, text, items, "pip", "optional", optional=True, label=f"[project.optional-dependencies].{clean(extra, 60)}")
    if "dependencies" in (project.get("dynamic") or []):
        parsed.note("[project].dependencies is declared dynamic: the build backend computes it, so it is not in this file")
    for group, items in _table(data.get("dependency-groups")).items():
        scope = "test" if _TEST_HINT.search(str(group)) else "dev"
        _pep508_list(parsed, text, items, "pip", scope, label=f"[dependency-groups].{clean(group, 60)}")
    _pep508_list(parsed, text, _table(data.get("build-system")).get("requires"), "pip", "build", label="[build-system].requires")

    _poetry_table(parsed, text, poetry.get("dependencies"), "runtime", "[tool.poetry.dependencies]")
    _poetry_table(parsed, text, poetry.get("dev-dependencies"), "dev", "[tool.poetry.dev-dependencies]")
    for group, body in _table(poetry.get("group")).items():
        scope = "test" if _TEST_HINT.search(str(group)) else "dev"
        _poetry_table(parsed, text, _table(body).get("dependencies"), scope, f"[tool.poetry.group.{clean(group, 60)}.dependencies]")

    _pep508_list(parsed, text, _table(tool.get("uv")).get("dev-dependencies"), "uv", "dev", label="[tool.uv].dev-dependencies")
    for group, items in _table(_table(tool.get("pdm")).get("dev-dependencies")).items():
        _pep508_list(parsed, text, items, "pdm", "dev", label=f"[tool.pdm.dev-dependencies].{clean(group, 60)}")
    return parsed


def parse_setup_cfg(path: str, text: str) -> ParsedFile:
    parsed = ParsedFile(path=path, kind=MANIFEST, package_manager="pip", ecosystem=ECOSYSTEM)
    config = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        config.read_string(text.lstrip("﻿"))
    except configparser.Error as exc:
        raise ParseFailure(f"Not a valid setup.cfg: {clean(str(exc), 160)}") from exc

    def lines(value: str) -> list[str]:
        return [item.strip() for item in re.split(r"[\n;]" if "\n" in value else r";", value) if item.strip() and not item.strip().startswith("#")]

    if config.has_option("options", "install_requires"):
        _pep508_list(parsed, text, lines(config.get("options", "install_requires")), "pip", "runtime", label="[options].install_requires")
    if config.has_section("options.extras_require"):
        for extra, value in config.items("options.extras_require"):
            _pep508_list(parsed, text, lines(value), "pip", "optional", optional=True, label=f"[options.extras_require].{clean(extra, 60)}")
    return parsed


# --- Pipenv -----------------------------------------------------------------

def parse_pipfile(path: str, text: str) -> ParsedFile:
    data = _load_toml(text)
    parsed = ParsedFile(path=path, kind=MANIFEST, package_manager="pipenv", ecosystem=ECOSYSTEM)
    for section, scope in (("packages", "runtime"), ("dev-packages", "dev")):
        for name, spec in _table(data.get(section)).items():
            constraint, source, extras = None, None, ()
            if isinstance(spec, str):
                constraint = spec
            elif isinstance(spec, dict):
                constraint = spec.get("version") if isinstance(spec.get("version"), str) else None
                if isinstance(spec.get("extras"), list):
                    extras = tuple(sorted(str(x) for x in spec["extras"]))
                for kind in ("git", "path", "file"):
                    if isinstance(spec.get(kind), str):
                        source = {"type": "url" if kind == "file" else kind, "location": clean(_redact(spec[kind]), 300)}
            parsed.declared.append(Declared(
                ecosystem=ECOSYSTEM, package_manager="pipenv", name=str(name), source_file=path, line=find_line(text, str(name)),
                raw=clean(f"{name} = {json.dumps(spec, default=str)}"), constraint=constraint,
                exact_version=exact_from_specifier(constraint), scope=scope, extras=extras, source=source,
                reason=f"Declared in [{section}]",
            ))
    for src in data.get("source") or []:
        if isinstance(src, dict) and isinstance(src.get("url"), str):
            parsed.note(f"Package index {clean(_redact(src['url']), 200)} (recorded, never contacted)")
    return parsed


def parse_pipfile_lock(path: str, text: str) -> ParsedFile:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ParseFailure(f"Not valid JSON: {clean(str(exc), 160)}") from exc
    if not isinstance(data, dict):
        raise ParseFailure("Pipfile.lock must contain a JSON object")
    parsed = ParsedFile(path=path, kind=LOCKFILE, package_manager="pipenv", ecosystem=ECOSYSTEM)
    for section, dev in (("default", False), ("develop", True)):
        for name, entry in _table(data.get(section)).items():
            entry = _table(entry)
            version = exact_from_specifier(entry.get("version")) if isinstance(entry.get("version"), str) else None
            hashes = []
            for item in entry.get("hashes") or []:
                if isinstance(item, str) and ":" in item:
                    algorithm, _, digest = item.partition(":")
                    hashes.append({"algorithm": clean(algorithm, 20).lower(), "value": clean(digest, 200)})
            source = None
            for kind in ("git", "path", "file"):
                if isinstance(entry.get(kind), str):
                    source = {"type": "url" if kind == "file" else kind, "location": clean(_redact(entry[kind]), 300)}
            key = f"{section}:{normalize_name(ECOSYSTEM, str(name))}"
            parsed.locked.append(Locked(
                ecosystem=ECOSYSTEM, package_manager="pipenv", name=str(name), version=version, source_file=path, key=key,
                line=find_line(text, f'"{name}"'), dev=dev, scope_known=True, integrity=hashes[:MAX_INTEGRITY], source=source,
            ))
    return parsed


# --- Poetry lock ------------------------------------------------------------

def parse_poetry_lock(path: str, text: str) -> ParsedFile:
    data = _load_toml(text)
    parsed = ParsedFile(path=path, kind=LOCKFILE, package_manager="poetry", ecosystem=ECOSYSTEM, records_edges=True)
    legacy_files = _table(_table(data.get("metadata")).get("files"))
    packages = data.get("package")
    if not isinstance(packages, list):
        return parsed
    by_name: dict[str, list[Locked]] = {}
    pending: list[tuple[Locked, list[str]]] = []
    for entry in packages:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            continue
        name, version = entry["name"], entry.get("version") if isinstance(entry.get("version"), str) else None
        files = entry.get("files") if isinstance(entry.get("files"), list) else legacy_files.get(name, [])
        hashes = []
        for item in files if isinstance(files, list) else []:
            digest = item.get("hash") if isinstance(item, dict) else None
            if isinstance(digest, str) and ":" in digest:
                algorithm, _, value = digest.partition(":")
                hashes.append({"algorithm": clean(algorithm, 20).lower(), "value": clean(value, 200)})
        groups = entry.get("groups") if isinstance(entry.get("groups"), list) else None
        dev = entry.get("category") == "dev" or (groups is not None and "main" not in groups)
        src = _table(entry.get("source"))
        source = {"type": clean(src.get("type", "url"), 20), "location": clean(_redact(str(src.get("url", ""))), 300)} if src else None
        normalized = normalize_name(ECOSYSTEM, name)
        locked = Locked(
            ecosystem=ECOSYSTEM, package_manager="poetry", name=name, version=version, source_file=path,
            key=f"{normalized}@{version}", line=find_line(text, f'name = "{name}"'), dev=dev,
            scope_known=entry.get("category") is not None or groups is not None,
            optional=entry.get("optional") is True, integrity=hashes[:MAX_INTEGRITY], source=source,
        )
        parsed.locked.append(locked)
        by_name.setdefault(normalized, []).append(locked)
        pending.append((locked, [str(k) for k in _table(entry.get("dependencies"))]))
    for locked, names in pending:
        for dep in names:
            targets = by_name.get(normalize_name(ECOSYSTEM, dep), [])
            # With several locked versions of one name the file does not say which one is meant.
            locked.deps.append((dep, None, targets[0].key if len(targets) == 1 else None))
    return parsed
