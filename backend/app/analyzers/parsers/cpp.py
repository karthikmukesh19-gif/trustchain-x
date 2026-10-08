"""C / C++ dependency files: vcpkg.json, conanfile.txt, CMakeLists.txt."""

from __future__ import annotations

import json
import re

from app.analyzers.model import INFERRED, MANIFEST, Declared, ParsedFile, ParseFailure, clean, find_line

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,100}$")
_CMAKE_COMMENT = re.compile(r"#.*$", re.M)
_FIND_PACKAGE = re.compile(r"\bfind_package\s*\(\s*(?P<name>[A-Za-z0-9_.+-]+)(?P<rest>[^)]*)\)", re.I)
_FETCH = re.compile(r"\bFetchContent_Declare\s*\(\s*(?P<name>[A-Za-z0-9_.+-]+)(?P<rest>[^)]*)\)", re.I | re.S)
_VERSION = re.compile(r"^\d+(\.\d+){0,3}$")
CMAKE_REASON = "Matched by pattern in a CMake script. The script is not evaluated, so conditions and variables are not applied."


def parse_vcpkg(path: str, text: str) -> ParsedFile:
    try:
        data = json.loads(text.lstrip("﻿"))
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ParseFailure(f"Not valid JSON: {clean(str(exc), 160)}") from exc
    if not isinstance(data, dict):
        raise ParseFailure("vcpkg.json must contain a JSON object")
    parsed = ParsedFile(path=path, kind=MANIFEST, package_manager="vcpkg", ecosystem="vcpkg")
    overrides = {o["name"]: o.get("version") or o.get("version-string") or o.get("version-semver")
                 for o in data.get("overrides") or [] if isinstance(o, dict) and isinstance(o.get("name"), str)}
    for dep in data.get("dependencies") or []:
        body = dep if isinstance(dep, dict) else {"name": dep}
        name = body.get("name")
        if not isinstance(name, str) or not _NAME.match(name):
            parsed.note("A dependency entry without a valid name was ignored")
            continue
        minimum = body.get("version>=") if isinstance(body.get("version>="), str) else None
        override = overrides.get(name) if isinstance(overrides.get(name), str) else None
        parsed.declared.append(Declared(
            ecosystem="vcpkg", package_manager="vcpkg", name=name, source_file=path, line=find_line(text, f'"{name}"'),
            raw=clean(json.dumps(dep)), constraint=f"={override}" if override else (f">={minimum}" if minimum else None),
            exact_version=override, scope="build" if body.get("host") is True else "runtime",
            extras=tuple(sorted(str(f) for f in body.get("features") or [] if isinstance(f, str))),
            reason="Declared in dependencies" + ("; version pinned by overrides" if override else ""),
        ))
    if isinstance(data.get("builtin-baseline"), str):
        parsed.note(f"builtin-baseline {clean(data['builtin-baseline'], 60)}: unpinned versions come from that vcpkg registry commit")
    return parsed


def parse_conanfile_txt(path: str, text: str) -> ParsedFile:
    parsed = ParsedFile(path=path, kind=MANIFEST, package_manager="conan", ecosystem="conan")
    section = None
    scopes = {"requires": "runtime", "tool_requires": "build", "build_requires": "build", "test_requires": "test"}
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.split("#", 1)[0].strip() if not line.strip().startswith("#") else ""
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if section not in scopes:
            continue
        reference = line.split("@", 1)[0]
        name, _, version = reference.partition("/")
        if not _NAME.match(name):
            parsed.note(f"Line {number}: not a name/version reference")
            continue
        version = version.strip() or None
        is_range = version is not None and version.startswith("[")
        parsed.declared.append(Declared(
            ecosystem="conan", package_manager="conan", name=name, source_file=path, line=number, raw=clean(line),
            constraint=version, exact_version=None if is_range or version is None else version, scope=scopes[section],
            reason=f"Declared in [{section}]",
        ))
    return parsed


def parse_cmake(path: str, text: str) -> ParsedFile:
    parsed = ParsedFile(path=path, kind=MANIFEST, package_manager="cmake", ecosystem="cmake", reliable_manifest=False)
    body = _CMAKE_COMMENT.sub("", text)
    seen: set[str] = set()
    for match in _FIND_PACKAGE.finditer(body):
        name = match.group("name")
        if "$" in name or name.lower() in seen:
            continue
        seen.add(name.lower())
        words = match.group("rest").split()
        version = words[0] if words and _VERSION.match(words[0]) else None
        parsed.declared.append(Declared(
            ecosystem="cmake", package_manager="cmake", name=name, source_file=path, line=body.count("\n", 0, match.start()) + 1,
            raw=clean(match.group(0)), constraint=f">={version}" if version else None,
            optional="REQUIRED" not in (w.upper() for w in words), basis=INFERRED,
            reason=CMAKE_REASON + " find_package() locates a package already installed on the build machine.",
        ))
    for match in _FETCH.finditer(body):
        name = match.group("name")
        if "$" in name or name.lower() in seen:
            continue
        seen.add(name.lower())
        words = match.group("rest").split()
        options = {words[i].upper(): words[i + 1] for i in range(len(words) - 1)}
        location = options.get("GIT_REPOSITORY") or options.get("URL")
        tag = options.get("GIT_TAG")
        parsed.declared.append(Declared(
            ecosystem="cmake", package_manager="cmake", name=name, source_file=path, line=body.count("\n", 0, match.start()) + 1,
            raw=clean(" ".join(match.group(0).split())), constraint=clean(tag, 100) if tag and "$" not in tag else None,
            source={"type": "git" if "GIT_REPOSITORY" in options else "url", "location": clean(re.sub(r"(?<=://)[^/@\s]+@", "***@", location), 300)} if location and "$" not in location else None,
            basis=INFERRED, reason=CMAKE_REASON + " FetchContent downloads this source at configure time.",
        ))
    parsed.note("CMake scripts are code; dependencies were pattern-matched without evaluating the script")
    return parsed
