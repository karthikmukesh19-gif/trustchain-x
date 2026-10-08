"""Java dependency files: pom.xml, build.gradle(.kts), gradle.lockfile."""

from __future__ import annotations

import re
from typing import Any
from xml.etree.ElementTree import Element, ParseError

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from app.analyzers.model import INFERRED, LOCKFILE, MANIFEST, OBSERVED, Declared, Locked, ParsedFile, ParseFailure, clean, find_line

ECOSYSTEM = "maven"
_PLACEHOLDER = re.compile(r"\$\{([^}]+)\}")
_COORD = re.compile(r"^[A-Za-z0-9_.-]+$")
_RANGE = re.compile(r"[\[\](),]")
SCOPES = {"compile": "runtime", "runtime": "runtime", "test": "test", "provided": "provided", "system": "provided", "import": "import"}


def _strip(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(node: Element | None, name: str) -> Element | None:
    if node is None:
        return None
    for child in node:
        if _strip(child.tag) == name:
            return child
    return None


def _children(node: Element | None) -> list[Element]:
    return list(node) if node is not None else []


def _text(node: Element | None, name: str) -> str | None:
    child = _child(node, name)
    return child.text.strip() if child is not None and child.text and child.text.strip() else None


def _substitute(value: str | None, properties: dict[str, str]) -> str | None:
    if value is None:
        return None
    for _ in range(5):
        replaced = _PLACEHOLDER.sub(lambda m: properties.get(m.group(1), m.group(0)), value)
        if replaced == value:
            break
        value = replaced
    return value


def parse_pom(path: str, text: str) -> ParsedFile:
    try:
        root = SafeET.fromstring(text.lstrip("﻿").encode("utf-8"), forbid_dtd=True)
    except (ParseError, DefusedXmlException, ValueError, RecursionError) as exc:
        raise ParseFailure(f"Not valid or not safe XML: {clean(type(exc).__name__ + ' ' + str(exc), 160)}") from exc
    if _strip(root.tag) != "project":
        raise ParseFailure("pom.xml must have a <project> root element")
    parsed = ParsedFile(path=path, kind=MANIFEST, package_manager="maven", ecosystem=ECOSYSTEM)

    parent = _child(root, "parent")
    properties: dict[str, str] = {}
    for key, value in (("project.groupId", _text(root, "groupId") or _text(parent, "groupId")),
                       ("project.version", _text(root, "version") or _text(parent, "version")),
                       ("project.parent.version", _text(parent, "version"))):
        if value:
            properties[key] = value
            properties[key.replace("project.", "pom.")] = value
    for prop in _children(_child(root, "properties")):
        if prop.text and prop.text.strip():
            properties[_strip(prop.tag)] = prop.text.strip()
    if parent is not None:
        parsed.note(f"Inherits from parent POM {clean(_text(parent, 'groupId'), 80)}:{clean(_text(parent, 'artifactId'), 80)}:{clean(_text(parent, 'version'), 40)}; "
                    "versions and dependencies defined there are not visible in this file")
    if _child(root, "modules") is not None:
        parsed.note("Multi-module build: each module's pom.xml is analysed separately")

    managed: dict[str, str] = {}
    for dep in _children(_child(_child(root, "dependencyManagement"), "dependencies")):
        group, artifact = _substitute(_text(dep, "groupId"), properties), _substitute(_text(dep, "artifactId"), properties)
        version = _substitute(_text(dep, "version"), properties)
        if group and artifact and version:
            managed[f"{group}:{artifact}"] = version
            if _text(dep, "scope") == "import":
                parsed.note(f"Imports BOM {clean(group, 80)}:{clean(artifact, 80)}:{clean(version, 40)}; versions it manages are not visible in this file")

    def collect(container: Element | None, label: str) -> None:
        for dep in _children(_child(container, "dependencies")):
            if _strip(dep.tag) != "dependency":
                continue
            group = _substitute(_text(dep, "groupId"), properties)
            artifact = _substitute(_text(dep, "artifactId"), properties)
            if not group or not artifact or not _COORD.match(group) or not _COORD.match(artifact):
                parsed.note(f"{label}: dependency with missing or unresolved coordinates ignored")
                continue
            name = f"{group}:{artifact}"
            declared_version = _text(dep, "version")
            version = _substitute(declared_version, properties)
            reason = f"Declared in {label}"
            exact, constraint = None, version
            if version is None:
                if name in managed:
                    version = managed[name]
                    reason += "; version from <dependencyManagement> in the same file"
                else:
                    reason += "; no version in this file (managed by a parent POM or BOM)"
            if version is not None:
                if _PLACEHOLDER.search(version):
                    reason += "; version uses a property that is not defined in this file"
                    constraint = version
                elif _RANGE.search(version):
                    constraint = version
                else:
                    exact, constraint = version, version
            scope = SCOPES.get((_text(dep, "scope") or "compile").lower(), "runtime")
            parsed.declared.append(Declared(
                ecosystem=ECOSYSTEM, package_manager="maven", name=name, source_file=path, line=find_line(text, artifact),
                raw=clean(f"{name}:{declared_version or '(no version)'}"), constraint=constraint, exact_version=exact, scope=scope,
                optional=(_text(dep, "optional") or "").lower() == "true", reason=reason,
            ))

    collect(root, "<dependencies>")
    for profile in _children(_child(root, "profiles")):
        collect(profile, f"<profile {clean(_text(profile, 'id') or '?', 40)}>")
    return parsed


# --- Gradle -----------------------------------------------------------------

CONFIGURATIONS = (
    "implementation|api|compileOnly|compileOnlyApi|runtimeOnly|annotationProcessor|kapt|ksp|classpath|compile|runtime|"
    "testImplementation|testApi|testCompileOnly|testRuntimeOnly|testAnnotationProcessor|testCompile|testRuntime|"
    "androidTestImplementation|debugImplementation|releaseImplementation|developmentOnly|integrationTestImplementation"
)
_GRADLE_STRING = re.compile(
    r"\b(?P<conf>" + CONFIGURATIONS + r")\b\s*\(?\s*(?:(?:enforcedPlatform|platform)\s*\(\s*)?"
    r"""['"](?P<group>[A-Za-z0-9_.-]+):(?P<artifact>[A-Za-z0-9_.-]+)(?::(?P<version>[^'":@\s]+))?(?:[:@][^'"]*)?['"]"""
)
_GRADLE_MAP = re.compile(
    r"\b(?P<conf>" + CONFIGURATIONS + r")\b\s*\(?\s*group\s*[:=]\s*['\"](?P<group>[A-Za-z0-9_.-]+)['\"]\s*,\s*"
    r"name\s*[:=]\s*['\"](?P<artifact>[A-Za-z0-9_.-]+)['\"](?:\s*,\s*version\s*[:=]\s*['\"](?P<version>[^'\"]+)['\"])?"
)
_GRADLE_CATALOG = re.compile(r"\b(?:" + CONFIGURATIONS + r")\b\s*\(?\s*(?:platform\s*\(\s*)?libs\.[A-Za-z0-9_.]+")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
GRADLE_REASON = (
    "Matched by pattern in a Gradle build script. The script is not evaluated, so variables, conditions, "
    "plugins and version catalogs are not applied."
)


def _gradle_scope(configuration: str) -> str:
    lowered = configuration.lower()
    if "test" in lowered:
        return "test"
    if configuration in {"annotationProcessor", "kapt", "ksp", "classpath"}:
        return "build"
    if configuration in {"compileOnly", "compileOnlyApi"}:
        return "provided"
    if configuration in {"developmentOnly", "debugImplementation"}:
        return "dev"
    return "runtime"


def parse_gradle(path: str, text: str) -> ParsedFile:
    parsed = ParsedFile(path=path, kind=MANIFEST, package_manager="gradle", ecosystem=ECOSYSTEM, reliable_manifest=False)
    # Blank out comments but keep line breaks so reported line numbers stay correct.
    body = _BLOCK_COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    body = "\n".join(re.sub(r"(?<![:'\"])//.*$", "", line) for line in body.splitlines())
    seen: set[tuple[str, str, str | None]] = set()
    for pattern in (_GRADLE_STRING, _GRADLE_MAP):
        for match in pattern.finditer(body):
            name = f"{match.group('group')}:{match.group('artifact')}"
            version = match.group("version")
            if (name, match.group("conf"), version) in seen:
                continue
            seen.add((name, match.group("conf"), version))
            dynamic = version is not None and ("$" in version or "+" in version or _RANGE.search(version) is not None)
            parsed.declared.append(Declared(
                ecosystem=ECOSYSTEM, package_manager="gradle", name=name, source_file=path,
                line=body.count("\n", 0, match.start()) + 1, raw=clean(match.group(0)), constraint=version,
                exact_version=None if dynamic else version, scope=_gradle_scope(match.group("conf")), basis=INFERRED,
                reason=GRADLE_REASON,
            ))
    catalog = len(_GRADLE_CATALOG.findall(body))
    if catalog:
        parsed.note(f"{catalog} dependency declaration(s) reference a version catalog (libs.*) and were not resolved")
    parsed.note("Gradle build scripts are code; dependencies were pattern-matched without evaluating the script")
    return parsed


def parse_gradle_lockfile(path: str, text: str) -> ParsedFile:
    parsed = ParsedFile(path=path, kind=LOCKFILE, package_manager="gradle", ecosystem=ECOSYSTEM)
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        coordinate, _, configurations = line.partition("=")
        parts = coordinate.split(":")
        if len(parts) != 3 or not all(_COORD.match(p) or (i == 2 and p) for i, p in enumerate(parts)):
            parsed.note(f"Line {number}: not a group:artifact:version entry")
            continue
        confs = [c for c in configurations.split(",") if c]
        parsed.locked.append(Locked(
            ecosystem=ECOSYSTEM, package_manager="gradle", name=f"{parts[0]}:{parts[1]}", version=clean(parts[2], 100),
            source_file=path, key=coordinate, line=number, dev=bool(confs) and all("test" in c.lower() for c in confs),
        ))
    return parsed
