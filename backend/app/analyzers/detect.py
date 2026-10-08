"""Language and package-manager detection from the repository file listing.

Detection uses only file paths and sizes from the snapshot. Vendored and
generated directories are ignored so that third-party code checked into the
repository is not mistaken for the project's own.
"""

from __future__ import annotations

import fnmatch
import posixpath
from dataclasses import dataclass
from typing import Any, Callable

from app.analyzers.model import INFERRED, LOCKFILE, MANIFEST, NOT_EVALUATED, OBSERVED, UNSUPPORTED, ParsedFile
from app.analyzers.parsers import cpp, go, java, javascript, python, rust

IGNORED_DIRS = {
    "node_modules", "vendor", "third_party", "third-party", "bower_components", ".git", "dist", "build", "out", "target",
    "venv", ".venv", "env", "site-packages", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".next", ".nuxt",
    "coverage", ".gradle", ".idea", ".vscode", "Pods",
}

EXTENSIONS: dict[str, str] = {
    ".py": "Python", ".pyi": "Python", ".pyx": "Python",
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript",
    ".java": "Java", ".go": "Go", ".rs": "Rust",
    ".c": "C", ".cpp": "C++", ".cc": "C++", ".cxx": "C++", ".hpp": "C++", ".hh": "C++", ".hxx": "C++",
    ".php": "PHP", ".rb": "Ruby", ".kt": "Kotlin", ".kts": "Kotlin", ".cs": "C#", ".swift": "Swift", ".scala": "Scala",
    ".sh": "Shell", ".bash": "Shell",
}
HEADER = ".h"
ECOSYSTEM_LANGUAGES = {
    "pypi": {"Python"}, "npm": {"JavaScript", "TypeScript"}, "maven": {"Java", "Kotlin", "Scala"}, "golang": {"Go"},
    "cargo": {"Rust"}, "vcpkg": {"C", "C++"}, "conan": {"C", "C++"}, "cmake": {"C", "C++"},
}
MAX_EVIDENCE = 5

Parser = Callable[[str, str], ParsedFile]


@dataclass(frozen=True)
class FileType:
    pattern: str
    package_manager: str
    ecosystem: str
    kind: str
    parser: Parser | None = None
    status: str | None = None        # set when the file is recognised but not parsed
    reason: str | None = None


FILE_TYPES: tuple[FileType, ...] = (
    FileType("requirements*.txt", "pip", "pypi", MANIFEST, python.parse_requirements),
    FileType("*requirements.txt", "pip", "pypi", MANIFEST, python.parse_requirements),
    FileType("requirements*.in", "pip", "pypi", MANIFEST, python.parse_requirements),
    FileType("pyproject.toml", "pip", "pypi", MANIFEST, python.parse_pyproject),
    FileType("setup.cfg", "pip", "pypi", MANIFEST, python.parse_setup_cfg),
    FileType("setup.py", "pip", "pypi", MANIFEST, None, NOT_EVALUATED, "setup.py is executable Python and is never run"),
    FileType("Pipfile", "pipenv", "pypi", MANIFEST, python.parse_pipfile),
    FileType("Pipfile.lock", "pipenv", "pypi", LOCKFILE, python.parse_pipfile_lock),
    FileType("poetry.lock", "poetry", "pypi", LOCKFILE, python.parse_poetry_lock),
    FileType("package.json", "npm", "npm", MANIFEST, javascript.parse_package_json),
    FileType("package-lock.json", "npm", "npm", LOCKFILE, javascript.parse_package_lock),
    FileType("npm-shrinkwrap.json", "npm", "npm", LOCKFILE, javascript.parse_package_lock),
    FileType("yarn.lock", "yarn", "npm", LOCKFILE, javascript.parse_yarn_lock),
    FileType("pnpm-lock.yaml", "pnpm", "npm", LOCKFILE, javascript.parse_pnpm_lock),
    FileType("pom.xml", "maven", "maven", MANIFEST, java.parse_pom),
    FileType("build.gradle", "gradle", "maven", MANIFEST, java.parse_gradle),
    FileType("build.gradle.kts", "gradle", "maven", MANIFEST, java.parse_gradle),
    FileType("gradle.lockfile", "gradle", "maven", LOCKFILE, java.parse_gradle_lockfile),
    FileType("go.mod", "go", "golang", MANIFEST, go.parse_go_mod),
    FileType("go.sum", "go", "golang", LOCKFILE, go.parse_go_sum),
    FileType("Cargo.toml", "cargo", "cargo", MANIFEST, rust.parse_cargo_toml),
    FileType("Cargo.lock", "cargo", "cargo", LOCKFILE, rust.parse_cargo_lock),
    FileType("vcpkg.json", "vcpkg", "vcpkg", MANIFEST, cpp.parse_vcpkg),
    FileType("conanfile.txt", "conan", "conan", MANIFEST, cpp.parse_conanfile_txt),
    FileType("conanfile.py", "conan", "conan", MANIFEST, None, NOT_EVALUATED, "conanfile.py is executable Python and is never run"),
    FileType("CMakeLists.txt", "cmake", "cmake", MANIFEST, cpp.parse_cmake),
    # Recognised, extraction not implemented.
    FileType("uv.lock", "uv", "pypi", LOCKFILE, None, UNSUPPORTED, "uv.lock extraction is not implemented"),
    FileType("pdm.lock", "pdm", "pypi", LOCKFILE, None, UNSUPPORTED, "pdm.lock extraction is not implemented"),
    FileType("bun.lockb", "bun", "npm", LOCKFILE, None, UNSUPPORTED, "bun.lockb is a binary format and is not read"),
    FileType("bun.lock", "bun", "npm", LOCKFILE, None, UNSUPPORTED, "bun.lock extraction is not implemented"),
    FileType("Gemfile", "bundler", "rubygems", MANIFEST, None, UNSUPPORTED, "Ruby (Bundler) extraction is not implemented"),
    FileType("Gemfile.lock", "bundler", "rubygems", LOCKFILE, None, UNSUPPORTED, "Ruby (Bundler) extraction is not implemented"),
    FileType("composer.json", "composer", "packagist", MANIFEST, None, UNSUPPORTED, "PHP (Composer) extraction is not implemented"),
    FileType("composer.lock", "composer", "packagist", LOCKFILE, None, UNSUPPORTED, "PHP (Composer) extraction is not implemented"),
    FileType("*.csproj", "nuget", "nuget", MANIFEST, None, UNSUPPORTED, ".NET (NuGet) extraction is not implemented"),
    FileType("packages.config", "nuget", "nuget", MANIFEST, None, UNSUPPORTED, ".NET (NuGet) extraction is not implemented"),
    FileType("Package.swift", "swiftpm", "swift", MANIFEST, None, UNSUPPORTED, "Swift Package Manager extraction is not implemented"),
    FileType("pubspec.yaml", "pub", "pub", MANIFEST, None, UNSUPPORTED, "Dart (pub) extraction is not implemented"),
    FileType("mix.exs", "mix", "hex", MANIFEST, None, UNSUPPORTED, "Elixir (Mix) extraction is not implemented"),
    FileType("build.sbt", "sbt", "maven", MANIFEST, None, UNSUPPORTED, "Scala (sbt) extraction is not implemented"),
)


REQUIREMENTS_FILE = FILE_TYPES[0]


def classify_file(path: str) -> FileType | None:
    name = posixpath.basename(path)
    for file_type in FILE_TYPES:
        if fnmatch.fnmatchcase(name, file_type.pattern):
            return file_type
    # requirements/base.txt, requirements/dev.txt ...
    if posixpath.basename(posixpath.dirname(path)) == "requirements" and name.endswith((".txt", ".in")):
        return REQUIREMENTS_FILE
    return None


def is_ignored(path: str) -> bool:
    return any(part in IGNORED_DIRS for part in path.split("/")[:-1])


def detect_manifests(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Dependency files in the listing, shallowest first, with the evidence that identified them."""
    found = []
    for entry in files:
        path = entry["path"]
        if is_ignored(path):
            continue
        file_type = classify_file(path)
        if file_type is None:
            continue
        found.append({
            "path": path, "size": entry.get("size"), "git_blob_sha": entry.get("sha"),
            "package_manager": file_type.package_manager, "ecosystem": file_type.ecosystem, "kind": file_type.kind,
            "parseable": file_type.parser is not None, "status": file_type.status, "reason": file_type.reason,
            "matched_pattern": file_type.pattern,
        })
    found.sort(key=lambda m: (m["path"].count("/"), m["path"]))
    return found


def detect_package_managers(manifests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for manifest in manifests:
        item = grouped.setdefault(manifest["package_manager"], {
            "package_manager": manifest["package_manager"], "ecosystem": manifest["ecosystem"], "basis": OBSERVED,
            "supported": False, "manifest_files": [], "lock_files": [],
        })
        item["supported"] = item["supported"] or manifest["parseable"]
        item["lock_files" if manifest["kind"] == LOCKFILE else "manifest_files"].append(manifest["path"])
    return sorted(grouped.values(), key=lambda p: p["package_manager"])


def detect_languages(files: list[dict[str, Any]], manifests: list[dict[str, Any]]) -> dict[str, Any]:
    """Languages by source bytes.

    Confidence rule (documented, not a probability):
      HIGH    at least 3 source files, or source files plus a dependency file of the matching ecosystem
      MEDIUM  1-2 source files and no matching dependency file
      LOW     only ambiguous evidence (.h headers attributed by the rule below)
    A ".h" header may be C or C++. Headers count as C++ when the repository has
    C++ sources and no C sources, otherwise as C; that attribution is INFERRED.
    """
    stats: dict[str, dict[str, Any]] = {}
    headers: list[dict[str, Any]] = []

    def add(language: str, entry: dict[str, Any], basis: str = OBSERVED) -> None:
        item = stats.setdefault(language, {"language": language, "files": 0, "bytes": 0, "evidence": [], "bases": set()})
        item["files"] += 1
        item["bytes"] += int(entry.get("size") or 0)
        item["evidence"].append((int(entry.get("size") or 0), entry["path"]))
        item["bases"].add(basis)

    for entry in files:
        path = entry["path"]
        if is_ignored(path) or path.endswith((".min.js", ".d.ts", ".bundle.js")):
            continue
        extension = posixpath.splitext(path)[1].lower()
        if extension == HEADER:
            headers.append(entry)
        elif extension in EXTENSIONS:
            add(EXTENSIONS[extension], entry)
    if headers:
        target = "C++" if "C++" in stats and "C" not in stats else "C"
        for entry in headers:
            add(target, entry, INFERRED)

    ecosystems = {m["ecosystem"] for m in manifests}
    backed = {language for eco in ecosystems for language in ECOSYSTEM_LANGUAGES.get(eco, set())}
    total = sum(item["bytes"] for item in stats.values())
    languages = []
    for item in stats.values():
        only_inferred = item["bases"] == {INFERRED}
        if only_inferred:
            confidence = "LOW"
        elif item["files"] >= 3 or item["language"] in backed:
            confidence = "HIGH"
        else:
            confidence = "MEDIUM"
        evidence = [path for _, path in sorted(item["evidence"], key=lambda e: (-e[0], e[1]))[:MAX_EVIDENCE]]
        languages.append({
            "language": item["language"], "files": item["files"], "bytes": item["bytes"],
            "share": round(item["bytes"] / total, 4) if total else 0.0, "confidence": confidence,
            "basis": INFERRED if only_inferred else OBSERVED, "evidence_files": evidence,
            "dependency_file_present": item["language"] in backed,
        })
    languages.sort(key=lambda l: (-l["bytes"], l["language"]))
    return {
        "languages": languages,
        "primary_language": languages[0]["language"] if languages else None,
        "method": "File extensions weighted by size in bytes; vendored and generated directories are excluded.",
    }
