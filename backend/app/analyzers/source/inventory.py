"""Choose which files of a repository snapshot are analysed as source code.

Works only on the snapshot's file listing (path, size, git blob id). Nothing is
read here; the caller fetches the selected files by blob id.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass
from typing import Any

from app.analyzers.detect import EXTENSIONS
from app.analyzers.source.base import SourceAnalyzer
from app.collectors.github import safe_repository_path

SELECTED = "SELECTED"
SKIPPED_IGNORED_DIRECTORY = "SKIPPED_IGNORED_DIRECTORY"   # vendored, generated or build output, by directory name
SKIPPED_GENERATED = "SKIPPED_GENERATED"                   # generated code, by file name
SKIPPED_TOO_LARGE = "SKIPPED_TOO_LARGE"                   # one file above the per-file limit
SKIPPED_FILE_LIMIT = "SKIPPED_FILE_LIMIT"                 # more source files than the limit
SKIPPED_SIZE_LIMIT = "SKIPPED_SIZE_LIMIT"                 # total source size above the limit
SKIPPED_UNSAFE_PATH = "SKIPPED_UNSAFE_PATH"
SKIPPED_UNSUPPORTED_FORMAT = "SKIPPED_UNSUPPORTED_FORMAT"  # code of a supported language in a form that is not parsed (notebooks, Cython)
# Skips that leave application code unread, so that "no path found" cannot be concluded.
INCOMPLETE_REASONS = (SKIPPED_TOO_LARGE, SKIPPED_FILE_LIMIT, SKIPPED_SIZE_LIMIT, SKIPPED_UNSAFE_PATH, SKIPPED_UNSUPPORTED_FORMAT)

# Directories that hold other people's code or caches, never the application's own source. Deliberately
# narrower than the list used for language statistics: "build", "dist", "env" or "out" can be real packages,
# and skipping application code silently would make "no path found" wrong.
IGNORED_DIRS = frozenset({
    "node_modules", "vendor", "third_party", "third-party", "bower_components", ".git", "venv", ".venv", "site-packages",
    "__pycache__", ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".eggs", "Pods",
})
# Code of an analysed language that the analyzer cannot read. Stub files (.pyi) contain no calls and are left out.
UNPARSED_FORMATS = {".ipynb": "python", ".pyx": "python"}

_GENERATED_SUFFIXES = ("_pb2.py", "_pb2_grpc.py")
_TEST_DIRECTORIES = {"tests", "test", "testing"}


@dataclass(frozen=True)
class InventoryLimits:
    max_files: int
    max_file_bytes: int
    max_total_bytes: int


def is_test_path(path: str) -> bool:
    parts = path.split("/")
    name = parts[-1]
    return any(part in _TEST_DIRECTORIES for part in parts[:-1]) or name.startswith("test_") or name.endswith("_test.py") \
        or name == "conftest.py"


def select(files: list[dict[str, Any]], analyzers: dict[str, SourceAnalyzer], limits: InventoryLimits) -> dict[str, Any]:
    """Return {"entries": [...], "other_languages": {language: files}} for a snapshot's file listing.

    When there are more source files than the limits allow, application code is
    preferred over tests and shallow paths over deep ones; the order is
    deterministic, and everything left out is listed with the reason.
    """
    by_extension = {extension: analyzer for analyzer in analyzers.values() for extension in analyzer.extensions}
    entries: list[dict[str, Any]] = []
    other: dict[str, int] = {}
    for item in files:
        path = item.get("path")
        extension = posixpath.splitext(path)[1].lower() if isinstance(path, str) else ""
        analyzer = by_extension.get(extension)
        if analyzer is None and UNPARSED_FORMATS.get(extension) in analyzers and safe_repository_path(path) \
                and not any(part in IGNORED_DIRS for part in path.split("/")[:-1]):
            entries.append({"path": path, "language": UNPARSED_FORMATS[extension], "size": int(item.get("size") or 0),
                            "git_blob_sha": item.get("sha"), "is_test": is_test_path(path), "selection": SKIPPED_UNSUPPORTED_FORMAT})
            continue
        if analyzer is None:
            language = EXTENSIONS.get(extension)
            if language and language.lower() not in analyzers and isinstance(path, str) \
                    and not any(part in IGNORED_DIRS for part in path.split("/")[:-1]):
                other[language] = other.get(language, 0) + 1
            continue
        entry = {"path": path, "language": analyzer.language, "size": int(item.get("size") or 0), "git_blob_sha": item.get("sha"),
                 "is_test": False, "selection": SELECTED}
        if not safe_repository_path(path) or not isinstance(item.get("sha"), str):
            entry["selection"] = SKIPPED_UNSAFE_PATH
        else:
            entry["is_test"] = is_test_path(path)
            if any(part in IGNORED_DIRS for part in path.split("/")[:-1]):
                entry["selection"] = SKIPPED_IGNORED_DIRECTORY
            elif path.endswith(_GENERATED_SUFFIXES):
                entry["selection"] = SKIPPED_GENERATED
            elif entry["size"] > limits.max_file_bytes:
                entry["selection"] = SKIPPED_TOO_LARGE
        entries.append(entry)

    candidates = sorted((e for e in entries if e["selection"] == SELECTED),
                        key=lambda e: (e["is_test"], e["path"].count("/"), e["path"]))
    total = 0
    for position, entry in enumerate(candidates):
        if position >= limits.max_files:
            entry["selection"] = SKIPPED_FILE_LIMIT
        elif total + entry["size"] > limits.max_total_bytes:
            entry["selection"] = SKIPPED_SIZE_LIMIT
        else:
            total += entry["size"]
    entries.sort(key=lambda e: str(e["path"]))
    return {"entries": entries, "other_languages": dict(sorted(other.items()))}
