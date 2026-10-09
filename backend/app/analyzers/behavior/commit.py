"""Analyses one commit: what it changed and which indicators that raises."""

from __future__ import annotations

from typing import Any

from app.analyzers.behavior.diff import parse_patch
from app.analyzers.behavior.security_changes import MAX_FINDINGS, OBSERVED, SEVERITY_RANK, _finding, classify_path, file_findings

LARGE_FILES, LARGE_LINES = 50, 2000          # a commit at or beyond either is a large changeset, whatever the repository's habits
MAX_FILES_LISTED = 300


def analyse_commit(detail: dict[str, Any]) -> dict[str, Any]:
    """Findings and statistics for a commit as returned by GitHubSession.commit_detail. Pure: no I/O, nothing executed."""
    files = detail.get("files") or []
    findings: list[dict[str, Any]] = []
    listed = []
    without_patch = truncated = manifests = lockfiles = 0
    for changed in files:
        parsed = parse_patch(changed.get("patch"))
        kinds = classify_path(changed["path"])
        manifests += kinds["manifest"]
        lockfiles += kinds["lockfile"]
        if not changed.get("patch_available"):
            without_patch += 1
        truncated += bool(changed.get("patch_truncated") or parsed["truncated"])
        findings += file_findings(changed, parsed)
        if len(listed) < MAX_FILES_LISTED:
            listed.append({"path": changed["path"], "status": changed.get("status"), "additions": changed.get("additions", 0),
                           "deletions": changed.get("deletions", 0), "previous_path": changed.get("previous_path"),
                           "diff_inspected": bool(changed.get("patch_available")), "diff_truncated": bool(changed.get("patch_truncated")),
                           "kinds": sorted(name for name, flag in kinds.items() if flag and name not in ("low_signal", "text_only"))})
    additions = detail.get("additions") if detail.get("additions") is not None else sum(f.get("additions", 0) for f in files)
    deletions = detail.get("deletions") if detail.get("deletions") is not None else sum(f.get("deletions", 0) for f in files)
    file_count = max(detail.get("files_listed") or 0, len(files))
    lines = additions + deletions
    if lockfiles and not manifests:
        findings.append(_finding("DEPENDENCY_CHANGE", "lockfile_changed_without_manifest", "MEDIUM", OBSERVED, 1.0,
                                 next(f["path"] for f in files if classify_path(f["path"])["lockfile"]),
                                 "A lockfile changed while no dependency manifest did: resolved versions or sources moved without a declared change."))
    if file_count >= LARGE_FILES or lines >= LARGE_LINES:
        findings.append(_finding("LARGE_CHANGESET", "large_changeset", "LOW", OBSERVED, 1.0, "",
                                 f"The commit changes {file_count} file(s) and {lines} line(s) (thresholds: {LARGE_FILES} files or {LARGE_LINES} lines)."))
    findings.sort(key=lambda item: (-SEVERITY_RANK[item["severity"]], item["type"], item["file"], item["line"] or 0, item["rule"]))
    dropped = max(0, len(findings) - MAX_FINDINGS)
    findings = findings[:MAX_FINDINGS]
    return {
        "findings": findings, "findings_dropped": dropped, "indicator_types": sorted({item["type"] for item in findings}),
        "files": listed, "stats": {"files": file_count, "additions": additions, "deletions": deletions, "lines": lines,
                                   "manifests": manifests, "lockfiles": lockfiles},
        "coverage": {"files_listed": file_count, "files_inspected": len(files) - without_patch, "files_without_diff": without_patch,
                     "files_not_listed": max(0, file_count - len(files)), "diffs_truncated": truncated,
                     "complete": without_patch == 0 and truncated == 0 and file_count <= len(files)},
    }
