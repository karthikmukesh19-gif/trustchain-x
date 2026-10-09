"""Reads the unified-diff text of one changed file. The text is data: it is split into lines and never interpreted as code."""

from __future__ import annotations

import re
from typing import Any

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
MAX_LINES = 20_000          # diff lines read per file
MAX_LINE_LENGTH = 2_000     # characters kept of one line; the full length is still recorded


def parse_patch(patch: str | None) -> dict[str, Any]:
    """Added and removed lines with their line numbers: {"added": [(n, text, length)], "removed": [...], "hunks", "truncated"}.

    Added lines are numbered as in the new file, removed lines as in the old
    one. Lines outside a hunk are ignored. A missing patch (binary file, or a
    diff too large for GitHub to include) gives empty lists.
    """
    result: dict[str, Any] = {"added": [], "removed": [], "hunks": 0, "truncated": False}
    if not isinstance(patch, str) or not patch:
        return result
    old_line = new_line = 0
    in_hunk = False
    for count, raw in enumerate(patch.split("\n")):
        if count >= MAX_LINES:
            result["truncated"] = True
            break
        header = _HUNK.match(raw)
        if header:
            old_line, new_line, in_hunk = int(header.group(1)), int(header.group(3)), True
            result["hunks"] += 1
            continue
        if not in_hunk or raw.startswith("\\"):          # "\ No newline at end of file"
            continue
        if raw.startswith("+"):
            result["added"].append((new_line, raw[1:1 + MAX_LINE_LENGTH], len(raw) - 1))
            new_line += 1
        elif raw.startswith("-"):
            result["removed"].append((old_line, raw[1:1 + MAX_LINE_LENGTH], len(raw) - 1))
            old_line += 1
        else:
            old_line += 1
            new_line += 1
    return result
