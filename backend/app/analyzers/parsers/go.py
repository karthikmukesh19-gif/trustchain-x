"""Go dependency files: go.mod and go.sum."""

from __future__ import annotations

import re

from app.analyzers.model import DIRECT, LOCKFILE, MANIFEST, OBSERVED, TRANSITIVE, Declared, ParsedFile, clean

ECOSYSTEM = "golang"
_MODULE = re.compile(r"^[A-Za-z0-9._~/-]+$")
_VERSION = re.compile(r"^v\d+\.\d+\.\d+[A-Za-z0-9.+-]*$")


def _strip_comment(line: str) -> tuple[str, str]:
    code, _, comment = line.partition("//")
    return code.strip(), comment.strip()


def parse_go_mod(path: str, text: str) -> ParsedFile:
    parsed = ParsedFile(path=path, kind=MANIFEST, package_manager="go", ecosystem=ECOSYSTEM)
    block: str | None = None
    requires: dict[str, Declared] = {}
    replaces: list[tuple[str, str]] = []
    go_version: tuple[int, ...] | None = None

    def add_require(fields: list[str], comment: str, number: int, raw: str) -> None:
        if len(fields) < 2 or not _MODULE.match(fields[0]) or not _VERSION.match(fields[1]):
            parsed.note(f"Line {number}: not a 'module version' requirement")
            return
        indirect = "indirect" in comment.split()
        requires[fields[0]] = Declared(
            ecosystem=ECOSYSTEM, package_manager="go", name=fields[0], source_file=path, line=number, raw=clean(raw),
            constraint=fields[1], exact_version=fields[1],
            relationship=TRANSITIVE if indirect else DIRECT, basis=OBSERVED,
            reason="Marked '// indirect' in go.mod; go.mod does not record which module requires it" if indirect
            else "Required in go.mod without an '// indirect' marker",
        )

    for number, line in enumerate(text.splitlines(), start=1):
        code, comment = _strip_comment(line)
        if not code:
            continue
        if block is not None:
            if code == ")":
                block = None
            elif block == "require":
                add_require(code.split(), comment, number, line)
            elif block == "replace" and "=>" in code:
                old, _, new = code.partition("=>")
                replaces.append((old.strip(), new.strip()))
            continue
        fields = code.split()
        keyword = fields[0]
        if len(fields) >= 2 and fields[1] == "(":
            block = keyword
        elif keyword == "require":
            add_require(fields[1:], comment, number, line)
        elif keyword == "replace" and "=>" in code:
            old, _, new = code[len("replace"):].partition("=>")
            replaces.append((old.strip(), new.strip()))
        elif keyword == "go" and len(fields) >= 2:
            try:
                go_version = tuple(int(p) for p in fields[1].split(".")[:2])
            except ValueError:
                go_version = None
        elif keyword == "module" and len(fields) >= 2:
            parsed.note(f"Module {clean(fields[1].strip('\"'), 200)}")

    for old, new in replaces:
        module = old.split()[0] if old.split() else ""
        target = requires.get(module)
        if target is not None:
            local = new.startswith((".", "/")) or (len(new) > 1 and new[1] == ":")
            target.source = {"type": "path" if local else "replace", "location": clean(new, 300)}
            target.reason += f"; replaced by '{clean(new, 120)}'"
    if go_version is not None and go_version < (1, 17):
        parsed.note("go directive is older than 1.17: go.mod then lists only some indirect requirements, so the transitive set is incomplete")
    parsed.declared = list(requires.values())
    return parsed


def parse_go_sum(path: str, text: str) -> ParsedFile:
    """go.sum holds checksums for every module version Go ever examined, including ones the build
    does not use. It is therefore used only to attach hashes to modules required in go.mod."""
    parsed = ParsedFile(path=path, kind=LOCKFILE, package_manager="go", ecosystem=ECOSYSTEM)
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 3 or fields[1].endswith("/go.mod"):
            continue
        algorithm, _, digest = fields[2].partition(":")
        if _MODULE.match(fields[0]) and digest:
            parsed.integrity_index[(fields[0], fields[1])] = {"algorithm": clean(algorithm, 10), "value": clean(digest, 120)}
    parsed.note(f"{len(parsed.integrity_index)} module checksums; used for integrity only, not as a dependency list")
    return parsed
