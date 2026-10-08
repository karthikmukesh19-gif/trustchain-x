"""Which functions or classes of a package an advisory names as affected.

Two sources are accepted, and nothing else:

  ADVISORY            fields of the advisory record itself:
                        affected[].ecosystem_specific.affected_functions   ["pkg.module.function", ...]
                        affected[].ecosystem_specific.imports[]            {"path": "pkg.module", "symbols": ["Class.method"]}
                      (and the same keys under database_specific)
  OPERATOR_SUPPLIED   an entry in the installation's own mapping file. Each entry must
                      name the advisory, the package, the symbols and an https source
                      URL that justifies them. The file ships empty.

When neither yields a symbol the result is SYMBOL_MAPPING_UNKNOWN. A symbol is
never derived from an advisory's title, description, references or patch.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from app.analyzers.normalize import normalize_name

ADVISORY = "ADVISORY"
OPERATOR_SUPPLIED = "OPERATOR_SUPPLIED"
SYMBOL_MAPPING_UNKNOWN = "SYMBOL_MAPPING_UNKNOWN"

EXACT = "EXACT"                 # the observed name is the affected name, or lies inside it
NAME = "NAME"                   # same package and same trailing name, different module path (possibly a re-export)

MAX_SYMBOLS = 200
MAX_MAPPING_BYTES = 2 * 1024 * 1024
_SYMBOL = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*){0,15}")
_ADVISORY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}")
_ECOSYSTEMS = {"pypi": "pypi"}                 # OSV ecosystem name (lower case) -> platform ecosystem


@dataclass(frozen=True)
class AffectedSymbol:
    symbol: str                 # dotted, as published: package.module.function or package.module.Class.method
    module_only: bool           # the source names a module, not a function: anything inside it counts
    source: str                 # ADVISORY | OPERATOR_SUPPLIED
    origin: str                 # the advisory field, or the operator entry's source URL
    note: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"symbol": self.symbol, "module_only": self.module_only, "source": self.source, "origin": self.origin, "note": self.note}


def _valid(symbol: Any) -> str | None:
    if isinstance(symbol, str):
        symbol = symbol.strip().replace(":", ".")
        if len(symbol) <= 200 and _SYMBOL.fullmatch(symbol):
            return symbol
    return None


def from_advisory(raw: Any, ecosystem: str, normalized_name: str) -> list[AffectedSymbol]:
    """Affected symbols published in an advisory record for one package. Empty when it publishes none."""
    found: dict[str, AffectedSymbol] = {}
    affected = raw.get("affected") if isinstance(raw, dict) else None
    for entry in affected if isinstance(affected, list) else []:
        package = entry.get("package") if isinstance(entry, dict) else None
        if not isinstance(package, dict) or not isinstance(package.get("name"), str) or not isinstance(package.get("ecosystem"), str):
            continue
        if _ECOSYSTEMS.get(package["ecosystem"].split(":", 1)[0].lower()) != ecosystem \
                or normalize_name(ecosystem, package["name"]) != normalized_name:
            continue
        for key in ("ecosystem_specific", "database_specific"):
            specific = entry.get(key)
            if not isinstance(specific, dict):
                continue
            functions = specific.get("affected_functions")
            for item in functions if isinstance(functions, list) else []:
                symbol = _valid(item)
                if symbol and len(found) < MAX_SYMBOLS:
                    found.setdefault(symbol, AffectedSymbol(symbol, False, ADVISORY, f"affected[].{key}.affected_functions"))
            imports = specific.get("imports")
            for item in imports if isinstance(imports, list) else []:
                path = _valid(item.get("path")) if isinstance(item, dict) else None
                if not path:
                    continue
                names = item.get("symbols")
                names = [n for n in (_valid(x) for x in names)] if isinstance(names, list) else []
                names = [n for n in names if n]
                if not names and len(found) < MAX_SYMBOLS:
                    found.setdefault(path, AffectedSymbol(path, True, ADVISORY, f"affected[].{key}.imports[].path"))
                for name in names:
                    if len(found) < MAX_SYMBOLS:
                        found.setdefault(f"{path}.{name}", AffectedSymbol(f"{path}.{name}", False, ADVISORY, f"affected[].{key}.imports[].symbols"))
    return sorted(found.values(), key=lambda s: s.symbol)


def load_operator_mappings(path: str | Path | None) -> tuple[list[dict[str, Any]], list[str]]:
    """Read the operator's mapping file. Returns (valid entries, problems). A missing file is an empty mapping."""
    if not path:
        return [], []
    file = Path(path)
    try:
        if not file.is_file():
            return [], []
        if file.stat().st_size > MAX_MAPPING_BYTES:
            return [], ["The symbol mapping file is too large and was ignored."]
        data = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [], [f"The symbol mapping file could not be read ({type(exc).__name__}) and was ignored."]
    items = data.get("mappings") if isinstance(data, dict) else data
    if not isinstance(items, list):
        return [], ["The symbol mapping file must contain a list of mappings and was ignored."]
    entries: list[dict[str, Any]] = []
    problems: list[str] = []
    for position, item in enumerate(items[:5000]):
        problem = _mapping_problem(item)
        if problem:
            problems.append(f"Mapping {position + 1} was ignored: {problem}")
            continue
        symbols = [_valid(s) for s in item["symbols"]]
        entries.append({
            "advisory_ids": [item["advisory_id"], *[a for a in item.get("aliases", []) if isinstance(a, str) and _ADVISORY_ID.fullmatch(a)]],
            "ecosystem": item["ecosystem"].lower(), "package": normalize_name(item["ecosystem"].lower(), item["package"]),
            "symbols": [s for s in symbols if s][:MAX_SYMBOLS], "source_url": item["source_url"],
            "note": item["note"][:300] if isinstance(item.get("note"), str) else None,
        })
    return entries, problems[:50]


def _mapping_problem(item: Any) -> str | None:
    if not isinstance(item, dict):
        return "it is not an object"
    if not isinstance(item.get("advisory_id"), str) or not _ADVISORY_ID.fullmatch(item["advisory_id"]):
        return "advisory_id is missing or not a valid advisory id"
    if not isinstance(item.get("ecosystem"), str) or item["ecosystem"].lower() not in _ECOSYSTEMS:
        return "ecosystem is missing or not supported"
    if not isinstance(item.get("package"), str) or not item["package"].strip() or len(item["package"]) > 200:
        return "package is missing"
    symbols = item.get("symbols")
    if not isinstance(symbols, list) or not symbols or not all(_valid(s) for s in symbols):
        return "symbols must be a non-empty list of dotted names such as package.module.function"
    url = item.get("source_url")
    if not isinstance(url, str) or len(url) > 500:
        return "source_url is missing"
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        return "source_url must be an https URL that justifies the mapping"
    return None


def from_operator(mappings: list[dict[str, Any]], advisory_ids: list[str], ecosystem: str, normalized_name: str) -> list[AffectedSymbol]:
    wanted = set(advisory_ids)
    found: dict[str, AffectedSymbol] = {}
    for entry in mappings:
        if entry["ecosystem"] == ecosystem and entry["package"] == normalized_name and wanted & set(entry["advisory_ids"]):
            for symbol in entry["symbols"]:
                found.setdefault(symbol, AffectedSymbol(symbol, False, OPERATOR_SUPPLIED, entry["source_url"], entry["note"]))
    return sorted(found.values(), key=lambda s: s.symbol)


def match(affected: AffectedSymbol, observed: str) -> str | None:
    """How an observed dotted name (for example requests.get) corresponds to an affected symbol, if it does."""
    wanted, seen = affected.symbol.split("."), observed.split(".")
    if seen[: len(wanted)] == wanted:
        return EXACT                                   # the symbol itself, or a member of it (a method of an affected class)
    if affected.module_only:
        return None
    if wanted[0] != seen[0] or len(seen) < 2:
        return None
    # Packages re-export names (requests.get is requests.api.get). The module path may differ; the name may not.
    # A top-level name can only stand for a module-level function or class, so the affected name's
    # parent must look like a module (lower-case), not a class.
    if len(seen) == 2 and seen[-1] == wanted[-1] and (len(wanted) == 2 or not wanted[-2][:1].isupper()):
        return NAME
    if len(seen) >= 3 and len(wanted) >= 3 and seen[-2:] == wanted[-2:]:
        return NAME
    return None
