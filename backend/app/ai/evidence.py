"""Evidence references: the only things a finding may rest on.

An evidence item is a pointer to a stored record (collection and id) with a
one-line summary of what that record says and how it is known (its basis).
Findings cite evidence by id. `validate` refuses any finding whose citations
do not resolve, so a statement without a source cannot be stored.
"""

from __future__ import annotations

import re
from typing import Any

OBSERVED, DERIVED, INFERRED, PREDICTED, RECOMMENDED = "OBSERVED", "DERIVED", "INFERRED", "PREDICTED", "RECOMMENDED"
BASES = (OBSERVED, DERIVED, INFERRED, PREDICTED)
STATEMENT_BASES = (OBSERVED, DERIVED, PREDICTED, RECOMMENDED)
# Phrases that assert a source. They are only acceptable in a statement that actually cites one.
_SOURCE_CLAIM = re.compile(r"\b(according to|as reported by|sources? (say|says|indicate|indicates|confirm|confirms)|studies show|it is known that)\b", re.I)
_CITATION = re.compile(r"\[(E\d+)\]")


class EvidenceStore:
    """Evidence gathered for one reasoning run. Ids are assigned in insertion order, so the same context gives the same ids."""

    def __init__(self) -> None:
        self._items: dict[str, dict[str, Any]] = {}
        self._by_key: dict[tuple[str, str, str], str] = {}

    def add(self, *, layer: str, collection: str, record_id: Any, basis: str, summary: str, subject: str | None = None,
            as_of: Any = None, confidence: float | None = None) -> str:
        if basis not in BASES:
            raise ValueError(f"unknown evidence basis {basis!r}")
        key = (layer, collection, f"{record_id}|{subject or ''}|{summary}")
        known = self._by_key.get(key)
        if known is not None:
            return known
        identifier = f"E{len(self._items) + 1}"
        self._items[identifier] = {"ref": identifier, "layer": layer, "collection": collection, "record_id": record_id, "basis": basis,
                                   "summary": summary[:400], "subject": subject, "as_of": as_of, "confidence": confidence}
        self._by_key[key] = identifier
        return identifier

    def get(self, identifier: str) -> dict[str, Any] | None:
        return self._items.get(identifier)

    def resolve(self, identifiers: list[str]) -> list[dict[str, Any]]:
        return [self._items[identifier] for identifier in identifiers if identifier in self._items]

    def __contains__(self, identifier: object) -> bool:
        return identifier in self._items

    def __len__(self) -> int:
        return len(self._items)

    def ids(self) -> list[str]:
        return list(self._items)


def cited(text: str) -> list[str]:
    """Evidence ids cited in a text as [E1], [E2], ..."""
    return _CITATION.findall(text or "")


def validate(finding: dict[str, Any], store: EvidenceStore) -> list[str]:
    """Every reason a finding is not grounded. An empty list means it may be stored."""
    problems: list[str] = []
    refs = finding.get("evidence_refs") or []
    if not refs:
        problems.append("The finding cites no evidence.")
    unknown = [ref for ref in refs if ref not in store]
    if unknown:
        problems.append(f"The finding cites evidence that does not exist: {', '.join(unknown[:5])}.")
    statements = finding.get("statements") or []
    if not statements:
        problems.append("The finding makes no statement.")
    for position, statement in enumerate(statements, start=1):
        basis, cites = statement.get("basis"), statement.get("evidence_refs") or []
        if basis not in STATEMENT_BASES:
            problems.append(f"Statement {position} has no valid basis.")
        if not cites:
            problems.append(f"Statement {position} cites no evidence.")
        if any(ref not in refs for ref in cites):
            problems.append(f"Statement {position} cites evidence outside the finding's evidence list.")
        if _SOURCE_CLAIM.search(statement.get("text") or "") and not cites:
            problems.append(f"Statement {position} refers to a source without citing one.")
        if basis == OBSERVED and any((store.get(ref) or {}).get("basis") != OBSERVED for ref in cites if ref in store):
            problems.append(f"Statement {position} is presented as observed but rests on evidence that is not.")
    recommendation = finding.get("recommendation") or {}
    if recommendation and recommendation.get("basis") != RECOMMENDED:
        problems.append("The recommendation is not marked as a recommendation.")
    if recommendation and not recommendation.get("evidence_refs"):
        problems.append("The recommendation cites no evidence.")
    layers = {(store.get(ref) or {}).get("layer") for ref in refs if ref in store}
    if set(finding.get("contributing_layers") or []) - layers:
        problems.append("The finding names a contributing layer it cites no evidence from.")
    for ref in cited(finding.get("explanation") or ""):
        if ref not in refs:
            problems.append(f"The explanation cites {ref}, which is not in the finding's evidence list.")
    if _SOURCE_CLAIM.search(finding.get("explanation") or "") and not cited(finding.get("explanation") or ""):
        problems.append("The explanation refers to a source without citing one.")
    return problems


def grounding(findings: list[dict[str, Any]], store: EvidenceStore, rejected: int = 0) -> dict[str, Any]:
    """How well a set of findings is tied to evidence. Measured, not assumed.

      evidence_grounding      share of statements that cite at least one existing evidence item
      unsupported_claim_rate  share of statements that cite none
      evidence_coverage       share of the gathered evidence that at least one finding uses
    """
    statements = [statement for finding in findings for statement in finding.get("statements") or []]
    grounded = sum(1 for statement in statements if any(ref in store for ref in statement.get("evidence_refs") or []))
    used = {ref for finding in findings for ref in finding.get("evidence_refs") or [] if ref in store}
    return {
        "findings": len(findings), "statements": len(statements), "grounded_statements": grounded,
        "evidence_grounding": round(grounded / len(statements), 4) if statements else None,
        "unsupported_claim_rate": round(1 - grounded / len(statements), 4) if statements else None,
        "evidence_items": len(store), "evidence_used": len(used),
        "evidence_coverage": round(len(used) / len(store), 4) if len(store) else None, "findings_rejected": rejected,
    }
