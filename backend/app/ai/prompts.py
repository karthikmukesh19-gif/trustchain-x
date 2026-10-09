"""Prompts for a language-model provider, when one is configured.

The model is asked to rephrase a finding the rules already produced. It is
given that finding's statements and the evidence they cite, and nothing
else: no repository content, no other findings, no room to add facts. Its
answer is checked by `provider.guard` before it is used.
"""

from __future__ import annotations

from typing import Any

SYSTEM_RULES = """You explain software supply-chain security findings.

Rules you must follow:
1. Use only the evidence items given to you. Do not add facts, numbers, package names, versions, identifiers or causes that are not in them.
2. Cite evidence by its id in square brackets, like [E3], after each sentence that relies on it. Every sentence needs at least one citation.
3. Keep the given distinction between OBSERVED, DERIVED, PREDICTED and RECOMMENDED statements. Never present a derived or predicted statement as observed.
4. Do not say or imply that an attack happened, will happen or would succeed, that something is exploitable, or that any person acted with bad intent.
5. Do not write "according to the source" or similar unless the sentence cites an evidence id.
6. If the evidence does not support a statement, leave the statement out."""


def explanation_prompt(finding: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, str]:
    """The (system, user) prompt asking for a plain-language explanation of one finding."""
    lines = [f"Finding category: {finding['category']}", f"Severity: {finding['severity']}", f"Confidence: {finding['confidence']}", "",
             "Statements (basis in capitals, then the text, then the evidence it rests on):"]
    for item in finding["statements"]:
        lines.append(f"- {item['basis']}: {item['text']} {' '.join(f'[{ref}]' for ref in item['evidence_refs'])}")
    recommendation = finding["recommendation"]
    lines += ["", f"- RECOMMENDED: {recommendation['text']} {' '.join(f'[{ref}]' for ref in recommendation['evidence_refs'])}", "", "Evidence:"]
    for item in evidence:
        lines.append(f"[{item['ref']}] ({item['basis']}, {item['layer']}) {item['summary']}")
    lines += ["", "Write a short explanation (at most 120 words) of what was found and why it matters, following the rules."]
    return {"system": SYSTEM_RULES, "user": "\n".join(lines)}
