"""Reasoning providers: who phrases a finding's explanation.

The built-in provider is deterministic: it joins the finding's own
statements, each followed by its citations. A language-model provider can
implement the same interface; the platform then treats its output as
untrusted text and keeps it only if `guard` accepts it. Without an external
provider nothing leaves the platform and no API key is needed.
"""

from __future__ import annotations

import re
from typing import Any, Protocol

from app.ai import evidence as evidence_rules
from app.ai.prompts import explanation_prompt

_OVERCLAIM = re.compile(r"\b(exploit(ed|able)?\s+(is\s+)?confirmed|will be (exploited|attacked|compromised)|guarantee[ds]?|"
                        r"malicious (maintainer|author|contributor|developer|person)|zero[- ]day)\b", re.I)
MAX_EXPLANATION = 1500


class ReasoningProvider(Protocol):
    name: str
    model_version: str
    deterministic: bool

    def explain(self, finding: dict[str, Any], evidence: list[dict[str, Any]]) -> str | None:
        """An explanation of the finding that cites evidence as [E1], or None when the provider has nothing to offer."""


class DeterministicProvider:
    """Builds the explanation from the finding's statements. No model, no network, no randomness."""

    name = "deterministic"
    model_version = "deterministic-explanations-v1"
    deterministic = True

    def explain(self, finding: dict[str, Any], evidence: list[dict[str, Any]]) -> str:      # noqa: ARG002 - same interface as other providers
        parts = [f"{item['text']} {''.join(f'[{ref}]' for ref in item['evidence_refs'])}" for item in finding["statements"]]
        return " ".join(parts)[:MAX_EXPLANATION]


def get_provider(name: str) -> ReasoningProvider:
    """The configured provider. Unknown names are refused at start-up by the settings; this is the single place a provider is created."""
    if name == "deterministic":
        return DeterministicProvider()
    raise ValueError(f"unknown reasoning provider {name!r}")


_LEADING_CITATIONS = re.compile(r"^((?:\[E\d+\])+)\s*(.*)$", re.S)


def sentences(text: str) -> list[str]:
    """The text split into sentences, each keeping its citations whether they stand before or after the full stop."""
    result: list[str] = []
    for chunk in re.split(r"(?<=[.!?])\s+", text.strip()):
        leading = _LEADING_CITATIONS.match(chunk)
        if leading and result:
            result[-1] += " " + leading.group(1)          # "... is affected. [E1] Next ..." - the citation belongs to what came before
            chunk = leading.group(2)
        if chunk.strip():
            result.append(chunk.strip())
    return result


def guard(text: Any, finding: dict[str, Any]) -> list[str]:
    """Why a provider's explanation cannot be used. An empty list means it can.

    The text must be a bounded string, cite at least one evidence item, cite
    only items the finding already cites, and avoid claims the platform never
    makes. Sentences without a citation are refused, so a model cannot slip in
    an unsupported statement next to supported ones.
    """
    if not isinstance(text, str) or not text.strip():
        return ["The provider returned no text."]
    if len(text) > MAX_EXPLANATION:
        return ["The provider's text is longer than allowed."]
    problems = []
    allowed = set(finding.get("evidence_refs") or [])
    cited = evidence_rules.cited(text)
    if not cited:
        problems.append("The text cites no evidence.")
    outside = sorted(set(cited) - allowed)
    if outside:
        problems.append(f"The text cites evidence the finding does not use: {', '.join(outside)}.")
    if any(not evidence_rules.cited(sentence) for sentence in sentences(text)):
        problems.append("A sentence carries no citation.")
    if _OVERCLAIM.search(text):
        problems.append("The text makes a claim the platform does not make (confirmed exploitation, a guarantee, or intent).")
    return problems


def explain(provider: ReasoningProvider, finding: dict[str, Any], evidence: list[dict[str, Any]]) -> tuple[str, dict[str, Any]]:
    """The explanation to store and an audit record of how it was produced.

    A non-deterministic provider's output is used only if the guard accepts
    it; otherwise the deterministic explanation is used and the rejection is
    recorded. A provider that fails does not fail the analysis.
    """
    fallback = DeterministicProvider().explain(finding, evidence)
    if provider.deterministic:
        return fallback, {"provider": provider.name, "model_version": provider.model_version, "accepted": True, "problems": []}
    try:
        text = provider.explain(finding, evidence)
    except Exception as exc:  # noqa: BLE001 - an external provider must never break the analysis
        return fallback, {"provider": provider.name, "model_version": provider.model_version, "accepted": False,
                          "problems": [f"The provider failed ({type(exc).__name__})."], "fallback": "deterministic"}
    problems = guard(text, finding)
    if problems:
        return fallback, {"provider": provider.name, "model_version": provider.model_version, "accepted": False, "problems": problems,
                          "fallback": "deterministic"}
    return str(text).strip(), {"provider": provider.name, "model_version": provider.model_version, "accepted": True, "problems": [],
                               "prompt_evidence": [item["ref"] for item in evidence]}


__all__ = ["DeterministicProvider", "ReasoningProvider", "explain", "explanation_prompt", "get_provider", "guard"]
