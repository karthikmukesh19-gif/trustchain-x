"""Where each field of a record comes from, and how complete that trail is."""

from __future__ import annotations

from typing import Any

# The analysis layer every feature and label is taken from.
FIELD_LAYER = {
    "relationship": "inventory", "depth": "inventory", "dependents": "inventory", "dependencies": "inventory", "version_resolved": "inventory",
    "vulnerability_count": "vulnerabilities", "max_severity": "vulnerabilities", "vulnerable": "vulnerabilities",
    "reachability_state": "reachability", "reachable_vulnerability": "reachability",
    "fragility_score": "fragility", "graph_risk": "graph_risk", "predictive_risk": "predictive", "risk_level": "predictive",
    "attack_path_count": "attack_paths", "max_attack_path_score": "attack_paths",
}
LAYERS = ("inventory", "vulnerabilities", "reachability", "fragility", "graph_risk", "predictive", "attack_paths")
REQUIRED = ("collection", "reference", "collected_at", "basis")


def evaluate(records: list[dict[str, Any]], layers_available: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Share of known fields whose source is fully described, and how many of the expected layers contributed."""
    known = traced = 0
    untraced: dict[str, int] = {}
    for record in records:
        sources = {entry.get("layer"): entry for entry in record.get("provenance") or []}
        for group in ("features", "labels"):
            for name, value in (record.get(group) or {}).items():
                if value is None:
                    continue
                known += 1
                entry = sources.get(FIELD_LAYER.get(name, ""))
                if entry is not None and all(entry.get(key) is not None for key in REQUIRED):
                    traced += 1
                else:
                    untraced[name] = untraced.get(name, 0) + 1
    present = [layer for layer in LAYERS if layer in layers_available]
    missing = [layer for layer in LAYERS if layer not in layers_available]
    completeness = traced / known if known else None
    coverage = len(present) / len(LAYERS)
    return {
        "fields_known": known, "fields_traced": traced, "field_provenance_completeness": round(completeness, 4) if completeness is not None else None,
        "untraced_fields": dict(sorted(untraced.items())), "source_layers_present": present, "source_layers_missing": missing,
        "source_diversity": len(present), "source_coverage": round(coverage, 4),
        "value": None if completeness is None else round(0.5 * completeness + 0.5 * coverage, 4),
        "sources": [{"layer": layer, **layers_available[layer]} for layer in present],
    }
