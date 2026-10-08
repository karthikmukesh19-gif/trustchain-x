"""The fragility score (model "fragility-v1").

    fragility = Σ weight_i × value_i          over the factors whose value is known
    confidence = Σ weight_i (known) / 100

Weights sum to 100, every value is between 0 and 1, so the score is between 0
and 100. A factor without data contributes nothing and lowers the confidence;
it is never replaced by a guess. The same inputs always give the same score.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.analyzers.fragility import concentration, health, metrics, version_risk
from app.analyzers.graph.graph_metrics import Structure

MODEL_VERSION = "fragility-v1"
WEIGHTS = {"downstream_impact": 25, "fan_in": 10, "introduced_dependencies": 10, "transitive_depth": 10, "graph_centrality": 15,
           "version_lag": 20, "release_staleness": 10}
LOW, MEDIUM, HIGH = "LOW", "MEDIUM", "HIGH"


def level(score: float) -> str:
    return HIGH if score >= 67 else MEDIUM if score >= 34 else LOW


@dataclass
class FragilityInputs:
    dependencies: list[dict[str, Any]]                        # the snapshot's dependency records
    structure: Structure                                      # graph metrics and centrality
    metadata: dict[tuple[str, str], dict[str, Any]]           # (ecosystem, normalized name) -> registry metadata
    vulnerabilities: dict[str, dict[str, Any]]                # node id -> summary of Phase 3 matches
    reachability: dict[str, dict[str, Any]]                   # node id -> summary of Phase 4 findings and usage
    reachability_analysed: bool
    application_modules: int | None
    as_of: datetime
    notes: list[str] = field(default_factory=list)


class DependencyFragilityAnalyzer:
    """Computes a fragility result for every dependency of a snapshot. Pure: reads its inputs, stores nothing."""

    model_version = MODEL_VERSION

    def analyze(self, inputs: FragilityInputs) -> list[dict[str, Any]]:
        packages = inputs.structure.model.size
        results = []
        for dependency in sorted(inputs.dependencies, key=lambda d: d["node_id"]):
            row = inputs.structure.rows.get(dependency["node_id"])
            if row is None:
                continue                                      # not a node of the stored graph; nothing can be measured
            meta = inputs.metadata.get((dependency["ecosystem"], dependency["normalized_name"]))
            version = version_risk.assess(dependency["ecosystem"], dependency.get("version"), meta, inputs.as_of)
            version.update(registry=(meta or {}).get("registry"), metadata_fetched_at=(meta or {}).get("fetched_at"),
                           metadata_url=(meta or {}).get("source_url"),
                           metadata_stale=bool((meta or {}).get("stale")))      # an expired answer reused because a refresh failed
            vulnerabilities = inputs.vulnerabilities.get(dependency["node_id"], {"distinct": 0, "matches": 0})
            reach = {"analysed": inputs.reachability_analysed, **inputs.reachability.get(dependency["node_id"], {})}
            factors = [
                metrics.downstream_impact(row, packages, WEIGHTS["downstream_impact"]),
                metrics.fan_in(row, WEIGHTS["fan_in"]),
                metrics.introduced(row, WEIGHTS["introduced_dependencies"]),
                metrics.depth(row, WEIGHTS["transitive_depth"]),
                metrics.centrality(row, WEIGHTS["graph_centrality"]),
                metrics.version_lag(version, WEIGHTS["version_lag"]),
                metrics.release_staleness(version, WEIGHTS["release_staleness"]),
            ]
            score = round(sum(f["contribution"] for f in factors), 1)
            confidence = round(sum(f["weight"] for f in factors if f["status"] == metrics.KNOWN) / 100, 2)
            usage = inputs.reachability.get(dependency["node_id"]) if inputs.reachability_analysed else None
            results.append({
                "dependency_id": dependency.get("_id"), "node_id": dependency["node_id"], "package_name": dependency.get("name"),
                "normalized_name": dependency["normalized_name"], "ecosystem": dependency["ecosystem"], "version": dependency.get("version"),
                "relationship": dependency.get("relationship"),
                "fragility_score": score, "fragility_level": level(score), "confidence": confidence, "model_version": MODEL_VERSION,
                "factors": factors,
                "observed_metrics": {key: row[key] for key in (
                    "direct", "depth", "fan_in", "fan_out", "dependents", "dependents_share", "introduced", "exclusive",
                    "reached_by_direct", "reached_by_direct_share", "in_cycle", "connected_to_project")},
                "inferred_metrics": {
                    "degree_centrality": row["degree_centrality"], "betweenness_centrality": row["betweenness_centrality"],
                    "relative_centrality": row["relative_centrality"], "centrality_measure": row["centrality_measure"],
                    "single_point": concentration.single_point(row),
                    "concentration": concentration.dependency_concentration(row, usage, inputs.application_modules),
                    "version": {key: version[key] for key in (
                        "comparison_status", "position", "reason", "comparator", "latest_version", "major_distance", "minor_distance",
                        "patch_distance", "releases_behind", "lag_days", "installed_age_days", "latest_age_days", "releases_last_365_days",
                        "installed_withdrawn", "installed_deprecated")},
                },
                "health": health.profile(dependency, row, version, vulnerabilities, reach),
                "unknown_factors": [f["name"] for f in factors if f["status"] == metrics.UNKNOWN],
            })
        return results
