"""Component weights of the trust model.

These weights are expert-defined initial weights and are not statistically trained.

They state how much each layer counts towards the risk score. They were set
by judgement, not fitted to outcome data, and should be read as a transparent
starting point: a different weighting is a legitimate choice and would give a
different score from the same evidence.
"""

from __future__ import annotations

MODEL_VERSION = "trust-v1"
WEIGHTS_STATEMENT = "These weights are expert-defined initial weights and are not statistically trained."

WEIGHTS: dict[str, int] = {
    "dependency_risk": 15,
    "sbom_integrity": 15,
    "vulnerability_exposure": 15,
    "code_reachability": 10,
    "dependency_fragility": 10,
    "attack_path_risk": 10,
    "maintainer_behaviour": 10,
    "commit_behaviour": 5,
    "dataset_confidence": 5,
    "predictive_risk": 5,
}
assert sum(WEIGHTS.values()) == 100

LABELS = {
    "dependency_risk": "Dependency risk", "sbom_integrity": "SBOM integrity", "vulnerability_exposure": "Vulnerability exposure",
    "code_reachability": "Code reachability", "dependency_fragility": "Dependency fragility", "attack_path_risk": "Attack-path risk",
    "maintainer_behaviour": "Maintainer behaviour", "commit_behaviour": "Commit behaviour", "dataset_confidence": "Dataset confidence",
    "predictive_risk": "Predictive risk",
}
# The analysis layer each component reads.
SOURCE_LAYER = {
    "dependency_risk": "inventory", "sbom_integrity": "sbom", "vulnerability_exposure": "vulnerabilities", "code_reachability": "reachability",
    "dependency_fragility": "fragility", "attack_path_risk": "attack_paths", "maintainer_behaviour": "maintainers", "commit_behaviour": "commits",
    "dataset_confidence": "dataset", "predictive_risk": "predictive",
}
