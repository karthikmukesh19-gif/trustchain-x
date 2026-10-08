"""Collection names and index definitions.

All 29 collections of the data model are declared here so the schema is
visible in one place and indexes exist before any phase writes data. A
collection listed here is not necessarily written to yet — docs/database.md
records which phase populates each one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pymongo import ASCENDING, DESCENDING


@dataclass(frozen=True)
class Index:
    keys: tuple[tuple[str, int], ...]
    options: dict[str, Any] = field(default_factory=dict)


def idx(*keys: tuple[str, int], **options: Any) -> Index:
    return Index(keys=tuple(keys), options=options)


A, D = ASCENDING, DESCENDING

USERS = "users"
PROJECTS = "projects"
REPOSITORIES = "repositories"
REPOSITORY_SNAPSHOTS = "repository_snapshots"
DEPENDENCIES = "dependencies"
DEPENDENCY_VERSIONS = "dependency_versions"
DEPENDENCY_GRAPHS = "dependency_graphs"
SBOMS = "sboms"
SBOM_COMPONENTS = "sbom_components"
SBOM_DIFFERENCES = "sbom_differences"
VULNERABILITIES = "vulnerabilities"
VULNERABILITY_MATCHES = "vulnerability_matches"
CODE_REACHABILITY = "code_reachability"
ATTACK_PATHS = "attack_paths"
MAINTAINERS = "maintainers"
MAINTAINER_PROFILES = "maintainer_profiles"
BEHAVIOUR_EVENTS = "behaviour_events"
COMMITS = "commits"
COMMIT_ANALYSIS = "commit_analysis"
SECURITY_EVENTS = "security_events"
PREDICTIONS = "predictions"
TRUST_SCORES = "trust_scores"
AI_FINDINGS = "ai_findings"
REMEDIATION_ACTIONS = "remediation_actions"
DATASETS = "datasets"
DATASET_RECORDS = "dataset_records"
DATASET_QUALITY = "dataset_quality"
ANALYSIS_JOBS = "analysis_jobs"
AUDIT_LOGS = "audit_logs"

INDEXES: dict[str, list[Index]] = {
    USERS: [idx(("email", A), unique=True)],
    PROJECTS: [
        idx(("owner_id", A), ("repository_key", A), unique=True),
        idx(("owner_id", A), ("created_at", D)),
        idx(("repository_id", A)),
    ],
    REPOSITORIES: [idx(("key", A), unique=True)],
    REPOSITORY_SNAPSHOTS: [
        idx(("project_id", A), ("commit_sha", A), ("analyzer_version", A), unique=True),
        idx(("project_id", A), ("collected_at", D)),
    ],
    DEPENDENCIES: [
        idx(("snapshot_id", A), ("node_id", A), unique=True),
        idx(("project_id", A), ("snapshot_id", A), ("ecosystem", A), ("normalized_name", A)),
    ],
    DEPENDENCY_VERSIONS: [idx(("ecosystem", A), ("package_name", A), ("version", A), unique=True)],
    DEPENDENCY_GRAPHS: [idx(("snapshot_id", A), unique=True), idx(("project_id", A), ("created_at", D))],
    SBOMS: [idx(("project_id", A), ("snapshot_id", A), ("kind", A)), idx(("content_hash", A))],
    SBOM_COMPONENTS: [idx(("sbom_id", A), ("purl", A))],
    SBOM_DIFFERENCES: [idx(("project_id", A), ("snapshot_id", A), ("difference_type", A))],
    VULNERABILITIES: [
        idx(("source", A), ("source_id", A), unique=True),
        idx(("aliases", A)),
        idx(("affected.ecosystem", A), ("affected.package_name", A)),
    ],
    VULNERABILITY_MATCHES: [
        idx(("snapshot_id", A), ("dependency_id", A), ("vulnerability_id", A), unique=True),
        idx(("project_id", A), ("severity", A)),
    ],
    CODE_REACHABILITY: [idx(("snapshot_id", A), ("match_id", A), unique=True)],
    ATTACK_PATHS: [idx(("project_id", A), ("snapshot_id", A), ("path_risk", D))],
    MAINTAINERS: [idx(("platform", A), ("login", A), unique=True)],
    MAINTAINER_PROFILES: [idx(("repository_id", A), ("maintainer_id", A), unique=True)],
    BEHAVIOUR_EVENTS: [idx(("repository_id", A), ("occurred_at", D)), idx(("project_id", A), ("anomaly_score", D))],
    COMMITS: [idx(("repository_id", A), ("sha", A), unique=True), idx(("repository_id", A), ("committed_at", D))],
    COMMIT_ANALYSIS: [idx(("commit_id", A), unique=True), idx(("project_id", A), ("risk_level", A))],
    SECURITY_EVENTS: [idx(("project_id", A), ("created_at", D))],
    PREDICTIONS: [idx(("project_id", A), ("snapshot_id", A), ("subject_type", A), ("subject_id", A))],
    TRUST_SCORES: [idx(("project_id", A), ("created_at", D))],
    AI_FINDINGS: [idx(("project_id", A), ("snapshot_id", A), ("severity", A))],
    REMEDIATION_ACTIONS: [idx(("project_id", A), ("created_at", D))],
    DATASETS: [idx(("name", A), ("version", A), unique=True), idx(("owner_id", A))],
    DATASET_RECORDS: [idx(("dataset_id", A), ("record_hash", A))],
    DATASET_QUALITY: [idx(("dataset_id", A), ("created_at", D))],
    ANALYSIS_JOBS: [idx(("project_id", A), ("created_at", D)), idx(("state", A), ("created_at", A))],
    AUDIT_LOGS: [idx(("actor_id", A), ("timestamp", D)), idx(("action", A), ("timestamp", D))],
}

ALL_COLLECTIONS: tuple[str, ...] = tuple(INDEXES)
