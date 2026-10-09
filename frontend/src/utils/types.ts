export interface User {
  id: string;
  email: string;
  full_name: string;
  role: string;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export type MetadataStatus = "PENDING" | "FETCHED" | "UNAVAILABLE";

export interface RepositoryMetadata {
  github_id: number | null;
  description: string | null;
  default_branch: string | null;
  primary_language: string | null;
  stars: number | null;
  forks: number | null;
  open_issues: number | null;
  size_kb: number | null;
  archived: boolean | null;
  is_fork: boolean | null;
  visibility: string | null;
  license: string | null;
  github_created_at: string | null;
  pushed_at: string | null;
}

export interface Repository {
  host: string;
  owner: string;
  name: string;
  full_name: string;
  url: string;
  metadata_status: MetadataStatus;
  metadata_error: string | null;
  metadata_fetched_at: string | null;
  metadata: RepositoryMetadata | null;
}

export interface Project {
  id: string;
  name: string;
  description: string;
  repository_url: string;
  status: string;
  default_branch: string | null;
  languages: string[];
  created_at: string;
  updated_at: string;
  last_analysis: string | null;
  latest_snapshot_id?: string | null;
  repository: Repository | null;
}

export interface ProjectList {
  items: Project[];
  total: number;
  skip: number;
  limit: number;
}

export interface ActivityEvent {
  timestamp: string;
  action: string;
  outcome: string;
  resource_type: string | null;
  resource_id: string | null;
  details: Record<string, unknown>;
}

export interface DashboardSummary {
  generated_at: string;
  projects_total: number;
  projects_analysed: number;
  projects_by_status: Record<string, number>;
  repository_metadata: Record<string, number>;
  registrations_by_day: { date: string; projects: number }[];
  recent_projects: Project[];
  recent_activity: ActivityEvent[];
  /** Each project's current trust result. Score fields are present only when a score was calculated. */
  trust: import("./platformTypes").DashboardTrust[];
}

export interface Readiness {
  status: "ok" | "degraded" | "unavailable";
  checks: {
    mongodb: { ok: boolean };
    redis: { ok: boolean };
    worker: { ok: boolean; last_heartbeat: string | null };
  };
  time: string;
}

export interface Liveness {
  status: string;
  service: string;
  version: string;
  time: string;
}

// --- Phase 2: dependency analysis -------------------------------------------

/** How a statement is known: read from a file, derived by a documented rule, or not established. */
export type Basis = "OBSERVED" | "INFERRED" | "UNKNOWN";
export type Relationship = "DIRECT" | "TRANSITIVE" | "UNKNOWN";
/** "partial": the job finished and stored its results, but part of its input could not be collected (see the job's error). */
export type JobState = "queued" | "running" | "completed" | "partial" | "failed";

export interface AnalysisSummary {
  dependencies: number;
  direct: number;
  transitive: number;
  relationship_unknown: number;
  unresolved_versions: number;
  edges: number;
  max_depth: number;
  ecosystems: string[];
  package_managers: string[];
  languages: string[];
  primary_language: string | null;
  dependency_files: number;
  files: number;
}

export interface AnalysisJob {
  id: string;
  project_id: string;
  state: JobState;
  stage: string;
  stage_index: number;
  stage_count: number;
  message: string;
  error: { code: string; message: string; retry_at?: string } | null;
  snapshot_id: string | null;
  summary: AnalysisSummary | null;
  reused_snapshot: boolean;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface AnalysisStatus {
  job: AnalysisJob | null;
  has_results: boolean;
  last_analysis: string | null;
}

export interface DetectedLanguage {
  language: string;
  files: number;
  bytes: number;
  share: number;
  confidence: "HIGH" | "MEDIUM" | "LOW";
  basis: Basis;
  evidence_files: string[];
  dependency_file_present: boolean;
}

export interface DetectedPackageManager {
  package_manager: string;
  ecosystem: string;
  basis: Basis;
  supported: boolean;
  manifest_files: string[];
  lock_files: string[];
}

export interface DependencyFile {
  path: string;
  size: number | null;
  git_blob_sha: string | null;
  sha256: string | null;
  package_manager: string;
  ecosystem: string;
  kind: "manifest" | "lockfile";
  status: "PARSED" | "ERROR" | "NOT_EVALUATED" | "UNSUPPORTED" | "SKIPPED";
  detail: string | null;
  dependencies_found: number;
  notes: string[];
  referenced_by: string | null;
}

export interface Snapshot {
  id: string;
  repository_url: string;
  repository_full_name: string;
  branch: string;
  commit_sha: string;
  tree_sha: string;
  committed_at: string | null;
  commit_message: string | null;
  collected_at: string;
  status: string;
  analyzer_version: string;
  collection_method: string;
  file_count: number;
  total_bytes: number;
  rejected_paths: number;
  symlinks_skipped: number;
  submodules_skipped: number;
  languages: { languages: DetectedLanguage[]; primary_language: string | null; method: string };
  github_primary_language: string | null;
  package_managers: DetectedPackageManager[];
  dependency_files: DependencyFile[];
  notes: string[];
  summary: AnalysisSummary;
}

export interface SnapshotRef {
  id: string;
  commit_sha: string;
  branch: string;
  collected_at: string;
  analyzer_version: string;
}

export interface DependencyEvidence {
  source_file: string;
  file_kind: "manifest" | "lockfile";
  package_manager: string;
  line: number | null;
  declaration: string;
  constraint: string | null;
  scope: string | null;
  evidence_type: string;
  git_blob_sha: string | null;
}

export interface GraphNode {
  node_id: string;
  ecosystem: string;
  name: string;
  normalized_name: string;
  version: string | null;
  version_status: "RESOLVED" | "UNRESOLVED";
  version_basis: Basis;
  version_reason: string;
  purl: string | null;
  constraints: string[];
  package_managers: string[];
  relationship: Relationship;
  relationship_basis: Basis;
  relationship_reason: string;
  scopes: string[];
  optional: boolean;
  source: { type: string; location: string } | null;
  evidence_count: number;
  depth: number | null;
  shortest_path_count: number;
  parents: string[];
  parent_count: number;
  dependents_count: number;
  dependency_count: number;
}

export interface Dependency extends GraphNode {
  integrity: { algorithm: string; value: string }[];
  evidence: DependencyEvidence[];
}

export interface GraphStats {
  total: number;
  direct: number;
  transitive: number;
  relationship_unknown: number;
  unresolved_versions: number;
  edges: number;
  max_depth: number;
  without_path: number;
  unresolved_edges: number;
  by_ecosystem: Record<string, number>;
  by_package_manager: Record<string, number>;
  by_depth: Record<string, number>;
  by_relationship_basis: Record<string, number>;
  by_scope: Record<string, number>;
}

export interface DependencyList {
  snapshot: SnapshotRef;
  summary: GraphStats;
  total: number;
  skip: number;
  limit: number;
  items: Dependency[];
}

export interface GraphEdge {
  source: string;
  target: string;
  type: string;
  relation: string;
  basis: Basis;
  evidence_files: string[];
  requirement: string | null;
}

export interface DependencyGraphData {
  snapshot: SnapshotRef;
  root: { id: string; type: string; label: string };
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: GraphStats;
  paths?: string[][];
}

// --- Phase 3: vulnerability intelligence and SBOM ------------------------------

export type JobType =
  | "dependencies" | "vulnerability_sync" | "vulnerability_analysis" | "sbom_generation" | "code_reachability_analysis"
  | "dependency_fragility_analysis" | "graph_risk_analysis" | "predictive_dependency_analysis"
  | "attack_path_analysis" | "maintainer_analysis" | "commit_behaviour_analysis" | "ai_security_analysis" | "dataset_validation" | "trust_analysis";

/** A background job of any type, as returned by /jobs. */
export interface ProjectJob {
  id: string;
  project_id: string;
  type: JobType;
  state: JobState;
  stage: string;
  stage_index: number;
  stage_count: number;
  stages?: string[];
  message: string;
  error: { code: string; message: string; retry_at?: string } | null;
  summary: Record<string, unknown> | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface JobListing {
  active: ProjectJob | null;
  items: ProjectJob[];
}

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
export type MatchStatus = "AFFECTED" | "UNSUPPORTED" | "CONFLICT";

export interface CvssRecord {
  type: string;
  vector: string;
  version: string | null;
  base_score: number | null;
  score_origin: string | null;
}

export interface VulnerabilityMatch {
  id: string;
  dependency_node_id: string;
  source: string;
  source_id: string;
  aliases: string[];
  group_key: string;
  summary: string | null;
  ecosystem: string;
  package_name: string;
  normalized_name: string;
  matched_version: string;
  relationship: Relationship | null;
  depth: number | null;
  match_status: MatchStatus;
  classification: "OBSERVED" | null;
  confidence: "HIGH" | "LOW" | "UNDETERMINED";
  confidence_meaning: string;
  severity: Severity;
  severity_source: string | null;
  cvss: CvssRecord[] | null;
  affected_range: string | null;
  fixed_version: string | null;
  fixed_versions: string[];
  matched_at: string;
  first_matched_at?: string;
}

export interface MatchEvidence {
  evidence_type: string;
  source: { provider: string; source_id: string; url: string | null; modified_at: string | null; record_sha256: string | null; retrieved_at: string | null };
  observed: {
    package: string;
    normalized_name: string;
    ecosystem: string;
    installed_version: string;
    purl: string | null;
    version_basis: Basis | null;
    version_reason: string | null;
    relationship: Relationship | null;
    depth: number | null;
    declared_in: { source_file: string | null; line: number | null; declaration: string | null; file_kind: string | null; git_blob_sha: string | null }[];
  };
  match: {
    comparator: string | null;
    range_type: string | null;
    affected_range: string | null;
    introduced: string | null;
    fixed: string | null;
    last_affected: string | null;
    limit: string | null;
    events: Record<string, string>[];
    version_listed_by_source: boolean;
    provider_reported: boolean | null;
    explanation: string;
    source_range_note: string | null;
  };
}

export interface Advisory {
  id: string;
  source: string;
  source_id: string;
  source_url: string | null;
  aliases: string[];
  summary: string | null;
  details: string | null;
  severity: Severity;
  severity_source: string | null;
  cvss: CvssRecord[] | null;
  cwe_ids: string[];
  references: { type: string | null; url: string }[];
  published_at: string | null;
  modified_at: string | null;
  withdrawn_at: string | null;
  first_seen_at: string | null;
  ingested_at: string | null;
}

export interface MatchDetail {
  match: VulnerabilityMatch & { evidence: MatchEvidence };
  vulnerability: Advisory | null;
}

export interface VulnerabilityScan {
  snapshot_id: string;
  commit_sha: string;
  matched_at: string;
  matcher_version: string;
  dependencies_total: number;
  dependencies_checked: number;
  dependencies_unresolved: number;
  dependencies_unsupported_ecosystem: number;
  unsupported_ecosystems: Record<string, number>;
  advisories_considered: number;
  advisories_withdrawn_skipped: number;
  affected_matches: number;
  affected_dependencies: number;
  distinct_vulnerabilities: number;
  unsupported_matches: number;
  conflict_matches: number;
  by_severity: Record<Severity, number>;
  reported_but_not_stored: { dependency: string; source_id: string }[];
  reported_but_not_stored_count: number;
  intelligence: { sync_id: string; provider: string; status: string; completed_at: string | null; records_seen: number | null; records_failed: number | null } | null;
}

export interface VulnerabilitySync {
  id: string;
  provider: string;
  status: "running" | "completed" | "partial" | "failed";
  started_at: string;
  completed_at: string | null;
  packages_queried: number;
  packages_unsupported: number;
  packages_unresolved: number;
  records_seen: number;
  records_inserted: number;
  records_updated: number;
  records_unchanged: number;
  records_failed: number;
  errors: { source_id: string; code: string; message: string }[];
  error_summary: string | null;
}

export interface VulnerabilityList {
  job: ProjectJob | null;
  providers: string[];
  snapshot: { id: string; commit_sha: string; branch: string; collected_at: string } | null;
  scan: VulnerabilityScan | null;
  sync: VulnerabilitySync | null;
  total: number;
  skip: number;
  limit: number;
  items: VulnerabilityMatch[];
}

export interface SbomLinkage {
  components_with_matches: number;
  affected_matches: number;
  latest_match_at: string | null;
}

export interface SbomRecord {
  id: string;
  snapshot_id: string;
  commit_sha: string;
  branch: string | null;
  version: number;
  previous_sbom_id: string | null;
  format: string;
  spec_version: string;
  media_type: string;
  serial_number: string;
  generator: { name: string; version: string };
  generated_at: string;
  component_count: number;
  relationship_count: number;
  unresolved_components: number;
  components_with_hashes: number;
  completeness: string;
  digest_algorithm: string;
  canonicalization: string;
  content_digest: string;
  document_digest: string;
  document_size: number;
  last_verification: { valid: boolean; verified_at: string; failed_checks: string[] } | null;
  vulnerability_linkage?: SbomLinkage;
}

export interface SbomListing {
  job: ProjectJob | null;
  latest: SbomRecord | null;
  history: SbomRecord[];
  has_inventory: boolean;
  latest_snapshot_id: string | null;
}

export interface SbomDiffItem {
  ecosystem: string;
  name: string;
  change: "ADDED" | "REMOVED" | "CHANGED";
  change_type?: "version" | "metadata";
  old_versions: (string | null)[];
  new_versions: (string | null)[];
  old_version?: string | null;
  new_version?: string | null;
  fields?: { field: string; old: unknown; new: unknown; version: string | null }[];
}

export interface SbomDiffSummary {
  added: number;
  removed: number;
  changed: number;
  version_changes: number;
  metadata_changes: number;
  ecosystem_changes: number;
  relationships_added: number;
  relationships_removed: number;
  components_before: number;
  components_after: number;
  document_changes: number;
  identical: boolean;
}

export interface SbomDiff {
  id?: string;
  base_sbom_id?: string;
  target_sbom_id?: string;
  base_version?: number;
  target_version?: number;
  base_commit_sha?: string;
  target_commit_sha?: string;
  summary: SbomDiffSummary;
  items: SbomDiffItem[];
  items_truncated?: boolean;
  ecosystem_changes?: { name: string; old_ecosystem: string; new_ecosystem: string; basis: string; reason: string }[];
  document_changes: { field: string; old: unknown; new: unknown }[];
  relationships_added: { from: string; to: string }[];
  relationships_removed: { from: string; to: string }[];
}

export interface SbomVerification {
  sbom_id: string;
  valid: boolean;
  verified_at: string;
  checks: { name: string; ok: boolean; detail: string; expected?: string; actual?: string; differing?: string[] }[];
  digest_algorithm: string;
  canonicalization: string;
  difference_from_regenerated: Pick<SbomDiff, "summary" | "items" | "relationships_added" | "relationships_removed" | "document_changes"> | null;
  meaning: string;
}

export interface SbomComponent {
  bom_ref: string;
  ecosystem: string | null;
  name: string;
  normalized_name: string | null;
  version: string | null;
  purl: string | null;
  scope: string | null;
  relationship: string | null;
  hashes: { alg: string; content: string }[];
  depends_on: string[];
  component_digest: string;
  vulnerabilities: { match_id: string; source_id: string; severity: Severity; fixed_version: string | null }[];
}

export interface SbomComponentList {
  sbom_id: string;
  total: number;
  skip: number;
  limit: number;
  items: SbomComponent[];
  vulnerability_linkage: SbomLinkage;
}

// --- code reachability (Phase 4) ----------------------------------------------

export type ReachabilityStatus = "REACHABLE" | "NOT_CONFIRMED_REACHABLE" | "UNKNOWN" | "UNSUPPORTED";
export type EvidenceConfidence = "HIGH" | "MEDIUM" | "LOW";
export type UsageLevel = "CALLED" | "REFERENCED" | "IMPORTED_ONLY" | "NOT_OBSERVED";

export interface SourceLocation {
  source_file: string | null;
  line: number | null;
  col?: number | null;
  end_line?: number | null;
  text: string | null;
}

export interface AffectedSymbol {
  symbol: string;
  module_only: boolean;
  source: "ADVISORY" | "OPERATOR_SUPPLIED";
  origin: string;
  note: string | null;
}

export interface MatchedSymbol extends AffectedSymbol {
  observed: string;
  match: "EXACT" | "NAME";
}

export interface ReachabilityFinding {
  id: string;
  match_id: string;
  advisory_source: string;
  advisory_id: string;
  aliases: string[];
  summary: string | null;
  severity: Severity;
  ecosystem: string;
  dependency: string;
  normalized_name: string;
  resolved_version: string;
  relationship: Relationship | null;
  status: ReachabilityStatus;
  confidence: EvidenceConfidence | null;
  reason: string;
  symbol_mapping: "ADVISORY" | "OPERATOR_SUPPLIED" | "SYMBOL_MAPPING_UNKNOWN";
  matched_symbol: MatchedSymbol | null;
  evidence: { source_file: string | null; line: number | null; symbol: string | null; text: string | null; path: string[] };
  usage_level: UsageLevel | null;
  analyzed_at: string;
  analyzer_version: string;
}

export interface CodePathNode {
  id: string;
  kind: "module" | "class" | "function" | "method" | "external";
  label: string;
  path: string | null;
  line: number | null;
  is_test: boolean;
}

export interface CodePathEdge {
  kind: "calls" | "references" | "imports" | "constructs";
  source: string;
  target: string;
  confidence: EvidenceConfidence;
  basis: string;
  via: string | null;
  hops: string[] | null;
  evidence: SourceLocation | null;
}

export interface CodePath {
  nodes: CodePathNode[];
  edges: CodePathEdge[];
  length: number;
  truncated: boolean;
  start_is_entry: boolean;
  through_tests_only: boolean;
  confidence: EvidenceConfidence;
}

export interface UsageSite extends SourceLocation {
  symbol: string;
  used: string;
  kind: string;
  confidence: EvidenceConfidence;
  basis: string;
  is_test: boolean;
}

export interface DependencyUsage {
  level: UsageLevel;
  imported: boolean;
  import_sites: UsageSite[];
  import_site_count: number;
  use_sites: UsageSite[];
  use_site_count: number;
  used_names: string[];
}

export interface ReachabilityFindingDetail extends ReachabilityFinding {
  snapshot_id: string;
  analysis_id: string;
  vulnerability_id: string;
  explanation: string;
  confidence_meaning: string;
  affected_symbols: AffectedSymbol[];
  observed: {
    dependency_usage: DependencyUsage | null;
    path: CodePath | null;
    usage_path: CodePath | null;
    dynamic_sites: ({ reason: string; expr: string } & SourceLocation)[] | null;
  };
  inferred: { status: ReachabilityStatus; reason: string; notes: string[] };
}

export interface ReachabilityAnalysis {
  id: string;
  snapshot_id: string;
  commit_sha: string;
  branch: string | null;
  analyzer_version: string;
  completed_at: string;
  source_analysed_at?: string;
  source_complete: boolean;
  incomplete_reasons: { reason: string; files: number }[];
  source: {
    languages: string[];
    files_found: number;
    files_analysed: number;
    files_parsed: number;
    test_files: number;
    by_status: Record<string, number>;
    other_languages: Record<string, number>;
  };
  graph: { modules: number; classes: number; functions: number; external_symbols: number; edges: number; unresolved: number;
           unresolved_by_reason: Record<string, number> };
  findings: { findings: number; by_status: Record<ReachabilityStatus, number>; by_reason: Record<string, number>;
              with_symbol_mapping: number; dependencies_used: number; matches_not_evaluated: Record<string, number> };
  vulnerability_scan_matched_at: string | null;
  operator_mappings: number;
  operator_mapping_problems: string[];
}

export interface ReachabilityList {
  job: ProjectJob | null;
  snapshot: { id: string; commit_sha: string; branch: string | null } | null;
  has_vulnerability_scan: boolean;
  vulnerability_scan_matched_at: string | null;
  analysis: ReachabilityAnalysis | null;
  supported_ecosystems: string[];
  statuses: ReachabilityStatus[];
  total: number;
  skip: number;
  limit: number;
  items: ReachabilityFinding[];
}

// --- dependency intelligence (fragility, graph risk, predictive indicators) --------------

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH";
export type ExposureClassification = "DIRECT_VULNERABILITY" | "DEPENDENCY_PROPAGATION" | "INDIRECT_EXPOSURE" | "NO_OBSERVED_PROPAGATION";
export type EvidenceKind = "OBSERVED" | "DERIVED" | "PREDICTED" | "RECOMMENDED";
export type ReachabilityState = ReachabilityStatus | "NOT_ANALYSED";
export type IntelligenceKind = "fragility" | "graph_risk" | "predictive";

export interface ScoreFactor {
  name: string;
  weight: number;
  /** 0-1, or null when the data for this factor is not available. An unknown factor contributes nothing and is never estimated. */
  value: number | null;
  contribution: number;
  /** ASSUMED: the fact is not established (severity not published, reachability undecided) and the model uses its stated neutral value. */
  status: "KNOWN" | "UNKNOWN" | "ASSUMED";
  basis: "OBSERVED" | "DERIVED";
  detail: string;
  inputs?: Record<string, unknown>;
}

export interface VersionAssessment {
  comparison_status: "COMPARED" | "UNSUPPORTED" | "UNKNOWN";
  position: "UP_TO_DATE" | "BEHIND" | "AHEAD_OF_LATEST" | null;
  reason: string | null;
  comparator: string | null;
  latest_version: string | null;
  major_distance: number | null;
  minor_distance: number | null;
  patch_distance: number | null;
  releases_behind: number | null;
  lag_days: number | null;
  installed_age_days: number | null;
  latest_age_days: number | null;
  releases_last_365_days: number | null;
  installed_withdrawn: boolean | null;
  installed_deprecated: boolean | null;
}

export interface FragilityRow {
  dependency_id: string;
  node_id: string;
  package_name: string;
  normalized_name: string;
  ecosystem: string;
  version: string | null;
  relationship: Relationship;
  fragility_score: number;
  fragility_level: RiskLevel;
  confidence: number;
  model_version: string;
  factors: ScoreFactor[];
  observed_metrics: {
    direct: boolean; depth: number | null; fan_in: number; fan_out: number; dependents: number; dependents_share: number;
    introduced: number; exclusive: number; reached_by_direct: number; reached_by_direct_share: number | null; in_cycle: boolean;
    connected_to_project: boolean;
  };
  inferred_metrics: {
    degree_centrality: number; betweenness_centrality: number | null; relative_centrality: number; centrality_measure: string;
    single_point: boolean; version: VersionAssessment;
    concentration: { importing_modules: number | null; importing_module_share: number | null; use_sites: number | null };
  };
  unknown_factors: string[];
}

export interface DependencyHealth {
  installed_version: string | null;
  latest_release: string | null;
  latest_release_at: string | null;
  installed_release_at: string | null;
  release_age_days: number | null;
  latest_release_age_days: number | null;
  release_frequency: number | null;
  known_vulnerability_count: number | null;
  reachable_vulnerability_count: number | null;
  dependency_count: number | null;
  downstream_dependents: number | null;
  repository_activity: null;
  metadata_confidence: "HIGH" | "MEDIUM" | "LOW" | "NONE";
  metadata_source: { registry: string | null; status: string | null; detail: string | null; fetched_at: string | null; url: string | null; stale: boolean };
  version: VersionAssessment;
  unknown: { field: string; status: "UNKNOWN"; reason: string }[];
}

export interface GraphRiskRow {
  dependency_id: string | null;
  node_id: string;
  package_name: string | null;
  normalized_name: string | null;
  ecosystem: string | null;
  version: string | null;
  relationship: Relationship | null;
  classification: ExposureClassification;
  components: { vulnerability_signal: number; reachability_signal: number | null; centrality_signal: number; downstream_impact: number; confidence: number | null };
  own_risk: number;
  propagated_risk: number;
  graph_risk: number;
  severity: Severity | null;
  reachability_state: ReachabilityState | null;
  vulnerability_count: number;
  exposure_sources: { node_id: string; distance: number; source_risk: number; influence: number }[];
  exposure_source_count: number;
  exposes: number;
  model_version: string;
}

export interface PredictiveIndicator {
  type: string;
  severity: RiskLevel;
  confidence: number;
  evidence: string[];
  basis: "OBSERVED" | "DERIVED";
  indicator_version: string;
}

export interface PredictionRow {
  dependency_id: string;
  node_id: string;
  package_name: string;
  normalized_name: string;
  ecosystem: string;
  version: string | null;
  relationship: Relationship;
  score: number;
  level: RiskLevel;
  confidence: number;
  model_version: string;
  meaning: string;
  fragility_score: number;
  fragility_confidence: number;
  graph_risk: number;
  exposure_classification: ExposureClassification;
  vulnerability_count: number;
  max_severity: Severity | null;
  /** null when no reachability analysis covers this dependency. */
  reachable_vulnerability_count: number | null;
  reachability_state: ReachabilityState | null;
  dependents: number;
  depth: number | null;
  relative_centrality: number;
  indicator_types: string[];
  indicator_count: number;
  monitoring_rank: number;
}

export interface PredictionDetailRow extends PredictionRow {
  factors: ScoreFactor[];
  evidence: Record<EvidenceKind, string[]>;
}

export interface PredictionDetail {
  prediction: PredictionDetailRow;
  indicators: PredictiveIndicator[];
  fragility: FragilityRow | null;
  health: DependencyHealth | null;
  graph_risk: GraphRiskRow | null;
}

export interface FragilityDetail {
  fragility: FragilityRow;
  health: DependencyHealth | null;
}

export interface MetadataStats {
  packages: number; from_cache: number; fetched: number; not_found: number; errors: number; unsupported_ecosystem: number;
  invalid_name: number; skipped_by_limit: number; skipped_after_failures: number; incomplete: boolean; providers: string[];
}

export interface GraphConcentration {
  packages: number; relationships: number; direct_dependencies: number; unconnected_packages: number; max_depth: number;
  packages_in_cycles: number; effective_packages: number | null;
  top_dependents: { node_id: string; dependents: number; share: number }[];
  largest_subtrees: { node_id: string; introduced: number; share: number }[];
}

export interface IntelligenceSummary {
  kind: IntelligenceKind;
  packages: number;
  graph: GraphConcentration;
  betweenness_computed: boolean;
  vulnerability_scan: boolean;
  reachability_analysed: boolean;
  metadata?: MetadataStats | null;
  fragility?: {
    dependencies: number; by_level: Partial<Record<RiskLevel, number>>; highest: number | null; mean: number | null;
    mean_confidence: number | null; single_points: number; version_comparison: Record<string, number>;
  };
  graph_risk?: {
    by_classification: Record<ExposureClassification, number>;
    project: { classification: ExposureClassification; vulnerable_packages: number; reachable_from_project: number; highest_graph_risk: number };
    paths: { node_id: string; path: string[] | null; length: number | null; own_risk: number; path_truncated: boolean }[];
    paths_truncated: boolean;
    parameters: { decay: number };
  };
  predictive?: {
    dependencies: number; by_level: Partial<Record<RiskLevel, number>>; indicators: Record<string, number>; indicator_total: number;
    highest: number | null;
  };
}

export interface IntelligenceAnalysis {
  id: string;
  kind: IntelligenceKind;
  layers: string[];
  commit_sha: string;
  created_at: string;
  completed_at: string | null;
  model_versions: { fragility: string; graph_risk: string; predictive: string; indicators: string };
  inputs: { vulnerability_scan_matched_at: string | null; reachability: { completed_at: string | null } | null; metadata_providers: string[] };
  summary: IntelligenceSummary;
}

export interface IntelligenceList<Row> {
  job: ProjectJob | null;
  snapshot: { id: string; commit_sha: string; branch: string | null } | null;
  has_vulnerability_scan: boolean;
  /** When the snapshot's inputs last changed; compared with `analysis.inputs` to tell when the analysis is out of date. */
  current_inputs: { vulnerability_scan_matched_at: string | null; reachability_completed_at: string | null } | null;
  /** null until an analysis of the latest snapshot has completed. Nothing is reported without one. */
  analysis: IntelligenceAnalysis | null;
  total: number;
  skip: number;
  limit: number;
  items: Row[];
  indicator_types?: string[];
}

export interface RiskGraphNode {
  dependency_id: string;
  node_id: string;
  package_name: string;
  normalized_name: string;
  ecosystem: string;
  version: string | null;
  relationship: Relationship;
  depth: number | null;
  score: number;
  level: RiskLevel;
  confidence: number;
  fragility_score: number;
  graph_risk: number;
  exposure_classification: ExposureClassification;
  vulnerability_count: number;
  reachable_vulnerability_count: number | null;
  relative_centrality: number;
  dependents: number;
  indicator_types: string[];
}

export interface RiskGraphData {
  analysis: { id: string; created_at: string };
  root: { id: string; label?: string };
  nodes: RiskGraphNode[];
  edges: { source: string; target: string }[];
}

export interface AnalysisComparison {
  base: { analysis_id: string; created_at: string; commit_sha: string };
  target: { analysis_id: string; created_at: string; commit_sha: string };
  comparable: boolean;
  summary: { added: number; removed: number; changed: number; unchanged: number };
  items: {
    ecosystem: string;
    normalized_name: string;
    change: "ADDED" | "REMOVED" | "CHANGED";
    before?: { version?: string | null; predictive_risk?: number; fragility_score?: number };
    after?: { version?: string | null; predictive_risk?: number; fragility_score?: number };
    deltas?: Partial<Record<"fragility_score" | "predictive_risk" | "graph_risk", number>>;
    indicators_added?: string[];
    indicators_removed?: string[];
    version_changed?: boolean;
  }[];
  items_truncated: boolean;
}
