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
export type JobState = "queued" | "running" | "completed" | "failed";

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
