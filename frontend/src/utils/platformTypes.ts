/** Types for the layers added with the attack-path, behaviour, reasoning, dataset and trust features. */

import type { ProjectJob, Severity } from "./types";

export type EvidenceBasis = "OBSERVED" | "DERIVED" | "INFERRED" | "PREDICTED" | "RECOMMENDED" | "METHOD" | "UNKNOWN";
export type Level = "LOW" | "MEDIUM" | "HIGH";
export interface SnapshotRef { id: string; commit_sha: string; branch: string | null }

/** One execution of a layer, as stored. */
export interface AnalysisRun<S = Record<string, unknown>> {
  id: string;
  kind: string;
  state: string;
  model_version: string;
  created_at: string;
  completed_at?: string;
  commit_sha: string | null;
  branch: string | null;
  snapshot_id: string | null;
  summary: S;
  inputs: Record<string, unknown>;
}

// --- attack paths --------------------------------------------------------------------

export type AttackPathStatus = "SUPPORTED_PATH" | "POTENTIAL_PATH" | "UNKNOWN_PATH" | "OBSERVED_COMPONENT";
export type AttackStage = "ENTRY" | "DEPENDENCY" | "VULNERABILITY" | "REACHABILITY" | "APPLICATION" | "DOWNSTREAM_COMPONENT" | "IMPACT";

export interface AttackNode {
  id: string;
  stage: AttackStage;
  label: string;
  basis: EvidenceBasis;
  detail: string;
  evidence?: Record<string, unknown>[];
  vulnerable?: boolean;
  severity?: Severity;
  state?: string;
  paths?: number;
  max_score?: number;
  node_id?: string;
}

export interface AttackEdge { source: string; target: string; kind: string; basis: EvidenceBasis; confidence: number; reason: string; paths?: number }

export interface AttackPathSummary {
  paths: number;
  candidates: number;
  paths_truncated: boolean;
  by_status: Record<AttackPathStatus, number>;
  by_level: Partial<Record<Level, number>>;
  by_severity: Partial<Record<Severity, number>>;
  highest_score: number | null;
  vulnerable_packages: number;
  exploit_confirmed: number;
  reachability_analysed: boolean;
  meaning: string;
}

export interface AttackPathRow {
  attack_path_id: string;
  rank: number;
  status: AttackPathStatus;
  status_meaning: string;
  score: number;
  level: Level;
  confidence: number;
  exploit_confirmed: boolean;
  target: { node_id: string; package_name: string; version: string | null; ecosystem: string; relationship: string };
  advisory: { source_id: string; severity: Severity; summary: string | null; fixed_versions: string[]; match_count: number };
  reachability: { state: string; source_file: string | null; line: number | null };
  route: string[] | null;
  route_length: number | null;
  alternative_routes: string[][];
  routes_truncated: boolean;
  downstream: { dependents: number; examples: string[] };
  components: {
    vulnerability_signal: number; severity: string; reachability_signal: number; reachability_state: string; graph_impact: number; confidence: number;
    graph_impact_detail: { proximity: number; downstream: number; chain_length: number | null; dependents: number };
    confidence_lowered_by?: { edge: string; confidence: number; reason: string }[];
  };
  related: { predictive_risk: number | null; fragility_score: number | null; graph_risk: number | null } | null;
}

export interface AttackPathDetail extends AttackPathRow {
  nodes: AttackNode[];
  edges: AttackEdge[];
  evidence: ({ type: string; basis: EvidenceBasis; node: string; stage: AttackStage } & Record<string, unknown>)[];
  explanation: { basis: EvidenceBasis; text: string }[];
  break_points: { basis: "RECOMMENDED"; action: string; node_id: string; detail: string }[];
  model_version: string;
}

export interface AttackPathList {
  job: ProjectJob | null;
  snapshot: SnapshotRef | null;
  has_vulnerability_scan: boolean;
  analysis: AnalysisRun<AttackPathSummary> | null;
  statuses: AttackPathStatus[];
  status_meaning: Record<AttackPathStatus, string>;
  meaning: string;
  total: number;
  items: AttackPathRow[];
}

export interface ChokePoint { node_id: string; paths: number; score_sum: number; max_score: number; is_target: boolean }
export interface WhatIf { node_id: string; paths_before: number; paths_removed: number; paths_undetermined: number; paths_remaining: number;
  highest_score_before: number | null; highest_score_after: number | null; note: string }

export interface AttackGraphData {
  nodes: AttackNode[];
  edges: AttackEdge[];
  stages: AttackStage[];
  truncated: boolean;
  paths_included: number;
  paths_total: number;
  choke_points: ChokePoint[];
  what_if: WhatIf | null;
  meaning: string;
}

// --- maintainers ---------------------------------------------------------------------

export type IndicatorStatus = "OBSERVED" | "NOT_OBSERVED" | "UNKNOWN";
export interface BehaviourIndicator { type: string; status: IndicatorStatus; strength: number; weight: number; detail: string; evidence: Record<string, unknown>; basis: string }

export interface MaintainerProfile {
  repository: string;
  data_status: "COLLECTED" | "PARTIAL" | "UNAVAILABLE";
  unavailable: { source: string; code: string; reason: string }[];
  contributor_count: number | null;
  contributor_count_listed_by_github: number | null;
  commit_frequency: { total: number; first_at: string | null; last_at: string | null; per_week_mean: number | null; days_since_last: number | null; active_weeks: number; weeks: number } | null;
  contributor_concentration: { top_share: number | null; top_contributor: { display_name: string } | null; effective_contributors: number | null; half_of_commits_by: number | null } | null;
  release_frequency: { total: number; median_interval_days: number | null; days_since_last: number | null } | null;
  weekly_activity: { week_start: string; commits: number; contributors: number }[];
  anomaly_indicators: BehaviourIndicator[];
  attention_score: number | null;
  attention_level: Level | "UNKNOWN";
  confidence: number;
  evidence: { commits_observed: number | null; commits_truncated?: boolean; releases_observed?: number | null; commit_analysis_rows?: number; sources: string[] };
  meaning: string;
  model_version: string;
  as_of: string;
}

export interface MaintainerRow {
  maintainer_id: string;
  login: string | null;
  display_name: string;
  identified_by: string;
  commits: number;
  share: number;
  first_commit_at: string;
  last_commit_at: string;
  active_days: number;
  recent_commits: number;
  verified_commits: number;
  rank: number;
  indicators: { type: string; detail: string }[];
  change_patterns: { commits: number; security_sensitive: number; dependency_changes: number; large_changesets: number } | null;
  sample_commits?: string[];
}

export interface MaintainerList {
  job: ProjectJob | null;
  analysis: AnalysisRun | null;
  profile: MaintainerProfile | null;
  indicator_types: string[];
  meaning: string;
  total: number;
  items: MaintainerRow[];
}

// --- commits -------------------------------------------------------------------------

export type EventSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH";
export interface CommitFinding { type: string; rule: string; severity: EventSeverity; basis: EvidenceBasis; confidence: number; file: string;
  line: number | null; side: string | null; detail: string; excerpt: string | null; more_in_file?: number }
export interface AnomalyFactor { name: string; weight: number; status: "KNOWN" | "UNKNOWN"; value: number | null; contribution: number | null; detail: string }

export interface CommitRow {
  commit_sha: string;
  author_login: string | null;
  author_name: string | null;
  committed_at: string | null;
  message: string | null;
  anomaly_score: number;
  level: Level;
  confidence: number;
  indicator_types: string[];
  stats: { files: number; additions: number; deletions: number; lines: number };
  is_merge: boolean;
  verified: boolean | null;
}

export interface CommitDetail {
  commit: CommitRow & {
    files: { path: string; status: string; additions: number; deletions: number; diff_inspected: boolean; kinds: string[] }[];
    findings: CommitFinding[];
    factors: AnomalyFactor[];
    baseline: { commits: number; sufficient: boolean; median_lines: number; median_files: number; authors: number };
    coverage: { files_listed: number; files_inspected: number; files_without_diff: number; complete: boolean };
    meaning: string;
    model_version: string;
  };
  events: BehaviourEvent[];
}

export interface BehaviourEvent {
  commit_sha: string;
  repository: string;
  occurred_at: string | null;
  event_type: string;
  severity: EventSeverity;
  confidence: number;
  observed_or_inferred: string;
  changed_files: string[];
  evidence: { rule: string; file: string; line: number | null; detail: string; excerpt: string | null; basis: EvidenceBasis }[];
  summary: string;
  author: string | null;
  review_note: string;
}

export interface Monitoring { enabled: boolean; method: string; interval_minutes: number | null; polling_active: boolean; last_checked_at: string | null; note: string | null }

export interface CommitList {
  job: ProjectJob | null;
  analysis: AnalysisRun<{ data_status: string; analysed: number; not_yet_analysed: number; events: Record<string, number>; security_events: number;
    highest_anomaly: number | null; commits_analysed_total: number }> | null;
  monitoring: Monitoring;
  indicator_types: string[];
  meaning: string;
  weights: Record<string, number>;
  total: number;
  analysed_total: number;
  items: CommitRow[];
}

export interface EventList { total: number; items: BehaviourEvent[]; event_types: string[]; severities: string[]; meaning: string }

// --- cross-layer reasoning -----------------------------------------------------------

export type FindingSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export interface EvidenceItem { ref: string; layer: string; collection: string; record_id: string; basis: EvidenceBasis; summary: string; subject: string | null; confidence: number | null }
export interface FindingStatement { basis: EvidenceBasis; text: string; evidence_refs: string[] }

export interface AiFinding {
  finding_id: string;
  rule_id: string;
  category: string;
  category_meaning: string;
  severity: FindingSeverity;
  confidence: number;
  explanation: string;
  statements: FindingStatement[];
  evidence_refs: string[];
  evidence: EvidenceItem[];
  contributing_layers: string[];
  recommendation: FindingStatement;
  subject: { type: string; package_name?: string; advisory?: string; count?: number };
  model_version: string;
  provider: string;
  conditions?: { condition: string; result: "TRUE" | "FALSE" | "UNKNOWN"; note: string | null }[];
  confidence_detail?: { weakest_evidence: number; corroboration: number; completeness: number; layers: number };
}

export interface AiSummary {
  findings: number;
  by_severity: Partial<Record<FindingSeverity, number>>;
  by_category: Record<string, number>;
  grounding: { statements: number; evidence_grounding: number | null; unsupported_claim_rate: number | null; evidence_coverage: number | null;
    evidence_items: number; findings_rejected: number };
  provider: string;
  deterministic: boolean;
  layers_missing: string[];
  evidence_items: number;
  rejected_findings: unknown[];
}

export interface AiList {
  job: ProjectJob | null;
  snapshot: SnapshotRef | null;
  analysis: AnalysisRun<AiSummary> | null;
  categories: Record<string, string>;
  severities: FindingSeverity[];
  meaning: string;
  total: number;
  items: AiFinding[];
}

// --- dataset -------------------------------------------------------------------------

export type DatasetStatus = "VALID" | "WARNING" | "LOW_CONFIDENCE" | "INVALID" | "UNKNOWN";
export interface DatasetVersion {
  id: string;
  version: number;
  record_count: number;
  dataset_hash: string;
  chain_hash: string;
  hash_algorithm: string;
  commit_sha: string | null;
  created_at: string;
  truncated: boolean;
  records_pruned: boolean;
  validations: number;
  previous_dataset_id: string | null;
  changes: { comparable: boolean; added?: number; removed?: number; changed?: number; unchanged?: number } | null;
  latest_quality: { status: DatasetStatus; quality_score: number | null; confidence: number; validated_at: string } | null;
  sources?: { layer: string; collection: string; basis: string; model_version: string | null; collected_at: string | null }[];
}

export interface DatasetList {
  job: ProjectJob | null;
  snapshot: SnapshotRef | null;
  current: DatasetVersion | null;
  statuses: DatasetStatus[];
  weights: Record<string, number>;
  limitation: string;
  chain_intact: boolean | null;
  total: number;
  items: DatasetVersion[];
}

export interface QualityFactor { name: string; weight: number; status: "KNOWN" | "UNKNOWN"; value: number | null; contribution: number | null; detail: string; warnings: string[] }

export interface DatasetQuality {
  dataset: { id: string; version: number; record_count: number; dataset_hash: string; chain_hash: string; hash_algorithm: string };
  quality: {
    status: DatasetStatus;
    quality_score: number | null;
    confidence: number;
    factors: QualityFactor[];
    warnings: string[];
    reasons: string[];
    records: number;
    integrity: { status: string; records_checked: number; altered_count: number };
    completeness: { value: number | null; missing_by_field: Record<string, number>; cells: number; filled: number };
    provenance: { source_layers_present: string[]; source_layers_missing: string[]; field_provenance_completeness: number | null; source_diversity: number;
      sources: { layer: string; collection: string; basis: string; model_version: string | null }[] };
    duplicates: { exact_duplicate_records: number; repeated_identity_records: number; near_duplicate_groups: number; near_duplicate_records: number;
      label_conflict_records: number; note: string };
    balance: { label: string; labelled: number; unlabelled: number; classes: Record<string, number>; minority_share: number | null; note: string | null;
      distributions: Record<string, Record<string, number>> };
    suspicious_records: { record_id: string; problems: { kind: string; rule: string; detail: string }[] }[];
    limitation: string;
    created_at: string;
  } | null;
  history: { created_at: string; status: DatasetStatus; quality_score: number | null; confidence: number; records: number }[];
  integrity_now: { status: string; records_checked?: number; altered_count?: number; altered_records?: string[]; chain_intact?: boolean | null; reason?: string };
  limitation: string;
}

// --- trust ---------------------------------------------------------------------------

export interface TrustComponent {
  name: string;
  label: string;
  weight: number;
  status: "KNOWN" | "UNKNOWN";
  risk: number | null;
  contribution: number | null;
  confidence: number;
  basis: EvidenceBasis;
  detail: string;
  layer?: string;
  layer_status?: string;
  inputs?: Record<string, unknown>;
}

export interface TrustResult {
  id: string;
  status: "SCORED" | "INSUFFICIENT_DATA";
  trust_score: number | null;
  risk_score: number | null;
  band: string | null;
  confidence: number;
  coverage: number;
  min_coverage?: number;
  risk_low: number;
  risk_high: number;
  trust_low: number;
  trust_high: number;
  unknown_components: string[];
  insufficient_reason?: string;
  components: TrustComponent[];
  evidence?: { layer: string; label: string; status: string; reference: { collection: string; id: string } | null; as_of: string | null }[];
  explanation?: TrustExplanation;
  created_at: string;
  commit_sha?: string | null;
  model_version: string;
}

export interface TrustExplanation {
  headline: string;
  status: string;
  calculation: { formula: string; worked: string | null; bounds: string; confidence: string; weights_statement: string };
  top_risks: { name: string; label: string; risk: number; contribution: number; weight: number; detail: string }[];
  unknown: { name: string; label: string; weight: number; reason: string; layer_status: string }[];
  recommendations: { basis: "RECOMMENDED"; component: string; priority: number; text: string; because: string }[];
  meaning: string;
}

export interface TrustCurrent {
  job: ProjectJob | null;
  snapshot: SnapshotRef | null;
  trust: TrustResult | null;
  up_to_date: boolean | null;
  model_version: string;
  weights: Record<string, number>;
  labels: Record<string, string>;
  weights_statement: string;
  meaning: string;
}

export interface TrustPoint { id?: string; created_at: string; status: string; trust_score: number | null; risk_score: number | null; confidence: number | null; coverage: number | null; commit_sha?: string | null }

// --- overview and report -------------------------------------------------------------

export interface ScoreBucket { range: string; count: number }
export interface LayerState { name: string; label: string; status: "ANALYSED" | "NOT_ANALYSED" | "STALE" | "UNAVAILABLE"; as_of: string | null }

export interface Overview {
  generated_at: string;
  project: { id: string; name: string; repository_url: string };
  snapshot: { id: string; commit_sha: string; branch: string | null } | null;
  layers: LayerState[];
  missing: { layer: string; label: string; status: string; action: string }[];
  trust: { current: (Omit<TrustResult, "evidence" | "explanation">) | null; trend: TrustPoint[]; weights_statement: string };
  executive: {
    headline: string;
    top_risks: TrustExplanation["top_risks"];
    recommendations: TrustExplanation["recommendations"];
    findings: Pick<AiFinding, "finding_id" | "category" | "severity" | "confidence" | "explanation" | "contributing_layers">[];
    attack_paths: Pick<AttackPathRow, "attack_path_id" | "score" | "level" | "status" | "confidence" | "target" | "advisory">[];
    numbers: Record<"dependencies" | "vulnerabilities" | "reachable" | "attack_paths" | "security_events" | "ai_findings", number | null>;
  };
  technical: {
    inventory: { total: number; direct: number | null; transitive: number | null; unresolved_versions: number | null; max_depth: number | null; by_ecosystem: Record<string, number> } | null;
    vulnerabilities: { by_severity: Record<string, number>; affected_dependencies: number; distinct: number } | null;
    sbom: { version: number; component_count: number; verified: boolean | null; content_digest: string } | null;
    reachability: { by_status: Record<string, number>; findings: number; source_complete: boolean } | null;
    fragility: { summary: { dependencies: number; by_level: Record<string, number>; highest: number | null; mean: number | null }; distribution: ScoreBucket[] } | null;
    predictive: { summary: { dependencies: number; by_level: Record<string, number>; indicators: Record<string, number>; indicator_total: number }; distribution: ScoreBucket[] } | null;
    attack_paths: { summary: { paths: number; by_status: Record<string, number>; by_level: Record<string, number>; by_severity: Record<string, number>; highest_score: number | null }; distribution: ScoreBucket[] } | null;
    maintainers: { attention_score: number | null; attention_level: string; confidence: number; contributor_count: number | null; top_share: number | null;
      indicators: { type: string; status: IndicatorStatus; detail: string }[] } | null;
    commits: { analysed_total: number; by_level: Record<string, number>; security_events: number; security_events_by_type: Record<string, number>;
      highest_anomaly: number | null; mean_anomaly: number | null;
      timeline: { commit_sha: string; committed_at: string | null; anomaly_score: number; level: Level; message: string | null }[];
      recent_events: { commit_sha: string; event_type: string; severity: EventSeverity; occurred_at: string | null; summary: string }[] } | null;
    dataset: { version: number; record_count: number; quality_status: DatasetStatus; quality_score: number | null; quality_confidence: number | null } | null;
    ai: { summary: Pick<AiSummary, "findings" | "by_severity" | "by_category" | "grounding"> } | null;
  };
  research: {
    model_versions: Record<string, string>;
    weights_statement: string;
    component_confidence: { name: string; label: string; status: string; confidence: number; basis: string }[];
    measured: { evidence_grounding: number | null; unsupported_claim_rate: number | null; evidence_coverage: number | null; layer_coverage: number;
      trust_weight_coverage: number | null; dataset_quality_score: number | null; execution_seconds: { job_type: string; state: string; seconds: number }[] };
    not_measured_note: string;
  };
}

export interface ReportStatement { basis: EvidenceBasis; text: string; evidence: string[] }
export interface ReportTable { title: string; columns: string[]; rows: { cells: (string | number | null)[]; evidence: string[] }[] }
export interface ReportSection { number: number; id: string; title: string; available: boolean; statements: ReportStatement[]; tables: ReportTable[] }
export interface ReportEvidence { ref: string; kind: "record" | "method"; layer: string; collection: string | null; record_id: string | null; document?: string; model_version?: string | null; as_of: string | null }
export interface Report {
  title: string;
  generated_at: string;
  project: { id: string; name: string; repository_url: string };
  snapshot: { commit_sha: string; branch: string | null } | null;
  sections: ReportSection[];
  evidence: ReportEvidence[];
  statement_count: number;
}

export interface EvaluationRow { component: string; measure: string; status: "EVALUATED" | "NOT_EVALUATED"; value: number | null; benchmark: string | null; needs: string; measured_per_run: boolean; display?: string }
export interface DashboardTrust { project_id: string; name: string; analysed: boolean; status: string; trust_score?: number | null; risk_score?: number | null; confidence?: number | null; coverage?: number | null }
