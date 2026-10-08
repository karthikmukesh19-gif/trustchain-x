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
