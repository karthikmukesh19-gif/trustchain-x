import type {
  JobListing, JobType, MatchDetail, ProjectJob, SbomComponentList, SbomDiff, SbomListing, SbomVerification, VulnerabilityList,
} from "../utils/types";
import { api } from "./api";

const base = (projectId: string) => `/projects/${encodeURIComponent(projectId)}`;
const clean = (query: object) => Object.fromEntries(Object.entries(query).filter(([, value]) => value !== undefined && value !== "" && value !== false));

export async function listJobs(projectId: string, types?: JobType[]): Promise<JobListing> {
  const { data } = await api.get<JobListing>(`${base(projectId)}/jobs`, { params: types?.length ? { type: types.join(",") } : undefined });
  return data;
}

async function startJob(path: string): Promise<ProjectJob> {
  const { data } = await api.post<{ job: ProjectJob }>(path);
  return data.job;
}

// --- vulnerabilities ---------------------------------------------------------

export const startVulnerabilitySync = (projectId: string) => startJob(`${base(projectId)}/vulnerabilities/sync`);
export const startVulnerabilityMatching = (projectId: string) => startJob(`${base(projectId)}/vulnerabilities/analyze`);

export interface VulnerabilityQuery {
  skip?: number;
  limit?: number;
  severity?: string;
  match_status?: string;
  ecosystem?: string;
  q?: string;
}

export async function listVulnerabilities(projectId: string, query: VulnerabilityQuery = {}): Promise<VulnerabilityList> {
  const { data } = await api.get<VulnerabilityList>(`${base(projectId)}/vulnerabilities`, { params: clean(query) });
  return data;
}

export async function getVulnerabilityMatch(projectId: string, matchId: string): Promise<MatchDetail> {
  const { data } = await api.get<MatchDetail>(`${base(projectId)}/vulnerabilities/${encodeURIComponent(matchId)}`);
  return data;
}

// --- SBOM --------------------------------------------------------------------

export const startSbomGeneration = (projectId: string) => startJob(`${base(projectId)}/sbom/generate`);

export async function listSboms(projectId: string): Promise<SbomListing> {
  const { data } = await api.get<SbomListing>(`${base(projectId)}/sbom`);
  return data;
}

export async function verifySbom(projectId: string, sbomId: string): Promise<SbomVerification> {
  const { data } = await api.post<SbomVerification>(`${base(projectId)}/sbom/${encodeURIComponent(sbomId)}/verify`, undefined, { timeout: 60000 });
  return data;
}

export async function diffSboms(projectId: string, baseId: string, targetId: string): Promise<SbomDiff> {
  const { data } = await api.get<SbomDiff>(
    `${base(projectId)}/sbom/${encodeURIComponent(baseId)}/diff/${encodeURIComponent(targetId)}`, { timeout: 60000 });
  return data;
}

export interface ComponentQuery {
  skip?: number;
  limit?: number;
  q?: string;
  only_vulnerable?: boolean;
}

export async function listSbomComponents(projectId: string, sbomId: string, query: ComponentQuery = {}): Promise<SbomComponentList> {
  const { data } = await api.get<SbomComponentList>(`${base(projectId)}/sbom/${encodeURIComponent(sbomId)}/components`, { params: clean(query) });
  return data;
}

/** Fetch the CycloneDX document with the session's credentials and hand it to the browser as a file. */
export async function downloadSbom(projectId: string, sbomId: string, filename: string): Promise<void> {
  const { data } = await api.get<Blob>(`${base(projectId)}/sbom/${encodeURIComponent(sbomId)}/document`, { responseType: "blob", timeout: 60000 });
  const url = URL.createObjectURL(data);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
