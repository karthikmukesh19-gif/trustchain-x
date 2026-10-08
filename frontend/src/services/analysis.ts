import type { AnalysisJob, AnalysisStatus, DependencyGraphData, DependencyList, Snapshot } from "../utils/types";
import { api } from "./api";

const base = (projectId: string) => `/projects/${encodeURIComponent(projectId)}`;

export async function startDependencyAnalysis(projectId: string): Promise<AnalysisJob> {
  const { data } = await api.post<{ job: AnalysisJob }>(`${base(projectId)}/analysis/dependencies`);
  return data.job;
}

export async function getAnalysisStatus(projectId: string): Promise<AnalysisStatus> {
  const { data } = await api.get<AnalysisStatus>(`${base(projectId)}/analysis/status`);
  return data;
}

export async function getSnapshot(projectId: string): Promise<Snapshot> {
  const { data } = await api.get<Snapshot>(`${base(projectId)}/snapshot`);
  return data;
}

export interface DependencyQuery {
  skip?: number;
  limit?: number;
  ecosystem?: string;
  relationship?: string;
  version_status?: string;
  q?: string;
}

export async function listDependencies(projectId: string, query: DependencyQuery = {}): Promise<DependencyList> {
  const params = Object.fromEntries(Object.entries(query).filter(([, value]) => value !== undefined && value !== ""));
  const { data } = await api.get<DependencyList>(`${base(projectId)}/dependencies`, { params });
  return data;
}

export async function getDependencyGraph(projectId: string, pathsTo?: string): Promise<DependencyGraphData> {
  const { data } = await api.get<DependencyGraphData>(`${base(projectId)}/dependencies/graph`, {
    params: pathsTo ? { paths_to: pathsTo } : undefined,
    timeout: 60000,
  });
  return data;
}

export async function getDependencyPaths(projectId: string, nodeId: string): Promise<string[][]> {
  const { data } = await api.get<{ paths: string[][] }>(`${base(projectId)}/dependencies/paths`, { params: { to: nodeId } });
  return data.paths;
}
