import type {
  AnalysisComparison, FragilityDetail, FragilityRow, IntelligenceAnalysis, IntelligenceKind, IntelligenceList, PredictionDetail, PredictionRow,
  ProjectJob, RiskGraphData,
} from "../utils/types";
import { api } from "./api";

const base = (projectId: string) => `/projects/${encodeURIComponent(projectId)}`;
const clean = (query: object) => Object.fromEntries(Object.entries(query).filter(([, value]) => value !== undefined && value !== "" && value !== false));

async function startJob(path: string): Promise<ProjectJob> {
  const { data } = await api.post<{ job: ProjectJob }>(path);
  return data.job;
}

/** Fragility, graph risk, indicators and predictive dependency risk in one job. Needs a vulnerability check of the snapshot. */
export const startPredictiveAnalysis = (projectId: string) => startJob(`${base(projectId)}/predictive-risk/analyze`);
/** Structure and upkeep only. Does not need a vulnerability check. */
export const startFragilityAnalysis = (projectId: string) => startJob(`${base(projectId)}/fragility/analyze`);

export interface IntelligenceQuery {
  skip?: number;
  limit?: number;
  q?: string;
  ecosystem?: string;
  level?: string;
  relationship?: string;
  indicator?: string;
  vulnerable?: boolean;
  reachable?: boolean;
  sort?: string;
}

export async function listPredictiveRisk(projectId: string, query: IntelligenceQuery = {}): Promise<IntelligenceList<PredictionRow>> {
  const { data } = await api.get<IntelligenceList<PredictionRow>>(`${base(projectId)}/predictive-risk`, { params: clean(query) });
  return data;
}

export async function listFragility(projectId: string, query: IntelligenceQuery = {}): Promise<IntelligenceList<FragilityRow>> {
  const { q, ecosystem, level, relationship, skip, limit } = query;
  const { data } = await api.get<IntelligenceList<FragilityRow>>(`${base(projectId)}/fragility`, { params: clean({ q, ecosystem, level, relationship, skip, limit }) });
  return data;
}

export async function getPredictiveRisk(projectId: string, dependencyId: string): Promise<PredictionDetail> {
  const { data } = await api.get<PredictionDetail>(`${base(projectId)}/predictive-risk/${encodeURIComponent(dependencyId)}`);
  return data;
}

export async function getFragility(projectId: string, dependencyId: string): Promise<FragilityDetail> {
  const { data } = await api.get<FragilityDetail>(`${base(projectId)}/fragility/${encodeURIComponent(dependencyId)}`);
  return data;
}

export async function getRiskGraph(projectId: string): Promise<RiskGraphData> {
  const { data } = await api.get<RiskGraphData>(`${base(projectId)}/predictive-risk/graph`);
  return data;
}

export async function listAnalysisHistory(projectId: string, kind?: IntelligenceKind): Promise<IntelligenceAnalysis[]> {
  const { data } = await api.get<{ items: IntelligenceAnalysis[] }>(`${base(projectId)}/predictive-risk/history`, { params: clean({ kind, limit: 20 }) });
  return data.items;
}

export async function compareAnalyses(projectId: string, baseId: string, targetId: string): Promise<AnalysisComparison> {
  const { data } = await api.get<AnalysisComparison>(`${base(projectId)}/predictive-risk/compare`, { params: { base: baseId, target: targetId } });
  return data;
}
