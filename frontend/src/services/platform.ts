import type {
  AiFinding, AiList, AnalysisRun, AttackGraphData, AttackPathDetail, AttackPathList, CommitDetail, CommitList, DatasetList, DatasetQuality, DatasetVersion,
  EvaluationRow, EventList, MaintainerList, MaintainerRow, Monitoring, Overview, Report, TrustCurrent, TrustExplanation, TrustPoint,
} from "../utils/platformTypes";
import type { ProjectJob } from "../utils/types";
import { api } from "./api";

const base = (projectId: string) => `/projects/${encodeURIComponent(projectId)}`;
const clean = (query: object) => Object.fromEntries(Object.entries(query).filter(([, value]) => value !== undefined && value !== "" && value !== null));

async function startJob(path: string): Promise<ProjectJob> {
  const { data } = await api.post<{ job: ProjectJob }>(path);
  return data.job;
}

async function read<T>(path: string, params?: object): Promise<T> {
  const { data } = await api.get<T>(path, params ? { params: clean(params) } : undefined);
  return data;
}

// attack paths
export const startAttackPathAnalysis = (projectId: string) => startJob(`${base(projectId)}/attack-paths/analyze`);
export const listAttackPaths = (projectId: string, query: { status?: string; level?: string; q?: string; limit?: number } = {}) =>
  read<AttackPathList>(`${base(projectId)}/attack-paths`, { limit: 200, ...query });
export const getAttackPath = (projectId: string, pathId: string) => read<AttackPathDetail>(`${base(projectId)}/attack-paths/${encodeURIComponent(pathId)}`);
export const getAttackGraph = (projectId: string, without?: string) => read<AttackGraphData>(`${base(projectId)}/attack-paths/graph`, { without });

// maintainers
export const startMaintainerAnalysis = (projectId: string) => startJob(`${base(projectId)}/maintainers/analyze`);
export const listMaintainers = (projectId: string) => read<MaintainerList>(`${base(projectId)}/maintainers`, { limit: 200 });
export const getMaintainer = (projectId: string, maintainerId: string) =>
  read<{ maintainer: MaintainerRow; repository: { repository: string; data_status: string }; meaning: string }>(`${base(projectId)}/maintainers/${encodeURIComponent(maintainerId)}`);

// commits
export const startCommitAnalysis = (projectId: string) => startJob(`${base(projectId)}/commits/analyze`);
export const listCommits = (projectId: string, query: { level?: string; indicator?: string; q?: string; sort?: string } = {}) =>
  read<CommitList>(`${base(projectId)}/commits`, { limit: 200, ...query });
export const getCommit = (projectId: string, sha: string) => read<CommitDetail>(`${base(projectId)}/commits/${encodeURIComponent(sha)}`);
export const listSecurityEvents = (projectId: string, query: { type?: string; severity?: string } = {}) =>
  read<EventList>(`${base(projectId)}/security-events`, { limit: 200, ...query });
export async function setCommitMonitoring(projectId: string, enabled: boolean): Promise<Monitoring> {
  const { data } = await api.post<{ monitoring: Monitoring }>(`${base(projectId)}/commits/monitoring`, { enabled });
  return data.monitoring;
}

// cross-layer reasoning
export const startAiAnalysis = (projectId: string) => startJob(`${base(projectId)}/ai-analysis`);
export const listAiFindings = (projectId: string, query: { severity?: string; category?: string; layer?: string } = {}) =>
  read<AiList>(`${base(projectId)}/ai-analysis`, { limit: 200, ...query });
export const getAiFinding = (projectId: string, findingId: string) => read<AiFinding>(`${base(projectId)}/ai-analysis/${encodeURIComponent(findingId)}`);

// dataset
export const startDatasetValidation = (projectId: string) => startJob(`${base(projectId)}/datasets/validate`);
export const listDatasets = (projectId: string) => read<DatasetList>(`${base(projectId)}/datasets`);
export const getDatasetQuality = (projectId: string, datasetId: string) => read<DatasetQuality>(`${base(projectId)}/datasets/${encodeURIComponent(datasetId)}/quality`);
export const getDataset = (projectId: string, datasetId: string, query: { suspicious?: boolean; limit?: number } = {}) =>
  read<{ dataset: DatasetVersion; records: { total: number; items: Record<string, unknown>[] } }>(`${base(projectId)}/datasets/${encodeURIComponent(datasetId)}`, query);

// trust
export const startTrustAnalysis = (projectId: string) => startJob(`${base(projectId)}/trust/analyze`);
export const getTrust = (projectId: string) => read<TrustCurrent>(`${base(projectId)}/trust`);
export const getTrustHistory = (projectId: string) => read<{ items: TrustPoint[] }>(`${base(projectId)}/trust/history`, { limit: 100 });
export const getTrustExplanation = (projectId: string) => read<TrustExplanation & { evidence: NonNullable<TrustCurrent["trust"]>["evidence"] }>(`${base(projectId)}/trust/explanation`);

// overview, report, evaluation
export const getOverview = (projectId: string) => read<Overview>(`${base(projectId)}/overview`);
export const getReport = (projectId: string) => read<Report>(`${base(projectId)}/report`);
export async function downloadReportMarkdown(projectId: string): Promise<Blob> {
  const { data } = await api.get<Blob>(`${base(projectId)}/report`, { params: { format: "markdown" }, responseType: "blob" });
  return data;
}
export const getEvaluation = () => read<{ items: EvaluationRow[]; not_evaluated: number; total: number; note: string }>("/dashboard/evaluation");
export type { AnalysisRun };
