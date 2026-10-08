import type { DashboardSummary, Project, ProjectList } from "../utils/types";
import { api } from "./api";

export interface NewProject {
  name: string;
  repository_url: string;
  description: string;
}

export async function listProjects(): Promise<ProjectList> {
  const { data } = await api.get<ProjectList>("/projects", { params: { limit: 100 } });
  return data;
}

export async function getProject(id: string): Promise<Project> {
  const { data } = await api.get<Project>(`/projects/${encodeURIComponent(id)}`);
  return data;
}

export async function createProject(project: NewProject): Promise<Project> {
  const { data } = await api.post<Project>("/projects", project);
  return data;
}

export async function refreshMetadata(id: string): Promise<Project> {
  const { data } = await api.post<Project>(`/projects/${encodeURIComponent(id)}/refresh-metadata`);
  return data;
}

export async function deleteProject(id: string): Promise<void> {
  await api.delete(`/projects/${encodeURIComponent(id)}`);
}

export async function getDashboardSummary(): Promise<DashboardSummary> {
  const { data } = await api.get<DashboardSummary>("/dashboard/summary");
  return data;
}
