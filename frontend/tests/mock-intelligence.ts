import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import type { Page, Request, Route } from "@playwright/test";

import { COMMIT, PROJECT_ID } from "./mock-api";

/**
 * Test double for the Phase 5 endpoints (dependency intelligence). Register it after mockApi.
 *
 * The data in fixtures/intelligence.json was recorded from the real backend running its test
 * scenario (see backend/tests/record_ui_fixture.py), so the page is exercised against what the
 * API actually returns. Package versions and dates in it are test data, not registry facts.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */
type Json = any;
const recorded: Json = JSON.parse(readFileSync(fileURLToPath(new URL("./fixtures/intelligence.json", import.meta.url)), "utf-8"));
export const predictive: Json = recorded.predictive;
export const fragilityOnly: Json = recorded.fragility;
export const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value));

const base = `/projects/${PROJECT_ID}`;
const snapshot = { id: "s1", commit_sha: COMMIT, branch: "main" };
const STAGES = ["GRAPH_METRICS", "PACKAGE_METADATA", "FRAGILITY", "RISK_PROPAGATION", "PREDICTION"];

export function makeIntelligenceJob(state: string, overrides: Record<string, unknown> = {}) {
  const done = state === "completed" || state === "partial";
  const index = state === "queued" ? 0 : state === "running" ? 2 : done ? STAGES.length + 1 : 1;
  return {
    id: "job-intelligence", project_id: PROJECT_ID, type: "predictive_dependency_analysis", state, stages: STAGES, stage_count: STAGES.length + 1,
    stage_index: index, stage: index === 0 ? "QUEUED" : done ? "COMPLETED" : STAGES[index - 1],
    message: state === "running" ? "Looked up 5 of 9 package(s) in their registries" : done ? "9 dependencies assessed; 6 indicator(s)" : "Waiting for the background worker",
    error: state === "partial" ? { code: "METADATA_INCOMPLETE", message: "Release metadata could not be collected for 1 of 9 package(s). Their version and release-age factors are unknown, not estimated; everything else was analysed." } : null,
    summary: null, created_at: "2026-02-03T10:20:00Z", started_at: state === "queued" ? null : "2026-02-03T10:20:02Z",
    finished_at: done || state === "failed" ? "2026-02-03T10:20:09Z" : null, ...overrides,
  };
}

export interface IntelligenceState {
  analysed: boolean;                       // the project has a dependency inventory
  scanned: boolean;                        // a vulnerability check exists for the snapshot
  mode: "predictive" | "fragility" | "none";
  list: Json;                              // the predictive list response (analysis + items)
  fragilityList: Json;
  details: Record<string, Json>;
  graph: Json;
  history: Json;
  compare: Json;
  currentInputs: Json | null;              // null: same as the analysis' inputs
  jobs: (ReturnType<typeof makeIntelligenceJob> | null)[];
  startJobs: (ReturnType<typeof makeIntelligenceJob> | null)[] | null;
  afterAnalysis: Partial<IntelligenceState> | null;
  otherActive: Record<string, unknown> | null;
  failures: Record<string, number>;
  startStatus: number;
  requests: { method: string; path: string; query: Record<string, string> }[];
}

export function intelligenceState(overrides: Partial<IntelligenceState> = {}): IntelligenceState {
  return {
    analysed: true, scanned: true, mode: "predictive", list: clone(predictive.list), fragilityList: clone(fragilityOnly.list),
    details: clone(predictive.details), graph: clone(predictive.graph), history: clone(predictive.history), compare: clone(predictive.compare),
    currentInputs: null, jobs: [makeIntelligenceJob("completed")], startJobs: null, afterAnalysis: null, otherActive: null, failures: {},
    startStatus: 202, requests: [], ...overrides,
  };
}

/** The state of a snapshot for which only fragility was analysed (no vulnerability check). */
export function fragilityOnlyState(overrides: Partial<IntelligenceState> = {}): IntelligenceState {
  return intelligenceState({
    scanned: false, mode: "fragility", details: clone(fragilityOnly.details),
    history: { items: [clone(fragilityOnly.list.analysis)] },
    jobs: [makeIntelligenceJob("completed", { type: "dependency_fragility_analysis", message: "9 dependencies scored for fragility" })], ...overrides,
  });
}

export const idOf = (name: string): string => predictive.list.items.find((item: Json) => item.normalized_name === name).dependency_id;

const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
const LEVELS = { fragility: "fragility_level", predictive: "level" } as const;

function filterRows(items: Json[], query: Record<string, string>, levelField: string): Json[] {
  let rows = items;
  if (query.q) rows = rows.filter((row) => row.normalized_name.includes(query.q.toLowerCase()));
  if (query.level) rows = rows.filter((row) => row[levelField] === query.level);
  if (query.relationship) rows = rows.filter((row) => row.relationship === query.relationship);
  if (query.ecosystem) rows = rows.filter((row) => row.ecosystem === query.ecosystem);
  if (query.indicator) rows = rows.filter((row) => row.indicator_types.includes(query.indicator));
  if (query.vulnerable === "true") rows = rows.filter((row) => row.vulnerability_count > 0);
  const key = { fragility: "fragility_score", centrality: "relative_centrality", dependents: "dependents" }[query.sort ?? ""];
  if (key) rows = [...rows].sort((a, b) => b[key] - a[key] || a.node_id.localeCompare(b.node_id));
  if (query.sort === "name") rows = [...rows].sort((a, b) => a.normalized_name.localeCompare(b.normalized_name));
  return rows;
}

export async function mockIntelligence(page: Page, state: IntelligenceState): Promise<void> {
  let polls = 0;
  await page.route("**/api/projects/*/{jobs,fragility,graph-risk,predictive-risk}**", async (route: Route, request: Request) => {
    const url = new URL(request.url());
    const path = url.pathname.replace(/^\/api/, "");
    const query = Object.fromEntries(url.searchParams.entries());
    const method = request.method();
    state.requests.push({ method, path, query });
    for (const [fragment, status] of Object.entries(state.failures)) {
      if (path.endsWith(fragment)) return json(route, status, { detail: status === 500 ? "Internal server error" : "Simulated failure" });
    }
    const latest = () => state.jobs[Math.min(polls, state.jobs.length - 1)] ?? null;
    const envelope = (source: Json, present: boolean, levelField: string) => {
      const rows = present ? filterRows(source.items, query, levelField) : [];
      const skip = Number(query.skip ?? 0);
      const limit = Number(query.limit ?? 100);
      const analysis = present ? source.analysis : null;
      return {
        ...source, job: latest(), snapshot: state.analysed ? snapshot : null, has_vulnerability_scan: state.analysed && state.scanned,
        current_inputs: !state.analysed ? null : state.currentInputs ?? {
          vulnerability_scan_matched_at: analysis?.inputs.vulnerability_scan_matched_at ?? null,
          reachability_completed_at: analysis?.inputs.reachability?.completed_at ?? null },
        analysis: analysis ? { ...analysis, commit_sha: COMMIT } : null, total: rows.length, skip, limit, items: rows.slice(skip, skip + limit),
      };
    };

    if (path === `${base}/jobs`) {
      const job = latest();
      polls += 1;
      if (job && (job.state === "completed" || job.state === "partial") && state.afterAnalysis) {
        Object.assign(state, state.afterAnalysis);
        state.afterAnalysis = null;
      }
      const active = job && (job.state === "queued" || job.state === "running") ? job : state.otherActive;
      return json(route, 200, { active, items: job ? [job] : [] });
    }
    if (method === "POST" && (path === `${base}/predictive-risk/analyze` || path === `${base}/fragility/analyze`)) {
      if (state.startStatus !== 202) {
        return json(route, state.startStatus, { detail: state.startStatus === 409 ? "Another job is already queued or running for this project"
          : "Too many jobs requested. Try again later." });
      }
      if (state.startJobs) state.jobs = state.startJobs;
      polls = 0;
      return json(route, 202, { job: state.jobs[0] });
    }
    if (path === `${base}/predictive-risk`) return json(route, 200, envelope(state.list, state.mode === "predictive", LEVELS.predictive));
    if (path === `${base}/fragility`) return json(route, 200, envelope(state.fragilityList, state.mode !== "none", LEVELS.fragility));
    if (path === `${base}/predictive-risk/graph`) {
      return state.mode === "predictive" ? json(route, 200, state.graph) : json(route, 404, { detail: "No predictive analysis exists for the latest snapshot" });
    }
    if (path === `${base}/predictive-risk/history`) return json(route, 200, state.mode === "none" ? { items: [] } : state.history);
    if (path === `${base}/predictive-risk/compare`) return json(route, 200, state.compare);
    const dependencyId = path.match(new RegExp(`^${base}/(?:predictive-risk|fragility)/([^/]+)$`))?.[1];
    if (dependencyId) {
      const detail = state.details[dependencyId];
      return detail ? json(route, 200, detail) : json(route, 404, { detail: "No analysis result exists for that dependency" });
    }
    return route.fallback();
  });
}
