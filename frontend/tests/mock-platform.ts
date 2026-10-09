import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import type { Page, Request, Route } from "@playwright/test";

import { PROJECT_ID, makeProject, user } from "./mock-api";

/**
 * Test double for the attack-path, maintainer, commit, reasoning, dataset, trust, overview and report endpoints.
 * Register it after mockApi.
 *
 * fixtures/platform.json was recorded from the real backend running its test scenario
 * (backend/tests/record_ui_fixture.py --platform), so the pages are exercised against what the API actually returns:
 * `empty` is a project with only a dependency inventory, `full` the same project after every layer was analysed.
 * Advisories named TEST-*, the commit history and the people in it are test data.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */
type Json = any;
const recorded: Json = JSON.parse(readFileSync(fileURLToPath(new URL("./fixtures/platform.json", import.meta.url)), "utf-8"));
export const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value));
export const full: Json = recorded.full;
export const empty: Json = recorded.empty;
export const insufficient: Json = recorded.insufficient;
export const dashboard: Json = recorded.dashboard;
export const evaluation: Json = recorded.evaluation;

const base = `/projects/${PROJECT_ID}`;
const START_PATHS: Record<string, string> = {
  "/attack-paths/analyze": "attack_paths", "/maintainers/analyze": "maintainers", "/commits/analyze": "commits", "/ai-analysis": "ai",
  "/datasets/validate": "dataset", "/trust/analyze": "trust",
};

/** A job of the given recorded kind in another state. */
export function makeJob(kind: string, state: string, overrides: Record<string, unknown> = {}) {
  const done: Json = clone(full.jobs[kind]);
  const stages: string[] = done.stages;
  const index = state === "queued" ? 0 : state === "running" ? Math.min(2, stages.length) : state === "failed" ? 1 : stages.length + 1;
  const finished = state === "completed" || state === "partial" || state === "failed";
  return {
    ...done, state, stage_index: index, stage: index === 0 ? "QUEUED" : index > stages.length ? "COMPLETED" : stages[index - 1],
    message: state === "queued" ? "Waiting for the background worker" : state === "running" ? "Working" : state === "failed" ? "The job stopped" : done.message,
    error: state === "failed" ? { code: "INTERNAL_ERROR", message: "The job stopped because of an internal error." } : state === "partial" ? done.error ?? { code: "PARTIAL", message: "Part of the input was missing." } : null,
    finished_at: finished ? done.finished_at : null, started_at: state === "queued" ? null : done.started_at, ...overrides,
  };
}

export interface PlatformState {
  /** Responses currently served: a (possibly modified) copy of `full` or `empty`. */
  data: Json;
  /** Whether the project has a dependency inventory at all. */
  analysed: boolean;
  /** Jobs returned by successive polls of /jobs; the last repeats. null = never run. */
  jobs: (Json | null)[];
  /** Jobs to serve after a start request. */
  startJobs: (Json | null)[] | null;
  /** Data that replaces `data` once a served job has completed. */
  afterAnalysis: Json | null;
  startStatus: number;
  failures: Record<string, number>;
  requests: { method: string; path: string; query: Record<string, string>; body: Json }[];
}

export function platformState(overrides: Partial<PlatformState> = {}): PlatformState {
  return { data: clone(full), analysed: true, jobs: [null], startJobs: null, afterAnalysis: null, startStatus: 202, failures: {}, requests: [], ...overrides };
}

/** The state of a project whose layers have not been analysed yet. */
export const emptyState = (overrides: Partial<PlatformState> = {}) => platformState({ data: clone(empty), ...overrides });

const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });

export async function mockPlatform(page: Page, state: PlatformState): Promise<void> {
  let polls = 0;
  const latest = () => state.jobs[Math.min(polls, state.jobs.length - 1)] ?? null;

  await page.route("**/api/dashboard/**", async (route: Route, request: Request) => {
    const path = new URL(request.url()).pathname.replace(/^\/api/, "");
    state.requests.push({ method: request.method(), path, query: {}, body: null });
    if (path === "/dashboard/evaluation") return json(route, 200, evaluation);
    if (path === "/dashboard/summary") {
      const trust = state.data.trust.trust;
      const entry = { project_id: PROJECT_ID, name: "ShadowWatch", analysed: state.analysed, status: trust?.status ?? "NOT_ANALYSED",
        ...(trust ? { trust_score: trust.trust_score, risk_score: trust.risk_score, confidence: trust.confidence, coverage: trust.coverage, band: trust.band, created_at: trust.created_at } : {}) };
      return json(route, 200, { ...dashboard, projects_total: 1, projects_analysed: state.analysed ? 1 : 0, recent_projects: [makeProject()], trust: [entry] });
    }
    return route.fallback();
  });

  await page.route("**/api/projects/*/{jobs,attack-paths,maintainers,commits,security-events,behaviour-events,ai-analysis,datasets,trust,overview,report}**", async (route: Route, request: Request) => {
    const url = new URL(request.url());
    const path = url.pathname.replace(/^\/api/, "");
    const query = Object.fromEntries(url.searchParams.entries());
    const method = request.method();
    const body = method === "POST" ? request.postDataJSON() : null;
    state.requests.push({ method, path, query, body });
    for (const [fragment, status] of Object.entries(state.failures)) {
      if (path.endsWith(fragment)) return json(route, status, { detail: status === 500 ? "Internal server error" : "Simulated failure" });
    }
    const data = state.data;
    const rest = path.slice(base.length);

    if (rest === "/jobs") {
      const job = latest();
      polls += 1;
      if (job && (job.state === "completed" || job.state === "partial") && state.afterAnalysis) {
        state.data = state.afterAnalysis;
        state.afterAnalysis = null;
      }
      return json(route, 200, { active: job && (job.state === "queued" || job.state === "running") ? job : null, items: job ? [job] : [] });
    }
    if (method === "POST" && rest in START_PATHS) {
      if (state.startStatus !== 202) {
        return json(route, state.startStatus, { detail: state.startStatus === 409 ? "Another job is already queued or running for this project" : "Too many jobs requested. Try again later." });
      }
      if (state.startJobs) state.jobs = state.startJobs;
      polls = 0;
      return json(route, 202, { job: state.jobs[0] });
    }
    const envelope = (source: Json) => ({ ...source, job: latest() ?? source.job, snapshot: state.analysed ? source.snapshot : null });

    if (rest === "/attack-paths") return json(route, 200, envelope(data.attack_paths));
    if (rest === "/attack-paths/graph") {
      if (!data.attack_graph) return json(route, 404, { detail: "No attack-path analysis exists for the latest snapshot" });
      return json(route, 200, query.without ? { ...data.attack_what_if, what_if: { ...data.attack_what_if.what_if, node_id: query.without } } : data.attack_graph);
    }
    const pathId = rest.match(/^\/attack-paths\/([0-9a-f]{24})$/)?.[1];
    if (pathId) return data.attack_path_details?.[pathId] ? json(route, 200, data.attack_path_details[pathId]) : json(route, 404, { detail: "Attack path not found" });

    if (rest === "/maintainers") return json(route, 200, envelope(data.maintainers));
    const maintainerId = rest.match(/^\/maintainers\/([0-9a-f]{24})$/)?.[1];
    if (maintainerId) return data.maintainer_details?.[maintainerId] ? json(route, 200, data.maintainer_details[maintainerId]) : json(route, 404, { detail: "Contributor not found" });

    if (rest === "/commits/monitoring" && method === "POST") {
      data.commits.monitoring = { ...data.commits.monitoring, enabled: body.enabled };
      return json(route, 200, { monitoring: data.commits.monitoring });
    }
    if (rest === "/commits") return json(route, 200, envelope(data.commits));
    if (rest === "/security-events") return json(route, 200, data.security_events);
    const sha = rest.match(/^\/commits\/([0-9a-f]{40})$/)?.[1];
    if (sha) return data.commit_details?.[sha] ? json(route, 200, data.commit_details[sha]) : json(route, 404, { detail: "No analysis exists for that commit" });

    if (rest === "/ai-analysis") return json(route, 200, envelope(data.ai));
    const findingId = rest.match(/^\/ai-analysis\/([0-9a-f]{24})$/)?.[1];
    if (findingId) return data.finding_details?.[findingId] ? json(route, 200, data.finding_details[findingId]) : json(route, 404, { detail: "Finding not found" });

    if (rest === "/datasets") return json(route, 200, envelope(data.datasets));
    if (/^\/datasets\/[0-9a-f]{24}\/quality$/.test(rest)) return json(route, 200, data.dataset_quality);
    if (/^\/datasets\/[0-9a-f]{24}$/.test(rest)) return json(route, 200, data.dataset);

    if (rest === "/trust") return json(route, 200, envelope(data.trust));
    if (rest === "/trust/history") return json(route, 200, data.trust_history);
    if (rest === "/trust/explanation") return data.trust_explanation ? json(route, 200, data.trust_explanation) : json(route, 404, { detail: "No trust analysis exists for the latest snapshot" });

    if (rest === "/overview") return json(route, 200, data.overview);
    if (rest === "/report") {
      if (query.format === "markdown") return route.fulfill({ status: 200, contentType: "text/markdown; charset=utf-8", body: data.report_markdown ?? "# report\n" });
      return json(route, 200, data.report);
    }
    return route.fallback();
  });
}

export { PROJECT_ID, user };
