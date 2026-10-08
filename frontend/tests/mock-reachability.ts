import type { Page, Request, Route } from "@playwright/test";

import { COMMIT, PROJECT_ID } from "./mock-api";

/**
 * Test double for the Phase 4 endpoints (code reachability and its job). Register it after mockApi.
 * GHSA-x84v-xcm2-53pg is a real advisory for requests 2.19.1; the TEST-* ids are synthetic,
 * because real Python advisories do not publish affected functions.
 */

const base = `/projects/${PROJECT_ID}`;
const STAGES = ["SOURCE_INVENTORY", "SOURCE_PARSING", "GRAPH_BUILDING", "SYMBOL_MAPPING", "REACHABILITY"];

export function makeReachabilityJob(state: string, overrides: Record<string, unknown> = {}) {
  const index = state === "queued" ? 0 : state === "running" ? 2 : state === "completed" ? STAGES.length + 1 : 1;
  return {
    id: "job-reachability", project_id: PROJECT_ID, type: "code_reachability_analysis", state, stages: STAGES, stage_count: STAGES.length + 1,
    stage_index: index, stage: index === 0 ? "QUEUED" : STAGES[index - 1] ?? "COMPLETED",
    message: state === "running" ? "Read and parsed 25 of 38 source file(s)"
      : state === "completed" ? "4 finding(s) analysed: 1 reachable, 1 not confirmed, 1 unknown, 1 unsupported" : "Waiting for the background worker",
    error: null, summary: null, created_at: "2026-02-03T10:10:00Z", started_at: state === "queued" ? null : "2026-02-03T10:10:02Z",
    finished_at: state === "completed" || state === "failed" ? "2026-02-03T10:10:20Z" : null, ...overrides,
  };
}

function finding(id: string, advisory: string, dependency: string, ecosystem: string, version: string, status: string, extra: Record<string, unknown> = {}) {
  return {
    id, match_id: `m-${id}`, advisory_source: "osv", advisory_id: advisory, aliases: [] as string[], summary: null as string | null, severity: "HIGH",
    ecosystem, dependency, normalized_name: dependency, resolved_version: version, relationship: "DIRECT", status, confidence: null as string | null,
    reason: "SYMBOL_MAPPING_UNKNOWN", symbol_mapping: "SYMBOL_MAPPING_UNKNOWN", matched_symbol: null as unknown,
    evidence: { source_file: null as string | null, line: null as number | null, symbol: null as string | null, text: null as string | null, path: [] as string[] },
    usage_level: null as string | null, analyzed_at: "2026-02-03T10:10:20Z", analyzer_version: "4.0.0", ...extra,
  };
}

const callEdge = { kind: "calls", confidence: "HIGH", via: null, hops: null };
export const reachablePath = {
  nodes: [
    { id: "app.main:handle_request", kind: "function", label: "app.main:handle_request", path: "app/main.py", line: 4, is_test: false },
    { id: "app.client:fetch", kind: "function", label: "app.client:fetch", path: "app/client.py", line: 4, is_test: false },
    { id: "ext:requests.get", kind: "external", label: "requests.get", path: null, line: null, is_test: false },
  ],
  edges: [
    { ...callEdge, source: "app.main:handle_request", target: "app.client:fetch", basis: "call to a definition in the analysed source",
      evidence: { source_file: "app/main.py", line: 5, col: 11, end_line: 5, text: "return fetch(url)" } },
    { ...callEdge, source: "app.client:fetch", target: "ext:requests.get", basis: "call to an explicitly imported name",
      evidence: { source_file: "app/client.py", line: 5, col: 11, end_line: 5, text: "return requests.get(url)" } },
  ],
  length: 2, truncated: false, start_is_entry: true, through_tests_only: false, confidence: "HIGH",
};

const located = { source_file: "app/client.py", line: 5, symbol: "app.client:fetch", text: "return requests.get(url)",
  path: ["app.main:handle_request", "app.client:fetch", "requests.get"] };

export const findings = [
  finding("f1", "TEST-REQ-GET", "requests", "pypi", "2.19.1", "REACHABLE", {
    confidence: "HIGH", reason: "PATH_FOUND", symbol_mapping: "ADVISORY", usage_level: "CALLED", evidence: located,
    matched_symbol: { symbol: "requests.get", module_only: false, source: "ADVISORY", origin: "affected[].ecosystem_specific.affected_functions",
      note: null, observed: "requests.get", match: "EXACT" } }),
  finding("f2", "GHSA-x84v-xcm2-53pg", "requests", "pypi", "2.19.1", "UNKNOWN", {
    aliases: ["CVE-2018-18074"], usage_level: "CALLED", evidence: { ...located, path: [] } }),
  finding("f3", "TEST-YAML-LOAD", "PyYAML", "pypi", "5.1", "NOT_CONFIRMED_REACHABLE", {
    normalized_name: "pyyaml", confidence: "MEDIUM", reason: "NO_PATH_FOUND", symbol_mapping: "ADVISORY", usage_level: "CALLED",
    evidence: { source_file: "app/config.py", line: 5, symbol: "app.config:load", text: "return yaml.safe_load(text)", path: [] } }),
  finding("f4", "GHSA-4r6h-8v6p-xvw6", "xlsx", "npm", "0.18.5", "UNSUPPORTED", { aliases: ["CVE-2023-30533"], reason: "LANGUAGE_NOT_SUPPORTED" }),
];

const usage = {
  level: "CALLED", imported: true, import_site_count: 1, use_site_count: 1, used_names: ["requests.get"],
  import_sites: [{ symbol: "app.client", used: "requests", kind: "imports", confidence: "HIGH", basis: "import statement", source_file: "app/client.py",
    line: 1, text: "import requests", is_test: false }],
  use_sites: [{ symbol: "app.client:fetch", used: "requests.get", kind: "calls", confidence: "HIGH", basis: "call to an explicitly imported name",
    source_file: "app/client.py", line: 5, text: "return requests.get(url)", is_test: false }],
};

const EXPLANATIONS: Record<string, string> = {
  REACHABLE: "Application code statically refers to a name identified as affected. This is evidence that the affected functionality is used; it does not show that the vulnerability can be exploited.",
  UNKNOWN: "The advisory does not publish which functions or classes are affected, and no operator mapping exists, so reachability of the affected functionality cannot be decided. What the source shows about the package as a whole is listed as dependency usage.",
  NOT_CONFIRMED_REACHABLE: "The package is present, but the analysed source does not establish a path to the functionality identified as affected. This is not a statement that the application is safe.",
  UNSUPPORTED: "Source analysis is not implemented for the npm ecosystem, so nothing is concluded.",
};

export function makeFindingDetail(item: (typeof findings)[number]) {
  const reachable = item.status === "REACHABLE";
  const python = item.ecosystem === "pypi";
  return {
    ...item, snapshot_id: "s1", analysis_id: "a1", vulnerability_id: `v-${item.id}`, explanation: EXPLANATIONS[item.status],
    confidence_meaning: "How directly the source text establishes the result. It is not a likelihood of exploitation.",
    affected_symbols: item.symbol_mapping === "SYMBOL_MAPPING_UNKNOWN" ? [] : [{
      symbol: item.dependency === "PyYAML" ? "yaml.load" : "requests.get", module_only: false, source: "ADVISORY",
      origin: "affected[].ecosystem_specific.affected_functions", note: null }],
    observed: {
      dependency_usage: python ? (item.dependency === "PyYAML" ? { ...usage, used_names: ["yaml.safe_load"], import_sites: [{ ...usage.import_sites[0],
        source_file: "app/config.py", text: "import yaml" }] } : usage) : null,
      path: reachable ? reachablePath : null, usage_path: item.status === "UNKNOWN" ? reachablePath : null, dynamic_sites: null,
    },
    inferred: { status: item.status, reason: item.reason, notes: python ? ["The import name was mapped to the dependency by name, not by reading the installed package."] : [] },
  };
}

export function makeAnalysis(list = findings, overrides: Record<string, unknown> = {}) {
  const count = (status: string) => list.filter((f) => f.status === status).length;
  return {
    id: "a1", snapshot_id: "s1", commit_sha: COMMIT, branch: "main", analyzer_version: "4.0.0", completed_at: "2026-02-03T10:10:20Z",
    source_complete: true, incomplete_reasons: [] as { reason: string; files: number }[],
    source: { languages: ["python"], files_found: 38, files_analysed: 38, files_parsed: 38, test_files: 4, by_status: { PARSED: 38 },
      other_languages: { JavaScript: 61 } },
    graph: { modules: 38, classes: 21, functions: 58, external_symbols: 32, edges: 207, unresolved: 71, unresolved_by_reason: { UNKNOWN_RECEIVER: 71 } },
    findings: { findings: list.length, by_status: { REACHABLE: count("REACHABLE"), NOT_CONFIRMED_REACHABLE: count("NOT_CONFIRMED_REACHABLE"),
      UNKNOWN: count("UNKNOWN"), UNSUPPORTED: count("UNSUPPORTED") }, by_reason: {},
      with_symbol_mapping: list.filter((f) => f.symbol_mapping !== "SYMBOL_MAPPING_UNKNOWN").length, dependencies_used: 2, matches_not_evaluated: {} },
    vulnerability_scan_matched_at: "2026-02-03T10:05:30Z", operator_mappings: 0, operator_mapping_problems: [] as string[], ...overrides,
  };
}

export interface ReachabilityState {
  analysed: boolean;                 // the project has a dependency inventory
  scanned: boolean;                  // a vulnerability check exists for the snapshot
  scanMatchedAt: string;
  analysis: ReturnType<typeof makeAnalysis> | null;
  findings: typeof findings;
  jobs: (ReturnType<typeof makeReachabilityJob> | null)[];   // successive answers of the jobs endpoint
  startJobs: (ReturnType<typeof makeReachabilityJob> | null)[] | null;   // answers of the jobs endpoint once an analysis is started
  afterAnalysis: Partial<ReachabilityState> | null;          // applied when the job is first seen completed
  otherActive: Record<string, unknown> | null;
  failures: Record<string, number>;
  startStatus: number;
  requests: { method: string; path: string; query: Record<string, string> }[];
}

export function reachabilityState(overrides: Partial<ReachabilityState> = {}): ReachabilityState {
  return { analysed: true, scanned: true, scanMatchedAt: "2026-02-03T10:05:30Z", analysis: makeAnalysis(), findings,
    jobs: [makeReachabilityJob("completed")], startJobs: null, afterAnalysis: null, otherActive: null, failures: {}, startStatus: 202, requests: [], ...overrides };
}

const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });

export async function mockReachability(page: Page, state: ReachabilityState): Promise<void> {
  let polls = 0;
  await page.route("**/api/projects/*/{jobs,code-reachability}**", async (route: Route, request: Request) => {
    const url = new URL(request.url());
    const path = url.pathname.replace(/^\/api/, "");
    const query = Object.fromEntries(url.searchParams.entries());
    const method = request.method();
    state.requests.push({ method, path, query });
    for (const [fragment, status] of Object.entries(state.failures)) {
      if (path.endsWith(fragment)) return json(route, status, { detail: status === 500 ? "Internal server error" : "Simulated failure" });
    }
    const latest = () => state.jobs[Math.min(polls, state.jobs.length - 1)] ?? null;

    if (path === `${base}/jobs`) {
      const job = latest();
      polls += 1;
      if (job?.state === "completed" && state.afterAnalysis) {
        Object.assign(state, state.afterAnalysis);
        state.afterAnalysis = null;
      }
      const active = job && (job.state === "queued" || job.state === "running") ? job : state.otherActive;
      return json(route, 200, { active, items: job ? [job] : [] });
    }
    if (path === `${base}/code-reachability/analyze` && method === "POST") {
      if (state.startStatus !== 202) {
        return json(route, state.startStatus, { detail: state.startStatus === 409 ? "Another job is already queued or running for this project"
          : "Too many jobs requested. Try again later." });
      }
      if (state.startJobs) state.jobs = state.startJobs;
      polls = 0;
      return json(route, 202, { job: state.jobs[0] });
    }
    if (path === `${base}/code-reachability`) {
      let items = state.analysis ? state.findings : [];
      if (query.status) items = items.filter((f) => f.status === query.status);
      if (query.q) items = items.filter((f) => `${f.normalized_name} ${f.advisory_id} ${f.aliases.join(" ")}`.toLowerCase().includes(query.q.toLowerCase()));
      const skip = Number(query.skip ?? 0);
      const limit = Number(query.limit ?? 100);
      return json(route, 200, {
        job: latest(), snapshot: state.analysed ? { id: "s1", commit_sha: COMMIT, branch: "main" } : null,
        has_vulnerability_scan: state.analysed && state.scanned, vulnerability_scan_matched_at: state.analysed && state.scanned ? state.scanMatchedAt : null,
        analysis: state.analysis, supported_ecosystems: ["pypi"], statuses: ["REACHABLE", "NOT_CONFIRMED_REACHABLE", "UNKNOWN", "UNSUPPORTED"],
        total: items.length, skip, limit, items: items.slice(skip, skip + limit),
      });
    }
    const findingId = path.match(new RegExp(`^${base}/code-reachability/([^/]+)$`))?.[1];
    if (findingId) {
      const item = state.findings.find((f) => f.id === findingId);
      return item ? json(route, 200, makeFindingDetail(item)) : json(route, 404, { detail: "Reachability finding not found" });
    }
    return route.fallback();
  });
}
