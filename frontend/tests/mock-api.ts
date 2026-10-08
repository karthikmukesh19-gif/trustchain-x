import type { Page, Request, Route } from "@playwright/test";

/** Test double for the backend: every /api request is answered from this in-memory state. */

export const PROJECT_ID = "665f00000000000000000001";
export const COMMIT = "4c8057c3bbed0e55f916341187cf4f2d3ddaaea6";

export const user = { id: "u1", email: "tester@example.com", full_name: "Test User", role: "user", created_at: "2026-01-01T00:00:00Z" };

export function makeProject(overrides: Record<string, unknown> = {}) {
  return {
    id: PROJECT_ID, name: "ShadowWatch", description: "", repository_url: "https://github.com/octo/demo", status: "ACTIVE",
    default_branch: "main", languages: [], created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z",
    last_analysis: null, latest_snapshot_id: null,
    repository: {
      host: "github.com", owner: "octo", name: "demo", full_name: "octo/demo", url: "https://github.com/octo/demo",
      metadata_status: "FETCHED", metadata_error: null, metadata_fetched_at: "2026-01-01T00:00:00Z",
      metadata: { github_id: 1, description: "Demo repository", default_branch: "main", primary_language: "Python", stars: 3, forks: 1,
        open_issues: 0, size_kb: 120, archived: false, is_fork: false, visibility: "public", license: "MIT",
        github_created_at: "2025-01-01T00:00:00Z", pushed_at: "2026-01-01T00:00:00Z" },
    },
    ...overrides,
  };
}

type Node = Record<string, unknown> & { node_id: string; depth: number | null; relationship: string; ecosystem: string; name: string; normalized_name: string };

function node(ecosystem: string, name: string, version: string | null, relationship: string, basis: string, depth: number | null, extra: Record<string, unknown> = {}): Node {
  return {
    node_id: `${ecosystem}:${name}@${version ?? "unresolved"}`, ecosystem, name, normalized_name: name, version,
    version_status: version ? "RESOLVED" : "UNRESOLVED", version_basis: version ? "OBSERVED" : "UNKNOWN",
    version_reason: version ? "Locked in web/package-lock.json" : "No lockfile entry or exact pin establishes the version",
    purl: `pkg:${ecosystem}/${name}${version ? `@${version}` : ""}`, constraints: [], package_managers: [ecosystem === "pypi" ? "pip" : "npm"],
    relationship, relationship_basis: basis, relationship_reason: "Declared in dependencies", scopes: ["runtime"], optional: false, source: null,
    evidence_count: 1, depth, shortest_path_count: depth === null ? 0 : 1, parents: [], parent_count: depth === null ? 0 : 1,
    dependents_count: 0, dependency_count: 0, integrity: [],
    evidence: [{ source_file: ecosystem === "pypi" ? "backend/requirements.txt" : "web/package.json", file_kind: "manifest",
      package_manager: ecosystem === "pypi" ? "pip" : "npm", line: 3, declaration: `${name}${version ? `==${version}` : ">=2.31"}`,
      constraint: version ? `==${version}` : ">=2.31", scope: "runtime", evidence_type: "repository_file", git_blob_sha: "a".repeat(40) }],
    ...extra,
  };
}

export const nodes: Node[] = [
  node("npm", "react", "19.2.7", "DIRECT", "OBSERVED", 1, { dependency_count: 1, constraints: ["^19.2.7"] }),
  node("npm", "scheduler", "0.27.0", "TRANSITIVE", "OBSERVED", 2, { relationship_reason: "Required by react according to web/package-lock.json", parents: ["npm:react@19.2.7"], dependency_count: 1 }),
  node("npm", "loose-envify", "1.4.0", "TRANSITIVE", "OBSERVED", 3, { parents: ["npm:scheduler@0.27.0"] }),
  node("pypi", "flask", "3.0.0", "DIRECT", "INFERRED", 1, { relationship_reason: "Listed in a requirements file. Such a file can also list transitive packages, so 'direct' is inferred rather than observed.", version_reason: "Exact version declared in backend/requirements.txt" }),
  node("pypi", "requests", null, "DIRECT", "INFERRED", 1, { constraints: [">=2.31"] }),
  node("pypi", "orphan", "1.0.0", "UNKNOWN", "UNKNOWN", null, { relationship_reason: "Pipfile.lock does not record which packages are direct, and no manifest beside it declares them" }),
];

export const edges = [
  { source: "root", target: "npm:react@19.2.7", type: "depends_on", relation: "direct", basis: "OBSERVED", evidence_files: ["web/package.json"], requirement: "^19.2.7" },
  { source: "npm:react@19.2.7", target: "npm:scheduler@0.27.0", type: "depends_on", relation: "requires", basis: "OBSERVED", evidence_files: ["web/package-lock.json"], requirement: "^0.27.0" },
  { source: "npm:scheduler@0.27.0", target: "npm:loose-envify@1.4.0", type: "depends_on", relation: "requires", basis: "OBSERVED", evidence_files: ["web/package-lock.json"], requirement: null },
  { source: "root", target: "pypi:flask@3.0.0", type: "depends_on", relation: "direct", basis: "INFERRED", evidence_files: ["backend/requirements.txt"], requirement: "==3.0.0" },
  { source: "root", target: "pypi:requests@unresolved", type: "depends_on", relation: "direct", basis: "INFERRED", evidence_files: ["backend/requirements.txt"], requirement: ">=2.31" },
];

export function statsFor(list: Node[], edgeCount = edges.length) {
  const count = (key: string) => list.reduce<Record<string, number>>((acc, n) => ({ ...acc, [String(n[key])]: (acc[String(n[key])] ?? 0) + 1 }), {});
  const depths = list.map((n) => n.depth).filter((d): d is number => d !== null);
  return {
    total: list.length, direct: list.filter((n) => n.relationship === "DIRECT").length,
    transitive: list.filter((n) => n.relationship === "TRANSITIVE").length,
    relationship_unknown: list.filter((n) => n.relationship === "UNKNOWN").length,
    unresolved_versions: list.filter((n) => n.version === null).length, edges: edgeCount, max_depth: Math.max(0, ...depths),
    without_path: list.filter((n) => n.depth === null).length, unresolved_edges: 0, by_ecosystem: count("ecosystem"),
    by_package_manager: list.reduce<Record<string, number>>((acc, n) => { const pm = (n.package_managers as string[])[0]; return { ...acc, [pm]: (acc[pm] ?? 0) + 1 }; }, {}),
    by_depth: {}, by_relationship_basis: count("relationship_basis"), by_scope: { runtime: list.length },
  };
}

export const snapshotRef = { id: "s1", commit_sha: COMMIT, branch: "main", collected_at: "2026-02-03T10:00:00Z", analyzer_version: "2.0.0" };

export function makeSnapshot(list: Node[] = nodes) {
  const stats = statsFor(list);
  return {
    ...snapshotRef, repository_url: "https://github.com/octo/demo", repository_full_name: "octo/demo", tree_sha: "b".repeat(40),
    committed_at: "2026-02-01T09:00:00Z", commit_message: "Update notification_repository.py", status: "COMPLETE",
    collection_method: "GitHub REST API (commits, git/trees, git/blobs); no repository code executed",
    file_count: 104, total_bytes: 1_500_000, rejected_paths: 0, symlinks_skipped: 0, submodules_skipped: 0,
    languages: { primary_language: "JavaScript", method: "File extensions weighted by size in bytes; vendored and generated directories are excluded.",
      languages: [
        { language: "JavaScript", files: 38, bytes: 70000, share: 0.71, confidence: "HIGH", basis: "OBSERVED", evidence_files: ["frontend/src/App.jsx"], dependency_file_present: true },
        { language: "Python", files: 38, bytes: 29000, share: 0.29, confidence: "HIGH", basis: "OBSERVED", evidence_files: ["backend/app/main.py"], dependency_file_present: true },
      ] },
    github_primary_language: "Python",
    package_managers: [
      { package_manager: "npm", ecosystem: "npm", basis: "OBSERVED", supported: true, manifest_files: ["web/package.json"], lock_files: ["web/package-lock.json"] },
      { package_manager: "pip", ecosystem: "pypi", basis: "OBSERVED", supported: true, manifest_files: ["backend/requirements.txt"], lock_files: [] },
      { package_manager: "bundler", ecosystem: "rubygems", basis: "OBSERVED", supported: false, manifest_files: ["Gemfile"], lock_files: [] },
    ],
    dependency_files: [
      { path: "web/package.json", size: 300, git_blob_sha: "c".repeat(40), sha256: "d".repeat(64), package_manager: "npm", ecosystem: "npm", kind: "manifest", status: "PARSED", detail: null, dependencies_found: 1, notes: [], referenced_by: null },
      { path: "web/package-lock.json", size: 9000, git_blob_sha: "c".repeat(40), sha256: "d".repeat(64), package_manager: "npm", ecosystem: "npm", kind: "lockfile", status: "PARSED", detail: null, dependencies_found: 3, notes: [], referenced_by: null },
      { path: "backend/requirements.txt", size: 40, git_blob_sha: "c".repeat(40), sha256: "d".repeat(64), package_manager: "pip", ecosystem: "pypi", kind: "manifest", status: "PARSED", detail: null, dependencies_found: 2, notes: [], referenced_by: null },
      { path: "Gemfile", size: 20, git_blob_sha: "c".repeat(40), sha256: null, package_manager: "bundler", ecosystem: "rubygems", kind: "manifest", status: "UNSUPPORTED", detail: "Ruby (Bundler) extraction is not implemented", dependencies_found: 0, notes: [], referenced_by: null },
      { path: "broken/package.json", size: 5, git_blob_sha: "c".repeat(40), sha256: "d".repeat(64), package_manager: "npm", ecosystem: "npm", kind: "manifest", status: "ERROR", detail: "Not valid JSON: Expecting value", dependencies_found: 0, notes: [], referenced_by: null },
    ],
    notes: [],
    summary: { dependencies: stats.total, direct: stats.direct, transitive: stats.transitive, relationship_unknown: stats.relationship_unknown,
      unresolved_versions: stats.unresolved_versions, edges: stats.edges, max_depth: stats.max_depth, ecosystems: Object.keys(stats.by_ecosystem).sort(),
      package_managers: ["npm", "pip"], languages: ["JavaScript", "Python"], primary_language: "JavaScript", dependency_files: 5, files: 104 },
  };
}

export function makeJob(state: string, overrides: Record<string, unknown> = {}) {
  const stageIndex = { queued: 0, running: 3, completed: 5, failed: 2 }[state] ?? 0;
  return {
    id: "j1", project_id: PROJECT_ID, type: "dependencies", state, stage_count: 5, stage_index: stageIndex,
    stage: ["QUEUED", "REPOSITORY_SNAPSHOT", "REPOSITORY_DISCOVERY", "DEPENDENCY_DISCOVERY", "GRAPH_BUILDING", "COMPLETED"][stageIndex],
    message: state === "running" ? "Reading 5 dependency file(s)" : state === "completed" ? "Analysis complete" : "Waiting for the background worker",
    error: null, snapshot_id: state === "completed" ? "s1" : null, summary: null, reused_snapshot: false,
    created_at: "2026-02-03T09:59:00Z", started_at: state === "queued" ? null : "2026-02-03T09:59:05Z",
    finished_at: state === "completed" || state === "failed" ? "2026-02-03T10:00:00Z" : null, ...overrides,
  };
}

export interface ApiState {
  /** Whether a completed analysis exists. */
  analysed: boolean;
  /** Jobs returned by successive status polls; the last one repeats. null = never run. */
  jobs: (ReturnType<typeof makeJob> | null)[];
  nodes: Node[];
  edges: typeof edges;
  /** path fragment -> HTTP status to force (e.g. { "/dependencies": 500 }). */
  failures: Record<string, number>;
  /** Response for POST /analysis/dependencies. */
  startStatus: number;
  /** Every request seen, for assertions. */
  requests: { method: string; path: string; query: Record<string, string> }[];
}

export function defaultState(overrides: Partial<ApiState> = {}): ApiState {
  return { analysed: true, jobs: [makeJob("completed")], nodes, edges, failures: {}, startStatus: 202, requests: [], ...overrides };
}

const json = (route: Route, status: number, body: unknown) =>
  route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });

export async function mockApi(page: Page, state: ApiState): Promise<void> {
  await page.addInitScript(() => window.sessionStorage.setItem("trustchain.token", "test-token"));
  let polls = 0;

  await page.route("**/api/**", async (route: Route, request: Request) => {
    const url = new URL(request.url());
    const path = url.pathname.replace(/^\/api/, "");
    const query = Object.fromEntries(url.searchParams.entries());
    state.requests.push({ method: request.method(), path, query });

    for (const [fragment, status] of Object.entries(state.failures)) {
      if (path.endsWith(fragment)) return json(route, status, { detail: status === 500 ? "Internal server error" : "Simulated failure" });
    }
    const notAnalysed = () => json(route, 404, { detail: "This project has not been analysed yet" });
    const base = `/projects/${PROJECT_ID}`;

    if (path === "/auth/me") return json(route, 200, user);
    if (path === "/health/ready") return json(route, 200, { status: "ok", checks: { mongodb: { ok: true }, redis: { ok: true }, worker: { ok: true, last_heartbeat: "2026-02-03T10:00:00Z" } }, time: "2026-02-03T10:00:00Z" });
    if (path === base) return json(route, 200, makeProject(state.analysed ? { last_analysis: "2026-02-03T10:00:00Z", latest_snapshot_id: "s1" } : {}));

    if (path === `${base}/analysis/dependencies` && request.method() === "POST") {
      if (state.startStatus !== 202) return json(route, state.startStatus, { detail: "An analysis is already queued or running for this project" });
      return json(route, 202, { job: makeJob("queued") });
    }
    if (path === `${base}/analysis/status`) {
      const job = state.jobs[Math.min(polls, state.jobs.length - 1)] ?? null;
      polls += 1;
      if (job?.state === "completed") state.analysed = true;
      return json(route, 200, { job, has_results: state.analysed, last_analysis: state.analysed ? "2026-02-03T10:00:00Z" : null });
    }
    if (path === `${base}/snapshot`) return state.analysed ? json(route, 200, makeSnapshot(state.nodes)) : notAnalysed();

    if (path === `${base}/dependencies`) {
      if (!state.analysed) return notAnalysed();
      let items = state.nodes;
      if (query.ecosystem) items = items.filter((n) => n.ecosystem === query.ecosystem);
      if (query.relationship) items = items.filter((n) => n.relationship === query.relationship);
      if (query.version_status === "UNRESOLVED") items = items.filter((n) => n.version === null);
      if (query.q) items = items.filter((n) => n.normalized_name.includes(query.q.toLowerCase()));
      const skip = Number(query.skip ?? 0);
      const limit = Number(query.limit ?? 100);
      return json(route, 200, { snapshot: snapshotRef, summary: statsFor(state.nodes, state.edges.length), total: items.length, skip, limit, items: items.slice(skip, skip + limit) });
    }
    if (path === `${base}/dependencies/graph`) {
      if (!state.analysed) return notAnalysed();
      return json(route, 200, { snapshot: snapshotRef, root: { id: "root", type: "application", label: "octo/demo" }, nodes: state.nodes, edges: state.edges, stats: statsFor(state.nodes, state.edges.length) });
    }
    if (path === `${base}/dependencies/paths`) {
      const paths = query.to === "npm:loose-envify@1.4.0" ? [["root", "npm:react@19.2.7", "npm:scheduler@0.27.0", "npm:loose-envify@1.4.0"]]
        : query.to === "pypi:orphan@1.0.0" ? [] : [["root", query.to]];
      return json(route, 200, { to: query.to, paths });
    }
    return json(route, 404, { detail: "Not found" });
  });
}

export const projectUrl = (suffix = "") => `/projects/${PROJECT_ID}${suffix}`;
