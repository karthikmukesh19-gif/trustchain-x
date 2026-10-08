import type { Page, Request, Route } from "@playwright/test";

import { COMMIT, PROJECT_ID } from "./mock-api";

/**
 * Test double for the Phase 3 endpoints (jobs, vulnerabilities, SBOM). Register it after mockApi:
 * it answers its own paths and leaves every other request to mockApi.
 *
 * The advisory identifiers used here are real public advisories for the package versions shown.
 */

const base = `/projects/${PROJECT_ID}`;

export function makeSecurityJob(type: string, state: string, overrides: Record<string, unknown> = {}) {
  const stages = type === "sbom_generation" ? ["SBOM_GENERATION", "SBOM_COMPARISON"] : type === "vulnerability_analysis" ? ["MATCHING"]
    : ["PROVIDER_QUERY", "RECORD_INGESTION", "MATCHING"];
  const index = state === "queued" ? 0 : state === "running" ? Math.min(2, stages.length) : state === "completed" ? stages.length + 1 : 1;
  return {
    id: `job-${type}`, project_id: PROJECT_ID, type, state, stages, stage_count: stages.length + 1, stage_index: index,
    stage: index === 0 ? "QUEUED" : stages[index - 1] ?? "COMPLETED",
    message: state === "running" ? (type === "sbom_generation" ? "Generating a CycloneDX 1.5 SBOM for commit 4c8057c3bb" : "Fetching 3 advisory record(s)")
      : state === "completed" ? (type === "sbom_generation" ? "SBOM version 1 generated with 4 component(s)" : "OSV data synchronised; 3 match(es) on 2 dependency version(s)")
      : "Waiting for the background worker",
    error: null, summary: null, created_at: "2026-02-03T10:05:00Z", started_at: state === "queued" ? null : "2026-02-03T10:05:02Z",
    finished_at: state === "completed" || state === "failed" ? "2026-02-03T10:05:30Z" : null, ...overrides,
  };
}

function match(id: string, pkg: string, ecosystem: string, version: string, sourceId: string, extra: Record<string, unknown> = {}) {
  return {
    id, dependency_node_id: `${ecosystem}:${pkg}@${version}`, source: "osv", source_id: sourceId, aliases: [] as string[], group_key: sourceId,
    summary: null as string | null, ecosystem, package_name: pkg, normalized_name: pkg, matched_version: version, relationship: "DIRECT", depth: 1,
    match_status: "AFFECTED", classification: "OBSERVED", confidence: "HIGH",
    confidence_meaning: "Deterministic comparison of the observed version with the versions the source publishes as affected. Confidence describes the version match only, not exploitability.",
    severity: "HIGH", severity_source: "source_label", cvss: null as unknown, affected_range: "< 2.20.0", fixed_version: "2.20.0" as string | null,
    fixed_versions: ["2.20.0"], matched_at: "2026-02-03T10:05:30Z", ...extra,
  };
}

export const matches = [
  match("m1", "requests", "pypi", "2.19.1", "GHSA-x84v-xcm2-53pg", {
    aliases: ["CVE-2018-18074"], group_key: "CVE-2018-18074", summary: "Insufficiently Protected Credentials in Requests",
    cvss: [{ type: "CVSS_V3", vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", version: "3.1", base_score: 7.5, score_origin: "computed_from_vector" }] }),
  match("m2", "requests", "pypi", "2.19.1", "PYSEC-2018-28", {
    aliases: ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"], group_key: "CVE-2018-18074", severity: "UNKNOWN", severity_source: null }),
  match("m3", "xlsx", "npm", "0.18.5", "GHSA-4r6h-8v6p-xvw6", {
    aliases: ["CVE-2023-30533"], affected_range: "all versions (no fixed version published)", fixed_version: null, fixed_versions: [] }),
  match("m4", "com.google.guava:guava", "maven", "31.1-jre", "GHSA-7g45-4rm6-3mm3", {
    match_status: "UNSUPPORTED", classification: "OBSERVED", confidence: "UNDETERMINED", severity: "MEDIUM", affected_range: null, fixed_version: null,
    fixed_versions: ["32.0.0-android"], confidence_meaning: "The version comparison could not be carried out safely, so no conclusion is drawn." }),
];

export function makeDetail(item: (typeof matches)[number]) {
  return {
    match: {
      ...item,
      evidence: {
        evidence_type: item.match_status === "AFFECTED" ? "version_range_match" : "provider_report_only",
        source: { provider: "osv", source_id: item.source_id, url: `https://osv.dev/vulnerability/${item.source_id}`, modified_at: "2024-10-21T21:26:17Z",
          record_sha256: "ab".repeat(32), retrieved_at: "2026-02-03T10:05:20Z" },
        observed: { package: item.package_name, normalized_name: item.normalized_name, ecosystem: item.ecosystem, installed_version: item.matched_version,
          purl: `pkg:${item.ecosystem}/${item.package_name}@${item.matched_version}`, version_basis: "OBSERVED",
          version_reason: "Exact version declared in api/requirements.txt", relationship: "DIRECT", depth: 1,
          declared_in: [{ source_file: "api/requirements.txt", line: 1, declaration: `${item.package_name}==${item.matched_version}`, file_kind: "manifest", git_blob_sha: "c".repeat(40) }] },
        match: { comparator: "pep440", range_type: "ECOSYSTEM", affected_range: item.affected_range, introduced: "0", fixed: item.fixed_version, last_affected: null, limit: null,
          events: [{ introduced: "0" }, ...(item.fixed_version ? [{ fixed: item.fixed_version }] : [])], version_listed_by_source: false, provider_reported: true,
          explanation: item.match_status === "AFFECTED" ? `Version ${item.matched_version} is inside the affected range (${item.affected_range}).`
            : "The installed version cannot be ordered (Maven version outside the supported subset: '31.1-jre').",
          source_range_note: item.source_id === "GHSA-4r6h-8v6p-xvw6" ? "< 0.19.3" : null },
      },
    },
    vulnerability: { id: `v-${item.id}`, source: "osv", source_id: item.source_id, source_url: `https://osv.dev/vulnerability/${item.source_id}`, aliases: item.aliases,
      summary: item.summary, details: null, severity: item.severity, severity_source: item.severity_source, cvss: item.cvss, cwe_ids: [],
      references: [{ type: "ADVISORY", url: "https://nvd.nist.gov/vuln/detail/CVE-2018-18074" }], published_at: "2018-10-29T19:06:46Z",
      modified_at: "2024-10-21T21:26:17Z", withdrawn_at: null, first_seen_at: "2026-02-03T10:05:20Z", ingested_at: "2026-02-03T10:05:20Z" },
  };
}

export function makeScan(list = matches, overrides: Record<string, unknown> = {}) {
  const affected = list.filter((m) => m.match_status === "AFFECTED");
  const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 } as Record<string, number>;
  affected.forEach((m) => { bySeverity[m.severity] += 1; });
  return {
    snapshot_id: "s1", commit_sha: COMMIT, matched_at: "2026-02-03T10:05:30Z", matcher_version: "3.0.0", dependencies_total: 12, dependencies_checked: 10,
    dependencies_unresolved: 1, dependencies_unsupported_ecosystem: 1, unsupported_ecosystems: { vcpkg: 1 }, advisories_considered: list.length,
    advisories_withdrawn_skipped: 0, affected_matches: affected.length, affected_dependencies: new Set(affected.map((m) => m.dependency_node_id)).size,
    distinct_vulnerabilities: new Set(affected.map((m) => m.group_key)).size, unsupported_matches: list.filter((m) => m.match_status === "UNSUPPORTED").length,
    conflict_matches: 0, by_severity: bySeverity, reported_but_not_stored: [], reported_but_not_stored_count: 0,
    intelligence: { sync_id: "sync1", provider: "osv", status: "completed", completed_at: "2026-02-03T10:05:25Z", records_seen: list.length, records_failed: 0 },
    ...overrides,
  };
}

export function makeSync(status = "completed", overrides: Record<string, unknown> = {}) {
  return { id: "sync1", provider: "osv", status, started_at: "2026-02-03T10:05:02Z", completed_at: "2026-02-03T10:05:25Z", packages_queried: 10,
    packages_unsupported: 1, packages_unresolved: 1, provider_requests: 1, records_seen: 4, records_inserted: 4, records_updated: 0, records_unchanged: 0,
    records_failed: status === "partial" ? 1 : 0, errors: [], error_summary: status === "completed" ? null
      : status === "partial" ? "1 of 4 advisory record(s) could not be stored, so the vulnerability data for this project is incomplete. Records that were fetched have been kept."
      : "OSV returned HTTP 503.", ...overrides };
}

export function makeSbom(version: number, overrides: Record<string, unknown> = {}) {
  return {
    id: `sbom${version}`, snapshot_id: `s${version}`, commit_sha: version === 1 ? "1111111111aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" : COMMIT, branch: "main", version,
    previous_sbom_id: version > 1 ? `sbom${version - 1}` : null, format: "CycloneDX", spec_version: "1.5", media_type: "application/vnd.cyclonedx+json",
    serial_number: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", generator: { name: "TrustChain-X", version: "3.0.0" },
    generated_at: `2026-02-0${version}T11:00:00Z`, component_count: 3 + version, relationship_count: 4, unresolved_components: 1, components_with_hashes: 2,
    completeness: "incomplete", digest_algorithm: "SHA-256", canonicalization: "UTF-8 JSON, object keys sorted, no insignificant whitespace (RFC 8785 style); SHA-256",
    content_digest: `${version}c`.repeat(32), document_digest: `${version}d`.repeat(32), document_size: 20480, last_verification: null,
    vulnerability_linkage: { components_with_matches: 0, affected_matches: 0, latest_match_at: null }, ...overrides,
  };
}

export const components = [
  { bom_ref: "npm:xlsx@0.18.5", ecosystem: "npm", name: "xlsx", normalized_name: "xlsx", version: "0.18.5", purl: "pkg:npm/xlsx@0.18.5", scope: "required",
    relationship: "DIRECT", hashes: [{ alg: "SHA-512", content: "76".repeat(64) }], depends_on: [], component_digest: "a1".repeat(32),
    vulnerabilities: [{ match_id: "m3", source_id: "GHSA-4r6h-8v6p-xvw6", severity: "HIGH", fixed_version: null }] },
  { bom_ref: "pypi:requests@2.19.1", ecosystem: "pypi", name: "requests", normalized_name: "requests", version: "2.19.1", purl: "pkg:pypi/requests@2.19.1", scope: "required",
    relationship: "DIRECT", hashes: [], depends_on: [], component_digest: "a2".repeat(32),
    vulnerabilities: [{ match_id: "m1", source_id: "GHSA-x84v-xcm2-53pg", severity: "HIGH", fixed_version: "2.20.0" }, { match_id: "m2", source_id: "PYSEC-2018-28", severity: "UNKNOWN", fixed_version: "2.20.0" }] },
  { bom_ref: "pypi:flask@unresolved", ecosystem: "pypi", name: "flask", normalized_name: "flask", version: null, purl: "pkg:pypi/flask", scope: "required",
    relationship: "DIRECT", hashes: [], depends_on: [], component_digest: "a3".repeat(32), vulnerabilities: [] },
  { bom_ref: "npm:left@1.0.0", ecosystem: "npm", name: "left", normalized_name: "left", version: "1.0.0", purl: "pkg:npm/left@1.0.0", scope: "required",
    relationship: "DIRECT", hashes: [], depends_on: ["npm:lodash@4.17.21"], component_digest: "a4".repeat(32), vulnerabilities: [] },
];

export const diff = {
  id: "d1", base_sbom_id: "sbom1", target_sbom_id: "sbom2", base_version: 1, target_version: 2,
  summary: { added: 1, removed: 1, changed: 2, version_changes: 1, metadata_changes: 1, ecosystem_changes: 0, relationships_added: 2, relationships_removed: 1,
    components_before: 4, components_after: 5, document_changes: 4, identical: false },
  items: [
    { ecosystem: "npm", name: "right", change: "ADDED", old_versions: [], new_versions: ["2.0.0"] },
    { ecosystem: "golang", name: "golang.org/x/crypto", change: "REMOVED", old_versions: ["v0.30.0"], new_versions: [] },
    { ecosystem: "pypi", name: "requests", change: "CHANGED", change_type: "version", old_versions: ["2.19.1"], new_versions: ["2.32.0"], old_version: "2.19.1", new_version: "2.32.0" },
    { ecosystem: "npm", name: "xlsx", change: "CHANGED", change_type: "metadata", old_versions: ["0.18.5"], new_versions: ["0.18.5"],
      fields: [{ field: "hashes", old: [], new: [], version: "0.18.5" }] },
  ],
  ecosystem_changes: [], document_changes: [], relationships_added: [], relationships_removed: [],
};

const CHECKS = ["stored_document_digest", "canonical_form", "content_digest", "component_records", "regeneration"];

export function makeVerification(sbomId: string, failed: string[] = []) {
  return {
    sbom_id: sbomId, valid: failed.length === 0, verified_at: "2026-02-03T12:00:00Z",
    checks: CHECKS.map((name) => ({ name, ok: !failed.includes(name), detail: failed.includes(name) ? `Simulated failure of ${name}.` : "ok" })),
    digest_algorithm: "SHA-256", canonicalization: "UTF-8 JSON",
    difference_from_regenerated: failed.includes("regeneration") ? { summary: { ...diff.summary, added: 0, removed: 0, changed: 1, relationships_added: 0, relationships_removed: 1, document_changes: 0 },
      items: [], relationships_added: [], relationships_removed: [], document_changes: [] } : null,
    meaning: "Integrity-verifiable: the SBOM is checked against its recorded digests and against a fresh generation from the snapshot. It is not cryptographically signed.",
  };
}

type Job = ReturnType<typeof makeSecurityJob>;

export interface SecurityState {
  /** Whether the project has a dependency inventory. */
  analysed: boolean;
  /** Vulnerability results currently visible. */
  scan: ReturnType<typeof makeScan> | null;
  sync: ReturnType<typeof makeSync> | null;
  matches: typeof matches;
  /** Results that become visible once a vulnerability job has been served as completed. */
  afterCheck: { scan: ReturnType<typeof makeScan> | null; sync: ReturnType<typeof makeSync> | null; matches: typeof matches } | null;
  /** Successive answers to job polls per page; the last one repeats. null = never run. */
  vulnerabilityJobs: (Job | null)[];
  sbomJobs: (Job | null)[];
  /** A job of another type currently occupying the project. */
  otherActive: Job | null;
  sboms: ReturnType<typeof makeSbom>[];
  /** SBOMs that appear once a generation job has been served as completed. */
  afterGeneration: ReturnType<typeof makeSbom>[] | null;
  components: typeof components;
  failedChecks: string[];
  failures: Record<string, number>;
  startStatus: number;
  requests: { method: string; path: string; query: Record<string, string> }[];
}

export function securityState(overrides: Partial<SecurityState> = {}): SecurityState {
  return { analysed: true, scan: makeScan(), sync: makeSync(), matches, afterCheck: null, vulnerabilityJobs: [makeSecurityJob("vulnerability_sync", "completed")],
    sbomJobs: [makeSecurityJob("sbom_generation", "completed")], otherActive: null, sboms: [makeSbom(2), makeSbom(1)], afterGeneration: null, components,
    failedChecks: [], failures: {}, startStatus: 202, requests: [], ...overrides };
}

const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });

export async function mockSecurity(page: Page, state: SecurityState): Promise<void> {
  const polls = { vulnerability: 0, sbom: 0 };

  await page.route("**/api/projects/*/{jobs,vulnerabilities,sbom}**", async (route: Route, request: Request) => {
    const url = new URL(request.url());
    const path = url.pathname.replace(/^\/api/, "");
    const query = Object.fromEntries(url.searchParams.entries());
    const method = request.method();
    state.requests.push({ method, path, query });
    for (const [fragment, status] of Object.entries(state.failures)) {
      if (path.endsWith(fragment)) return json(route, status, { detail: status === 500 ? "Internal server error" : "Simulated failure" });
    }

    if (path === `${base}/jobs`) {
      const kind = (query.type ?? "").includes("sbom") ? "sbom" : "vulnerability";
      const list = kind === "sbom" ? state.sbomJobs : state.vulnerabilityJobs;
      const job = list[Math.min(polls[kind], list.length - 1)] ?? null;
      polls[kind] += 1;
      if (job?.state === "completed") {
        if (kind === "vulnerability" && state.afterCheck) { Object.assign(state, state.afterCheck); state.afterCheck = null; }
        if (kind === "sbom" && state.afterGeneration) { state.sboms = state.afterGeneration; state.afterGeneration = null; }
      }
      const running = job && (job.state === "queued" || job.state === "running") ? job : null;
      return json(route, 200, { active: running ?? state.otherActive, items: job ? [job] : [] });
    }

    if (method === "POST" && (path === `${base}/vulnerabilities/sync` || path === `${base}/vulnerabilities/analyze` || path === `${base}/sbom/generate`)) {
      if (state.startStatus !== 202) return json(route, state.startStatus, { detail: "Another job is already queued or running for this project" });
      const type = path.endsWith("/sync") ? "vulnerability_sync" : path.endsWith("/analyze") ? "vulnerability_analysis" : "sbom_generation";
      return json(route, 202, { job: makeSecurityJob(type, "queued") });
    }

    if (path === `${base}/vulnerabilities`) {
      const snapshot = state.analysed ? { id: "s1", commit_sha: COMMIT, branch: "main", collected_at: "2026-02-03T10:00:00Z" } : null;
      let items = state.scan ? state.matches : [];
      if (query.severity) items = items.filter((m) => m.severity === query.severity);
      if (query.match_status) items = items.filter((m) => m.match_status === query.match_status);
      if (query.ecosystem) items = items.filter((m) => m.ecosystem === query.ecosystem);
      if (query.q) items = items.filter((m) => [m.normalized_name, m.source_id, ...m.aliases].some((v) => v.toLowerCase().includes(query.q.toLowerCase())));
      const skip = Number(query.skip ?? 0);
      const limit = Number(query.limit ?? 100);
      return json(route, 200, { job: null, providers: ["osv"], snapshot, scan: state.scan, sync: state.sync, total: items.length, skip, limit, items: items.slice(skip, skip + limit) });
    }
    const matchId = path.match(new RegExp(`^${base}/vulnerabilities/([^/]+)$`))?.[1];
    if (matchId) {
      const item = state.matches.find((m) => m.id === matchId);
      return item ? json(route, 200, makeDetail(item)) : json(route, 404, { detail: "Vulnerability match not found" });
    }

    if (path === `${base}/sbom`) {
      return json(route, 200, { job: null, latest: state.sboms[0] ?? null, history: state.sboms, has_inventory: state.analysed, latest_snapshot_id: state.analysed ? "s1" : null });
    }
    const sbomPath = path.match(new RegExp(`^${base}/sbom/([^/]+)(/.*)?$`));
    if (sbomPath) {
      const [, sbomId, rest = ""] = sbomPath;
      const sbom = state.sboms.find((s) => s.id === sbomId);
      if (!sbom) return json(route, 404, { detail: "SBOM not found" });
      if (rest === "/verify" && method === "POST") {
        sbom.last_verification = { valid: state.failedChecks.length === 0, verified_at: "2026-02-03T12:00:00Z", failed_checks: state.failedChecks } as never;
        return json(route, 200, makeVerification(sbomId, state.failedChecks));
      }
      if (rest === "/document") {
        return route.fulfill({ status: 200, contentType: "application/vnd.cyclonedx+json", body: JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.5", components: [] }),
          headers: { "content-disposition": `attachment; filename="sbom-v${sbom.version}.cdx.json"` } });
      }
      if (rest === "/components") {
        let items = state.components;
        if (query.q) items = items.filter((c) => c.normalized_name.includes(query.q.toLowerCase()));
        if (query.only_vulnerable === "true") items = items.filter((c) => c.vulnerabilities.length > 0);
        const skip = Number(query.skip ?? 0);
        const limit = Number(query.limit ?? 100);
        const withMatches = state.components.filter((c) => c.vulnerabilities.length > 0);
        return json(route, 200, { sbom_id: sbomId, total: items.length, skip, limit, items: items.slice(skip, skip + limit),
          vulnerability_linkage: { components_with_matches: withMatches.length, affected_matches: withMatches.reduce((n, c) => n + c.vulnerabilities.length, 0),
            latest_match_at: withMatches.length ? "2026-02-03T10:05:30Z" : null } });
      }
      const other = rest.match(/^\/diff\/([^/]+)$/)?.[1];
      if (other) {
        return state.sboms.some((s) => s.id === other) ? json(route, 200, { ...diff, base_sbom_id: sbomId, target_sbom_id: other }) : json(route, 404, { detail: "SBOM not found" });
      }
      if (rest === "") return json(route, 200, sbom);
    }
    return json(route, 404, { detail: "Not found" });
  });
}
