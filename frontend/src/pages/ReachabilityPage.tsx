import { Fragment, useCallback, useEffect, useState } from "react";
import { FiAlertTriangle, FiChevronDown, FiChevronRight, FiCode, FiSearch } from "react-icons/fi";
import { Link, useParams } from "react-router-dom";

import { JobPanel } from "../components/analysis/JobPanel";
import { NotAnalysed, ProjectPageShell } from "../components/analysis/ProjectPageShell";
import { ReachabilityEvidencePanel, reasonText } from "../components/analysis/ReachabilityEvidencePanel";
import { ErrorNotice, Spinner } from "../components/Feedback";
import { StatTile } from "../components/StatTile";
import { ConfidenceLabel, ReachabilityBadge, SeverityBadge } from "../components/StatusBadge";
import { useAsync } from "../hooks/useAsync";
import { useProjectJobs } from "../hooks/useProjectJobs";
import { getProject } from "../services/projects";
import { getReachabilityFinding, listReachability, startReachabilityAnalysis } from "../services/security";
import { errorMessage } from "../utils/errors";
import { ecosystemLabel, formatDateTime, shortSha } from "../utils/format";
import type { JobType, ReachabilityFindingDetail, ReachabilityStatus } from "../utils/types";

const PAGE_SIZE = 50;
const JOB_TYPES: JobType[] = ["code_reachability_analysis"];
const STATUS_LABELS: Record<ReachabilityStatus, string> = {
  REACHABLE: "Reachable", NOT_CONFIRMED_REACHABLE: "Not confirmed", UNKNOWN: "Unknown", UNSUPPORTED: "Unsupported",
};
const INCOMPLETE: Record<string, string> = {
  SYNTAX_ERROR: "could not be parsed", NOT_TEXT: "were not text", TOO_COMPLEX: "were too complex to analyse",
  SKIPPED_TOO_LARGE: "were larger than the per-file limit", SKIPPED_FILE_LIMIT: "were beyond the file-count limit",
  SKIPPED_SIZE_LIMIT: "were beyond the total-size limit", SKIPPED_UNSAFE_PATH: "had unusable paths", SKIPPED_UNSUPPORTED_FORMAT: "were notebooks or Cython, which are not parsed", FETCH_FAILED: "could not be fetched",
  RECORDS_TRUNCATED: "had more records than are kept", GRAPH_TRUNCATED: "exceeded the graph size limit",
};

export function ReachabilityPage() {
  const { id = "" } = useParams();
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [details, setDetails] = useState<Record<string, ReachabilityFindingDetail | { error: string }>>({});
  const [repositoryUrl, setRepositoryUrl] = useState<string | undefined>();

  useEffect(() => {
    const next = search.trim();
    if (next === query) return;
    const timer = window.setTimeout(() => {
      setQuery(next);
      setPage(0);
    }, 300);
    return () => window.clearTimeout(timer);
  }, [search, query]);

  const { data, error, loading, reload } = useAsync(
    () => listReachability(id, { q: query, status, skip: page * PAGE_SIZE, limit: PAGE_SIZE }),
    [id, query, status, page],
  );

  const refresh = useCallback(() => {
    setDetails({});
    setExpanded(null);
    void reload({ silent: true });
  }, [reload]);
  const jobs = useProjectJobs(id, JOB_TYPES, refresh);

  useEffect(() => {
    let cancelled = false;
    getProject(id)
      .then((project) => {
        if (!cancelled) setRepositoryUrl(project.repository_url);
      })
      .catch(() => undefined);      // the page works without links to the repository
    return () => {
      cancelled = true;
    };
  }, [id]);

  async function loadDetail(findingId: string) {
    setDetails((current) => Object.fromEntries(Object.entries(current).filter(([key]) => key !== findingId)));
    try {
      const detail = await getReachabilityFinding(id, findingId);
      setDetails((current) => ({ ...current, [findingId]: detail }));
    } catch (caught) {
      setDetails((current) => ({ ...current, [findingId]: { error: errorMessage(caught) } }));
    }
  }

  async function toggle(findingId: string) {
    if (expanded === findingId) {
      setExpanded(null);
      return;
    }
    setExpanded(findingId);
    const known = details[findingId];
    if (known && !("error" in known)) return;
    await loadDetail(findingId);
  }

  const analysis = data?.analysis ?? null;
  const filtered = query !== "" || status !== "";
  const pages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;
  const disabled = jobs.loading || jobs.busy || jobs.starting || !data?.has_vulnerability_scan;
  const stale = analysis !== null && data?.vulnerability_scan_matched_at != null && analysis.vulnerability_scan_matched_at !== data.vulnerability_scan_matched_at;

  return (
    <ProjectPageShell projectId={id}>
      {loading && !data ? (
        <Spinner label="Loading reachability data" />
      ) : error && !data ? (
        <ErrorNotice message={error} onRetry={() => void reload()} />
      ) : !data || !data.snapshot ? (
        <NotAnalysed projectId={id} />
      ) : (
        <>
          <JobPanel
            title="Code reachability analysis"
            testId="reachability-job"
            jobs={jobs}
            idle="Reads the repository's Python source at the snapshot's commit, without running it, and checks whether the code statically reaches the functionality each known vulnerability affects. A path found this way is evidence of use, not proof that a vulnerability can be exploited."
            failureNote="The analysis failed. Findings below, if any, are from an earlier run."
            actions={
              <button type="button" className="btn btn-primary" disabled={disabled} onClick={() => void jobs.run(() => startReachabilityAnalysis(id))}
                title={data.has_vulnerability_scan ? undefined : "Run a vulnerability check for this snapshot first"}>
                <FiCode aria-hidden /> {jobs.running ? "Analysis in progress" : jobs.starting ? "Starting…" : analysis ? "Analyse again" : "Start analysis"}
              </button>
            }
          />

          {!data.has_vulnerability_scan ? (
            <div className="card mt-6 border-dashed px-6 py-10 text-center" data-testid="needs-scan">
              <h2 className="text-base font-semibold">Run a vulnerability check first</h2>
              <p className="mx-auto mt-1.5 max-w-xl text-sm text-muted">
                Reachability is analysed for known vulnerabilities in this snapshot's dependencies, and snapshot{" "}
                <span className="font-mono">{shortSha(data.snapshot.commit_sha)}</span> has not been checked yet.
              </p>
              <Link to={`/projects/${id}/vulnerabilities`} className="btn btn-primary mt-5">Go to vulnerabilities</Link>
            </div>
          ) : !analysis ? (
            <div className="card mt-6 border-dashed px-6 py-10 text-center" data-testid="not-analysed">
              <h2 className="text-base font-semibold">No reachability analysis has been run for this snapshot</h2>
              <p className="mx-auto mt-1.5 max-w-xl text-sm text-muted">
                Nothing is shown until an analysis completes. A vulnerable dependency without a result here has not been
                found unreachable; it has not been analysed.
              </p>
            </div>
          ) : (
            <>
              {stale && (
                <div role="alert" className="mt-4 flex items-start gap-3 rounded-md bg-warn-soft px-4 py-3 text-sm text-warn" data-testid="stale-warning">
                  <FiAlertTriangle className="mt-0.5 shrink-0" aria-hidden />
                  <p>The vulnerability check has been run again since this analysis. Analyse again to cover the current findings.</p>
                </div>
              )}

              <div className="mt-6 grid grid-cols-2 gap-3 lg:grid-cols-5" data-testid="reachability-stats">
                <StatTile label="Reachable" value={analysis.findings.by_status.REACHABLE} note="A static path to affected functionality" />
                <StatTile label="Not confirmed" value={analysis.findings.by_status.NOT_CONFIRMED_REACHABLE} note="No path established; not a safety statement" />
                <StatTile label="Unknown" value={analysis.findings.by_status.UNKNOWN} note="Could not be decided" />
                <StatTile label="Unsupported" value={analysis.findings.by_status.UNSUPPORTED} note="Ecosystem not analysed" />
                <StatTile label="Source files" value={`${analysis.source.files_parsed} / ${analysis.source.files_found}`} note="Python files parsed / found" />
              </div>

              <dl className="mt-4 flex flex-wrap gap-x-8 gap-y-2 text-sm">
                <div><dt className="eyebrow inline">Snapshot </dt><dd className="inline font-mono" title={analysis.commit_sha}>{shortSha(analysis.commit_sha)}</dd></div>
                <div><dt className="eyebrow inline">Analysed </dt><dd className="inline">{formatDateTime(analysis.completed_at)}</dd></div>
                <div>
                  <dt className="eyebrow inline">Code graph </dt>
                  <dd className="inline">{analysis.graph.functions} functions · {analysis.graph.edges} edges · {analysis.graph.unresolved} unresolved uses</dd>
                </div>
              </dl>

              <ul className="mt-4 space-y-1 rounded-md border border-line bg-surface px-4 py-3 text-sm text-ink-soft" data-testid="coverage-notes">
                <li>
                  {analysis.findings.with_symbol_mapping} of {analysis.findings.findings} finding{analysis.findings.findings === 1 ? "" : "s"} name the
                  affected functions. For the rest, reachability of the affected functionality cannot be decided and only the use of the package is shown.
                </li>
                {!analysis.source_complete && (
                  <li data-testid="incomplete-source">
                    The source was not analysed completely:{" "}
                    {analysis.incomplete_reasons.map((item) => `${item.files} file${item.files === 1 ? "" : "s"} ${INCOMPLETE[item.reason] ?? item.reason}`).join("; ")}.
                    Where no path was found, the result is Unknown rather than Not confirmed.
                  </li>
                )}
                {Object.keys(analysis.source.other_languages).length > 0 && (
                  <li>
                    Source in other languages is not analysed ({Object.entries(analysis.source.other_languages).map(([name, count]) => `${name}: ${count} file${count === 1 ? "" : "s"}`).join(", ")}).
                  </li>
                )}
                {analysis.graph.unresolved > 0 && (
                  <li>{analysis.graph.unresolved} call{analysis.graph.unresolved === 1 ? "" : "s"} or reference{analysis.graph.unresolved === 1 ? "" : "s"} could not be bound statically and are not part of any path.</li>
                )}
              </ul>

              <div className="mt-6 flex flex-wrap items-end gap-3">
                <div className="min-w-[220px] flex-1">
                  <label htmlFor="reachability-search" className="mb-1 block text-xs font-medium text-muted">Search by package or identifier</label>
                  <div className="relative">
                    <FiSearch aria-hidden className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint" />
                    <input id="reachability-search" className="field pl-9" value={search} onChange={(event) => setSearch(event.target.value)} maxLength={100} placeholder="e.g. requests or CVE-2018-18074" />
                  </div>
                </div>
                <div>
                  <label htmlFor="reachability-status" className="mb-1 block text-xs font-medium text-muted">Reachability</label>
                  <select id="reachability-status" className="field" value={status} onChange={(event) => { setStatus(event.target.value); setPage(0); }}>
                    <option value="">All</option>
                    {data.statuses.map((value) => <option key={value} value={value}>{STATUS_LABELS[value] ?? value}</option>)}
                  </select>
                </div>
              </div>

              {error && (
                <div className="mt-4">
                  <ErrorNotice message={error} onRetry={() => void reload()} />
                </div>
              )}

              {data.total === 0 ? (
                <div className="card mt-4 px-6 py-8 text-center" data-testid="no-findings">
                  <h2 className="text-base font-semibold">{filtered ? "No findings match these filters" : "No vulnerable dependencies to analyse"}</h2>
                  {!filtered && (
                    <p className="mx-auto mt-1.5 max-w-xl text-sm text-muted">
                      The vulnerability check matched no advisory to this snapshot's dependency versions, so there was nothing to trace.
                    </p>
                  )}
                </div>
              ) : (
                <div className="card mt-4 overflow-x-auto">
                  <table className="w-full min-w-[980px] text-left text-sm" data-testid="reachability-table">
                    <thead>
                      <tr className="border-b border-line">
                        <th className="w-8 px-2 py-2.5" />
                        <th className="eyebrow px-3 py-2.5 font-medium">Dependency</th>
                        <th className="eyebrow px-3 py-2.5 font-medium">Version</th>
                        <th className="eyebrow px-3 py-2.5 font-medium">Vulnerability</th>
                        <th className="eyebrow px-3 py-2.5 font-medium">Severity</th>
                        <th className="eyebrow px-3 py-2.5 font-medium">Reachability</th>
                        <th className="eyebrow px-3 py-2.5 font-medium">Confidence</th>
                        <th className="eyebrow px-3 py-2.5 font-medium">Source location</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.items.map((item) => {
                        const open = expanded === item.id;
                        const detail = details[item.id];
                        return (
                          <Fragment key={item.id}>
                            <tr className={`border-b border-line ${open ? "bg-paper/60" : "hover:bg-paper/60"}`}>
                              <td className="px-2 py-2.5">
                                <button type="button" onClick={() => void toggle(item.id)} aria-expanded={open}
                                  aria-label={`${open ? "Hide" : "Show"} evidence for ${item.dependency} ${item.advisory_id}`} className="rounded p-1 hover:bg-line/60">
                                  {open ? <FiChevronDown aria-hidden /> : <FiChevronRight aria-hidden />}
                                </button>
                              </td>
                              <td className="px-3 py-2.5">
                                <div className="font-mono text-[13px]">{item.dependency}</div>
                                <div className="text-xs text-muted">{ecosystemLabel(item.ecosystem)}{item.relationship ? ` · ${item.relationship.toLowerCase()}` : ""}</div>
                              </td>
                              <td className="px-3 py-2.5 font-mono text-[13px]">{item.resolved_version}</td>
                              <td className="px-3 py-2.5">
                                <div className="font-mono text-[13px]">{item.advisory_id}</div>
                                {item.aliases.length > 0 && <div className="font-mono text-xs text-muted">{item.aliases.slice(0, 2).join(", ")}</div>}
                              </td>
                              <td className="px-3 py-2.5"><SeverityBadge severity={item.severity} /></td>
                              <td className="px-3 py-2.5">
                                <ReachabilityBadge status={item.status} />
                                <div className="mt-0.5 max-w-[260px] text-xs text-muted">{reasonText(item.reason)}</div>
                              </td>
                              <td className="px-3 py-2.5"><ConfidenceLabel confidence={item.confidence} /></td>
                              <td className="px-3 py-2.5 font-mono text-[12px]">
                                {item.evidence.source_file ? `${item.evidence.source_file}${item.evidence.line ? `:${item.evidence.line}` : ""}` : "—"}
                              </td>
                            </tr>
                            {open && (
                              <tr className="border-b border-line bg-paper/60">
                                <td />
                                <td colSpan={7} className="px-3 pb-5 pt-2">
                                  {!detail ? (
                                    <Spinner label="Loading evidence" />
                                  ) : "error" in detail ? (
                                    <ErrorNotice message={detail.error} onRetry={() => void loadDetail(item.id)} />
                                  ) : (
                                    <ReachabilityEvidencePanel detail={detail} repositoryUrl={repositoryUrl} commitSha={analysis.commit_sha} />
                                  )}
                                </td>
                              </tr>
                            )}
                          </Fragment>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}

              {data.total > 0 && (
                <div className="mt-3 flex flex-wrap items-center justify-between gap-3 text-sm text-muted">
                  <span data-testid="reachability-range">
                    {data.skip + 1}–{data.skip + data.items.length} of {data.total}
                    {filtered ? ` (filtered from ${analysis.findings.findings})` : ""}
                  </span>
                  {pages > 1 && (
                    <span className="flex items-center gap-2">
                      <button type="button" className="btn btn-secondary" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
                      <span>Page {page + 1} of {pages}</span>
                      <button type="button" className="btn btn-secondary" disabled={page + 1 >= pages} onClick={() => setPage(page + 1)}>Next</button>
                    </span>
                  )}
                </div>
              )}

              <p className="mt-6 max-w-3xl text-xs text-muted" data-testid="reachability-meaning">
                <strong className="font-semibold">Static reachability is not exploitability.</strong> "Reachable" means the source text refers to
                functionality an advisory identifies as affected. It does not show that an attacker can reach or trigger it. "Not confirmed"
                and "Unknown" do not mean safe. The call graph is conservative and incomplete: calls decided at run time are not followed.
              </p>
            </>
          )}
        </>
      )}
    </ProjectPageShell>
  );
}
