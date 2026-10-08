import { Fragment, useCallback, useEffect, useState } from "react";
import { FiAlertTriangle, FiChevronDown, FiChevronRight, FiRefreshCw, FiSearch, FiShield } from "react-icons/fi";
import { useParams } from "react-router-dom";

import { JobPanel } from "../components/analysis/JobPanel";
import { MatchEvidencePanel } from "../components/analysis/MatchEvidencePanel";
import { NotAnalysed, ProjectPageShell } from "../components/analysis/ProjectPageShell";
import { ErrorNotice, Spinner } from "../components/Feedback";
import { MatchStatusBadge, SeverityBadge } from "../components/StatusBadge";
import { StatTile } from "../components/StatTile";
import { useAsync } from "../hooks/useAsync";
import { useProjectJobs } from "../hooks/useProjectJobs";
import { getProject } from "../services/projects";
import { getVulnerabilityMatch, listVulnerabilities, startVulnerabilityMatching, startVulnerabilitySync } from "../services/security";
import { errorMessage } from "../utils/errors";
import { ecosystemLabel, formatDateTime, shortSha } from "../utils/format";
import type { JobType, MatchDetail, Severity } from "../utils/types";

const PAGE_SIZE = 50;
const JOB_TYPES: JobType[] = ["vulnerability_sync", "vulnerability_analysis"];
const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

export function VulnerabilitiesPage() {
  const { id = "" } = useParams();
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("");
  const [matchStatus, setMatchStatus] = useState("");
  const [ecosystem, setEcosystem] = useState("");
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [details, setDetails] = useState<Record<string, MatchDetail | { error: string }>>({});
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
    () => listVulnerabilities(id, { q: query, severity, match_status: matchStatus, ecosystem, skip: page * PAGE_SIZE, limit: PAGE_SIZE }),
    [id, query, severity, matchStatus, ecosystem, page],
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
      .catch(() => undefined); // only used to link evidence files to GitHub
    return () => {
      cancelled = true;
    };
  }, [id]);

  async function loadDetail(matchId: string) {
    setDetails((current) => Object.fromEntries(Object.entries(current).filter(([key]) => key !== matchId)));
    try {
      const detail = await getVulnerabilityMatch(id, matchId);
      setDetails((current) => ({ ...current, [matchId]: detail }));
    } catch (caught) {
      setDetails((current) => ({ ...current, [matchId]: { error: errorMessage(caught) } }));
    }
  }

  async function toggle(matchId: string) {
    if (expanded === matchId) {
      setExpanded(null);
      return;
    }
    setExpanded(matchId);
    const known = details[matchId];
    if (known && !("error" in known)) return;
    await loadDetail(matchId);
  }

  const scan = data?.scan ?? null;
  const sync = data?.sync ?? null;
  const filtered = query !== "" || severity !== "" || matchStatus !== "" || ecosystem !== "";
  const pages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;
  const ecosystems = scan ? Array.from(new Set(data?.items.map((item) => item.ecosystem) ?? [])).sort() : [];
  const disabled = jobs.loading || jobs.busy || jobs.starting;

  return (
    <ProjectPageShell projectId={id}>
      {loading && !data ? (
        <Spinner label="Loading vulnerability data" />
      ) : error && !data ? (
        <ErrorNotice message={error} onRetry={() => void reload()} />
      ) : !data || !data.snapshot ? (
        <NotAnalysed projectId={id} />
      ) : (
        <>
          <JobPanel
            title="Vulnerability check"
            testId="vulnerability-job"
            jobs={jobs}
            idle="Asks the configured vulnerability source which advisories apply to the dependency versions found in this repository, stores those advisories, and compares each version with the affected versions they publish. Nothing is estimated or predicted."
            failureNote="The vulnerability check failed. Findings below, if any, are from an earlier run."
            actions={
              <>
                <button type="button" className="btn btn-secondary" disabled={disabled || !sync} onClick={() => void jobs.run(() => startVulnerabilityMatching(id))}
                  title="Compare dependency versions with the advisories already stored, without contacting the source">
                  <FiRefreshCw aria-hidden /> Re-match stored advisories
                </button>
                <button type="button" className="btn btn-primary" disabled={disabled} onClick={() => void jobs.run(() => startVulnerabilitySync(id))}>
                  <FiShield aria-hidden /> {jobs.running ? "Check in progress" : jobs.starting ? "Starting…" : scan ? "Check again" : "Check for vulnerabilities"}
                </button>
              </>
            }
          />

          {sync && sync.status !== "completed" && sync.status !== "running" && (
            <div role="alert" className="mt-4 flex items-start gap-3 rounded-md bg-warn-soft px-4 py-3 text-sm text-warn" data-testid="sync-warning">
              <FiAlertTriangle className="mt-0.5 shrink-0" aria-hidden />
              <div>
                <p className="font-semibold">
                  {sync.status === "partial" ? "The last synchronisation was incomplete." : "The last synchronisation failed."}
                </p>
                <p className="mt-0.5">
                  {sync.error_summary} {scan ? "The findings below may be missing advisories." : "No findings are shown until a check completes."}
                </p>
              </div>
            </div>
          )}

          {!scan ? (
            <div className="card mt-6 border-dashed px-6 py-10 text-center" data-testid="not-scanned">
              <h2 className="text-base font-semibold">No vulnerability check has been run for this snapshot</h2>
              <p className="mx-auto mt-1.5 max-w-xl text-sm text-muted">
                Snapshot <span className="font-mono">{shortSha(data.snapshot.commit_sha)}</span> has a dependency inventory but has not been
                compared with any vulnerability data. No findings are shown, and the absence of findings here does not mean
                the dependencies are free of known vulnerabilities.
              </p>
            </div>
          ) : (
            <>
              <div className="mt-6 grid grid-cols-2 gap-3 lg:grid-cols-6" data-testid="vulnerability-stats">
                <StatTile label="Affected versions" value={scan.affected_dependencies} note={`of ${scan.dependencies_checked} dependency versions checked`} />
                <StatTile label="Vulnerabilities" value={scan.distinct_vulnerabilities} note={`${scan.affected_matches} advisory match${scan.affected_matches === 1 ? "" : "es"}`} />
                <StatTile label="Critical" value={scan.by_severity.CRITICAL} />
                <StatTile label="High" value={scan.by_severity.HIGH} />
                <StatTile label="Medium / Low" value={`${scan.by_severity.MEDIUM} / ${scan.by_severity.LOW}`} />
                <StatTile label="Severity unknown" value={scan.by_severity.UNKNOWN} note="The source publishes none" />
              </div>

              <dl className="mt-4 flex flex-wrap gap-x-8 gap-y-2 text-sm">
                <div>
                  <dt className="eyebrow inline">Source </dt>
                  <dd className="inline">{scan.intelligence ? `${scan.intelligence.provider.toUpperCase()} · synchronised ${formatDateTime(scan.intelligence.completed_at)}` : "stored advisories only"}</dd>
                </div>
                <div>
                  <dt className="eyebrow inline">Snapshot </dt>
                  <dd className="inline font-mono" title={scan.commit_sha}>{shortSha(scan.commit_sha)}</dd>
                </div>
                <div>
                  <dt className="eyebrow inline">Matched </dt>
                  <dd className="inline">{formatDateTime(scan.matched_at)}</dd>
                </div>
              </dl>

              {(scan.dependencies_unresolved > 0 || scan.dependencies_unsupported_ecosystem > 0 || scan.unsupported_matches > 0 ||
                scan.conflict_matches > 0 || scan.reported_but_not_stored_count > 0) && (
                <ul className="mt-4 space-y-1 rounded-md border border-line bg-surface px-4 py-3 text-sm text-ink-soft" data-testid="coverage-notes">
                  {scan.dependencies_unresolved > 0 && (
                    <li>{scan.dependencies_unresolved} dependenc{scan.dependencies_unresolved === 1 ? "y has" : "ies have"} no resolved version and could not be checked.</li>
                  )}
                  {scan.dependencies_unsupported_ecosystem > 0 && (
                    <li>
                      {scan.dependencies_unsupported_ecosystem} dependenc{scan.dependencies_unsupported_ecosystem === 1 ? "y is" : "ies are"} in an ecosystem the
                      source does not cover ({Object.keys(scan.unsupported_ecosystems).map(ecosystemLabel).join(", ")}) and could not be checked.
                    </li>
                  )}
                  {scan.unsupported_matches > 0 && (
                    <li>{scan.unsupported_matches} advisory match{scan.unsupported_matches === 1 ? "" : "es"} could not be verified because the version cannot be ordered safely. They are listed as "Not verified", not as affected.</li>
                  )}
                  {scan.conflict_matches > 0 && (
                    <li>{scan.conflict_matches} advisory match{scan.conflict_matches === 1 ? " is" : "es are"} reported by the source but not confirmed by the published ranges ("Conflict").</li>
                  )}
                  {scan.reported_but_not_stored_count > 0 && (
                    <li>{scan.reported_but_not_stored_count} advisory record{scan.reported_but_not_stored_count === 1 ? "" : "s"} reported by the source could not be fetched and {scan.reported_but_not_stored_count === 1 ? "is" : "are"} missing from these results.</li>
                  )}
                </ul>
              )}

              <div className="mt-6 flex flex-wrap items-end gap-3">
                <div className="min-w-[220px] flex-1">
                  <label htmlFor="vulnerability-search" className="mb-1 block text-xs font-medium text-muted">Search by package or identifier</label>
                  <div className="relative">
                    <FiSearch aria-hidden className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint" />
                    <input id="vulnerability-search" className="field pl-9" value={search} onChange={(event) => setSearch(event.target.value)} maxLength={100} placeholder="e.g. requests or CVE-2018-18074" />
                  </div>
                </div>
                <div>
                  <label htmlFor="vulnerability-severity" className="mb-1 block text-xs font-medium text-muted">Severity</label>
                  <select id="vulnerability-severity" className="field" value={severity} onChange={(event) => { setSeverity(event.target.value); setPage(0); }}>
                    <option value="">All</option>
                    {SEVERITIES.map((level) => <option key={level} value={level}>{level.charAt(0) + level.slice(1).toLowerCase()}</option>)}
                  </select>
                </div>
                <div>
                  <label htmlFor="vulnerability-status" className="mb-1 block text-xs font-medium text-muted">Status</label>
                  <select id="vulnerability-status" className="field" value={matchStatus} onChange={(event) => { setMatchStatus(event.target.value); setPage(0); }}>
                    <option value="">All</option>
                    <option value="AFFECTED">Affected</option>
                    <option value="UNSUPPORTED">Not verified</option>
                    <option value="CONFLICT">Conflict</option>
                  </select>
                </div>
                {(ecosystems.length > 1 || ecosystem !== "") && (
                  <div>
                    <label htmlFor="vulnerability-ecosystem" className="mb-1 block text-xs font-medium text-muted">Ecosystem</label>
                    <select id="vulnerability-ecosystem" className="field" value={ecosystem} onChange={(event) => { setEcosystem(event.target.value); setPage(0); }}>
                      <option value="">All</option>
                      {Array.from(new Set([...ecosystems, ecosystem].filter(Boolean))).map((name) => <option key={name} value={name}>{ecosystemLabel(name)}</option>)}
                    </select>
                  </div>
                )}
              </div>

              {error && (
                <div className="mt-4">
                  <ErrorNotice message={error} onRetry={() => void reload()} />
                </div>
              )}

              {data.total === 0 ? (
                <div className="card mt-4 px-6 py-8 text-center" data-testid="no-matches">
                  <h2 className="text-base font-semibold">{filtered ? "No findings match these filters" : "No known vulnerabilities matched"}</h2>
                  {!filtered && (
                    <p className="mx-auto mt-1.5 max-w-xl text-sm text-muted">
                      None of the {scan.dependencies_checked} dependency versions checked falls inside the affected versions published
                      by the advisories that were retrieved. This reflects the source's data at the time of the check, and only the
                      versions that could be checked.
                    </p>
                  )}
                </div>
              ) : (
                <div className="card mt-4 overflow-x-auto">
                  <table className="w-full min-w-[980px] text-left text-sm" data-testid="vulnerability-table">
                    <thead>
                      <tr className="border-b border-line">
                        <th className="w-8 px-2 py-2.5" />
                        <th className="eyebrow px-3 py-2.5 font-medium">Package</th>
                        <th className="eyebrow px-3 py-2.5 font-medium">Installed</th>
                        <th className="eyebrow px-3 py-2.5 font-medium">Vulnerability</th>
                        <th className="eyebrow px-3 py-2.5 font-medium">Severity</th>
                        <th className="eyebrow px-3 py-2.5 font-medium">Source</th>
                        <th className="eyebrow px-3 py-2.5 font-medium">Affected range</th>
                        <th className="eyebrow px-3 py-2.5 font-medium">Fixed in</th>
                        <th className="eyebrow px-3 py-2.5 font-medium">Status</th>
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
                                  aria-label={`${open ? "Hide" : "Show"} evidence for ${item.package_name} ${item.source_id}`} className="rounded p-1 hover:bg-line/60">
                                  {open ? <FiChevronDown aria-hidden /> : <FiChevronRight aria-hidden />}
                                </button>
                              </td>
                              <td className="px-3 py-2.5">
                                <div className="font-mono text-[13px]">{item.package_name}</div>
                                <div className="text-xs text-muted">{ecosystemLabel(item.ecosystem)}{item.relationship ? ` · ${item.relationship.toLowerCase()}` : ""}</div>
                              </td>
                              <td className="px-3 py-2.5 font-mono text-[13px]">{item.matched_version}</td>
                              <td className="px-3 py-2.5">
                                <div className="font-mono text-[13px]">{item.source_id}</div>
                                {item.aliases.length > 0 && <div className="font-mono text-xs text-muted">{item.aliases.slice(0, 2).join(", ")}</div>}
                              </td>
                              <td className="px-3 py-2.5"><SeverityBadge severity={item.severity} /></td>
                              <td className="px-3 py-2.5 uppercase">{item.source}</td>
                              <td className="px-3 py-2.5 font-mono text-[13px]">{item.affected_range ?? "—"}</td>
                              <td className="px-3 py-2.5 font-mono text-[13px]">{item.fixed_version ?? (item.match_status === "AFFECTED" ? "none published" : "—")}</td>
                              <td className="px-3 py-2.5"><MatchStatusBadge status={item.match_status} /></td>
                            </tr>
                            {open && (
                              <tr className="border-b border-line bg-paper/60">
                                <td />
                                <td colSpan={8} className="px-3 pb-5 pt-2">
                                  {!detail ? (
                                    <Spinner label="Loading evidence" />
                                  ) : "error" in detail ? (
                                    <ErrorNotice message={detail.error} onRetry={() => void loadDetail(item.id)} />
                                  ) : (
                                    <MatchEvidencePanel detail={detail} repositoryUrl={repositoryUrl} commitSha={scan.commit_sha} />
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
                  <span data-testid="vulnerability-range">
                    {data.skip + 1}–{data.skip + data.items.length} of {data.total}
                    {filtered ? ` (filtered from ${scan.affected_matches + scan.unsupported_matches + scan.conflict_matches})` : ""}
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

              <p className="mt-6 max-w-4xl text-xs text-muted">
                A finding means the installed version lies inside the affected versions an advisory publishes. That is an{" "}
                <strong className="font-semibold text-ink-soft">observed</strong> fact about version numbers. It does not say that the vulnerable
                code is used or reachable, or how likely exploitation is; those are not assessed here. Severity is shown as the
                source publishes it.
              </p>
            </>
          )}
        </>
      )}
    </ProjectPageShell>
  );
}
