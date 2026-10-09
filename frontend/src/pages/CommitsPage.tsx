import { useState } from "react";
import { FiGitCommit, FiX } from "react-icons/fi";
import { useParams } from "react-router-dom";

import { CommitTimelineChart } from "../charts/PlatformCharts";
import { JobPanel } from "../components/analysis/JobPanel";
import { ProjectPageShell } from "../components/analysis/ProjectPageShell";
import { ErrorNotice, Spinner } from "../components/Feedback";
import { BasisTag, Confidence, LevelBadge, Meaning, NotRun, Panel, Score, useLayer, words } from "../components/platform/common";
import { StatTile } from "../components/StatTile";
import { useAsync } from "../hooks/useAsync";
import { getCommit, listCommits, listSecurityEvents, setCommitMonitoring, startCommitAnalysis } from "../services/platform";
import { errorMessage } from "../utils/errors";
import { formatDateTime } from "../utils/format";
import type { CommitList, CommitRow, EventList } from "../utils/platformTypes";
import type { JobType } from "../utils/types";

const JOB_TYPES: JobType[] = ["commit_behaviour_analysis"];

function CommitDetailPanel({ projectId, row, onClose }: { projectId: string; row: CommitRow; onClose: () => void }) {
  const { data, error, loading } = useAsync(() => getCommit(projectId, row.commit_sha), [projectId, row.commit_sha]);
  const commit = data?.commit;
  return (
    <Panel title={`Commit ${row.commit_sha.slice(0, 10)}`} testId="commit-detail" aside={<button type="button" className="btn btn-secondary" onClick={onClose}><FiX aria-hidden /> Close</button>}>
      <p className="text-sm">{row.message ?? "(no message)"} <span className="text-muted">— {row.author_login ?? row.author_name ?? "unknown author"}, {formatDateTime(row.committed_at)}</span></p>
      <div className="mt-2 flex flex-wrap items-center gap-2 text-sm">
        <LevelBadge level={row.level} /> <span className="text-muted">anomaly</span> <Score value={row.anomaly_score} /> <span className="text-muted">confidence</span> <Confidence value={row.confidence} />
        <span className="text-muted">{row.stats.files} file(s), +{row.stats.additions} −{row.stats.deletions}</span>
      </div>
      {loading && <Spinner label="Loading commit" />}
      {error && <ErrorNotice message={error} />}
      {commit && (
        <>
          <h3 className="mt-5 text-sm font-semibold">Security indicators</h3>
          {commit.findings.length === 0 ? <p className="mt-1 text-sm text-muted">No rule matched this commit's diff.</p> : (
            <ul className="mt-2 space-y-2" data-testid="commit-findings">
              {commit.findings.map((finding, index) => (
                <li key={index} className="rounded-md border border-line px-3 py-2 text-sm" data-testid="commit-finding" data-type={finding.type} data-rule={finding.rule}>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[12px] font-semibold">{finding.type}</span> <LevelBadge level={finding.severity} /> <BasisTag basis={finding.basis} />
                    <Confidence value={finding.confidence} />
                    {finding.file && <span className="font-mono text-xs text-muted">{finding.file}{finding.line ? `:${finding.line}` : ""}</span>}
                  </div>
                  <p className="mt-1">{finding.detail}</p>
                  {finding.excerpt && <pre className="mt-1 overflow-x-auto rounded bg-paper px-2 py-1 font-mono text-[12px]" data-testid="finding-excerpt">{finding.side === "removed" ? "− " : "+ "}{finding.excerpt}</pre>}
                </li>
              ))}
            </ul>
          )}
          <h3 className="mt-5 text-sm font-semibold">How the anomaly score was formed</h3>
          <p className="text-xs text-muted">Compared with {commit.baseline.commits} earlier commit(s){commit.baseline.sufficient ? `: median ${commit.baseline.median_lines} lines in ${commit.baseline.median_files} file(s)` : "; too few for a baseline, so the comparisons are unknown"}.</p>
          <table className="mt-2 w-full text-left text-sm" data-testid="anomaly-factors">
            <thead className="eyebrow border-b border-line"><tr><th className="py-1 pr-3">Factor</th><th className="pr-3">Weight</th><th className="pr-3">Value</th><th className="pr-3">Points</th><th>Detail</th></tr></thead>
            <tbody>
              {commit.factors.map((factor) => (
                <tr key={factor.name} className="border-b border-line/60" data-factor={factor.name} data-status={factor.status}>
                  <td className="py-1 pr-3 font-mono text-xs">{words(factor.name)}</td><td className="pr-3 font-mono">{factor.weight}</td>
                  <td className="pr-3 font-mono">{factor.value === null ? "unknown" : factor.value}</td><td className="pr-3 font-mono">{factor.contribution ?? "—"}</td>
                  <td className="text-[13px] text-ink-soft">{factor.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <h3 className="mt-5 text-sm font-semibold">Changed files</h3>
          <ul className="mt-1 space-y-0.5 font-mono text-xs" data-testid="changed-files">
            {commit.files.map((file) => <li key={file.path}>{file.path} <span className="text-muted">{file.status} +{file.additions} −{file.deletions}{file.diff_inspected ? "" : " · diff not available"}{file.kinds.length ? ` · ${file.kinds.join(", ")}` : ""}</span></li>)}
          </ul>
          {!commit.coverage.complete && <p className="mt-2 text-xs text-warn">{commit.coverage.files_listed - commit.coverage.files_inspected} of {commit.coverage.files_listed} file(s) could not be inspected (binary, or too large for GitHub to include). Confidence is lowered accordingly.</p>}
        </>
      )}
    </Panel>
  );
}

export function CommitsPage() {
  const { id: projectId = "" } = useParams();
  const { data, jobs } = useLayer<{ commits: CommitList; events: EventList }>(projectId, JOB_TYPES, async () => {
    const [commits, events] = await Promise.all([listCommits(projectId), listSecurityEvents(projectId)]);
    return { commits, events };
  });
  const [selected, setSelected] = useState<CommitRow | null>(null);
  const [toggleError, setToggleError] = useState<string | null>(null);
  // What the user just chose, shown at once; the stored state replaces it when the reload arrives.
  const [pendingMonitoring, setPendingMonitoring] = useState<boolean | null>(null);
  const [indicator, setIndicator] = useState("");
  const list = data.data?.commits;
  const events = data.data?.events;
  const summary = list?.analysis?.summary;
  const rows = (list?.items ?? []).filter((row) => !indicator || row.indicator_types.includes(indicator));
  const start = <button type="button" className="btn btn-primary" disabled={jobs.busy || jobs.starting} onClick={() => void jobs.run(() => startCommitAnalysis(projectId))}>
    <FiGitCommit aria-hidden /> {list?.analysed_total ? "Check for new commits" : "Start analysis"}</button>;

  async function toggle(enabled: boolean) {
    setPendingMonitoring(enabled);
    try {
      setToggleError(null);
      await setCommitMonitoring(projectId, enabled);
      await data.reload({ silent: true });
    } catch (caught) {
      setToggleError(errorMessage(caught));
    } finally {
      setPendingMonitoring(null);
    }
  }

  return (
    <ProjectPageShell projectId={projectId}>
      {data.loading && !list ? <Spinner label="Loading commit behaviour" /> : data.error && !list ? <ErrorNotice message={data.error} onRetry={() => void data.reload()} /> : list && events && (
        <div className="space-y-6">
          <JobPanel title="Commit behaviour analysis" jobs={jobs} actions={start} testId="commit-job"
            idle="Reads the newest commits and their diffs from GitHub as text and looks for security-relevant changes. Each commit is compared with the repository's own earlier commits. Nothing is checked out or executed."
            failureNote="The analysis did not finish. Commits shown are from earlier runs." />
          <Panel title="Monitoring" testId="monitoring">
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={pendingMonitoring ?? list.monitoring.enabled} disabled={pendingMonitoring !== null} onChange={(event) => void toggle(event.target.checked)} />
              Check this repository for new commits periodically
            </label>
            <p className="mt-1 text-xs text-muted">
              By polling{list.monitoring.interval_minutes ? ` every ${list.monitoring.interval_minutes} minute(s)` : ""}; no webhook is registered. Last checked {formatDateTime(list.monitoring.last_checked_at)}.
              {list.monitoring.note ? ` ${list.monitoring.note}` : ""}
            </p>
            {toggleError && <div className="mt-2"><ErrorNotice message={toggleError} /></div>}
          </Panel>
          <Meaning testId="commit-meaning">{list.meaning}</Meaning>
          {list.analysed_total === 0 ? (
            <NotRun title="Analysis not available">
              {summary?.data_status === "UNAVAILABLE" ? "GitHub could not be read, so no commit was analysed. Nothing is assumed about the commits that could not be read."
                : "No commit has been analysed for this project. Until then there are no behaviour events to show, which is not the same as there being none."}
            </NotRun>
          ) : (
            <>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4" data-testid="commit-summary">
                <StatTile label="Commits analysed" value={list.analysed_total} note={summary?.not_yet_analysed ? `${summary.not_yet_analysed} newer commit(s) still waiting` : "all listed commits"} />
                <StatTile label="Listed for security review" value={events.total} note="events of medium or high severity" />
                <StatTile label="Highest anomaly" value={<Score value={Math.max(...list.items.map((row) => row.anomaly_score))} />} note="0–100, against the repository's own history" />
                <StatTile label="High-anomaly commits" value={list.items.filter((row) => row.level === "HIGH").length} note="reasons to review, not verdicts" />
              </div>
              <Panel title="Commit timeline" testId="commit-timeline"><CommitTimelineChart commits={list.items} /></Panel>

              <Panel title="Events listed for security review" testId="security-events">
                {events.items.length === 0 ? <p className="text-sm text-muted">No event of medium or high severity among the analysed commits.</p> : (
                  <ul className="space-y-2">
                    {events.items.map((event, index) => (
                      <li key={index} className="rounded-md border border-line px-3 py-2 text-sm" data-testid="security-event" data-type={event.event_type}>
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono text-[12px] font-semibold">{event.event_type}</span> <LevelBadge level={event.severity} />
                          <span className="font-mono text-xs text-muted">{words(event.observed_or_inferred)}</span> <Confidence value={event.confidence} />
                          <span className="font-mono text-xs text-muted">{event.commit_sha.slice(0, 10)} · {formatDateTime(event.occurred_at)}</span>
                        </div>
                        <p className="mt-1">{event.summary}</p>
                        {event.changed_files.length > 0 && <p className="font-mono text-xs text-muted">{event.changed_files.join(", ")}</p>}
                        <p className="mt-1 text-xs text-muted">{event.review_note}</p>
                      </li>
                    ))}
                  </ul>
                )}
              </Panel>

              <Panel title="Commits" testId="commit-table"
                aside={(
                  <select aria-label="Filter by indicator" className="rounded-md border border-line bg-surface px-2 py-1 text-sm" value={indicator} onChange={(event) => setIndicator(event.target.value)}>
                    <option value="">All commits</option>
                    {list.indicator_types.map((type) => <option key={type} value={type}>{type}</option>)}
                  </select>
                )}>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead className="eyebrow border-b border-line"><tr><th className="py-2 pr-3">Commit</th><th className="pr-3">When</th><th className="pr-3">Author</th><th className="pr-3">Anomaly</th><th className="pr-3">Confidence</th><th className="pr-3">Size</th><th>Indicators</th></tr></thead>
                    <tbody>
                      {rows.map((row) => (
                        <tr key={row.commit_sha} className="border-b border-line/60" data-testid="commit-row" data-sha={row.commit_sha} data-level={row.level}>
                          <td className="py-2 pr-3"><button type="button" className="text-left hover:underline" onClick={() => setSelected(row)}><span className="font-mono text-xs">{row.commit_sha.slice(0, 10)}</span> {row.message}</button></td>
                          <td className="pr-3 whitespace-nowrap text-[13px]">{formatDateTime(row.committed_at)}</td>
                          <td className="pr-3">{row.author_login ?? row.author_name ?? "—"}</td>
                          <td className="pr-3"><Score value={row.anomaly_score} /> <LevelBadge level={row.level} /></td>
                          <td className="pr-3"><Confidence value={row.confidence} /></td>
                          <td className="pr-3 font-mono text-xs">{row.stats.files}f +{row.stats.additions} −{row.stats.deletions}</td>
                          <td className="font-mono text-xs text-muted">{row.indicator_types.join(", ") || "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Panel>
              {selected && <CommitDetailPanel projectId={projectId} row={selected} onClose={() => setSelected(null)} />}
            </>
          )}
        </div>
      )}
    </ProjectPageShell>
  );
}
