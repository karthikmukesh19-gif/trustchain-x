import { useState } from "react";
import { FiUsers, FiX } from "react-icons/fi";
import { useParams } from "react-router-dom";

import { ActivityChart } from "../charts/PlatformCharts";
import { JobPanel } from "../components/analysis/JobPanel";
import { ProjectPageShell } from "../components/analysis/ProjectPageShell";
import { ErrorNotice, Spinner } from "../components/Feedback";
import { Confidence, Meaning, NotRun, Panel, Score, percent, useLayer, words } from "../components/platform/common";
import { StatTile } from "../components/StatTile";
import { Badge } from "../components/StatusBadge";
import { useAsync } from "../hooks/useAsync";
import { getMaintainer, listMaintainers, startMaintainerAnalysis } from "../services/platform";
import { formatDate } from "../utils/format";
import type { BehaviourIndicator, IndicatorStatus, MaintainerList, MaintainerRow } from "../utils/platformTypes";
import type { JobType } from "../utils/types";

const JOB_TYPES: JobType[] = ["maintainer_analysis"];
const STATUS_VIEW: Record<IndicatorStatus, { label: string; tone: "warn" | "neutral" | "good" }> = {
  OBSERVED: { label: "Observed", tone: "warn" }, NOT_OBSERVED: { label: "Not observed", tone: "good" }, UNKNOWN: { label: "Unknown", tone: "neutral" },
};

function evidenceLines(evidence: Record<string, unknown>): string[] {
  return Object.entries(evidence)
    .filter(([, value]) => typeof value === "number" || typeof value === "string")
    .map(([key, value]) => `${words(key)}: ${typeof value === "number" && value > 0 && value <= 1 && key.includes("share") ? percent(value) : String(value)}`);
}

function Indicator({ indicator }: { indicator: BehaviourIndicator }) {
  const [open, setOpen] = useState(false);
  const view = STATUS_VIEW[indicator.status];
  const lines = evidenceLines(indicator.evidence);
  return (
    <li className="border-b border-line/60 py-3 last:border-0" data-testid="indicator" data-type={indicator.type} data-status={indicator.status}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-[13px] font-semibold">{indicator.type}</span>
        <Badge tone={view.tone}>{view.label}</Badge>
        <span className="text-xs text-muted">weight {indicator.weight}{indicator.status === "OBSERVED" ? ` · strength ${indicator.strength}` : ""}</span>
        {lines.length > 0 && <button type="button" className="text-xs font-medium text-trust hover:underline" onClick={() => setOpen(!open)} aria-expanded={open}>{open ? "Hide evidence" : "Evidence"}</button>}
      </div>
      <p className="mt-1 text-sm text-ink-soft">{indicator.detail}</p>
      {open && <ul className="mt-2 space-y-0.5 font-mono text-xs text-muted" data-testid="indicator-evidence">{lines.map((line) => <li key={line}>{line}</li>)}</ul>}
    </li>
  );
}

function ContributorDetail({ projectId, row, onClose }: { projectId: string; row: MaintainerRow; onClose: () => void }) {
  const { data, error, loading } = useAsync(() => getMaintainer(projectId, row.maintainer_id), [projectId, row.maintainer_id]);
  const person = data?.maintainer ?? row;
  return (
    <Panel title={`Contributor: ${row.display_name}`} testId="contributor-detail" aside={<button type="button" className="btn btn-secondary" onClick={onClose}><FiX aria-hidden /> Close</button>}>
      {loading && <Spinner label="Loading contributor" />}
      {error && <ErrorNotice message={error} />}
      <dl className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
        <div><dt className="eyebrow">Commits observed</dt><dd>{person.commits} ({percent(person.share)})</dd></div>
        <div><dt className="eyebrow">First / last commit</dt><dd>{formatDate(person.first_commit_at)} – {formatDate(person.last_commit_at)}</dd></div>
        <div><dt className="eyebrow">Active days</dt><dd>{person.active_days}</dd></div>
        <div><dt className="eyebrow">Signed commits</dt><dd>{person.verified_commits}</dd></div>
        <div><dt className="eyebrow">Identified by</dt><dd>{person.identified_by === "login" ? "GitHub account" : person.identified_by === "email" ? "commit e-mail (not shown)" : "author name"}</dd></div>
        <div><dt className="eyebrow">Last 90 days</dt><dd>{person.recent_commits} commit(s)</dd></div>
        {person.change_patterns && <div className="sm:col-span-2"><dt className="eyebrow">Analysed changes</dt><dd>{person.change_patterns.security_sensitive} security-sensitive, {person.change_patterns.dependency_changes} dependency, {person.change_patterns.large_changesets} large, of {person.change_patterns.commits} analysed</dd></div>}
      </dl>
      {person.indicators.length > 0 && (
        <>
          <h3 className="mt-4 text-sm font-semibold">Repository indicators whose evidence names this contributor</h3>
          <ul className="mt-1 space-y-1 text-sm">{person.indicators.map((item) => <li key={item.type}><span className="font-mono text-xs">{item.type}</span> — {item.detail}</li>)}</ul>
        </>
      )}
      {person.sample_commits && <p className="mt-3 font-mono text-xs text-muted">Sample commits: {person.sample_commits.slice(0, 6).map((sha) => sha.slice(0, 10)).join(", ")}</p>}
      <p className="mt-3 text-xs text-muted">{data?.meaning}</p>
    </Panel>
  );
}

export function MaintainersPage() {
  const { id: projectId = "" } = useParams();
  const { data, jobs } = useLayer<MaintainerList>(projectId, JOB_TYPES, () => listMaintainers(projectId));
  const [selected, setSelected] = useState<MaintainerRow | null>(null);
  const list = data.data;
  const profile = list?.profile ?? null;
  const start = <button type="button" className="btn btn-primary" disabled={jobs.busy || jobs.starting} onClick={() => void jobs.run(() => startMaintainerAnalysis(projectId))}>
    <FiUsers aria-hidden /> {list?.analysis ? "Run again" : "Start analysis"}</button>;

  return (
    <ProjectPageShell projectId={projectId}>
      {data.loading && !list ? <Spinner label="Loading maintainer intelligence" /> : data.error && !list ? <ErrorNotice message={data.error} onRetry={() => void data.reload()} /> : list && (
        <div className="space-y-6">
          <JobPanel title="Maintainer behaviour analysis" jobs={jobs} actions={start} testId="maintainer-job"
            idle="Reads public metadata from GitHub (commits, contributors, releases) and describes how the repository is maintained. It reports behavioural indicators, never a judgement about a person."
            failureNote="The analysis did not finish. Any profile shown is from an earlier run." />
          <Meaning testId="maintainer-meaning">{list.meaning}</Meaning>
          {!profile ? (
            <NotRun title="Analysis not available">No maintainer behaviour analysis exists for this repository. Until one has run, every indicator is unknown.</NotRun>
          ) : profile.data_status === "UNAVAILABLE" ? (
            <NotRun title="Maintainer data unavailable" testId="maintainer-unavailable">
              GitHub could not be read ({profile.unavailable.map((item) => `${item.source}: ${item.code}`).join(", ")}). Every indicator is unknown; nothing was estimated in its place.
            </NotRun>
          ) : (
            <>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5" data-testid="maintainer-summary">
                <StatTile label="Contributors" value={profile.contributor_count ?? "—"} note={`in ${profile.evidence.commits_observed ?? 0} observed commit(s)${profile.evidence.commits_truncated ? " (newest only)" : ""}`} />
                <StatTile label="Top contributor share" value={percent(profile.contributor_concentration?.top_share)} note={profile.contributor_concentration?.top_contributor?.display_name ?? ""} />
                <StatTile label="Commits per week" value={profile.commit_frequency?.per_week_mean ?? "—"} note={`last commit ${profile.commit_frequency?.days_since_last ?? "?"} day(s) ago`} />
                <StatTile label="Attention score" value={<Score value={profile.attention_score} />} note={`${words(profile.attention_level)} · how much of the pattern deserves a look`} />
                <StatTile label="Confidence" value={<Confidence value={profile.confidence} />} note={profile.data_status === "PARTIAL" ? "some GitHub data was unavailable" : "share of indicators that could be evaluated"} />
              </div>

              <Panel title="Activity timeline" testId="activity-timeline">
                {profile.weekly_activity.length > 0 ? <ActivityChart weeks={profile.weekly_activity} /> : <p className="text-sm text-muted">No dated commit was observed.</p>}
                <p className="mt-2 text-xs text-muted">
                  {profile.release_frequency?.total ?? 0} release(s) published on GitHub
                  {profile.release_frequency?.median_interval_days != null ? `, median interval ${profile.release_frequency.median_interval_days} days` : ""}.
                  Source: {profile.evidence.sources.join("; ")}.
                </p>
              </Panel>

              <Panel title="Behavioural indicators" testId="indicators">
                <ul>{profile.anomaly_indicators.map((indicator) => <Indicator key={indicator.type} indicator={indicator} />)}</ul>
              </Panel>

              <Panel title="Contributors" testId="contributors">
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead className="eyebrow border-b border-line"><tr><th className="py-2 pr-3">Contributor</th><th className="pr-3">Commits</th><th className="pr-3">Share</th><th className="pr-3">First seen</th><th className="pr-3">Last seen</th><th>Named by indicators</th></tr></thead>
                    <tbody>
                      {list.items.map((row) => (
                        <tr key={row.maintainer_id} className="border-b border-line/60" data-testid="contributor-row" data-name={row.display_name}>
                          <td className="py-2 pr-3"><button type="button" className="font-medium hover:underline" onClick={() => setSelected(row)}>{row.display_name}</button></td>
                          <td className="pr-3 font-mono tabular-nums">{row.commits}</td>
                          <td className="pr-3 font-mono tabular-nums">{percent(row.share)}</td>
                          <td className="pr-3">{formatDate(row.first_commit_at)}</td>
                          <td className="pr-3">{formatDate(row.last_commit_at)}</td>
                          <td className="font-mono text-xs text-muted">{row.indicators.map((item) => item.type).join(", ") || "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Panel>
              {selected && <ContributorDetail projectId={projectId} row={selected} onClose={() => setSelected(null)} />}
            </>
          )}
        </div>
      )}
    </ProjectPageShell>
  );
}
