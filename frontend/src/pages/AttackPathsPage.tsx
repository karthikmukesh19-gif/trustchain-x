import { useEffect, useMemo, useState } from "react";
import { FiCrosshair, FiX } from "react-icons/fi";
import { Link, useParams } from "react-router-dom";

import { JobPanel } from "../components/analysis/JobPanel";
import { NotAnalysed, ProjectPageShell } from "../components/analysis/ProjectPageShell";
import { ErrorNotice, Spinner } from "../components/Feedback";
import { BasisTag, Confidence, LevelBadge, Meaning, NotRun, Panel, Score, shortNode, useLayer, words } from "../components/platform/common";
import { StatTile } from "../components/StatTile";
import { Badge, SeverityBadge } from "../components/StatusBadge";
import { AttackGraph } from "../graph/AttackGraph";
import { useAsync } from "../hooks/useAsync";
import { getAttackGraph, getAttackPath, listAttackPaths, startAttackPathAnalysis } from "../services/platform";
import { errorMessage } from "../utils/errors";
import { shortSha } from "../utils/format";
import type { AttackGraphData, AttackPathDetail, AttackPathList, AttackPathRow, AttackPathStatus } from "../utils/platformTypes";
import type { JobType } from "../utils/types";

const JOB_TYPES: JobType[] = ["attack_path_analysis"];
const STATUS_VIEW: Record<AttackPathStatus, { label: string; tone: "good" | "warn" | "bad" | "neutral" }> = {
  SUPPORTED_PATH: { label: "Supported path", tone: "bad" },
  POTENTIAL_PATH: { label: "Potential path", tone: "warn" },
  UNKNOWN_PATH: { label: "Unknown path", tone: "neutral" },
  OBSERVED_COMPONENT: { label: "Observed component", tone: "neutral" },
};

export function StatusTag({ status, title }: { status: AttackPathStatus; title?: string }) {
  const view = STATUS_VIEW[status] ?? { label: status, tone: "neutral" as const };
  return <span title={title}><Badge tone={view.tone}>{view.label}</Badge></span>;
}

function PathDetail({ projectId, row, onClose }: { projectId: string; row: AttackPathRow; onClose: () => void }) {
  const { data: detail, error, loading } = useAsync<AttackPathDetail>(() => getAttackPath(projectId, row.attack_path_id), [projectId, row.attack_path_id]);
  const parts = row.components;
  return (
    <Panel title={`Path to ${row.target.package_name} ${row.target.version ?? ""}`} testId="attack-path-detail"
      aside={<button type="button" className="btn btn-secondary" onClick={onClose}><FiX aria-hidden /> Close</button>}>
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <StatusTag status={row.status} /> <LevelBadge level={row.level} />
        <span className="text-muted">score</span> <Score value={row.score} /> <span className="text-muted">confidence</span> <Confidence value={row.confidence} />
        <span className="font-mono text-xs text-muted">exploit confirmed: no</span>
      </div>
      <p className="mt-2 text-sm text-ink-soft">{row.status_meaning}</p>

      <div className="mt-4 grid gap-2 text-sm sm:grid-cols-2 lg:grid-cols-5" data-testid="path-stages">
        <div><div className="eyebrow">Source</div>Project dependency declaration</div>
        <div><div className="eyebrow">Dependency</div>{(row.route ?? [row.target.node_id]).map(shortNode).join(" → ")}</div>
        <div><div className="eyebrow">Vulnerability</div>{row.advisory.source_id} <SeverityBadge severity={row.advisory.severity} /></div>
        <div><div className="eyebrow">Reachable component</div>{row.reachability.source_file ? `${row.reachability.source_file}:${row.reachability.line ?? "?"}` : `not established (${words(row.reachability.state)})`}</div>
        <div><div className="eyebrow">Downstream impact</div>{row.downstream.dependents} dependent package(s)</div>
      </div>

      <div className="mt-4 rounded-md bg-paper px-3 py-2 font-mono text-[12px]" data-testid="path-score">
        {parts.vulnerability_signal} (severity {parts.severity}) × {parts.reachability_signal} (reachability {words(parts.reachability_state)}) × {parts.graph_impact} (graph impact) × {parts.confidence} (confidence) = {row.score.toFixed(1)}
      </div>

      {loading && <Spinner label="Loading path" />}
      {error && <div className="mt-3"><ErrorNotice message={error} /></div>}
      {detail && (
        <>
          <div className="mt-4"><AttackGraph nodes={detail.nodes} edges={detail.edges} viewKey={detail.attack_path_id} height={260} /></div>
          <h3 className="mt-5 text-sm font-semibold">Explanation</h3>
          <ul className="mt-2 space-y-1.5 text-sm" data-testid="path-explanation">
            {detail.explanation.map((line, index) => <li key={index} className="flex items-start gap-2"><BasisTag basis={line.basis} /> <span>{line.text}</span></li>)}
          </ul>
          <h3 className="mt-5 text-sm font-semibold">Evidence</h3>
          <ul className="mt-2 space-y-1 text-[13px]" data-testid="path-evidence">
            {detail.evidence.map((item, index) => (
              <li key={index} className="flex flex-wrap items-center gap-2">
                <BasisTag basis={item.basis} /> <span className="font-mono text-xs text-muted">{words(item.stage)}</span>
                <span>{words(item.type)}{typeof item.source_file === "string" ? ` · ${item.source_file}${item.line ? `:${String(item.line)}` : ""}` : ""}
                  {typeof item.metric === "string" ? ` · ${item.metric} = ${String(item.value)}` : ""}</span>
              </li>
            ))}
          </ul>
          <h3 className="mt-5 text-sm font-semibold">What would remove this path</h3>
          <ul className="mt-2 space-y-1.5 text-sm">
            {detail.break_points.map((point, index) => <li key={index} className="flex items-start gap-2"><BasisTag basis="RECOMMENDED" /> <span>{point.detail}</span></li>)}
          </ul>
          {row.alternative_routes.length > 0 && (
            <p className="mt-4 text-[13px] text-muted">Other dependency chains to this package: {row.alternative_routes.map((route) => route.map(shortNode).join(" → ")).join("; ")}{row.routes_truncated ? " (more exist)" : ""}.</p>
          )}
        </>
      )}
    </Panel>
  );
}

export function AttackPathsPage() {
  const { id: projectId = "" } = useParams();
  const [status, setStatus] = useState("");
  const { data, jobs } = useLayer<AttackPathList>(projectId, JOB_TYPES, () => listAttackPaths(projectId));
  const [graph, setGraph] = useState<AttackGraphData | null>(null);
  const [graphError, setGraphError] = useState<string | null>(null);
  const [selected, setSelected] = useState<AttackPathRow | null>(null);
  const [whatIf, setWhatIf] = useState("");
  const list = data.data;
  const analysisId = list?.analysis?.id ?? null;

  useEffect(() => {
    setSelected(null);
    if (!analysisId) { setGraph(null); return; }
    let cancelled = false;
    getAttackGraph(projectId, whatIf || undefined)
      .then((result) => { if (!cancelled) { setGraph(result); setGraphError(null); } })
      .catch((caught) => { if (!cancelled) setGraphError(errorMessage(caught)); });
    return () => { cancelled = true; };
  }, [projectId, analysisId, whatIf]);

  const rows = useMemo(() => (list?.items ?? []).filter((row) => !status || row.status === status), [list, status]);
  const highlight = useMemo(() => {
    if (!selected || !graph) return null;
    const route = selected.route ?? [selected.target.node_id];
    const target = selected.target.node_id;
    return new Set(["entry:project", ...route.map((node) => `dep:${node}`), ...graph.nodes.filter((node) => node.id.includes(`:${target}`)).map((node) => node.id)]);
  }, [selected, graph]);

  const summary = list?.analysis?.summary;
  const start = <button type="button" className="btn btn-primary" disabled={jobs.busy || jobs.starting || !list?.has_vulnerability_scan}
    onClick={() => void jobs.run(() => startAttackPathAnalysis(projectId))}><FiCrosshair aria-hidden /> {list?.analysis ? "Run again" : "Start simulation"}</button>;

  return (
    <ProjectPageShell projectId={projectId}>
      {data.loading && !list ? <Spinner label="Loading attack paths" /> : data.error && !list ? <ErrorNotice message={data.error} onRetry={() => void data.reload()} />
        : !list?.snapshot ? <NotAnalysed projectId={projectId} /> : (
          <div className="space-y-6">
            <JobPanel title="Attack-path simulation" jobs={jobs} actions={start} testId="attack-path-job"
              idle="Builds possible attack paths from what is already stored: the dependency graph, advisory matches and reachability findings. It is a static reading of evidence. No exploit is attempted and no repository code is run."
              failureNote="The simulation did not finish. Any paths shown are from an earlier run." />
            {!list.has_vulnerability_scan && (
              <p className="text-sm text-muted" data-testid="needs-scan">
                Attack paths start from matched advisories. <Link className="font-medium text-trust hover:underline" to={`/projects/${projectId}/vulnerabilities`}>Run a vulnerability check</Link> for this snapshot first.
              </p>
            )}
            {!list.analysis || !summary ? (
              <NotRun title="Analysis not available">No attack-path simulation exists for commit {shortSha(list.snapshot.commit_sha)}. Until one has run there are no paths to show, which is not the same as there being none.</NotRun>
            ) : (
              <>
                <Meaning testId="attack-meaning">{list.meaning}</Meaning>
                <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5" data-testid="attack-summary">
                  <StatTile label="Paths" value={summary.paths} note={`${summary.vulnerable_packages} affected package(s)`} />
                  <StatTile label="Supported" value={summary.by_status.SUPPORTED_PATH} note="evidence at every step" />
                  <StatTile label="Potential" value={summary.by_status.POTENTIAL_PATH} note="no code reaching it was found" />
                  <StatTile label="Unknown" value={summary.by_status.UNKNOWN_PATH} note={summary.reachability_analysed ? "reachability undecided" : "reachability not analysed"} />
                  <StatTile label="Highest score" value={<Score value={summary.highest_score} />} note="0–100, orders paths for review" />
                </div>

                <Panel title="Attack-path graph" testId="attack-graph-panel"
                  aside={graph && <span className="text-xs text-muted">{graph.paths_included} of {graph.paths_total} path(s) drawn{graph.truncated ? "; the rest exceed the display limit" : ""}</span>}>
                  {graphError && <ErrorNotice message={graphError} />}
                  {graph && graph.nodes.length > 0 && <AttackGraph nodes={graph.nodes} edges={graph.edges} highlight={highlight} viewKey={`${analysisId}-${graph.nodes.length}`} />}
                  {graph && graph.nodes.length === 0 && <p className="text-sm text-muted">The simulation found no attack path, so there is nothing to draw.</p>}
                  <p className="mt-2 text-xs text-muted">Solid lines are observed or derived steps; dashed lines are inferred. Columns run from the project on the left to potential impact on the right.</p>
                  {graph && graph.choke_points.length > 0 && (
                    <div className="mt-4" data-testid="what-if">
                      <label className="text-sm font-medium" htmlFor="what-if-select">What if a package were fixed?</label>
                      <select id="what-if-select" className="ml-2 rounded-md border border-line bg-surface px-2 py-1 text-sm" value={whatIf} onChange={(event) => setWhatIf(event.target.value)}>
                        <option value="">Choose a package</option>
                        {graph.choke_points.map((point) => <option key={point.node_id} value={point.node_id}>{shortNode(point.node_id)} — on {point.paths} path(s)</option>)}
                      </select>
                      {graph.what_if && (
                        <p className="mt-2 text-sm" data-testid="what-if-result">
                          <BasisTag basis="DERIVED" /> Without {shortNode(graph.what_if.node_id)}: {graph.what_if.paths_removed} of {graph.what_if.paths_before} path(s) would no longer exist
                          {graph.what_if.paths_undetermined ? `, ${graph.what_if.paths_undetermined} cannot be determined` : ""}; highest score {graph.what_if.highest_score_after ?? "—"}.
                          <span className="text-muted"> {graph.what_if.note}</span>
                        </p>
                      )}
                    </div>
                  )}
                </Panel>

                <Panel title="Paths" testId="attack-path-table"
                  aside={(
                    <select aria-label="Filter by status" className="rounded-md border border-line bg-surface px-2 py-1 text-sm" value={status} onChange={(event) => setStatus(event.target.value)}>
                      <option value="">All statuses</option>
                      {list.statuses.map((value) => <option key={value} value={value}>{STATUS_VIEW[value].label}</option>)}
                    </select>
                  )}>
                  {rows.length === 0 ? <p className="text-sm text-muted">{list.items.length === 0 ? "The simulation found no attack path." : "No path has this status."}</p> : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-sm">
                        <thead className="eyebrow border-b border-line"><tr><th className="py-2 pr-3">#</th><th className="pr-3">Package</th><th className="pr-3">Vulnerability</th><th className="pr-3">Status</th><th className="pr-3">Score</th><th className="pr-3">Confidence</th><th>Dependency chain</th></tr></thead>
                        <tbody>
                          {rows.map((row) => (
                            <tr key={row.attack_path_id} data-testid="attack-path-row" data-status={row.status}
                              className={`cursor-pointer border-b border-line/60 hover:bg-paper ${selected?.attack_path_id === row.attack_path_id ? "bg-paper" : ""}`}
                              onClick={() => setSelected(row)}>
                              <td className="py-2 pr-3 font-mono text-xs text-muted">{row.rank}</td>
                              <td className="pr-3 font-mono text-[13px] font-semibold">
                                <button type="button" className="text-left hover:underline" onClick={() => setSelected(row)}>{row.target.package_name} <span className="font-normal text-muted">{row.target.version ?? "unresolved"}</span></button>
                              </td>
                              <td className="pr-3">{row.advisory.source_id} <SeverityBadge severity={row.advisory.severity} /></td>
                              <td className="pr-3"><StatusTag status={row.status} title={list.status_meaning[row.status]} /></td>
                              <td className="pr-3"><Score value={row.score} /></td>
                              <td className="pr-3"><Confidence value={row.confidence} /></td>
                              <td className="font-mono text-xs text-muted">{row.route ? row.route.map(shortNode).join(" → ") : "no recorded chain"}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </Panel>
                {selected && <PathDetail projectId={projectId} row={selected} onClose={() => setSelected(null)} />}
              </>
            )}
          </div>
        )}
    </ProjectPageShell>
  );
}
