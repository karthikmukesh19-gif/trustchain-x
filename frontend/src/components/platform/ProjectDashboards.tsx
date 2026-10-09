import { useState } from "react";
import { Link } from "react-router-dom";

import { CommitTimelineChart, ContributionChart, CountChart, DistributionChart, TrustTrendChart } from "../../charts/PlatformCharts";
import { TrustHeadline } from "../../pages/TrustPage";
import { useAsync } from "../../hooks/useAsync";
import { getEvaluation, getOverview } from "../../services/platform";
import { formatDateTime, shortSha } from "../../utils/format";
import type { Overview } from "../../utils/platformTypes";
import { ErrorNotice, Spinner } from "../Feedback";
import { StatTile } from "../StatTile";
import { Badge } from "../StatusBadge";
import { BasisTag, Confidence, LevelBadge, Panel, Score, percent, shortNode, words } from "./common";

type View = "executive" | "technical" | "research";
const VIEWS: { id: View; label: string; note: string }[] = [
  { id: "executive", label: "Executive", note: "The result, what drives it and what to do" },
  { id: "technical", label: "Technical", note: "Every layer's figures" },
  { id: "research", label: "Research", note: "Models, confidence and what has been measured" },
];
const LAYER_TONE = { ANALYSED: "good", NOT_ANALYSED: "neutral", STALE: "warn", UNAVAILABLE: "warn" } as const;
const number = (value: number | null | undefined) => (value === null || value === undefined ? "—" : value);

/** Shown in place of a chart when its layer has no result: an empty chart would look like a clean one. */
function NoData({ layer, projectId, route }: { layer: string; projectId: string; route: string }) {
  return (
    <p className="rounded-md border border-dashed border-line px-3 py-6 text-center text-sm text-muted" data-testid="chart-not-available">
      {layer} has not been analysed. <Link className="font-medium text-trust hover:underline" to={`/projects/${projectId}/${route}`}>Open it</Link>
    </p>
  );
}

function Layers({ overview }: { overview: Overview }) {
  return (
    <div className="flex flex-wrap gap-2" data-testid="layer-status">
      {overview.layers.map((layer) => (
        <span key={layer.name} className="inline-flex items-center gap-1.5 text-xs" data-layer={layer.name} data-status={layer.status}
          title={layer.as_of ? `As of ${formatDateTime(layer.as_of)}` : undefined}>
          {layer.label} <Badge tone={LAYER_TONE[layer.status]}>{words(layer.status)}</Badge>
        </span>
      ))}
    </div>
  );
}

function Executive({ overview, projectId }: { overview: Overview; projectId: string }) {
  const { executive, trust } = overview;
  const numbers = executive.numbers;
  return (
    <div className="space-y-6" data-testid="executive-dashboard">
      {trust.current ? <TrustHeadline trust={trust.current} /> : (
        <div className="card border-dashed px-6 py-6 text-center" data-testid="no-trust-score">
          <div className="text-base font-semibold">No trust score yet</div>
          <p className="mt-1 text-sm text-muted">{executive.headline} <Link className="font-medium text-trust hover:underline" to={`/projects/${projectId}/trust`}>Open the trust page</Link></p>
        </div>
      )}
      <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-6" data-testid="executive-numbers">
        <StatTile label="Dependencies" value={number(numbers.dependencies)} />
        <StatTile label="Known vulnerabilities" value={number(numbers.vulnerabilities)} note={numbers.vulnerabilities === null ? "not checked" : undefined} />
        <StatTile label="Reached by code" value={number(numbers.reachable)} note={numbers.reachable === null ? "not analysed" : undefined} />
        <StatTile label="Attack paths" value={number(numbers.attack_paths)} note={numbers.attack_paths === null ? "not simulated" : undefined} />
        <StatTile label="Events to review" value={number(numbers.security_events)} note={numbers.security_events === null ? "not analysed" : undefined} />
        <StatTile label="AI findings" value={number(numbers.ai_findings)} note={numbers.ai_findings === null ? "not run" : undefined} />
      </div>
      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Trust and risk trend" testId="executive-trend">
          {trust.trend.length > 1 ? <TrustTrendChart points={trust.trend} /> : <p className="text-sm text-muted">{trust.trend.length === 1 ? "One result so far; a trend needs at least two." : "No trust analysis has been run."}</p>}
        </Panel>
        <Panel title="What drives the risk" testId="executive-contribution">
          {trust.current && trust.current.components.some((component) => component.status === "KNOWN") ? <ContributionChart components={trust.current.components} />
            : <p className="text-sm text-muted">No component has been scored.</p>}
          {trust.current && trust.current.unknown_components.length > 0 && <p className="mt-2 text-xs text-warn">Unknown, so not drawn: {trust.current.unknown_components.map(words).join(", ")}.</p>}
        </Panel>
        <Panel title="Top findings" testId="executive-findings">
          {executive.findings.length === 0 ? <p className="text-sm text-muted">No cross-layer finding. {numbers.ai_findings === null ? "The reasoning has not been run." : ""}</p> : (
            <ul className="space-y-2 text-sm">{executive.findings.map((finding) => (
              <li key={finding.finding_id}><LevelBadge level={finding.severity} /> <span className="font-mono text-xs font-semibold">{finding.category}</span>
                <div className="text-[13px] text-ink-soft">{finding.explanation.replace(/\s*\[E\d+\]/g, "")}</div></li>
            ))}</ul>
          )}
          <Link className="mt-2 inline-block text-sm font-medium text-trust hover:underline" to={`/projects/${projectId}/ai-analysis`}>All findings with their evidence</Link>
        </Panel>
        <Panel title="Recommended next steps" testId="executive-recommendations">
          {executive.recommendations.length === 0 ? <p className="text-sm text-muted">{overview.missing.length ? "Run the analyses listed as not analysed above." : "No recommendation follows from the current result."}</p> : (
            <ol className="space-y-2 text-sm">{executive.recommendations.map((item) => <li key={item.priority} className="flex items-start gap-2"><BasisTag basis="RECOMMENDED" /> <span>{item.text}</span></li>)}</ol>
          )}
          <Link className="mt-2 inline-block text-sm font-medium text-trust hover:underline" to={`/projects/${projectId}/report`}>Full report</Link>
        </Panel>
      </div>
    </div>
  );
}

function Technical({ overview, projectId }: { overview: Overview; projectId: string }) {
  const t = overview.technical;
  return (
    <div className="grid gap-6 lg:grid-cols-2" data-testid="technical-dashboard">
      <Panel title="Vulnerability distribution" testId="chart-vulnerabilities">
        {t.vulnerabilities ? <><CountChart counts={t.vulnerabilities.by_severity} label="Advisory matches by severity" testId="vulnerability-chart" />
          <p className="mt-1 text-xs text-muted">{t.vulnerabilities.distinct} distinct vulnerabilit(ies) in {t.vulnerabilities.affected_dependencies} package(s). Severity is the source's; “unknown” means it publishes none.</p></>
          : <NoData layer="Vulnerability intelligence" projectId={projectId} route="vulnerabilities" />}
      </Panel>
      <Panel title="Dependency risk distribution" testId="chart-dependency-risk">
        {t.predictive ? <><DistributionChart buckets={t.predictive.distribution} label="Dependencies by predictive risk score" testId="dependency-risk-chart" />
          <p className="mt-1 text-xs text-muted">Predictive dependency risk (0–100) of {t.predictive.summary.dependencies} dependencies; {t.predictive.summary.indicator_total} indicator(s) raised.</p></>
          : <NoData layer="Predictive dependency risk" projectId={projectId} route="fragility" />}
      </Panel>
      <Panel title="Fragility distribution" testId="chart-fragility">
        {t.fragility ? <><DistributionChart buckets={t.fragility.distribution} label="Dependencies by fragility score" testId="fragility-chart" />
          <p className="mt-1 text-xs text-muted">Mean {number(t.fragility.summary.mean)}, highest {number(t.fragility.summary.highest)} (of 100).</p></>
          : <NoData layer="Dependency fragility" projectId={projectId} route="fragility" />}
      </Panel>
      <Panel title="Attack-path severity" testId="chart-attack-paths">
        {t.attack_paths ? <><DistributionChart buckets={t.attack_paths.distribution} label="Attack paths by score" testId="attack-path-chart" />
          <p className="mt-1 text-xs text-muted">{t.attack_paths.summary.paths} path(s): {Object.entries(t.attack_paths.summary.by_status).filter(([, count]) => count).map(([status, count]) => `${count} ${words(status)}`).join(", ") || "none"}. <Link className="text-trust hover:underline" to={`/projects/${projectId}/attack-paths`}>Attack-path graph</Link></p></>
          : <NoData layer="Attack paths" projectId={projectId} route="attack-paths" />}
      </Panel>
      <Panel title="Behaviour timeline" testId="chart-behaviour">
        {t.commits && t.commits.timeline.length > 0 ? <><CommitTimelineChart commits={t.commits.timeline} />
          <p className="mt-1 text-xs text-muted">{t.commits.analysed_total} commit(s) analysed; {t.commits.security_events} event(s) listed for review.</p></>
          : <NoData layer="Commit behaviour" projectId={projectId} route="commits" />}
      </Panel>
      <Panel title="Code reachability" testId="chart-reachability">
        {t.reachability ? (t.reachability.findings ? <CountChart counts={t.reachability.by_status} label="Vulnerability findings by reachability status" testId="reachability-chart"
          colours={{ REACHABLE: "#b3261e", UNKNOWN: "#a35a00", UNSUPPORTED: "#8d93a0", NOT_CONFIRMED_REACHABLE: "#0f766e" }} /> : <p className="text-sm text-muted">No vulnerability finding had to be evaluated.</p>)
          : <NoData layer="Code reachability" projectId={projectId} route="reachability" />}
      </Panel>
      <Panel title="Dependencies and SBOM" testId="panel-inventory">
        {t.inventory ? (
          <dl className="grid grid-cols-2 gap-2 text-sm">
            <div><dt className="eyebrow">Packages</dt><dd className="font-mono">{t.inventory.total} ({number(t.inventory.direct)} direct, {number(t.inventory.transitive)} transitive)</dd></div>
            <div><dt className="eyebrow">Unresolved versions</dt><dd className="font-mono">{number(t.inventory.unresolved_versions)}</dd></div>
            <div><dt className="eyebrow">Deepest chain</dt><dd className="font-mono">{number(t.inventory.max_depth)}</dd></div>
            <div><dt className="eyebrow">SBOM</dt><dd>{t.sbom ? `version ${t.sbom.version}, ${t.sbom.component_count} components, ${t.sbom.verified === null ? "not verified" : t.sbom.verified ? "verified" : "verification FAILED"}` : "not generated"}</dd></div>
          </dl>
        ) : <NoData layer="The dependency inventory" projectId={projectId} route="" />}
        <Link className="mt-2 inline-block text-sm font-medium text-trust hover:underline" to={`/projects/${projectId}/graph`}>Dependency graph</Link>
      </Panel>
      <Panel title="Maintainers, dataset and AI findings" testId="panel-other">
        <dl className="space-y-2 text-sm">
          <div><dt className="eyebrow">Maintainer behaviour</dt><dd>{t.maintainers ? <>attention <Score value={t.maintainers.attention_score} /> · confidence <Confidence value={t.maintainers.confidence} /> · {t.maintainers.indicators.filter((item) => item.status === "OBSERVED").length} indicator(s) observed</> : "not analysed"}</dd></div>
          <div><dt className="eyebrow">Dataset quality</dt><dd>{t.dataset ? <>version {t.dataset.version} · {words(t.dataset.quality_status)} · score <Score value={t.dataset.quality_score} /></> : "not built"}</dd></div>
          <div><dt className="eyebrow">AI findings</dt><dd>{t.ai ? `${t.ai.summary.findings} finding(s); evidence grounding ${percent(t.ai.summary.grounding.evidence_grounding)}` : "not run"}</dd></div>
        </dl>
        {overview.executive.attack_paths.length > 0 && <p className="mt-2 text-xs text-muted">Highest attack path: {shortNode(overview.executive.attack_paths[0].target.package_name)} via {overview.executive.attack_paths[0].advisory.source_id}, score {overview.executive.attack_paths[0].score}.</p>}
      </Panel>
    </div>
  );
}

function Research({ overview }: { overview: Overview }) {
  const { research } = overview;
  const evaluation = useAsync(getEvaluation, []);
  const measured = research.measured;
  return (
    <div className="space-y-6" data-testid="research-dashboard">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5" data-testid="research-measured">
        <StatTile label="Layer coverage" value={percent(measured.layer_coverage)} note="analysis layers with results (measured)" />
        <StatTile label="Trust weight coverage" value={percent(measured.trust_weight_coverage)} note="of the trust model's weight" />
        <StatTile label="Evidence grounding" value={percent(measured.evidence_grounding)} note="AI statements citing stored evidence" />
        <StatTile label="Unsupported-claim rate" value={percent(measured.unsupported_claim_rate)} note="measured on the latest reasoning run" />
        <StatTile label="Dataset quality" value={<Score value={measured.dataset_quality_score} />} note="latest validation" />
      </div>
      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Models in use" testId="research-models">
          {Object.keys(research.model_versions).length === 0 ? <p className="text-sm text-muted">No model has produced a result for this project.</p>
            : <ul className="space-y-1 font-mono text-xs">{Object.entries(research.model_versions).map(([layer, version]) => <li key={layer}>{words(layer)}: {version}</li>)}</ul>}
          <p className="mt-3 text-sm font-medium" data-testid="research-weights-statement">{research.weights_statement}</p>
        </Panel>
        <Panel title="Evidence confidence by component" testId="research-confidence">
          {research.component_confidence.length === 0 ? <p className="text-sm text-muted">No trust analysis has been run.</p> : (
            <table className="w-full text-left text-sm">
              <thead className="eyebrow border-b border-line"><tr><th className="py-1.5 pr-3">Component</th><th className="pr-3">Status</th><th className="pr-3">Confidence</th><th>Basis</th></tr></thead>
              <tbody>{research.component_confidence.map((row) => (
                <tr key={row.name} className="border-b border-line/60"><td className="py-1.5 pr-3">{row.label}</td><td className="pr-3">{words(row.status)}</td>
                  <td className="pr-3">{row.status === "KNOWN" ? <Confidence value={row.confidence} /> : "—"}</td><td><BasisTag basis={row.basis} /></td></tr>
              ))}</tbody>
            </table>
          )}
        </Panel>
        <Panel title="Execution time" testId="research-timings">
          {measured.execution_seconds.length === 0 ? <p className="text-sm text-muted">No job has finished for this project.</p> : (
            <ul className="space-y-0.5 font-mono text-xs">{measured.execution_seconds.map((row) => <li key={row.job_type}>{words(row.job_type)}: {row.seconds}s ({row.state})</li>)}</ul>
          )}
          <p className="mt-2 text-xs text-muted">Duration of the latest job of each type on this installation. A measurement, not a benchmark.</p>
        </Panel>
        <Panel title="Evaluation measures" testId="research-evaluation">
          <p className="text-sm text-ink-soft">{research.not_measured_note}</p>
          {evaluation.loading && <Spinner label="Loading measures" />}
          {evaluation.error && <ErrorNotice message={evaluation.error} />}
          {evaluation.data && (
            <div className="mt-2 max-h-72 overflow-y-auto">
              <table className="w-full text-left text-[13px]">
                <thead className="eyebrow border-b border-line"><tr><th className="py-1.5 pr-3">Component</th><th className="pr-3">Measure</th><th>Result</th></tr></thead>
                <tbody>{evaluation.data.items.map((row) => (
                  <tr key={`${row.component}.${row.measure}`} className="border-b border-line/60" data-testid="evaluation-row" data-status={row.status} title={`Would be measured against: ${row.needs}`}>
                    <td className="py-1 pr-3">{words(row.component)}</td><td className="pr-3">{words(row.measure)}</td>
                    <td className="font-mono text-xs">{row.status === "EVALUATED" ? `${row.value} (${row.benchmark})` : row.display}</td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}

/** The three dashboards of one project. All three read the same overview, so they cannot disagree. */
export function ProjectDashboards({ projectId }: { projectId: string }) {
  const [view, setView] = useState<View>("executive");
  const { data: overview, error, loading, reload } = useAsync(() => getOverview(projectId), [projectId]);
  if (loading && !overview) return <Spinner label="Loading dashboard" />;
  if (error && !overview) return <ErrorNotice message={error} onRetry={() => void reload()} />;
  if (!overview) return null;
  return (
    <div className="space-y-5" data-testid="project-dashboards">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div role="tablist" aria-label="Dashboard view" className="flex gap-1 rounded-md border border-line bg-surface p-1">
          {VIEWS.map((item) => (
            <button key={item.id} type="button" role="tab" aria-selected={view === item.id} title={item.note} onClick={() => setView(item.id)}
              className={`rounded px-3 py-1.5 text-sm font-medium ${view === item.id ? "bg-ink text-white" : "text-muted hover:text-ink"}`}>{item.label}</button>
          ))}
        </div>
        <p className="text-xs text-muted">
          {overview.snapshot ? <>Commit <span className="font-mono">{shortSha(overview.snapshot.commit_sha)}</span> · </> : "Not analysed · "}
          <Link className="font-medium text-trust hover:underline" to={`/projects/${projectId}`}>Open project</Link>
        </p>
      </div>
      <Layers overview={overview} />
      {view === "executive" && <Executive overview={overview} projectId={projectId} />}
      {view === "technical" && <Technical overview={overview} projectId={projectId} />}
      {view === "research" && <Research overview={overview} />}
    </div>
  );
}
