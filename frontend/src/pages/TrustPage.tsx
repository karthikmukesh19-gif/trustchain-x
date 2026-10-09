import { FiShield } from "react-icons/fi";
import { Link, useParams } from "react-router-dom";

import { ContributionChart, TrustTrendChart } from "../charts/PlatformCharts";
import { JobPanel } from "../components/analysis/JobPanel";
import { NotAnalysed, ProjectPageShell } from "../components/analysis/ProjectPageShell";
import { ErrorNotice, Spinner } from "../components/Feedback";
import { BasisTag, Confidence, Meaning, NotRun, Panel, Score, percent, useLayer, words } from "../components/platform/common";
import { Badge } from "../components/StatusBadge";
import { getTrust, getTrustHistory, startTrustAnalysis } from "../services/platform";
import { formatDateTime } from "../utils/format";
import type { TrustCurrent, TrustPoint, TrustResult } from "../utils/platformTypes";
import type { JobType } from "../utils/types";

const JOB_TYPES: JobType[] = ["trust_analysis"];
const LAYER_ROUTE: Record<string, string> = {
  inventory: "dependencies", sbom: "sbom", vulnerabilities: "vulnerabilities", reachability: "reachability", fragility: "fragility", graph_risk: "fragility",
  predictive: "fragility", attack_paths: "attack-paths", maintainers: "maintainers", commits: "commits", dataset: "dataset",
};

/** The headline figures. With insufficient data there is no number at all: the words say why. */
export function TrustHeadline({ trust }: { trust: Pick<TrustResult, "status" | "trust_score" | "risk_score" | "confidence" | "coverage" | "band" | "trust_low" | "trust_high" | "insufficient_reason"> }) {
  if (trust.status !== "SCORED") {
    return (
      <div className="card border-warn/40 bg-warn-soft px-6 py-6" data-testid="insufficient-data">
        <div className="font-mono text-2xl font-semibold tracking-tight text-warn">INSUFFICIENT DATA</div>
        <p className="mt-2 max-w-3xl text-sm text-ink-soft">{trust.insufficient_reason}</p>
        <p className="mt-2 text-sm text-ink-soft">Analysed layers carry {percent(trust.coverage)} of the model's weight. With what is known, trust would lie anywhere between {trust.trust_low} and {trust.trust_high}.</p>
      </div>
    );
  }
  return (
    <div className="grid gap-3 sm:grid-cols-3" data-testid="trust-headline">
      <div className="card px-5 py-4" data-testid="trust-score">
        <div className="eyebrow">Trust score</div>
        <div className="mt-1 font-mono text-4xl font-semibold tabular-nums">{trust.trust_score?.toFixed(1)}<span className="text-lg text-muted"> / 100</span></div>
        <div className="mt-1 text-xs text-muted">{trust.band ? words(trust.band) : ""} · between {trust.trust_low} and {trust.trust_high} depending on what is unknown</div>
      </div>
      <div className="card px-5 py-4" data-testid="risk-score">
        <div className="eyebrow">Risk score</div>
        <div className="mt-1 font-mono text-4xl font-semibold tabular-nums">{trust.risk_score?.toFixed(1)}<span className="text-lg text-muted"> / 100</span></div>
        <div className="mt-1 text-xs text-muted">trust = 100 − risk</div>
      </div>
      <div className="card px-5 py-4" data-testid="trust-confidence">
        <div className="eyebrow">Confidence</div>
        <div className="mt-1 font-mono text-4xl font-semibold tabular-nums">{percent(trust.confidence)}</div>
        <div className="mt-1 text-xs text-muted">{percent(trust.coverage)} of the model's weight rests on analysed layers</div>
      </div>
    </div>
  );
}

export function TrustPage() {
  const { id: projectId = "" } = useParams();
  const { data, jobs } = useLayer<{ current: TrustCurrent; history: TrustPoint[] }>(projectId, JOB_TYPES, async () => {
    const [current, history] = await Promise.all([getTrust(projectId), getTrustHistory(projectId)]);
    return { current, history: [...history.items].reverse() };
  });
  const current = data.data?.current;
  const trust = current?.trust ?? null;
  const explanation = trust?.explanation;
  const start = <button type="button" className="btn btn-primary" disabled={jobs.busy || jobs.starting} onClick={() => void jobs.run(() => startTrustAnalysis(projectId))}>
    <FiShield aria-hidden /> {trust ? "Recalculate" : "Calculate trust"}</button>;

  return (
    <ProjectPageShell projectId={projectId}>
      {data.loading && !current ? <Spinner label="Loading trust" /> : data.error && !current ? <ErrorNotice message={data.error} onRetry={() => void data.reload()} />
        : !current?.snapshot ? <NotAnalysed projectId={projectId} /> : (
          <div className="space-y-6">
            <JobPanel title="Trust analysis" jobs={jobs} actions={start} testId="trust-job"
              idle="Combines what every layer has stored for this snapshot into a risk score and a trust score, with the calculation shown. Layers that have not been analysed are unknown: they are never counted as good."
              failureNote="The trust analysis did not finish. Any score shown is from an earlier run." />
            {!trust || !explanation ? (
              <NotRun title="No trust score yet">No trust analysis exists for this snapshot. There is no score to show, and none is estimated.</NotRun>
            ) : (
              <>
                {current.up_to_date === false && (
                  <p className="rounded-md bg-warn-soft px-3 py-2 text-sm text-warn" role="status" data-testid="trust-outdated">
                    A layer has been analysed or changed since this result was calculated ({formatDateTime(trust.created_at)}). Recalculate to include it.
                  </p>
                )}
                <TrustHeadline trust={trust} />
                <Meaning testId="trust-meaning">{current.meaning} {current.weights_statement}</Meaning>

                <Panel title="Component scores" testId="trust-components">
                  {trust.components.some((component) => component.status === "KNOWN") && <ContributionChart components={trust.components} />}
                  <div className="mt-3 overflow-x-auto">
                    <table className="w-full text-left text-sm">
                      <thead className="eyebrow border-b border-line"><tr><th className="py-2 pr-3">Component</th><th className="pr-3">Weight</th><th className="pr-3">Risk</th><th className="pr-3">Points</th><th className="pr-3">Confidence</th><th className="pr-3">Basis</th><th>How the value was reached</th></tr></thead>
                      <tbody>
                        {trust.components.map((component) => (
                          <tr key={component.name} className="border-b border-line/60 align-top" data-testid="trust-component" data-component={component.name} data-status={component.status}>
                            <td className="py-2 pr-3 font-medium">
                              {component.layer && LAYER_ROUTE[component.layer] ? <Link className="hover:underline" to={`/projects/${projectId}/${LAYER_ROUTE[component.layer]}`}>{component.label}</Link> : component.label}
                            </td>
                            <td className="pr-3 font-mono">{component.weight}%</td>
                            <td className="pr-3">{component.status === "KNOWN" ? <Score value={component.risk} /> : <Badge tone="neutral">Unknown</Badge>}</td>
                            <td className="pr-3 font-mono">{component.contribution ?? "—"}</td>
                            <td className="pr-3">{component.status === "KNOWN" ? <Confidence value={component.confidence} /> : "—"}</td>
                            <td className="pr-3"><BasisTag basis={component.basis} /></td>
                            <td className="text-[13px] text-ink-soft">{component.detail}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Panel>

                <Panel title="How the score was calculated" testId="trust-calculation">
                  <p className="font-mono text-[12px]">{explanation.calculation.formula}</p>
                  {explanation.calculation.worked && <p className="mt-1 font-mono text-[12px]" data-testid="trust-worked">{explanation.calculation.worked}</p>}
                  <p className="mt-2 text-sm text-ink-soft">{explanation.calculation.bounds}</p>
                  <p className="mt-2 text-sm font-medium" data-testid="weights-statement">{explanation.calculation.weights_statement}</p>
                </Panel>

                <div className="grid gap-6 lg:grid-cols-2">
                  <Panel title="Top risks" testId="trust-top-risks">
                    {explanation.top_risks.length === 0 ? <p className="text-sm text-muted">No known component carries risk.</p> : (
                      <ol className="space-y-2 text-sm">{explanation.top_risks.map((risk) => (
                        <li key={risk.name}><span className="font-medium">{risk.label}</span> <span className="font-mono text-xs text-muted">{risk.contribution} points · risk {risk.risk}</span><div className="text-[13px] text-ink-soft">{risk.detail}</div></li>
                      ))}</ol>
                    )}
                  </Panel>
                  <Panel title="Recommendations" testId="trust-recommendations">
                    {explanation.recommendations.length === 0 ? <p className="text-sm text-muted">No recommendation follows from the current result.</p> : (
                      <ol className="space-y-2 text-sm">{explanation.recommendations.map((item) => (
                        <li key={item.priority} className="flex items-start gap-2"><BasisTag basis="RECOMMENDED" /><span>{item.text}<span className="block text-[13px] text-muted">{item.because}</span></span></li>
                      ))}</ol>
                    )}
                  </Panel>
                </div>

                <Panel title="Trend" testId="trust-trend">
                  {data.data && data.data.history.length > 1 ? <TrustTrendChart points={data.data.history} /> : <p className="text-sm text-muted">One result so far. A trend appears once the analysis has been repeated.</p>}
                  <ul className="mt-2 space-y-0.5 font-mono text-xs text-muted" data-testid="trust-history">
                    {(data.data?.history ?? []).map((point, index) => <li key={index}>{formatDateTime(point.created_at)} · {point.status === "SCORED" ? `trust ${point.trust_score} · risk ${point.risk_score}` : "insufficient data"} · coverage {percent(point.coverage)}</li>)}
                  </ul>
                </Panel>

                <Panel title="Evidence" testId="trust-evidence">
                  <ul className="space-y-1 text-[13px]">
                    {(trust.evidence ?? []).map((item) => (
                      <li key={item.layer} data-status={item.status}><span className="font-medium">{item.label}</span>{" "}
                        {item.reference ? <span className="font-mono text-xs text-muted">{item.reference.collection}/{String(item.reference.id).slice(0, 12)} · {formatDateTime(item.as_of)}</span>
                          : <span className="text-warn">{words(item.status)}</span>}</li>
                    ))}
                  </ul>
                </Panel>
              </>
            )}
          </div>
        )}
    </ProjectPageShell>
  );
}
