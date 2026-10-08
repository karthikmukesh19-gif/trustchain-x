import type { ExposureClassification, GraphRiskRow, IntelligenceSummary } from "../../utils/types";
import { CLASSIFICATION, ClassificationBadge, REACHABILITY_STATE_LABEL, nodeLabel, score } from "./labels";

const ORDER: ExposureClassification[] = ["DIRECT_VULNERABILITY", "DEPENDENCY_PROPAGATION", "INDIRECT_EXPOSURE", "NO_OBSERVED_PROPAGATION"];

/** Project level: how many packages fall in each exposure class, and how the project reaches each vulnerable package. */
export function GraphRiskPanel({ risk }: { risk: NonNullable<IntelligenceSummary["graph_risk"]> }) {
  const paths = risk.paths.filter((entry) => entry.path !== null);
  const unreached = risk.paths.length - paths.length;
  return (
    <section className="card p-5" aria-label="Graph risk" data-testid="graph-risk-panel">
      <h3 className="text-base font-semibold">Exposure through the dependency graph</h3>
      <p className="mt-1 max-w-3xl text-sm text-muted">
        Only "Known vulnerability" says an advisory matches a package. The other classes say a vulnerable package lies in what a package
        depends on; whether that matters depends on how it is used.
      </p>
      <dl className="mt-4 grid grid-cols-2 gap-3 lg:grid-cols-4" data-testid="classification-counts">
        {ORDER.map((name) => (
          <div key={name} className="rounded-md border border-line px-3 py-2.5" data-classification={name} title={CLASSIFICATION[name].meaning}>
            <dt className="text-xs text-muted">{CLASSIFICATION[name].label}</dt>
            <dd className="mt-0.5 font-mono text-xl font-semibold tabular-nums">{risk.by_classification[name] ?? 0}</dd>
          </div>
        ))}
      </dl>

      <h4 className="mt-5 text-sm font-semibold">Paths from the project to vulnerable packages</h4>
      {risk.paths.length === 0 ? (
        <p className="mt-1 text-sm text-muted" data-testid="no-risk-paths">The vulnerability check matched no advisory, so there is no exposure to trace.</p>
      ) : (
        <>
          <ol className="mt-2 space-y-1.5" data-testid="risk-paths">
            {paths.slice(0, 12).map((entry) => (
              <li key={entry.node_id} className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 text-xs" data-testid="risk-path">
                <span className="break-all font-mono text-ink-soft">{(entry.path ?? []).map((step) => (step === "…" ? step : nodeLabel(step))).join("  →  ")}</span>
                <span className="text-muted">own risk {score(entry.own_risk)}</span>
              </li>
            ))}
          </ol>
          {(paths.length > 12 || risk.paths_truncated) && <p className="mt-1.5 text-xs text-muted">Only the first paths are listed; the table has every package.</p>}
          {paths.slice(0, 12).some((entry) => entry.path_truncated) && <p className="mt-1.5 text-xs text-muted">"…" marks packages left out of the middle of a long path.</p>}
          {unreached > 0 && <p className="mt-1.5 text-xs text-muted">{unreached} vulnerable package(s) have no established path from the project.</p>}
          <p className="mt-2 text-xs text-muted">One shortest chain of declared dependencies is shown per package. A path here is a dependency relationship, not a code path.</p>
        </>
      )}
    </section>
  );
}

/** One package: its class and the visible components of its graph risk. */
export function DependencyGraphRisk({ risk }: { risk: GraphRiskRow }) {
  const components = risk.components;
  const vulnerable = risk.classification === "DIRECT_VULNERABILITY";
  return (
    <section className="rounded-md border border-line bg-surface p-4" aria-label="Graph risk" data-testid="dependency-graph-risk">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h4 className="text-sm font-semibold">Graph risk</h4>
        <span className="font-mono text-[11px] text-faint">{risk.model_version}</span>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-3">
        <span className="font-mono text-2xl font-semibold tabular-nums">{score(risk.graph_risk)}</span>
        <span className="text-xs text-muted">of 100</span>
        <ClassificationBadge classification={risk.classification} />
      </div>
      <p className="mt-1.5 text-xs text-muted">{CLASSIFICATION[risk.classification]?.meaning}</p>

      <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1.5 text-xs">
        <div className="flex justify-between gap-3 border-b border-line/60 pb-1"><dt className="text-muted">Own risk</dt><dd className="font-mono">{score(risk.own_risk)}</dd></div>
        <div className="flex justify-between gap-3 border-b border-line/60 pb-1"><dt className="text-muted">Propagated risk</dt><dd className="font-mono">{score(risk.propagated_risk)}</dd></div>
        {vulnerable && (
          <>
            <div className="flex justify-between gap-3 border-b border-line/60 pb-1"><dt className="text-muted">Severity signal ({risk.severity === "UNKNOWN" ? "not published" : risk.severity?.toLowerCase()})</dt><dd className="font-mono">{components.vulnerability_signal}</dd></div>
            <div className="flex justify-between gap-3 border-b border-line/60 pb-1">
              <dt className="text-muted">Reachability ({risk.reachability_state ? REACHABILITY_STATE_LABEL[risk.reachability_state].toLowerCase() : "—"})</dt>
              <dd className="font-mono">× {components.reachability_signal}</dd>
            </div>
            <div className="flex justify-between gap-3 border-b border-line/60 pb-1"><dt className="text-muted">Centrality</dt><dd className="font-mono">× {components.centrality_signal}</dd></div>
            <div className="flex justify-between gap-3 border-b border-line/60 pb-1"><dt className="text-muted">Downstream impact</dt><dd className="font-mono">× {components.downstream_impact}</dd></div>
            <div className="flex justify-between gap-3 border-b border-line/60 pb-1"><dt className="text-muted">Confidence</dt><dd className="font-mono">× {components.confidence}</dd></div>
            <div className="flex justify-between gap-3 border-b border-line/60 pb-1"><dt className="text-muted">Packages exposed through it</dt><dd className="font-mono">{risk.exposes}</dd></div>
          </>
        )}
      </dl>
      {risk.exposure_sources.length > 0 && (
        <div className="mt-3 text-xs" data-testid="exposure-sources">
          <div className="font-medium">Vulnerable packages it depends on</div>
          <ul className="mt-1 space-y-0.5 text-ink-soft">
            {risk.exposure_sources.map((source) => (
              <li key={source.node_id}>
                <span className="font-mono">{nodeLabel(source.node_id)}</span> · {source.distance} step{source.distance === 1 ? "" : "s"} away · risk {score(source.source_risk)} → influence {score(source.influence)}
              </li>
            ))}
            {risk.exposure_source_count > risk.exposure_sources.length && <li className="text-muted">+{risk.exposure_source_count - risk.exposure_sources.length} more</li>}
          </ul>
        </div>
      )}
      <p className="mt-3 text-[11px] text-muted">Influence halves with each dependency step. Graph risk is the larger of own and propagated risk.</p>
    </section>
  );
}
