import { formatDateTime, shortSha } from "../../utils/format";
import type { IntelligenceAnalysis } from "../../utils/types";
import { StatTile } from "../StatTile";
import { indicatorLabel, nodeLabel, score } from "./labels";

const NOT_ANALYSED = <span className="text-base font-medium text-muted">Not analysed</span>;

/** Project-level figures of the analysis on screen. A layer that was not analysed says so; it is never shown as zero. */
export function FragilityOverview({ analysis }: { analysis: IntelligenceAnalysis }) {
  const { summary } = analysis;
  const { fragility, predictive, graph_risk: risk, metadata, graph } = summary;
  const elevated = (levels?: Partial<Record<"LOW" | "MEDIUM" | "HIGH", number>>) => (levels?.MEDIUM ?? 0) + (levels?.HIGH ?? 0);
  const missing = metadata ? metadata.errors + metadata.skipped_by_limit + metadata.skipped_after_failures : 0;
  const unknownVersions = fragility ? (fragility.version_comparison.UNKNOWN ?? 0) + (fragility.version_comparison.UNSUPPORTED ?? 0) : 0;
  return (
    <section aria-label="Overview" data-testid="fragility-overview">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <StatTile label="Dependencies" value={summary.packages} note={`${graph.direct_dependencies} direct · depth up to ${graph.max_depth}`} />
        <StatTile label="Highest predictive risk" value={predictive ? (predictive.highest === null ? "—" : score(predictive.highest)) : NOT_ANALYSED}
          note={predictive ? `${elevated(predictive.by_level)} at medium or higher · of 100` : "Needs the full analysis"} />
        <StatTile label="Highest fragility" value={fragility ? (fragility.highest === null ? "—" : score(fragility.highest)) : NOT_ANALYSED}
          note={fragility ? `${elevated(fragility.by_level)} at medium or higher · mean ${fragility.mean === null ? "—" : score(fragility.mean)}` : undefined} />
        <StatTile label="Known-vulnerable packages" value={risk ? risk.project.vulnerable_packages : NOT_ANALYSED}
          note={risk ? `${(risk.by_classification.DEPENDENCY_PROPAGATION ?? 0) + (risk.by_classification.INDIRECT_EXPOSURE ?? 0)} more depend on one` : "Needs a vulnerability check"} />
        <StatTile label="Indicators" value={predictive ? predictive.indicator_total : NOT_ANALYSED} note={predictive ? "Each with its evidence" : undefined} />
      </div>

      <dl className="mt-4 flex flex-wrap gap-x-8 gap-y-2 text-sm">
        <div><dt className="eyebrow inline">Snapshot </dt><dd className="inline font-mono" title={analysis.commit_sha}>{shortSha(analysis.commit_sha)}</dd></div>
        <div><dt className="eyebrow inline">Analysed </dt><dd className="inline">{formatDateTime(analysis.completed_at ?? analysis.created_at)}</dd></div>
        <div>
          <dt className="eyebrow inline">Models </dt>
          <dd className="inline font-mono text-[12px]" data-testid="model-versions">
            {[fragility && analysis.model_versions.fragility, risk && analysis.model_versions.graph_risk, predictive && analysis.model_versions.predictive,
              predictive && analysis.model_versions.indicators].filter(Boolean).join(" · ")}
          </dd>
        </div>
      </dl>

      <ul className="mt-4 space-y-1 rounded-md border border-line bg-surface px-4 py-3 text-sm text-ink-soft" data-testid="coverage-notes">
        {metadata && metadata.providers.length === 0 && (
          <li data-testid="registries-off">No package registry is enabled, so latest versions and release dates are unknown for every dependency.</li>
        )}
        {metadata && missing > 0 && (
          <li className="text-warn" data-testid="metadata-incomplete">
            Release metadata could not be collected for {missing} of {metadata.packages} packages. Their version and release-age factors are unknown, not estimated.
          </li>
        )}
        {fragility && unknownVersions > 0 && (
          <li data-testid="unknown-versions">
            {unknownVersions} of {fragility.dependencies} dependencies could not be compared with a latest release
            {metadata && metadata.not_found > 0 ? ` (${metadata.not_found} not found in their registry` : ""}
            {metadata && metadata.unsupported_ecosystem > 0 ? `${metadata.not_found > 0 ? ", " : " ("}${metadata.unsupported_ecosystem} in ecosystems without a registry client` : ""}
            {metadata && (metadata.not_found > 0 || metadata.unsupported_ecosystem > 0) ? ")" : ""}. They carry an "Insufficient metadata" indicator and a lower confidence.
          </li>
        )}
        {!summary.vulnerability_scan && <li data-testid="no-scan-note">No vulnerability check covers this snapshot: vulnerability counts are unknown and exposure was not traced.</li>}
        {summary.vulnerability_scan && !summary.reachability_analysed && (
          <li data-testid="no-reachability-note">No code reachability analysis covers this snapshot: whether vulnerable functionality is used is not known, and is not assumed either way.</li>
        )}
        {!summary.betweenness_computed && <li>The graph is too large for betweenness centrality; degree centrality is used and confidence is lowered.</li>}
        {graph.top_dependents.length > 0 && (
          <li data-testid="concentration-note">
            Most depended-on: {graph.top_dependents.slice(0, 3).map((item) => `${nodeLabel(item.node_id)} (${item.dependents} dependents, ${Math.round(item.share * 100)}%)`).join("; ")}.
          </li>
        )}
        {graph.unconnected_packages > 0 && <li>{graph.unconnected_packages} package(s) have no established path from the project; their depth is unknown.</li>}
        {predictive && predictive.indicator_total > 0 && (
          <li data-testid="indicator-counts">
            Indicators: {Object.entries(predictive.indicators).map(([type, count]) => `${indicatorLabel(type)} × ${count}`).join(" · ")}.
          </li>
        )}
      </ul>
    </section>
  );
}
