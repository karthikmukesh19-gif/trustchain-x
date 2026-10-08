import { useAsync } from "../../hooks/useAsync";
import { compareAnalyses, listAnalysisHistory } from "../../services/intelligence";
import { formatDateTime, shortSha } from "../../utils/format";
import type { AnalysisComparison, IntelligenceAnalysis, IntelligenceKind } from "../../utils/types";
import { ErrorNotice } from "../Feedback";
import { indicatorLabel } from "./labels";

const signed = (value: number) => `${value > 0 ? "+" : ""}${value.toFixed(1)}`;

/** What changed since the previous analysis of the same kind. Analyses are kept, so this is a comparison of two stored runs. */
export function AnalysisChanges({ projectId, analysisId, kind }: { projectId: string; analysisId: string; kind: IntelligenceKind }) {
  const { data, error, loading, reload } = useAsync<{ history: IntelligenceAnalysis[]; diff: AnalysisComparison | null }>(async () => {
    const history = await listAnalysisHistory(projectId, kind);
    const position = history.findIndex((item) => item.id === analysisId);
    const previous = position >= 0 ? history[position + 1] : undefined;
    return { history, diff: previous ? await compareAnalyses(projectId, previous.id, analysisId) : null };
  }, [projectId, analysisId, kind]);

  if (loading && !data) return null;
  return (
    <section className="card p-5" aria-label="Changes since the previous analysis" data-testid="analysis-changes">
      <h3 className="text-base font-semibold">Changes since the previous analysis</h3>
      {error ? (
        <div className="mt-3"><ErrorNotice message={error} onRetry={() => void reload()} /></div>
      ) : !data?.diff ? (
        <p className="mt-1 text-sm text-muted" data-testid="no-previous-analysis">
          This is the only stored analysis of this kind. Later analyses are kept alongside it and compared here.
        </p>
      ) : (
        <>
          <p className="mt-1 text-sm text-muted" data-testid="changes-summary">
            Compared with {formatDateTime(data.diff.base.created_at)}
            {data.diff.base.commit_sha !== data.diff.target.commit_sha ? ` (commit ${shortSha(data.diff.base.commit_sha)})` : " (same commit)"}:{" "}
            {data.diff.summary.changed} changed · {data.diff.summary.added} added · {data.diff.summary.removed} removed · {data.diff.summary.unchanged} unchanged.
          </p>
          {data.diff.items.length > 0 && (
            <ul className="mt-3 divide-y divide-line border-t border-line text-sm" data-testid="changes-list">
              {data.diff.items.slice(0, 15).map((item) => (
                <li key={`${item.ecosystem}:${item.normalized_name}`} className="flex flex-wrap items-baseline gap-x-4 gap-y-0.5 py-2" data-change={item.change}>
                  <span className="font-mono text-[13px]">{item.normalized_name}</span>
                  {item.change === "ADDED" && <span className="text-xs text-muted">added{item.after?.version ? ` at ${item.after.version}` : ""}</span>}
                  {item.change === "REMOVED" && <span className="text-xs text-muted">removed</span>}
                  {item.change === "CHANGED" && (
                    <span className="text-xs text-ink-soft">
                      {[
                        item.version_changed ? `version ${item.before?.version ?? "?"} → ${item.after?.version ?? "?"}` : "",
                        item.deltas?.predictive_risk !== undefined ? `predictive risk ${signed(item.deltas.predictive_risk)}` : "",
                        item.deltas?.fragility_score !== undefined ? `fragility ${signed(item.deltas.fragility_score)}` : "",
                        item.deltas?.graph_risk !== undefined ? `graph risk ${signed(item.deltas.graph_risk)}` : "",
                        ...(item.indicators_added ?? []).map((type) => `new indicator: ${indicatorLabel(type)}`),
                        ...(item.indicators_removed ?? []).map((type) => `no longer: ${indicatorLabel(type)}`),
                      ].filter(Boolean).join(" · ")}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          )}
          {(data.diff.items.length > 15 || data.diff.items_truncated) && <p className="mt-2 text-xs text-muted">Only the first changes are listed.</p>}
          <p className="mt-2 text-xs text-muted">{data.history.length} analyses of this kind are stored for this project.</p>
        </>
      )}
    </section>
  );
}
