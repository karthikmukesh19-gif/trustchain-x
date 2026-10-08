import { FiAlertTriangle, FiCheckCircle, FiLoader, FiPlay, FiRefreshCw } from "react-icons/fi";

import type { AnalysisStatusState } from "../../hooks/useAnalysisStatus";
import { formatDateTime } from "../../utils/format";
import { ErrorNotice } from "../Feedback";
import { Badge } from "../StatusBadge";

const STAGES = [
  { key: "REPOSITORY_SNAPSHOT", label: "Snapshot" },
  { key: "REPOSITORY_DISCOVERY", label: "Detection" },
  { key: "DEPENDENCY_DISCOVERY", label: "Dependencies" },
  { key: "GRAPH_BUILDING", label: "Graph" },
];

const STATE_BADGE = {
  queued: { tone: "neutral", label: "Queued" },
  running: { tone: "warn", label: "Running" },
  completed: { tone: "good", label: "Completed" },
  partial: { tone: "warn", label: "Partial" },
  failed: { tone: "bad", label: "Failed" },
} as const;

export function AnalysisStatusCard({ analysis }: { analysis: AnalysisStatusState }) {
  const { status, loading, error, active, starting, start } = analysis;
  const job = status?.job ?? null;
  const badge = job ? STATE_BADGE[job.state] : null;

  return (
    <section className="card p-5" aria-label="Analysis status" data-testid="analysis-status">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <h2 className="text-base font-semibold">Dependency analysis</h2>
          {badge ? <Badge tone={badge.tone}>{badge.label}</Badge> : !loading && <Badge tone="neutral">Not run</Badge>}
        </div>
        <button type="button" className="btn btn-primary" onClick={() => void start()} disabled={loading || active || starting}>
          {active || starting ? <FiLoader aria-hidden className="animate-spin" /> : job ? <FiRefreshCw aria-hidden /> : <FiPlay aria-hidden />}
          {active ? "Analysis in progress" : starting ? "Starting…" : job ? "Run again" : "Run dependency analysis"}
        </button>
      </div>

      {error && (
        <div className="mt-4">
          <ErrorNotice message={error} />
        </div>
      )}

      {!job && !loading && !error && (
        <p className="mt-3 max-w-3xl text-sm text-muted">
          Reads the repository&apos;s file list and dependency files through the GitHub API, then builds the dependency
          inventory and graph. Nothing from the repository is executed.
        </p>
      )}

      {job && active && (
        <div className="mt-4" role="status">
          <ol className="grid grid-cols-4 gap-2">
            {STAGES.map((stage, index) => {
              const position = index + 1;
              const done = job.stage_index > position;
              const current = job.stage_index === position;
              return (
                <li key={stage.key}>
                  <div className={`h-1.5 rounded-full ${done ? "bg-trust" : current ? "bg-trust/50" : "bg-line"}`} />
                  <div className={`mt-1.5 text-xs ${current ? "font-semibold text-ink" : "text-muted"}`}>{stage.label}</div>
                </li>
              );
            })}
          </ol>
          <p className="mt-3 text-sm text-ink-soft">
            {job.state === "queued" ? "Waiting for the background worker to pick up the job." : job.message}
          </p>
        </div>
      )}

      {job && job.state === "failed" && (
        <div role="alert" className="mt-4 flex items-start gap-3 rounded-md border border-danger/30 bg-danger-soft px-4 py-3 text-sm text-danger">
          <FiAlertTriangle className="mt-0.5 shrink-0" aria-hidden />
          <div>
            <p className="font-semibold">The analysis failed. No results were stored from this run.</p>
            <p className="mt-0.5">{job.error?.message ?? job.message}</p>
            <p className="mt-1 font-mono text-xs opacity-80">
              {job.error?.code ?? "ERROR"}
              {job.error?.retry_at ? ` · retry after ${formatDateTime(job.error.retry_at)}` : ""}
              {` · ${formatDateTime(job.finished_at)}`}
            </p>
          </div>
        </div>
      )}

      {job && job.state === "completed" && (
        <p className="mt-3 flex items-center gap-2 text-sm text-ink-soft">
          <FiCheckCircle aria-hidden className="shrink-0 text-trust" />
          {job.reused_snapshot
            ? "The repository has not changed since the previous analysis, so the existing results were kept."
            : "Analysis complete."}{" "}
          <span className="text-muted">Finished {formatDateTime(job.finished_at)}.</span>
        </p>
      )}
    </section>
  );
}
