import type { ReactNode } from "react";
import { FiAlertTriangle, FiCheckCircle } from "react-icons/fi";

import type { ProjectJobsState } from "../../hooks/useProjectJobs";
import { formatDateTime } from "../../utils/format";
import { ErrorNotice } from "../Feedback";
import { Badge } from "../StatusBadge";

const STATE_BADGE = {
  queued: { tone: "neutral", label: "Queued" },
  running: { tone: "warn", label: "Running" },
  completed: { tone: "good", label: "Completed" },
  failed: { tone: "bad", label: "Failed" },
} as const;

const STAGE_LABELS: Record<string, string> = {
  PROVIDER_QUERY: "Query provider",
  RECORD_INGESTION: "Fetch advisories",
  MATCHING: "Match versions",
  SBOM_GENERATION: "Generate",
  SBOM_COMPARISON: "Compare",
  SOURCE_INVENTORY: "List source",
  SOURCE_PARSING: "Parse",
  GRAPH_BUILDING: "Build graph",
  SYMBOL_MAPPING: "Map symbols",
  REACHABILITY: "Search paths",
};

const JOB_NAMES: Record<string, string> = {
  dependencies: "A dependency analysis",
  vulnerability_sync: "A vulnerability check",
  vulnerability_analysis: "A vulnerability re-match",
  sbom_generation: "An SBOM generation",
  code_reachability_analysis: "A code reachability analysis",
};

/**
 * Status of a page's background job: progress while it runs, the reason when
 * it fails, and a plain statement when it completes. `failureNote` says what a
 * failure means for the data on the page.
 */
export function JobPanel({ title, jobs, actions, idle, failureNote, testId }: {
  title: string;
  jobs: ProjectJobsState;
  actions: ReactNode;
  idle: string;
  failureNote: string;
  testId: string;
}) {
  const { job, activeJob, running, loading, error } = jobs;
  const badge = job ? STATE_BADGE[job.state] : null;
  const stages = job?.stages ?? [];
  const otherJob = activeJob && (!job || activeJob.id !== job.id) ? activeJob : null;

  return (
    <section className="card p-5" aria-label={title} data-testid={testId}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <h2 className="text-base font-semibold">{title}</h2>
          {badge ? <Badge tone={badge.tone}>{badge.label}</Badge> : !loading && <Badge tone="neutral">Not run</Badge>}
        </div>
        <div className="flex flex-wrap items-center gap-2">{actions}</div>
      </div>

      {error && (
        <div className="mt-4">
          <ErrorNotice message={error} />
        </div>
      )}

      {otherJob && (
        <p className="mt-3 text-sm text-muted" role="status">
          {JOB_NAMES[otherJob.type] ?? "Another job"} is in progress for this project. Only one job runs at a time.
        </p>
      )}

      {!job && !loading && !error && <p className="mt-3 max-w-3xl text-sm text-muted">{idle}</p>}

      {job && running && (
        <div className="mt-4" role="status">
          <ol className="grid gap-2" style={{ gridTemplateColumns: `repeat(${Math.max(1, stages.length)}, minmax(0, 1fr))` }}>
            {stages.map((stage, index) => {
              const position = index + 1;
              const done = job.stage_index > position;
              const current = job.stage_index === position;
              return (
                <li key={stage}>
                  <div className={`h-1.5 rounded-full ${done ? "bg-trust" : current ? "bg-trust/50" : "bg-line"}`} />
                  <div className={`mt-1.5 text-xs ${current ? "font-semibold text-ink" : "text-muted"}`}>{STAGE_LABELS[stage] ?? stage}</div>
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
            <p className="font-semibold">{failureNote}</p>
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
          {job.message}. <span className="text-muted">Finished {formatDateTime(job.finished_at)}.</span>
        </p>
      )}
    </section>
  );
}
