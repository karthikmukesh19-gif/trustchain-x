import type { ReactNode } from "react";
import { FiInfo } from "react-icons/fi";

import { useAsync } from "../../hooks/useAsync";
import type { AsyncState } from "../../hooks/useAsync";
import { useProjectJobs } from "../../hooks/useProjectJobs";
import type { ProjectJobsState } from "../../hooks/useProjectJobs";
import type { EvidenceBasis } from "../../utils/platformTypes";
import type { JobType } from "../../utils/types";
import { Badge } from "../StatusBadge";

const BASIS: Record<string, { tone: "good" | "warn" | "bad" | "neutral"; title: string }> = {
  OBSERVED: { tone: "good", title: "Read from the repository or an advisory source" },
  DERIVED: { tone: "neutral", title: "Computed from observed data by a documented analysis" },
  INFERRED: { tone: "warn", title: "A reasoned step that the evidence makes possible but does not establish" },
  PREDICTED: { tone: "warn", title: "A model's estimate, not an observation" },
  RECOMMENDED: { tone: "neutral", title: "A suggested action: a judgement, not a fact" },
  METHOD: { tone: "neutral", title: "A statement about how the platform works" },
  UNKNOWN: { tone: "neutral", title: "Not established" },
};

/** How a statement is known. Always shown as text. */
export function BasisTag({ basis }: { basis: EvidenceBasis | string }) {
  const view = BASIS[basis] ?? BASIS.UNKNOWN;
  return (
    <span title={view.title} data-basis={basis}>
      <Badge tone={view.tone}>{basis}</Badge>
    </span>
  );
}

const LEVEL_TONE = { HIGH: "bad", CRITICAL: "bad", MEDIUM: "warn", LOW: "neutral", INFO: "neutral", UNKNOWN: "neutral" } as const;

export function LevelBadge({ level }: { level: string }) {
  return <Badge tone={LEVEL_TONE[level as keyof typeof LEVEL_TONE] ?? "neutral"}>{level}</Badge>;
}

/** A 0-1 confidence as a percentage. A dash when there is none. */
export function Confidence({ value }: { value: number | null | undefined }) {
  if (value === null || value === undefined) return <span className="text-faint">—</span>;
  return <span className="font-mono text-[12px] tabular-nums" title="How well the stored evidence supports the result. Not a likelihood of attack.">{Math.round(value * 100)}%</span>;
}

/** A 0-100 score, or a dash with a reason when there is none. Never renders a missing score as 0. */
export function Score({ value, digits = 1 }: { value: number | null | undefined; digits?: number }) {
  if (value === null || value === undefined) return <span className="text-faint" title="Not available">—</span>;
  return <span className="font-mono tabular-nums">{value.toFixed(digits)}</span>;
}

/** The standing explanation of what a page's figures mean and do not mean. */
export function Meaning({ children, testId }: { children: ReactNode; testId?: string }) {
  return (
    <p className="flex items-start gap-2 rounded-md border border-line bg-paper px-3 py-2 text-[13px] leading-relaxed text-ink-soft" data-testid={testId}>
      <FiInfo aria-hidden className="mt-0.5 shrink-0 text-muted" />
      <span>{children}</span>
    </p>
  );
}

/** Shown where results would be, when the layer has not produced any. States plainly that nothing is known yet. */
export function NotRun({ title, children, testId = "analysis-not-available" }: { title: string; children: ReactNode; testId?: string }) {
  return (
    <div className="card border-dashed px-6 py-10 text-center" data-testid={testId}>
      <h2 className="text-base font-semibold">{title}</h2>
      <p className="mx-auto mt-1.5 max-w-xl text-sm text-muted">{children}</p>
    </div>
  );
}

export function Panel({ title, children, testId, aside }: { title: string; children: ReactNode; testId?: string; aside?: ReactNode }) {
  return (
    <section className="card p-5" aria-label={title} data-testid={testId}>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-base font-semibold">{title}</h2>
        {aside}
      </div>
      {children}
    </section>
  );
}

export const shortNode = (nodeId: string) => nodeId.replace(/^[a-z0-9]+:/, "");
export const words = (value: string) => value.replace(/_/g, " ").toLowerCase();
export const percent = (value: number | null | undefined) => (value === null || value === undefined ? "—" : `${Math.round(value * 100)}%`);

/**
 * A page's data together with the background jobs that produce it: the data is
 * loaded on mount and again whenever a watched job finishes.
 */
export function useLayer<T>(projectId: string, jobTypes: JobType[], loader: () => Promise<T>): { data: AsyncState<T>; jobs: ProjectJobsState } {
  const data = useAsync(loader, [projectId]);
  const jobs = useProjectJobs(projectId, jobTypes, () => void data.reload({ silent: true }));
  return { data, jobs };
}
