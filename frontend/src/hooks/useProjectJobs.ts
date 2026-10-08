import { useCallback, useEffect, useRef, useState } from "react";

import { listJobs } from "../services/security";
import { errorMessage } from "../utils/errors";
import type { JobType, ProjectJob } from "../utils/types";

const POLL_MS = 2000;

export interface ProjectJobsState {
  /** Most recent job of the watched types, whatever its state. */
  job: ProjectJob | null;
  /** The job queued or running on the project right now, of any type (a project runs one job at a time). */
  activeJob: ProjectJob | null;
  /** True while a watched job is queued or running. */
  running: boolean;
  /** True while any job is queued or running, including types this page does not watch. */
  busy: boolean;
  loading: boolean;
  error: string | null;
  starting: boolean;
  run: (starter: () => Promise<ProjectJob>) => Promise<void>;
}

/**
 * Follow background jobs of the given types for a project. While a job is
 * queued or running the list is polled; `onFinished` fires once when a watched
 * job completes or fails.
 */
export function useProjectJobs(projectId: string, types: JobType[], onFinished?: (job: ProjectJob) => void): ProjectJobsState {
  const [job, setJob] = useState<ProjectJob | null>(null);
  const [activeJob, setActiveJob] = useState<ProjectJob | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [startError, setStartError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const watching = useRef<string | null>(null);
  const finished = useRef(onFinished);
  finished.current = onFinished;
  const typeKey = types.join(",");

  const refresh = useCallback(async () => {
    try {
      const listing = await listJobs(projectId, typeKey.split(",") as JobType[]);
      const latest = listing.items[0] ?? null;
      setJob(latest);
      setActiveJob(listing.active);
      setError(null);
      if (latest && (latest.state === "queued" || latest.state === "running")) {
        watching.current = latest.id;
      } else if (latest && watching.current === latest.id) {
        watching.current = null;
        finished.current?.(latest);
      }
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setLoading(false);
    }
  }, [projectId, typeKey]);

  useEffect(() => {
    watching.current = null;
    setJob(null);
    setActiveJob(null);
    setStartError(null);
    setLoading(true);
    void refresh();
  }, [refresh]);

  const running = job !== null && (job.state === "queued" || job.state === "running");
  const busy = activeJob !== null || running;

  useEffect(() => {
    if (!busy) return;
    const timer = window.setInterval(() => void refresh(), POLL_MS);
    return () => window.clearInterval(timer);
  }, [busy, refresh]);

  const run = useCallback(async (starter: () => Promise<ProjectJob>) => {
    setStarting(true);
    setStartError(null);
    try {
      const started = await starter();
      watching.current = started.id;
      setJob(started);
      setActiveJob(started);
    } catch (caught) {
      // Kept separately so that the refresh below does not erase the explanation.
      setStartError(errorMessage(caught));
      void refresh();
    } finally {
      setStarting(false);
    }
  }, [refresh]);

  return { job, activeJob, running, busy, loading, error: startError ?? error, starting, run };
}
