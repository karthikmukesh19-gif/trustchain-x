import { useCallback, useEffect, useRef, useState } from "react";

import { getAnalysisStatus, startDependencyAnalysis } from "../services/analysis";
import { errorMessage } from "../utils/errors";
import type { AnalysisStatus } from "../utils/types";

const POLL_MS = 2000;

export interface AnalysisStatusState {
  status: AnalysisStatus | null;
  loading: boolean;
  error: string | null;
  /** True from the moment a run is requested until the job reaches completed or failed. */
  active: boolean;
  starting: boolean;
  start: () => Promise<void>;
}

/**
 * Follow a project's analysis job. While the job is queued or running the
 * status is polled; `onFinished` fires once when it completes or fails.
 */
export function useAnalysisStatus(projectId: string, onFinished?: (state: "completed" | "failed") => void): AnalysisStatusState {
  const [status, setStatus] = useState<AnalysisStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [startError, setStartError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const watching = useRef(false);
  const finished = useRef(onFinished);
  finished.current = onFinished;

  const state = status?.job?.state;
  const active = state === "queued" || state === "running";

  const refresh = useCallback(async () => {
    try {
      const next = await getAnalysisStatus(projectId);
      setStatus(next);
      setError(null);
      const nextState = next.job?.state;
      if (nextState === "queued" || nextState === "running") {
        watching.current = true;
      } else if (watching.current && (nextState === "completed" || nextState === "failed")) {
        watching.current = false;
        finished.current?.(nextState);
      }
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  useEffect(() => {
    watching.current = false;
    setStatus(null);
    setStartError(null);
    setLoading(true);
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (!active) return;
    const timer = window.setInterval(() => void refresh(), POLL_MS);
    return () => window.clearInterval(timer);
  }, [active, refresh]);

  const start = useCallback(async () => {
    setStarting(true);
    setStartError(null);
    try {
      const job = await startDependencyAnalysis(projectId);
      watching.current = true;
      setStatus((previous) => ({
        job,
        has_results: previous?.has_results ?? false,
        last_analysis: previous?.last_analysis ?? null,
      }));
    } catch (caught) {
      // Kept separately so that the status refresh below does not erase the explanation.
      setStartError(errorMessage(caught));
      void refresh();
    } finally {
      setStarting(false);
    }
  }, [projectId, refresh]);

  return { status, loading, error: startError ?? error, active, starting, start };
}
