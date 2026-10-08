import { useCallback, useEffect, useRef, useState } from "react";

import { errorMessage } from "../utils/errors";

export interface AsyncState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  /** Run the loader again. `silent` keeps the current data on screen meanwhile. */
  reload: (options?: { silent?: boolean }) => Promise<void>;
  setData: (data: T | null) => void;
}

/**
 * Load data when the component mounts and whenever `deps` change.
 * Results from a superseded or unmounted load are discarded.
 */
export function useAsync<T>(loader: () => Promise<T>, deps: readonly unknown[]): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const generation = useRef(0);
  const loaderRef = useRef(loader);
  loaderRef.current = loader;

  const reload = useCallback(async (options?: { silent?: boolean }) => {
    const current = ++generation.current;
    if (!options?.silent) setLoading(true);
    try {
      const result = await loaderRef.current();
      if (current === generation.current) {
        setData(result);
        setError(null);
      }
    } catch (caught) {
      if (current === generation.current) setError(errorMessage(caught));
    } finally {
      if (current === generation.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
    return () => {
      generation.current += 1;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, error, loading, reload, setData };
}
