import { useEffect, useMemo, useState } from "react";
import { FiX } from "react-icons/fi";
import { useParams } from "react-router-dom";

import { DependencyEvidence } from "../components/analysis/EvidenceList";
import { NotAnalysed, ProjectPageShell } from "../components/analysis/ProjectPageShell";
import { ErrorNotice, Spinner } from "../components/Feedback";
import { DependencyGraph } from "../graph/DependencyGraph";
import { ROOT_ID, layoutGraph, maxDepthOf } from "../graph/layout";
import type { GraphFilters } from "../graph/layout";
import { useAsync } from "../hooks/useAsync";
import { getDependencyGraph, getDependencyPaths, getSnapshot, listDependencies } from "../services/analysis";
import { errorMessage } from "../utils/errors";
import { ecosystemLabel, shortSha } from "../utils/format";
import type { Dependency, DependencyGraphData } from "../utils/types";

interface Detail {
  dependency: Dependency | null;
  paths: string[][];
}

export function GraphPage() {
  const { id = "" } = useParams();
  const [filters, setFilters] = useState<GraphFilters>({ search: "", ecosystem: "", relationship: "", maxDepth: null });
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<Detail | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [repositoryUrl, setRepositoryUrl] = useState<string | null>(null);

  const { data, error, loading, reload } = useAsync<{ graph: DependencyGraphData | null }>(async () => {
    try {
      return { graph: await getDependencyGraph(id) };
    } catch (caught) {
      if ((caught as { response?: { status?: number } }).response?.status === 404) return { graph: null };
      throw caught;
    }
  }, [id]);
  const graph = data?.graph ?? null;

  useEffect(() => {
    let cancelled = false;
    getSnapshot(id)
      .then((snapshot) => {
        if (!cancelled) setRepositoryUrl(snapshot.repository_url);
      })
      .catch(() => undefined); // only used to link evidence to GitHub
    return () => {
      cancelled = true;
    };
  }, [id]);

  const layout = useMemo(() => (graph ? layoutGraph(graph, filters) : null), [graph, filters]);
  const selected = useMemo(() => graph?.nodes.find((node) => node.node_id === selectedId) ?? null, [graph, selectedId]);
  const labels = useMemo(() => {
    const map = new Map<string, string>();
    if (graph) {
      map.set(ROOT_ID, graph.root.label);
      for (const node of graph.nodes) map.set(node.node_id, `${node.name}${node.version ? `@${node.version}` : ""}`);
    }
    return map;
  }, [graph]);

  // Evidence and paths for the selected package are loaded on demand.
  useEffect(() => {
    setDetail(null);
    setDetailError(null);
    if (!selected) return;
    let cancelled = false;
    Promise.all([
      listDependencies(id, { q: selected.normalized_name, ecosystem: selected.ecosystem, limit: 200 }),
      getDependencyPaths(id, selected.node_id),
    ])
      .then(([list, paths]) => {
        if (!cancelled) setDetail({ dependency: list.items.find((item) => item.node_id === selected.node_id) ?? null, paths });
      })
      .catch((caught) => {
        if (!cancelled) setDetailError(errorMessage(caught));
      });
    return () => {
      cancelled = true;
    };
  }, [id, selected]);

  const deepest = graph ? maxDepthOf(graph.nodes) : 0;
  const update = (patch: Partial<GraphFilters>) => {
    setFilters((current) => ({ ...current, ...patch }));
    setSelectedId(null);
  };

  return (
    <ProjectPageShell projectId={id}>
      {loading && !data ? (
        <Spinner label="Loading dependency graph" />
      ) : error && !data ? (
        <ErrorNotice message={error} onRetry={() => void reload()} />
      ) : !graph || !layout ? (
        <NotAnalysed projectId={id} />
      ) : graph.nodes.length === 0 ? (
        <div className="card border-dashed px-6 py-10 text-center" data-testid="empty-graph">
          <h2 className="text-base font-semibold">There is no graph to draw</h2>
          <p className="mx-auto mt-1.5 max-w-md text-sm text-muted">
            The analysis found no dependencies in this repository, so the graph has no packages or edges.
          </p>
        </div>
      ) : (
        <>
          <div className="flex flex-wrap items-end gap-3">
            <div className="min-w-[200px] flex-1">
              <label htmlFor="graph-search" className="mb-1 block text-xs font-medium text-muted">Search by name</label>
              <input id="graph-search" className="field" value={filters.search} onChange={(event) => update({ search: event.target.value })} maxLength={100} />
            </div>
            <div>
              <label htmlFor="graph-ecosystem" className="mb-1 block text-xs font-medium text-muted">Ecosystem</label>
              <select id="graph-ecosystem" className="field" value={filters.ecosystem} onChange={(event) => update({ ecosystem: event.target.value })}>
                <option value="">All</option>
                {Object.keys(graph.stats.by_ecosystem).sort().map((name) => <option key={name} value={name}>{ecosystemLabel(name)}</option>)}
              </select>
            </div>
            <div>
              <label htmlFor="graph-relationship" className="mb-1 block text-xs font-medium text-muted">Relationship</label>
              <select id="graph-relationship" className="field" value={filters.relationship} onChange={(event) => update({ relationship: event.target.value })}>
                <option value="">All</option>
                <option value="DIRECT">Direct</option>
                <option value="TRANSITIVE">Transitive</option>
                <option value="UNKNOWN">Unknown</option>
              </select>
            </div>
            <div>
              <label htmlFor="graph-depth" className="mb-1 block text-xs font-medium text-muted">Depth</label>
              <select id="graph-depth" className="field" value={filters.maxDepth ?? ""} onChange={(event) => update({ maxDepth: event.target.value === "" ? null : Number(event.target.value) })}>
                <option value="">All depths</option>
                {Array.from({ length: deepest }, (_, index) => index + 1).map((depth) => (
                  <option key={depth} value={depth}>{depth === 1 ? "Direct only" : `Up to ${depth}`}</option>
                ))}
              </select>
            </div>
          </div>

          <p className="mt-3 text-sm text-muted" data-testid="graph-summary">
            Showing {layout.nodes.length - 1} of {graph.nodes.length} packages and {layout.edges.length} of {graph.edges.length} edges
            {" · "}snapshot <span className="font-mono">{shortSha(graph.snapshot.commit_sha)}</span>
            {layout.hidden > 0 && (
              <span className="text-warn"> · {layout.hidden} matching packages are not drawn; narrow the filters to see them</span>
            )}
          </p>

          <div className="mt-3 grid gap-4 lg:grid-cols-[minmax(0,1fr)_360px]">
            <div>
              {layout.nodes.length === 1 ? (
                <div className="card border-dashed px-6 py-10 text-center text-sm text-muted">No packages match these filters.</div>
              ) : (
                <DependencyGraph layout={layout} selectedId={selectedId} onSelect={setSelectedId} viewKey={JSON.stringify(filters)} />
              )}
              <ul className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-xs text-muted">
                <li><span className="mr-1.5 inline-block h-2.5 w-2.5 rounded-sm border border-trust bg-trust-soft align-middle" />Direct</li>
                <li><span className="mr-1.5 inline-block h-2.5 w-2.5 rounded-sm border border-line bg-surface align-middle" />Transitive</li>
                <li><span className="mr-1.5 inline-block h-2.5 w-2.5 rounded-sm border border-dashed border-faint bg-paper align-middle" />Relationship unknown</li>
                <li>Columns are dependency depth, left to right; dashed edges are inferred.</li>
                {graph.stats.without_path > 0 && <li>{graph.stats.without_path} package(s) have no established path and are drawn unconnected.</li>}
              </ul>
            </div>

            <aside className="card h-fit p-4" aria-label="Selected package" data-testid="graph-details">
              {!selected ? (
                <p className="text-sm text-muted">Select a package in the graph to see where it comes from.</p>
              ) : (
                <>
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="eyebrow">{ecosystemLabel(selected.ecosystem)}</div>
                      <h2 className="break-all font-mono text-sm font-semibold">{selected.name}</h2>
                    </div>
                    <button type="button" className="rounded p-1 text-muted hover:text-ink" onClick={() => setSelectedId(null)} aria-label="Close details">
                      <FiX aria-hidden />
                    </button>
                  </div>
                  <dl className="mt-3 grid grid-cols-3 gap-2 text-sm">
                    <div><dt className="eyebrow">Depth</dt><dd className="font-mono">{selected.depth ?? "—"}</dd></div>
                    <div><dt className="eyebrow">Required by</dt><dd className="font-mono">{selected.parent_count}</dd></div>
                    <div><dt className="eyebrow">Requires</dt><dd className="font-mono">{selected.dependency_count}</dd></div>
                  </dl>

                  {detailError && <div className="mt-3"><ErrorNotice message={detailError} /></div>}
                  {!detail && !detailError && <Spinner label="Loading evidence" />}
                  {detail && (
                    <>
                      <div className="mt-4">
                        <div className="eyebrow">Paths from the project</div>
                        {detail.paths.length === 0 ? (
                          <p className="mt-1 text-xs text-muted">The repository evidence does not establish how the project reaches this package.</p>
                        ) : (
                          <ol className="mt-1 space-y-1.5">
                            {detail.paths.slice(0, 5).map((path, index) => (
                              <li key={index} className="break-all font-mono text-[11px] leading-relaxed text-ink-soft">
                                {path.map((step) => labels.get(step) ?? step).join("  →  ")}
                              </li>
                            ))}
                            {detail.paths.length > 5 && <li className="text-xs text-muted">+{detail.paths.length - 5} more path(s)</li>}
                          </ol>
                        )}
                      </div>
                      {detail.dependency && (
                        <div className="mt-4 border-t border-line pt-4">
                          <DependencyEvidence dependency={detail.dependency} repositoryUrl={repositoryUrl ?? undefined} commitSha={graph.snapshot.commit_sha} />
                        </div>
                      )}
                    </>
                  )}
                </>
              )}
            </aside>
          </div>
        </>
      )}
    </ProjectPageShell>
  );
}
