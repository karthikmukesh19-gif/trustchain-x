import { useCallback, useEffect, useMemo, useState } from "react";
import { FiActivity, FiAlertTriangle, FiSearch, FiX } from "react-icons/fi";
import { Link, useParams } from "react-router-dom";

import { JobPanel } from "../components/analysis/JobPanel";
import { NotAnalysed, ProjectPageShell } from "../components/analysis/ProjectPageShell";
import { ErrorNotice, Spinner } from "../components/Feedback";
import { AnalysisChanges } from "../components/intelligence/AnalysisChanges";
import { DependencyDetail } from "../components/intelligence/DependencyDetail";
import { DependencyRiskTable } from "../components/intelligence/DependencyRiskTable";
import type { DetailState } from "../components/intelligence/DependencyRiskTable";
import { FragilityOverview } from "../components/intelligence/FragilityOverview";
import { GraphRiskPanel } from "../components/intelligence/GraphRiskPanel";
import { indicatorLabel } from "../components/intelligence/labels";
import { RiskGraph } from "../graph/RiskGraph";
import { CENTRALITY_THRESHOLD, NO_RISK_FILTERS, layoutRiskGraph } from "../graph/riskLayout";
import type { RiskFilters } from "../graph/riskLayout";
import { useAsync } from "../hooks/useAsync";
import { useProjectJobs } from "../hooks/useProjectJobs";
import {
  getFragility, getPredictiveRisk, getRiskGraph, listFragility, listPredictiveRisk, startFragilityAnalysis, startPredictiveAnalysis,
} from "../services/intelligence";
import { errorMessage } from "../utils/errors";
import { shortSha } from "../utils/format";
import type { FragilityRow, IntelligenceList, JobType, PredictionRow, RiskGraphData } from "../utils/types";

const PAGE_SIZE = 50;
const JOB_TYPES: JobType[] = ["predictive_dependency_analysis", "dependency_fragility_analysis", "graph_risk_analysis"];

type Loaded =
  | { mode: "predictive"; list: IntelligenceList<PredictionRow> }
  | { mode: "fragility" | "none"; list: IntelligenceList<FragilityRow> };

export function FragilityPage() {
  const { id = "" } = useParams();
  const [view, setView] = useState<"table" | "graph">("table");
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");
  const [level, setLevel] = useState("");
  const [relationship, setRelationship] = useState("");
  const [indicator, setIndicator] = useState("");
  const [vulnerable, setVulnerable] = useState(false);
  const [sort, setSort] = useState("risk");
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [details, setDetails] = useState<Record<string, DetailState>>({});
  const [graphFilters, setGraphFilters] = useState<RiskFilters>(NO_RISK_FILTERS);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  useEffect(() => {
    const next = search.trim();
    if (next === query) return;
    const timer = window.setTimeout(() => {
      setQuery(next);
      setPage(0);
    }, 300);
    return () => window.clearTimeout(timer);
  }, [search, query]);

  const { data, error, loading, reload } = useAsync<Loaded>(async () => {
    const filters = { q: query, level, relationship, skip: page * PAGE_SIZE, limit: PAGE_SIZE };
    const predictive = await listPredictiveRisk(id, { ...filters, indicator, vulnerable: vulnerable || undefined, sort });
    if (predictive.analysis) return { mode: "predictive", list: predictive };
    // No full analysis of this snapshot: a fragility-only analysis may still exist.
    const fragility = await listFragility(id, filters);
    return { mode: fragility.analysis ? "fragility" : "none", list: fragility };
  }, [id, query, level, relationship, indicator, vulnerable, sort, page]);

  const analysisId = data?.list.analysis?.id ?? null;
  const graph = useAsync<RiskGraphData | null>(
    async () => (view === "graph" && data?.mode === "predictive" ? getRiskGraph(id) : null),
    [id, view, data?.mode, analysisId],
  );

  const refresh = useCallback(() => {
    setDetails({});
    setExpanded(null);
    setSelectedNode(null);
    void reload({ silent: true });
  }, [reload]);
  const jobs = useProjectJobs(id, JOB_TYPES, refresh);

  const mode = data?.mode ?? "none";
  const loadDetail = useCallback(async (dependencyId: string) => {
    setDetails((current) => Object.fromEntries(Object.entries(current).filter(([key]) => key !== dependencyId)));
    try {
      const detail = mode === "predictive" ? await getPredictiveRisk(id, dependencyId) : await getFragility(id, dependencyId);
      setDetails((current) => ({ ...current, [dependencyId]: detail }));
    } catch (caught) {
      setDetails((current) => ({ ...current, [dependencyId]: { error: errorMessage(caught) } }));
    }
  }, [id, mode]);

  function toggle(dependencyId: string) {
    if (expanded === dependencyId) {
      setExpanded(null);
      return;
    }
    setExpanded(dependencyId);
    const known = details[dependencyId];
    if (!known || "error" in known) void loadDetail(dependencyId);
  }

  const layout = useMemo(() => (graph.data ? layoutRiskGraph(graph.data, graphFilters) : null), [graph.data, graphFilters]);
  const selected = useMemo(() => graph.data?.nodes.find((node) => node.node_id === selectedNode) ?? null, [graph.data, selectedNode]);
  const selectedDetail = selected ? details[selected.dependency_id] : undefined;
  useEffect(() => {
    if (selected && !details[selected.dependency_id]) void loadDetail(selected.dependency_id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected]);

  const list = data?.list ?? null;
  const analysis = list?.analysis ?? null;
  const hasScan = list?.has_vulnerability_scan ?? false;
  const filtered = query !== "" || level !== "" || relationship !== "" || indicator !== "" || vulnerable;
  const pages = list ? Math.max(1, Math.ceil(list.total / PAGE_SIZE)) : 1;
  const disabled = jobs.loading || jobs.busy || jobs.starting;
  const inputs = list?.current_inputs ?? null;
  const stale = analysis !== null && inputs !== null && mode === "predictive" && (
    (inputs.vulnerability_scan_matched_at ?? null) !== (analysis.inputs.vulnerability_scan_matched_at ?? null)
    || (inputs.reachability_completed_at ?? null) !== (analysis.inputs.reachability?.completed_at ?? null));
  const updateGraph = (patch: Partial<RiskFilters>) => {
    setGraphFilters((current) => ({ ...current, ...patch }));
    setSelectedNode(null);
  };
  const reset = (setter: () => void) => {
    setter();
    setPage(0);
    setExpanded(null);
  };

  return (
    <ProjectPageShell projectId={id}>
      {loading && !data ? (
        <Spinner label="Loading dependency intelligence" />
      ) : error && !data ? (
        <ErrorNotice message={error} onRetry={() => void reload()} />
      ) : !list || !list.snapshot ? (
        <NotAnalysed projectId={id} />
      ) : (
        <>
          <JobPanel
            title="Dependency intelligence"
            testId="intelligence-job"
            jobs={jobs}
            idle="Measures each dependency's place in the graph, compares installed versions with the registries' latest releases, traces known-vulnerable packages through the graph and derives indicators. Scores rank dependencies for attention. They are estimates from the evidence listed with them, not predictions of specific vulnerabilities or attacks."
            failureNote="The analysis failed. Results below, if any, are from an earlier run."
            actions={
              hasScan ? (
                <button type="button" className="btn btn-primary" disabled={disabled} onClick={() => void jobs.run(() => startPredictiveAnalysis(id))}>
                  <FiActivity aria-hidden /> {jobs.running ? "Analysis in progress" : jobs.starting ? "Starting…" : mode === "predictive" ? "Analyse again" : "Start analysis"}
                </button>
              ) : (
                <button type="button" className="btn btn-secondary" disabled={disabled} onClick={() => void jobs.run(() => startFragilityAnalysis(id))}
                  title="Exposure, indicators and predictive risk need a vulnerability check of this snapshot">
                  <FiActivity aria-hidden /> {jobs.running ? "Analysis in progress" : jobs.starting ? "Starting…" : "Analyse fragility only"}
                </button>
              )
            }
          />

          {!hasScan && (
            <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-md border border-line bg-surface px-4 py-3 text-sm" data-testid="needs-scan">
              <p className="max-w-3xl text-ink-soft">
                Snapshot <span className="font-mono">{shortSha(list.snapshot.commit_sha)}</span> has no vulnerability check. Fragility can be analysed
                now; exposure through the graph, indicators and predictive risk need the check first.
              </p>
              <Link to={`/projects/${id}/vulnerabilities`} className="btn btn-secondary">Go to vulnerabilities</Link>
            </div>
          )}

          {!analysis ? (
            <div className="card mt-6 border-dashed px-6 py-10 text-center" data-testid="analysis-not-available">
              <h2 className="text-base font-semibold">Analysis not available</h2>
              <p className="mx-auto mt-1.5 max-w-xl text-sm text-muted">
                No dependency intelligence analysis has completed for this snapshot, so there are no fragility or risk figures to show.
                A missing figure is not a low one.
              </p>
            </div>
          ) : (
            <>
              {mode === "fragility" && hasScan && (
                <div role="status" className="mt-4 rounded-md bg-warn-soft px-4 py-3 text-sm text-warn" data-testid="fragility-only-note">
                  Only fragility has been analysed for this snapshot. Start the analysis to add exposure, indicators and predictive risk.
                </div>
              )}
              {stale && (
                <div role="alert" className="mt-4 flex items-start gap-3 rounded-md bg-warn-soft px-4 py-3 text-sm text-warn" data-testid="stale-warning">
                  <FiAlertTriangle className="mt-0.5 shrink-0" aria-hidden />
                  <p>The vulnerability check or the code reachability analysis has been run since this analysis. Analyse again to take the newer findings into account.</p>
                </div>
              )}

              <div className="mt-6"><FragilityOverview analysis={analysis} /></div>

              {analysis.summary.graph_risk && <div className="mt-6"><GraphRiskPanel risk={analysis.summary.graph_risk} /></div>}

              <div className="mt-8 flex flex-wrap items-center justify-between gap-3">
                <h2 className="text-base font-semibold">Dependencies</h2>
                <div className="inline-flex rounded-md border border-line bg-surface p-0.5" role="tablist" aria-label="View">
                  {(["table", "graph"] as const).map((name) => (
                    <button key={name} type="button" role="tab" aria-selected={view === name} onClick={() => setView(name)}
                      className={`rounded px-3 py-1 text-sm font-medium ${view === name ? "bg-ink text-white" : "text-muted hover:text-ink"}`}>
                      {name === "table" ? "Table" : "Risk graph"}
                    </button>
                  ))}
                </div>
              </div>

              {view === "table" ? (
                <>
                  <div className="mt-3 flex flex-wrap items-end gap-3">
                    <div className="min-w-[200px] flex-1">
                      <label htmlFor="risk-search" className="mb-1 block text-xs font-medium text-muted">Search by package</label>
                      <div className="relative">
                        <FiSearch aria-hidden className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint" />
                        <input id="risk-search" className="field pl-9" value={search} onChange={(event) => setSearch(event.target.value)} maxLength={100} />
                      </div>
                    </div>
                    <div>
                      <label htmlFor="risk-level" className="mb-1 block text-xs font-medium text-muted">{mode === "predictive" ? "Predictive risk" : "Fragility"}</label>
                      <select id="risk-level" className="field" value={level} onChange={(event) => reset(() => setLevel(event.target.value))}>
                        <option value="">All</option>
                        <option value="HIGH">High</option>
                        <option value="MEDIUM">Medium</option>
                        <option value="LOW">Low</option>
                      </select>
                    </div>
                    <div>
                      <label htmlFor="risk-relationship" className="mb-1 block text-xs font-medium text-muted">Relationship</label>
                      <select id="risk-relationship" className="field" value={relationship} onChange={(event) => reset(() => setRelationship(event.target.value))}>
                        <option value="">All</option>
                        <option value="DIRECT">Direct</option>
                        <option value="TRANSITIVE">Transitive</option>
                      </select>
                    </div>
                    {mode === "predictive" && (
                      <>
                        <div>
                          <label htmlFor="risk-indicator" className="mb-1 block text-xs font-medium text-muted">Indicator</label>
                          <select id="risk-indicator" className="field" value={indicator} onChange={(event) => reset(() => setIndicator(event.target.value))}>
                            <option value="">Any</option>
                            {(list.indicator_types ?? []).map((type) => <option key={type} value={type}>{indicatorLabel(type)}</option>)}
                          </select>
                        </div>
                        <div>
                          <label htmlFor="risk-sort" className="mb-1 block text-xs font-medium text-muted">Sort by</label>
                          <select id="risk-sort" className="field" value={sort} onChange={(event) => reset(() => setSort(event.target.value))}>
                            <option value="risk">Predictive risk</option>
                            <option value="fragility">Fragility</option>
                            <option value="centrality">Centrality</option>
                            <option value="dependents">Dependents</option>
                            <option value="name">Name</option>
                          </select>
                        </div>
                        <label className="flex items-center gap-2 pb-2 text-sm">
                          <input type="checkbox" checked={vulnerable} onChange={(event) => reset(() => setVulnerable(event.target.checked))} />
                          Known vulnerabilities only
                        </label>
                      </>
                    )}
                  </div>

                  {error && <div className="mt-4"><ErrorNotice message={error} onRetry={() => void reload()} /></div>}

                  {list.total === 0 ? (
                    <div className="card mt-4 px-6 py-8 text-center" data-testid="no-rows">
                      <h3 className="text-base font-semibold">{filtered ? "No dependencies match these filters" : "This snapshot has no dependencies"}</h3>
                    </div>
                  ) : (
                    <div className="mt-4">
                      <DependencyRiskTable mode={mode === "predictive" ? "predictive" : "fragility"}
                        predictions={data?.mode === "predictive" ? data.list.items : []} fragility={data && data.mode !== "predictive" ? data.list.items : []}
                        expanded={expanded} details={details} onToggle={toggle} onRetry={(dependencyId) => void loadDetail(dependencyId)} />
                    </div>
                  )}

                  {list.total > 0 && (
                    <div className="mt-3 flex flex-wrap items-center justify-between gap-3 text-sm text-muted">
                      <span data-testid="risk-range">
                        {list.skip + 1}–{list.skip + list.items.length} of {list.total}{filtered ? ` (filtered from ${analysis.summary.packages})` : ""}
                      </span>
                      {pages > 1 && (
                        <span className="flex items-center gap-2">
                          <button type="button" className="btn btn-secondary" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
                          <span>Page {page + 1} of {pages}</span>
                          <button type="button" className="btn btn-secondary" disabled={page + 1 >= pages} onClick={() => setPage(page + 1)}>Next</button>
                        </span>
                      )}
                    </div>
                  )}
                </>
              ) : mode !== "predictive" ? (
                <div className="card mt-4 border-dashed px-6 py-10 text-center" data-testid="graph-not-available">
                  <h3 className="text-base font-semibold">Analysis not available</h3>
                  <p className="mx-auto mt-1.5 max-w-xl text-sm text-muted">The risk graph is drawn from the full analysis, which has not been run for this snapshot.</p>
                </div>
              ) : graph.loading && !graph.data ? (
                <Spinner label="Loading risk graph" />
              ) : graph.error && !graph.data ? (
                <div className="mt-4"><ErrorNotice message={graph.error} onRetry={() => void graph.reload()} /></div>
              ) : !graph.data || !layout ? null : (
                <>
                  <div className="mt-3 flex flex-wrap items-end gap-3" data-testid="graph-filters">
                    <div className="min-w-[180px] flex-1">
                      <label htmlFor="graph-risk-search" className="mb-1 block text-xs font-medium text-muted">Search by package</label>
                      <input id="graph-risk-search" className="field" value={graphFilters.search} onChange={(event) => updateGraph({ search: event.target.value })} maxLength={100} />
                    </div>
                    <div>
                      <label htmlFor="graph-risk-level" className="mb-1 block text-xs font-medium text-muted">Predictive risk</label>
                      <select id="graph-risk-level" className="field" value={graphFilters.risk} onChange={(event) => updateGraph({ risk: event.target.value as RiskFilters["risk"] })}>
                        <option value="">Any</option>
                        <option value="MEDIUM">Medium or higher</option>
                        <option value="HIGH">High</option>
                      </select>
                    </div>
                    <div>
                      <label htmlFor="graph-fragility-level" className="mb-1 block text-xs font-medium text-muted">Fragility</label>
                      <select id="graph-fragility-level" className="field" value={graphFilters.fragility} onChange={(event) => updateGraph({ fragility: event.target.value as RiskFilters["fragility"] })}>
                        <option value="">Any</option>
                        <option value="MEDIUM">Medium or higher</option>
                        <option value="HIGH">High</option>
                      </select>
                    </div>
                    <div>
                      <label htmlFor="graph-risk-relationship" className="mb-1 block text-xs font-medium text-muted">Relationship</label>
                      <select id="graph-risk-relationship" className="field" value={graphFilters.relationship} onChange={(event) => updateGraph({ relationship: event.target.value as RiskFilters["relationship"] })}>
                        <option value="">All</option>
                        <option value="DIRECT">Direct</option>
                        <option value="TRANSITIVE">Transitive</option>
                      </select>
                    </div>
                    <fieldset className="flex flex-wrap items-center gap-x-4 gap-y-1 pb-2 text-sm">
                      <legend className="sr-only">Show only</legend>
                      <label className="flex items-center gap-1.5"><input type="checkbox" checked={graphFilters.vulnerable} onChange={(event) => updateGraph({ vulnerable: event.target.checked })} /> Vulnerable</label>
                      <label className="flex items-center gap-1.5"><input type="checkbox" checked={graphFilters.reachable} onChange={(event) => updateGraph({ reachable: event.target.checked })} /> Reachable</label>
                      <label className="flex items-center gap-1.5" title={`At least ${CENTRALITY_THRESHOLD * 100}% of the highest centrality in this graph`}>
                        <input type="checkbox" checked={graphFilters.central} onChange={(event) => updateGraph({ central: event.target.checked })} /> High centrality
                      </label>
                    </fieldset>
                  </div>

                  <p className="mt-3 text-sm text-muted" data-testid="risk-graph-summary">
                    Showing {layout.nodes.length - 1} of {graph.data.nodes.length} packages and {layout.edges.length} of {graph.data.edges.length} edges
                    {layout.hidden > 0 && <span className="text-warn"> · {layout.hidden} matching packages are not drawn; narrow the filters to see them</span>}
                  </p>

                  <div className="mt-3 grid gap-4 lg:grid-cols-[minmax(0,1fr)_380px]">
                    <div>
                      {layout.nodes.length === 1 ? (
                        <div className="card border-dashed px-6 py-10 text-center text-sm text-muted" data-testid="graph-no-match">No packages match these filters.</div>
                      ) : (
                        <RiskGraph layout={layout} selectedId={selectedNode} onSelect={setSelectedNode} viewKey={JSON.stringify(graphFilters)} />
                      )}
                      <ul className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-xs text-muted" data-testid="risk-graph-legend">
                        <li><span className="mr-1.5 inline-block h-2.5 w-2.5 rounded-sm border border-danger bg-danger-soft align-middle" />High predictive risk</li>
                        <li><span className="mr-1.5 inline-block h-2.5 w-2.5 rounded-sm border border-warn bg-warn-soft align-middle" />Medium</li>
                        <li><span className="mr-1.5 inline-block h-2.5 w-2.5 rounded-sm border border-line bg-surface align-middle" />Low</li>
                        <li><span className="mr-1.5 inline-block h-0.5 w-4 bg-danger align-middle" />Leads to a package with a known vulnerability</li>
                        <li>Only packages and dependency edges found in the repository are drawn.</li>
                      </ul>
                    </div>
                    <aside className="card h-fit max-h-[720px] overflow-y-auto p-4" aria-label="Selected package" data-testid="risk-graph-details">
                      {!selected ? (
                        <p className="text-sm text-muted">Select a package in the graph to see its scores and the evidence behind them.</p>
                      ) : (
                        <>
                          <div className="flex items-start justify-between gap-2">
                            <div className="min-w-0">
                              <div className="eyebrow">{selected.relationship.toLowerCase()} · depth {selected.depth ?? "unknown"}</div>
                              <h3 className="break-all font-mono text-sm font-semibold">{selected.package_name}{selected.version ? `@${selected.version}` : ""}</h3>
                            </div>
                            <button type="button" className="rounded p-1 text-muted hover:text-ink" onClick={() => setSelectedNode(null)} aria-label="Close details"><FiX aria-hidden /></button>
                          </div>
                          <div className="mt-3">
                            {!selectedDetail ? <Spinner label="Loading evidence" />
                              : "error" in selectedDetail ? <ErrorNotice message={selectedDetail.error} onRetry={() => void loadDetail(selected.dependency_id)} />
                              : <DependencyDetail detail={selectedDetail} compact />}
                          </div>
                        </>
                      )}
                    </aside>
                  </div>
                </>
              )}

              <div className="mt-8"><AnalysisChanges projectId={id} analysisId={analysis.id} kind={analysis.kind} /></div>

              <p className="mt-6 max-w-3xl text-xs text-muted" data-testid="intelligence-meaning">
                <strong className="font-semibold">These are estimates, not forecasts.</strong> This system estimates dependency fragility and predictive
                risk indicators. It does not guarantee prediction of future vulnerabilities or attacks. Scores are deterministic sums of the
                factors shown with them; a factor without data is unknown and adds nothing. A low score is not a statement that a dependency is safe.
              </p>
            </>
          )}
        </>
      )}
    </ProjectPageShell>
  );
}
