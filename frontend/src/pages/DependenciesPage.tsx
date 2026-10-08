import { Fragment, useEffect, useState } from "react";
import { FiChevronDown, FiChevronRight, FiSearch } from "react-icons/fi";
import { useParams } from "react-router-dom";

import { DependencyEvidence } from "../components/analysis/EvidenceList";
import { NotAnalysed, ProjectPageShell } from "../components/analysis/ProjectPageShell";
import { ErrorNotice, Spinner } from "../components/Feedback";
import { BasisBadge, RelationshipLabel } from "../components/StatusBadge";
import { StatTile } from "../components/StatTile";
import { useAsync } from "../hooks/useAsync";
import { getSnapshot, listDependencies } from "../services/analysis";
import { ecosystemLabel, formatDateTime, shortSha } from "../utils/format";
import type { DependencyList } from "../utils/types";

const PAGE_SIZE = 50;

interface Loaded {
  /** null when the project has no completed analysis. */
  list: DependencyList | null;
}

export function DependenciesPage() {
  const { id = "" } = useParams();
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");
  const [ecosystem, setEcosystem] = useState("");
  const [relationship, setRelationship] = useState("");
  const [unresolvedOnly, setUnresolvedOnly] = useState(false);
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [repositoryUrl, setRepositoryUrl] = useState<string | null>(null);

  // Wait for typing to pause before searching. The page is reset only when the
  // search text really changed, so paging is not undone by this timer.
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
    try {
      const list = await listDependencies(id, {
        q: query,
        ecosystem,
        relationship,
        version_status: unresolvedOnly ? "UNRESOLVED" : undefined,
        skip: page * PAGE_SIZE,
        limit: PAGE_SIZE,
      });
      return { list };
    } catch (caught) {
      if ((caught as { response?: { status?: number } }).response?.status === 404) return { list: null };
      throw caught;
    }
  }, [id, query, ecosystem, relationship, unresolvedOnly, page]);

  useEffect(() => {
    let cancelled = false;
    getSnapshot(id)
      .then((snapshot) => {
        if (!cancelled) setRepositoryUrl(snapshot.repository_url);
      })
      .catch(() => undefined); // only used to link evidence to GitHub; the page works without it
    return () => {
      cancelled = true;
    };
  }, [id]);

  const list = data?.list ?? null;
  const summary = list?.summary;
  const filtered = query !== "" || ecosystem !== "" || relationship !== "" || unresolvedOnly;
  const pages = list ? Math.max(1, Math.ceil(list.total / PAGE_SIZE)) : 1;

  return (
    <ProjectPageShell projectId={id}>
      {loading && !data ? (
        <Spinner label="Loading dependencies" />
      ) : error && !data ? (
        <ErrorNotice message={error} onRetry={() => void reload()} />
      ) : !list ? (
        <NotAnalysed projectId={id} />
      ) : (
        <>
          {summary && (
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-6" data-testid="dependency-stats">
              <StatTile label="Total dependencies" value={summary.total} />
              <StatTile label="Direct" value={summary.direct} />
              <StatTile label="Transitive" value={summary.transitive} />
              <StatTile label="Unresolved versions" value={summary.unresolved_versions} />
              <StatTile label="Dependency depth" value={summary.max_depth} note={summary.without_path > 0 ? `${summary.without_path} without an established path` : undefined} />
              <StatTile label="Relationship unknown" value={summary.relationship_unknown} />
            </div>
          )}

          <dl className="mt-4 flex flex-wrap gap-x-8 gap-y-2 text-sm">
            <div>
              <dt className="eyebrow inline">Ecosystems </dt>
              <dd className="inline">{summary && Object.keys(summary.by_ecosystem).length ? Object.entries(summary.by_ecosystem).map(([name, count]) => `${ecosystemLabel(name)} ${count}`).join(" · ") : "—"}</dd>
            </div>
            <div>
              <dt className="eyebrow inline">Package managers </dt>
              <dd className="inline">{summary && Object.keys(summary.by_package_manager).length ? Object.entries(summary.by_package_manager).map(([name, count]) => `${name} ${count}`).join(" · ") : "—"}</dd>
            </div>
            <div>
              <dt className="eyebrow inline">Snapshot </dt>
              <dd className="inline font-mono" title={list.snapshot.commit_sha}>{shortSha(list.snapshot.commit_sha)}</dd>
            </div>
            <div>
              <dt className="eyebrow inline">Analysed </dt>
              <dd className="inline">{formatDateTime(list.snapshot.collected_at)}</dd>
            </div>
          </dl>

          {summary && summary.total === 0 ? (
            <div className="card mt-6 border-dashed px-6 py-10 text-center" data-testid="no-dependencies">
              <h2 className="text-base font-semibold">No dependencies were found</h2>
              <p className="mx-auto mt-1.5 max-w-md text-sm text-muted">
                The analysis completed, but no dependency declarations were extracted from this repository. The project
                overview lists the dependency files that were found and how each was handled.
              </p>
            </div>
          ) : (
            <>
              <div className="mt-6 flex flex-wrap items-end gap-3">
                <div className="min-w-[220px] flex-1">
                  <label htmlFor="dependency-search" className="mb-1 block text-xs font-medium text-muted">Search by name</label>
                  <div className="relative">
                    <FiSearch aria-hidden className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint" />
                    <input id="dependency-search" className="field pl-9" value={search} onChange={(event) => setSearch(event.target.value)} maxLength={100} placeholder="e.g. requests" />
                  </div>
                </div>
                <div>
                  <label htmlFor="dependency-ecosystem" className="mb-1 block text-xs font-medium text-muted">Ecosystem</label>
                  <select id="dependency-ecosystem" className="field" value={ecosystem} onChange={(event) => { setEcosystem(event.target.value); setPage(0); }}>
                    <option value="">All</option>
                    {summary && Object.keys(summary.by_ecosystem).sort().map((name) => <option key={name} value={name}>{ecosystemLabel(name)}</option>)}
                  </select>
                </div>
                <div>
                  <label htmlFor="dependency-relationship" className="mb-1 block text-xs font-medium text-muted">Relationship</label>
                  <select id="dependency-relationship" className="field" value={relationship} onChange={(event) => { setRelationship(event.target.value); setPage(0); }}>
                    <option value="">All</option>
                    <option value="DIRECT">Direct</option>
                    <option value="TRANSITIVE">Transitive</option>
                    <option value="UNKNOWN">Unknown</option>
                  </select>
                </div>
                <label className="flex items-center gap-2 pb-2 text-sm">
                  <input type="checkbox" checked={unresolvedOnly} onChange={(event) => { setUnresolvedOnly(event.target.checked); setPage(0); }} />
                  Unresolved versions only
                </label>
              </div>

              {error && <div className="mt-4"><ErrorNotice message={error} onRetry={() => void reload()} /></div>}

              <div className="card mt-4 overflow-x-auto">
                <table className="w-full min-w-[760px] text-left text-sm" data-testid="dependency-table">
                  <thead>
                    <tr className="border-b border-line">
                      <th className="w-8 px-2 py-2.5"><span className="sr-only">Details</span></th>
                      <th className="eyebrow px-3 py-2.5 font-medium">Package</th>
                      <th className="eyebrow px-3 py-2.5 font-medium">Version</th>
                      <th className="eyebrow px-3 py-2.5 font-medium">Ecosystem</th>
                      <th className="eyebrow px-3 py-2.5 font-medium">Relationship</th>
                      <th className="eyebrow px-3 py-2.5 font-medium">Depth</th>
                      <th className="eyebrow px-3 py-2.5 font-medium">Scope</th>
                      <th className="eyebrow px-3 py-2.5 font-medium">Declared in</th>
                    </tr>
                  </thead>
                  <tbody>
                    {list.items.length === 0 && (
                      <tr>
                        <td colSpan={8} className="px-4 py-8 text-center text-sm text-muted">
                          No dependencies match {filtered ? "these filters" : "this view"}.
                        </td>
                      </tr>
                    )}
                    {list.items.map((dependency) => {
                      const open = expanded === dependency.node_id;
                      const files = [...new Set(dependency.evidence.map((item) => item.source_file))];
                      return (
                        <Fragment key={dependency.node_id}>
                          <tr className={`border-b border-line ${open ? "bg-paper/60" : "hover:bg-paper/60"}`}>
                            <td className="px-2 py-2">
                              <button type="button" className="rounded p-1 text-muted hover:text-ink" aria-expanded={open} aria-label={`${open ? "Hide" : "Show"} evidence for ${dependency.name}`} onClick={() => setExpanded(open ? null : dependency.node_id)}>
                                {open ? <FiChevronDown aria-hidden /> : <FiChevronRight aria-hidden />}
                              </button>
                            </td>
                            <td className="max-w-[260px] break-all px-3 py-2 font-mono text-[13px] font-medium">{dependency.name}</td>
                            <td className="px-3 py-2 font-mono text-[13px]">
                              {dependency.version ?? <span className="text-warn" title={dependency.version_reason}>unresolved</span>}
                              {!dependency.version && dependency.constraints[0] && <span className="ml-1.5 text-xs text-muted">({dependency.constraints[0]})</span>}
                            </td>
                            <td className="px-3 py-2">{ecosystemLabel(dependency.ecosystem)}</td>
                            <td className="whitespace-nowrap px-3 py-2">
                              <RelationshipLabel relationship={dependency.relationship} /> <BasisBadge basis={dependency.relationship_basis} />
                            </td>
                            <td className="px-3 py-2 font-mono">{dependency.depth ?? "—"}</td>
                            <td className="px-3 py-2 text-muted">{dependency.scopes.join(", ")}</td>
                            <td className="max-w-[220px] break-all px-3 py-2 font-mono text-xs text-muted">
                              {files[0]}{files.length > 1 && ` +${files.length - 1}`}
                            </td>
                          </tr>
                          {open && (
                            <tr className="border-b border-line bg-paper/60">
                              <td />
                              <td colSpan={7} className="px-3 pb-4 pt-1">
                                <DependencyEvidence dependency={dependency} repositoryUrl={repositoryUrl ?? undefined} commitSha={list.snapshot.commit_sha} />
                              </td>
                            </tr>
                          )}
                        </Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              <div className="mt-3 flex flex-wrap items-center justify-between gap-3 text-sm text-muted">
                <span>
                  {list.total === 0 ? "0 dependencies" : `${list.skip + 1}–${list.skip + list.items.length} of ${list.total}`}
                  {filtered && summary ? ` (filtered from ${summary.total})` : ""}
                </span>
                {pages > 1 && (
                  <div className="flex items-center gap-2">
                    <button type="button" className="btn btn-secondary" disabled={page === 0 || loading} onClick={() => setPage((value) => value - 1)}>Previous</button>
                    <span>Page {page + 1} of {pages}</span>
                    <button type="button" className="btn btn-secondary" disabled={page + 1 >= pages || loading} onClick={() => setPage((value) => value + 1)}>Next</button>
                  </div>
                )}
              </div>
              <p className="mt-4 max-w-3xl text-xs text-muted">
                <strong>OBSERVED</strong> means read directly from a repository file. <strong>INFERRED</strong> means derived
                by a stated rule. <strong>UNKNOWN</strong> means the files do not establish it. Open a row to see the rule and
                the files behind each classification.
              </p>
            </>
          )}
        </>
      )}
    </ProjectPageShell>
  );
}
