import { useCallback, useEffect, useState } from "react";
import { FiCheckCircle, FiDownload, FiFileText, FiSearch, FiXCircle } from "react-icons/fi";
import { Link, useParams } from "react-router-dom";

import { JobPanel } from "../components/analysis/JobPanel";
import { NotAnalysed, ProjectPageShell } from "../components/analysis/ProjectPageShell";
import { ErrorNotice, Spinner } from "../components/Feedback";
import { Badge, SeverityBadge } from "../components/StatusBadge";
import { useAsync } from "../hooks/useAsync";
import { useProjectJobs } from "../hooks/useProjectJobs";
import { diffSboms, downloadSbom, listSbomComponents, listSboms, startSbomGeneration, verifySbom } from "../services/security";
import { errorMessage } from "../utils/errors";
import { ecosystemLabel, formatBytes, formatDateTime, shortSha } from "../utils/format";
import type { JobType, SbomDiff, SbomRecord, SbomVerification } from "../utils/types";

const JOB_TYPES: JobType[] = ["sbom_generation"];
const PAGE_SIZE = 50;

const CHECK_LABELS: Record<string, string> = {
  stored_document_readable: "Stored document can be read",
  stored_document_digest: "Stored document matches its recorded digest",
  canonical_form: "Stored document is in canonical form",
  content_digest: "Content matches the recorded content digest",
  component_records: "Component records match the document",
  regeneration: "Regenerating from the snapshot gives the same content",
};

function IntegrityBadge({ sbom }: { sbom: SbomRecord }) {
  if (!sbom.last_verification) return <Badge tone="neutral">Not verified yet</Badge>;
  return sbom.last_verification.valid ? <Badge tone="good">Verified</Badge> : <Badge tone="bad">Verification failed</Badge>;
}

function versionText(versions: (string | null)[]): string {
  return versions.map((version) => version ?? "unresolved").join(", ");
}

function DiffView({ diff }: { diff: SbomDiff }) {
  const { summary } = diff;
  if (summary.added + summary.removed + summary.changed === 0 && summary.relationships_added + summary.relationships_removed === 0) {
    return (
      <p className="mt-3 text-sm text-muted" data-testid="diff-empty">
        No components or relationships differ between these two SBOMs
        {summary.document_changes > 0 ? "; only what they describe (commit, snapshot) differs." : "."}
      </p>
    );
  }
  return (
    <div className="mt-3" data-testid="sbom-diff">
      <div className="flex flex-wrap gap-2 text-sm">
        <Badge tone="good">{`${summary.added} added`}</Badge>
        <Badge tone="bad">{`${summary.removed} removed`}</Badge>
        <Badge tone="warn">{`${summary.changed} changed`}</Badge>
        <span className="text-muted">
          {summary.components_before} → {summary.components_after} components · {summary.relationships_added} relationship(s) added,{" "}
          {summary.relationships_removed} removed
        </span>
      </div>
      {diff.items.length > 0 && (
        <div className="mt-3 overflow-x-auto">
          <table className="w-full min-w-[640px] text-left text-sm">
            <thead>
              <tr className="border-b border-line">
                <th className="eyebrow px-3 py-2 font-medium">Change</th>
                <th className="eyebrow px-3 py-2 font-medium">Component</th>
                <th className="eyebrow px-3 py-2 font-medium">Before</th>
                <th className="eyebrow px-3 py-2 font-medium">After</th>
                <th className="eyebrow px-3 py-2 font-medium">What changed</th>
              </tr>
            </thead>
            <tbody>
              {diff.items.map((item) => (
                <tr key={`${item.ecosystem}:${item.name}`} className="border-b border-line last:border-0">
                  <td className="px-3 py-2">
                    <Badge tone={item.change === "ADDED" ? "good" : item.change === "REMOVED" ? "bad" : "warn"}>{item.change}</Badge>
                  </td>
                  <td className="px-3 py-2">
                    <span className="font-mono text-[13px]">{item.name}</span> <span className="text-xs text-muted">{ecosystemLabel(item.ecosystem)}</span>
                  </td>
                  <td className="px-3 py-2 font-mono text-[13px]">{item.old_versions.length ? versionText(item.old_versions) : "—"}</td>
                  <td className="px-3 py-2 font-mono text-[13px]">{item.new_versions.length ? versionText(item.new_versions) : "—"}</td>
                  <td className="px-3 py-2 text-xs text-muted">
                    {item.change === "ADDED" ? "Newly introduced dependency" : item.change === "REMOVED" ? "Dependency removed"
                      : item.change_type === "version" ? "Version" : `Metadata: ${Array.from(new Set((item.fields ?? []).map((f) => f.field))).join(", ")}`}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {diff.items_truncated && <p className="mt-2 text-xs text-muted">The list is truncated; download both SBOMs to compare them in full.</p>}
        </div>
      )}
      {(diff.ecosystem_changes ?? []).map((change) => (
        <p key={`${change.name}-${change.new_ecosystem}`} className="mt-2 text-xs text-muted">
          <Badge tone="warn">INFERRED</Badge> <span className="font-mono">{change.name}</span> left {ecosystemLabel(change.old_ecosystem)} and appeared in{" "}
          {ecosystemLabel(change.new_ecosystem)}. Equal names in different ecosystems are not necessarily the same software.
        </p>
      ))}
    </div>
  );
}

export function SbomPage() {
  const { id = "" } = useParams();
  const { data, error, loading, reload } = useAsync(() => listSboms(id), [id]);
  const [selected, setSelected] = useState<string | null>(null);
  const [verification, setVerification] = useState<SbomVerification | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [baseId, setBaseId] = useState<string>("");
  const [diff, setDiff] = useState<SbomDiff | null>(null);
  const [diffError, setDiffError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");
  const [onlyVulnerable, setOnlyVulnerable] = useState(false);
  const [page, setPage] = useState(0);

  const refresh = useCallback(() => {
    setSelected(null);
    setVerification(null);
    void reload({ silent: true });
  }, [reload]);
  const jobs = useProjectJobs(id, JOB_TYPES, refresh);

  const history = data?.history ?? [];
  const current = history.find((entry) => entry.id === selected) ?? data?.latest ?? null;
  const currentId = current?.id ?? null;
  const others = history.filter((entry) => entry.id !== currentId);
  const defaultBase = current?.previous_sbom_id && others.some((entry) => entry.id === current.previous_sbom_id) ? current.previous_sbom_id : others[0]?.id ?? "";
  const effectiveBase = others.some((entry) => entry.id === baseId) ? baseId : defaultBase;

  useEffect(() => {
    const next = search.trim();
    if (next === query) return;
    const timer = window.setTimeout(() => {
      setQuery(next);
      setPage(0);
    }, 300);
    return () => window.clearTimeout(timer);
  }, [search, query]);

  useEffect(() => {
    setDiff(null);
    setDiffError(null);
    if (!currentId || !effectiveBase) return;
    let cancelled = false;
    diffSboms(id, effectiveBase, currentId)
      .then((result) => {
        if (!cancelled) setDiff(result);
      })
      .catch((caught) => {
        if (!cancelled) setDiffError(errorMessage(caught));
      });
    return () => {
      cancelled = true;
    };
  }, [id, currentId, effectiveBase]);

  const components = useAsync(
    () => (currentId ? listSbomComponents(id, currentId, { q: query, only_vulnerable: onlyVulnerable, skip: page * PAGE_SIZE, limit: PAGE_SIZE }) : Promise.resolve(null)),
    [id, currentId, query, onlyVulnerable, page],
  );

  async function handleVerify() {
    if (!current) return;
    setVerifying(true);
    setActionError(null);
    try {
      setVerification(await verifySbom(id, current.id));
      void reload({ silent: true });
    } catch (caught) {
      setActionError(errorMessage(caught));
    } finally {
      setVerifying(false);
    }
  }

  async function handleDownload() {
    if (!current) return;
    setActionError(null);
    try {
      await downloadSbom(id, current.id, `sbom-v${current.version}-${current.commit_sha.slice(0, 10)}.cdx.json`);
    } catch (caught) {
      setActionError(errorMessage(caught, "The SBOM could not be downloaded."));
    }
  }

  function select(sbomId: string) {
    setSelected(sbomId);
    setVerification(null);
    setActionError(null);
    setPage(0);
  }

  const shownVerification = verification && verification.sbom_id === currentId ? verification : null;
  const componentPages = components.data ? Math.max(1, Math.ceil(components.data.total / PAGE_SIZE)) : 1;
  const linkage = components.data?.vulnerability_linkage ?? current?.vulnerability_linkage ?? null;

  return (
    <ProjectPageShell projectId={id}>
      {loading && !data ? (
        <Spinner label="Loading SBOMs" />
      ) : error && !data ? (
        <ErrorNotice message={error} onRetry={() => void reload()} />
      ) : !data || !data.has_inventory ? (
        <NotAnalysed projectId={id} />
      ) : (
        <>
          <JobPanel
            title="SBOM generation"
            testId="sbom-job"
            jobs={jobs}
            idle="Generates a CycloneDX SBOM from the dependency inventory of the latest snapshot. Only what the repository files establish is written: no licences, hashes or versions are filled in."
            failureNote="SBOM generation failed. No SBOM was stored from this run."
            actions={
              <button type="button" className="btn btn-primary" disabled={jobs.loading || jobs.busy || jobs.starting} onClick={() => void jobs.run(() => startSbomGeneration(id))}>
                <FiFileText aria-hidden /> {jobs.running ? "Generation in progress" : jobs.starting ? "Starting…" : data.latest ? "Generate again" : "Generate SBOM"}
              </button>
            }
          />

          {!current ? (
            <div className="card mt-6 border-dashed px-6 py-10 text-center" data-testid="no-sbom">
              <h2 className="text-base font-semibold">No SBOM has been generated for this project</h2>
              <p className="mx-auto mt-1.5 max-w-xl text-sm text-muted">
                An SBOM is generated from the dependency inventory of a snapshot and kept with a digest so that later changes can be detected.
              </p>
            </div>
          ) : (
            <>
              <section className="card mt-6 p-5" data-testid="sbom-summary">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <h2 className="text-base font-semibold">SBOM version {current.version}</h2>
                      <IntegrityBadge sbom={current} />
                      {current.id !== data.latest?.id && <Badge tone="neutral">Earlier version</Badge>}
                    </div>
                    <p className="mt-0.5 text-sm text-muted">
                      {current.format} {current.spec_version} JSON · generated {formatDateTime(current.generated_at)} by {current.generator.name}{" "}
                      {current.generator.version}
                    </p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <button type="button" className="btn btn-secondary" onClick={() => void handleVerify()} disabled={verifying}>
                      <FiCheckCircle aria-hidden /> {verifying ? "Verifying…" : "Verify integrity"}
                    </button>
                    <button type="button" className="btn btn-secondary" onClick={() => void handleDownload()}>
                      <FiDownload aria-hidden /> Download
                    </button>
                  </div>
                </div>

                {actionError && (
                  <div className="mt-4">
                    <ErrorNotice message={actionError} />
                  </div>
                )}

                <dl className="mt-5 grid grid-cols-2 gap-x-6 gap-y-4 text-sm lg:grid-cols-4">
                  <div>
                    <dt className="eyebrow">Snapshot</dt>
                    <dd className="mt-1 font-mono" title={current.commit_sha}>{shortSha(current.commit_sha)}{current.branch ? ` · ${current.branch}` : ""}</dd>
                  </div>
                  <div>
                    <dt className="eyebrow">Components</dt>
                    <dd className="mt-1 font-mono">{current.component_count}</dd>
                    <dd className="text-xs text-muted">{current.unresolved_components} without a resolved version · {current.components_with_hashes} with a recorded hash</dd>
                  </div>
                  <div>
                    <dt className="eyebrow">Relationships</dt>
                    <dd className="mt-1 font-mono">{current.relationship_count}</dd>
                  </div>
                  <div>
                    <dt className="eyebrow">Completeness</dt>
                    <dd className="mt-1">{current.completeness === "incomplete" ? "Known to be incomplete" : "Not established"}</dd>
                    <dd className="text-xs text-muted">
                      {current.completeness === "incomplete" ? "Some dependency files or versions could not be resolved" : "Repository files alone cannot prove completeness"}
                    </dd>
                  </div>
                  <div className="col-span-2">
                    <dt className="eyebrow">Content digest ({current.digest_algorithm})</dt>
                    <dd className="mt-1 break-all font-mono text-xs" data-testid="content-digest">{current.content_digest}</dd>
                    <dd className="text-xs text-muted">Same for every SBOM generated from the same inventory</dd>
                  </div>
                  <div className="col-span-2">
                    <dt className="eyebrow">Document digest ({current.digest_algorithm})</dt>
                    <dd className="mt-1 break-all font-mono text-xs">{current.document_digest}</dd>
                    <dd className="text-xs text-muted">Of the stored file, {formatBytes(current.document_size)}</dd>
                  </div>
                </dl>

                {shownVerification ? (
                  <div className={`mt-5 rounded-md px-4 py-3 text-sm ${shownVerification.valid ? "bg-trust-soft text-trust-strong" : "bg-danger-soft text-danger"}`}
                    role={shownVerification.valid ? "status" : "alert"} data-testid="verification-result">
                    <p className="flex items-center gap-2 font-semibold">
                      {shownVerification.valid ? <FiCheckCircle aria-hidden /> : <FiXCircle aria-hidden />}
                      {shownVerification.valid ? "Integrity verified" : "Integrity verification failed"}
                      <span className="font-normal opacity-80">· {formatDateTime(shownVerification.verified_at)}</span>
                    </p>
                    <ul className="mt-2 space-y-1">
                      {shownVerification.checks.map((check) => (
                        <li key={check.name} className="flex items-start gap-2">
                          {check.ok ? <FiCheckCircle aria-hidden className="mt-0.5 shrink-0" /> : <FiXCircle aria-hidden className="mt-0.5 shrink-0" />}
                          <span>
                            <span className="font-medium">{CHECK_LABELS[check.name] ?? check.name}</span>
                            {!check.ok && <span className="block text-xs">{check.detail}</span>}
                          </span>
                        </li>
                      ))}
                    </ul>
                    {shownVerification.difference_from_regenerated && (
                      <p className="mt-2 text-xs">
                        Compared with a fresh generation from the snapshot: {shownVerification.difference_from_regenerated.summary.added} added,{" "}
                        {shownVerification.difference_from_regenerated.summary.removed} removed,{" "}
                        {shownVerification.difference_from_regenerated.summary.changed} changed component(s);{" "}
                        {shownVerification.difference_from_regenerated.summary.relationships_added + shownVerification.difference_from_regenerated.summary.relationships_removed} relationship
                        difference(s); {shownVerification.difference_from_regenerated.document_changes.length} document field(s).
                      </p>
                    )}
                    <p className="mt-2 text-xs opacity-80">{shownVerification.meaning}</p>
                  </div>
                ) : (
                  <p className="mt-5 text-xs text-muted">
                    {current.last_verification
                      ? `Last verified ${formatDateTime(current.last_verification.verified_at)}: ${current.last_verification.valid ? "valid" : `failed (${current.last_verification.failed_checks.join(", ")})`}.`
                      : "This SBOM is integrity-verifiable: it can be checked against its recorded digests and against a fresh generation from its snapshot. It is not cryptographically signed."}
                  </p>
                )}
              </section>

              <section className="card mt-6 p-5" data-testid="sbom-linkage">
                <h2 className="text-base font-semibold">Vulnerability linkage</h2>
                {linkage && linkage.latest_match_at ? (
                  <p className="mt-1 text-sm text-ink-soft">
                    {linkage.components_with_matches} component{linkage.components_with_matches === 1 ? "" : "s"} of this SBOM {linkage.components_with_matches === 1 ? "has" : "have"}{" "}
                    {linkage.affected_matches} stored advisory match{linkage.affected_matches === 1 ? "" : "es"} (last matched {formatDateTime(linkage.latest_match_at)}).{" "}
                    <Link to={`/projects/${id}/vulnerabilities`} className="font-medium text-trust hover:underline">View findings</Link>
                  </p>
                ) : (
                  <p className="mt-1 text-sm text-muted">
                    No advisory matches are stored for this SBOM&apos;s snapshot. That means no affected versions were found, or no vulnerability check
                    has been run for it. <Link to={`/projects/${id}/vulnerabilities`} className="font-medium text-trust hover:underline">Open the vulnerability check</Link>
                  </p>
                )}
              </section>

              <section className="card mt-6 p-5" data-testid="sbom-changes">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <h2 className="text-base font-semibold">Changes</h2>
                  {others.length > 0 && (
                    <label className="flex items-center gap-2 text-sm text-muted">
                      Compared with
                      <select className="field w-auto" value={effectiveBase} onChange={(event) => setBaseId(event.target.value)} aria-label="SBOM version to compare with">
                        {others.map((entry) => <option key={entry.id} value={entry.id}>{`version ${entry.version} (${shortSha(entry.commit_sha)})`}</option>)}
                      </select>
                    </label>
                  )}
                </div>
                {others.length === 0 ? (
                  <p className="mt-2 text-sm text-muted">This is the only SBOM of the project, so there is nothing to compare it with yet.</p>
                ) : diffError ? (
                  <div className="mt-3"><ErrorNotice message={diffError} /></div>
                ) : !diff ? (
                  <Spinner label="Comparing" />
                ) : (
                  <DiffView diff={diff} />
                )}
              </section>

              <section className="mt-6" data-testid="sbom-components">
                <div className="flex flex-wrap items-end justify-between gap-3">
                  <h2 className="text-base font-semibold">Components</h2>
                  <div className="flex flex-wrap items-end gap-3">
                    <div className="relative">
                      <FiSearch aria-hidden className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint" />
                      <input className="field pl-9" value={search} onChange={(event) => setSearch(event.target.value)} maxLength={100} placeholder="Search by name" aria-label="Search components by name" />
                    </div>
                    <label className="flex items-center gap-2 pb-2 text-sm">
                      <input type="checkbox" checked={onlyVulnerable} onChange={(event) => { setOnlyVulnerable(event.target.checked); setPage(0); }} />
                      With advisory matches only
                    </label>
                  </div>
                </div>
                {components.loading && !components.data ? (
                  <Spinner label="Loading components" />
                ) : components.error && !components.data ? (
                  <div className="mt-3"><ErrorNotice message={components.error} onRetry={() => void components.reload()} /></div>
                ) : components.data && components.data.total === 0 ? (
                  <p className="card mt-3 px-5 py-6 text-center text-sm text-muted">
                    {query || onlyVulnerable ? "No components match these filters." : "This SBOM has no components: no dependencies were found in the snapshot."}
                  </p>
                ) : components.data && (
                  <>
                    <div className="card mt-3 overflow-x-auto">
                      <table className="w-full min-w-[820px] text-left text-sm" data-testid="component-table">
                        <thead>
                          <tr className="border-b border-line">
                            <th className="eyebrow px-3 py-2.5 font-medium">Component</th>
                            <th className="eyebrow px-3 py-2.5 font-medium">Version</th>
                            <th className="eyebrow px-3 py-2.5 font-medium">Ecosystem</th>
                            <th className="eyebrow px-3 py-2.5 font-medium">Package URL</th>
                            <th className="eyebrow px-3 py-2.5 font-medium">Hash</th>
                            <th className="eyebrow px-3 py-2.5 font-medium">Advisory matches</th>
                          </tr>
                        </thead>
                        <tbody>
                          {components.data.items.map((item) => (
                            <tr key={item.bom_ref} className="border-b border-line last:border-0">
                              <td className="px-3 py-2 font-mono text-[13px]">{item.name}</td>
                              <td className="px-3 py-2 font-mono text-[13px]">{item.version ?? <span className="text-muted">unresolved</span>}</td>
                              <td className="px-3 py-2">{item.ecosystem ? ecosystemLabel(item.ecosystem) : "—"}</td>
                              <td className="max-w-[260px] truncate px-3 py-2 font-mono text-xs" title={item.purl ?? undefined}>{item.purl ?? "—"}</td>
                              <td className="px-3 py-2 font-mono text-xs">{item.hashes.length ? item.hashes[0].alg : <span className="text-muted">none recorded</span>}</td>
                              <td className="px-3 py-2">
                                {item.vulnerabilities.length === 0 ? <span className="text-muted">—</span> : (
                                  <span className="flex flex-wrap items-center gap-1.5">
                                    {item.vulnerabilities.slice(0, 3).map((entry) => (
                                      <span key={entry.match_id} className="inline-flex items-center gap-1">
                                        <SeverityBadge severity={entry.severity} /> <span className="font-mono text-xs">{entry.source_id}</span>
                                      </span>
                                    ))}
                                    {item.vulnerabilities.length > 3 && <span className="text-xs text-muted">+{item.vulnerabilities.length - 3} more</span>}
                                  </span>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <div className="mt-3 flex flex-wrap items-center justify-between gap-3 text-sm text-muted">
                      <span>{components.data.skip + 1}–{components.data.skip + components.data.items.length} of {components.data.total}</span>
                      {componentPages > 1 && (
                        <span className="flex items-center gap-2">
                          <button type="button" className="btn btn-secondary" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
                          <span>Page {page + 1} of {componentPages}</span>
                          <button type="button" className="btn btn-secondary" disabled={page + 1 >= componentPages} onClick={() => setPage(page + 1)}>Next</button>
                        </span>
                      )}
                    </div>
                  </>
                )}
              </section>

              <section className="mt-8" data-testid="sbom-history">
                <h2 className="text-base font-semibold">History</h2>
                <div className="card mt-3 overflow-x-auto">
                  <table className="w-full min-w-[720px] text-left text-sm">
                    <thead>
                      <tr className="border-b border-line">
                        <th className="eyebrow px-3 py-2.5 font-medium">Version</th>
                        <th className="eyebrow px-3 py-2.5 font-medium">Generated</th>
                        <th className="eyebrow px-3 py-2.5 font-medium">Snapshot</th>
                        <th className="eyebrow px-3 py-2.5 font-medium">Components</th>
                        <th className="eyebrow px-3 py-2.5 font-medium">Content digest</th>
                        <th className="eyebrow px-3 py-2.5 font-medium">Integrity</th>
                        <th className="px-3 py-2.5" />
                      </tr>
                    </thead>
                    <tbody>
                      {history.map((entry) => (
                        <tr key={entry.id} className={`border-b border-line last:border-0 ${entry.id === currentId ? "bg-paper/60" : ""}`}>
                          <td className="px-3 py-2 font-mono">{entry.version}</td>
                          <td className="whitespace-nowrap px-3 py-2">{formatDateTime(entry.generated_at)}</td>
                          <td className="px-3 py-2 font-mono text-[13px]">{shortSha(entry.commit_sha)}</td>
                          <td className="px-3 py-2 font-mono">{entry.component_count}</td>
                          <td className="px-3 py-2 font-mono text-xs" title={entry.content_digest}>{entry.content_digest.slice(0, 16)}…</td>
                          <td className="px-3 py-2"><IntegrityBadge sbom={entry} /></td>
                          <td className="px-3 py-2 text-right">
                            {entry.id === currentId ? <span className="text-xs text-muted">Shown above</span> : (
                              <button type="button" className="text-sm font-medium text-trust hover:underline" onClick={() => select(entry.id)}>
                                View version {entry.version}
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            </>
          )}
        </>
      )}
    </ProjectPageShell>
  );
}
