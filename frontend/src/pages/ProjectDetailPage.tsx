import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { FiArrowLeft, FiExternalLink, FiRefreshCw, FiTrash2 } from "react-icons/fi";
import { Link, useNavigate, useParams } from "react-router-dom";

import { AnalysisStatusCard } from "../components/analysis/AnalysisStatusCard";
import { ProjectTabs } from "../components/analysis/ProjectTabs";
import { DependencySummaryCard, LanguagesCard, PackageManagersCard, SnapshotCard } from "../components/analysis/SnapshotSections";
import { ErrorNotice, PageHeader, Spinner } from "../components/Feedback";
import { Badge, MetadataBadge } from "../components/StatusBadge";
import { useAnalysisStatus } from "../hooks/useAnalysisStatus";
import { useAsync } from "../hooks/useAsync";
import { getSnapshot } from "../services/analysis";
import { deleteProject, getProject, refreshMetadata } from "../services/projects";
import { errorMessage } from "../utils/errors";
import { formatCount, formatDate, formatDateTime, formatSize } from "../utils/format";

/** Evidence layers that later phases will add to this page. None of them exist yet. */
const PLANNED_ANALYSIS: { name: string; phase: number | null }[] = [
  { name: "Dependency fragility and predicted risk", phase: 5 },
  { name: "Attack-path simulation", phase: 7 },
  { name: "Maintainer and commit behaviour", phase: 8 },
  { name: "Cross-layer AI reasoning", phase: 10 },
  { name: "Trust score and security report", phase: 12 },
  { name: "Self-healing SBOM (verification of external SBOMs and repair)", phase: null },
];

const PENDING_POLL_MS = 2000;
const PENDING_POLL_LIMIT = 15;

function Fact({ label, children, mono = false }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div>
      <dt className="eyebrow">{label}</dt>
      <dd className={`mt-1 text-sm ${mono ? "font-mono" : ""}`}>{children}</dd>
    </div>
  );
}

export function ProjectDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const { data: project, error, loading, reload, setData } = useAsync(() => getProject(id), [id]);
  const [busy, setBusy] = useState<"refresh" | "delete" | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const polls = useRef(0);

  // Results are loaded only when a completed analysis exists, and again whenever a run finishes.
  const snapshot = useAsync(async () => {
    try {
      return await getSnapshot(id);
    } catch (caught) {
      const status = (caught as { response?: { status?: number } }).response?.status;
      if (status === 404) return null; // not analysed yet: an expected state, not an error
      throw caught;
    }
  }, [id]);
  const analysis = useAnalysisStatus(id, (state) => {
    if (state === "completed") {
      void snapshot.reload({ silent: true });
      void reload({ silent: true });
    }
  });

  // Metadata is fetched just after registration; keep checking until it settles.
  const pending = project?.repository?.metadata_status === "PENDING";
  useEffect(() => {
    if (!pending) {
      polls.current = 0;
      return;
    }
    if (polls.current >= PENDING_POLL_LIMIT) return;
    const timer = window.setTimeout(() => {
      polls.current += 1;
      void reload({ silent: true });
    }, PENDING_POLL_MS);
    return () => window.clearTimeout(timer);
  }, [pending, project, reload]);

  async function handleRefresh() {
    setActionError(null);
    setBusy("refresh");
    try {
      setData(await refreshMetadata(id));
    } catch (caught) {
      setActionError(errorMessage(caught));
    } finally {
      setBusy(null);
    }
  }

  async function handleDelete() {
    setActionError(null);
    setBusy("delete");
    try {
      await deleteProject(id);
      navigate("/projects", { replace: true });
    } catch (caught) {
      setActionError(errorMessage(caught));
      setBusy(null);
    }
  }

  if (loading && !project) return <Spinner label="Loading project" />;
  if (error && !project) {
    return (
      <div className="space-y-4">
        <ErrorNotice message={error} onRetry={() => void reload()} />
        <Link to="/projects" className="inline-flex items-center gap-1.5 text-sm font-medium text-trust hover:underline">
          <FiArrowLeft aria-hidden /> Back to projects
        </Link>
      </div>
    );
  }
  if (!project) return null;

  const repository = project.repository;
  const metadata = repository?.metadata ?? null;

  return (
    <>
      <Link to="/projects" className="mb-4 inline-flex items-center gap-1.5 text-sm text-muted hover:text-ink">
        <FiArrowLeft aria-hidden /> Projects
      </Link>

      <PageHeader eyebrow={repository?.full_name ?? "Project"} title={project.name}>
        <button type="button" className="btn btn-secondary" onClick={handleRefresh} disabled={busy !== null}>
          <FiRefreshCw aria-hidden className={busy === "refresh" ? "animate-spin" : ""} />
          {busy === "refresh" ? "Refreshing…" : "Refresh repository data"}
        </button>
        {confirmingDelete ? (
          <>
            <button type="button" className="btn btn-danger" onClick={handleDelete} disabled={busy !== null}>
              {busy === "delete" ? "Deleting…" : "Confirm delete"}
            </button>
            <button type="button" className="btn btn-secondary" onClick={() => setConfirmingDelete(false)} disabled={busy !== null}>
              Cancel
            </button>
          </>
        ) : (
          <button type="button" className="btn btn-danger" onClick={() => setConfirmingDelete(true)} disabled={busy !== null}>
            <FiTrash2 aria-hidden /> Delete
          </button>
        )}
      </PageHeader>

      <ProjectTabs projectId={id} />

      {actionError && (
        <div className="mb-4">
          <ErrorNotice message={actionError} />
        </div>
      )}

      {project.description && <p className="mb-6 max-w-3xl text-sm text-ink-soft">{project.description}</p>}

      <section className="card p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-base font-semibold">Repository</h2>
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={project.status === "ACTIVE" ? "good" : "neutral"}>{project.status}</Badge>
            {repository && <MetadataBadge status={repository.metadata_status} />}
          </div>
        </div>

        <a
          href={project.repository_url}
          target="_blank"
          rel="noopener noreferrer"
          className="mt-2 inline-flex items-center gap-1.5 break-all font-mono text-sm text-trust hover:underline"
        >
          {project.repository_url} <FiExternalLink aria-hidden className="shrink-0" />
        </a>

        {repository?.metadata_status === "UNAVAILABLE" && (
          <div className="mt-4 rounded-md bg-warn-soft px-4 py-3 text-sm text-warn">
            <strong className="font-semibold">Repository data could not be fetched.</strong>{" "}
            {repository.metadata_error ?? "GitHub did not return the repository."}
            {metadata && " The values below are from the last successful fetch."}
          </div>
        )}
        {repository?.metadata_status === "PENDING" && (
          <p className="mt-4 text-sm text-muted">Fetching repository data from GitHub…</p>
        )}

        {metadata && (
          <>
            {metadata.description && <p className="mt-4 max-w-3xl text-sm text-ink-soft">{metadata.description}</p>}
            <dl className="mt-5 grid grid-cols-2 gap-x-6 gap-y-5 sm:grid-cols-3 lg:grid-cols-4">
              <Fact label="Default branch" mono>{metadata.default_branch ?? "—"}</Fact>
              <Fact label="Primary language (GitHub)">{metadata.primary_language ?? "—"}</Fact>
              <Fact label="Licence" mono>{metadata.license ?? "—"}</Fact>
              <Fact label="Visibility">{metadata.visibility ?? "—"}</Fact>
              <Fact label="Stars" mono>{formatCount(metadata.stars)}</Fact>
              <Fact label="Forks" mono>{formatCount(metadata.forks)}</Fact>
              <Fact label="Open issues" mono>{formatCount(metadata.open_issues)}</Fact>
              <Fact label="Repository size" mono>{formatSize(metadata.size_kb)}</Fact>
              <Fact label="Created on GitHub">{formatDate(metadata.github_created_at)}</Fact>
              <Fact label="Last push">{formatDateTime(metadata.pushed_at)}</Fact>
              <Fact label="Archived">{metadata.archived === null ? "—" : metadata.archived ? "Yes" : "No"}</Fact>
              <Fact label="Fork">{metadata.is_fork === null ? "—" : metadata.is_fork ? "Yes" : "No"}</Fact>
            </dl>
            <p className="mt-5 text-xs text-muted">
              Observed from the GitHub API on {formatDateTime(repository?.metadata_fetched_at)}.
            </p>
          </>
        )}
      </section>

      <div className="mt-6">
        <AnalysisStatusCard analysis={analysis} />
      </div>

      {snapshot.error && !snapshot.data && (
        <div className="mt-6">
          <ErrorNotice message={snapshot.error} onRetry={() => void snapshot.reload()} />
        </div>
      )}

      {snapshot.data && (
        <div className="mt-6 space-y-6">
          <SnapshotCard snapshot={snapshot.data} />
          <DependencySummaryCard snapshot={snapshot.data} projectId={id} />
          <div className="grid gap-6 lg:grid-cols-2">
            <LanguagesCard snapshot={snapshot.data} />
            <PackageManagersCard snapshot={snapshot.data} />
          </div>
        </div>
      )}

      <section className="card mt-6 p-5">
        <h2 className="text-base font-semibold">Not yet available</h2>
        <p className="mt-1 max-w-3xl text-sm text-muted">
          Dependency analysis, vulnerability matching, static code reachability (Python) and SBOMs are available from the
          tabs above. How likely exploitation is, and any risk or trust figure, are not assessed: the parts of the platform
          that would produce them have not been built.
        </p>
        <ol className="mt-4 divide-y divide-line border-t border-line">
          {PLANNED_ANALYSIS.map((item) => (
            <li key={item.name} className="flex items-center justify-between gap-3 py-2.5 text-sm">
              <span>{item.name}</span>
              <span className="shrink-0 font-mono text-xs text-faint">{item.phase === null ? "Not scheduled" : `Phase ${item.phase}`} · not built</span>
            </li>
          ))}
        </ol>
      </section>

      <p className="mt-4 text-xs text-muted">
        Registered {formatDateTime(project.created_at)} · Updated {formatDateTime(project.updated_at)}
      </p>
    </>
  );
}
