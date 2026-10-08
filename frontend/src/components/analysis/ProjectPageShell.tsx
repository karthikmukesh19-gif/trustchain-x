import type { ReactNode } from "react";
import { FiArrowLeft } from "react-icons/fi";
import { Link } from "react-router-dom";

import { useAsync } from "../../hooks/useAsync";
import { getProject } from "../../services/projects";
import { ErrorNotice, PageHeader, Spinner } from "../Feedback";
import { ProjectTabs } from "./ProjectTabs";

/** Header and tabs shared by a project's dependency pages. Shows a clear error when the project cannot be loaded. */
export function ProjectPageShell({ projectId, actions, children }: { projectId: string; actions?: ReactNode; children: ReactNode }) {
  const { data: project, error, loading, reload } = useAsync(() => getProject(projectId), [projectId]);

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

  return (
    <>
      <Link to="/projects" className="mb-4 inline-flex items-center gap-1.5 text-sm text-muted hover:text-ink">
        <FiArrowLeft aria-hidden /> Projects
      </Link>
      <PageHeader eyebrow={project.repository?.full_name ?? "Project"} title={project.name}>
        {actions}
      </PageHeader>
      <ProjectTabs projectId={projectId} />
      {children}
    </>
  );
}

/** Shown on result pages when no completed analysis exists. */
export function NotAnalysed({ projectId }: { projectId: string }) {
  return (
    <div className="card border-dashed px-6 py-10 text-center" data-testid="not-analysed">
      <h2 className="text-base font-semibold">This project has not been analysed yet</h2>
      <p className="mx-auto mt-1.5 max-w-md text-sm text-muted">
        Run a dependency analysis from the project overview. Results appear here once the background worker has finished.
      </p>
      <Link to={`/projects/${projectId}`} className="btn btn-primary mt-5">
        Go to overview
      </Link>
    </div>
  );
}
