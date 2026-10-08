import { useState } from "react";
import { FiPlus } from "react-icons/fi";
import { useNavigate, useSearchParams } from "react-router-dom";

import { EmptyState, ErrorNotice, PageHeader, Spinner } from "../components/Feedback";
import { ProjectForm } from "../components/ProjectForm";
import { ProjectTable } from "../components/ProjectTable";
import { useAsync } from "../hooks/useAsync";
import { listProjects } from "../services/projects";

export function ProjectsPage() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [formOpen, setFormOpen] = useState(params.get("new") === "1");
  const { data, error, loading, reload } = useAsync(listProjects, []);

  function closeForm() {
    setFormOpen(false);
    if (params.has("new")) setParams({}, { replace: true });
  }

  const projects = data?.items ?? [];

  return (
    <>
      <PageHeader eyebrow="Projects" title="Registered repositories">
        {!formOpen && (
          <button type="button" className="btn btn-primary" onClick={() => setFormOpen(true)}>
            <FiPlus aria-hidden /> Register project
          </button>
        )}
      </PageHeader>

      {formOpen && (
        <div className="mb-6">
          <ProjectForm onCreated={(project) => navigate(`/projects/${project.id}`)} onCancel={closeForm} />
        </div>
      )}

      {loading && !data ? (
        <Spinner label="Loading projects" />
      ) : error && !data ? (
        <ErrorNotice message={error} onRetry={() => void reload()} />
      ) : projects.length === 0 ? (
        !formOpen && (
          <EmptyState
            title="No projects yet"
            action={
              <button type="button" className="btn btn-primary" onClick={() => setFormOpen(true)}>
                <FiPlus aria-hidden /> Register project
              </button>
            }
          >
            Add a public GitHub repository to register your first project.
          </EmptyState>
        )
      ) : (
        <>
          <ProjectTable projects={projects} />
          {data && data.total > projects.length && (
            <p className="mt-3 text-sm text-muted">
              Showing the {projects.length} most recent of {data.total} projects.
            </p>
          )}
        </>
      )}
    </>
  );
}
