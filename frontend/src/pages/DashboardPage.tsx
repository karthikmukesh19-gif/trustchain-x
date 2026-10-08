import { FiPlus } from "react-icons/fi";
import { Link } from "react-router-dom";

import { RegistrationsChart } from "../charts/RegistrationsChart";
import { EmptyState, ErrorNotice, PageHeader, Spinner } from "../components/Feedback";
import { ProjectTable } from "../components/ProjectTable";
import { StatTile } from "../components/StatTile";
import { useAuth } from "../context/AuthContext";
import { useAsync } from "../hooks/useAsync";
import { getDashboardSummary } from "../services/projects";
import { describeAction, formatDateTime } from "../utils/format";

export function DashboardPage() {
  const { user } = useAuth();
  const { data, error, loading, reload } = useAsync(getDashboardSummary, []);

  if (loading && !data) return <Spinner label="Loading dashboard" />;
  if (error && !data) return <ErrorNotice message={error} onRetry={() => void reload()} />;
  if (!data) return null;

  const fetched = data.repository_metadata.FETCHED ?? 0;
  const unavailable = data.repository_metadata.UNAVAILABLE ?? 0;
  const pending = data.repository_metadata.PENDING ?? 0;
  const hasProjects = data.projects_total > 0;

  return (
    <>
      <PageHeader eyebrow="Overview" title={`Welcome, ${user?.full_name.split(" ")[0] ?? "there"}`}>
        <Link to="/projects?new=1" className="btn btn-primary">
          <FiPlus aria-hidden /> Register project
        </Link>
      </PageHeader>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile label="Projects" value={data.projects_total} note="Repositories you have registered" />
        <StatTile
          label="Repository data fetched"
          value={`${fetched}/${data.projects_total}`}
          note={
            unavailable > 0
              ? `${unavailable} unavailable — open the project to retry`
              : pending > 0
                ? `${pending} still being fetched`
                : "Public metadata from GitHub"
          }
        />
        <StatTile
          label="Projects analysed"
          value={`${data.projects_analysed}/${data.projects_total}`}
          note="Analysis engine not yet available"
        />
        <StatTile label="Trust score" value="—" note="Produced once a project has been analysed" />
      </div>

      {!hasProjects ? (
        <div className="mt-6">
          <EmptyState
            title="No projects yet"
            action={
              <Link to="/projects?new=1" className="btn btn-primary">
                <FiPlus aria-hidden /> Register your first project
              </Link>
            }
          >
            Register a public GitHub repository to start. Its metadata is fetched straight away; dependency, SBOM,
            vulnerability and behaviour analysis will appear here as the analysis engine is delivered.
          </EmptyState>
        </div>
      ) : (
        <>
          <section className="mt-8">
            <div className="mb-3 flex items-baseline justify-between">
              <h2 className="text-base font-semibold">Recent projects</h2>
              <Link to="/projects" className="text-sm font-medium text-trust hover:underline">
                All projects
              </Link>
            </div>
            <ProjectTable projects={data.recent_projects} />
          </section>

          <div className="mt-8 grid gap-6 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
            <section className="card p-5">
              <h2 className="text-base font-semibold">Projects registered</h2>
              <p className="text-sm text-muted">Per day over the last 14 days (UTC)</p>
              <div className="mt-3">
                <RegistrationsChart data={data.registrations_by_day} />
              </div>
            </section>

            <section className="card p-5">
              <h2 className="text-base font-semibold">Recent account activity</h2>
              <p className="text-sm text-muted">From the audit log</p>
              {data.recent_activity.length === 0 ? (
                <p className="mt-4 text-sm text-muted">No activity recorded yet.</p>
              ) : (
                <ul className="mt-3 divide-y divide-line">
                  {data.recent_activity.map((event, index) => (
                    <li key={`${event.timestamp}-${index}`} className="flex items-baseline justify-between gap-3 py-2 text-sm">
                      <span className={event.outcome === "success" ? "" : "text-danger"}>
                        {describeAction(event.action)}
                        {event.outcome !== "success" && " (failed)"}
                      </span>
                      <span className="shrink-0 font-mono text-xs text-muted">{formatDateTime(event.timestamp)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>
        </>
      )}
    </>
  );
}
