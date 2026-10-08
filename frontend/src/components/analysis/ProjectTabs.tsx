import { NavLink } from "react-router-dom";

/** Sub-navigation shared by a project's pages. */
export function ProjectTabs({ projectId }: { projectId: string }) {
  const tabs = [
    { to: `/projects/${projectId}`, label: "Overview", end: true },
    { to: `/projects/${projectId}/dependencies`, label: "Dependencies", end: false },
    { to: `/projects/${projectId}/graph`, label: "Dependency graph", end: false },
  ];
  return (
    <nav className="mb-6 flex gap-1 overflow-x-auto border-b border-line" aria-label="Project sections">
      {tabs.map((tab) => (
        <NavLink
          key={tab.to}
          to={tab.to}
          end={tab.end}
          className={({ isActive }) =>
            `-mb-px whitespace-nowrap border-b-2 px-3 py-2 text-sm font-medium ${
              isActive ? "border-ink text-ink" : "border-transparent text-muted hover:text-ink"
            }`
          }
        >
          {tab.label}
        </NavLink>
      ))}
    </nav>
  );
}
