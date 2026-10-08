import { Link } from "react-router-dom";

import { formatDate } from "../utils/format";
import type { Project } from "../utils/types";
import { AnalysisBadge, MetadataBadge } from "./StatusBadge";

export function ProjectTable({ projects }: { projects: Project[] }) {
  return (
    <div className="card overflow-x-auto">
      <table className="w-full min-w-[640px] text-left text-sm">
        <thead>
          <tr className="border-b border-line">
            <th className="eyebrow px-4 py-2.5 font-medium">Project</th>
            <th className="eyebrow px-4 py-2.5 font-medium">Repository</th>
            <th className="eyebrow px-4 py-2.5 font-medium">Repository data</th>
            <th className="eyebrow px-4 py-2.5 font-medium">Analysis</th>
            <th className="eyebrow px-4 py-2.5 font-medium">Registered</th>
          </tr>
        </thead>
        <tbody>
          {projects.map((project) => (
            <tr key={project.id} className="border-b border-line last:border-0 hover:bg-paper/60">
              <td className="px-4 py-3">
                <Link to={`/projects/${project.id}`} className="font-semibold hover:text-trust hover:underline">
                  {project.name}
                </Link>
              </td>
              <td className="px-4 py-3 font-mono text-[13px] text-ink-soft">
                {project.repository?.full_name ?? project.repository_url}
              </td>
              <td className="px-4 py-3">
                {project.repository ? <MetadataBadge status={project.repository.metadata_status} /> : "—"}
              </td>
              <td className="px-4 py-3">
                <AnalysisBadge lastAnalysis={project.last_analysis} />
              </td>
              <td className="whitespace-nowrap px-4 py-3 text-muted">{formatDate(project.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
