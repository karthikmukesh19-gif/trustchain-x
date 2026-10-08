import { useState } from "react";
import { Link } from "react-router-dom";

import { ecosystemLabel, formatBytes, formatDateTime, formatPercent, shortSha } from "../../utils/format";
import type { DependencyFile, Snapshot } from "../../utils/types";
import { Badge, BasisBadge } from "../StatusBadge";
import { StatTile } from "../StatTile";

const FILE_STATUS: Record<DependencyFile["status"], { tone: "good" | "warn" | "bad" | "neutral"; label: string }> = {
  PARSED: { tone: "good", label: "Parsed" },
  ERROR: { tone: "bad", label: "Could not parse" },
  NOT_EVALUATED: { tone: "neutral", label: "Not evaluated" },
  UNSUPPORTED: { tone: "neutral", label: "Not supported" },
  SKIPPED: { tone: "warn", label: "Skipped" },
};

export function SnapshotCard({ snapshot }: { snapshot: Snapshot }) {
  return (
    <section className="card p-5" aria-label="Repository snapshot">
      <h2 className="text-base font-semibold">Repository snapshot</h2>
      <p className="mt-0.5 text-sm text-muted">The exact repository state these results describe.</p>
      <dl className="mt-4 grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-4">
        <div>
          <dt className="eyebrow">Commit</dt>
          <dd className="mt-1 font-mono text-sm" title={snapshot.commit_sha}>
            <a
              href={`${snapshot.repository_url}/commit/${snapshot.commit_sha}`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-trust hover:underline"
            >
              {shortSha(snapshot.commit_sha)}
            </a>
          </dd>
        </div>
        <div>
          <dt className="eyebrow">Branch</dt>
          <dd className="mt-1 break-all font-mono text-sm">{snapshot.branch}</dd>
        </div>
        <div>
          <dt className="eyebrow">Committed</dt>
          <dd className="mt-1 text-sm">{formatDateTime(snapshot.committed_at)}</dd>
        </div>
        <div>
          <dt className="eyebrow">Collected</dt>
          <dd className="mt-1 text-sm">{formatDateTime(snapshot.collected_at)}</dd>
        </div>
        <div>
          <dt className="eyebrow">Files</dt>
          <dd className="mt-1 font-mono text-sm">{snapshot.file_count.toLocaleString()}</dd>
        </div>
        <div>
          <dt className="eyebrow">Total size</dt>
          <dd className="mt-1 font-mono text-sm">{formatBytes(snapshot.total_bytes)}</dd>
        </div>
        <div>
          <dt className="eyebrow">Dependency files</dt>
          <dd className="mt-1 font-mono text-sm">{snapshot.dependency_files.length}</dd>
        </div>
        <div>
          <dt className="eyebrow">Analyzer</dt>
          <dd className="mt-1 font-mono text-sm">{snapshot.analyzer_version}</dd>
        </div>
      </dl>
      {snapshot.commit_message && <p className="mt-4 truncate text-sm text-ink-soft">“{snapshot.commit_message}”</p>}
      <p className="mt-3 text-xs text-muted">
        {snapshot.collection_method}.
        {snapshot.rejected_paths + snapshot.symlinks_skipped + snapshot.submodules_skipped > 0 &&
          ` Not followed: ${snapshot.symlinks_skipped} symbolic link(s), ${snapshot.submodules_skipped} submodule(s), ${snapshot.rejected_paths} entr(ies) with unsafe paths.`}
      </p>
    </section>
  );
}

export function LanguagesCard({ snapshot }: { snapshot: Snapshot }) {
  const { languages, primary_language: primary, method } = snapshot.languages;
  const github = snapshot.github_primary_language;
  return (
    <section className="card p-5" aria-label="Language detection">
      <h2 className="text-base font-semibold">Language detection</h2>
      {languages.length === 0 ? (
        <p className="mt-2 text-sm text-muted">No source files in a recognised language were found.</p>
      ) : (
        <>
          <p className="mt-0.5 text-sm text-muted">
            Primary language: <strong className="text-ink">{primary}</strong>
            {github && github !== primary && ` (GitHub reports ${github})`}
          </p>
          <ul className="mt-4 space-y-3">
            {languages.map((language) => (
              <li key={language.language}>
                <div className="flex items-baseline justify-between gap-3 text-sm">
                  <span className="font-medium">{language.language}</span>
                  <span className="font-mono text-xs text-muted">
                    {formatPercent(language.share)} · {language.files} file{language.files === 1 ? "" : "s"} · {language.confidence.toLowerCase()} confidence
                  </span>
                </div>
                <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-line">
                  <div className="h-full rounded-full bg-trust" style={{ width: `${Math.max(1, language.share * 100)}%` }} />
                </div>
                <details className="mt-1 text-xs text-muted">
                  <summary className="cursor-pointer select-none">
                    Evidence <span className="ml-1 inline-block align-middle"><BasisBadge basis={language.basis} /></span>
                  </summary>
                  <ul className="mt-1 space-y-0.5 font-mono">
                    {language.evidence_files.map((file) => (
                      <li key={file} className="break-all">{file}</li>
                    ))}
                  </ul>
                </details>
              </li>
            ))}
          </ul>
          <p className="mt-4 text-xs text-muted">{method}</p>
        </>
      )}
    </section>
  );
}

export function PackageManagersCard({ snapshot }: { snapshot: Snapshot }) {
  const [showFiles, setShowFiles] = useState(false);
  const files = snapshot.dependency_files;
  return (
    <section className="card p-5" aria-label="Package managers">
      <h2 className="text-base font-semibold">Package managers</h2>
      {snapshot.package_managers.length === 0 ? (
        <p className="mt-2 text-sm text-muted">No dependency files were found in this repository.</p>
      ) : (
        <>
          <ul className="mt-3 divide-y divide-line">
            {snapshot.package_managers.map((manager) => (
              <li key={manager.package_manager} className="py-2.5">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-sm font-medium">
                    {manager.package_manager} <span className="font-normal text-muted">· {ecosystemLabel(manager.ecosystem)}</span>
                  </span>
                  {!manager.supported && <Badge tone="neutral">Detected only</Badge>}
                </div>
                <div className="mt-1 break-all font-mono text-xs text-muted">
                  {[...manager.manifest_files, ...manager.lock_files].join(" · ")}
                </div>
              </li>
            ))}
          </ul>
          <button type="button" className="mt-3 text-sm font-medium text-trust hover:underline" onClick={() => setShowFiles((open) => !open)} aria-expanded={showFiles}>
            {showFiles ? "Hide" : "Show"} all {files.length} dependency file{files.length === 1 ? "" : "s"}
          </button>
          {showFiles && (
            <div className="mt-3 overflow-x-auto">
              <table className="w-full min-w-[560px] text-left text-sm">
                <thead>
                  <tr className="border-b border-line">
                    <th className="eyebrow py-2 pr-3 font-medium">File</th>
                    <th className="eyebrow py-2 pr-3 font-medium">Kind</th>
                    <th className="eyebrow py-2 pr-3 font-medium">Result</th>
                    <th className="eyebrow py-2 font-medium">Entries</th>
                  </tr>
                </thead>
                <tbody>
                  {files.map((file) => (
                    <tr key={file.path} className="border-b border-line align-top last:border-0">
                      <td className="py-2 pr-3">
                        <div className="break-all font-mono text-[13px]">{file.path}</div>
                        {file.detail && <div className="mt-0.5 text-xs text-muted">{file.detail}</div>}
                        {file.referenced_by && <div className="mt-0.5 text-xs text-muted">Included from {file.referenced_by}</div>}
                        {file.sha256 && <div className="mt-0.5 font-mono text-[11px] text-faint" title={file.sha256}>sha256 {file.sha256.slice(0, 16)}…</div>}
                      </td>
                      <td className="py-2 pr-3 text-muted">{file.kind}</td>
                      <td className="py-2 pr-3"><Badge tone={FILE_STATUS[file.status]?.tone ?? "neutral"}>{FILE_STATUS[file.status]?.label ?? file.status}</Badge></td>
                      <td className="py-2 font-mono">{file.status === "PARSED" ? file.dependencies_found : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </section>
  );
}

export function DependencySummaryCard({ snapshot, projectId }: { snapshot: Snapshot; projectId: string }) {
  const summary = snapshot.summary;
  return (
    <section className="card p-5" aria-label="Dependencies">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-base font-semibold">Dependencies</h2>
        <div className="flex gap-2">
          <Link to={`/projects/${projectId}/dependencies`} className="btn btn-secondary">View dependencies</Link>
          <Link to={`/projects/${projectId}/graph`} className="btn btn-secondary">View graph</Link>
        </div>
      </div>
      {summary.dependencies === 0 ? (
        <p className="mt-3 text-sm text-muted">
          No dependencies were extracted. {snapshot.dependency_files.length === 0
            ? "The repository contains no dependency files."
            : "See the dependency files above for what was found and why nothing was extracted."}
        </p>
      ) : (
        <div className="mt-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
          <StatTile label="Total" value={summary.dependencies} note={summary.ecosystems.map(ecosystemLabel).join(", ")} />
          <StatTile label="Direct" value={summary.direct} />
          <StatTile label="Transitive" value={summary.transitive} note={`Deepest path: ${summary.max_depth}`} />
          <StatTile
            label="Unresolved versions"
            value={summary.unresolved_versions}
            note={summary.relationship_unknown > 0 ? `${summary.relationship_unknown} with unknown relationship` : "Version not established by the files"}
          />
        </div>
      )}
    </section>
  );
}
