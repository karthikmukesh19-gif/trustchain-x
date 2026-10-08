import type { Dependency } from "../../utils/types";
import { BasisBadge, RelationshipLabel } from "../StatusBadge";

/** Where a dependency came from and how each statement about it is known. */
export function DependencyEvidence({ dependency, repositoryUrl, commitSha }: { dependency: Dependency; repositoryUrl?: string; commitSha?: string }) {
  return (
    <div className="space-y-4 text-sm" data-testid="dependency-evidence">
      <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
        <div>
          <dt className="eyebrow">Classification</dt>
          <dd className="mt-1 flex flex-wrap items-center gap-2">
            <RelationshipLabel relationship={dependency.relationship} /> <BasisBadge basis={dependency.relationship_basis} />
          </dd>
          <dd className="mt-1 text-xs text-muted">{dependency.relationship_reason}</dd>
        </div>
        <div>
          <dt className="eyebrow">Version</dt>
          <dd className="mt-1 flex flex-wrap items-center gap-2">
            <span className="font-mono">{dependency.version ?? "unresolved"}</span> <BasisBadge basis={dependency.version_basis} />
          </dd>
          <dd className="mt-1 text-xs text-muted">{dependency.version_reason}</dd>
        </div>
        <div>
          <dt className="eyebrow">Declared constraint</dt>
          <dd className="mt-1 break-all font-mono">{dependency.constraints.length ? dependency.constraints.join("  ·  ") : "none declared"}</dd>
        </div>
        <div>
          <dt className="eyebrow">Package URL</dt>
          <dd className="mt-1 break-all font-mono text-xs">{dependency.purl ?? "—"}</dd>
        </div>
        {dependency.source && (
          <div className="sm:col-span-2">
            <dt className="eyebrow">Source ({dependency.source.type})</dt>
            <dd className="mt-1 break-all font-mono text-xs">{dependency.source.location}</dd>
          </div>
        )}
        {dependency.integrity.length > 0 && (
          <div className="sm:col-span-2">
            <dt className="eyebrow">Integrity recorded in the repository</dt>
            <dd className="mt-1 break-all font-mono text-xs">
              {dependency.integrity[0].algorithm}: {dependency.integrity[0].value}
              {dependency.integrity.length > 1 && <span className="text-muted"> (+{dependency.integrity.length - 1} more)</span>}
            </dd>
          </div>
        )}
      </dl>

      <div>
        <div className="eyebrow">
          Evidence · {dependency.evidence_count} occurrence{dependency.evidence_count === 1 ? "" : "s"} in repository files
        </div>
        <ul className="mt-2 divide-y divide-line rounded-md border border-line bg-surface">
          {dependency.evidence.map((item, index) => {
            const href =
              repositoryUrl && commitSha
                ? `${repositoryUrl}/blob/${commitSha}/${item.source_file.split("/").map(encodeURIComponent).join("/")}${item.line ? `#L${item.line}` : ""}`
                : null;
            return (
              <li key={`${item.source_file}-${index}`} className="px-3 py-2">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  {href ? (
                    <a href={href} target="_blank" rel="noopener noreferrer" className="break-all font-mono text-[13px] text-trust hover:underline">
                      {item.source_file}{item.line ? `:${item.line}` : ""}
                    </a>
                  ) : (
                    <span className="break-all font-mono text-[13px]">{item.source_file}{item.line ? `:${item.line}` : ""}</span>
                  )}
                  <span className="text-xs text-muted">
                    {item.file_kind} · {item.package_manager}{item.scope ? ` · ${item.scope}` : ""}
                  </span>
                </div>
                <code className="mt-1 block break-all rounded bg-paper px-2 py-1 font-mono text-xs text-ink-soft">{item.declaration}</code>
              </li>
            );
          })}
        </ul>
        {dependency.evidence_count > dependency.evidence.length && (
          <p className="mt-1 text-xs text-muted">Showing the first {dependency.evidence.length}.</p>
        )}
      </div>
    </div>
  );
}
