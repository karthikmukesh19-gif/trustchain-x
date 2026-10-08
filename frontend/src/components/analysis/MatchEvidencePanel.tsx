import type { ReactNode } from "react";
import { FiExternalLink } from "react-icons/fi";

import { formatDateTime, shortSha } from "../../utils/format";
import type { MatchDetail } from "../../utils/types";
import { BasisBadge, RelationshipLabel } from "../StatusBadge";

function Block({ label, children }: { label: string; children: ReactNode }) {
  return (
    <section>
      <h4 className="eyebrow">{label}</h4>
      <div className="mt-1.5 space-y-1 text-sm">{children}</div>
    </section>
  );
}

/** Only http(s) addresses are rendered as links; anything else from a source is shown as text. */
function isWebUrl(value: string | null | undefined): value is string {
  return typeof value === "string" && /^https?:\/\//i.test(value);
}

/** Why a dependency was matched to an advisory: the source, what was observed, the comparison, and the data behind it. */
export function MatchEvidencePanel({ detail, repositoryUrl, commitSha }: { detail: MatchDetail; repositoryUrl?: string; commitSha?: string }) {
  const { match, vulnerability } = detail;
  const { source, observed, match: comparison } = match.evidence;
  const fileUrl = (path: string | null, line: number | null) =>
    repositoryUrl && commitSha && path ? `${repositoryUrl}/blob/${commitSha}/${path.split("/").map(encodeURIComponent).join("/")}${line ? `#L${line}` : ""}` : null;

  return (
    <div className="space-y-5" data-testid="match-evidence">
      {(vulnerability?.summary || match.summary) && <p className="max-w-4xl text-sm font-medium">{vulnerability?.summary ?? match.summary}</p>}

      <div className="grid gap-5 lg:grid-cols-2">
        <Block label="Source · where the information comes from">
          <p>
            <span className="font-semibold uppercase">{source.provider}</span> record{" "}
            {isWebUrl(source.url) ? (
              <a href={source.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 font-mono text-trust hover:underline">
                {source.source_id} <FiExternalLink aria-hidden />
              </a>
            ) : (
              <span className="font-mono">{source.source_id}</span>
            )}
          </p>
          {match.aliases.length > 0 && <p className="text-muted">Also known as <span className="font-mono text-ink">{match.aliases.join(", ")}</span></p>}
          <p className="text-xs text-muted">
            Modified at the source {formatDateTime(source.modified_at)} · retrieved {formatDateTime(source.retrieved_at)}
            {source.record_sha256 ? ` · record SHA-256 ${source.record_sha256.slice(0, 16)}…` : ""}
          </p>
        </Block>

        <Block label="Observed · what was found in the repository">
          <p>
            <span className="font-mono">{observed.package}</span> <span className="font-mono font-semibold">{observed.installed_version}</span>{" "}
            {observed.version_basis && <BasisBadge basis={observed.version_basis} />}
          </p>
          {observed.version_reason && <p className="text-xs text-muted">{observed.version_reason}</p>}
          <p className="text-muted">
            {observed.relationship && <RelationshipLabel relationship={observed.relationship} />}
            {observed.depth !== null ? ` dependency at depth ${observed.depth}` : " dependency; no path from the project is established"}
          </p>
          <ul className="space-y-1">
            {observed.declared_in.map((entry, index) => {
              const href = fileUrl(entry.source_file, entry.line);
              const label = `${entry.source_file}${entry.line ? `:${entry.line}` : ""}`;
              return (
                <li key={`${label}-${index}`} className="font-mono text-xs">
                  {href ? <a href={href} target="_blank" rel="noopener noreferrer" className="text-trust hover:underline">{label}</a> : label}
                  {entry.declaration && <span className="ml-2 rounded bg-paper px-1.5 py-0.5 text-ink-soft">{entry.declaration}</span>}
                </li>
              );
            })}
          </ul>
        </Block>

        <Block label="Match · why this version is flagged">
          <p>{comparison.explanation}</p>
          <p className="text-xs text-muted">{match.confidence_meaning}</p>
        </Block>

        <Block label="Evidence · the data behind the conclusion">
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
            <dt className="text-muted">Evidence type</dt>
            <dd className="font-mono">{match.evidence.evidence_type}</dd>
            <dt className="text-muted">Affected range</dt>
            <dd className="font-mono">{comparison.affected_range ?? "not determined"}</dd>
            <dt className="text-muted">Fixed version</dt>
            <dd className="font-mono">{comparison.fixed ?? (match.fixed_versions.length ? match.fixed_versions.join(", ") : "none published")}</dd>
            {comparison.events.length > 0 && (
              <>
                <dt className="text-muted">Published events</dt>
                <dd className="font-mono">{comparison.events.map((event) => Object.entries(event).map(([k, v]) => `${k} ${v}`).join("")).join(" → ")}</dd>
              </>
            )}
            <dt className="text-muted">Version ordering</dt>
            <dd className="font-mono">{comparison.comparator ?? "none available"}{comparison.range_type ? ` · ${comparison.range_type} range` : ""}</dd>
            <dt className="text-muted">Listed by the source</dt>
            <dd>{comparison.version_listed_by_source ? "Yes, this exact version is listed" : "No"}</dd>
            <dt className="text-muted">Reported by the provider</dt>
            <dd>{comparison.provider_reported === null ? "Not checked in the last synchronisation" : comparison.provider_reported ? "Yes, for this version" : "No"}</dd>
            {comparison.source_range_note && (
              <>
                <dt className="text-muted">Source note</dt>
                <dd><span className="font-mono">{comparison.source_range_note}</span> (free text from the source; not evaluated)</dd>
              </>
            )}
            {match.cvss?.map((entry) => (
              <div key={entry.vector} className="contents">
                <dt className="text-muted">{entry.type.replace("_", " ")}</dt>
                <dd className="break-all font-mono">
                  {entry.vector}
                  {entry.base_score !== null ? ` · base score ${entry.base_score.toFixed(1)} (computed from the vector)` : " · not scored"}
                </dd>
              </div>
            ))}
            <dt className="text-muted">Severity source</dt>
            <dd>{match.severity_source ? match.severity_source.replace(/_/g, " ") : "the source gives no severity"}</dd>
            <dt className="text-muted">Snapshot</dt>
            <dd className="font-mono">{shortSha(commitSha)}</dd>
          </dl>
        </Block>
      </div>

      {vulnerability && vulnerability.references.length > 0 && (
        <Block label="References published by the source">
          <ul className="space-y-0.5 text-xs">
            {vulnerability.references.slice(0, 6).map((reference) => (
              <li key={reference.url} className="truncate">
                {isWebUrl(reference.url) ? (
                  <a href={reference.url} target="_blank" rel="noopener noreferrer" className="text-trust hover:underline">{reference.url}</a>
                ) : (
                  <span className="font-mono">{reference.url}</span>
                )}
              </li>
            ))}
          </ul>
        </Block>
      )}
    </div>
  );
}
