import type { ReactNode } from "react";

import { PathGraph } from "../../graph/PathGraph";
import { formatDateTime, shortSha } from "../../utils/format";
import type { CodePath, ReachabilityFindingDetail, SourceLocation } from "../../utils/types";
import { ConfidenceLabel } from "../StatusBadge";

const REASONS: Record<string, string> = {
  PATH_FOUND: "A path to the affected functionality was found",
  NO_PATH_FOUND: "No path to the affected functionality was found",
  SYMBOL_MAPPING_UNKNOWN: "The advisory does not say which functions are affected",
  SYMBOL_MATCH_UNCERTAIN: "A use resembles an affected name but may be a different function",
  AMBIGUOUS_DEPENDENCY: "The import name is shared with a local module or another package",
  IMPORT_MAPPING_UNKNOWN: "The package's import name is not known and some imports are unexplained",
  DEPENDENCY_SOURCE_NOT_ANALYSED: "Used only through other packages, whose source is not analysed",
  INCOMPLETE_SOURCE: "Part of the source could not be analysed",
  DYNAMIC_CODE: "The source uses constructs decided at run time",
  LANGUAGE_NOT_SUPPORTED: "This ecosystem's source is not analysed",
};

const USAGE: Record<string, string> = {
  CALLED: "Application code calls into this package",
  REFERENCED: "Application code refers to names of this package without calling them directly",
  IMPORTED_ONLY: "The package is imported, but no use of it was bound statically",
  NOT_OBSERVED: "The application's source does not import this package",
};

export function reasonText(reason: string): string {
  return REASONS[reason] ?? reason;
}

function Block({ label, children }: { label: string; children: ReactNode }) {
  return (
    <section>
      <h4 className="eyebrow">{label}</h4>
      <div className="mt-1.5 space-y-1 text-sm">{children}</div>
    </section>
  );
}

function Location({ site, repositoryUrl, commitSha }: { site: SourceLocation; repositoryUrl?: string; commitSha?: string }) {
  if (!site.source_file) return null;
  const label = `${site.source_file}${site.line ? `:${site.line}` : ""}`;
  const web = repositoryUrl && /^https:\/\//i.test(repositoryUrl) && commitSha;
  const href = web ? `${repositoryUrl}/blob/${commitSha}/${site.source_file.split("/").map(encodeURIComponent).join("/")}${site.line ? `#L${site.line}` : ""}` : null;
  return href
    ? <a href={href} target="_blank" rel="noopener noreferrer" className="font-mono text-[12px] text-trust hover:underline">{label}</a>
    : <span className="font-mono text-[12px]">{label}</span>;
}

function PathSteps({ path, repositoryUrl, commitSha }: { path: CodePath; repositoryUrl?: string; commitSha?: string }) {
  return (
    <ol className="space-y-2" data-testid="path-steps">
      {path.edges.map((edge, index) => (
        <li key={`${edge.source}-${edge.target}-${index}`} className="rounded-md border border-line bg-surface px-3 py-2">
          <div className="flex flex-wrap items-baseline gap-x-2 font-mono text-[12px]">
            <span className="font-semibold">{path.nodes[index]?.label}</span>
            <span className="text-muted">{edge.kind}</span>
            <span className="font-semibold">{path.nodes[index + 1]?.label}</span>
            <span className="ml-auto text-muted">{edge.confidence}</span>
          </div>
          {edge.evidence && (
            <div className="mt-1 flex flex-wrap items-baseline gap-x-3">
              <Location site={edge.evidence} repositoryUrl={repositoryUrl} commitSha={commitSha} />
              {edge.evidence.text && <code className="break-all font-mono text-[12px] text-ink-soft">{edge.evidence.text}</code>}
            </div>
          )}
          <div className="mt-0.5 text-xs text-muted">{edge.basis}</div>
        </li>
      ))}
    </ol>
  );
}

/** Why a finding has its status: what was observed in the source, and what was concluded from it. */
export function ReachabilityEvidencePanel({ detail, repositoryUrl, commitSha }: { detail: ReachabilityFindingDetail; repositoryUrl?: string; commitSha?: string }) {
  const usage = detail.observed.dependency_usage;
  const path = detail.observed.path;
  const usagePath = detail.observed.usage_path;
  const shown = path ?? usagePath;

  return (
    <div className="space-y-5" data-testid="reachability-evidence">
      <p className="max-w-4xl text-sm">{detail.explanation}</p>

      {shown && (
        <Block label={path ? "Observed · path to the affected functionality" : "Observed · path to the package (not to a known affected function)"}>
          <PathGraph path={shown} affected={path !== null} />
          <p className="text-xs text-muted">
            {shown.length} step{shown.length === 1 ? "" : "s"}
            {shown.truncated ? " shown (the start of a longer path is left out)" : ""}
            {shown.start_is_entry ? " · starts at code that nothing else in the analysed source calls (a possible entry point)" : ""}
            {shown.through_tests_only ? " · starts in test code" : ""}
          </p>
          <PathSteps path={shown} repositoryUrl={repositoryUrl} commitSha={commitSha} />
        </Block>
      )}

      <div className="grid gap-5 lg:grid-cols-2">
        <Block label="Observed · use of the package in the source">
          {!usage ? (
            <p className="text-muted">Not analysed for this ecosystem.</p>
          ) : (
            <>
              <p>{USAGE[usage.level] ?? usage.level}.</p>
              {usage.import_sites.length > 0 && (
                <ul className="space-y-1" data-testid="import-sites">
                  {usage.import_sites.slice(0, 5).map((site, index) => (
                    <li key={`${site.source_file}-${site.line}-${index}`} className="flex flex-wrap items-baseline gap-x-3">
                      <Location site={site} repositoryUrl={repositoryUrl} commitSha={commitSha} />
                      <code className="break-all font-mono text-[12px] text-ink-soft">{site.text}</code>
                    </li>
                  ))}
                </ul>
              )}
              {usage.used_names.length > 0 && (
                <p className="text-xs text-muted">
                  Names used ({usage.use_site_count} site{usage.use_site_count === 1 ? "" : "s"}):{" "}
                  <span className="font-mono text-ink">{usage.used_names.slice(0, 12).join(", ")}</span>
                  {usage.used_names.length > 12 ? " …" : ""}
                </p>
              )}
            </>
          )}
        </Block>

        <Block label="Affected functionality · where it comes from">
          {detail.affected_symbols.length === 0 ? (
            <p data-testid="symbol-mapping-unknown">
              <span className="font-mono text-[12px] font-semibold">SYMBOL_MAPPING_UNKNOWN</span> — the advisory names the package and its
              versions, not the functions or classes that are affected. None is assumed.
            </p>
          ) : (
            <>
              <p>
                {detail.symbol_mapping === "OPERATOR_SUPPLIED" ? "Supplied by this installation's operator, not by the advisory." : "Published in the advisory record."}
              </p>
              <ul className="space-y-0.5 font-mono text-[12px]">
                {detail.affected_symbols.slice(0, 10).map((symbol) => (
                  <li key={symbol.symbol}>{symbol.symbol}{symbol.module_only ? " (whole module)" : ""}</li>
                ))}
              </ul>
              {detail.matched_symbol && (
                <p className="text-xs text-muted">
                  Observed <span className="font-mono text-ink">{detail.matched_symbol.observed}</span>,{" "}
                  {detail.matched_symbol.match === "EXACT" ? "the affected name itself" : "which has the same trailing name but a different module path; not treated as a match"}.
                </p>
              )}
            </>
          )}
        </Block>
      </div>

      {detail.observed.dynamic_sites && detail.observed.dynamic_sites.length > 0 && (
        <Block label="Observed · constructs decided at run time">
          <ul className="space-y-1">
            {detail.observed.dynamic_sites.slice(0, 5).map((site, index) => (
              <li key={`${site.source_file}-${site.line}-${index}`} className="flex flex-wrap items-baseline gap-x-3">
                <Location site={site} repositoryUrl={repositoryUrl} commitSha={commitSha} />
                <span className="font-mono text-[11px] text-muted">{site.reason}</span>
                <code className="break-all font-mono text-[12px] text-ink-soft">{site.expr}</code>
              </li>
            ))}
          </ul>
        </Block>
      )}

      <Block label="Inferred · the conclusion and what it rests on">
        <dl className="grid grid-cols-[150px_1fr] gap-x-3 gap-y-1 text-[13px]">
          <dt className="text-muted">Result</dt><dd>{reasonText(detail.reason)}</dd>
          <dt className="text-muted">Confidence</dt>
          <dd><ConfidenceLabel confidence={detail.confidence} /> <span className="text-xs text-muted">{detail.confidence ? detail.confidence_meaning : "Nothing was concluded, so no confidence applies."}</span></dd>
          <dt className="text-muted">Snapshot</dt><dd className="font-mono">{shortSha(commitSha)}</dd>
          <dt className="text-muted">Analysed</dt><dd>{formatDateTime(detail.analyzed_at)} · analyzer {detail.analyzer_version}</dd>
        </dl>
        {detail.inferred.notes.length > 0 && (
          <ul className="mt-2 list-disc space-y-0.5 pl-5 text-xs text-muted" data-testid="inference-notes">
            {detail.inferred.notes.map((note) => <li key={note}>{note}</li>)}
          </ul>
        )}
      </Block>
    </div>
  );
}
