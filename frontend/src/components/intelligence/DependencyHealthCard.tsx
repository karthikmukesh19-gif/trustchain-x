import { formatDate } from "../../utils/format";
import type { DependencyHealth } from "../../utils/types";
import { UNKNOWN_TEXT } from "./labels";

const POSITION: Record<string, string> = { UP_TO_DATE: "Up to date", BEHIND: "Behind the latest release", AHEAD_OF_LATEST: "Ahead of the registry's latest" };
const COMPARISON: Record<string, string> = {
  UNSUPPORTED: "Not compared: the versions cannot be ordered safely for this ecosystem",
  UNKNOWN: "Not compared: release metadata is not available",
};

function Value({ value, suffix = "" }: { value: string | number | null; suffix?: string }) {
  if (value === null) return <span className="text-warn">{UNKNOWN_TEXT}</span>;
  return <span className="font-mono">{value}{suffix}</span>;
}

/** What is known about a dependency's upkeep. Anything the registry did not provide is shown as unknown, with the reason. */
export function DependencyHealthCard({ health }: { health: DependencyHealth }) {
  const version = health.version;
  const source = health.metadata_source;
  const reasons = new Map(health.unknown.map((entry) => [entry.field, entry.reason]));
  const rows: { label: string; field: string; value: string | number | null; suffix?: string }[] = [
    { label: "Installed version", field: "installed_version", value: health.installed_version },
    { label: "Latest release", field: "latest_release", value: health.latest_release },
    { label: "Latest released", field: "latest_release_at", value: health.latest_release_at ? formatDate(health.latest_release_at) : null },
    { label: "Installed version released", field: "installed_release_at", value: health.installed_release_at ? formatDate(health.installed_release_at) : null },
    { label: "Installed version age", field: "release_age_days", value: health.release_age_days, suffix: " days" },
    { label: "Releases in the last year", field: "release_frequency", value: health.release_frequency },
    { label: "Known vulnerabilities", field: "known_vulnerability_count", value: health.known_vulnerability_count },
    { label: "Reachable vulnerabilities", field: "reachable_vulnerability_count", value: health.reachable_vulnerability_count },
    { label: "Requires directly", field: "dependency_count", value: health.dependency_count },
    { label: "Dependent packages", field: "downstream_dependents", value: health.downstream_dependents },
    { label: "Source repository activity", field: "repository_activity", value: health.repository_activity },
  ];
  return (
    <section className="rounded-md border border-line bg-surface p-4" aria-label="Dependency health" data-testid="health-card">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h4 className="text-sm font-semibold">Dependency health</h4>
        <span className="text-xs text-muted">
          metadata confidence <span className="font-mono font-medium text-ink" data-testid="metadata-confidence">{health.metadata_confidence}</span>
        </span>
      </div>
      <p className="mt-1.5 text-xs" data-testid="version-position">
        {version.comparison_status === "COMPARED"
          ? <>{POSITION[version.position ?? ""] ?? version.position}{version.releases_behind ? ` · ${version.releases_behind} release(s) behind` : ""}{version.lag_days ? ` · ${version.lag_days} days between the two releases` : ""}</>
          : <span className="text-warn">{COMPARISON[version.comparison_status] ?? version.comparison_status}{version.reason ? `. ${version.reason}` : ""}</span>}
      </p>
      {(version.installed_withdrawn || version.installed_deprecated) && (
        <p className="mt-1 text-xs text-warn" data-testid="installed-status">
          The registry marks the installed version as {version.installed_withdrawn ? "withdrawn" : "deprecated"}.
        </p>
      )}
      <dl className="mt-3 grid grid-cols-1 gap-x-6 gap-y-1.5 text-xs sm:grid-cols-2">
        {rows.map((row) => (
          <div key={row.field} className="flex items-baseline justify-between gap-3 border-b border-line/60 pb-1" data-field={row.field}
            title={row.value === null ? reasons.get(row.field) : undefined}>
            <dt className="text-muted">{row.label}</dt>
            <dd className="text-right"><Value value={row.value} suffix={row.suffix} /></dd>
          </div>
        ))}
      </dl>
      {health.unknown.length > 0 && (
        <details className="mt-3 text-xs">
          <summary className="cursor-pointer font-medium text-ink-soft">Why {health.unknown.length} value{health.unknown.length === 1 ? " is" : "s are"} unknown</summary>
          <ul className="mt-1.5 space-y-1 text-muted" data-testid="health-unknown">
            {health.unknown.map((entry) => <li key={entry.field}><span className="font-mono">{entry.field}</span>: {entry.reason}</li>)}
          </ul>
        </details>
      )}
      <p className="mt-3 text-[11px] text-muted" data-testid="metadata-source">
        {source.registry
          ? <>Release metadata: {source.registry}{source.status ? ` · ${source.status.toLowerCase().replace("_", " ")}` : ""}{source.detail === "COMPACT" ? " · versions only, no release dates" : ""}{source.fetched_at ? ` · fetched ${formatDate(source.fetched_at)}` : ""}{source.stale ? " · an earlier answer was reused because the registry could not be reached" : ""}</>
          : "Release metadata: no registry is consulted for this ecosystem."}
      </p>
    </section>
  );
}
