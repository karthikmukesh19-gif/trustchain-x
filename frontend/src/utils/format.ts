const dateTime = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
const dateOnly = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });
const compact = new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 });

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : dateTime.format(date);
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : dateOnly.format(date);
}

export function formatCount(value: number | null | undefined): string {
  return value === null || value === undefined ? "—" : compact.format(value);
}

export function formatSize(kilobytes: number | null | undefined): string {
  if (kilobytes === null || kilobytes === undefined) return "—";
  if (kilobytes < 1024) return `${kilobytes} KB`;
  return `${(kilobytes / 1024).toFixed(1)} MB`;
}

const ACTION_LABELS: Record<string, string> = {
  "auth.register": "Account created",
  "auth.login": "Signed in",
  "project.create": "Project created",
  "project.delete": "Project deleted",
  "project.refresh_metadata": "Repository metadata refreshed",
  "analysis.dependencies.request": "Dependency analysis requested",
  "analysis.dependencies.finish": "Dependency analysis finished",
};

export function describeAction(action: string): string {
  return ACTION_LABELS[action] ?? action;
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatPercent(share: number): string {
  const percent = share * 100;
  return percent > 0 && percent < 0.1 ? "<0.1%" : `${percent.toFixed(1)}%`;
}

export function shortSha(sha: string | null | undefined): string {
  return sha ? sha.slice(0, 10) : "—";
}

const ECOSYSTEM_LABELS: Record<string, string> = {
  pypi: "PyPI", npm: "npm", maven: "Maven", golang: "Go", cargo: "Cargo", vcpkg: "vcpkg", conan: "Conan", cmake: "CMake",
};

export function ecosystemLabel(ecosystem: string): string {
  return ECOSYSTEM_LABELS[ecosystem] ?? ecosystem;
}
