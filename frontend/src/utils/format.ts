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
};

export function describeAction(action: string): string {
  return ACTION_LABELS[action] ?? action;
}
