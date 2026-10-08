import type { Basis, MatchStatus, MetadataStatus, Relationship, Severity } from "../utils/types";

type Tone = "good" | "warn" | "bad" | "neutral";

const TONES: Record<Tone, string> = {
  good: "bg-trust-soft text-trust-strong",
  warn: "bg-warn-soft text-warn",
  bad: "bg-danger-soft text-danger",
  neutral: "bg-paper text-muted border border-line",
};

export function Badge({ tone, children }: { tone: Tone; children: string }) {
  return (
    <span
      className={`inline-flex items-center whitespace-nowrap rounded px-1.5 py-0.5 font-mono text-[11px] font-medium uppercase tracking-wide ${TONES[tone]}`}
    >
      {children}
    </span>
  );
}

const METADATA: Record<MetadataStatus, { tone: Tone; label: string }> = {
  FETCHED: { tone: "good", label: "Metadata fetched" },
  PENDING: { tone: "neutral", label: "Fetching metadata" },
  UNAVAILABLE: { tone: "warn", label: "Metadata unavailable" },
};

export function MetadataBadge({ status }: { status: MetadataStatus }) {
  const { tone, label } = METADATA[status] ?? { tone: "neutral" as Tone, label: status };
  return <Badge tone={tone}>{label}</Badge>;
}

export function AnalysisBadge({ lastAnalysis }: { lastAnalysis: string | null }) {
  return lastAnalysis ? <Badge tone="good">Analysed</Badge> : <Badge tone="neutral">Not analysed</Badge>;
}

const BASIS: Record<Basis, { tone: Tone; title: string }> = {
  OBSERVED: { tone: "good", title: "Read directly from a repository file" },
  INFERRED: { tone: "warn", title: "Derived by a documented rule from what the files contain" },
  UNKNOWN: { tone: "neutral", title: "The repository evidence does not establish this" },
};

/** OBSERVED / INFERRED / UNKNOWN. The label is always shown as text, never by colour alone. */
export function BasisBadge({ basis }: { basis: Basis }) {
  const { tone, title } = BASIS[basis] ?? BASIS.UNKNOWN;
  return (
    <span title={title}>
      <Badge tone={tone}>{basis}</Badge>
    </span>
  );
}

const RELATIONSHIP_LABEL: Record<Relationship, string> = { DIRECT: "Direct", TRANSITIVE: "Transitive", UNKNOWN: "Unknown" };

export function RelationshipLabel({ relationship }: { relationship: Relationship }) {
  return <span className="font-medium">{RELATIONSHIP_LABEL[relationship] ?? relationship}</span>;
}

const SEVERITY_TONE = { CRITICAL: "bad", HIGH: "bad", MEDIUM: "warn", LOW: "neutral", UNKNOWN: "neutral" } as const;

/** Severity as published by the source. UNKNOWN means the source gives none; nothing is estimated. */
export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge tone={SEVERITY_TONE[severity] ?? "neutral"}>{severity === "UNKNOWN" ? "Unknown" : severity.charAt(0) + severity.slice(1).toLowerCase()}</Badge>;
}

const MATCH_STATUS = {
  AFFECTED: { tone: "bad", label: "Affected" },
  UNSUPPORTED: { tone: "neutral", label: "Not verified" },
  CONFLICT: { tone: "warn", label: "Conflict" },
} as const;

export function MatchStatusBadge({ status }: { status: MatchStatus }) {
  const view = MATCH_STATUS[status] ?? { tone: "neutral" as const, label: status };
  return <Badge tone={view.tone}>{view.label}</Badge>;
}
