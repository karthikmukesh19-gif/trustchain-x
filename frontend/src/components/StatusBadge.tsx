import type { Basis, EvidenceConfidence, MatchStatus, MetadataStatus, ReachabilityStatus, Relationship, Severity } from "../utils/types";

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

const REACHABILITY: Record<ReachabilityStatus, { tone: Tone; label: string; title: string }> = {
  REACHABLE: { tone: "bad", label: "Reachable", title: "The source statically refers to functionality identified as affected. Not a statement about exploitability." },
  NOT_CONFIRMED_REACHABLE: { tone: "neutral", label: "Not confirmed", title: "The analysed source does not establish a path to the affected functionality. Not a statement that it is safe." },
  UNKNOWN: { tone: "warn", label: "Unknown", title: "Reachability could not be decided." },
  UNSUPPORTED: { tone: "neutral", label: "Unsupported", title: "Source analysis is not implemented for this ecosystem." },
};

/** Static reachability of the affected functionality. Never "exploitable", never "safe". */
export function ReachabilityBadge({ status }: { status: ReachabilityStatus }) {
  const { tone, label, title } = REACHABILITY[status] ?? REACHABILITY.UNKNOWN;
  return (
    <span title={title}>
      <Badge tone={tone}>{label}</Badge>
    </span>
  );
}

/** Evidence quality of a result. A dash when it does not apply (unknown, unsupported). */
export function ConfidenceLabel({ confidence }: { confidence: EvidenceConfidence | null }) {
  if (confidence === null) return <span className="text-faint" title="Not applicable: nothing was concluded">—</span>;
  return <span className="font-mono text-[12px] font-medium" title="How directly the source text establishes the result. Not a likelihood of exploitation.">{confidence}</span>;
}
