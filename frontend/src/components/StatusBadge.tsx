import type { MetadataStatus } from "../utils/types";

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
