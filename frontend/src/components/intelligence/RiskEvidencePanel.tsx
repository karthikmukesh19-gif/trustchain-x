import type { EvidenceKind } from "../../utils/types";
import { Badge } from "../StatusBadge";
import { EVIDENCE_KIND } from "./labels";

const ORDER: EvidenceKind[] = ["OBSERVED", "DERIVED", "PREDICTED", "RECOMMENDED"];

/** Why a dependency has the scores it has, grouped by how each statement is known. */
export function RiskEvidencePanel({ evidence }: { evidence: Record<EvidenceKind, string[]> }) {
  return (
    <section className="rounded-md border border-line bg-surface p-4" aria-label="Evidence" data-testid="risk-evidence">
      <h4 className="text-sm font-semibold">Evidence</h4>
      <div className="mt-3 grid gap-4 md:grid-cols-2">
        {ORDER.map((kind) => {
          const view = EVIDENCE_KIND[kind];
          const lines = evidence[kind] ?? [];
          return (
            <div key={kind} data-testid={`evidence-${kind.toLowerCase()}`}>
              <div className="flex items-center gap-2">
                <Badge tone={view.tone}>{kind}</Badge>
                <span className="text-[11px] text-muted">{view.meaning}</span>
              </div>
              {lines.length === 0 ? (
                <p className="mt-1.5 text-xs text-muted">Nothing in this category.</p>
              ) : (
                <ul className="mt-1.5 list-disc space-y-0.5 pl-4 text-xs text-ink-soft">
                  {lines.map((line) => <li key={line}>{line}</li>)}
                </ul>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}
