import type { PredictiveIndicator } from "../../utils/types";
import { LevelBadge, confidence, indicatorLabel } from "./labels";

/** Indicators for one dependency. Each is listed with the evidence that produced it; none exists without evidence. */
export function PredictiveIndicators({ indicators }: { indicators: PredictiveIndicator[] }) {
  return (
    <section className="rounded-md border border-line bg-surface p-4" aria-label="Predictive indicators" data-testid="indicators">
      <h4 className="text-sm font-semibold">Predictive indicators</h4>
      <p className="mt-1 text-xs text-muted">Reasons to watch this dependency more closely. An indicator is not a prediction of a specific vulnerability or attack.</p>
      {indicators.length === 0 ? (
        <p className="mt-3 text-xs text-muted" data-testid="no-indicators">The evidence for this dependency supports no indicator.</p>
      ) : (
        <ul className="mt-3 space-y-3">
          {indicators.map((indicator) => (
            <li key={indicator.type} className="border-l-2 border-line pl-3" data-testid="indicator" data-type={indicator.type}>
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs font-semibold">{indicatorLabel(indicator.type)}</span>
                <LevelBadge level={indicator.severity} />
                <span className="font-mono text-[10px] uppercase tracking-wide text-muted">{indicator.basis}</span>
                <span className="text-[11px] text-muted">confidence {confidence(indicator.confidence)}</span>
              </div>
              <ul className="mt-1 space-y-0.5 text-xs text-ink-soft">
                {indicator.evidence.map((line) => <li key={line}>{line}</li>)}
              </ul>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
