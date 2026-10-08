import type { RiskLevel, ScoreFactor } from "../../utils/types";
import { FACTOR_LABEL, LevelBadge, confidence, score } from "./labels";

/**
 * One model score with every factor behind it. A factor whose data is not
 * available is listed as unknown and adds nothing: it is never filled in.
 */
export function FragilityScoreCard({ title, value, level, confidenceValue, modelVersion, factors, note, testId }: {
  title: string;
  value: number;
  level: RiskLevel;
  confidenceValue: number;
  modelVersion: string;
  factors: ScoreFactor[];
  note: string;
  testId: string;
}) {
  const unknown = factors.filter((factor) => factor.status === "UNKNOWN");
  const assumed = factors.filter((factor) => factor.status === "ASSUMED");
  return (
    <section className="rounded-md border border-line bg-surface p-4" aria-label={title} data-testid={testId}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h4 className="text-sm font-semibold">{title}</h4>
        <span className="font-mono text-[11px] text-faint">{modelVersion}</span>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-3">
        <span className="font-mono text-2xl font-semibold tabular-nums" data-testid={`${testId}-value`}>{score(value)}</span>
        <span className="text-xs text-muted">of 100</span>
        <LevelBadge level={level} />
        <span className="text-xs text-muted" title="Share of the model's inputs that were available for this dependency">
          confidence <span className="font-mono font-medium text-ink">{confidence(confidenceValue)}</span>
        </span>
      </div>
      <p className="mt-1.5 text-xs text-muted">{note}</p>

      <div className="overflow-x-auto">
      <table className="mt-3 w-full min-w-[360px] text-left text-xs">
        <thead>
          <tr className="border-b border-line text-muted">
            <th className="py-1.5 pr-2 font-medium">Factor</th>
            <th className="py-1.5 pr-2 text-right font-medium">Weight</th>
            <th className="py-1.5 pr-2 text-right font-medium">Value</th>
            <th className="py-1.5 pr-2 text-right font-medium">Adds</th>
            <th className="py-1.5 font-medium">Basis</th>
          </tr>
        </thead>
        <tbody>
          {factors.map((factor) => (
            <tr key={factor.name} className="border-b border-line/70 align-top" data-factor={factor.name} data-status={factor.status}>
              <td className="py-1.5 pr-2">
                <div className="font-medium">{FACTOR_LABEL[factor.name] ?? factor.name}</div>
                <div className="text-muted">{factor.detail}</div>
              </td>
              <td className="py-1.5 pr-2 text-right font-mono tabular-nums">{factor.weight}</td>
              <td className="py-1.5 pr-2 text-right font-mono tabular-nums">
                {factor.value === null ? <span className="text-warn">unknown</span> : factor.value.toFixed(2)}
                {factor.status === "ASSUMED" && <div className="text-[10px] font-sans text-warn">assumed</div>}
              </td>
              <td className="py-1.5 pr-2 text-right font-mono tabular-nums">{factor.value === null ? "—" : factor.contribution.toFixed(1)}</td>
              <td className="py-1.5 font-mono text-[10px] uppercase tracking-wide text-muted">{factor.basis}</td>
            </tr>
          ))}
        </tbody>
      </table>
      </div>
      <p className="mt-2 text-[11px] text-muted">Score = sum of weight × value. Weights total 100.</p>
      {unknown.length > 0 && (
        <p className="mt-1 text-[11px] text-warn" data-testid={`${testId}-unknown`}>
          {unknown.length} factor{unknown.length === 1 ? " has" : "s have"} no data and add{unknown.length === 1 ? "s" : ""} nothing. The score is
          a lower bound on what the model would give with complete data.
        </p>
      )}
      {assumed.length > 0 && (
        <p className="mt-1 text-[11px] text-warn" data-testid={`${testId}-assumed`}>
          {assumed.length} factor{assumed.length === 1 ? " uses" : "s use"} the model's neutral value because the fact is not established. It is a
          modelling choice, not a measurement, and it lowers the confidence.
        </p>
      )}
    </section>
  );
}
