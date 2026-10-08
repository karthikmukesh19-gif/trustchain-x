import { Fragment } from "react";
import { FiChevronDown, FiChevronRight } from "react-icons/fi";

import { ecosystemLabel } from "../../utils/format";
import type { ExposureClassification, FragilityDetail, FragilityRow, PredictionDetail, PredictionRow, ReachabilityState, RiskLevel } from "../../utils/types";
import { ErrorNotice, Spinner } from "../Feedback";
import { DependencyDetail } from "./DependencyDetail";
import { ClassificationBadge, LevelBadge, REACHABILITY_STATE_LABEL, confidence, indicatorLabel, score } from "./labels";

export type DetailState = PredictionDetail | FragilityDetail | { error: string };

interface Row {
  id: string;
  name: string;
  ecosystem: string;
  version: string | null;
  relationship: string;
  fragility: { score: number; level: RiskLevel; confidence: number };
  /** null when only fragility was analysed. */
  predictive: { score: number; level: RiskLevel; confidence: number; rank: number } | null;
  classification: ExposureClassification | null;
  vulnerabilities: number | null;
  reachable: number | null;
  reachability: ReachabilityState | null;
  indicators: string[] | null;
}

function fromPrediction(item: PredictionRow): Row {
  return {
    id: item.dependency_id, name: item.package_name || item.normalized_name, ecosystem: item.ecosystem, version: item.version,
    relationship: item.relationship, fragility: { score: item.fragility_score, level: item.fragility_score >= 67 ? "HIGH" : item.fragility_score >= 34 ? "MEDIUM" : "LOW", confidence: item.fragility_confidence },
    predictive: { score: item.score, level: item.level, confidence: item.confidence, rank: item.monitoring_rank },
    classification: item.exposure_classification, vulnerabilities: item.vulnerability_count, reachable: item.reachable_vulnerability_count,
    reachability: item.reachability_state, indicators: item.indicator_types,
  };
}

function fromFragility(item: FragilityRow): Row {
  return {
    id: item.dependency_id, name: item.package_name || item.normalized_name, ecosystem: item.ecosystem, version: item.version,
    relationship: item.relationship, fragility: { score: item.fragility_score, level: item.fragility_level, confidence: item.confidence },
    predictive: null, classification: null, vulnerabilities: null, reachable: null, reachability: null, indicators: null,
  };
}

const NOT_ANALYSED = <span className="text-xs text-muted" title="This layer was not part of the analysis on screen">Not analysed</span>;

function Score({ value, level, confidenceValue }: { value: number; level: RiskLevel; confidenceValue: number }) {
  return (
    <div>
      <div className="flex items-center gap-2">
        <span className="font-mono text-[13px] font-semibold tabular-nums">{score(value)}</span>
        <LevelBadge level={level} />
      </div>
      <div className="text-[11px] text-muted">confidence {confidence(confidenceValue)}</div>
    </div>
  );
}

/**
 * Dependencies with their scores. A row expands to the factors, health, indicators and evidence behind the numbers.
 * In "fragility" mode the columns of layers that were not analysed say so; they never show zero.
 */
export function DependencyRiskTable({ mode, predictions, fragility, expanded, details, onToggle, onRetry }: {
  mode: "predictive" | "fragility";
  predictions: PredictionRow[];
  fragility: FragilityRow[];
  expanded: string | null;
  details: Record<string, DetailState>;
  onToggle: (dependencyId: string) => void;
  onRetry: (dependencyId: string) => void;
}) {
  const rows = mode === "predictive" ? predictions.map(fromPrediction) : fragility.map(fromFragility);
  return (
    <div className="card overflow-x-auto">
      <table className="w-full min-w-[1040px] text-left text-sm" data-testid="risk-table" data-mode={mode}>
        <thead>
          <tr className="border-b border-line">
            <th className="w-8 px-2 py-2.5" />
            <th className="eyebrow px-3 py-2.5 font-medium">Dependency</th>
            <th className="eyebrow px-3 py-2.5 font-medium">Version</th>
            <th className="eyebrow px-3 py-2.5 font-medium" title="Relative priority for monitoring, 0-100. Not a probability.">Predictive risk</th>
            <th className="eyebrow px-3 py-2.5 font-medium" title="Structure and upkeep, 0-100. Not vulnerability severity.">Fragility</th>
            <th className="eyebrow px-3 py-2.5 font-medium">Exposure</th>
            <th className="eyebrow px-3 py-2.5 font-medium">Reachability</th>
            <th className="eyebrow px-3 py-2.5 font-medium">Indicators</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const open = expanded === row.id;
            const detail = details[row.id];
            return (
              <Fragment key={row.id}>
                <tr className={`border-b border-line align-top ${open ? "bg-paper/60" : "hover:bg-paper/60"}`} data-testid="risk-row" data-name={row.name}>
                  <td className="px-2 py-2.5">
                    <button type="button" onClick={() => onToggle(row.id)} aria-expanded={open}
                      aria-label={`${open ? "Hide" : "Show"} evidence for ${row.name}`} className="rounded p-1 hover:bg-line/60">
                      {open ? <FiChevronDown aria-hidden /> : <FiChevronRight aria-hidden />}
                    </button>
                  </td>
                  <td className="px-3 py-2.5">
                    <div className="font-mono text-[13px]">{row.name}</div>
                    <div className="text-xs text-muted">{ecosystemLabel(row.ecosystem)} · {row.relationship.toLowerCase()}</div>
                  </td>
                  <td className="px-3 py-2.5 font-mono text-[13px]">{row.version ?? <span className="text-muted">unresolved</span>}</td>
                  <td className="px-3 py-2.5" data-testid="cell-predictive">
                    {row.predictive ? <Score value={row.predictive.score} level={row.predictive.level} confidenceValue={row.predictive.confidence} /> : NOT_ANALYSED}
                  </td>
                  <td className="px-3 py-2.5" data-testid="cell-fragility">
                    <Score value={row.fragility.score} level={row.fragility.level} confidenceValue={row.fragility.confidence} />
                  </td>
                  <td className="px-3 py-2.5" data-testid="cell-exposure">
                    {row.classification === null ? NOT_ANALYSED : (
                      <>
                        <ClassificationBadge classification={row.classification} />
                        {row.vulnerabilities !== null && row.vulnerabilities > 0 && (
                          <div className="mt-0.5 text-[11px] text-muted">{row.vulnerabilities} known vulnerabilit{row.vulnerabilities === 1 ? "y" : "ies"}</div>
                        )}
                      </>
                    )}
                  </td>
                  <td className="px-3 py-2.5 text-xs" data-testid="cell-reachability">
                    {row.classification === null ? NOT_ANALYSED
                      : !row.vulnerabilities ? <span className="text-faint" title="Not applicable: no advisory matches this package">—</span>
                      : (
                        <span title="Static reachability of the affected functionality, from the code reachability analysis. Not exploitability.">
                          {REACHABILITY_STATE_LABEL[row.reachability ?? "NOT_ANALYSED"]}
                          {row.reachability === "REACHABLE" && row.reachable ? ` (${row.reachable})` : ""}
                        </span>
                      )}
                  </td>
                  <td className="px-3 py-2.5 text-xs" data-testid="cell-indicators">
                    {row.indicators === null ? NOT_ANALYSED : row.indicators.length === 0 ? <span className="text-faint">None</span> : (
                      <ul className="space-y-0.5">
                        {row.indicators.map((type) => <li key={type}>{indicatorLabel(type)}</li>)}
                      </ul>
                    )}
                  </td>
                </tr>
                {open && (
                  <tr className="border-b border-line bg-paper/60">
                    <td />
                    <td colSpan={7} className="px-3 pb-5 pt-2">
                      {!detail ? <Spinner label="Loading evidence" />
                        : "error" in detail ? <ErrorNotice message={detail.error} onRetry={() => onRetry(row.id)} />
                        : <DependencyDetail detail={detail} />}
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
