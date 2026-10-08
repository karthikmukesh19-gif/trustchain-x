import type { FragilityDetail, PredictionDetail } from "../../utils/types";
import { DependencyHealthCard } from "./DependencyHealthCard";
import { FragilityScoreCard } from "./FragilityScoreCard";
import { DependencyGraphRisk } from "./GraphRiskPanel";
import { PredictiveIndicators } from "./PredictiveIndicators";
import { RiskEvidencePanel } from "./RiskEvidencePanel";

const FRAGILITY_NOTE = "Structure and upkeep. Not vulnerability severity, and not a statement that the package is unsafe.";

/** Everything stored about one dependency. Layers that were not analysed are named as such instead of being left blank. */
export function DependencyDetail({ detail, compact = false }: { detail: PredictionDetail | FragilityDetail; compact?: boolean }) {
  const prediction = "prediction" in detail ? detail.prediction : null;
  const fragility = detail.fragility;
  return (
    <div className={`grid gap-4 ${compact ? "" : "xl:grid-cols-2"}`} data-testid="dependency-detail">
      {prediction ? (
        <FragilityScoreCard title="Predictive dependency risk" testId="predictive-score" value={prediction.score} level={prediction.level}
          confidenceValue={prediction.confidence} modelVersion={prediction.model_version} factors={prediction.factors} note={prediction.meaning} />
      ) : (
        <section className="rounded-md border border-dashed border-line p-4 text-xs text-muted" data-testid="predictive-not-analysed">
          <h4 className="text-sm font-semibold text-ink">Predictive dependency risk</h4>
          <p className="mt-1.5">Analysis not available. Only fragility has been analysed for this snapshot; run the full analysis for exposure, indicators and predictive risk.</p>
        </section>
      )}
      {fragility && (
        <FragilityScoreCard title="Fragility" testId="fragility-score" value={fragility.fragility_score} level={fragility.fragility_level}
          confidenceValue={fragility.confidence} modelVersion={fragility.model_version} factors={fragility.factors} note={FRAGILITY_NOTE} />
      )}
      {"graph_risk" in detail && detail.graph_risk && <DependencyGraphRisk risk={detail.graph_risk} />}
      {detail.health && <DependencyHealthCard health={detail.health} />}
      {"indicators" in detail && <PredictiveIndicators indicators={detail.indicators} />}
      {prediction && <div className={compact ? "" : "xl:col-span-2"}><RiskEvidencePanel evidence={prediction.evidence} /></div>}
    </div>
  );
}
