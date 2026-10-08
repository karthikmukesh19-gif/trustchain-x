import type { EvidenceKind, ExposureClassification, ReachabilityState, RiskLevel } from "../../utils/types";
import { Badge } from "../StatusBadge";

export const LEVEL_LABEL: Record<RiskLevel, string> = { LOW: "Low", MEDIUM: "Medium", HIGH: "High" };
const LEVEL_TONE = { LOW: "neutral", MEDIUM: "warn", HIGH: "bad" } as const;

/** A level on the model's own 0-100 scale (low below 34, high from 67). Always shown with the number it comes from. */
export function LevelBadge({ level }: { level: RiskLevel }) {
  return <Badge tone={LEVEL_TONE[level] ?? "neutral"}>{LEVEL_LABEL[level] ?? level}</Badge>;
}

export const CLASSIFICATION: Record<ExposureClassification, { label: string; tone: "bad" | "warn" | "neutral"; meaning: string }> = {
  DIRECT_VULNERABILITY: { label: "Known vulnerability", tone: "bad", meaning: "An advisory matches this package's own installed version." },
  DEPENDENCY_PROPAGATION: {
    label: "Requires a vulnerable package", tone: "warn",
    meaning: "No advisory matches this package. It directly requires a package with a known vulnerability.",
  },
  INDIRECT_EXPOSURE: {
    label: "Indirect exposure", tone: "warn",
    meaning: "No advisory matches this package. A package with a known vulnerability lies further down what it depends on.",
  },
  NO_OBSERVED_PROPAGATION: { label: "None observed", tone: "neutral", meaning: "No known vulnerability was observed in this package or in what it depends on." },
};

export function ClassificationBadge({ classification }: { classification: ExposureClassification }) {
  const view = CLASSIFICATION[classification] ?? { label: classification, tone: "neutral" as const, meaning: "" };
  return (
    <span title={view.meaning}>
      <Badge tone={view.tone}>{view.label}</Badge>
    </span>
  );
}

export const INDICATOR_LABEL: Record<string, string> = {
  REACHABLE_VULNERABLE_DEPENDENCY: "Reachable vulnerable dependency",
  VULNERABILITY_CLUSTER: "Vulnerability cluster",
  SINGLE_POINT_DEPENDENCY: "Single-point dependency",
  HIGH_DOWNSTREAM_IMPACT: "High downstream impact",
  HIGH_DEPENDENCY_CONCENTRATION: "High dependency concentration",
  HIGH_GRAPH_CENTRALITY: "High graph centrality",
  HIGH_TRANSITIVE_DEPTH: "High transitive depth",
  OUTDATED_DEPENDENCY: "Outdated dependency",
  RAPID_VERSION_GAP: "Rapid version gap",
  INSUFFICIENT_METADATA: "Insufficient metadata",
};

export const indicatorLabel = (type: string) => INDICATOR_LABEL[type] ?? type;

export const FACTOR_LABEL: Record<string, string> = {
  downstream_impact: "Downstream impact",
  fan_in: "Direct dependents",
  introduced_dependencies: "Dependencies it brings in",
  transitive_depth: "Transitive depth",
  graph_centrality: "Graph centrality",
  version_lag: "Version lag",
  release_staleness: "Release staleness",
  vulnerability_exposure: "Vulnerability exposure",
  reachability: "Reachability",
  fragility: "Fragility",
  dependency_concentration: "Dependency concentration",
  version_indicators: "Version indicators",
};

export const REACHABILITY_STATE_LABEL: Record<ReachabilityState, string> = {
  REACHABLE: "Reachable",
  NOT_CONFIRMED_REACHABLE: "Not confirmed",
  UNKNOWN: "Unknown",
  UNSUPPORTED: "Unsupported",
  NOT_ANALYSED: "Not analysed",
};

export const EVIDENCE_KIND: Record<EvidenceKind, { title: string; meaning: string; tone: "good" | "warn" | "neutral" }> = {
  OBSERVED: { title: "Observed", meaning: "Read from the repository, the advisory sources, the registries or the code analysis.", tone: "good" },
  DERIVED: { title: "Derived", meaning: "Computed from observed facts by a documented rule.", tone: "neutral" },
  PREDICTED: { title: "Predicted", meaning: "A model's ranking of where to look first. Not a forecast of a specific event.", tone: "warn" },
  RECOMMENDED: { title: "Recommended", meaning: "Suggested follow-up. Nothing is changed automatically.", tone: "neutral" },
};

/** A score out of 100 to one decimal place. */
export const score = (value: number) => value.toFixed(1);
/** Confidence as a percentage: the share of the model's inputs that were available. */
export const confidence = (value: number) => `${Math.round(value * 100)}%`;
/** node ids look like "npm:debug@2.6.9"; show the readable part. */
export const nodeLabel = (nodeId: string) => (nodeId === "root" ? "project" : nodeId.slice(nodeId.indexOf(":") + 1));
export const UNKNOWN_TEXT = "Unknown";
