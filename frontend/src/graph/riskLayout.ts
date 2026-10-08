import type { RiskGraphData, RiskGraphNode } from "../utils/types";
import { ROOT_ID } from "./layout";

/** Most packages drawn at once. The highest predictive risk is kept when a graph is larger. */
export const MAX_RISK_NODES = 200;
/** "High centrality": at least half of the highest centrality in this graph. */
export const CENTRALITY_THRESHOLD = 0.5;

const NODE_SLOT = 250;
const GROUP_GAP = 110;
const ROW_HEIGHT = 76;
const MAX_ROWS = 10;

export interface RiskFilters {
  search: string;
  /** "" = any, "MEDIUM" = medium or higher, "HIGH" = high only. */
  fragility: "" | "MEDIUM" | "HIGH";
  risk: "" | "MEDIUM" | "HIGH";
  relationship: "" | "DIRECT" | "TRANSITIVE";
  vulnerable: boolean;
  reachable: boolean;
  central: boolean;
}

export const NO_RISK_FILTERS: RiskFilters = { search: "", fragility: "", risk: "", relationship: "", vulnerable: false, reachable: false, central: false };

const atLeast = (value: number, level: "" | "MEDIUM" | "HIGH") => level === "" || value >= (level === "HIGH" ? 67 : 34);

export function matchesRiskFilters(node: RiskGraphNode, filters: RiskFilters): boolean {
  const needle = filters.search.trim().toLowerCase();
  if (needle && !node.normalized_name.toLowerCase().includes(needle) && !node.package_name.toLowerCase().includes(needle)) return false;
  if (!atLeast(node.fragility_score, filters.fragility)) return false;
  if (!atLeast(node.score, filters.risk)) return false;
  if (filters.relationship && node.relationship !== filters.relationship) return false;
  if (filters.vulnerable && node.vulnerability_count === 0) return false;
  if (filters.reachable && !(node.reachable_vulnerability_count !== null && node.reachable_vulnerability_count > 0)) return false;
  if (filters.central && node.relative_centrality < CENTRALITY_THRESHOLD) return false;
  return true;
}

export interface RiskLayoutNode {
  id: string;
  x: number;
  y: number;
  node: RiskGraphNode | null;
  label: string;
}

export interface RiskLayoutEdge {
  id: string;
  source: string;
  target: string;
  /** The target is, or depends on, a package with a known vulnerability: exposure reaches the source along this edge. */
  exposure: boolean;
}

export interface RiskLayout {
  nodes: RiskLayoutNode[];
  edges: RiskLayoutEdge[];
  matching: number;
  hidden: number;
}

/**
 * Columns by dependency depth, as in the dependency graph. Only packages and
 * edges returned by the API are drawn; filtering removes nodes, it never adds any.
 */
export function layoutRiskGraph(data: RiskGraphData, filters: RiskFilters, limit = MAX_RISK_NODES): RiskLayout {
  const matching = data.nodes.filter((node) => matchesRiskFilters(node, filters));
  const shown = [...matching].sort((a, b) => b.score - a.score || a.node_id.localeCompare(b.node_id)).slice(0, limit);
  const deepest = shown.reduce((max, node) => (node.depth !== null && node.depth > max ? node.depth : max), 0);
  const byColumn = new Map<number, RiskGraphNode[]>();
  for (const node of shown) {
    const column = node.depth ?? deepest + 1;
    byColumn.set(column, [...(byColumn.get(column) ?? []), node]);
  }
  const groups = [...byColumn.entries()].sort((a, b) => a[0] - b[0]);
  const tallest = Math.max(1, ...groups.map(([, items]) => Math.min(items.length, MAX_ROWS)));
  const nodes: RiskLayoutNode[] = [{ id: ROOT_ID, x: 0, y: ((tallest - 1) * ROW_HEIGHT) / 2, node: null, label: data.root.label ?? "Project" }];
  let x = NODE_SLOT + GROUP_GAP;
  for (const [, items] of groups) {
    const strips = Math.ceil(items.length / MAX_ROWS);
    for (let strip = 0; strip < strips; strip += 1) {
      const slice = items.slice(strip * MAX_ROWS, (strip + 1) * MAX_ROWS);
      const offset = ((tallest - slice.length) * ROW_HEIGHT) / 2;
      slice.forEach((node, index) => {
        nodes.push({ id: node.node_id, x: x + strip * NODE_SLOT, y: offset + index * ROW_HEIGHT, node, label: node.package_name || node.normalized_name });
      });
    }
    x += strips * NODE_SLOT + GROUP_GAP;
  }
  const visible = new Set(nodes.map((node) => node.id));
  const classification = new Map(data.nodes.map((node) => [node.node_id, node.exposure_classification]));
  const edges = data.edges
    .filter((edge) => visible.has(edge.source) && visible.has(edge.target))
    .map((edge) => ({
      id: `${edge.source}->${edge.target}`, source: edge.source, target: edge.target,
      exposure: (classification.get(edge.target) ?? "NO_OBSERVED_PROPAGATION") !== "NO_OBSERVED_PROPAGATION",
    }));
  return { nodes, edges, matching: matching.length, hidden: matching.length - shown.length };
}
