import type { DependencyGraphData, GraphNode } from "../utils/types";

export const ROOT_ID = "root";
/** Most packages drawn at once. Larger graphs are narrowed with the filters. */
export const MAX_RENDERED_NODES = 250;

const NODE_SLOT = 240;        // one package column (node width plus spacing)
const GROUP_GAP = 110;        // extra space between one depth and the next, where the edges run
const ROW_HEIGHT = 58;
/** A depth with more packages than this is wrapped into several side-by-side columns. */
const MAX_ROWS = 12;

export interface GraphFilters {
  search: string;
  ecosystem: string;
  relationship: string;
  /** Show packages up to this depth; null shows every depth. Packages without a path are kept unless a depth is set. */
  maxDepth: number | null;
}

export interface PositionedNode {
  id: string;
  x: number;
  y: number;
  /** null for the project node. */
  node: GraphNode | null;
  label: string;
}

export interface PositionedEdge {
  id: string;
  source: string;
  target: string;
  inferred: boolean;
}

export interface GraphLayout {
  nodes: PositionedNode[];
  edges: PositionedEdge[];
  /** Packages matching the filters. */
  matching: number;
  /** Matching packages left out because of MAX_RENDERED_NODES. */
  hidden: number;
  /** Column headings, in order. */
  columns: { x: number; label: string; count: number }[];
}

export function filterNodes(nodes: GraphNode[], filters: GraphFilters): GraphNode[] {
  const needle = filters.search.trim().toLowerCase();
  return nodes.filter((node) => {
    if (filters.ecosystem && node.ecosystem !== filters.ecosystem) return false;
    if (filters.relationship && node.relationship !== filters.relationship) return false;
    if (filters.maxDepth !== null && (node.depth === null || node.depth > filters.maxDepth)) return false;
    if (needle && !node.normalized_name.toLowerCase().includes(needle) && !node.name.toLowerCase().includes(needle)) return false;
    return true;
  });
}

/**
 * Place packages in columns by dependency depth (1 = direct). Packages for
 * which the evidence establishes no path from the project go in a final
 * column of their own; they are never connected with invented edges.
 */
export function layoutGraph(data: DependencyGraphData, filters: GraphFilters, limit = MAX_RENDERED_NODES): GraphLayout {
  const matching = filterNodes(data.nodes, filters);
  const ordered = [...matching].sort(
    (a, b) => (a.depth ?? Number.MAX_SAFE_INTEGER) - (b.depth ?? Number.MAX_SAFE_INTEGER) || a.normalized_name.localeCompare(b.normalized_name),
  );
  const shown = ordered.slice(0, limit);
  const deepest = shown.reduce((max, node) => (node.depth !== null && node.depth > max ? node.depth : max), 0);
  const unknownColumn = deepest + 1; // packages without a path sort after every real depth

  const byColumn = new Map<number, GraphNode[]>();
  for (const node of shown) {
    const column = node.depth ?? unknownColumn;
    byColumn.set(column, [...(byColumn.get(column) ?? []), node]);
  }
  const groups = [...byColumn.entries()].sort((a, b) => a[0] - b[0]);
  const tallest = Math.max(1, ...groups.map(([, items]) => Math.min(items.length, MAX_ROWS)));

  const nodes: PositionedNode[] = [
    { id: ROOT_ID, x: 0, y: ((tallest - 1) * ROW_HEIGHT) / 2, node: null, label: data.root.label },
  ];
  const columns: GraphLayout["columns"] = [];
  let x = NODE_SLOT + GROUP_GAP;
  for (const [column, items] of groups) {
    const isUnknown = items[0].depth === null;
    columns.push({
      x,
      label: isUnknown ? "No path established" : column === 1 ? "Depth 1 · direct" : `Depth ${column}`,
      count: items.length,
    });
    const strips = Math.ceil(items.length / MAX_ROWS);
    for (let strip = 0; strip < strips; strip += 1) {
      const slice = items.slice(strip * MAX_ROWS, (strip + 1) * MAX_ROWS);
      const offset = ((tallest - slice.length) * ROW_HEIGHT) / 2;
      slice.forEach((node, index) => {
        nodes.push({ id: node.node_id, x: x + strip * NODE_SLOT, y: offset + index * ROW_HEIGHT, node, label: node.name });
      });
    }
    x += strips * NODE_SLOT + GROUP_GAP;
  }

  const visible = new Set(nodes.map((node) => node.id));
  const edges: PositionedEdge[] = data.edges
    .filter((edge) => visible.has(edge.source) && visible.has(edge.target))
    .map((edge) => ({ id: `${edge.source}->${edge.target}`, source: edge.source, target: edge.target, inferred: edge.basis !== "OBSERVED" }));

  return { nodes, edges, matching: matching.length, hidden: matching.length - shown.length, columns };
}

/** Deepest depth present in the graph (0 when nothing has a path). */
export function maxDepthOf(nodes: GraphNode[]): number {
  return nodes.reduce((max, node) => (node.depth !== null && node.depth > max ? node.depth : max), 0);
}
