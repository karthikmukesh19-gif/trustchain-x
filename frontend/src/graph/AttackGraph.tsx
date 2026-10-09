import { Background, Controls, Handle, MiniMap, Position, ReactFlow } from "@xyflow/react";
import type { Edge, Node, NodeProps } from "@xyflow/react";
import { memo, useMemo } from "react";

import "@xyflow/react/dist/style.css";

import type { AttackEdge, AttackNode, AttackStage } from "../utils/platformTypes";

type AttackData = { node: AttackNode; highlighted: boolean; dimmed: boolean };
type AttackFlowNode = Node<AttackData, "attack">;

const STAGE_LABEL: Record<AttackStage, string> = {
  ENTRY: "Source", DEPENDENCY: "Dependency", VULNERABILITY: "Vulnerability", REACHABILITY: "Reachability", APPLICATION: "Reachable component",
  DOWNSTREAM_COMPONENT: "Downstream", IMPACT: "Potential impact",
};
const STAGE_TONE: Record<AttackStage, string> = {
  ENTRY: "border-ink bg-ink text-white", DEPENDENCY: "border-line bg-surface", VULNERABILITY: "border-danger bg-danger-soft",
  REACHABILITY: "border-warn bg-warn-soft", APPLICATION: "border-line bg-surface", DOWNSTREAM_COMPONENT: "border-line bg-paper",
  IMPACT: "border-dashed border-ink-soft bg-paper",
};
const COLUMN = 250;
const ROW = 74;

/**
 * Left-to-right layers: a node sits one column after the furthest of its predecessors, so every edge points right and a
 * dependency chain reads as a chain. Passes are bounded, which also keeps a cyclic dependency graph from looping.
 */
export function layoutAttackGraph(nodes: AttackNode[], edges: AttackEdge[]): { id: string; x: number; y: number; node: AttackNode }[] {
  const layer = new Map(nodes.map((node) => [node.id, 0]));
  for (let pass = 0; pass < Math.min(nodes.length, 40); pass += 1) {
    let moved = false;
    for (const edge of edges) {
      const from = layer.get(edge.source);
      const to = layer.get(edge.target);
      if (from !== undefined && to !== undefined && to < from + 1 && from + 1 <= 40) {
        layer.set(edge.target, from + 1);
        moved = true;
      }
    }
    if (!moved) break;
  }
  const columns = new Map<number, AttackNode[]>();
  for (const node of nodes) {
    const column = layer.get(node.id) ?? 0;
    columns.set(column, [...(columns.get(column) ?? []), node]);
  }
  const placed: { id: string; x: number; y: number; node: AttackNode }[] = [];
  for (const [column, members] of [...columns.entries()].sort((a, b) => a[0] - b[0])) {
    members.sort((a, b) => (b.max_score ?? 0) - (a.max_score ?? 0) || a.id.localeCompare(b.id));
    members.forEach((node, index) => placed.push({ id: node.id, x: column * COLUMN, y: (index - (members.length - 1) / 2) * ROW, node }));
  }
  return placed;
}

const AttackNodeView = memo(function AttackNodeView({ data }: NodeProps<AttackFlowNode>) {
  const { node } = data;
  return (
    <div
      className={`w-[210px] rounded-md border px-3 py-1.5 ${STAGE_TONE[node.stage]} ${data.highlighted ? "ring-2 ring-ink" : ""} ${data.dimmed ? "opacity-30" : ""}`}
      data-testid="attack-node" data-stage={node.stage} data-node={node.id} data-basis={node.basis} title={node.detail}
    >
      <Handle type="target" position={Position.Left} isConnectable={false} />
      <div className={`font-mono text-[10px] uppercase tracking-wider ${node.stage === "ENTRY" ? "text-signal" : "text-muted"}`}>
        {STAGE_LABEL[node.stage]}{node.vulnerable ? " · affected" : ""}
      </div>
      <div className="truncate text-[12px] font-semibold">{node.label}</div>
      <div className={`font-mono text-[10px] ${node.stage === "ENTRY" ? "text-white/70" : "text-muted"}`}>
        {node.basis.toLowerCase()}{node.paths ? ` · ${node.paths} path${node.paths === 1 ? "" : "s"}` : ""}
      </div>
      <Handle type="source" position={Position.Right} isConnectable={false} />
    </div>
  );
});

const nodeTypes = { attack: AttackNodeView };

/**
 * Attack paths as a graph. Solid edges are observed or derived steps; dashed edges are inferred ones. Nothing in the
 * graph says that a path was exercised.
 */
export function AttackGraph({ nodes, edges, highlight, onSelect, viewKey, height = 520 }: {
  nodes: AttackNode[];
  edges: AttackEdge[];
  /** Node ids to emphasise (for example one path). Everything else is dimmed. */
  highlight?: Set<string> | null;
  onSelect?: (node: AttackNode | null) => void;
  viewKey: string;
  height?: number;
}) {
  const placed = useMemo(() => layoutAttackGraph(nodes, edges), [nodes, edges]);
  const flowNodes = useMemo<AttackFlowNode[]>(
    () => placed.map((item) => ({
      id: item.id, type: "attack", position: { x: item.x, y: item.y }, draggable: true, connectable: false,
      data: { node: item.node, highlighted: Boolean(highlight?.has(item.id)), dimmed: Boolean(highlight && highlight.size > 0 && !highlight.has(item.id)) },
    })),
    [placed, highlight],
  );
  const flowEdges = useMemo<Edge[]>(
    () => edges.map((edge) => {
      const active = !highlight || highlight.size === 0 || (highlight.has(edge.source) && highlight.has(edge.target));
      const inferred = edge.basis === "INFERRED";
      return {
        id: `${edge.source}->${edge.target}:${edge.kind}`, source: edge.source, target: edge.target,
        style: { stroke: active ? "#2a313c" : "#d6d2c7", strokeWidth: active ? 1.4 : 1, strokeDasharray: inferred ? "5 4" : undefined },
        interactionWidth: 0, selectable: false, focusable: false,
      };
    }),
    [edges, highlight],
  );
  return (
    <div className="w-full overflow-hidden rounded-md border border-line bg-surface" style={{ height }} data-testid="attack-graph">
      <ReactFlow
        key={viewKey} nodes={flowNodes} edges={flowEdges} nodeTypes={nodeTypes} nodesConnectable={false} elementsSelectable
        onNodeClick={(_event, node) => onSelect?.(node.data.node)} onPaneClick={() => onSelect?.(null)}
        fitView fitViewOptions={{ padding: 0.12, maxZoom: 1 }} minZoom={0.05} maxZoom={2}
      >
        <Background gap={24} color="#e8e5dc" />
        <Controls showInteractive={false} />
        <MiniMap pannable zoomable nodeStrokeWidth={2} />
      </ReactFlow>
    </div>
  );
}
