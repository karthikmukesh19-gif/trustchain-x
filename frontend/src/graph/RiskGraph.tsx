import { Background, Controls, Handle, MiniMap, Position, ReactFlow } from "@xyflow/react";
import type { Edge, Node, NodeProps } from "@xyflow/react";
import { memo, useMemo } from "react";

import "@xyflow/react/dist/style.css";

import type { RiskGraphNode } from "../utils/types";
import { ROOT_ID } from "./layout";
import type { RiskLayout } from "./riskLayout";

type RiskData = { label: string; node: RiskGraphNode | null; selected: boolean };
type RiskFlowNode = Node<RiskData, "risk">;

const LEVEL_TONE: Record<string, string> = {
  HIGH: "border-danger bg-danger-soft",
  MEDIUM: "border-warn bg-warn-soft",
  LOW: "border-line bg-surface",
};
const EXPOSURE_TAG: Record<string, string> = {
  DIRECT_VULNERABILITY: "known vulnerability",
  DEPENDENCY_PROPAGATION: "requires vulnerable",
  INDIRECT_EXPOSURE: "indirect exposure",
};

const RiskNode = memo(function RiskNode({ data }: NodeProps<RiskFlowNode>) {
  const node = data.node;
  if (node === null) {
    return (
      <div className="w-[220px] rounded-md border-2 border-ink bg-ink px-3 py-2 text-white" data-testid="risk-graph-root">
        <div className="font-mono text-[10px] uppercase tracking-wider text-signal">Project</div>
        <div className="truncate text-sm font-semibold">{data.label}</div>
        <Handle type="source" position={Position.Right} isConnectable={false} />
      </div>
    );
  }
  const tag = EXPOSURE_TAG[node.exposure_classification];
  const reachable = node.reachable_vulnerability_count !== null && node.reachable_vulnerability_count > 0;
  return (
    <div
      className={`w-[230px] rounded-md border px-3 py-1.5 ${LEVEL_TONE[node.level] ?? LEVEL_TONE.LOW} ${data.selected ? "ring-2 ring-ink" : ""}`}
      data-testid="risk-node" data-node={node.normalized_name} data-level={node.level} data-classification={node.exposure_classification}
      data-relationship={node.relationship}
    >
      <Handle type="target" position={Position.Left} isConnectable={false} />
      <div className="flex items-baseline justify-between gap-2">
        <span className="truncate font-mono text-[12px] font-semibold" title={node.package_name}>{node.package_name || node.normalized_name}</span>
        <span className="shrink-0 font-mono text-[10px] text-muted">{node.version ?? "unresolved"}</span>
      </div>
      <div className="flex items-center justify-between gap-2 font-mono text-[11px]">
        <span title="Predictive dependency risk, 0-100">risk {node.score.toFixed(1)}</span>
        <span className="text-muted" title="Fragility, 0-100">fragility {node.fragility_score.toFixed(1)}</span>
      </div>
      <div className="truncate text-[10px] uppercase tracking-wide text-muted">
        {node.relationship === "DIRECT" ? "direct" : node.relationship === "TRANSITIVE" ? "transitive" : "unknown"}
        {tag ? ` · ${tag}` : ""}{reachable ? " · reachable" : ""}
      </div>
      <Handle type="source" position={Position.Right} isConnectable={false} />
    </div>
  );
});

const nodeTypes = { risk: RiskNode };

/** The dependency graph with each package's scores. Red edges are those along which exposure to a known vulnerability travels. */
export function RiskGraph({ layout, selectedId, onSelect, viewKey }: {
  layout: RiskLayout;
  selectedId: string | null;
  onSelect: (nodeId: string | null) => void;
  viewKey: string;
}) {
  const nodes = useMemo<RiskFlowNode[]>(
    () => layout.nodes.map((item) => ({
      id: item.id, type: "risk", position: { x: item.x, y: item.y },
      data: { label: item.label, node: item.node, selected: item.id === selectedId }, draggable: true, connectable: false,
    })),
    [layout.nodes, selectedId],
  );
  const edges = useMemo<Edge[]>(
    () => layout.edges.map((edge) => {
      const highlighted = selectedId !== null && (edge.source === selectedId || edge.target === selectedId);
      return {
        id: edge.id, source: edge.source, target: edge.target, className: edge.exposure ? "exposure-edge" : "plain-edge",
        style: { stroke: edge.exposure ? "#b3261e" : highlighted ? "#12161c" : "#b9b5aa", strokeWidth: highlighted ? 2 : edge.exposure ? 1.4 : 1 },
        // Edges are not interactive: an edge between two packages of the same depth curves back across the column and
        // must not take clicks meant for the package underneath it.
        interactionWidth: 0, selectable: false, focusable: false,
      };
    }),
    [layout.edges, selectedId],
  );
  return (
    <div className="h-[620px] w-full overflow-hidden rounded-md border border-line bg-surface" data-testid="risk-graph">
      <ReactFlow
        key={viewKey} nodes={nodes} edges={edges} nodeTypes={nodeTypes}
        onNodeClick={(_event, node) => onSelect(node.id === ROOT_ID ? null : node.id)} onPaneClick={() => onSelect(null)}
        nodesConnectable={false} elementsSelectable fitView fitViewOptions={{ padding: 0.15, maxZoom: 1 }} minZoom={0.05} maxZoom={2}
      >
        <Background gap={24} color="#e8e5dc" />
        <Controls showInteractive={false} />
        <MiniMap pannable zoomable nodeStrokeWidth={2} />
      </ReactFlow>
    </div>
  );
}
