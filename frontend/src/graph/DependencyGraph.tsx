import { Background, Controls, Handle, MiniMap, Position, ReactFlow } from "@xyflow/react";
import type { Edge, Node, NodeProps } from "@xyflow/react";
import { memo, useMemo } from "react";

import "@xyflow/react/dist/style.css";

import type { GraphNode } from "../utils/types";
import { ROOT_ID } from "./layout";
import type { GraphLayout } from "./layout";

type PackageData = { label: string; node: GraphNode | null; selected: boolean };
type PackageFlowNode = Node<PackageData, "package">;

const TONE: Record<string, string> = {
  DIRECT: "border-trust bg-trust-soft",
  TRANSITIVE: "border-line bg-surface",
  UNKNOWN: "border-dashed border-faint bg-paper",
};

const PackageNode = memo(function PackageNode({ data }: NodeProps<PackageFlowNode>) {
  const node = data.node;
  if (node === null) {
    return (
      <div className="w-[220px] rounded-md border-2 border-ink bg-ink px-3 py-2 text-white" data-testid="graph-root">
        <div className="font-mono text-[10px] uppercase tracking-wider text-signal">Project</div>
        <div className="truncate text-sm font-semibold">{data.label}</div>
        <Handle type="source" position={Position.Right} isConnectable={false} />
      </div>
    );
  }
  return (
    <div
      className={`w-[220px] rounded-md border px-3 py-1.5 ${TONE[node.relationship] ?? TONE.UNKNOWN} ${data.selected ? "ring-2 ring-ink" : ""}`}
      data-testid="graph-node"
      data-relationship={node.relationship}
      data-depth={node.depth ?? "none"}
    >
      <Handle type="target" position={Position.Left} isConnectable={false} />
      <div className="truncate font-mono text-[12px] font-semibold" title={node.name}>{node.name}</div>
      <div className="flex items-center justify-between gap-2 text-[11px] text-muted">
        <span className="truncate font-mono">{node.version ?? "unresolved"}</span>
        <span className="shrink-0">
          {node.relationship === "DIRECT" ? "direct" : node.relationship === "TRANSITIVE" ? "transitive" : "unknown"}
          {node.depth !== null ? ` · d${node.depth}` : ""}
        </span>
      </div>
      <Handle type="source" position={Position.Right} isConnectable={false} />
    </div>
  );
});

const nodeTypes = { package: PackageNode };

interface Props {
  layout: GraphLayout;
  selectedId: string | null;
  onSelect: (nodeId: string | null) => void;
  /** Changes whenever the set of drawn packages changes, so the view is fitted to the new layout. */
  viewKey: string;
}

export function DependencyGraph({ layout, selectedId, onSelect, viewKey }: Props) {
  const nodes = useMemo<PackageFlowNode[]>(
    () =>
      layout.nodes.map((item) => ({
        id: item.id,
        type: "package",
        position: { x: item.x, y: item.y },
        data: { label: item.label, node: item.node, selected: item.id === selectedId },
        draggable: true,
        connectable: false,
      })),
    [layout.nodes, selectedId],
  );
  const edges = useMemo<Edge[]>(
    () =>
      layout.edges.map((edge) => {
        const highlighted = selectedId !== null && (edge.source === selectedId || edge.target === selectedId);
        return {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          style: {
            stroke: highlighted ? "#12161c" : "#b9b5aa",
            strokeWidth: highlighted ? 1.8 : 1,
            strokeDasharray: edge.inferred ? "5 4" : undefined,
          },
          zIndex: highlighted ? 1 : 0,
        };
      }),
    [layout.edges, selectedId],
  );

  return (
    <div className="h-[620px] w-full overflow-hidden rounded-md border border-line bg-surface" data-testid="dependency-graph">
      <ReactFlow
        key={viewKey}
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodeClick={(_event, node) => onSelect(node.id === ROOT_ID ? null : node.id)}
        onPaneClick={() => onSelect(null)}
        nodesConnectable={false}
        elementsSelectable
        fitView
        fitViewOptions={{ padding: 0.15, maxZoom: 1 }}
        minZoom={0.05}
        maxZoom={2}
        onlyRenderVisibleElements
      >
        <Background gap={24} color="#e8e5dc" />
        <Controls showInteractive={false} />
        <MiniMap pannable zoomable nodeStrokeWidth={2} />
      </ReactFlow>
    </div>
  );
}
