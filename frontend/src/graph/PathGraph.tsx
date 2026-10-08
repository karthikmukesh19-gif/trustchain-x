import { Background, Controls, Handle, Position, ReactFlow } from "@xyflow/react";
import type { Edge, Node, NodeProps } from "@xyflow/react";
import { memo, useMemo } from "react";

import "@xyflow/react/dist/style.css";

import type { CodePath, CodePathNode } from "../utils/types";

type StepData = { node: CodePathNode; first: boolean; last: boolean; affected: boolean };
type StepNode = Node<StepData, "step">;

const SPACING = 290;
const KIND_LABEL: Record<string, string> = { module: "module", class: "class", function: "function", method: "method", external: "dependency" };

const Step = memo(function Step({ data }: NodeProps<StepNode>) {
  const { node, first, last, affected } = data;
  const external = node.kind === "external";
  return (
    <div
      className={`w-[240px] rounded-md border px-3 py-2 ${external && affected ? "border-danger bg-danger-soft" : external ? "border-ink bg-paper" : "border-line bg-surface"}`}
      data-testid="path-node"
      data-kind={node.kind}
    >
      {!first && <Handle type="target" position={Position.Left} isConnectable={false} />}
      <div className="font-mono text-[10px] uppercase tracking-wider text-muted">
        {external && affected ? "affected · " : ""}{KIND_LABEL[node.kind] ?? node.kind}{node.is_test ? " · test code" : ""}
      </div>
      <div className="truncate font-mono text-[12px] font-semibold" title={node.label}>{node.label}</div>
      {node.path && <div className="truncate font-mono text-[11px] text-muted" title={node.path}>{node.path}{node.line ? `:${node.line}` : ""}</div>}
      {!last && <Handle type="source" position={Position.Right} isConnectable={false} />}
    </div>
  );
});

const nodeTypes = { step: Step };

/**
 * A discovered code path, drawn left to right. Dashed edges are not explicit calls.
 * `affected` says whether the path ends at a name identified as affected, or only at a use of the package.
 */
export function PathGraph({ path, affected }: { path: CodePath; affected: boolean }) {
  const nodes = useMemo<StepNode[]>(
    () => path.nodes.map((node, index) => ({
      id: `${index}`, type: "step", position: { x: index * SPACING, y: 0 },
      data: { node, first: index === 0, last: index === path.nodes.length - 1, affected }, draggable: false, connectable: false,
    })),
    [path.nodes, affected],
  );
  const edges = useMemo<Edge[]>(
    () => path.edges.map((edge, index) => ({
      id: `e${index}`, source: `${index}`, target: `${index + 1}`,
      label: `${edge.kind} · ${edge.confidence}`,
      labelStyle: { fontSize: 10, fontFamily: "ui-monospace, monospace" },
      style: { stroke: "#12161c", strokeWidth: 1.4, strokeDasharray: edge.kind === "calls" && edge.confidence === "HIGH" ? undefined : "5 4" },
    })),
    [path.edges],
  );
  return (
    <div className="h-[170px] rounded-md border border-line bg-paper" data-testid="path-graph" aria-label="Discovered code path">
      <ReactFlow
        nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.15, maxZoom: 1 }}
        nodesConnectable={false} nodesDraggable={false} elementsSelectable={false} proOptions={{ hideAttribution: true }} minZoom={0.2}
      >
        <Background gap={24} color="#e4e1d8" />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
