import type { GraphKind, GraphNode } from "./types";

export type GraphScope = GraphKind | "all";
export type HealthTone = "nominal" | "active" | "attention" | "critical" | "unknown";

export interface HealthSignal {
  color: string;
  edgeColor: string;
  edgeType: "solid" | "dashed";
  label: string;
  pulse: boolean;
  tone: HealthTone;
}

export interface GridLane {
  count: number;
  graph: GraphKind;
  label: string;
  shortLabel: string;
  tone: HealthTone;
}

export interface GridNodeModel extends GraphNode {
  health: HealthSignal;
  size: number;
  symbol: "circle" | "diamond" | "roundRect";
  x: number;
  y: number;
}

export interface GridLinkModel {
  health: HealthSignal;
  source: GridNodeModel;
  target: GridNodeModel;
}

export interface GridModel {
  lanes: GridLane[];
  links: GridLinkModel[];
  nodes: GridNodeModel[];
  summary: GridSummary;
  unresolvedDependencies: number;
}

export interface GridSummary {
  active: number;
  attention: number;
  critical: number;
  nominal: number;
  overallTone: HealthTone;
  total: number;
  unknown: number;
}

export const graphOrder: GraphKind[] = ["mathematical", "formal", "execution"];

export const graphPresentation: Record<
  GraphKind,
  { label: string; shortLabel: string; symbol: GridNodeModel["symbol"] }
> = {
  mathematical: {
    label: "Builder · Mathematical",
    shortLabel: "Builder",
    symbol: "circle"
  },
  formal: {
    label: "Bridge · Formal",
    shortLabel: "Contract",
    symbol: "diamond"
  },
  execution: {
    label: "Prover · Execution",
    shortLabel: "Execution",
    symbol: "roundRect"
  }
};

const tonePriority: Record<HealthTone, number> = {
  unknown: 0,
  nominal: 1,
  attention: 2,
  active: 3,
  critical: 4
};

export function healthForStatus(status: string): HealthSignal {
  const normalized = status.trim().toLowerCase();
  if (["blocked", "failed", "rejected", "expired", "stale"].includes(normalized)) {
    return {
      color: "#dc6156",
      edgeColor: "#e37a70",
      edgeType: "dashed",
      label: "Critical",
      pulse: true,
      tone: "critical"
    };
  }
  if (["running", "claimed", "active"].includes(normalized)) {
    return {
      color: "#46b8c8",
      edgeColor: "#67c9d5",
      edgeType: "solid",
      label: "Active",
      pulse: true,
      tone: "active"
    };
  }
  if (["queued", "candidate", "review", "pending"].includes(normalized)) {
    return {
      color: "#d7ae54",
      edgeColor: "#cbb36f",
      edgeType: "dashed",
      label: "Attention",
      pulse: false,
      tone: "attention"
    };
  }
  if (["frozen", "verified", "accepted", "succeeded", "ready"].includes(normalized)) {
    return {
      color: "#4eb489",
      edgeColor: "#65b997",
      edgeType: "solid",
      label: "Nominal",
      pulse: false,
      tone: "nominal"
    };
  }
  return {
    color: "#859096",
    edgeColor: "#6f7b80",
    edgeType: "solid",
    label: "Unknown",
    pulse: false,
    tone: "unknown"
  };
}

export function summarizeGrid(nodes: GraphNode[]): GridSummary {
  const summary: GridSummary = {
    active: 0,
    attention: 0,
    critical: 0,
    nominal: 0,
    overallTone: "unknown",
    total: nodes.length,
    unknown: 0
  };
  for (const node of nodes) {
    summary[healthForStatus(node.status).tone] += 1;
  }
  if (summary.critical > 0) summary.overallTone = "critical";
  else if (summary.active > 0) summary.overallTone = "active";
  else if (summary.attention > 0) summary.overallTone = "attention";
  else if (summary.nominal > 0) summary.overallTone = "nominal";
  return summary;
}

function strongestTone(nodes: GraphNode[]): HealthTone {
  let strongest: HealthTone = "unknown";
  for (const node of nodes) {
    const tone = healthForStatus(node.status).tone;
    if (tonePriority[tone] > tonePriority[strongest]) strongest = tone;
  }
  return strongest;
}

function topologicalOrder(nodes: GraphNode[]): GraphNode[] {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const incoming = new Map(nodes.map((node) => [node.id, 0]));
  const outgoing = new Map(nodes.map((node) => [node.id, [] as string[]]));

  for (const node of nodes) {
    for (const dependency of node.dependencies) {
      if (!byId.has(dependency)) continue;
      incoming.set(node.id, (incoming.get(node.id) ?? 0) + 1);
      outgoing.get(dependency)?.push(node.id);
    }
  }

  const queue = nodes
    .filter((node) => incoming.get(node.id) === 0)
    .sort((left, right) => left.id.localeCompare(right.id));
  const ordered: GraphNode[] = [];
  while (queue.length > 0) {
    const current = queue.shift();
    if (!current) break;
    ordered.push(current);
    for (const target of outgoing.get(current.id) ?? []) {
      const next = (incoming.get(target) ?? 1) - 1;
      incoming.set(target, next);
      if (next === 0) {
        const targetNode = byId.get(target);
        if (targetNode) {
          queue.push(targetNode);
          queue.sort((left, right) => left.id.localeCompare(right.id));
        }
      }
    }
  }

  const emitted = new Set(ordered.map((node) => node.id));
  return ordered.concat(
    nodes.filter((node) => !emitted.has(node.id)).sort((left, right) => left.id.localeCompare(right.id))
  );
}

function layoutLane(
  nodes: GraphNode[],
  graph: GraphKind,
  laneIndex: number,
  laneCount: number,
  scope: GraphScope
): GridNodeModel[] {
  const ordered = topologicalOrder(nodes);
  const maximumColumns = scope === "all" ? 3 : 8;
  const columns = Math.min(maximumColumns, Math.max(1, Math.ceil(Math.sqrt(ordered.length * 0.7))));
  const rows = Math.max(1, Math.ceil(ordered.length / columns));
  const laneWidth = 100 / laneCount;
  const center = laneWidth * laneIndex + laneWidth / 2;
  const horizontalSpan = laneWidth * (scope === "all" ? 0.58 : 0.78);
  const presentation = graphPresentation[graph];

  return ordered.map((node, index) => {
    const column = index % columns;
    const row = Math.floor(index / columns);
    const x =
      columns === 1
        ? center
        : center - horizontalSpan / 2 + (horizontalSpan * column) / (columns - 1);
    const y = rows === 1 ? 50 : 14 + (72 * row) / (rows - 1);
    return {
      ...node,
      health: healthForStatus(node.status),
      size: Math.min(31, (node.kind === "mission" ? 25 : 17) + Math.min(6, node.dependencies.length)),
      symbol: presentation.symbol,
      x,
      y
    };
  });
}

export function buildGridModel(nodes: GraphNode[], scope: GraphScope = "all"): GridModel {
  const visibleGraphs = scope === "all" ? graphOrder : [scope];
  const visibleNodes = nodes.filter((node) => visibleGraphs.includes(node.graph));
  const lanes: GridLane[] = visibleGraphs.map((graph) => {
    const graphNodes = visibleNodes.filter((node) => node.graph === graph);
    return {
      count: graphNodes.length,
      graph,
      label: graphPresentation[graph].label,
      shortLabel: graphPresentation[graph].shortLabel,
      tone: strongestTone(graphNodes)
    };
  });
  const positioned = visibleGraphs.flatMap((graph, laneIndex) =>
    layoutLane(
      visibleNodes.filter((node) => node.graph === graph),
      graph,
      laneIndex,
      visibleGraphs.length,
      scope
    )
  );
  const byId = new Map(positioned.map((node) => [node.id, node]));
  const links: GridLinkModel[] = [];
  let unresolvedDependencies = 0;
  for (const node of positioned) {
    for (const dependency of node.dependencies) {
      const source = byId.get(dependency);
      if (!source) {
        unresolvedDependencies += 1;
        continue;
      }
      links.push({ health: node.health, source, target: node });
    }
  }

  return {
    lanes,
    links,
    nodes: positioned,
    summary: summarizeGrid(visibleNodes),
    unresolvedDependencies
  };
}
