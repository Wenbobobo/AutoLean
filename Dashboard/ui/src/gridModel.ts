import type { EventView, GraphKind, GraphNode } from "./types";

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

export type DagEventState =
  | "attempt"
  | "gap"
  | "contract_change"
  | "verification"
  | "synthetic_execution"
  | "benchmark"
  | "other"
  | null;

export interface DagHealthCell {
  attempts: number;
  dependencies: number;
  dependents: number;
  eventState: DagEventState;
  gaps: number;
  graph: GraphKind;
  healthLabel: string;
  id: string;
  kind: string;
  label: string;
  revision: number;
  taskId: string;
  tone: HealthTone;
}

export interface DagHealthColumn {
  attempts: number;
  cells: DagHealthCell[];
  externalDependencies: number;
  gaps: number;
  graph: GraphKind;
  label: string;
  nodeCount: number;
  omitted: number;
  shortLabel: string;
  tone: HealthTone;
}

export interface DagHealthMap {
  columns: DagHealthColumn[];
  scope: GraphScope;
  totalAttempts: number;
  totalEdges: number;
  totalGaps: number;
  totalNodes: number;
  unresolvedDependencies: number;
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
    label: "Contract boundary · Formal",
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
  nominal: 0,
  attention: 1,
  active: 2,
  unknown: 3,
  critical: 4
};

export function healthForStatus(status: string): HealthSignal {
  const normalized = status.trim().toLowerCase();
  if (["blocked", "critical", "failed", "rejected", "expired", "stale", "synthetic_failed"].includes(normalized)) {
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
  if ([
    "attention",
    "queued",
    "candidate",
    "review",
    "pending",
    "synthetic_complete",
    "synthetic_reused",
    "benchmark_running",
    "benchmark_verified",
    "benchmark_rejected"
  ].includes(normalized)) {
    return {
      color: "#d7ae54",
      edgeColor: "#cbb36f",
      edgeType: "dashed",
      label: "Attention",
      pulse: false,
      tone: "attention"
    };
  }
  if (["nominal", "frozen", "verified", "accepted", "succeeded", "ready"].includes(normalized)) {
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
  else if (summary.unknown > 0) summary.overallTone = "unknown";
  else if (summary.active > 0) summary.overallTone = "active";
  else if (summary.attention > 0) summary.overallTone = "attention";
  else if (summary.nominal > 0) summary.overallTone = "nominal";
  return summary;
}

function strongestTone(nodes: GraphNode[]): HealthTone {
  if (nodes.length === 0) return "unknown";
  let strongest = healthForStatus(nodes[0]!.status).tone;
  for (const node of nodes.slice(1)) {
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
  const horizontalSpan = laneWidth * (scope === "all" ? 0.58 : 0.5);
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

function eventStateForType(eventType: string): Exclude<DagEventState, null> {
  if (eventType === "gap.reported") return "gap";
  if (eventType === "contract_change.requested") return "contract_change";
  if (eventType === "proof.submitted") return "attempt";
  if (eventType.startsWith("verification.")) return "verification";
  if (eventType.startsWith("t7_synthetic_node_v2.")) return "synthetic_execution";
  if (eventType.startsWith("fate.attempt.")) return "benchmark";
  return "other";
}

function eventMatchesNode(event: EventView, node: GraphNode): boolean {
  if (node.kind === "synthetic_execution") {
    return (
      event.task_id === node.task_id &&
      event.event_type.startsWith("t7_synthetic_node_v2.")
    );
  }
  return (
    event.task_id === node.task_id ||
    event.entity_id === node.id ||
    event.entity_id === node.source_node_id
  );
}

function relevantEventsForNodes(events: EventView[], nodes: GraphNode[]): EventView[] {
  const bySequence = new Map<number, EventView>();
  for (const event of events) {
    if (nodes.some((node) => eventMatchesNode(event, node))) {
      bySequence.set(event.sequence, event);
    }
  }
  return [...bySequence.values()].sort((left, right) => right.sequence - left.sequence);
}

function countEvents(events: EventView[], eventType: string): number {
  return events.filter((event) => event.event_type === eventType).length;
}

function dominantEventState(events: EventView[]): DagEventState {
  if (events.some((event) => event.event_type === "gap.reported")) return "gap";
  if (events.some((event) => event.event_type === "contract_change.requested")) {
    return "contract_change";
  }
  if (events.some((event) => event.event_type === "proof.submitted")) return "attempt";
  if (events.some((event) => event.event_type.startsWith("verification."))) return "verification";
  if (events.some((event) => event.event_type.startsWith("t7_synthetic_node_v2."))) {
    return "synthetic_execution";
  }
  if (events.some((event) => event.event_type.startsWith("fate.attempt."))) return "benchmark";
  return events.length > 0 ? eventStateForType(events[0]!.event_type) : null;
}

/**
 * Read-only operational minimap: node colors remain current projected health;
 * attempt/gap markers are immutable event pressure, not automatic promotion state.
 */
export function buildDagHealthMap(
  nodes: GraphNode[],
  events: EventView[],
  scope: GraphScope = "all",
  cellLimit = 48
): DagHealthMap {
  if (!Number.isInteger(cellLimit) || cellLimit < 1) {
    throw new RangeError("cellLimit must be a positive integer");
  }
  const visibleGraphs = scope === "all" ? graphOrder : [scope];
  const visibleNodes = nodes.filter((node) => visibleGraphs.includes(node.graph));
  const visibleById = new Map(visibleNodes.map((node) => [node.id, node]));
  const dependents = new Map(visibleNodes.map((node) => [node.id, 0]));
  let totalEdges = 0;
  let unresolvedDependencies = 0;

  for (const node of visibleNodes) {
    for (const dependency of node.dependencies) {
      if (visibleById.has(dependency)) {
        totalEdges += 1;
        dependents.set(dependency, (dependents.get(dependency) ?? 0) + 1);
      } else {
        unresolvedDependencies += 1;
      }
    }
  }

  const columns = visibleGraphs.map((graph) => {
    const graphNodes = visibleNodes.filter((node) => node.graph === graph);
    const ordered = topologicalOrder(graphNodes);
    const graphEvents = relevantEventsForNodes(events, graphNodes);
    const attempts = countEvents(graphEvents, "proof.submitted");
    const gaps = countEvents(graphEvents, "gap.reported");
    const externalDependencies = graphNodes.reduce(
      (total, node) =>
        total + node.dependencies.filter((dependency) => !visibleById.has(dependency)).length,
      0
    );

    return {
      attempts,
      cells: ordered.slice(0, cellLimit).map((node) => {
        const nodeEvents = relevantEventsForNodes(events, [node]);
        const health = healthForStatus(node.status);
        return {
          attempts: countEvents(nodeEvents, "proof.submitted"),
          dependencies: node.dependencies.length,
          dependents: dependents.get(node.id) ?? 0,
          eventState: dominantEventState(nodeEvents),
          gaps: countEvents(nodeEvents, "gap.reported"),
          graph,
          healthLabel: health.label,
          id: node.id,
          kind: node.kind,
          label: node.label,
          revision: node.revision,
          taskId: node.task_id,
          tone: health.tone
        };
      }),
      externalDependencies,
      gaps,
      graph,
      label: graphPresentation[graph].label,
      nodeCount: graphNodes.length,
      omitted: Math.max(0, graphNodes.length - cellLimit),
      shortLabel: graphPresentation[graph].shortLabel,
      tone: strongestTone(graphNodes)
    };
  });

  return {
    columns,
    scope,
    totalAttempts: columns.reduce((total, column) => total + column.attempts, 0),
    totalEdges,
    totalGaps: columns.reduce((total, column) => total + column.gaps, 0),
    totalNodes: visibleNodes.length,
    unresolvedDependencies
  };
}
