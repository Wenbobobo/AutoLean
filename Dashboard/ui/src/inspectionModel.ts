import { healthForStatus } from "./gridModel.ts";
import type {
  EventView,
  GraphNode,
  RunSummary,
  WorkRecord,
  WorkRecordCategory
} from "./types";

export interface DependencyReference {
  id: string;
  node: GraphNode | null;
}

export interface NodeInspection {
  downstream: GraphNode[];
  node: GraphNode;
  runs: RunSummary[];
  totalCostUsd: number;
  totalTokens: number;
  upstream: DependencyReference[];
  workRecords: WorkRecord[];
}

const focusPriority = {
  critical: 0,
  unknown: 1,
  active: 2,
  attention: 3,
  nominal: 4
} as const;

export function classifyWorkRecord(event: EventView): WorkRecord {
  let category: WorkRecordCategory = "other";
  if (event.event_type === "gap.reported") category = "gap";
  else if (event.event_type === "contract_change.requested") category = "contract_change";
  else if (event.event_type.startsWith("verification.")) category = "verification";
  else if (event.event_type.startsWith("t7_synthetic_node_v2.")) category = "synthetic_execution";
  else if (event.event_type.startsWith("fate.attempt.")) category = "benchmark";
  else if (event.event_type === "proof.submitted") category = "attempt";
  else if (event.event_type.startsWith("task.")) category = "task";
  return { sequence: event.sequence, category, event };
}

export function focusNode(nodes: GraphNode[], requestedId: string | null): GraphNode | null {
  const requested = nodes.find((node) => node.id === requestedId);
  if (requested) return requested;
  return (
    [...nodes].sort((left, right) => {
      const leftPriority = focusPriority[healthForStatus(left.status).tone];
      const rightPriority = focusPriority[healthForStatus(right.status).tone];
      return leftPriority - rightPriority || left.id.localeCompare(right.id);
    })[0] ?? null
  );
}

export function buildNodeInspection(
  nodes: GraphNode[],
  runs: RunSummary[],
  events: EventView[],
  nodeId: string | null
): NodeInspection | null {
  const node = nodes.find((candidate) => candidate.id === nodeId);
  if (!node) return null;

  const byId = new Map(nodes.map((candidate) => [candidate.id, candidate]));
  const syntheticExecution = node.kind === "synthetic_execution";
  const relatedRuns = syntheticExecution
    ? []
    : runs
        .filter((run) => run.task_id === node.task_id)
        .sort((left, right) => (right.started_at ?? "").localeCompare(left.started_at ?? ""));
  const workRecords = events
    .filter(
      (event) =>
        event.task_id === node.task_id &&
        (!syntheticExecution || event.event_type.startsWith("t7_synthetic_node_v2."))
    )
    .map(classifyWorkRecord)
    .sort((left, right) => right.sequence - left.sequence);

  return {
    downstream: nodes
      .filter((candidate) => candidate.dependencies.includes(node.id))
      .sort((left, right) => left.id.localeCompare(right.id)),
    node,
    runs: relatedRuns,
    totalCostUsd: relatedRuns.reduce((total, run) => total + run.cost_usd, 0),
    totalTokens: relatedRuns.reduce(
      (total, run) => total + run.input_tokens + run.output_tokens,
      0
    ),
    upstream: node.dependencies.map((id) => ({ id, node: byId.get(id) ?? null })),
    workRecords
  };
}
