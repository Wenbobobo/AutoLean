export type GraphKind = "mathematical" | "formal" | "execution";

export interface Metric {
  label: string;
  value: string | number;
  trend?: number | null;
}

export interface Overview {
  generated_at: string;
  mission: string;
  metrics: Metric[];
  active_runs: number;
  blocked_nodes: number;
}

export interface GraphNode {
  id: string;
  label: string;
  graph: GraphKind;
  status: string;
  revision: number;
  kind: string;
  dependencies: string[];
  updated_at?: string | null;
}

export interface RunSummary {
  id: string;
  task_id: string;
  provider: string;
  model: string;
  status: string;
  started_at?: string | null;
  duration_ms?: number | null;
  input_tokens: number;
  output_tokens: number;
  cost_usd: number;
  verification: string;
}

export interface ArtifactSummary {
  digest: string;
  media_type: string;
  size: number;
  kind: string;
  created_at?: string | null;
}

export interface EventView {
  sequence: number;
  event_type: string;
  entity_id: string;
  occurred_at: string;
  summary: string;
}

export interface DashboardSnapshot {
  overview: Overview;
  nodes: GraphNode[];
  runs: RunSummary[];
  artifacts: ArtifactSummary[];
  events: EventView[];
}

export type WorkRecordCategory =
  | "task"
  | "attempt"
  | "gap"
  | "contract_change"
  | "verification"
  | "other";

export interface WorkRecord {
  sequence: number;
  category: WorkRecordCategory;
  event: EventView;
}
