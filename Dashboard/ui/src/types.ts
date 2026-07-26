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
  source_node_id: string;
  task_id: string;
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
  task_id: string | null;
  occurred_at: string;
  summary: string;
}

export interface PhaseFeedback {
  schema_version: "phase-feedback.v1";
  task_id: string;
  builder_fidelity: {
    state: "frozen_attested_with_evidence" | "frozen_attested_without_public_evidence";
    contract_id: string;
    revision: number;
    contract_hash: string;
    bundle_hash: string;
    registration_event_sequence: number;
    registration_event_id: string;
    registered_at: string;
    evidence_digest: string | null;
  };
  prover_verification: {
    state:
      | "not_submitted"
      | "candidate_pending_verification"
      | "verified_candidate_available"
      | "all_candidates_rejected"
      | "mixed_candidates";
    submitted_proof_ids: string[];
    pending_proof_ids: string[];
    accepted_proof_ids: string[];
    rejected_proof_ids: string[];
  };
  unresolved_human_review_assumptions: Array<{
    id: string;
    kind: "gap" | "contract_change";
    state: "unresolved";
    source_event_sequence: number;
    source_event_id: string;
    opened_at: string;
    evidence_digest: string | null;
  }>;
  mathematical_dependency_node_count: number;
  dependency_leverage_exact_node_limit: 512;
  dependency_leverage_mode: "exact_transitive" | "direct_only_over_limit";
  mathematical_dependency_leverage: Array<{
    node_id: string;
    source_node_id: string;
    label: string;
    direct_dependents: number;
    transitive_dependents: number | null;
  }>;
  milestones: Array<{
    phase: "builder_fidelity" | "prover_candidate" | "prover_verification" | "human_review";
    state: "recorded" | "pending" | "accepted" | "rejected" | "unresolved";
    source_event_sequence: number;
    source_event_id: string;
    occurred_at: string;
    evidence_digest: string | null;
    proof_id: string | null;
    review_assumption_id: string | null;
  }>;
  replay: {
    first_relevant_event_sequence: number;
    last_relevant_event_sequence: number;
    last_relevant_event_id: string;
    last_relevant_event_recorded_at: string;
    relevant_event_count: number;
    relevant_event_sequences: number[];
    replay_head_event_sequence: number;
    replay_head_event_id: string;
    replay_head_recorded_at: string;
    events_observed_after_last_relevant: number;
    last_relevant_event_is_replay_head: boolean;
    freshness_scope: "bounded_to_replayed_events";
  };
  promotion_state: "not_a_promotion";
}

export interface DashboardSnapshot {
  overview: Overview;
  nodes: GraphNode[];
  runs: RunSummary[];
  artifacts: ArtifactSummary[];
  events: EventView[];
  phase_feedback: PhaseFeedback[];
}

export type WorkRecordCategory =
  | "task"
  | "attempt"
  | "gap"
  | "contract_change"
  | "verification"
  | "synthetic_execution"
  | "benchmark"
  | "other";

export interface WorkRecord {
  sequence: number;
  category: WorkRecordCategory;
  event: EventView;
}
