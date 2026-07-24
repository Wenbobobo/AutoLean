import type { PhaseFeedback } from "./types";

export const LEVERAGE_DISPLAY_LIMIT = 24;

export type FeedbackTone = "nominal" | "active" | "attention" | "critical";

export interface LeverageWindow {
  rows: PhaseFeedback["mathematical_dependency_leverage"];
  omittedCount: number;
  isDegraded: boolean;
}

export interface LeverageMetric {
  value: number;
  label: "transitive" | "direct";
}

export function leverageWindow(
  rows: PhaseFeedback["mathematical_dependency_leverage"],
  limit = LEVERAGE_DISPLAY_LIMIT
): LeverageWindow {
  if (!Number.isInteger(limit) || limit < 1) {
    throw new RangeError("Leverage display limit must be a positive integer");
  }
  return {
    rows: rows.slice(0, limit),
    omittedCount: Math.max(0, rows.length - limit),
    isDegraded: rows.length > limit
  };
}

export function leverageMetric(
  row: PhaseFeedback["mathematical_dependency_leverage"][number],
  mode: PhaseFeedback["dependency_leverage_mode"]
): LeverageMetric {
  if (mode === "exact_transitive") {
    if (row.transitive_dependents === null) {
      throw new Error("Exact transitive leverage requires a transitive count");
    }
    return { value: row.transitive_dependents, label: "transitive" };
  }
  if (row.transitive_dependents !== null) {
    throw new Error("Direct-only leverage must not expose a transitive count");
  }
  return { value: row.direct_dependents, label: "direct" };
}

export function feedbackTone(feedback: PhaseFeedback): FeedbackTone {
  if (feedback.prover_verification.state === "all_candidates_rejected") return "critical";
  if (feedback.unresolved_human_review_assumptions.length > 0) return "attention";
  if (
    feedback.prover_verification.state === "candidate_pending_verification" ||
    feedback.prover_verification.state === "mixed_candidates"
  ) {
    return "active";
  }
  return "nominal";
}
