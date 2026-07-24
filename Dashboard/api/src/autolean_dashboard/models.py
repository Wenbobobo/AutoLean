from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

StrictPositiveInt = Annotated[int, Field(strict=True, ge=1)]
StrictNonNegativeInt = Annotated[int, Field(strict=True, ge=0)]
DEPENDENCY_LEVERAGE_EXACT_NODE_LIMIT = 512


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Metric(StrictModel):
    label: str
    value: int | float | str
    trend: float | None = None


class Overview(StrictModel):
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    mission: str = "Open problem portfolio"
    metrics: tuple[Metric, ...] = ()
    active_runs: int = 0
    blocked_nodes: int = 0


class GraphNode(StrictModel):
    id: str = Field(min_length=1, max_length=768)
    source_node_id: str = Field(min_length=1, max_length=256)
    task_id: str = Field(min_length=1, max_length=256)
    label: str = Field(min_length=1, max_length=512)
    graph: Literal["mathematical", "formal", "execution"]
    status: str = Field(min_length=1, max_length=64)
    revision: StrictPositiveInt = 1
    kind: str = Field(default="statement", min_length=1, max_length=64)
    dependencies: tuple[str, ...] = ()
    updated_at: datetime | None = None


class RunSummary(StrictModel):
    id: str = Field(min_length=1, max_length=256)
    task_id: str = Field(min_length=1, max_length=256)
    provider: str = Field(min_length=1, max_length=128)
    model: str = Field(min_length=1, max_length=256)
    status: str = Field(min_length=1, max_length=64)
    started_at: datetime | None = None
    duration_ms: StrictNonNegativeInt | None = None
    input_tokens: StrictNonNegativeInt = 0
    output_tokens: StrictNonNegativeInt = 0
    cost_usd: float = Field(default=0.0, ge=0.0)
    verification: str = Field(default="pending", min_length=1, max_length=64)


class ArtifactSummary(StrictModel):
    digest: str = Field(min_length=1, max_length=256)
    media_type: str = Field(min_length=1, max_length=128)
    size: StrictNonNegativeInt
    kind: str = Field(min_length=1, max_length=64)
    created_at: datetime | None = None


class EventView(StrictModel):
    sequence: StrictPositiveInt
    event_type: str = Field(min_length=1, max_length=128)
    entity_id: str = Field(min_length=1, max_length=256)
    task_id: str | None = Field(default=None, min_length=1, max_length=256)
    occurred_at: datetime
    summary: str = Field(min_length=1, max_length=512)


class StatementRevision(StrictModel):
    """A public, revision-oriented view derived from graph nodes only."""

    id: str = Field(min_length=1, max_length=768)
    source_node_id: str = Field(min_length=1, max_length=256)
    task_id: str = Field(min_length=1, max_length=256)
    label: str = Field(min_length=1, max_length=512)
    graph: Literal["mathematical", "formal", "execution"]
    revision: StrictPositiveInt
    status: str = Field(min_length=1, max_length=64)
    kind: str = Field(min_length=1, max_length=64)
    updated_at: datetime | None = None


WorkRecordCategory = Literal[
    "task",
    "attempt",
    "gap",
    "contract_change",
    "verification",
    "other",
]


class WorkRecord(StrictModel):
    """A safe event classification; no source, prompt, or artifact body is included."""

    sequence: StrictPositiveInt
    category: WorkRecordCategory
    event_type: str = Field(min_length=1, max_length=128)
    entity_id: str = Field(min_length=1, max_length=256)
    task_id: str | None = Field(default=None, min_length=1, max_length=256)
    occurred_at: datetime
    summary: str = Field(min_length=1, max_length=512)


BuilderFidelityState = Literal[
    "frozen_attested_with_evidence",
    "frozen_attested_without_public_evidence",
]


class BuilderFidelityFeedback(StrictModel):
    """Observed Builder handoff state, not an independent promotion decision."""

    state: BuilderFidelityState
    contract_id: str = Field(min_length=1, max_length=256)
    revision: StrictPositiveInt
    contract_hash: str = Field(min_length=1, max_length=256)
    bundle_hash: str = Field(min_length=1, max_length=256)
    registration_event_sequence: StrictPositiveInt
    registration_event_id: str = Field(min_length=1, max_length=256)
    registered_at: datetime
    evidence_digest: str | None = Field(default=None, min_length=1, max_length=256)


ProverVerificationState = Literal[
    "not_submitted",
    "candidate_pending_verification",
    "verified_candidate_available",
    "all_candidates_rejected",
    "mixed_candidates",
]


class ProverVerificationFeedback(StrictModel):
    """Terminal verifier outcomes are reported, never converted into a release decision."""

    state: ProverVerificationState
    submitted_proof_ids: tuple[str, ...] = ()
    pending_proof_ids: tuple[str, ...] = ()
    accepted_proof_ids: tuple[str, ...] = ()
    rejected_proof_ids: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_evidence_partition(self) -> Self:
        collections = (
            self.submitted_proof_ids,
            self.pending_proof_ids,
            self.accepted_proof_ids,
            self.rejected_proof_ids,
        )
        if any(
            len(items) != len(set(items)) or any(not item for item in items)
            for items in collections
        ):
            raise ValueError("proof evidence IDs must be non-empty and unique")
        pending = set(self.pending_proof_ids)
        accepted = set(self.accepted_proof_ids)
        rejected = set(self.rejected_proof_ids)
        if pending & accepted or pending & rejected or accepted & rejected:
            raise ValueError("proof evidence states must be disjoint")
        if pending | accepted | rejected != set(self.submitted_proof_ids):
            raise ValueError("proof evidence states must partition submitted proofs")
        populated = sum(bool(items) for items in (pending, accepted, rejected))
        if not self.submitted_proof_ids:
            expected = "not_submitted"
        elif populated > 1:
            expected = "mixed_candidates"
        elif pending:
            expected = "candidate_pending_verification"
        elif accepted:
            expected = "verified_candidate_available"
        else:
            expected = "all_candidates_rejected"
        if self.state != expected:
            raise ValueError("prover verification state conflicts with candidate evidence")
        return self


ReviewAssumptionKind = Literal["gap", "contract_change"]


class UnresolvedHumanReviewAssumption(StrictModel):
    """A review input whose artifact body intentionally remains outside the dashboard."""

    id: str = Field(min_length=1, max_length=256)
    kind: ReviewAssumptionKind
    state: Literal["unresolved"] = "unresolved"
    source_event_sequence: StrictPositiveInt
    source_event_id: str = Field(min_length=1, max_length=256)
    opened_at: datetime
    evidence_digest: str | None = Field(default=None, min_length=1, max_length=256)


class MathematicalDependencyLeverage(StrictModel):
    """Structural reachability, not a progress score or an inferred scientific value."""

    node_id: str = Field(min_length=1, max_length=768)
    source_node_id: str = Field(min_length=1, max_length=256)
    label: str = Field(min_length=1, max_length=512)
    direct_dependents: StrictNonNegativeInt
    transitive_dependents: StrictNonNegativeInt | None


DependencyLeverageMode = Literal["exact_transitive", "direct_only_over_limit"]


FeedbackMilestonePhase = Literal[
    "builder_fidelity",
    "prover_candidate",
    "prover_verification",
    "human_review",
]
FeedbackMilestoneState = Literal["recorded", "pending", "accepted", "rejected", "unresolved"]


class FeedbackMilestone(StrictModel):
    phase: FeedbackMilestonePhase
    state: FeedbackMilestoneState
    source_event_sequence: StrictPositiveInt
    source_event_id: str = Field(min_length=1, max_length=256)
    occurred_at: datetime
    evidence_digest: str | None = Field(default=None, min_length=1, max_length=256)
    proof_id: str | None = Field(default=None, min_length=1, max_length=256)
    review_assumption_id: str | None = Field(default=None, min_length=1, max_length=256)

    @model_validator(mode="after")
    def validate_phase_reference(self) -> Self:
        allowed_states = {
            "builder_fidelity": {"recorded"},
            "prover_candidate": {"pending"},
            "prover_verification": {"accepted", "rejected"},
            "human_review": {"unresolved"},
        }
        if self.state not in allowed_states[self.phase]:
            raise ValueError("milestone state conflicts with its phase")
        if self.phase in {"prover_candidate", "prover_verification"}:
            if self.proof_id is None or self.review_assumption_id is not None:
                raise ValueError("prover milestones require only a proof reference")
        elif self.phase == "human_review":
            if self.review_assumption_id is None or self.proof_id is not None:
                raise ValueError("human-review milestones require only a review reference")
        elif self.proof_id is not None or self.review_assumption_id is not None:
            raise ValueError("builder milestones cannot carry proof or review references")
        return self


class FeedbackReplayLinkage(StrictModel):
    """Exact source events plus the replay head; this does not claim live-store freshness."""

    first_relevant_event_sequence: StrictPositiveInt
    last_relevant_event_sequence: StrictPositiveInt
    last_relevant_event_id: str = Field(min_length=1, max_length=256)
    last_relevant_event_recorded_at: datetime
    relevant_event_count: StrictPositiveInt
    relevant_event_sequences: tuple[StrictPositiveInt, ...] = Field(min_length=1)
    replay_head_event_sequence: StrictPositiveInt
    replay_head_event_id: str = Field(min_length=1, max_length=256)
    replay_head_recorded_at: datetime
    events_observed_after_last_relevant: StrictNonNegativeInt
    last_relevant_event_is_replay_head: bool
    freshness_scope: Literal["bounded_to_replayed_events"] = "bounded_to_replayed_events"

    @model_validator(mode="after")
    def validate_replay_linkage(self) -> Self:
        sequences = self.relevant_event_sequences
        if tuple(sorted(set(sequences))) != sequences:
            raise ValueError("relevant event sequences must be strictly increasing")
        if self.relevant_event_count != len(sequences):
            raise ValueError("relevant event count does not match its sequence linkage")
        if (
            self.first_relevant_event_sequence != sequences[0]
            or self.last_relevant_event_sequence != sequences[-1]
        ):
            raise ValueError("relevant event bounds do not match their sequence linkage")
        if self.replay_head_event_sequence < self.last_relevant_event_sequence:
            raise ValueError("replay head cannot precede a relevant event")
        at_head = self.replay_head_event_sequence == self.last_relevant_event_sequence
        if self.last_relevant_event_is_replay_head != at_head:
            raise ValueError("replay-head status conflicts with event linkage")
        if (self.events_observed_after_last_relevant == 0) != at_head:
            raise ValueError("events-after count conflicts with replay-head status")
        if at_head and (
            self.last_relevant_event_id != self.replay_head_event_id
            or self.last_relevant_event_recorded_at != self.replay_head_recorded_at
        ):
            raise ValueError("replay-head evidence conflicts with the last relevant event")
        return self


class PhaseFeedback(StrictModel):
    """Read-only, replayable research-progress feedback for one frozen bundle."""

    schema_version: Literal["phase-feedback.v1"] = "phase-feedback.v1"
    task_id: str = Field(min_length=1, max_length=256)
    builder_fidelity: BuilderFidelityFeedback
    prover_verification: ProverVerificationFeedback
    unresolved_human_review_assumptions: tuple[UnresolvedHumanReviewAssumption, ...] = ()
    mathematical_dependency_node_count: StrictNonNegativeInt
    dependency_leverage_exact_node_limit: Literal[512]
    dependency_leverage_mode: DependencyLeverageMode
    mathematical_dependency_leverage: tuple[MathematicalDependencyLeverage, ...] = ()
    milestones: tuple[FeedbackMilestone, ...] = ()
    replay: FeedbackReplayLinkage
    promotion_state: Literal["not_a_promotion"] = "not_a_promotion"

    @model_validator(mode="after")
    def validate_milestone_linkage(self) -> Self:
        milestone_sequences = tuple(item.source_event_sequence for item in self.milestones)
        if tuple(sorted(milestone_sequences)) != milestone_sequences:
            raise ValueError("feedback milestones must follow replay order")
        if milestone_sequences != self.replay.relevant_event_sequences:
            raise ValueError("feedback milestones must exactly match relevant replay events")
        if not self.milestones or self.milestones[0].phase != "builder_fidelity":
            raise ValueError("phase feedback must begin at Builder fidelity registration")
        builder = self.milestones[0]
        if (
            builder.source_event_sequence != self.builder_fidelity.registration_event_sequence
            or builder.source_event_id != self.builder_fidelity.registration_event_id
        ):
            raise ValueError("Builder milestone conflicts with its registration evidence")
        candidate_ids = tuple(
            item.proof_id
            for item in self.milestones
            if item.phase == "prover_candidate" and item.proof_id is not None
        )
        if candidate_ids != self.prover_verification.submitted_proof_ids:
            raise ValueError("submitted proof evidence conflicts with candidate milestones")
        candidate_sequences = {
            item.proof_id: item.source_event_sequence
            for item in self.milestones
            if item.phase == "prover_candidate" and item.proof_id is not None
        }
        terminals: dict[str, FeedbackMilestone] = {}
        for item in self.milestones:
            if item.phase != "prover_verification" or item.proof_id is None:
                continue
            previous = terminals.get(item.proof_id)
            if previous is not None:
                if previous.state != item.state:
                    raise ValueError(
                        "proof evidence has conflicting accepted and rejected terminals"
                    )
                raise ValueError("proof evidence has a duplicate terminal verification")
            candidate_sequence = candidate_sequences.get(item.proof_id)
            if candidate_sequence is None:
                raise ValueError("terminal verification has no candidate submission")
            if item.source_event_sequence <= candidate_sequence:
                raise ValueError("terminal verification precedes its candidate submission")
            terminals[item.proof_id] = item
        accepted_ids = {
            proof_id for proof_id, item in terminals.items() if item.state == "accepted"
        }
        rejected_ids = {
            proof_id for proof_id, item in terminals.items() if item.state == "rejected"
        }
        if accepted_ids != set(self.prover_verification.accepted_proof_ids) or rejected_ids != set(
            self.prover_verification.rejected_proof_ids
        ):
            raise ValueError("terminal proof evidence conflicts with verification milestones")
        review_evidence = {
            item.id: (item.source_event_sequence, item.source_event_id)
            for item in self.unresolved_human_review_assumptions
        }
        if len(review_evidence) != len(self.unresolved_human_review_assumptions):
            raise ValueError("human-review assumption IDs must be unique")
        milestone_review_evidence = {
            item.review_assumption_id: (item.source_event_sequence, item.source_event_id)
            for item in self.milestones
            if item.phase == "human_review" and item.review_assumption_id is not None
        }
        if review_evidence != milestone_review_evidence:
            raise ValueError("human-review assumptions conflict with their milestones")
        leverage = self.mathematical_dependency_leverage
        leverage_ids = {item.node_id for item in leverage}
        if len(leverage_ids) != len(leverage):
            raise ValueError("mathematical dependency leverage node IDs must be unique")
        if len(leverage) != self.mathematical_dependency_node_count:
            raise ValueError("mathematical dependency leverage must include every task node")
        if self.dependency_leverage_mode == "exact_transitive":
            if self.mathematical_dependency_node_count > DEPENDENCY_LEVERAGE_EXACT_NODE_LIMIT:
                raise ValueError("exact transitive leverage exceeds its node limit")
            if any(item.transitive_dependents is None for item in leverage):
                raise ValueError("exact transitive leverage requires every transitive count")
            leverage_order = tuple(
                (
                    -cast(int, item.transitive_dependents),
                    -item.direct_dependents,
                    item.node_id,
                )
                for item in leverage
            )
            if leverage_order != tuple(sorted(leverage_order)):
                raise ValueError(
                    "mathematical dependency leverage must be ranked by structural reach"
                )
        else:
            if self.mathematical_dependency_node_count <= DEPENDENCY_LEVERAGE_EXACT_NODE_LIMIT:
                raise ValueError("direct-only leverage requires a graph over the node limit")
            if any(item.transitive_dependents is not None for item in leverage):
                raise ValueError("direct-only leverage must omit transitive counts")
            direct_order = tuple((-item.direct_dependents, item.node_id) for item in leverage)
            if direct_order != tuple(sorted(direct_order)):
                raise ValueError("direct-only leverage must be ranked by direct dependents")
        return self


class DashboardSnapshot(StrictModel):
    overview: Overview = Field(default_factory=Overview)
    nodes: tuple[GraphNode, ...] = ()
    runs: tuple[RunSummary, ...] = ()
    artifacts: tuple[ArtifactSummary, ...] = ()
    events: tuple[EventView, ...] = ()
    phase_feedback: tuple[PhaseFeedback, ...] = ()
