"""Read-only Dashboard projection rebuilt solely from append-only control-plane events."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from .errors import ProjectionError
from .events import JsonObject, JsonValue, StoredEvent, canonical_json

_EXACT_TRANSITIVE_LEVERAGE_NODE_LIMIT = 512
_T7_SYNTHETIC_EVENT_SCHEMA = "autolean.t7-synthetic-node-result.v2"
_T7_SYNTHETIC_ENTITY_TYPE = "t7_synthetic_node_v2"
_T7_SYNTHETIC_EVIDENCE_CLASS = "synthetic_fake_node_v1"
_T7_PUBLIC_NODE_REF_DOMAIN = b"autolean.dashboard.t7-public-node-ref.v1\x00"
_T7_SYNTHETIC_EVENT_OUTCOMES = {
    "t7_synthetic_node_v2.synthetic_complete": "synthetic_complete",
    "t7_synthetic_node_v2.synthetic_failed": "synthetic_failed",
    "t7_synthetic_node_v2.synthetic_reused": "synthetic_reused",
}
_FATE_EVENT_SCHEMAS = frozenset(
    {
        "autolean.fate-execution.v1",
        "autolean.fate-execution.v2",
    }
)
_FATE_STARTED_EVENT = "fate.attempt.started"
_FATE_VERIFIED_EVENT = "fate.attempt.verified"


@dataclass(frozen=True, slots=True)
class _MathematicalDependencyLeverage:
    node_count: int
    mode: str
    rows: list[JsonObject]


@dataclass(slots=True)
class _PhaseFeedbackState:
    """Private replay accumulator; only allowlisted metadata reaches the snapshot."""

    task_id: str
    registration_event: StoredEvent
    builder_fidelity: JsonObject
    relevant_events: list[StoredEvent] = field(default_factory=list)
    submitted_proof_ids: list[str] = field(default_factory=list)
    accepted_proof_ids: list[str] = field(default_factory=list)
    rejected_proof_ids: list[str] = field(default_factory=list)
    unresolved_review_ids: set[str] = field(default_factory=set)
    unresolved_reviews: list[JsonObject] = field(default_factory=list)
    milestones: list[JsonObject] = field(default_factory=list)


@dataclass(slots=True)
class _FateReplayState:
    """Ephemeral replay binding for a public FATE attempt stream."""

    identity: tuple[str, str, str, int, str | None]
    started_at: str
    terminal_seen: bool = False


class DashboardProjection:
    """A deliberately lossy projection: it never exposes proof/source artifact contents."""

    def __init__(self, events: Iterable[StoredEvent]) -> None:
        self._events = tuple(sorted(events, key=lambda item: item.global_position))

    def snapshot(self) -> JsonObject:
        nodes: dict[str, JsonObject] = {}
        runs: dict[str, JsonObject] = {}
        artifacts: dict[str, JsonObject] = {}
        event_views: list[JsonObject] = []
        active_bundles: set[str] = set()
        blocked_bundles: set[str] = set()
        fate_replays: dict[str, _FateReplayState] = {}

        for event in self._events:
            payload = event.payload
            bundle_id = self._event_task_id(event)
            if event.event_type == "task.registered":
                for raw_node in self._optional_list(payload, "graph_nodes"):
                    if isinstance(raw_node, dict):
                        node = self._public_identity_node(
                            cast(JsonObject, raw_node),
                            event_bundle_id=bundle_id,
                        )
                        if node is not None:
                            nodes[cast(str, node["id"])] = node
                self._capture_artifact(payload, "bundle_artifact", artifacts)
            elif event.event_type in _T7_SYNTHETIC_EVENT_OUTCOMES:
                node = self._t7_synthetic_node(event, bundle_id)
                nodes[cast(str, node["id"])] = node
            elif event.event_type in {_FATE_STARTED_EVENT, _FATE_VERIFIED_EVENT}:
                fate_run = self._fate_run(event, bundle_id, fate_replays)
                fate_run_id = cast(str, fate_run["id"])
                existing = runs.get(fate_run_id)
                if event.event_type == _FATE_STARTED_EVENT:
                    if existing is not None:
                        raise ProjectionError("FATE run identity collides with an existing run")
                elif existing is None or existing.get("provider") != "fate-execution":
                    raise ProjectionError("FATE terminal run identity lost its started event")
                runs[fate_run_id] = fate_run
            elif event.event_type == "task.claimed" and bundle_id:
                active_bundles.add(bundle_id)
                self._set_task_status(nodes, bundle_id, "running")
            elif event.event_type == "proof.submitted":
                proof_id = self._optional_text(payload, "proof_id") or event.entity_id
                if proof_id in runs:
                    raise ProjectionError("proof run identity collides with an existing run")
                runs[proof_id] = self._run_from_submission(payload, proof_id)
                self._capture_artifact(payload, "proof_artifact", artifacts)
            elif event.event_type == "gap.reported" and bundle_id:
                blocked_bundles.add(bundle_id)
                active_bundles.discard(bundle_id)
                self._set_task_status(nodes, bundle_id, "blocked")
                self._capture_artifact(payload, "gap_artifact", artifacts)
            elif event.event_type == "contract_change.requested" and bundle_id:
                blocked_bundles.add(bundle_id)
                active_bundles.discard(bundle_id)
                self._set_task_status(nodes, bundle_id, "blocked")
                self._capture_artifact(payload, "request_artifact", artifacts)
            elif event.event_type.startswith("verification."):
                verified_proof_id = self._optional_text(payload, "proof_id")
                accepted = self._verification_accepted(event)
                if verified_proof_id and verified_proof_id in runs:
                    if runs[verified_proof_id].get("provider") == "fate-execution":
                        raise ProjectionError(
                            "generic verification cannot target a FATE benchmark run"
                        )
                    runs[verified_proof_id]["status"] = "succeeded" if accepted else "failed"
                    runs[verified_proof_id]["verification"] = "accepted" if accepted else "rejected"
                if bundle_id:
                    active_bundles.discard(bundle_id)
                    self._set_task_status(nodes, bundle_id, "verified" if accepted else "blocked")
                    if not accepted:
                        blocked_bundles.add(bundle_id)
                self._capture_artifact(payload, "verification_artifact", artifacts)

            event_views.append(self._event_view(event, task_id=bundle_id))

        return self._json_object(
            {
                "overview": {
                    "generated_at": datetime.now(UTC).isoformat(),
                    "mission": "Open problem portfolio",
                    "metrics": [
                        {"label": "events", "value": len(self._events)},
                        {"label": "artifacts", "value": len(artifacts)},
                    ],
                    "active_runs": len(active_bundles),
                    "blocked_nodes": len(blocked_bundles),
                },
                "nodes": [self._public_node(node) for node in nodes.values()],
                "runs": list(runs.values()),
                "artifacts": list(artifacts.values()),
                "events": event_views,
                "phase_feedback": self._phase_feedback(nodes),
            }
        )

    def _phase_feedback(self, nodes: dict[str, JsonObject]) -> list[JsonObject]:
        """Project event-backed research feedback without assigning a portfolio score.

        Each item is anchored at a canonical frozen registration event.  It records observation
        and evidence positions only: a later bundle or wall-clock passage cannot resolve an open
        review input, and a verifier acceptance cannot promote a result beyond its own evidence.
        """

        states: dict[str, _PhaseFeedbackState] = {}
        for event in self._events:
            if event.event_type != "task.registered":
                continue
            task_id = self._event_task_id(event)
            state = self._phase_feedback_registration(event, task_id)
            if state is None:
                continue
            if state.task_id in states:
                raise ProjectionError("duplicate registered bundle in phase feedback projection")
            states[state.task_id] = state

        for event in self._events:
            task_id = self._event_task_id(event)
            if task_id is None or (state := states.get(task_id)) is None:
                continue
            if event.global_position < state.registration_event.global_position:
                raise ProjectionError("phase feedback event precedes its registered bundle")
            payload = event.payload
            if event.event_type == "task.registered":
                state.relevant_events.append(event)
                state.milestones.append(
                    self._feedback_milestone(
                        phase="builder_fidelity",
                        state="recorded",
                        event=event,
                        evidence_digest=state.builder_fidelity.get("evidence_digest"),
                    )
                )
            elif event.event_type == "proof.submitted":
                proof_id = self._optional_text(payload, "proof_id") or event.entity_id
                if proof_id in state.submitted_proof_ids:
                    raise ProjectionError("duplicate proof submission in phase feedback projection")
                state.relevant_events.append(event)
                state.submitted_proof_ids.append(proof_id)
                state.milestones.append(
                    self._feedback_milestone(
                        phase="prover_candidate",
                        state="pending",
                        event=event,
                        evidence_digest=self._artifact_digest(payload, "proof_artifact"),
                        proof_id=proof_id,
                    )
                )
            elif event.event_type.startswith("verification."):
                verification_proof_id = self._optional_text(payload, "proof_id")
                if (
                    verification_proof_id is None
                    or verification_proof_id not in state.submitted_proof_ids
                ):
                    raise ProjectionError(
                        "phase feedback verification has no matching proof submission"
                    )
                if (
                    verification_proof_id in state.accepted_proof_ids
                    or verification_proof_id in state.rejected_proof_ids
                ):
                    raise ProjectionError(
                        "duplicate terminal verification in phase feedback projection"
                    )
                accepted = self._verification_accepted(event)
                state.relevant_events.append(event)
                terminal_ids = state.accepted_proof_ids if accepted else state.rejected_proof_ids
                terminal_ids.append(verification_proof_id)
                state.milestones.append(
                    self._feedback_milestone(
                        phase="prover_verification",
                        state="accepted" if accepted else "rejected",
                        event=event,
                        evidence_digest=self._artifact_digest(payload, "verification_artifact"),
                        proof_id=verification_proof_id,
                    )
                )
            elif event.event_type in {"gap.reported", "contract_change.requested"}:
                review = self._unresolved_review_assumption(event)
                review_id = cast(str, review["id"])
                if review_id in state.unresolved_review_ids:
                    raise ProjectionError(
                        "duplicate human-review assumption in phase feedback projection"
                    )
                state.relevant_events.append(event)
                state.unresolved_review_ids.add(review_id)
                state.unresolved_reviews.append(review)
                state.milestones.append(
                    self._feedback_milestone(
                        phase="human_review",
                        state="unresolved",
                        event=event,
                        evidence_digest=review.get("evidence_digest"),
                        review_assumption_id=review["id"],
                    )
                )

        leverage_by_task = self._mathematical_dependency_leverage(nodes)
        feedback: list[JsonObject] = []
        for task_id, state in sorted(states.items()):
            if not state.relevant_events:
                raise ProjectionError("registered phase feedback has no replay source events")
            pending = [
                proof_id
                for proof_id in state.submitted_proof_ids
                if (
                    proof_id not in state.accepted_proof_ids
                    and proof_id not in state.rejected_proof_ids
                )
            ]
            verification_state = self._prover_verification_state(
                submitted=state.submitted_proof_ids,
                pending=pending,
                accepted=state.accepted_proof_ids,
                rejected=state.rejected_proof_ids,
            )
            leverage = leverage_by_task.get(
                task_id,
                _MathematicalDependencyLeverage(
                    node_count=0,
                    mode="exact_transitive",
                    rows=[],
                ),
            )
            first = state.relevant_events[0]
            last = state.relevant_events[-1]
            replay_head = self._events[-1]
            events_after_last_relevant = sum(
                event.global_position > last.global_position for event in self._events
            )
            feedback.append(
                self._json_object(
                    {
                        "schema_version": "phase-feedback.v1",
                        "task_id": task_id,
                        "builder_fidelity": state.builder_fidelity,
                        "prover_verification": {
                            "state": verification_state,
                            "submitted_proof_ids": state.submitted_proof_ids,
                            "pending_proof_ids": pending,
                            "accepted_proof_ids": state.accepted_proof_ids,
                            "rejected_proof_ids": state.rejected_proof_ids,
                        },
                        # No inferred closure is permitted. Only a future explicit reviewed
                        # resolution event may change this contract.
                        "unresolved_human_review_assumptions": state.unresolved_reviews,
                        "mathematical_dependency_node_count": leverage.node_count,
                        "dependency_leverage_exact_node_limit": (
                            _EXACT_TRANSITIVE_LEVERAGE_NODE_LIMIT
                        ),
                        "dependency_leverage_mode": leverage.mode,
                        "mathematical_dependency_leverage": leverage.rows,
                        "milestones": state.milestones,
                        "replay": {
                            "first_relevant_event_sequence": first.global_position,
                            "last_relevant_event_sequence": last.global_position,
                            "last_relevant_event_id": last.event_id,
                            "last_relevant_event_recorded_at": last.recorded_at,
                            "relevant_event_count": len(state.relevant_events),
                            "relevant_event_sequences": [
                                event.global_position for event in state.relevant_events
                            ],
                            "replay_head_event_sequence": replay_head.global_position,
                            "replay_head_event_id": replay_head.event_id,
                            "replay_head_recorded_at": replay_head.recorded_at,
                            "events_observed_after_last_relevant": events_after_last_relevant,
                            "last_relevant_event_is_replay_head": (
                                last.global_position == replay_head.global_position
                            ),
                            "freshness_scope": "bounded_to_replayed_events",
                        },
                        "promotion_state": "not_a_promotion",
                    }
                )
            )
        return feedback

    @staticmethod
    def _prover_verification_state(
        *,
        submitted: list[str],
        pending: list[str],
        accepted: list[str],
        rejected: list[str],
    ) -> str:
        """Summarize candidate evidence without hiding concurrent or conflicting outcomes."""

        if not submitted:
            return "not_submitted"
        populated = sum(bool(items) for items in (pending, accepted, rejected))
        if populated > 1:
            return "mixed_candidates"
        if pending:
            return "candidate_pending_verification"
        if accepted:
            return "verified_candidate_available"
        return "all_candidates_rejected"

    @staticmethod
    def _phase_feedback_registration(
        event: StoredEvent,
        task_id: str | None,
    ) -> _PhaseFeedbackState | None:
        """Return feedback only when the event carries the complete immutable binding."""

        payload = event.payload
        if task_id is None:
            return None
        contract_id = DashboardProjection._optional_text(payload, "contract_id")
        revision = DashboardProjection._optional_int(payload, "revision")
        contract_hash = DashboardProjection._optional_text(payload, "contract_hash")
        bundle_hash = DashboardProjection._optional_text(payload, "bundle_hash")
        builder_attestation = payload.get("builder_attestation")
        if (
            contract_id is None
            or revision is None
            or revision < 1
            or contract_hash is None
            or bundle_hash is None
            or not isinstance(builder_attestation, dict)
            or any(
                DashboardProjection._optional_text(builder_attestation, key) is None
                for key in (
                    "purpose",
                    "key_id",
                    "payload_hash",
                    "evidence_identity",
                    "expires_at",
                )
            )
        ):
            return None
        evidence_digest = DashboardProjection._artifact_digest(
            payload,
            "fidelity_evidence_artifact",
        )
        return _PhaseFeedbackState(
            task_id=task_id,
            registration_event=event,
            builder_fidelity=DashboardProjection._json_object(
                {
                    "state": (
                        "frozen_attested_with_evidence"
                        if evidence_digest is not None
                        else "frozen_attested_without_public_evidence"
                    ),
                    "contract_id": contract_id,
                    "revision": revision,
                    "contract_hash": contract_hash,
                    "bundle_hash": bundle_hash,
                    "registration_event_sequence": event.global_position,
                    "registration_event_id": event.event_id,
                    "registered_at": event.recorded_at,
                    "evidence_digest": evidence_digest,
                }
            ),
        )

    @staticmethod
    def _feedback_milestone(
        *,
        phase: str,
        state: str,
        event: StoredEvent,
        evidence_digest: JsonValue | None,
        proof_id: str | None = None,
        review_assumption_id: JsonValue | None = None,
    ) -> JsonObject:
        return DashboardProjection._json_object(
            {
                "phase": phase,
                "state": state,
                "source_event_sequence": event.global_position,
                "source_event_id": event.event_id,
                "occurred_at": event.recorded_at,
                "evidence_digest": evidence_digest if isinstance(evidence_digest, str) else None,
                "proof_id": proof_id,
                "review_assumption_id": (
                    review_assumption_id if isinstance(review_assumption_id, str) else None
                ),
            }
        )

    @staticmethod
    def _unresolved_review_assumption(event: StoredEvent) -> JsonObject:
        payload = event.payload
        is_gap = event.event_type == "gap.reported"
        identifier = (
            DashboardProjection._optional_text(
                payload,
                "report_id" if is_gap else "request_id",
            )
            or event.event_id
        )
        return DashboardProjection._json_object(
            {
                "id": identifier,
                "kind": "gap" if is_gap else "contract_change",
                "state": "unresolved",
                "source_event_sequence": event.global_position,
                "source_event_id": event.event_id,
                "opened_at": event.recorded_at,
                "evidence_digest": DashboardProjection._artifact_digest(
                    payload,
                    "gap_artifact" if is_gap else "request_artifact",
                ),
            }
        )

    @staticmethod
    def _mathematical_dependency_leverage(
        nodes: dict[str, JsonObject],
    ) -> dict[str, _MathematicalDependencyLeverage]:
        """Expose bounded structural reachability without a scalar progress score.

        Exact transitive counts require a graph traversal from every node, so they are only
        projected for reasonably sized task graphs. Larger graphs retain their direct dependent
        counts and declare that the transitive metric is unavailable rather than approximating it.
        """

        by_task: dict[str, list[JsonObject]] = {}
        for node in nodes.values():
            if node.get("graph") != "mathematical":
                continue
            task_id = DashboardProjection._optional_text(node, "bundle_id")
            if task_id is not None:
                by_task.setdefault(task_id, []).append(node)

        result: dict[str, _MathematicalDependencyLeverage] = {}
        for task_id, task_nodes in by_task.items():
            known_ids = {cast(str, node["id"]) for node in task_nodes}
            dependents: dict[str, set[str]] = {node_id: set() for node_id in known_ids}
            for node in task_nodes:
                node_id = cast(str, node["id"])
                for dependency in DashboardProjection._optional_list(node, "dependencies"):
                    if dependency in known_ids:
                        dependents[dependency].add(node_id)

            exact_transitive = len(task_nodes) <= _EXACT_TRANSITIVE_LEVERAGE_NODE_LIMIT
            projected = [
                DashboardProjection._json_object(
                    {
                        "node_id": node_id,
                        "source_node_id": DashboardProjection._optional_text(node, "source_node_id")
                        or node_id,
                        "label": DashboardProjection._optional_text(node, "label") or node_id,
                        "direct_dependents": len(dependents[node_id]),
                        "transitive_dependents": (
                            DashboardProjection._transitive_dependents(dependents, node_id)
                            if exact_transitive
                            else None
                        ),
                    }
                )
                for node in task_nodes
                for node_id in (cast(str, node["id"]),)
            ]
            if exact_transitive:
                projected.sort(
                    key=lambda item: (
                        -cast(int, item["transitive_dependents"]),
                        -cast(int, item["direct_dependents"]),
                        cast(str, item["node_id"]),
                    )
                )
            else:
                projected.sort(
                    key=lambda item: (
                        -cast(int, item["direct_dependents"]),
                        cast(str, item["node_id"]),
                    )
                )
            result[task_id] = _MathematicalDependencyLeverage(
                node_count=len(task_nodes),
                mode=("exact_transitive" if exact_transitive else "direct_only_over_limit"),
                rows=projected,
            )
        return result

    @staticmethod
    def _transitive_dependents(dependents: dict[str, set[str]], node_id: str) -> int:
        seen: set[str] = set()
        pending = list(dependents[node_id])
        while pending:
            candidate = pending.pop()
            if candidate in seen or candidate == node_id:
                continue
            seen.add(candidate)
            pending.extend(dependents[candidate])
        return len(seen)

    @staticmethod
    def _artifact_digest(payload: JsonObject, key: str) -> str | None:
        artifact = payload.get(key)
        return (
            DashboardProjection._optional_text(artifact, "digest")
            if isinstance(artifact, dict)
            else None
        )

    @staticmethod
    def _set_task_status(nodes: dict[str, JsonObject], bundle_id: str, status: str) -> None:
        # Bundle IDs are not graph IDs. The event only affects nodes tied to that task's revision;
        # node state stays conservative when the graph had no nodes. Synthetic fixture nodes have
        # their own closed status protocol and must never be promoted or failed by task/proof
        # events that happen to share a public bundle ID.
        for node in nodes.values():
            if node.get("bundle_id") == bundle_id and node.get("kind") != "synthetic_execution":
                node["status"] = status

    @staticmethod
    def _public_node(node: JsonObject) -> JsonObject:
        return DashboardProjection._json_object(
            {key: value for key, value in node.items() if key != "bundle_id"}
        )

    @staticmethod
    def _public_identity_node(
        raw_node: JsonObject,
        *,
        event_bundle_id: str | None,
    ) -> JsonObject | None:
        source_node_id = DashboardProjection._optional_text(raw_node, "id")
        graph = DashboardProjection._optional_text(raw_node, "graph")
        bundle_id = event_bundle_id or DashboardProjection._optional_text(raw_node, "bundle_id")
        label = DashboardProjection._optional_text(raw_node, "label")
        status = DashboardProjection._optional_text(raw_node, "status")
        revision = DashboardProjection._optional_int(raw_node, "revision")
        kind = DashboardProjection._optional_text(raw_node, "kind")
        if (
            source_node_id is None
            or graph not in {"mathematical", "formal", "execution"}
            or bundle_id is None
            or label is None
            or status is None
            or revision is None
            or revision < 1
            or kind is None
        ):
            return None

        dependencies: list[JsonValue] = [
            DashboardProjection._public_node_id(bundle_id, graph, identifier)
            for identifier in DashboardProjection._optional_list(raw_node, "dependencies")
            if isinstance(identifier, str) and identifier
        ]
        return DashboardProjection._json_object(
            {
                # Internal-only key retained for status projection, then removed by _public_node.
                "bundle_id": bundle_id,
                "dependencies": dependencies,
                "graph": graph,
                "id": DashboardProjection._public_node_id(bundle_id, graph, source_node_id),
                "kind": kind,
                "label": label,
                "revision": revision,
                "source_node_id": source_node_id,
                "status": status,
                # This is the explicit public join key shared by nodes, runs, and events.
                # Bundle IDs are already exposed as RunSummary.task_id.
                "task_id": bundle_id,
                "updated_at": DashboardProjection._optional_text(raw_node, "updated_at"),
            }
        )

    @staticmethod
    def _public_node_id(bundle_id: str, graph: str, source_node_id: str) -> str:
        """Build the one public graph-node identity used by every projection path."""

        # StableIdentifierV1 values cannot contain "|", so this tuple encoding is
        # unambiguous while remaining inspectable and stable across event replays.
        return f"dashboard-node|{bundle_id}|{graph}|{source_node_id}"

    @staticmethod
    def _t7_synthetic_node(event: StoredEvent, bundle_id: str | None) -> JsonObject:
        """Project T7 fixture results as explicitly non-promotable execution nodes.

        This is intentionally an allowlist rather than a generic event-to-node adapter.  In
        particular, it omits the lease holder, fencing token, artifact references, source module,
        and every future event field.  A completed synthetic fixture is not a kernel-verified
        proof, so it stays an attention state in the UI rather than becoming ``verified``.
        """

        payload = event.payload
        outcome = _T7_SYNTHETIC_EVENT_OUTCOMES[event.event_type]
        node_id = DashboardProjection._optional_text(payload, "node_id")
        event_bundle_id = DashboardProjection._optional_text(payload, "bundle_id")
        valid_identity = (
            event.entity_type == _T7_SYNTHETIC_ENTITY_TYPE
            and event.entity_sequence == 1
            and event.metadata == {}
            and bundle_id is not None
            and event_bundle_id == bundle_id
            and isinstance(node_id, str)
            and len(node_id) <= 240
            and payload.get("schema_version") == _T7_SYNTHETIC_EVENT_SCHEMA
            and payload.get("typed_outcome") == outcome
            and payload.get("evidence_class") == _T7_SYNTHETIC_EVIDENCE_CLASS
            and payload.get("promotion_eligible") is False
        )
        if not valid_identity or bundle_id is None or node_id is None:
            raise ProjectionError("T7 synthetic event cannot be safely projected")

        public_ref = DashboardProjection._t7_public_node_ref(bundle_id, node_id)
        source_node_id = f"t7-public:{public_ref}"
        status = {
            "synthetic_complete": "synthetic_complete",
            "synthetic_failed": "synthetic_failed",
            "synthetic_reused": "synthetic_reused",
        }[outcome]
        return DashboardProjection._json_object(
            {
                "bundle_id": bundle_id,
                "dependencies": [],
                "graph": "execution",
                "id": DashboardProjection._public_node_id(bundle_id, "execution", source_node_id),
                "kind": "synthetic_execution",
                "label": f"T7 synthetic node {public_ref[:12]}",
                "revision": 1,
                "source_node_id": source_node_id,
                "status": status,
                "task_id": bundle_id,
                "updated_at": event.recorded_at,
            }
        )

    @staticmethod
    def _t7_public_node_ref(bundle_id: str, node_id: str) -> str:
        material = canonical_json({"bundle_id": bundle_id, "node_id": node_id}).encode("utf-8")
        return hashlib.sha256(_T7_PUBLIC_NODE_REF_DOMAIN + material).hexdigest()

    @staticmethod
    def _fate_run(
        event: StoredEvent,
        bundle_id: str | None,
        replay_states: dict[str, _FateReplayState],
    ) -> JsonObject:
        """Replay and project only the redacted FATE envelope, never private artifacts."""

        payload = event.payload
        event_bundle_id = DashboardProjection._optional_text(payload, "bundle_id")
        run_id = DashboardProjection._optional_text(payload, "run_id")
        problem_id = DashboardProjection._optional_text(payload, "problem_id")
        attempt_number = DashboardProjection._optional_int(payload, "attempt_number")
        raw_attempt_seed = payload.get("attempt_seed")
        attempt_seed = (
            raw_attempt_seed if isinstance(raw_attempt_seed, str) and raw_attempt_seed else None
        )
        schema_version = payload.get("schema_version")
        valid_v2_seed = (
            isinstance(attempt_seed, str)
            and len(attempt_seed) == 64
            and all(character in "0123456789abcdef" for character in attempt_seed)
        )
        if (
            event.entity_type != "fate-attempt"
            or event.entity_id != bundle_id
            or event.entity_sequence != (1 if event.event_type == _FATE_STARTED_EVENT else 2)
            or bundle_id is None
            or event_bundle_id != bundle_id
            or not run_id
            or not problem_id
            or attempt_number is None
            or attempt_number < 1
            or (raw_attempt_seed is not None and attempt_seed is None)
            or schema_version not in _FATE_EVENT_SCHEMAS
            or (schema_version == "autolean.fate-execution.v2" and not valid_v2_seed)
        ):
            raise ProjectionError("FATE event cannot be safely projected")

        identity = (cast(str, schema_version), run_id, problem_id, attempt_number, attempt_seed)
        public_id = f"fate:{bundle_id}"
        if len(public_id) > 256:
            raise ProjectionError("FATE public attempt identity is too long")
        base: JsonObject = {
            "id": public_id,
            "task_id": bundle_id,
            # The FATE event never needs to disclose an endpoint or a provider configuration.
            "provider": "fate-execution",
            "model": "redacted-by-public-sidecar",
            "started_at": event.recorded_at,
            "duration_ms": None,
            "input_tokens": 0,
            "output_tokens": 0,
            "cost_usd": 0.0,
            "status": "benchmark_running",
            "verification": "benchmark_pending",
        }

        if event.event_type == _FATE_STARTED_EVENT:
            if payload.get("raw_output_persisted") is not False:
                raise ProjectionError("FATE start event has an invalid public-output boundary")
            if event.entity_id in replay_states:
                raise ProjectionError("duplicate FATE started event in replay")
            replay_states[event.entity_id] = _FateReplayState(
                identity=identity,
                started_at=event.recorded_at,
            )
            return DashboardProjection._json_object(base)

        replay_state = replay_states.get(event.entity_id)
        if replay_state is None:
            raise ProjectionError("FATE terminal event has no matching started event")
        if replay_state.identity != identity:
            raise ProjectionError("FATE terminal event identity differs from its started event")
        if replay_state.terminal_seen:
            raise ProjectionError("duplicate FATE terminal event in replay")

        required_false_flags = (
            "contains_raw_output",
            "contains_candidate_source",
            "contains_private_digests",
        )
        accepted = payload.get("accepted")
        elapsed_ms = DashboardProjection._optional_int(payload, "elapsed_ms")
        input_tokens = DashboardProjection._optional_int(payload, "input_tokens")
        output_tokens = DashboardProjection._optional_int(payload, "output_tokens")
        cost_microusd = DashboardProjection._optional_int(payload, "cost_microusd")
        if (
            not isinstance(accepted, bool)
            or elapsed_ms is None
            or input_tokens is None
            or output_tokens is None
            or cost_microusd is None
            or any(payload.get(flag) is not False for flag in required_false_flags)
            or payload.get("private_artifacts_persisted") is not True
        ):
            raise ProjectionError("FATE terminal event has an invalid public-output boundary")
        replay_state.terminal_seen = True
        base.update(
            {
                "started_at": replay_state.started_at,
                "duration_ms": elapsed_ms,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cost_usd": cost_microusd / 1_000_000,
                "status": "benchmark_verified" if accepted else "benchmark_rejected",
                "verification": "benchmark_accepted" if accepted else "benchmark_rejected",
            }
        )
        return DashboardProjection._json_object(base)

    @staticmethod
    def _run_from_submission(payload: JsonObject, proof_id: str) -> JsonObject:
        return DashboardProjection._json_object(
            {
                "id": proof_id,
                "task_id": DashboardProjection._optional_text(payload, "bundle_id") or "unknown",
                "provider": DashboardProjection._optional_text(payload, "provider")
                or "unattributed",
                "model": DashboardProjection._optional_text(payload, "model") or "unattributed",
                "status": "candidate",
                "verification": "pending",
                "duration_ms": DashboardProjection._optional_int(payload, "duration_ms"),
                "input_tokens": DashboardProjection._optional_int(payload, "input_tokens") or 0,
                "output_tokens": DashboardProjection._optional_int(payload, "output_tokens") or 0,
                "cost_usd": DashboardProjection._optional_float(payload, "cost_usd") or 0.0,
            }
        )

    @staticmethod
    def _capture_artifact(payload: JsonObject, key: str, target: dict[str, JsonObject]) -> None:
        value = payload.get(key)
        if not isinstance(value, dict):
            return
        artifact = value
        digest = DashboardProjection._optional_text(artifact, "digest")
        if not digest:
            return
        target[digest] = DashboardProjection._json_object(
            {
                "digest": digest,
                "media_type": DashboardProjection._optional_text(artifact, "media_type")
                or "application/octet-stream",
                "size": artifact.get("size", 0),
                "kind": DashboardProjection._optional_text(artifact, "kind") or "artifact",
            }
        )

    @staticmethod
    def _event_view(event: StoredEvent, *, task_id: str | None) -> JsonObject:
        summary = event.event_type.replace(".", " ")
        if event.event_type in _T7_SYNTHETIC_EVENT_OUTCOMES:
            outcome = _T7_SYNTHETIC_EVENT_OUTCOMES[event.event_type].replace("_", " ")
            summary = f"T7 {outcome}"
        elif event.event_type == _FATE_STARTED_EVENT:
            summary = "FATE benchmark attempt started"
        elif event.event_type == _FATE_VERIFIED_EVENT:
            accepted = event.payload.get("accepted")
            if accepted is True:
                summary = "FATE benchmark verifier accepted"
            elif accepted is False:
                summary = "FATE benchmark verifier rejected"
        return DashboardProjection._json_object(
            {
                "sequence": event.global_position,
                "event_type": event.event_type,
                "entity_id": task_id or event.entity_id,
                "task_id": task_id,
                "occurred_at": event.recorded_at,
                "summary": summary,
            }
        )

    @staticmethod
    def _event_task_id(event: StoredEvent) -> str | None:
        payload_id = DashboardProjection._optional_text(event.payload, "bundle_id")
        if payload_id is not None:
            return payload_id
        # task.claimed stores its task identity in the task stream rather than duplicating
        # it inside the payload. No other entity stream is treated as a task implicitly.
        if event.entity_type == "task" and event.entity_id:
            return event.entity_id
        return None

    @staticmethod
    def _verification_accepted(event: StoredEvent) -> bool:
        promotion_state = event.payload.get("promotion_state", "not_a_promotion")
        if promotion_state != "not_a_promotion":
            raise ProjectionError("local verification event claims promotion authority")
        authority_class = event.payload.get("execution_authority_class", "test-only-local")
        if authority_class != "test-only-local":
            raise ProjectionError("local verification event claims a production authority")
        accepted = event.payload.get("accepted")
        if not isinstance(accepted, bool):
            raise ProjectionError("verification acceptance flag must be a boolean")
        expected_type = "verification.accepted" if accepted else "verification.rejected"
        if event.event_type != expected_type:
            raise ProjectionError("verification event type conflicts with its acceptance flag")
        return accepted

    @staticmethod
    def _optional_text(payload: JsonObject, key: str) -> str | None:
        value = payload.get(key)
        return value if isinstance(value, str) and value else None

    @staticmethod
    def _optional_list(payload: JsonObject, key: str) -> list[object]:
        value = payload.get(key)
        items: list[object] = []
        if isinstance(value, list):
            items.extend(value)
        return items

    @staticmethod
    def _optional_int(payload: JsonObject, key: str) -> int | None:
        value = payload.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
        return None

    @staticmethod
    def _optional_float(payload: JsonObject, key: str) -> float | None:
        value = payload.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            return None
        return float(value)

    @staticmethod
    def _json_object(value: object) -> JsonObject:
        loaded = json.loads(canonical_json(value))
        if not isinstance(loaded, dict):
            raise TypeError("projection value must be a JSON object")
        return cast(JsonObject, loaded)


def export_dashboard_projection(path: str | Path, events: Iterable[StoredEvent]) -> Path:
    """Atomically export a JSON snapshot that a separate read-only Dashboard process can read."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json(DashboardProjection(events).snapshot()).encode("utf-8")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=destination.parent, prefix=".projection-", delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return destination
