"""Control-plane integration evidence for the fixed 20-node project DAG.

This module is deliberately a test fixture adapter, not a scheduler.  ``ProjectDagV1`` remains
the authoritative *formal* cross-file topology.  Every registered task bundle contains only its
own local formal node; its mathematical and execution graphs remain empty.  Runtime progress is
therefore an append-only event projection instead of an edge added to either of those graphs.

No Lean command, OCI worker, or proof search runs here.  Passing tests based on this module are
evidence that the control-plane scheduling boundary behaves correctly for the fixed fixture; they
are not Lean compilation or theorem-proving evidence.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, cast

from autolean_contracts import FormalizationTaskBundleV1, ProofSubmissionV1, VerificationReportV1
from autolean_control_plane import (
    ClaimReceipt,
    ControlPlane,
    Idempotency,
    NewEvent,
    StoredEvent,
    TaskBinding,
    VerificationOutcome,
    request_hash,
)
from autolean_control_plane.events import JsonObject
from autolean_control_plane.leases import Lease

from benchmarks.project_dag import ProjectDagV1, ProjectNodeV1


class ProjectIntegrationError(ValueError):
    """The fixed project fixture was used outside its frozen scheduling contract."""


ProjectExecutionStatusV1 = Literal[
    "blocked",
    "ready",
    "running",
    "submitted",
    "verified",
    "invalidated",
]


_RUN_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
_PROJECT_EVENT_ENTITY_TYPE = "project_fixture"
_PROJECT_REGISTERED_EVENT = "project.integration.registered"
_PROJECT_REPLANNED_EVENT = "project.api_change.replanned"


@dataclass(frozen=True, slots=True)
class ProjectNodeExecutionStateV1:
    """One node in a read-only projection of the fixture's formal and execution state."""

    node_id: str
    source_file: str
    formal_dependencies: tuple[str, ...]
    execution_status: ProjectExecutionStatusV1


@dataclass(frozen=True, slots=True)
class ProjectIntegrationStatusProjectionV1:
    """Replayable scheduling evidence, explicitly not a Lean build result."""

    fixture_name: str
    run_id: str
    nodes: tuple[ProjectNodeExecutionStateV1, ...]
    relevant_event_count: int
    lean_compilation_executed: Literal[False] = False

    @property
    def by_node_id(self) -> dict[str, ProjectNodeExecutionStateV1]:
        return {node.node_id: node for node in self.nodes}


@dataclass(slots=True)
class ProjectControlPlaneFixtureV1:
    """A narrow adapter that connects one frozen 20-node DAG to public control-plane APIs.

    It intentionally supports no policy discovery, queue selection, retry policy, or arbitrary
    dependency model.  Those are production-control-plane concerns.  This adapter records a
    fixed formal graph manifest and converts only its completion/replan facts into an execution
    status projection for architecture tests.
    """

    dag: ProjectDagV1
    plane: ControlPlane
    bundles: Mapping[str, FormalizationTaskBundleV1]
    run_id: str

    def __post_init__(self) -> None:
        if not _RUN_ID.fullmatch(self.run_id):
            raise ProjectIntegrationError("project fixture run ID is invalid")
        bundle_copy = dict(self.bundles)
        expected = set(self.dag.by_id)
        if set(bundle_copy) != expected:
            raise ProjectIntegrationError(
                "fixture bundles must match the frozen project DAG exactly"
            )
        bundle_ids = [bundle.bundle_id.value for bundle in bundle_copy.values()]
        if len(set(bundle_ids)) != len(bundle_ids):
            raise ProjectIntegrationError("fixture bundle IDs must be unique")
        for node_id, bundle in bundle_copy.items():
            self._validate_local_bundle(node_id, bundle)
        self.bundles = MappingProxyType(bundle_copy)

    @property
    def project_event_entity_id(self) -> str:
        return f"{self.dag.name}:{self.run_id}"

    def register_all(self) -> tuple[TaskBinding, ...]:
        """Register every signed frozen bundle and one immutable formal-graph manifest."""

        bindings = tuple(
            self.plane.register_bundle(
                self.bundles[node_id],
                idempotency_key=f"{self.run_id}:register:{node_id}",
            )
            for node_id in self.dag.topological_order()
        )
        self._record_project_manifest()
        return bindings

    def formal_frontier(self) -> tuple[ProjectNodeV1, ...]:
        """Return logical readiness from the formal DAG, never from execution edges."""

        self._assert_registered()
        return self.dag.ready_frontier(self._completed_nodes_from_events())

    def completed_nodes(self) -> frozenset[str]:
        """Return nodes with an accepted current execution state after event replay."""

        self._assert_registered()
        return self._completed_nodes_from_events()

    def claim_frontier(
        self,
        node_id: str,
        *,
        worker_id: str,
        ttl_seconds: float,
    ) -> ClaimReceipt:
        """Claim one formally ready node through the public fenced-lease API."""

        self._require_node(node_id)
        frontier = {node.node_id for node in self.formal_frontier()}
        if node_id not in frontier:
            raise ProjectIntegrationError(
                "node is outside the current formal dependency frontier and cannot be claimed"
            )
        bundle_id = self.bundles[node_id].bundle_id.value
        return self.plane.claim(
            bundle_id,
            worker_id=worker_id,
            ttl_seconds=ttl_seconds,
            idempotency_key=f"{self.run_id}:claim:{node_id}:{worker_id}",
        )

    def submit_proof(
        self,
        node_id: str,
        *,
        lease: Lease,
        submission: ProofSubmissionV1,
    ) -> StoredEvent:
        """Submit test evidence through the frozen bundle's normal proof boundary."""

        self._require_node(node_id)
        return self.plane.submit_proof(
            self.bundles[node_id].bundle_id.value,
            lease=lease,
            submission=submission,
            idempotency_key=f"{self.run_id}:submit:{node_id}:{submission.proof_id.value}",
        )

    def verify_submission(
        self,
        node_id: str,
        *,
        lease: Lease,
        report: VerificationReportV1,
    ) -> VerificationOutcome:
        """Record an independently signed test verifier result for one local bundle."""

        self._require_node(node_id)
        return self.plane.verify_submission(
            self.bundles[node_id].bundle_id.value,
            lease=lease,
            report=report,
            idempotency_key=f"{self.run_id}:verify:{node_id}:{report.report_id.value}",
        )

    def replan_for_api_change(
        self,
        changed_node_ids: frozenset[str],
        *,
        change_id: str,
    ) -> StoredEvent:
        """Append the exact formal reverse closure as an execution invalidation overlay.

        This does not mutate the formal DAG or any frozen bundle.  A later successful proof can
        move an invalidated node back to ``verified`` through the normal control-plane lifecycle.
        """

        self._assert_registered()
        if not _RUN_ID.fullmatch(change_id):
            raise ProjectIntegrationError("project API change ID is invalid")
        affected = self.dag.affected_by(changed_node_ids)
        payload = cast(
            JsonObject,
            {
                "schema_version": "autolean.project-api-replan.v1",
                "fixture_name": self.dag.name,
                "run_id": self.run_id,
                "formal_changed_node_ids": sorted(changed_node_ids),
                "formal_reverse_closure_node_ids": [node.node_id for node in affected],
                "execution_effect": "invalidate_and_replan",
                "lean_compilation_executed": False,
            },
        )
        events = self.plane.events.append(
            _PROJECT_EVENT_ENTITY_TYPE,
            self.project_event_entity_id,
            expected_sequence=self.plane.events.current_sequence(
                _PROJECT_EVENT_ENTITY_TYPE,
                self.project_event_entity_id,
            ),
            events=(NewEvent(_PROJECT_REPLANNED_EVENT, payload=payload),),
            idempotency=Idempotency(
                scope="project_api_change",
                key=f"{self.run_id}:api-change:{change_id}",
                request_hash=request_hash(payload),
            ),
        )
        return events[0]

    def project_events(self) -> tuple[StoredEvent, ...]:
        """Return only this fixture run's immutable control-plane overlay events."""

        return tuple(
            event for event in self.plane.events.read_all() if self._is_project_event(event)
        )

    def status_projection(self) -> ProjectIntegrationStatusProjectionV1:
        """Replay 20-node formal topology plus execution facts without merging their graphs."""

        self._assert_registered()
        states = self._execution_states()
        completed = frozenset(node_id for node_id, status in states.items() if status == "verified")
        frontier = {node.node_id for node in self.dag.ready_frontier(completed)}
        nodes = tuple(
            ProjectNodeExecutionStateV1(
                node_id=node.node_id,
                source_file=node.source_file,
                formal_dependencies=node.depends_on,
                execution_status=(
                    "ready"
                    if states[node.node_id] == "blocked" and node.node_id in frontier
                    else states[node.node_id]
                ),
            )
            for node in self.dag.nodes
        )
        return ProjectIntegrationStatusProjectionV1(
            fixture_name=self.dag.name,
            run_id=self.run_id,
            nodes=nodes,
            relevant_event_count=len(self._relevant_events()),
        )

    def _record_project_manifest(self) -> StoredEvent:
        formal_nodes = [
            {
                "node_id": node.node_id,
                "source_file": node.source_file,
                "formal_dependencies": list(node.depends_on),
                "bundle_id": self.bundles[node.node_id].bundle_id.value,
            }
            for node in self.dag.nodes
        ]
        payload = cast(
            JsonObject,
            {
                "schema_version": "autolean.project-integration.v1",
                "fixture_name": self.dag.name,
                "run_id": self.run_id,
                "formal_graph_nodes": formal_nodes,
                "mathematical_graph": "not_modeled_by_project_fixture",
                "execution_graph": "derived_only_from_append_only_events",
                "lean_compilation_executed": False,
            },
        )
        events = self.plane.events.append(
            _PROJECT_EVENT_ENTITY_TYPE,
            self.project_event_entity_id,
            expected_sequence=0,
            events=(NewEvent(_PROJECT_REGISTERED_EVENT, payload=payload),),
            idempotency=Idempotency(
                scope="project_fixture_registration",
                key=f"{self.run_id}:manifest",
                request_hash=request_hash(payload),
            ),
        )
        return events[0]

    def _completed_nodes_from_events(self) -> frozenset[str]:
        states = self._execution_states()
        return frozenset(node_id for node_id, status in states.items() if status == "verified")

    def _execution_states(self) -> dict[str, ProjectExecutionStatusV1]:
        states: dict[str, ProjectExecutionStatusV1] = {
            node.node_id: "blocked" for node in self.dag.nodes
        }
        for event in self.plane.events.read_all():
            if event.event_type == _PROJECT_REPLANNED_EVENT and self._is_project_event(event):
                for node_id in self._required_project_node_ids(
                    event.payload,
                    "formal_reverse_closure_node_ids",
                ):
                    states[node_id] = "invalidated"
                continue

            task_node_id = self._node_for_task_event(event)
            if task_node_id is None:
                continue
            if event.event_type == "task.claimed":
                states[task_node_id] = "running"
            elif event.event_type == "proof.submitted":
                states[task_node_id] = "submitted"
            elif event.event_type == "verification.accepted":
                states[task_node_id] = "verified"
            elif event.event_type == "verification.rejected":
                states[task_node_id] = "blocked"
        return states

    def _node_for_task_event(self, event: StoredEvent) -> str | None:
        bundle_to_node = self._bundle_to_node()
        if event.entity_type == "task":
            return bundle_to_node.get(event.entity_id)
        bundle_id = event.payload.get("bundle_id")
        if not isinstance(bundle_id, str):
            return None
        return bundle_to_node.get(bundle_id)

    def _relevant_events(self) -> tuple[StoredEvent, ...]:
        bundle_ids = set(self._bundle_to_node())
        relevant: list[StoredEvent] = []
        for event in self.plane.events.read_all():
            if self._is_project_event(event):
                relevant.append(event)
                continue
            if event.entity_type == "task" and event.entity_id in bundle_ids:
                relevant.append(event)
                continue
            bundle_id = event.payload.get("bundle_id")
            if isinstance(bundle_id, str) and bundle_id in bundle_ids:
                relevant.append(event)
        return tuple(relevant)

    def _assert_registered(self) -> None:
        if not any(
            event.event_type == _PROJECT_REGISTERED_EVENT for event in self.project_events()
        ):
            raise ProjectIntegrationError("register_all must record the fixture manifest first")

    def _is_project_event(self, event: StoredEvent) -> bool:
        return (
            event.entity_type == _PROJECT_EVENT_ENTITY_TYPE
            and event.entity_id == self.project_event_entity_id
        )

    def _bundle_to_node(self) -> dict[str, str]:
        return {bundle.bundle_id.value: node_id for node_id, bundle in self.bundles.items()}

    def _require_node(self, node_id: str) -> None:
        if node_id not in self.dag.by_id:
            raise ProjectIntegrationError("unknown project DAG node")

    def _required_project_node_ids(self, payload: JsonObject, key: str) -> tuple[str, ...]:
        raw = payload.get(key)
        if not isinstance(raw, list) or not raw or not all(isinstance(value, str) for value in raw):
            raise ProjectIntegrationError("project replan event has an invalid formal closure")
        identifiers = tuple(cast(str, value) for value in raw)
        if len(set(identifiers)) != len(identifiers) or set(identifiers) - set(self.dag.by_id):
            raise ProjectIntegrationError("project replan event references an unknown formal node")
        return identifiers

    def _validate_local_bundle(
        self,
        node_id: str,
        bundle: FormalizationTaskBundleV1,
    ) -> None:
        if bundle.graphs.mathematical.nodes or bundle.graphs.mathematical.edges:
            raise ProjectIntegrationError(
                "fixture bundles must not repurpose the mathematical graph"
            )
        if bundle.graphs.execution.nodes or bundle.graphs.execution.edges:
            raise ProjectIntegrationError("fixture bundles must not repurpose the execution graph")
        formal_nodes = bundle.graphs.formal.nodes
        if len(formal_nodes) != 1 or bundle.graphs.formal.edges:
            raise ProjectIntegrationError(
                "each fixture bundle must contain exactly one local formal node"
            )
        metadata = formal_nodes[0].metadata
        if metadata.get("project_fixture_node_id") != node_id:
            raise ProjectIntegrationError(
                "local formal node must declare its project fixture identity"
            )
