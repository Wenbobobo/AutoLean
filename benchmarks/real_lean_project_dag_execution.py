"""Lease-fenced result-recording skeleton for T7 changed-source rebuild plans.

This module does not run Lean or define complete worker input.  It content-addresses a
recomputed planning/result manifest and atomically fences per-node records.  Source CAS
bytes, an environment/image binding, and a typed Lean execution receipt remain absent.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal, cast

from autolean_control_plane import (
    ArtifactRef,
    ArtifactStore,
    EventStore,
    Idempotency,
    Lease,
    LeaseStore,
    NewEvent,
    StoredEvent,
    request_hash,
)
from autolean_control_plane.errors import StaleFence
from autolean_control_plane.events import JsonObject

from benchmarks.real_lean_project_dag import RealLeanProjectDagV1
from benchmarks.real_lean_project_dag_rebuild import (
    RealLeanRebuildBundleV1,
    RealLeanRebuildPlanError,
    plan_real_lean_rebuild,
)

EXECUTION_BUNDLE_SCHEMA: Final[str] = "autolean.real-lean-project-dag-execution-bundle.v1"
NODE_RESULT_SCHEMA: Final[str] = "autolean.real-lean-project-dag-node-result.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REBUILD = "rebuild"
_REUSE = "reuse"
_VERIFIED = "VERIFIED"
_FAILED = "FAILED"
_REUSED = "REUSED"
_PENDING = "PENDING"
_NODE_RESULT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "bundle_id",
        "execution_bundle_sha256",
        "execution_bundle_artifact",
        "rebuild_plan_sha256",
        "node_id",
        "module",
        "planned_action",
        "outcome",
        "result_artifact",
        "fencing_token",
    }
)
type NodeOutcome = Literal["VERIFIED", "FAILED", "REUSED"]


class RealLeanRebuildExecutionError(RuntimeError):
    """A T7 result recorder attempted an unsafe or inconsistent state transition."""


@dataclass(frozen=True, slots=True)
class RebuildExecutionNodeV1:
    """One declaration node bound to its fixed rebuild/reuse action and prerequisites."""

    node_id: str
    module: str
    action: str
    depends_on: tuple[str, ...]
    baseline_artifact: ArtifactRef | None

    def __post_init__(self) -> None:
        if not self.node_id or not self.module or self.action not in {_REBUILD, _REUSE}:
            raise RealLeanRebuildExecutionError("execution node is invalid")
        if self.node_id in self.depends_on or len(set(self.depends_on)) != len(self.depends_on):
            raise RealLeanRebuildExecutionError("execution node dependencies are invalid")
        if any(not item for item in self.depends_on):
            raise RealLeanRebuildExecutionError("execution node dependency is invalid")
        if (self.action == _REUSE) != (self.baseline_artifact is not None):
            raise RealLeanRebuildExecutionError("execution node baseline binding is invalid")


@dataclass(frozen=True, slots=True)
class RealLeanRebuildExecutionBundleV1:
    """Immutable result manifest rooted in a recomputed changed-source planning artifact."""

    fixture_manifest_sha256: str
    rebuild_plan_sha256: str
    rebuild_plan_artifact: ArtifactRef
    nodes: tuple[RebuildExecutionNodeV1, ...]

    def __post_init__(self) -> None:
        if (
            _SHA256.fullmatch(self.fixture_manifest_sha256) is None
            or _SHA256.fullmatch(self.rebuild_plan_sha256) is None
            or self.rebuild_plan_artifact.digest != self.rebuild_plan_sha256
        ):
            raise RealLeanRebuildExecutionError("execution bundle plan binding is invalid")
        node_ids = tuple(item.node_id for item in self.nodes)
        if not node_ids or len(set(node_ids)) != len(node_ids):
            raise RealLeanRebuildExecutionError("execution bundle nodes are invalid")
        known_nodes = set(node_ids)
        if any(set(item.depends_on) - known_nodes for item in self.nodes):
            raise RealLeanRebuildExecutionError("execution bundle dependency is unknown")

    def _content_document(self) -> dict[str, object]:
        return {
            "schema_version": EXECUTION_BUNDLE_SCHEMA,
            "fixture_manifest_sha256": self.fixture_manifest_sha256,
            "rebuild_plan_sha256": self.rebuild_plan_sha256,
            "rebuild_plan_artifact": _artifact_document(self.rebuild_plan_artifact),
            "nodes": [
                {
                    "node_id": item.node_id,
                    "module": item.module,
                    "action": item.action,
                    "depends_on": list(item.depends_on),
                    "baseline_artifact": (
                        None
                        if item.baseline_artifact is None
                        else _artifact_document(item.baseline_artifact)
                    ),
                }
                for item in self.nodes
            ],
        }

    def canonical_bytes(self) -> bytes:
        rendered = json.dumps(
            self._content_document(), ensure_ascii=True, sort_keys=True, separators=(",", ":")
        )
        return (rendered + "\n").encode("utf-8")

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @property
    def job_id(self) -> str:
        """The lease key is derived exclusively from immutable result-manifest bytes."""

        return f"t7-real-lean-rebuild:{self.content_sha256}"

    @property
    def nodes_by_id(self) -> dict[str, RebuildExecutionNodeV1]:
        return {item.node_id: item for item in self.nodes}


@dataclass(frozen=True, slots=True)
class FrozenRealLeanRebuildExecutionBundleV1:
    """A result manifest paired with its exact content-addressed artifact."""

    bundle: RealLeanRebuildExecutionBundleV1
    artifact: ArtifactRef

    def __post_init__(self) -> None:
        if self.artifact.digest != self.bundle.content_sha256 or self.artifact.size != len(
            self.bundle.canonical_bytes()
        ):
            raise RealLeanRebuildExecutionError("execution bundle artifact does not bind its bytes")


def freeze_real_lean_rebuild_execution_bundle(
    fixture: RealLeanProjectDagV1,
    rebuild_plan: RealLeanRebuildBundleV1,
    artifacts: ArtifactStore,
    *,
    reuse_baseline_artifacts: Mapping[str, ArtifactRef],
) -> FrozenRealLeanRebuildExecutionBundleV1:
    """Recompute and seal a plan plus declaration result graph as artifacts."""

    if rebuild_plan.fixture_manifest_sha256 != fixture.manifest_sha256():
        raise RealLeanRebuildExecutionError("rebuild plan belongs to another fixture manifest")
    source_snapshot_sha256 = {
        binding.module: binding.snapshot_source_sha256 for binding in rebuild_plan.source_bindings
    }
    try:
        expected_plan = plan_real_lean_rebuild(
            fixture,
            source_snapshot_sha256,
            changed_declaration_ids=rebuild_plan.changed_declaration_ids,
        )
    except RealLeanRebuildPlanError as error:
        raise RealLeanRebuildExecutionError(
            "rebuild plan cannot be recomputed from its frozen source bindings"
        ) from error
    if expected_plan.canonical_bytes() != rebuild_plan.canonical_bytes():
        raise RealLeanRebuildExecutionError(
            "rebuild plan does not match the recomputed source-change closure"
        )
    plan_artifact = artifacts.put_bytes(rebuild_plan.canonical_bytes())
    if plan_artifact.digest != rebuild_plan.content_sha256 or plan_artifact.size != len(
        rebuild_plan.canonical_bytes()
    ):
        raise RealLeanRebuildExecutionError("rebuild plan artifact does not bind its bytes")

    actions = {item.node_id: item for item in rebuild_plan.declaration_actions}
    declarations = fixture.declaration_topological_order()
    if tuple(item.node_id for item in rebuild_plan.declaration_actions) != tuple(
        item.node_id for item in declarations
    ) or set(actions) != {item.node_id for item in declarations}:
        raise RealLeanRebuildExecutionError("rebuild plan declaration actions are incomplete")
    if any(
        actions[declaration.node_id].module != declaration.module for declaration in declarations
    ):
        raise RealLeanRebuildExecutionError(
            "rebuild plan declaration action module is inconsistent"
        )

    expected_reuse_nodes = {
        declaration.node_id
        for declaration in declarations
        if actions[declaration.node_id].action == _REUSE
    }
    if set(reuse_baseline_artifacts) != expected_reuse_nodes:
        raise RealLeanRebuildExecutionError(
            "reuse baseline artifacts must bind exactly every unchanged node"
        )
    for reference in reuse_baseline_artifacts.values():
        artifacts.verify(reference)
    nodes = tuple(
        RebuildExecutionNodeV1(
            node_id=declaration.node_id,
            module=declaration.module,
            action=actions[declaration.node_id].action,
            depends_on=declaration.depends_on,
            baseline_artifact=reuse_baseline_artifacts.get(declaration.node_id),
        )
        for declaration in declarations
    )

    bundle = RealLeanRebuildExecutionBundleV1(
        fixture_manifest_sha256=fixture.manifest_sha256(),
        rebuild_plan_sha256=rebuild_plan.content_sha256,
        rebuild_plan_artifact=plan_artifact,
        nodes=nodes,
    )
    artifact = artifacts.put_bytes(bundle.canonical_bytes())
    return FrozenRealLeanRebuildExecutionBundleV1(bundle=bundle, artifact=artifact)


class RealLeanRebuildExecutionStore:
    """Commit per-node T7 rebuild results only through an atomic lease fence.

    A successful node result is local execution evidence, not a proof result, task-contract
    decision, or promotion.  Reuse is explicit: every unchanged node records the baseline
    artifact it reused, and a changed node may record only ``VERIFIED`` or ``FAILED``.
    """

    def __init__(
        self,
        *,
        events: EventStore,
        leases: LeaseStore,
        artifacts: ArtifactStore,
    ) -> None:
        if events.path.resolve() != leases.path.resolve():
            raise RealLeanRebuildExecutionError(
                "event and lease stores must share one SQLite database for atomic fencing"
            )
        self.events = events
        self.leases = leases
        self.artifacts = artifacts

    def claim(
        self,
        frozen: FrozenRealLeanRebuildExecutionBundleV1,
        *,
        worker_id: str,
        ttl_seconds: float,
    ) -> Lease:
        """Claim the immutable bundle's derived lease key with the existing CAS lease store."""

        self._verify_frozen_bundle(frozen)
        return self.leases.claim(frozen.bundle.job_id, worker_id, ttl_seconds=ttl_seconds)

    def commit_node(
        self,
        frozen: FrozenRealLeanRebuildExecutionBundleV1,
        *,
        lease: Lease,
        node_id: str,
        outcome: NodeOutcome,
        result_artifact: ArtifactRef,
        idempotency_key: str,
    ) -> StoredEvent:
        """Atomically append one terminal node result while ``lease`` is still current.

        ``EventStore.append_fenced`` performs the fencing-token and expiry check in the same
        SQLite transaction as the append.  Consequently an expired or superseded recorder cannot
        create a new ``VERIFIED`` result, even if expiry occurs after this method begins.
        """

        self._verify_frozen_bundle(frozen)
        node = frozen.bundle.nodes_by_id.get(node_id)
        if node is None:
            raise RealLeanRebuildExecutionError("execution result references an unknown node")
        self._validate_outcome(node, outcome, result_artifact)
        self.artifacts.verify(result_artifact)
        idempotency = self._idempotency(
            frozen,
            lease=lease,
            node=node,
            outcome=outcome,
            result_artifact=result_artifact,
            key=idempotency_key,
        )
        replayed = self.events.lookup_idempotency(idempotency)
        if replayed is not None:
            if len(replayed) != 1:
                raise RealLeanRebuildExecutionError("node result idempotency record is invalid")
            return replayed[0]
        if lease.job_id != frozen.bundle.job_id:
            raise StaleFence("lease belongs to another rebuild bundle")
        # This makes an invalid lease fail before recorder-side dependency checks.  The fenced
        # append below repeats the check atomically with the durable state transition.
        self.leases.assert_current(lease)
        self._assert_dependencies_completed(frozen.bundle, node)
        payload: JsonObject = {
            "schema_version": NODE_RESULT_SCHEMA,
            "bundle_id": frozen.bundle.job_id,
            "execution_bundle_sha256": frozen.bundle.content_sha256,
            "execution_bundle_artifact": _artifact_document(frozen.artifact),
            "rebuild_plan_sha256": frozen.bundle.rebuild_plan_sha256,
            "node_id": node.node_id,
            "module": node.module,
            "planned_action": node.action,
            "outcome": outcome,
            "result_artifact": _artifact_document(result_artifact),
            "fencing_token": lease.fencing_token,
        }
        events = self.events.append_fenced(
            "t7_rebuild_node",
            self._node_entity_id(frozen.bundle, node.node_id),
            task_id=frozen.bundle.job_id,
            lease=lease,
            expected_sequence=0,
            events=(
                NewEvent(
                    f"t7_rebuild_node.{outcome.lower()}",
                    payload=payload,
                ),
            ),
            idempotency=idempotency,
        )
        return events[0]

    def execution_status(self, frozen: FrozenRealLeanRebuildExecutionBundleV1) -> str:
        """Derive a non-promotable aggregate from immutable terminal node events."""

        self._verify_frozen_bundle(frozen)
        outcomes = {
            node.node_id: self._node_outcome(frozen.bundle, node.node_id)
            for node in frozen.bundle.nodes
        }
        if _FAILED in outcomes.values():
            return _FAILED
        for node in frozen.bundle.nodes:
            expected = _VERIFIED if node.action == _REBUILD else _REUSED
            if outcomes[node.node_id] != expected:
                return _PENDING
        return _VERIFIED

    def _verify_frozen_bundle(self, frozen: FrozenRealLeanRebuildExecutionBundleV1) -> None:
        self.artifacts.verify(frozen.bundle.rebuild_plan_artifact)
        self.artifacts.verify(frozen.artifact)
        for node in frozen.bundle.nodes:
            if node.baseline_artifact is not None:
                self.artifacts.verify(node.baseline_artifact)
        if self.artifacts.get_bytes(frozen.artifact) != frozen.bundle.canonical_bytes():
            raise RealLeanRebuildExecutionError("execution bundle artifact content changed")

    def _assert_dependencies_completed(
        self,
        bundle: RealLeanRebuildExecutionBundleV1,
        node: RebuildExecutionNodeV1,
    ) -> None:
        for dependency_id in node.depends_on:
            dependency = bundle.nodes_by_id[dependency_id]
            outcome = self._node_outcome(bundle, dependency_id)
            expected = _VERIFIED if dependency.action == _REBUILD else _REUSED
            if outcome == _FAILED:
                raise RealLeanRebuildExecutionError("execution dependency failed")
            if outcome != expected:
                raise RealLeanRebuildExecutionError("execution dependency is not complete")

    def _node_outcome(self, bundle: RealLeanRebuildExecutionBundleV1, node_id: str) -> str:
        events = self.events.read_stream("t7_rebuild_node", self._node_entity_id(bundle, node_id))
        if not events:
            return _PENDING
        if len(events) != 1:
            raise RealLeanRebuildExecutionError("node result stream is not terminal")
        event = events[0]
        payload = event.payload
        node = bundle.nodes_by_id.get(node_id)
        if node is None or set(payload) != _NODE_RESULT_FIELDS:
            raise RealLeanRebuildExecutionError("node result payload shape is invalid")
        if (
            payload["schema_version"] != NODE_RESULT_SCHEMA
            or payload["bundle_id"] != bundle.job_id
            or payload["execution_bundle_sha256"] != bundle.content_sha256
            or payload["rebuild_plan_sha256"] != bundle.rebuild_plan_sha256
            or payload["node_id"] != node.node_id
            or payload["module"] != node.module
            or payload["planned_action"] != node.action
        ):
            raise RealLeanRebuildExecutionError("node result payload identity is inconsistent")
        fencing_token = payload["fencing_token"]
        if type(fencing_token) is not int or fencing_token <= 0:
            raise RealLeanRebuildExecutionError("node result fencing token is invalid")
        execution_artifact = _artifact_reference(
            payload["execution_bundle_artifact"], label="execution bundle"
        )
        expected_execution_artifact = ArtifactRef(
            digest=bundle.content_sha256,
            size=len(bundle.canonical_bytes()),
        )
        if execution_artifact != expected_execution_artifact:
            raise RealLeanRebuildExecutionError("node result execution artifact is inconsistent")
        self.artifacts.verify(execution_artifact)
        result_artifact = _artifact_reference(payload["result_artifact"], label="node result")
        self.artifacts.verify(result_artifact)
        outcome = payload["outcome"]
        if not isinstance(outcome, str) or outcome not in {_VERIFIED, _FAILED, _REUSED}:
            raise RealLeanRebuildExecutionError("node result outcome is invalid")
        self._validate_outcome(node, cast(NodeOutcome, outcome), result_artifact)
        if event.event_type != f"t7_rebuild_node.{outcome.lower()}":
            raise RealLeanRebuildExecutionError("node result event is inconsistent")
        return outcome

    @staticmethod
    def _node_entity_id(bundle: RealLeanRebuildExecutionBundleV1, node_id: str) -> str:
        return f"{bundle.content_sha256}:{node_id}"

    @staticmethod
    def _validate_outcome(
        node: RebuildExecutionNodeV1,
        outcome: NodeOutcome,
        result_artifact: ArtifactRef,
    ) -> None:
        if node.action == _REUSE and outcome != _REUSED:
            raise RealLeanRebuildExecutionError("unchanged node must record explicit reuse")
        if node.action == _REUSE and result_artifact != node.baseline_artifact:
            raise RealLeanRebuildExecutionError("reused node artifact does not match its baseline")
        if node.action == _REBUILD and outcome not in {_VERIFIED, _FAILED}:
            raise RealLeanRebuildExecutionError("changed node must record verification or failure")

    @staticmethod
    def _idempotency(
        frozen: FrozenRealLeanRebuildExecutionBundleV1,
        *,
        lease: Lease,
        node: RebuildExecutionNodeV1,
        outcome: NodeOutcome,
        result_artifact: ArtifactRef,
        key: str,
    ) -> Idempotency:
        # The expiry is intentionally excluded: it is volatile authority, not command meaning.
        value = {
            "execution_bundle_sha256": frozen.bundle.content_sha256,
            "lease": {
                "job_id": lease.job_id,
                "holder_id": lease.holder_id,
                "fencing_token": lease.fencing_token,
            },
            "node_id": node.node_id,
            "outcome": outcome,
            "result_artifact": _artifact_document(result_artifact),
        }
        return Idempotency(
            scope="t7_rebuild_node_commit",
            key=key,
            request_hash=request_hash(value),
        )


def _artifact_document(reference: ArtifactRef) -> JsonObject:
    return {
        "algorithm": reference.algorithm,
        "digest": reference.digest,
        "size": reference.size,
    }


def _artifact_reference(value: object, *, label: str) -> ArtifactRef:
    if not isinstance(value, dict) or set(value) != {"algorithm", "digest", "size"}:
        raise RealLeanRebuildExecutionError(f"{label} artifact reference is invalid")
    algorithm = value.get("algorithm")
    digest = value.get("digest")
    size = value.get("size")
    if not isinstance(algorithm, str) or not isinstance(digest, str) or type(size) is not int:
        raise RealLeanRebuildExecutionError(f"{label} artifact reference is invalid")
    try:
        return ArtifactRef(algorithm=algorithm, digest=digest, size=size)
    except ValueError as error:
        raise RealLeanRebuildExecutionError(f"{label} artifact reference is invalid") from error
