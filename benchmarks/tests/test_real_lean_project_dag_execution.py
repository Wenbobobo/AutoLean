from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from autolean_control_plane import (
    ArtifactRef,
    ArtifactStore,
    EventStore,
    Lease,
    LeaseStore,
    StoredEvent,
)
from autolean_control_plane.errors import (
    ArtifactCorruption,
    ArtifactNotFound,
    ConcurrencyError,
    StaleFence,
)

from benchmarks.real_lean_project_dag import (
    RealLeanProjectDagV1,
    load_default_real_lean_project_dag,
)
from benchmarks.real_lean_project_dag_execution import (
    FrozenRealLeanRebuildExecutionBundleV1,
    RealLeanRebuildExecutionError,
    RealLeanRebuildExecutionStore,
    freeze_real_lean_rebuild_execution_bundle,
)
from benchmarks.real_lean_project_dag_rebuild import (
    RealLeanRebuildBundleV1,
    RebuildDeclarationActionV1,
    RebuildModuleActionV1,
    plan_real_lean_rebuild,
)


def _changed_hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _frozen_leaf_bundle(
    tmp_path: Path,
) -> tuple[
    RealLeanProjectDagV1,
    RealLeanRebuildBundleV1,
    ArtifactStore,
    FrozenRealLeanRebuildExecutionBundleV1,
]:
    fixture = load_default_real_lean_project_dag()
    hashes = {module.module: module.source_sha256 for module in fixture.modules}
    changed_module = "AutoLean.ProjectDagPreflight.Capstone"
    hashes[changed_module] = _changed_hash("capstone execution change")
    plan = plan_real_lean_rebuild(
        fixture,
        hashes,
        changed_declaration_ids=("capstone.capstone",),
    )
    artifacts = ArtifactStore(tmp_path / "artifacts")
    reuse_baseline_artifacts = {
        action.node_id: artifacts.put_bytes(f"baseline:{action.node_id}".encode())
        for action in plan.declaration_actions
        if action.action == "reuse"
    }
    frozen = freeze_real_lean_rebuild_execution_bundle(
        fixture,
        plan,
        artifacts,
        reuse_baseline_artifacts=reuse_baseline_artifacts,
    )
    return fixture, plan, artifacts, frozen


def _store(
    tmp_path: Path,
    artifacts: ArtifactStore,
    *,
    clock: Callable[[], datetime] | None = None,
) -> RealLeanRebuildExecutionStore:
    database = tmp_path / "control.db"
    return RealLeanRebuildExecutionStore(
        events=EventStore(database, clock=clock),
        leases=LeaseStore(database, clock=clock),
        artifacts=artifacts,
    )


def _result(artifacts: ArtifactStore, label: str) -> ArtifactRef:
    return artifacts.put_bytes(label.encode("utf-8"))


def _commit_reused_nodes(
    store: RealLeanRebuildExecutionStore,
    frozen: FrozenRealLeanRebuildExecutionBundleV1,
    lease: Lease,
    artifacts: ArtifactStore,
) -> None:
    for node in frozen.bundle.nodes:
        if node.action == "reuse":
            assert node.baseline_artifact is not None
            store.commit_node(
                frozen,
                lease=lease,
                node_id=node.node_id,
                outcome="REUSED",
                result_artifact=node.baseline_artifact,
                idempotency_key=f"reuse-{node.node_id}",
            )


def _commit_rebuilt_nodes(
    store: RealLeanRebuildExecutionStore,
    frozen: FrozenRealLeanRebuildExecutionBundleV1,
    lease: Lease,
    artifacts: ArtifactStore,
) -> list[StoredEvent]:
    events: list[StoredEvent] = []
    for node in frozen.bundle.nodes:
        if node.action == "rebuild":
            events.append(
                store.commit_node(
                    frozen,
                    lease=lease,
                    node_id=node.node_id,
                    outcome="VERIFIED",
                    result_artifact=_result(artifacts, f"verified:{node.node_id}"),
                    idempotency_key=f"verified-{node.node_id}",
                )
            )
    return events


def _result_artifact(event: StoredEvent) -> ArtifactRef:
    value = event.payload["result_artifact"]
    assert isinstance(value, dict)
    algorithm = value["algorithm"]
    digest = value["digest"]
    size = value["size"]
    assert isinstance(algorithm, str)
    assert isinstance(digest, str)
    assert type(size) is int
    return ArtifactRef(algorithm=algorithm, digest=digest, size=size)


def test_freeze_seals_plan_and_complete_execution_graph_as_immutable_artifacts(
    tmp_path: Path,
) -> None:
    fixture, plan, artifacts, frozen = _frozen_leaf_bundle(tmp_path)

    assert artifacts.get_bytes(frozen.bundle.rebuild_plan_artifact) == plan.canonical_bytes()
    assert artifacts.get_bytes(frozen.artifact) == frozen.bundle.canonical_bytes()
    assert frozen.artifact.digest == frozen.bundle.content_sha256
    assert frozen.bundle.fixture_manifest_sha256 == fixture.manifest_sha256()
    assert [node.node_id for node in frozen.bundle.nodes] == [
        declaration.node_id for declaration in fixture.declaration_topological_order()
    ]
    assert {node.node_id for node in frozen.bundle.nodes if node.action == "rebuild"} == {
        declaration.node_id
        for declaration in fixture.declarations
        if declaration.module == "AutoLean.ProjectDagPreflight.Capstone"
    }
    for node in frozen.bundle.nodes:
        if node.action == "reuse":
            assert node.baseline_artifact is not None
            expected_baseline = f"baseline:{node.node_id}".encode()
            assert artifacts.get_bytes(node.baseline_artifact) == expected_baseline
    with pytest.raises(FrozenInstanceError):
        frozen.bundle.nodes = ()  # type: ignore[misc]


def test_freeze_requires_a_baseline_artifact_for_every_reused_node(tmp_path: Path) -> None:
    fixture, plan, artifacts, _ = _frozen_leaf_bundle(tmp_path)

    with pytest.raises(RealLeanRebuildExecutionError, match="exactly every unchanged node"):
        freeze_real_lean_rebuild_execution_bundle(
            fixture,
            plan,
            artifacts,
            reuse_baseline_artifacts={},
        )


def test_freeze_rejects_a_forged_changed_source_plan_that_marks_everything_reused(
    tmp_path: Path,
) -> None:
    fixture = load_default_real_lean_project_dag()
    hashes = {module.module: module.source_sha256 for module in fixture.modules}
    hashes["AutoLean.ProjectDagPreflight.Arithmetic"] = _changed_hash("forged arithmetic")
    plan = plan_real_lean_rebuild(
        fixture,
        hashes,
        changed_declaration_ids=("arithmetic.score",),
    )
    forged = replace(
        plan,
        module_actions=tuple(
            RebuildModuleActionV1(
                module=action.module,
                action="reuse",
                reason="unchanged_source_reuse",
            )
            for action in plan.module_actions
        ),
        declaration_actions=tuple(
            RebuildDeclarationActionV1(
                node_id=action.node_id,
                module=action.module,
                action="reuse",
            )
            for action in plan.declaration_actions
        ),
    )
    artifacts = ArtifactStore(tmp_path / "artifacts")
    forged_baselines = {
        action.node_id: artifacts.put_bytes(f"forged:{action.node_id}".encode())
        for action in forged.declaration_actions
    }

    with pytest.raises(RealLeanRebuildExecutionError, match="recomputed source-change closure"):
        freeze_real_lean_rebuild_execution_bundle(
            fixture,
            forged,
            artifacts,
            reuse_baseline_artifacts=forged_baselines,
        )


def test_commit_requires_the_bundle_lease_and_records_unchanged_nodes_as_reused(
    tmp_path: Path,
) -> None:
    _, _, artifacts, frozen = _frozen_leaf_bundle(tmp_path)
    store = _store(tmp_path, artifacts)
    foreign = store.leases.claim("another-bundle", "worker", ttl_seconds=60)
    capstone = next(node for node in frozen.bundle.nodes if node.action == "rebuild")

    with pytest.raises(StaleFence):
        store.commit_node(
            frozen,
            lease=foreign,
            node_id=capstone.node_id,
            outcome="VERIFIED",
            result_artifact=_result(artifacts, "capstone"),
            idempotency_key="foreign-lease",
        )

    assert (
        store.events.read_stream(
            "t7_rebuild_node", f"{frozen.bundle.content_sha256}:{capstone.node_id}"
        )
        == ()
    )
    lease = store.claim(frozen, worker_id="worker", ttl_seconds=60)
    _commit_reused_nodes(store, frozen, lease, artifacts)
    event = _commit_rebuilt_nodes(store, frozen, lease, artifacts)[-1]

    assert event.payload["fencing_token"] == lease.fencing_token
    assert event.payload["execution_bundle_sha256"] == frozen.bundle.content_sha256
    assert event.payload["outcome"] == "VERIFIED"
    assert store.execution_status(frozen) == "VERIFIED"


def test_reused_node_rejects_an_artifact_other_than_its_frozen_baseline(tmp_path: Path) -> None:
    _, _, artifacts, frozen = _frozen_leaf_bundle(tmp_path)
    store = _store(tmp_path, artifacts)
    lease = store.claim(frozen, worker_id="worker", ttl_seconds=60)
    reusable = next(node for node in frozen.bundle.nodes if not node.depends_on)
    assert reusable.action == "reuse"

    with pytest.raises(RealLeanRebuildExecutionError, match="does not match its baseline"):
        store.commit_node(
            frozen,
            lease=lease,
            node_id=reusable.node_id,
            outcome="REUSED",
            result_artifact=_result(artifacts, "not the baseline artifact"),
            idempotency_key="wrong-reuse-artifact",
        )

    assert (
        store.events.read_stream(
            "t7_rebuild_node", f"{frozen.bundle.content_sha256}:{reusable.node_id}"
        )
        == ()
    )


def test_status_refuses_a_bundle_when_a_frozen_baseline_artifact_is_lost(tmp_path: Path) -> None:
    _, _, artifacts, frozen = _frozen_leaf_bundle(tmp_path)
    store = _store(tmp_path, artifacts)
    lease = store.claim(frozen, worker_id="worker", ttl_seconds=60)
    _commit_reused_nodes(store, frozen, lease, artifacts)
    _commit_rebuilt_nodes(store, frozen, lease, artifacts)
    baseline = next(
        node.baseline_artifact for node in frozen.bundle.nodes if node.baseline_artifact is not None
    )
    artifacts.path_for(baseline).unlink()

    with pytest.raises(ArtifactNotFound):
        store.execution_status(frozen)


def test_status_refuses_a_verified_rebuild_when_its_result_artifact_is_lost(
    tmp_path: Path,
) -> None:
    _, _, artifacts, frozen = _frozen_leaf_bundle(tmp_path)
    store = _store(tmp_path, artifacts)
    lease = store.claim(frozen, worker_id="worker", ttl_seconds=60)
    _commit_reused_nodes(store, frozen, lease, artifacts)
    rebuilt = _commit_rebuilt_nodes(store, frozen, lease, artifacts)
    assert store.execution_status(frozen) == "VERIFIED"
    result_artifact = _result_artifact(rebuilt[-1])
    artifacts.path_for(result_artifact).unlink()

    with pytest.raises(ArtifactNotFound):
        store.execution_status(frozen)


def test_status_refuses_same_size_corruption_of_a_verified_rebuild_artifact(
    tmp_path: Path,
) -> None:
    _, _, artifacts, frozen = _frozen_leaf_bundle(tmp_path)
    store = _store(tmp_path, artifacts)
    lease = store.claim(frozen, worker_id="worker", ttl_seconds=60)
    _commit_reused_nodes(store, frozen, lease, artifacts)
    rebuilt = _commit_rebuilt_nodes(store, frozen, lease, artifacts)
    assert store.execution_status(frozen) == "VERIFIED"
    result_artifact = _result_artifact(rebuilt[-1])
    artifacts.path_for(result_artifact).write_bytes(b"\x00" * result_artifact.size)

    with pytest.raises(ArtifactCorruption):
        store.execution_status(frozen)


def test_failed_node_cannot_be_republished_as_verified(tmp_path: Path) -> None:
    _, _, artifacts, frozen = _frozen_leaf_bundle(tmp_path)
    store = _store(tmp_path, artifacts)
    lease = store.claim(frozen, worker_id="worker", ttl_seconds=60)
    _commit_reused_nodes(store, frozen, lease, artifacts)
    capstone = next(node for node in frozen.bundle.nodes if node.action == "rebuild")
    failed = store.commit_node(
        frozen,
        lease=lease,
        node_id=capstone.node_id,
        outcome="FAILED",
        result_artifact=_result(artifacts, "compile diagnostic"),
        idempotency_key="capstone-failed",
    )

    with pytest.raises(ConcurrencyError):
        store.commit_node(
            frozen,
            lease=lease,
            node_id=capstone.node_id,
            outcome="VERIFIED",
            result_artifact=_result(artifacts, "late verified result"),
            idempotency_key="capstone-verified",
        )

    assert failed.event_type == "t7_rebuild_node.failed"
    assert store.execution_status(frozen) == "FAILED"
    node_events = store.events.read_stream(
        "t7_rebuild_node", f"{frozen.bundle.content_sha256}:{capstone.node_id}"
    )
    assert [event.event_type for event in node_events] == ["t7_rebuild_node.failed"]


def test_expiry_between_preflight_and_fenced_append_cannot_publish_verified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = {"now": datetime(2026, 1, 1, tzinfo=UTC)}

    def clock() -> datetime:
        return state["now"]

    _, _, artifacts, frozen = _frozen_leaf_bundle(tmp_path)
    store = _store(tmp_path, artifacts, clock=clock)
    lease = store.claim(frozen, worker_id="worker", ttl_seconds=5)
    _commit_reused_nodes(store, frozen, lease, artifacts)
    capstone = next(node for node in frozen.bundle.nodes if node.action == "rebuild")
    original_append = store.events.append_fenced

    def expire_then_append(*args: Any, **kwargs: Any) -> tuple[StoredEvent, ...]:
        state["now"] += timedelta(seconds=6)
        return original_append(*args, **kwargs)

    monkeypatch.setattr(store.events, "append_fenced", expire_then_append)
    with pytest.raises(StaleFence):
        store.commit_node(
            frozen,
            lease=lease,
            node_id=capstone.node_id,
            outcome="VERIFIED",
            result_artifact=_result(artifacts, "expired capstone"),
            idempotency_key="expired-capstone",
        )

    assert store.execution_status(frozen) == "PENDING"
    assert (
        store.events.read_stream(
            "t7_rebuild_node", f"{frozen.bundle.content_sha256}:{capstone.node_id}"
        )
        == ()
    )


def test_rebuild_nodes_require_completed_prerequisites(tmp_path: Path) -> None:
    _, _, artifacts, frozen = _frozen_leaf_bundle(tmp_path)
    store = _store(tmp_path, artifacts)
    lease = store.claim(frozen, worker_id="worker", ttl_seconds=60)
    capstone = next(node for node in frozen.bundle.nodes if node.action == "rebuild")

    with pytest.raises(RealLeanRebuildExecutionError, match="dependency is not complete"):
        store.commit_node(
            frozen,
            lease=lease,
            node_id=capstone.node_id,
            outcome="VERIFIED",
            result_artifact=_result(artifacts, "out-of-order"),
            idempotency_key="out-of-order",
        )
