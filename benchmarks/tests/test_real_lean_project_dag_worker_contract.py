from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from autolean_control_plane import (
    ArtifactRef,
    ArtifactStore,
    EventStore,
    Lease,
    LeaseStore,
    NewEvent,
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
from benchmarks.real_lean_project_dag_change import (
    RealLeanChangeCaseV1,
    load_default_real_lean_change_case,
)
from benchmarks.real_lean_project_dag_execution import (
    FrozenRealLeanRebuildExecutionBundleV1,
    RealLeanRebuildExecutionStore,
    freeze_real_lean_rebuild_execution_bundle,
)
from benchmarks.real_lean_project_dag_rebuild import (
    RealLeanRebuildBundleV1,
)
from benchmarks.real_lean_project_dag_worker_contract import (
    SYNTHETIC_FAKE_NODE_EVIDENCE_CLASS,
    SYNTHETIC_NODE_EVENT_ENTITY_TYPE,
    SYNTHETIC_NODE_EVENT_SCHEMA,
    ChangedSourceWitnessV1,
    FrozenChangedSourceWitnessV1,
    FrozenLeanNodeVerificationReceiptV1,
    FrozenRealLeanImmutableWorkerInputV1,
    LeanWorkerEnvironmentV1,
    RealLeanTypedWorkerReceiptStore,
    RealLeanWorkerContractError,
    SyntheticNodeCommitResultV2,
    TypedWorkerExecutionStatusV1,
    freeze_changed_source_witness,
    freeze_lean_node_verification_receipt,
    freeze_real_lean_immutable_worker_input,
    plan_real_lean_rebuild_from_witness,
)

_CHANGED_MODULE = "AutoLean.ProjectDagPreflight.Arithmetic"
_CHANGED_NODE = "arithmetic.score"


@dataclass(frozen=True, slots=True)
class _ReviewedCandidate:
    fixture: RealLeanProjectDagV1
    reviewed_successor: RealLeanChangeCaseV1
    artifacts: ArtifactStore
    source_root: Path

    def freeze_witness(self) -> FrozenChangedSourceWitnessV1:
        return freeze_changed_source_witness(
            self.fixture,
            self.reviewed_successor,
            self.artifacts,
            source_snapshot_root=self.source_root,
        )


@dataclass(frozen=True, slots=True)
class _PreparedWorker:
    fixture: RealLeanProjectDagV1
    reviewed_successor: RealLeanChangeCaseV1
    witness: FrozenChangedSourceWitnessV1
    plan: RealLeanRebuildBundleV1
    execution: FrozenRealLeanRebuildExecutionBundleV1
    environment: LeanWorkerEnvironmentV1
    artifacts: ArtifactStore
    source_root: Path

    def freeze(self) -> FrozenRealLeanImmutableWorkerInputV1:
        return freeze_real_lean_immutable_worker_input(
            self.fixture,
            self.witness,
            self.execution,
            self.environment,
            self.artifacts,
        )


@dataclass(slots=True)
class _FakeLeanNodeVerifier:
    """Deterministic test double; it never invokes Lean, Docker, or a subprocess."""

    artifacts: ArtifactStore

    def run(
        self,
        worker: FrozenRealLeanImmutableWorkerInputV1,
        lease: Lease,
        node_id: str,
        dependency_artifacts: Mapping[str, ArtifactRef],
        *,
        outcome: str = "VERIFIED",
        exit_code: int = 0,
    ) -> FrozenLeanNodeVerificationReceiptV1:
        if outcome not in {"VERIFIED", "FAILED"}:
            raise AssertionError("fake runner outcome is unsupported")
        stdout = self.artifacts.put_bytes(f"fake stdout:{node_id}".encode())
        stderr = self.artifacts.put_bytes(
            b"" if outcome == "VERIFIED" else f"fake failure:{node_id}".encode()
        )
        result = self.artifacts.put_bytes(
            f"fake node result:{node_id}".encode() if outcome == "VERIFIED" else b""
        )
        return freeze_lean_node_verification_receipt(
            worker,
            self.artifacts,
            lease=lease,
            node_id=node_id,
            outcome=outcome,  # type: ignore[arg-type]
            exit_code=exit_code,
            dependency_artifacts=dependency_artifacts,
            stdout_artifact=stdout,
            stderr_artifact=stderr,
            result_artifact=result,
        )


def _environment(*, oci_repo_digest: str | None = None) -> LeanWorkerEnvironmentV1:
    return LeanWorkerEnvironmentV1(
        lean_version="4.28.0",
        mathlib_revision="a" * 40,
        oci_repo_digest=(oci_repo_digest or f"ghcr.io/autolean/mathlib-worker@sha256:{'b' * 64}"),
        runner_policy_sha256="c" * 64,
    )


def _reviewed_candidate(tmp_path: Path) -> _ReviewedCandidate:
    fixture = load_default_real_lean_project_dag()
    reviewed_successor = load_default_real_lean_change_case()
    source_root = tmp_path / "candidate"
    for module in fixture.module_topological_order():
        source = reviewed_successor.apply_to_module(module.module, successor=True)
        destination = source_root.joinpath(*Path(module.file).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source)
    return _ReviewedCandidate(
        fixture=fixture,
        reviewed_successor=reviewed_successor,
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        source_root=source_root,
    )


def _prepare(tmp_path: Path) -> _PreparedWorker:
    candidate = _reviewed_candidate(tmp_path)
    witness = candidate.freeze_witness()
    plan = plan_real_lean_rebuild_from_witness(
        candidate.fixture,
        witness,
        candidate.artifacts,
    )
    baselines = {
        action.node_id: candidate.artifacts.put_bytes(f"baseline:{action.node_id}".encode())
        for action in plan.declaration_actions
        if action.action == "reuse"
    }
    execution = freeze_real_lean_rebuild_execution_bundle(
        candidate.fixture,
        plan,
        candidate.artifacts,
        reuse_baseline_artifacts=baselines,
    )
    return _PreparedWorker(
        fixture=candidate.fixture,
        reviewed_successor=candidate.reviewed_successor,
        witness=witness,
        plan=plan,
        execution=execution,
        environment=_environment(),
        artifacts=candidate.artifacts,
        source_root=candidate.source_root,
    )


def _adapter(
    tmp_path: Path,
    artifacts: ArtifactStore,
    *,
    clock: Callable[[], datetime] | None = None,
) -> RealLeanTypedWorkerReceiptStore:
    database = tmp_path / "control.db"
    return RealLeanTypedWorkerReceiptStore(
        RealLeanRebuildExecutionStore(
            events=EventStore(database, clock=clock),
            leases=LeaseStore(database, clock=clock),
            artifacts=artifacts,
        )
    )


def _commit_all_synthetic_success(
    worker: FrozenRealLeanImmutableWorkerInputV1,
    adapter: RealLeanTypedWorkerReceiptStore,
    lease: Lease,
) -> tuple[dict[str, ArtifactRef], list[FrozenLeanNodeVerificationReceiptV1]]:
    results: dict[str, ArtifactRef] = {}
    receipts: list[FrozenLeanNodeVerificationReceiptV1] = []
    runner = _FakeLeanNodeVerifier(adapter.artifacts)
    for node in worker.execution.bundle.nodes:
        if node.action == "reuse":
            adapter.commit_reuse(
                worker,
                lease=lease,
                node_id=node.node_id,
                idempotency_key=f"reuse-{node.node_id}",
            )
            assert node.baseline_artifact is not None
            results[node.node_id] = node.baseline_artifact
            continue
        receipt = runner.run(
            worker,
            lease,
            node.node_id,
            {dependency: results[dependency] for dependency in node.depends_on},
        )
        adapter.commit_receipt(
            worker,
            lease=lease,
            frozen_receipt=receipt,
            idempotency_key=f"receipt-{node.node_id}",
        )
        results[node.node_id] = receipt.receipt.result_artifact
        receipts.append(receipt)
    return results, receipts


def _first_synthetic_receipt(
    worker: FrozenRealLeanImmutableWorkerInputV1,
    adapter: RealLeanTypedWorkerReceiptStore,
    lease: Lease,
) -> FrozenLeanNodeVerificationReceiptV1:
    results: dict[str, ArtifactRef] = {}
    for node in worker.execution.bundle.nodes:
        if node.action == "reuse":
            adapter.commit_reuse(
                worker,
                lease=lease,
                node_id=node.node_id,
                idempotency_key=f"prefix-reuse-{node.node_id}",
            )
            assert node.baseline_artifact is not None
            results[node.node_id] = node.baseline_artifact
            continue
        return _FakeLeanNodeVerifier(adapter.artifacts).run(
            worker,
            lease,
            node.node_id,
            {dependency: results[dependency] for dependency in node.depends_on},
        )
    raise AssertionError("reviewed changed-source fixture has no rebuild node")


def test_worker_input_captures_every_exact_source_byte_and_environment(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    worker = prepared.freeze()

    assert worker.bundle.execution_bundle_artifact == prepared.execution.artifact
    assert worker.bundle.environment_sha256 == prepared.environment.content_sha256
    assert isinstance(prepared.witness.witness, ChangedSourceWitnessV1)
    assert prepared.witness.witness.claimed_declaration_ids == (_CHANGED_NODE,)
    assert prepared.witness.witness.changed_module_ids == (
        "AutoLean.ProjectDagPreflight.Arithmetic",
        "AutoLean.ProjectDagPreflight.Relations",
        "AutoLean.ProjectDagPreflight.Capstone",
    )
    assert prepared.witness.witness.promotion_eligible is False
    assert (
        prepared.artifacts.get_bytes(worker.bundle.environment_artifact)
        == prepared.environment.canonical_bytes()
    )
    assert [source.module for source in worker.bundle.sources] == [
        module.module for module in prepared.fixture.module_topological_order()
    ]
    plan_bindings = {binding.module: binding for binding in prepared.plan.source_bindings}
    for source in worker.bundle.sources:
        expected_bytes = prepared.source_root.joinpath(*Path(source.file).parts).read_bytes()
        assert prepared.artifacts.get_bytes(source.artifact) == expected_bytes
        assert source.artifact.size == len(expected_bytes)
        assert source.artifact.digest == plan_bindings[source.module].snapshot_source_sha256


def test_worker_input_fails_closed_when_a_source_is_missing(tmp_path: Path) -> None:
    candidate = _reviewed_candidate(tmp_path)
    source = candidate.fixture.modules_by_name[_CHANGED_MODULE]
    candidate.source_root.joinpath(*Path(source.file).parts).unlink()

    with pytest.raises(RealLeanWorkerContractError, match="snapshot is incomplete"):
        candidate.freeze_witness()


def test_worker_input_fails_closed_when_source_bytes_drift_from_review(
    tmp_path: Path,
) -> None:
    candidate = _reviewed_candidate(tmp_path)
    source = candidate.fixture.modules_by_name[_CHANGED_MODULE]
    source_path = candidate.source_root.joinpath(*Path(source.file).parts)
    source_path.write_bytes(source_path.read_bytes() + b"-- unplanned drift\n")

    with pytest.raises(RealLeanWorkerContractError, match="exact reviewed successor"):
        candidate.freeze_witness()


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (
            b"import AutoLean.ProjectDagPreflight.Foundations",
            b"import AutoLean.ProjectDagPreflight.Capstone",
        ),
        (
            b"def score (bonus : Nat)",
            b"def renamedScore (bonus : Nat)",
        ),
    ],
)
def test_witness_rejects_unreviewed_import_or_declaration_surface_drift(
    tmp_path: Path,
    old: bytes,
    new: bytes,
) -> None:
    candidate = _reviewed_candidate(tmp_path)
    module = candidate.fixture.modules_by_name[_CHANGED_MODULE]
    source_path = candidate.source_root.joinpath(*Path(module.file).parts)
    source = source_path.read_bytes()
    assert source.count(old) == 1
    source_path.write_bytes(source.replace(old, new))

    with pytest.raises(RealLeanWorkerContractError, match="exact reviewed successor"):
        candidate.freeze_witness()


def test_witness_rejects_score_change_claimed_as_sum_is_seven(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    forged_witness = replace(
        prepared.witness.witness,
        claimed_declaration_ids=("arithmetic.sum-is-seven",),
    )
    frozen_forgery = FrozenChangedSourceWitnessV1(
        witness=forged_witness,
        artifact=prepared.artifacts.put_bytes(forged_witness.canonical_bytes()),
        reviewed_successor=prepared.reviewed_successor,
        fixture=prepared.fixture,
    )

    with pytest.raises(RealLeanWorkerContractError, match="review binding"):
        plan_real_lean_rebuild_from_witness(
            prepared.fixture,
            frozen_forgery,
            prepared.artifacts,
        )


def test_witness_rejects_empty_changed_declarations_for_changed_sources(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)

    with pytest.raises(RealLeanWorkerContractError, match="witness is invalid"):
        replace(prepared.witness.witness, claimed_declaration_ids=())


def test_witness_rejects_candidate_artifact_substitution(tmp_path: Path) -> None:
    prepared = _prepare(tmp_path)
    pairs = list(prepared.witness.witness.source_artifacts)
    changed_index = next(
        index for index, pair in enumerate(pairs) if pair.module == _CHANGED_MODULE
    )
    pairs[changed_index] = replace(
        pairs[changed_index],
        candidate_source_artifact=prepared.artifacts.put_bytes(b"substituted source"),
    )
    substituted = replace(
        prepared.witness.witness,
        source_artifacts=tuple(pairs),
    )
    frozen_substitution = FrozenChangedSourceWitnessV1(
        witness=substituted,
        artifact=prepared.artifacts.put_bytes(substituted.canonical_bytes()),
        reviewed_successor=prepared.reviewed_successor,
        fixture=prepared.fixture,
    )

    with pytest.raises(RealLeanWorkerContractError, match="source artifact"):
        plan_real_lean_rebuild_from_witness(
            prepared.fixture,
            frozen_substitution,
            prepared.artifacts,
        )


def test_witness_rejects_reviewed_manifest_artifact_loss(tmp_path: Path) -> None:
    prepared = _prepare(tmp_path)
    reviewed_manifest = prepared.witness.witness.reviewed_successor_manifest_artifact
    prepared.artifacts.path_for(reviewed_manifest).unlink()

    with pytest.raises(ArtifactNotFound):
        plan_real_lean_rebuild_from_witness(
            prepared.fixture,
            prepared.witness,
            prepared.artifacts,
        )


def test_witness_cannot_be_marked_promotion_eligible(tmp_path: Path) -> None:
    prepared = _prepare(tmp_path)

    with pytest.raises(RealLeanWorkerContractError, match="witness is invalid"):
        replace(prepared.witness.witness, promotion_eligible=True)


def test_frozen_worker_rejects_a_forged_nested_fixture_identity(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    worker = prepared.freeze()
    forged_bundle = replace(worker.bundle, fixture_manifest_sha256="f" * 64)
    forged_artifact = prepared.artifacts.put_bytes(forged_bundle.canonical_bytes())

    with pytest.raises(RealLeanWorkerContractError, match="binding is invalid"):
        FrozenRealLeanImmutableWorkerInputV1(
            bundle=forged_bundle,
            artifact=forged_artifact,
            environment=worker.environment,
            changed_source_witness=worker.changed_source_witness,
            rebuild_plan=worker.rebuild_plan,
            execution=worker.execution,
            fixture=worker.fixture,
        )


def test_worker_input_recomputes_execution_graph_instead_of_trusting_shape(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    forged_node = replace(
        prepared.execution.bundle.nodes[-1],
        module="Forged.Module",
    )
    forged_bundle = replace(
        prepared.execution.bundle,
        nodes=(*prepared.execution.bundle.nodes[:-1], forged_node),
    )
    forged_execution = FrozenRealLeanRebuildExecutionBundleV1(
        bundle=forged_bundle,
        artifact=prepared.artifacts.put_bytes(forged_bundle.canonical_bytes()),
    )

    with pytest.raises(
        RealLeanWorkerContractError, match="differs from recomputed fixture and plan"
    ):
        freeze_real_lean_immutable_worker_input(
            prepared.fixture,
            prepared.witness,
            forged_execution,
            prepared.environment,
            prepared.artifacts,
        )


@pytest.mark.parametrize(
    "image",
    [
        "ghcr.io/autolean/mathlib-worker:latest",
        f"sha256:{'b' * 64}",
        f"ghcr.io/autolean/mathlib-worker:tag@sha256:{'b' * 64}",
        f"GHCR.IO/autolean/mathlib-worker@sha256:{'b' * 64}",
    ],
)
def test_environment_rejects_tags_image_ids_and_noncanonical_repositories(
    image: str,
) -> None:
    with pytest.raises(RealLeanWorkerContractError, match="RepoDigest"):
        _environment(oci_repo_digest=image)


def test_environment_accepts_registry_port_with_exact_repo_digest() -> None:
    environment = _environment(
        oci_repo_digest=f"registry.example:5000/autolean/worker@sha256:{'d' * 64}"
    )

    assert environment.oci_repo_digest.startswith("registry.example:5000/")


@pytest.mark.parametrize(
    ("outcome", "exit_code", "message"),
    [
        ("VERIFIED", 1, "VERIFIED receipt"),
        ("FAILED", 0, "FAILED receipt"),
    ],
)
def test_typed_receipt_enforces_exit_code_semantics(
    tmp_path: Path,
    outcome: str,
    exit_code: int,
    message: str,
) -> None:
    prepared = _prepare(tmp_path)
    worker = prepared.freeze()
    adapter = _adapter(tmp_path, prepared.artifacts)
    lease = adapter.claim(worker, worker_id="fake", ttl_seconds=60)
    target = next(node for node in worker.execution.bundle.nodes if node.action == "rebuild")
    dependencies = {
        dependency: worker.execution.bundle.nodes_by_id[dependency].baseline_artifact
        for dependency in target.depends_on
    }
    assert all(reference is not None for reference in dependencies.values())

    with pytest.raises(RealLeanWorkerContractError, match=message):
        _FakeLeanNodeVerifier(prepared.artifacts).run(
            worker,
            lease,
            target.node_id,
            {
                node_id: reference
                for node_id, reference in dependencies.items()
                if reference is not None
            },
            outcome=outcome,
            exit_code=exit_code,
        )


def test_fake_node_receipts_return_only_nonpromotable_typed_status(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    worker = prepared.freeze()
    adapter = _adapter(tmp_path, prepared.artifacts)
    lease = adapter.claim(worker, worker_id="fake", ttl_seconds=60)

    _, receipts = _commit_all_synthetic_success(worker, adapter, lease)

    assert receipts
    status = adapter.execution_status(worker)
    assert isinstance(status, TypedWorkerExecutionStatusV1)
    assert status.state == "SYNTHETIC_COMPLETE"
    assert status.evidence_class == SYNTHETIC_FAKE_NODE_EVIDENCE_CLASS
    assert status.promotion_eligible is False
    for receipt in receipts:
        assert receipt.receipt.evidence_class == SYNTHETIC_FAKE_NODE_EVIDENCE_CLASS
        assert receipt.receipt.promotion_eligible is False
        events = adapter._store.events.read_stream(
            SYNTHETIC_NODE_EVENT_ENTITY_TYPE,
            f"{worker.bundle.content_sha256}:{receipt.receipt.node_id}",
        )
        assert len(events) == 1
        event = events[0]
        assert event.event_type == "t7_synthetic_node_v2.synthetic_complete"
        assert "VERIFIED" not in event.event_type
        assert "outcome" not in event.payload
        assert "VERIFIED" not in json.dumps(event.payload, sort_keys=True)
        assert event.payload["schema_version"] == SYNTHETIC_NODE_EVENT_SCHEMA
        assert event.payload["typed_outcome"] == "SYNTHETIC_COMPLETE"
        assert event.payload["evidence_class"] == SYNTHETIC_FAKE_NODE_EVIDENCE_CLASS
        assert event.payload["promotion_eligible"] is False
        receipt_reference = event.payload["receipt_artifact"]
        assert isinstance(receipt_reference, dict)
        assert receipt_reference["digest"] == receipt.artifact.digest
        assert event.payload["receipt_sha256"] == receipt.artifact.digest
        result_reference = event.payload["node_result_artifact"]
        assert isinstance(result_reference, dict)
        assert result_reference["digest"] == receipt.receipt.result_artifact.digest
        assert (
            adapter._store.events.read_stream(
                "t7_rebuild_node",
                f"{worker.execution.bundle.content_sha256}:{receipt.receipt.node_id}",
            )
            == ()
        )


def test_synthetic_commit_returns_typed_result_and_replays_at_most_once(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    worker = prepared.freeze()
    adapter = _adapter(tmp_path, prepared.artifacts)
    lease = adapter.claim(worker, worker_id="fake", ttl_seconds=60)
    receipt = _first_synthetic_receipt(worker, adapter, lease)

    first = adapter.commit_receipt(
        worker,
        lease=lease,
        frozen_receipt=receipt,
        idempotency_key="typed-result-replay",
    )
    replayed = adapter.commit_receipt(
        worker,
        lease=lease,
        frozen_receipt=receipt,
        idempotency_key="typed-result-replay",
    )

    assert isinstance(first, SyntheticNodeCommitResultV2)
    assert first == replayed
    assert first.typed_outcome == "SYNTHETIC_COMPLETE"
    assert first.evidence_class == SYNTHETIC_FAKE_NODE_EVIDENCE_CLASS
    assert first.promotion_eligible is False
    assert not hasattr(first, "outcome")
    events = adapter._node_events(worker, receipt.receipt.node_id)
    assert len(events) == 1

    with pytest.raises(ConcurrencyError):
        adapter.commit_receipt(
            worker,
            lease=lease,
            frozen_receipt=receipt,
            idempotency_key="different-command-same-node",
        )


def test_synthetic_job_identity_includes_the_complete_worker_environment(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    first_worker = prepared.freeze()
    second_worker = replace(
        prepared,
        environment=_environment(
            oci_repo_digest=f"ghcr.io/autolean/mathlib-worker@sha256:{'d' * 64}"
        ),
    ).freeze()
    adapter = _adapter(tmp_path, prepared.artifacts)

    first_lease = adapter.claim(first_worker, worker_id="first", ttl_seconds=60)
    second_lease = adapter.claim(second_worker, worker_id="second", ttl_seconds=60)

    assert first_worker.bundle.job_id != second_worker.bundle.job_id
    assert first_lease.job_id == first_worker.bundle.job_id
    assert second_lease.job_id == second_worker.bundle.job_id


@pytest.mark.parametrize(
    "mutation",
    ["evidence_class", "promotion_eligible"],
)
def test_fake_receipt_cannot_claim_promotable_or_other_evidence(
    tmp_path: Path,
    mutation: str,
) -> None:
    prepared = _prepare(tmp_path)
    worker = prepared.freeze()
    adapter = _adapter(tmp_path, prepared.artifacts)
    lease = adapter.claim(worker, worker_id="fake", ttl_seconds=60)
    receipt = _first_synthetic_receipt(worker, adapter, lease)

    with pytest.raises(RealLeanWorkerContractError, match="receipt identity"):
        if mutation == "evidence_class":
            replace(receipt.receipt, evidence_class="forged_evidence")
        else:
            replace(receipt.receipt, promotion_eligible=True)


@pytest.mark.parametrize(
    "mutation",
    ["evidence_class", "promotion_eligible"],
)
def test_typed_status_cannot_be_relabelled_or_promoted(mutation: str) -> None:
    with pytest.raises(RealLeanWorkerContractError, match="status is invalid"):
        if mutation == "evidence_class":
            TypedWorkerExecutionStatusV1(
                state="SYNTHETIC_COMPLETE",
                evidence_class="forged_evidence",
            )
        else:
            TypedWorkerExecutionStatusV1(
                state="SYNTHETIC_COMPLETE",
                promotion_eligible=True,
            )


@pytest.mark.parametrize("mutation", ["missing", "mismatched", "promotable"])
def test_typed_status_rejects_unqualified_synthetic_event(
    tmp_path: Path,
    mutation: str,
) -> None:
    prepared = _prepare(tmp_path)
    worker = prepared.freeze()
    adapter = _adapter(tmp_path, prepared.artifacts)
    lease = adapter.claim(worker, worker_id="fake", ttl_seconds=60)
    receipt = _first_synthetic_receipt(worker, adapter, lease)
    node = worker.execution.bundle.nodes_by_id[receipt.receipt.node_id]
    document = adapter._synthetic_event_payload(
        worker,
        lease=lease,
        node=node,
        typed_outcome="SYNTHETIC_COMPLETE",
        frozen_receipt=receipt,
        node_result_artifact=receipt.receipt.result_artifact,
    )
    if mutation == "missing":
        del document["evidence_class"]
    elif mutation == "mismatched":
        document["evidence_class"] = "forged_evidence"
    else:
        document["promotion_eligible"] = True
    adapter._store.events.append_fenced(
        SYNTHETIC_NODE_EVENT_ENTITY_TYPE,
        adapter._synthetic_entity_id(worker, node.node_id),
        task_id=worker.bundle.job_id,
        lease=lease,
        expected_sequence=0,
        events=(
            NewEvent(
                "t7_synthetic_node_v2.synthetic_complete",
                payload=document,
            ),
        ),
    )

    with pytest.raises(RealLeanWorkerContractError):
        adapter.execution_status(worker)


def test_adapter_rejects_dependency_artifact_drift(tmp_path: Path) -> None:
    prepared = _prepare(tmp_path)
    worker = prepared.freeze()
    adapter = _adapter(tmp_path, prepared.artifacts)
    lease = adapter.claim(worker, worker_id="fake", ttl_seconds=60)
    results: dict[str, ArtifactRef] = {}
    runner = _FakeLeanNodeVerifier(prepared.artifacts)

    for node in worker.execution.bundle.nodes:
        if node.action == "reuse":
            adapter.commit_reuse(
                worker,
                lease=lease,
                node_id=node.node_id,
                idempotency_key=f"reuse-{node.node_id}",
            )
            assert node.baseline_artifact is not None
            results[node.node_id] = node.baseline_artifact
            continue
        assert node.depends_on
        forged_dependencies = {dependency: results[dependency] for dependency in node.depends_on}
        forged_dependencies[node.depends_on[0]] = prepared.artifacts.put_bytes(b"forged dependency")
        receipt = runner.run(
            worker,
            lease,
            node.node_id,
            forged_dependencies,
        )
        with pytest.raises(RealLeanWorkerContractError, match="drifted from durable results"):
            adapter.commit_receipt(
                worker,
                lease=lease,
                frozen_receipt=receipt,
                idempotency_key="forged-dependency",
            )
        break
    else:
        raise AssertionError("fixture has no rebuilt node with dependencies")


def test_same_size_receipt_tamper_is_detected_during_status(tmp_path: Path) -> None:
    prepared = _prepare(tmp_path)
    worker = prepared.freeze()
    adapter = _adapter(tmp_path, prepared.artifacts)
    lease = adapter.claim(worker, worker_id="fake", ttl_seconds=60)
    _, receipts = _commit_all_synthetic_success(worker, adapter, lease)
    receipt = receipts[-1]
    prepared.artifacts.path_for(receipt.artifact).write_bytes(b"\x00" * receipt.artifact.size)

    with pytest.raises(ArtifactCorruption):
        adapter.execution_status(worker)


@pytest.mark.parametrize(
    "artifact_field",
    ["stdout_artifact", "stderr_artifact", "result_artifact"],
)
def test_status_reverifies_every_receipt_output_artifact(
    tmp_path: Path,
    artifact_field: str,
) -> None:
    prepared = _prepare(tmp_path)
    worker = prepared.freeze()
    adapter = _adapter(tmp_path, prepared.artifacts)
    lease = adapter.claim(worker, worker_id="fake", ttl_seconds=60)
    _, receipts = _commit_all_synthetic_success(worker, adapter, lease)
    reference = getattr(receipts[-1].receipt, artifact_field)
    assert isinstance(reference, ArtifactRef)
    prepared.artifacts.path_for(reference).unlink()

    with pytest.raises(ArtifactNotFound):
        adapter.execution_status(worker)


def test_status_fails_when_a_frozen_source_artifact_is_lost(tmp_path: Path) -> None:
    prepared = _prepare(tmp_path)
    worker = prepared.freeze()
    adapter = _adapter(tmp_path, prepared.artifacts)
    source = worker.bundle.sources[-1].artifact
    prepared.artifacts.path_for(source).unlink()

    with pytest.raises(ArtifactNotFound):
        adapter.execution_status(worker)


def test_status_fails_when_the_environment_artifact_is_lost(tmp_path: Path) -> None:
    prepared = _prepare(tmp_path)
    worker = prepared.freeze()
    adapter = _adapter(tmp_path, prepared.artifacts)
    prepared.artifacts.path_for(worker.bundle.environment_artifact).unlink()

    with pytest.raises(ArtifactNotFound):
        adapter.execution_status(worker)


def test_stale_fencing_token_cannot_commit_a_typed_receipt(tmp_path: Path) -> None:
    state = {"now": datetime(2026, 1, 1, tzinfo=UTC)}

    def clock() -> datetime:
        return state["now"]

    prepared = _prepare(tmp_path)
    worker = prepared.freeze()
    adapter = _adapter(tmp_path, prepared.artifacts, clock=clock)
    stale_lease = adapter.claim(worker, worker_id="old", ttl_seconds=1)
    results: dict[str, ArtifactRef] = {}
    target = next(node for node in worker.execution.bundle.nodes if node.action == "rebuild")
    for node in worker.execution.bundle.nodes:
        if node.node_id == target.node_id:
            break
        assert node.action == "reuse"
        adapter.commit_reuse(
            worker,
            lease=stale_lease,
            node_id=node.node_id,
            idempotency_key=f"reuse-{node.node_id}",
        )
        assert node.baseline_artifact is not None
        results[node.node_id] = node.baseline_artifact
    receipt = _FakeLeanNodeVerifier(prepared.artifacts).run(
        worker,
        stale_lease,
        target.node_id,
        {dependency: results[dependency] for dependency in target.depends_on},
    )
    state["now"] += timedelta(seconds=2)
    current_lease = adapter.claim(worker, worker_id="new", ttl_seconds=60)
    assert current_lease.fencing_token > stale_lease.fencing_token

    with pytest.raises(StaleFence):
        adapter.commit_receipt(
            worker,
            lease=stale_lease,
            frozen_receipt=receipt,
            idempotency_key="stale-receipt",
        )
