from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from autolean_control_plane import (
    ArtifactRef,
    ArtifactStore,
    EventStore,
    Idempotency,
    LeaseStore,
    NewEvent,
    request_hash,
)
from autolean_control_plane.errors import (
    ArtifactCorruption,
    ArtifactNotFound,
    StaleFence,
)
from autolean_control_plane.events import JsonObject

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
    freeze_real_lean_rebuild_execution_bundle,
)
from benchmarks.real_lean_project_dag_module_build import (
    MODULE_EVENT_ENTITY_TYPE,
    MODULE_EVENT_SCHEMA,
    OPERATOR_LOCAL_MODULE_EVIDENCE_CLASS,
    SYNTHETIC_MODULE_EVIDENCE_CLASS,
    CommittedLeanModuleBuildV1,
    FrozenLeanDeclarationQueryManifestV1,
    FrozenLeanModuleBuildReceiptV1,
    FrozenLeanModuleBuildRequestV1,
    LeanDeclarationQueryRecordV1,
    LeanModuleBuildError,
    LeanModuleBuildReceiptV1,
    LeanModuleBuildStore,
    LeanModuleImageBindingV1,
    LeanModuleRuntimeObservationV1,
    ModuleAction,
    OciPlatformV1,
    OperatorLocalModuleRunnerCapabilityV1,
    RawLeanModuleRunObservationV1,
    SyntheticLeanModuleRunner,
    freeze_expected_declaration_query,
    freeze_lean_module_build_spec,
    operator_local_module_runner_preflight,
    require_trusted_module_receipt_for_kernel_acceptance,
    verify_frozen_lean_module_build_receipt,
)
from benchmarks.real_lean_project_dag_rebuild import RealLeanRebuildBundleV1
from benchmarks.real_lean_project_dag_worker_contract import (
    FrozenChangedSourceWitnessV1,
    FrozenRealLeanImmutableWorkerInputV1,
    LeanWorkerEnvironmentV1,
    freeze_changed_source_witness,
    freeze_real_lean_immutable_worker_input,
    plan_real_lean_rebuild_from_witness,
)

_FOUNDATIONS = "AutoLean.ProjectDagPreflight.Foundations"
_ARITHMETIC = "AutoLean.ProjectDagPreflight.Arithmetic"
_IMAGE = f"ghcr.io/autolean/library-substrate@sha256:{'b' * 64}"
_CONFIG = f"sha256:{'d' * 64}"
_START = "2026-07-27T00:00:00Z"
_FINISH = "2026-07-27T00:00:00.125000Z"


@dataclass(frozen=True, slots=True)
class _Prepared:
    fixture: RealLeanProjectDagV1
    successor: RealLeanChangeCaseV1
    witness: FrozenChangedSourceWitnessV1
    plan: RealLeanRebuildBundleV1
    execution: FrozenRealLeanRebuildExecutionBundleV1
    worker: FrozenRealLeanImmutableWorkerInputV1
    artifacts: ArtifactStore
    image: LeanModuleImageBindingV1
    lake_manifest: ArtifactRef


@dataclass(slots=True)
class _FakeModuleRunner(SyntheticLeanModuleRunner):
    mode: str = "success"
    calls: int = 0

    @property
    def runner_identity(self) -> str:
        return "fake:t7-module-tests"

    def run(
        self,
        request: FrozenLeanModuleBuildRequestV1,
    ) -> RawLeanModuleRunObservationV1:
        self.calls += 1
        spec = request.frozen_spec.spec
        image = request.frozen_spec.image_binding
        platform = image.platform
        repo_digest = image.oci_repo_digest
        config_digest = image.oci_config_digest
        policy_sha256 = image.runner_policy_sha256
        query: bytes | None = request.frozen_spec.expected_query.manifest.canonical_bytes()
        output: bytes | None = f"fake olean:{spec.module}:{spec.source_tree_sha256}".encode()
        exit_code: int | None = 0
        timed_out = False
        if self.mode == "failure":
            output = None
            query = None
            exit_code = 1
        elif self.mode == "timeout":
            output = None
            query = None
            exit_code = None
            timed_out = True
        elif self.mode == "missing-output":
            output = None
        elif self.mode == "missing-query":
            query = None
        elif self.mode == "changed-type":
            manifest = request.frozen_spec.expected_query.manifest
            first = manifest.records[0]
            query = replace(
                manifest,
                records=(
                    replace(first, elaborated_type_sha256="e" * 64),
                    *manifest.records[1:],
                ),
            ).canonical_bytes()
        elif self.mode == "changed-axiom":
            manifest = request.frozen_spec.expected_query.manifest
            first = manifest.records[0]
            query = replace(
                manifest,
                records=(
                    replace(first, axioms=("Classical.choice",)),
                    *manifest.records[1:],
                ),
            ).canonical_bytes()
        elif self.mode == "wrong-image":
            repo_digest = f"ghcr.io/autolean/other@sha256:{'f' * 64}"
        elif self.mode == "wrong-platform":
            platform = OciPlatformV1(os="linux", architecture="arm64")
        elif self.mode == "wrong-policy":
            policy_sha256 = "f" * 64
        runtime = LeanModuleRuntimeObservationV1(
            runtime_kind="synthetic_injected",
            runtime_engine="fake",
            runtime_engine_version="1.0",
            oci_repo_digest=repo_digest,
            oci_config_digest=config_digest,
            platform=platform,
            runner_policy_sha256=policy_sha256,
            command_argv=spec.command_argv,
            working_directory=spec.working_directory,
            container_identity=None,
            network_mode="none",
            root_filesystem_read_only=True,
            started_at_utc=_START,
            finished_at_utc=_FINISH,
            duration_ms=125,
            exit_code=exit_code,
            timed_out=timed_out,
        )
        return RawLeanModuleRunObservationV1(
            runtime=runtime,
            stdout=f"fake stdout:{spec.module}".encode(),
            stderr=b"" if exit_code == 0 else b"fake failure",
            output_olean=output,
            declaration_query=query,
        )


def _prepare(tmp_path: Path, *, image: str = _IMAGE) -> _Prepared:
    fixture = load_default_real_lean_project_dag()
    successor = load_default_real_lean_change_case()
    artifacts = ArtifactStore(tmp_path / "artifacts")
    candidate_root = tmp_path / "candidate"
    for module in fixture.module_topological_order():
        destination = candidate_root.joinpath(*Path(module.file).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(successor.apply_to_module(module.module, successor=True))
    witness = freeze_changed_source_witness(
        fixture,
        successor,
        artifacts,
        source_snapshot_root=candidate_root,
    )
    plan = plan_real_lean_rebuild_from_witness(
        fixture,
        witness,
        artifacts,
    )
    baselines = {
        action.node_id: artifacts.put_bytes(f"synthetic-v1-baseline:{action.node_id}".encode())
        for action in plan.declaration_actions
        if action.action == "reuse"
    }
    execution = freeze_real_lean_rebuild_execution_bundle(
        fixture,
        plan,
        artifacts,
        reuse_baseline_artifacts=baselines,
    )
    policy = artifacts.put_bytes(b'{"schema_version":"test-policy.v1"}\n')
    verification = artifacts.put_bytes(b'{"schema_version":"synthetic-image-verification.v1"}\n')
    image_binding = LeanModuleImageBindingV1(
        oci_repo_digest=image,
        oci_config_digest=_CONFIG,
        platform=OciPlatformV1(os="linux", architecture="amd64"),
        runner_policy_image_path=("/opt/autolean/policies/t7-module-runner-policy.v1.json"),
        runner_policy_sha256=policy.digest,
        runner_policy_artifact=policy,
        image_verification_artifact=verification,
    )
    environment = LeanWorkerEnvironmentV1(
        lean_version="4.28.0",
        mathlib_revision="a" * 40,
        oci_repo_digest=image,
        runner_policy_sha256=policy.digest,
    )
    worker = freeze_real_lean_immutable_worker_input(
        fixture,
        witness,
        execution,
        environment,
        artifacts,
    )
    lake_manifest = artifacts.put_bytes(
        b'{"schema_version":"test-lake-manifest.v1","packages":[]}\n'
    )
    return _Prepared(
        fixture=fixture,
        successor=successor,
        witness=witness,
        plan=plan,
        execution=execution,
        worker=worker,
        artifacts=artifacts,
        image=image_binding,
        lake_manifest=lake_manifest,
    )


def _query(
    prepared: _Prepared,
    module: str,
    *,
    omit_last: bool = False,
) -> FrozenLeanDeclarationQueryManifestV1:
    declarations = tuple(
        item for item in prepared.fixture.declaration_topological_order() if item.module == module
    )
    if omit_last:
        declarations = declarations[:-1]
    return freeze_expected_declaration_query(
        prepared.fixture,
        module,
        tuple(
            LeanDeclarationQueryRecordV1(
                node_id=item.node_id,
                declaration=item.declaration,
                elaborated_type_sha256=hashlib.sha256(
                    f"locked-type:{item.declaration}".encode()
                ).hexdigest(),
                axioms=(),
            )
            for item in declarations
        ),
        prepared.artifacts,
    )


def _store(
    tmp_path: Path,
    artifacts: ArtifactStore,
    *,
    clock: Callable[[], datetime] | None = None,
) -> LeanModuleBuildStore:
    database = tmp_path / "control.db"
    return LeanModuleBuildStore(
        events=EventStore(database, clock=clock),
        leases=LeaseStore(database, clock=clock),
        artifacts=artifacts,
    )


def _request(
    prepared: _Prepared,
    store: LeanModuleBuildStore,
    module: str,
    *,
    action: ModuleAction = "build",
    dependencies: Sequence[CommittedLeanModuleBuildV1] = (),
    baseline: CommittedLeanModuleBuildV1 | None = None,
    lake_manifest: ArtifactRef | None = None,
    image: LeanModuleImageBindingV1 | None = None,
    worker_id: str = "worker-a",
) -> FrozenLeanModuleBuildRequestV1:
    frozen = freeze_lean_module_build_spec(
        prepared.worker,
        module=module,
        action=action,
        image_binding=image or prepared.image,
        lake_manifest_artifact=lake_manifest or prepared.lake_manifest,
        expected_query=_query(prepared, module),
        dependencies=tuple(dependencies),
        baseline=baseline,
        command_argv=(
            "/opt/autolean/bin/autolean-t7-build-module",
            "--module",
            module,
        ),
        working_directory="/workspace",
        output_olean_path=f"outputs/{module.replace('.', '/')}.olean",
        declaration_query_path="outputs/declaration-query.v1.json",
        artifacts=prepared.artifacts,
    )
    lease = store.claim(
        frozen,
        worker_id=worker_id,
        ttl_seconds=60.0,
    )
    return store.bind_request(
        frozen,
        lease=lease,
        worker_identity=f"test:{worker_id}",
    )


def _successful_foundations(
    prepared: _Prepared,
    store: LeanModuleBuildStore,
) -> CommittedLeanModuleBuildV1:
    request = _request(prepared, store, _FOUNDATIONS)
    result = store.execute_and_commit(
        request,
        runner=_FakeModuleRunner(),
        idempotency_key="build-foundations",
    )
    assert isinstance(result, CommittedLeanModuleBuildV1)
    return result


def test_module_receipt_and_complete_fanout_commit_atomically(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    store = _store(tmp_path, prepared.artifacts)
    foundations = _successful_foundations(prepared, store)
    request = _request(
        prepared,
        store,
        _ARITHMETIC,
        dependencies=(foundations,),
    )
    runner = _FakeModuleRunner()
    result = store.execute_and_commit(
        request,
        runner=runner,
        idempotency_key="build-arithmetic",
    )
    assert isinstance(result, CommittedLeanModuleBuildV1)
    assert runner.calls == 1
    assert len(result.fanout) == 5
    assert {item.record.node_id for item in result.fanout} == {
        "arithmetic.sum-seeds",
        "arithmetic.sum-is-seven",
        "arithmetic.triple-seed",
        "arithmetic.triple-is-six",
        "arithmetic.score",
    }
    assert all(
        item.record.module_receipt_artifact == result.receipt.artifact
        and item.record.output_olean_artifact == result.receipt.receipt.output_olean_artifact
        and item.record.promotion_eligible is False
        and "stdout" not in item.record.canonical_bytes().decode()
        for item in result.fanout
    )
    status = store.status(request)
    assert status.state == "MODULE_BUILD_SUCCEEDED_NONPROMOTABLE"
    assert status.evidence_class == SYNTHETIC_MODULE_EVIDENCE_CLASS
    assert status.promotion_eligible is False
    stream = store.events.read_stream(
        MODULE_EVENT_ENTITY_TYPE,
        request.frozen_spec.spec.content_sha256,
    )
    assert len(stream) == 6
    assert "VERIFIED" not in json.dumps(
        [event.payload for event in stream],
        sort_keys=True,
    )


def test_retry_returns_same_stream_without_rerunning_module(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    store = _store(tmp_path, prepared.artifacts)
    request = _request(prepared, store, _FOUNDATIONS)
    runner = _FakeModuleRunner()
    first = store.execute_and_commit(
        request,
        runner=runner,
        idempotency_key="once",
    )
    second = store.execute_and_commit(
        request,
        runner=runner,
        idempotency_key="different-key",
    )
    assert runner.calls == 1
    assert first == second


def test_public_receipt_verifier_never_grants_kernel_acceptance(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    store = _store(tmp_path, prepared.artifacts)
    request = _request(prepared, store, _FOUNDATIONS)
    result = store.execute_and_commit(
        request,
        runner=_FakeModuleRunner(),
        idempotency_key="public-verifier",
    )
    assert isinstance(result, CommittedLeanModuleBuildV1)
    verify_frozen_lean_module_build_receipt(
        result.receipt,
        prepared.artifacts,
    )
    assert result.receipt.receipt.kernel_acceptance_eligible is False
    assert all(item.record.kernel_acceptance_eligible is False for item in result.fanout)
    with pytest.raises(
        LeanModuleBuildError,
        match="not kernel acceptance",
    ):
        require_trusted_module_receipt_for_kernel_acceptance(
            result.receipt,
            prepared.artifacts,
        )


def test_request_and_public_verifier_reject_lease_for_unrelated_spec_job(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    store = _store(tmp_path, prepared.artifacts)
    request = _request(prepared, store, _FOUNDATIONS)
    result = store.execute_and_commit(
        request,
        runner=_FakeModuleRunner(),
        idempotency_key="job-binding",
    )
    assert isinstance(result, CommittedLeanModuleBuildV1)

    unrelated_job = "attacker-unrelated-job"
    forged_lease = replace(request.lease, job_id=unrelated_job)
    forged_request_document = replace(
        request.request,
        lease_job_id=unrelated_job,
    )
    forged_request_artifact = prepared.artifacts.put_bytes(
        forged_request_document.canonical_bytes()
    )
    with pytest.raises(
        LeanModuleBuildError,
        match="frozen module request binding",
    ):
        FrozenLeanModuleBuildRequestV1(
            request=forged_request_document,
            artifact=forged_request_artifact,
            frozen_spec=request.frozen_spec,
            lease=forged_lease,
        )

    # Bypass the constructor to prove the public verifier repeats this authority
    # binding instead of relying on an in-process dataclass invariant.
    forged_request = object.__new__(FrozenLeanModuleBuildRequestV1)
    object.__setattr__(forged_request, "request", forged_request_document)
    object.__setattr__(forged_request, "artifact", forged_request_artifact)
    object.__setattr__(forged_request, "frozen_spec", request.frozen_spec)
    object.__setattr__(forged_request, "lease", forged_lease)
    forged_receipt_document = replace(
        result.receipt.receipt,
        request_sha256=forged_request_document.content_sha256,
        request_artifact=forged_request_artifact,
    )
    forged_receipt_artifact = prepared.artifacts.put_bytes(
        forged_receipt_document.canonical_bytes()
    )
    forged_receipt = FrozenLeanModuleBuildReceiptV1(
        receipt=forged_receipt_document,
        artifact=forged_receipt_artifact,
        request=forged_request,
        runtime=result.receipt.runtime,
    )
    with pytest.raises(
        LeanModuleBuildError,
        match="module receipt artifact binding changed",
    ):
        verify_frozen_lean_module_build_receipt(
            forged_receipt,
            prepared.artifacts,
        )


@pytest.mark.parametrize("mode", ["failure", "timeout"])
def test_failed_process_has_receipt_but_no_fanout(
    tmp_path: Path,
    mode: str,
) -> None:
    prepared = _prepare(tmp_path)
    store = _store(tmp_path, prepared.artifacts)
    request = _request(prepared, store, _FOUNDATIONS)
    receipt = store.execute_and_commit(
        request,
        runner=_FakeModuleRunner(mode=mode),
        idempotency_key=f"failed-{mode}",
    )
    assert isinstance(receipt, FrozenLeanModuleBuildReceiptV1)
    assert receipt.receipt.promotion_eligible is False
    assert receipt.receipt.output_olean_artifact is None
    assert store.status(request).state == "MODULE_BUILD_FAILED_NONPROMOTABLE"
    assert (
        len(
            store.events.read_stream(
                MODULE_EVENT_ENTITY_TYPE,
                request.frozen_spec.spec.content_sha256,
            )
        )
        == 1
    )


@pytest.mark.parametrize(
    "mode",
    [
        "missing-output",
        "missing-query",
        "changed-type",
        "changed-axiom",
        "wrong-image",
        "wrong-platform",
        "wrong-policy",
    ],
)
def test_runner_substitution_attacks_fail_before_event(
    tmp_path: Path,
    mode: str,
) -> None:
    prepared = _prepare(tmp_path)
    store = _store(tmp_path, prepared.artifacts)
    request = _request(prepared, store, _FOUNDATIONS)
    with pytest.raises(LeanModuleBuildError):
        store.execute_and_commit(
            request,
            runner=_FakeModuleRunner(mode=mode),
            idempotency_key=f"attack-{mode}",
        )
    assert store.status(request).state == "MODULE_PENDING"


def test_query_manifest_requires_every_locked_declaration(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    with pytest.raises(
        LeanModuleBuildError,
        match="does not cover the exact fixture module",
    ):
        _query(prepared, _FOUNDATIONS, omit_last=True)


def test_direct_import_requires_matching_durable_module_receipt(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    store = _store(tmp_path, prepared.artifacts)
    with pytest.raises(
        LeanModuleBuildError,
        match="dependencies must cover direct imports",
    ):
        _request(prepared, store, _ARITHMETIC)


def test_dependency_lake_manifest_drift_is_rejected(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    store = _store(tmp_path, prepared.artifacts)
    foundations = _successful_foundations(prepared, store)
    changed_lake = prepared.artifacts.put_bytes(
        b'{"schema_version":"test-lake-manifest.v1","packages":["drift"]}\n'
    )
    with pytest.raises(
        LeanModuleBuildError,
        match="source or environment drift",
    ):
        _request(
            prepared,
            store,
            _ARITHMETIC,
            dependencies=(foundations,),
            lake_manifest=changed_lake,
        )


def test_reuse_requires_and_projects_earlier_same_receipt(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    store = _store(tmp_path, prepared.artifacts)
    baseline = _successful_foundations(prepared, store)
    request = _request(
        prepared,
        store,
        _FOUNDATIONS,
        action="reuse",
        baseline=baseline,
        worker_id="worker-reuse",
    )
    reused = store.commit_reuse(
        request,
        idempotency_key="reuse-foundations",
    )
    assert reused.receipt.artifact == baseline.receipt.artifact
    assert all(
        item.record.current_request_artifact == request.artifact
        and item.record.module_receipt_artifact == reused.receipt.artifact
        for item in reused.fanout
    )
    status = store.status(request)
    assert status.state == "MODULE_REUSED_NONPROMOTABLE"
    assert status.promotion_eligible is False


def test_wrong_module_receipt_cannot_be_reused_as_baseline(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    store = _store(tmp_path, prepared.artifacts)
    foundations = _successful_foundations(prepared, store)
    arithmetic_request = _request(
        prepared,
        store,
        _ARITHMETIC,
        dependencies=(foundations,),
    )
    arithmetic = store.execute_and_commit(
        arithmetic_request,
        runner=_FakeModuleRunner(),
        idempotency_key="arithmetic-baseline",
    )
    assert isinstance(arithmetic, CommittedLeanModuleBuildV1)
    with pytest.raises(
        LeanModuleBuildError,
        match="same source and environment",
    ):
        _request(
            prepared,
            store,
            _FOUNDATIONS,
            action="reuse",
            baseline=arithmetic,
            worker_id="wrong-baseline",
        )


def test_deleted_or_corrupt_output_and_query_invalidate_status(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    store = _store(tmp_path, prepared.artifacts)
    request = _request(prepared, store, _FOUNDATIONS)
    result = store.execute_and_commit(
        request,
        runner=_FakeModuleRunner(),
        idempotency_key="delete-output",
    )
    assert isinstance(result, CommittedLeanModuleBuildV1)
    output = result.receipt.receipt.output_olean_artifact
    assert output is not None
    prepared.artifacts.path_for(output).unlink()
    with pytest.raises(ArtifactNotFound):
        store.status(request)

    other = _prepare(tmp_path / "query-corruption")
    other_store = _store(tmp_path / "query-corruption", other.artifacts)
    other_request = _request(other, other_store, _FOUNDATIONS)
    other_result = other_store.execute_and_commit(
        other_request,
        runner=_FakeModuleRunner(),
        idempotency_key="corrupt-query",
    )
    assert isinstance(other_result, CommittedLeanModuleBuildV1)
    query = other_result.receipt.receipt.declaration_query_artifact
    assert query is not None
    other.artifacts.path_for(query).write_bytes(b"substituted")
    with pytest.raises(ArtifactCorruption):
        other_store.status(other_request)


def test_fake_receipt_can_never_be_promoted() -> None:
    reference = ArtifactRef(digest="a" * 64, size=1)
    with pytest.raises(LeanModuleBuildError):
        LeanModuleBuildReceiptV1(
            request_sha256="a" * 64,
            request_artifact=reference,
            spec_sha256="b" * 64,
            module=_FOUNDATIONS,
            runtime_observation_sha256="c" * 64,
            runtime_observation_artifact=ArtifactRef(
                digest="c" * 64,
                size=1,
            ),
            stdout_artifact=reference,
            stderr_artifact=reference,
            output_olean_artifact=reference,
            declaration_query_artifact=reference,
            outcome="PROCESS_SUCCEEDED",
            evidence_class="synthetic_fake_module_v1",
            runner_identity="fake:attack",
            gateway_attestation_class="none",
            gateway_attestation_artifact=None,
            promotion_eligible=True,
        )
    with pytest.raises(LeanModuleBuildError):
        LeanModuleBuildReceiptV1(
            request_sha256="a" * 64,
            request_artifact=reference,
            spec_sha256="b" * 64,
            module=_FOUNDATIONS,
            runtime_observation_sha256="c" * 64,
            runtime_observation_artifact=ArtifactRef(
                digest="c" * 64,
                size=1,
            ),
            stdout_artifact=reference,
            stderr_artifact=reference,
            output_olean_artifact=reference,
            declaration_query_artifact=reference,
            outcome="PROCESS_SUCCEEDED",
            evidence_class="synthetic_fake_module_v1",
            runner_identity="fake:attack",
            gateway_attestation_class="none",
            gateway_attestation_artifact=None,
            kernel_acceptance_eligible=True,
        )


def test_stale_fence_cannot_create_module_stream(tmp_path: Path) -> None:
    now = datetime(2026, 7, 27, tzinfo=UTC)

    def clock() -> datetime:
        return now

    prepared = _prepare(tmp_path)
    store = _store(tmp_path, prepared.artifacts, clock=clock)
    old = _request(prepared, store, _FOUNDATIONS, worker_id="old")
    now += timedelta(seconds=61)
    replacement_lease = store.claim(
        old.frozen_spec,
        worker_id="new",
        ttl_seconds=60,
    )
    assert replacement_lease.fencing_token > old.lease.fencing_token
    with pytest.raises(StaleFence):
        store.execute_and_commit(
            old,
            runner=_FakeModuleRunner(),
            idempotency_key="stale",
        )
    assert not store.events.read_stream(
        MODULE_EVENT_ENTITY_TYPE,
        old.frozen_spec.spec.content_sha256,
    )


def test_forged_or_partial_terminal_stream_is_rejected(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    store = _store(tmp_path, prepared.artifacts)
    request = _request(prepared, store, _FOUNDATIONS)
    observation = _FakeModuleRunner().run(request)
    receipt = store._freeze_observation(
        request,
        observation,
        evidence_class="synthetic_fake_module_v1",
        required_runtime_kind="synthetic_injected",
        runner_identity="fake:forged-stream",
    )
    payload: JsonObject = {
        "schema_version": MODULE_EVENT_SCHEMA,
        "bundle_id": request.lease.job_id,
        "request_sha256": request.request.content_sha256,
        "request_artifact": {
            "algorithm": request.artifact.algorithm,
            "digest": request.artifact.digest,
            "size": request.artifact.size,
        },
        "spec_sha256": request.frozen_spec.spec.content_sha256,
        "module": _FOUNDATIONS,
        "action": "build",
        "outcome": "PROCESS_SUCCEEDED",
        "receipt_sha256": receipt.receipt.content_sha256,
        "receipt_artifact": {
            "algorithm": receipt.artifact.algorithm,
            "digest": receipt.artifact.digest,
            "size": receipt.artifact.size,
        },
        "evidence_class": SYNTHETIC_MODULE_EVIDENCE_CLASS,
        "promotion_eligible": False,
        "kernel_acceptance_eligible": False,
        "fanout_count": 5,
        "lease_holder_id": request.lease.holder_id,
        "fencing_token": request.lease.fencing_token,
    }
    store.events.append_fenced(
        MODULE_EVENT_ENTITY_TYPE,
        request.frozen_spec.spec.content_sha256,
        task_id=request.lease.job_id,
        lease=request.lease,
        expected_sequence=0,
        events=(
            NewEvent(
                "t7_module.build_succeeded_nonpromotable",
                payload=payload,
            ),
        ),
        idempotency=Idempotency(
            scope="partial-attack",
            key="partial",
            request_hash=request_hash(payload),
        ),
    )
    with pytest.raises(
        LeanModuleBuildError,
        match="partial fanout",
    ):
        store.status(request)


def test_operator_capability_cannot_be_self_asserted(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    with pytest.raises(
        LeanModuleBuildError,
        match="capability is invalid",
    ):
        OperatorLocalModuleRunnerCapabilityV1(
            image_binding=prepared.image,
            preflight_artifact=prepared.artifacts.put_bytes(b"forged"),
            runtime_engine_version="28.0",
            runner_identity="operator:forged",
            _preflight_marker=object(),
        )


def test_operator_preflight_reuses_t6_and_stays_nonpromotable(
    tmp_path: Path,
) -> None:
    artifacts = ArtifactStore(tmp_path / "preflight-artifacts")
    calls: list[tuple[str, ...]] = []
    verification = {
        "schema_version": ("autolean.library-substrate-image-verification.v1"),
        "image": _IMAGE,
        "image_id": _CONFIG,
    }
    outputs = iter(
        (
            json.dumps(verification, sort_keys=True).encode(),
            b'"linux" "amd64" ""\n',
            b'"28.3.3"\n',
            b'{"schema_version":"t7-runner-policy.v1"}\n',
        )
    )

    def run(
        argv: Sequence[str],
        timeout_seconds: float,
    ) -> subprocess.CompletedProcess[bytes]:
        del timeout_seconds
        calls.append(tuple(argv))
        return subprocess.CompletedProcess(
            tuple(argv),
            0,
            stdout=next(outputs),
            stderr=b"",
        )

    capability = operator_local_module_runner_preflight(
        oci_repo_digest=_IMAGE,
        runner_policy_image_path=("/opt/autolean/policies/t7-module-runner-policy.v1.json"),
        artifacts=artifacts,
        runner_identity="operator:local-preflight",
        run_command=run,
    )
    assert calls
    assert calls[0][-3:] == ("verify", "--image", _IMAGE)
    assert capability.capability_class == (OPERATOR_LOCAL_MODULE_EVIDENCE_CLASS)
    assert capability.promotion_eligible is False
    assert capability.image_binding.oci_config_digest == _CONFIG
    assert capability.image_binding.platform.architecture == "amd64"
    assert (
        artifacts.get_bytes(capability.image_binding.runner_policy_artifact)
        == b'{"schema_version":"t7-runner-policy.v1"}\n'
    )


def test_operator_preflight_fails_before_t6_for_mutable_tag(
    tmp_path: Path,
) -> None:
    calls = 0

    def run(
        argv: Sequence[str],
        timeout_seconds: float,
    ) -> subprocess.CompletedProcess[bytes]:
        del argv, timeout_seconds
        nonlocal calls
        calls += 1
        raise AssertionError("preflight must reject before command execution")

    with pytest.raises(LeanModuleBuildError, match="input is invalid"):
        operator_local_module_runner_preflight(
            oci_repo_digest="ghcr.io/autolean/library-substrate:latest",
            runner_policy_image_path="/opt/autolean/policy.json",
            artifacts=ArtifactStore(tmp_path / "artifacts"),
            runner_identity="operator:local",
            run_command=run,
        )
    assert calls == 0
