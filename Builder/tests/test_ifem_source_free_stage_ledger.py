"""Crash/recovery checks for the private source-free 27-stage journal."""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Callable
from pathlib import Path

import pytest
from autolean_builder import ifem_next_calibration_case_intents as intents_module
from autolean_builder import ifem_source_free_private_seed as private_seed
from autolean_builder import ifem_source_free_stage_ledger as stage_ledger
from autolean_contracts import (
    HashKindV1,
    ModelWorkRoleV1,
    canonical_json_bytes,
    digest_model,
    stable_identifier,
)

ROOT = Path(__file__).resolve().parents[2]
ROLE_ORDER = (
    ModelWorkRoleV1.STATEMENT_FORMALIZER,
    ModelWorkRoleV1.FIDELITY_REVIEWER,
    ModelWorkRoleV1.CHEATING_SUPERVISOR,
)


class SimulatedProcessCrash(BaseException):
    pass


def _manifest() -> private_seed.PrivateSourceFreeSeedManifestV2:
    return private_seed.build_test_private_seed_manifest(_queue(), run_nonce=b"l" * 32)


def _queue() -> intents_module.IFEMNextCalibrationCaseIntentsV1:
    return intents_module.build_ifem_next_calibration_case_intents_from_paths()


def _seed_store(tmp_path: Path) -> private_seed.LocalSourceFreePrivateSeedStore:
    store = private_seed.LocalSourceFreePrivateSeedStore(
        (tmp_path / "operator-private-seed").resolve(),
        repository_root=ROOT,
        run_label="stage-ledger-seed",
    )
    store.commit_for_queue(_queue(), test_entropy=lambda size: b"l" * size)
    return store


def _binding(
    coordinate: stage_ledger.SourceFreeStageCoordinateV1,
) -> stage_ledger.SourceFreeStageCompletionBindingV1:
    coordinate_hash = coordinate.coordinate_sha256
    payload: dict[str, object] = {
        "schema_version": "autolean.ifem-source-free-stage-completion-binding.v1",
        "coordinate_sha256": coordinate_hash,
        "model_work_bundle_id": stable_identifier(
            "model-work-bundle",
            f"test:{coordinate_hash}",
        ).model_dump(mode="json"),
        "model_work_bundle_hash": digest_model(
            HashKindV1.BUNDLE,
            {"test_coordinate_sha256": coordinate_hash},
        ).model_dump(mode="json"),
        "completion_id": stable_identifier(
            "model-execution-completion",
            f"test:{coordinate_hash}",
        ).model_dump(mode="json"),
        "completion_receipt_hash": digest_model(
            HashKindV1.MODEL_EXECUTION_COMPLETION,
            {"test_coordinate_sha256": coordinate_hash},
        ).model_dump(mode="json"),
        "public_output_commitment": digest_model(
            HashKindV1.MODEL_OUTPUT_COMMITMENT,
            {"test_coordinate_sha256": coordinate_hash},
        ).model_dump(mode="json"),
    }
    payload["binding_content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return stage_ledger.SourceFreeStageCompletionBindingV1.model_validate(payload)


class CountingExecutor:
    def __init__(self, *, fail: bool = False) -> None:
        self.calls = 0
        self.fail = fail
        self.bindings: dict[str, stage_ledger.SourceFreeStageCompletionBindingV1] = {}

    def __call__(
        self,
        coordinate: stage_ledger.SourceFreeStageCoordinateV1,
        item: private_seed.PrivateSourceFreeSeedItemV2,
    ) -> stage_ledger.SourceFreeStageCompletionBindingV1:
        self.calls += 1
        assert item.case_id == coordinate.case_id
        if self.fail:
            raise RuntimeError("provider outcome deliberately unknown")
        binding = _binding(coordinate)
        self.bindings[coordinate.coordinate_sha256] = binding
        return binding


class DeterministicTestBindingVerifier:
    """Test-only stand-in for the future operator-private receipt resolver."""

    def __init__(self) -> None:
        self.calls = 0

    def verify_binding(
        self,
        coordinate: stage_ledger.SourceFreeStageCoordinateV1,
        binding: stage_ledger.SourceFreeStageCompletionBindingV1,
    ) -> None:
        self.calls += 1
        if binding != _binding(coordinate):
            raise RuntimeError("test binding does not resolve to its expected completion")


def _ledger(
    tmp_path: Path,
    *,
    seed_store: private_seed.LocalSourceFreePrivateSeedStore | None = None,
    verifier: DeterministicTestBindingVerifier | None = None,
) -> stage_ledger.LocalSourceFreeStageLedger:
    return stage_ledger.LocalSourceFreeStageLedger(
        (tmp_path / "operator-private-stage-ledger").resolve(),
        repository_root=ROOT,
        seed_store=seed_store or _seed_store(tmp_path),
        intent_queue=_queue(),
        completion_binding_verifier=verifier or DeterministicTestBindingVerifier(),
    )


def test_run_is_exactly_nine_cases_by_three_roles_in_fixed_order(tmp_path: Path) -> None:
    manifest = _manifest()
    ledger = _ledger(tmp_path)

    assert len(ledger.run.coordinates) == 27
    assert tuple(item.ordinal for item in ledger.run.coordinates) == tuple(range(1, 28))
    actual = tuple((item.case_id, item.role) for item in ledger.run.coordinates)
    expected = tuple((item.case_id, role) for item in manifest.items for role in ROLE_ORDER)
    assert actual == expected
    assert Counter(item.role for item in ledger.run.coordinates) == {
        ModelWorkRoleV1.STATEMENT_FORMALIZER: 9,
        ModelWorkRoleV1.FIDELITY_REVIEWER: 9,
        ModelWorkRoleV1.CHEATING_SUPERVISOR: 9,
    }

    projection = ledger.public_projection()
    assert projection.pending_count == 27
    assert projection.executor_dispatch_count == 0
    assert projection.complete is False


def test_complete_run_dispatches_exactly_27_once_and_resume_is_noop(tmp_path: Path) -> None:
    verifier = DeterministicTestBindingVerifier()
    ledger = _ledger(tmp_path, verifier=verifier)
    executor = CountingExecutor()

    first = ledger.resume(executor)
    first_calls = executor.calls
    second = ledger.resume(executor)

    assert first_calls == 27
    assert executor.calls == 27
    assert first == second
    assert first.complete is True
    assert first.completion_committed_count == 27
    assert first.reconciliation_required_count == 0
    assert first.executor_dispatch_count == 27
    assert first.immutable_event_count == 81
    assert verifier.calls == 27


@pytest.mark.parametrize(
    ("crash_point", "calls_after_crash", "calls_after_resume", "complete_after_resume"),
    (
        ("claim_committed", 0, 27, True),
        ("dispatch_committed", 0, 24, False),
        ("executor_returned", 1, 25, False),
        ("completion_committed", 1, 27, True),
    ),
)
def test_every_durable_crash_point_recovers_without_dispatch_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    crash_point: str,
    calls_after_crash: int,
    calls_after_resume: int,
    complete_after_resume: bool,
) -> None:
    ledger = _ledger(tmp_path)
    executor = CountingExecutor()
    first_coordinate = ledger.run.coordinates[0]
    armed = True

    def crash_once(
        name: str,
        coordinate: stage_ledger.SourceFreeStageCoordinateV1,
    ) -> None:
        nonlocal armed
        if armed and name == crash_point and coordinate == first_coordinate:
            armed = False
            raise SimulatedProcessCrash(crash_point)

    monkeypatch.setattr(ledger, "_checkpoint", crash_once)
    with pytest.raises(SimulatedProcessCrash, match=crash_point):
        ledger.resume(executor)
    assert executor.calls == calls_after_crash

    monkeypatch.setattr(ledger, "_checkpoint", lambda _name, _coordinate: None)
    resumed = ledger.resume(executor)
    calls_before_repeat = executor.calls
    repeated = ledger.resume(executor)

    assert executor.calls == calls_after_resume
    assert calls_before_repeat == executor.calls
    assert executor.calls <= 27
    assert resumed == repeated
    assert resumed.complete is complete_after_resume

    if crash_point == "dispatch_committed":
        assert resumed.dispatch_started_count == 1
        assert resumed.reconciliation_required_count == 0
        assert resumed.pending_count == 2
        reconciled = ledger.mark_interrupted_dispatches_for_reconciliation(
            operator_confirmed_quiescent=True
        )
        assert ledger.state_for(first_coordinate) is (
            stage_ledger.SourceFreeStageLedgerStateV1.RECONCILIATION_REQUIRED
        )
        assert reconciled.reconciliation_required_count == 1
        assert executor.calls == 24
    elif crash_point == "executor_returned":
        assert resumed.dispatch_started_count == 1
        assert resumed.reconciliation_required_count == 0
        ledger.mark_interrupted_dispatches_for_reconciliation(operator_confirmed_quiescent=True)
        recovered = executor.bindings[first_coordinate.coordinate_sha256]
        reconciled = ledger.reconcile_completion(first_coordinate, recovered)
        assert reconciled.complete is False
        assert reconciled.completion_committed_count == 25
        assert executor.calls == 25
        completed = ledger.resume(executor)
        assert completed.complete is True
        assert completed.completion_committed_count == 27
        assert executor.calls == 27
        assert ledger.resume(executor) == completed
        assert executor.calls == 27


def test_executor_exception_is_persisted_and_never_retried(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    executor = CountingExecutor(fail=True)

    failed = ledger.resume(executor)
    repeated = ledger.resume(executor)

    assert executor.calls == 9
    assert failed == repeated
    assert failed.pending_count == 18
    assert failed.reconciliation_required_count == 9
    assert failed.completion_committed_count == 0
    assert failed.executor_dispatch_count == 9
    assert failed.complete is False


def test_downstream_roles_wait_for_their_case_predecessor(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    first_case = ledger.run.coordinates[0].case_id
    calls: list[tuple[object, ModelWorkRoleV1]] = []

    def executor(
        coordinate: stage_ledger.SourceFreeStageCoordinateV1,
        _item: private_seed.PrivateSourceFreeSeedItemV2,
    ) -> stage_ledger.SourceFreeStageCompletionBindingV1:
        calls.append((coordinate.case_id, coordinate.role))
        if (
            coordinate.case_id == first_case
            and coordinate.role is ModelWorkRoleV1.STATEMENT_FORMALIZER
        ):
            raise RuntimeError("first formalizer outcome is unknown")
        return _binding(coordinate)

    projection = ledger.resume(executor)

    assert len(calls) == 25
    assert projection.executor_dispatch_count == 25
    assert projection.completion_committed_count == 24
    assert projection.reconciliation_required_count == 1
    assert projection.pending_count == 2
    assert not any(
        case_id == first_case and role is not ModelWorkRoleV1.STATEMENT_FORMALIZER
        for case_id, role in calls
    )
    assert ledger.resume(executor) == projection
    assert len(calls) == 25


def test_explicit_reconciliation_commits_reference_without_executor_call(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    executor = CountingExecutor()
    first_coordinate = ledger.run.coordinates[0]

    def crash_after_executor(
        name: str,
        coordinate: stage_ledger.SourceFreeStageCoordinateV1,
    ) -> None:
        if name == "executor_returned" and coordinate == first_coordinate:
            raise SimulatedProcessCrash("lost ledger commit")

    ledger._checkpoint = crash_after_executor  # type: ignore[method-assign]
    with pytest.raises(SimulatedProcessCrash):
        ledger.resume(executor)
    assert executor.calls == 1
    recovered = executor.bindings[first_coordinate.coordinate_sha256]

    projection = ledger.reconcile_completion(first_coordinate, recovered)
    assert projection.completion_committed_count == 1
    assert executor.calls == 1

    ledger._checkpoint = lambda _name, _coordinate: None  # type: ignore[method-assign]
    completed = ledger.resume(executor)
    assert completed.complete is True
    assert executor.calls == 27
    assert ledger.reconcile_completion(first_coordinate, recovered) == completed
    assert executor.calls == 27


def test_completion_for_another_coordinate_is_rejected(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    executor = CountingExecutor()
    first, second = ledger.run.coordinates[:2]

    def crash_after_dispatch(
        name: str,
        coordinate: stage_ledger.SourceFreeStageCoordinateV1,
    ) -> None:
        if name == "dispatch_committed" and coordinate == first:
            raise SimulatedProcessCrash("dispatch boundary")

    ledger._checkpoint = crash_after_dispatch  # type: ignore[method-assign]
    with pytest.raises(SimulatedProcessCrash):
        ledger.resume(executor)

    with pytest.raises(stage_ledger.SourceFreeStageLedgerError, match="different coordinate"):
        ledger.reconcile_completion(first, _binding(second))
    assert executor.calls == 0


def test_public_projection_is_aggregate_only_and_withholds_authority(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    projection = ledger.resume(CountingExecutor())
    rendered = stage_ledger.render_stage_ledger_public_projection(projection)

    for forbidden in (
        b'"case_id"',
        b'"coordinate"',
        b'"role"',
        b'"run_id"',
        b'"completion_id"',
        b'"model_work_bundle_id"',
    ):
        assert forbidden not in rendered
    assert projection.case_ids_disclosed is False
    assert projection.role_coordinates_disclosed is False
    assert projection.completion_ids_disclosed is False
    assert projection.raw_model_output_retained is False
    assert projection.automatic_dispatch_replay_allowed is False
    assert projection.provider_dispatch_performed_by_ledger is False
    assert projection.completion_verification_attested is False
    assert projection.live_model_eligible is False
    assert projection.heldout_worker_isolation_claimed is False
    assert projection.authority.freeze_allowed is False
    assert projection.authority.prover_handoff_allowed is False
    with pytest.raises(stage_ledger.SourceFreeStageLedgerError, match="cannot classify"):
        projection.freeze_statement()
    with pytest.raises(stage_ledger.SourceFreeStageLedgerError, match="cannot classify"):
        projection.handoff_to_prover()


def test_private_journal_stores_no_raw_model_output(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    secret = b"SECRET_RAW_MODEL_OUTPUT_MUST_NOT_BE_STORED"

    def executor(
        coordinate: stage_ledger.SourceFreeStageCoordinateV1,
        _item: private_seed.PrivateSourceFreeSeedItemV2,
    ) -> stage_ledger.SourceFreeStageCompletionBindingV1:
        # The journal API has no response-text field; this local value models data retained by the
        # existing operator-private ModelWork completion store, not by this stage ledger.
        assert secret
        return _binding(coordinate)

    ledger.resume(executor)
    retained = b"".join(path.read_bytes() for path in ledger.run_root.rglob("*.json"))
    assert secret not in retained
    assert b'"text"' not in retained
    assert b'"tool_calls"' not in retained
    assert b'"private_output"' not in retained


def test_store_rejects_relative_checkout_internal_and_linked_roots(tmp_path: Path) -> None:
    seed_store = _seed_store(tmp_path)
    for root in (Path("relative-ledger"), ROOT / ".cache" / "private-stage-ledger"):
        with pytest.raises(stage_ledger.SourceFreeStageLedgerError):
            stage_ledger.LocalSourceFreeStageLedger(
                root,
                repository_root=ROOT,
                seed_store=seed_store,
                intent_queue=_queue(),
                completion_binding_verifier=DeterministicTestBindingVerifier(),
            )

    physical = tmp_path / "physical"
    physical.mkdir()
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(physical, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlink creation is unavailable: {error}")
    with pytest.raises(stage_ledger.SourceFreeStageLedgerError, match=r"symlink|reparse"):
        stage_ledger.LocalSourceFreeStageLedger(
            linked.absolute(),
            repository_root=ROOT,
            seed_store=seed_store,
            intent_queue=_queue(),
            completion_binding_verifier=DeterministicTestBindingVerifier(),
        )


def test_rehashed_run_tampering_is_rejected(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    executor = CountingExecutor()
    ledger.resume(executor)

    run_payload = ledger.run.model_dump(mode="json")
    run_payload["case_count"] = 9
    coordinates = run_payload["coordinates"]
    assert isinstance(coordinates, list)
    first = coordinates[0]
    assert isinstance(first, dict)
    first["ordinal"] = 2
    first.pop("coordinate_sha256")
    first["coordinate_sha256"] = hashlib.sha256(canonical_json_bytes(first)).hexdigest()
    run_payload.pop("run_content_sha256")
    run_payload["run_content_sha256"] = hashlib.sha256(
        canonical_json_bytes(run_payload)
    ).hexdigest()
    run_path = ledger.run_root / "run.json"
    run_path.write_bytes(canonical_json_bytes(run_payload) + b"\n")

    with pytest.raises(stage_ledger.SourceFreeStageReconciliationRequired):
        ledger.public_projection()


def test_corrupted_event_bytes_are_rejected(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    ledger.resume(CountingExecutor())
    coordinate = ledger.run.coordinates[0]
    event_path = ledger._event_path(  # type: ignore[attr-defined]
        coordinate,
        stage_ledger.SourceFreeStageLedgerStateV1.COMPLETION_COMMITTED,
    )
    event_path.write_bytes(b'{"truncated":')

    with pytest.raises(stage_ledger.SourceFreeStageReconciliationRequired):
        ledger.public_projection()


def test_completion_binding_rejects_wrong_digest_kind_and_rehashed_conflict(
    tmp_path: Path,
) -> None:
    ledger = _ledger(tmp_path)
    coordinate = ledger.run.coordinates[0]
    binding = _binding(coordinate)
    payload = binding.model_dump(mode="json")
    payload["model_work_bundle_hash"] = digest_model(
        HashKindV1.CONTRACT,
        {"wrong": "kind"},
    ).model_dump(mode="json")
    payload.pop("binding_content_sha256")
    payload["binding_content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    with pytest.raises(ValueError, match="model_work_bundle_hash"):
        stage_ledger.SourceFreeStageCompletionBindingV1.model_validate(payload)

    executor = CountingExecutor()

    def crash_after_executor(
        name: str,
        stage: stage_ledger.SourceFreeStageCoordinateV1,
    ) -> None:
        if name == "executor_returned" and stage == coordinate:
            raise SimulatedProcessCrash("terminal lost")

    ledger._checkpoint = crash_after_executor  # type: ignore[method-assign]
    with pytest.raises(SimulatedProcessCrash):
        ledger.resume(executor)
    retained = executor.bindings[coordinate.coordinate_sha256]
    ledger.reconcile_completion(coordinate, retained)

    conflicting_payload = retained.model_dump(mode="json")
    conflicting_payload["completion_id"] = stable_identifier(
        "model-execution-completion",
        "conflict",
    ).model_dump(mode="json")
    conflicting_payload.pop("binding_content_sha256")
    conflicting_payload["binding_content_sha256"] = hashlib.sha256(
        canonical_json_bytes(conflicting_payload)
    ).hexdigest()
    conflicting = stage_ledger.SourceFreeStageCompletionBindingV1.model_validate(
        conflicting_payload
    )
    with pytest.raises(stage_ledger.SourceFreeStageLedgerError, match="operator-private"):
        ledger.reconcile_completion(coordinate, conflicting)


def test_two_resumers_still_allow_at_most_one_executor_call_per_coordinate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _ledger(tmp_path)
    second = _ledger(tmp_path)
    executor = CountingExecutor()
    coordinate = first.run.coordinates[0]

    # Simulate another process winning the immutable dispatch event between this process's claim
    # and dispatch CAS.  The losing process must not invoke its executor.
    original_append = first._append_event
    injected = False

    def racing_append(  # type: ignore[no-untyped-def]
        stage,
        *,
        state,
        completion=None,
        reconciliation_reason=None,
        require_new=False,
    ):
        nonlocal injected
        if (
            not injected
            and stage == coordinate
            and state is stage_ledger.SourceFreeStageLedgerStateV1.DISPATCH_STARTED
        ):
            injected = True
            second._append_event(
                stage,
                state=stage_ledger.SourceFreeStageLedgerStateV1.CLAIMED,
            )
            second._append_event(
                stage,
                state=stage_ledger.SourceFreeStageLedgerStateV1.DISPATCH_STARTED,
                require_new=True,
            )
        return original_append(
            stage,
            state=state,
            completion=completion,
            reconciliation_reason=reconciliation_reason,
            require_new=require_new,
        )

    monkeypatch.setattr(first, "_append_event", racing_append)
    projection = first.resume(executor)

    assert executor.calls == 24
    assert projection.executor_dispatch_count == 25
    assert projection.dispatch_started_count == 1
    assert projection.completion_committed_count == 24
    assert projection.pending_count == 2
    repeated = first.resume(executor)
    assert repeated.dispatch_started_count == 1
    assert repeated.reconciliation_required_count == 0
    assert repeated.pending_count == 2
    assert executor.calls == 24
    reconciled = first.mark_interrupted_dispatches_for_reconciliation(
        operator_confirmed_quiescent=True
    )
    assert reconciled.reconciliation_required_count == 1
    assert reconciled.pending_count == 2
    assert executor.calls == 24


def test_execute_coordinate_advances_only_the_requested_canary_coordinate(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    executor = CountingExecutor()
    first, second = ledger.run.coordinates[:2]

    projection = ledger.execute_coordinate(first, executor)
    repeated = ledger.execute_coordinate(first, executor)

    assert projection == repeated
    assert executor.calls == 1
    assert projection.executor_dispatch_count == 1
    assert projection.completion_committed_count == 1
    assert projection.reconciliation_required_count == 0
    assert projection.pending_count == 26
    assert ledger.state_for(first) is stage_ledger.SourceFreeStageLedgerStateV1.COMPLETION_COMMITTED
    assert ledger.state_for(second) is stage_ledger.SourceFreeStageLedgerStateV1.PENDING


def test_execute_coordinate_never_bypasses_an_unfinished_predecessor(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    executor = CountingExecutor()
    reviewer = ledger.run.coordinates[1]

    projection = ledger.execute_coordinate(reviewer, executor)

    assert executor.calls == 0
    assert projection.executor_dispatch_count == 0
    assert projection.completion_committed_count == 0
    assert projection.reconciliation_required_count == 0
    assert projection.pending_count == 27
    assert ledger.state_for(reviewer) is stage_ledger.SourceFreeStageLedgerStateV1.PENDING


@pytest.mark.parametrize(
    "invalid_executor",
    (
        None,
        1,
        "not-callable",
    ),
)
def test_resume_requires_a_callable_executor(tmp_path: Path, invalid_executor: object) -> None:
    ledger = _ledger(tmp_path)
    with pytest.raises(stage_ledger.SourceFreeStageLedgerError, match="callable"):
        ledger.resume(invalid_executor)  # type: ignore[arg-type]


def test_ledger_requires_a_completion_binding_verifier(tmp_path: Path) -> None:
    with pytest.raises(stage_ledger.SourceFreeStageLedgerError, match="binding verifier"):
        stage_ledger.LocalSourceFreeStageLedger(
            (tmp_path / "operator-private-stage-ledger").resolve(),
            repository_root=ROOT,
            seed_store=_seed_store(tmp_path),
            intent_queue=_queue(),
            completion_binding_verifier=object(),  # type: ignore[arg-type]
        )


def test_ledger_requires_a_persisted_seed_and_exact_queue(tmp_path: Path) -> None:
    empty_store = private_seed.LocalSourceFreePrivateSeedStore(
        (tmp_path / "empty-seed").resolve(),
        repository_root=ROOT,
        run_label="empty-seed",
    )
    with pytest.raises(stage_ledger.SourceFreeStageLedgerError, match="persisted and replayable"):
        stage_ledger.LocalSourceFreeStageLedger(
            (tmp_path / "empty-ledger").resolve(),
            repository_root=ROOT,
            seed_store=empty_store,
            intent_queue=_queue(),
            completion_binding_verifier=DeterministicTestBindingVerifier(),
        )

    class QueueSubclass(intents_module.IFEMNextCalibrationCaseIntentsV1):
        pass

    queue_subclass = QueueSubclass.model_validate(_queue().model_dump(mode="json"))
    with pytest.raises(stage_ledger.SourceFreeStageLedgerError, match="persisted and replayable"):
        stage_ledger.LocalSourceFreeStageLedger(
            (tmp_path / "wrong-queue-ledger").resolve(),
            repository_root=ROOT,
            seed_store=_seed_store(tmp_path),
            intent_queue=queue_subclass,
            completion_binding_verifier=DeterministicTestBindingVerifier(),
        )


def test_reconciliation_requires_explicit_quiescence_confirmation(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    with pytest.raises(stage_ledger.SourceFreeStageLedgerError, match="quiescence"):
        ledger.mark_interrupted_dispatches_for_reconciliation(
            operator_confirmed_quiescent=1  # type: ignore[arg-type]
        )


def test_coordinate_and_seed_store_exact_types_are_required(tmp_path: Path) -> None:
    class SeedStoreSubclass(private_seed.LocalSourceFreePrivateSeedStore):
        pass

    subclass = SeedStoreSubclass(
        (tmp_path / "subclass-seed").resolve(),
        repository_root=ROOT,
        run_label="subclass-seed",
    )
    subclass.commit_for_queue(_queue(), test_entropy=lambda size: b"l" * size)
    with pytest.raises(stage_ledger.SourceFreeStageLedgerError, match="exact persisted"):
        _ledger(tmp_path, seed_store=subclass)

    ledger = _ledger(tmp_path / "separate")
    coordinate = ledger.run.coordinates[0]

    class CoordinateSubclass(stage_ledger.SourceFreeStageCoordinateV1):
        pass

    coordinate_subclass = CoordinateSubclass.model_validate(coordinate.model_dump(mode="json"))
    with pytest.raises(stage_ledger.SourceFreeStageLedgerError, match="exact type"):
        ledger.state_for(coordinate_subclass)


def test_executor_type_alias_is_narrow() -> None:
    executor: Callable[
        [
            stage_ledger.SourceFreeStageCoordinateV1,
            private_seed.PrivateSourceFreeSeedItemV2,
        ],
        stage_ledger.SourceFreeStageCompletionBindingV1,
    ] = CountingExecutor()
    assert callable(executor)
