"""End-to-end execution and crash recovery for the source-free ModelWork sidecar."""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from autolean_builder import ifem_next_calibration_case_intents as intents_module
from autolean_builder import ifem_source_free_private_seed as private_seed
from autolean_builder import ifem_source_free_stage_ledger as stage_ledger
from autolean_contracts import (
    AttestationPurposeV1,
    AttestationV1,
    EndpointClassV1,
    HmacAttestationKeyV1,
    HmacAttestationSignerV1,
    HmacAttestationVerifierV1,
    ModelExecutionAuthorizationV1,
    ModelExecutionPricingV1,
    ModelExecutionProviderApprovalV1,
    ModelExecutionProviderBindingV1,
    ModelWorkBundleV2,
    model_work_admission_evidence_identity,
    model_work_admission_payload,
    stable_identifier,
)
from autolean_control_plane import (
    ArtifactStore,
    ControlPlane,
    EventStore,
    Lease,
    LeaseStore,
    ModelExecutionAuthorizationService,
)
from autolean_control_plane.errors import StaleFence
from autolean_prover.providers import (
    Capability,
    FakeProvider,
    LocalPrivateModelOutputStore,
    ModelRequest,
    ModelResponse,
    ProviderCapabilities,
    ProviderRegistry,
    StaticCapabilityProbe,
    TokenUsage,
)

from benchmarks.ifem_source_free_model_work_sidecar import (
    EventStoreSourceFreeModelWorkAttemptStore,
    SourceFreeModelWorkAttemptBindingV1,
    SourceFreeModelWorkError,
    SourceFreeModelWorkExecutionSidecar,
    SourceFreeModelWorkReconciliationRequired,
    render_source_free_model_work_public_report,
)

ROOT = Path(__file__).resolve().parents[2]

_MODEL_KEY = HmacAttestationKeyV1(
    key_id="ifem-source-free-model-work-model-v1",
    secret=b"ifem-source-free-model-work-model-secret-00001",
    allowed_purposes=frozenset({AttestationPurposeV1.MODEL_EXECUTION}),
)
_ADMISSION_KEY = HmacAttestationKeyV1(
    key_id="ifem-source-free-model-work-admission-v1",
    secret=b"ifem-source-free-model-work-admission-secret-01",
    allowed_purposes=frozenset({AttestationPurposeV1.MODEL_WORK_ADMISSION}),
)
_COMPLETION_KEY = HmacAttestationKeyV1(
    key_id="ifem-source-free-model-work-completion-v1",
    secret=b"ifem-source-free-model-work-completion-secret-1",
    allowed_purposes=frozenset({AttestationPurposeV1.MODEL_EXECUTION_COMPLETION}),
)
_CAPABILITIES = ProviderCapabilities.of(
    Capability.TEXT_GENERATION,
    Capability.USAGE_ACCOUNTING,
    Capability.STRUCTURED_JSON,
)


class SimulatedProcessCrash(BaseException):
    pass


class CountingProvider(FakeProvider):
    def __init__(self, responses: list[ModelResponse]) -> None:
        super().__init__(
            responses,
            model_id="source-free-test-model",
            capabilities=_CAPABILITIES,
            timeout_seconds=120,
        )
        self.calls = 0

    def generate(self, request: ModelRequest) -> ModelResponse:
        self.calls += 1
        return super().generate(request)


class AdmissionResolver:
    def __init__(self, signer: HmacAttestationSignerV1) -> None:
        self.signer = signer
        self.calls = 0

    def admit_model_work(self, bundle: ModelWorkBundleV2) -> AttestationV1:
        self.calls += 1
        return self.signer.issue(
            purpose=AttestationPurposeV1.MODEL_WORK_ADMISSION,
            payload=model_work_admission_payload(bundle),
            evidence_identity=model_work_admission_evidence_identity(bundle),
            ttl_seconds=3600,
        )


class CrashSidecar(SourceFreeModelWorkExecutionSidecar):
    def __init__(self, *args: object, crash_at: str, **kwargs: object) -> None:
        self.crash_at = crash_at
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]

    def _checkpoint(
        self,
        name: str,
        _coordinate: stage_ledger.SourceFreeStageCoordinateV1,
    ) -> None:
        if name == self.crash_at:
            raise SimulatedProcessCrash(name)


@dataclass(frozen=True)
class Harness:
    database: Path
    events: EventStore
    manifest: private_seed.PrivateSourceFreeSeedManifestV2
    seed_store: private_seed.LocalSourceFreePrivateSeedStore
    service: ModelExecutionAuthorizationService
    registry: ProviderRegistry
    approval: ModelExecutionProviderApprovalV1
    output_store: LocalPrivateModelOutputStore
    admission: AdmissionResolver
    provider: CountingProvider

    def sidecar(
        self,
        sidecar_type: type[SourceFreeModelWorkExecutionSidecar] = (
            SourceFreeModelWorkExecutionSidecar
        ),
        **kwargs: object,
    ) -> SourceFreeModelWorkExecutionSidecar:
        return sidecar_type(
            seed_store=self.seed_store,
            intent_queue=_queue(),
            attempt_store=EventStoreSourceFreeModelWorkAttemptStore(self.events),
            authorization_service=self.service,
            registry=self.registry,
            approval=self.approval,
            output_store=self.output_store,
            admission_resolver=self.admission,
            **kwargs,  # type: ignore[arg-type]
        )


def _clock() -> datetime:
    return datetime(2026, 8, 1, 12, tzinfo=UTC)


def _queue() -> intents_module.IFEMNextCalibrationCaseIntentsV1:
    return intents_module.build_ifem_next_calibration_case_intents_from_paths()


def _response_texts(
    manifest: private_seed.PrivateSourceFreeSeedManifestV2,
) -> list[str]:
    responses: list[str] = []
    for item in manifest.items:
        candidate = item.hidden_oracle.expected_candidate.model_dump(mode="json")
        responses.extend(
            (
                json.dumps(
                    {
                        "schema_version": "autolean.ifem-source-free-authoring-response.v1",
                        "disposition": "propose",
                        "selected_slot": item.selector,
                        "candidate": candidate,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                json.dumps(
                    {
                        "schema_version": "autolean.ifem-source-free-review-response.v1",
                        "disposition": "accept",
                        "observed_change_count": 1,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                json.dumps(
                    {
                        "schema_version": "autolean.ifem-source-free-supervisor-response.v1",
                        "disposition": "allow",
                        "violation_detected": False,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            )
        )
    return responses


def _harness(
    tmp_path: Path,
    *,
    response_texts: list[str] | None = None,
) -> Harness:
    queue = _queue()
    seed_store = private_seed.LocalSourceFreePrivateSeedStore(
        (tmp_path / "operator-private-seed").resolve(),
        repository_root=ROOT,
        run_label="source-free-model-work-sidecar",
    )
    manifest, _commitment = seed_store.commit_for_queue(
        queue,
        test_entropy=lambda size: b"s" * size,
    )
    selected = response_texts or _response_texts(manifest)
    provider = CountingProvider(
        [
            ModelResponse(
                provider_id="fake",
                model_id="source-free-test-model",
                text=text,
                usage=TokenUsage(input_tokens=12, cached_input_tokens=2, output_tokens=8),
            )
            for text in selected
        ]
    )
    database = tmp_path / "control.db"
    events = EventStore(database, clock=_clock)
    verifier = HmacAttestationVerifierV1(
        {
            _MODEL_KEY.key_id: _MODEL_KEY,
            _ADMISSION_KEY.key_id: _ADMISSION_KEY,
            _COMPLETION_KEY.key_id: _COMPLETION_KEY,
        },
        clock=_clock,
    )
    plane = ControlPlane(
        events=events,
        leases=LeaseStore(database, clock=_clock),
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        attestation_verifier=verifier,
    )
    output_store = LocalPrivateModelOutputStore((tmp_path / "private-output").resolve())
    service = ModelExecutionAuthorizationService(
        control_plane=plane,
        signer=HmacAttestationSignerV1(_MODEL_KEY, clock=_clock),
        verifier=verifier,
        admission_verifier=verifier,
        completion_signer=HmacAttestationSignerV1(_COMPLETION_KEY, clock=_clock),
        completion_verifier=verifier,
        private_output_verifier=output_store,
        clock=_clock,
    )
    approval = ModelExecutionProviderApprovalV1(
        approval_id=stable_identifier("ifem-source-free-provider", "fake-v1"),
        binding=ModelExecutionProviderBindingV1(
            registry_name="fake",
            provider_id=provider.provider_id,
            model_id=provider.model_id,
            model_revision="source-free-test-model-v1",
            endpoint_class=EndpointClassV1.LOCAL,
            configuration_hash=provider.configuration_hash,
        ),
        pricing=ModelExecutionPricingV1(),
        approved_by="source-free-test-operator",
        approved_at=_clock(),
    )
    service.register_operator_approval(approval, idempotency_key="register-source-free-fake")
    registry = ProviderRegistry(authorization_gate=service)
    registry.register(
        "fake",
        provider=provider,
        probe=StaticCapabilityProbe(provider.capabilities),
        endpoint_class=EndpointClassV1.LOCAL,
        model_revision="source-free-test-model-v1",
    )
    return Harness(
        database=database,
        events=events,
        manifest=manifest,
        seed_store=seed_store,
        service=service,
        registry=registry,
        approval=approval,
        output_store=output_store,
        admission=AdmissionResolver(HmacAttestationSignerV1(_ADMISSION_KEY, clock=_clock)),
        provider=provider,
    )


def _ledger(
    tmp_path: Path,
    harness: Harness,
    sidecar: SourceFreeModelWorkExecutionSidecar,
) -> stage_ledger.LocalSourceFreeStageLedger:
    return stage_ledger.LocalSourceFreeStageLedger(
        (tmp_path / "operator-private-stage-ledger").resolve(),
        repository_root=ROOT,
        seed_store=harness.seed_store,
        intent_queue=_queue(),
        completion_binding_verifier=sidecar,
    )


def _table_count(database: Path, table: str) -> int:
    with sqlite3.connect(database) as connection:
        row = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
    assert row is not None
    return int(row[0])


def test_full_ledger_run_uses_exactly_27_provider_calls_and_projects_privately(
    tmp_path: Path,
) -> None:
    harness = _harness(tmp_path)
    sidecar = harness.sidecar()
    ledger = _ledger(tmp_path, harness, sidecar)

    projection = ledger.resume(sidecar.execute_once)
    report = sidecar.public_report(ledger)
    rendered = render_source_free_model_work_public_report(report)

    assert projection.complete is True
    assert harness.provider.calls == 27
    assert harness.admission.calls == 27
    assert _table_count(harness.database, "model_execution_completion_settlements") == 27
    assert _table_count(harness.database, "model_execution_completion_receipts") == 27
    assert harness.events.count_events(entity_type="ifem_source_free_model_work_attempt") == 27
    assert report.completion_receipt_count == 27
    assert report.maximum_authorized_provider_attempts == 27
    assert report.actual_provider_dispatch_count_claimed is False
    assert report.authority == type(report.authority)()
    assert report.builder_freeze == "forbidden"
    assert report.prover_handoff == "forbidden"
    for forbidden in (
        b'"case_id"',
        b'"role"',
        b'"provider_id"',
        b'"model_id"',
        b'"completion_id"',
        b'"authorization"',
        b'"prompt"',
    ):
        assert forbidden not in rendered

    ledger.resume(sidecar.execute_once)
    assert harness.provider.calls == 27


def test_prepared_cards_never_include_private_seed_or_oracle_fields(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    sidecar = harness.sidecar()
    ledger = _ledger(tmp_path, harness, sidecar)
    first_coordinate = ledger.run.coordinates[0]
    item = harness.manifest.items[0]

    prepared = sidecar.prepare(first_coordinate, item)
    serialized = prepared.request.prompt.encode("utf-8")

    assert prepared.work_bundle.native_tools_enabled is False
    assert prepared.work_bundle.retrieval_enabled is False
    assert prepared.request.tools == ()
    for forbidden in (
        b"node_id",
        b"partition",
        b"hidden_oracle",
        b"run_nonce_hex",
        b"intent_id",
        b"item_content_sha256",
    ):
        assert forbidden not in serialized


@pytest.mark.parametrize(
    ("crash_at", "expected_calls", "settled"),
    (
        ("authorization_bound", 0, False),
        ("completion_obtained", 1, True),
    ),
)
def test_crash_recovery_never_redispatches_provider(
    tmp_path: Path,
    crash_at: str,
    expected_calls: int,
    settled: bool,
) -> None:
    harness = _harness(tmp_path)
    crashing = cast(
        CrashSidecar,
        harness.sidecar(CrashSidecar, crash_at=crash_at),
    )
    ledger = _ledger(tmp_path, harness, crashing)
    coordinate = ledger.run.coordinates[0]
    item = harness.manifest.items[0]

    with pytest.raises(SimulatedProcessCrash):
        crashing.execute_once(coordinate, item)

    assert harness.provider.calls == expected_calls
    recovered = harness.sidecar()
    if settled:
        binding = recovered.recover(coordinate, item)
        recovered.verify_binding(coordinate, binding)
    else:
        with pytest.raises(
            SourceFreeModelWorkReconciliationRequired,
            match="no durable completion settlement",
        ):
            recovered.recover(coordinate, item)
    assert harness.provider.calls == expected_calls

    if settled:
        assert recovered.execute_once(coordinate, item) == binding
    else:
        with pytest.raises(SourceFreeModelWorkReconciliationRequired):
            recovered.execute_once(coordinate, item)
    assert harness.provider.calls == expected_calls


def test_invalid_receipt_bound_json_cannot_be_retried_into_success(tmp_path: Path) -> None:
    harness = _harness(tmp_path, response_texts=["{not-json"])
    sidecar = harness.sidecar()
    ledger = _ledger(tmp_path, harness, sidecar)
    coordinate = ledger.run.coordinates[0]
    item = harness.manifest.items[0]

    with pytest.raises(ValueError, match="strict finite JSON schema"):
        sidecar.execute_once(coordinate, item)

    assert harness.provider.calls == 1
    assert _table_count(harness.database, "model_execution_completion_settlements") == 1
    with pytest.raises(ValueError, match="strict finite JSON schema"):
        sidecar.execute_once(coordinate, item)
    assert harness.provider.calls == 1


def test_attempt_store_rejects_another_coordinate_and_is_append_only(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    sidecar = harness.sidecar()
    ledger = _ledger(tmp_path, harness, sidecar)
    first = ledger.run.coordinates[0]
    second = ledger.run.coordinates[1]
    item = harness.manifest.items[0]

    binding = sidecar.execute_once(first, item)
    sidecar.verify_binding(first, binding)
    store = EventStoreSourceFreeModelWorkAttemptStore(harness.events)

    assert store.load(first) is not None
    assert store.load(second) is None
    with (
        sqlite3.connect(harness.database) as connection,
        pytest.raises(
            sqlite3.IntegrityError,
            match="append-only",
        ),
    ):
        connection.execute(
            "UPDATE events SET entity_id = ? WHERE entity_type = ?",
            (second.coordinate_sha256, "ifem_source_free_model_work_attempt"),
        )


def test_missing_admission_fails_before_attempt_or_provider_call(tmp_path: Path) -> None:
    harness = _harness(tmp_path)

    class RejectingAdmission:
        def admit_model_work(self, _bundle: ModelWorkBundleV2) -> AttestationV1:
            raise RuntimeError("admission unavailable")

    sidecar = SourceFreeModelWorkExecutionSidecar(
        seed_store=harness.seed_store,
        intent_queue=_queue(),
        attempt_store=EventStoreSourceFreeModelWorkAttemptStore(harness.events),
        authorization_service=harness.service,
        registry=harness.registry,
        approval=harness.approval,
        output_store=harness.output_store,
        admission_resolver=RejectingAdmission(),
    )
    ledger = _ledger(tmp_path, harness, sidecar)

    with pytest.raises(ValueError, match="admission or authorization failed"):
        sidecar.execute_once(ledger.run.coordinates[0], harness.manifest.items[0])

    assert harness.provider.calls == 0
    assert harness.events.count_events(entity_type="ifem_source_free_model_work_attempt") == 0


def test_attempt_event_contains_no_prompt_response_or_credentials(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    sidecar = harness.sidecar()
    ledger = _ledger(tmp_path, harness, sidecar)
    coordinate = ledger.run.coordinates[0]

    sidecar.execute_once(coordinate, harness.manifest.items[0])
    event = harness.events.read_stream(
        "ifem_source_free_model_work_attempt",
        coordinate.coordinate_sha256,
    )[0]
    serialized = str(event.payload)

    assert "system_prompt" not in serialized
    assert "permitted_excerpt" not in serialized
    assert "raw_output" not in serialized
    assert "response_id" not in serialized
    assert "artifact_digest" not in serialized
    assert "secret" not in serialized.lower()
    assert "api_key" not in serialized.lower()
    assert cast(str, event.payload["bundle_id"]) in serialized
    assert isinstance(event.payload, Mapping)


def test_sidecar_reloads_and_replays_the_persisted_seed(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    harness.seed_store.manifest_path.write_text("{}", encoding="utf-8")

    with pytest.raises(
        SourceFreeModelWorkError,
        match="private seed is not persisted and replayable",
    ):
        harness.sidecar()


def test_public_report_refuses_a_detached_projection(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    sidecar = harness.sidecar()
    ledger = _ledger(tmp_path, harness, sidecar)
    projection = ledger.public_projection()

    with pytest.raises(
        SourceFreeModelWorkError,
        match="exact persisted stage ledger",
    ):
        sidecar.public_report(projection)  # type: ignore[arg-type]


def test_concurrent_same_stage_binds_once_before_one_provider_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two callers may race to bind, but only the winning binding may dispatch."""

    harness = _harness(tmp_path)
    attempt_store = EventStoreSourceFreeModelWorkAttemptStore(harness.events)
    bind_barrier = threading.Barrier(2)
    original_bind_once = attempt_store.bind_once
    provisional_sidecar = harness.sidecar()
    provisional_ledger = _ledger(tmp_path, harness, provisional_sidecar)
    coordinate = provisional_ledger.run.coordinates[0]
    item = harness.manifest.items[0]
    prepared = provisional_sidecar.prepare(coordinate, item)
    admission = harness.admission.admit_model_work(prepared.work_bundle)

    class ReplayAdmissionResolver:
        def admit_model_work(self, bundle: ModelWorkBundleV2) -> AttestationV1:
            if bundle != prepared.work_bundle:
                raise AssertionError("test admission was requested for another ModelWork bundle")
            return admission

    def synchronized_bind_once(
        coordinate: stage_ledger.SourceFreeStageCoordinateV1,
        *,
        bundle: ModelWorkBundleV2,
        authorization: ModelExecutionAuthorizationV1,
        lease: Lease,
    ) -> SourceFreeModelWorkAttemptBindingV1:
        # This point is after admission, registration, lease issuance, and authorization, but
        # before the write-once attempt event and any provider generation.
        bind_barrier.wait(timeout=10)
        return original_bind_once(
            coordinate,
            bundle=bundle,
            authorization=authorization,
            lease=lease,
        )

    monkeypatch.setattr(attempt_store, "bind_once", synchronized_bind_once)
    sidecars = tuple(
        SourceFreeModelWorkExecutionSidecar(
            seed_store=harness.seed_store,
            intent_queue=_queue(),
            attempt_store=attempt_store,
            authorization_service=harness.service,
            registry=harness.registry,
            approval=harness.approval,
            output_store=harness.output_store,
            admission_resolver=ReplayAdmissionResolver(),
        )
        for _ in range(2)
    )
    outcomes: list[
        tuple[
            SourceFreeModelWorkExecutionSidecar,
            stage_ledger.SourceFreeStageCompletionBindingV1 | Exception,
        ]
    ] = []
    outcomes_lock = threading.Lock()

    def execute(sidecar: SourceFreeModelWorkExecutionSidecar) -> None:
        try:
            outcome: stage_ledger.SourceFreeStageCompletionBindingV1 | Exception = (
                sidecar.execute_once(coordinate, item)
            )
        except Exception as error:
            outcome = error
        with outcomes_lock:
            outcomes.append((sidecar, outcome))

    threads = tuple(threading.Thread(target=execute, args=(sidecar,)) for sidecar in sidecars)
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)
        assert not thread.is_alive()

    successes = [
        (sidecar, outcome)
        for sidecar, outcome in outcomes
        if isinstance(outcome, stage_ledger.SourceFreeStageCompletionBindingV1)
    ]
    reconciliations = [
        (sidecar, outcome)
        for sidecar, outcome in outcomes
        if isinstance(outcome, SourceFreeModelWorkReconciliationRequired)
    ]
    assert len(outcomes) == 2
    assert len(successes) == 1
    assert len(reconciliations) == 1
    assert harness.events.count_events(entity_type="ifem_source_free_model_work_attempt") == 1
    assert harness.provider.calls == 1

    winner = successes[0][1]
    assert isinstance(winner, stage_ledger.SourceFreeStageCompletionBindingV1)
    losing_sidecar = reconciliations[0][0]
    assert losing_sidecar.recover(coordinate, item) == winner
    assert harness.provider.calls == 1


def test_attempt_store_on_another_database_fails_before_provider_dispatch(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    disconnected_events = EventStore(tmp_path / "disconnected-events.db", clock=_clock)
    sidecar = SourceFreeModelWorkExecutionSidecar(
        seed_store=harness.seed_store,
        intent_queue=_queue(),
        attempt_store=EventStoreSourceFreeModelWorkAttemptStore(disconnected_events),
        authorization_service=harness.service,
        registry=harness.registry,
        approval=harness.approval,
        output_store=harness.output_store,
        admission_resolver=harness.admission,
    )
    ledger = _ledger(tmp_path, harness, sidecar)

    with pytest.raises(
        SourceFreeModelWorkError,
        match="source-free ModelWork admission or authorization failed",
    ) as raised:
        sidecar.execute_once(ledger.run.coordinates[0], harness.manifest.items[0])

    assert isinstance(raised.value.__cause__, StaleFence | sqlite3.OperationalError)
    assert harness.provider.calls == 0
    assert disconnected_events.count_events(entity_type="ifem_source_free_model_work_attempt") == 0
    assert harness.events.count_events(entity_type="ifem_source_free_model_work_attempt") == 0


def test_downstream_prompts_are_strict_finite_predecessor_projections(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    sidecar = harness.sidecar()
    ledger = _ledger(tmp_path, harness, sidecar)
    author_coordinate, reviewer_coordinate, supervisor_coordinate = ledger.run.coordinates[:3]
    item = harness.manifest.items[0]

    sidecar.execute_once(author_coordinate, item)
    reviewer = sidecar.prepare(reviewer_coordinate, item)
    reviewer_payload = cast(dict[str, object], json.loads(reviewer.request.prompt))
    reviewer_card = cast(dict[str, object], reviewer_payload["card"])
    assert reviewer_payload["role"] == reviewer_coordinate.role.value
    assert set(reviewer_card) == {
        "author_candidate",
        "author_disposition",
        "author_selected_slot",
        "baseline",
        "case_id",
        "increment",
        "selector",
        "source_free",
    }
    assert reviewer_card["author_candidate"] == item.hidden_oracle.expected_candidate.model_dump(
        mode="json"
    )

    sidecar.execute_once(reviewer_coordinate, item)
    supervisor = sidecar.prepare(supervisor_coordinate, item)
    supervisor_payload = cast(dict[str, object], json.loads(supervisor.request.prompt))
    supervisor_card = cast(dict[str, object], supervisor_payload["card"])
    assert supervisor_payload["role"] == supervisor_coordinate.role.value
    assert set(supervisor_card) == {
        "author_disposition",
        "case_id",
        "observed_change_count",
        "reviewer_disposition",
        "source_free",
    }
    assert supervisor_card["observed_change_count"] == 1

    for prompt in (reviewer.request.prompt, supervisor.request.prompt):
        encoded = prompt.encode("utf-8")
        for forbidden in (
            b"authorization",
            b"authoring-response",
            b"cached_input_tokens",
            b"completion",
            b"hidden_oracle",
            b"input_tokens",
            b"model_id",
            b"node_id",
            b"nonce",
            b"output_tokens",
            b"partition",
            b"provider_id",
            b"raw_output",
            b"review-response",
            b"response_id",
            b"run_nonce_hex",
        ):
            assert forbidden not in encoded
    assert harness.provider.calls == 2


@pytest.mark.parametrize(
    "malformed_author_response",
    (
        "{not-json",
        (
            '{"schema_version":"autolean.ifem-source-free-authoring-response.v1",'
            '"disposition":"propose","disposition":"abstain",'
            '"selected_slot":null,"candidate":null}'
        ),
    ),
)
def test_malformed_or_duplicate_predecessor_completion_blocks_downstream_dispatch(
    tmp_path: Path,
    malformed_author_response: str,
) -> None:
    harness = _harness(tmp_path, response_texts=[malformed_author_response])
    sidecar = harness.sidecar()
    ledger = _ledger(tmp_path, harness, sidecar)
    author_coordinate, reviewer_coordinate = ledger.run.coordinates[:2]
    item = harness.manifest.items[0]

    with pytest.raises(SourceFreeModelWorkError, match="strict finite JSON schema"):
        sidecar.execute_once(author_coordinate, item)
    assert harness.provider.calls == 1
    assert harness.events.count_events(entity_type="ifem_source_free_model_work_attempt") == 1
    assert _table_count(harness.database, "model_execution_completion_settlements") == 1

    with pytest.raises(SourceFreeModelWorkError, match="strict finite JSON schema"):
        sidecar.execute_once(reviewer_coordinate, item)
    assert harness.provider.calls == 1
    assert harness.events.count_events(entity_type="ifem_source_free_model_work_attempt") == 1
