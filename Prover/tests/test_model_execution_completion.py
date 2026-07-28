from __future__ import annotations

import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pytest
from autolean_contracts import (
    AttestationError,
    AttestationPurposeV1,
    AttestationV1,
    HmacAttestationKeyV1,
    HmacAttestationSignerV1,
    HmacAttestationVerifierV1,
    ModelExecutionAuthorizationError,
    ModelExecutionAuthorizationV1,
    ModelExecutionCompletionRecoveryReasonV1,
    ModelResponseArtifactRefV1,
    ModelResponseArtifactV1,
    build_model_execution_private_output,
    model_execution_completion_public,
    stable_identifier,
)
from autolean_control_plane import (
    ArtifactStore,
    ControlPlane,
    EventStore,
    LeaseStore,
    ModelExecutionAuthorizationService,
)
from autolean_prover.errors import PolicyViolation, ProviderResponseError
from autolean_prover.providers import (
    LocalPrivateModelOutputStore,
    ModelExecutionCompletionRecoveryRequired,
    ModelRequest,
    ModelResponse,
    PrivateModelOutputStore,
    ProviderRegistry,
    TokenUsage,
    ToolCall,
    model_response_artifact,
)

from .test_model_execution_authorization import (
    _BUILDER_KEY,
    _MODEL_KEY,
    CountingFakeProvider,
    _approval,
    _bound_request,
    _budget,
    _clock_state,
    _issue_inputs,
    _issue_registered_authorization,
    _registry,
    _response,
    _signed_bundle,
)

_COMPLETION_KEY = HmacAttestationKeyV1(
    key_id="provider-test-completion-v1",
    secret=b"provider-test-completion-secret-material-012345",
    allowed_purposes=frozenset({AttestationPurposeV1.MODEL_EXECUTION_COMPLETION}),
)


class FailOnceCompletionSigner:
    def __init__(self, delegate: HmacAttestationSignerV1) -> None:
        self.delegate = delegate
        self.calls = 0

    def issue(
        self,
        *,
        purpose: AttestationPurposeV1,
        payload: Mapping[str, object],
        evidence_identity: str,
        ttl_seconds: float,
        nonce: str | None = None,
    ) -> AttestationV1:
        self.calls += 1
        if self.calls == 1:
            raise AttestationError("injected completion signer outage")
        return self.delegate.issue(
            purpose=purpose,
            payload=payload,
            evidence_identity=evidence_identity,
            ttl_seconds=ttl_seconds,
            nonce=nonce,
        )


class VanishingPrivateOutputStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.delegate = LocalPrivateModelOutputStore(root)

    def put_response(self, response: ModelResponse) -> ModelResponseArtifactRefV1:
        reference = self.delegate.put_response(response)
        self._path(reference).unlink()
        return reference

    def verify(self, reference: ModelResponseArtifactRefV1) -> None:
        self.delegate.verify(reference)

    def read_artifact(
        self,
        reference: ModelResponseArtifactRefV1,
    ) -> ModelResponseArtifactV1:
        return self.delegate.read_artifact(reference)

    def read_response(self, reference: ModelResponseArtifactRefV1) -> ModelResponse:
        return self.delegate.read_response(reference)

    def _path(self, reference: ModelResponseArtifactRefV1) -> Path:
        digest = reference.artifact_digest.value
        return self.root / digest[:2] / digest[2:]


class DeleteBeforeAttestationOutputStore:
    """Delete the CAS object on the post-settlement pre-sign read."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.delegate = LocalPrivateModelOutputStore(root)
        self.read_calls = 0
        self.response: ModelResponse | None = None

    def put_response(self, response: ModelResponse) -> ModelResponseArtifactRefV1:
        self.response = response
        return self.delegate.put_response(response)

    def read_artifact(
        self,
        reference: ModelResponseArtifactRefV1,
    ) -> ModelResponseArtifactV1:
        self.read_calls += 1
        if self.read_calls == 3:
            self._path(reference).unlink()
        return self.delegate.read_artifact(reference)

    def verify(self, reference: ModelResponseArtifactRefV1) -> None:
        self.read_artifact(reference)

    def read_response(self, reference: ModelResponseArtifactRefV1) -> ModelResponse:
        return self.delegate.read_response(reference)

    def restore(self) -> None:
        assert self.response is not None
        self.delegate.put_response(self.response)

    def _path(self, reference: ModelResponseArtifactRefV1) -> Path:
        digest = reference.artifact_digest.value
        return self.root / digest[:2] / digest[2:]


class ReadSwapPrivateOutputStore(LocalPrivateModelOutputStore):
    """Expose a different byte snapshot on a second read."""

    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.alternate_payload: bytes | None = None
        self.read_calls = 0

    def arm(self, replacement: ModelResponse) -> None:
        self.alternate_payload = model_response_artifact(replacement).canonical_bytes()
        self.read_calls = 0

    def _read(self, reference: ModelResponseArtifactRefV1) -> bytes:
        if self.alternate_payload is None:
            return super()._read(reference)
        self.read_calls += 1
        if self.read_calls == 1:
            return super()._read(reference)
        return self.alternate_payload


@dataclass(frozen=True, slots=True)
class CompletionHarness:
    database: Path
    service: ModelExecutionAuthorizationService
    output_store: PrivateModelOutputStore
    authorization: ModelExecutionAuthorizationV1
    request: ModelRequest
    provider: CountingFakeProvider
    registry: ProviderRegistry


def _completion_verifier(clock: Callable[[], datetime]) -> HmacAttestationVerifierV1:
    return HmacAttestationVerifierV1(
        {
            _BUILDER_KEY.key_id: _BUILDER_KEY,
            _MODEL_KEY.key_id: _MODEL_KEY,
            _COMPLETION_KEY.key_id: _COMPLETION_KEY,
        },
        clock=clock,
    )


def _completion_harness(
    tmp_path: Path,
    *,
    completion_signer: HmacAttestationSignerV1 | FailOnceCompletionSigner | None = None,
    response: ModelResponse | None = None,
    output_store: PrivateModelOutputStore | None = None,
) -> CompletionHarness:
    _state, clock = _clock_state()
    database = tmp_path / "control.db"
    verifier = _completion_verifier(clock)
    plane = ControlPlane(
        events=EventStore(database, clock=clock),
        leases=LeaseStore(database, clock=clock),
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        attestation_verifier=verifier,
        allow_test_only_unreviewed_bundles=True,
    )
    selected_output_store = output_store or LocalPrivateModelOutputStore(
        (tmp_path / "private-output").resolve()
    )
    service = ModelExecutionAuthorizationService(
        control_plane=plane,
        signer=HmacAttestationSignerV1(_MODEL_KEY, clock=clock),
        verifier=verifier,
        completion_signer=completion_signer
        or HmacAttestationSignerV1(_COMPLETION_KEY, clock=clock),
        completion_verifier=verifier,
        private_output_verifier=selected_output_store,
        clock=clock,
    )
    bundle = _signed_bundle(clock)
    plane.register_bundle(bundle, idempotency_key="register")
    approval = _approval(clock=clock)
    service.register_operator_approval(approval, idempotency_key="register-approval")
    lease, request = _issue_inputs(plane, bundle)
    authorization = service.issue(
        bundle,
        authorization_id=stable_identifier("provider-test", "completion-authorization"),
        approval_id=approval.approval_id,
        budget=_budget(),
        lease=lease,
        context_pack_hash=request.context_pack_hash,
        outbound_request_hash=request.outbound_request_hash(),
        ttl_seconds=300,
        idempotency_key="issue-completion",
    )
    provider = CountingFakeProvider([response or _response()])
    registry = _registry(service, [], provider=provider)
    return CompletionHarness(
        database=database,
        service=service,
        output_store=selected_output_store,
        authorization=authorization,
        request=request,
        provider=provider,
        registry=registry,
    )


def _table_count(database: Path, table: str, *, event_type: str | None = None) -> int:
    with sqlite3.connect(database) as connection:
        if event_type is None:
            row = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
        else:
            row = connection.execute(
                f"SELECT COUNT(*) FROM {table} WHERE event_type = ?",
                (event_type,),
            ).fetchone()
    assert row is not None
    return int(row[0])


def test_private_response_cas_is_canonical_and_round_trips_zero_usage(tmp_path: Path) -> None:
    store = LocalPrivateModelOutputStore((tmp_path / "private").resolve())
    response = ModelResponse(
        provider_id="fake",
        model_id="fake-model",
        response_id="response-123",
        text="exact private output",
        tool_calls=(
            ToolCall(
                call_id="call-1",
                name="lean_check",
                arguments_json='{"file":"Main.lean"}',
            ),
        ),
        usage=TokenUsage(),
    )

    first = store.put_response(response)
    second = store.put_response(response)

    assert first == second
    assert store.read_response(first) == response
    artifact_path = tmp_path / "private" / first.artifact_digest.value[:2]
    payload = next(artifact_path.iterdir()).read_bytes()
    assert len(payload) == first.size_bytes
    assert b"response-123" in payload
    assert b"lean_check" in payload


def test_private_response_read_uses_one_verified_byte_snapshot(tmp_path: Path) -> None:
    store = ReadSwapPrivateOutputStore((tmp_path / "private").resolve())
    original = _response()
    reference = store.put_response(original)
    store.arm(
        ModelResponse(
            provider_id=original.provider_id,
            model_id=original.model_id,
            text="swapped",
            usage=original.usage,
        )
    )

    observed = store.read_response(reference)

    assert observed == original
    assert store.read_calls == 1


def test_generate_completed_binds_output_usage_and_public_projection(tmp_path: Path) -> None:
    harness = _completion_harness(tmp_path)

    completed = harness.registry.generate_completed(
        harness.authorization,
        harness.request,
        output_store=harness.output_store,
        commitment_nonce="a" * 64,
    )

    record = completed.receipt.record
    assert completed.response == harness.output_store.read_response(record.private_output.artifact)
    assert record.authorization == harness.authorization
    assert record.authorization_hash == harness.authorization.authorization_hash()
    assert record.actual_usage.input_tokens == completed.response.usage.input_tokens
    assert record.actual_usage.output_tokens == completed.response.usage.output_tokens
    assert record.actual_usage.actual_cost_microusd == 0
    assert record.private_output.commitment_nonce == "a" * 64
    harness.service.verify_completion(completed.receipt)

    projection = model_execution_completion_public(completed.receipt).model_dump(mode="json")
    assert set(projection) == {
        "schema_version",
        "completion_id",
        "receipt_hash",
        "public_output_commitment",
    }
    serialized = str(projection)
    assert "by rfl" not in serialized
    assert "artifact_digest" not in serialized
    assert "commitment_nonce" not in serialized
    assert "actual_usage" not in serialized
    assert _table_count(harness.database, "model_execution_completion_settlements") == 1
    assert _table_count(harness.database, "model_execution_completion_receipts") == 1
    assert (
        _table_count(
            harness.database,
            "model_execution_authorization_ledger",
            event_type="settled",
        )
        == 1
    )


def test_legacy_generate_remains_non_promotable(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    _plane, service, _bundle, authorization = _issue_registered_authorization(
        tmp_path,
        clock=clock,
    )
    response = _registry(service, [_response()]).generate(authorization, _bound_request())

    assert response.text == "by rfl"
    assert _table_count(tmp_path / "control.db", "model_execution_completion_settlements") == 0
    assert _table_count(tmp_path / "control.db", "model_execution_completion_receipts") == 0


def test_completion_preflight_fails_before_provider_without_completion_authority(
    tmp_path: Path,
) -> None:
    _state, clock = _clock_state()
    _plane, service, _bundle, authorization = _issue_registered_authorization(
        tmp_path,
        clock=clock,
    )
    provider = CountingFakeProvider([_response()])
    registry = _registry(service, [], provider=provider)
    output_store = LocalPrivateModelOutputStore((tmp_path / "private").resolve())

    with pytest.raises(PolicyViolation, match="completion authority was denied"):
        registry.generate_completed(
            authorization,
            _bound_request(),
            output_store=output_store,
        )

    assert provider.calls == 0
    assert not any((tmp_path / "private").rglob("*"))


def test_completed_generation_rejects_changed_request_before_provider_or_output(
    tmp_path: Path,
) -> None:
    harness = _completion_harness(tmp_path)
    replaced_request = ModelRequest(
        prompt="different prompt",
        max_input_tokens=harness.request.max_input_tokens,
        max_output_tokens=harness.request.max_output_tokens,
        context_pack_hash=harness.request.context_pack_hash,
    )

    with pytest.raises(PolicyViolation, match="authorization was denied"):
        harness.registry.generate_completed(
            harness.authorization,
            replaced_request,
            output_store=harness.output_store,
        )

    assert harness.provider.calls == 0
    assert not any((tmp_path / "private-output").rglob("*"))


@pytest.mark.parametrize(
    ("artifact_model", "artifact_input", "settled_input", "expected_message"),
    [
        ("substituted-model", 1, 1, "provider or model differs"),
        ("fake-model", 2, 1, "usage differs"),
    ],
)
def test_direct_settlement_rejects_cas_model_or_usage_substitution(
    tmp_path: Path,
    artifact_model: str,
    artifact_input: int,
    settled_input: int,
    expected_message: str,
) -> None:
    harness = _completion_harness(tmp_path)
    reservation = harness.service.reserve(
        harness.authorization,
        provider=harness.authorization.provider,
        requested_input_tokens=harness.request.max_input_tokens,
        requested_output_tokens=harness.request.max_output_tokens,
        context_pack_hash=harness.request.context_pack_hash,
        outbound_request_hash=harness.request.outbound_request_hash(),
    )
    artifact = harness.output_store.put_response(
        ModelResponse(
            provider_id="fake",
            model_id=artifact_model,
            text="substituted private response",
            usage=TokenUsage(input_tokens=artifact_input, output_tokens=1),
        )
    )
    private_output = build_model_execution_private_output(
        authorization_hash=harness.authorization.authorization_hash(),
        reservation_id=reservation.reservation_id,
        artifact=artifact,
        commitment_nonce="e" * 64,
    )

    with pytest.raises(ModelExecutionAuthorizationError, match=expected_message):
        harness.service.settle_completed(
            reservation,
            input_tokens=settled_input,
            cached_input_tokens=0,
            output_tokens=1,
            private_output=private_output,
        )

    assert harness.provider.calls == 0
    assert _table_count(harness.database, "model_execution_completion_settlements") == 0
    assert (
        _table_count(
            harness.database,
            "model_execution_authorization_ledger",
            event_type="settled",
        )
        == 0
    )


def test_missing_private_output_abandons_without_settlement(tmp_path: Path) -> None:
    harness = _completion_harness(tmp_path)
    root = (tmp_path / "vanishing-output").resolve()
    output_store = VanishingPrivateOutputStore(root)

    with pytest.raises(ProviderResponseError, match="persistence failed"):
        harness.registry.generate_completed(
            harness.authorization,
            harness.request,
            output_store=output_store,
        )

    assert harness.provider.calls == 1
    assert _table_count(harness.database, "model_execution_completion_settlements") == 0
    assert (
        _table_count(
            harness.database,
            "model_execution_authorization_ledger",
            event_type="settled",
        )
        == 0
    )
    assert (
        _table_count(
            harness.database,
            "model_execution_authorization_ledger",
            event_type="abandoned",
        )
        == 1
    )


def test_completion_replay_is_exact_and_rejects_changed_usage_or_output(tmp_path: Path) -> None:
    harness = _completion_harness(tmp_path)
    completed = harness.registry.generate_completed(
        harness.authorization,
        harness.request,
        output_store=harness.output_store,
        commitment_nonce="b" * 64,
    )
    record = completed.receipt.record

    replay = harness.service.settle_completed(
        record.reservation,
        input_tokens=record.actual_usage.input_tokens,
        cached_input_tokens=record.actual_usage.cached_input_tokens,
        output_tokens=record.actual_usage.output_tokens,
        private_output=record.private_output,
    )
    assert replay == completed.receipt

    with pytest.raises(ModelExecutionAuthorizationError, match="usage differs"):
        harness.service.settle_completed(
            record.reservation,
            input_tokens=record.actual_usage.input_tokens + 1,
            cached_input_tokens=record.actual_usage.cached_input_tokens,
            output_tokens=record.actual_usage.output_tokens,
            private_output=record.private_output,
        )

    changed_response = ModelResponse(
        provider_id=completed.response.provider_id,
        model_id=completed.response.model_id,
        text="different private output",
        usage=completed.response.usage,
    )
    changed_artifact = harness.output_store.put_response(changed_response)
    changed_output = build_model_execution_private_output(
        authorization_hash=harness.authorization.authorization_hash(),
        reservation_id=record.reservation.reservation_id,
        artifact=changed_artifact,
        commitment_nonce="c" * 64,
    )
    with pytest.raises(ModelExecutionAuthorizationError, match="replay differs"):
        harness.service.settle_completed(
            record.reservation,
            input_tokens=record.actual_usage.input_tokens,
            cached_input_tokens=record.actual_usage.cached_input_tokens,
            output_tokens=record.actual_usage.output_tokens,
            private_output=changed_output,
        )


def test_receipt_or_cas_tamper_is_rejected(tmp_path: Path) -> None:
    harness = _completion_harness(tmp_path)
    completed = harness.registry.generate_completed(
        harness.authorization,
        harness.request,
        output_store=harness.output_store,
    )
    record = completed.receipt.record
    tampered_output = record.private_output.model_copy(
        update={"commitment_nonce": "d" * 64},
    )
    with pytest.raises(ValueError, match="public output commitment is inconsistent"):
        record.model_copy(update={"private_output": tampered_output})
    tampered_authorization_hash = record.authorization_hash.model_copy(update={"value": "0" * 64})
    with pytest.raises(ValueError, match="authorization hash does not match"):
        record.model_copy(update={"authorization_hash": tampered_authorization_hash})

    reference = record.private_output.artifact
    artifact = (
        tmp_path
        / "private-output"
        / reference.artifact_digest.value[:2]
        / reference.artifact_digest.value[2:]
    )
    artifact.write_bytes(b"tampered")
    with pytest.raises(ModelExecutionAuthorizationError, match="artifact verification failed"):
        harness.service.verify_completion(completed.receipt)


def test_usage_and_output_binding_rollback_together_on_insert_failure(tmp_path: Path) -> None:
    harness = _completion_harness(tmp_path)
    with sqlite3.connect(harness.database) as connection:
        connection.executescript(
            """
            CREATE TRIGGER reject_completion_for_test
            BEFORE INSERT ON model_execution_completion_settlements
            BEGIN
                SELECT RAISE(ABORT, 'injected completion persistence failure');
            END;
            """
        )

    with pytest.raises(PolicyViolation, match="settlement was denied"):
        harness.registry.generate_completed(
            harness.authorization,
            harness.request,
            output_store=harness.output_store,
        )

    assert harness.provider.calls == 1
    assert _table_count(harness.database, "model_execution_completion_settlements") == 0
    assert (
        _table_count(
            harness.database,
            "model_execution_authorization_ledger",
            event_type="settled",
        )
        == 0
    )
    assert (
        _table_count(
            harness.database,
            "model_execution_authorization_ledger",
            event_type="abandoned",
        )
        == 1
    )


def test_signer_failure_recovers_without_rerunning_provider(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    signer = FailOnceCompletionSigner(HmacAttestationSignerV1(_COMPLETION_KEY, clock=clock))
    harness = _completion_harness(tmp_path, completion_signer=signer)

    with pytest.raises(ModelExecutionCompletionRecoveryRequired) as captured:
        harness.registry.generate_completed(
            harness.authorization,
            harness.request,
            output_store=harness.output_store,
        )

    recovery = captured.value
    assert recovery.reason is ModelExecutionCompletionRecoveryReasonV1.ATTESTATION_UNAVAILABLE
    assert harness.provider.calls == 1
    assert _table_count(harness.database, "model_execution_completion_settlements") == 1
    assert _table_count(harness.database, "model_execution_completion_receipts") == 0
    assert (
        _table_count(
            harness.database,
            "model_execution_authorization_ledger",
            event_type="abandoned",
        )
        == 0
    )

    completed = harness.registry.recover_completed(
        recovery.recovery_handle,
        output_store=harness.output_store,
    )

    assert signer.calls == 2
    assert harness.provider.calls == 1
    assert completed.response.text == "by rfl"
    harness.service.verify_completion(completed.receipt)
    assert _table_count(harness.database, "model_execution_completion_receipts") == 1


def test_post_settlement_output_loss_returns_safe_handle_and_recovers_without_provider(
    tmp_path: Path,
) -> None:
    output_store = DeleteBeforeAttestationOutputStore((tmp_path / "private-output").resolve())
    harness = _completion_harness(tmp_path, output_store=output_store)

    with pytest.raises(ModelExecutionCompletionRecoveryRequired) as captured:
        harness.registry.generate_completed(
            harness.authorization,
            harness.request,
            output_store=output_store,
        )

    recovery = captured.value
    assert recovery.reason is ModelExecutionCompletionRecoveryReasonV1.PRIVATE_OUTPUT_UNAVAILABLE
    serialized_handle = str(recovery.recovery_handle.model_dump(mode="json"))
    assert "artifact" not in serialized_handle
    assert "commitment" not in serialized_handle
    assert "by rfl" not in serialized_handle
    assert harness.provider.calls == 1
    assert _table_count(harness.database, "model_execution_completion_settlements") == 1
    assert _table_count(harness.database, "model_execution_completion_receipts") == 0
    assert (
        _table_count(
            harness.database,
            "model_execution_authorization_ledger",
            event_type="abandoned",
        )
        == 0
    )

    output_store.restore()
    completed = harness.registry.recover_completed(
        recovery.recovery_handle,
        output_store=output_store,
    )

    assert completed.response.text == "by rfl"
    assert harness.provider.calls == 1
    harness.service.verify_completion(completed.receipt)
