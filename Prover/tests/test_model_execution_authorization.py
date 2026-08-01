from __future__ import annotations

import inspect
import sqlite3
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from autolean_contracts import (
    AttestationError,
    AttestationPurposeV1,
    AttestationV1,
    DigestV1,
    EndpointClassV1,
    HashKindV1,
    HmacAttestationKeyV1,
    HmacAttestationSignerV1,
    HmacAttestationVerifierV1,
    ModelExecutionAuthorizationError,
    ModelExecutionBudgetV1,
    ModelExecutionPricingV1,
    ModelExecutionProviderApprovalV1,
    ModelExecutionProviderBindingV1,
    ModelExecutionSubjectKindV1,
    ModelWorkBundleV2,
    ModelWorkRoleV1,
    PermissionDecisionV1,
    RightsRecordV1,
    SourceRecordV1,
    SourceSpanV1,
    builder_attestation_payload,
    digest_model,
    digest_text,
    model_work_admission_evidence_identity,
    model_work_admission_payload,
    model_work_bundle_id,
    model_work_case_contract_hash,
    model_work_case_hash,
    model_work_cell_contract_hash,
    model_work_cell_hash,
    model_work_contract_id,
    model_work_item_hash,
    model_work_rights_binding,
    model_work_run_hash,
    model_work_source_binding,
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
from autolean_prover.errors import PolicyViolation, ProviderResponseError
from autolean_prover.providers import (
    Capability,
    FakeProvider,
    ModelRequest,
    ModelResponse,
    ProviderCapabilities,
    ProviderFailureCodeV1,
    ProviderRegistry,
    StaticCapabilityProbe,
    TokenUsage,
)
from autolean_prover.providers.registry import CapabilityProbe

from .helpers import frozen_bundle

_BUILDER_KEY = HmacAttestationKeyV1(
    key_id="provider-test-builder-v1",
    secret=b"provider-test-builder-secret-material-012345",
    allowed_purposes=frozenset({AttestationPurposeV1.BUILDER_FREEZE}),
)
_MODEL_KEY = HmacAttestationKeyV1(
    key_id="provider-test-model-v1",
    secret=b"provider-test-model-secret-material-01234567",
    allowed_purposes=frozenset({AttestationPurposeV1.MODEL_EXECUTION}),
)
_MODEL_WORK_ADMISSION_KEY = HmacAttestationKeyV1(
    key_id="provider-test-model-work-admission-v1",
    secret=b"provider-test-admission-secret-material-012345",
    allowed_purposes=frozenset({AttestationPurposeV1.MODEL_WORK_ADMISSION}),
)
_AUTH_CAPABILITIES = ProviderCapabilities.of(
    Capability.TEXT_GENERATION,
    Capability.USAGE_ACCOUNTING,
)
_PROVIDER_SECRET_MARKER = "credential-like-provider-error-must-not-be-persisted"


class CountingProbe:
    def __init__(self, observed: ProviderCapabilities) -> None:
        self.observed = observed
        self.calls = 0

    def probe(self, provider: object) -> ProviderCapabilities:
        del provider
        self.calls += 1
        return self.observed


class SecretFailingProvider(FakeProvider):
    def __init__(self) -> None:
        super().__init__([], capabilities=_AUTH_CAPABILITIES)

    def generate(self, request: ModelRequest) -> ModelResponse:
        del request
        raise RuntimeError(_PROVIDER_SECRET_MARKER)


class CountingFakeProvider(FakeProvider):
    def __init__(
        self,
        responses: list[ModelResponse],
        *,
        model_id: str = "fake-model",
    ) -> None:
        super().__init__(responses, model_id=model_id, capabilities=_AUTH_CAPABILITIES)
        self.calls = 0

    def generate(self, request: ModelRequest) -> ModelResponse:
        self.calls += 1
        return super().generate(request)


class RejectVerification:
    def __init__(
        self,
        delegate: HmacAttestationVerifierV1,
        *,
        reject_call: int,
    ) -> None:
        self.delegate = delegate
        self.reject_call = reject_call
        self.calls = 0

    def verify(
        self,
        attestation: AttestationV1,
        *,
        expected_purpose: AttestationPurposeV1,
        payload: Mapping[str, object],
    ) -> None:
        self.calls += 1
        if self.calls == self.reject_call:
            raise AttestationError("test authority revoked at transaction boundary")
        self.delegate.verify(
            attestation,
            expected_purpose=expected_purpose,
            payload=payload,
        )


def _clock_state() -> tuple[dict[str, datetime], Callable[[], datetime]]:
    state = {"now": datetime(2026, 1, 1, tzinfo=UTC)}

    def clock() -> datetime:
        return state["now"]

    return state, clock


def _verifier(clock: Callable[[], datetime]) -> HmacAttestationVerifierV1:
    return HmacAttestationVerifierV1(
        {
            _BUILDER_KEY.key_id: _BUILDER_KEY,
            _MODEL_KEY.key_id: _MODEL_KEY,
            _MODEL_WORK_ADMISSION_KEY.key_id: _MODEL_WORK_ADMISSION_KEY,
        },
        clock=clock,
    )


def _signed_bundle(clock: Callable[[], datetime]):
    unsigned = frozen_bundle()
    attestation = HmacAttestationSignerV1(_BUILDER_KEY, clock=clock).issue(
        purpose=AttestationPurposeV1.BUILDER_FREEZE,
        payload=builder_attestation_payload(unsigned),
        evidence_identity="provider-test-builder-freeze",
        ttl_seconds=3600,
    )
    return unsigned.model_copy(update={"builder_attestation": attestation})


def _plane_and_service(
    tmp_path: Path,
    clock: Callable[[], datetime],
    *,
    max_ttl_seconds: float = 60.0 * 60.0,
    provider_failure_threshold: int = 3,
    provider_failure_cooldown_seconds: float = 60.0,
):
    database = tmp_path / "control.db"
    verifier = _verifier(clock)
    plane = ControlPlane(
        events=EventStore(database, clock=clock),
        leases=LeaseStore(database, clock=clock),
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        attestation_verifier=verifier,
        allow_test_only_unreviewed_bundles=True,
    )
    service = ModelExecutionAuthorizationService(
        control_plane=plane,
        signer=HmacAttestationSignerV1(_MODEL_KEY, clock=clock),
        verifier=verifier,
        admission_verifier=verifier,
        clock=clock,
        max_ttl_seconds=max_ttl_seconds,
        provider_failure_threshold=provider_failure_threshold,
        provider_failure_cooldown_seconds=provider_failure_cooldown_seconds,
    )
    return plane, service


def _restart_plane(tmp_path: Path, clock: Callable[[], datetime]) -> ControlPlane:
    database = tmp_path / "control.db"
    return ControlPlane(
        events=EventStore(database, clock=clock),
        leases=LeaseStore(database, clock=clock),
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        attestation_verifier=_verifier(clock),
        allow_test_only_unreviewed_bundles=True,
    )


def _restart_service(
    tmp_path: Path,
    clock: Callable[[], datetime],
    *,
    provider_failure_threshold: int = 3,
    provider_failure_cooldown_seconds: float = 60.0,
) -> ModelExecutionAuthorizationService:
    return ModelExecutionAuthorizationService(
        control_plane=_restart_plane(tmp_path, clock),
        signer=HmacAttestationSignerV1(_MODEL_KEY, clock=clock),
        verifier=_verifier(clock),
        admission_verifier=_verifier(clock),
        clock=clock,
        provider_failure_threshold=provider_failure_threshold,
        provider_failure_cooldown_seconds=provider_failure_cooldown_seconds,
    )


def _approval(
    *,
    clock: Callable[[], datetime],
    model_id: str = "fake-model",
    pricing: ModelExecutionPricingV1 | None = None,
    endpoint_class: EndpointClassV1 = EndpointClassV1.LOCAL,
) -> ModelExecutionProviderApprovalV1:
    return ModelExecutionProviderApprovalV1(
        approval_id=stable_identifier("provider-test", f"approval-{model_id}"),
        binding=ModelExecutionProviderBindingV1(
            registry_name="fake",
            provider_id="fake",
            model_id=model_id,
            model_revision="fake-model-v1",
            endpoint_class=endpoint_class,
            configuration_hash=FakeProvider(
                [],
                model_id=model_id,
                capabilities=_AUTH_CAPABILITIES,
            ).configuration_hash,
        ),
        pricing=pricing or ModelExecutionPricingV1(),
        approved_by="test-operator",
        approved_at=clock(),
    )


def _budget(*, attempts: int = 2, cost: int = 0) -> ModelExecutionBudgetV1:
    return ModelExecutionBudgetV1(
        max_attempts=attempts,
        max_input_tokens=8,
        max_output_tokens=8,
        max_total_tokens=16,
        max_cost_microusd=cost,
    )


def _bound_request() -> ModelRequest:
    return ModelRequest(
        prompt="prove it",
        max_input_tokens=4,
        max_output_tokens=4,
        context_pack_hash=digest_text(HashKindV1.PROMPT, "provider-test-context-pack"),
    )


def _model_work(
    request: ModelRequest,
    *,
    overall_decision: PermissionDecisionV1 = PermissionDecisionV1.ALLOW,
    model_egress: PermissionDecisionV1 = PermissionDecisionV1.ALLOW,
    allowed_endpoint_classes: tuple[EndpointClassV1, ...] = (EndpointClassV1.APPROVED_EXTERNAL,),
    private_marker: str = "provider-test",
) -> ModelWorkBundleV2:
    assert request.context_pack_hash is not None
    egress_content = "provider-test-answer-free-egress"
    egress_content_hash = digest_text(HashKindV1.SOURCE_SPAN, egress_content)
    source = SourceRecordV1(
        source_id=stable_identifier(f"{private_marker}-model-work-source", "calibration"),
        work_id=f"{private_marker}-model-work",
        title=f"Synthetic calibration {private_marker}",
        version="1",
        locator=f"repo://{private_marker}/calibration-pairs.v3.json",
        content_hash=digest_text(HashKindV1.SOURCE_BYTES, f"{private_marker}-model-work"),
        spans=(
            SourceSpanV1(
                span_id=stable_identifier(f"{private_marker}-model-work-span", "calibration"),
                locator=f"answer-free-egress:{private_marker}-case",
                content_hash=egress_content_hash,
            ),
        ),
    )
    rights = RightsRecordV1(
        rights_id=stable_identifier(f"{private_marker}-model-work-rights", "calibration"),
        source_id=source.source_id,
        source_license=(
            f"LicenseRef-{private_marker}"
            if overall_decision is PermissionDecisionV1.ALLOW
            else None
        ),
        overall_decision=overall_decision,
        model_egress=model_egress,
        allowed_endpoint_classes=allowed_endpoint_classes,
        reviewed_by=("test-operator" if overall_decision is PermissionDecisionV1.ALLOW else None),
        reviewed_at=(
            datetime(2026, 1, 1, tzinfo=UTC)
            if overall_decision is PermissionDecisionV1.ALLOW
            else None
        ),
    )
    run_hash = model_work_run_hash(f"{private_marker}-run")
    cell_hash = model_work_cell_hash(f"{private_marker}-cell")
    case_hash = model_work_case_hash(f"{private_marker}-case")
    cell_contract_hash = model_work_cell_contract_hash("1" * 64)
    case_contract_hash = model_work_case_contract_hash("2" * 64)
    return ModelWorkBundleV2(
        bundle_id=model_work_bundle_id(
            run_hash=run_hash,
            cell_hash=cell_hash,
            case_hash=case_hash,
            repetition=1,
            role=ModelWorkRoleV1.PROVER,
        ),
        work_contract_id=model_work_contract_id(
            cell_contract_hash=cell_contract_hash,
            case_contract_hash=case_contract_hash,
        ),
        run_hash=run_hash,
        cell_hash=cell_hash,
        case_hash=case_hash,
        repetition=1,
        role=ModelWorkRoleV1.PROVER,
        cell_contract_hash=cell_contract_hash,
        case_contract_hash=case_contract_hash,
        work_item_hash=model_work_item_hash("3" * 64),
        role_environment_hash=digest_text(HashKindV1.ENVIRONMENT, "provider-test-role-env"),
        egress_content_hash=egress_content_hash,
        context_pack_hash=request.context_pack_hash,
        request_hash=request.outbound_request_hash(),
        source=model_work_source_binding(source),
        rights=model_work_rights_binding(rights),
    )


def _model_work_admission(
    work: ModelWorkBundleV2,
    clock: Callable[[], datetime],
    *,
    key: HmacAttestationKeyV1 = _MODEL_WORK_ADMISSION_KEY,
    purpose: AttestationPurposeV1 = AttestationPurposeV1.MODEL_WORK_ADMISSION,
    ttl_seconds: float = 3600,
    nonce: str | None = None,
) -> AttestationV1:
    return HmacAttestationSignerV1(key, clock=clock).issue(
        purpose=purpose,
        payload=model_work_admission_payload(work),
        evidence_identity=model_work_admission_evidence_identity(work),
        ttl_seconds=ttl_seconds,
        nonce=nonce,
    )


def _replace_model_work_trial_binding(
    work: ModelWorkBundleV2,
    *,
    field: str,
    replacement: object,
) -> ModelWorkBundleV2:
    update = {field: replacement}
    if field in {"run_hash", "cell_hash", "case_hash", "repetition", "role"}:
        run_hash = replacement if field == "run_hash" else work.run_hash
        cell_hash = replacement if field == "cell_hash" else work.cell_hash
        case_hash = replacement if field == "case_hash" else work.case_hash
        repetition = replacement if field == "repetition" else work.repetition
        role = replacement if field == "role" else work.role
        assert isinstance(run_hash, DigestV1)
        assert isinstance(cell_hash, DigestV1)
        assert isinstance(case_hash, DigestV1)
        assert isinstance(repetition, int)
        assert isinstance(role, ModelWorkRoleV1)
        update["bundle_id"] = model_work_bundle_id(
            run_hash=run_hash,
            cell_hash=cell_hash,
            case_hash=case_hash,
            repetition=repetition,
            role=role,
        )
    return work.model_copy(update=update)


def _issue_inputs(plane: ControlPlane, bundle, *, worker_id: str = "provider-test-worker"):
    request = _bound_request()
    assert request.context_pack_hash is not None
    lease = plane.claim(
        bundle.bundle_id.value,
        worker_id=worker_id,
        ttl_seconds=7200,
        idempotency_key=f"claim-{worker_id}",
    ).lease
    return lease, request


def _issue_registered_authorization(
    tmp_path: Path,
    *,
    clock: Callable[[], datetime],
    approval: ModelExecutionProviderApprovalV1 | None = None,
    budget: ModelExecutionBudgetV1 | None = None,
    ttl_seconds: float = 300,
    max_ttl_seconds: float = 60.0 * 60.0,
    provider_failure_threshold: int = 3,
    provider_failure_cooldown_seconds: float = 60.0,
):
    plane, service = _plane_and_service(
        tmp_path,
        clock,
        max_ttl_seconds=max_ttl_seconds,
        provider_failure_threshold=provider_failure_threshold,
        provider_failure_cooldown_seconds=provider_failure_cooldown_seconds,
    )
    bundle = _signed_bundle(clock)
    plane.register_bundle(bundle, idempotency_key="register")
    selected_approval = approval or _approval(clock=clock)
    service.register_operator_approval(
        selected_approval,
        idempotency_key="register-approval",
    )
    lease, request = _issue_inputs(plane, bundle)
    authorization = service.issue(
        bundle,
        authorization_id=stable_identifier("provider-test", "authorization"),
        approval_id=selected_approval.approval_id,
        budget=budget or _budget(),
        lease=lease,
        context_pack_hash=request.context_pack_hash,
        outbound_request_hash=request.outbound_request_hash(),
        ttl_seconds=ttl_seconds,
        idempotency_key="issue",
    )
    return plane, service, bundle, authorization


def _registry(
    service: ModelExecutionAuthorizationService,
    responses: list[ModelResponse],
    *,
    model_id: str = "fake-model",
    probe: CapabilityProbe | None = None,
    provider: FakeProvider | None = None,
) -> ProviderRegistry:
    registry = ProviderRegistry(authorization_gate=service)
    registry.register(
        "fake",
        provider=provider
        or FakeProvider(responses, model_id=model_id, capabilities=_AUTH_CAPABILITIES),
        probe=probe or StaticCapabilityProbe(_AUTH_CAPABILITIES),
        endpoint_class=EndpointClassV1.LOCAL,
        model_revision="fake-model-v1",
    )
    return registry


def _secret_failure_registry(
    service: ModelExecutionAuthorizationService,
) -> ProviderRegistry:
    provider = SecretFailingProvider()
    registry = ProviderRegistry(authorization_gate=service)
    registry.register(
        "fake",
        provider=provider,
        probe=StaticCapabilityProbe(_AUTH_CAPABILITIES),
        endpoint_class=EndpointClassV1.LOCAL,
        model_revision="fake-model-v1",
    )
    return registry


def _response(
    *,
    input_tokens: int = 2,
    output_tokens: int = 2,
    model_id: str = "fake-model",
) -> ModelResponse:
    return ModelResponse(
        provider_id="fake",
        model_id=model_id,
        text="by rfl",
        usage=TokenUsage(input_tokens=input_tokens, output_tokens=output_tokens),
    )


def test_control_plane_issued_authorization_allows_only_its_bound_provider(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    _plane, service, _bundle, authorization = _issue_registered_authorization(tmp_path, clock=clock)
    registry = _registry(service, [_response()])

    response = registry.generate(
        authorization,
        _bound_request(),
    )

    assert response.text == "by rfl"


def test_authorization_rejects_replaced_context_or_prompt_before_a_probe(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    _plane, service, _bundle, authorization = _issue_registered_authorization(tmp_path, clock=clock)
    probe = CountingProbe(_AUTH_CAPABILITIES)
    registry = _registry(service, [_response()], probe=probe)
    context_hash = _bound_request().context_pack_hash
    assert context_hash is not None

    with pytest.raises(PolicyViolation, match="authorization was denied"):
        registry.generate(
            authorization,
            ModelRequest(
                prompt="replace the frozen context with arbitrary text",
                max_input_tokens=4,
                max_output_tokens=4,
                context_pack_hash=context_hash,
            ),
        )
    with pytest.raises(PolicyViolation, match="authorization was denied"):
        registry.generate(
            authorization,
            ModelRequest(prompt="prove it", max_input_tokens=4, max_output_tokens=4),
        )

    assert probe.calls == 0


def test_replaced_worker_lease_cannot_reuse_model_authorization(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    plane, service, bundle, authorization = _issue_registered_authorization(tmp_path, clock=clock)
    lease = authorization.lease
    plane.leases.release(
        Lease(
            job_id=lease.bundle_id.value,
            holder_id=lease.worker_id,
            fencing_token=lease.fencing_token,
            expires_at=lease.expires_at,
        )
    )
    replacement = plane.leases.claim(
        bundle.bundle_id.value,
        "replacement-worker",
        ttl_seconds=7200,
    )
    assert replacement.fencing_token > lease.fencing_token
    probe = CountingProbe(_AUTH_CAPABILITIES)
    registry = _registry(service, [_response()], probe=probe)

    with pytest.raises(PolicyViolation, match="authorization was denied"):
        registry.generate(authorization, _bound_request())

    assert probe.calls == 0


def test_issue_refuses_authorization_that_outlives_its_current_lease(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    plane, service = _plane_and_service(tmp_path, clock)
    bundle = _signed_bundle(clock)
    plane.register_bundle(bundle, idempotency_key="register")
    approval = _approval(clock=clock)
    service.register_operator_approval(approval, idempotency_key="register-approval")
    lease = plane.claim(
        bundle.bundle_id.value,
        worker_id="short-lease-worker",
        ttl_seconds=60,
        idempotency_key="claim",
    ).lease
    request = _bound_request()
    assert request.context_pack_hash is not None

    with pytest.raises(ModelExecutionAuthorizationError, match="no later than its current worker"):
        service.issue(
            bundle,
            authorization_id=stable_identifier("provider-test", "lease-overrun"),
            approval_id=approval.approval_id,
            budget=_budget(),
            lease=lease,
            context_pack_hash=request.context_pack_hash,
            outbound_request_hash=request.outbound_request_hash(),
            ttl_seconds=61,
            idempotency_key="issue",
        )


def test_provider_model_mismatch_is_rejected_before_model_execution(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    _plane, service, _bundle, authorization = _issue_registered_authorization(tmp_path, clock=clock)
    registry = _registry(service, [_response()], model_id="other-model")

    with pytest.raises(PolicyViolation, match="authorization was denied"):
        registry.generate(
            authorization,
            _bound_request(),
        )


def test_tampered_authorization_budget_is_rejected_by_its_signature(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    _plane, service, _bundle, authorization = _issue_registered_authorization(tmp_path, clock=clock)
    tampered = authorization.model_copy(update={"budget": _budget(attempts=1)})
    registry = _registry(service, [_response()])

    with pytest.raises(PolicyViolation, match="authorization was denied"):
        registry.generate(
            tampered,
            _bound_request(),
        )


def test_expired_authorization_is_rejected(tmp_path: Path) -> None:
    state, clock = _clock_state()
    _plane, service, _bundle, authorization = _issue_registered_authorization(tmp_path, clock=clock)
    state["now"] += timedelta(seconds=301)
    probe = CountingProbe(_AUTH_CAPABILITIES)
    registry = _registry(service, [_response()], probe=probe)

    with pytest.raises(PolicyViolation, match="authorization was denied"):
        registry.generate(
            authorization,
            _bound_request(),
        )
    assert probe.calls == 0


def test_revoked_authorization_is_rejected_after_restart(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    _plane, service, _bundle, authorization = _issue_registered_authorization(tmp_path, clock=clock)
    service.revoke(
        authorization.authorization_id,
        reason="endpoint_compromised",
        idempotency_key="revoke",
    )
    restarted = ModelExecutionAuthorizationService(
        control_plane=_restart_plane(tmp_path, clock),
        signer=HmacAttestationSignerV1(_MODEL_KEY, clock=clock),
        verifier=_verifier(clock),
        clock=clock,
    )
    registry = _registry(restarted, [_response()])

    with pytest.raises(PolicyViolation, match="authorization was denied"):
        registry.generate(
            authorization,
            _bound_request(),
        )


def test_attempt_budget_is_durable_across_authorization_service_restart(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    _plane, service, _bundle, authorization = _issue_registered_authorization(
        tmp_path,
        clock=clock,
        budget=_budget(attempts=1),
    )
    request = _bound_request()
    _registry(service, [_response()]).generate(authorization, request)
    restarted = ModelExecutionAuthorizationService(
        control_plane=_restart_plane(tmp_path, clock),
        signer=HmacAttestationSignerV1(_MODEL_KEY, clock=clock),
        verifier=_verifier(clock),
        clock=clock,
    )

    with pytest.raises(PolicyViolation, match="authorization was denied"):
        _registry(restarted, [_response()]).generate(authorization, request)


def test_provider_circuit_is_durable_secret_free_and_recovers_after_cooldown(
    tmp_path: Path,
) -> None:
    state, clock = _clock_state()
    plane, service, _bundle, authorization = _issue_registered_authorization(
        tmp_path,
        clock=clock,
        budget=_budget(attempts=4),
        provider_failure_threshold=2,
        provider_failure_cooldown_seconds=60,
    )
    request = _bound_request()

    for _ in range(2):
        with pytest.raises(ProviderResponseError) as error:
            _secret_failure_registry(service).generate(authorization, request)
        assert _PROVIDER_SECRET_MARKER not in str(error.value)
        assert error.value.__cause__ is None

    with plane.events.connection() as connection:
        abandoned = connection.execute(
            """
            SELECT reason
            FROM model_execution_authorization_ledger
            WHERE event_type = 'abandoned'
            ORDER BY event_sequence
            """
        ).fetchall()
        health = connection.execute(
            """
            SELECT event_type, failure_code, binding_json
            FROM model_execution_provider_health_ledger
            ORDER BY event_sequence
            """
        ).fetchall()
        database_dump = "\n".join(connection.iterdump())
    assert [str(row["reason"]) for row in abandoned] == [
        ProviderFailureCodeV1.GENERATION_FAILED,
        ProviderFailureCodeV1.GENERATION_FAILED,
    ]
    assert [(str(row["event_type"]), str(row["failure_code"])) for row in health] == [
        ("failure", ProviderFailureCodeV1.GENERATION_FAILED),
        ("failure", ProviderFailureCodeV1.GENERATION_FAILED),
    ]
    assert all(
        '"schema_version":"autolean.provider-circuit-binding.v1"' in row["binding_json"]
        for row in health
    )
    assert _PROVIDER_SECRET_MARKER not in database_dump
    with (
        pytest.raises(sqlite3.IntegrityError, match="append-only"),
        plane.events.write_transaction() as connection,
    ):
        connection.execute(
            "UPDATE model_execution_provider_health_ledger SET failure_code = 'changed'"
        )

    restarted = _restart_service(
        tmp_path,
        clock,
        provider_failure_threshold=2,
        provider_failure_cooldown_seconds=60,
    )
    with pytest.raises(ModelExecutionAuthorizationError, match="circuit is open"):
        restarted.reserve(
            authorization,
            provider=authorization.provider,
            requested_input_tokens=request.max_input_tokens,
            requested_output_tokens=request.max_output_tokens,
            context_pack_hash=request.context_pack_hash,
            outbound_request_hash=request.outbound_request_hash(),
        )
    blocked_probe = CountingProbe(_AUTH_CAPABILITIES)
    with pytest.raises(PolicyViolation, match="authorization was denied"):
        _registry(restarted, [_response()], probe=blocked_probe).generate(
            authorization,
            request,
        )
    assert blocked_probe.calls == 0

    state["now"] += timedelta(seconds=60)
    response = _registry(restarted, [_response()]).generate(authorization, request)
    assert response.text == "by rfl"


def test_successful_settlement_resets_consecutive_provider_failures(tmp_path: Path) -> None:
    state, clock = _clock_state()
    _plane, service, _bundle, authorization = _issue_registered_authorization(
        tmp_path,
        clock=clock,
        budget=_budget(attempts=5),
        provider_failure_threshold=2,
        provider_failure_cooldown_seconds=1,
    )
    request = _bound_request()
    for _ in range(2):
        with pytest.raises(ProviderResponseError):
            _secret_failure_registry(service).generate(authorization, request)

    state["now"] += timedelta(seconds=1)
    assert _registry(service, [_response()]).generate(authorization, request).text == "by rfl"
    with pytest.raises(ProviderResponseError):
        _secret_failure_registry(service).generate(authorization, request)

    assert _registry(service, [_response()]).generate(authorization, request).text == "by rfl"


def test_provider_circuit_isolated_by_complete_binding(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    plane, service, bundle, authorization_a = _issue_registered_authorization(
        tmp_path,
        clock=clock,
        budget=_budget(attempts=3),
        provider_failure_threshold=1,
        provider_failure_cooldown_seconds=60,
    )
    request = _bound_request()
    with pytest.raises(ProviderResponseError):
        _secret_failure_registry(service).generate(authorization_a, request)

    approval_b = _approval(clock=clock, model_id="fake-model-b")
    service.register_operator_approval(
        approval_b,
        idempotency_key="register-approval-b",
    )
    lease_binding = authorization_a.lease
    authorization_b = service.issue(
        bundle,
        authorization_id=stable_identifier("provider-test", "authorization-b"),
        approval_id=approval_b.approval_id,
        budget=_budget(),
        lease=Lease(
            job_id=lease_binding.bundle_id.value,
            holder_id=lease_binding.worker_id,
            fencing_token=lease_binding.fencing_token,
            expires_at=lease_binding.expires_at,
        ),
        context_pack_hash=request.context_pack_hash,
        outbound_request_hash=request.outbound_request_hash(),
        ttl_seconds=300,
        idempotency_key="issue-b",
    )
    assert (
        _registry(
            service,
            [_response(model_id="fake-model-b")],
            model_id="fake-model-b",
        )
        .generate(authorization_b, request)
        .text
        == "by rfl"
    )

    blocked_probe = CountingProbe(_AUTH_CAPABILITIES)
    with pytest.raises(PolicyViolation, match="authorization was denied"):
        _registry(service, [_response()], probe=blocked_probe).generate(
            authorization_a,
            request,
        )
    assert blocked_probe.calls == 0

    with plane.events.connection() as connection:
        binding_count = connection.execute(
            """
            SELECT COUNT(DISTINCT binding_json) AS count
            FROM model_execution_provider_health_ledger
            """
        ).fetchone()
    assert binding_count is not None
    assert int(binding_count["count"]) == 2


def test_local_policy_failure_code_does_not_advance_provider_circuit(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    plane, service, _bundle, authorization = _issue_registered_authorization(
        tmp_path,
        clock=clock,
        budget=_budget(attempts=2),
        provider_failure_threshold=1,
        provider_failure_cooldown_seconds=60,
    )
    request = _bound_request()
    reservation = service.reserve(
        authorization,
        provider=authorization.provider,
        requested_input_tokens=request.max_input_tokens,
        requested_output_tokens=request.max_output_tokens,
        context_pack_hash=request.context_pack_hash,
        outbound_request_hash=request.outbound_request_hash(),
    )
    with pytest.raises(ModelExecutionAuthorizationError, match="stable V1 code"):
        service.abandon(
            reservation,
            failure_code="raw-provider-error-must-not-be-stored",
        )
    service.abandon(
        reservation,
        failure_code=ProviderFailureCodeV1.LOCAL_POLICY_REJECTED,
    )
    with plane.events.connection() as connection:
        health_count = connection.execute(
            "SELECT COUNT(*) AS count FROM model_execution_provider_health_ledger"
        ).fetchone()
    assert health_count is not None
    assert int(health_count["count"]) == 0
    assert _registry(service, [_response()]).generate(authorization, request).text == "by rfl"


def test_provider_circuit_policy_has_hard_configuration_bounds(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    with pytest.raises(ModelExecutionAuthorizationError, match="between 1 and 100"):
        _plane_and_service(
            tmp_path / "threshold-low",
            clock,
            provider_failure_threshold=0,
        )
    with pytest.raises(ModelExecutionAuthorizationError, match="between 1 and 100"):
        _plane_and_service(
            tmp_path / "threshold-high",
            clock,
            provider_failure_threshold=101,
        )
    with pytest.raises(ModelExecutionAuthorizationError, match="between 1 and 86400"):
        _plane_and_service(
            tmp_path / "cooldown-low",
            clock,
            provider_failure_cooldown_seconds=0.999,
        )
    with pytest.raises(ModelExecutionAuthorizationError, match="between 1 and 86400"):
        _plane_and_service(
            tmp_path / "cooldown-high",
            clock,
            provider_failure_cooldown_seconds=86400.001,
        )


def test_cost_budget_is_reserved_before_an_external_model_call(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    pricing = ModelExecutionPricingV1(
        input_microusd_per_token=1,
        output_microusd_per_token=2,
    )
    _plane, service, _bundle, authorization = _issue_registered_authorization(
        tmp_path,
        clock=clock,
        approval=_approval(clock=clock, pricing=pricing),
        budget=_budget(cost=7),
    )
    registry = _registry(service, [_response()])

    with pytest.raises(PolicyViolation, match="authorization was denied"):
        registry.generate(
            authorization,
            _bound_request(),
        )


def test_unapproved_external_egress_cannot_receive_a_model_capability(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    plane, service = _plane_and_service(tmp_path, clock)
    bundle = _signed_bundle(clock)
    plane.register_bundle(bundle, idempotency_key="register")
    approval = _approval(
        clock=clock,
        endpoint_class=EndpointClassV1.APPROVED_EXTERNAL,
    )
    service.register_operator_approval(approval, idempotency_key="register-external-approval")
    lease, request = _issue_inputs(plane, bundle, worker_id="external-worker")

    with pytest.raises(ModelExecutionAuthorizationError, match="source rights"):
        service.issue(
            bundle,
            authorization_id=stable_identifier("provider-test", "external-authorization"),
            approval_id=approval.approval_id,
            budget=_budget(),
            lease=lease,
            context_pack_hash=request.context_pack_hash,
            outbound_request_hash=request.outbound_request_hash(),
            ttl_seconds=300,
            idempotency_key="issue-external",
        )


def test_issue_requires_an_operator_registered_provider_approval(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    plane, service = _plane_and_service(tmp_path, clock)
    bundle = _signed_bundle(clock)
    plane.register_bundle(bundle, idempotency_key="register")
    lease, request = _issue_inputs(plane, bundle, worker_id="unregistered-worker")

    with pytest.raises(ModelExecutionAuthorizationError, match="approval is not registered"):
        service.issue(
            bundle,
            authorization_id=stable_identifier("provider-test", "unregistered-authorization"),
            approval_id=_approval(clock=clock).approval_id,
            budget=_budget(),
            lease=lease,
            context_pack_hash=request.context_pack_hash,
            outbound_request_hash=request.outbound_request_hash(),
            ttl_seconds=300,
            idempotency_key="issue-unregistered",
        )


def test_operator_approval_registry_is_immutable_and_survives_restart(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    plane, service = _plane_and_service(tmp_path, clock)
    approval = _approval(clock=clock)
    service.register_operator_approval(approval, idempotency_key="register-approval")

    with (
        pytest.raises(sqlite3.IntegrityError, match="immutable"),
        plane.events.write_transaction() as connection,
    ):
        connection.execute("UPDATE model_execution_provider_approvals SET approval_hash = 'bad'")

    bundle = _signed_bundle(clock)
    plane.register_bundle(bundle, idempotency_key="register-bundle")
    lease, request = _issue_inputs(plane, bundle, worker_id="restart-worker")
    restarted = ModelExecutionAuthorizationService(
        control_plane=_restart_plane(tmp_path, clock),
        signer=HmacAttestationSignerV1(_MODEL_KEY, clock=clock),
        verifier=_verifier(clock),
        clock=clock,
    )
    authorization = restarted.issue(
        bundle,
        authorization_id=stable_identifier("provider-test", "restart-authorization"),
        approval_id=approval.approval_id,
        budget=_budget(),
        lease=lease,
        context_pack_hash=request.context_pack_hash,
        outbound_request_hash=request.outbound_request_hash(),
        ttl_seconds=300,
        idempotency_key="issue-after-restart",
    )

    assert authorization.approval_hash() == approval.approval_hash()


def test_operator_approval_registration_rejects_a_changed_snapshot_for_the_same_id(
    tmp_path: Path,
) -> None:
    _state, clock = _clock_state()
    _plane, service = _plane_and_service(tmp_path, clock)
    approval = _approval(clock=clock)
    service.register_operator_approval(approval, idempotency_key="register-original")
    changed = approval.model_copy(
        update={
            "pricing": ModelExecutionPricingV1(input_microusd_per_token=1),
        }
    )

    with pytest.raises(ModelExecutionAuthorizationError, match="different immutable record"):
        service.register_operator_approval(changed, idempotency_key="register-changed")


def test_authorization_ttl_respects_the_default_one_hour_cap(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    _plane, _service, _bundle, authorization = _issue_registered_authorization(
        tmp_path,
        clock=clock,
        ttl_seconds=60.0 * 60.0,
    )
    assert authorization.expires_at - authorization.issued_at == timedelta(hours=1)

    plane, service = _plane_and_service(tmp_path / "excess", clock)
    bundle = _signed_bundle(clock)
    plane.register_bundle(bundle, idempotency_key="register")
    approval = _approval(clock=clock)
    service.register_operator_approval(approval, idempotency_key="register-approval")
    lease, request = _issue_inputs(plane, bundle, worker_id="overlong-worker")
    with pytest.raises(ModelExecutionAuthorizationError, match="configured maximum"):
        service.issue(
            bundle,
            authorization_id=stable_identifier("provider-test", "overlong-authorization"),
            approval_id=approval.approval_id,
            budget=_budget(),
            lease=lease,
            context_pack_hash=request.context_pack_hash,
            outbound_request_hash=request.outbound_request_hash(),
            ttl_seconds=60.0 * 60.0 + 0.001,
            idempotency_key="issue-overlong",
        )


def test_operator_can_only_reduce_the_authorization_ttl_limit(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    _plane, _service, _bundle, authorization = _issue_registered_authorization(
        tmp_path,
        clock=clock,
        ttl_seconds=60,
        max_ttl_seconds=60,
    )
    assert authorization.expires_at - authorization.issued_at == timedelta(seconds=60)

    plane, service = _plane_and_service(tmp_path / "excess", clock, max_ttl_seconds=60)
    bundle = _signed_bundle(clock)
    plane.register_bundle(bundle, idempotency_key="register")
    approval = _approval(clock=clock)
    service.register_operator_approval(approval, idempotency_key="register-approval")
    lease, request = _issue_inputs(plane, bundle, worker_id="reduced-ttl-worker")
    with pytest.raises(ModelExecutionAuthorizationError, match="configured maximum"):
        service.issue(
            bundle,
            authorization_id=stable_identifier("provider-test", "too-long-for-policy"),
            approval_id=approval.approval_id,
            budget=_budget(),
            lease=lease,
            context_pack_hash=request.context_pack_hash,
            outbound_request_hash=request.outbound_request_hash(),
            ttl_seconds=60.001,
            idempotency_key="issue-over-policy",
        )

    with pytest.raises(ModelExecutionAuthorizationError, match="one-hour hard cap"):
        _plane_and_service(tmp_path / "invalid-config", clock, max_ttl_seconds=3601)


def test_forbidden_provider_identifier_cannot_be_approved() -> None:
    with pytest.raises(ValueError, match="Anthropic and Claude"):
        ModelExecutionProviderBindingV1(
            registry_name="fake",
            provider_id="fake",
            model_id="claude-model",
            model_revision="fixture-v1",
            endpoint_class=EndpointClassV1.LOCAL,
            configuration_hash=FakeProvider(
                [],
                capabilities=ProviderCapabilities.of(Capability.TEXT_GENERATION),
            ).configuration_hash,
        )


def test_model_work_uses_the_existing_authorization_wire_and_registry_path(
    tmp_path: Path,
) -> None:
    _state, clock = _clock_state()
    plane, service = _plane_and_service(tmp_path, clock)
    request = _bound_request()
    work = _model_work(request)
    admission = _model_work_admission(work, clock)
    approval = _approval(clock=clock)
    service.register_operator_approval(approval, idempotency_key="register-approval")
    assert (
        service.register_model_work(
            work,
            admission=admission,
        )
        == work
    )
    assert (
        service.register_model_work(
            work,
            admission=admission,
        )
        == work
    )
    assert (
        service.register_model_work(
            work,
            admission=admission,
        )
        == work
    )
    lease = service.claim_model_work(
        work,
        ttl_seconds=600,
    )
    authorization = service.issue_model_work(
        work,
        approval_id=approval.approval_id,
        budget=_budget(attempts=1),
        lease=lease,
        ttl_seconds=300,
    )

    assert authorization.contract_id == work.work_contract_id
    assert authorization.contract_hash == work.semantic_hash()
    assert authorization.bundle_hash == work.handoff_hash()
    assert _registry(service, [_response()]).generate(authorization, request).text == "by rfl"
    with plane.events.connection() as connection:
        stored = connection.execute(
            """
            SELECT bundle_hash, admission_attestation_hash, admission_attestation_json
            FROM model_execution_work_bundles
            WHERE bundle_id = ?
            """,
            (work.bundle_id.value,),
        ).fetchone()
    assert stored is not None
    assert stored["bundle_hash"] == work.handoff_hash().value
    assert (
        stored["admission_attestation_hash"]
        == digest_model(
            HashKindV1.ATTESTATION,
            admission,
        ).value
    )
    assert AttestationV1.model_validate_json(stored["admission_attestation_json"]) == admission


def test_model_work_registration_fails_closed_without_admission_verifier(
    tmp_path: Path,
) -> None:
    _state, clock = _clock_state()
    plane, _service = _plane_and_service(tmp_path, clock)
    service = ModelExecutionAuthorizationService(
        control_plane=plane,
        signer=HmacAttestationSignerV1(_MODEL_KEY, clock=clock),
        verifier=_verifier(clock),
        clock=clock,
    )
    work = _model_work(_bound_request())

    with pytest.raises(ModelExecutionAuthorizationError, match="trusted admission verifier"):
        service.register_model_work(
            work,
            admission=_model_work_admission(work, clock),
        )


def test_model_work_registration_reverifies_admission_inside_insert_transaction(
    tmp_path: Path,
) -> None:
    _state, clock = _clock_state()
    plane, _service = _plane_and_service(tmp_path, clock)
    admission_verifier = RejectVerification(_verifier(clock), reject_call=2)
    service = ModelExecutionAuthorizationService(
        control_plane=plane,
        signer=HmacAttestationSignerV1(_MODEL_KEY, clock=clock),
        verifier=_verifier(clock),
        admission_verifier=admission_verifier,
        clock=clock,
    )
    work = _model_work(_bound_request())

    with pytest.raises(ModelExecutionAuthorizationError, match="attestation was rejected"):
        service.register_model_work(
            work,
            admission=_model_work_admission(work, clock),
        )

    assert admission_verifier.calls == 2
    with plane.events.connection() as connection:
        count = connection.execute("SELECT COUNT(*) FROM model_execution_work_bundles").fetchone()
    assert count is not None
    assert int(count[0]) == 0


def test_model_work_issue_reverifies_parent_inside_insert_transaction(
    tmp_path: Path,
) -> None:
    _state, clock = _clock_state()
    plane, _service = _plane_and_service(tmp_path, clock)
    admission_verifier = RejectVerification(_verifier(clock), reject_call=5)
    service = ModelExecutionAuthorizationService(
        control_plane=plane,
        signer=HmacAttestationSignerV1(_MODEL_KEY, clock=clock),
        verifier=_verifier(clock),
        admission_verifier=admission_verifier,
        clock=clock,
    )
    work = _model_work(_bound_request())
    approval = _approval(clock=clock)
    service.register_operator_approval(approval, idempotency_key="transaction-issue-approval")
    service.register_model_work(
        work,
        admission=_model_work_admission(work, clock),
    )
    lease = service.claim_model_work(work, ttl_seconds=600)

    with pytest.raises(ModelExecutionAuthorizationError, match="attestation was rejected"):
        service.issue_model_work(
            work,
            approval_id=approval.approval_id,
            budget=_budget(attempts=1),
            lease=lease,
            ttl_seconds=300,
        )

    assert admission_verifier.calls == 5
    with plane.events.connection() as connection:
        count = connection.execute("SELECT COUNT(*) FROM model_execution_authorizations").fetchone()
    assert count is not None
    assert int(count[0]) == 0


def test_legacy_unsigned_model_work_row_is_not_promoted_during_schema_migration(
    tmp_path: Path,
) -> None:
    _state, clock = _clock_state()
    database = tmp_path / "control.db"
    verifier = _verifier(clock)
    plane = ControlPlane(
        events=EventStore(database, clock=clock),
        leases=LeaseStore(database, clock=clock),
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        attestation_verifier=verifier,
        allow_test_only_unreviewed_bundles=True,
    )
    work = _model_work(_bound_request())
    with plane.events.connection() as connection:
        connection.execute(
            """
            CREATE TABLE model_execution_work_bundles (
                bundle_id TEXT PRIMARY KEY,
                bundle_hash TEXT NOT NULL,
                bundle_json TEXT NOT NULL,
                registration_request_hash TEXT NOT NULL,
                registered_at TEXT NOT NULL
            ) WITHOUT ROWID
            """
        )
        connection.execute(
            """
            INSERT INTO model_execution_work_bundles (
                bundle_id, bundle_hash, bundle_json,
                registration_request_hash, registered_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                work.bundle_id.value,
                work.handoff_hash().value,
                work.model_dump_json(),
                "legacy-unsigned-request",
                "2026-01-01T00:00:00.000000Z",
            ),
        )
    service = ModelExecutionAuthorizationService(
        control_plane=plane,
        signer=HmacAttestationSignerV1(_MODEL_KEY, clock=clock),
        verifier=verifier,
        admission_verifier=verifier,
        clock=clock,
    )

    with pytest.raises(
        ModelExecutionAuthorizationError,
        match="bundle or admission is corrupt",
    ):
        service.claim_model_work(
            work,
            ttl_seconds=600,
        )


def test_formalization_issue_remains_independent_of_model_work_admission_verifier(
    tmp_path: Path,
) -> None:
    _state, clock = _clock_state()
    plane, _service = _plane_and_service(tmp_path, clock)
    service = ModelExecutionAuthorizationService(
        control_plane=plane,
        signer=HmacAttestationSignerV1(_MODEL_KEY, clock=clock),
        verifier=_verifier(clock),
        clock=clock,
    )
    bundle = _signed_bundle(clock)
    plane.register_bundle(bundle, idempotency_key="register-theorem-without-admission")
    approval = _approval(clock=clock, model_id="theorem-no-admission")
    service.register_operator_approval(
        approval,
        idempotency_key="register-theorem-no-admission-approval",
    )
    lease, request = _issue_inputs(
        plane,
        bundle,
        worker_id="theorem-no-admission-worker",
    )

    authorization = service.issue(
        bundle,
        authorization_id=stable_identifier(
            "provider-test",
            "theorem-without-model-work-admission",
        ),
        approval_id=approval.approval_id,
        budget=_budget(),
        lease=lease,
        context_pack_hash=request.context_pack_hash,
        outbound_request_hash=request.outbound_request_hash(),
        ttl_seconds=300,
        idempotency_key="issue-theorem-without-model-work-admission",
    )

    assert authorization.bundle_id == bundle.bundle_id
    assert authorization.subject_kind is ModelExecutionSubjectKindV1.THEOREM
    assert authorization.parent_admission_hash is None
    assert authorization.parent_admission_expires_at is None
    assert (
        _registry(
            service,
            [_response(model_id="theorem-no-admission")],
            model_id="theorem-no-admission",
        )
        .generate(authorization, request)
        .text
        == "by rfl"
    )


def test_model_work_registration_rejects_wrong_purpose_and_execution_key(
    tmp_path: Path,
) -> None:
    _state, clock = _clock_state()
    _plane, service = _plane_and_service(tmp_path, clock)
    work = _model_work(_bound_request())
    wrong = _model_work_admission(
        work,
        clock,
        key=_MODEL_KEY,
        purpose=AttestationPurposeV1.MODEL_EXECUTION,
    )

    with pytest.raises(ModelExecutionAuthorizationError, match="attestation was rejected"):
        service.register_model_work(
            work,
            admission=wrong,
        )


def test_model_work_registration_rejects_untrusted_admission_key(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    _plane, service = _plane_and_service(tmp_path, clock)
    work = _model_work(_bound_request())
    untrusted_key = HmacAttestationKeyV1(
        key_id="provider-test-untrusted-admission-v1",
        secret=b"provider-test-untrusted-admission-material-0123",
        allowed_purposes=frozenset({AttestationPurposeV1.MODEL_WORK_ADMISSION}),
    )

    with pytest.raises(ModelExecutionAuthorizationError, match="attestation was rejected"):
        service.register_model_work(
            work,
            admission=_model_work_admission(work, clock, key=untrusted_key),
        )


def test_model_work_registration_rejects_caller_label_as_admission_nonce(
    tmp_path: Path,
) -> None:
    _state, clock = _clock_state()
    _plane, service = _plane_and_service(tmp_path, clock)
    work = _model_work(_bound_request())

    with pytest.raises(
        ModelExecutionAuthorizationError,
        match="signer-generated 48-digit hex",
    ):
        service.register_model_work(
            work,
            admission=_model_work_admission(
                work,
                clock,
                nonce="caller-chosen-admission-nonce",
            ),
        )


def test_model_work_registration_rejects_wrong_payload_and_cross_bundle_reuse(
    tmp_path: Path,
) -> None:
    _state, clock = _clock_state()
    _plane, service = _plane_and_service(tmp_path, clock)
    work = _model_work(_bound_request())
    other_case_hash = model_work_case_hash("provider-test-case-2")
    other = work.model_copy(
        update={
            "bundle_id": model_work_bundle_id(
                run_hash=work.run_hash,
                cell_hash=work.cell_hash,
                case_hash=other_case_hash,
                repetition=work.repetition,
                role=work.role,
            ),
            "case_hash": other_case_hash,
        }
    )
    admission = _model_work_admission(work, clock)

    with pytest.raises(
        ModelExecutionAuthorizationError,
        match=r"evidence identity|attestation was rejected",
    ):
        service.register_model_work(
            other,
            admission=admission,
        )
    with pytest.raises(
        ModelExecutionAuthorizationError,
        match=r"evidence identity|attestation was rejected",
    ):
        service.register_model_work(
            work,
            admission=_model_work_admission(other, clock),
        )


@pytest.mark.parametrize("clock_offset_seconds", [-120, 120])
def test_model_work_registration_rejects_expired_or_future_attestation(
    tmp_path: Path,
    clock_offset_seconds: int,
) -> None:
    _state, clock = _clock_state()
    _plane, service = _plane_and_service(tmp_path, clock)
    work = _model_work(_bound_request())

    def shifted_clock() -> datetime:
        return clock() + timedelta(seconds=clock_offset_seconds)

    admission = _model_work_admission(
        work,
        shifted_clock,
        ttl_seconds=60,
    )
    with pytest.raises(ModelExecutionAuthorizationError, match="attestation was rejected"):
        service.register_model_work(
            work,
            admission=admission,
        )


def test_model_work_claim_and_issue_revalidate_expiry(tmp_path: Path) -> None:
    state, clock = _clock_state()
    _plane, service = _plane_and_service(tmp_path, clock)
    work = _model_work(_bound_request())
    approval = _approval(clock=clock)
    service.register_operator_approval(approval, idempotency_key="register-expiry-approval")
    service.register_model_work(
        work,
        admission=_model_work_admission(work, clock, ttl_seconds=60),
    )
    lease = service.claim_model_work(
        work,
        ttl_seconds=600,
    )
    state["now"] += timedelta(seconds=61)

    with pytest.raises(ModelExecutionAuthorizationError, match="attestation was rejected"):
        service.claim_model_work(
            work,
            ttl_seconds=600,
        )
    with pytest.raises(ModelExecutionAuthorizationError, match="attestation was rejected"):
        service.issue_model_work(
            work,
            approval_id=approval.approval_id,
            budget=_budget(attempts=1),
            lease=lease,
            ttl_seconds=300,
        )


def test_model_work_claim_revalidates_admission_key_revocation(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    plane, service = _plane_and_service(tmp_path, clock)
    work = _model_work(_bound_request())
    service.register_model_work(
        work,
        admission=_model_work_admission(work, clock),
    )
    lease = service.claim_model_work(
        work,
        ttl_seconds=600,
    )
    revoked_key = HmacAttestationKeyV1(
        key_id=_MODEL_WORK_ADMISSION_KEY.key_id,
        secret=_MODEL_WORK_ADMISSION_KEY.secret,
        allowed_purposes=_MODEL_WORK_ADMISSION_KEY.allowed_purposes,
        revoked=True,
    )
    restarted = ModelExecutionAuthorizationService(
        control_plane=plane,
        signer=HmacAttestationSignerV1(_MODEL_KEY, clock=clock),
        verifier=_verifier(clock),
        admission_verifier=HmacAttestationVerifierV1(
            {revoked_key.key_id: revoked_key},
            clock=clock,
        ),
        clock=clock,
    )

    with pytest.raises(ModelExecutionAuthorizationError, match="attestation was rejected"):
        restarted.claim_model_work(
            work,
            ttl_seconds=600,
        )
    with pytest.raises(ModelExecutionAuthorizationError, match="attestation was rejected"):
        restarted.issue_model_work(
            work,
            approval_id=stable_identifier(
                "provider-test",
                "missing-for-revocation",
            ),
            budget=_budget(attempts=1),
            lease=lease,
            ttl_seconds=300,
        )


def test_model_work_registration_identity_includes_exact_admission(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    _plane, service = _plane_and_service(tmp_path, clock)
    work = _model_work(_bound_request())
    original = _model_work_admission(work, clock, nonce="a" * 48)
    replacement = _model_work_admission(work, clock, nonce="b" * 48)
    service.register_model_work(
        work,
        admission=original,
    )
    assert service.register_model_work(work, admission=original) == work

    with pytest.raises(ModelExecutionAuthorizationError, match="different immutable work"):
        service.register_model_work(
            work,
            admission=replacement,
        )


def test_model_work_preflight_is_read_only_and_checks_existing_exact_admission(
    tmp_path: Path,
) -> None:
    _state, clock = _clock_state()
    plane, service = _plane_and_service(tmp_path, clock)
    work = _model_work(_bound_request())
    admission = _model_work_admission(work, clock, nonce="a" * 48)
    service.register_model_work(work, admission=admission)
    with plane.events.connection() as connection:
        before = "\n".join(connection.iterdump())

    service.preflight_model_work_registration(
        work,
        admission=admission,
        required_validity_seconds=300,
    )
    with pytest.raises(ModelExecutionAuthorizationError, match="differs from its immutable"):
        service.preflight_model_work_registration(
            work,
            admission=_model_work_admission(work, clock, nonce="b" * 48),
            required_validity_seconds=300,
        )

    with plane.events.connection() as connection:
        after = "\n".join(connection.iterdump())
    assert after == before


def test_model_work_claim_detects_persisted_admission_tamper(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    plane, service = _plane_and_service(tmp_path, clock)
    work = _model_work(_bound_request())
    service.register_model_work(
        work,
        admission=_model_work_admission(work, clock),
    )
    with plane.events.write_transaction() as connection:
        connection.execute("DROP TRIGGER model_execution_work_bundles_forbid_update")
        connection.execute(
            """
            UPDATE model_execution_work_bundles
            SET admission_attestation_hash = ?
            WHERE bundle_id = ?
            """,
            ("0" * 64, work.bundle_id.value),
        )

    with pytest.raises(ModelExecutionAuthorizationError, match="admission hash is corrupt"):
        service.claim_model_work(
            work,
            ttl_seconds=600,
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("role", ModelWorkRoleV1.FIDELITY_REVIEWER),
        ("case_hash", model_work_case_hash("provider-test-replaced-case")),
        ("work_item_hash", model_work_item_hash("4" * 64)),
        ("request_hash", digest_text(HashKindV1.PROMPT, "replaced-prompt")),
    ],
)
def test_registered_model_work_rejects_trial_binding_replacement(
    tmp_path: Path,
    field: str,
    replacement: object,
) -> None:
    _state, clock = _clock_state()
    _plane, service = _plane_and_service(tmp_path, clock)
    work = _model_work(_bound_request())
    service.register_model_work(
        work,
        admission=_model_work_admission(work, clock),
    )
    changed = _replace_model_work_trial_binding(
        work,
        field=field,
        replacement=replacement,
    )

    with pytest.raises(
        ModelExecutionAuthorizationError,
        match=r"registered immutable|not registered",
    ):
        service.claim_model_work(
            changed,
            ttl_seconds=600,
        )


def test_model_work_issue_rejects_caller_bundle_substitution(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    _plane, service = _plane_and_service(tmp_path, clock)
    work = _model_work(_bound_request())
    service.register_model_work(
        work,
        admission=_model_work_admission(work, clock),
    )
    lease = service.claim_model_work(
        work,
        ttl_seconds=600,
    )
    substituted = work.model_copy(
        update={
            "request_hash": digest_text(
                HashKindV1.PROMPT,
                "caller-substituted-request",
            )
        }
    )

    with pytest.raises(ModelExecutionAuthorizationError, match="registered immutable"):
        service.issue_model_work(
            substituted,
            approval_id=stable_identifier(
                "provider-test",
                "missing-for-substitution",
            ),
            budget=_budget(attempts=1),
            lease=lease,
            ttl_seconds=300,
        )


@pytest.mark.parametrize(
    "overall_decision",
    [PermissionDecisionV1.DENY, PermissionDecisionV1.UNKNOWN],
)
def test_model_work_rights_deny_or_unknown_cannot_issue(
    tmp_path: Path,
    overall_decision: PermissionDecisionV1,
) -> None:
    _state, clock = _clock_state()
    _plane, service = _plane_and_service(tmp_path, clock)
    request = _bound_request()
    work = _model_work(request, overall_decision=overall_decision)
    approval = _approval(clock=clock)
    service.register_operator_approval(approval, idempotency_key="register-approval")
    service.register_model_work(
        work,
        admission=_model_work_admission(work, clock),
    )
    lease = service.claim_model_work(work, ttl_seconds=600)

    with pytest.raises(ModelExecutionAuthorizationError, match="source rights"):
        service.issue_model_work(
            work,
            approval_id=approval.approval_id,
            budget=_budget(attempts=1),
            lease=lease,
            ttl_seconds=300,
        )


def test_model_work_requires_registration_and_current_matching_lease(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    plane, service = _plane_and_service(tmp_path, clock)
    work = _model_work(_bound_request())

    with pytest.raises(ModelExecutionAuthorizationError, match="not registered"):
        service.claim_model_work(work, ttl_seconds=600)

    service.register_model_work(
        work,
        admission=_model_work_admission(work, clock),
    )
    lease = service.claim_model_work(work, ttl_seconds=600)
    plane.leases.release(lease)
    with pytest.raises(ModelExecutionAuthorizationError, match="stale or expired"):
        service.issue_model_work(
            work,
            approval_id=stable_identifier("provider-test", "missing-approval"),
            budget=_budget(attempts=1),
            lease=lease,
            ttl_seconds=300,
        )


@pytest.mark.parametrize(
    "model_egress",
    [PermissionDecisionV1.DENY, PermissionDecisionV1.UNKNOWN],
)
def test_model_work_endpoint_class_must_be_permitted_by_source_rights(
    tmp_path: Path,
    model_egress: PermissionDecisionV1,
) -> None:
    _state, clock = _clock_state()
    _plane, service = _plane_and_service(tmp_path, clock)
    request = _bound_request()
    work = _model_work(
        request,
        model_egress=model_egress,
        allowed_endpoint_classes=(EndpointClassV1.APPROVED_EXTERNAL,),
    )
    approval = _approval(
        clock=clock,
        endpoint_class=EndpointClassV1.APPROVED_EXTERNAL,
    )
    service.register_operator_approval(approval, idempotency_key="register-approval")
    service.register_model_work(
        work,
        admission=_model_work_admission(work, clock),
    )
    lease = service.claim_model_work(work, ttl_seconds=600)

    with pytest.raises(ModelExecutionAuthorizationError, match="source rights"):
        service.issue_model_work(
            work,
            approval_id=approval.approval_id,
            budget=_budget(attempts=1),
            lease=lease,
            ttl_seconds=300,
        )


def test_model_work_attempt_budget_cannot_be_reused(tmp_path: Path) -> None:
    _state, clock = _clock_state()
    _plane, service = _plane_and_service(tmp_path, clock)
    request = _bound_request()
    work = _model_work(request)
    approval = _approval(clock=clock)
    service.register_operator_approval(approval, idempotency_key="register-approval")
    service.register_model_work(
        work,
        admission=_model_work_admission(work, clock),
    )
    lease = service.claim_model_work(work, ttl_seconds=600)
    authorization = service.issue_model_work(
        work,
        approval_id=approval.approval_id,
        budget=_budget(attempts=1),
        lease=lease,
        ttl_seconds=300,
    )

    assert _registry(service, [_response()]).generate(authorization, request).text == "by rfl"
    with pytest.raises(PolicyViolation, match="authorization was denied"):
        _registry(service, [_response()]).generate(authorization, request)


@pytest.mark.parametrize(
    "channel",
    [
        "case_id",
        "source_id_namespace",
        "span_id_namespace",
        "source_license_id",
        "attestation_evidence_identity",
        "idempotency_key",
        "cell_contract_hash_encoding",
    ],
)
def test_model_work_admission_public_records_do_not_retain_text_canaries(
    tmp_path: Path,
    channel: str,
) -> None:
    """Security regression target for every currently direct ModelWork text channel.

    The valid behavior rejects the input or retains only a fixed-form derived opaque value.
    """

    _state, clock = _clock_state()
    plane, service = _plane_and_service(tmp_path, clock)
    marker = "model-work-private-canary"
    work = _model_work(_bound_request())
    rejected = False

    try:
        if channel == "case_id":
            work = work.model_copy(update={"case_id": marker})
        elif channel == "source_id_namespace":
            source_id = stable_identifier(marker, "source")
            work = work.model_copy(
                update={
                    "source": work.source.model_copy(update={"source_id": source_id}),
                    "rights": work.rights.model_copy(update={"source_id": source_id}),
                }
            )
        elif channel == "span_id_namespace":
            span_id = stable_identifier(marker, "span")
            span = work.source.spans[0].model_copy(update={"span_id": span_id})
            work = work.model_copy(
                update={"source": work.source.model_copy(update={"spans": (span,)})}
            )
        elif channel == "source_license_id":
            work = work.model_copy(
                update={"rights": work.rights.model_copy(update={"source_license_id": marker})}
            )
        elif channel == "idempotency_key":
            pass
        elif channel == "cell_contract_hash_encoding":
            marker = b"model-work-private-canary".hex().ljust(64, "0")
            work = work.model_copy(update={"cell_contract_hash": marker})

        if channel == "attestation_evidence_identity":
            admission = HmacAttestationSignerV1(_MODEL_WORK_ADMISSION_KEY, clock=clock).issue(
                purpose=AttestationPurposeV1.MODEL_WORK_ADMISSION,
                payload=model_work_admission_payload(work),
                evidence_identity=marker,
                ttl_seconds=60,
            )
        else:
            admission = _model_work_admission(work, clock)
        if channel == "idempotency_key":
            assert (
                "idempotency_key" not in inspect.signature(service.register_model_work).parameters
            )
            rejected = True
        else:
            service.register_model_work(work, admission=admission)
    except (
        AttributeError,
        ModelExecutionAuthorizationError,
        TypeError,
        ValueError,
    ):
        rejected = True

    with plane.events.connection() as connection:
        persisted = "\n".join(connection.iterdump())
    assert rejected or work.bundle_id.value in persisted
    assert marker not in persisted


def test_model_work_normal_projection_does_not_persist_private_planner_text(
    tmp_path: Path,
) -> None:
    _state, clock = _clock_state()
    plane, service = _plane_and_service(tmp_path, clock)
    marker = "model-work-normal-path-private-canary"
    request = _bound_request()
    work = _model_work(request, private_marker=marker)
    admission = _model_work_admission(work, clock)
    approval = _approval(clock=clock)
    service.register_operator_approval(approval, idempotency_key="normal-canary-approval")
    service.register_model_work(work, admission=admission)
    lease = service.claim_model_work(work, ttl_seconds=600)
    service.issue_model_work(
        work,
        approval_id=approval.approval_id,
        budget=_budget(attempts=1),
        lease=lease,
        ttl_seconds=300,
    )

    with plane.events.connection() as connection:
        persisted = "\n".join(connection.iterdump())
    assert marker not in persisted


def test_model_work_execution_capability_expires_with_its_parent_admission(
    tmp_path: Path,
) -> None:
    """A short admission cannot mint a longer provider-I/O capability."""

    state, clock = _clock_state()
    _plane, service = _plane_and_service(tmp_path, clock)
    request = _bound_request()
    work = _model_work(request)
    approval = _approval(clock=clock)
    service.register_operator_approval(
        approval,
        idempotency_key="register-parent-expiry-approval",
    )
    admission = _model_work_admission(work, clock, ttl_seconds=1)
    service.register_model_work(work, admission=admission)
    lease = service.claim_model_work(work, ttl_seconds=600)
    with pytest.raises(
        ModelExecutionAuthorizationError,
        match="TTL exceeds its parent admission",
    ):
        service.issue_model_work(
            work,
            approval_id=approval.approval_id,
            budget=_budget(attempts=1),
            lease=lease,
            ttl_seconds=300,
        )
    authorization = service.issue_model_work(
        work,
        approval_id=approval.approval_id,
        budget=_budget(attempts=1),
        lease=lease,
        ttl_seconds=1,
    )
    assert authorization.subject_kind is ModelExecutionSubjectKindV1.MODEL_WORK
    assert authorization.parent_admission_hash == digest_model(HashKindV1.ATTESTATION, admission)
    assert authorization.parent_admission_expires_at == admission.expires_at
    assert authorization.expires_at == admission.expires_at
    state["now"] += timedelta(seconds=2)

    provider = CountingFakeProvider([_response()])
    probe = CountingProbe(_AUTH_CAPABILITIES)
    with pytest.raises(PolicyViolation, match="authorization was denied"):
        _registry(service, [], provider=provider, probe=probe).generate(authorization, request)
    assert probe.calls == 0
    assert provider.calls == 0


def test_model_work_execution_capability_rechecks_parent_admission_revocation(
    tmp_path: Path,
) -> None:
    """A revoked admission authority must stop an already-issued ModelWork capability."""

    _state, clock = _clock_state()
    plane, service = _plane_and_service(tmp_path, clock)
    request = _bound_request()
    work = _model_work(request)
    approval = _approval(clock=clock)
    service.register_operator_approval(
        approval,
        idempotency_key="register-parent-revocation-approval",
    )
    service.register_model_work(work, admission=_model_work_admission(work, clock))
    lease = service.claim_model_work(work, ttl_seconds=600)
    authorization = service.issue_model_work(
        work,
        approval_id=approval.approval_id,
        budget=_budget(attempts=1),
        lease=lease,
        ttl_seconds=300,
    )
    revoked_admission_key = HmacAttestationKeyV1(
        key_id=_MODEL_WORK_ADMISSION_KEY.key_id,
        secret=_MODEL_WORK_ADMISSION_KEY.secret,
        allowed_purposes=_MODEL_WORK_ADMISSION_KEY.allowed_purposes,
        revoked=True,
    )
    restarted = ModelExecutionAuthorizationService(
        control_plane=plane,
        signer=HmacAttestationSignerV1(_MODEL_KEY, clock=clock),
        verifier=_verifier(clock),
        admission_verifier=HmacAttestationVerifierV1(
            {revoked_admission_key.key_id: revoked_admission_key},
            clock=clock,
        ),
        clock=clock,
    )

    provider = CountingFakeProvider([_response()])
    probe = CountingProbe(_AUTH_CAPABILITIES)
    with pytest.raises(PolicyViolation, match="authorization was denied"):
        _registry(restarted, [], provider=provider, probe=probe).generate(
            authorization,
            request,
        )
    assert probe.calls == 0
    assert provider.calls == 0


def test_model_work_reserve_reverifies_parent_inside_budget_transaction(
    tmp_path: Path,
) -> None:
    _state, clock = _clock_state()
    plane, _service = _plane_and_service(tmp_path, clock)
    admission_verifier = RejectVerification(_verifier(clock), reject_call=7)
    service = ModelExecutionAuthorizationService(
        control_plane=plane,
        signer=HmacAttestationSignerV1(_MODEL_KEY, clock=clock),
        verifier=_verifier(clock),
        admission_verifier=admission_verifier,
        clock=clock,
    )
    request = _bound_request()
    work = _model_work(request)
    approval = _approval(clock=clock)
    service.register_operator_approval(approval, idempotency_key="transaction-reserve-approval")
    service.register_model_work(
        work,
        admission=_model_work_admission(work, clock),
    )
    lease = service.claim_model_work(work, ttl_seconds=600)
    authorization = service.issue_model_work(
        work,
        approval_id=approval.approval_id,
        budget=_budget(attempts=1),
        lease=lease,
        ttl_seconds=300,
    )
    provider = CountingFakeProvider([_response()])
    probe = CountingProbe(_AUTH_CAPABILITIES)

    with pytest.raises(PolicyViolation, match="authorization was denied"):
        _registry(service, [], provider=provider, probe=probe).generate(
            authorization,
            request,
        )

    assert admission_verifier.calls == 7
    assert probe.calls == 0
    assert provider.calls == 0
    with plane.events.connection() as connection:
        count = connection.execute(
            """
            SELECT COUNT(*)
            FROM model_execution_authorization_ledger
            WHERE event_type = 'reserved'
            """
        ).fetchone()
    assert count is not None
    assert int(count[0]) == 0
