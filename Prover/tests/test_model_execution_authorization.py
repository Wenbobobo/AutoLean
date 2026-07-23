from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from autolean_contracts import (
    AttestationPurposeV1,
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
    builder_attestation_payload,
    digest_text,
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
) -> ProviderRegistry:
    registry = ProviderRegistry(authorization_gate=service)
    registry.register(
        "fake",
        provider=FakeProvider(responses, model_id=model_id, capabilities=_AUTH_CAPABILITIES),
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
