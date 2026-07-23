from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

import pytest
from autolean_contracts import (
    EndpointClassV1,
    HashKindV1,
    ModelEgressPolicyV1,
    ModelExecutionAuthorizationError,
    ModelExecutionAuthorizationV1,
    ModelExecutionBudgetV1,
    ModelExecutionLeaseBindingV1,
    ModelExecutionPricingV1,
    ModelExecutionProviderApprovalV1,
    ModelExecutionProviderBindingV1,
    ModelExecutionReservationV1,
    PermissionDecisionV1,
    digest_text,
    stable_identifier,
)
from autolean_prover.errors import (
    CapabilityError,
    ConfigurationError,
    PolicyViolation,
    ProviderResponseError,
)
from autolean_prover.execution import ProcessResult
from autolean_prover.providers import (
    Capability,
    ChatCompletionsProvider,
    ChatCompletionsSettings,
    CodexCliProvider,
    CodexCliSettings,
    FakeProvider,
    ModelProvider,
    ModelRequest,
    ModelResponse,
    ProviderCapabilities,
    ProviderFailureCodeV1,
    ProviderRegistry,
    ResponsesProvider,
    ResponsesSettings,
    StaticCapabilityProbe,
    TokenUsage,
)


class RecordingTransport:
    def __init__(self, response: Mapping[str, object]) -> None:
        self.response = response
        self.calls: list[dict[str, object]] = []

    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        self.calls.append(
            {
                "url": url,
                "headers": dict(headers),
                "payload": dict(payload),
                "timeout_seconds": timeout_seconds,
            }
        )
        return self.response


class FailingProbe:
    def probe(self, provider: ModelProvider) -> ProviderCapabilities:
        del provider
        raise RuntimeError("capability endpoint unavailable")


class MutableProvider:
    def __init__(
        self,
        *,
        response_model_id: str | None = None,
        generation_error: Exception | None = None,
    ) -> None:
        self.provider_id = "fake"
        self.model_id = "model-a"
        self.endpoint_class = EndpointClassV1.LOCAL
        self.capabilities = ProviderCapabilities.of(
            Capability.TEXT_GENERATION,
            Capability.USAGE_ACCOUNTING,
        )
        self.configuration_hash = FakeProvider(
            [],
            model_id=self.model_id,
            capabilities=self.capabilities,
        ).configuration_hash
        self._response_model_id = response_model_id
        self._generation_error = generation_error

    def generate(self, request: ModelRequest) -> ModelResponse:
        del request
        if self._generation_error is not None:
            raise self._generation_error
        return ModelResponse(
            provider_id=self.provider_id,
            model_id=self._response_model_id or self.model_id,
            text="by rfl",
            usage=TokenUsage(input_tokens=1, output_tokens=1),
        )


class FailingCodexHarness:
    def execute(self, request: object) -> ProcessResult:
        del request
        return ProcessResult(
            argv=("codex",),
            returncode=17,
            stdout="",
            stderr="credential-like-stderr-must-not-escape",
            duration_seconds=0.01,
        )


class PermitGate:
    """Test double: production validation and durable accounting live in the control plane."""

    def __init__(self, *, reject_settlement: bool = False) -> None:
        self.reserved: list[ModelExecutionReservationV1] = []
        self.settled: list[ModelExecutionReservationV1] = []
        self.abandoned: list[tuple[ModelExecutionReservationV1, str]] = []
        self.reject_settlement = reject_settlement

    def preflight(
        self,
        authorization: ModelExecutionAuthorizationV1,
        *,
        provider: ModelExecutionProviderBindingV1,
        requested_input_tokens: int,
        requested_output_tokens: int,
        context_pack_hash,
        outbound_request_hash,
    ) -> None:
        del (
            requested_input_tokens,
            requested_output_tokens,
            context_pack_hash,
            outbound_request_hash,
        )
        if authorization.provider != provider:
            raise ModelExecutionAuthorizationError("test authorization does not bind this provider")

    def reserve(
        self,
        authorization: ModelExecutionAuthorizationV1,
        *,
        provider: ModelExecutionProviderBindingV1,
        requested_input_tokens: int,
        requested_output_tokens: int,
        context_pack_hash,
        outbound_request_hash,
    ) -> ModelExecutionReservationV1:
        del context_pack_hash, outbound_request_hash
        if authorization.provider != provider:
            raise ModelExecutionAuthorizationError("test authorization does not bind this provider")
        reservation = ModelExecutionReservationV1(
            reservation_id=stable_identifier("provider-test", f"reservation-{len(self.reserved)}"),
            authorization_id=authorization.authorization_id,
            attempt_number=len(self.reserved) + 1,
            reserved_input_tokens=requested_input_tokens,
            reserved_output_tokens=requested_output_tokens,
            reserved_cost_microusd=0,
            reserved_at=datetime.now(UTC),
        )
        self.reserved.append(reservation)
        return reservation

    def settle(
        self,
        reservation: ModelExecutionReservationV1,
        *,
        input_tokens: int,
        cached_input_tokens: int,
        output_tokens: int,
    ) -> None:
        del input_tokens, cached_input_tokens, output_tokens
        if self.reject_settlement:
            raise ModelExecutionAuthorizationError("test settlement rejected")
        self.settled.append(reservation)

    def abandon(
        self,
        reservation: ModelExecutionReservationV1,
        *,
        failure_code: str,
    ) -> None:
        self.abandoned.append((reservation, failure_code))


def _authorization(
    *,
    registry_name: str,
    provider_id: str = "fake",
    model_id: str = "fake-model",
    model_revision: str = "fixture-v1",
    endpoint_class: EndpointClassV1 = EndpointClassV1.LOCAL,
    capabilities: ProviderCapabilities | None = None,
) -> ModelExecutionAuthorizationV1:
    now = datetime.now(UTC)
    provider_capabilities = capabilities or ProviderCapabilities.of(
        Capability.TEXT_GENERATION,
        Capability.USAGE_ACCOUNTING,
    )
    bundle_id = stable_identifier("provider-test", "bundle")
    context_pack_hash = digest_text(HashKindV1.PROMPT, "provider-test-context-pack")
    request = ModelRequest(prompt="prove it", context_pack_hash=context_pack_hash)
    return ModelExecutionAuthorizationV1(
        authorization_id=stable_identifier("provider-test", f"authorization-{registry_name}"),
        bundle_id=bundle_id,
        bundle_hash=digest_text(HashKindV1.BUNDLE, "bundle"),
        contract_id=stable_identifier("provider-test", "contract"),
        revision=1,
        contract_hash=digest_text(HashKindV1.CONTRACT, "contract"),
        environment_hash=digest_text(HashKindV1.ENVIRONMENT, "environment"),
        lease=ModelExecutionLeaseBindingV1(
            bundle_id=bundle_id,
            worker_id="provider-test-worker",
            fencing_token=1,
            expires_at=now + timedelta(hours=1),
        ),
        context_pack_hash=context_pack_hash,
        request_hash=request.outbound_request_hash(),
        egress_policy=ModelEgressPolicyV1(
            rights_id=stable_identifier("provider-test", "rights"),
            overall_decision=PermissionDecisionV1.ALLOW,
            model_egress=PermissionDecisionV1.UNKNOWN,
        ),
        approval_snapshot=ModelExecutionProviderApprovalV1(
            approval_id=stable_identifier("provider-test", "approval"),
            binding=ModelExecutionProviderBindingV1(
                registry_name=registry_name,
                provider_id=provider_id,
                model_id=model_id,
                model_revision=model_revision,
                endpoint_class=endpoint_class,
                configuration_hash=FakeProvider(
                    [],
                    model_id=model_id,
                    capabilities=provider_capabilities,
                ).configuration_hash,
            ),
            pricing=ModelExecutionPricingV1(),
            approved_by="provider-test-operator",
            approved_at=now,
        ),
        budget=ModelExecutionBudgetV1(
            max_attempts=4,
            max_input_tokens=4096,
            max_output_tokens=4096,
            max_total_tokens=8192,
            max_cost_microusd=0,
        ),
        issued_at=now,
        expires_at=now + timedelta(hours=1),
    )


def _registry(gate: PermitGate) -> ProviderRegistry:
    return ProviderRegistry(authorization_gate=gate)


def test_registry_rejects_run_when_capability_probe_fails() -> None:
    capabilities = ProviderCapabilities.of(
        Capability.TEXT_GENERATION,
        Capability.USAGE_ACCOUNTING,
    )
    provider = FakeProvider(["proof"], capabilities=capabilities)
    gate = PermitGate()
    registry = _registry(gate)
    registry.register(
        "fake",
        provider=provider,
        probe=FailingProbe(),
        endpoint_class=EndpointClassV1.LOCAL,
        model_revision="fixture-v1",
    )
    with pytest.raises(CapabilityError, match="probe failed"):
        registry.generate(
            _authorization(registry_name="fake", capabilities=provider.capabilities),
            ModelRequest(prompt="prove it"),
        )
    assert gate.abandoned[0][1] == ProviderFailureCodeV1.PROBE_FAILED


def test_registry_requires_observed_capability_not_just_declared_capability() -> None:
    capabilities = ProviderCapabilities.of(
        Capability.TEXT_GENERATION,
        Capability.TOOL_CALLING,
        Capability.USAGE_ACCOUNTING,
    )
    provider = FakeProvider(["proof"], capabilities=capabilities)
    registry = _registry(PermitGate())
    registry.register(
        "fake",
        provider=provider,
        probe=StaticCapabilityProbe(ProviderCapabilities.of(Capability.TEXT_GENERATION)),
        endpoint_class=EndpointClassV1.LOCAL,
        model_revision="fixture-v1",
    )
    with pytest.raises(CapabilityError, match="probe_capability_mismatch_v1"):
        registry.generate(
            _authorization(registry_name="fake", capabilities=capabilities),
            ModelRequest(
                prompt="prove it",
                required_capabilities=frozenset({Capability.TOOL_CALLING}),
            ),
        )


def test_registry_requires_usage_accounting_for_authorized_generation() -> None:
    capabilities = ProviderCapabilities.of(Capability.TEXT_GENERATION)
    provider = FakeProvider(["proof"], capabilities=capabilities)
    registry = _registry(PermitGate())
    registry.register(
        "fake",
        provider=provider,
        probe=StaticCapabilityProbe(capabilities),
        endpoint_class=EndpointClassV1.LOCAL,
        model_revision="fixture-v1",
    )

    with pytest.raises(CapabilityError, match="usage_accounting"):
        registry.generate(
            _authorization(registry_name="fake", capabilities=capabilities),
            ModelRequest(prompt="prove it"),
        )


def test_registry_rejects_missing_usage_in_an_authorized_response() -> None:
    capabilities = ProviderCapabilities.of(
        Capability.TEXT_GENERATION,
        Capability.USAGE_ACCOUNTING,
    )
    gate = PermitGate()
    registry = _registry(gate)
    registry.register(
        "fake",
        provider=FakeProvider(
            [
                ModelResponse(
                    provider_id="fake",
                    model_id="fake-model",
                    text="proof",
                    usage=TokenUsage(),
                )
            ],
            capabilities=capabilities,
        ),
        probe=StaticCapabilityProbe(capabilities),
        endpoint_class=EndpointClassV1.LOCAL,
        model_revision="fixture-v1",
    )

    with pytest.raises(ProviderResponseError, match="invalid authorized response"):
        registry.generate(
            _authorization(registry_name="fake", capabilities=capabilities),
            ModelRequest(prompt="prove it"),
        )
    assert len(gate.abandoned) == 1
    assert gate.abandoned[0][1] == ProviderFailureCodeV1.RESPONSE_INVALID


def test_registry_locks_provider_identity_and_model_after_registration() -> None:
    provider = MutableProvider()
    registry = _registry(PermitGate())
    registry.register(
        "model-a",
        provider=provider,
        probe=StaticCapabilityProbe(provider.capabilities),
        endpoint_class=EndpointClassV1.LOCAL,
        model_revision="fixture-v1",
    )
    provider.model_id = "model-b"
    with pytest.raises(PolicyViolation, match="changed identity"):
        registry.generate(
            _authorization(registry_name="model-a", model_id="model-a"),
            ModelRequest(prompt="prove it"),
        )


def test_registry_locks_the_provider_configuration_hash_after_registration() -> None:
    provider = MutableProvider()
    registry = _registry(PermitGate())
    registry.register(
        "model-a",
        provider=provider,
        probe=StaticCapabilityProbe(provider.capabilities),
        endpoint_class=EndpointClassV1.LOCAL,
        model_revision="fixture-v1",
    )
    provider.configuration_hash = digest_text(HashKindV1.CONFIG, "changed-operator-config")

    with pytest.raises(PolicyViolation, match="configuration"):
        registry.generate(
            _authorization(registry_name="model-a", model_id="model-a"),
            ModelRequest(prompt="prove it"),
        )


def test_registry_rejects_response_claiming_a_different_model() -> None:
    provider = MutableProvider(response_model_id="model-b")
    gate = PermitGate()
    registry = _registry(gate)
    registry.register(
        "model-a",
        provider=provider,
        probe=StaticCapabilityProbe(provider.capabilities),
        endpoint_class=EndpointClassV1.LOCAL,
        model_revision="fixture-v1",
    )
    with pytest.raises(ProviderResponseError, match="invalid authorized response"):
        registry.generate(
            _authorization(registry_name="model-a", model_id="model-a"),
            ModelRequest(prompt="prove it"),
        )
    assert gate.abandoned[0][1] == ProviderFailureCodeV1.RESPONSE_INVALID


def test_registry_classifies_generation_and_settlement_failures_without_raw_text() -> None:
    secret_marker = "credential-like-provider-error-must-not-escape"
    failing_provider = MutableProvider(generation_error=RuntimeError(secret_marker))
    generation_gate = PermitGate()
    generation_registry = _registry(generation_gate)
    generation_registry.register(
        "model-a",
        provider=failing_provider,
        probe=StaticCapabilityProbe(failing_provider.capabilities),
        endpoint_class=EndpointClassV1.LOCAL,
        model_revision="fixture-v1",
    )

    with pytest.raises(ProviderResponseError) as generation_error:
        generation_registry.generate(
            _authorization(registry_name="model-a", model_id="model-a"),
            ModelRequest(prompt="prove it"),
        )

    assert secret_marker not in str(generation_error.value)
    assert generation_error.value.__cause__ is None
    assert generation_gate.abandoned[0][1] == ProviderFailureCodeV1.GENERATION_FAILED

    settlement_gate = PermitGate(reject_settlement=True)
    settlement_registry = _registry(settlement_gate)
    provider = MutableProvider()
    settlement_registry.register(
        "model-a",
        provider=provider,
        probe=StaticCapabilityProbe(provider.capabilities),
        endpoint_class=EndpointClassV1.LOCAL,
        model_revision="fixture-v1",
    )
    with pytest.raises(PolicyViolation, match="settlement_rejected_v1"):
        settlement_registry.generate(
            _authorization(registry_name="model-a", model_id="model-a"),
            ModelRequest(prompt="prove it"),
        )
    assert settlement_gate.abandoned[0][1] == ProviderFailureCodeV1.SETTLEMENT_REJECTED


def test_model_switching_is_explicit_and_never_falls_back() -> None:
    capabilities = ProviderCapabilities.of(
        Capability.TEXT_GENERATION,
        Capability.USAGE_ACCOUNTING,
    )
    first = FakeProvider(["first"], model_id="model-first", capabilities=capabilities)
    second = FakeProvider(["second"], model_id="model-second", capabilities=capabilities)
    registry = _registry(PermitGate())
    registry.register(
        "first",
        provider=first,
        probe=StaticCapabilityProbe(capabilities),
        endpoint_class=EndpointClassV1.LOCAL,
        model_revision="fixture-v1",
    )
    registry.register(
        "second",
        provider=second,
        probe=StaticCapabilityProbe(capabilities),
        endpoint_class=EndpointClassV1.LOCAL,
        model_revision="fixture-v1",
    )

    response = registry.generate(
        _authorization(registry_name="second", model_id="model-second"),
        ModelRequest(prompt="prove it"),
    )
    assert response.model_id == "model-second"
    assert response.text == "second"
    with pytest.raises(ConfigurationError, match="unknown model provider"):
        registry.generate(
            _authorization(registry_name="unregistered"),
            ModelRequest(prompt="prove it"),
        )


def test_registry_routing_names_are_canonical_and_cannot_be_shadowed() -> None:
    capabilities = ProviderCapabilities.of(
        Capability.TEXT_GENERATION,
        Capability.USAGE_ACCOUNTING,
    )
    registry = _registry(PermitGate())
    registry.register(
        "MODEL-A",
        provider=FakeProvider(["proof"], capabilities=capabilities),
        probe=StaticCapabilityProbe(capabilities),
        endpoint_class=EndpointClassV1.LOCAL,
        model_revision="fixture-v1",
    )
    with pytest.raises(ConfigurationError, match="already registered"):
        registry.register(
            "model-a",
            provider=FakeProvider(["proof"], capabilities=capabilities),
            probe=StaticCapabilityProbe(capabilities),
            endpoint_class=EndpointClassV1.LOCAL,
            model_revision="fixture-v1",
        )
    assert (
        registry.generate(
            _authorization(registry_name="model-a"),
            ModelRequest(prompt="prove it"),
        ).text
        == "proof"
    )


def test_registry_rejects_the_legacy_raw_provider_name_bypass() -> None:
    capabilities = ProviderCapabilities.of(Capability.TEXT_GENERATION)
    registry = _registry(PermitGate())
    registry.register(
        "fake",
        provider=FakeProvider(["proof"], capabilities=capabilities),
        probe=StaticCapabilityProbe(capabilities),
        endpoint_class=EndpointClassV1.LOCAL,
        model_revision="fixture-v1",
    )
    with pytest.raises(PolicyViolation, match="ModelExecutionAuthorizationV1"):
        registry.generate("fake", ModelRequest(prompt="prove it"))


def test_registry_fails_closed_when_no_authorization_gate_is_injected() -> None:
    capabilities = ProviderCapabilities.of(Capability.TEXT_GENERATION)
    registry = ProviderRegistry()
    registry.register(
        "fake",
        provider=FakeProvider(["proof"], capabilities=capabilities),
        probe=StaticCapabilityProbe(capabilities),
        endpoint_class=EndpointClassV1.LOCAL,
        model_revision="fixture-v1",
    )

    with pytest.raises(PolicyViolation, match="injected authorization gate"):
        registry.generate(_authorization(registry_name="fake"), ModelRequest(prompt="prove it"))


def test_registry_rejects_a_mislabeled_provider_endpoint_class() -> None:
    capabilities = ProviderCapabilities.of(Capability.TEXT_GENERATION)
    with pytest.raises(PolicyViolation, match="endpoint_class"):
        _registry(PermitGate()).register(
            "fake",
            provider=FakeProvider(["proof"], capabilities=capabilities),
            probe=StaticCapabilityProbe(capabilities),
            endpoint_class=EndpointClassV1.APPROVED_EXTERNAL,
            model_revision="fixture-v1",
        )


def test_custom_chat_adapter_keeps_secret_as_environment_reference() -> None:
    transport = RecordingTransport(
        {
            "id": "response-1",
            "choices": [{"message": {"content": "by rfl"}}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 2},
        }
    )
    provider = ChatCompletionsProvider(
        ChatCompletionsSettings(
            provider_id="local-chat",
            model_id="open-model",
            base_url="http://127.0.0.1:8080/v1",
            api_key_env="LOCAL_MODEL_TOKEN",
            capabilities=ProviderCapabilities.of(Capability.TEXT_GENERATION),
            endpoint_class=EndpointClassV1.LOCAL,
        ),
        transport=transport,
        environment={"LOCAL_MODEL_TOKEN": "unit-test-token"},
    )
    response = provider.generate(ModelRequest(prompt="prove it"))
    assert response.text == "by rfl"
    assert transport.calls[0]["headers"] == {
        "Content-Type": "application/json",
        "Authorization": "Bearer unit-test-token",
    }
    assert "unit-test-token" not in repr(provider._settings)


def test_custom_responses_adapter_supports_explicit_https_model_switching() -> None:
    transport = RecordingTransport(
        {
            "id": "response-2",
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": "by omega"}],
                }
            ],
            "usage": {"input_tokens": 3, "output_tokens": 2},
        }
    )
    provider = ResponsesProvider(
        ResponsesSettings(
            provider_id="operator-model",
            model_id="open-model-revision-2",
            base_url="https://models.example/v1",
            api_key_env="OPERATOR_MODEL_TOKEN",
            capabilities=ProviderCapabilities.of(Capability.TEXT_GENERATION),
            endpoint_class=EndpointClassV1.APPROVED_EXTERNAL,
        ),
        transport=transport,
        environment={"OPERATOR_MODEL_TOKEN": "unit-test-token"},
    )
    response = provider.generate(ModelRequest(prompt="prove it"))
    assert response.model_id == "open-model-revision-2"
    assert response.text == "by omega"
    assert transport.calls[0]["url"] == "https://models.example/v1/responses"
    assert transport.calls[0]["payload"] == {
        "model": "open-model-revision-2",
        "input": [{"role": "user", "content": [{"type": "input_text", "text": "prove it"}]}],
        "max_output_tokens": 4096,
    }


def test_openai_responses_configuration_is_bound_to_the_official_endpoint() -> None:
    settings = ResponsesSettings(
        provider_id="openai-responses",
        model_id="gpt-test-model",
        base_url="https://api.openai.com/v1/",
        api_key_env="OPENAI_API_KEY",
        capabilities=ProviderCapabilities.of(Capability.TEXT_GENERATION),
        endpoint_class=EndpointClassV1.APPROVED_EXTERNAL,
    )
    assert settings.base_url == "https://api.openai.com/v1"

    with pytest.raises(PolicyViolation, match="official"):
        ResponsesSettings(
            provider_id="openai-responses",
            model_id="gpt-test-model",
            base_url="https://gateway.example/v1",
            api_key_env="OPENAI_API_KEY",
            capabilities=ProviderCapabilities.of(Capability.TEXT_GENERATION),
        )
    with pytest.raises(ConfigurationError, match="requires an API key"):
        ResponsesSettings(
            provider_id="openai-responses",
            model_id="gpt-test-model",
            base_url="https://api.openai.com/v1",
            api_key_env=None,
            capabilities=ProviderCapabilities.of(Capability.TEXT_GENERATION),
        )


@pytest.mark.parametrize(
    ("base_url", "endpoint_class"),
    [
        ("http://127.0.0.1:8080/v1", EndpointClassV1.APPROVED_EXTERNAL),
        ("https://models.example/v1", EndpointClassV1.LOCAL),
        ("https://models.example/v1", EndpointClassV1.EXTERNAL),
    ],
)
def test_endpoint_class_must_match_the_endpoint(
    base_url: str,
    endpoint_class: EndpointClassV1,
) -> None:
    with pytest.raises(PolicyViolation, match="endpoint_class"):
        ChatCompletionsSettings(
            provider_id="custom-chat",
            model_id="open-model",
            base_url=base_url,
            api_key_env=None,
            capabilities=ProviderCapabilities.of(Capability.TEXT_GENERATION),
            endpoint_class=endpoint_class,
        )


@pytest.mark.parametrize(
    "base_url",
    [
        "http://models.example/v1",
        "https://token@models.example/v1",
        "https://models.example/v1?api_key=unit-test-token",
        "https://models.example/v1?",
        "https://models.example/v1#unit-test-token",
        "https://@models.example/v1",
        "https://192.168.1.10/v1",
        "https://models.example/token/unit-test-token",
    ],
)
def test_unsafe_custom_endpoint_forms_are_rejected(base_url: str) -> None:
    with pytest.raises((ConfigurationError, PolicyViolation)):
        ResponsesSettings(
            provider_id="custom-responses",
            model_id="open-model",
            base_url=base_url,
            api_key_env="CUSTOM_API_KEY",
            capabilities=ProviderCapabilities.of(Capability.TEXT_GENERATION),
        )


@pytest.mark.parametrize(
    ("provider_id", "model_id"),
    [
        ("claude-compatible", "open-model"),
        ("custom-provider", "claude-model"),
        ("custom-provider", "\uff23\uff4c\uff41\uff55\uff44\uff45-model"),
    ],
)
def test_prohibited_provider_and_model_identifiers_are_rejected(
    provider_id: str,
    model_id: str,
) -> None:
    with pytest.raises(PolicyViolation):
        ChatCompletionsSettings(
            provider_id=provider_id,
            model_id=model_id,
            base_url="https://models.example/v1",
            api_key_env="MODEL_API_KEY",
            capabilities=ProviderCapabilities.of(Capability.TEXT_GENERATION),
        )


def test_prohibited_endpoint_identifier_is_rejected() -> None:
    with pytest.raises(PolicyViolation):
        ResponsesSettings(
            provider_id="custom-responses",
            model_id="open-model",
            base_url="https://claude.example/v1",
            api_key_env="MODEL_API_KEY",
            capabilities=ProviderCapabilities.of(Capability.TEXT_GENERATION),
        )


def test_prohibited_registry_and_codex_identifiers_are_rejected() -> None:
    capabilities = ProviderCapabilities.of(Capability.TEXT_GENERATION)
    provider = FakeProvider(["proof"], capabilities=capabilities)
    with pytest.raises(PolicyViolation):
        ProviderRegistry().register(
            "claude-route",
            provider=provider,
            probe=StaticCapabilityProbe(capabilities),
            endpoint_class=EndpointClassV1.LOCAL,
            model_revision="fixture-v1",
        )
    with pytest.raises(PolicyViolation):
        CodexCliSettings(model_id="claude-model")


@pytest.mark.parametrize("reference", ["sk-unit-test", "Bearer unit-test", "MODEL_API_KEY "])
def test_inline_or_malformed_credential_references_are_rejected(reference: str) -> None:
    with pytest.raises(ConfigurationError):
        ResponsesSettings(
            provider_id="custom-responses",
            model_id="open-model",
            base_url="https://models.example/v1",
            api_key_env=reference,
            capabilities=ProviderCapabilities.of(Capability.TEXT_GENERATION),
        )


def test_credential_value_is_not_echoed_when_rejected() -> None:
    provider = ResponsesProvider(
        ResponsesSettings(
            provider_id="custom-responses",
            model_id="open-model",
            base_url="https://models.example/v1",
            api_key_env="MODEL_API_KEY",
            capabilities=ProviderCapabilities.of(Capability.TEXT_GENERATION),
        ),
        transport=RecordingTransport({"output": []}),
        environment={"MODEL_API_KEY": "unit-test-token\r\ninvalid"},
    )
    with pytest.raises(ConfigurationError) as error:
        provider.generate(ModelRequest(prompt="prove it"))
    assert "unit-test-token" not in str(error.value)


def test_codex_cli_rejects_unsafe_sandbox_and_reasoning_configuration() -> None:
    with pytest.raises(ConfigurationError, match="sandbox"):
        CodexCliSettings(model_id="gpt-test-model", sandbox="danger-full-access")
    with pytest.raises(ConfigurationError, match="read-only"):
        CodexCliSettings(model_id="gpt-test-model", sandbox="workspace-write")
    with pytest.raises(ConfigurationError, match="reasoning"):
        CodexCliSettings(
            model_id="gpt-test-model",
            default_reasoning_effort='high" unexpected=true',
        )
    with pytest.raises(ConfigurationError, match="finite"):
        CodexCliSettings(model_id="gpt-test-model", timeout_seconds=float("nan"))


def test_codex_cli_failure_does_not_surface_stderr(tmp_path) -> None:
    provider = CodexCliProvider(
        CodexCliSettings(model_id="gpt-test-model"),
        harness=FailingCodexHarness(),
    )
    with pytest.raises(ProviderResponseError) as error:
        provider.generate(ModelRequest(prompt="prove it", working_directory=tmp_path))
    assert "17" in str(error.value)
    assert "credential-like-stderr-must-not-escape" not in str(error.value)
