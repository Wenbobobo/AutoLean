"""Capability-probed provider selection without implicit fallbacks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from autolean_contracts import DigestV1, EndpointClassV1
from autolean_contracts.authorization import (
    ModelExecutionAuthorizationV1,
    ModelExecutionProviderBindingV1,
)

from autolean_prover.errors import (
    CapabilityError,
    ConfigurationError,
    PolicyViolation,
    ProviderResponseError,
)
from autolean_prover.providers.authorization import (
    ModelExecutionAuthorizationGate,
    ProviderFailureCodeV1,
)
from autolean_prover.providers.base import (
    Capability,
    ModelExecutionTimeoutPolicyV1,
    ModelProvider,
    ModelRequest,
    ModelResponse,
    ProviderCapabilities,
    TokenUsage,
)
from autolean_prover.providers.policy import (
    validate_provider_identity,
    validate_registry_name,
)


class CapabilityProbe(Protocol):
    """An operator-approved capability probe. Failure must prevent model execution."""

    def probe(self, provider: ModelProvider) -> ProviderCapabilities: ...


@dataclass(frozen=True, slots=True)
class StaticCapabilityProbe:
    """Offline probe for fake/test providers or an externally attested fixed endpoint."""

    observed: ProviderCapabilities

    def __post_init__(self) -> None:
        if not isinstance(self.observed, ProviderCapabilities):
            raise ConfigurationError("static probe must report ProviderCapabilities")

    def probe(self, provider: ModelProvider) -> ProviderCapabilities:
        return self.observed


@dataclass(frozen=True, slots=True)
class _RegisteredProvider:
    provider: ModelProvider
    probe: CapabilityProbe
    provider_id: str
    model_id: str
    model_revision: str
    endpoint_class: EndpointClassV1
    configuration_hash: DigestV1
    binding: ModelExecutionProviderBindingV1
    declared_capabilities: ProviderCapabilities
    execution_timeout_policy: ModelExecutionTimeoutPolicyV1


class ProviderRegistry:
    """Explicit registry that only executes signed, control-plane-issued capabilities.

    Registering a provider is deliberately not permission to call it.  ``generate`` accepts an
    authorization capability, from which it derives the route; the old
    ``generate(name, request)`` shape is rejected even when the name is registered.
    """

    def __init__(
        self, *, authorization_gate: ModelExecutionAuthorizationGate | None = None
    ) -> None:
        self._providers: dict[str, _RegisteredProvider] = {}
        self._authorization_gate = authorization_gate

    def register(
        self,
        name: str,
        *,
        provider: ModelProvider,
        probe: CapabilityProbe,
        endpoint_class: EndpointClassV1,
        model_revision: str,
    ) -> None:
        registry_key = validate_registry_name(name)
        (
            provider_id,
            model_id,
            declared_capabilities,
            provider_endpoint_class,
            configuration_hash,
            execution_timeout_policy,
        ) = self._read_provider_binding(provider)
        validate_provider_identity(provider_id, model_id)
        if endpoint_class is not provider_endpoint_class:
            raise PolicyViolation(
                "registered endpoint_class does not match the provider's configured endpoint"
            )
        binding = ModelExecutionProviderBindingV1(
            registry_name=registry_key,
            provider_id=provider_id,
            model_id=model_id,
            model_revision=model_revision,
            endpoint_class=endpoint_class,
            configuration_hash=configuration_hash,
        )
        if registry_key in self._providers:
            raise ConfigurationError(f"provider registry name is already registered: {name}")
        self._providers[registry_key] = _RegisteredProvider(
            provider=provider,
            probe=probe,
            provider_id=provider_id,
            model_id=model_id,
            model_revision=model_revision,
            endpoint_class=endpoint_class,
            configuration_hash=configuration_hash,
            binding=binding,
            declared_capabilities=declared_capabilities,
            execution_timeout_policy=execution_timeout_policy,
        )

    def execution_timeout_policy(
        self,
        binding: ModelExecutionProviderBindingV1,
    ) -> ModelExecutionTimeoutPolicyV1:
        """Return the frozen local timeout policy without a capability or network probe."""

        return self._registered_for_binding(binding).execution_timeout_policy

    def effective_timeout_seconds(
        self,
        binding: ModelExecutionProviderBindingV1,
        request: ModelRequest,
    ) -> float:
        """Compute the actual local provider deadline without performing provider I/O."""

        if not isinstance(request, ModelRequest):
            raise PolicyViolation("effective timeout requires a ModelRequest")
        return self.execution_timeout_policy(binding).effective_timeout_seconds(request)

    def generate(
        self,
        authorization: ModelExecutionAuthorizationV1,
        request: ModelRequest,
    ) -> ModelResponse:
        registered, requested = self._preflight_generate(authorization, request)
        authorization_gate = self._authorization_gate
        if authorization_gate is None:  # Kept local for type narrowing after the shared preflight.
            raise PolicyViolation("model generation requires an injected authorization gate")
        registry_key = authorization.provider.registry_name
        outbound_request_hash = request.outbound_request_hash()
        try:
            reservation = authorization_gate.reserve(
                authorization,
                provider=registered.binding,
                requested_input_tokens=request.max_input_tokens,
                requested_output_tokens=request.max_output_tokens,
                context_pack_hash=request.context_pack_hash,
                outbound_request_hash=outbound_request_hash,
            )
        except Exception:
            raise PolicyViolation("model execution authorization was denied") from None
        settled = False
        failure_code = ProviderFailureCodeV1.LOCAL_POLICY_REJECTED
        try:
            failure_code = ProviderFailureCodeV1.PROBE_FAILED
            try:
                observed: object = registered.probe.probe(registered.provider)
            except Exception:
                raise CapabilityError(
                    f"provider capability probe failed ({failure_code.value})"
                ) from None
            if not isinstance(observed, ProviderCapabilities):
                failure_code = ProviderFailureCodeV1.PROBE_INVALID
                raise CapabilityError(
                    f"provider capability probe returned invalid evidence ({failure_code.value})"
                )
            failure_code = ProviderFailureCodeV1.LOCAL_POLICY_REJECTED
            self._assert_provider_binding(registered, name=registry_key)
            failure_code = ProviderFailureCodeV1.PROBE_CAPABILITY_MISMATCH
            try:
                observed.require(requested, provider_id=registered.provider_id)
            except CapabilityError:
                raise CapabilityError(
                    "provider capability probe did not satisfy the authorized request "
                    f"({failure_code.value})"
                ) from None
            failure_code = ProviderFailureCodeV1.GENERATION_FAILED
            try:
                response = registered.provider.generate(request)
            except (CapabilityError, ConfigurationError, PolicyViolation):
                failure_code = ProviderFailureCodeV1.LOCAL_POLICY_REJECTED
                raise PolicyViolation(
                    f"provider generation violated local policy ({failure_code.value})"
                ) from None
            except Exception:
                raise ProviderResponseError(
                    f"provider generation failed ({failure_code.value})"
                ) from None
            failure_code = ProviderFailureCodeV1.RESPONSE_INVALID
            if (
                not isinstance(response, ModelResponse)
                or response.provider_id != registered.provider_id
                or response.model_id != registered.model_id
                or not isinstance(response.text, str)
                or not isinstance(response.usage, TokenUsage)
                or response.usage.input_tokens <= 0
                or response.usage.input_tokens > request.max_input_tokens
                or response.usage.output_tokens < 0
                or response.usage.output_tokens > request.max_output_tokens
                or response.usage.cached_input_tokens > response.usage.input_tokens
            ):
                raise ProviderResponseError(
                    f"provider returned an invalid authorized response ({failure_code.value})"
                )
            failure_code = ProviderFailureCodeV1.LOCAL_POLICY_REJECTED
            self._assert_provider_binding(registered, name=registry_key)
            failure_code = ProviderFailureCodeV1.SETTLEMENT_REJECTED
            try:
                authorization_gate.settle(
                    reservation,
                    input_tokens=response.usage.input_tokens,
                    cached_input_tokens=response.usage.cached_input_tokens,
                    output_tokens=response.usage.output_tokens,
                )
            except Exception:
                raise PolicyViolation(
                    f"model execution settlement was denied ({failure_code.value})"
                ) from None
            settled = True
            return response
        finally:
            if not settled:
                try:
                    authorization_gate.abandon(
                        reservation,
                        failure_code=failure_code.value,
                    )
                except Exception:
                    raise PolicyViolation(
                        "model execution failure accounting was unavailable"
                    ) from None

    def preflight_generate(
        self,
        authorization: ModelExecutionAuthorizationV1,
        request: ModelRequest,
    ) -> None:
        """Validate a route and signed request without probing or calling the provider."""

        self._preflight_generate(authorization, request)

    def _preflight_generate(
        self,
        authorization: ModelExecutionAuthorizationV1,
        request: ModelRequest,
    ) -> tuple[_RegisteredProvider, frozenset[Capability]]:
        if not isinstance(authorization, ModelExecutionAuthorizationV1):
            raise PolicyViolation(
                "model generation requires a control-plane-issued ModelExecutionAuthorizationV1"
            )
        if not isinstance(request, ModelRequest):
            raise PolicyViolation("model generation requires a ModelRequest")
        if self._authorization_gate is None:
            raise PolicyViolation("model generation requires an injected authorization gate")
        registry_key = authorization.provider.registry_name
        registered = self._providers.get(registry_key)
        if registered is None:
            raise ConfigurationError(f"unknown model provider: {registry_key}")
        self._assert_provider_binding(registered, name=registry_key)
        outbound_request_hash = request.outbound_request_hash()
        try:
            self._authorization_gate.preflight(
                authorization,
                provider=registered.binding,
                requested_input_tokens=request.max_input_tokens,
                requested_output_tokens=request.max_output_tokens,
                context_pack_hash=request.context_pack_hash,
                outbound_request_hash=outbound_request_hash,
            )
        except Exception:
            raise PolicyViolation("model execution authorization was denied") from None
        # Token and cost budgets are meaningful only when the provider reports non-optional usage.
        # A missing usage record must fail before it can be treated as zero spend.
        requested = request.inferred_capabilities() | {Capability.USAGE_ACCOUNTING}
        registered.declared_capabilities.require(requested, provider_id=registered.provider_id)
        return registered, requested

    @staticmethod
    def _read_provider_binding(
        provider: ModelProvider,
    ) -> tuple[
        str,
        str,
        ProviderCapabilities,
        EndpointClassV1,
        DigestV1,
        ModelExecutionTimeoutPolicyV1,
    ]:
        try:
            provider_id = provider.provider_id
            model_id = provider.model_id
            endpoint_class = provider.endpoint_class
            configuration_hash = provider.configuration_hash
            capabilities = provider.capabilities
            execution_timeout_policy = provider.execution_timeout_policy
        except Exception as exc:
            raise ConfigurationError(
                "provider properties could not be read during registration"
            ) from exc
        if not isinstance(provider_id, str) or not isinstance(model_id, str):
            raise ConfigurationError("provider_id and model_id must be strings")
        if not isinstance(capabilities, ProviderCapabilities):
            raise ConfigurationError("provider capabilities must be ProviderCapabilities")
        if not isinstance(endpoint_class, EndpointClassV1):
            raise ConfigurationError("provider endpoint_class must be EndpointClassV1")
        if not isinstance(configuration_hash, DigestV1):
            raise ConfigurationError("provider configuration_hash must be DigestV1")
        if not isinstance(execution_timeout_policy, ModelExecutionTimeoutPolicyV1):
            raise ConfigurationError(
                "provider execution_timeout_policy must be ModelExecutionTimeoutPolicyV1"
            )
        return (
            provider_id,
            model_id,
            capabilities,
            endpoint_class,
            configuration_hash,
            execution_timeout_policy,
        )

    @classmethod
    def _assert_provider_binding(cls, registered: _RegisteredProvider, *, name: str) -> None:
        (
            provider_id,
            model_id,
            capabilities,
            endpoint_class,
            configuration_hash,
            execution_timeout_policy,
        ) = cls._read_provider_binding(registered.provider)
        validate_provider_identity(provider_id, model_id)
        if (
            provider_id != registered.provider_id
            or model_id != registered.model_id
            or endpoint_class is not registered.endpoint_class
            or configuration_hash != registered.configuration_hash
            or capabilities != registered.declared_capabilities
            or execution_timeout_policy != registered.execution_timeout_policy
        ):
            raise PolicyViolation(
                f"provider {name!r} changed identity, model, endpoint, configuration, or "
                "declared capabilities "
                "after registration"
            )

    def _registered_for_binding(
        self,
        binding: ModelExecutionProviderBindingV1,
    ) -> _RegisteredProvider:
        if not isinstance(binding, ModelExecutionProviderBindingV1):
            raise PolicyViolation(
                "provider execution policy requires a ModelExecutionProviderBindingV1"
            )
        registered = self._providers.get(binding.registry_name)
        if registered is None:
            raise ConfigurationError(f"unknown model provider: {binding.registry_name}")
        self._assert_provider_binding(registered, name=binding.registry_name)
        if registered.binding != binding:
            raise PolicyViolation("provider execution policy binding differs from registration")
        return registered
