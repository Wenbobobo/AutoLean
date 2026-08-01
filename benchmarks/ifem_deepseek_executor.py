"""Exact-body DeepSeek adapter for the private iFEM calibration lane.

This adapter is deliberately narrower than a model authorization service. It proves that the
audited Chat Completions provider sends the same canonical bytes prepared by the iFEM bridge, but
it does not grant egress, benchmark, semantic, freeze, Prover, or promotion authority.
"""

from __future__ import annotations

from collections.abc import Mapping

from autolean_contracts import DigestV1, OutboundRequestBodyV1
from autolean_prover.errors import ConfigurationError, ProviderResponseError
from autolean_prover.providers import (
    CanonicalJsonRequestBody,
    Capability,
    ChatCompletionsOperatorProfileV1,
    ModelRequest,
)
from autolean_prover.providers.chat import ChatCompletionsProvider

from benchmarks.ifem_synthetic_role_bridge import (
    IFEMSyntheticRoleModelOutputV1,
    IFEMSyntheticRoleRequestPolicyV1,
)


class IFEMDeepSeekExecutorError(ValueError):
    """The exact DeepSeek adapter received a mismatched request or unsupported response."""


class _NoIoTransport:
    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del url, headers, payload, timeout_seconds
        raise AssertionError("profile comparison must not perform provider I/O")

    def post_json_bytes(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del url, headers, body, timeout_seconds
        raise AssertionError("profile comparison must not perform provider I/O")


class IFEMDeepSeekExactExecutor:
    """Bridge adapter over one fixed DeepSeek Chat Completions provider."""

    def __init__(
        self,
        provider: ChatCompletionsProvider,
        *,
        profile_bytes: bytes,
    ) -> None:
        if not isinstance(provider, ChatCompletionsProvider):
            raise IFEMDeepSeekExecutorError("DeepSeek executor requires a ChatCompletionsProvider")
        try:
            profile = ChatCompletionsOperatorProfileV1.from_json_bytes(profile_bytes)
        except ConfigurationError as error:
            raise IFEMDeepSeekExecutorError(
                "DeepSeek executor requires validated operator-profile bytes"
            ) from error
        expected = profile.create_provider(transport=_NoIoTransport(), environment={})
        if provider.configuration_hash != expected.configuration_hash:
            raise IFEMDeepSeekExecutorError(
                "DeepSeek executor provider differs from the fixed operator profile"
            )
        self._provider = provider
        self._request_policy = IFEMSyntheticRoleRequestPolicyV1(
            max_input_tokens=profile.canary_max_input_tokens,
            max_output_tokens=profile.canary_max_output_tokens,
            reasoning_effort=profile.default_reasoning_effort,
            require_usage_accounting=True,
        )

    @property
    def provider_id(self) -> str:
        return self._provider.provider_id

    @property
    def model_id(self) -> str:
        return self._provider.model_id

    @property
    def configuration_hash(self) -> DigestV1:
        return self._provider.configuration_hash

    @property
    def request_policy(self) -> IFEMSyntheticRoleRequestPolicyV1:
        return self._request_policy

    def prepare_request_body(self, request: ModelRequest) -> CanonicalJsonRequestBody:
        policy = self._request_policy
        if (
            request.max_input_tokens != policy.max_input_tokens
            or request.max_output_tokens != policy.max_output_tokens
            or request.reasoning_effort != policy.reasoning_effort
            or request.response_format != "json_object"
            or Capability.USAGE_ACCOUNTING not in request.required_capabilities
        ):
            raise ConfigurationError(
                "iFEM DeepSeek request differs from the fixed operator generation policy"
            )
        return self._provider.prepare_request_body(request)

    def execute_prepared(
        self,
        *,
        request: ModelRequest,
        body: bytes,
        binding: OutboundRequestBodyV1,
    ) -> IFEMSyntheticRoleModelOutputV1:
        try:
            prepared = CanonicalJsonRequestBody(body=body, binding=binding)
            response = self._provider.generate_prepared(request, prepared)
        except (ConfigurationError, ProviderResponseError):
            raise
        except Exception:
            raise IFEMDeepSeekExecutorError("DeepSeek exact-body execution failed") from None
        return IFEMSyntheticRoleModelOutputV1(
            text=response.text,
            body_binding=binding,
            provider_id=response.provider_id,
            model_id=response.model_id,
            response_id=response.response_id,
            usage=response.usage,
            tool_calls=response.tool_calls,
        )


__all__ = ["IFEMDeepSeekExactExecutor", "IFEMDeepSeekExecutorError"]
