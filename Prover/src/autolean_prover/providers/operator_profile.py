"""Credential-free, operator-owned DeepSeek Chat Completions profile loading.

The profile fixes one public endpoint and refers to an API key only by environment-variable name.
It is an operator-side construction aid, not an authorization to register a provider or egress a
ContextPack.
"""

from __future__ import annotations

import json
import math
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from autolean_contracts import EndpointClassV1

from autolean_prover.errors import ConfigurationError
from autolean_prover.providers.base import Capability, ModelRequest, ProviderCapabilities
from autolean_prover.providers.chat import ChatCompletionsProvider, ChatCompletionsSettings
from autolean_prover.providers.policy import (
    validate_positive_timeout,
    validate_provider_identity,
    validate_reasoning_effort,
    validate_secret_reference,
)
from autolean_prover.providers.responses import ResponsesTransport

_SCHEMA_VERSION = "autolean.operator-profile.chat-completions.v1"
_DEEPSEEK_PROVIDER_ID = "deepseek"
_DEEPSEEK_MODEL_ID = "deepseek-v4-pro"
_DEEPSEEK_BASE_URL = "https://api.deepseek.com"
_REQUIRED_CAPABILITIES = frozenset(
    {
        Capability.TEXT_GENERATION,
        Capability.USAGE_ACCOUNTING,
        Capability.REASONING_EFFORT,
        Capability.STRUCTURED_JSON,
    }
)
_REQUIRED_FIELDS = frozenset(
    {
        "schema_version",
        "profile_id",
        "provider_id",
        "model_id",
        "base_url",
        "api_key_env",
        "endpoint_class",
        "capabilities",
        "timeout_seconds",
        "thinking_enabled",
        "default_reasoning_effort",
        "canary_max_input_tokens",
        "canary_max_output_tokens",
    }
)


def _positive_token_limit(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigurationError(f"{label} must be a positive integer")
    return value


def _string(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ConfigurationError(f"{label} must be a non-empty trimmed string")
    return value


@dataclass(frozen=True, slots=True)
class ChatCompletionsOperatorProfileV1:
    """A constrained profile that creates a provider and small capability canary requests."""

    profile_id: str
    provider_id: str
    model_id: str
    base_url: str
    api_key_env: str
    endpoint_class: EndpointClassV1
    capabilities: ProviderCapabilities
    timeout_seconds: float
    thinking_enabled: bool
    default_reasoning_effort: str
    canary_max_input_tokens: int
    canary_max_output_tokens: int

    @classmethod
    def from_json_file(cls, path: Path) -> ChatCompletionsOperatorProfileV1:
        """Load an exact V1 profile without resolving its API key reference."""

        try:
            loaded: object = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ConfigurationError("operator profile must be readable canonical JSON") from error
        if not isinstance(loaded, dict) or set(loaded) != _REQUIRED_FIELDS:
            raise ConfigurationError("operator profile has an unsupported schema")
        if loaded.get("schema_version") != _SCHEMA_VERSION:
            raise ConfigurationError("operator profile schema_version is unsupported")

        capabilities_value = loaded["capabilities"]
        if not isinstance(capabilities_value, list) or not capabilities_value:
            raise ConfigurationError("operator profile capabilities must be a non-empty list")
        try:
            capabilities = tuple(Capability(value) for value in capabilities_value)
        except (TypeError, ValueError) as error:
            raise ConfigurationError("operator profile contains an unknown capability") from error
        if len(set(capabilities)) != len(capabilities):
            raise ConfigurationError("operator profile capabilities must not contain duplicates")
        if frozenset(capabilities) != _REQUIRED_CAPABILITIES:
            raise ConfigurationError("operator profile capabilities are not supported")

        endpoint_class_value = loaded["endpoint_class"]
        try:
            endpoint_class = EndpointClassV1(endpoint_class_value)
        except (TypeError, ValueError) as error:
            raise ConfigurationError("operator profile endpoint_class is invalid") from error
        if endpoint_class is not EndpointClassV1.APPROVED_EXTERNAL:
            raise ConfigurationError("operator profile supports approved_external endpoints only")

        timeout = loaded["timeout_seconds"]
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, int | float)
            or not math.isfinite(timeout)
        ):
            raise ConfigurationError("operator profile timeout_seconds is invalid")
        validate_positive_timeout(timeout, label="operator profile timeout_seconds")
        thinking_enabled = loaded["thinking_enabled"]
        if thinking_enabled is not True:
            raise ConfigurationError("operator profile must enable thinking")
        effort = _string(loaded["default_reasoning_effort"], label="default_reasoning_effort")
        validate_reasoning_effort(effort, label="operator profile default_reasoning_effort")
        if effort not in {"high", "max"}:
            raise ConfigurationError("operator profile supports only high or max reasoning effort")

        profile = cls(
            profile_id=_string(loaded["profile_id"], label="profile_id"),
            provider_id=_string(loaded["provider_id"], label="provider_id"),
            model_id=_string(loaded["model_id"], label="model_id"),
            base_url=_string(loaded["base_url"], label="base_url"),
            api_key_env=_string(loaded["api_key_env"], label="api_key_env"),
            endpoint_class=endpoint_class,
            capabilities=ProviderCapabilities.of(*capabilities),
            timeout_seconds=float(timeout),
            thinking_enabled=thinking_enabled,
            default_reasoning_effort=effort,
            canary_max_input_tokens=_positive_token_limit(
                loaded["canary_max_input_tokens"],
                label="canary_max_input_tokens",
            ),
            canary_max_output_tokens=_positive_token_limit(
                loaded["canary_max_output_tokens"],
                label="canary_max_output_tokens",
            ),
        )
        validate_provider_identity(profile.provider_id, profile.model_id)
        if profile.provider_id != _DEEPSEEK_PROVIDER_ID or profile.model_id != _DEEPSEEK_MODEL_ID:
            raise ConfigurationError(
                "operator profile does not identify the supported DeepSeek model"
            )
        if profile.base_url != _DEEPSEEK_BASE_URL:
            raise ConfigurationError("operator profile must use the official DeepSeek endpoint")
        validate_secret_reference(profile.api_key_env)
        return profile

    def create_provider(
        self,
        *,
        transport: ResponsesTransport,
        environment: Mapping[str, str] | None = None,
    ) -> ChatCompletionsProvider:
        """Construct the adapter; only its named API key is resolved at request time."""

        source_environment = environment if environment is not None else os.environ
        return ChatCompletionsProvider(
            ChatCompletionsSettings(
                provider_id=self.provider_id,
                model_id=self.model_id,
                base_url=self.base_url,
                api_key_env=self.api_key_env,
                capabilities=self.capabilities,
                endpoint_class=self.endpoint_class,
                timeout_seconds=self.timeout_seconds,
                thinking_enabled=self.thinking_enabled,
            ),
            transport=transport,
            environment=source_environment,
        )

    def canary_request(self, prompt: str, *, system_prompt: str | None = None) -> ModelRequest:
        """Make a bounded request that proves only adapter/probe wiring, not benchmark quality."""

        return ModelRequest(
            prompt=prompt,
            system_prompt=system_prompt,
            max_input_tokens=self.canary_max_input_tokens,
            max_output_tokens=self.canary_max_output_tokens,
            reasoning_effort=self.default_reasoning_effort,
            required_capabilities=frozenset({Capability.USAGE_ACCOUNTING}),
        )
