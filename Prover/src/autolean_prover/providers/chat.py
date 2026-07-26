"""A narrow Chat Completions-compatible adapter for explicitly configured endpoints."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

from autolean_contracts import DigestV1, EndpointClassV1, HashKindV1, digest_model

from autolean_prover.errors import ConfigurationError, ProviderResponseError
from autolean_prover.providers.base import (
    ModelExecutionTimeoutPolicyV1,
    ModelRequest,
    ModelResponse,
    ProviderCapabilities,
    TokenUsage,
    ToolCall,
    effective_model_timeout_seconds,
    require_request_capabilities,
)
from autolean_prover.providers.policy import (
    is_official_openai_provider,
    resolve_secret_reference,
    validate_endpoint_class,
    validate_endpoint_url,
    validate_positive_timeout,
    validate_provider_identity,
    validate_secret_reference,
)
from autolean_prover.providers.responses import ResponsesTransport


@dataclass(frozen=True, slots=True)
class ChatCompletionsSettings:
    provider_id: str
    model_id: str
    base_url: str
    api_key_env: str | None
    capabilities: ProviderCapabilities
    endpoint_class: EndpointClassV1 = EndpointClassV1.APPROVED_EXTERNAL
    timeout_seconds: float = 120.0
    thinking_enabled: bool = False

    def __post_init__(self) -> None:
        validate_provider_identity(self.provider_id, self.model_id)
        validate_secret_reference(self.api_key_env)
        official_openai = is_official_openai_provider(self.provider_id)
        if official_openai and self.api_key_env is None:
            raise ConfigurationError("the OpenAI provider requires an API key environment variable")
        normalized_url = validate_endpoint_url(self.base_url, allow_custom=not official_openai)
        validate_endpoint_class(normalized_url, self.endpoint_class)
        object.__setattr__(self, "base_url", normalized_url)
        if not isinstance(self.capabilities, ProviderCapabilities):
            raise ConfigurationError("provider capabilities must be ProviderCapabilities")
        validate_positive_timeout(self.timeout_seconds, label="provider timeout_seconds")
        if not isinstance(self.thinking_enabled, bool):
            raise ConfigurationError("provider thinking_enabled must be a boolean")


class ChatCompletionsProvider:
    def __init__(
        self,
        settings: ChatCompletionsSettings,
        *,
        transport: ResponsesTransport,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self._settings = settings
        self._transport = transport
        self._environment = environment if environment is not None else os.environ

    @property
    def provider_id(self) -> str:
        return self._settings.provider_id

    @property
    def model_id(self) -> str:
        return self._settings.model_id

    @property
    def endpoint_class(self) -> EndpointClassV1:
        return self._settings.endpoint_class

    @property
    def configuration_hash(self) -> DigestV1:
        return digest_model(
            HashKindV1.CONFIG,
            {
                "schema_version": "autolean.provider-config.chat-completions.v1",
                "provider_id": self.provider_id,
                "model_id": self.model_id,
                "endpoint_class": self.endpoint_class.value,
                "base_url": self._settings.base_url,
                "api_key_env": self._settings.api_key_env,
                "timeout_seconds": self._settings.timeout_seconds,
                "thinking_enabled": self._settings.thinking_enabled,
                "capabilities": sorted(capability.value for capability in self.capabilities.values),
            },
        )

    @property
    def capabilities(self) -> ProviderCapabilities:
        return self._settings.capabilities

    @property
    def execution_timeout_policy(self) -> ModelExecutionTimeoutPolicyV1:
        return ModelExecutionTimeoutPolicyV1(self._settings.timeout_seconds)

    def generate(self, request: ModelRequest) -> ModelResponse:
        require_request_capabilities(self, request)
        headers = {"Content-Type": "application/json"}
        key = resolve_secret_reference(self._settings.api_key_env, self._environment)
        if key is not None:
            headers["Authorization"] = f"Bearer {key}"
        try:
            raw = self._transport.post_json(
                url=f"{self._settings.base_url}/chat/completions",
                headers=headers,
                payload=self._request_payload(request),
                timeout_seconds=effective_model_timeout_seconds(
                    request,
                    provider_timeout_seconds=self._settings.timeout_seconds,
                ),
            )
        except ProviderResponseError:
            raise
        except Exception:
            raise ProviderResponseError("Chat Completions request failed") from None
        return self._parse_response(raw)

    def _request_payload(self, request: ModelRequest) -> dict[str, object]:
        messages: list[dict[str, str]] = []
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})
        messages.append({"role": "user", "content": request.prompt})
        payload: dict[str, object] = {
            "model": self.model_id,
            "messages": messages,
            "max_tokens": request.max_output_tokens,
        }
        if self._settings.thinking_enabled:
            payload["thinking"] = {"type": "enabled"}
        if request.reasoning_effort is not None:
            payload["reasoning_effort"] = request.reasoning_effort
        if request.tools:
            payload["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": dict(tool.parameters),
                        "strict": tool.strict,
                    },
                }
                for tool in request.tools
            ]
        return payload

    def _parse_response(self, raw: Mapping[str, object]) -> ModelResponse:
        response_model_id = raw.get("model")
        if response_model_id is not None:
            if not isinstance(response_model_id, str):
                raise ProviderResponseError("Chat Completions model must be a string")
            if response_model_id != self.model_id:
                raise ProviderResponseError("Chat Completions model does not match the request")
        choices = raw.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise ProviderResponseError("Chat Completions payload is missing choices[0]")
        message = choices[0].get("message")
        if not isinstance(message, dict):
            raise ProviderResponseError("Chat Completions choice is missing a message")
        content = message.get("content")
        if content is None:
            text = ""
        elif isinstance(content, str):
            text = content
        else:
            raise ProviderResponseError("Chat Completions message content must be a string")
        tool_calls = self._parse_tool_calls(message.get("tool_calls"))
        if not text and not tool_calls:
            raise ProviderResponseError("Chat Completions payload contains no text or tool call")
        response_id = raw.get("id")
        if response_id is not None and not isinstance(response_id, str):
            raise ProviderResponseError("Chat Completions id must be a string")
        return ModelResponse(
            provider_id=self.provider_id,
            model_id=self.model_id,
            text=text,
            response_id=response_id,
            tool_calls=tool_calls,
            usage=self._parse_usage(raw.get("usage")),
        )

    @staticmethod
    def _parse_tool_calls(value: object) -> tuple[ToolCall, ...]:
        if value is None:
            return ()
        if not isinstance(value, list):
            raise ProviderResponseError("Chat Completions tool_calls must be a list")
        calls: list[ToolCall] = []
        for item in value:
            if not isinstance(item, dict):
                raise ProviderResponseError("Chat Completions tool call must be an object")
            call_id = item.get("id")
            function = item.get("function")
            if not isinstance(call_id, str) or not isinstance(function, dict):
                raise ProviderResponseError("Chat Completions tool call is incomplete")
            name = function.get("name")
            arguments = function.get("arguments")
            if not isinstance(name, str) or not isinstance(arguments, str):
                raise ProviderResponseError("Chat Completions function call is incomplete")
            calls.append(ToolCall(call_id=call_id, name=name, arguments_json=arguments))
        return tuple(calls)

    @staticmethod
    def _parse_usage(value: object) -> TokenUsage:
        if value is None:
            return TokenUsage()
        if not isinstance(value, dict):
            raise ProviderResponseError("Chat Completions usage must be an object")

        def read(key: str) -> int:
            item: object = value.get(key, 0)
            if isinstance(item, bool) or not isinstance(item, int) or item < 0:
                raise ProviderResponseError(f"usage field {key!r} must be a non-negative integer")
            return item

        input_tokens = read("prompt_tokens")
        cached_input_tokens = read("prompt_cache_hit_tokens")
        if cached_input_tokens > input_tokens:
            raise ProviderResponseError(
                "usage field 'prompt_cache_hit_tokens' cannot exceed 'prompt_tokens'"
            )
        return TokenUsage(
            input_tokens=input_tokens,
            output_tokens=read("completion_tokens"),
            cached_input_tokens=cached_input_tokens,
        )
