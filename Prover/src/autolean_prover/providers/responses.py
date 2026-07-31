from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

import httpx
from autolean_contracts import (
    DigestV1,
    EndpointClassV1,
    HashKindV1,
    digest_model,
    outbound_request_body_binding,
)

from autolean_prover.errors import ConfigurationError, ProviderResponseError
from autolean_prover.providers.base import (
    CanonicalJsonRequestBody,
    ModelExecutionTimeoutPolicyV1,
    ModelRequest,
    ModelResponse,
    ProviderCapabilities,
    TokenUsage,
    ToolCall,
    canonical_json_request_body,
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


class ResponsesTransport(Protocol):
    def post_json_bytes(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> Mapping[str, object]: ...

    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]: ...


class HttpxResponsesTransport:
    """Small transport adapter kept injectable so unit tests never use the network."""

    def __init__(self, client: httpx.Client | None = None) -> None:
        self._client = client

    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        return self.post_json_bytes(
            url=url,
            headers=headers,
            body=canonical_json_request_body(payload).body,
            timeout_seconds=timeout_seconds,
        )

    def post_json_bytes(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        if not isinstance(body, bytes):
            raise ProviderResponseError("JSON request body must be bytes")
        try:
            outbound_request_body_binding(body)
        except ValueError:
            raise ProviderResponseError(
                "JSON request body must use canonical UTF-8 object bytes"
            ) from None
        if self._client is None:
            with httpx.Client(timeout=timeout_seconds) as client:
                response = client.post(url, headers=dict(headers), content=body)
        else:
            response = self._client.post(
                url,
                headers=dict(headers),
                content=body,
                timeout=timeout_seconds,
            )
        response.raise_for_status()
        parsed = response.json()
        if not isinstance(parsed, dict):
            raise ProviderResponseError("Responses endpoint returned a non-object JSON body")
        return parsed


@dataclass(frozen=True, slots=True)
class ResponsesSettings:
    provider_id: str
    model_id: str
    base_url: str
    api_key_env: str | None
    capabilities: ProviderCapabilities
    endpoint_class: EndpointClassV1 = EndpointClassV1.APPROVED_EXTERNAL
    timeout_seconds: float = 120.0

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


class ResponsesProvider:
    def __init__(
        self,
        settings: ResponsesSettings,
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
                "schema_version": "autolean.provider-config.responses.v1",
                "provider_id": self.provider_id,
                "model_id": self.model_id,
                "endpoint_class": self.endpoint_class.value,
                "base_url": self._settings.base_url,
                "api_key_env": self._settings.api_key_env,
                "timeout_seconds": self._settings.timeout_seconds,
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
        prepared_body = self.prepare_request_body(request)
        headers = {"Content-Type": "application/json"}
        api_key = resolve_secret_reference(self._settings.api_key_env, self._environment)
        if api_key is not None:
            headers["Authorization"] = f"Bearer {api_key}"
        try:
            raw = self._transport.post_json_bytes(
                url=f"{self._settings.base_url.rstrip('/')}/responses",
                headers=headers,
                body=prepared_body.body,
                timeout_seconds=effective_model_timeout_seconds(
                    request,
                    provider_timeout_seconds=self._settings.timeout_seconds,
                ),
            )
        except ProviderResponseError:
            raise
        except Exception:
            raise ProviderResponseError("Responses request failed") from None
        return self._parse_response(raw)

    def prepare_request_body(self, request: ModelRequest) -> CanonicalJsonRequestBody:
        """Build the exact credential-free JSON body without resolving an API key."""

        require_request_capabilities(self, request)
        return canonical_json_request_body(self._request_payload(request))

    def _request_payload(self, request: ModelRequest) -> dict[str, object]:
        inputs: list[dict[str, object]] = []
        if request.system_prompt:
            inputs.append(
                {
                    "role": "system",
                    "content": [{"type": "input_text", "text": request.system_prompt}],
                }
            )
        inputs.append(
            {
                "role": "user",
                "content": [{"type": "input_text", "text": request.prompt}],
            }
        )
        payload: dict[str, object] = {
            "model": self.model_id,
            "input": inputs,
            "max_output_tokens": request.max_output_tokens,
        }
        if request.reasoning_effort is not None:
            payload["reasoning"] = {"effort": request.reasoning_effort}
        if request.tools:
            payload["tools"] = [
                {
                    "type": "function",
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": dict(tool.parameters),
                    "strict": tool.strict,
                }
                for tool in request.tools
            ]
        return payload

    def _parse_response(self, raw: Mapping[str, object]) -> ModelResponse:
        output = raw.get("output")
        if not isinstance(output, list):
            raise ProviderResponseError("Responses payload is missing an output list")
        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for item in output:
            if not isinstance(item, dict):
                raise ProviderResponseError("Responses output item is not an object")
            item_type = item.get("type")
            if item_type == "message":
                content = item.get("content")
                if not isinstance(content, list):
                    raise ProviderResponseError("message output is missing content")
                for part in content:
                    if not isinstance(part, dict):
                        raise ProviderResponseError("message content item is not an object")
                    if part.get("type") == "output_text":
                        value = part.get("text")
                        if not isinstance(value, str):
                            raise ProviderResponseError("output_text item is missing text")
                        text_parts.append(value)
            elif item_type == "function_call":
                call_id = item.get("call_id")
                name = item.get("name")
                arguments = item.get("arguments")
                if not all(isinstance(value, str) for value in (call_id, name, arguments)):
                    raise ProviderResponseError("function_call output is incomplete")
                tool_calls.append(
                    ToolCall(
                        call_id=str(call_id),
                        name=str(name),
                        arguments_json=str(arguments),
                    )
                )
        if not text_parts and not tool_calls:
            raise ProviderResponseError("Responses payload contains no text or tool call")
        usage = self._parse_usage(raw.get("usage"))
        response_id = raw.get("id")
        if response_id is not None and not isinstance(response_id, str):
            raise ProviderResponseError("Responses id must be a string when present")
        return ModelResponse(
            provider_id=self.provider_id,
            model_id=self.model_id,
            text="".join(text_parts),
            response_id=response_id,
            tool_calls=tuple(tool_calls),
            usage=usage,
        )

    @staticmethod
    def _parse_usage(value: object) -> TokenUsage:
        if value is None:
            return TokenUsage()
        if not isinstance(value, dict):
            raise ProviderResponseError("Responses usage must be an object")
        details = value.get("input_tokens_details")
        cached = 0
        if details is not None:
            if not isinstance(details, dict):
                raise ProviderResponseError("input_tokens_details must be an object")
            cached = ResponsesProvider._usage_int(details, "cached_tokens")
        return TokenUsage(
            input_tokens=ResponsesProvider._usage_int(value, "input_tokens"),
            output_tokens=ResponsesProvider._usage_int(value, "output_tokens"),
            cached_input_tokens=cached,
        )

    @staticmethod
    def _usage_int(value: Mapping[str, object], key: str) -> int:
        item = value.get(key, 0)
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise ProviderResponseError(f"usage field {key!r} must be a non-negative integer")
        return item
