from __future__ import annotations

from collections.abc import Mapping

import httpx
import pytest
from autolean_contracts import HashKindV1
from autolean_contracts.outbound_request import outbound_request_body_binding
from autolean_prover.errors import ConfigurationError, ProviderResponseError
from autolean_prover.providers import (
    Capability,
    ChatCompletionsProvider,
    ChatCompletionsSettings,
    ModelRequest,
    ProviderCapabilities,
    canonical_json_request_body,
)
from autolean_prover.providers.responses import HttpxResponsesTransport


class _RawCaptureTransport:
    def __init__(self) -> None:
        self.body: bytes | None = None
        self.headers: Mapping[str, str] | None = None

    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del url, headers, payload, timeout_seconds
        raise AssertionError("the provider must use the exact-bytes transport path")

    def post_json_bytes(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del url, timeout_seconds
        self.body = body
        self.headers = dict(headers)
        return {
            "id": "response-1",
            "model": "deepseek-v4-pro",
            "choices": [{"message": {"content": "ok"}}],
        }


class _FakeHttpxResponse:
    def raise_for_status(self) -> None:
        return None

    def json(self) -> Mapping[str, object]:
        return {"ok": True}


class _FakeHttpxClient:
    def __init__(self) -> None:
        self.kwargs: dict[str, object] | None = None

    def post(self, url: str, **kwargs: object) -> _FakeHttpxResponse:
        self.kwargs = {"url": url, **kwargs}
        return _FakeHttpxResponse()


def test_canonical_body_is_sorted_and_credential_free() -> None:
    prepared = canonical_json_request_body({"z": 1, "a": "prompt"})
    assert prepared.body == b'{"a":"prompt","z":1}'
    assert prepared.binding.body_hash.kind is HashKindV1.OUTBOUND_REQUEST_BODY
    assert prepared.binding.body_size_bytes == len(prepared.body)
    assert b"Authorization" not in prepared.body
    assert b"secret-token" not in prepared.body


def test_chat_provider_sends_exact_prepared_bytes_and_keeps_auth_header_out_of_binding() -> None:
    transport = _RawCaptureTransport()
    provider = ChatCompletionsProvider(
        ChatCompletionsSettings(
            provider_id="deepseek",
            model_id="deepseek-v4-pro",
            base_url="https://example.invalid/v1",
            api_key_env="AUTOLEAN_TEST_API_KEY",
            capabilities=ProviderCapabilities.of(Capability.TEXT_GENERATION),
        ),
        transport=transport,
        environment={"AUTOLEAN_TEST_API_KEY": "secret-token"},
    )
    request = ModelRequest(prompt="return JSON", max_output_tokens=32)

    prepared = provider.prepare_request_body(request)
    response = provider.generate(request)

    assert response.text == "ok"
    assert transport.body == prepared.body
    assert transport.headers is not None
    assert transport.headers["Authorization"] == "Bearer secret-token"
    assert b"secret-token" not in transport.body
    assert prepared.binding.body_hash.value


def test_chat_provider_generate_prepared_rejects_request_drift_before_transport() -> None:
    transport = _RawCaptureTransport()
    provider = ChatCompletionsProvider(
        ChatCompletionsSettings(
            provider_id="deepseek",
            model_id="deepseek-v4-pro",
            base_url="https://example.invalid/v1",
            api_key_env="AUTOLEAN_TEST_API_KEY",
            capabilities=ProviderCapabilities.of(Capability.TEXT_GENERATION),
        ),
        transport=transport,
        environment={"AUTOLEAN_TEST_API_KEY": "secret-token"},
    )
    prepared = provider.prepare_request_body(ModelRequest(prompt="alpha", max_output_tokens=32))

    with pytest.raises(ConfigurationError, match="differs from the logical request"):
        provider.generate_prepared(
            ModelRequest(prompt="beta", max_output_tokens=32),
            prepared,
        )

    assert transport.body is None


def test_canonical_body_binding_changes_when_payload_changes() -> None:
    first = canonical_json_request_body({"prompt": "alpha"})
    second = canonical_json_request_body({"prompt": "beta"})
    assert first.body != second.body
    assert first.binding.body_hash.value != second.binding.body_hash.value


def test_httpx_transport_uses_content_bytes_not_json_reserialization() -> None:
    client = _FakeHttpxClient()
    transport = HttpxResponsesTransport(client=client)  # type: ignore[arg-type]
    body = b'{"a":1}'

    assert transport.post_json_bytes(
        url="https://example.invalid/v1/chat/completions",
        headers={"Content-Type": "application/json"},
        body=body,
        timeout_seconds=3,
    ) == {"ok": True}
    assert client.kwargs is not None
    assert client.kwargs["content"] == body
    assert "json" not in client.kwargs


def test_httpx_mock_transport_observes_the_exact_body_bytes() -> None:
    captured: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request.content)
        return httpx.Response(200, json={"ok": True}, request=request)

    body = b'{"a":"exact","z":1}'
    transport = HttpxResponsesTransport(client=httpx.Client(transport=httpx.MockTransport(handler)))

    assert transport.post_json_bytes(
        url="https://example.invalid/v1/chat/completions",
        headers={"Content-Type": "application/json"},
        body=body,
        timeout_seconds=3,
    ) == {"ok": True}
    assert captured == [body]


def test_httpx_transport_rejects_noncanonical_bytes_before_dispatch() -> None:
    client = _FakeHttpxClient()
    transport = HttpxResponsesTransport(client=client)  # type: ignore[arg-type]

    with pytest.raises(ProviderResponseError, match="canonical UTF-8 object"):
        transport.post_json_bytes(
            url="https://example.invalid/v1/chat/completions",
            headers={"Content-Type": "application/json"},
            body=b'{"z":1,"a":2}',
            timeout_seconds=3,
        )

    assert client.kwargs is None


def test_body_binding_rejects_noncanonical_or_nonobject_json() -> None:
    with pytest.raises(ValueError, match="canonical JSON object"):
        outbound_request_body_binding(b'{"z":1,"a":2}')
    with pytest.raises(ValueError, match="canonical JSON object"):
        outbound_request_body_binding(b"[1,2]")
