"""Exact-body tests for the iFEM DeepSeek execution adapter."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

import pytest
from autolean_contracts import OutboundRequestBodyV1
from autolean_prover.errors import ConfigurationError
from autolean_prover.providers import (
    Capability,
    ChatCompletionsOperatorProfileV1,
    ProviderCapabilities,
)
from autolean_prover.providers.chat import ChatCompletionsProvider, ChatCompletionsSettings

from benchmarks.ifem_deepseek_executor import (
    IFEMDeepSeekExactExecutor,
    IFEMDeepSeekExecutorError,
)
from benchmarks.ifem_synthetic_role_bridge import (
    IFEMSyntheticRoleBridgeError,
    execute,
    prepare,
)
from benchmarks.ifem_synthetic_role_fixture import build_ifem_synthetic_role_fixture
from benchmarks.tests.test_ifem_synthetic_role_fixture import _corpus


class RecordingTransport:
    def __init__(self, response: Mapping[str, object] | None = None) -> None:
        self.bodies: list[bytes] = []
        self.response = response

    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del url, headers, payload, timeout_seconds
        raise AssertionError("exact-body adapter must not use mapping transport")

    def post_json_bytes(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del url, timeout_seconds
        assert headers["Authorization"] == "Bearer test-token"
        self.bodies.append(body)
        return self.response or {
            "id": "ifem-response-1",
            "model": "deepseek-v4-pro",
            "choices": [{"message": {"content": '{"selected_option":"option_a"}'}}],
            "usage": {
                "prompt_tokens": 31,
                "prompt_cache_hit_tokens": 7,
                "completion_tokens": 9,
            },
        }


def _executor(transport: RecordingTransport) -> IFEMDeepSeekExactExecutor:
    profile_bytes = (
        Path(__file__).resolve().parents[2]
        / "Prover"
        / "operator-profiles"
        / "deepseek-v4-pro.chat-completions.v1.json"
    ).read_bytes()
    profile = ChatCompletionsOperatorProfileV1.from_json_bytes(profile_bytes)
    return IFEMDeepSeekExactExecutor(
        profile.create_provider(
            transport=transport,
            environment={"AUTOLEAN_DEEPSEEK_API_KEY": "test-token"},
        ),
        profile_bytes=profile_bytes,
    )


def test_executor_sends_the_exact_prepared_body_and_preserves_usage() -> None:
    fixture = build_ifem_synthetic_role_fixture(_corpus(), operator_seed="executor-seed")
    transport = RecordingTransport()
    executor = _executor(transport)
    prepared = prepare(
        fixture,
        fixture.cases[0].case_id,
        executor,
        request_policy=executor.request_policy,
    )

    execution = execute(prepared, executor)

    assert transport.bodies == [prepared.body]
    assert execution.output.response_id == "ifem-response-1"
    assert execution.output.usage.input_tokens == 31
    assert execution.output.usage.cached_input_tokens == 7
    assert execution.output.usage.output_tokens == 9


def test_executor_rejects_a_body_binding_drift_before_transport() -> None:
    fixture = build_ifem_synthetic_role_fixture(_corpus(), operator_seed="executor-seed")
    transport = RecordingTransport()
    executor = _executor(transport)
    prepared = prepare(
        fixture,
        fixture.cases[0].case_id,
        executor,
        request_policy=executor.request_policy,
    )
    wrong_binding = OutboundRequestBodyV1(
        body_hash=prepared.body_binding.body_hash,
        body_size_bytes=prepared.body_binding.body_size_bytes + 1,
    )

    with pytest.raises(ConfigurationError, match="binding does not match"):
        executor.execute_prepared(
            request=prepared.request,
            body=prepared.body,
            binding=wrong_binding,
        )

    assert transport.bodies == []


def test_executor_rejects_a_same_name_provider_outside_the_fixed_profile() -> None:
    transport = RecordingTransport()
    provider = ChatCompletionsProvider(
        ChatCompletionsSettings(
            provider_id="deepseek",
            model_id="deepseek-v4-pro",
            base_url="https://models.example/v1",
            api_key_env="AUTOLEAN_DEEPSEEK_API_KEY",
            capabilities=ProviderCapabilities.of(
                Capability.TEXT_GENERATION,
                Capability.USAGE_ACCOUNTING,
                Capability.REASONING_EFFORT,
                Capability.STRUCTURED_JSON,
            ),
            thinking_enabled=False,
        ),
        transport=transport,
        environment={"AUTOLEAN_DEEPSEEK_API_KEY": "test-token"},
    )
    profile_bytes = (
        Path(__file__).resolve().parents[2]
        / "Prover"
        / "operator-profiles"
        / "deepseek-v4-pro.chat-completions.v1.json"
    ).read_bytes()

    with pytest.raises(IFEMDeepSeekExecutorError, match="fixed operator profile"):
        IFEMDeepSeekExactExecutor(provider, profile_bytes=profile_bytes)


def test_executor_policy_binds_reasoning_limits_and_usage_capability() -> None:
    fixture = build_ifem_synthetic_role_fixture(_corpus(), operator_seed="executor-seed")
    executor = _executor(RecordingTransport())

    with pytest.raises(IFEMSyntheticRoleBridgeError, match="could not prepare"):
        prepare(fixture, fixture.cases[0].case_id, executor)

    prepared = prepare(
        fixture,
        fixture.cases[0].case_id,
        executor,
        request_policy=executor.request_policy,
    )
    body = json.loads(prepared.body)
    assert prepared.request.max_input_tokens == 2048
    assert prepared.request.max_output_tokens == 256
    assert prepared.request.reasoning_effort == "high"
    assert Capability.USAGE_ACCOUNTING in prepared.request.required_capabilities
    assert body["max_tokens"] == 256
    assert body["reasoning_effort"] == "high"


def test_executor_retains_unexpected_tool_call_and_usage_without_executing_it() -> None:
    fixture = build_ifem_synthetic_role_fixture(_corpus(), operator_seed="executor-seed")
    transport = RecordingTransport(
        {
            "id": "ifem-tool-response",
            "model": "deepseek-v4-pro",
            "choices": [
                {
                    "message": {
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "call-private-1",
                                "function": {
                                    "name": "unavailable_tool",
                                    "arguments": "{}",
                                },
                            }
                        ],
                    }
                }
            ],
            "usage": {"prompt_tokens": 31, "completion_tokens": 5},
        }
    )
    executor = _executor(transport)
    prepared = prepare(
        fixture,
        fixture.cases[0].case_id,
        executor,
        request_policy=executor.request_policy,
    )

    execution = execute(prepared, executor)

    assert execution.output.text == ""
    assert execution.output.usage.output_tokens == 5
    assert len(execution.output.tool_calls) == 1
    assert execution.output.tool_calls[0].name == "unavailable_tool"
