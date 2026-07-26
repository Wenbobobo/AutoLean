from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

import pytest
from autolean_prover.errors import ConfigurationError
from autolean_prover.providers import ChatCompletionsOperatorProfileV1


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


PROFILE_PATH = (
    Path(__file__).resolve().parents[1]
    / "operator-profiles"
    / "deepseek-v4-pro.chat-completions.v1.json"
)


def _profile_payload() -> dict[str, object]:
    return json.loads(PROFILE_PATH.read_text(encoding="utf-8"))


def test_deepseek_profile_is_reference_only_and_builds_a_bounded_canary() -> None:
    profile = ChatCompletionsOperatorProfileV1.from_json_file(PROFILE_PATH)
    assert profile.provider_id == "deepseek"
    assert profile.model_id == "deepseek-v4-pro"
    assert profile.base_url == "https://api.deepseek.com"
    assert profile.api_key_env == "AUTOLEAN_DEEPSEEK_API_KEY"

    canary = profile.canary_request("Return only the Lean token rfl.")
    assert canary.reasoning_effort == "high"
    assert canary.max_input_tokens == 2048
    assert canary.max_output_tokens == 256

    transport = RecordingTransport(
        {
            "id": "response-1",
            "model": "deepseek-v4-pro",
            "choices": [{"message": {"content": "rfl"}}],
            "usage": {
                "prompt_tokens": 8,
                "completion_tokens": 1,
                "prompt_cache_hit_tokens": 3,
            },
        }
    )
    provider = profile.create_provider(
        transport=transport,
        environment={
            "AUTOLEAN_DEEPSEEK_API_KEY": "unit-test-token",
        },
    )
    response = provider.generate(canary)
    assert response.text == "rfl"
    assert response.usage.cached_input_tokens == 3
    assert transport.calls == [
        {
            "url": "https://api.deepseek.com/chat/completions",
            "headers": {
                "Content-Type": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "payload": {
                "model": "deepseek-v4-pro",
                "messages": [{"role": "user", "content": "Return only the Lean token rfl."}],
                "max_tokens": 256,
                "thinking": {"type": "enabled"},
                "reasoning_effort": "high",
            },
            "timeout_seconds": 120.0,
        }
    ]
    assert "unit-test-token" not in repr(provider._settings)
    assert "unit-test-token" not in provider.configuration_hash.value


@pytest.mark.parametrize(
    "field,value",
    [
        ("base_url", "https://models.example/v1"),
        ("api_key_env", "sk-inline-secret"),
        ("thinking_enabled", False),
        ("endpoint_class", "local"),
        ("capabilities", ["text_generation", "usage_accounting", "custom_endpoint"]),
        ("provider_id", "claude-compatible"),
        ("capabilities", ["text_generation", "usage_accounting"]),
        ("model_id", "deepseek-v4-pro-revision-2"),
        ("default_reasoning_effort", "low"),
    ],
)
def test_profile_rejects_literal_or_unsafe_configuration(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    payload = _profile_payload()
    payload[field] = value
    candidate = tmp_path / "profile.json"
    candidate.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ConfigurationError):
        ChatCompletionsOperatorProfileV1.from_json_file(candidate)


def test_profile_uses_the_fixed_official_endpoint_despite_environment_drift() -> None:
    profile = ChatCompletionsOperatorProfileV1.from_json_file(PROFILE_PATH)
    provider = profile.create_provider(
        transport=RecordingTransport({"choices": []}),
        environment={
            "AUTOLEAN_DEEPSEEK_BASE_URL": "https://endpoint-drift.example/v1",
            "AUTOLEAN_DEEPSEEK_API_KEY": "unit-test-token",
        },
    )
    assert provider._settings.base_url == "https://api.deepseek.com"
