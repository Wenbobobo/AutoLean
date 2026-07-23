from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass

from autolean_contracts import DigestV1, EndpointClassV1, HashKindV1, digest_model

from autolean_prover.errors import ConfigurationError, ProviderResponseError
from autolean_prover.execution import ExecutionHarness, ProcessRequest
from autolean_prover.providers.base import (
    Capability,
    ModelRequest,
    ModelResponse,
    ProviderCapabilities,
    TokenUsage,
    require_request_capabilities,
)
from autolean_prover.providers.policy import (
    validate_positive_timeout,
    validate_provider_identity,
    validate_reasoning_effort,
)


@dataclass(frozen=True, slots=True)
class CodexCliSettings:
    model_id: str
    binary: str = "codex"
    sandbox: str = "read-only"
    default_reasoning_effort: str | None = None
    timeout_seconds: float = 900.0
    max_output_bytes: int = 16 * 1024 * 1024

    def __post_init__(self) -> None:
        validate_provider_identity("codex-cli", self.model_id)
        if not isinstance(self.binary, str) or not self.binary.strip() or "\x00" in self.binary:
            raise ConfigurationError("Codex CLI model_id and binary must not be empty")
        if self.sandbox != "read-only":
            raise ConfigurationError(
                "Codex CLI sandbox must remain read-only until a verified patch worker is enabled"
            )
        validate_reasoning_effort(
            self.default_reasoning_effort,
            label="Codex CLI default_reasoning_effort",
        )
        validate_positive_timeout(self.timeout_seconds, label="Codex CLI timeout_seconds")
        if isinstance(self.max_output_bytes, bool) or not isinstance(self.max_output_bytes, int):
            raise ConfigurationError("Codex CLI max_output_bytes must be a positive integer")
        if self.max_output_bytes <= 0:
            raise ConfigurationError("Codex CLI max_output_bytes must be a positive integer")


class CodexCliProvider:
    _CAPABILITIES = ProviderCapabilities.of(
        Capability.TEXT_GENERATION,
        Capability.USAGE_ACCOUNTING,
        Capability.REASONING_EFFORT,
        Capability.LOCAL_EXECUTION,
    )

    def __init__(self, settings: CodexCliSettings, *, harness: ExecutionHarness) -> None:
        self._settings = settings
        self._harness = harness

    @property
    def provider_id(self) -> str:
        return "codex-cli"

    @property
    def model_id(self) -> str:
        return self._settings.model_id

    @property
    def endpoint_class(self) -> EndpointClassV1:
        return EndpointClassV1.LOCAL

    @property
    def configuration_hash(self) -> DigestV1:
        return digest_model(
            HashKindV1.CONFIG,
            {
                "schema_version": "autolean.provider-config.codex-cli.v1",
                "provider_id": self.provider_id,
                "model_id": self.model_id,
                "endpoint_class": self.endpoint_class.value,
                "binary": self._settings.binary,
                "sandbox": self._settings.sandbox,
                "default_reasoning_effort": self._settings.default_reasoning_effort,
                "timeout_seconds": self._settings.timeout_seconds,
                "max_output_bytes": self._settings.max_output_bytes,
            },
        )

    @property
    def capabilities(self) -> ProviderCapabilities:
        return self._CAPABILITIES

    def generate(self, request: ModelRequest) -> ModelResponse:
        require_request_capabilities(self, request)
        if request.working_directory is None:
            raise ConfigurationError("Codex CLI requests require a working_directory")
        argv = self._build_argv(request)
        result = self._harness.execute(
            ProcessRequest(
                argv=argv,
                cwd=request.working_directory,
                stdin=self._stdin_prompt(request),
                timeout_seconds=self._settings.timeout_seconds,
                max_output_bytes=self._settings.max_output_bytes,
            )
        )
        if result.timed_out:
            raise ProviderResponseError("Codex CLI timed out")
        if result.output_truncated:
            raise ProviderResponseError("Codex CLI output exceeded the configured limit")
        if result.returncode != 0:
            # CLI stderr can contain endpoint or credential-adjacent diagnostics.  It is never
            # safe to promote into a report, event, or dashboard-visible error message.
            raise ProviderResponseError(f"Codex CLI exited with {result.returncode}")
        return self._parse_jsonl(result.stdout)

    def _build_argv(self, request: ModelRequest) -> tuple[str, ...]:
        argv = [
            self._settings.binary,
            "exec",
            "--json",
            "--ephemeral",
            "--skip-git-repo-check",
            "--sandbox",
            self._settings.sandbox,
            "-m",
            self.model_id,
        ]
        effort = request.reasoning_effort or self._settings.default_reasoning_effort
        if effort is not None:
            argv.extend(("-c", f'model_reasoning_effort="{effort}"'))
        argv.append("-")
        return tuple(argv)

    @staticmethod
    def _stdin_prompt(request: ModelRequest) -> str:
        if request.system_prompt:
            return f"{request.system_prompt}\n\n{request.prompt}"
        return request.prompt

    def _parse_jsonl(self, output: str) -> ModelResponse:
        text_parts: list[str] = []
        usage = TokenUsage()
        response_id: str | None = None
        for line_number, line in enumerate(output.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ProviderResponseError(
                    f"Codex CLI emitted invalid JSON on line {line_number}"
                ) from exc
            if not isinstance(event, dict):
                raise ProviderResponseError(
                    f"Codex CLI event on line {line_number} is not an object"
                )
            event_type = event.get("type")
            if event_type in {"thread.started", "session_start"}:
                candidate = event.get("thread_id", event.get("session_id"))
                if isinstance(candidate, str):
                    response_id = candidate
            if event_type == "item.completed":
                item = event.get("item")
                if isinstance(item, dict) and item.get("type") == "agent_message":
                    message = item.get("text")
                    if isinstance(message, str):
                        text_parts.append(message)
            elif event_type in {"message", "agent_message"}:
                message = event.get("text")
                if isinstance(message, str):
                    text_parts.append(message)
            event_usage = event.get("usage")
            if isinstance(event_usage, dict):
                usage = self._parse_usage(event_usage)
        if not text_parts:
            raise ProviderResponseError("Codex CLI stream contained no final agent message")
        return ModelResponse(
            provider_id=self.provider_id,
            model_id=self.model_id,
            text="".join(text_parts),
            response_id=response_id,
            usage=usage,
        )

    @staticmethod
    def _parse_usage(value: Mapping[str, object]) -> TokenUsage:
        def read(*keys: str) -> int:
            for key in keys:
                item = value.get(key)
                if item is not None:
                    if isinstance(item, bool) or not isinstance(item, int) or item < 0:
                        raise ProviderResponseError(
                            f"Codex usage field {key!r} must be a non-negative integer"
                        )
                    return item
            return 0

        return TokenUsage(
            input_tokens=read("input_tokens", "inputTokens"),
            output_tokens=read("output_tokens", "outputTokens"),
            cached_input_tokens=read("cached_input_tokens", "cachedInputTokens"),
        )
