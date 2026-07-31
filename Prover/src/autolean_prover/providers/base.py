from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable

from autolean_contracts import (
    DigestV1,
    EndpointClassV1,
    HashKindV1,
    OutboundRequestBodyV1,
    canonical_json_bytes,
    digest_model,
    outbound_request_body_binding,
)
from autolean_contracts.hashing import require_digest_kind

from autolean_prover.errors import CapabilityError, ConfigurationError
from autolean_prover.providers.policy import (
    validate_positive_timeout,
    validate_reasoning_effort,
)

if TYPE_CHECKING:
    from autolean_prover.context import ContextPack

MAX_MODEL_REQUEST_TIMEOUT_SECONDS = 3600.0


class Capability(StrEnum):
    TEXT_GENERATION = "text_generation"
    USAGE_ACCOUNTING = "usage_accounting"
    REASONING_EFFORT = "reasoning_effort"
    STRUCTURED_JSON = "structured_json"
    TOOL_CALLING = "tool_calling"
    STREAMING = "streaming"
    LOCAL_EXECUTION = "local_execution"
    CUSTOM_ENDPOINT = "custom_endpoint"


@dataclass(frozen=True, slots=True)
class ProviderCapabilities:
    values: frozenset[Capability]

    def __post_init__(self) -> None:
        if not isinstance(self.values, frozenset) or not all(
            isinstance(value, Capability) for value in self.values
        ):
            raise ConfigurationError(
                "provider capabilities must be a frozenset of Capability values"
            )

    @classmethod
    def of(cls, *values: Capability) -> ProviderCapabilities:
        return cls(frozenset(values))

    def require(self, required: Iterable[Capability], *, provider_id: str) -> None:
        missing = frozenset(required) - self.values
        if missing:
            names = ", ".join(sorted(value.value for value in missing))
            raise CapabilityError(f"provider {provider_id!r} lacks required capabilities: {names}")


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    description: str
    parameters: Mapping[str, object]
    strict: bool = True

    def __post_init__(self) -> None:
        if not self.name or not self.name.replace("_", "").isalnum():
            raise ConfigurationError(f"invalid tool name: {self.name!r}")


@dataclass(frozen=True, slots=True)
class ToolCall:
    call_id: str
    name: str
    arguments_json: str


@dataclass(frozen=True, slots=True)
class TokenUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    cached_input_tokens: int = 0

    def __post_init__(self) -> None:
        values = (self.input_tokens, self.output_tokens, self.cached_input_tokens)
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in values
        ):
            raise ConfigurationError("token usage must contain non-negative integer values")
        if self.cached_input_tokens > self.input_tokens:
            raise ConfigurationError("cached_input_tokens cannot exceed input_tokens")


@dataclass(frozen=True, slots=True)
class CanonicalJsonRequestBody:
    """Exact credential-free JSON bytes prepared for one provider transport call.

    ``binding`` is safe to retain as evidence; ``body`` remains an in-memory send input and must
    not be copied into public reports or response artifacts.
    """

    body: bytes
    binding: OutboundRequestBodyV1

    def __post_init__(self) -> None:
        if not isinstance(self.body, bytes):
            raise ConfigurationError("canonical JSON request body must be bytes")
        try:
            expected = outbound_request_body_binding(self.body)
        except ValueError as error:
            raise ConfigurationError("canonical JSON request body is invalid") from error
        if self.binding != expected:
            raise ConfigurationError("canonical JSON request body binding does not match its bytes")


def canonical_json_request_body(payload: Mapping[str, object]) -> CanonicalJsonRequestBody:
    """Serialize one credential-free provider payload into its exact JSON wire bytes."""

    if not isinstance(payload, Mapping):
        raise ConfigurationError("canonical JSON request payload must be a mapping")
    try:
        body = canonical_json_bytes(dict(payload))
        binding = outbound_request_body_binding(body)
    except (TypeError, ValueError) as error:
        raise ConfigurationError("canonical JSON request payload is not serializable") from error
    return CanonicalJsonRequestBody(body=body, binding=binding)


@dataclass(frozen=True, slots=True)
class ModelRequest:
    prompt: str
    system_prompt: str | None = None
    max_input_tokens: int = 4096
    max_output_tokens: int = 4096
    timeout_seconds: float | None = None
    reasoning_effort: str | None = None
    response_format: Literal["json_object"] | None = None
    tools: tuple[ToolSpec, ...] = ()
    required_capabilities: frozenset[Capability] = field(default_factory=frozenset)
    working_directory: Path | None = None
    context_pack_hash: DigestV1 | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.prompt, str) or not self.prompt.strip():
            raise ConfigurationError("model prompt cannot be empty")
        if self.system_prompt is not None and not isinstance(self.system_prompt, str):
            raise ConfigurationError("system_prompt must be a string or None")
        for label, value in (
            ("max_input_tokens", self.max_input_tokens),
            ("max_output_tokens", self.max_output_tokens),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ConfigurationError(f"{label} must be positive")
        if self.timeout_seconds is not None:
            validate_positive_timeout(
                self.timeout_seconds,
                label="model request timeout_seconds",
            )
            if self.timeout_seconds > MAX_MODEL_REQUEST_TIMEOUT_SECONDS:
                raise ConfigurationError(
                    "model request timeout_seconds exceeds the supported upper bound"
                )
        validate_reasoning_effort(self.reasoning_effort, label="reasoning_effort")
        if self.response_format not in {None, "json_object"}:
            raise ConfigurationError("response_format must be None or 'json_object'")
        if not isinstance(self.required_capabilities, frozenset) or not all(
            isinstance(value, Capability) for value in self.required_capabilities
        ):
            raise ConfigurationError(
                "required_capabilities must be a frozenset of Capability values"
            )
        if not isinstance(self.tools, tuple) or not all(
            isinstance(tool, ToolSpec) for tool in self.tools
        ):
            raise ConfigurationError("tools must be a tuple of ToolSpec values")
        if self.working_directory is not None and (
            not isinstance(self.working_directory, Path) or not self.working_directory.is_absolute()
        ):
            raise ConfigurationError("working_directory must be an absolute path")
        if self.context_pack_hash is not None:
            try:
                require_digest_kind(
                    self.context_pack_hash,
                    HashKindV1.PROMPT,
                    "context_pack_hash",
                )
            except ValueError as error:
                raise ConfigurationError(str(error)) from error

    @classmethod
    def from_context_pack(
        cls,
        context_pack: ContextPack,
        *,
        system_prompt: str | None = None,
        max_input_tokens: int = 4096,
        max_output_tokens: int = 4096,
        timeout_seconds: float | None = None,
        reasoning_effort: str | None = None,
        response_format: Literal["json_object"] | None = None,
        tools: tuple[ToolSpec, ...] = (),
        required_capabilities: frozenset[Capability] = frozenset(),
        working_directory: Path | None = None,
    ) -> ModelRequest:
        """Create an egress request whose prompt is exactly a frozen ContextPack projection."""

        from autolean_prover.context import ContextPack as RuntimeContextPack

        if not isinstance(context_pack, RuntimeContextPack):
            raise ConfigurationError("context_pack must be a ContextPack")
        return cls(
            prompt=context_pack.render(),
            system_prompt=system_prompt,
            max_input_tokens=max_input_tokens,
            max_output_tokens=max_output_tokens,
            timeout_seconds=timeout_seconds,
            reasoning_effort=reasoning_effort,
            response_format=response_format,
            tools=tools,
            required_capabilities=required_capabilities,
            working_directory=working_directory,
            context_pack_hash=context_pack.content_hash(),
        )

    def outbound_request_hash(self) -> DigestV1:
        """Hash all outbound model inputs without storing their raw text in an authorization."""

        try:
            return digest_model(
                HashKindV1.PROMPT,
                {
                    "schema_version": "autolean.model-request.v3",
                    "prompt": self.prompt,
                    "system_prompt": self.system_prompt,
                    "max_input_tokens": self.max_input_tokens,
                    "max_output_tokens": self.max_output_tokens,
                    "timeout_seconds": self.timeout_seconds,
                    "reasoning_effort": self.reasoning_effort,
                    "response_format": self.response_format,
                    "tools": [
                        {
                            "name": tool.name,
                            "description": tool.description,
                            "parameters": dict(tool.parameters),
                            "strict": tool.strict,
                        }
                        for tool in self.tools
                    ],
                    "required_capabilities": sorted(
                        capability.value for capability in self.required_capabilities
                    ),
                    "working_directory": (
                        None if self.working_directory is None else str(self.working_directory)
                    ),
                    "context_pack_hash": (
                        None
                        if self.context_pack_hash is None
                        else self.context_pack_hash.model_dump(mode="json")
                    ),
                },
            )
        except (TypeError, ValueError) as error:
            raise ConfigurationError("model request cannot be canonically hashed") from error

    def inferred_capabilities(self) -> frozenset[Capability]:
        required = set(self.required_capabilities)
        required.add(Capability.TEXT_GENERATION)
        if self.reasoning_effort is not None:
            required.add(Capability.REASONING_EFFORT)
        if self.response_format is not None:
            required.add(Capability.STRUCTURED_JSON)
        if self.tools:
            required.add(Capability.TOOL_CALLING)
        if self.working_directory is not None:
            required.add(Capability.LOCAL_EXECUTION)
        return frozenset(required)


@dataclass(frozen=True, slots=True)
class ModelExecutionTimeoutPolicyV1:
    """Local, immutable execution deadline policy for one registered provider."""

    configured_ceiling_seconds: float

    def __post_init__(self) -> None:
        validate_positive_timeout(
            self.configured_ceiling_seconds,
            label="provider configured timeout ceiling",
        )
        object.__setattr__(
            self,
            "configured_ceiling_seconds",
            float(self.configured_ceiling_seconds),
        )

    def effective_timeout_seconds(self, request: ModelRequest) -> float:
        """Return the actual provider deadline without probing or performing I/O."""

        return effective_model_timeout_seconds(
            request,
            provider_timeout_seconds=self.configured_ceiling_seconds,
        )


@dataclass(frozen=True, slots=True)
class ModelResponse:
    provider_id: str
    model_id: str
    text: str
    response_id: str | None = None
    tool_calls: tuple[ToolCall, ...] = ()
    usage: TokenUsage = field(default_factory=TokenUsage)


@runtime_checkable
class ModelProvider(Protocol):
    @property
    def provider_id(self) -> str: ...

    @property
    def model_id(self) -> str: ...

    @property
    def endpoint_class(self) -> EndpointClassV1: ...

    @property
    def configuration_hash(self) -> DigestV1: ...

    @property
    def capabilities(self) -> ProviderCapabilities: ...

    @property
    def execution_timeout_policy(self) -> ModelExecutionTimeoutPolicyV1: ...

    def generate(self, request: ModelRequest) -> ModelResponse: ...


def require_request_capabilities(provider: ModelProvider, request: ModelRequest) -> None:
    provider.capabilities.require(request.inferred_capabilities(), provider_id=provider.provider_id)


def effective_model_timeout_seconds(
    request: ModelRequest,
    *,
    provider_timeout_seconds: float,
) -> float:
    """Return the enforced deadline; a request may only lower the provider ceiling."""

    validate_positive_timeout(
        provider_timeout_seconds,
        label="provider timeout_seconds",
    )
    if request.timeout_seconds is None:
        return float(provider_timeout_seconds)
    return min(float(provider_timeout_seconds), float(request.timeout_seconds))
