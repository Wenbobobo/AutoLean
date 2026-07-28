"""Operator-private response CAS used before model-execution settlement.

The local filesystem implementation is a test and single-host adapter.  Production deployments
may replace it through :class:`PrivateModelOutputStore` without changing receipt semantics.
"""

from __future__ import annotations

import os
import secrets
from contextlib import suppress
from pathlib import Path
from typing import Protocol, runtime_checkable

from autolean_contracts import (
    ModelResponseArtifactRefV1,
    ModelResponseArtifactV1,
    ModelResponseToolCallV1,
    ModelResponseUsageV1,
)

from ..errors import ProviderResponseError
from .base import ModelResponse, TokenUsage, ToolCall


def model_response_artifact(response: ModelResponse) -> ModelResponseArtifactV1:
    """Normalize one validated provider response without endpoint or credential metadata."""

    if not isinstance(response, ModelResponse):
        raise ProviderResponseError("private model output requires a ModelResponse")
    return ModelResponseArtifactV1(
        provider_id=response.provider_id,
        model_id=response.model_id,
        response_id=response.response_id,
        text=response.text,
        tool_calls=tuple(
            ModelResponseToolCallV1(
                call_id=item.call_id,
                name=item.name,
                arguments_json=item.arguments_json,
            )
            for item in response.tool_calls
        ),
        usage=ModelResponseUsageV1(
            input_tokens=response.usage.input_tokens,
            cached_input_tokens=response.usage.cached_input_tokens,
            output_tokens=response.usage.output_tokens,
        ),
    )


def response_from_artifact(artifact: ModelResponseArtifactV1) -> ModelResponse:
    return ModelResponse(
        provider_id=artifact.provider_id,
        model_id=artifact.model_id,
        response_id=artifact.response_id,
        text=artifact.text,
        tool_calls=tuple(
            ToolCall(
                call_id=item.call_id,
                name=item.name,
                arguments_json=item.arguments_json,
            )
            for item in artifact.tool_calls
        ),
        usage=TokenUsage(
            input_tokens=artifact.usage.input_tokens,
            cached_input_tokens=artifact.usage.cached_input_tokens,
            output_tokens=artifact.usage.output_tokens,
        ),
    )


@runtime_checkable
class PrivateModelOutputStore(Protocol):
    """Write, read, and independently re-hash an operator-private response artifact."""

    def put_response(self, response: ModelResponse) -> ModelResponseArtifactRefV1: ...

    def read_artifact(
        self,
        reference: ModelResponseArtifactRefV1,
    ) -> ModelResponseArtifactV1: ...

    def verify(self, reference: ModelResponseArtifactRefV1) -> None: ...

    def read_response(self, reference: ModelResponseArtifactRefV1) -> ModelResponse: ...


class LocalPrivateModelOutputStore:
    """Small content-addressed local adapter with write-then-read verification."""

    def __init__(self, root: Path) -> None:
        if not isinstance(root, Path) or not root.is_absolute():
            raise ValueError("private model output root must be an absolute Path")
        root.mkdir(parents=True, exist_ok=True)
        self._root = root.resolve(strict=True)
        if not self._root.is_dir():
            raise ValueError("private model output root must be a directory")

    def put_response(self, response: ModelResponse) -> ModelResponseArtifactRefV1:
        artifact = model_response_artifact(response)
        payload = artifact.canonical_bytes()
        reference = ModelResponseArtifactRefV1(
            artifact_digest=artifact.artifact_digest(),
            size_bytes=len(payload),
        )
        target = self._path(reference)
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            temporary = target.parent / f".{target.name}.{secrets.token_hex(16)}.tmp"
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, target)
            finally:
                with suppress(FileNotFoundError):
                    temporary.unlink()
        self.verify(reference)
        return reference

    def read_artifact(
        self,
        reference: ModelResponseArtifactRefV1,
    ) -> ModelResponseArtifactV1:
        """Parse and verify one immutable byte snapshot exactly once."""

        payload = self._read(reference)
        try:
            artifact = ModelResponseArtifactV1.model_validate_json(payload)
        except ValueError as error:
            raise ProviderResponseError("private model response artifact is invalid") from error
        if (
            artifact.canonical_bytes() != payload
            or artifact.artifact_digest() != reference.artifact_digest
        ):
            raise ProviderResponseError("private model response artifact is not canonical")
        return artifact

    def verify(self, reference: ModelResponseArtifactRefV1) -> None:
        self.read_artifact(reference)

    def read_response(self, reference: ModelResponseArtifactRefV1) -> ModelResponse:
        return response_from_artifact(self.read_artifact(reference))

    def _read(self, reference: ModelResponseArtifactRefV1) -> bytes:
        try:
            payload = self._path(reference).read_bytes()
        except OSError as error:
            raise ProviderResponseError("private model response artifact is unavailable") from error
        if len(payload) != reference.size_bytes:
            raise ProviderResponseError("private model response artifact size is inconsistent")
        return payload

    def _path(self, reference: ModelResponseArtifactRefV1) -> Path:
        digest = reference.artifact_digest.value
        candidate = self._root / digest[:2] / digest[2:]
        resolved = candidate.resolve(strict=False)
        if self._root not in resolved.parents:
            raise ProviderResponseError("private model response path escaped its store")
        return resolved
