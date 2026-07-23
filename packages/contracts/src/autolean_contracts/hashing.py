from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping
from enum import StrEnum
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from .base import ContractModel


class HashKindV1(StrEnum):
    SOURCE_BYTES = "source_bytes"
    SOURCE_SPAN = "source_span"
    SOURCE_PREPARATION = "source_preparation"
    STATEMENT_SOURCE = "statement_source"
    ELABORATED_TYPE = "elaborated_type"
    ENVIRONMENT = "environment"
    GRAPH_SNAPSHOT = "graph_snapshot"
    CONTRACT = "contract"
    PROOF_SOURCE = "proof_source"
    TRUSTED_STATEMENT = "trusted_statement"
    WORKSPACE_MANIFEST = "workspace_manifest"
    PROOF_BOUNDARY = "proof_boundary"
    BUNDLE = "bundle"
    FREEZE_EVIDENCE = "freeze_evidence"
    VERIFICATION_REPORT = "verification_report"
    VERIFICATION_EVIDENCE = "verification_evidence"
    DEPENDENCY_MANIFEST = "dependency_manifest"
    VERIFICATION_COMMAND = "verification_command"
    MODEL_EXECUTION_APPROVAL = "model_execution_approval"
    MODEL_EXECUTION_AUTHORIZATION = "model_execution_authorization"
    ATTESTATION_PAYLOAD = "attestation_payload"
    EVENT = "event"
    CONFIG = "config"
    PROMPT = "prompt"
    TOOL = "tool"


class DigestV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    kind: HashKindV1
    algorithm: Literal["sha256"] = "sha256"
    value: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("value", mode="before")
    @classmethod
    def lowercase_digest(cls, value: object) -> object:
        return value.lower() if isinstance(value, str) else value


class StableIdentifierV1(ContractModel):
    """A durable identity, intentionally unrelated to mutable content hashes."""

    schema_version: Literal["1.0"] = "1.0"
    namespace: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z0-9_.-]+$",
    )
    value: str = Field(pattern=r"^urn:autolean:v1:[a-z0-9_.-]+:[0-9a-f-]{36}$")

    @model_validator(mode="after")
    def validate_namespace(self) -> StableIdentifierV1:
        prefix = "urn:autolean:v1:"
        embedded_namespace, _separator, _uuid = self.value.removeprefix(prefix).rpartition(":")
        if not embedded_namespace or embedded_namespace != self.namespace:
            raise ValueError("identifier namespace must match the namespace embedded in value")
        return self


def canonical_json_bytes(value: Any) -> bytes:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json", exclude_none=False)
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def digest_bytes(kind: HashKindV1, payload: bytes) -> DigestV1:
    return DigestV1(kind=kind, value=hashlib.sha256(payload).hexdigest())


def digest_text(kind: HashKindV1, payload: str) -> DigestV1:
    return digest_bytes(kind, payload.encode("utf-8"))


def digest_model(
    kind: HashKindV1,
    value: Any,
    *,
    exclude: set[str] | Mapping[str, Any] | None = None,
) -> DigestV1:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json", exclude=exclude, exclude_none=False)
    return digest_bytes(kind, canonical_json_bytes(value))


def stable_identifier(namespace: str, external_key: str) -> StableIdentifierV1:
    if not namespace.strip():
        raise ValueError("namespace must not be empty")
    if not external_key:
        raise ValueError("external_key must not be empty")
    normalized_namespace = namespace.strip().lower().replace(" ", "-")
    identifier = uuid.uuid5(uuid.NAMESPACE_URL, f"autolean:{normalized_namespace}:{external_key}")
    return StableIdentifierV1(
        namespace=normalized_namespace,
        value=f"urn:autolean:v1:{normalized_namespace}:{identifier}",
    )


def require_digest_kind(digest: DigestV1, expected: HashKindV1, field_name: str) -> None:
    if digest.kind is not expected:
        raise ValueError(f"{field_name} must use digest kind {expected.value}")
