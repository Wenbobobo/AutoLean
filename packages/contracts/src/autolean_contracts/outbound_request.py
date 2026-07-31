"""Credential-free request-body evidence for provider egress."""

from __future__ import annotations

import json
from typing import Final, Literal, Self

from pydantic import Field, model_validator

from .base import ContractModel
from .hashing import (
    DigestV1,
    HashKindV1,
    canonical_json_bytes,
    digest_bytes,
    require_digest_kind,
)

_CANONICAL_JSON_UTF8_V1: Final[Literal["canonical_json_utf8_v1"]] = "canonical_json_utf8_v1"


class OutboundRequestBodyV1(ContractModel):
    """Public-safe binding for an exact credential-free HTTP JSON body.

    The body itself is intentionally not a contract field: it can contain source-authorized prompt
    text and belongs only at the send boundary.  Authentication headers are not JSON body bytes and
    are never represented here.
    """

    schema_version: Literal["autolean.outbound-request-body.v1"] = (
        "autolean.outbound-request-body.v1"
    )
    media_type: Literal["application/json"] = "application/json"
    serialization: Literal["canonical_json_utf8_v1"] = _CANONICAL_JSON_UTF8_V1
    body_hash: DigestV1
    body_size_bytes: int = Field(ge=2, le=16_777_216)

    @model_validator(mode="after")
    def validate_body_hash(self) -> Self:
        require_digest_kind(
            self.body_hash,
            HashKindV1.OUTBOUND_REQUEST_BODY,
            "body_hash",
        )
        return self


def outbound_request_body_binding(body: bytes) -> OutboundRequestBodyV1:
    """Bind canonical JSON object bytes without retaining them in a contract."""

    if not isinstance(body, bytes) or len(body) < 2:
        raise ValueError("outbound request body must be a non-empty JSON byte string")
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        raise ValueError("outbound request body must be valid UTF-8 JSON") from error
    if not isinstance(parsed, dict) or canonical_json_bytes(parsed) != body:
        raise ValueError("outbound request body must use canonical JSON object bytes")
    return OutboundRequestBodyV1(
        body_hash=digest_bytes(HashKindV1.OUTBOUND_REQUEST_BODY, body),
        body_size_bytes=len(body),
    )
