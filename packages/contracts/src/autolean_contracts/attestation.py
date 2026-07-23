"""Versioned attestation primitives for AutoLean trust boundaries.

The process-local HMAC-SHA256 implementation is a test fixture, not a production authority.  The
public interfaces separate signing from verification so a remote KMS/HSM authority can replace
key custody without changing Builder--Prover semantics.  An asymmetric signature needs a future
versioned attestation schema because ``AttestationV1`` intentionally fixes a 32-byte HMAC.
"""

from __future__ import annotations

import hmac
import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol

from pydantic import Field, model_validator

from .base import ContractModel
from .hashing import DigestV1, HashKindV1, canonical_json_bytes, digest_model, require_digest_kind

_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_NONCE = re.compile(r"^[A-Za-z0-9._-]{16,256}$")
_SIGNATURE = re.compile(r"^[0-9a-f]{64}$")
_DOMAIN = "autolean.attestation.hmac-sha256.v1"
_PAYLOAD_DOMAIN = "autolean.attestation.payload.v1"


class AttestationPurposeV1(StrEnum):
    """The mutually exclusive authority domains accepted by V1."""

    BUILDER_FREEZE = "builder_freeze"
    VERIFICATION = "verification"
    MODEL_EXECUTION = "model_execution"


class AttestationError(ValueError):
    """An attestation failed a local cryptographic or authority-policy check."""


class AttestationV1(ContractModel):
    """Public, serializable metadata for one signed authority decision.

    ``signature`` is an authenticator, not a secret.  The key material is deliberately absent
    from this model and must never be put into an artifact, bundle, workspace, log, or endpoint
    configuration.
    """

    schema_version: str = "1.0"
    purpose: AttestationPurposeV1
    key_id: str = Field(min_length=1, max_length=128)
    issued_at: datetime
    expires_at: datetime
    nonce: str = Field(min_length=16, max_length=256)
    evidence_identity: str = Field(min_length=1, max_length=512)
    payload_hash: DigestV1
    signature: str = Field(min_length=64, max_length=64)

    @model_validator(mode="after")
    def validate_attestation(self) -> AttestationV1:
        if self.schema_version != "1.0":
            raise ValueError("unsupported attestation schema version")
        if not _KEY_ID.fullmatch(self.key_id):
            raise ValueError("attestation key_id is not a safe identifier")
        if not _NONCE.fullmatch(self.nonce):
            raise ValueError("attestation nonce is not a safe V1 nonce")
        if not _SIGNATURE.fullmatch(self.signature):
            raise ValueError("attestation signature must be a lowercase SHA-256 HMAC")
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("attestation timestamps must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("attestation expiry must be after issuance")
        require_digest_kind(
            self.payload_hash,
            HashKindV1.ATTESTATION_PAYLOAD,
            "payload_hash",
        )
        return self


@dataclass(frozen=True, slots=True)
class HmacAttestationKeyV1:
    """Test-fixture HMAC key material.

    This is intentionally a normal runtime object rather than a contract model.  It cannot be
    serialized by ``model_dump`` and its secret is omitted from ``repr`` and equality checks.
    """

    key_id: str
    secret: bytes = field(repr=False, compare=False)
    allowed_purposes: frozenset[AttestationPurposeV1]
    revoked: bool = False

    def __post_init__(self) -> None:
        if not _KEY_ID.fullmatch(self.key_id):
            raise ValueError("attestation key_id is not a safe identifier")
        if len(self.secret) < 32:
            raise ValueError("HMAC attestation secrets must contain at least 32 bytes")
        if not self.allowed_purposes:
            raise ValueError("an attestation key must authorize at least one purpose")


class AttestationSignerV1(Protocol):
    """Signing side of a replaceable attestation authority."""

    def issue(
        self,
        *,
        purpose: AttestationPurposeV1,
        payload: Mapping[str, object],
        evidence_identity: str,
        ttl_seconds: float,
        nonce: str | None = None,
    ) -> AttestationV1: ...


class AttestationVerifierV1(Protocol):
    """Verification side of a replaceable attestation authority."""

    def verify(
        self,
        attestation: AttestationV1,
        *,
        expected_purpose: AttestationPurposeV1,
        payload: Mapping[str, object],
    ) -> None: ...


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _normalized_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise AttestationError("attestation clock returned a naive timestamp")
    return value.astimezone(UTC)


def _utc_text(value: datetime) -> str:
    return _normalized_utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _payload_envelope(
    purpose: AttestationPurposeV1,
    payload: Mapping[str, object],
) -> dict[str, object]:
    """Create the domain-separated hash preimage for an authority payload."""

    return {
        "schema_version": "1.0",
        "domain": _PAYLOAD_DOMAIN,
        "purpose": purpose.value,
        "payload": dict(payload),
    }


def attestation_payload_hash(
    purpose: AttestationPurposeV1,
    payload: Mapping[str, object],
) -> DigestV1:
    """Return a canonical, purpose-separated digest of an attested payload."""

    return digest_model(HashKindV1.ATTESTATION_PAYLOAD, _payload_envelope(purpose, payload))


def _signature_message(attestation: AttestationV1) -> bytes:
    """Produce the exact HMAC preimage without ever exposing a key."""

    envelope = {
        "schema_version": "1.0",
        "domain": _DOMAIN,
        "purpose": attestation.purpose.value,
        "key_id": attestation.key_id,
        "issued_at": _utc_text(attestation.issued_at),
        "expires_at": _utc_text(attestation.expires_at),
        "nonce": attestation.nonce,
        "evidence_identity": attestation.evidence_identity,
        "payload_hash": attestation.payload_hash.value,
    }
    return canonical_json_bytes(envelope)


def _signature(secret: bytes, attestation: AttestationV1) -> str:
    return hmac.digest(secret, _signature_message(attestation), "sha256").hex()


@dataclass(frozen=True, slots=True)
class HmacAttestationSignerV1:
    """Test-only signer backed by one process-local HMAC key.

    Do not inject this object into a production Prover or worker.  Production verification uses
    the dedicated signing-gateway request contract and a non-exportable authority.
    """

    key: HmacAttestationKeyV1
    clock: Callable[[], datetime] = field(default=_utc_now, repr=False, compare=False)

    def issue(
        self,
        *,
        purpose: AttestationPurposeV1,
        payload: Mapping[str, object],
        evidence_identity: str,
        ttl_seconds: float,
        nonce: str | None = None,
    ) -> AttestationV1:
        if self.key.revoked:
            raise AttestationError("a revoked attestation key cannot issue a signature")
        if purpose not in self.key.allowed_purposes:
            raise AttestationError("attestation key is not authorized for this purpose")
        if not evidence_identity.strip():
            raise AttestationError("attestation evidence_identity must not be empty")
        if ttl_seconds <= 0:
            raise AttestationError("attestation ttl_seconds must be positive")
        issued_at = _normalized_utc(self.clock())
        expires_at = issued_at + timedelta(seconds=ttl_seconds)
        actual_nonce = nonce or secrets.token_hex(24)
        payload_hash = attestation_payload_hash(purpose, payload)
        unsigned = AttestationV1(
            purpose=purpose,
            key_id=self.key.key_id,
            issued_at=issued_at,
            expires_at=expires_at,
            nonce=actual_nonce,
            evidence_identity=evidence_identity,
            payload_hash=payload_hash,
            signature="0" * 64,
        )
        return unsigned.model_copy(update={"signature": _signature(self.key.secret, unsigned)})


@dataclass(frozen=True, slots=True)
class HmacAttestationVerifierV1:
    """Test-only verification keyring with explicit roles and revocation state.

    This verifier necessarily has the same secret bytes as a signer and therefore cannot
    establish worker/control-plane independence.  It exists for deterministic protocol tests;
    production V1 must use an isolated KMS/HSM verify operation, while asymmetric verification
    requires a versioned attestation schema.
    """

    keys: Mapping[str, HmacAttestationKeyV1]
    clock: Callable[[], datetime] = field(default=_utc_now, repr=False, compare=False)

    def __post_init__(self) -> None:
        copied = dict(self.keys)
        if not copied:
            raise ValueError("an attestation verifier requires at least one trusted key")
        if any(key_id != key.key_id for key_id, key in copied.items()):
            raise ValueError("attestation keyring keys must match their key_id")
        object.__setattr__(self, "keys", MappingProxyType(copied))

    def verify(
        self,
        attestation: AttestationV1,
        *,
        expected_purpose: AttestationPurposeV1,
        payload: Mapping[str, object],
    ) -> None:
        if attestation.purpose is not expected_purpose:
            raise AttestationError("attestation purpose does not match the requested authority")
        key = self.keys.get(attestation.key_id)
        if key is None:
            raise AttestationError("attestation key is not in the trusted allowlist")
        if key.revoked:
            raise AttestationError("attestation key is revoked")
        if expected_purpose not in key.allowed_purposes:
            raise AttestationError("attestation key is not authorized for this purpose")
        if expected_purpose in {
            AttestationPurposeV1.BUILDER_FREEZE,
            AttestationPurposeV1.VERIFICATION,
        } and key.allowed_purposes != frozenset({expected_purpose}):
            raise AttestationError("Builder and verifier authority keys must be role-dedicated")
        now = _normalized_utc(self.clock())
        if attestation.issued_at > now:
            raise AttestationError("attestation was issued in the future")
        if attestation.expires_at <= now:
            raise AttestationError("attestation has expired")
        expected_payload_hash = attestation_payload_hash(expected_purpose, payload)
        if not hmac.compare_digest(attestation.payload_hash.value, expected_payload_hash.value):
            raise AttestationError("attestation payload hash does not match")
        if not hmac.compare_digest(attestation.signature, _signature(key.secret, attestation)):
            raise AttestationError("attestation signature does not match")
