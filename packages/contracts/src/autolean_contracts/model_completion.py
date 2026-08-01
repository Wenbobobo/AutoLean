"""Private, output-bound completion evidence for one authorized model execution.

The complete receipt is operator-private because a raw content digest can be enumerable for
low-entropy responses.  Public consumers receive only :class:`ModelExecutionCompletionPublicV1`,
whose salted output commitment is not a CAS locator.
"""

from __future__ import annotations

import re
import secrets
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, model_validator

from .attestation import (
    AttestationPurposeV1,
    AttestationV1,
    attestation_payload_hash,
)
from .authorization import (
    ModelExecutionAuthorizationError,
    ModelExecutionAuthorizationV1,
    ModelExecutionReservationV1,
)
from .base import ContractModel
from .hashing import (
    DigestV1,
    HashKindV1,
    StableIdentifierV1,
    canonical_json_bytes,
    digest_bytes,
    digest_model,
    require_digest_kind,
    stable_identifier,
)

_COMMITMENT_NONCE = re.compile(r"^[0-9a-f]{64}$")
_LEDGER_EVENT_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("model execution timestamp must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


class ModelResponseToolCallV1(ContractModel):
    """One provider tool-call value retained only in the private response artifact."""

    call_id: str = Field(min_length=1, max_length=1024)
    name: str = Field(min_length=1, max_length=256)
    arguments_json: str = Field(max_length=8_388_608)


class ModelResponseUsageV1(ContractModel):
    input_tokens: int = Field(ge=0)
    cached_input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_cached_usage(self) -> Self:
        if self.cached_input_tokens > self.input_tokens:
            raise ValueError("cached input tokens cannot exceed input tokens")
        return self


class ModelResponseArtifactV1(ContractModel):
    """Canonical credential-free bytes for one private provider response."""

    schema_version: Literal["autolean.model-response-artifact.v1"] = (
        "autolean.model-response-artifact.v1"
    )
    provider_id: str = Field(min_length=1, max_length=256)
    model_id: str = Field(min_length=1, max_length=512)
    response_id: str | None = Field(default=None, max_length=2048)
    text: str = Field(max_length=16_777_216)
    tool_calls: tuple[ModelResponseToolCallV1, ...] = ()
    usage: ModelResponseUsageV1

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self)

    def artifact_digest(self) -> DigestV1:
        return digest_bytes(HashKindV1.MODEL_RESPONSE_ARTIFACT, self.canonical_bytes())


class ModelResponseArtifactRefV1(ContractModel):
    """Content address and size for an operator-private response CAS."""

    schema_version: Literal["autolean.model-response-artifact-ref.v1"] = (
        "autolean.model-response-artifact-ref.v1"
    )
    artifact_digest: DigestV1
    size_bytes: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_artifact_digest(self) -> Self:
        require_digest_kind(
            self.artifact_digest,
            HashKindV1.MODEL_RESPONSE_ARTIFACT,
            "artifact_digest",
        )
        return self


class ModelExecutionActualUsageV1(ContractModel):
    schema_version: Literal["autolean.model-execution-actual-usage.v1"] = (
        "autolean.model-execution-actual-usage.v1"
    )
    input_tokens: int = Field(ge=0)
    cached_input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(ge=0)
    actual_cost_microusd: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_cached_usage(self) -> Self:
        if self.cached_input_tokens > self.input_tokens:
            raise ValueError("cached input tokens cannot exceed input tokens")
        return self


def model_execution_output_commitment(
    *,
    authorization_hash: DigestV1,
    reservation_id: StableIdentifierV1,
    artifact: ModelResponseArtifactRefV1,
    commitment_nonce: str,
) -> DigestV1:
    """Return a salted public commitment that is not a private CAS locator."""

    require_digest_kind(
        authorization_hash,
        HashKindV1.MODEL_EXECUTION_AUTHORIZATION,
        "authorization_hash",
    )
    if _COMMITMENT_NONCE.fullmatch(commitment_nonce) is None:
        raise ValueError("model output commitment nonce must be 32-byte lowercase hex")
    return digest_model(
        HashKindV1.MODEL_OUTPUT_COMMITMENT,
        {
            "schema_version": "autolean.model-output-commitment.v1",
            "authorization_hash": authorization_hash.model_dump(mode="json"),
            "reservation_id": reservation_id.model_dump(mode="json"),
            "artifact": artifact.model_dump(mode="json"),
            "commitment_nonce": commitment_nonce,
        },
    )


class ModelExecutionPrivateOutputBindingV1(ContractModel):
    """Operator-private CAS coordinate plus a non-enumerable public commitment."""

    schema_version: Literal["autolean.model-execution-private-output.v1"] = (
        "autolean.model-execution-private-output.v1"
    )
    artifact: ModelResponseArtifactRefV1
    commitment_nonce: str = Field(pattern=r"^[0-9a-f]{64}$")
    public_output_commitment: DigestV1

    @model_validator(mode="after")
    def validate_commitment_kind(self) -> Self:
        require_digest_kind(
            self.public_output_commitment,
            HashKindV1.MODEL_OUTPUT_COMMITMENT,
            "public_output_commitment",
        )
        return self


def build_model_execution_private_output(
    *,
    authorization_hash: DigestV1,
    reservation_id: StableIdentifierV1,
    artifact: ModelResponseArtifactRefV1,
    commitment_nonce: str | None = None,
) -> ModelExecutionPrivateOutputBindingV1:
    nonce = commitment_nonce or secrets.token_hex(32)
    return ModelExecutionPrivateOutputBindingV1(
        artifact=artifact,
        commitment_nonce=nonce,
        public_output_commitment=model_execution_output_commitment(
            authorization_hash=authorization_hash,
            reservation_id=reservation_id,
            artifact=artifact,
            commitment_nonce=nonce,
        ),
    )


def model_execution_settlement_event_payload(
    *,
    authorization_hash: DigestV1,
    reservation: ModelExecutionReservationV1,
    actual_usage: ModelExecutionActualUsageV1,
    private_output: ModelExecutionPrivateOutputBindingV1,
    settled_at: datetime,
    settlement_event_id: str,
) -> dict[str, object]:
    return {
        "schema_version": "autolean.model-execution-settlement-event.v1",
        "authorization_hash": authorization_hash.model_dump(mode="json"),
        "reservation": reservation.model_dump(mode="json"),
        "actual_usage": actual_usage.model_dump(mode="json"),
        "private_output": private_output.model_dump(mode="json"),
        "settled_at": _utc_text(settled_at),
        "settlement_event_id": settlement_event_id,
    }


class ModelExecutionCompletionRecordV1(ContractModel):
    """Immutable settlement record before its dedicated completion signature is attached."""

    schema_version: Literal["autolean.model-execution-completion-record.v1"] = (
        "autolean.model-execution-completion-record.v1"
    )
    completion_id: StableIdentifierV1
    authorization: ModelExecutionAuthorizationV1
    authorization_hash: DigestV1
    reservation: ModelExecutionReservationV1
    actual_usage: ModelExecutionActualUsageV1
    private_output: ModelExecutionPrivateOutputBindingV1
    settled_at: datetime
    settlement_event_id: str
    settlement_event_hash: DigestV1

    @model_validator(mode="after")
    def validate_record(self) -> Self:
        if self.authorization_hash != self.authorization.authorization_hash():
            raise ValueError("completion authorization hash does not match its snapshot")
        if self.reservation.authorization_id != self.authorization.authorization_id:
            raise ValueError("completion reservation belongs to a different authorization")
        if (
            self.actual_usage.input_tokens > self.reservation.reserved_input_tokens
            or self.actual_usage.output_tokens > self.reservation.reserved_output_tokens
            or self.actual_usage.actual_cost_microusd > self.reservation.reserved_cost_microusd
        ):
            raise ValueError("completion usage exceeds its reservation")
        if self.settled_at.tzinfo is None:
            raise ValueError("completion settlement timestamp must be timezone-aware")
        if self.settled_at < self.reservation.reserved_at:
            raise ValueError("completion cannot settle before its reservation")
        if (
            self.settled_at > self.authorization.expires_at
            or self.settled_at > self.authorization.lease.expires_at
        ):
            raise ValueError("completion settlement is outside its authorized lease lifetime")
        if _LEDGER_EVENT_ID.fullmatch(self.settlement_event_id) is None:
            raise ValueError("completion settlement event id must be a lowercase UUID")
        expected_commitment = model_execution_output_commitment(
            authorization_hash=self.authorization_hash,
            reservation_id=self.reservation.reservation_id,
            artifact=self.private_output.artifact,
            commitment_nonce=self.private_output.commitment_nonce,
        )
        if self.private_output.public_output_commitment != expected_commitment:
            raise ValueError("completion public output commitment is inconsistent")
        expected_event_hash = digest_model(
            HashKindV1.MODEL_EXECUTION_SETTLEMENT,
            model_execution_settlement_event_payload(
                authorization_hash=self.authorization_hash,
                reservation=self.reservation,
                actual_usage=self.actual_usage,
                private_output=self.private_output,
                settled_at=self.settled_at,
                settlement_event_id=self.settlement_event_id,
            ),
        )
        if self.settlement_event_hash != expected_event_hash:
            raise ValueError("completion settlement event hash is inconsistent")
        expected_id = stable_identifier(
            "model-execution-completion",
            self.settlement_event_hash.value,
        )
        if self.completion_id != expected_id:
            raise ValueError("completion id is not derived from its settlement event")
        return self

    def record_hash(self) -> DigestV1:
        return digest_model(HashKindV1.MODEL_EXECUTION_COMPLETION, self)


def build_model_execution_completion_record(
    *,
    authorization: ModelExecutionAuthorizationV1,
    reservation: ModelExecutionReservationV1,
    actual_usage: ModelExecutionActualUsageV1,
    private_output: ModelExecutionPrivateOutputBindingV1,
    settled_at: datetime,
    settlement_event_id: str | None = None,
) -> ModelExecutionCompletionRecordV1:
    event_id = settlement_event_id or str(uuid.uuid4())
    authorization_hash = authorization.authorization_hash()
    event_hash = digest_model(
        HashKindV1.MODEL_EXECUTION_SETTLEMENT,
        model_execution_settlement_event_payload(
            authorization_hash=authorization_hash,
            reservation=reservation,
            actual_usage=actual_usage,
            private_output=private_output,
            settled_at=settled_at,
            settlement_event_id=event_id,
        ),
    )
    return ModelExecutionCompletionRecordV1(
        completion_id=stable_identifier("model-execution-completion", event_hash.value),
        authorization=authorization,
        authorization_hash=authorization_hash,
        reservation=reservation,
        actual_usage=actual_usage,
        private_output=private_output,
        settled_at=settled_at,
        settlement_event_id=event_id,
        settlement_event_hash=event_hash,
    )


def model_execution_completion_attestation_payload(
    record: ModelExecutionCompletionRecordV1,
) -> dict[str, object]:
    return {
        "schema_version": "autolean.model-execution-completion-attestation-payload.v1",
        "record": record.model_dump(mode="json"),
        "receipt_hash": record.record_hash().model_dump(mode="json"),
    }


def model_execution_completion_evidence_identity(
    record: ModelExecutionCompletionRecordV1,
) -> str:
    return f"model-execution-completion:{record.record_hash().value}"


class ModelExecutionCompletionReceiptV1(ContractModel):
    """Signed operator-private evidence for an output-bound settled reservation."""

    schema_version: Literal["autolean.model-execution-completion-receipt.v1"] = (
        "autolean.model-execution-completion-receipt.v1"
    )
    record: ModelExecutionCompletionRecordV1
    receipt_hash: DigestV1
    completion_attestation: AttestationV1

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        expected_hash = self.record.record_hash()
        if self.receipt_hash != expected_hash:
            raise ValueError("completion receipt hash does not match its record")
        attestation = self.completion_attestation
        if attestation.purpose is not AttestationPurposeV1.MODEL_EXECUTION_COMPLETION:
            raise ValueError("completion receipt uses the wrong attestation purpose")
        if attestation.evidence_identity != model_execution_completion_evidence_identity(
            self.record
        ):
            raise ValueError("completion attestation evidence identity is inconsistent")
        expected_payload_hash = attestation_payload_hash(
            AttestationPurposeV1.MODEL_EXECUTION_COMPLETION,
            model_execution_completion_attestation_payload(self.record),
        )
        if attestation.payload_hash != expected_payload_hash:
            raise ValueError("completion attestation payload hash is inconsistent")
        return self


class ModelExecutionCompletionRecoveryReasonV1(StrEnum):
    """Credential-free reason codes for an already-settled incomplete receipt."""

    PRIVATE_OUTPUT_UNAVAILABLE = "private_output_unavailable_v1"
    ATTESTATION_UNAVAILABLE = "completion_attestation_unavailable_v1"
    RECEIPT_PERSISTENCE_UNAVAILABLE = "completion_receipt_persistence_unavailable_v1"


class ModelExecutionCompletionRecoveryHandleV1(ContractModel):
    """Stable, credential-free coordinate for retrying receipt creation only."""

    schema_version: Literal["autolean.model-execution-completion-recovery.v1"] = (
        "autolean.model-execution-completion-recovery.v1"
    )
    reservation_id: StableIdentifierV1
    completion_id: StableIdentifierV1
    receipt_hash: DigestV1

    @model_validator(mode="after")
    def validate_handle(self) -> Self:
        if self.reservation_id.namespace != "model-execution-reservation":
            raise ValueError("completion recovery handle has the wrong reservation namespace")
        if self.completion_id.namespace != "model-execution-completion":
            raise ValueError("completion recovery handle has the wrong completion namespace")
        require_digest_kind(
            self.receipt_hash,
            HashKindV1.MODEL_EXECUTION_COMPLETION,
            "receipt_hash",
        )
        return self


def model_execution_completion_recovery_handle(
    record: ModelExecutionCompletionRecordV1,
) -> ModelExecutionCompletionRecoveryHandleV1:
    return ModelExecutionCompletionRecoveryHandleV1(
        reservation_id=record.reservation.reservation_id,
        completion_id=record.completion_id,
        receipt_hash=record.record_hash(),
    )


class ModelExecutionCompletionPendingError(ModelExecutionAuthorizationError):
    """A settlement committed, but its recoverable receipt path is incomplete."""

    def __init__(
        self,
        recovery_handle: ModelExecutionCompletionRecoveryHandleV1,
        *,
        reason: ModelExecutionCompletionRecoveryReasonV1,
    ) -> None:
        if not isinstance(recovery_handle, ModelExecutionCompletionRecoveryHandleV1):
            raise TypeError("completion pending error requires a recovery handle")
        if not isinstance(reason, ModelExecutionCompletionRecoveryReasonV1):
            raise TypeError("completion pending error requires a recovery reason")
        self.recovery_handle = recovery_handle
        self.reason = reason
        super().__init__(
            f"model execution settled; completion receipt recovery is required ({reason.value})"
        )


class ModelExecutionCompletionPublicV1(ContractModel):
    """The only public projection of a private model completion receipt."""

    schema_version: Literal["autolean.model-execution-completion-public.v1"] = (
        "autolean.model-execution-completion-public.v1"
    )
    completion_id: StableIdentifierV1
    receipt_hash: DigestV1
    public_output_commitment: DigestV1


def model_execution_completion_public(
    receipt: ModelExecutionCompletionReceiptV1,
) -> ModelExecutionCompletionPublicV1:
    return ModelExecutionCompletionPublicV1(
        completion_id=receipt.record.completion_id,
        receipt_hash=receipt.receipt_hash,
        public_output_commitment=receipt.record.private_output.public_output_commitment,
    )
