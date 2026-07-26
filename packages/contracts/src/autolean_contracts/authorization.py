"""Signed, contract-bound authorization for model execution.

The Builder-Prover protocol deliberately treats model generation as an egressing side effect, not
as a harmless helper call.  This module contains only public, serializable capability metadata;
credential references and endpoint URLs stay in operator-owned provider configuration.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from .attestation import AttestationPurposeV1, AttestationV1
from .base import ContractModel
from .hashing import DigestV1, HashKindV1, StableIdentifierV1, digest_model, require_digest_kind
from .models import EndpointClassV1, PermissionDecisionV1

_FORBIDDEN_IDENTIFIERS = ("anthropic", "claude")
_MODEL_WORK_WORKER = re.compile(r"^model-work-worker-[0-9a-f]{64}$")


class ModelExecutionSubjectKindV1(StrEnum):
    """The authority lineage of one model-execution capability."""

    THEOREM = "theorem"
    MODEL_WORK = "model_work"


class ModelExecutionAuthorizationError(ValueError):
    """A signed model-execution capability was invalid, exhausted, or no longer authorized."""


def _validate_public_identifier(value: str, *, label: str) -> None:
    """Reject ambiguous routing/identity values without pretending they are secrets."""

    if not value or value != value.strip() or any(character.isspace() for character in value):
        raise ValueError(f"{label} must be a non-empty identifier without whitespace")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{label} must not contain control characters")
    normalized = unicodedata.normalize("NFKC", value).casefold()
    if any(term in normalized for term in _FORBIDDEN_IDENTIFIERS):
        raise ValueError("Anthropic and Claude identifiers are not permitted in AutoLean")


class ModelExecutionProviderBindingV1(ContractModel):
    """The exact registry/provider/model/endpoint selection an authorization permits."""

    registry_name: str = Field(min_length=1, max_length=128)
    provider_id: str = Field(min_length=1, max_length=256)
    model_id: str = Field(min_length=1, max_length=512)
    model_revision: str = Field(min_length=1, max_length=512)
    endpoint_class: EndpointClassV1
    configuration_hash: DigestV1

    @model_validator(mode="after")
    def validate_binding(self) -> ModelExecutionProviderBindingV1:
        for label, value in (
            ("registry_name", self.registry_name),
            ("provider_id", self.provider_id),
            ("model_id", self.model_id),
            ("model_revision", self.model_revision),
        ):
            _validate_public_identifier(value, label=label)
        if self.registry_name != unicodedata.normalize("NFKC", self.registry_name).casefold():
            raise ValueError("registry_name must use its canonical lower-case routing form")
        if self.endpoint_class in {EndpointClassV1.NONE, EndpointClassV1.EXTERNAL}:
            raise ValueError(
                "model execution requires a local or operator-approved external endpoint"
            )
        require_digest_kind(self.configuration_hash, HashKindV1.CONFIG, "configuration_hash")
        return self


class ModelExecutionPricingV1(ContractModel):
    """Operator-approved upper-bound accounting schedule in integer micro-USD."""

    input_microusd_per_token: int = Field(default=0, ge=0)
    cached_input_microusd_per_token: int = Field(default=0, ge=0)
    output_microusd_per_token: int = Field(default=0, ge=0)

    def cost_for_usage(
        self,
        *,
        input_tokens: int,
        cached_input_tokens: int,
        output_tokens: int,
    ) -> int:
        if min(input_tokens, cached_input_tokens, output_tokens) < 0:
            raise ValueError("token usage must be non-negative")
        if cached_input_tokens > input_tokens:
            raise ValueError("cached input tokens cannot exceed input tokens")
        uncached_input = input_tokens - cached_input_tokens
        return (
            uncached_input * self.input_microusd_per_token
            + cached_input_tokens * self.cached_input_microusd_per_token
            + output_tokens * self.output_microusd_per_token
        )

    def reserve_cost(
        self,
        *,
        max_input_tokens: int,
        max_output_tokens: int,
    ) -> int:
        """Reserve a conservative cost even when cached-token classification is unknown."""

        if min(max_input_tokens, max_output_tokens) < 0:
            raise ValueError("token reservation must be non-negative")
        input_rate = max(
            self.input_microusd_per_token,
            self.cached_input_microusd_per_token,
        )
        return input_rate * max_input_tokens + self.output_microusd_per_token * max_output_tokens


class ModelExecutionBudgetV1(ContractModel):
    """A whole-capability budget, not a caller-selected per-call hint."""

    max_attempts: int = Field(ge=1)
    max_input_tokens: int = Field(ge=1)
    max_output_tokens: int = Field(ge=1)
    max_total_tokens: int = Field(ge=2)
    max_cost_microusd: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_total(self) -> ModelExecutionBudgetV1:
        if self.max_total_tokens < self.max_input_tokens + self.max_output_tokens:
            raise ValueError("max_total_tokens must cover one permitted request")
        return self


class ModelEgressPolicyV1(ContractModel):
    """The frozen source-rights facts relevant to a selected model endpoint."""

    rights_id: StableIdentifierV1
    overall_decision: PermissionDecisionV1
    model_egress: PermissionDecisionV1
    allowed_endpoint_classes: tuple[EndpointClassV1, ...] = ()

    @model_validator(mode="after")
    def validate_endpoint_classes(self) -> ModelEgressPolicyV1:
        if len(self.allowed_endpoint_classes) != len(set(self.allowed_endpoint_classes)):
            raise ValueError("allowed_endpoint_classes must not contain duplicates")
        return self

    def permits(self, endpoint_class: EndpointClassV1) -> bool:
        if self.overall_decision in {PermissionDecisionV1.UNKNOWN, PermissionDecisionV1.DENY}:
            return False
        if endpoint_class is EndpointClassV1.LOCAL:
            return True
        return (
            endpoint_class is EndpointClassV1.APPROVED_EXTERNAL
            and self.model_egress is PermissionDecisionV1.ALLOW
            and endpoint_class in self.allowed_endpoint_classes
        )


class ModelExecutionProviderApprovalV1(ContractModel):
    """Operator-owned, credential-free approval input used when minting a capability."""

    approval_id: StableIdentifierV1
    binding: ModelExecutionProviderBindingV1
    pricing: ModelExecutionPricingV1
    approved_by: str = Field(min_length=1, max_length=256)
    approved_at: datetime
    enabled: bool = True

    @model_validator(mode="after")
    def validate_approval(self) -> ModelExecutionProviderApprovalV1:
        if self.approved_at.tzinfo is None:
            raise ValueError("provider approval timestamp must be timezone-aware")
        return self

    def approval_hash(self) -> DigestV1:
        """Return the immutable, public audit digest for this approval record."""

        return digest_model(HashKindV1.MODEL_EXECUTION_APPROVAL, self)


class ModelExecutionLeaseBindingV1(ContractModel):
    """The one fenced worker lease that may use a model-execution capability.

    This is a public, credential-free projection of a control-plane lease.  The control plane
    rechecks it against its authoritative SQLite lease store before endpoint I/O and settlement.
    """

    bundle_id: StableIdentifierV1
    worker_id: str = Field(min_length=1, max_length=256)
    fencing_token: int = Field(ge=1)
    expires_at: datetime

    @model_validator(mode="after")
    def validate_lease_binding(self) -> ModelExecutionLeaseBindingV1:
        _validate_public_identifier(self.worker_id, label="worker_id")
        if self.expires_at.tzinfo is None:
            raise ValueError("model execution lease expiry must be timezone-aware")
        return self


class ModelExecutionAuthorizationV1(ContractModel):
    """A short-lived, signed capability for one frozen bundle and model selection."""

    schema_version: Literal["1.0"] = "1.0"
    subject_kind: ModelExecutionSubjectKindV1
    authorization_id: StableIdentifierV1
    bundle_id: StableIdentifierV1
    bundle_hash: DigestV1
    contract_id: StableIdentifierV1
    revision: int = Field(ge=1)
    contract_hash: DigestV1
    environment_hash: DigestV1
    lease: ModelExecutionLeaseBindingV1
    context_pack_hash: DigestV1
    request_hash: DigestV1
    egress_policy: ModelEgressPolicyV1
    approval_snapshot: ModelExecutionProviderApprovalV1
    budget: ModelExecutionBudgetV1
    issued_at: datetime
    expires_at: datetime
    parent_admission_hash: DigestV1 | None = None
    parent_admission_expires_at: datetime | None = None
    attestation: AttestationV1 | None = None

    @property
    def provider(self) -> ModelExecutionProviderBindingV1:
        """The selected route, derived only from the signed approval snapshot."""

        return self.approval_snapshot.binding

    @property
    def approval_id(self) -> StableIdentifierV1:
        return self.approval_snapshot.approval_id

    @property
    def pricing(self) -> ModelExecutionPricingV1:
        return self.approval_snapshot.pricing

    def approval_hash(self) -> DigestV1:
        """Expose a stable audit handle for the full, credential-free approval snapshot."""

        return self.approval_snapshot.approval_hash()

    def authorization_hash(self) -> DigestV1:
        return digest_model(
            HashKindV1.MODEL_EXECUTION_AUTHORIZATION,
            self.model_dump(mode="json", exclude={"attestation"}, exclude_none=False),
        )

    @model_validator(mode="after")
    def validate_authorization(self) -> ModelExecutionAuthorizationV1:
        require_digest_kind(self.bundle_hash, HashKindV1.BUNDLE, "bundle_hash")
        require_digest_kind(self.contract_hash, HashKindV1.CONTRACT, "contract_hash")
        require_digest_kind(self.environment_hash, HashKindV1.ENVIRONMENT, "environment_hash")
        require_digest_kind(self.context_pack_hash, HashKindV1.PROMPT, "context_pack_hash")
        require_digest_kind(self.request_hash, HashKindV1.PROMPT, "request_hash")
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("authorization timestamps must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("authorization expiry must be after issuance")
        if self.lease.bundle_id != self.bundle_id:
            raise ValueError("model execution lease binds a different bundle")
        if self.expires_at > self.lease.expires_at:
            raise ValueError("model execution authorization outlives its worker lease")
        if self.subject_kind is ModelExecutionSubjectKindV1.THEOREM:
            if (
                self.parent_admission_hash is not None
                or self.parent_admission_expires_at is not None
            ):
                raise ValueError("theorem authorization cannot claim a ModelWork parent admission")
        else:
            if self.parent_admission_hash is None or self.parent_admission_expires_at is None:
                raise ValueError("model-work authorization requires its exact parent admission")
            require_digest_kind(
                self.parent_admission_hash,
                HashKindV1.ATTESTATION,
                "parent_admission_hash",
            )
            if self.parent_admission_expires_at.tzinfo is None:
                raise ValueError("parent admission expiry must be timezone-aware")
            if self.expires_at > self.parent_admission_expires_at:
                raise ValueError("model-work authorization outlives its parent admission")
            if self.authorization_id.namespace != "model-work-authorization":
                raise ValueError("model-work authorization must use the fixed system namespace")
            if self.bundle_id.namespace != "model-work-bundle":
                raise ValueError(
                    "model-work authorization bundle must use the fixed system namespace"
                )
            if self.contract_id.namespace != "model-work-contract":
                raise ValueError(
                    "model-work authorization contract must use the fixed system namespace"
                )
            if self.egress_policy.rights_id.namespace != "model-work-rights":
                raise ValueError(
                    "model-work authorization rights must use the fixed system namespace"
                )
            if _MODEL_WORK_WORKER.fullmatch(self.lease.worker_id) is None:
                raise ValueError(
                    "model-work authorization worker must use an opaque system reference"
                )
        if not self.approval_snapshot.enabled:
            raise ValueError("model execution authorization requires an enabled provider approval")
        if not self.egress_policy.permits(self.provider.endpoint_class):
            raise ValueError("frozen source rights do not permit the selected model endpoint")
        if (
            self.attestation is not None
            and self.attestation.purpose is not AttestationPurposeV1.MODEL_EXECUTION
        ):
            raise ValueError("authorization attestation must use the model_execution purpose")
        return self


class ModelExecutionReservationV1(ContractModel):
    """Public reservation receipt. It contains no prompt, credentials, or endpoint URL."""

    reservation_id: StableIdentifierV1
    authorization_id: StableIdentifierV1
    attempt_number: int = Field(ge=1)
    reserved_input_tokens: int = Field(ge=1)
    reserved_output_tokens: int = Field(ge=1)
    reserved_cost_microusd: int = Field(ge=0)
    reserved_at: datetime

    @model_validator(mode="after")
    def validate_reservation_time(self) -> ModelExecutionReservationV1:
        if self.reserved_at.tzinfo is None:
            raise ValueError("reservation timestamp must be timezone-aware")
        return self


def model_execution_authorization_payload(
    authorization: ModelExecutionAuthorizationV1,
) -> dict[str, object]:
    """Return the exact public capability payload a control-plane authority signs."""

    return {
        "schema_version": "autolean.model-execution-authorization-payload.v1",
        "authorization": authorization.model_dump(
            mode="json",
            exclude={"attestation"},
            exclude_none=False,
        ),
        "approval_hash": authorization.approval_hash().value,
        "authorization_hash": authorization.authorization_hash().value,
    }
