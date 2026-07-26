"""Rights-bound model work that is not a theorem statement.

``ModelWorkBundleV2`` is the public control-plane projection for benchmark and orchestration
work. Complete planner coordinates, source records, rights records, licenses, prompts, and
operator labels remain private. The shared bundle contains only fixed-namespace opaque
identifiers, domain-separated digests, enums, and bounded numbers.

This projection prevents accidental plaintext persistence on the normal path. It is not a
confidentiality proof against a malicious admission authority: an authority that may choose
arbitrary digest bytes can still construct a covert channel. Deployment must therefore keep the
admission authority independent and audit how every digest is reconstructed from private inputs.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, model_validator

from .attestation import (
    AttestationPurposeV1,
    attestation_payload_hash,
)
from .base import ContractModel
from .hashing import (
    DigestV1,
    HashKindV1,
    StableIdentifierV1,
    digest_model,
    require_digest_kind,
    stable_identifier,
)
from .models import (
    EndpointClassV1,
    PermissionDecisionV1,
    RightsRecordV1,
    SourceRecordV1,
)

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_BUNDLE_NAMESPACE = "model-work-bundle"
_CONTRACT_NAMESPACE = "model-work-contract"


class ModelWorkRoleV1(StrEnum):
    """The first independently measured AutoLean agent roles."""

    PROVER = "prover"
    STATEMENT_FORMALIZER = "statement_formalizer"
    FIDELITY_REVIEWER = "fidelity_reviewer"
    CHEATING_SUPERVISOR = "cheating_supervisor"
    TASK_ALLOCATOR = "task_allocator"


class ModelWorkSourceSpanBindingV2(ContractModel):
    """Text-free identity of one source span used for model egress."""

    content_hash: DigestV1
    start_offset: int | None = Field(default=None, ge=0)
    end_offset: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_span(self) -> Self:
        require_digest_kind(self.content_hash, HashKindV1.SOURCE_SPAN, "content_hash")
        if (
            self.start_offset is not None
            and self.end_offset is not None
            and self.end_offset < self.start_offset
        ):
            raise ValueError("end_offset must not precede start_offset")
        return self


class ModelWorkSourceBindingV2(ContractModel):
    """Digest-only projection of a complete local source record."""

    schema_version: Literal["autolean.model-work-source-binding.v2"] = (
        "autolean.model-work-source-binding.v2"
    )
    source_identity_hash: DigestV1
    source_content_hash: DigestV1
    source_record_hash: DigestV1
    spans: tuple[ModelWorkSourceSpanBindingV2, ...]

    @model_validator(mode="after")
    def validate_source_binding(self) -> Self:
        require_digest_kind(
            self.source_identity_hash,
            HashKindV1.SOURCE_IDENTITY,
            "source_identity_hash",
        )
        require_digest_kind(
            self.source_content_hash,
            HashKindV1.SOURCE_BYTES,
            "source_content_hash",
        )
        require_digest_kind(
            self.source_record_hash,
            HashKindV1.SOURCE_RECORD,
            "source_record_hash",
        )
        span_coordinates = [
            (span.content_hash.value, span.start_offset, span.end_offset) for span in self.spans
        ]
        if len(span_coordinates) != len(set(span_coordinates)):
            raise ValueError("model work source span bindings must be unique")
        return self


class ModelWorkRightsBindingV2(ContractModel):
    """Digest/enum-only projection of a complete local rights record."""

    schema_version: Literal["autolean.model-work-rights-binding.v2"] = (
        "autolean.model-work-rights-binding.v2"
    )
    source_identity_hash: DigestV1
    rights_record_hash: DigestV1
    overall_decision: PermissionDecisionV1
    redistribution: PermissionDecisionV1
    model_egress: PermissionDecisionV1
    training: PermissionDecisionV1
    embedding: PermissionDecisionV1
    allowed_endpoint_classes: tuple[EndpointClassV1, ...]

    @model_validator(mode="after")
    def validate_rights_binding(self) -> Self:
        require_digest_kind(
            self.source_identity_hash,
            HashKindV1.SOURCE_IDENTITY,
            "source_identity_hash",
        )
        require_digest_kind(
            self.rights_record_hash,
            HashKindV1.RIGHTS_RECORD,
            "rights_record_hash",
        )
        if self.model_egress is PermissionDecisionV1.ALLOW and not self.allowed_endpoint_classes:
            raise ValueError("allowed model egress requires explicit endpoint classes")
        if len(self.allowed_endpoint_classes) != len(set(self.allowed_endpoint_classes)):
            raise ValueError("allowed endpoint classes must be unique")
        return self


def _source_identity_hash(source_id: StableIdentifierV1) -> DigestV1:
    return digest_model(HashKindV1.SOURCE_IDENTITY, source_id)


def model_work_source_binding(source: SourceRecordV1) -> ModelWorkSourceBindingV2:
    """Project a complete source record without retaining caller-controlled identifiers."""

    return ModelWorkSourceBindingV2(
        source_identity_hash=_source_identity_hash(source.source_id),
        source_content_hash=source.content_hash,
        source_record_hash=digest_model(HashKindV1.SOURCE_RECORD, source),
        spans=tuple(
            ModelWorkSourceSpanBindingV2(
                content_hash=span.content_hash,
                start_offset=span.start_offset,
                end_offset=span.end_offset,
            )
            for span in source.spans
        ),
    )


def model_work_rights_binding(rights: RightsRecordV1) -> ModelWorkRightsBindingV2:
    """Project rights without retaining license, reviewer, restriction, or identifier text."""

    return ModelWorkRightsBindingV2(
        source_identity_hash=_source_identity_hash(rights.source_id),
        rights_record_hash=digest_model(HashKindV1.RIGHTS_RECORD, rights),
        overall_decision=rights.overall_decision,
        redistribution=rights.redistribution,
        model_egress=rights.model_egress,
        training=rights.training,
        embedding=rights.embedding,
        allowed_endpoint_classes=rights.allowed_endpoint_classes,
    )


def _coordinate_hash(kind: HashKindV1, value: str) -> DigestV1:
    if not isinstance(value, str) or not value:
        raise ValueError("model work planner coordinate must be a nonempty string")
    return digest_model(
        kind,
        {
            "schema_version": "autolean.model-work-coordinate.v2",
            "coordinate_kind": kind.value,
            "value": value,
        },
    )


def model_work_run_hash(run_id: str) -> DigestV1:
    """Hide a planner run coordinate behind a domain-separated typed digest."""

    return _coordinate_hash(HashKindV1.MODEL_WORK_RUN, run_id)


def model_work_cell_hash(cell_id: str) -> DigestV1:
    """Hide a planner cell coordinate behind a domain-separated typed digest."""

    return _coordinate_hash(HashKindV1.MODEL_WORK_CELL, cell_id)


def model_work_case_hash(case_id: str) -> DigestV1:
    """Hide a planner case coordinate behind a domain-separated typed digest."""

    return _coordinate_hash(HashKindV1.MODEL_WORK_CASE, case_id)


def _upstream_contract_hash(kind: HashKindV1, value: str) -> DigestV1:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError("model work upstream contract hash must be lowercase SHA-256")
    return digest_model(
        kind,
        {
            "schema_version": "autolean.model-work-upstream-hash.v2",
            "upstream_kind": kind.value,
            "upstream_sha256": value,
        },
    )


def model_work_cell_contract_hash(value: str) -> DigestV1:
    return _upstream_contract_hash(HashKindV1.MODEL_WORK_CELL_CONTRACT, value)


def model_work_case_contract_hash(value: str) -> DigestV1:
    return _upstream_contract_hash(HashKindV1.MODEL_WORK_CASE_CONTRACT, value)


def model_work_item_hash(value: str) -> DigestV1:
    return _upstream_contract_hash(HashKindV1.MODEL_WORK_ITEM, value)


class ModelWorkBundleV2(ContractModel):
    """One immutable, rights-bound, tool-free model trial."""

    schema_version: Literal["autolean.model-work-bundle.v2"] = "autolean.model-work-bundle.v2"
    bundle_id: StableIdentifierV1
    work_contract_id: StableIdentifierV1
    revision: Literal[2] = 2
    run_hash: DigestV1
    cell_hash: DigestV1
    case_hash: DigestV1
    repetition: int = Field(ge=1, le=100)
    role: ModelWorkRoleV1
    cell_contract_hash: DigestV1
    case_contract_hash: DigestV1
    work_item_hash: DigestV1
    role_environment_hash: DigestV1
    egress_content_hash: DigestV1
    context_pack_hash: DigestV1
    request_hash: DigestV1
    source: ModelWorkSourceBindingV2
    rights: ModelWorkRightsBindingV2
    native_tools_enabled: Literal[False] = False
    retrieval_enabled: Literal[False] = False

    @model_validator(mode="after")
    def validate_model_work(self) -> Self:
        if self.bundle_id.namespace != _BUNDLE_NAMESPACE:
            raise ValueError("model work bundle identifier must use the fixed system namespace")
        if self.work_contract_id.namespace != _CONTRACT_NAMESPACE:
            raise ValueError("model work contract identifier must use the fixed system namespace")
        for value, kind, label in (
            (self.run_hash, HashKindV1.MODEL_WORK_RUN, "run_hash"),
            (self.cell_hash, HashKindV1.MODEL_WORK_CELL, "cell_hash"),
            (self.case_hash, HashKindV1.MODEL_WORK_CASE, "case_hash"),
            (
                self.cell_contract_hash,
                HashKindV1.MODEL_WORK_CELL_CONTRACT,
                "cell_contract_hash",
            ),
            (
                self.case_contract_hash,
                HashKindV1.MODEL_WORK_CASE_CONTRACT,
                "case_contract_hash",
            ),
            (self.work_item_hash, HashKindV1.MODEL_WORK_ITEM, "work_item_hash"),
            (self.role_environment_hash, HashKindV1.ENVIRONMENT, "role_environment_hash"),
            (self.egress_content_hash, HashKindV1.SOURCE_SPAN, "egress_content_hash"),
            (self.context_pack_hash, HashKindV1.PROMPT, "context_pack_hash"),
            (self.request_hash, HashKindV1.PROMPT, "request_hash"),
        ):
            require_digest_kind(value, kind, label)
        if self.rights.source_identity_hash != self.source.source_identity_hash:
            raise ValueError("model work rights must reference its single source identity")
        if self.bundle_id != model_work_bundle_id(
            run_hash=self.run_hash,
            cell_hash=self.cell_hash,
            case_hash=self.case_hash,
            repetition=self.repetition,
            role=self.role,
        ):
            raise ValueError("model work bundle identifier must be derived from its coordinates")
        if self.work_contract_id != model_work_contract_id(
            cell_contract_hash=self.cell_contract_hash,
            case_contract_hash=self.case_contract_hash,
        ):
            raise ValueError("model work contract identifier must be derived from its contracts")
        matching_spans = tuple(
            span for span in self.source.spans if span.content_hash == self.egress_content_hash
        )
        if len(matching_spans) != 1:
            raise ValueError("model work egress hash must match one explicit source span")
        return self

    def semantic_hash(self) -> DigestV1:
        """Hash the complete per-trial contract independently from its handoff envelope."""

        return digest_model(
            HashKindV1.CONTRACT,
            self,
            exclude={"bundle_id"},
        )

    def handoff_hash(self) -> DigestV1:
        """Hash the exact immutable work bundle registered with the control plane."""

        return digest_model(HashKindV1.BUNDLE, self)


def model_work_bundle_id(
    *,
    run_hash: DigestV1,
    cell_hash: DigestV1,
    case_hash: DigestV1,
    repetition: int,
    role: ModelWorkRoleV1,
) -> StableIdentifierV1:
    """Derive the fixed-namespace bundle ID without retaining planner coordinates."""

    coordinate = digest_model(
        HashKindV1.MODEL_WORK_ITEM,
        {
            "schema_version": "autolean.model-work-bundle-coordinate.v2",
            "run_hash": run_hash.model_dump(mode="json"),
            "cell_hash": cell_hash.model_dump(mode="json"),
            "case_hash": case_hash.model_dump(mode="json"),
            "repetition": repetition,
            "role": role.value,
        },
    )
    return stable_identifier(_BUNDLE_NAMESPACE, coordinate.value)


def model_work_contract_id(
    *,
    cell_contract_hash: DigestV1,
    case_contract_hash: DigestV1,
) -> StableIdentifierV1:
    """Derive the fixed-namespace work-contract ID from typed upstream contracts."""

    contract = digest_model(
        HashKindV1.CONTRACT,
        {
            "schema_version": "autolean.model-work-contract-coordinate.v2",
            "cell_contract_hash": cell_contract_hash.model_dump(mode="json"),
            "case_contract_hash": case_contract_hash.model_dump(mode="json"),
        },
    )
    return stable_identifier(_CONTRACT_NAMESPACE, contract.value)


def model_work_admission_payload(bundle: ModelWorkBundleV2) -> Mapping[str, object]:
    """Bind the complete immutable public work bundle to one admission decision."""

    return {
        "schema_version": "autolean.model-work-admission-payload.v2",
        "bundle_id": bundle.bundle_id.model_dump(mode="json"),
        "bundle_hash": bundle.handoff_hash().model_dump(mode="json"),
        "semantic_hash": bundle.semantic_hash().model_dump(mode="json"),
        "bundle": bundle.model_dump(mode="json", exclude_none=False),
    }


def model_work_admission_evidence_identity(bundle: ModelWorkBundleV2) -> str:
    """Return the only evidence identity accepted for a ModelWork admission."""

    payload_hash = attestation_payload_hash(
        AttestationPurposeV1.MODEL_WORK_ADMISSION,
        model_work_admission_payload(bundle),
    )
    return f"model-work-admission:{payload_hash.value}"
