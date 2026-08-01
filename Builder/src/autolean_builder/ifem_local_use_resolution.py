"""Private candidate for resolving the pending iFEM local-use request.

The candidate binds an exact text-free source record to the current plan and request.  Until a
trusted rights authority attests that claim, it grants no local processing, model execution,
semantic review, statement freeze, or Prover handoff authority.
"""

from __future__ import annotations

import hashlib
from typing import Final, Literal, Never, Self, cast

from autolean_contracts import (
    EndpointClassV1,
    HashKindV1,
    PermissionDecisionV1,
    RightsRecordV1,
    SourceRecordV1,
    SourceSpanV1,
    StableIdentifierV1,
    canonical_json_bytes,
    digest_model,
    stable_identifier,
)
from autolean_contracts.base import ContractModel
from pydantic import Field, model_validator

from .ifem_coarse_local_calibration_plan import IFEMCoarseLocalCalibrationPlanV1
from .ifem_local_use_request import IFEMLocalUseRequestV1

IFEM_LOCAL_USE_RESOLUTION_SCHEMA: Final[Literal["autolean.ifem-local-use-resolution.v1"]] = (
    "autolean.ifem-local-use-resolution.v1"
)
IFEM_LOCAL_USE_RESOLUTION_PROTOCOL: Final[
    Literal["autolean.builder-ifem-local-use-resolution.v1"]
] = "autolean.builder-ifem-local-use-resolution.v1"
IFEM_LOCAL_USE_RESOLUTION_KIND: Final[Literal["private_local_processing_rights_candidate"]] = (
    "private_local_processing_rights_candidate"
)
IFEM_LOCAL_USE_RESOLUTION_NAMESPACE: Final[Literal["ifem-local-use-resolution"]] = (
    "ifem-local-use-resolution"
)

_SHA256 = r"^[0-9a-f]{64}$"
_OPENING_NOTEBOOK_PATH: Final[str] = "primal/first_example.ipynb"
_SOURCE_WORK_ID: Final[str] = "ifem-interactive-fem-chapters-01-10"
_SOURCE_TITLE: Final[str] = "iFEM locked notebook source"
_RIGHTS_CLAIM_NAMESPACE: Final[str] = "ifem-local-rights-claim"
_RIGHTS_CLAIM_ATTRIBUTION: Final[str] = "iFEM contributors; CC BY 4.0"
_SOURCE_METADATA: Final[dict[str, object]] = {
    "model_egress_policy": "local_only",
    "source_alignment_only": True,
    "semantic_review_state": "not_performed",
}
_REQUIRED_RESTRICTIONS: Final[tuple[str, ...]] = (
    "local-model-processing-only",
    "no-embedding",
    "no-external-model-source-text",
    "no-prover-handoff",
    "no-promotion",
    "no-public-source-excerpt",
    "no-source-redistribution",
    "no-statement-freeze",
    "no-training",
)


class IFEMLocalUseResolutionError(ValueError):
    """The candidate is inconsistent or is being used as authority."""


class IFEMLocalUseResolutionAuthorityV1(ContractModel):
    """A claim is present, but no trusted rights or workflow authority exists."""

    schema_version: Literal["autolean.ifem-local-use-resolution-authority.v1"] = (
        "autolean.ifem-local-use-resolution-authority.v1"
    )
    rights_claim_recorded: Literal[True] = True
    trusted_rights_attestation_present: Literal[False] = False
    rights_claim_verified: Literal[False] = False
    local_model_processing_authorized: Literal[False] = False
    external_model_egress_authorized: Literal[False] = False
    model_execution_authorized: Literal[False] = False
    semantic_review_authorized: Literal[False] = False
    statement_contract_authorized: Literal[False] = False
    builder_freeze_authorized: Literal[False] = False
    prover_handoff_authorized: Literal[False] = False
    kernel_verification_authorized: Literal[False] = False
    promotion_authorized: Literal[False] = False
    release_authorized: Literal[False] = False


class IFEMLocalUseResolutionV1(ContractModel):
    """A private, non-authoritative successor candidate to one pending request."""

    schema_version: Literal["autolean.ifem-local-use-resolution.v1"] = (
        IFEM_LOCAL_USE_RESOLUTION_SCHEMA
    )
    protocol: Literal["autolean.builder-ifem-local-use-resolution.v1"] = (
        IFEM_LOCAL_USE_RESOLUTION_PROTOCOL
    )
    artifact_kind: Literal["private_local_processing_rights_candidate"] = (
        IFEM_LOCAL_USE_RESOLUTION_KIND
    )
    resolution_id: StableIdentifierV1
    coarse_plan: IFEMCoarseLocalCalibrationPlanV1
    coarse_plan_content_sha256: str = Field(pattern=_SHA256)
    pending_request: IFEMLocalUseRequestV1
    pending_request_id: StableIdentifierV1
    pending_request_content_sha256: str = Field(pattern=_SHA256)
    source: SourceRecordV1
    source_record_sha256: str = Field(pattern=_SHA256)
    unverified_rights_claim: RightsRecordV1
    rights_claim_sha256: str = Field(pattern=_SHA256)
    requested_endpoint_class: Literal[EndpointClassV1.LOCAL] = EndpointClassV1.LOCAL
    resolution_state: Literal["candidate_pending_trusted_rights_attestation"] = (
        "candidate_pending_trusted_rights_attestation"
    )
    source_text_included: Literal[False] = False
    model_input_included: Literal[False] = False
    model_execution_capability_included: Literal[False] = False
    public_artifact: Literal[False] = False
    authority: IFEMLocalUseResolutionAuthorityV1 = Field(
        default_factory=IFEMLocalUseResolutionAuthorityV1
    )
    builder_freeze: Literal["forbidden"] = "forbidden"
    prover_handoff: Literal["forbidden"] = "forbidden"
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_resolution(self) -> Self:
        if self.coarse_plan_content_sha256 != self.coarse_plan.content_sha256:
            raise ValueError("local-use candidate plan hash does not match its typed plan")
        if self.pending_request_id != self.pending_request.request_id:
            raise ValueError("local-use candidate request id does not match its typed request")
        if self.pending_request_content_sha256 != self.pending_request.content_sha256:
            raise ValueError("local-use candidate request hash does not match its typed request")
        if (
            self.source_record_sha256
            != digest_model(
                HashKindV1.SOURCE_RECORD,
                self.source,
            ).value
        ):
            raise ValueError("local-use candidate source-record hash does not match")
        if (
            self.rights_claim_sha256
            != digest_model(
                HashKindV1.RIGHTS_RECORD,
                self.unverified_rights_claim,
            ).value
        ):
            raise ValueError("local-use candidate rights-claim hash does not match")
        _validate_cross_bindings(self.coarse_plan, self.pending_request, self.source)
        _validate_source(self.coarse_plan, self.source)
        _validate_rights_claim(
            self.pending_request,
            self.source,
            self.unverified_rights_claim,
        )
        expected_id = _resolution_id(
            coarse_plan_content_sha256=self.coarse_plan_content_sha256,
            pending_request_id=self.pending_request_id,
            pending_request_content_sha256=self.pending_request_content_sha256,
            source_record_sha256=self.source_record_sha256,
            rights_claim_sha256=self.rights_claim_sha256,
        )
        if self.resolution_id != expected_id:
            raise ValueError("local-use candidate id does not bind its exact inputs")
        if self.authority != IFEMLocalUseResolutionAuthorityV1():
            raise ValueError("local-use candidate authority flags drifted")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("local-use candidate content hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(dict[str, object], self.model_dump(mode="json", exclude={"content_sha256"}))

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.content_payload())).hexdigest()

    def assert_not_authoritative(self) -> Never:
        raise IFEMLocalUseResolutionError(
            "iFEM local-use candidate is pending a trusted rights attestation and cannot "
            "authorize processing, execution, freeze, or Prover handoff"
        )

    def assert_rights_allow_local_processing(self) -> Never:
        """Retained as a fail-closed API: an unverified claim cannot allow processing."""

        self.assert_not_authoritative()

    def authorize_model_execution(self) -> Never:
        self.assert_not_authoritative()

    def authorize_external_egress(self) -> Never:
        self.assert_not_authoritative()

    def freeze_statement(self) -> Never:
        self.assert_not_authoritative()

    def handoff_to_prover(self) -> Never:
        self.assert_not_authoritative()


def build_ifem_local_use_resolution(
    *,
    coarse_plan: IFEMCoarseLocalCalibrationPlanV1,
    pending_request: IFEMLocalUseRequestV1,
    source: SourceRecordV1,
    rights_claim: RightsRecordV1,
) -> IFEMLocalUseResolutionV1:
    """Build a non-authoritative candidate without reading source text or calling a model."""

    if type(coarse_plan) is not IFEMCoarseLocalCalibrationPlanV1:
        raise IFEMLocalUseResolutionError("coarse plan must use its exact typed model")
    if type(pending_request) is not IFEMLocalUseRequestV1:
        raise IFEMLocalUseResolutionError("pending request must use its exact typed model")
    if type(source) is not SourceRecordV1:
        raise IFEMLocalUseResolutionError("source must use its exact typed model")
    if type(rights_claim) is not RightsRecordV1:
        raise IFEMLocalUseResolutionError("rights claim must use its exact typed model")
    try:
        verified_plan = IFEMCoarseLocalCalibrationPlanV1.model_validate(
            coarse_plan.model_dump(mode="json")
        )
        verified_request = IFEMLocalUseRequestV1.model_validate(
            pending_request.model_dump(mode="json")
        )
        verified_source = SourceRecordV1.model_validate(source.model_dump(mode="json"))
        verified_rights = RightsRecordV1.model_validate(rights_claim.model_dump(mode="json"))
        _validate_cross_bindings(verified_plan, verified_request, verified_source)
        _validate_source(verified_plan, verified_source)
        _validate_rights_claim(verified_request, verified_source, verified_rights)
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMLocalUseResolutionError(
            f"local-use candidate input failed revalidation: {error}"
        ) from error
    source_sha256 = digest_model(HashKindV1.SOURCE_RECORD, verified_source).value
    rights_sha256 = digest_model(HashKindV1.RIGHTS_RECORD, verified_rights).value
    payload: dict[str, object] = {
        "schema_version": IFEM_LOCAL_USE_RESOLUTION_SCHEMA,
        "protocol": IFEM_LOCAL_USE_RESOLUTION_PROTOCOL,
        "artifact_kind": IFEM_LOCAL_USE_RESOLUTION_KIND,
        "resolution_id": _resolution_id(
            coarse_plan_content_sha256=verified_plan.content_sha256,
            pending_request_id=verified_request.request_id,
            pending_request_content_sha256=verified_request.content_sha256,
            source_record_sha256=source_sha256,
            rights_claim_sha256=rights_sha256,
        ).model_dump(mode="json"),
        "coarse_plan": verified_plan.model_dump(mode="json"),
        "coarse_plan_content_sha256": verified_plan.content_sha256,
        "pending_request": verified_request.model_dump(mode="json"),
        "pending_request_id": verified_request.request_id.model_dump(mode="json"),
        "pending_request_content_sha256": verified_request.content_sha256,
        "source": verified_source.model_dump(mode="json"),
        "source_record_sha256": source_sha256,
        "unverified_rights_claim": verified_rights.model_dump(mode="json"),
        "rights_claim_sha256": rights_sha256,
        "requested_endpoint_class": EndpointClassV1.LOCAL.value,
        "resolution_state": "candidate_pending_trusted_rights_attestation",
        "source_text_included": False,
        "model_input_included": False,
        "model_execution_capability_included": False,
        "public_artifact": False,
        "authority": IFEMLocalUseResolutionAuthorityV1().model_dump(mode="json"),
        "builder_freeze": "forbidden",
        "prover_handoff": "forbidden",
    }
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    try:
        return IFEMLocalUseResolutionV1.model_validate(payload)
    except ValueError as error:
        raise IFEMLocalUseResolutionError("inputs cannot form a local-use candidate") from error


def verify_ifem_local_use_resolution_against_current_inputs(
    resolution: IFEMLocalUseResolutionV1,
    *,
    coarse_plan: IFEMCoarseLocalCalibrationPlanV1,
    pending_request: IFEMLocalUseRequestV1,
    source: SourceRecordV1,
) -> None:
    """Verify exact current bindings without granting processing or workflow authority."""

    if type(resolution) is not IFEMLocalUseResolutionV1:
        raise IFEMLocalUseResolutionError("candidate must use its exact typed model")
    if type(coarse_plan) is not IFEMCoarseLocalCalibrationPlanV1:
        raise IFEMLocalUseResolutionError("current coarse plan must use its exact typed model")
    if type(pending_request) is not IFEMLocalUseRequestV1:
        raise IFEMLocalUseResolutionError("current request must use its exact typed model")
    if type(source) is not SourceRecordV1:
        raise IFEMLocalUseResolutionError("current source must use its exact typed model")
    try:
        verified = IFEMLocalUseResolutionV1.model_validate(resolution.model_dump(mode="json"))
        verified_plan = IFEMCoarseLocalCalibrationPlanV1.model_validate(
            coarse_plan.model_dump(mode="json")
        )
        verified_request = IFEMLocalUseRequestV1.model_validate(
            pending_request.model_dump(mode="json")
        )
        verified_source = SourceRecordV1.model_validate(source.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMLocalUseResolutionError(
            "local-use candidate or current input failed revalidation"
        ) from error
    if (
        verified.coarse_plan != verified_plan
        or verified.pending_request != verified_request
        or verified.source != verified_source
    ):
        raise IFEMLocalUseResolutionError(
            "local-use candidate differs from the supplied current inputs"
        )


def render_ifem_local_use_resolution(resolution: IFEMLocalUseResolutionV1) -> bytes:
    """Render private canonical bytes; the result remains non-authoritative and non-public."""

    if type(resolution) is not IFEMLocalUseResolutionV1:
        raise IFEMLocalUseResolutionError("candidate must use its exact typed model")
    try:
        verified = IFEMLocalUseResolutionV1.model_validate(resolution.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMLocalUseResolutionError("local-use candidate failed revalidation") from error
    return canonical_json_bytes(verified.model_dump(mode="json")) + b"\n"


def _validate_cross_bindings(
    plan: IFEMCoarseLocalCalibrationPlanV1,
    request: IFEMLocalUseRequestV1,
    source: SourceRecordV1,
) -> None:
    if plan.pending_local_use_request.request_id != request.request_id:
        raise ValueError("coarse plan and pending request ids differ")
    if plan.pending_local_use_request.content_sha256 != request.content_sha256:
        raise ValueError("coarse plan and pending request hashes differ")
    if plan.source_lock.receipt_sha256 != request.source.source_lock_receipt_sha256:
        raise ValueError("coarse plan and request source locks differ")
    if source.version != f"git-{plan.source_lock.source_revision}":
        raise ValueError("candidate source revision differs from the coarse plan")
    if source.snapshot_ref != f"ifem-source-lock:sha256:{plan.source_lock.receipt_sha256}":
        raise ValueError("candidate source snapshot differs from the coarse plan")
    if source.content_hash.value != plan.opening_spans[0].source_file_sha256:
        raise ValueError("candidate source bytes differ from the coarse plan")


def _expected_source_id(plan: IFEMCoarseLocalCalibrationPlanV1) -> StableIdentifierV1:
    return stable_identifier(
        "ifem.source-record",
        ":".join(
            (
                plan.source_lock.source_revision,
                _OPENING_NOTEBOOK_PATH,
                plan.opening_spans[0].source_file_sha256,
            )
        ),
    )


def _span_signature(span: SourceSpanV1) -> tuple[object, ...]:
    return (
        span.span_id,
        span.locator,
        span.content_hash.kind,
        span.content_hash.value,
        span.start_offset,
        span.end_offset,
        span.permitted_excerpt,
    )


def _validate_source(plan: IFEMCoarseLocalCalibrationPlanV1, source: SourceRecordV1) -> None:
    if source.source_id != _expected_source_id(plan):
        raise ValueError("local-use candidate source id is not the deterministic current id")
    if source.locator != _OPENING_NOTEBOOK_PATH:
        raise ValueError("local-use candidate source is not the opening iFEM notebook")
    if source.work_id != _SOURCE_WORK_ID:
        raise ValueError("local-use candidate source has the wrong work id")
    if source.title != _SOURCE_TITLE:
        raise ValueError("local-use candidate source has the wrong title")
    if source.retrieved_at.tzinfo is None or source.retrieved_at.utcoffset() is None:
        raise ValueError("local-use candidate source retrieval timestamp must be timezone-aware")
    if dict(source.metadata) != _SOURCE_METADATA:
        raise ValueError("local-use candidate source metadata must match the exact allowlist")
    expected_spans = tuple(
        (
            planned.span_id,
            f"notebook-cell:{planned.cell_index}:type:markdown",
            HashKindV1.SOURCE_SPAN,
            planned.cell_content_sha256,
            None,
            None,
            None,
        )
        for planned in plan.opening_spans
    )
    actual_spans = tuple(_span_signature(span) for span in source.spans)
    if actual_spans != expected_spans:
        raise ValueError(
            "local-use candidate source must contain exactly the ordered opening cells 0-3"
        )


def _expected_rights_claim_id(
    request: IFEMLocalUseRequestV1,
    source: SourceRecordV1,
) -> StableIdentifierV1:
    return stable_identifier(
        _RIGHTS_CLAIM_NAMESPACE,
        f"{request.request_id.value}:{source.source_id.value}",
    )


def _validate_rights_claim(
    request: IFEMLocalUseRequestV1,
    source: SourceRecordV1,
    rights: RightsRecordV1,
) -> None:
    if rights.rights_id != _expected_rights_claim_id(request, source):
        raise ValueError("local-use rights claim id does not bind the request and source")
    if rights.source_id != source.source_id:
        raise ValueError("local-use rights claim does not bind the exact source")
    if rights.source_license != "CC-BY-4.0":
        raise ValueError("local-use rights claim must bind the locked CC-BY-4.0 license")
    if rights.generated_code_license is not None:
        raise ValueError("local-use rights claim cannot decide generated-code licensing")
    if rights.overall_decision is not PermissionDecisionV1.UNKNOWN:
        raise ValueError("unattested local-use rights claim must remain unknown")
    if rights.redistribution is not PermissionDecisionV1.DENY:
        raise ValueError("local-use rights claim must forbid source redistribution")
    if rights.model_egress is not PermissionDecisionV1.DENY:
        raise ValueError("local-use rights claim must forbid external model egress")
    if rights.allowed_endpoint_classes:
        raise ValueError("local-use rights claim must not allow endpoint classes")
    if rights.training is not PermissionDecisionV1.DENY:
        raise ValueError("local-use rights claim must forbid training")
    if rights.embedding is not PermissionDecisionV1.DENY:
        raise ValueError("local-use rights claim must forbid embedding")
    if rights.attribution != _RIGHTS_CLAIM_ATTRIBUTION:
        raise ValueError("local-use rights claim attribution drifted")
    if rights.restrictions != _REQUIRED_RESTRICTIONS:
        raise ValueError("local-use rights claim restrictions drifted")
    if rights.reviewed_by is not None or rights.reviewed_at is not None:
        raise ValueError("unattested local-use rights claim cannot name a reviewer or review time")


def _resolution_id(
    *,
    coarse_plan_content_sha256: str,
    pending_request_id: StableIdentifierV1,
    pending_request_content_sha256: str,
    source_record_sha256: str,
    rights_claim_sha256: str,
) -> StableIdentifierV1:
    return stable_identifier(
        IFEM_LOCAL_USE_RESOLUTION_NAMESPACE,
        ":".join(
            (
                coarse_plan_content_sha256,
                pending_request_id.value,
                pending_request_content_sha256,
                source_record_sha256,
                rights_claim_sha256,
            )
        ),
    )


__all__ = [
    "IFEM_LOCAL_USE_RESOLUTION_KIND",
    "IFEM_LOCAL_USE_RESOLUTION_NAMESPACE",
    "IFEM_LOCAL_USE_RESOLUTION_PROTOCOL",
    "IFEM_LOCAL_USE_RESOLUTION_SCHEMA",
    "IFEMLocalUseResolutionAuthorityV1",
    "IFEMLocalUseResolutionError",
    "IFEMLocalUseResolutionV1",
    "build_ifem_local_use_resolution",
    "render_ifem_local_use_resolution",
    "verify_ifem_local_use_resolution_against_current_inputs",
]
