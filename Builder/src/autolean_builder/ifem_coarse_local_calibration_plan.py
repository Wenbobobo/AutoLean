"""Bind a text-free, non-executable coarse local calibration plan for iFEM.

The plan is a fail-closed inventory of already available digest-only evidence.  It does not
authorize reading source text into a model, create model input, execute a provider, freeze a
statement contract, or hand any artifact to Prover.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Final, Literal, Never, Self, cast

from autolean_contracts import StableIdentifierV1, canonical_json_bytes, stable_identifier
from autolean_contracts.base import ContractModel
from pydantic import Field, model_validator

from .ifem_local_use_request import (
    DEFAULT_DISCOVERY_MANIFEST_PATH,
    IFEMLocalUseRequestError,
    IFEMLocalUseRequestV1,
    build_ifem_local_use_request_from_manifest,
    verify_ifem_local_use_request_against_manifest,
)
from .ifem_notebook_source_span_index import (
    IFEMNotebookCellSourceSpanV1,
    IFEMNotebookSourceSpanIndexV1,
    render_ifem_notebook_source_span_index,
)

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CACHE_ROOT = ROOT / ".cache" / "references"
IFEM_LOCK_DIRECTORY: Final[str] = "ifem-interactive-fem-chapters-01-10-git-a4ab841-lock"
IFEM_SOURCE_LOCK_FILENAME: Final[str] = "source-lock.v1.json"
IFEM_NOTEBOOK_SOURCE_SPAN_INDEX_FILENAME: Final[str] = "notebook-source-span-index.v1.json"

IFEM_COARSE_LOCAL_CALIBRATION_PLAN_SCHEMA: Final[
    Literal["autolean.ifem-coarse-local-calibration-plan.v1"]
] = "autolean.ifem-coarse-local-calibration-plan.v1"
IFEM_COARSE_LOCAL_CALIBRATION_PLAN_PROTOCOL: Final[
    Literal["autolean.builder-ifem-coarse-local-calibration-plan.v1"]
] = "autolean.builder-ifem-coarse-local-calibration-plan.v1"
IFEM_COARSE_LOCAL_CALIBRATION_PLAN_KIND: Final[
    Literal["text_free_non_executable_coarse_local_calibration_plan"]
] = "text_free_non_executable_coarse_local_calibration_plan"
IFEM_COARSE_LOCAL_CALIBRATION_PLAN_NAMESPACE: Final[
    Literal["ifem-coarse-local-calibration-plan"]
] = "ifem-coarse-local-calibration-plan"

CURRENT_SOURCE_LOCK_RECEIPT_SHA256: Final[str] = (
    "74eca6689fe69dcbf2f34ea524a99cacc2054c0a39cfecfb11887c29e13cf239"
)
CURRENT_REFERENCE_MANIFEST_CANDIDATE_SHA256: Final[str] = (
    "4a5d859d77b606d6e485d98bd3e4afc41f6c566c6fb09f5e3dc2b2a539f18398"
)
CURRENT_SOURCE_REVISION: Final[str] = "a4ab841c4e5ec726e9b7742c9dcb352cb9645736"
CURRENT_NOTEBOOK_INDEX_CANONICAL_SHA256: Final[str] = (
    "3a0d39527481170a647cc8dc23917577e156f9ac42cb126f73759d784f8b03a7"
)
CURRENT_NOTEBOOK_INDEX_RENDERED_SHA256: Final[str] = (
    "afc4ae97a9d5ac79a044195712e2a0591d93132d233bb1f6e2f8abb745dd7204"
)
CURRENT_LOCAL_USE_REQUEST_SHA256: Final[str] = (
    "7fc6988f39d8b3233c2c836788f73b40ba82a839a79460aad7178d9d31356f33"
)
CURRENT_DISCOVERY_MANIFEST_SHA256: Final[str] = (
    "40073963427d6c8917145619c6d1b75cd085b1c3b817d2650edd2305b3b0e70b"
)

_CURRENT_LOCAL_USE_REQUEST_ID: Final[str] = (
    "urn:autolean:v1:ifem-local-use-request:e759e20b-6c79-5ca7-990f-cd07d5c4493d"
)
_CURRENT_OPENING_NOTEBOOK_SOURCE_PATH: Final[str] = "primal/first_example.ipynb"
_CURRENT_SOURCE_FILE_COUNT: Final[int] = 13
_CURRENT_NOTEBOOK_FILE_COUNT: Final[int] = 10
_CURRENT_NOTEBOOK_CELL_COUNT: Final[int] = 161
_CURRENT_OPENING_SPAN_SIGNATURES: Final[tuple[tuple[object, ...], ...]] = (
    (
        "urn:autolean:v1:ifem.notebook-source-span:3c998eb4-e0b0-57cc-a90e-502a35941954",
        "e6541ed4074229c9026393617d093fc9b1b85386bc3b459a56c9541caae7e74e",
        3,
        0,
        "markdown",
        "42267c3ee93d76f87949e4960df2448f1db3cbdbd78e9d37e8ace2719f04aa4e",
        759,
    ),
    (
        "urn:autolean:v1:ifem.notebook-source-span:6da8868b-ab7e-54f2-9023-3d9137946cf8",
        "e6541ed4074229c9026393617d093fc9b1b85386bc3b459a56c9541caae7e74e",
        3,
        1,
        "markdown",
        "5bfeb6229159207d76c6967d9cc6fa25c0adc9a30079cce99454c29006b13857",
        1640,
    ),
    (
        "urn:autolean:v1:ifem.notebook-source-span:85a2cbde-32e1-540b-8e54-bf92266a51c3",
        "e6541ed4074229c9026393617d093fc9b1b85386bc3b459a56c9541caae7e74e",
        3,
        2,
        "markdown",
        "c79742c5a34510d0c4b93bd751adcdaebf64ab0edc5c45ba5e9f952e175e878a",
        2141,
    ),
    (
        "urn:autolean:v1:ifem.notebook-source-span:f680f603-519e-5145-a323-98744255d946",
        "e6541ed4074229c9026393617d093fc9b1b85386bc3b459a56c9541caae7e74e",
        3,
        3,
        "markdown",
        "546a972e09c6bf66ce1ac92af5a2fdef3eed93fce96243e5822487215965098b",
        2095,
    ),
)
_FIXED_BLOCKERS: Final[
    tuple[
        Literal["rights_decision_missing"],
        Literal["local_model_processing_not_authorized"],
    ]
] = (
    "rights_decision_missing",
    "local_model_processing_not_authorized",
)
_SHA256 = r"^[0-9a-f]{64}$"
_REVISION = r"^[0-9a-f]{40}$"
_FORBIDDEN_RENDERED_FIELDS: Final[tuple[bytes, ...]] = (
    b'"source_text"',
    b'"cell_text"',
    b'"source_path"',
    b'"private_path"',
    b'"cache_root"',
    b'"model_input"',
    b'"prompt"',
    b'"provider"',
    b'"endpoint"',
)
_FORBIDDEN_KEYS: Final[frozenset[str]] = frozenset(
    {
        "cache_root",
        "cell_text",
        "model_input",
        "private_path",
        "prompt",
        "source_path",
        "source_text",
    }
)


class IFEMCoarseLocalCalibrationPlanError(ValueError):
    """Current bindings drifted or a caller tried to cross the plan-only boundary."""


class IFEMCoarseLocalCalibrationSourceLockBindingV1(ContractModel):
    """Public identity of the exact current local source lock."""

    schema_version: Literal["autolean.ifem-source-lock.v1"] = "autolean.ifem-source-lock.v1"
    receipt_sha256: str = Field(pattern=_SHA256)
    reference_manifest_candidate_sha256: str = Field(pattern=_SHA256)
    source_revision: str = Field(pattern=_REVISION)
    source_file_count: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_current_binding(self) -> Self:
        if (
            self.receipt_sha256 != CURRENT_SOURCE_LOCK_RECEIPT_SHA256
            or self.reference_manifest_candidate_sha256
            != CURRENT_REFERENCE_MANIFEST_CANDIDATE_SHA256
            or self.source_revision != CURRENT_SOURCE_REVISION
            or self.source_file_count != _CURRENT_SOURCE_FILE_COUNT
        ):
            raise ValueError("coarse calibration plan source-lock binding is not current")
        return self


class IFEMCoarseLocalCalibrationNotebookIndexBindingV1(ContractModel):
    """Canonical and persisted identities of the current text-free notebook index."""

    schema_version: Literal["autolean.ifem-notebook-source-span-index.v1"] = (
        "autolean.ifem-notebook-source-span-index.v1"
    )
    canonical_sha256: str = Field(pattern=_SHA256)
    rendered_sha256: str = Field(pattern=_SHA256)
    notebook_file_count: int = Field(gt=0)
    notebook_cell_count: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_current_binding(self) -> Self:
        if (
            self.canonical_sha256 != CURRENT_NOTEBOOK_INDEX_CANONICAL_SHA256
            or self.rendered_sha256 != CURRENT_NOTEBOOK_INDEX_RENDERED_SHA256
            or self.notebook_file_count != _CURRENT_NOTEBOOK_FILE_COUNT
            or self.notebook_cell_count != _CURRENT_NOTEBOOK_CELL_COUNT
        ):
            raise ValueError("coarse calibration plan notebook-index binding is not current")
        return self


class IFEMCoarseLocalCalibrationSpanBindingV1(ContractModel):
    """One coarse opening-cell identity without its source path or source text."""

    span_id: StableIdentifierV1
    source_file_sha256: str = Field(pattern=_SHA256)
    source_file_index: int = Field(ge=0)
    cell_index: int = Field(ge=0)
    cell_type: Literal["markdown"] = "markdown"
    cell_content_sha256: str = Field(pattern=_SHA256)
    cell_character_count: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_namespace(self) -> Self:
        if self.span_id.namespace != "ifem.notebook-source-span":
            raise ValueError("coarse calibration span has the wrong stable-id namespace")
        return self


class IFEMCoarseLocalCalibrationPendingRequestBindingV1(ContractModel):
    """Digest-only binding to the still-pending local-use request."""

    schema_version: Literal["autolean.ifem-local-use-request.v1"] = (
        "autolean.ifem-local-use-request.v1"
    )
    request_id: StableIdentifierV1
    discovery_manifest_content_sha256: str = Field(pattern=_SHA256)
    content_sha256: str = Field(pattern=_SHA256)
    request_status: Literal["pending_operator_rights_decision"] = "pending_operator_rights_decision"

    @model_validator(mode="after")
    def validate_current_binding(self) -> Self:
        if (
            self.request_id.schema_version != "1.0"
            or self.request_id.namespace != "ifem-local-use-request"
            or self.request_id.value != _CURRENT_LOCAL_USE_REQUEST_ID
            or self.discovery_manifest_content_sha256 != CURRENT_DISCOVERY_MANIFEST_SHA256
            or self.content_sha256 != CURRENT_LOCAL_USE_REQUEST_SHA256
        ):
            raise ValueError("coarse calibration plan pending-request binding is not current")
        return self


class IFEMCoarseLocalCalibrationAuthorityV1(ContractModel):
    """Every authority bit remains false while the two blockers are open."""

    schema_version: Literal["autolean.ifem-coarse-local-calibration-authority.v1"] = (
        "autolean.ifem-coarse-local-calibration-authority.v1"
    )
    rights_decision_authorized: Literal[False] = False
    local_model_processing_authorized: Literal[False] = False
    model_execution_authorized: Literal[False] = False
    semantic_review_authorized: Literal[False] = False
    statement_contract_authorized: Literal[False] = False
    builder_freeze_authorized: Literal[False] = False
    prover_handoff_authorized: Literal[False] = False
    kernel_verification_authorized: Literal[False] = False
    promotion_authorized: Literal[False] = False
    release_authorized: Literal[False] = False


class IFEMCoarseLocalCalibrationPlanV1(ContractModel):
    """A current, text-free plan record carrying no execution or workflow authority."""

    schema_version: Literal["autolean.ifem-coarse-local-calibration-plan.v1"] = (
        IFEM_COARSE_LOCAL_CALIBRATION_PLAN_SCHEMA
    )
    protocol: Literal["autolean.builder-ifem-coarse-local-calibration-plan.v1"] = (
        IFEM_COARSE_LOCAL_CALIBRATION_PLAN_PROTOCOL
    )
    artifact_kind: Literal["text_free_non_executable_coarse_local_calibration_plan"] = (
        IFEM_COARSE_LOCAL_CALIBRATION_PLAN_KIND
    )
    plan_id: StableIdentifierV1
    source_lock: IFEMCoarseLocalCalibrationSourceLockBindingV1
    notebook_index: IFEMCoarseLocalCalibrationNotebookIndexBindingV1
    opening_spans: tuple[IFEMCoarseLocalCalibrationSpanBindingV1, ...] = Field(
        min_length=4,
        max_length=4,
    )
    pending_local_use_request: IFEMCoarseLocalCalibrationPendingRequestBindingV1
    selection_state: Literal["coarse_source_containers_not_claim_spans"] = (
        "coarse_source_containers_not_claim_spans"
    )
    plan_state: Literal["blocked_before_local_model_processing"] = (
        "blocked_before_local_model_processing"
    )
    source_text_present: Literal[False] = False
    model_input_present: Literal[False] = False
    executable: Literal[False] = False
    synthetic_self_calibration_reused: Literal[False] = False
    blockers: tuple[
        Literal["rights_decision_missing"],
        Literal["local_model_processing_not_authorized"],
    ] = _FIXED_BLOCKERS
    authority: IFEMCoarseLocalCalibrationAuthorityV1 = Field(
        default_factory=IFEMCoarseLocalCalibrationAuthorityV1
    )
    builder_freeze: Literal["forbidden"] = "forbidden"
    prover_handoff: Literal["forbidden"] = "forbidden"
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_plan(self) -> Self:
        if tuple(_span_signature(span) for span in self.opening_spans) != (
            _CURRENT_OPENING_SPAN_SIGNATURES
        ):
            raise ValueError("coarse calibration plan does not bind opening cells 0-3")
        if self.blockers != _FIXED_BLOCKERS:
            raise ValueError("coarse calibration plan blockers drifted")
        if self.authority != IFEMCoarseLocalCalibrationAuthorityV1():
            raise ValueError("coarse calibration plan authority flags drifted")
        expected_id = _plan_id(
            source_lock_sha256=self.source_lock.receipt_sha256,
            notebook_index_sha256=self.notebook_index.canonical_sha256,
            opening_spans=self.opening_spans,
            local_use_request_sha256=self.pending_local_use_request.content_sha256,
        )
        if self.plan_id != expected_id:
            raise ValueError("coarse calibration plan id does not bind its inputs")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("coarse calibration plan content hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(dict[str, object], self.model_dump(mode="json", exclude={"content_sha256"}))

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.content_payload())).hexdigest()

    def assert_non_executable(self) -> Never:
        raise IFEMCoarseLocalCalibrationPlanError(
            "iFEM coarse calibration plan is blocked before local model processing and "
            "cannot execute, freeze a statement, or hand work to Prover"
        )

    def freeze_statement(self) -> Never:
        self.assert_non_executable()

    def handoff_to_prover(self) -> Never:
        self.assert_non_executable()


def _span_signature(span: IFEMCoarseLocalCalibrationSpanBindingV1) -> tuple[object, ...]:
    return (
        span.span_id.value,
        span.source_file_sha256,
        span.source_file_index,
        span.cell_index,
        span.cell_type,
        span.cell_content_sha256,
        span.cell_character_count,
    )


def _source_span_signature(span: IFEMNotebookCellSourceSpanV1) -> tuple[object, ...]:
    return (
        span.span_id.value,
        span.source_file_sha256,
        span.source_file_index,
        span.cell_index,
        span.cell_type,
        span.cell_content_sha256,
        span.cell_character_count,
    )


def _plan_id(
    *,
    source_lock_sha256: str,
    notebook_index_sha256: str,
    opening_spans: tuple[IFEMCoarseLocalCalibrationSpanBindingV1, ...],
    local_use_request_sha256: str,
) -> StableIdentifierV1:
    return stable_identifier(
        IFEM_COARSE_LOCAL_CALIBRATION_PLAN_NAMESPACE,
        ":".join(
            (
                source_lock_sha256,
                notebook_index_sha256,
                *(span.span_id.value for span in opening_spans),
                *(span.cell_content_sha256 for span in opening_spans),
                local_use_request_sha256,
            )
        ),
    )


def build_ifem_coarse_local_calibration_plan(
    *,
    notebook_index: IFEMNotebookSourceSpanIndexV1,
    notebook_index_rendered_sha256: str,
    pending_local_use_request: IFEMLocalUseRequestV1,
) -> IFEMCoarseLocalCalibrationPlanV1:
    """Build the plan only from exact, typed, current digest-only inputs."""

    if type(notebook_index) is not IFEMNotebookSourceSpanIndexV1:
        raise IFEMCoarseLocalCalibrationPlanError("notebook index must use its exact typed model")
    if type(pending_local_use_request) is not IFEMLocalUseRequestV1:
        raise IFEMCoarseLocalCalibrationPlanError(
            "pending local-use request must use its exact typed model"
        )
    try:
        verified_index = IFEMNotebookSourceSpanIndexV1.model_validate(
            notebook_index.model_dump(mode="json")
        )
        verified_request = IFEMLocalUseRequestV1.model_validate(
            pending_local_use_request.model_dump(mode="json")
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMCoarseLocalCalibrationPlanError(
            "coarse calibration plan input failed self-revalidation"
        ) from error

    if verified_index.source_lock.source_lock_sha256 != CURRENT_SOURCE_LOCK_RECEIPT_SHA256:
        raise IFEMCoarseLocalCalibrationPlanError("current source-lock receipt does not match")
    if verified_index.source_lock.source_revision != CURRENT_SOURCE_REVISION:
        raise IFEMCoarseLocalCalibrationPlanError("current source revision does not match")
    if verified_index.source_lock.source_file_count != _CURRENT_SOURCE_FILE_COUNT:
        raise IFEMCoarseLocalCalibrationPlanError("current source-file count does not match")
    if verified_index.source_lock.notebook_file_count != _CURRENT_NOTEBOOK_FILE_COUNT:
        raise IFEMCoarseLocalCalibrationPlanError("current notebook-file count does not match")
    if verified_index.notebook_cell_count != _CURRENT_NOTEBOOK_CELL_COUNT:
        raise IFEMCoarseLocalCalibrationPlanError("current notebook-cell count does not match")
    if verified_index.canonical_sha256() != CURRENT_NOTEBOOK_INDEX_CANONICAL_SHA256:
        raise IFEMCoarseLocalCalibrationPlanError("current notebook-index identity does not match")
    if notebook_index_rendered_sha256 != CURRENT_NOTEBOOK_INDEX_RENDERED_SHA256:
        raise IFEMCoarseLocalCalibrationPlanError(
            "current persisted notebook-index identity does not match"
        )
    if (
        verified_request.source.source_lock_receipt_sha256 != CURRENT_SOURCE_LOCK_RECEIPT_SHA256
        or verified_request.source.reference_manifest_candidate_sha256
        != CURRENT_REFERENCE_MANIFEST_CANDIDATE_SHA256
        or verified_request.source.resolved_revision != CURRENT_SOURCE_REVISION
        or verified_request.discovery_manifest_content_sha256 != CURRENT_DISCOVERY_MANIFEST_SHA256
        or verified_request.content_sha256 != CURRENT_LOCAL_USE_REQUEST_SHA256
        or verified_request.request_id.value != _CURRENT_LOCAL_USE_REQUEST_ID
    ):
        raise IFEMCoarseLocalCalibrationPlanError(
            "current pending local-use request identity does not match"
        )

    selected = tuple(
        span
        for span in verified_index.spans
        if span.source_path == _CURRENT_OPENING_NOTEBOOK_SOURCE_PATH
        and span.cell_index in (0, 1, 2, 3)
    )
    if tuple(_source_span_signature(span) for span in selected) != (
        _CURRENT_OPENING_SPAN_SIGNATURES
    ):
        raise IFEMCoarseLocalCalibrationPlanError(
            "current notebook index does not bind the expected opening cells 0-3"
        )
    opening_spans = tuple(
        IFEMCoarseLocalCalibrationSpanBindingV1(
            span_id=span.span_id,
            source_file_sha256=span.source_file_sha256,
            source_file_index=span.source_file_index,
            cell_index=span.cell_index,
            cell_type=cast(Literal["markdown"], span.cell_type),
            cell_content_sha256=span.cell_content_sha256,
            cell_character_count=span.cell_character_count,
        )
        for span in selected
    )
    source_lock = IFEMCoarseLocalCalibrationSourceLockBindingV1(
        receipt_sha256=verified_index.source_lock.source_lock_sha256,
        reference_manifest_candidate_sha256=(
            verified_request.source.reference_manifest_candidate_sha256
        ),
        source_revision=verified_index.source_lock.source_revision,
        source_file_count=verified_index.source_lock.source_file_count,
    )
    index_binding = IFEMCoarseLocalCalibrationNotebookIndexBindingV1(
        canonical_sha256=verified_index.canonical_sha256(),
        rendered_sha256=notebook_index_rendered_sha256,
        notebook_file_count=verified_index.source_lock.notebook_file_count,
        notebook_cell_count=verified_index.notebook_cell_count,
    )
    request_binding = IFEMCoarseLocalCalibrationPendingRequestBindingV1(
        request_id=verified_request.request_id,
        discovery_manifest_content_sha256=(verified_request.discovery_manifest_content_sha256),
        content_sha256=verified_request.content_sha256,
    )
    payload: dict[str, object] = {
        "schema_version": IFEM_COARSE_LOCAL_CALIBRATION_PLAN_SCHEMA,
        "protocol": IFEM_COARSE_LOCAL_CALIBRATION_PLAN_PROTOCOL,
        "artifact_kind": IFEM_COARSE_LOCAL_CALIBRATION_PLAN_KIND,
        "plan_id": _plan_id(
            source_lock_sha256=source_lock.receipt_sha256,
            notebook_index_sha256=index_binding.canonical_sha256,
            opening_spans=opening_spans,
            local_use_request_sha256=request_binding.content_sha256,
        ).model_dump(mode="json"),
        "source_lock": source_lock.model_dump(mode="json"),
        "notebook_index": index_binding.model_dump(mode="json"),
        "opening_spans": [span.model_dump(mode="json") for span in opening_spans],
        "pending_local_use_request": request_binding.model_dump(mode="json"),
        "selection_state": "coarse_source_containers_not_claim_spans",
        "plan_state": "blocked_before_local_model_processing",
        "source_text_present": False,
        "model_input_present": False,
        "executable": False,
        "synthetic_self_calibration_reused": False,
        "blockers": list(_FIXED_BLOCKERS),
        "authority": IFEMCoarseLocalCalibrationAuthorityV1().model_dump(mode="json"),
        "builder_freeze": "forbidden",
        "prover_handoff": "forbidden",
    }
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    try:
        plan = IFEMCoarseLocalCalibrationPlanV1.model_validate(payload)
    except ValueError as error:
        raise IFEMCoarseLocalCalibrationPlanError(
            "current inputs cannot form the coarse calibration plan"
        ) from error
    render_ifem_coarse_local_calibration_plan(plan)
    return plan


def build_current_ifem_coarse_local_calibration_plan(
    *,
    cache_root: Path = DEFAULT_CACHE_ROOT,
    discovery_manifest_path: Path = DEFAULT_DISCOVERY_MANIFEST_PATH,
) -> IFEMCoarseLocalCalibrationPlanV1:
    """Replay the current lock, stored index, and pending request, then build the plan."""

    root = _require_cache_root(cache_root)
    lock_path = root / IFEM_LOCK_DIRECTORY / IFEM_SOURCE_LOCK_FILENAME
    index_path = root / IFEM_LOCK_DIRECTORY / IFEM_NOTEBOOK_SOURCE_SPAN_INDEX_FILENAME
    lock_raw = _read_confined_regular_file(lock_path, root=root, label="iFEM source lock")
    index_raw = _read_confined_regular_file(
        index_path,
        root=root,
        label="iFEM notebook source-span index",
    )
    if hashlib.sha256(lock_raw).hexdigest() != CURRENT_SOURCE_LOCK_RECEIPT_SHA256:
        raise IFEMCoarseLocalCalibrationPlanError("current source-lock receipt does not match")
    if hashlib.sha256(index_raw).hexdigest() != CURRENT_NOTEBOOK_INDEX_RENDERED_SHA256:
        raise IFEMCoarseLocalCalibrationPlanError(
            "current persisted notebook-index identity does not match"
        )
    stored_index = _load_notebook_index(index_raw)
    if stored_index.canonical_sha256() != CURRENT_NOTEBOOK_INDEX_CANONICAL_SHA256:
        raise IFEMCoarseLocalCalibrationPlanError("current notebook-index identity does not match")
    if stored_index.source_lock.source_lock_sha256 != hashlib.sha256(lock_raw).hexdigest():
        raise IFEMCoarseLocalCalibrationPlanError(
            "persisted notebook index does not bind the current source lock"
        )
    try:
        pending_request = build_ifem_local_use_request_from_manifest(discovery_manifest_path)
        verify_ifem_local_use_request_against_manifest(
            pending_request,
            discovery_manifest_path,
        )
    except IFEMLocalUseRequestError as error:
        raise IFEMCoarseLocalCalibrationPlanError(
            "cannot replay the current pending local-use request"
        ) from error
    plan = build_ifem_coarse_local_calibration_plan(
        notebook_index=stored_index,
        notebook_index_rendered_sha256=hashlib.sha256(index_raw).hexdigest(),
        pending_local_use_request=pending_request,
    )
    _require_unchanged(lock_path, root=root, expected=lock_raw, label="iFEM source lock")
    _require_unchanged(
        index_path,
        root=root,
        expected=index_raw,
        label="iFEM notebook source-span index",
    )
    return plan


def render_ifem_coarse_local_calibration_plan(
    plan: IFEMCoarseLocalCalibrationPlanV1,
) -> bytes:
    """Render canonical public JSON and reject payload-bearing field surfaces."""

    if type(plan) is not IFEMCoarseLocalCalibrationPlanV1:
        raise IFEMCoarseLocalCalibrationPlanError("plan must use its exact typed model")
    try:
        verified = IFEMCoarseLocalCalibrationPlanV1.model_validate(plan.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMCoarseLocalCalibrationPlanError("plan failed self-revalidation") from error
    document = cast(dict[str, object], verified.model_dump(mode="json"))
    _reject_forbidden_surface(document)
    rendered = canonical_json_bytes(document) + b"\n"
    if any(field in rendered for field in _FORBIDDEN_RENDERED_FIELDS):
        raise IFEMCoarseLocalCalibrationPlanError(
            "plan rendering exposed a source, model, provider, endpoint, or private-path field"
        )
    return rendered


def load_ifem_coarse_local_calibration_plan(path: Path) -> IFEMCoarseLocalCalibrationPlanV1:
    """Load only the strict canonical public plan; current-input replay remains separate."""

    raw = _read_regular_file(path, label="iFEM coarse local calibration plan")
    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_constant,
        )
    except IFEMCoarseLocalCalibrationPlanError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IFEMCoarseLocalCalibrationPlanError(
            "iFEM coarse local calibration plan is not strict UTF-8 JSON"
        ) from error
    if not isinstance(payload, dict):
        raise IFEMCoarseLocalCalibrationPlanError(
            "iFEM coarse local calibration plan must be a JSON object"
        )
    try:
        plan = IFEMCoarseLocalCalibrationPlanV1.model_validate(payload)
    except ValueError as error:
        raise IFEMCoarseLocalCalibrationPlanError(
            "iFEM coarse local calibration plan is invalid"
        ) from error
    if render_ifem_coarse_local_calibration_plan(plan) != raw:
        raise IFEMCoarseLocalCalibrationPlanError(
            "iFEM coarse local calibration plan is not canonically rendered"
        )
    return plan


def materialize_ifem_coarse_local_calibration_plan_once(
    output_path: Path,
    *,
    cache_root: Path = DEFAULT_CACHE_ROOT,
    discovery_manifest_path: Path = DEFAULT_DISCOVERY_MANIFEST_PATH,
) -> IFEMCoarseLocalCalibrationPlanV1:
    """Write the exact current plan once; identical bytes are idempotent, conflicts reject."""

    plan = build_current_ifem_coarse_local_calibration_plan(
        cache_root=cache_root,
        discovery_manifest_path=discovery_manifest_path,
    )
    _write_once(output_path, render_ifem_coarse_local_calibration_plan(plan))
    persisted = load_ifem_coarse_local_calibration_plan(output_path)
    if persisted != plan:
        raise IFEMCoarseLocalCalibrationPlanError(
            "persisted coarse local calibration plan differs from current replay"
        )
    verify_ifem_coarse_local_calibration_plan_against_current_inputs(
        persisted,
        cache_root=cache_root,
        discovery_manifest_path=discovery_manifest_path,
    )
    return persisted


def verify_ifem_coarse_local_calibration_plan_against_current_inputs(
    plan: IFEMCoarseLocalCalibrationPlanV1,
    *,
    cache_root: Path = DEFAULT_CACHE_ROOT,
    discovery_manifest_path: Path = DEFAULT_DISCOVERY_MANIFEST_PATH,
) -> None:
    """Require byte-equivalent logical replay of every current plan input."""

    if type(plan) is not IFEMCoarseLocalCalibrationPlanV1:
        raise IFEMCoarseLocalCalibrationPlanError("plan must use its exact typed model")
    expected = build_current_ifem_coarse_local_calibration_plan(
        cache_root=cache_root,
        discovery_manifest_path=discovery_manifest_path,
    )
    if plan != expected:
        raise IFEMCoarseLocalCalibrationPlanError(
            "coarse local calibration plan differs from current input replay"
        )


def _load_notebook_index(raw: bytes) -> IFEMNotebookSourceSpanIndexV1:
    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_constant,
        )
    except IFEMCoarseLocalCalibrationPlanError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IFEMCoarseLocalCalibrationPlanError(
            "current notebook index is not strict UTF-8 JSON"
        ) from error
    try:
        index = IFEMNotebookSourceSpanIndexV1.model_validate(payload)
    except ValueError as error:
        raise IFEMCoarseLocalCalibrationPlanError(
            "current notebook index does not satisfy its typed contract"
        ) from error
    if render_ifem_notebook_source_span_index(index) != raw:
        raise IFEMCoarseLocalCalibrationPlanError(
            "current notebook index is not canonically rendered"
        )
    return index


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IFEMCoarseLocalCalibrationPlanError("duplicate JSON key")
        result[key] = value
    return result


def _reject_nonfinite_constant(value: str) -> Never:
    raise IFEMCoarseLocalCalibrationPlanError(f"non-finite JSON constant is forbidden: {value}")


def _reject_forbidden_surface(value: object) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if (
                key in _FORBIDDEN_KEYS
                or "provider" in key
                or "endpoint" in key
                or key.endswith("_private_path")
            ):
                raise IFEMCoarseLocalCalibrationPlanError(
                    "plan rendering exposed a source, model, provider, endpoint, or "
                    "private-path field"
                )
            _reject_forbidden_surface(child)
    elif isinstance(value, list):
        for child in value:
            _reject_forbidden_surface(child)


def _require_cache_root(path: Path) -> Path:
    try:
        root = path.resolve(strict=True)
    except OSError as error:
        raise IFEMCoarseLocalCalibrationPlanError(
            "current local iFEM cache is absent or inaccessible"
        ) from error
    if not root.is_dir():
        raise IFEMCoarseLocalCalibrationPlanError("current local iFEM cache is not a directory")
    return root


def _read_regular_file(path: Path, *, label: str) -> bytes:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise IFEMCoarseLocalCalibrationPlanError(f"{label} must be an unlinked regular file")
        return path.read_bytes()
    except OSError as error:
        raise IFEMCoarseLocalCalibrationPlanError(f"cannot read {label}") from error


def _read_confined_regular_file(path: Path, *, root: Path, label: str) -> bytes:
    try:
        relative = path.relative_to(root)
        cursor = root
        for part in relative.parts:
            cursor /= part
            if cursor.is_symlink():
                raise IFEMCoarseLocalCalibrationPlanError(f"{label} must not cross a symbolic link")
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise IFEMCoarseLocalCalibrationPlanError(
            f"{label} is absent or escapes the local cache"
        ) from error
    return _read_regular_file(resolved, label=label)


def _write_once(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError:
        existing = _read_regular_file(
            path,
            label="existing iFEM coarse local calibration plan",
        )
        if existing != content:
            raise IFEMCoarseLocalCalibrationPlanError(
                "coarse local calibration plan output already exists with different bytes"
            ) from None


def _require_unchanged(
    path: Path,
    *,
    root: Path,
    expected: bytes,
    label: str,
) -> None:
    if _read_confined_regular_file(path, root=root, label=label) != expected:
        raise IFEMCoarseLocalCalibrationPlanError(f"{label} changed while the plan was being built")


__all__ = [
    "CURRENT_DISCOVERY_MANIFEST_SHA256",
    "CURRENT_LOCAL_USE_REQUEST_SHA256",
    "CURRENT_NOTEBOOK_INDEX_CANONICAL_SHA256",
    "CURRENT_NOTEBOOK_INDEX_RENDERED_SHA256",
    "CURRENT_REFERENCE_MANIFEST_CANDIDATE_SHA256",
    "CURRENT_SOURCE_LOCK_RECEIPT_SHA256",
    "CURRENT_SOURCE_REVISION",
    "DEFAULT_CACHE_ROOT",
    "IFEM_COARSE_LOCAL_CALIBRATION_PLAN_KIND",
    "IFEM_COARSE_LOCAL_CALIBRATION_PLAN_NAMESPACE",
    "IFEM_COARSE_LOCAL_CALIBRATION_PLAN_PROTOCOL",
    "IFEM_COARSE_LOCAL_CALIBRATION_PLAN_SCHEMA",
    "IFEMCoarseLocalCalibrationAuthorityV1",
    "IFEMCoarseLocalCalibrationNotebookIndexBindingV1",
    "IFEMCoarseLocalCalibrationPendingRequestBindingV1",
    "IFEMCoarseLocalCalibrationPlanError",
    "IFEMCoarseLocalCalibrationPlanV1",
    "IFEMCoarseLocalCalibrationSourceLockBindingV1",
    "IFEMCoarseLocalCalibrationSpanBindingV1",
    "build_current_ifem_coarse_local_calibration_plan",
    "build_ifem_coarse_local_calibration_plan",
    "load_ifem_coarse_local_calibration_plan",
    "materialize_ifem_coarse_local_calibration_plan_once",
    "render_ifem_coarse_local_calibration_plan",
    "verify_ifem_coarse_local_calibration_plan_against_current_inputs",
]
