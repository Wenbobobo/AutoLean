"""Fail-closed boundaries for the private iFEM local-use rights candidate."""

from __future__ import annotations

import ast
import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from autolean_builder import ifem_local_use_resolution as resolution_module
from autolean_builder.ifem_coarse_local_calibration_plan import (
    IFEMCoarseLocalCalibrationPlanV1,
    load_ifem_coarse_local_calibration_plan,
)
from autolean_builder.ifem_local_use_request import (
    IFEMLocalUseRequestV1,
    build_ifem_local_use_request_from_manifest,
)
from autolean_contracts import (
    DigestV1,
    EndpointClassV1,
    HashKindV1,
    ModelEgressPolicyV1,
    PermissionDecisionV1,
    RightsRecordV1,
    SourceRecordV1,
    SourceSpanV1,
    StableIdentifierV1,
    canonical_json_bytes,
    digest_model,
    stable_identifier,
)

ROOT = Path(__file__).resolve().parents[2]
PLAN_PATH = (
    ROOT
    / "Builder"
    / "pilots"
    / "ifem-source-alignment"
    / "ifem-coarse-local-calibration-plan.v1.json"
)
_RESTRICTIONS = (
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


def _plan() -> IFEMCoarseLocalCalibrationPlanV1:
    return load_ifem_coarse_local_calibration_plan(PLAN_PATH)


def _request() -> IFEMLocalUseRequestV1:
    return build_ifem_local_use_request_from_manifest()


def _source(plan: IFEMCoarseLocalCalibrationPlanV1) -> SourceRecordV1:
    source_sha256 = plan.opening_spans[0].source_file_sha256
    source_path = "primal/first_example.ipynb"
    return SourceRecordV1(
        source_id=stable_identifier(
            "ifem.source-record",
            f"{plan.source_lock.source_revision}:{source_path}:{source_sha256}",
        ),
        work_id="ifem-interactive-fem-chapters-01-10",
        title="iFEM locked notebook source",
        version=f"git-{plan.source_lock.source_revision}",
        locator=source_path,
        content_hash=DigestV1(kind=HashKindV1.SOURCE_BYTES, value=source_sha256),
        snapshot_ref=f"ifem-source-lock:sha256:{plan.source_lock.receipt_sha256}",
        retrieved_at=datetime(2026, 7, 29, tzinfo=UTC),
        spans=tuple(
            SourceSpanV1(
                span_id=span.span_id,
                locator=f"notebook-cell:{span.cell_index}:type:markdown",
                content_hash=DigestV1(
                    kind=HashKindV1.SOURCE_SPAN,
                    value=span.cell_content_sha256,
                ),
            )
            for span in plan.opening_spans
        ),
        metadata={
            "model_egress_policy": "local_only",
            "source_alignment_only": True,
            "semantic_review_state": "not_performed",
        },
    )


def _rights(
    source: SourceRecordV1,
    request: IFEMLocalUseRequestV1 | None = None,
    **changes: object,
) -> RightsRecordV1:
    current_request = request or _request()
    payload: dict[str, object] = {
        "rights_id": stable_identifier(
            "ifem-local-rights-claim",
            f"{current_request.request_id.value}:{source.source_id.value}",
        ),
        "source_id": source.source_id,
        "source_license": "CC-BY-4.0",
        "generated_code_license": None,
        "overall_decision": PermissionDecisionV1.UNKNOWN,
        "redistribution": PermissionDecisionV1.DENY,
        "model_egress": PermissionDecisionV1.DENY,
        "training": PermissionDecisionV1.DENY,
        "embedding": PermissionDecisionV1.DENY,
        "allowed_endpoint_classes": (),
        "attribution": "iFEM contributors; CC BY 4.0",
        "restrictions": _RESTRICTIONS,
        "reviewed_by": None,
        "reviewed_at": None,
    }
    payload.update(changes)
    return RightsRecordV1.model_validate(payload)


def _resolution() -> resolution_module.IFEMLocalUseResolutionV1:
    plan = _plan()
    request = _request()
    source = _source(plan)
    return resolution_module.build_ifem_local_use_resolution(
        coarse_plan=plan,
        pending_request=request,
        source=source,
        rights_claim=_rights(source, request),
    )


def _rehash(payload: dict[str, object]) -> None:
    payload["content_sha256"] = hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in payload.items() if key != "content_sha256"}
        )
    ).hexdigest()


def _rebind_resolution_id(payload: dict[str, object]) -> None:
    payload["resolution_id"] = resolution_module._resolution_id(
        coarse_plan_content_sha256=cast(str, payload["coarse_plan_content_sha256"]),
        pending_request_id=StableIdentifierV1.model_validate(payload["pending_request_id"]),
        pending_request_content_sha256=cast(str, payload["pending_request_content_sha256"]),
        source_record_sha256=cast(str, payload["source_record_sha256"]),
        rights_claim_sha256=cast(str, payload["rights_claim_sha256"]),
    ).model_dump(mode="json")
    _rehash(payload)


def test_builds_only_a_private_candidate_with_no_processing_authority() -> None:
    resolution = _resolution()

    assert resolution.artifact_kind == "private_local_processing_rights_candidate"
    assert resolution.resolution_state == "candidate_pending_trusted_rights_attestation"
    assert resolution.coarse_plan_content_sha256 == _plan().content_sha256
    assert resolution.pending_request_content_sha256 == _request().content_sha256
    assert resolution.source_text_included is False
    assert resolution.model_input_included is False
    assert resolution.model_execution_capability_included is False
    assert resolution.public_artifact is False
    assert resolution.requested_endpoint_class is EndpointClassV1.LOCAL
    assert resolution.authority.rights_claim_recorded is True
    assert all(
        value is False
        for name, value in resolution.authority
        if name not in {"schema_version", "rights_claim_recorded"}
    )
    assert resolution.unverified_rights_claim.overall_decision is PermissionDecisionV1.UNKNOWN
    assert resolution.unverified_rights_claim.reviewed_by is None
    assert resolution.unverified_rights_claim.reviewed_at is None
    assert resolution_module.render_ifem_local_use_resolution(resolution).endswith(b"\n")


def test_unverified_claim_cannot_enter_any_model_endpoint_class() -> None:
    claim = _resolution().unverified_rights_claim
    policy = ModelEgressPolicyV1(
        rights_id=claim.rights_id,
        overall_decision=claim.overall_decision,
        model_egress=claim.model_egress,
        allowed_endpoint_classes=claim.allowed_endpoint_classes,
    )

    assert policy.permits(EndpointClassV1.LOCAL) is False
    assert policy.permits(EndpointClassV1.APPROVED_EXTERNAL) is False
    assert policy.permits(EndpointClassV1.EXTERNAL) is False


def test_candidate_always_rejects_processing_execution_freeze_and_handoff() -> None:
    resolution = _resolution()

    for operation in (
        resolution.assert_rights_allow_local_processing,
        resolution.authorize_model_execution,
        resolution.authorize_external_egress,
        resolution.freeze_statement,
        resolution.handoff_to_prover,
    ):
        with pytest.raises(
            resolution_module.IFEMLocalUseResolutionError,
            match="pending a trusted rights attestation",
        ):
            operation()


def test_current_input_verifier_checks_binding_but_grants_nothing() -> None:
    resolution = _resolution()
    plan = _plan()
    source = _source(plan)

    assert (
        resolution_module.verify_ifem_local_use_resolution_against_current_inputs(
            resolution,
            coarse_plan=plan,
            pending_request=_request(),
            source=source,
        )
        is None
    )
    with pytest.raises(resolution_module.IFEMLocalUseResolutionError):
        resolution.assert_rights_allow_local_processing()


@pytest.mark.parametrize(
    ("changes", "message"),
    (
        ({"rights_id": stable_identifier("attacker-rights", "claim")}, "claim id"),
        ({"source_license": "unknown"}, "CC-BY-4.0"),
        ({"generated_code_license": "MIT"}, "generated-code"),
        ({"overall_decision": PermissionDecisionV1.RESTRICTED}, "must remain unknown"),
        (
            {
                "overall_decision": PermissionDecisionV1.ALLOW,
                "reviewed_by": "attacker-controlled-identity",
                "reviewed_at": datetime(2099, 1, 1, tzinfo=UTC),
            },
            "must remain unknown",
        ),
        ({"redistribution": PermissionDecisionV1.ALLOW}, "redistribution"),
        (
            {
                "model_egress": PermissionDecisionV1.ALLOW,
                "allowed_endpoint_classes": (EndpointClassV1.APPROVED_EXTERNAL,),
            },
            "external model egress",
        ),
        ({"training": PermissionDecisionV1.ALLOW}, "training"),
        ({"embedding": PermissionDecisionV1.ALLOW}, "embedding"),
        ({"attribution": "attacker attribution"}, "attribution drifted"),
        ({"reviewed_by": "attacker-controlled-identity"}, "cannot name a reviewer"),
        ({"reviewed_at": datetime(2099, 1, 1, tzinfo=UTC)}, "cannot name a reviewer"),
        ({"reviewed_at": datetime(2026, 8, 1)}, "cannot name a reviewer"),
        ({"restrictions": _RESTRICTIONS[:-1]}, "restrictions drifted"),
        ({"restrictions": tuple(reversed(_RESTRICTIONS))}, "restrictions drifted"),
        ({"restrictions": (*_RESTRICTIONS, "extra")}, "restrictions drifted"),
    ),
)
def test_rejects_untrusted_or_widened_rights_claim(
    changes: dict[str, object],
    message: str,
) -> None:
    plan = _plan()
    request = _request()
    source = _source(plan)

    with pytest.raises(resolution_module.IFEMLocalUseResolutionError, match=message):
        resolution_module.build_ifem_local_use_resolution(
            coarse_plan=plan,
            pending_request=request,
            source=source,
            rights_claim=_rights(source, request, **changes),
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("wrong_path", "opening iFEM notebook"),
        ("wrong_source_id", "deterministic current id"),
        ("wrong_source_hash", "source bytes differ"),
        ("wrong_revision", "revision differs"),
        ("wrong_snapshot", "snapshot differs"),
        ("missing_cell", "exactly the ordered"),
        ("extra_cell", "exactly the ordered"),
        ("reordered_cells", "exactly the ordered"),
        ("selected_offset", "exactly the ordered"),
        ("semantic_claim", "metadata must match"),
        ("extra_metadata", "metadata must match"),
        ("naive_retrieval", "timezone-aware"),
    ),
)
def test_rejects_source_or_plan_scope_drift(mutation: str, message: str) -> None:
    plan = _plan()
    source_payload = _source(plan).model_dump(mode="json")
    if mutation == "wrong_path":
        source_payload["locator"] = "primal/other.ipynb"
    elif mutation == "wrong_source_id":
        source_payload["source_id"] = stable_identifier(
            "attacker-source",
            "arbitrary",
        ).model_dump(mode="json")
    elif mutation == "wrong_source_hash":
        cast(dict[str, object], source_payload["content_hash"])["value"] = "0" * 64
    elif mutation == "wrong_revision":
        source_payload["version"] = "git-" + "0" * 40
    elif mutation == "wrong_snapshot":
        source_payload["snapshot_ref"] = "attacker:snapshot"
    elif mutation == "missing_cell":
        cast(list[dict[str, object]], source_payload["spans"]).pop()
    elif mutation == "extra_cell":
        cast(list[dict[str, object]], source_payload["spans"]).append(
            SourceSpanV1(
                span_id=stable_identifier("ifem.notebook-source-span", "attacker-extra"),
                locator="notebook-cell:999:type:markdown",
                content_hash=DigestV1(kind=HashKindV1.SOURCE_SPAN, value="d" * 64),
            ).model_dump(mode="json")
        )
    elif mutation == "reordered_cells":
        cast(list[dict[str, object]], source_payload["spans"]).reverse()
    elif mutation == "selected_offset":
        span = cast(list[dict[str, object]], source_payload["spans"])[0]
        span["start_offset"] = 0
        span["end_offset"] = 1
    elif mutation == "semantic_claim":
        cast(dict[str, object], source_payload["metadata"])["semantic_review_state"] = "passed"
    elif mutation == "extra_metadata":
        cast(dict[str, object], source_payload["metadata"])["source_text"] = "secret text"
    elif mutation == "naive_retrieval":
        source_payload["retrieved_at"] = "2026-07-29T00:00:00"
    source = SourceRecordV1.model_validate(source_payload)

    with pytest.raises(resolution_module.IFEMLocalUseResolutionError, match=message):
        resolution_module.build_ifem_local_use_resolution(
            coarse_plan=plan,
            pending_request=_request(),
            source=source,
            rights_claim=_rights(source),
        )


def test_recomputed_all_hashes_cannot_replace_current_bindings() -> None:
    resolution = _resolution()
    payload = resolution.model_dump(mode="json")
    payload["coarse_plan_content_sha256"] = "a" * 64
    payload["pending_request_content_sha256"] = "b" * 64
    source_payload = cast(dict[str, object], payload["source"])
    source_payload["version"] = "git-" + "0" * 40
    source_payload["snapshot_ref"] = "attacker:snapshot"
    cast(dict[str, object], source_payload["content_hash"])["value"] = "c" * 64
    forged_source = SourceRecordV1.model_validate(source_payload)
    payload["source_record_sha256"] = digest_model(
        HashKindV1.SOURCE_RECORD,
        forged_source,
    ).value
    _rebind_resolution_id(payload)

    with pytest.raises(ValueError):
        resolution_module.IFEMLocalUseResolutionV1.model_validate(payload)


def test_rehashed_source_scope_and_metadata_injection_is_rejected() -> None:
    resolution = _resolution()
    payload = resolution.model_dump(mode="json")
    source_payload = cast(dict[str, object], payload["source"])
    cast(dict[str, object], source_payload["metadata"])["source_text"] = (
        "REAL TEXT SHOULD NOT BE HERE"
    )
    forged_source = SourceRecordV1.model_validate(source_payload)
    payload["source_record_sha256"] = digest_model(
        HashKindV1.SOURCE_RECORD,
        forged_source,
    ).value
    _rebind_resolution_id(payload)

    with pytest.raises(ValueError, match="metadata must match"):
        resolution_module.IFEMLocalUseResolutionV1.model_validate(payload)


def test_model_construct_cannot_bypass_renderer_or_current_input_verifier() -> None:
    resolution = _resolution()
    payload = resolution.model_dump(mode="python")
    payload["coarse_plan_content_sha256"] = "f" * 64
    unsafe = resolution_module.IFEMLocalUseResolutionV1.model_construct(**payload)

    with pytest.raises(resolution_module.IFEMLocalUseResolutionError):
        resolution_module.render_ifem_local_use_resolution(unsafe)
    with pytest.raises(resolution_module.IFEMLocalUseResolutionError):
        resolution_module.verify_ifem_local_use_resolution_against_current_inputs(
            unsafe,
            coarse_plan=_plan(),
            pending_request=_request(),
            source=_source(_plan()),
        )


def test_current_input_verifier_rejects_a_different_source_record() -> None:
    resolution = _resolution()
    plan = _plan()
    source_payload = _source(plan).model_dump(mode="json")
    source_payload["retrieved_at"] = "2026-07-30T00:00:00Z"
    other_source = SourceRecordV1.model_validate(source_payload)

    with pytest.raises(
        resolution_module.IFEMLocalUseResolutionError,
        match="differs from the supplied current inputs",
    ):
        resolution_module.verify_ifem_local_use_resolution_against_current_inputs(
            resolution,
            coarse_plan=plan,
            pending_request=_request(),
            source=other_source,
        )


def test_candidate_hashes_bind_exact_typed_inputs() -> None:
    resolution = _resolution()

    assert resolution.coarse_plan_content_sha256 == resolution.coarse_plan.content_sha256
    assert resolution.pending_request_id == resolution.pending_request.request_id
    assert resolution.pending_request_content_sha256 == resolution.pending_request.content_sha256
    assert (
        resolution.source_record_sha256
        == digest_model(
            HashKindV1.SOURCE_RECORD,
            resolution.source,
        ).value
    )
    assert (
        resolution.rights_claim_sha256
        == digest_model(
            HashKindV1.RIGHTS_RECORD,
            resolution.unverified_rights_claim,
        ).value
    )


def test_pending_request_alone_cannot_be_used_as_a_candidate() -> None:
    request = _request()

    with pytest.raises((TypeError, ValueError)):
        resolution_module.IFEMLocalUseResolutionV1.model_validate(request.model_dump(mode="json"))


def test_module_has_no_provider_network_prover_execution_or_attestation_import() -> None:
    module_path = Path(resolution_module.__file__)
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    imported_roots = {
        alias.name.split(".", 1)[0]
        for statement in ast.walk(tree)
        if isinstance(statement, ast.Import)
        for alias in statement.names
    }
    imported_roots.update(
        statement.module.split(".", 1)[0]
        for statement in ast.walk(tree)
        if isinstance(statement, ast.ImportFrom) and statement.module is not None
    )

    assert not imported_roots.intersection(
        {
            "Prover",
            "attestation",
            "benchmarks",
            "http",
            "httpx",
            "openai",
            "requests",
            "socket",
            "urllib",
        }
    )
