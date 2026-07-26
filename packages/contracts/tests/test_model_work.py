from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from autolean_contracts import (
    DigestV1,
    EndpointClassV1,
    HashKindV1,
    ModelWorkBundleV2,
    ModelWorkRoleV1,
    PermissionDecisionV1,
    RightsRecordV1,
    SourceRecordV1,
    SourceSpanV1,
    digest_text,
    model_work_admission_evidence_identity,
    model_work_admission_payload,
    model_work_bundle_id,
    model_work_case_contract_hash,
    model_work_case_hash,
    model_work_cell_contract_hash,
    model_work_cell_hash,
    model_work_contract_id,
    model_work_item_hash,
    model_work_rights_binding,
    model_work_run_hash,
    model_work_source_binding,
    stable_identifier,
)


def _source(name: str = "source", *, egress: str = "answer-free egress") -> SourceRecordV1:
    return SourceRecordV1(
        source_id=stable_identifier("model-work-source", name),
        work_id=f"synthetic-{name}",
        title="Synthetic model-work calibration",
        version="1",
        locator="repo://benchmarks/roles/calibration-pairs.v3.json",
        content_hash=digest_text(HashKindV1.SOURCE_BYTES, name),
        spans=(
            SourceSpanV1(
                span_id=stable_identifier("model-work-source-span", name),
                locator=f"answer-free-egress:{name}",
                content_hash=digest_text(HashKindV1.SOURCE_SPAN, egress),
            ),
        ),
    )


def _rights(source: SourceRecordV1) -> RightsRecordV1:
    return RightsRecordV1(
        rights_id=stable_identifier("model-work-rights", source.work_id),
        source_id=source.source_id,
        source_license="CC0-1.0",
        overall_decision=PermissionDecisionV1.ALLOW,
        model_egress=PermissionDecisionV1.ALLOW,
        allowed_endpoint_classes=(EndpointClassV1.APPROVED_EXTERNAL,),
        reviewed_by="test-operator",
        reviewed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _bundle(
    *,
    source_record: SourceRecordV1 | None = None,
    rights_record: RightsRecordV1 | None = None,
) -> ModelWorkBundleV2:
    source = source_record or _source()
    rights = rights_record or _rights(source)
    run_hash = model_work_run_hash("run.1")
    cell_hash = model_work_cell_hash("cell.1")
    case_hash = model_work_case_hash("case.1")
    cell_contract_hash = model_work_cell_contract_hash("1" * 64)
    case_contract_hash = model_work_case_contract_hash("2" * 64)
    return ModelWorkBundleV2(
        bundle_id=model_work_bundle_id(
            run_hash=run_hash,
            cell_hash=cell_hash,
            case_hash=case_hash,
            repetition=1,
            role=ModelWorkRoleV1.PROVER,
        ),
        work_contract_id=model_work_contract_id(
            cell_contract_hash=cell_contract_hash,
            case_contract_hash=case_contract_hash,
        ),
        run_hash=run_hash,
        cell_hash=cell_hash,
        case_hash=case_hash,
        repetition=1,
        role=ModelWorkRoleV1.PROVER,
        cell_contract_hash=cell_contract_hash,
        case_contract_hash=case_contract_hash,
        work_item_hash=model_work_item_hash("3" * 64),
        role_environment_hash=digest_text(HashKindV1.ENVIRONMENT, "role-env"),
        egress_content_hash=source.spans[0].content_hash,
        context_pack_hash=digest_text(HashKindV1.PROMPT, "context"),
        request_hash=digest_text(HashKindV1.PROMPT, "request"),
        source=model_work_source_binding(source),
        rights=model_work_rights_binding(rights),
    )


def _replace_trial_binding(
    bundle: ModelWorkBundleV2,
    *,
    field: str,
    replacement: object,
) -> ModelWorkBundleV2:
    update = {field: replacement}
    if field in {"run_hash", "cell_hash", "case_hash", "repetition", "role"}:
        run_hash = replacement if field == "run_hash" else bundle.run_hash
        cell_hash = replacement if field == "cell_hash" else bundle.cell_hash
        case_hash = replacement if field == "case_hash" else bundle.case_hash
        repetition = replacement if field == "repetition" else bundle.repetition
        role = replacement if field == "role" else bundle.role
        assert isinstance(run_hash, DigestV1)
        assert isinstance(cell_hash, DigestV1)
        assert isinstance(case_hash, DigestV1)
        assert isinstance(repetition, int)
        assert isinstance(role, ModelWorkRoleV1)
        update["bundle_id"] = model_work_bundle_id(
            run_hash=run_hash,
            cell_hash=cell_hash,
            case_hash=case_hash,
            repetition=repetition,
            role=role,
        )
    return bundle.model_copy(update=update)


def test_model_work_binds_exactly_one_role_trial_and_distinct_hash_domains() -> None:
    bundle = _bundle()

    assert bundle.revision == 2
    assert bundle.native_tools_enabled is False
    assert bundle.retrieval_enabled is False
    assert bundle.semantic_hash().kind is HashKindV1.CONTRACT
    assert bundle.handoff_hash().kind is HashKindV1.BUNDLE
    assert bundle.semantic_hash() != bundle.handoff_hash()


def test_model_work_helpers_domain_separate_identical_inputs() -> None:
    coordinate = "same-low-entropy-coordinate"
    coordinate_values = {
        model_work_run_hash(coordinate).value,
        model_work_cell_hash(coordinate).value,
        model_work_case_hash(coordinate).value,
    }
    assert len(coordinate_values) == 3

    upstream_sha256 = "a" * 64
    upstream_values = {
        model_work_cell_contract_hash(upstream_sha256).value,
        model_work_case_contract_hash(upstream_sha256).value,
        model_work_item_hash(upstream_sha256).value,
    }
    assert len(upstream_values) == 3


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("role", ModelWorkRoleV1.FIDELITY_REVIEWER),
        ("request_hash", digest_text(HashKindV1.PROMPT, "different request")),
        ("context_pack_hash", digest_text(HashKindV1.PROMPT, "different context")),
        ("role_environment_hash", digest_text(HashKindV1.ENVIRONMENT, "different env")),
    ],
)
def test_model_work_admission_payload_binds_the_complete_immutable_bundle(
    field: str,
    replacement: object,
) -> None:
    original = _bundle()
    changed = _replace_trial_binding(original, field=field, replacement=replacement)

    payload = model_work_admission_payload(original)
    changed_payload = model_work_admission_payload(changed)

    assert payload["bundle"] == original.model_dump(mode="json", exclude_none=False)
    assert payload["bundle_hash"] == original.handoff_hash().model_dump(mode="json")
    assert payload != changed_payload


def test_model_work_admission_payload_binds_exact_source_and_rights_records() -> None:
    source = _source()
    rights = _rights(source)
    original = _bundle(source_record=source, rights_record=rights)
    changed_source = _bundle(
        source_record=source.model_copy(update={"title": "Changed source provenance"}),
        rights_record=rights,
    )
    changed_rights = _bundle(
        source_record=source,
        rights_record=rights.model_copy(update={"attribution": "Changed rights provenance"}),
    )

    payload = model_work_admission_payload(original)
    assert payload != model_work_admission_payload(changed_source)
    assert payload != model_work_admission_payload(changed_rights)
    assert changed_source.source.source_record_hash != original.source.source_record_hash
    assert changed_rights.rights.rights_record_hash != original.rights.rights_record_hash


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("role", ModelWorkRoleV1.FIDELITY_REVIEWER),
        ("case_hash", model_work_case_hash("case.replaced")),
        ("work_item_hash", model_work_item_hash("4" * 64)),
        ("request_hash", digest_text(HashKindV1.PROMPT, "replaced prompt")),
        ("role_environment_hash", digest_text(HashKindV1.ENVIRONMENT, "replaced env")),
    ],
)
def test_model_work_trial_binding_changes_its_contract_hash(
    field: str,
    replacement: object,
) -> None:
    original = _bundle()
    changed = _replace_trial_binding(original, field=field, replacement=replacement)

    assert changed.semantic_hash() != original.semantic_hash()
    assert changed.handoff_hash() != original.handoff_hash()


def test_model_work_requires_its_single_rights_record_to_match_source() -> None:
    original = _bundle()
    other_source = _source("other")

    with pytest.raises(ValidationError, match="single source"):
        ModelWorkBundleV2.model_validate(
            {
                **original.model_dump(mode="json"),
                "rights": model_work_rights_binding(_rights(other_source)).model_dump(mode="json"),
            }
        )


def test_model_work_egress_must_match_an_explicit_redacted_source_span() -> None:
    original = _bundle()

    with pytest.raises(ValidationError, match="explicit source span"):
        ModelWorkBundleV2.model_validate(
            {
                **original.model_dump(mode="json"),
                "egress_content_hash": digest_text(
                    HashKindV1.SOURCE_SPAN,
                    "unrelated permissive content",
                ).model_dump(mode="json"),
            }
        )


def test_model_work_rejects_nested_prompt_canary_in_source_metadata() -> None:
    original = _bundle().model_dump(mode="json")
    source = original["source"]
    assert isinstance(source, dict)
    source["metadata"] = {
        "nested": {
            "system_prompt": "MODEL-WORK-PRIVATE-PROMPT-CANARY",
            "source_excerpt": "MODEL-WORK-PRIVATE-SOURCE-CANARY",
        }
    }

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ModelWorkBundleV2.model_validate(
            {
                **original,
                "source": source,
            }
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("title", "MODEL-WORK-PRIVATE-PROMPT-CANARY"),
        ("locator", "MODEL-WORK-PRIVATE-PROMPT-CANARY"),
        ("snapshot_ref", "MODEL-WORK-PRIVATE-PROMPT-CANARY"),
    ],
)
def test_model_work_source_projection_has_no_free_text_channel(
    field: str,
    value: str,
) -> None:
    payload = _bundle().model_dump(mode="json")
    source = payload["source"]
    assert isinstance(source, dict)
    source[field] = value

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ModelWorkBundleV2.model_validate(payload)


@pytest.mark.parametrize("field", ["attribution", "restrictions", "reviewed_by"])
def test_model_work_rights_projection_has_no_free_text_channel(field: str) -> None:
    payload = _bundle().model_dump(mode="json")
    rights = payload["rights"]
    assert isinstance(rights, dict)
    rights[field] = "MODEL-WORK-PRIVATE-PROMPT-CANARY"

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ModelWorkBundleV2.model_validate(payload)


def test_model_work_v2_projection_removes_normal_path_coordinate_and_identifier_text() -> None:
    marker = "model-work-private-canary"
    source = _source(marker)
    rights = _rights(source).model_copy(update={"source_license": marker})
    run_hash = model_work_run_hash(marker)
    cell_hash = model_work_cell_hash(marker)
    case_hash = model_work_case_hash(marker)
    cell_contract_hash = model_work_cell_contract_hash(marker.encode().hex().ljust(64, "0"))
    case_contract_hash = model_work_case_contract_hash("2" * 64)
    bundle = ModelWorkBundleV2(
        bundle_id=model_work_bundle_id(
            run_hash=run_hash,
            cell_hash=cell_hash,
            case_hash=case_hash,
            repetition=1,
            role=ModelWorkRoleV1.PROVER,
        ),
        work_contract_id=model_work_contract_id(
            cell_contract_hash=cell_contract_hash,
            case_contract_hash=case_contract_hash,
        ),
        run_hash=run_hash,
        cell_hash=cell_hash,
        case_hash=case_hash,
        repetition=1,
        role=ModelWorkRoleV1.PROVER,
        cell_contract_hash=cell_contract_hash,
        case_contract_hash=case_contract_hash,
        work_item_hash=model_work_item_hash("3" * 64),
        role_environment_hash=digest_text(HashKindV1.ENVIRONMENT, "role-env"),
        egress_content_hash=source.spans[0].content_hash,
        context_pack_hash=digest_text(HashKindV1.PROMPT, "context"),
        request_hash=digest_text(HashKindV1.PROMPT, "request"),
        source=model_work_source_binding(source),
        rights=model_work_rights_binding(rights),
    )

    serialized = bundle.model_dump_json()
    assert marker not in serialized
    assert "source_license" not in serialized
    assert '"source_id"' not in serialized
    assert '"span_id"' not in serialized
    assert model_work_admission_evidence_identity(bundle).startswith("model-work-admission:")


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        (
            "bundle_id",
            stable_identifier("model-work-bundle", "caller-selected-unrelated-id"),
        ),
        (
            "work_contract_id",
            stable_identifier("model-work-contract", "caller-selected-unrelated-id"),
        ),
    ],
)
def test_model_work_v2_requires_exact_system_derived_identifiers(
    field: str,
    replacement: object,
) -> None:
    payload = _bundle().model_dump(mode="json")
    payload[field] = replacement

    with pytest.raises(ValidationError, match="identifier must be derived"):
        ModelWorkBundleV2.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("native_tools_enabled", True),
        ("retrieval_enabled", True),
    ],
)
def test_model_work_v2_cannot_enable_tools_or_retrieval(field: str, value: bool) -> None:
    with pytest.raises(ValidationError):
        ModelWorkBundleV2.model_validate(
            {
                **_bundle().model_dump(mode="json"),
                field: value,
            }
        )
