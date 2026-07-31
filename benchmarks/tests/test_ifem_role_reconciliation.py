"""Tests for private-input iFEM role reconciliation."""

from __future__ import annotations

import hashlib
from typing import Any, cast

import pytest
from autolean_contracts import (
    HashKindV1,
    canonical_json_bytes,
    digest_bytes,
    digest_model,
    digest_text,
)

from benchmarks.ifem_role_reconciliation import (
    IFEMRoleReconciliationError,
    build_ifem_role_reconciliation,
    render_ifem_role_reconciliation_report,
)
from benchmarks.ifem_synthetic_role_bridge import (
    IFEMSyntheticRoleFakeExecutor,
    IFEMSyntheticRoleReceiptV1,
    execute,
    prepare,
    receipt,
)
from benchmarks.ifem_synthetic_role_fixture import (
    build_ifem_synthetic_role_fixture,
    build_ifem_synthetic_role_oracle,
)
from benchmarks.tests.test_ifem_synthetic_role_fixture import _corpus


def _inputs() -> tuple[Any, Any, Any]:
    corpus = _corpus()
    seed = b"reconciliation-seed"
    return (
        build_ifem_synthetic_role_fixture(corpus, operator_seed=seed),
        build_ifem_synthetic_role_oracle(corpus, operator_seed=seed),
        corpus,
    )


def _receipts(fixture: Any) -> tuple[IFEMSyntheticRoleReceiptV1, ...]:
    result: list[IFEMSyntheticRoleReceiptV1] = []
    for case in fixture.cases:
        executor = IFEMSyntheticRoleFakeExecutor(["option_a"])
        prepared = prepare(fixture, case.case_id, executor)
        result.append(receipt(execute(prepared, executor)))
    return tuple(result)


def test_reconciliation_rebuilds_private_inputs_and_counts_roles() -> None:
    fixture, oracle, corpus = _inputs()
    receipts = _receipts(fixture)
    preparation_executor = IFEMSyntheticRoleFakeExecutor(["option_a"])
    report = build_ifem_role_reconciliation(
        fixture,
        oracle,
        corpus,
        operator_seed=b"reconciliation-seed",
        receipts=receipts,
        preparation_executor=preparation_executor,
    )

    assert report.case_count == 16
    assert report.role_counts == {
        "statement_formalizer": 8,
        "fidelity_reviewer": 4,
        "cheating_supervisor": 4,
    }
    assert report.oracle_case_match_count == 16
    assert report.receipt_count == 16
    assert report.receipt_case_match_count == 16
    assert report.receipt_role_match_count == 16
    assert report.receipt_body_binding_count == 16
    assert report.authority.private_rebuild_verified is True
    assert report.authority.benchmark_authority is False
    rendered = render_ifem_role_reconciliation_report(
        report,
        fixture=fixture,
        oracle=oracle,
        corpus=corpus,
        operator_seed=b"reconciliation-seed",
        receipts=receipts,
        preparation_executor=preparation_executor,
    )
    assert b"baseline_option" not in rendered
    assert b"pair_sha256" not in rendered
    assert b"reconciliation-seed" not in rendered
    assert b"oracle_digest" not in rendered
    raw_oracle_digest = digest_model(
        HashKindV1.VERIFICATION_EVIDENCE,
        oracle.model_dump(mode="json"),
    ).value
    assert raw_oracle_digest.encode("ascii") not in rendered


def test_reconciliation_rejects_legal_clause_rehash_tamper() -> None:
    fixture, oracle, corpus = _inputs()
    payload = fixture.model_dump(mode="json")
    cases = cast(list[object], payload["cases"])
    first = cast(dict[str, object], cases[0])
    prompt = cast(str, first["prompt"])
    changed_prompt = prompt.replace(
        "The scalar c is strictly positive (c > 0).",
        "The scalar c is allowed to be nonnegative (c >= 0).",
        1,
    )
    assert changed_prompt != prompt
    first["prompt"] = changed_prompt
    source = cast(dict[str, object], first["source"])
    source_bytes = changed_prompt.encode("utf-8")
    source["content_hash"] = digest_bytes(HashKindV1.SOURCE_BYTES, source_bytes).model_dump(
        mode="json"
    )
    span = cast(dict[str, object], cast(list[object], source["spans"])[0])
    span["permitted_excerpt"] = changed_prompt
    span["end_offset"] = len(source_bytes)
    span["content_hash"] = digest_text(HashKindV1.SOURCE_SPAN, changed_prompt).model_dump(
        mode="json"
    )
    first["content_sha256"] = hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in first.items() if key != "content_sha256"}
        )
    ).hexdigest()
    payload["content_sha256"] = hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in payload.items() if key != "content_sha256"}
        )
    ).hexdigest()
    tampered = type(fixture).model_validate(payload)
    with pytest.raises(IFEMRoleReconciliationError, match="private corpus/seed rebuild"):
        build_ifem_role_reconciliation(
            tampered,
            oracle,
            corpus,
            operator_seed=b"reconciliation-seed",
        )


def test_renderer_rejects_self_hashed_forged_report() -> None:
    fixture, oracle, corpus = _inputs()
    report = build_ifem_role_reconciliation(
        fixture,
        oracle,
        corpus,
        operator_seed=b"reconciliation-seed",
    )
    payload = report.model_dump(mode="json")
    payload["receipt_count"] = 1
    payload["receipt_case_match_count"] = 1
    payload["receipt_role_match_count"] = 1
    payload["receipt_body_binding_count"] = 1
    payload["content_sha256"] = hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in payload.items() if key != "content_sha256"}
        )
    ).hexdigest()
    forged = type(report).model_validate(payload)
    with pytest.raises(IFEMRoleReconciliationError, match="does not match"):
        render_ifem_role_reconciliation_report(
            forged,
            fixture=fixture,
            oracle=oracle,
            corpus=corpus,
            operator_seed=b"reconciliation-seed",
        )


def test_reconciliation_rejects_receipt_from_another_fixture() -> None:
    fixture, oracle, corpus = _inputs()
    other = build_ifem_synthetic_role_fixture(corpus, operator_seed=b"other-seed")
    with pytest.raises(IFEMRoleReconciliationError, match="another fixture"):
        build_ifem_role_reconciliation(
            fixture,
            oracle,
            corpus,
            operator_seed=b"reconciliation-seed",
            receipts=_receipts(other)[:1],
            preparation_executor=IFEMSyntheticRoleFakeExecutor(["option_a"]),
        )


def test_reconciliation_rejects_self_hashed_request_binding_tamper() -> None:
    fixture, oracle, corpus = _inputs()
    valid = _receipts(fixture)[0]
    payload = valid.model_dump(mode="json")
    prompt_digest = cast(dict[str, object], payload["prompt_digest"])
    prompt_digest["value"] = "e" * 64
    request_binding = cast(dict[str, object], payload["request_body_binding"])
    body_digest = cast(dict[str, object], request_binding["body_hash"])
    body_digest["value"] = "f" * 64
    payload["content_sha256"] = hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in payload.items() if key != "content_sha256"}
        )
    ).hexdigest()
    forged = IFEMSyntheticRoleReceiptV1.model_validate(payload)

    with pytest.raises(IFEMRoleReconciliationError, match="rebuilt provider request"):
        build_ifem_role_reconciliation(
            fixture,
            oracle,
            corpus,
            operator_seed=b"reconciliation-seed",
            receipts=(forged,),
            preparation_executor=IFEMSyntheticRoleFakeExecutor(["option_a"]),
        )


def test_receipts_require_an_independent_preparation_executor() -> None:
    fixture, oracle, corpus = _inputs()
    with pytest.raises(IFEMRoleReconciliationError, match="preparation executor"):
        build_ifem_role_reconciliation(
            fixture,
            oracle,
            corpus,
            operator_seed=b"reconciliation-seed",
            receipts=_receipts(fixture)[:1],
        )
