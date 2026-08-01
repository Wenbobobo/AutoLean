"""Focused tests for the provider-neutral iFEM synthetic-role bridge."""

from __future__ import annotations

from typing import Any, cast

import pytest
from autolean_contracts import HashKindV1, canonical_json_bytes, digest_bytes, digest_text
from autolean_contracts.outbound_request import outbound_request_body_binding

from benchmarks.ifem_synthetic_role_bridge import (
    IFEMSyntheticRoleBridgeError,
    IFEMSyntheticRoleFakeExecutor,
    IFEMSyntheticRoleModelOutputV1,
    IFEMSyntheticRolePredictionV1,
    IFEMSyntheticRoleReceiptV1,
    evaluate,
    execute,
    ifem_synthetic_role_system_prompt,
    prepare,
    receipt,
    render_receipt,
)
from benchmarks.ifem_synthetic_role_fixture import (
    IFEMSyntheticRoleOptionV1,
    IFEMSyntheticRolePrivateOracleV1,
    IFEMSyntheticRolePublicFixtureV1,
    build_ifem_synthetic_role_fixture,
    build_ifem_synthetic_role_oracle,
)
from benchmarks.tests.test_ifem_synthetic_role_fixture import _corpus


def _inputs() -> tuple[IFEMSyntheticRolePublicFixtureV1, IFEMSyntheticRolePrivateOracleV1]:
    corpus = _corpus()
    return (
        build_ifem_synthetic_role_fixture(corpus, operator_seed="bridge-seed"),
        build_ifem_synthetic_role_oracle(corpus, operator_seed="bridge-seed"),
    )


def test_prepare_binds_exact_body_without_private_fields() -> None:
    fixture, _oracle = _inputs()
    executor = IFEMSyntheticRoleFakeExecutor(["option_a"])

    prepared = prepare(fixture, fixture.cases[0].case_id, executor)

    assert prepared.fixture_content_sha256 == fixture.content_sha256
    assert prepared.body_binding == outbound_request_body_binding(prepared.body)
    assert prepared.body_binding.body_hash.kind is HashKindV1.OUTBOUND_REQUEST_BODY
    assert prepared.body_binding.body_size_bytes == len(prepared.body)
    assert fixture.cases[0].prompt.encode().replace(b"\n", b"\\n") in prepared.body
    assert b"private-oracle" not in prepared.body
    assert b"Authorization" not in prepared.body


def test_execute_reuses_exact_body_and_receipt_is_digest_only() -> None:
    fixture, oracle = _inputs()
    response_text = '{"selected_option":"option_a","reason":"private output"}'
    executor = IFEMSyntheticRoleFakeExecutor([response_text])

    prepared = prepare(fixture, fixture.cases[0].case_id, executor)
    execution = execute(prepared, executor)
    public_receipt = receipt(execution)
    serialized = render_receipt(public_receipt)

    assert executor.bodies == (prepared.body,)
    assert response_text not in repr(execution.output)
    assert "synthetic-fake-response-1" not in repr(execution.output)
    assert public_receipt.request_body_binding == prepared.body_binding
    public_payload = public_receipt.model_dump(mode="json")
    assert "output_digest" not in public_payload
    assert "response_id_digest" not in public_payload
    assert fixture.cases[0].prompt.encode() not in serialized
    assert response_text.encode() not in serialized
    assert b"private output" not in serialized
    raw_output_digest = digest_text(HashKindV1.MODEL_OUTPUT_COMMITMENT, response_text).value
    raw_response_id_digest = digest_text(
        HashKindV1.MODEL_OUTPUT_COMMITMENT,
        "synthetic-fake-response-1",
    ).value
    assert raw_output_digest.encode("ascii") not in serialized
    assert raw_response_id_digest.encode("ascii") not in serialized
    assert b"private-oracle" not in serialized
    assert b"oracle" not in serialized.lower()
    assert public_receipt.authority.benchmark_authority is False
    assert public_receipt.authority.freeze_allowed is False
    assert public_receipt.authority.prover_handoff_allowed is False
    assert public_receipt.authority.promotion_allowed is False
    assert public_receipt.is_promotable is False

    result = evaluate(execution, oracle, fixture=fixture)
    assert result.predicted_option is IFEMSyntheticRolePredictionV1.OPTION_A
    assert result.expected_option in set(IFEMSyntheticRoleOptionV1)
    assert isinstance(public_receipt, IFEMSyntheticRoleReceiptV1)


def test_prepare_uses_fixed_role_system_prompt_and_rejects_drift() -> None:
    fixture, _oracle = _inputs()
    case = fixture.cases[0]
    executor = IFEMSyntheticRoleFakeExecutor(["option_a"])
    prepared = prepare(fixture, case.case_id, executor)
    assert prepared.request.system_prompt == ifem_synthetic_role_system_prompt(case.role)
    with pytest.raises(IFEMSyntheticRoleBridgeError, match="system prompt"):
        prepare(
            fixture,
            case.case_id,
            executor,
            system_prompt="operator supplied private oracle prompt",
        )
    with pytest.raises(IFEMSyntheticRoleBridgeError, match="JSON response"):
        prepare(fixture, case.case_id, executor, response_format=None)


def test_evaluate_is_private_oracle_join_and_malformed_output_abstains() -> None:
    fixture, oracle = _inputs()
    executor = IFEMSyntheticRoleFakeExecutor(["not-json"])
    execution = execute(prepare(fixture, fixture.cases[1].case_id, executor), executor)

    result = evaluate(execution, oracle, fixture=fixture)

    assert result.predicted_option is IFEMSyntheticRolePredictionV1.ABSTAIN
    assert result.parse_error is True
    assert result.correct is False


def test_evaluate_rejects_a_fixture_rebound_after_preparation() -> None:
    fixture, oracle = _inputs()
    other_fixture = build_ifem_synthetic_role_fixture(_corpus(), operator_seed="other-seed")
    executor = IFEMSyntheticRoleFakeExecutor(["option_a"])
    execution = execute(prepare(fixture, fixture.cases[0].case_id, executor), executor)

    with pytest.raises(IFEMSyntheticRoleBridgeError, match="differs from preparation"):
        evaluate(execution, oracle, fixture=other_fixture)


def test_execute_rejects_an_executor_acknowledging_different_body() -> None:
    fixture, _oracle = _inputs()
    executor = IFEMSyntheticRoleFakeExecutor(["option_a"])
    prepared = prepare(fixture, fixture.cases[0].case_id, executor)

    class WrongAckExecutor(IFEMSyntheticRoleFakeExecutor):
        def execute_prepared(self, *, request, body, binding):  # type: ignore[no-untyped-def]
            wrong = digest_bytes(HashKindV1.OUTBOUND_REQUEST_BODY, body + b"x")
            return IFEMSyntheticRoleModelOutputV1(
                text="option_a",
                body_binding=type(binding)(body_hash=wrong, body_size_bytes=len(body) + 1),
                provider_id=self.provider_id,
                model_id=self.model_id,
            )

    wrong_executor = WrongAckExecutor(["option_a"])
    with pytest.raises(IFEMSyntheticRoleBridgeError, match="acknowledge"):
        execute(prepared, wrong_executor)


def test_prepare_rejects_private_body_fields_and_receipt_tampering() -> None:
    fixture, _oracle = _inputs()
    executor = IFEMSyntheticRoleFakeExecutor(["option_a"])

    class PrivateBodyExecutor(IFEMSyntheticRoleFakeExecutor):
        def prepare_request_body(self, request):  # type: ignore[no-untyped-def]
            prepared = super().prepare_request_body(request)
            payload = {"prompt": request.prompt, "private_oracle": "hidden"}
            body = canonical_json_bytes(payload)
            return type(prepared)(
                body=body,
                binding=type(prepared.binding)(
                    body_hash=digest_bytes(HashKindV1.OUTBOUND_REQUEST_BODY, body),
                    body_size_bytes=len(body),
                ),
            )

    with pytest.raises(IFEMSyntheticRoleBridgeError, match="private"):
        prepare(fixture, fixture.cases[0].case_id, PrivateBodyExecutor(["option_a"]))

    execution = execute(prepare(fixture, fixture.cases[0].case_id, executor), executor)
    valid = receipt(execution)
    payload = valid.model_dump(mode="python")
    payload["role"] = valid.role
    payload["content_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="content hash"):
        cast(Any, type(valid)).model_construct(**payload)


def test_public_receipt_is_reproducible_and_intentionally_output_independent() -> None:
    fixture, _oracle = _inputs()
    first_executor = IFEMSyntheticRoleFakeExecutor(["option_a"])
    second_executor = IFEMSyntheticRoleFakeExecutor(["option_b"])
    first = receipt(
        execute(prepare(fixture, fixture.cases[0].case_id, first_executor), first_executor)
    )
    second = receipt(
        execute(prepare(fixture, fixture.cases[0].case_id, second_executor), second_executor)
    )

    assert first == second
    assert first.content_sha256 == first.computed_content_sha256()
