"""Focused D33 private-evaluator aggregation and anti-forgery tests."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, cast

import pytest
from autolean_builder.ifem_structural_witness_validation import (
    validate_ifem_structural_witnesses,
)
from autolean_contracts import (
    HashKindV1,
    OutboundRequestBodyV1,
    canonical_json_bytes,
    digest_bytes,
    digest_text,
)
from autolean_prover.providers import (
    LocalPrivateModelOutputStore,
    ModelRequest,
    TokenUsage,
    ToolCall,
)

from benchmarks.ifem_private_evaluator import (
    IFEM_PRIVATE_EVALUATOR_PUBLIC_REPORT_FILENAME,
    IFEMPrivateEvaluatorError,
    evaluate_ifem_private_role_run,
    render_ifem_private_evaluator_public_report,
    write_ifem_private_evaluator_public_report,
)
from benchmarks.ifem_synthetic_role_bridge import (
    IFEMSyntheticRoleFakeExecutor,
    IFEMSyntheticRoleModelOutputV1,
    prepare,
)
from benchmarks.ifem_synthetic_role_fixture import (
    build_ifem_synthetic_role_fixture,
    build_ifem_synthetic_role_oracle,
)
from benchmarks.ifem_synthetic_role_private_ledger import (
    LocalIFEMSyntheticRolePrivateLedger,
    TestOnlyIFEMSyntheticRoleHmacAuthenticator,
)
from benchmarks.tests.test_ifem_synthetic_role_fixture import _corpus, _valid_graph

_HMAC_SECRET = b"iFEM D33 private evaluator test secret exceeds thirty-two bytes"
_SEED = b"D33 synthetic private evaluator seed"


class _UsageExecutor(IFEMSyntheticRoleFakeExecutor):
    """Deterministic fake output with distinct private per-case usage values."""

    def __init__(self, responses: list[str]) -> None:
        super().__init__(responses)
        self._usage_index = 0

    def execute_prepared(
        self,
        *,
        request: ModelRequest,
        body: bytes,
        binding: OutboundRequestBodyV1,
    ) -> IFEMSyntheticRoleModelOutputV1:
        output = super().execute_prepared(request=request, body=body, binding=binding)
        index = self._usage_index
        self._usage_index += 1
        return IFEMSyntheticRoleModelOutputV1(
            text=output.text,
            body_binding=output.body_binding,
            provider_id=output.provider_id,
            model_id=output.model_id,
            response_id=output.response_id,
            usage=TokenUsage(
                input_tokens=40 + index,
                cached_input_tokens=index % 4,
                output_tokens=10 + index,
            ),
            tool_calls=(
                (
                    ToolCall(
                        call_id="unexpected-private-tool-call",
                        name="unavailable_tool",
                        arguments_json="{}",
                    ),
                )
                if index == 6
                else ()
            ),
        )


def _ledger(root: Path) -> LocalIFEMSyntheticRolePrivateLedger:
    return LocalIFEMSyntheticRolePrivateLedger(
        root / "private-ledger",
        output_store=LocalPrivateModelOutputStore(root / "private-cas"),
        authenticator=TestOnlyIFEMSyntheticRoleHmacAuthenticator(_HMAC_SECRET),
    )


def _run(tmp_path: Path) -> tuple[Any, ...]:
    graph = _valid_graph()
    corpus = _corpus()
    fixture = build_ifem_synthetic_role_fixture(corpus, operator_seed=_SEED)
    oracle = build_ifem_synthetic_role_oracle(corpus, operator_seed=_SEED)
    expected_by_case = {item.public_case_id: item.baseline_option.value for item in oracle.records}
    responses = [
        f'{{"selected_option":"{expected_by_case[case.case_id]}"}}' for case in fixture.cases
    ]
    # These are intentionally rejected by D33 even though the legacy bridge parser is permissive.
    responses[1] = "option_a"
    responses[2] = '{"selected_option":"abstain"}'
    responses[3] = '{"selected_option":"option_a","selected_option":"option_b"}'
    responses[4] = '{"option":"option_a"}'
    expected = expected_by_case[fixture.cases[5].case_id]
    responses[5] = (
        '{"selected_option":"option_b"}'
        if expected == "option_a"
        else ('{"selected_option":"option_a"}')
    )

    executor = _UsageExecutor(responses)
    prepared = tuple(prepare(fixture, case.case_id, executor) for case in fixture.cases)
    ledger = _ledger(tmp_path)
    for request in prepared:
        ledger.execute_once(request, executor)
    ledger.commit_manifest(fixture, prepared)
    witness_report = validate_ifem_structural_witnesses(corpus=corpus, graph=graph)
    # This executor has the same fixed configuration but is never allowed to execute here.
    preparation_executor = IFEMSyntheticRoleFakeExecutor(["unused"])
    report = evaluate_ifem_private_role_run(
        fixture=fixture,
        oracle=oracle,
        corpus=corpus,
        graph=graph,
        witness_report=witness_report,
        operator_seed=_SEED,
        ledger=ledger,
        preparation_executor=preparation_executor,
    )
    return (
        report,
        fixture,
        oracle,
        corpus,
        graph,
        witness_report,
        ledger,
        preparation_executor,
        responses,
    )


def _render_inputs(run: tuple[Any, ...]) -> dict[str, Any]:
    (
        _report,
        fixture,
        oracle,
        corpus,
        graph,
        witness_report,
        ledger,
        preparation_executor,
        _responses,
    ) = run
    return {
        "fixture": fixture,
        "oracle": oracle,
        "corpus": corpus,
        "graph": graph,
        "witness_report": witness_report,
        "operator_seed": _SEED,
        "ledger": ledger,
        "preparation_executor": preparation_executor,
    }


def test_d33_strictly_parses_private_outputs_and_projects_safe_aggregates(tmp_path: Path) -> None:
    run = _run(tmp_path)
    report = run[0]
    rendered = render_ifem_private_evaluator_public_report(report, **_render_inputs(run))

    assert report.case_count == 16
    assert sum(item.correct_count for item in report.role_aggregates) == 10
    assert sum(item.incorrect_count for item in report.role_aggregates) == 1
    assert sum(item.abstention_count for item in report.role_aggregates) == 1
    assert sum(item.invalid_count for item in report.role_aggregates) == 4
    assert sum(item.case_count for item in report.risk_aggregates) == 16
    assert report.token_usage.input_tokens_total == 760
    assert report.token_usage.cached_input_tokens_total == 24
    assert report.token_usage.output_tokens_total == 280
    assert report.token_usage.input_tokens_bucket == "256_to_1023"
    assert report.token_usage.cached_input_tokens_bucket == "1_to_255"
    assert report.token_usage.output_tokens_bucket == "256_to_1023"
    assert report.private_rebuild_verified
    assert report.witness_validation_recomputed
    assert report.private_manifest_recovered
    assert report.schema_version == "autolean.ifem-private-evaluator-public-report.v1"
    assert report.protocol_binding is None
    assert not report.authority.semantic_equivalence_claimed
    assert not report.authority.benchmark_authority
    assert not report.authority.freeze_allowed
    assert not report.authority.prover_handoff_allowed
    assert not report.authority.promotion_allowed
    assert not report.is_promotable
    assert (
        rendered == canonical_json_bytes(report.model_dump(mode="json", exclude_none=True)) + b"\n"
    )
    for marker in (
        b"baseline_option",
        b"expected_option",
        b"predicted_option",
        b'"oracle":',
        b'"operator_seed":',
        b'"response_id":',
        b"artifact",
        b"output_commitment",
        _SEED,
    ):
        assert marker not in rendered.lower()
    for raw in cast(list[str], run[-1]):
        assert raw.encode("utf-8") not in rendered


def test_d33_renderer_rejects_self_hashed_forgery_and_writer_rebuilds(tmp_path: Path) -> None:
    run = _run(tmp_path)
    report = run[0]
    payload = report.model_dump(mode="json", exclude_none=True)
    usage = cast(dict[str, object], payload["token_usage"])
    usage["output_tokens_total"] = 0
    usage["output_tokens_bucket"] = "zero"
    payload["content_sha256"] = hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in payload.items() if key != "content_sha256"}
        )
    ).hexdigest()
    forged = type(report).model_validate(payload)
    with pytest.raises(
        IFEMPrivateEvaluatorError,
        match="differs from the private evaluator rebuild",
    ):
        render_ifem_private_evaluator_public_report(forged, **_render_inputs(run))

    public_root = tmp_path / "public"
    public_root.mkdir()
    output = public_root / IFEM_PRIVATE_EVALUATOR_PUBLIC_REPORT_FILENAME
    write_ifem_private_evaluator_public_report(
        cache_root=public_root,
        output_path=output,
        report=report,
        **_render_inputs(run),
    )
    assert (
        output.read_bytes()
        == canonical_json_bytes(report.model_dump(mode="json", exclude_none=True)) + b"\n"
    )
    with pytest.raises(IFEMPrivateEvaluatorError, match="stay below"):
        write_ifem_private_evaluator_public_report(
            cache_root=public_root,
            output_path=tmp_path / IFEM_PRIVATE_EVALUATOR_PUBLIC_REPORT_FILENAME,
            report=report,
            **_render_inputs(run),
        )


def test_d33_rejects_rehashed_fixture_drift_before_private_output_evaluation(
    tmp_path: Path,
) -> None:
    run = _run(tmp_path)
    fixture = run[1]
    payload = fixture.model_dump(mode="json")
    cases = cast(list[object], payload["cases"])
    first = cast(dict[str, object], cases[0])
    prompt = cast(str, first["prompt"])
    first["prompt"] = prompt.replace("neither option is privileged", "option A is preferred", 1)
    source = cast(dict[str, object], first["source"])
    span = cast(dict[str, object], cast(list[object], source["spans"])[0])
    changed = cast(str, first["prompt"])
    # This keeps the public fixture internally valid only where its own identity rules permit it;
    # the D33 corpus/seed rebuild remains the independent authority and rejects it.
    source_bytes = changed.encode("utf-8")
    source["content_hash"] = digest_bytes(HashKindV1.SOURCE_BYTES, source_bytes).model_dump(
        mode="json"
    )
    span["permitted_excerpt"] = changed
    span["end_offset"] = len(source_bytes)
    span["content_hash"] = digest_text(HashKindV1.SOURCE_SPAN, changed).model_dump(mode="json")
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
    inputs = _render_inputs(run)
    inputs["fixture"] = tampered
    with pytest.raises(IFEMPrivateEvaluatorError, match="private corpus/seed rebuild"):
        evaluate_ifem_private_role_run(**inputs)
