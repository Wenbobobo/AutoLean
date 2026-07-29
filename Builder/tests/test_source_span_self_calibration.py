from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

import pytest
from autolean_builder.local_calibration import (
    LocalCalibrationDifferenceKindV1,
    LocalCalibrationFixtureCorpusV1,
    PreCalibrationFixtureRecordV1,
)
from autolean_builder.source_span_self_calibration import (
    AdjudicatedCandidateFindingV1,
    CalibrationAdjudicationDispositionV1,
    CalibrationMutationAnchorV1,
    CalibrationMutationFamilyV1,
    QuantifierBoundaryCritiqueOutputV1,
    QuantifierBoundaryMutationV1,
    ReverseRenderFindingV1,
    ReverseRenderReviewOutputV1,
    ScriptedFakeSourceSpanCalibrationProvider,
    SourceSpanAdjudicationOutputV1,
    SourceSpanCalibrationRoleV1,
    SourceSpanConversionOutputV1,
    SourceSpanSelfCalibrationError,
    SourceSpanSelfCalibrationHarness,
    VerifiedSourceSpanCalibrationCorpus,
    build_scripted_fake_calibration_actor,
    build_source_span_calibration_input_binding,
    load_source_span_calibration_corpus,
    source_span_conversion_proposal_id,
)

_ROOT = Path(__file__).resolve().parents[2]
_CORPUS = (
    _ROOT / "Builder" / "pilots" / "local-calibration" / "project-synthetic-opening-corpus.v1.json"
)
_BOUNDARY_DIFFERENCE_KINDS = {
    LocalCalibrationDifferenceKindV1.DROP_NONEMPTY,
    LocalCalibrationDifferenceKindV1.DROP_REGULARITY,
    LocalCalibrationDifferenceKindV1.VACUITY,
    LocalCalibrationDifferenceKindV1.DROP_FINITE,
    LocalCalibrationDifferenceKindV1.DROP_NOETHERIAN,
}


def _corpus() -> VerifiedSourceSpanCalibrationCorpus:
    return load_source_span_calibration_corpus(_CORPUS)


def _samples() -> tuple[PreCalibrationFixtureRecordV1, ...]:
    return _corpus().corpus.samples


def _json(value: object) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _unique_candidate_fragment(
    statement: str,
    source_fragment: str,
    *,
    label: str,
) -> str:
    matches = tuple(re.finditer(re.escape(source_fragment), statement, flags=re.IGNORECASE))
    assert len(matches) == 1, f"{label} must occur once in the candidate statement"
    return matches[0].group(0)


def _fixture_boundary_anchor(
    sample: PreCalibrationFixtureRecordV1,
    statement: str,
    *,
    excluded_baseline: str,
) -> tuple[str, CalibrationMutationAnchorV1]:
    conclusion_matches = tuple(
        re.finditer(re.escape(sample.normalized.conclusion), statement, flags=re.IGNORECASE)
    )
    if len(conclusion_matches) == 1:
        conclusion = conclusion_matches[0].group(0)
        if conclusion.casefold() != excluded_baseline.casefold():
            return conclusion, CalibrationMutationAnchorV1.CONCLUSION
    for fixture in sample.mutation_fixtures:
        if fixture.difference_kind is LocalCalibrationDifferenceKindV1.QUANTIFIER_SWAP:
            continue
        if fixture.baseline_fragment.casefold() == excluded_baseline.casefold():
            continue
        matches = tuple(
            re.finditer(re.escape(fixture.baseline_fragment), statement, flags=re.IGNORECASE)
        )
        if len(matches) == 1:
            anchor = (
                CalibrationMutationAnchorV1.BOUNDARY_CONDITION
                if fixture.difference_kind in _BOUNDARY_DIFFERENCE_KINDS
                else CalibrationMutationAnchorV1.CONCLUSION
            )
            return matches[0].group(0), anchor
    raise AssertionError("a declared synthetic fixture boundary anchor must occur once")


def _conversion(
    sample: PreCalibrationFixtureRecordV1,
    *,
    suffix: str,
    added_assumption: str | None = None,
    reverse_quantifiers: bool = False,
) -> SourceSpanConversionOutputV1:
    assumptions = sample.normalized.assumptions
    if added_assumption is not None:
        assumptions = (*assumptions, added_assumption)
    return SourceSpanConversionOutputV1(
        normalized_statement=sample.normalized.normalized_statement,
        quantifiers=(
            tuple(reversed(sample.normalized.quantifiers))
            if reverse_quantifiers
            else sample.normalized.quantifiers
        ),
        assumptions=assumptions,
        conclusion=sample.normalized.conclusion,
        illustrative_lean_statement=(
            f"theorem calibration_{suffix} : SyntheticCalibrationClaim := by exact "
            f"syntheticCalibrationWitness_{suffix}"
        ),
        reverse_rendering=(
            "Independent synthetic reverse rendering preserving the fixture projection "
            f"through path {suffix}."
        ),
        ambiguities=tuple(item.description for item in sample.ambiguities),
        limitations=("Unparsed illustrative Lean text; no semantic or kernel claim.",),
    )


@dataclass(frozen=True)
class _RunParts:
    outputs: dict[str, str]
    proposal_ids: tuple[str, str]


def _run_parts(
    sample: PreCalibrationFixtureRecordV1,
    *,
    added_assumption: str | None = None,
    omit_boundary: bool = False,
    reverse_quantifiers: bool = False,
    unreplayable_mutation: bool = False,
    unapproved_boundary_anchor: bool = False,
    duplicate_mutation_baseline: bool = False,
) -> _RunParts:
    conversions = {
        "conversion-a": _conversion(sample, suffix="a"),
        "conversion-b": _conversion(
            sample,
            suffix="b",
            added_assumption=added_assumption,
            reverse_quantifiers=reverse_quantifiers,
        ),
    }
    binding = build_source_span_calibration_input_binding(
        _corpus(),
        sample_id=sample.sample_id,
    )
    proposal_output_by_id = {
        source_span_conversion_proposal_id(
            actor_id,
            output,
            binding.input_sha256,
        ): output
        for actor_id, output in conversions.items()
    }
    proposal_ids = tuple(sorted(proposal_output_by_id))
    reverse = ReverseRenderReviewOutputV1(
        findings=tuple(
            ReverseRenderFindingV1(
                proposal_id=proposal_id,
                source_equivalent=True,
                reconstructed_statement=(
                    "The source-bound candidate keeps its explicit quantifiers, assumptions, "
                    "and conclusion."
                ),
                assumption_drift=(),
                quantifier_drift=(),
                boundary_drift=(),
                rationale="Scripted fake review for deterministic harness verification.",
            )
            for proposal_id in proposal_ids
        ),
        unresolved_issues=(),
    )
    mutations = []
    for proposal_id in proposal_ids:
        proposal_output = proposal_output_by_id[proposal_id]
        normalized = proposal_output.normalized_statement
        quantifier = proposal_output.quantifiers[0]
        quantifier_baseline = _unique_candidate_fragment(
            normalized,
            quantifier,
            label="explicit candidate quantifier",
        )
        quantifier_replacement = f"{quantifier_baseline} with adversarial binder order"
        mutations.append(
            QuantifierBoundaryMutationV1(
                proposal_id=proposal_id,
                family=CalibrationMutationFamilyV1.QUANTIFIER,
                anchor=CalibrationMutationAnchorV1.QUANTIFIER,
                baseline_fragment=quantifier_baseline,
                replacement_fragment=quantifier_replacement,
                applied_statement=normalized.replace(
                    quantifier_baseline,
                    quantifier_replacement,
                    1,
                ),
                expected_semantic_failure="The witness may no longer depend on its parameter.",
                rationale="Adversarial quantifier probe.",
            )
        )
        if omit_boundary:
            second_replacement = f"{quantifier_baseline} with a second binder mutation"
            mutations.append(
                QuantifierBoundaryMutationV1(
                    proposal_id=proposal_id,
                    family=CalibrationMutationFamilyV1.QUANTIFIER,
                    anchor=CalibrationMutationAnchorV1.QUANTIFIER,
                    baseline_fragment=quantifier_baseline,
                    replacement_fragment=second_replacement,
                    applied_statement=normalized.replace(
                        quantifier_baseline,
                        second_replacement,
                        1,
                    ),
                    expected_semantic_failure="Boundary coverage is still absent.",
                    rationale="Duplicate-family probe used to test coverage rejection.",
                )
            )
        else:
            if unapproved_boundary_anchor:
                boundary_baseline = normalized
                boundary_anchor = CalibrationMutationAnchorV1.CONCLUSION
            elif duplicate_mutation_baseline:
                boundary_baseline = quantifier_baseline
                boundary_anchor = CalibrationMutationAnchorV1.CONCLUSION
            else:
                boundary_baseline, boundary_anchor = _fixture_boundary_anchor(
                    sample,
                    normalized,
                    excluded_baseline=quantifier_baseline,
                )
            boundary_replacement = f"weakened boundary replacing ({boundary_baseline})"
            mutations.append(
                QuantifierBoundaryMutationV1(
                    proposal_id=proposal_id,
                    family=CalibrationMutationFamilyV1.BOUNDARY,
                    anchor=boundary_anchor,
                    baseline_fragment=boundary_baseline,
                    replacement_fragment=boundary_replacement,
                    applied_statement=normalized.replace(
                        boundary_baseline,
                        boundary_replacement,
                        1,
                    ),
                    expected_semantic_failure="The source boundary condition is changed.",
                    rationale="Adversarial boundary probe.",
                )
            )
    mutation_critique = {
        "mutations": [item.model_dump(mode="json") for item in mutations],
        "unresolved_issues": [],
    }
    if unreplayable_mutation:
        first_mutation = mutation_critique["mutations"][0]
        first_mutation["baseline_fragment"] = "fragment absent from every proposal"
        first_mutation["replacement_fragment"] = "unrelated replacement"
        first_mutation["applied_statement"] = "unrelated mathematical text"
    adjudication = SourceSpanAdjudicationOutputV1(
        disposition=CalibrationAdjudicationDispositionV1.CONTINUE,
        candidate_findings=tuple(
            AdjudicatedCandidateFindingV1(
                proposal_id=proposal_id,
                suitable_for_next_builder_round=True,
                rationale="Retain as an advisory candidate for the next Builder round only.",
            )
            for proposal_id in proposal_ids
        ),
        preferred_proposal_id=proposal_ids[0],
        unresolved_issues=("Declared agent independence and semantic fidelity remain unverified.",),
    )
    return _RunParts(
        outputs={
            "conversion-a": _json(conversions["conversion-a"]),
            "conversion-b": _json(conversions["conversion-b"]),
            "reverse-reviewer": _json(reverse),
            "mutation-critic": _json(mutation_critique),
            "adjudicator": _json(adjudication),
        },
        proposal_ids=(proposal_ids[0], proposal_ids[1]),
    )


def _run(
    sample: PreCalibrationFixtureRecordV1,
    *,
    run_id: str = "source-span-calibration-run",
    added_assumption: str | None = None,
    omit_boundary: bool = False,
    reverse_quantifiers: bool = False,
    unreplayable_mutation: bool = False,
    unapproved_boundary_anchor: bool = False,
    duplicate_mutation_baseline: bool = False,
    output_tokens: int = 32,
    duplicate_independence: bool = False,
):
    parts = _run_parts(
        sample,
        added_assumption=added_assumption,
        omit_boundary=omit_boundary,
        reverse_quantifiers=reverse_quantifiers,
        unreplayable_mutation=unreplayable_mutation,
        unapproved_boundary_anchor=unapproved_boundary_anchor,
        duplicate_mutation_baseline=duplicate_mutation_baseline,
    )
    roles = {
        "conversion-a": SourceSpanCalibrationRoleV1.CONVERSION_PROPOSER,
        "conversion-b": SourceSpanCalibrationRoleV1.CONVERSION_PROPOSER,
        "reverse-reviewer": SourceSpanCalibrationRoleV1.REVERSE_RENDER_REVIEWER,
        "mutation-critic": SourceSpanCalibrationRoleV1.QUANTIFIER_BOUNDARY_CRITIC,
        "adjudicator": SourceSpanCalibrationRoleV1.ADJUDICATOR,
    }
    providers = {
        actor_id: ScriptedFakeSourceSpanCalibrationProvider(
            (response,),
            model_id=f"fake-{actor_id}",
            input_tokens=32,
            output_tokens=output_tokens,
        )
        for actor_id, response in parts.outputs.items()
    }
    actors = tuple(
        build_scripted_fake_calibration_actor(
            actor_id=actor_id,
            role=roles[actor_id],
            independence_group=(
                "shared-independence"
                if duplicate_independence and actor_id in {"conversion-a", "conversion-b"}
                else f"independence-{actor_id}"
            ),
            provider=providers[actor_id],
            max_output_tokens=1024,
        )
        for actor_id in reversed(tuple(roles))
    )
    return SourceSpanSelfCalibrationHarness().run(
        _corpus(),
        sample_id=sample.sample_id,
        run_id=run_id,
        actors=actors,
        providers=providers,
    )


@pytest.mark.parametrize("sample", _samples(), ids=lambda item: item.sample_id)
def test_all_eleven_project_synthetic_spans_complete_the_offline_fake_loop(
    sample: PreCalibrationFixtureRecordV1,
) -> None:
    result = _run(sample)

    assert len(result.proposals) == 2
    assert len(result.executions) == 5
    assert result.machine_advisory_continue is True
    assert result.input_binding.sample_id == sample.sample_id
    assert result.input_binding.source_text_retained is False
    assert result.statement_contract_present is False
    assert result.formalization_task_bundle_present is False
    assert all(item.actor.provider_id == "fake" for item in result.executions)
    assert all(item.actor.endpoint_class.value == "local" for item in result.executions)
    assert all(item.actor.max_output_tokens == 1024 for item in result.executions)
    assert all(item.execution_receipt_verified is False for item in result.executions)
    assert all(
        item.token_usage_assurance == "scripted_fake_declared_not_tokenized"
        for item in result.executions
    )
    assert all(item.authority.freeze_authority is False for item in result.executions)
    assert "MACHINE_ADVISORY_ONLY" in result.blockers
    assert sample.source_text not in _json(result)
    assert result.input_binding.corpus.sample_count == 11
    assert result.input_binding.corpus.corpus_sha256
    assert result.input_binding.corpus.release_manifest_sha256


def test_replay_has_stable_input_execution_and_result_hashes() -> None:
    sample = next(item for item in _samples() if item.sample_id == "mg-a-quantifier-order")

    first = _run(sample, run_id="stable-calibration-run")
    replay = _run(sample, run_id="stable-calibration-run")

    assert first.evidence_sha256 == replay.evidence_sha256
    assert first.input_binding.input_sha256 == replay.input_binding.input_sha256
    assert tuple(item.execution_sha256 for item in first.executions) == tuple(
        item.execution_sha256 for item in replay.executions
    )
    with pytest.raises(ValueError, match="evidence hash differs"):
        first.model_copy(update={"evidence_sha256": "f" * 64})
    with pytest.raises(ValueError, match="blockers differ"):
        first.model_copy(update={"blockers": ("MACHINE_ADVISORY_ONLY",)})
    with pytest.raises(ValueError, match="canonical order"):
        first.model_copy(update={"executions": tuple(reversed(first.executions))})
    with pytest.raises(ValueError, match="output-token budget"):
        first.executions[0].model_copy(
            update={"output_tokens": first.executions[0].actor.max_output_tokens + 1}
        )


def test_added_assumption_is_never_silent_or_promotable() -> None:
    sample = next(item for item in _samples() if item.sample_id == "mg-a-quantifier-order")
    result = _run(sample, added_assumption="the chosen curve is unique")

    changed = next(item for item in result.proposals if item.actor_id == "conversion-b")
    assert changed.structural_delta.added_assumptions == ("the chosen curve is unique",)
    assert changed.structural_delta.has_drift is True
    assert result.machine_advisory_continue is False
    assert "STRUCTURAL_DELTA_REQUIRES_REVIEW" in result.blockers
    with pytest.raises(SourceSpanSelfCalibrationError, match="cannot freeze"):
        result.freeze_statement()
    with pytest.raises(SourceSpanSelfCalibrationError, match="cannot create a Prover handoff"):
        result.handoff_to_prover()


def test_quantifier_order_change_is_explicit_even_when_statement_text_is_unchanged() -> None:
    sample = next(item for item in _samples() if item.sample_id == "mg-a-quantifier-order")
    result = _run(sample, reverse_quantifiers=True)

    changed = next(item for item in result.proposals if item.actor_id == "conversion-b")
    assert changed.structural_delta.added_quantifiers == ()
    assert changed.structural_delta.removed_quantifiers == ()
    assert changed.structural_delta.quantifier_sequence_changed is True
    assert changed.structural_delta.has_drift is True
    assert result.machine_advisory_continue is False
    assert "STRUCTURAL_DELTA_REQUIRES_REVIEW" in result.blockers


def test_reverse_reviewer_cannot_claim_equivalence_while_reporting_drift() -> None:
    with pytest.raises(ValueError, match="inverse of its structured drift"):
        ReverseRenderFindingV1(
            proposal_id="proposal-0123456789abcdefabcd",
            source_equivalent=True,
            reconstructed_statement="A purported reverse rendering.",
            assumption_drift=("omitted nonempty hypothesis",),
            quantifier_drift=(),
            boundary_drift=(),
            rationale="Contradictory scripted reviewer response.",
        )


def test_reverse_reviewer_must_encode_disagreement_as_structured_drift() -> None:
    with pytest.raises(ValueError, match="inverse of its structured drift"):
        ReverseRenderFindingV1(
            proposal_id="proposal-0123456789abcdefabcd",
            source_equivalent=False,
            reconstructed_statement="Prose claims that the candidate is not equivalent.",
            assumption_drift=(),
            quantifier_drift=(),
            boundary_drift=(),
            rationale="Unstructured disagreement must not become a machine signal.",
        )


def test_reverse_reviewer_prose_is_retained_but_not_machine_interpreted() -> None:
    finding = ReverseRenderFindingV1(
        proposal_id="proposal-0123456789abcdefabcd",
        source_equivalent=True,
        reconstructed_statement="This prose says NOT EQUIVALENT but has no structured drift.",
        assumption_drift=(),
        quantifier_drift=(),
        boundary_drift=(),
        rationale="Untrusted prose deliberately contains an adverse phrase.",
    )

    assert finding.has_structured_drift is False


def test_runtime_reverified_corpus_handle_rejects_unlisted_source_span() -> None:
    corpus = _corpus()

    with pytest.raises(SourceSpanSelfCalibrationError, match="absent from the verified"):
        corpus.sample("unlisted-source")
    with pytest.raises(SourceSpanSelfCalibrationError, match="absent from the verified"):
        build_source_span_calibration_input_binding(corpus, sample_id="unlisted-source")


def test_model_construct_forged_sample_cannot_enter_runtime_reverified_corpus() -> None:
    verified = _corpus()
    canonical = verified.corpus
    forged_sample_payload = canonical.samples[0].model_dump(mode="python")
    forged_sample_payload["sample_id"] = "forged-non-corpus-source"
    forged_sample = PreCalibrationFixtureRecordV1.model_construct(**forged_sample_payload)
    forged_corpus = LocalCalibrationFixtureCorpusV1.model_construct(
        **canonical.model_dump(exclude={"samples"}),
        samples=(forged_sample, *canonical.samples[1:]),
    )
    forged_handle = object.__new__(VerifiedSourceSpanCalibrationCorpus)
    object.__setattr__(forged_handle, "_path", _CORPUS.resolve())
    object.__setattr__(forged_handle, "_binding", verified.binding)

    with pytest.raises(AttributeError):
        object.__setattr__(forged_handle, "_corpus", forged_corpus)
    with pytest.raises(SourceSpanSelfCalibrationError, match="absent from the verified"):
        SourceSpanSelfCalibrationHarness().run(
            forged_handle,
            sample_id=forged_sample.sample_id,
            run_id="forged-corpus-run",
            actors=(),
            providers={},
        )


def test_runtime_reverification_rejects_forged_loader_binding() -> None:
    verified = _corpus()
    forged_handle = object.__new__(VerifiedSourceSpanCalibrationCorpus)
    object.__setattr__(forged_handle, "_path", _CORPUS.resolve())
    object.__setattr__(
        forged_handle,
        "_binding",
        verified.binding.model_copy(update={"corpus_sha256": "f" * 64}),
    )

    with pytest.raises(SourceSpanSelfCalibrationError, match="binding differs"):
        SourceSpanSelfCalibrationHarness().run(
            forged_handle,
            sample_id="mg-a-quantifier-order",
            run_id="forged-binding-run",
            actors=(),
            providers={},
        )


def test_declared_proposer_independence_must_not_overlap() -> None:
    sample = next(item for item in _samples() if item.sample_id == "mg-a-quantifier-order")

    with pytest.raises(SourceSpanSelfCalibrationError, match="independence groups must be unique"):
        _run(sample, duplicate_independence=True)


def test_quantifier_and_boundary_coverage_is_mandatory_for_each_proposal() -> None:
    sample = next(item for item in _samples() if item.sample_id == "mg-a-quantifier-order")

    with pytest.raises(SourceSpanSelfCalibrationError, match="quantifier and one boundary"):
        _run(sample, omit_boundary=True)


def test_mutation_must_be_a_harness_replayable_local_replacement() -> None:
    sample = next(item for item in _samples() if item.sample_id == "mg-a-quantifier-order")

    with pytest.raises(SourceSpanSelfCalibrationError, match="occur exactly once"):
        _run(sample, unreplayable_mutation=True)


def test_boundary_mutation_cannot_use_an_arbitrary_candidate_fragment() -> None:
    sample = next(item for item in _samples() if item.sample_id == "mg-a-quantifier-order")

    with pytest.raises(SourceSpanSelfCalibrationError, match="source-declared conclusion anchor"):
        _run(sample, unapproved_boundary_anchor=True)


def test_quantifier_and_boundary_mutations_require_distinct_baselines() -> None:
    sample = next(item for item in _samples() if item.sample_id == "pde-a-weak-uniqueness")

    with pytest.raises(SourceSpanSelfCalibrationError, match="distinct proposal baselines"):
        _run(sample, duplicate_mutation_baseline=True)


def test_source_fixture_anchor_classes_are_disjoint_and_difference_kind_bound() -> None:
    quantifier_sample = next(
        item for item in _samples() if item.sample_id == "mg-a-quantifier-order"
    )
    quantifier_binding = build_source_span_calibration_input_binding(
        _corpus(), sample_id=quantifier_sample.sample_id
    )
    quantifier_fixture, conclusion_fixture = quantifier_sample.mutation_fixtures
    quantifier_hash = hashlib.sha256(quantifier_fixture.baseline_fragment.encode()).hexdigest()
    conclusion_hash = hashlib.sha256(conclusion_fixture.baseline_fragment.encode()).hexdigest()

    assert quantifier_hash not in quantifier_binding.conclusion_anchor_sha256
    assert quantifier_hash not in quantifier_binding.boundary_condition_anchor_sha256
    assert conclusion_hash in quantifier_binding.conclusion_anchor_sha256
    assert not (
        set(quantifier_binding.conclusion_anchor_sha256)
        & set(quantifier_binding.boundary_condition_anchor_sha256)
    )

    boundary_sample = next(
        item for item in _samples() if item.sample_id == "mg-a-finite-noetherian-compactness"
    )
    boundary_binding = build_source_span_calibration_input_binding(
        _corpus(), sample_id=boundary_sample.sample_id
    )
    boundary_hash = hashlib.sha256(
        boundary_sample.mutation_fixtures[0].baseline_fragment.encode()
    ).hexdigest()
    assert boundary_hash in boundary_binding.boundary_condition_anchor_sha256


def test_mutation_family_must_match_explicit_anchor_category() -> None:
    with pytest.raises(ValueError, match="family does not match"):
        QuantifierBoundaryMutationV1(
            proposal_id="proposal-0123456789abcdefabcd",
            family=CalibrationMutationFamilyV1.QUANTIFIER,
            anchor=CalibrationMutationAnchorV1.CONCLUSION,
            baseline_fragment="for every x",
            replacement_fragment="there exists x",
            applied_statement="there exists x, P x",
            expected_semantic_failure="The quantifier changed.",
            rationale="Category mismatch regression.",
        )


@pytest.mark.parametrize(
    ("baseline", "replacement", "message"),
    (
        ("Å", "A\u030a", "Unicode normalization"),
        ("for every x", "for every x\u200b", "control or format"),
        ("for every x", "for every x\x00", "control or format"),
    ),
)
def test_mutation_rejects_unicode_invisible_or_normalization_only_changes(
    baseline: str,
    replacement: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        QuantifierBoundaryMutationV1(
            proposal_id="proposal-0123456789abcdefabcd",
            family=CalibrationMutationFamilyV1.QUANTIFIER,
            anchor=CalibrationMutationAnchorV1.QUANTIFIER,
            baseline_fragment=baseline,
            replacement_fragment=replacement,
            applied_statement=replacement,
            expected_semantic_failure="The quantifier changed.",
            rationale="Unicode mutation regression.",
        )


def test_role_output_budget_is_bound_and_enforced() -> None:
    sample = next(item for item in _samples() if item.sample_id == "mg-a-quantifier-order")

    with pytest.raises(SourceSpanSelfCalibrationError, match="output-token budget"):
        _run(sample, output_tokens=1025)


def test_role_environment_hash_is_recomputed_from_actor_configuration() -> None:
    sample = next(item for item in _samples() if item.sample_id == "mg-a-quantifier-order")
    result = _run(sample)

    with pytest.raises(ValueError, match="environment hash does not bind"):
        result.executions[0].actor.model_copy(update={"role_environment_sha256": "f" * 64})


def test_duplicate_json_keys_are_rejected_before_adjudication() -> None:
    sample = next(item for item in _samples() if item.sample_id == "mg-a-quantifier-order")
    parts = _run_parts(sample)
    duplicate = '{"normalized_statement":"one","normalized_statement":"two"}'
    parts.outputs["conversion-a"] = duplicate
    roles = {
        "conversion-a": SourceSpanCalibrationRoleV1.CONVERSION_PROPOSER,
        "conversion-b": SourceSpanCalibrationRoleV1.CONVERSION_PROPOSER,
        "reverse-reviewer": SourceSpanCalibrationRoleV1.REVERSE_RENDER_REVIEWER,
        "mutation-critic": SourceSpanCalibrationRoleV1.QUANTIFIER_BOUNDARY_CRITIC,
        "adjudicator": SourceSpanCalibrationRoleV1.ADJUDICATOR,
    }
    providers = {
        actor_id: ScriptedFakeSourceSpanCalibrationProvider(
            (response,), model_id=f"fake-{actor_id}"
        )
        for actor_id, response in parts.outputs.items()
    }
    actors = tuple(
        build_scripted_fake_calibration_actor(
            actor_id=actor_id,
            role=role,
            independence_group=f"independence-{actor_id}",
            provider=providers[actor_id],
        )
        for actor_id, role in roles.items()
    )

    with pytest.raises(SourceSpanSelfCalibrationError, match="not strict JSON"):
        SourceSpanSelfCalibrationHarness().run(
            _corpus(),
            sample_id=sample.sample_id,
            run_id="duplicate-json-run",
            actors=actors,
            providers=providers,
        )


def test_mutation_output_shape_cannot_be_relabelled_as_semantic_evidence() -> None:
    sample = next(item for item in _samples() if item.sample_id == "mg-a-quantifier-order")
    result = _run(sample)
    payload = result.model_dump(mode="json")
    payload["authority"]["semantic_review_authority"] = True

    with pytest.raises(ValueError):
        type(result).model_validate(payload)

    assert isinstance(result.mutation_critique, QuantifierBoundaryCritiqueOutputV1)
