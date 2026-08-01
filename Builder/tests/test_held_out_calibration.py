"""Tests for the deterministic, structural-only Builder held-out calibration protocol."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from autolean_builder import held_out_calibration as held_out_protocol
from autolean_builder.held_out_calibration import (
    HeldOutCalibrationBudgetV1,
    HeldOutCalibrationError,
    HeldOutCalibrationFakeResponseModeV1,
    HeldOutCalibrationPartitionNameV1,
    HeldOutCalibrationProviderDescriptorV1,
    HeldOutCalibrationProviderResponseV1,
    HeldOutCalibrationRequestV1,
    HeldOutCalibrationResultV1,
    HeldOutCalibrationRunConfigV1,
    HeldOutCalibrationSplitV1,
    ScriptedFakeHeldOutCalibrationProvider,
    VerifiedHeldOutCalibrationCorpus,
    build_held_out_calibration_run_config,
    build_held_out_calibration_split,
    load_held_out_calibration_corpus,
    run_held_out_calibration,
    verify_held_out_calibration_split,
)
from autolean_contracts import canonical_json_bytes

_ROOT = Path(__file__).resolve().parents[2]
_CORPUS_PATH = (
    _ROOT / "Builder" / "pilots" / "local-calibration" / "project-synthetic-opening-corpus.v1.json"
)


def _sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _corpus() -> VerifiedHeldOutCalibrationCorpus:
    return load_held_out_calibration_corpus(_CORPUS_PATH)


def _split(*, seed: str = "heldout-calibration-split-v1") -> HeldOutCalibrationSplitV1:
    return build_held_out_calibration_split(_corpus(), split_seed=seed)


def _budget() -> HeldOutCalibrationBudgetV1:
    return HeldOutCalibrationBudgetV1(
        max_input_tokens=128,
        max_output_tokens=128,
        max_response_bytes=4096,
        timeout_seconds=1.0,
    )


def _run(
    *,
    mode: HeldOutCalibrationFakeResponseModeV1 = HeldOutCalibrationFakeResponseModeV1.NORMAL,
    repetitions: int = 2,
) -> tuple[
    VerifiedHeldOutCalibrationCorpus,
    HeldOutCalibrationSplitV1,
    HeldOutCalibrationRunConfigV1,
    HeldOutCalibrationResultV1,
]:
    corpus = _corpus()
    split = build_held_out_calibration_split(corpus, split_seed="heldout-calibration-split-v1")
    provider = ScriptedFakeHeldOutCalibrationProvider(response_mode=mode)
    configuration = build_held_out_calibration_run_config(
        split,
        run_id="heldout-calibration-run-v1",
        repetition_seed="heldout-calibration-repeat-v1",
        repetitions=repetitions,
        provider=provider,
        budget=_budget(),
    )
    return (
        corpus,
        split,
        configuration,
        run_held_out_calibration(
            corpus,
            split,
            configuration,
            provider=provider,
        ),
    )


def _rehash_partition(payload: dict[str, object]) -> None:
    payload["partition_sha256"] = _sha256_json(
        {key: value for key, value in payload.items() if key != "partition_sha256"}
    )


def _rehash_split(payload: dict[str, object]) -> None:
    payload["split_sha256"] = _sha256_json(
        {key: value for key, value in payload.items() if key != "split_sha256"}
    )


def test_manifest_bound_split_is_deterministic_exhaustive_and_non_authoritative() -> None:
    corpus = _corpus()
    first = build_held_out_calibration_split(corpus, split_seed="heldout-calibration-split-v1")
    replay = build_held_out_calibration_split(corpus, split_seed="heldout-calibration-split-v1")
    changed = build_held_out_calibration_split(corpus, split_seed="heldout-calibration-split-v2")

    assert first == replay
    assert first.split_sha256 == replay.split_sha256
    assert first.split_sha256 != changed.split_sha256
    assert (len(first.train.samples), len(first.dev.samples), len(first.held_out.samples)) == (
        5,
        3,
        3,
    )
    assert (
        tuple(
            sorted(
                item.sample_id
                for partition in (first.train, first.dev, first.held_out)
                for item in partition.samples
            )
        )
        == corpus.binding.sample_ids
    )
    assert first.corpus.release_manifest_sha256
    assert first.egress_guard.external_egress_allowed is False
    assert first.authority.freeze_authority is False
    assert first.authority.prover_handoff_authority is False


@pytest.mark.parametrize(
    ("field", "expected_message"),
    (
        ("sample_id", "sample identifiers cannot cross"),
        ("source_sha256", "source hashes cannot cross"),
        ("derived_mutation_sha256", "derived mutation hashes cannot cross"),
    ),
)
def test_split_rejects_sample_source_and_mutation_cross_partition_leakage(
    field: str,
    expected_message: str,
) -> None:
    payload = _split().model_dump(mode="json")
    train_sample = payload["train"]["samples"][0]
    dev_sample = payload["dev"]["samples"][0]
    assert isinstance(train_sample, dict)
    assert isinstance(dev_sample, dict)
    if field == "derived_mutation_sha256":
        dev_sample[field] = sorted(train_sample[field])
    else:
        dev_sample[field] = train_sample[field]
    _rehash_partition(payload["dev"])
    _rehash_split(payload)

    with pytest.raises(ValueError, match=expected_message):
        HeldOutCalibrationSplitV1.model_validate(payload)


def test_run_replays_bound_seeds_provider_budgets_and_partition_isolation() -> None:
    corpus, split, configuration, first = _run(repetitions=3)
    provider = ScriptedFakeHeldOutCalibrationProvider()
    replay = run_held_out_calibration(corpus, split, configuration, provider=provider)

    assert first == replay
    assert first.result_sha256 == replay.result_sha256
    assert tuple(item.repetition_index for item in first.repetitions) == (0, 1, 2)
    assert len({item.repetition_seed for item in first.repetitions}) == 3
    assert all(
        item.configuration_sha256 == configuration.configuration_sha256
        for item in first.repetitions
    )
    assert all(item.provider == configuration.provider for item in first.repetitions)
    assert all(item.budget == configuration.budget for item in first.repetitions)
    assert all(item.authority.release_authority is False for item in first.repetitions)
    assert first.configuration.precommitted_before_held_out is True
    assert first.configuration.semantic_correctness_scoring_present is False

    train_ids = {item.sample_id for item in split.train.samples}
    dev_ids = {item.sample_id for item in split.dev.samples}
    held_out_ids = {item.sample_id for item in split.held_out.samples}
    assert train_ids.isdisjoint(dev_ids)
    assert train_ids.isdisjoint(held_out_ids)
    assert dev_ids.isdisjoint(held_out_ids)
    for repetition in first.repetitions:
        for outcome in repetition.outcomes:
            expected_ids = {
                HeldOutCalibrationPartitionNameV1.TRAIN: train_ids,
                HeldOutCalibrationPartitionNameV1.DEV: dev_ids,
                HeldOutCalibrationPartitionNameV1.HELD_OUT: held_out_ids,
            }[outcome.partition]
            assert outcome.case.sample.sample_id in expected_ids
            assert outcome.case.source_text_present is False
            assert outcome.egress_guard.external_egress_allowed is False

    serialized = json.dumps(first.model_dump(mode="json"), sort_keys=True)
    assert corpus.corpus.samples[0].source_text not in serialized
    assert first.statement_contract_present is False
    assert first.formalization_task_bundle_present is False
    assert first.semantic_correctness_claimed is False
    with pytest.raises(HeldOutCalibrationError, match="cannot freeze"):
        first.freeze_statement()
    with pytest.raises(HeldOutCalibrationError, match="cannot create a Prover handoff"):
        first.handoff_to_prover()


def test_run_rejects_a_rehashed_but_nondeterministic_partition_allocation() -> None:
    corpus = _corpus()
    payload = _split().model_dump(mode="json")
    train_sample = payload["train"]["samples"][0]
    dev_sample = payload["dev"]["samples"][0]
    assert isinstance(train_sample, dict)
    assert isinstance(dev_sample, dict)
    payload["train"]["samples"][0] = dev_sample
    payload["dev"]["samples"][0] = train_sample
    payload["train"]["samples"].sort(key=lambda item: item["sample_id"])
    payload["dev"]["samples"].sort(key=lambda item: item["sample_id"])
    _rehash_partition(payload["train"])
    _rehash_partition(payload["dev"])
    _rehash_split(payload)
    altered = HeldOutCalibrationSplitV1.model_validate(payload)

    with pytest.raises(HeldOutCalibrationError, match="does not match"):
        verify_held_out_calibration_split(altered, corpus)


def test_split_builder_reloads_canonical_corpus_before_trusting_capability() -> None:
    corpus = _corpus()
    forged_first_sample = corpus.sample_bindings[0].model_copy(update={"source_sha256": "0" * 64})
    forged = held_out_protocol.VerifiedHeldOutCalibrationCorpus(
        corpus=corpus.corpus,
        binding=corpus.binding,
        sample_bindings=(forged_first_sample, *corpus.sample_bindings[1:]),
        token=held_out_protocol._VERIFIED_CORPUS_TOKEN,
    )
    with pytest.raises(HeldOutCalibrationError, match="differs from the canonical"):
        build_held_out_calibration_split(
            forged,
            split_seed="heldout-calibration-split-v1",
        )


def test_split_builder_rejects_object_new_capability_with_model_constructed_corpus() -> None:
    corpus = _corpus()
    forged_corpus_payload = corpus.corpus.model_dump(mode="python")
    forged_corpus_payload["promotion_allowed"] = True
    forged_corpus = type(corpus.corpus).model_construct(**forged_corpus_payload)
    forged = object.__new__(VerifiedHeldOutCalibrationCorpus)
    object.__setattr__(forged, "_corpus", forged_corpus)
    object.__setattr__(forged, "_binding", corpus.binding)
    object.__setattr__(forged, "_sample_bindings", corpus.sample_bindings)
    object.__setattr__(forged, "_token", corpus._token)

    with pytest.raises(HeldOutCalibrationError, match="differs from the canonical"):
        build_held_out_calibration_split(
            forged,
            split_seed="heldout-calibration-split-v1",
        )


@pytest.mark.parametrize(
    ("mode", "expected_rates"),
    (
        (
            HeldOutCalibrationFakeResponseModeV1.NORMAL,
            (1.0, 1.0, 1.0),
        ),
        (
            HeldOutCalibrationFakeResponseModeV1.STRUCTURAL_MISS,
            (1.0, 0.0, 1.0),
        ),
        (
            HeldOutCalibrationFakeResponseModeV1.INCONSISTENT_ADVISORY,
            (1.0, 1.0, 0.0),
        ),
        (
            HeldOutCalibrationFakeResponseModeV1.INVALID_JSON,
            (0.0, 0.0, 0.0),
        ),
        (
            HeldOutCalibrationFakeResponseModeV1.DUPLICATE_JSON_KEY,
            (0.0, 0.0, 0.0),
        ),
    ),
)
def test_scores_only_structural_json_and_advisory_signals(
    mode: HeldOutCalibrationFakeResponseModeV1,
    expected_rates: tuple[float, float, float],
) -> None:
    _, _, _, result = _run(mode=mode, repetitions=1)
    score = next(
        item
        for item in result.repetitions[0].partition_scores
        if item.partition is HeldOutCalibrationPartitionNameV1.HELD_OUT
    )

    assert (
        score.json_compliance_rate,
        score.structural_drift_detection_rate,
        score.advisory_consistency_rate,
    ) == expected_rates
    assert score.semantic_correctness_score_present is False
    assert result.semantic_correctness_claimed is False


class _NetworkLikeProvider:
    """A shape-compatible stand-in that must not become an alternative execution route."""

    def descriptor(self) -> HeldOutCalibrationProviderDescriptorV1:
        return HeldOutCalibrationProviderDescriptorV1(
            model_id="network-like-provider-v1",
            provider_configuration_sha256="0" * 64,
        )

    def generate(
        self, request: HeldOutCalibrationRequestV1
    ) -> HeldOutCalibrationProviderResponseV1:
        raise AssertionError(f"network-like provider must not run: {request}")


def test_v1_refuses_any_provider_other_than_exact_no_egress_scripted_fake() -> None:
    split = _split()

    with pytest.raises(HeldOutCalibrationError, match="only the exact no-egress scripted fake"):
        build_held_out_calibration_run_config(
            split,
            run_id="heldout-calibration-run-v1",
            repetition_seed="heldout-calibration-repeat-v1",
            repetitions=1,
            provider=_NetworkLikeProvider(),
            budget=_budget(),
        )


def test_run_rejects_a_fake_whose_bound_response_mode_changed_after_precommit() -> None:
    corpus = _corpus()
    split = build_held_out_calibration_split(corpus, split_seed="heldout-calibration-split-v1")
    provider = ScriptedFakeHeldOutCalibrationProvider()
    configuration = build_held_out_calibration_run_config(
        split,
        run_id="heldout-calibration-provider-binding-v1",
        repetition_seed="heldout-calibration-repeat-v1",
        repetitions=1,
        provider=provider,
        budget=_budget(),
    )
    provider._response_mode = HeldOutCalibrationFakeResponseModeV1.STRUCTURAL_MISS

    with pytest.raises(HeldOutCalibrationError, match="provider differs"):
        run_held_out_calibration(corpus, split, configuration, provider=provider)
