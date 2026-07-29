"""Deterministic, no-egress held-out calibration protocol for Builder fixtures.

The protocol is intentionally narrower than a proposition-fidelity review.  It partitions only
the manifest-verified, repository-synthetic opening corpus and measures three mechanical signals:
declared structural-drift detection, strict JSON compliance, and whether a response is internally
consistent with its own advisory disposition.  It never scores mathematical correctness.

V1 permits one exact local scripted-fake provider.  That makes the executable protocol useful for
testing leakage controls and repeatability while preserving the corpus rights boundary.  It cannot
freeze a statement, create a formalization bundle, or hand anything to Prover.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from typing import Literal, Never, Protocol, Self

from autolean_contracts import (
    EndpointClassV1,
    canonical_json_bytes,
    validate_model_routing_identifier,
)
from autolean_contracts.base import ContractModel
from pydantic import ConfigDict, Field, model_validator

from .local_calibration import (
    LocalCalibrationFixtureCorpusV1,
    PreCalibrationFixtureRecordV1,
    load_local_calibration_fixture_corpus,
)

_SHA256 = r"^[0-9a-f]{64}$"
_IDENTIFIER = r"^[a-z][a-z0-9-]{2,127}$"
_PROVIDER_IDENTIFIER = r"^[a-z0-9][a-z0-9._-]{0,127}$"
_CORPUS_MANIFEST_NAME = "project-synthetic-opening-corpus.release-manifest.v1.json"
_TRAIN_COUNT = 5
_DEV_COUNT = 3
_HELD_OUT_COUNT = 3
_VERIFIED_CORPUS_TOKEN = object()


class HeldOutCalibrationError(ValueError):
    """A held-out calibration artifact is malformed or crosses an authority boundary."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_value(value: object) -> object:
    """Convert nested contract models before handing a value to the canonical JSON encoder."""

    if isinstance(value, ContractModel):
        return _canonical_value(value.model_dump(mode="json"))
    if isinstance(value, Mapping):
        return {str(key): _canonical_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_canonical_value(item) for item in value]
    return value


def _sha256_json(value: object) -> str:
    return _sha256_bytes(canonical_json_bytes(_canonical_value(value)))


def _sha256_model(value: ContractModel) -> str:
    return _sha256_json(value.model_dump(mode="json"))


def _sha256_file(path: Path) -> str:
    try:
        return _sha256_bytes(path.read_bytes())
    except OSError as error:
        raise HeldOutCalibrationError(
            f"cannot hash held-out calibration dependency: {path}"
        ) from error


def _canonical_corpus_path() -> Path:
    return (
        Path(__file__).resolve().parents[3]
        / "Builder"
        / "pilots"
        / "local-calibration"
        / "project-synthetic-opening-corpus.v1.json"
    )


class HeldOutCalibrationAuthorityV1(ContractModel):
    """Hard negative authority attached to protocol artifacts."""

    schema_version: Literal["autolean.held-out-calibration-authority.v1"] = (
        "autolean.held-out-calibration-authority.v1"
    )
    evidence_class: Literal["machine_advisory_structural_only"] = "machine_advisory_structural_only"
    rights_authority: Literal[False] = False
    semantic_review_authority: Literal[False] = False
    kernel_verification_authority: Literal[False] = False
    freeze_authority: Literal[False] = False
    prover_handoff_authority: Literal[False] = False
    release_authority: Literal[False] = False


class HeldOutCalibrationEgressGuardV1(ContractModel):
    """The current protocol has no route to an external model or network service."""

    schema_version: Literal["autolean.held-out-calibration-egress-guard.v1"] = (
        "autolean.held-out-calibration-egress-guard.v1"
    )
    egress_policy: Literal["deny_external_model_egress"] = "deny_external_model_egress"
    external_egress_allowed: Literal[False] = False
    external_authorization_present: Literal[False] = False
    source_text_export_allowed: Literal[False] = False
    authority: HeldOutCalibrationAuthorityV1 = Field(default_factory=HeldOutCalibrationAuthorityV1)

    def authorize_external_egress(self) -> Never:
        raise HeldOutCalibrationError(
            "held-out calibration has no external-model egress capability"
        )


class HeldOutCalibrationPartitionNameV1(StrEnum):
    TRAIN = "train"
    DEV = "dev"
    HELD_OUT = "held_out"


class HeldOutCalibrationCorpusBindingV1(ContractModel):
    """Digest-only binding to the canonical project-synthetic corpus and its release manifest."""

    schema_version: Literal["autolean.held-out-calibration-corpus-binding.v1"] = (
        "autolean.held-out-calibration-corpus-binding.v1"
    )
    corpus_id: Literal["project-synthetic-opening-pre-calibration"] = (
        "project-synthetic-opening-pre-calibration"
    )
    corpus_sha256: str = Field(pattern=_SHA256)
    release_manifest_sha256: str = Field(pattern=_SHA256)
    repository_license_sha256: str = Field(pattern=_SHA256)
    sample_count: Literal[11] = 11
    sample_ids: tuple[str, ...] = Field(min_length=11, max_length=11)
    authority: HeldOutCalibrationAuthorityV1 = Field(default_factory=HeldOutCalibrationAuthorityV1)

    @model_validator(mode="after")
    def validate_sample_ids(self) -> Self:
        if tuple(sorted(self.sample_ids)) != self.sample_ids or len(set(self.sample_ids)) != 11:
            raise ValueError("held-out corpus sample identifiers must be canonical and unique")
        return self


class HeldOutCalibrationSampleBindingV1(ContractModel):
    """One digest-only fixture binding; no source or mutation text is retained."""

    schema_version: Literal["autolean.held-out-calibration-sample-binding.v1"] = (
        "autolean.held-out-calibration-sample-binding.v1"
    )
    sample_id: str = Field(pattern=_IDENTIFIER)
    fixture_snapshot_sha256: str = Field(pattern=_SHA256)
    source_sha256: str = Field(pattern=_SHA256)
    source_span_sha256: str = Field(pattern=_SHA256)
    derived_mutation_sha256: tuple[str, ...] = Field(min_length=1)
    authority: HeldOutCalibrationAuthorityV1 = Field(default_factory=HeldOutCalibrationAuthorityV1)

    @model_validator(mode="after")
    def validate_mutation_hashes(self) -> Self:
        hashes = self.derived_mutation_sha256
        if tuple(sorted(hashes)) != hashes or len(set(hashes)) != len(hashes):
            raise ValueError("derived mutation hashes must be canonical and unique")
        return self


class VerifiedHeldOutCalibrationCorpus:
    """Capability issued only after the canonical fixture release manifest has been checked."""

    __slots__ = ("_binding", "_corpus", "_sample_bindings", "_token")

    def __init__(
        self,
        *,
        corpus: LocalCalibrationFixtureCorpusV1,
        binding: HeldOutCalibrationCorpusBindingV1,
        sample_bindings: tuple[HeldOutCalibrationSampleBindingV1, ...],
        token: object,
    ) -> None:
        if token is not _VERIFIED_CORPUS_TOKEN:
            raise HeldOutCalibrationError(
                "held-out calibration corpus capability requires release-manifest verification"
            )
        self._corpus = corpus
        self._binding = binding
        self._sample_bindings = sample_bindings
        self._token = token

    @property
    def corpus(self) -> LocalCalibrationFixtureCorpusV1:
        return self._corpus

    @property
    def binding(self) -> HeldOutCalibrationCorpusBindingV1:
        return self._binding

    @property
    def sample_bindings(self) -> tuple[HeldOutCalibrationSampleBindingV1, ...]:
        return self._sample_bindings

    def sample_binding(self, sample_id: str) -> HeldOutCalibrationSampleBindingV1:
        matches = tuple(item for item in self._sample_bindings if item.sample_id == sample_id)
        if len(matches) != 1:
            raise HeldOutCalibrationError("sample is absent from the verified held-out corpus")
        return matches[0]


class HeldOutCalibrationPartitionV1(ContractModel):
    """One named, disjoint partition in a deterministic split."""

    schema_version: Literal["autolean.held-out-calibration-partition.v1"] = (
        "autolean.held-out-calibration-partition.v1"
    )
    name: HeldOutCalibrationPartitionNameV1
    samples: tuple[HeldOutCalibrationSampleBindingV1, ...] = Field(min_length=1)
    partition_sha256: str = Field(pattern=_SHA256)
    authority: HeldOutCalibrationAuthorityV1 = Field(default_factory=HeldOutCalibrationAuthorityV1)

    @model_validator(mode="after")
    def validate_partition(self) -> Self:
        identifiers = tuple(item.sample_id for item in self.samples)
        if tuple(sorted(identifiers)) != identifiers or len(set(identifiers)) != len(identifiers):
            raise ValueError("partition sample identifiers must be canonical and unique")
        expected = _sha256_json(self.model_dump(mode="json", exclude={"partition_sha256"}))
        if self.partition_sha256 != expected:
            raise ValueError("held-out calibration partition hash differs")
        return self


class HeldOutCalibrationSplitV1(ContractModel):
    """A train/dev/held-out split that carries all partition-separation commitments."""

    schema_version: Literal["autolean.held-out-calibration-split.v1"] = (
        "autolean.held-out-calibration-split.v1"
    )
    split_id: Literal["project-synthetic-held-out-v1"] = "project-synthetic-held-out-v1"
    split_seed: str = Field(min_length=1, max_length=256)
    corpus: HeldOutCalibrationCorpusBindingV1
    train: HeldOutCalibrationPartitionV1
    dev: HeldOutCalibrationPartitionV1
    held_out: HeldOutCalibrationPartitionV1
    split_sha256: str = Field(pattern=_SHA256)
    egress_guard: HeldOutCalibrationEgressGuardV1 = Field(
        default_factory=HeldOutCalibrationEgressGuardV1
    )
    authority: HeldOutCalibrationAuthorityV1 = Field(default_factory=HeldOutCalibrationAuthorityV1)

    @model_validator(mode="after")
    def validate_split(self) -> Self:
        expected_names = (
            HeldOutCalibrationPartitionNameV1.TRAIN,
            HeldOutCalibrationPartitionNameV1.DEV,
            HeldOutCalibrationPartitionNameV1.HELD_OUT,
        )
        if (self.train.name, self.dev.name, self.held_out.name) != expected_names:
            raise ValueError("held-out calibration partitions have unexpected names or order")
        if (len(self.train.samples), len(self.dev.samples), len(self.held_out.samples)) != (
            _TRAIN_COUNT,
            _DEV_COUNT,
            _HELD_OUT_COUNT,
        ):
            raise ValueError(
                "held-out calibration split must contain 5 train, 3 dev, and 3 held-out samples"
            )
        all_samples = (*self.train.samples, *self.dev.samples, *self.held_out.samples)
        sample_ids = tuple(item.sample_id for item in all_samples)
        source_hashes = tuple(item.source_sha256 for item in all_samples)
        mutation_hashes = tuple(
            mutation_sha256
            for item in all_samples
            for mutation_sha256 in item.derived_mutation_sha256
        )
        if len(sample_ids) != len(set(sample_ids)):
            raise ValueError("sample identifiers cannot cross held-out calibration partitions")
        if len(source_hashes) != len(set(source_hashes)):
            raise ValueError("source hashes cannot cross held-out calibration partitions")
        if len(mutation_hashes) != len(set(mutation_hashes)):
            raise ValueError("derived mutation hashes cannot cross held-out calibration partitions")
        if tuple(sorted(sample_ids)) != self.corpus.sample_ids:
            raise ValueError("held-out partitions do not cover the manifest-bound corpus exactly")
        expected = _sha256_json(self.model_dump(mode="json", exclude={"split_sha256"}))
        if self.split_sha256 != expected:
            raise ValueError("held-out calibration split hash differs")
        return self

    def partition(self, name: HeldOutCalibrationPartitionNameV1) -> HeldOutCalibrationPartitionV1:
        return {
            HeldOutCalibrationPartitionNameV1.TRAIN: self.train,
            HeldOutCalibrationPartitionNameV1.DEV: self.dev,
            HeldOutCalibrationPartitionNameV1.HELD_OUT: self.held_out,
        }[name]


class HeldOutCalibrationBudgetV1(ContractModel):
    """Fixed per-case budget recorded in every repeated execution."""

    schema_version: Literal["autolean.held-out-calibration-budget.v1"] = (
        "autolean.held-out-calibration-budget.v1"
    )
    max_input_tokens: int = Field(ge=1, le=1_000_000)
    max_output_tokens: int = Field(ge=1, le=1_000_000)
    max_response_bytes: int = Field(ge=32, le=1_000_000)
    timeout_seconds: float = Field(gt=0, le=3600)
    authority: HeldOutCalibrationAuthorityV1 = Field(default_factory=HeldOutCalibrationAuthorityV1)

    @property
    def budget_sha256(self) -> str:
        return _sha256_model(self)


class HeldOutCalibrationFakeResponseModeV1(StrEnum):
    NORMAL = "normal"
    INVALID_JSON = "invalid_json"
    DUPLICATE_JSON_KEY = "duplicate_json_key"
    STRUCTURAL_MISS = "structural_miss"
    INCONSISTENT_ADVISORY = "inconsistent_advisory"


class HeldOutCalibrationProviderDescriptorV1(ContractModel):
    """Exact descriptor for the current local scripted-fake provider."""

    schema_version: Literal["autolean.held-out-calibration-provider.v1"] = (
        "autolean.held-out-calibration-provider.v1"
    )
    provider_id: Literal["fake"] = "fake"
    model_id: str = Field(pattern=_PROVIDER_IDENTIFIER)
    endpoint_class: Literal[EndpointClassV1.LOCAL] = EndpointClassV1.LOCAL
    execution_mode: Literal["offline_scripted_fake"] = "offline_scripted_fake"
    provider_configuration_sha256: str = Field(pattern=_SHA256)
    egress_guard: HeldOutCalibrationEgressGuardV1 = Field(
        default_factory=HeldOutCalibrationEgressGuardV1
    )
    authority: HeldOutCalibrationAuthorityV1 = Field(default_factory=HeldOutCalibrationAuthorityV1)

    @model_validator(mode="after")
    def validate_model(self) -> Self:
        validate_model_routing_identifier(self.model_id, label="model_id")
        return self


class HeldOutCalibrationRunConfigV1(ContractModel):
    """A precommitted configuration; no held-out result can tune it in V1."""

    schema_version: Literal["autolean.held-out-calibration-run-config.v1"] = (
        "autolean.held-out-calibration-run-config.v1"
    )
    run_id: str = Field(pattern=_IDENTIFIER)
    split_sha256: str = Field(pattern=_SHA256)
    repetitions: int = Field(ge=1, le=100)
    repetition_seed: str = Field(min_length=1, max_length=256)
    provider: HeldOutCalibrationProviderDescriptorV1
    budget: HeldOutCalibrationBudgetV1
    precommitted_before_held_out: Literal[True] = True
    semantic_correctness_scoring_present: Literal[False] = False
    configuration_sha256: str = Field(pattern=_SHA256)
    egress_guard: HeldOutCalibrationEgressGuardV1 = Field(
        default_factory=HeldOutCalibrationEgressGuardV1
    )
    authority: HeldOutCalibrationAuthorityV1 = Field(default_factory=HeldOutCalibrationAuthorityV1)

    @model_validator(mode="after")
    def validate_configuration_hash(self) -> Self:
        expected = _sha256_json(self.model_dump(mode="json", exclude={"configuration_sha256"}))
        if self.configuration_sha256 != expected:
            raise ValueError("held-out calibration configuration hash differs")
        return self


class HeldOutCalibrationCaseV1(ContractModel):
    """Text-free structural probe derived from a declared synthetic mutation fixture."""

    schema_version: Literal["autolean.held-out-calibration-case.v1"] = (
        "autolean.held-out-calibration-case.v1"
    )
    case_id: str = Field(pattern=_IDENTIFIER)
    partition: HeldOutCalibrationPartitionNameV1
    sample: HeldOutCalibrationSampleBindingV1
    mutation_sha256: str = Field(pattern=_SHA256)
    split_sha256: str = Field(pattern=_SHA256)
    case_sha256: str = Field(pattern=_SHA256)
    source_text_present: Literal[False] = False
    semantic_label_present: Literal[False] = False
    egress_guard: HeldOutCalibrationEgressGuardV1 = Field(
        default_factory=HeldOutCalibrationEgressGuardV1
    )
    authority: HeldOutCalibrationAuthorityV1 = Field(default_factory=HeldOutCalibrationAuthorityV1)

    @model_validator(mode="after")
    def validate_case(self) -> Self:
        if self.mutation_sha256 not in self.sample.derived_mutation_sha256:
            raise ValueError("held-out case mutation is detached from its sample binding")
        expected = _sha256_json(self.model_dump(mode="json", exclude={"case_sha256"}))
        if self.case_sha256 != expected:
            raise ValueError("held-out calibration case hash differs")
        return self


class HeldOutCalibrationRequestV1(ContractModel):
    """Text-free local request; it cannot serialize source bytes to an external endpoint."""

    schema_version: Literal["autolean.held-out-calibration-request.v1"] = (
        "autolean.held-out-calibration-request.v1"
    )
    repetition_index: int = Field(ge=0, le=99)
    repetition_seed: str = Field(pattern=_SHA256)
    configuration_sha256: str = Field(pattern=_SHA256)
    case: HeldOutCalibrationCaseV1
    request_sha256: str = Field(pattern=_SHA256)
    source_text_present: Literal[False] = False
    egress_guard: HeldOutCalibrationEgressGuardV1 = Field(
        default_factory=HeldOutCalibrationEgressGuardV1
    )
    authority: HeldOutCalibrationAuthorityV1 = Field(default_factory=HeldOutCalibrationAuthorityV1)

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        expected = _sha256_json(self.model_dump(mode="json", exclude={"request_sha256"}))
        if self.request_sha256 != expected:
            raise ValueError("held-out calibration request hash differs")
        return self


class HeldOutCalibrationProviderResponseV1(ContractModel):
    """Raw local fake response, retained only by hash in the result."""

    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True)

    provider_id: Literal["fake"] = "fake"
    model_id: str = Field(pattern=_PROVIDER_IDENTIFIER)
    request_sha256: str = Field(pattern=_SHA256)
    text: str = Field(min_length=1, max_length=1_000_000)
    declared_input_tokens: int = Field(ge=0)
    declared_output_tokens: int = Field(ge=0)


class HeldOutCalibrationProvider(Protocol):
    """Narrow protocol deliberately satisfied only by the exact local scripted fake in V1."""

    def descriptor(self) -> HeldOutCalibrationProviderDescriptorV1: ...

    def generate(
        self, request: HeldOutCalibrationRequestV1
    ) -> HeldOutCalibrationProviderResponseV1: ...


class ScriptedFakeHeldOutCalibrationProvider:
    """Synchronous deterministic fake with selectable failure modes for protocol tests."""

    def __init__(
        self,
        *,
        model_id: str = "autolean-heldout-scripted-fake-v1",
        response_mode: HeldOutCalibrationFakeResponseModeV1 = (
            HeldOutCalibrationFakeResponseModeV1.NORMAL
        ),
    ) -> None:
        validate_model_routing_identifier(model_id, label="model_id")
        self._model_id = model_id
        self._response_mode = response_mode

    def descriptor(self) -> HeldOutCalibrationProviderDescriptorV1:
        return HeldOutCalibrationProviderDescriptorV1(
            model_id=self._model_id,
            provider_configuration_sha256=_sha256_json(
                {
                    "schema_version": "autolean.held-out-calibration-scripted-fake.v1",
                    "provider_id": "fake",
                    "model_id": self._model_id,
                    "response_mode": self._response_mode,
                    "network_access": False,
                    "source_text_input": False,
                }
            ),
        )

    def generate(
        self, request: HeldOutCalibrationRequestV1
    ) -> HeldOutCalibrationProviderResponseV1:
        if self._response_mode is HeldOutCalibrationFakeResponseModeV1.INVALID_JSON:
            text = '{"case_sha256":'
        elif self._response_mode is HeldOutCalibrationFakeResponseModeV1.DUPLICATE_JSON_KEY:
            text = (
                '{"schema_version":"autolean.held-out-calibration-assessment.v1",'
                f'"case_sha256":"{request.case.case_sha256}",'
                f'"case_sha256":"{request.case.case_sha256}",'
                '"structural_drift_detected":true,'
                '"advisory_disposition":"record_structural_drift"}'
            )
        else:
            structural_drift_detected = (
                self._response_mode is not HeldOutCalibrationFakeResponseModeV1.STRUCTURAL_MISS
            )
            disposition = (
                "record_structural_drift" if structural_drift_detected else "no_structural_drift"
            )
            if self._response_mode is HeldOutCalibrationFakeResponseModeV1.INCONSISTENT_ADVISORY:
                disposition = "no_structural_drift"
            text = json.dumps(
                {
                    "schema_version": "autolean.held-out-calibration-assessment.v1",
                    "case_sha256": request.case.case_sha256,
                    "structural_drift_detected": structural_drift_detected,
                    "advisory_disposition": disposition,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        return HeldOutCalibrationProviderResponseV1(
            model_id=self._model_id,
            request_sha256=request.request_sha256,
            text=text,
            declared_input_tokens=0,
            declared_output_tokens=0,
        )


class HeldOutCalibrationAssessmentV1(ContractModel):
    """Strictly parsed structural-only assessment returned by the local fake."""

    schema_version: Literal["autolean.held-out-calibration-assessment.v1"] = (
        "autolean.held-out-calibration-assessment.v1"
    )
    case_sha256: str = Field(pattern=_SHA256)
    structural_drift_detected: bool
    advisory_disposition: Literal["record_structural_drift", "no_structural_drift"]


class HeldOutCalibrationOutcomeV1(ContractModel):
    """One scored execution outcome without raw source, mutation, or provider output bytes."""

    schema_version: Literal["autolean.held-out-calibration-outcome.v1"] = (
        "autolean.held-out-calibration-outcome.v1"
    )
    partition: HeldOutCalibrationPartitionNameV1
    case: HeldOutCalibrationCaseV1
    request_sha256: str = Field(pattern=_SHA256)
    provider: HeldOutCalibrationProviderDescriptorV1
    budget_sha256: str = Field(pattern=_SHA256)
    raw_response_sha256: str = Field(pattern=_SHA256)
    response_bytes: int = Field(ge=0)
    declared_input_tokens: int = Field(ge=0)
    declared_output_tokens: int = Field(ge=0)
    json_compliant: bool
    structural_drift_detected: bool | None
    advisory_consistent: bool
    outcome_sha256: str = Field(pattern=_SHA256)
    egress_guard: HeldOutCalibrationEgressGuardV1 = Field(
        default_factory=HeldOutCalibrationEgressGuardV1
    )
    authority: HeldOutCalibrationAuthorityV1 = Field(default_factory=HeldOutCalibrationAuthorityV1)

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        if self.partition is not self.case.partition:
            raise ValueError("outcome partition differs from its bound case")
        if self.json_compliant:
            if self.structural_drift_detected is None:
                raise ValueError("JSON-compliant outcome requires a structural-drift flag")
        elif self.structural_drift_detected is not None or self.advisory_consistent:
            raise ValueError("non-compliant JSON cannot carry a scored structural assessment")
        expected = _sha256_json(self.model_dump(mode="json", exclude={"outcome_sha256"}))
        if self.outcome_sha256 != expected:
            raise ValueError("held-out calibration outcome hash differs")
        return self


class HeldOutCalibrationPartitionScoreV1(ContractModel):
    """Counts and rates for mechanical protocol signals, never a semantic-fidelity score."""

    schema_version: Literal["autolean.held-out-calibration-partition-score.v1"] = (
        "autolean.held-out-calibration-partition-score.v1"
    )
    partition: HeldOutCalibrationPartitionNameV1
    case_count: int = Field(ge=1)
    json_compliant_count: int = Field(ge=0)
    structural_drift_detected_count: int = Field(ge=0)
    advisory_consistent_count: int = Field(ge=0)
    json_compliance_rate: float = Field(ge=0, le=1)
    structural_drift_detection_rate: float = Field(ge=0, le=1)
    advisory_consistency_rate: float = Field(ge=0, le=1)
    semantic_correctness_score_present: Literal[False] = False
    authority: HeldOutCalibrationAuthorityV1 = Field(default_factory=HeldOutCalibrationAuthorityV1)

    @model_validator(mode="after")
    def validate_counts(self) -> Self:
        counts = (
            self.json_compliant_count,
            self.structural_drift_detected_count,
            self.advisory_consistent_count,
        )
        if any(count > self.case_count for count in counts):
            raise ValueError("held-out calibration score count exceeds case count")
        expected_rates = (
            self.json_compliant_count / self.case_count,
            self.structural_drift_detected_count / self.case_count,
            self.advisory_consistent_count / self.case_count,
        )
        actual_rates = (
            self.json_compliance_rate,
            self.structural_drift_detection_rate,
            self.advisory_consistency_rate,
        )
        if actual_rates != expected_rates:
            raise ValueError("held-out calibration score rates differ from counts")
        return self


class HeldOutCalibrationRepetitionV1(ContractModel):
    """One fully bound repeated run across the three fixed partitions."""

    schema_version: Literal["autolean.held-out-calibration-repetition.v1"] = (
        "autolean.held-out-calibration-repetition.v1"
    )
    repetition_index: int = Field(ge=0, le=99)
    repetition_seed: str = Field(pattern=_SHA256)
    configuration_sha256: str = Field(pattern=_SHA256)
    provider: HeldOutCalibrationProviderDescriptorV1
    budget: HeldOutCalibrationBudgetV1
    outcomes: tuple[HeldOutCalibrationOutcomeV1, ...] = Field(min_length=1)
    partition_scores: tuple[HeldOutCalibrationPartitionScoreV1, ...] = Field(
        min_length=3, max_length=3
    )
    repetition_sha256: str = Field(pattern=_SHA256)
    authority: HeldOutCalibrationAuthorityV1 = Field(default_factory=HeldOutCalibrationAuthorityV1)

    @model_validator(mode="after")
    def validate_repetition(self) -> Self:
        score_names = tuple(item.partition for item in self.partition_scores)
        expected_names = (
            HeldOutCalibrationPartitionNameV1.TRAIN,
            HeldOutCalibrationPartitionNameV1.DEV,
            HeldOutCalibrationPartitionNameV1.HELD_OUT,
        )
        if score_names != expected_names:
            raise ValueError("repetition partition scores must use canonical partition order")
        if any(item.provider != self.provider for item in self.outcomes):
            raise ValueError("repetition outcome provider differs from repeated-run provider")
        if any(item.budget_sha256 != self.budget.budget_sha256 for item in self.outcomes):
            raise ValueError("repetition outcome budget differs from repeated-run budget")
        expected = _sha256_json(self.model_dump(mode="json", exclude={"repetition_sha256"}))
        if self.repetition_sha256 != expected:
            raise ValueError("held-out calibration repetition hash differs")
        return self


class HeldOutCalibrationResultV1(ContractModel):
    """Non-promotable report for a completely deterministic fake-provider calibration run."""

    schema_version: Literal["autolean.held-out-calibration-result.v1"] = (
        "autolean.held-out-calibration-result.v1"
    )
    split: HeldOutCalibrationSplitV1
    configuration: HeldOutCalibrationRunConfigV1
    repetitions: tuple[HeldOutCalibrationRepetitionV1, ...] = Field(min_length=1, max_length=100)
    structural_only: Literal[True] = True
    statement_contract_present: Literal[False] = False
    formalization_task_bundle_present: Literal[False] = False
    semantic_correctness_claimed: Literal[False] = False
    kernel_verification_present: Literal[False] = False
    result_sha256: str = Field(pattern=_SHA256)
    egress_guard: HeldOutCalibrationEgressGuardV1 = Field(
        default_factory=HeldOutCalibrationEgressGuardV1
    )
    authority: HeldOutCalibrationAuthorityV1 = Field(default_factory=HeldOutCalibrationAuthorityV1)

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.configuration.split_sha256 != self.split.split_sha256:
            raise ValueError("result configuration is detached from its held-out split")
        if len(self.repetitions) != self.configuration.repetitions:
            raise ValueError("result repetition count differs from configuration")
        if tuple(item.repetition_index for item in self.repetitions) != tuple(
            range(self.configuration.repetitions)
        ):
            raise ValueError("result repetition indexes must be canonical and contiguous")
        expected_cases = _case_map_for_split(self.split)
        for repetition in self.repetitions:
            if (
                repetition.configuration_sha256 != self.configuration.configuration_sha256
                or repetition.provider != self.configuration.provider
                or repetition.budget != self.configuration.budget
            ):
                raise ValueError("repetition differs from the precommitted run configuration")
            _validate_repetition_cases(repetition, expected_cases)
        expected = _sha256_json(self.model_dump(mode="json", exclude={"result_sha256"}))
        if self.result_sha256 != expected:
            raise ValueError("held-out calibration result hash differs")
        return self

    def freeze_statement(self) -> Never:
        raise HeldOutCalibrationError(
            "held-out structural calibration cannot freeze a Builder statement"
        )

    def handoff_to_prover(self) -> Never:
        raise HeldOutCalibrationError(
            "held-out structural calibration cannot create a Prover handoff"
        )


def load_held_out_calibration_corpus(path: Path) -> VerifiedHeldOutCalibrationCorpus:
    """Verify the exact public synthetic corpus before it can be partitioned or evaluated."""

    resolved = path.resolve()
    if resolved != _canonical_corpus_path():
        raise HeldOutCalibrationError(
            "held-out calibration must load the canonical project-synthetic corpus "
            "in this repository"
        )
    corpus = load_local_calibration_fixture_corpus(resolved)
    if (
        corpus.provenance_class != "project_synthetic_fixture"
        or corpus.production_rights_cleared
        or corpus.promotion_allowed
        or any(
            sample.authority.model_egress_allowed
            or sample.authority.production_ingestion
            or sample.authority.prover_handoff_allowed
            for sample in corpus.samples
        )
    ):
        raise HeldOutCalibrationError(
            "held-out calibration accepts only the exact non-promotable project-synthetic fixtures"
        )
    manifest_path = resolved.with_name(_CORPUS_MANIFEST_NAME)
    root = resolved.parents[3]
    sample_bindings = tuple(
        sorted(
            (_sample_binding(sample) for sample in corpus.samples), key=lambda item: item.sample_id
        )
    )
    binding = HeldOutCalibrationCorpusBindingV1(
        corpus_sha256=_sha256_file(resolved),
        release_manifest_sha256=_sha256_file(manifest_path),
        repository_license_sha256=_sha256_file(root / "LICENSE"),
        sample_ids=tuple(item.sample_id for item in sample_bindings),
    )
    return VerifiedHeldOutCalibrationCorpus(
        corpus=corpus,
        binding=binding,
        sample_bindings=sample_bindings,
        token=_VERIFIED_CORPUS_TOKEN,
    )


def build_held_out_calibration_split(
    corpus: VerifiedHeldOutCalibrationCorpus,
    *,
    split_seed: str,
) -> HeldOutCalibrationSplitV1:
    """Build the V1 5/3/3 split from a verified capability and a recorded deterministic seed."""

    if not split_seed.strip():
        raise HeldOutCalibrationError("held-out calibration split seed cannot be blank")
    trusted_corpus = load_held_out_calibration_corpus(_canonical_corpus_path())
    if (
        corpus.binding != trusted_corpus.binding
        or corpus.sample_bindings != trusted_corpus.sample_bindings
    ):
        raise HeldOutCalibrationError(
            "provided held-out corpus capability differs from the canonical "
            "manifest-verified corpus"
        )
    corpus = trusted_corpus
    ranked = tuple(
        sorted(
            corpus.sample_bindings,
            key=lambda item: (
                _sha256_json(
                    {
                        "schema_version": "autolean.held-out-calibration-rank.v1",
                        "split_seed": split_seed,
                        "corpus_sha256": corpus.binding.corpus_sha256,
                        "sample_id": item.sample_id,
                        "source_sha256": item.source_sha256,
                    }
                ),
                item.sample_id,
            ),
        )
    )
    train = _build_partition(HeldOutCalibrationPartitionNameV1.TRAIN, ranked[:_TRAIN_COUNT])
    dev = _build_partition(
        HeldOutCalibrationPartitionNameV1.DEV,
        ranked[_TRAIN_COUNT : _TRAIN_COUNT + _DEV_COUNT],
    )
    held_out = _build_partition(
        HeldOutCalibrationPartitionNameV1.HELD_OUT, ranked[-_HELD_OUT_COUNT:]
    )
    egress_guard = HeldOutCalibrationEgressGuardV1()
    authority = HeldOutCalibrationAuthorityV1()
    return HeldOutCalibrationSplitV1(
        split_seed=split_seed,
        corpus=corpus.binding,
        train=train,
        dev=dev,
        held_out=held_out,
        split_sha256=_sha256_json(
            {
                "schema_version": "autolean.held-out-calibration-split.v1",
                "split_id": "project-synthetic-held-out-v1",
                "split_seed": split_seed,
                "corpus": corpus.binding,
                "train": train,
                "dev": dev,
                "held_out": held_out,
                "egress_guard": egress_guard,
                "authority": authority,
            }
        ),
        egress_guard=egress_guard,
        authority=authority,
    )


def verify_held_out_calibration_split(
    split: HeldOutCalibrationSplitV1,
    corpus: VerifiedHeldOutCalibrationCorpus,
) -> None:
    """Reject a syntactically valid split when it does not match the capability allocation."""

    trusted_corpus = load_held_out_calibration_corpus(_canonical_corpus_path())
    if (
        corpus.binding != trusted_corpus.binding
        or corpus.sample_bindings != trusted_corpus.sample_bindings
    ):
        raise HeldOutCalibrationError(
            "provided held-out corpus capability differs from the canonical "
            "manifest-verified corpus"
        )
    if split.corpus != trusted_corpus.binding:
        raise HeldOutCalibrationError("held-out split corpus binding differs from verified corpus")
    expected = build_held_out_calibration_split(trusted_corpus, split_seed=split.split_seed)
    if split != expected:
        raise HeldOutCalibrationError(
            "held-out split does not match its manifest-bound deterministic seed allocation"
        )


def build_held_out_calibration_run_config(
    split: HeldOutCalibrationSplitV1,
    *,
    run_id: str,
    repetition_seed: str,
    repetitions: int,
    provider: HeldOutCalibrationProvider,
    budget: HeldOutCalibrationBudgetV1,
) -> HeldOutCalibrationRunConfigV1:
    """Bind repeated-run seeds, the exact local provider, and fixed per-case budgets."""

    _validate_scripted_fake_provider(provider)
    descriptor = provider.descriptor()
    egress_guard = HeldOutCalibrationEgressGuardV1()
    authority = HeldOutCalibrationAuthorityV1()
    return HeldOutCalibrationRunConfigV1(
        run_id=run_id,
        split_sha256=split.split_sha256,
        repetitions=repetitions,
        repetition_seed=repetition_seed,
        provider=descriptor,
        budget=budget,
        configuration_sha256=_sha256_json(
            {
                "schema_version": "autolean.held-out-calibration-run-config.v1",
                "run_id": run_id,
                "split_sha256": split.split_sha256,
                "repetitions": repetitions,
                "repetition_seed": repetition_seed,
                "provider": descriptor,
                "budget": budget,
                "precommitted_before_held_out": True,
                "semantic_correctness_scoring_present": False,
                "egress_guard": egress_guard,
                "authority": authority,
            }
        ),
        egress_guard=egress_guard,
        authority=authority,
    )


def run_held_out_calibration(
    corpus: VerifiedHeldOutCalibrationCorpus,
    split: HeldOutCalibrationSplitV1,
    configuration: HeldOutCalibrationRunConfigV1,
    *,
    provider: HeldOutCalibrationProvider,
) -> HeldOutCalibrationResultV1:
    """Run the no-egress fake protocol and return structural-only repeated-run evidence."""

    verify_held_out_calibration_split(split, corpus)
    _validate_scripted_fake_provider(provider)
    if configuration.split_sha256 != split.split_sha256:
        raise HeldOutCalibrationError("run configuration is detached from the supplied split")
    if configuration.provider != provider.descriptor():
        raise HeldOutCalibrationError("run configuration provider differs from local fake provider")
    cases = _case_map_for_split(split)
    repetitions = tuple(
        _run_repetition(configuration, cases, provider, repetition_index=index)
        for index in range(configuration.repetitions)
    )
    egress_guard = HeldOutCalibrationEgressGuardV1()
    authority = HeldOutCalibrationAuthorityV1()
    return HeldOutCalibrationResultV1(
        split=split,
        configuration=configuration,
        repetitions=repetitions,
        result_sha256=_sha256_json(
            {
                "schema_version": "autolean.held-out-calibration-result.v1",
                "split": split,
                "configuration": configuration,
                "repetitions": repetitions,
                "structural_only": True,
                "statement_contract_present": False,
                "formalization_task_bundle_present": False,
                "semantic_correctness_claimed": False,
                "kernel_verification_present": False,
                "egress_guard": egress_guard,
                "authority": authority,
            }
        ),
        egress_guard=egress_guard,
        authority=authority,
    )


def _sample_binding(sample: PreCalibrationFixtureRecordV1) -> HeldOutCalibrationSampleBindingV1:
    if len(sample.source.spans) != 1:
        raise HeldOutCalibrationError(
            "project-synthetic calibration sample must have exactly one span"
        )
    source_span = sample.source.spans[0]
    mutations = tuple(sorted(_sha256_model(mutation) for mutation in sample.mutation_fixtures))
    return HeldOutCalibrationSampleBindingV1(
        sample_id=sample.sample_id,
        fixture_snapshot_sha256=_sha256_model(sample),
        source_sha256=sample.source.content_hash.value,
        source_span_sha256=source_span.content_hash.value,
        derived_mutation_sha256=mutations,
    )


def _build_partition(
    name: HeldOutCalibrationPartitionNameV1,
    samples: tuple[HeldOutCalibrationSampleBindingV1, ...],
) -> HeldOutCalibrationPartitionV1:
    canonical_samples = tuple(sorted(samples, key=lambda item: item.sample_id))
    authority = HeldOutCalibrationAuthorityV1()
    return HeldOutCalibrationPartitionV1(
        name=name,
        samples=canonical_samples,
        partition_sha256=_sha256_json(
            {
                "schema_version": "autolean.held-out-calibration-partition.v1",
                "name": name,
                "samples": canonical_samples,
                "authority": authority,
            }
        ),
        authority=authority,
    )


def _case_map_for_split(
    split: HeldOutCalibrationSplitV1,
) -> dict[HeldOutCalibrationPartitionNameV1, tuple[HeldOutCalibrationCaseV1, ...]]:
    result: dict[HeldOutCalibrationPartitionNameV1, tuple[HeldOutCalibrationCaseV1, ...]] = {}
    for partition_name in HeldOutCalibrationPartitionNameV1:
        partition = split.partition(partition_name)
        cases: list[HeldOutCalibrationCaseV1] = []
        for sample in partition.samples:
            for mutation_sha256 in sample.derived_mutation_sha256:
                raw_case_id = _sha256_json(
                    {
                        "schema_version": "autolean.held-out-calibration-case-id.v1",
                        "split_sha256": split.split_sha256,
                        "partition": partition_name,
                        "sample_id": sample.sample_id,
                        "mutation_sha256": mutation_sha256,
                    }
                )
                case_id = f"case-{raw_case_id[:24]}"
                egress_guard = HeldOutCalibrationEgressGuardV1()
                authority = HeldOutCalibrationAuthorityV1()
                cases.append(
                    HeldOutCalibrationCaseV1(
                        case_id=case_id,
                        partition=partition_name,
                        sample=sample,
                        mutation_sha256=mutation_sha256,
                        split_sha256=split.split_sha256,
                        case_sha256=_sha256_json(
                            {
                                "schema_version": "autolean.held-out-calibration-case.v1",
                                "case_id": case_id,
                                "partition": partition_name,
                                "sample": sample,
                                "mutation_sha256": mutation_sha256,
                                "split_sha256": split.split_sha256,
                                "source_text_present": False,
                                "semantic_label_present": False,
                                "egress_guard": egress_guard,
                                "authority": authority,
                            }
                        ),
                        egress_guard=egress_guard,
                        authority=authority,
                    )
                )
        result[partition_name] = tuple(sorted(cases, key=lambda item: item.case_id))
    return result


def _run_repetition(
    configuration: HeldOutCalibrationRunConfigV1,
    cases: Mapping[HeldOutCalibrationPartitionNameV1, tuple[HeldOutCalibrationCaseV1, ...]],
    provider: HeldOutCalibrationProvider,
    *,
    repetition_index: int,
) -> HeldOutCalibrationRepetitionV1:
    repetition_seed = _sha256_json(
        {
            "schema_version": "autolean.held-out-calibration-repetition-seed.v1",
            "configuration_sha256": configuration.configuration_sha256,
            "repetition_seed": configuration.repetition_seed,
            "repetition_index": repetition_index,
        }
    )
    outcomes: list[HeldOutCalibrationOutcomeV1] = []
    for partition_name in HeldOutCalibrationPartitionNameV1:
        for case in cases[partition_name]:
            request = _build_request(
                repetition_index=repetition_index,
                repetition_seed=repetition_seed,
                configuration=configuration,
                case=case,
            )
            response = provider.generate(request)
            outcomes.append(_score_response(request, response, configuration))
    ordered_outcomes = tuple(
        sorted(outcomes, key=lambda item: (item.partition.value, item.case.case_id))
    )
    scores = tuple(
        _score_partition(partition_name, ordered_outcomes)
        for partition_name in HeldOutCalibrationPartitionNameV1
    )
    authority = HeldOutCalibrationAuthorityV1()
    return HeldOutCalibrationRepetitionV1(
        repetition_index=repetition_index,
        repetition_seed=repetition_seed,
        configuration_sha256=configuration.configuration_sha256,
        provider=configuration.provider,
        budget=configuration.budget,
        outcomes=ordered_outcomes,
        partition_scores=scores,
        repetition_sha256=_sha256_json(
            {
                "schema_version": "autolean.held-out-calibration-repetition.v1",
                "repetition_index": repetition_index,
                "repetition_seed": repetition_seed,
                "configuration_sha256": configuration.configuration_sha256,
                "provider": configuration.provider,
                "budget": configuration.budget,
                "outcomes": ordered_outcomes,
                "partition_scores": scores,
                "authority": authority,
            }
        ),
        authority=authority,
    )


def _build_request(
    *,
    repetition_index: int,
    repetition_seed: str,
    configuration: HeldOutCalibrationRunConfigV1,
    case: HeldOutCalibrationCaseV1,
) -> HeldOutCalibrationRequestV1:
    egress_guard = HeldOutCalibrationEgressGuardV1()
    authority = HeldOutCalibrationAuthorityV1()
    return HeldOutCalibrationRequestV1(
        repetition_index=repetition_index,
        repetition_seed=repetition_seed,
        configuration_sha256=configuration.configuration_sha256,
        case=case,
        request_sha256=_sha256_json(
            {
                "schema_version": "autolean.held-out-calibration-request.v1",
                "repetition_index": repetition_index,
                "repetition_seed": repetition_seed,
                "configuration_sha256": configuration.configuration_sha256,
                "case": case,
                "source_text_present": False,
                "egress_guard": egress_guard,
                "authority": authority,
            }
        ),
        egress_guard=egress_guard,
        authority=authority,
    )


def _score_response(
    request: HeldOutCalibrationRequestV1,
    response: HeldOutCalibrationProviderResponseV1,
    configuration: HeldOutCalibrationRunConfigV1,
) -> HeldOutCalibrationOutcomeV1:
    if response.model_id != configuration.provider.model_id:
        raise HeldOutCalibrationError("local fake response model differs from configuration")
    if response.request_sha256 != request.request_sha256:
        raise HeldOutCalibrationError("local fake response is detached from request")
    response_bytes = response.text.encode("utf-8")
    if len(response_bytes) > configuration.budget.max_response_bytes:
        raise HeldOutCalibrationError("local fake response exceeds configured byte budget")
    if response.declared_input_tokens > configuration.budget.max_input_tokens:
        raise HeldOutCalibrationError("local fake response exceeds configured input-token budget")
    if response.declared_output_tokens > configuration.budget.max_output_tokens:
        raise HeldOutCalibrationError("local fake response exceeds configured output-token budget")
    parsed = _parse_assessment(response.text)
    json_compliant = parsed is not None and parsed.case_sha256 == request.case.case_sha256
    structural_drift_detected: bool | None = None
    advisory_consistent = False
    if json_compliant:
        assert parsed is not None
        structural_drift_detected = parsed.structural_drift_detected
        advisory_consistent = parsed.advisory_disposition == (
            "record_structural_drift" if parsed.structural_drift_detected else "no_structural_drift"
        )
    raw_response_sha256 = _sha256_bytes(response_bytes)
    budget_sha256 = configuration.budget.budget_sha256
    egress_guard = HeldOutCalibrationEgressGuardV1()
    authority = HeldOutCalibrationAuthorityV1()
    return HeldOutCalibrationOutcomeV1(
        partition=request.case.partition,
        case=request.case,
        request_sha256=request.request_sha256,
        provider=configuration.provider,
        budget_sha256=budget_sha256,
        raw_response_sha256=raw_response_sha256,
        response_bytes=len(response_bytes),
        declared_input_tokens=response.declared_input_tokens,
        declared_output_tokens=response.declared_output_tokens,
        json_compliant=json_compliant,
        structural_drift_detected=structural_drift_detected,
        advisory_consistent=advisory_consistent,
        outcome_sha256=_sha256_json(
            {
                "schema_version": "autolean.held-out-calibration-outcome.v1",
                "partition": request.case.partition,
                "case": request.case,
                "request_sha256": request.request_sha256,
                "provider": configuration.provider,
                "budget_sha256": budget_sha256,
                "raw_response_sha256": raw_response_sha256,
                "response_bytes": len(response_bytes),
                "declared_input_tokens": response.declared_input_tokens,
                "declared_output_tokens": response.declared_output_tokens,
                "json_compliant": json_compliant,
                "structural_drift_detected": structural_drift_detected,
                "advisory_consistent": advisory_consistent,
                "egress_guard": egress_guard,
                "authority": authority,
            }
        ),
        egress_guard=egress_guard,
        authority=authority,
    )


def _parse_assessment(text: str) -> HeldOutCalibrationAssessmentV1 | None:
    try:
        payload = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
        return HeldOutCalibrationAssessmentV1.model_validate(payload)
    except (json.JSONDecodeError, ValueError):
        return None


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise HeldOutCalibrationError(f"duplicate JSON key in fake response: {key}")
        result[key] = value
    return result


def _score_partition(
    partition: HeldOutCalibrationPartitionNameV1,
    outcomes: tuple[HeldOutCalibrationOutcomeV1, ...],
) -> HeldOutCalibrationPartitionScoreV1:
    partition_outcomes = tuple(item for item in outcomes if item.partition is partition)
    case_count = len(partition_outcomes)
    if not case_count:
        raise HeldOutCalibrationError("partition has no structural calibration cases")
    json_compliant_count = sum(item.json_compliant for item in partition_outcomes)
    structural_drift_detected_count = sum(
        item.structural_drift_detected is True for item in partition_outcomes
    )
    advisory_consistent_count = sum(item.advisory_consistent for item in partition_outcomes)
    return HeldOutCalibrationPartitionScoreV1(
        partition=partition,
        case_count=case_count,
        json_compliant_count=json_compliant_count,
        structural_drift_detected_count=structural_drift_detected_count,
        advisory_consistent_count=advisory_consistent_count,
        json_compliance_rate=json_compliant_count / case_count,
        structural_drift_detection_rate=structural_drift_detected_count / case_count,
        advisory_consistency_rate=advisory_consistent_count / case_count,
    )


def _validate_repetition_cases(
    repetition: HeldOutCalibrationRepetitionV1,
    expected_cases: Mapping[
        HeldOutCalibrationPartitionNameV1, tuple[HeldOutCalibrationCaseV1, ...]
    ],
) -> None:
    expected_by_case = {
        item.case_sha256: item
        for partition_cases in expected_cases.values()
        for item in partition_cases
    }
    actual_by_case = {item.case.case_sha256: item for item in repetition.outcomes}
    if len(actual_by_case) != len(repetition.outcomes) or set(actual_by_case) != set(
        expected_by_case
    ):
        raise ValueError("repetition cases differ from the exact partition-bound structural probes")
    for case_sha256, outcome in actual_by_case.items():
        expected_case = expected_by_case[case_sha256]
        if outcome.case != expected_case or outcome.partition is not expected_case.partition:
            raise ValueError("repetition outcome crosses a source, hash, or mutation partition")
    for score in repetition.partition_scores:
        partition_outcomes = tuple(
            item for item in repetition.outcomes if item.partition is score.partition
        )
        expected_score = _score_partition(score.partition, partition_outcomes)
        if score != expected_score:
            raise ValueError("repetition score differs from structural-only outcomes")


def _validate_scripted_fake_provider(provider: HeldOutCalibrationProvider) -> None:
    if type(provider) is not ScriptedFakeHeldOutCalibrationProvider:
        raise HeldOutCalibrationError(
            "V1 held-out calibration accepts only the exact no-egress scripted fake provider"
        )
