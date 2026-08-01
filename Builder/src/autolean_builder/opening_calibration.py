"""Non-promotable opening-sample calibration for Builder proposition conversion.

This module is deliberately *before* :mod:`autolean_builder.fidelity_harness`.
It can bind an exact local source snapshot, prepare independent conversion controls and
adversarial mutations, and score blind reviewer outputs.  It cannot create a
``StatementContractV1`` or a ``FormalizationTaskBundleV1``.  In particular, all reports are
``machine_advisory`` and every bridge-shaped output is an explicitly non-routable preparation
bundle.

The first corpus is the repository's project-synthetic opening corpus.  That is useful for
testing the conversion harness, but its restricted rights record prohibits model egress.  Real
textbook bytes can enter only through the normal source/right workflow; a missing cache is
represented by an explicit ``source_unavailable`` marker rather than invented quotations.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Never, Self

from autolean_contracts import (
    AmbiguityV1,
    HashKindV1,
    MutationKindV1,
    PermissionDecisionV1,
    RightsRecordV1,
    SourceRecordV1,
    canonical_json_bytes,
    digest_bytes,
)
from autolean_contracts.base import ContractModel
from pydantic import Field, model_validator

from .local_calibration import (
    PreCalibrationFixtureRecordV1,
    load_local_calibration_fixture_corpus,
)
from .machine_semantic_quorum import MachineReviewerSpec, MachineSemanticReviewRole

_IDENTIFIER = r"^[a-z][a-z0-9-]{2,127}$"
_REVIEWER_IDENTIFIER = r"^[a-z0-9][a-z0-9._-]{0,127}$"
_SHA256 = r"^[0-9a-f]{64}$"
_OPTION_IDENTIFIER = r"^option-[0-9a-f]{16}$"
_TASK_IDENTIFIER = r"^opening-calibration-[0-9a-f]{24}$"

# These are the mutation families whose absence must remain visible in an opening calibration
# report.  A particular source is not required to support all of them; pretending otherwise
# would turn a coverage gap into an artificial pass.
_REQUIRED_OPENING_MUTATION_KINDS = frozenset(
    {
        MutationKindV1.SWAP_QUANTIFIERS,
        MutationKindV1.WEAKEN_RELATION,
        MutationKindV1.DROP_NONEMPTY,
        MutationKindV1.DROP_FINITE,
        MutationKindV1.DROP_NOETHERIAN,
        MutationKindV1.REVERSE_PARAMETERS,
        MutationKindV1.VACUITY,
    }
)


class OpeningCalibrationError(ValueError):
    """An opening calibration artifact is malformed or attempts to gain authority."""


def _sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class OpeningCalibrationAuthorityV1(ContractModel):
    """The hard, shared authority boundary for all calibration artifacts."""

    authority: Literal["machine_advisory"] = "machine_advisory"
    may_freeze: Literal[False] = False
    semantic_review_claimed: Literal[False] = False
    prover_handoff_allowed: Literal[False] = False
    external_model_egress_allowed: Literal[False] = False
    promotion_allowed: Literal[False] = False


class OpeningCalibrationEgressGuardV1(ContractModel):
    """Typed denial capability: this calibration slice cannot authorize a provider request."""

    policy: Literal["deny_external_model_egress"] = "deny_external_model_egress"
    authorization_present: Literal[False] = False
    source_text_export_allowed: Literal[False] = False

    def serialize_for_external_model(self) -> Never:
        raise OpeningCalibrationError(
            "opening calibration has no external-model egress capability; source text may not be "
            "serialized for a provider"
        )


class FrozenOpeningCalibrationSourceV1(ContractModel):
    """An exact local source snapshot or an explicit no-byte marker.

    ``source_unavailable`` carries a known expected source hash if one exists, but never text,
    spans, or a synthetic source record.  It therefore cannot be accidentally converted into an
    executable calibration task.
    """

    schema_version: Literal["autolean.builder-opening-calibration-source.v1"] = (
        "autolean.builder-opening-calibration-source.v1"
    )
    sample_id: str = Field(pattern=_IDENTIFIER)
    provenance: Literal["project_synthetic_fixture", "source_unavailable"]
    source_record: SourceRecordV1 | None = None
    rights_record: RightsRecordV1 | None = None
    source_text: str | None = None
    unavailable_reference_id: str | None = None
    expected_source_sha256: str | None = Field(default=None, pattern=_SHA256)
    source_snapshot_sha256: str = Field(pattern=_SHA256)
    authority: OpeningCalibrationAuthorityV1 = Field(default_factory=OpeningCalibrationAuthorityV1)

    @model_validator(mode="after")
    def validate_source_boundary(self) -> Self:
        if self.provenance == "project_synthetic_fixture":
            if self.source_record is None or self.rights_record is None or self.source_text is None:
                raise ValueError(
                    "an exact calibration source requires its source record, rights record, "
                    "and text"
                )
            if self.unavailable_reference_id is not None:
                raise ValueError(
                    "an exact calibration source cannot carry an unavailable reference"
                )
            expected_hash = digest_bytes(
                HashKindV1.SOURCE_BYTES,
                self.source_text.encode("utf-8"),
            ).value
            if self.source_record.content_hash.value != expected_hash:
                raise ValueError("calibration source text does not match its source-record hash")
            if self.expected_source_sha256 != expected_hash:
                raise ValueError("calibration source expected hash differs from exact source bytes")
            if not self.source_record.spans:
                raise ValueError("an exact calibration source requires at least one source span")
            if self.rights_record.source_id != self.source_record.source_id:
                raise ValueError("calibration rights record is detached from the source record")
            if self.rights_record.model_egress is not PermissionDecisionV1.DENY:
                raise ValueError("opening calibration source must deny model egress")
        else:
            if (
                self.source_record is not None
                or self.rights_record is not None
                or self.source_text is not None
            ):
                raise ValueError(
                    "source_unavailable must not carry source bytes, a source record, or rights"
                )
            if not self.unavailable_reference_id or not self.expected_source_sha256:
                raise ValueError(
                    "source_unavailable requires a reference identifier and expected source hash"
                )
        expected_snapshot = _sha256_json(
            self.model_dump(mode="json", exclude={"source_snapshot_sha256"})
        )
        if self.source_snapshot_sha256 != expected_snapshot:
            raise ValueError("calibration source snapshot hash is inconsistent")
        return self

    @property
    def exact_bytes_available(self) -> bool:
        return self.provenance == "project_synthetic_fixture"

    def serialize_for_external_model(self) -> Never:
        OpeningCalibrationEgressGuardV1().serialize_for_external_model()


class CalibrationSemanticProjectionV1(ContractModel):
    """The structured mathematical projection reviewers compare, not a frozen contract."""

    normalized_claim: str = Field(min_length=1)
    quantifier_order: tuple[str, ...] = Field(min_length=1)
    assumptions: tuple[str, ...] = ()
    conclusion: str = Field(min_length=1)
    boundary_conditions: tuple[str, ...] = ()
    ambiguities: tuple[AmbiguityV1, ...] = ()
    reverse_rendering: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_projection(self) -> Self:
        if any(not item.strip() for item in self.quantifier_order):
            raise ValueError("calibration quantifier order contains an empty field")
        if any(not item.strip() for item in self.assumptions):
            raise ValueError("calibration assumptions contain an empty field")
        if any(not item.strip() for item in self.boundary_conditions):
            raise ValueError("calibration boundary conditions contain an empty field")
        ambiguity_ids = [item.ambiguity_id.value for item in self.ambiguities]
        if len(ambiguity_ids) != len(set(ambiguity_ids)):
            raise ValueError("calibration ambiguities must have unique identifiers")
        return self

    @property
    def snapshot_sha256(self) -> str:
        return _sha256_json(self.model_dump(mode="json"))


class OpeningCalibrationCandidateV1(ContractModel):
    """One independently authored, explicitly unparsed conversion candidate."""

    schema_version: Literal["autolean.builder-opening-calibration-candidate.v1"] = (
        "autolean.builder-opening-calibration-candidate.v1"
    )
    candidate_id: str = Field(pattern=_IDENTIFIER)
    source_sample_id: str = Field(pattern=_IDENTIFIER)
    declared_independence_label: str = Field(min_length=1)
    candidate_source: str = Field(min_length=1)
    candidate_source_sha256: str = Field(pattern=_SHA256)
    semantic_projection: CalibrationSemanticProjectionV1
    candidate_kind: Literal["illustrative_unparsed_text"] = "illustrative_unparsed_text"
    lean_parsed: Literal[False] = False
    semantic_binding_claimed: Literal[False] = False
    authority: OpeningCalibrationAuthorityV1 = Field(default_factory=OpeningCalibrationAuthorityV1)

    @model_validator(mode="after")
    def validate_candidate(self) -> Self:
        if _sha256_text(self.candidate_source) != self.candidate_source_sha256:
            raise ValueError("candidate source hash is inconsistent")
        return self

    def serialize_for_external_model(self) -> Never:
        OpeningCalibrationEgressGuardV1().serialize_for_external_model()


class OpeningCalibrationMutationV1(ContractModel):
    """A source-bound adversarial alternative whose expected rejection is private at review time."""

    schema_version: Literal["autolean.builder-opening-calibration-mutation.v1"] = (
        "autolean.builder-opening-calibration-mutation.v1"
    )
    mutation_id: str = Field(pattern=_IDENTIFIER)
    source_sample_id: str = Field(pattern=_IDENTIFIER)
    kind: MutationKindV1
    baseline_claim_sha256: str = Field(pattern=_SHA256)
    mutated_claim: str = Field(min_length=1)
    mutated_claim_sha256: str = Field(pattern=_SHA256)
    expected_rejection_reason: str = Field(min_length=1)
    authority: OpeningCalibrationAuthorityV1 = Field(default_factory=OpeningCalibrationAuthorityV1)

    @model_validator(mode="after")
    def validate_mutation(self) -> Self:
        if _sha256_text(self.mutated_claim) != self.mutated_claim_sha256:
            raise ValueError("calibration mutation claim hash is inconsistent")
        return self


class OpeningCalibrationSampleV1(ContractModel):
    """A source-locked opening proposition and its non-authoritative controls."""

    schema_version: Literal["autolean.builder-opening-calibration-sample.v1"] = (
        "autolean.builder-opening-calibration-sample.v1"
    )
    sample_id: str = Field(pattern=_IDENTIFIER)
    source: FrozenOpeningCalibrationSourceV1
    semantic_projection: CalibrationSemanticProjectionV1 | None = None
    candidates: tuple[OpeningCalibrationCandidateV1, ...] = ()
    mutations: tuple[OpeningCalibrationMutationV1, ...] = ()
    positive_examples: tuple[str, ...] = ()
    negative_examples: tuple[str, ...] = ()
    sample_snapshot_sha256: str = Field(pattern=_SHA256)
    authority: OpeningCalibrationAuthorityV1 = Field(default_factory=OpeningCalibrationAuthorityV1)

    @model_validator(mode="after")
    def validate_sample(self) -> Self:
        if self.source.sample_id != self.sample_id:
            raise ValueError("calibration sample id must bind its frozen source")
        if self.source.exact_bytes_available:
            if self.semantic_projection is None:
                raise ValueError("an exact calibration sample requires a semantic projection")
            if len(self.candidates) < 2:
                raise ValueError("an exact calibration sample requires two independent candidates")
            if not self.mutations:
                raise ValueError("an exact calibration sample requires a declared mutation")
            if not self.positive_examples or not self.negative_examples:
                raise ValueError(
                    "an exact calibration sample requires positive and negative examples"
                )
            candidate_ids = [item.candidate_id for item in self.candidates]
            candidate_sources = [item.candidate_source_sha256 for item in self.candidates]
            candidate_labels = [item.declared_independence_label for item in self.candidates]
            if len(candidate_ids) != len(set(candidate_ids)):
                raise ValueError("calibration candidate identifiers must be unique")
            if len(candidate_sources) != len(set(candidate_sources)):
                raise ValueError("calibration candidate sources must be distinct")
            if len(candidate_labels) < 2 or len(set(candidate_labels)) < 2:
                raise ValueError("calibration candidates require two declared independence labels")
            if any(item.source_sample_id != self.sample_id for item in self.candidates):
                raise ValueError("candidate source sample id is detached from its sample")
            baseline_sha = _sha256_text(self.semantic_projection.normalized_claim)
            mutation_ids = [item.mutation_id for item in self.mutations]
            if len(mutation_ids) != len(set(mutation_ids)):
                raise ValueError("calibration mutation identifiers must be unique")
            if any(
                item.source_sample_id != self.sample_id
                or item.baseline_claim_sha256 != baseline_sha
                or item.mutated_claim == self.semantic_projection.normalized_claim
                for item in self.mutations
            ):
                raise ValueError("calibration mutation is detached from the baseline claim")
        elif any(
            (
                self.semantic_projection is not None,
                self.candidates,
                self.mutations,
                self.positive_examples,
                self.negative_examples,
            )
        ):
            raise ValueError(
                "a source-unavailable sample must not invent a proposition or controls"
            )
        expected_snapshot = _sha256_json(
            self.model_dump(mode="json", exclude={"sample_snapshot_sha256"})
        )
        if self.sample_snapshot_sha256 != expected_snapshot:
            raise ValueError("calibration sample snapshot hash is inconsistent")
        return self

    @property
    def available_mutation_kinds(self) -> frozenset[MutationKindV1]:
        return frozenset(item.kind for item in self.mutations)

    @property
    def missing_required_mutation_kinds(self) -> tuple[MutationKindV1, ...]:
        return tuple(
            sorted(_REQUIRED_OPENING_MUTATION_KINDS - self.available_mutation_kinds, key=str)
        )

    def serialize_for_external_model(self) -> Never:
        OpeningCalibrationEgressGuardV1().serialize_for_external_model()


class OpeningCalibrationBlindOptionV1(ContractModel):
    """A text-free blind option suitable for storage and event projection.

    The candidate claim is committed into the fingerprint but is deliberately not serialized here.
    This prevents this preparation artifact from becoming an accidental source-text egress bundle.
    """

    option_id: str = Field(pattern=_OPTION_IDENTIFIER)
    option_fingerprint_sha256: str = Field(pattern=_SHA256)


class OpeningCalibrationReviewTaskV1(ContractModel):
    """A text-free, non-egress blind task for one machine reviewer role."""

    schema_version: Literal["autolean.builder-opening-calibration-review-task.v1"] = (
        "autolean.builder-opening-calibration-review-task.v1"
    )
    task_id: str = Field(pattern=_TASK_IDENTIFIER)
    task_fingerprint_sha256: str = Field(pattern=_SHA256)
    reviewer_id: str = Field(pattern=_REVIEWER_IDENTIFIER)
    role: MachineSemanticReviewRole
    reviewer_binding_sha256: str = Field(pattern=_SHA256)
    sample_id: str = Field(pattern=_IDENTIFIER)
    source_snapshot_sha256: str = Field(pattern=_SHA256)
    source_claim_sha256: str = Field(pattern=_SHA256)
    source_quantifier_count: int = Field(ge=1)
    source_assumption_count: int = Field(ge=0)
    source_boundary_condition_count: int = Field(ge=0)
    source_ambiguity_count: int = Field(ge=0)
    positive_example_count: int = Field(ge=1)
    negative_example_count: int = Field(ge=1)
    options: tuple[OpeningCalibrationBlindOptionV1, ...] = Field(min_length=2)
    randomization_commitment_sha256: str = Field(pattern=_SHA256)
    local_text_material_present: Literal[False] = False
    egress_guard: OpeningCalibrationEgressGuardV1 = Field(
        default_factory=OpeningCalibrationEgressGuardV1
    )
    authority: OpeningCalibrationAuthorityV1 = Field(default_factory=OpeningCalibrationAuthorityV1)

    @model_validator(mode="after")
    def validate_task(self) -> Self:
        option_ids = [item.option_id for item in self.options]
        option_hashes = [item.option_fingerprint_sha256 for item in self.options]
        if len(option_ids) != len(set(option_ids)) or len(option_hashes) != len(set(option_hashes)):
            raise ValueError("blind calibration task options must be unique")
        expected_task = _sha256_json(
            self.model_dump(
                mode="json",
                exclude={"task_fingerprint_sha256", "task_id"},
            )
        )
        if self.task_fingerprint_sha256 != expected_task:
            raise ValueError("blind calibration task fingerprint is inconsistent")
        expected_id = "opening-calibration-" + expected_task[:24]
        if self.task_id != expected_id:
            raise ValueError("blind calibration task id is inconsistent")
        return self

    def authorize_external_model_egress(self) -> Never:
        self.egress_guard.serialize_for_external_model()

    def serialize_for_external_model(self) -> Never:
        self.egress_guard.serialize_for_external_model()


class OpeningCalibrationOptionFindingV1(ContractModel):
    option_id: str = Field(pattern=_OPTION_IDENTIFIER)
    option_fingerprint_sha256: str = Field(pattern=_SHA256)
    preserves_source_meaning: bool
    rationale: str = Field(min_length=1)


class OpeningCalibrationReviewVerdictV1(ContractModel):
    """A structurally bound but execution-unverified machine reviewer response."""

    schema_version: Literal["autolean.builder-opening-calibration-review-verdict.v1"] = (
        "autolean.builder-opening-calibration-review-verdict.v1"
    )
    task_id: str = Field(pattern=_TASK_IDENTIFIER)
    task_fingerprint_sha256: str = Field(pattern=_SHA256)
    reviewer_id: str = Field(pattern=_REVIEWER_IDENTIFIER)
    source_to_candidate_equivalent: bool
    positive_examples_valid: bool
    negative_examples_valid: bool
    non_vacuous: bool
    option_findings: tuple[OpeningCalibrationOptionFindingV1, ...] = Field(min_length=2)
    rationale: str = Field(min_length=1)
    execution_state: Literal["unverified_local_synthetic_response"] = (
        "unverified_local_synthetic_response"
    )
    authority: OpeningCalibrationAuthorityV1 = Field(default_factory=OpeningCalibrationAuthorityV1)

    @model_validator(mode="after")
    def validate_verdict(self) -> Self:
        option_ids = [item.option_id for item in self.option_findings]
        if len(option_ids) != len(set(option_ids)):
            raise ValueError("calibration verdict must score each option at most once")
        return self

    @property
    def artifact_sha256(self) -> str:
        return _sha256_json(self.model_dump(mode="json"))


@dataclass(frozen=True, slots=True)
class _OpeningCalibrationLocalMaterial:
    task_id: str
    option_claims: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class PreparedOpeningCalibrationRun:
    """Private local material paired with text-free cross-boundary task DTOs.

    This type deliberately offers no model payload exporter.  It is a local process preparation
    object, not a provider authorization or a cross-boundary source-text artifact.
    """

    sample: OpeningCalibrationSampleV1
    reviewers: tuple[MachineReviewerSpec, ...]
    tasks: tuple[OpeningCalibrationReviewTaskV1, ...]
    randomization_commitment_sha256: str
    preparation_fingerprint_sha256: str
    _local_material: tuple[_OpeningCalibrationLocalMaterial, ...]

    @property
    def authority(self) -> Literal["machine_advisory"]:
        return "machine_advisory"

    @property
    def may_freeze(self) -> Literal[False]:
        return False

    def authorize_external_model_egress(self) -> Never:
        OpeningCalibrationEgressGuardV1().serialize_for_external_model()

    def _claims_for_task(self, task_id: str) -> dict[str, str]:
        material = next((item for item in self._local_material if item.task_id == task_id), None)
        if material is None:
            raise OpeningCalibrationError(
                "opening calibration local material is detached from task"
            )
        return dict(material.option_claims)


class OpeningCalibrationReportV1(ContractModel):
    """Score summary with explicit coverage and authority limitations."""

    schema_version: Literal["autolean.builder-opening-calibration-report.v1"] = (
        "autolean.builder-opening-calibration-report.v1"
    )
    sample_id: str = Field(pattern=_IDENTIFIER)
    sample_snapshot_sha256: str = Field(pattern=_SHA256)
    preparation_fingerprint_sha256: str = Field(pattern=_SHA256)
    reviewer_binding_sha256: tuple[str, ...] = Field(min_length=3)
    reviewer_verdict_artifact_sha256: tuple[str, ...] = Field(min_length=3)
    reviewer_profile_agreement: bool
    semantic_controls_accepted: bool
    mutations_rejected: bool
    declared_checks_passed: bool
    observed_advisory_checks_passed: bool
    mutation_coverage_complete: bool
    unverified_advisory_checks_passed: bool
    covered_mutation_kinds: tuple[MutationKindV1, ...]
    missing_required_mutation_kinds: tuple[MutationKindV1, ...]
    blockers: tuple[str, ...] = Field(min_length=1)
    authority: OpeningCalibrationAuthorityV1 = Field(default_factory=OpeningCalibrationAuthorityV1)
    execution_evidence_verified: Literal[False] = False
    report_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        if len(self.reviewer_binding_sha256) != len(set(self.reviewer_binding_sha256)):
            raise ValueError("calibration reviewer bindings must be unique")
        if tuple(sorted(set(self.covered_mutation_kinds), key=str)) != self.covered_mutation_kinds:
            raise ValueError("covered calibration mutation kinds must be sorted and unique")
        if (
            tuple(sorted(set(self.missing_required_mutation_kinds), key=str))
            != self.missing_required_mutation_kinds
        ):
            raise ValueError("missing calibration mutation kinds must be sorted and unique")
        if set(self.covered_mutation_kinds) & set(self.missing_required_mutation_kinds):
            raise ValueError("covered and missing calibration mutation kinds overlap")
        expected_missing = _REQUIRED_OPENING_MUTATION_KINDS - set(self.covered_mutation_kinds)
        if set(self.missing_required_mutation_kinds) != expected_missing:
            raise ValueError(
                "calibration mutation coverage does not match the required mutation set"
            )
        if self.mutation_coverage_complete != (not self.missing_required_mutation_kinds):
            raise ValueError(
                "calibration coverage-complete flag is inconsistent with missing kinds"
            )
        if self.unverified_advisory_checks_passed != (
            self.observed_advisory_checks_passed and self.mutation_coverage_complete
        ):
            raise ValueError(
                "coverage-incomplete calibration cannot claim an unverified advisory pass"
            )
        expected = _sha256_json(self.model_dump(mode="json", exclude={"report_sha256"}))
        if self.report_sha256 != expected:
            raise ValueError("calibration report hash is inconsistent")
        return self


class StandardBridgePreparationBundleV1(ContractModel):
    """A bridge-shaped checklist, never ``FormalizationTaskBundleV1`` itself."""

    schema_version: Literal["autolean.builder-standard-bridge-preparation.v1"] = (
        "autolean.builder-standard-bridge-preparation.v1"
    )
    target_bundle_schema: Literal["autolean.formalization-task-bundle.v1"] = (
        "autolean.formalization-task-bundle.v1"
    )
    sample_id: str = Field(pattern=_IDENTIFIER)
    source_snapshot_sha256: str = Field(pattern=_SHA256)
    calibration_report_sha256: str = Field(pattern=_SHA256)
    candidate_source_sha256: tuple[str, ...] = Field(min_length=2)
    required_next_builder_gates: tuple[str, ...] = Field(min_length=1)
    blockers: tuple[str, ...] = Field(min_length=1)
    statement_contract_present: Literal[False] = False
    formalization_task_bundle_present: Literal[False] = False
    authority: OpeningCalibrationAuthorityV1 = Field(default_factory=OpeningCalibrationAuthorityV1)

    def assert_not_routable(self) -> Never:
        raise OpeningCalibrationError(
            "opening calibration preparation cannot enter the standard bridge; create a reviewed "
            "frozen StatementContractV1 and FormalizationTaskBundleV1 through Builder first"
        )


def _projection_from_fixture(
    fixture: PreCalibrationFixtureRecordV1,
) -> CalibrationSemanticProjectionV1:
    if not fixture.illustrative_lean_snippets:
        raise OpeningCalibrationError("fixture does not contain reverse-rendering evidence")
    return CalibrationSemanticProjectionV1(
        normalized_claim=fixture.normalized.normalized_statement,
        quantifier_order=fixture.normalized.quantifiers,
        assumptions=fixture.normalized.assumptions,
        conclusion=fixture.normalized.conclusion,
        boundary_conditions=fixture.normalized.edge_cases,
        ambiguities=fixture.ambiguities,
        reverse_rendering=fixture.illustrative_lean_snippets[0].reverse_rendering,
    )


def _source_from_fixture(
    fixture: PreCalibrationFixtureRecordV1,
) -> FrozenOpeningCalibrationSourceV1:
    payload: dict[str, object] = {
        "schema_version": "autolean.builder-opening-calibration-source.v1",
        "sample_id": fixture.sample_id,
        "provenance": "project_synthetic_fixture",
        "source_record": fixture.source.model_dump(mode="json"),
        "rights_record": fixture.rights.model_dump(mode="json"),
        "source_text": fixture.source_text,
        "unavailable_reference_id": None,
        "expected_source_sha256": fixture.source.content_hash.value,
    }
    payload["source_snapshot_sha256"] = _sha256_json(
        {**payload, "authority": OpeningCalibrationAuthorityV1().model_dump(mode="json")}
    )
    return FrozenOpeningCalibrationSourceV1.model_validate(payload)


def opening_calibration_sample_from_fixture(
    fixture: PreCalibrationFixtureRecordV1,
) -> OpeningCalibrationSampleV1:
    """Turn one exact local fixture into a calibration sample without changing its authority."""

    source = _source_from_fixture(fixture)
    projection = _projection_from_fixture(fixture)
    candidates = tuple(
        OpeningCalibrationCandidateV1(
            candidate_id=item.snippet_id,
            source_sample_id=fixture.sample_id,
            declared_independence_label=item.declared_independence_label,
            candidate_source=item.illustrative_lean_snippet,
            candidate_source_sha256=item.snapshot_sha256,
            semantic_projection=projection,
        )
        for item in fixture.illustrative_lean_snippets
    )
    baseline_claim = projection.normalized_claim
    baseline_hash = _sha256_text(baseline_claim)
    mutations: list[OpeningCalibrationMutationV1] = []
    for item in fixture.mutation_fixtures:
        if baseline_claim.count(item.baseline_fragment) != 1:
            raise OpeningCalibrationError(
                "fixture mutation baseline must occur exactly once in the normalized claim"
            )
        mutated_claim = baseline_claim.replace(item.baseline_fragment, item.mutated_fragment, 1)
        mutations.append(
            OpeningCalibrationMutationV1(
                mutation_id=(f"{fixture.sample_id}-{item.probe.kind.value.replace('_', '-')}"),
                source_sample_id=fixture.sample_id,
                kind=item.probe.kind,
                baseline_claim_sha256=baseline_hash,
                mutated_claim=mutated_claim,
                mutated_claim_sha256=_sha256_text(mutated_claim),
                expected_rejection_reason=item.blocker_reason,
            )
        )
    payload: dict[str, object] = {
        "schema_version": "autolean.builder-opening-calibration-sample.v1",
        "sample_id": fixture.sample_id,
        "source": source.model_dump(mode="json"),
        "semantic_projection": projection.model_dump(mode="json"),
        "candidates": [item.model_dump(mode="json") for item in candidates],
        "mutations": [item.model_dump(mode="json") for item in mutations],
        "positive_examples": [item.description for item in fixture.positive_examples],
        "negative_examples": [item.description for item in fixture.negative_examples],
    }
    payload["sample_snapshot_sha256"] = _sha256_json(
        {**payload, "authority": OpeningCalibrationAuthorityV1().model_dump(mode="json")}
    )
    return OpeningCalibrationSampleV1.model_validate(payload)


def source_unavailable_opening_calibration_sample(
    *,
    sample_id: str,
    reference_id: str,
    expected_source_sha256: str,
) -> OpeningCalibrationSampleV1:
    """Record missing source bytes without inventing quotations, candidates, or mutations."""

    source_payload: dict[str, object] = {
        "schema_version": "autolean.builder-opening-calibration-source.v1",
        "sample_id": sample_id,
        "provenance": "source_unavailable",
        "source_record": None,
        "rights_record": None,
        "source_text": None,
        "unavailable_reference_id": reference_id,
        "expected_source_sha256": expected_source_sha256,
    }
    source_payload["source_snapshot_sha256"] = _sha256_json(
        {**source_payload, "authority": OpeningCalibrationAuthorityV1().model_dump(mode="json")}
    )
    source = FrozenOpeningCalibrationSourceV1.model_validate(source_payload)
    payload: dict[str, object] = {
        "schema_version": "autolean.builder-opening-calibration-sample.v1",
        "sample_id": sample_id,
        "source": source.model_dump(mode="json"),
        "semantic_projection": None,
        "candidates": [],
        "mutations": [],
        "positive_examples": [],
        "negative_examples": [],
    }
    payload["sample_snapshot_sha256"] = _sha256_json(
        {**payload, "authority": OpeningCalibrationAuthorityV1().model_dump(mode="json")}
    )
    return OpeningCalibrationSampleV1.model_validate(payload)


def load_project_synthetic_opening_calibration_samples(
    path: str | Path,
) -> tuple[OpeningCalibrationSampleV1, ...]:
    """Load the fixed local opening corpus and derive only non-promotable calibration DTOs."""

    corpus = load_local_calibration_fixture_corpus(Path(path))
    return tuple(opening_calibration_sample_from_fixture(item) for item in corpus.samples)


def _validate_reviewers(
    sample: OpeningCalibrationSampleV1,
    reviewers: tuple[MachineReviewerSpec, ...],
) -> tuple[MachineReviewerSpec, ...]:
    if len(reviewers) < 3 or {item.role for item in reviewers} < set(MachineSemanticReviewRole):
        raise OpeningCalibrationError(
            "opening calibration requires the three semantic review roles"
        )
    reviewer_ids = [item.reviewer_id for item in reviewers]
    groups = [item.independence_group for item in reviewers]
    environments = [item.role_environment_hash.value for item in reviewers]
    run_ids = [item.run_id for item in reviewers]
    if any(
        len(values) != len(set(values)) for values in (reviewer_ids, groups, environments, run_ids)
    ):
        raise OpeningCalibrationError(
            "opening calibration reviewer ids, groups, environments, and runs must be unique"
        )
    if len({item.declared_failure_domain_id for item in reviewers}) < 2:
        raise OpeningCalibrationError("opening calibration requires two declared failure domains")
    candidate_groups = {item.declared_independence_label for item in sample.candidates}
    if candidate_groups & set(groups):
        raise OpeningCalibrationError("reviewer group overlaps a candidate independence group")
    return tuple(sorted(reviewers, key=lambda item: (item.reviewer_id, item.role.value)))


def _randomization_commitment(seed: bytes) -> str:
    if not isinstance(seed, bytes) or len(seed) < 32:
        raise OpeningCalibrationError(
            "opening calibration randomization seed must contain 32 bytes"
        )
    return hashlib.sha256(b"autolean.opening-calibration.seed.v1\x00" + seed).hexdigest()


def _reviewer_binding_sha256(reviewer: MachineReviewerSpec) -> str:
    """Bind declared reviewer isolation metadata without exporting it in a task DTO."""

    return _sha256_json(
        {
            "schema_version": "autolean.builder-opening-calibration-reviewer-binding.v1",
            "reviewer_id": reviewer.reviewer_id,
            "role": reviewer.role.value,
            "independence_group": reviewer.independence_group,
            "declared_failure_domain_id": reviewer.declared_failure_domain_id,
            "role_environment_hash": reviewer.role_environment_hash.model_dump(mode="json"),
            "run_id": reviewer.run_id,
        }
    )


def _origin_fingerprint(kind: str, claim: str, source_hashes: tuple[str, ...]) -> str:
    return _sha256_json(
        {
            "schema_version": "autolean.builder-opening-calibration-origin.v1",
            "kind": kind,
            "claim": claim,
            "source_hashes": list(sorted(source_hashes)),
        }
    )


def _blind_option(
    *,
    seed: bytes,
    reviewer_id: str,
    origin_fingerprint: str,
    claim: str,
) -> tuple[OpeningCalibrationBlindOptionV1, bytes]:
    alias_bytes = hmac.new(
        seed,
        f"autolean.opening-calibration.option.v1:{reviewer_id}:{origin_fingerprint}".encode(),
        hashlib.sha256,
    ).digest()
    option_id = "option-" + alias_bytes.hex()[:16]
    payload = {
        "schema_version": "autolean.builder-opening-calibration-blind-option.v1",
        "option_id": option_id,
        "candidate_claim": claim,
    }
    return (
        OpeningCalibrationBlindOptionV1(
            option_id=option_id,
            option_fingerprint_sha256=_sha256_json(payload),
        ),
        hmac.new(
            seed,
            f"autolean.opening-calibration.order.v1:{reviewer_id}:{origin_fingerprint}".encode(),
            hashlib.sha256,
        ).digest(),
    )


def prepare_opening_calibration(
    sample: OpeningCalibrationSampleV1,
    *,
    reviewers: tuple[MachineReviewerSpec, ...],
    randomization_seed: bytes,
) -> PreparedOpeningCalibrationRun:
    """Prepare blind local tasks; this function performs no model call or egress authorization."""

    if not sample.source.exact_bytes_available:
        raise OpeningCalibrationError("source-unavailable sample cannot prepare a calibration task")
    if sample.semantic_projection is None:
        raise OpeningCalibrationError("exact calibration sample lost its semantic projection")
    ordered_reviewers = _validate_reviewers(sample, reviewers)
    commitment = _randomization_commitment(randomization_seed)
    origins: list[tuple[str, str]] = [
        (
            _origin_fingerprint(
                "independent_conversion_control",
                candidate.semantic_projection.normalized_claim,
                (candidate.candidate_source_sha256,),
            ),
            candidate.semantic_projection.normalized_claim,
        )
        for candidate in sample.candidates
    ]
    origins.extend(
        (
            _origin_fingerprint(
                "adversarial_mutation", item.mutated_claim, (item.mutated_claim_sha256,)
            ),
            item.mutated_claim,
        )
        for item in sample.mutations
    )
    if len({item[0] for item in origins}) != len(origins):
        raise OpeningCalibrationError("opening calibration origins must be unique")

    tasks: list[OpeningCalibrationReviewTaskV1] = []
    local_material: list[_OpeningCalibrationLocalMaterial] = []
    for reviewer in ordered_reviewers:
        reviewer_binding = _reviewer_binding_sha256(reviewer)
        rows: list[tuple[bytes, OpeningCalibrationBlindOptionV1, str]] = []
        for origin, claim in origins:
            option, ordering = _blind_option(
                seed=randomization_seed,
                reviewer_id=reviewer.reviewer_id,
                origin_fingerprint=origin,
                claim=claim,
            )
            rows.append((ordering, option, claim))
        rows.sort(key=lambda item: item[0])
        options = tuple(item[1] for item in rows)
        task_payload: dict[str, object] = {
            "reviewer_id": reviewer.reviewer_id,
            "role": reviewer.role.value,
            "reviewer_binding_sha256": reviewer_binding,
            "sample_id": sample.sample_id,
            "source_snapshot_sha256": sample.source.source_snapshot_sha256,
            "source_claim_sha256": _sha256_text(sample.semantic_projection.normalized_claim),
            "source_quantifier_count": len(sample.semantic_projection.quantifier_order),
            "source_assumption_count": len(sample.semantic_projection.assumptions),
            "source_boundary_condition_count": len(sample.semantic_projection.boundary_conditions),
            "source_ambiguity_count": len(sample.semantic_projection.ambiguities),
            "positive_example_count": len(sample.positive_examples),
            "negative_example_count": len(sample.negative_examples),
            "options": [item.model_dump(mode="json") for item in options],
            "randomization_commitment_sha256": commitment,
            "local_text_material_present": False,
            "egress_guard": OpeningCalibrationEgressGuardV1().model_dump(mode="json"),
            "authority": OpeningCalibrationAuthorityV1().model_dump(mode="json"),
        }
        task_fingerprint = _sha256_json(
            {
                "schema_version": "autolean.builder-opening-calibration-review-task.v1",
                **task_payload,
            }
        )
        task = OpeningCalibrationReviewTaskV1(
            task_id="opening-calibration-" + task_fingerprint[:24],
            task_fingerprint_sha256=task_fingerprint,
            reviewer_id=reviewer.reviewer_id,
            role=reviewer.role,
            reviewer_binding_sha256=reviewer_binding,
            sample_id=sample.sample_id,
            source_snapshot_sha256=sample.source.source_snapshot_sha256,
            source_claim_sha256=_sha256_text(sample.semantic_projection.normalized_claim),
            source_quantifier_count=len(sample.semantic_projection.quantifier_order),
            source_assumption_count=len(sample.semantic_projection.assumptions),
            source_boundary_condition_count=len(sample.semantic_projection.boundary_conditions),
            source_ambiguity_count=len(sample.semantic_projection.ambiguities),
            positive_example_count=len(sample.positive_examples),
            negative_example_count=len(sample.negative_examples),
            options=options,
            randomization_commitment_sha256=commitment,
        )
        tasks.append(task)
        local_material.append(
            _OpeningCalibrationLocalMaterial(
                task_id=task.task_id,
                option_claims=tuple((option.option_id, claim) for _, option, claim in rows),
            )
        )
    preparation_payload = {
        "schema_version": "autolean.builder-opening-calibration-preparation.v1",
        "sample_snapshot_sha256": sample.sample_snapshot_sha256,
        "reviewer_ids": [item.reviewer_id for item in ordered_reviewers],
        "reviewer_binding_sha256": [_reviewer_binding_sha256(item) for item in ordered_reviewers],
        "task_fingerprints": [item.task_fingerprint_sha256 for item in tasks],
        "randomization_commitment_sha256": commitment,
    }
    return PreparedOpeningCalibrationRun(
        sample=sample,
        reviewers=ordered_reviewers,
        tasks=tuple(tasks),
        randomization_commitment_sha256=commitment,
        preparation_fingerprint_sha256=_sha256_json(preparation_payload),
        _local_material=tuple(local_material),
    )


def _validate_verdict_against_task(
    task: OpeningCalibrationReviewTaskV1,
    verdict: OpeningCalibrationReviewVerdictV1,
) -> None:
    if (
        verdict.task_id != task.task_id
        or verdict.task_fingerprint_sha256 != task.task_fingerprint_sha256
    ):
        raise OpeningCalibrationError("calibration verdict targets another prepared task")
    if verdict.reviewer_id != task.reviewer_id:
        raise OpeningCalibrationError("calibration verdict targets another reviewer")
    findings = {item.option_id: item for item in verdict.option_findings}
    task_options = {item.option_id: item for item in task.options}
    if set(findings) != set(task_options):
        raise OpeningCalibrationError("calibration verdict must score every blind option once")
    if any(
        findings[option_id].option_fingerprint_sha256 != option.option_fingerprint_sha256
        for option_id, option in task_options.items()
    ):
        raise OpeningCalibrationError("calibration verdict changes a blind option fingerprint")


def score_opening_calibration(
    prepared: PreparedOpeningCalibrationRun,
    verdicts: tuple[OpeningCalibrationReviewVerdictV1, ...],
) -> OpeningCalibrationReportV1:
    """Score bound reviewer replies without upgrading their execution or semantic authority."""

    verdict_by_task = {item.task_id: item for item in verdicts}
    task_ids = {item.task_id for item in prepared.tasks}
    if len(verdict_by_task) != len(verdicts) or set(verdict_by_task) != task_ids:
        raise OpeningCalibrationError(
            "calibration verdicts must cover every prepared task exactly once"
        )
    profiles: list[tuple[tuple[str, bool], ...]] = []
    control_claims = {
        item.semantic_projection.normalized_claim for item in prepared.sample.candidates
    }
    mutation_claims = {item.mutated_claim for item in prepared.sample.mutations}
    if control_claims & mutation_claims:
        raise OpeningCalibrationError(
            "calibration control and mutation claims overlap; blind scoring would be ambiguous"
        )
    expected_by_claim = {
        **{item: True for item in control_claims},
        **{item: False for item in mutation_claims},
    }
    all_controls_accepted = True
    all_mutations_rejected = True
    all_declared_checks = True
    for task in prepared.tasks:
        verdict = verdict_by_task[task.task_id]
        _validate_verdict_against_task(task, verdict)
        by_option = {item.option_id: item for item in verdict.option_findings}
        claims_by_option = prepared._claims_for_task(task.task_id)
        if set(claims_by_option) != set(by_option):
            raise OpeningCalibrationError(
                "calibration local material does not cover every scored blind option"
            )
        scored = []
        for option_id, claim in claims_by_option.items():
            expected = expected_by_claim.get(claim)
            if expected is None:
                raise OpeningCalibrationError(
                    "calibration local material includes a claim detached from its sample"
                )
            observed = by_option[option_id].preserves_source_meaning
            scored.append((_sha256_text(claim), observed))
            if expected and not observed:
                all_controls_accepted = False
            if not expected and observed:
                all_mutations_rejected = False
        profiles.append(tuple(sorted(scored)))
        all_declared_checks = all_declared_checks and all(
            (
                verdict.source_to_candidate_equivalent,
                verdict.positive_examples_valid,
                verdict.negative_examples_valid,
                verdict.non_vacuous,
            )
        )
    profile_agreement = len(set(profiles)) == 1
    observed_advisory_passed = (
        profile_agreement
        and all_controls_accepted
        and all_mutations_rejected
        and all_declared_checks
    )
    covered = tuple(sorted(prepared.sample.available_mutation_kinds, key=str))
    missing = prepared.sample.missing_required_mutation_kinds
    coverage_complete = not missing
    advisory_passed = observed_advisory_passed and coverage_complete
    blockers = [
        "MACHINE_ADVISORY_ONLY",
        "EXECUTION_EVIDENCE_UNVERIFIED",
        "NO_FROZEN_STATEMENT_CONTRACT",
        "NORMAL_BUILDER_FIDELITY_REQUIRED",
    ]
    if not profile_agreement:
        blockers.append("REVIEWER_DISAGREEMENT")
    if not all_controls_accepted:
        blockers.append("SEMANTIC_CONTROL_REJECTED")
    if not all_mutations_rejected:
        blockers.append("MUTATION_SURVIVED")
    if not all_declared_checks:
        blockers.append("DECLARED_CHECK_FAILED")
    if missing:
        blockers.append("MUTATION_COVERAGE_INCOMPLETE")
    payload: dict[str, object] = {
        "schema_version": "autolean.builder-opening-calibration-report.v1",
        "sample_id": prepared.sample.sample_id,
        "sample_snapshot_sha256": prepared.sample.sample_snapshot_sha256,
        "preparation_fingerprint_sha256": prepared.preparation_fingerprint_sha256,
        "reviewer_binding_sha256": [task.reviewer_binding_sha256 for task in prepared.tasks],
        "reviewer_verdict_artifact_sha256": [
            verdict_by_task[task.task_id].artifact_sha256 for task in prepared.tasks
        ],
        "reviewer_profile_agreement": profile_agreement,
        "semantic_controls_accepted": all_controls_accepted,
        "mutations_rejected": all_mutations_rejected,
        "declared_checks_passed": all_declared_checks,
        "observed_advisory_checks_passed": observed_advisory_passed,
        "mutation_coverage_complete": coverage_complete,
        "unverified_advisory_checks_passed": advisory_passed,
        "covered_mutation_kinds": [item.value for item in covered],
        "missing_required_mutation_kinds": [item.value for item in missing],
        "blockers": sorted(set(blockers)),
        "authority": OpeningCalibrationAuthorityV1().model_dump(mode="json"),
        "execution_evidence_verified": False,
    }
    payload["report_sha256"] = _sha256_json(payload)
    return OpeningCalibrationReportV1.model_validate(payload)


def prepare_standard_bridge_bundle(
    prepared: PreparedOpeningCalibrationRun,
    report: OpeningCalibrationReportV1,
) -> StandardBridgePreparationBundleV1:
    """Render a non-routable standard-bridge checklist from an advisory calibration report."""

    if report.sample_id != prepared.sample.sample_id:
        raise OpeningCalibrationError("calibration report targets another source sample")
    if report.preparation_fingerprint_sha256 != prepared.preparation_fingerprint_sha256:
        raise OpeningCalibrationError("calibration report targets another preparation")
    blockers = [
        "MACHINE_ADVISORY_ONLY",
        "NO_FROZEN_STATEMENT_CONTRACT",
        "NO_FORMALIZATION_TASK_BUNDLE",
        "INDEPENDENT_SEMANTIC_REVIEW_REQUIRED",
        "NORMAL_BUILDER_FREEZE_REQUIRED",
    ]
    if report.missing_required_mutation_kinds:
        blockers.append("MUTATION_COVERAGE_INCOMPLETE")
    return StandardBridgePreparationBundleV1(
        sample_id=prepared.sample.sample_id,
        source_snapshot_sha256=prepared.sample.source.source_snapshot_sha256,
        calibration_report_sha256=report.report_sha256,
        candidate_source_sha256=tuple(
            item.candidate_source_sha256 for item in prepared.sample.candidates
        ),
        required_next_builder_gates=(
            "rights-cleared-source-ingestion",
            "statement-fidelity-harness",
            "independent-semantic-review",
            "freeze-gate",
            "formalization-task-bundle-v1",
        ),
        blockers=tuple(sorted(blockers)),
    )
