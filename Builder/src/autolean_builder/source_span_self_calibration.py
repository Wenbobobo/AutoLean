"""Offline, proposal-only multi-role calibration for one unfrozen source span.

The harness is intentionally earlier than :mod:`fidelity_harness`: it can expose
disagreement and structural drift, but it cannot create a statement contract, a
semantic signoff, a rights decision, a kernel result, or a Builder freeze decision.
Only the repository's project-synthetic pre-calibration fixtures are accepted by the
V1 implementation, and only deterministic local fake providers may see their bytes.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Literal, Never, Protocol

from autolean_contracts import (
    EndpointClassV1,
    HashKindV1,
    PermissionDecisionV1,
    canonical_json_bytes,
    digest_model,
    validate_model_routing_identifier,
)
from autolean_contracts.base import ContractModel
from pydantic import ConfigDict, Field, model_validator

from .local_calibration import (
    LocalCalibrationDifferenceKindV1,
    LocalCalibrationFixtureCorpusV1,
    PreCalibrationFixtureRecordV1,
    load_local_calibration_fixture_corpus,
)

_SHA256 = r"^[0-9a-f]{64}$"
_IDENTIFIER = r"^[a-z][a-z0-9-]{2,95}$"
_PROVIDER_IDENTIFIER = r"^[a-z0-9][a-z0-9._-]{0,127}$"
_CORPUS_MANIFEST_NAME = "project-synthetic-opening-corpus.release-manifest.v1.json"
_CONCLUSION_MUTATION_DIFFERENCE_KINDS = frozenset(
    {
        LocalCalibrationDifferenceKindV1.SIGN_FLIP,
        LocalCalibrationDifferenceKindV1.STRICT_TO_NONSTRICT,
        LocalCalibrationDifferenceKindV1.INFIMUM_TO_ATTAINMENT,
        LocalCalibrationDifferenceKindV1.UNIQUENESS_TO_EXISTENCE,
        LocalCalibrationDifferenceKindV1.LENGTH_TO_GEODESIC,
        LocalCalibrationDifferenceKindV1.REVERSE_PARAMETERS,
    }
)
_BOUNDARY_MUTATION_DIFFERENCE_KINDS = frozenset(
    {
        LocalCalibrationDifferenceKindV1.DROP_NONEMPTY,
        LocalCalibrationDifferenceKindV1.DROP_REGULARITY,
        LocalCalibrationDifferenceKindV1.VACUITY,
        LocalCalibrationDifferenceKindV1.DROP_FINITE,
        LocalCalibrationDifferenceKindV1.DROP_NOETHERIAN,
    }
)


class SourceSpanSelfCalibrationError(ValueError):
    """The offline calibration request or evidence failed closed."""


class SourceSpanCalibrationRoleV1(StrEnum):
    CONVERSION_PROPOSER = "conversion_proposer"
    REVERSE_RENDER_REVIEWER = "reverse_render_reviewer"
    QUANTIFIER_BOUNDARY_CRITIC = "quantifier_boundary_critic"
    ADJUDICATOR = "adjudicator"


class CalibrationMutationFamilyV1(StrEnum):
    QUANTIFIER = "quantifier"
    BOUNDARY = "boundary"


class CalibrationMutationAnchorV1(StrEnum):
    """Structural location a critic claims to mutate."""

    QUANTIFIER = "quantifier"
    CONCLUSION = "conclusion"
    BOUNDARY_CONDITION = "boundary_condition"


class CalibrationAdjudicationDispositionV1(StrEnum):
    CONTINUE = "continue"
    GAP = "gap"
    REJECT = "reject"


_ROLE_PROTOCOLS: dict[SourceSpanCalibrationRoleV1, tuple[str, ...]] = {
    SourceSpanCalibrationRoleV1.CONVERSION_PROPOSER: (
        "Translate only the supplied source span into an explicit mathematical projection.",
        "List every quantifier and assumption; do not add a hidden premise.",
        "Return an illustrative Lean statement and a plain-language reverse rendering.",
        "The output is a proposal and has no semantic, rights, kernel, or freeze authority.",
    ),
    SourceSpanCalibrationRoleV1.REVERSE_RENDER_REVIEWER: (
        "Independently reverse-render every candidate and compare it with the source span.",
        "Report assumption, quantifier, conclusion, and boundary drift explicitly.",
        "The output is advisory evidence and cannot sign off semantic fidelity.",
    ),
    SourceSpanCalibrationRoleV1.QUANTIFIER_BOUNDARY_CRITIC: (
        "Generate one quantifier mutation and one boundary mutation for every candidate.",
        "Each mutation must change the candidate and explain the expected semantic failure.",
        "The output is advisory evidence and cannot weaken or edit a source statement.",
    ),
    SourceSpanCalibrationRoleV1.ADJUDICATOR: (
        "Reconcile the independently generated proposals, reverse review, and mutation critique.",
        "Preserve unresolved disagreements and never silently select a weaker claim.",
        "The disposition is a proposal for another Builder round, never a freeze decision.",
    ),
}


class SourceSpanCalibrationAuthorityV1(ContractModel):
    """Hard negative authority carried by every artifact from this harness."""

    schema_version: Literal["autolean.source-span-calibration-authority.v1"] = (
        "autolean.source-span-calibration-authority.v1"
    )
    evidence_class: Literal["machine_advisory_proposal_only"] = "machine_advisory_proposal_only"
    rights_authority: Literal[False] = False
    semantic_review_authority: Literal[False] = False
    kernel_verification_authority: Literal[False] = False
    freeze_authority: Literal[False] = False
    prover_handoff_authority: Literal[False] = False
    release_authority: Literal[False] = False


class SourceSpanCalibrationCorpusBindingV1(ContractModel):
    """Raw-byte binding created only after the canonical release manifest is verified."""

    schema_version: Literal["autolean.source-span-calibration-corpus-binding.v1"] = (
        "autolean.source-span-calibration-corpus-binding.v1"
    )
    corpus_id: Literal["project-synthetic-opening-pre-calibration"] = (
        "project-synthetic-opening-pre-calibration"
    )
    corpus_sha256: str = Field(pattern=_SHA256)
    release_manifest_sha256: str = Field(pattern=_SHA256)
    repository_license_sha256: str = Field(pattern=_SHA256)
    sample_count: Literal[11] = 11
    sample_ids: tuple[str, ...] = Field(min_length=11, max_length=11)

    @model_validator(mode="after")
    def validate_sample_ids(self) -> SourceSpanCalibrationCorpusBindingV1:
        if tuple(sorted(self.sample_ids)) != self.sample_ids or len(set(self.sample_ids)) != 11:
            raise ValueError("calibration corpus sample identifiers must be canonical and unique")
        return self


class VerifiedSourceSpanCalibrationCorpus:
    """Path-bound handle that re-verifies canonical corpus bytes on every use.

    This is deliberately not a security capability.  It carries no admitted corpus object and
    no same-process token; callers crossing this boundary are protected by reloading the exact
    canonical path through the release-manifest verifier and comparing its fresh binding.
    """

    __slots__ = ("_binding", "_path")

    def __init__(
        self,
        *,
        path: Path,
        binding: SourceSpanCalibrationCorpusBindingV1,
    ) -> None:
        self._path = path.resolve()
        self._binding = binding

    def reverify(self) -> LocalCalibrationFixtureCorpusV1:
        """Reload the bound path and reject any source or binding drift."""

        try:
            path = self._path
            loader_binding = self._binding
        except AttributeError as error:
            raise SourceSpanSelfCalibrationError(
                "runtime calibration corpus handle is incomplete"
            ) from error
        if (
            not isinstance(path, Path)
            or type(loader_binding) is not SourceSpanCalibrationCorpusBindingV1
        ):
            raise SourceSpanSelfCalibrationError(
                "runtime calibration corpus handle state is malformed"
            )
        corpus, binding = _load_and_bind_source_span_calibration_corpus(path)
        if binding != loader_binding:
            raise SourceSpanSelfCalibrationError(
                "runtime calibration corpus binding differs from the loader-created binding"
            )
        return corpus

    @property
    def corpus(self) -> LocalCalibrationFixtureCorpusV1:
        return self.reverify()

    @property
    def binding(self) -> SourceSpanCalibrationCorpusBindingV1:
        self.reverify()
        return self._binding

    def sample(self, sample_id: str) -> PreCalibrationFixtureRecordV1:
        corpus = self.reverify()
        matches = tuple(item for item in corpus.samples if item.sample_id == sample_id)
        if len(matches) != 1:
            raise SourceSpanSelfCalibrationError(
                "source-span candidate is absent from the verified eleven-sample corpus"
            )
        return matches[0]


class SourceSpanCalibrationInputBindingV1(ContractModel):
    """Digest-only public binding to one exact project-synthetic fixture input."""

    schema_version: Literal["autolean.source-span-calibration-input.v1"] = (
        "autolean.source-span-calibration-input.v1"
    )
    input_state: Literal["unfrozen_source_span_candidate"] = "unfrozen_source_span_candidate"
    corpus: SourceSpanCalibrationCorpusBindingV1
    sample_id: str = Field(pattern=_IDENTIFIER)
    fixture_snapshot_sha256: str = Field(pattern=_SHA256)
    source_record_sha256: str = Field(pattern=_SHA256)
    rights_record_sha256: str = Field(pattern=_SHA256)
    source_span_id: str = Field(min_length=1)
    source_span_sha256: str = Field(pattern=_SHA256)
    normalized_baseline_sha256: str = Field(pattern=_SHA256)
    mutation_fixture_sha256: tuple[str, ...] = Field(min_length=1)
    conclusion_anchor_sha256: tuple[str, ...] = Field(min_length=1)
    boundary_condition_anchor_sha256: tuple[str, ...]
    source_text_retained: Literal[False] = False
    statement_contract_present: Literal[False] = False
    frozen_revision_present: Literal[False] = False
    authority: SourceSpanCalibrationAuthorityV1 = Field(
        default_factory=SourceSpanCalibrationAuthorityV1
    )

    @model_validator(mode="after")
    def validate_boundary_anchor_hashes(self) -> SourceSpanCalibrationInputBindingV1:
        for label, anchors in (
            ("conclusion", self.conclusion_anchor_sha256),
            ("boundary-condition", self.boundary_condition_anchor_sha256),
        ):
            if tuple(sorted(anchors)) != anchors or len(set(anchors)) != len(anchors):
                raise ValueError(f"{label} anchors must be canonical and unique")
        if set(self.conclusion_anchor_sha256) & set(self.boundary_condition_anchor_sha256):
            raise ValueError("conclusion and boundary-condition anchor classes must be disjoint")
        return self

    @property
    def input_sha256(self) -> str:
        return _sha256_model(self)


class SourceSpanCalibrationActorV1(ContractModel):
    """Declared role identity and exact offline provider/budget provenance."""

    schema_version: Literal["autolean.source-span-calibration-actor.v1"] = (
        "autolean.source-span-calibration-actor.v1"
    )
    actor_id: str = Field(pattern=_IDENTIFIER)
    role: SourceSpanCalibrationRoleV1
    independence_group: str = Field(pattern=_IDENTIFIER)
    provider_id: Literal["fake"] = "fake"
    model_id: str = Field(pattern=_PROVIDER_IDENTIFIER)
    endpoint_class: Literal[EndpointClassV1.LOCAL] = EndpointClassV1.LOCAL
    provider_configuration_sha256: str = Field(pattern=_SHA256)
    role_environment_sha256: str = Field(pattern=_SHA256)
    prompt_contract_sha256: str = Field(pattern=_SHA256)
    max_input_tokens: int = Field(ge=1, le=1_000_000)
    max_output_tokens: int = Field(ge=1, le=1_000_000)
    max_response_bytes: int = Field(ge=128, le=8_388_608)
    timeout_seconds: float = Field(gt=0, le=3600)
    execution_mode: Literal["offline_scripted_fake"] = "offline_scripted_fake"
    authority: SourceSpanCalibrationAuthorityV1 = Field(
        default_factory=SourceSpanCalibrationAuthorityV1
    )

    @model_validator(mode="after")
    def validate_actor(self) -> SourceSpanCalibrationActorV1:
        validate_model_routing_identifier(self.model_id, label="model_id")
        expected_prompt = source_span_calibration_prompt_contract_sha256(self.role)
        if self.prompt_contract_sha256 != expected_prompt:
            raise ValueError("actor prompt contract does not match its fixed role protocol")
        expected_environment = _role_environment_sha256(
            actor_id=self.actor_id,
            role=self.role,
            independence_group=self.independence_group,
            provider_configuration_sha256=self.provider_configuration_sha256,
            max_input_tokens=self.max_input_tokens,
            max_output_tokens=self.max_output_tokens,
            max_response_bytes=self.max_response_bytes,
            timeout_seconds=self.timeout_seconds,
        )
        if self.role_environment_sha256 != expected_environment:
            raise ValueError("actor role environment hash does not bind its configuration")
        return self


class SourceSpanCalibrationRoleRequestV1(ContractModel):
    """Text-free request receipt; private role payload is represented only by its hash."""

    schema_version: Literal["autolean.source-span-calibration-role-request.v1"] = (
        "autolean.source-span-calibration-role-request.v1"
    )
    run_id: str = Field(pattern=_IDENTIFIER)
    actor: SourceSpanCalibrationActorV1
    input_binding_sha256: str = Field(pattern=_SHA256)
    private_input_sha256: str = Field(pattern=_SHA256)
    dependency_sha256: tuple[str, ...]
    output_schema_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_dependencies(self) -> SourceSpanCalibrationRoleRequestV1:
        if len(self.dependency_sha256) != len(set(self.dependency_sha256)):
            raise ValueError("role request dependencies must be unique")
        return self

    @property
    def request_sha256(self) -> str:
        return _sha256_model(self)


class SourceSpanCalibrationProviderResponseV1(ContractModel):
    """Minimal response envelope returned by the offline role provider."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=False,
        validate_default=True,
    )

    provider_id: Literal["fake"] = "fake"
    model_id: str = Field(pattern=_PROVIDER_IDENTIFIER)
    text: str = Field(min_length=2)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    token_usage_assurance: Literal["scripted_fake_declared_not_tokenized"] = (
        "scripted_fake_declared_not_tokenized"
    )


class SourceSpanCalibrationProvider(Protocol):
    """Offline provider surface; V1 rejects every non-fake or non-local implementation."""

    @property
    def provider_id(self) -> str: ...

    @property
    def model_id(self) -> str: ...

    @property
    def endpoint_class(self) -> EndpointClassV1: ...

    @property
    def configuration_sha256(self) -> str: ...

    def generate(
        self,
        request: SourceSpanCalibrationRoleRequestV1,
        *,
        local_payload: Mapping[str, object],
    ) -> SourceSpanCalibrationProviderResponseV1: ...


class ScriptedFakeSourceSpanCalibrationProvider:
    """Deterministic local provider for repeatable architecture and corpus tests."""

    def __init__(
        self,
        responses: Sequence[str],
        *,
        model_id: str = "fake-builder-calibrator",
        input_tokens: int = 32,
        output_tokens: int = 32,
    ) -> None:
        if not responses or any(
            not isinstance(item, str) or not item.strip() for item in responses
        ):
            raise SourceSpanSelfCalibrationError("fake provider responses must be nonempty text")
        if re.fullmatch(_PROVIDER_IDENTIFIER, model_id) is None:
            raise SourceSpanSelfCalibrationError("fake provider model id is invalid")
        try:
            validate_model_routing_identifier(model_id, label="model_id")
        except ValueError as error:
            raise SourceSpanSelfCalibrationError("forbidden provider or model family") from error
        if input_tokens < 0 or output_tokens < 0:
            raise SourceSpanSelfCalibrationError("fake provider usage cannot be negative")
        self._responses = tuple(responses)
        self._model_id = model_id
        self._input_tokens = input_tokens
        self._output_tokens = output_tokens
        self._next = 0

    @property
    def provider_id(self) -> str:
        return "fake"

    @property
    def model_id(self) -> str:
        return self._model_id

    @property
    def endpoint_class(self) -> EndpointClassV1:
        return EndpointClassV1.LOCAL

    @property
    def configuration_sha256(self) -> str:
        return _sha256_payload(
            {
                "schema_version": "autolean.source-span-calibration-fake-provider.v1",
                "provider_id": self.provider_id,
                "model_id": self.model_id,
                "endpoint_class": self.endpoint_class.value,
                "response_sha256": [
                    hashlib.sha256(item.encode("utf-8")).hexdigest() for item in self._responses
                ],
                "input_tokens": self._input_tokens,
                "output_tokens": self._output_tokens,
            }
        )

    def generate(
        self,
        request: SourceSpanCalibrationRoleRequestV1,
        *,
        local_payload: Mapping[str, object],
    ) -> SourceSpanCalibrationProviderResponseV1:
        if request.private_input_sha256 != _sha256_payload(local_payload):
            raise SourceSpanSelfCalibrationError("fake provider private payload hash differs")
        if self._next >= len(self._responses):
            raise SourceSpanSelfCalibrationError("fake provider has no scripted response remaining")
        text = self._responses[self._next]
        self._next += 1
        return SourceSpanCalibrationProviderResponseV1(
            provider_id="fake",
            model_id=self.model_id,
            text=text,
            input_tokens=self._input_tokens,
            output_tokens=self._output_tokens,
        )


class SourceSpanConversionOutputV1(ContractModel):
    """Strict JSON shape emitted by a conversion proposer."""

    normalized_statement: str = Field(min_length=1)
    quantifiers: tuple[str, ...] = Field(min_length=1)
    assumptions: tuple[str, ...]
    conclusion: str = Field(min_length=1)
    illustrative_lean_statement: str = Field(min_length=1)
    reverse_rendering: str = Field(min_length=1)
    ambiguities: tuple[str, ...]
    limitations: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_explicit_fields(self) -> SourceSpanConversionOutputV1:
        for label, values in (
            ("quantifiers", self.quantifiers),
            ("assumptions", self.assumptions),
            ("ambiguities", self.ambiguities),
            ("limitations", self.limitations),
        ):
            if any(not item.strip() for item in values):
                raise ValueError(f"conversion {label} must contain only nonempty text")
            if len(values) != len(set(values)):
                raise ValueError(f"conversion {label} must be unique")
        return self


class SourceSpanStructuralDeltaV1(ContractModel):
    """Harness-computed structural delta; never delegated to the proposer."""

    added_assumptions: tuple[str, ...]
    removed_assumptions: tuple[str, ...]
    added_quantifiers: tuple[str, ...]
    removed_quantifiers: tuple[str, ...]
    quantifier_sequence_changed: bool
    normalized_statement_changed: bool
    conclusion_changed: bool

    @property
    def has_drift(self) -> bool:
        return (
            any(
                (
                    self.added_assumptions,
                    self.removed_assumptions,
                    self.added_quantifiers,
                    self.removed_quantifiers,
                )
            )
            or self.quantifier_sequence_changed
            or self.normalized_statement_changed
            or self.conclusion_changed
        )


class SourceSpanConversionProposalV1(ContractModel):
    schema_version: Literal["autolean.source-span-conversion-proposal.v1"] = (
        "autolean.source-span-conversion-proposal.v1"
    )
    proposal_id: str = Field(pattern=_IDENTIFIER)
    actor_id: str = Field(pattern=_IDENTIFIER)
    independence_group: str = Field(pattern=_IDENTIFIER)
    input_binding_sha256: str = Field(pattern=_SHA256)
    output: SourceSpanConversionOutputV1
    output_sha256: str = Field(pattern=_SHA256)
    structural_delta: SourceSpanStructuralDeltaV1
    semantic_binding_claimed: Literal[False] = False
    lean_parsed: Literal[False] = False
    authority: SourceSpanCalibrationAuthorityV1 = Field(
        default_factory=SourceSpanCalibrationAuthorityV1
    )

    @model_validator(mode="after")
    def validate_output_hash(self) -> SourceSpanConversionProposalV1:
        if self.output_sha256 != _sha256_model(self.output):
            raise ValueError("conversion proposal output hash differs")
        return self


class ReverseRenderFindingV1(ContractModel):
    proposal_id: str = Field(pattern=_IDENTIFIER)
    source_equivalent: bool
    reconstructed_statement: str = Field(min_length=1)
    assumption_drift: tuple[str, ...]
    quantifier_drift: tuple[str, ...]
    boundary_drift: tuple[str, ...]
    rationale: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_equivalence_and_drift(self) -> ReverseRenderFindingV1:
        if self.source_equivalent is self.has_structured_drift:
            raise ValueError(
                "reverse review equivalence must be the inverse of its structured drift"
            )
        return self

    @property
    def has_structured_drift(self) -> bool:
        return any((self.assumption_drift, self.quantifier_drift, self.boundary_drift))


class ReverseRenderReviewOutputV1(ContractModel):
    findings: tuple[ReverseRenderFindingV1, ...] = Field(min_length=2)
    unresolved_issues: tuple[str, ...]

    @model_validator(mode="after")
    def validate_unique_findings(self) -> ReverseRenderReviewOutputV1:
        ids = [item.proposal_id for item in self.findings]
        if len(ids) != len(set(ids)):
            raise ValueError("reverse review proposal findings must be unique")
        return self


class QuantifierBoundaryMutationV1(ContractModel):
    proposal_id: str = Field(pattern=_IDENTIFIER)
    family: CalibrationMutationFamilyV1
    anchor: CalibrationMutationAnchorV1
    baseline_fragment: str = Field(min_length=1)
    replacement_fragment: str = Field(min_length=1)
    applied_statement: str = Field(min_length=1)
    expected_semantic_failure: str = Field(min_length=1)
    rationale: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_changed_fragment(self) -> QuantifierBoundaryMutationV1:
        if self.baseline_fragment == self.replacement_fragment:
            raise ValueError("mutation replacement must differ from its baseline fragment")
        expected_anchors = {
            CalibrationMutationFamilyV1.QUANTIFIER: {CalibrationMutationAnchorV1.QUANTIFIER},
            CalibrationMutationFamilyV1.BOUNDARY: {
                CalibrationMutationAnchorV1.CONCLUSION,
                CalibrationMutationAnchorV1.BOUNDARY_CONDITION,
            },
        }
        if self.anchor not in expected_anchors[self.family]:
            raise ValueError("mutation family does not match its declared anchor category")
        for label, fragment in (
            ("baseline", self.baseline_fragment),
            ("replacement", self.replacement_fragment),
        ):
            if not fragment.strip():
                raise ValueError(f"mutation {label} fragment must contain visible text")
            if any(unicodedata.category(character) in {"Cc", "Cf"} for character in fragment):
                raise ValueError(
                    f"mutation {label} fragment cannot contain Unicode control or format codepoints"
                )
        if unicodedata.normalize("NFKC", self.baseline_fragment) == unicodedata.normalize(
            "NFKC", self.replacement_fragment
        ):
            raise ValueError("mutation replacement must differ after Unicode normalization")
        return self


class QuantifierBoundaryCritiqueOutputV1(ContractModel):
    mutations: tuple[QuantifierBoundaryMutationV1, ...] = Field(min_length=4)
    unresolved_issues: tuple[str, ...]


class AdjudicatedCandidateFindingV1(ContractModel):
    proposal_id: str = Field(pattern=_IDENTIFIER)
    suitable_for_next_builder_round: bool
    rationale: str = Field(min_length=1)


class SourceSpanAdjudicationOutputV1(ContractModel):
    disposition: CalibrationAdjudicationDispositionV1
    candidate_findings: tuple[AdjudicatedCandidateFindingV1, ...] = Field(min_length=2)
    preferred_proposal_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    unresolved_issues: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_candidate_findings(self) -> SourceSpanAdjudicationOutputV1:
        ids = [item.proposal_id for item in self.candidate_findings]
        if len(ids) != len(set(ids)):
            raise ValueError("adjudication candidate findings must be unique")
        if self.preferred_proposal_id is not None and self.preferred_proposal_id not in ids:
            raise ValueError("preferred proposal is absent from adjudication findings")
        return self


class SourceSpanCalibrationExecutionEvidenceV1(ContractModel):
    """Hash-bound execution record without source text, prompts, or credentials."""

    schema_version: Literal["autolean.source-span-calibration-execution.v1"] = (
        "autolean.source-span-calibration-execution.v1"
    )
    actor: SourceSpanCalibrationActorV1
    request_sha256: str = Field(pattern=_SHA256)
    private_input_sha256: str = Field(pattern=_SHA256)
    dependency_sha256: tuple[str, ...]
    raw_response_sha256: str = Field(pattern=_SHA256)
    parsed_output_sha256: str = Field(pattern=_SHA256)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    response_bytes: int = Field(ge=1)
    token_usage_assurance: Literal["scripted_fake_declared_not_tokenized"] = (
        "scripted_fake_declared_not_tokenized"
    )
    control_plane_authorization_present: Literal[False] = False
    execution_receipt_verified: Literal[False] = False
    execution_sha256: str = Field(pattern=_SHA256)
    authority: SourceSpanCalibrationAuthorityV1 = Field(
        default_factory=SourceSpanCalibrationAuthorityV1
    )

    @model_validator(mode="after")
    def validate_execution_hash(self) -> SourceSpanCalibrationExecutionEvidenceV1:
        if len(self.dependency_sha256) != len(set(self.dependency_sha256)):
            raise ValueError("calibration execution dependencies must be unique")
        if self.input_tokens > self.actor.max_input_tokens:
            raise ValueError("calibration execution exceeds its input-token budget")
        if self.output_tokens > self.actor.max_output_tokens:
            raise ValueError("calibration execution exceeds its output-token budget")
        if self.response_bytes > self.actor.max_response_bytes:
            raise ValueError("calibration execution exceeds its response-byte budget")
        if self.execution_sha256 != _sha256_payload(
            self.model_dump(mode="json", exclude={"execution_sha256"})
        ):
            raise ValueError("calibration execution hash differs")
        return self


class SourceSpanSelfCalibrationResultV1(ContractModel):
    """Canonical proposal-only result for one complete five-role run."""

    schema_version: Literal["autolean.source-span-self-calibration-result.v1"] = (
        "autolean.source-span-self-calibration-result.v1"
    )
    run_id: str = Field(pattern=_IDENTIFIER)
    input_binding: SourceSpanCalibrationInputBindingV1
    proposals: tuple[SourceSpanConversionProposalV1, ...] = Field(min_length=2, max_length=2)
    reverse_review: ReverseRenderReviewOutputV1
    mutation_critique: QuantifierBoundaryCritiqueOutputV1
    adjudication: SourceSpanAdjudicationOutputV1
    executions: tuple[SourceSpanCalibrationExecutionEvidenceV1, ...] = Field(
        min_length=5, max_length=5
    )
    blockers: tuple[str, ...] = Field(min_length=1)
    machine_advisory_continue: bool
    statement_contract_present: Literal[False] = False
    formalization_task_bundle_present: Literal[False] = False
    evidence_sha256: str = Field(pattern=_SHA256)
    authority: SourceSpanCalibrationAuthorityV1 = Field(
        default_factory=SourceSpanCalibrationAuthorityV1
    )

    @model_validator(mode="after")
    def validate_result(self) -> SourceSpanSelfCalibrationResultV1:
        proposal_ids = tuple(item.proposal_id for item in self.proposals)
        if tuple(sorted(proposal_ids)) != proposal_ids or len(set(proposal_ids)) != 2:
            raise ValueError("calibration proposals must use two unique canonical identifiers")
        if any(
            item.input_binding_sha256 != self.input_binding.input_sha256 for item in self.proposals
        ):
            raise ValueError("calibration proposal is detached from the source-span input")
        review_ids = tuple(sorted(item.proposal_id for item in self.reverse_review.findings))
        if review_ids != proposal_ids:
            raise ValueError("reverse review does not cover every proposal")
        adjudication_ids = tuple(
            sorted(item.proposal_id for item in self.adjudication.candidate_findings)
        )
        if adjudication_ids != proposal_ids:
            raise ValueError("adjudication does not cover every proposal")
        try:
            _validate_mutation_coverage(
                self.mutation_critique,
                self.proposals,
                input_binding=self.input_binding,
            )
        except SourceSpanSelfCalibrationError as error:
            raise ValueError(str(error)) from error
        roles = tuple(item.actor.role for item in self.executions)
        expected_roles = (
            SourceSpanCalibrationRoleV1.CONVERSION_PROPOSER,
            SourceSpanCalibrationRoleV1.CONVERSION_PROPOSER,
            SourceSpanCalibrationRoleV1.REVERSE_RENDER_REVIEWER,
            SourceSpanCalibrationRoleV1.QUANTIFIER_BOUNDARY_CRITIC,
            SourceSpanCalibrationRoleV1.ADJUDICATOR,
        )
        if roles != expected_roles:
            raise ValueError("calibration result execution roles are not in canonical order")
        if len({item.actor.actor_id for item in self.executions}) != 5:
            raise ValueError("calibration result execution actors must be unique")
        proposer_actor_ids = tuple(
            item.actor.actor_id
            for item in self.executions
            if item.actor.role is SourceSpanCalibrationRoleV1.CONVERSION_PROPOSER
        )
        if tuple(sorted(proposer_actor_ids)) != proposer_actor_ids or set(proposer_actor_ids) != {
            item.actor_id for item in self.proposals
        }:
            raise ValueError("calibration proposal actors differ from proposer executions")
        proposal_by_actor = {item.actor_id: item for item in self.proposals}
        for execution in self.executions[:2]:
            proposal = proposal_by_actor[execution.actor.actor_id]
            if execution.dependency_sha256 or (
                execution.parsed_output_sha256 != proposal.output_sha256
            ):
                raise ValueError("proposer execution differs from its bound proposal")
        proposal_dependencies = tuple(item.output_sha256 for item in self.proposals)
        reverse_execution = self.executions[2]
        critic_execution = self.executions[3]
        adjudicator_execution = self.executions[4]
        if (
            reverse_execution.dependency_sha256 != proposal_dependencies
            or reverse_execution.parsed_output_sha256 != _sha256_model(self.reverse_review)
        ):
            raise ValueError("reverse-review execution differs from its bound evidence")
        if (
            critic_execution.dependency_sha256 != proposal_dependencies
            or critic_execution.parsed_output_sha256 != _sha256_model(self.mutation_critique)
        ):
            raise ValueError("mutation-critic execution differs from its bound evidence")
        expected_adjudication_dependencies = (
            *proposal_dependencies,
            _sha256_model(self.reverse_review),
            _sha256_model(self.mutation_critique),
        )
        if (
            adjudicator_execution.dependency_sha256 != expected_adjudication_dependencies
            or adjudicator_execution.parsed_output_sha256 != _sha256_model(self.adjudication)
        ):
            raise ValueError("adjudicator execution differs from its bound evidence")
        expected_blockers = _result_blockers(
            self.proposals,
            self.reverse_review,
            self.adjudication,
        )
        if self.blockers != expected_blockers:
            raise ValueError("self-calibration blockers differ from computed evidence")
        expected_continue = (
            self.adjudication.disposition is CalibrationAdjudicationDispositionV1.CONTINUE
            and not any(item.has_structured_drift for item in self.reverse_review.findings)
            and all(
                item.suitable_for_next_builder_round
                for item in self.adjudication.candidate_findings
            )
            and not any(item.structural_delta.has_drift for item in self.proposals)
        )
        if self.machine_advisory_continue is not expected_continue:
            raise ValueError("self-calibration continue flag differs from computed evidence")
        if self.evidence_sha256 != _sha256_payload(
            self.model_dump(mode="json", exclude={"evidence_sha256"})
        ):
            raise ValueError("self-calibration evidence hash differs")
        return self

    def freeze_statement(self) -> Never:
        raise SourceSpanSelfCalibrationError(
            "machine self-calibration cannot freeze a Builder statement"
        )

    def handoff_to_prover(self) -> Never:
        raise SourceSpanSelfCalibrationError(
            "machine self-calibration cannot create a Prover handoff"
        )


def source_span_calibration_prompt_contract_sha256(
    role: SourceSpanCalibrationRoleV1,
) -> str:
    """Bind a role to the fixed protocol text without storing prompts in the result."""

    return _sha256_payload(
        {
            "schema_version": "autolean.source-span-calibration-prompt-contract.v1",
            "role": role.value,
            "instructions": _ROLE_PROTOCOLS[role],
        }
    )


def build_scripted_fake_calibration_actor(
    *,
    actor_id: str,
    role: SourceSpanCalibrationRoleV1,
    independence_group: str,
    provider: ScriptedFakeSourceSpanCalibrationProvider,
    max_input_tokens: int = 4096,
    max_output_tokens: int = 1024,
    max_response_bytes: int = 65_536,
    timeout_seconds: float = 30.0,
) -> SourceSpanCalibrationActorV1:
    """Create a role spec whose environment binds the exact fake provider configuration."""

    environment_sha256 = _role_environment_sha256(
        actor_id=actor_id,
        role=role,
        independence_group=independence_group,
        provider_configuration_sha256=provider.configuration_sha256,
        max_input_tokens=max_input_tokens,
        max_output_tokens=max_output_tokens,
        max_response_bytes=max_response_bytes,
        timeout_seconds=timeout_seconds,
    )
    return SourceSpanCalibrationActorV1(
        actor_id=actor_id,
        role=role,
        independence_group=independence_group,
        model_id=provider.model_id,
        provider_configuration_sha256=provider.configuration_sha256,
        role_environment_sha256=environment_sha256,
        prompt_contract_sha256=source_span_calibration_prompt_contract_sha256(role),
        max_input_tokens=max_input_tokens,
        max_output_tokens=max_output_tokens,
        max_response_bytes=max_response_bytes,
        timeout_seconds=timeout_seconds,
    )


def _role_environment_sha256(
    *,
    actor_id: str,
    role: SourceSpanCalibrationRoleV1,
    independence_group: str,
    provider_configuration_sha256: str,
    max_input_tokens: int,
    max_output_tokens: int,
    max_response_bytes: int,
    timeout_seconds: float,
) -> str:
    return _sha256_payload(
        {
            "schema_version": "autolean.source-span-calibration-role-environment.v1",
            "actor_id": actor_id,
            "role": role.value,
            "independence_group": independence_group,
            "provider_configuration_sha256": provider_configuration_sha256,
            "budgets": {
                "max_input_tokens": max_input_tokens,
                "max_output_tokens": max_output_tokens,
                "max_response_bytes": max_response_bytes,
                "timeout_seconds": timeout_seconds,
            },
        }
    )


class SourceSpanSelfCalibrationHarness:
    """Run two proposals, reverse review, mutation critique, and advisory adjudication."""

    def run(
        self,
        corpus: VerifiedSourceSpanCalibrationCorpus,
        *,
        sample_id: str,
        run_id: str,
        actors: tuple[SourceSpanCalibrationActorV1, ...],
        providers: Mapping[str, SourceSpanCalibrationProvider],
    ) -> SourceSpanSelfCalibrationResultV1:
        if type(corpus) is not VerifiedSourceSpanCalibrationCorpus:
            raise SourceSpanSelfCalibrationError(
                "V1 requires a path-bound canonical calibration corpus handle"
            )
        sample = corpus.sample(sample_id)
        sample.assert_non_authoritative()
        if sample.rights.model_egress is not PermissionDecisionV1.DENY:
            raise SourceSpanSelfCalibrationError(
                "V1 accepts only the no-egress project-synthetic fixture boundary"
            )
        ordered_actors = _validate_and_order_actors(actors, providers)
        input_binding = build_source_span_calibration_input_binding(corpus, sample_id=sample_id)
        base_private = _source_private_payload(sample, input_binding)
        executions: list[SourceSpanCalibrationExecutionEvidenceV1] = []
        proposals: list[SourceSpanConversionProposalV1] = []

        for actor in ordered_actors[:2]:
            output, execution = self._execute(
                actor,
                providers[actor.actor_id],
                run_id=run_id,
                input_binding=input_binding,
                dependencies=(),
                local_payload={
                    **base_private,
                    "role_protocol": _ROLE_PROTOCOLS[actor.role],
                },
                output_type=SourceSpanConversionOutputV1,
            )
            executions.append(execution)
            proposal_id = source_span_conversion_proposal_id(
                actor.actor_id,
                output,
                input_binding.input_sha256,
            )
            proposals.append(
                SourceSpanConversionProposalV1(
                    proposal_id=proposal_id,
                    actor_id=actor.actor_id,
                    independence_group=actor.independence_group,
                    input_binding_sha256=input_binding.input_sha256,
                    output=output,
                    output_sha256=_sha256_model(output),
                    structural_delta=_structural_delta(sample, output),
                )
            )
        ordered_proposals = tuple(sorted(proposals, key=lambda item: item.proposal_id))
        proposal_dependencies = tuple(item.output_sha256 for item in ordered_proposals)

        reverse_actor = ordered_actors[2]
        reverse_review, reverse_execution = self._execute(
            reverse_actor,
            providers[reverse_actor.actor_id],
            run_id=run_id,
            input_binding=input_binding,
            dependencies=proposal_dependencies,
            local_payload={
                **base_private,
                "role_protocol": _ROLE_PROTOCOLS[reverse_actor.role],
                "proposals": [item.model_dump(mode="json") for item in ordered_proposals],
            },
            output_type=ReverseRenderReviewOutputV1,
        )
        _require_exact_proposal_ids(
            "reverse review",
            (item.proposal_id for item in reverse_review.findings),
            ordered_proposals,
        )
        executions.append(reverse_execution)

        critic_actor = ordered_actors[3]
        mutation_critique, critic_execution = self._execute(
            critic_actor,
            providers[critic_actor.actor_id],
            run_id=run_id,
            input_binding=input_binding,
            dependencies=proposal_dependencies,
            local_payload={
                **base_private,
                "role_protocol": _ROLE_PROTOCOLS[critic_actor.role],
                "proposals": [item.model_dump(mode="json") for item in ordered_proposals],
            },
            output_type=QuantifierBoundaryCritiqueOutputV1,
        )
        _validate_mutation_coverage(
            mutation_critique,
            ordered_proposals,
            input_binding=input_binding,
        )
        executions.append(critic_execution)

        adjudicator_actor = ordered_actors[4]
        adjudication_dependencies = (
            *proposal_dependencies,
            _sha256_model(reverse_review),
            _sha256_model(mutation_critique),
        )
        adjudication, adjudicator_execution = self._execute(
            adjudicator_actor,
            providers[adjudicator_actor.actor_id],
            run_id=run_id,
            input_binding=input_binding,
            dependencies=adjudication_dependencies,
            local_payload={
                **base_private,
                "role_protocol": _ROLE_PROTOCOLS[adjudicator_actor.role],
                "proposals": [item.model_dump(mode="json") for item in ordered_proposals],
                "reverse_review": reverse_review.model_dump(mode="json"),
                "mutation_critique": mutation_critique.model_dump(mode="json"),
            },
            output_type=SourceSpanAdjudicationOutputV1,
        )
        _require_exact_proposal_ids(
            "adjudication",
            (item.proposal_id for item in adjudication.candidate_findings),
            ordered_proposals,
        )
        executions.append(adjudicator_execution)

        blockers = _result_blockers(ordered_proposals, reverse_review, adjudication)
        machine_continue = (
            adjudication.disposition is CalibrationAdjudicationDispositionV1.CONTINUE
            and not any(item.has_structured_drift for item in reverse_review.findings)
            and all(
                item.suitable_for_next_builder_round for item in adjudication.candidate_findings
            )
            and not any(item.structural_delta.has_drift for item in ordered_proposals)
        )
        execution_records = tuple(executions)
        authority = SourceSpanCalibrationAuthorityV1()
        evidence_sha256 = _sha256_payload(
            {
                "schema_version": "autolean.source-span-self-calibration-result.v1",
                "run_id": run_id,
                "input_binding": input_binding.model_dump(mode="json"),
                "proposals": [item.model_dump(mode="json") for item in ordered_proposals],
                "reverse_review": reverse_review.model_dump(mode="json"),
                "mutation_critique": mutation_critique.model_dump(mode="json"),
                "adjudication": adjudication.model_dump(mode="json"),
                "executions": [item.model_dump(mode="json") for item in execution_records],
                "blockers": blockers,
                "machine_advisory_continue": machine_continue,
                "statement_contract_present": False,
                "formalization_task_bundle_present": False,
                "authority": authority.model_dump(mode="json"),
            }
        )
        return SourceSpanSelfCalibrationResultV1(
            run_id=run_id,
            input_binding=input_binding,
            proposals=ordered_proposals,
            reverse_review=reverse_review,
            mutation_critique=mutation_critique,
            adjudication=adjudication,
            executions=execution_records,
            blockers=blockers,
            machine_advisory_continue=machine_continue,
            evidence_sha256=evidence_sha256,
            authority=authority,
        )

    def _execute[OutputModel: ContractModel](
        self,
        actor: SourceSpanCalibrationActorV1,
        provider: SourceSpanCalibrationProvider,
        *,
        run_id: str,
        input_binding: SourceSpanCalibrationInputBindingV1,
        dependencies: tuple[str, ...],
        local_payload: Mapping[str, object],
        output_type: type[OutputModel],
    ) -> tuple[OutputModel, SourceSpanCalibrationExecutionEvidenceV1]:
        _validate_provider(actor, provider)
        request = SourceSpanCalibrationRoleRequestV1(
            run_id=run_id,
            actor=actor,
            input_binding_sha256=input_binding.input_sha256,
            private_input_sha256=_sha256_payload(local_payload),
            dependency_sha256=dependencies,
            output_schema_sha256=_sha256_payload(output_type.model_json_schema()),
        )
        response = provider.generate(request, local_payload=local_payload)
        _validate_response(actor, response)
        parsed = _parse_output(response.text, output_type)
        raw_bytes = response.text.encode("utf-8")
        if len(raw_bytes) > actor.max_response_bytes:
            raise SourceSpanSelfCalibrationError("role response exceeds its byte budget")
        request_sha256 = request.request_sha256
        raw_response_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        parsed_output_sha256 = _sha256_model(parsed)
        authority = SourceSpanCalibrationAuthorityV1()
        execution_sha256 = _sha256_payload(
            {
                "schema_version": "autolean.source-span-calibration-execution.v1",
                "actor": actor.model_dump(mode="json"),
                "request_sha256": request_sha256,
                "private_input_sha256": request.private_input_sha256,
                "dependency_sha256": dependencies,
                "raw_response_sha256": raw_response_sha256,
                "parsed_output_sha256": parsed_output_sha256,
                "input_tokens": response.input_tokens,
                "output_tokens": response.output_tokens,
                "response_bytes": len(raw_bytes),
                "token_usage_assurance": response.token_usage_assurance,
                "control_plane_authorization_present": False,
                "execution_receipt_verified": False,
                "authority": authority.model_dump(mode="json"),
            }
        )
        return parsed, SourceSpanCalibrationExecutionEvidenceV1(
            actor=actor,
            request_sha256=request_sha256,
            private_input_sha256=request.private_input_sha256,
            dependency_sha256=dependencies,
            raw_response_sha256=raw_response_sha256,
            parsed_output_sha256=parsed_output_sha256,
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            response_bytes=len(raw_bytes),
            token_usage_assurance=response.token_usage_assurance,
            execution_sha256=execution_sha256,
            authority=authority,
        )


def _load_and_bind_source_span_calibration_corpus(
    path: Path,
) -> tuple[LocalCalibrationFixtureCorpusV1, SourceSpanCalibrationCorpusBindingV1]:
    """Load canonical bytes and derive the complete binding from that same verification."""

    corpus = load_local_calibration_fixture_corpus(path)
    manifest_path = path.with_name(_CORPUS_MANIFEST_NAME)
    try:
        corpus_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    except OSError as error:
        raise SourceSpanSelfCalibrationError(
            "cannot hash the verified calibration corpus boundary"
        ) from error
    binding = SourceSpanCalibrationCorpusBindingV1(
        corpus_sha256=corpus_sha256,
        release_manifest_sha256=manifest_sha256,
        repository_license_sha256=corpus.repository_license_binding.repository_license_sha256,
        sample_ids=tuple(sorted(item.sample_id for item in corpus.samples)),
    )
    return corpus, binding


def load_source_span_calibration_corpus(
    path: Path,
) -> VerifiedSourceSpanCalibrationCorpus:
    """Create a path-bound handle after full canonical corpus verification."""

    resolved_path = path.resolve()
    _, binding = _load_and_bind_source_span_calibration_corpus(resolved_path)
    return VerifiedSourceSpanCalibrationCorpus(
        path=resolved_path,
        binding=binding,
    )


def build_source_span_calibration_input_binding(
    corpus: VerifiedSourceSpanCalibrationCorpus,
    *,
    sample_id: str,
) -> SourceSpanCalibrationInputBindingV1:
    """Bind one manifest-verified source-span fixture without retaining source text."""

    if type(corpus) is not VerifiedSourceSpanCalibrationCorpus:
        raise SourceSpanSelfCalibrationError(
            "input binding requires a path-bound canonical calibration corpus handle"
        )
    sample = corpus.sample(sample_id)

    span = sample.source.spans[0]
    return SourceSpanCalibrationInputBindingV1(
        corpus=corpus.binding,
        sample_id=sample.sample_id,
        fixture_snapshot_sha256=_sha256_model(sample),
        source_record_sha256=digest_model(HashKindV1.SOURCE_RECORD, sample.source).value,
        rights_record_sha256=digest_model(HashKindV1.RIGHTS_RECORD, sample.rights).value,
        source_span_id=span.span_id.value,
        source_span_sha256=span.content_hash.value,
        normalized_baseline_sha256=sample.normalized.sha256,
        mutation_fixture_sha256=tuple(_sha256_model(item) for item in sample.mutation_fixtures),
        conclusion_anchor_sha256=tuple(
            sorted(
                {
                    _fragment_sha256(sample.normalized.conclusion),
                    *(
                        _fragment_sha256(item.baseline_fragment)
                        for item in sample.mutation_fixtures
                        if item.difference_kind in _CONCLUSION_MUTATION_DIFFERENCE_KINDS
                    ),
                }
            )
        ),
        boundary_condition_anchor_sha256=tuple(
            sorted(
                {
                    _fragment_sha256(item.baseline_fragment)
                    for item in sample.mutation_fixtures
                    if item.difference_kind in _BOUNDARY_MUTATION_DIFFERENCE_KINDS
                    and _fragment_sha256(item.baseline_fragment)
                    != _fragment_sha256(sample.normalized.conclusion)
                }
            )
        ),
    )


def _source_private_payload(
    sample: PreCalibrationFixtureRecordV1,
    binding: SourceSpanCalibrationInputBindingV1,
) -> dict[str, object]:
    span = sample.source.spans[0]
    return {
        "schema_version": "autolean.source-span-calibration-private-input.v1",
        "input_binding_sha256": binding.input_sha256,
        "source_span": {
            "span_id": span.span_id.value,
            "content_sha256": span.content_hash.value,
            "locator": span.locator,
            "text": sample.source_text,
        },
        "ambiguities": [item.model_dump(mode="json") for item in sample.ambiguities],
        "authority": SourceSpanCalibrationAuthorityV1().model_dump(mode="json"),
    }


def _validate_and_order_actors(
    actors: tuple[SourceSpanCalibrationActorV1, ...],
    providers: Mapping[str, SourceSpanCalibrationProvider],
) -> tuple[SourceSpanCalibrationActorV1, ...]:
    if len(actors) != 5:
        raise SourceSpanSelfCalibrationError("calibration requires exactly five role actors")
    role_counts = {
        role: sum(item.role is role for item in actors) for role in SourceSpanCalibrationRoleV1
    }
    if role_counts != {
        SourceSpanCalibrationRoleV1.CONVERSION_PROPOSER: 2,
        SourceSpanCalibrationRoleV1.REVERSE_RENDER_REVIEWER: 1,
        SourceSpanCalibrationRoleV1.QUANTIFIER_BOUNDARY_CRITIC: 1,
        SourceSpanCalibrationRoleV1.ADJUDICATOR: 1,
    }:
        raise SourceSpanSelfCalibrationError("calibration actor role composition is invalid")
    for label, values in (
        ("actor ids", [item.actor_id for item in actors]),
        ("independence groups", [item.independence_group for item in actors]),
        ("role environments", [item.role_environment_sha256 for item in actors]),
    ):
        if len(values) != len(set(values)):
            raise SourceSpanSelfCalibrationError(f"calibration {label} must be unique")
    if set(providers) != {item.actor_id for item in actors}:
        raise SourceSpanSelfCalibrationError("provider map must match the exact actor set")
    role_order = {
        SourceSpanCalibrationRoleV1.CONVERSION_PROPOSER: 0,
        SourceSpanCalibrationRoleV1.REVERSE_RENDER_REVIEWER: 1,
        SourceSpanCalibrationRoleV1.QUANTIFIER_BOUNDARY_CRITIC: 2,
        SourceSpanCalibrationRoleV1.ADJUDICATOR: 3,
    }
    return tuple(sorted(actors, key=lambda item: (role_order[item.role], item.actor_id)))


def _validate_provider(
    actor: SourceSpanCalibrationActorV1,
    provider: SourceSpanCalibrationProvider,
) -> None:
    if (
        type(provider) is not ScriptedFakeSourceSpanCalibrationProvider
        or provider.provider_id != "fake"
        or provider.endpoint_class is not EndpointClassV1.LOCAL
        or provider.provider_id != actor.provider_id
        or provider.model_id != actor.model_id
        or provider.configuration_sha256 != actor.provider_configuration_sha256
    ):
        raise SourceSpanSelfCalibrationError(
            "V1 role provider differs from its exact local fake actor binding"
        )


def _validate_response(
    actor: SourceSpanCalibrationActorV1,
    response: SourceSpanCalibrationProviderResponseV1,
) -> None:
    if response.provider_id != actor.provider_id or response.model_id != actor.model_id:
        raise SourceSpanSelfCalibrationError("role response provider identity differs")
    if response.input_tokens > actor.max_input_tokens:
        raise SourceSpanSelfCalibrationError("role response exceeds its input-token budget")
    if response.output_tokens > actor.max_output_tokens:
        raise SourceSpanSelfCalibrationError("role response exceeds its output-token budget")


def _structural_delta(
    sample: PreCalibrationFixtureRecordV1,
    output: SourceSpanConversionOutputV1,
) -> SourceSpanStructuralDeltaV1:
    baseline_assumptions = set(sample.normalized.assumptions)
    output_assumptions = set(output.assumptions)
    baseline_quantifiers = set(sample.normalized.quantifiers)
    output_quantifiers = set(output.quantifiers)
    return SourceSpanStructuralDeltaV1(
        added_assumptions=tuple(sorted(output_assumptions - baseline_assumptions)),
        removed_assumptions=tuple(sorted(baseline_assumptions - output_assumptions)),
        added_quantifiers=tuple(sorted(output_quantifiers - baseline_quantifiers)),
        removed_quantifiers=tuple(sorted(baseline_quantifiers - output_quantifiers)),
        quantifier_sequence_changed=(output.quantifiers != sample.normalized.quantifiers),
        normalized_statement_changed=(
            output.normalized_statement != sample.normalized.normalized_statement
        ),
        conclusion_changed=output.conclusion != sample.normalized.conclusion,
    )


def source_span_conversion_proposal_id(
    actor_id: str,
    output: SourceSpanConversionOutputV1,
    input_sha256: str,
) -> str:
    """Derive a stable proposal identity from actor, exact output, and exact input."""

    if re.fullmatch(_IDENTIFIER, actor_id) is None:
        raise SourceSpanSelfCalibrationError("proposal actor id is invalid")
    if re.fullmatch(_SHA256, input_sha256) is None:
        raise SourceSpanSelfCalibrationError("proposal input digest is invalid")

    suffix = _sha256_payload(
        {
            "schema_version": "autolean.source-span-conversion-proposal-id.v1",
            "actor_id": actor_id,
            "input_sha256": input_sha256,
            "output": output.model_dump(mode="json"),
        }
    )[:20]
    return f"proposal-{suffix}"


def _require_exact_proposal_ids(
    label: str,
    observed_ids: Iterable[str],
    proposals: tuple[SourceSpanConversionProposalV1, ...],
) -> None:
    observed = tuple(sorted(observed_ids))
    expected = tuple(item.proposal_id for item in proposals)
    if observed != expected:
        raise SourceSpanSelfCalibrationError(f"{label} must cover every proposal exactly once")


def _validate_mutation_coverage(
    critique: QuantifierBoundaryCritiqueOutputV1,
    proposals: tuple[SourceSpanConversionProposalV1, ...],
    *,
    input_binding: SourceSpanCalibrationInputBindingV1,
) -> None:
    expected = {
        (proposal.proposal_id, family)
        for proposal in proposals
        for family in CalibrationMutationFamilyV1
    }
    observed = {(item.proposal_id, item.family) for item in critique.mutations}
    if observed != expected or len(critique.mutations) != len(observed):
        raise SourceSpanSelfCalibrationError(
            "mutation critic must provide one quantifier and one boundary mutation per proposal"
        )
    by_id = {item.proposal_id: item for item in proposals}
    by_proposal: dict[str, dict[CalibrationMutationFamilyV1, QuantifierBoundaryMutationV1]] = {
        proposal.proposal_id: {} for proposal in proposals
    }
    for mutation in critique.mutations:
        proposal = by_id[mutation.proposal_id]
        by_proposal[mutation.proposal_id][mutation.family] = mutation
        baseline = proposal.output.normalized_statement
        if baseline.count(mutation.baseline_fragment) != 1:
            raise SourceSpanSelfCalibrationError(
                "mutation baseline fragment must occur exactly once in its proposal"
            )
        fragment_sha256 = _fragment_sha256(mutation.baseline_fragment)
        if mutation.anchor is CalibrationMutationAnchorV1.QUANTIFIER:
            if not any(
                mutation.baseline_fragment.casefold() == quantifier.casefold()
                for quantifier in proposal.output.quantifiers
            ):
                raise SourceSpanSelfCalibrationError(
                    "quantifier mutation baseline must bind one explicit candidate quantifier"
                )
        elif mutation.anchor is CalibrationMutationAnchorV1.CONCLUSION:
            if fragment_sha256 not in input_binding.conclusion_anchor_sha256:
                raise SourceSpanSelfCalibrationError(
                    "conclusion mutation baseline must bind the source-declared conclusion anchor"
                )
        elif fragment_sha256 not in input_binding.boundary_condition_anchor_sha256:
            raise SourceSpanSelfCalibrationError(
                "boundary-condition mutation baseline must bind a source-declared fixture anchor"
            )
        expected_statement = baseline.replace(
            mutation.baseline_fragment,
            mutation.replacement_fragment,
            1,
        )
        if mutation.applied_statement != expected_statement:
            raise SourceSpanSelfCalibrationError(
                "mutation applied statement is not the harness-replayable local replacement"
            )
    for mutations in by_proposal.values():
        quantifier = mutations[CalibrationMutationFamilyV1.QUANTIFIER]
        boundary = mutations[CalibrationMutationFamilyV1.BOUNDARY]
        if unicodedata.normalize("NFKC", quantifier.baseline_fragment).casefold() == (
            unicodedata.normalize("NFKC", boundary.baseline_fragment).casefold()
        ):
            raise SourceSpanSelfCalibrationError(
                "quantifier and boundary mutations must use distinct proposal baselines"
            )


def _result_blockers(
    proposals: tuple[SourceSpanConversionProposalV1, ...],
    review: ReverseRenderReviewOutputV1,
    adjudication: SourceSpanAdjudicationOutputV1,
) -> tuple[str, ...]:
    blockers = {
        "DECLARED_AGENT_INDEPENDENCE_UNVERIFIED",
        "MACHINE_ADVISORY_ONLY",
        "NO_KERNEL_VERIFICATION",
        "NO_RIGHTS_AUTHORITY",
        "NO_SEMANTIC_REVIEW_AUTHORITY",
        "NO_STATEMENT_FREEZE_AUTHORITY",
    }
    if any(item.structural_delta.has_drift for item in proposals):
        blockers.add("STRUCTURAL_DELTA_REQUIRES_REVIEW")
    if any(item.has_structured_drift for item in review.findings):
        blockers.add("REVERSE_RENDER_DISAGREEMENT")
    if adjudication.disposition is not CalibrationAdjudicationDispositionV1.CONTINUE:
        blockers.add("ADJUDICATOR_DID_NOT_PROPOSE_CONTINUE")
    if not all(item.suitable_for_next_builder_round for item in adjudication.candidate_findings):
        blockers.add("CANDIDATE_NOT_RECOMMENDED_FOR_NEXT_ROUND")
    return tuple(sorted(blockers))


def _parse_output[OutputModel: ContractModel](
    text: str,
    output_type: type[OutputModel],
) -> OutputModel:
    try:
        payload = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, SourceSpanSelfCalibrationError) as error:
        raise SourceSpanSelfCalibrationError("role output is not strict JSON") from error
    if not isinstance(payload, dict):
        raise SourceSpanSelfCalibrationError("role output must be one JSON object")
    try:
        return output_type.model_validate(payload)
    except ValueError as error:
        raise SourceSpanSelfCalibrationError(
            "role output does not match its exact schema"
        ) from error


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise SourceSpanSelfCalibrationError("role output contains a duplicate JSON key")
        output[key] = value
    return output


def _sha256_model(value: ContractModel) -> str:
    return _sha256_payload(value.model_dump(mode="json"))


def _fragment_sha256(fragment: str) -> str:
    return hashlib.sha256(fragment.encode("utf-8")).hexdigest()


def _sha256_payload(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()
