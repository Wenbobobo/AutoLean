"""Non-authoritative Builder pre-calibration fixture records.

``pre_calibration_fixture`` is deliberately narrower than the rights-cleared
``local_calibration`` state in the Phase-2 roadmap. It stores project-synthetic fixture bytes, a
local normalization sketch, two illustrative unparsed Lean-like snippets, and declared synthetic
mutation fixtures. None of those records establishes semantic equivalence, human authorship,
legal review, or content review. It does *not* produce a ``StatementContractV1`` or a
``FormalizationTaskBundleV1``. The normal Builder fidelity workflow remains the only route to
generate candidates, review fidelity, freeze, and bridge a statement.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal, Never

from autolean_contracts import (
    AmbiguitySeverityV1,
    AmbiguityV1,
    HashKindV1,
    MathematicalSpecificationV1,
    MutationProbeV1,
    PermissionDecisionV1,
    RightsRecordV1,
    SourceRecordV1,
    SourceSpanV1,
    digest_bytes,
    digest_text,
    stable_identifier,
)
from autolean_contracts.base import ContractModel
from autolean_contracts.hashing import canonical_json_bytes
from pydantic import Field, model_validator

_IDENTIFIER = r"^[a-z][a-z0-9-]{2,95}$"
_SHA256 = r"^[0-9a-f]{64}$"
_PROJECT_SYNTHETIC_FIXTURE_PROVENANCE = "project_synthetic_fixture"
_PROJECT_SYNTHETIC_FIXTURE_AUTHORSHIP_CLAIM = (
    "generated_for_repository_pending_human_content_review"
)
_PROJECT_SYNTHETIC_FIXTURE_LICENSE_PATH = "LICENSE"
_PROJECT_SYNTHETIC_FIXTURE_LICENSE_SHA256 = (
    "5c9817c129b98e7bb966bca028c43c19107102ef8e03fe799bffb4354f4ef015"
)
_PROJECT_SYNTHETIC_FIXTURE_CORPUS_SHA256 = (
    "a8d9ae4faf4d376686e7e209c0ab8bce4c23d0647b81d142244feea9abcd30d7"
)
_PROJECT_SYNTHETIC_FIXTURE_CORPUS_NAME = "project-synthetic-opening-corpus.v1.json"
_PROJECT_SYNTHETIC_FIXTURE_MANIFEST_NAME = (
    "project-synthetic-opening-corpus.release-manifest.v1.json"
)
_PROJECT_SYNTHETIC_FIXTURE_RENDERER_NAME = "render_opening_corpus.py"


class LocalCalibrationError(ValueError):
    """A pre-calibration fixture is malformed or attempts to gain production authority."""


class LocalCalibrationDomainV1(StrEnum):
    PDE_A = "pde-a"
    MG_A = "mg-a"


class LocalCalibrationReviewStateV1(StrEnum):
    """This is a local status, not a semantic signoff or a freeze decision."""

    SYNTHETIC_FIXTURES_RECORDED_PENDING_INDEPENDENT_REVIEW = (
        "synthetic_fixtures_recorded_pending_independent_review"
    )


class LocalCalibrationDifferenceKindV1(StrEnum):
    SIGN_FLIP = "sign_flip"
    STRICT_TO_NONSTRICT = "strict_to_nonstrict"
    QUANTIFIER_SWAP = "quantifier_swap"
    DROP_NONEMPTY = "drop_nonempty"
    DROP_REGULARITY = "drop_regularity"
    INFIMUM_TO_ATTAINMENT = "infimum_to_attainment"
    UNIQUENESS_TO_EXISTENCE = "uniqueness_to_existence"
    LENGTH_TO_GEODESIC = "length_to_geodesic"
    REVERSE_PARAMETERS = "reverse_parameters"
    VACUITY = "vacuity"
    DROP_FINITE = "drop_finite"
    DROP_NOETHERIAN = "drop_noetherian"


class LocalCalibrationAuthorityBoundaryV1(ContractModel):
    """Hard authority boundary for a pre-calibration fixture."""

    production_ingestion: Literal[False] = False
    freeze_allowed: Literal[False] = False
    prover_handoff_allowed: Literal[False] = False
    model_egress_allowed: Literal[False] = False
    production_rights_cleared: Literal[False] = False
    promotion_allowed: Literal[False] = False


class ProjectSyntheticFixtureLicenseBindingV1(ContractModel):
    """Exact repository-license binding for the project-synthetic fixture bytes."""

    schema_version: Literal["autolean.project-synthetic-fixture-license-binding.v1"] = (
        "autolean.project-synthetic-fixture-license-binding.v1"
    )
    provenance_class: Literal["project_synthetic_fixture"] = "project_synthetic_fixture"
    authorship_claim: Literal["generated_for_repository_pending_human_content_review"] = (
        "generated_for_repository_pending_human_content_review"
    )
    repository_license_expression: Literal["Apache-2.0"] = "Apache-2.0"
    repository_license_path: Literal["LICENSE"] = "LICENSE"
    repository_license_sha256: str = Field(pattern=_SHA256)
    human_content_review_completed: Literal[False] = False
    legal_review_claimed: Literal[False] = False

    @model_validator(mode="after")
    def validate_repository_license(self) -> ProjectSyntheticFixtureLicenseBindingV1:
        if self.repository_license_sha256 != _PROJECT_SYNTHETIC_FIXTURE_LICENSE_SHA256:
            raise ValueError("project-synthetic fixture binds an unexpected repository LICENSE")
        return self


class ProjectSyntheticFixtureReleaseManifestV1(ContractModel):
    """Hash manifest checked before tracked fixture excerpts may be publicly released."""

    schema_version: Literal["autolean.project-synthetic-fixture-release-manifest.v1"] = (
        "autolean.project-synthetic-fixture-release-manifest.v1"
    )
    fixture_path: Literal[
        "Builder/pilots/local-calibration/project-synthetic-opening-corpus.v1.json"
    ] = "Builder/pilots/local-calibration/project-synthetic-opening-corpus.v1.json"
    fixture_sha256: str = Field(pattern=_SHA256)
    fixture_schema_version: Literal["autolean.builder-local-calibration-fixture-corpus.v1"] = (
        "autolean.builder-local-calibration-fixture-corpus.v1"
    )
    fixture_record_kind: Literal["local_calibration_fixture"] = "local_calibration_fixture"
    renderer_path: Literal["Builder/pilots/local-calibration/render_opening_corpus.py"] = (
        "Builder/pilots/local-calibration/render_opening_corpus.py"
    )
    renderer_sha256: str = Field(pattern=_SHA256)
    repository_license_path: Literal["LICENSE"] = "LICENSE"
    repository_license_sha256: str = Field(pattern=_SHA256)
    repository_license_expression: Literal["Apache-2.0"] = "Apache-2.0"
    provenance_class: Literal["project_synthetic_fixture"] = "project_synthetic_fixture"
    authorship_claim: Literal["generated_for_repository_pending_human_content_review"] = (
        "generated_for_repository_pending_human_content_review"
    )
    human_content_review_completed: Literal[False] = False
    legal_review_claimed: Literal[False] = False

    @model_validator(mode="after")
    def validate_repository_license(self) -> ProjectSyntheticFixtureReleaseManifestV1:
        if self.repository_license_sha256 != _PROJECT_SYNTHETIC_FIXTURE_LICENSE_SHA256:
            raise ValueError("release manifest binds an unexpected repository LICENSE")
        return self


class LocalCalibrationNormalizedStatementV1(ContractModel):
    """A structured projection that can later be re-entered through Builder's normal workflow."""

    normalized_statement: str = Field(min_length=1)
    quantifiers: tuple[str, ...] = Field(min_length=1)
    assumptions: tuple[str, ...] = ()
    conclusion: str = Field(min_length=1)
    definitions: tuple[str, ...] = ()
    edge_cases: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_fragments(self) -> LocalCalibrationNormalizedStatementV1:
        fragments = (*self.quantifiers, *self.assumptions, self.conclusion)
        if any(not fragment.strip() for fragment in fragments):
            raise ValueError(
                "normalized quantifiers, assumptions, and conclusion must be non-empty"
            )
        if len(self.quantifiers) != len(set(self.quantifiers)):
            raise ValueError("normalized quantifiers must be unique")
        if len(self.assumptions) != len(set(self.assumptions)):
            raise ValueError("normalized assumptions must be unique")
        return self

    def as_mathematical_specification(
        self,
        *,
        informal_statement: str,
        ambiguities: tuple[AmbiguityV1, ...],
    ) -> MathematicalSpecificationV1:
        """Reuse the canonical Builder mathematical-specification shape without freezing it."""

        return MathematicalSpecificationV1(
            informal_statement=informal_statement,
            normalized_statement=self.normalized_statement,
            assumptions=self.assumptions,
            quantifier_order=self.quantifiers,
            definitions=self.definitions,
            edge_cases=self.edge_cases,
            ambiguities=ambiguities,
        )

    @property
    def sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.model_dump(mode="json"))).hexdigest()


class LocalCalibrationIllustrativeLeanSnippetV1(ContractModel):
    """Unparsed illustrative text, never a formalization candidate or semantic binding."""

    snippet_id: str = Field(pattern=_IDENTIFIER)
    authoring_path: str = Field(min_length=1)
    declared_independence_label: str = Field(min_length=1)
    illustrative_lean_snippet: str = Field(min_length=1)
    reverse_rendering: str = Field(min_length=1)
    evidence_class: Literal["illustrative_unparsed_text"] = "illustrative_unparsed_text"
    lean_parsed: Literal[False] = False
    semantic_binding_claimed: Literal[False] = False
    promotion_allowed: Literal[False] = False

    @property
    def snapshot_sha256(self) -> str:
        return hashlib.sha256(self.illustrative_lean_snippet.encode("utf-8")).hexdigest()


class LocalCalibrationExampleV1(ContractModel):
    example_id: str = Field(pattern=_IDENTIFIER)
    description: str = Field(min_length=1)
    expected_outcome: str = Field(min_length=1)


class LocalCalibrationMutationFixtureV1(ContractModel):
    """A declared synthetic diff, not an executed check or semantic detection result."""

    difference_kind: LocalCalibrationDifferenceKindV1
    baseline_fragment: str = Field(min_length=1)
    mutated_fragment: str = Field(min_length=1)
    blocker_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,95}$")
    blocker_reason: str = Field(min_length=1)
    probe: MutationProbeV1
    status: Literal["declared_synthetic_mutation_fixture"] = "declared_synthetic_mutation_fixture"
    evidence_class: Literal["synthetic_fixture_not_semantic_evidence"] = (
        "synthetic_fixture_not_semantic_evidence"
    )
    semantic_detection_claimed: Literal[False] = False
    promotion_allowed: Literal[False] = False

    @model_validator(mode="after")
    def validate_shared_mutation_binding(self) -> LocalCalibrationMutationFixtureV1:
        if self.baseline_fragment == self.mutated_fragment:
            raise ValueError("a mutation must change a source fragment")
        if self.mutated_fragment not in self.probe.mutated_statement_source:
            raise ValueError("mutated fragment is absent from the shared mutation probe")
        return self


class LocalCalibrationReviewV1(ContractModel):
    state: LocalCalibrationReviewStateV1
    record_label: Literal["project-synthetic pre-calibration fixture"] = (
        "project-synthetic pre-calibration fixture"
    )
    independent_semantic_review_completed: Literal[False] = False
    notes: str = Field(min_length=1)


class PreCalibrationFixtureInterfacePreviewV1(ContractModel):
    """A deliberately non-routable preview of the later Builder-Prover boundary."""

    schema_version: Literal["autolean.builder-pre-calibration-interface-preview.v1"] = (
        "autolean.builder-pre-calibration-interface-preview.v1"
    )
    preview_only: Literal[True] = True
    sample_id: str = Field(pattern=_IDENTIFIER)
    source_id: str = Field(min_length=1)
    source_content_sha256: str = Field(pattern=_SHA256)
    source_span_ids: tuple[str, ...] = Field(min_length=1)
    rights_id: str = Field(min_length=1)
    normalized_statement_sha256: str = Field(pattern=_SHA256)
    illustrative_snippet_snapshot_sha256: tuple[str, ...] = Field(min_length=2)
    authority: LocalCalibrationAuthorityBoundaryV1 = Field(
        default_factory=LocalCalibrationAuthorityBoundaryV1
    )
    blockers: tuple[str, ...] = Field(min_length=1)

    def assert_not_routable(self) -> Never:
        raise LocalCalibrationError(
            "pre-calibration fixture interface previews cannot be routed to Prover; "
            "create a reviewed "
            "StatementContractV1 through the Builder workflow instead"
        )


class PreCalibrationFixtureRecordV1(ContractModel):
    """A local-only project-synthetic sketch with no production authority."""

    schema_version: Literal["autolean.builder-pre-calibration-fixture.v1"] = (
        "autolean.builder-pre-calibration-fixture.v1"
    )
    record_kind: Literal["pre_calibration_fixture"] = "pre_calibration_fixture"
    sample_id: str = Field(pattern=_IDENTIFIER)
    domain: LocalCalibrationDomainV1
    production_ingestion: Literal[False] = False
    freeze_allowed: Literal[False] = False
    prover_handoff_allowed: Literal[False] = False
    production_rights_cleared: Literal[False] = False
    promotion_allowed: Literal[False] = False
    source_text: str = Field(min_length=1)
    source: SourceRecordV1
    rights: RightsRecordV1
    normalized: LocalCalibrationNormalizedStatementV1
    ambiguities: tuple[AmbiguityV1, ...] = Field(min_length=1)
    illustrative_lean_snippets: tuple[LocalCalibrationIllustrativeLeanSnippetV1, ...] = Field(
        min_length=2
    )
    positive_examples: tuple[LocalCalibrationExampleV1, ...] = Field(min_length=1)
    negative_examples: tuple[LocalCalibrationExampleV1, ...] = Field(min_length=1)
    mutation_fixtures: tuple[LocalCalibrationMutationFixtureV1, ...] = Field(min_length=1)
    review: LocalCalibrationReviewV1
    authority: LocalCalibrationAuthorityBoundaryV1 = Field(
        default_factory=LocalCalibrationAuthorityBoundaryV1
    )

    @model_validator(mode="after")
    def validate_fixture_record(self) -> PreCalibrationFixtureRecordV1:
        source_bytes = self.source_text.encode("utf-8")
        expected_source_id = stable_identifier("pre-calibration-fixture-source", self.sample_id)
        if self.source.source_id != expected_source_id:
            raise ValueError("pre-calibration source id must deterministically bind the sample")
        if self.source.work_id != self.sample_id:
            raise ValueError("pre-calibration source work id must equal sample id")
        if self.source.content_hash != digest_bytes(HashKindV1.SOURCE_BYTES, source_bytes):
            raise ValueError("pre-calibration source text differs from its source-byte hash")
        if self.source.metadata.get("provenance_class") != _PROJECT_SYNTHETIC_FIXTURE_PROVENANCE:
            raise ValueError("pre-calibration source must be a project-synthetic fixture")
        if (
            self.source.metadata.get("authorship_claim")
            != _PROJECT_SYNTHETIC_FIXTURE_AUTHORSHIP_CLAIM
        ):
            raise ValueError("pre-calibration fixture must retain its pending content-review claim")
        if self.source.metadata.get("human_content_review_completed") is not False:
            raise ValueError("pre-calibration fixture cannot claim completed human content review")
        if self.source.metadata.get("purpose") != "pre_calibration_fixture":
            raise ValueError("pre-calibration source must retain its fixture-only purpose")
        if len(self.source.spans) != 1:
            raise ValueError("pre-calibration fixture requires one exact source span")
        span = self.source.spans[0]
        expected_span_id = stable_identifier("pre-calibration-fixture-span", self.sample_id)
        if span.span_id != expected_span_id:
            raise ValueError(
                "pre-calibration source span id must deterministically bind the sample"
            )
        if (
            span.start_offset != 0
            or span.end_offset != len(source_bytes)
            or span.permitted_excerpt != self.source_text
            or span.content_hash != digest_text(HashKindV1.SOURCE_SPAN, self.source_text)
        ):
            raise ValueError(
                "pre-calibration source span must exactly cover the synthetic fixture statement"
            )
        self._validate_rights()
        if any(item.severity is AmbiguitySeverityV1.BLOCKING for item in self.ambiguities):
            raise ValueError("pre-calibration fixtures cannot conceal a blocking ambiguity")
        if len({item.ambiguity_id for item in self.ambiguities}) != len(self.ambiguities):
            raise ValueError("pre-calibration fixture ambiguity identifiers must be unique")
        snippet_ids = [item.snippet_id for item in self.illustrative_lean_snippets]
        authoring_paths = [item.authoring_path for item in self.illustrative_lean_snippets]
        if len(snippet_ids) != len(set(snippet_ids)):
            raise ValueError("pre-calibration illustrative snippet identifiers must be unique")
        if len(authoring_paths) != len(set(authoring_paths)):
            raise ValueError("illustrative snippets must have distinct declared authoring paths")
        if len({item.declared_independence_label for item in self.illustrative_lean_snippets}) < 2:
            raise ValueError("illustrative snippets require two declared independence labels")
        if any(
            item.baseline_fragment not in self.normalized.normalized_statement
            for item in self.mutation_fixtures
        ):
            raise ValueError("mutation baseline fragment is absent from normalized statement")
        if self.review.independent_semantic_review_completed:
            raise ValueError("pre-calibration fixture cannot record an independent semantic review")
        self.assert_non_authoritative()
        return self

    def _validate_rights(self) -> None:
        if self.rights.source_id != self.source.source_id:
            raise ValueError("pre-calibration rights must bind the exact source")
        expected_rights_id = stable_identifier("pre-calibration-fixture-rights", self.sample_id)
        if self.rights.rights_id != expected_rights_id:
            raise ValueError("pre-calibration rights id must deterministically bind the sample")
        if self.rights.source_license != "Apache-2.0":
            raise ValueError(
                "project-synthetic fixture must bind the repository Apache-2.0 license"
            )
        if self.rights.overall_decision is not PermissionDecisionV1.RESTRICTED:
            raise ValueError("pre-calibration fixture must remain restricted from production use")
        if self.rights.redistribution is not PermissionDecisionV1.ALLOW:
            raise ValueError("exact project-synthetic fixture bytes must allow redistribution")
        if self.rights.model_egress is not PermissionDecisionV1.DENY:
            raise ValueError("pre-calibration fixtures cannot grant model egress")
        if self.rights.allowed_endpoint_classes:
            raise ValueError("pre-calibration fixtures cannot allow model endpoint classes")
        if self.rights.training is not PermissionDecisionV1.DENY:
            raise ValueError("pre-calibration fixtures cannot grant training rights")
        if self.rights.embedding is not PermissionDecisionV1.DENY:
            raise ValueError("pre-calibration fixtures cannot grant embedding rights")
        source_sha256 = self.source.content_hash.value
        required_restrictions = {
            "pre-calibration-fixture-only",
            "redistribution-only-exact-project-synthetic-fixture-bytes",
            f"source-bytes-sha256:{source_sha256}",
            "not-production-rights-cleared",
            "no-production-ingestion",
            "no-model-egress",
            "no-prover-handoff",
            "no-promotion",
            "human-content-review-pending",
        }
        if not required_restrictions <= set(self.rights.restrictions):
            raise ValueError("project-synthetic fixture rights restrictions are incomplete")

    def mathematical_specification(self) -> MathematicalSpecificationV1:
        """Return a shared mathematical shape for inspection only, never a contract draft."""

        return self.normalized.as_mathematical_specification(
            informal_statement=self.source_text,
            ambiguities=self.ambiguities,
        )

    def prover_interface_preview(self) -> PreCalibrationFixtureInterfacePreviewV1:
        return PreCalibrationFixtureInterfacePreviewV1(
            sample_id=self.sample_id,
            source_id=self.source.source_id.value,
            source_content_sha256=self.source.content_hash.value,
            source_span_ids=tuple(span.span_id.value for span in self.source.spans),
            rights_id=self.rights.rights_id.value,
            normalized_statement_sha256=self.normalized.sha256,
            illustrative_snippet_snapshot_sha256=tuple(
                item.snapshot_sha256 for item in self.illustrative_lean_snippets
            ),
            blockers=(
                "PRE_CALIBRATION_FIXTURE_ONLY",
                "PROJECT_SYNTHETIC_PROVENANCE_PENDING_HUMAN_CONTENT_REVIEW",
                "INDEPENDENT_SEMANTIC_REVIEW_REQUIRED",
                "NORMAL_BUILDER_FREEZE_REQUIRED",
            ),
        )

    def machine_readable_report(self) -> dict[str, object]:
        """Return differences and prohibition reasons suitable for a dashboard projection."""

        preview = self.prover_interface_preview()
        return {
            "schema_version": "autolean.builder-pre-calibration-fixture-report.v1",
            "sample_id": self.sample_id,
            "domain": self.domain.value,
            "review_state": self.review.state.value,
            "production_ingestion": False,
            "freeze_allowed": False,
            "prover_handoff_allowed": False,
            "production_rights_cleared": False,
            "promotion_allowed": False,
            "mutation_fixtures": [
                {
                    "difference_kind": item.difference_kind.value,
                    "baseline_fragment": item.baseline_fragment,
                    "mutated_fragment": item.mutated_fragment,
                    "blocker_code": item.blocker_code,
                    "blocker_reason": item.blocker_reason,
                    "probe_id": item.probe.probe_id.value,
                    "probe_kind": item.probe.kind.value,
                    "status": item.status,
                    "evidence_class": item.evidence_class,
                    "semantic_detection_claimed": item.semantic_detection_claimed,
                    "promotion_allowed": item.promotion_allowed,
                }
                for item in self.mutation_fixtures
            ],
            "block_reasons": list(preview.blockers),
            "builder_prover_interface_preview": preview.model_dump(mode="json"),
        }

    def assert_illustrative_snapshot_unchanged(
        self,
        *,
        snippet_id: str,
        observed_text: str,
    ) -> None:
        """Check exact illustrative bytes; success establishes no semantic property."""

        snippet = next(
            (item for item in self.illustrative_lean_snippets if item.snippet_id == snippet_id),
            None,
        )
        if snippet is None:
            raise LocalCalibrationError("unknown illustrative snippet snapshot")
        if observed_text != snippet.illustrative_lean_snippet:
            raise LocalCalibrationError(
                "illustrative snippet snapshot drift; this byte check establishes no semantics"
            )

    def assert_non_authoritative(self) -> None:
        if (
            self.production_ingestion
            or self.freeze_allowed
            or self.prover_handoff_allowed
            or self.production_rights_cleared
            or self.promotion_allowed
            or self.authority.production_ingestion
            or self.authority.freeze_allowed
            or self.authority.prover_handoff_allowed
            or self.authority.model_egress_allowed
            or self.authority.production_rights_cleared
            or self.authority.promotion_allowed
        ):
            raise LocalCalibrationError(
                "pre-calibration fixture artifacts must remain non-authoritative"
            )

    def freeze_builder_statement(self) -> Never:
        raise LocalCalibrationError(
            "pre-calibration fixture cannot freeze a statement; use "
            "StatementFidelityHarness and FreezeGate"
        )

    def handoff_to_prover(self) -> Never:
        raise LocalCalibrationError(
            "pre-calibration fixture cannot hand off to Prover; "
            "use the frozen Builder-Prover bridge"
        )


class LocalCalibrationFixtureCorpusV1(ContractModel):
    schema_version: Literal["autolean.builder-local-calibration-fixture-corpus.v1"] = (
        "autolean.builder-local-calibration-fixture-corpus.v1"
    )
    record_kind: Literal["local_calibration_fixture"] = "local_calibration_fixture"
    corpus_id: Literal["project-synthetic-opening-pre-calibration"] = (
        "project-synthetic-opening-pre-calibration"
    )
    provenance_class: Literal["project_synthetic_fixture"] = "project_synthetic_fixture"
    authorship_claim: Literal["generated_for_repository_pending_human_content_review"] = (
        "generated_for_repository_pending_human_content_review"
    )
    human_content_review_completed: Literal[False] = False
    legal_review_claimed: Literal[False] = False
    repository_license_binding: ProjectSyntheticFixtureLicenseBindingV1
    production_rights_cleared: Literal[False] = False
    promotion_allowed: Literal[False] = False
    samples: tuple[PreCalibrationFixtureRecordV1, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_corpus(self) -> LocalCalibrationFixtureCorpusV1:
        ids = [item.sample_id for item in self.samples]
        if len(ids) != len(set(ids)):
            raise ValueError("pre-calibration fixture sample identifiers must be unique")
        return self

    def assert_opening_coverage(self) -> None:
        """Check the deliberately small, named Phase-2 discovery opening set."""

        expected = {
            "pde-a-transport-sign",
            "pde-a-initial-trace",
            "pde-a-parabolic-regularity",
            "pde-a-weak-uniqueness",
            "pde-a-local-existence",
            "mg-a-infimum-attainment",
            "mg-a-length-geodesic",
            "mg-a-quantifier-order",
            "mg-a-nonempty-vacuity",
            "mg-a-finite-noetherian-compactness",
            "mg-a-endpoint-order",
        }
        actual = {item.sample_id for item in self.samples}
        if actual != expected:
            raise LocalCalibrationError(
                "opening corpus does not contain the required eleven samples"
            )
        by_domain = {domain: 0 for domain in LocalCalibrationDomainV1}
        for sample in self.samples:
            by_domain[sample.domain] += 1
        if by_domain != {LocalCalibrationDomainV1.PDE_A: 5, LocalCalibrationDomainV1.MG_A: 6}:
            raise LocalCalibrationError(
                "opening corpus must contain five PDE-A and six MG-A samples"
            )
        difference_kinds = {
            outcome.difference_kind
            for sample in self.samples
            for outcome in sample.mutation_fixtures
        }
        required = {
            LocalCalibrationDifferenceKindV1.SIGN_FLIP,
            LocalCalibrationDifferenceKindV1.STRICT_TO_NONSTRICT,
            LocalCalibrationDifferenceKindV1.QUANTIFIER_SWAP,
            LocalCalibrationDifferenceKindV1.DROP_NONEMPTY,
            LocalCalibrationDifferenceKindV1.DROP_REGULARITY,
            LocalCalibrationDifferenceKindV1.INFIMUM_TO_ATTAINMENT,
            LocalCalibrationDifferenceKindV1.UNIQUENESS_TO_EXISTENCE,
            LocalCalibrationDifferenceKindV1.DROP_FINITE,
            LocalCalibrationDifferenceKindV1.DROP_NOETHERIAN,
        }
        if not required <= difference_kinds:
            raise LocalCalibrationError(
                "opening corpus is missing a required declared synthetic mutation fixture"
            )

    def machine_readable_report(self) -> dict[str, object]:
        self.assert_opening_coverage()
        return {
            "schema_version": "autolean.builder-local-calibration-fixture-corpus-report.v1",
            "corpus_id": self.corpus_id,
            "record_kind": self.record_kind,
            "provenance_class": self.provenance_class,
            "authorship_claim": self.authorship_claim,
            "human_content_review_completed": self.human_content_review_completed,
            "legal_review_claimed": self.legal_review_claimed,
            "repository_license_binding": self.repository_license_binding.model_dump(mode="json"),
            "production_rights_cleared": self.production_rights_cleared,
            "promotion_allowed": self.promotion_allowed,
            "sample_count": len(self.samples),
            "reports": [sample.machine_readable_report() for sample in self.samples],
        }


def _sha256_file(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise LocalCalibrationError(
            f"cannot hash pre-calibration fixture dependency: {path}"
        ) from error


def _fixture_repository_root(path: Path) -> Path:
    resolved = path.resolve()
    expected_parts = (
        "Builder",
        "pilots",
        "local-calibration",
        _PROJECT_SYNTHETIC_FIXTURE_CORPUS_NAME,
    )
    if tuple(resolved.parts[-4:]) != expected_parts:
        raise LocalCalibrationError(
            "pre-calibration fixture must use its canonical repository path"
        )
    return resolved.parents[3]


def _verify_release_manifest(
    *,
    path: Path,
    corpus: LocalCalibrationFixtureCorpusV1,
) -> None:
    root = _fixture_repository_root(path)
    binding = corpus.repository_license_binding
    license_path = root / binding.repository_license_path
    if _sha256_file(license_path) != binding.repository_license_sha256:
        raise LocalCalibrationError("repository LICENSE bytes differ from the fixture binding")

    manifest_path = path.with_name(_PROJECT_SYNTHETIC_FIXTURE_MANIFEST_NAME)
    try:
        manifest_payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LocalCalibrationError(
            "cannot load project-synthetic fixture release manifest"
        ) from error
    manifest = ProjectSyntheticFixtureReleaseManifestV1.model_validate(manifest_payload)
    corpus_sha256 = _sha256_file(path)
    if (
        corpus_sha256 != _PROJECT_SYNTHETIC_FIXTURE_CORPUS_SHA256
        or manifest.fixture_sha256 != _PROJECT_SYNTHETIC_FIXTURE_CORPUS_SHA256
    ):
        raise LocalCalibrationError("pre-calibration corpus bytes differ from the release manifest")
    if manifest.repository_license_sha256 != _sha256_file(license_path):
        raise LocalCalibrationError("release manifest repository LICENSE hash differs")
    renderer_path = root / manifest.renderer_path
    if manifest.renderer_sha256 != _sha256_file(renderer_path):
        raise LocalCalibrationError(
            "pre-calibration renderer bytes differ from the release manifest"
        )


def load_local_calibration_fixture_corpus(path: Path) -> LocalCalibrationFixtureCorpusV1:
    """Load the exact project-synthetic fixture without reference-cache or model access."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LocalCalibrationError(
            f"cannot load pre-calibration fixture corpus: {path}"
        ) from error
    if not isinstance(payload, dict):
        raise LocalCalibrationError("pre-calibration fixture corpus root must be a JSON object")
    corpus = LocalCalibrationFixtureCorpusV1.model_validate(payload)
    corpus.assert_opening_coverage()
    _verify_release_manifest(path=path, corpus=corpus)
    return corpus


def project_synthetic_fixture_source_record(
    *,
    sample_id: str,
    source_text: str,
    title: str,
) -> SourceRecordV1:
    """Build exact project-synthetic bytes without claiming human authorship or review."""

    source_bytes = source_text.encode("utf-8")
    return SourceRecordV1(
        source_id=stable_identifier("pre-calibration-fixture-source", sample_id),
        work_id=sample_id,
        title=title,
        version="project-synthetic-fixture-v1",
        locator=f"autolean://builder/pre-calibration-fixture/{sample_id}",
        content_hash=digest_bytes(HashKindV1.SOURCE_BYTES, source_bytes),
        snapshot_ref=f"project-synthetic-fixture:{sample_id}:v1",
        retrieved_at=datetime(2026, 7, 27, tzinfo=UTC),
        spans=(
            SourceSpanV1(
                span_id=stable_identifier("pre-calibration-fixture-span", sample_id),
                locator=f"autolean://builder/pre-calibration-fixture/{sample_id}#statement",
                content_hash=digest_text(HashKindV1.SOURCE_SPAN, source_text),
                start_offset=0,
                end_offset=len(source_bytes),
                permitted_excerpt=source_text,
            ),
        ),
        metadata={
            "provenance_class": _PROJECT_SYNTHETIC_FIXTURE_PROVENANCE,
            "authorship_claim": _PROJECT_SYNTHETIC_FIXTURE_AUTHORSHIP_CLAIM,
            "human_content_review_completed": False,
            "purpose": "pre_calibration_fixture",
        },
    )


def project_synthetic_fixture_rights_record(
    *,
    sample_id: str,
    source_text: str,
) -> RightsRecordV1:
    """Allow public redistribution only for the exact repository-synthetic fixture bytes."""

    source_sha256 = hashlib.sha256(source_text.encode("utf-8")).hexdigest()

    return RightsRecordV1(
        rights_id=stable_identifier("pre-calibration-fixture-rights", sample_id),
        source_id=stable_identifier("pre-calibration-fixture-source", sample_id),
        source_license="Apache-2.0",
        generated_code_license="Apache-2.0",
        overall_decision=PermissionDecisionV1.RESTRICTED,
        redistribution=PermissionDecisionV1.ALLOW,
        model_egress=PermissionDecisionV1.DENY,
        training=PermissionDecisionV1.DENY,
        embedding=PermissionDecisionV1.DENY,
        allowed_endpoint_classes=(),
        attribution=None,
        restrictions=(
            "pre-calibration-fixture-only",
            "redistribution-only-exact-project-synthetic-fixture-bytes",
            f"source-bytes-sha256:{source_sha256}",
            "not-production-rights-cleared",
            "no-production-ingestion",
            "no-model-egress",
            "no-prover-handoff",
            "no-promotion",
            "human-content-review-pending",
        ),
        reviewed_by=None,
        reviewed_at=None,
    )
