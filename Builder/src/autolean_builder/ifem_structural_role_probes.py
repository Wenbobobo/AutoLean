"""Project-synthetic structural probe corpus for the iFEM risk catalog.

The corpus is public project-synthetic calibration metadata.  It commits to closed
structural signatures, paired mutations, and project-authored counterexample
specifications.  It contains no textbook text, Lean statement, prompt, prepared
provider request, or direct egress authority.  An independently rights-bound bridge
may derive prompts from it; that does not make this corpus held-out benchmark evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from enum import StrEnum
from pathlib import Path
from typing import Final, Literal, Never, Self, cast

from autolean_contracts import StableIdentifierV1, canonical_json_bytes, stable_identifier
from autolean_contracts.base import ContractModel
from pydantic import Field, model_validator

from .ifem_candidate_dependency_graph import (
    IFEMCandidateDependencyGraphV1,
    IFEMCandidateNodeIdV1,
)
from .ifem_structural_calibration import (
    IFEMStructuralCalibrationCaseV1,
    IFEMStructuralCalibrationCatalogV1,
    IFEMStructuralCalibrationRoleV1,
    IFEMStructuralCaseIdV1,
    IFEMStructuralMutationV1,
    IFEMStructuralRiskV1,
    build_ifem_structural_calibration_catalog,
)

IFEM_STRUCTURAL_ROLE_PROBE_SCHEMA: Final[
    Literal["autolean.ifem-structural-role-probe-corpus.v1"]
] = "autolean.ifem-structural-role-probe-corpus.v1"
IFEM_STRUCTURAL_ROLE_PROBE_KIND: Final[
    Literal["project_synthetic_evaluator_side_structural_probes"]
] = "project_synthetic_evaluator_side_structural_probes"
_SHA256 = r"^[0-9a-f]{64}$"


class IFEMStructuralRoleProbeError(ValueError):
    """A probe corpus drifted or attempted to cross its hard-negative boundary."""


class IFEMStructuralProbeRoleV1(StrEnum):
    """Closed future role projection, without importing the benchmark runtime."""

    STATEMENT_FORMALIZER = "statement_formalizer"
    FIDELITY_REVIEWER = "fidelity_reviewer"
    CHEATING_SUPERVISOR = "cheating_supervisor"


class IFEMStructuralProbeSlotV1(StrEnum):
    """The one structural slot a harmful mutant is allowed to change."""

    QUANTIFIER_ORDER = "quantifier_order"
    COERCIVITY_CONSTANT = "coercivity_constant"
    CONTINUITY_MAGNITUDE = "continuity_magnitude"
    SUBSPACE_TOPOLOGY = "subspace_topology"
    RESTRICTION_SCOPE = "restriction_scope"
    APPROXIMATION_TARGET = "approximation_target"
    FORM_PARAMETER_ORDER = "form_parameter_order"
    ANTECEDENT_STATUS = "antecedent_status"


class IFEMStructuralWitnessKindV1(StrEnum):
    """Closed project-authored falsification anchor vocabulary."""

    TWO_POINT_EQUALITY_QUANTIFIERS = "two_point_equality_quantifiers"
    NONTRIVIAL_ZERO_FORM = "nontrivial_zero_form"
    SIGNED_FORM_BOUND = "signed_form_bound"
    DENSE_NONCLOSED_SUBSPACE = "dense_nonclosed_subspace"
    AMBIENT_OUTSIDE_SUBSPACE = "ambient_outside_subspace"
    NONATTAINED_OPEN_INTERVAL_INFIMUM = "nonattained_open_interval_infimum"
    NONSYMMETRIC_FORM = "nonsymmetric_form"
    SATISFIABLE_ANTECEDENT = "satisfiable_antecedent"


_PROBE_ROLE_BY_CATALOG_ROLE: Final[
    dict[IFEMStructuralCalibrationRoleV1, IFEMStructuralProbeRoleV1]
] = {
    IFEMStructuralCalibrationRoleV1.CONVERSION_PROPOSER: (
        IFEMStructuralProbeRoleV1.STATEMENT_FORMALIZER
    ),
    IFEMStructuralCalibrationRoleV1.FIDELITY_REVIEWER: (
        IFEMStructuralProbeRoleV1.FIDELITY_REVIEWER
    ),
    IFEMStructuralCalibrationRoleV1.MUTATION_CRITIC: (
        IFEMStructuralProbeRoleV1.CHEATING_SUPERVISOR
    ),
}

_MUTATION_BY_RISK: Final[dict[IFEMStructuralRiskV1, IFEMStructuralMutationV1]] = {
    IFEMStructuralRiskV1.QUANTIFIER_ORDER: (IFEMStructuralMutationV1.QUANTIFIER_ORDER_SWAPPED),
    IFEMStructuralRiskV1.POSITIVITY: IFEMStructuralMutationV1.POSITIVITY_REMOVED,
    IFEMStructuralRiskV1.ABSOLUTE_VALUE: IFEMStructuralMutationV1.ABSOLUTE_VALUE_DROPPED,
    IFEMStructuralRiskV1.CLOSED_SUBSPACE: (IFEMStructuralMutationV1.CLOSED_SUBSPACE_REMOVED),
    IFEMStructuralRiskV1.RESTRICTION_DOMAIN: (IFEMStructuralMutationV1.RESTRICTION_DOMAIN_WIDENED),
    IFEMStructuralRiskV1.INFIMUM_TO_ATTAINMENT: (
        IFEMStructuralMutationV1.INFIMUM_REPLACED_BY_ATTAINMENT
    ),
    IFEMStructuralRiskV1.PARAMETER_REVERSAL: (IFEMStructuralMutationV1.PARAMETER_ORDER_REVERSED),
    IFEMStructuralRiskV1.VACUOUS_HYPOTHESIS: (
        IFEMStructuralMutationV1.VACUOUS_ANTECEDENT_INTRODUCED
    ),
}

_SLOT_BY_RISK: Final[dict[IFEMStructuralRiskV1, IFEMStructuralProbeSlotV1]] = {
    IFEMStructuralRiskV1.QUANTIFIER_ORDER: IFEMStructuralProbeSlotV1.QUANTIFIER_ORDER,
    IFEMStructuralRiskV1.POSITIVITY: IFEMStructuralProbeSlotV1.COERCIVITY_CONSTANT,
    IFEMStructuralRiskV1.ABSOLUTE_VALUE: IFEMStructuralProbeSlotV1.CONTINUITY_MAGNITUDE,
    IFEMStructuralRiskV1.CLOSED_SUBSPACE: IFEMStructuralProbeSlotV1.SUBSPACE_TOPOLOGY,
    IFEMStructuralRiskV1.RESTRICTION_DOMAIN: IFEMStructuralProbeSlotV1.RESTRICTION_SCOPE,
    IFEMStructuralRiskV1.INFIMUM_TO_ATTAINMENT: (IFEMStructuralProbeSlotV1.APPROXIMATION_TARGET),
    IFEMStructuralRiskV1.PARAMETER_REVERSAL: (IFEMStructuralProbeSlotV1.FORM_PARAMETER_ORDER),
    IFEMStructuralRiskV1.VACUOUS_HYPOTHESIS: IFEMStructuralProbeSlotV1.ANTECEDENT_STATUS,
}

_WITNESS_KIND_BY_RISK: Final[dict[IFEMStructuralRiskV1, IFEMStructuralWitnessKindV1]] = {
    IFEMStructuralRiskV1.QUANTIFIER_ORDER: (
        IFEMStructuralWitnessKindV1.TWO_POINT_EQUALITY_QUANTIFIERS
    ),
    IFEMStructuralRiskV1.POSITIVITY: IFEMStructuralWitnessKindV1.NONTRIVIAL_ZERO_FORM,
    IFEMStructuralRiskV1.ABSOLUTE_VALUE: IFEMStructuralWitnessKindV1.SIGNED_FORM_BOUND,
    IFEMStructuralRiskV1.CLOSED_SUBSPACE: (IFEMStructuralWitnessKindV1.DENSE_NONCLOSED_SUBSPACE),
    IFEMStructuralRiskV1.RESTRICTION_DOMAIN: (IFEMStructuralWitnessKindV1.AMBIENT_OUTSIDE_SUBSPACE),
    IFEMStructuralRiskV1.INFIMUM_TO_ATTAINMENT: (
        IFEMStructuralWitnessKindV1.NONATTAINED_OPEN_INTERVAL_INFIMUM
    ),
    IFEMStructuralRiskV1.PARAMETER_REVERSAL: (IFEMStructuralWitnessKindV1.NONSYMMETRIC_FORM),
    IFEMStructuralRiskV1.VACUOUS_HYPOTHESIS: (IFEMStructuralWitnessKindV1.SATISFIABLE_ANTECEDENT),
}


class IFEMStructuralRoleProbeAuthorityV1(ContractModel):
    """Hard-negative authority inherited by every probe artifact."""

    schema_version: Literal["autolean.ifem-structural-role-probe-authority.v1"] = (
        "autolean.ifem-structural-role-probe-authority.v1"
    )
    evidence_class: Literal["project_synthetic_structural_commitment_only"] = (
        "project_synthetic_structural_commitment_only"
    )
    source_text_derived: Literal[False] = False
    source_text_present: Literal[False] = False
    semantic_equivalence_claimed: Literal[False] = False
    mathematical_witness_validated: Literal[False] = False
    lean_statement_created: Literal[False] = False
    model_input_created: Literal[False] = False
    model_egress_allowed: Literal[False] = False
    benchmark_matrix_created: Literal[False] = False
    provider_work_created: Literal[False] = False
    statement_contract_created: Literal[False] = False
    formal_graph_created: Literal[False] = False
    execution_graph_created: Literal[False] = False
    freeze_allowed: Literal[False] = False
    prover_handoff_allowed: Literal[False] = False
    promotion_allowed: Literal[False] = False


class IFEMStructuralProbeRoleMappingV1(ContractModel):
    """One explicit, non-authoritative catalog-to-probe role projection."""

    catalog_role: IFEMStructuralCalibrationRoleV1
    probe_role: IFEMStructuralProbeRoleV1

    @model_validator(mode="after")
    def validate_mapping(self) -> Self:
        if self.probe_role is not _PROBE_ROLE_BY_CATALOG_ROLE[self.catalog_role]:
            raise ValueError("structural probe role mapping differs from the fixed projection")
        return self


class IFEMStructuralProbeSignatureV1(ContractModel):
    """One closed eight-slot signature; it is not a proposition or model payload."""

    schema_version: Literal["autolean.ifem-structural-probe-signature.v1"] = (
        "autolean.ifem-structural-probe-signature.v1"
    )
    quantifier_order: Literal["forall_exists", "exists_forall"]
    coercivity_constant: Literal["strictly_positive", "nonnegative_allowed"]
    continuity_magnitude: Literal["absolute_value", "raw_value"]
    subspace_topology: Literal["closed_required", "closedness_omitted"]
    restriction_scope: Literal["trial_subspace", "ambient_space"]
    approximation_target: Literal["infimum", "attained_minimum"]
    form_parameter_order: Literal["trial_test", "test_trial"]
    antecedent_status: Literal["satisfiable", "contradictory"]

    @property
    def content_sha256(self) -> str:
        return _sha256_json(self.model_dump(mode="json"))


class IFEMStructuralWitnessCommitmentV1(ContractModel):
    """Digest commitment to one fixed project-synthetic falsification anchor."""

    schema_version: Literal["autolean.ifem-structural-witness-commitment.v1"] = (
        "autolean.ifem-structural-witness-commitment.v1"
    )
    risk: IFEMStructuralRiskV1
    witness_kind: IFEMStructuralWitnessKindV1
    commitment_sha256: str = Field(pattern=_SHA256)
    specification_embedded: Literal[False] = False
    mathematical_validation_claimed: Literal[False] = False
    authority: IFEMStructuralRoleProbeAuthorityV1 = Field(
        default_factory=IFEMStructuralRoleProbeAuthorityV1
    )

    @model_validator(mode="after")
    def validate_commitment(self) -> Self:
        if self.witness_kind is not _WITNESS_KIND_BY_RISK[self.risk]:
            raise ValueError("witness kind differs from the fixed structural risk binding")
        if self.commitment_sha256 != _witness_commitment_sha256(self.risk):
            raise ValueError("witness commitment differs from the fixed project-synthetic anchor")
        return self


class IFEMStructuralRoleProbePairV1(ContractModel):
    """One surface-matched baseline/mutant pair bound to an exact catalog case."""

    schema_version: Literal["autolean.ifem-structural-role-probe-pair.v1"] = (
        "autolean.ifem-structural-role-probe-pair.v1"
    )
    pair_id: StableIdentifierV1
    catalog_case_id: IFEMStructuralCaseIdV1
    catalog_case_sha256: str = Field(pattern=_SHA256)
    catalog_role: IFEMStructuralCalibrationRoleV1
    probe_role: IFEMStructuralProbeRoleV1
    risk: IFEMStructuralRiskV1
    mutation: IFEMStructuralMutationV1
    candidate_node_ids: tuple[IFEMCandidateNodeIdV1, ...] = Field(min_length=2, max_length=3)
    baseline: IFEMStructuralProbeSignatureV1
    mutant: IFEMStructuralProbeSignatureV1
    changed_slot: IFEMStructuralProbeSlotV1
    witness: IFEMStructuralWitnessCommitmentV1
    pair_sha256: str = Field(pattern=_SHA256)
    authority: IFEMStructuralRoleProbeAuthorityV1 = Field(
        default_factory=IFEMStructuralRoleProbeAuthorityV1
    )

    @model_validator(mode="after")
    def validate_pair(self) -> Self:
        if self.pair_id.namespace != "ifem.structural-role-probe-pair":
            raise ValueError("structural probe pair identifier has an unexpected namespace")
        if self.probe_role is not _PROBE_ROLE_BY_CATALOG_ROLE[self.catalog_role]:
            raise ValueError("structural probe pair has an invalid role projection")
        if self.mutation is not _MUTATION_BY_RISK[self.risk]:
            raise ValueError("structural probe mutation differs from its risk family")
        if self.changed_slot is not _SLOT_BY_RISK[self.risk]:
            raise ValueError("structural probe changed slot differs from its risk family")
        if self.witness.risk is not self.risk:
            raise ValueError("structural probe witness differs from its risk family")
        if self.candidate_node_ids != tuple(sorted(set(self.candidate_node_ids))):
            raise ValueError("structural probe node identifiers must be canonical and unique")
        if self.baseline != _baseline_signature():
            raise ValueError("structural probe baseline differs from the fixed complete signature")
        if self.mutant != _mutant_signature(self.risk):
            raise ValueError("structural probe mutant differs from the fixed single-slot mutation")
        baseline = self.baseline.model_dump(mode="json")
        mutant = self.mutant.model_dump(mode="json")
        changed = tuple(key for key in baseline if baseline[key] != mutant[key])
        if changed != (self.changed_slot.value,):
            raise ValueError("baseline and mutant must differ in exactly the declared slot")
        if self.pair_sha256 != self.computed_pair_sha256():
            raise ValueError("structural probe pair hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"pair_sha256"}),
        )

    def computed_pair_sha256(self) -> str:
        return _sha256_json(self.content_payload())


class IFEMStructuralRoleProbeCorpusV1(ContractModel):
    """Complete public calibration corpus for the fixed source-text-free risk catalog."""

    schema_version: Literal["autolean.ifem-structural-role-probe-corpus.v1"] = (
        IFEM_STRUCTURAL_ROLE_PROBE_SCHEMA
    )
    artifact_kind: Literal["project_synthetic_evaluator_side_structural_probes"] = (
        IFEM_STRUCTURAL_ROLE_PROBE_KIND
    )
    authorship_class: Literal["autolean_project_synthetic"] = "autolean_project_synthetic"
    lane_id: Literal["ifem-coercive-galerkin"] = "ifem-coercive-galerkin"
    candidate_graph_content_sha256: str = Field(pattern=_SHA256)
    catalog: IFEMStructuralCalibrationCatalogV1
    role_mappings: tuple[IFEMStructuralProbeRoleMappingV1, ...] = Field(min_length=3)
    risk_families: tuple[IFEMStructuralRiskV1, ...] = Field(min_length=8)
    pairs: tuple[IFEMStructuralRoleProbePairV1, ...] = Field(min_length=16, max_length=16)
    contains_source_text: Literal[False] = False
    contains_source_excerpt: Literal[False] = False
    contains_lean_statement: Literal[False] = False
    contains_model_input: Literal[False] = False
    contains_provider_request: Literal[False] = False
    contains_benchmark_matrix: Literal[False] = False
    authority: IFEMStructuralRoleProbeAuthorityV1 = Field(
        default_factory=IFEMStructuralRoleProbeAuthorityV1
    )
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_corpus(self) -> Self:
        if (
            self.candidate_graph_content_sha256
            != self.catalog.source_binding.candidate_graph_content_sha256
        ):
            raise ValueError("probe corpus graph hash differs from its catalog binding")
        if self.role_mappings != _expected_role_mappings():
            raise ValueError("probe corpus role mappings differ from the fixed projection")
        expected_risks = tuple(sorted(IFEMStructuralRiskV1, key=str))
        if self.risk_families != expected_risks:
            raise ValueError("probe corpus risks differ from the closed vocabulary")
        expected_pairs = _expected_pairs(self.catalog)
        if self.pairs != expected_pairs:
            raise ValueError("probe corpus pairs differ from the exact catalog projection")
        case_ids = tuple(pair.catalog_case_id for pair in self.pairs)
        if len(set(case_ids)) != len(case_ids):
            raise ValueError("probe corpus maps a catalog case more than once")
        risk_counts = {risk: 0 for risk in IFEMStructuralRiskV1}
        for pair in self.pairs:
            risk_counts[pair.risk] += 1
        if set(risk_counts.values()) != {2}:
            raise ValueError("every structural risk must have exactly two role-specific pairs")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("probe corpus content hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(
            dict[str, object],
            self.model_dump(mode="json", exclude={"content_sha256"}),
        )

    def computed_content_sha256(self) -> str:
        return _sha256_json(self.content_payload())

    def assert_not_routable(self) -> Never:
        raise IFEMStructuralRoleProbeError(
            "the iFEM structural corpus cannot directly create model input, authorize egress, "
            "create a benchmark matrix, freeze a statement, or hand work to Prover; a separate "
            "rights-bound bridge is required"
        )

    def create_model_input(self) -> Never:
        self.assert_not_routable()

    def authorize_model_egress(self) -> Never:
        self.assert_not_routable()

    def create_benchmark_matrix(self) -> Never:
        self.assert_not_routable()

    def freeze_statement(self) -> Never:
        self.assert_not_routable()

    def handoff_to_prover(self) -> Never:
        self.assert_not_routable()


def build_ifem_structural_role_probe_corpus(
    *,
    catalog: IFEMStructuralCalibrationCatalogV1,
    graph: IFEMCandidateDependencyGraphV1,
) -> IFEMStructuralRoleProbeCorpusV1:
    """Rebuild the catalog from ``graph`` and return its exact paired projection."""

    verified_graph = _revalidate_graph(graph)
    verified_catalog = _revalidate_catalog(catalog)
    expected_catalog = build_ifem_structural_calibration_catalog(verified_graph)
    if verified_catalog != expected_catalog:
        raise IFEMStructuralRoleProbeError(
            "structural probe catalog is not the exact catalog rebuilt from the supplied graph"
        )
    role_mappings = _expected_role_mappings()
    risks = tuple(sorted(IFEMStructuralRiskV1, key=str))
    pairs = _expected_pairs(verified_catalog)
    authority = IFEMStructuralRoleProbeAuthorityV1()
    payload: dict[str, object] = {
        "schema_version": IFEM_STRUCTURAL_ROLE_PROBE_SCHEMA,
        "artifact_kind": IFEM_STRUCTURAL_ROLE_PROBE_KIND,
        "authorship_class": "autolean_project_synthetic",
        "lane_id": "ifem-coercive-galerkin",
        "candidate_graph_content_sha256": verified_graph.content_sha256,
        "catalog": verified_catalog.model_dump(mode="json"),
        "role_mappings": [item.model_dump(mode="json") for item in role_mappings],
        "risk_families": [str(risk) for risk in risks],
        "pairs": [pair.model_dump(mode="json") for pair in pairs],
        "contains_source_text": False,
        "contains_source_excerpt": False,
        "contains_lean_statement": False,
        "contains_model_input": False,
        "contains_provider_request": False,
        "contains_benchmark_matrix": False,
        "authority": authority.model_dump(mode="json"),
    }
    payload["content_sha256"] = _sha256_json(payload)
    try:
        return IFEMStructuralRoleProbeCorpusV1.model_validate(payload)
    except ValueError as error:
        raise IFEMStructuralRoleProbeError(
            "iFEM structural role probe corpus did not validate"
        ) from error


def render_ifem_structural_role_probe_corpus(
    corpus: IFEMStructuralRoleProbeCorpusV1,
) -> bytes:
    """Serialize only a completely revalidated evaluator-side corpus."""

    if type(corpus) is not IFEMStructuralRoleProbeCorpusV1:
        raise IFEMStructuralRoleProbeError(
            "cannot render an object that is not an iFEM structural role probe corpus"
        )
    try:
        verified = IFEMStructuralRoleProbeCorpusV1.model_validate(corpus.model_dump(mode="json"))
    except ValueError as error:
        raise IFEMStructuralRoleProbeError(
            "cannot render an invalid or model-constructed structural role probe corpus"
        ) from error
    return canonical_json_bytes(verified.model_dump(mode="json")) + b"\n"


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise IFEMStructuralRoleProbeError(f"duplicate corpus JSON key: {key}")
        document[key] = value
    return document


def _is_link_or_reparse(path: Path, metadata: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    file_attributes = getattr(metadata, "st_file_attributes", 0)
    return (
        stat.S_ISLNK(metadata.st_mode) or bool(file_attributes & reparse_flag) or path.is_symlink()
    )


def _physical_parent_identities(path: Path) -> tuple[tuple[int, int], ...]:
    identities: list[tuple[int, int]] = []
    for parent in path.parents:
        metadata = parent.stat(follow_symlinks=False)
        if _is_link_or_reparse(parent, metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise IFEMStructuralRoleProbeError(
                "structural probe corpus parent chain must contain only physical directories"
            )
        identities.append((metadata.st_dev, metadata.st_ino))
    return tuple(identities)


def load_ifem_structural_role_probe_corpus(
    path: Path,
    *,
    expected_file_sha256: str,
    expected_content_sha256: str,
) -> IFEMStructuralRoleProbeCorpusV1:
    """Load one exact public corpus without depending on operator-local source bytes."""

    if not isinstance(path, Path):
        raise IFEMStructuralRoleProbeError("structural probe corpus path must be a Path")
    try:
        parents_before = _physical_parent_identities(path)
        before = path.lstat()
        if _is_link_or_reparse(path, before) or not stat.S_ISREG(before.st_mode):
            raise IFEMStructuralRoleProbeError(
                "structural probe corpus must be an unlinked regular file"
            )
        raw = path.read_bytes()
        after = path.lstat()
        parents_after = _physical_parent_identities(path)
    except OSError as error:
        raise IFEMStructuralRoleProbeError("structural probe corpus is unavailable") from error
    if (
        _is_link_or_reparse(path, after)
        or not stat.S_ISREG(after.st_mode)
        or (before.st_dev, before.st_ino, before.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
        or parents_before != parents_after
    ):
        raise IFEMStructuralRoleProbeError("structural probe corpus changed while loading")
    if hashlib.sha256(raw).hexdigest() != expected_file_sha256:
        raise IFEMStructuralRoleProbeError("structural probe corpus file hash drifted")
    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IFEMStructuralRoleProbeError("structural probe corpus is not strict JSON") from error
    if not isinstance(payload, dict):
        raise IFEMStructuralRoleProbeError("structural probe corpus must be a JSON object")
    try:
        corpus = IFEMStructuralRoleProbeCorpusV1.model_validate(payload)
    except ValueError as error:
        raise IFEMStructuralRoleProbeError("structural probe corpus is invalid") from error
    if corpus.content_sha256 != expected_content_sha256:
        raise IFEMStructuralRoleProbeError("structural probe corpus content hash drifted")
    if render_ifem_structural_role_probe_corpus(corpus) != raw:
        raise IFEMStructuralRoleProbeError("structural probe corpus is not canonically rendered")
    return corpus


def _revalidate_graph(graph: IFEMCandidateDependencyGraphV1) -> IFEMCandidateDependencyGraphV1:
    if type(graph) is not IFEMCandidateDependencyGraphV1:
        raise IFEMStructuralRoleProbeError(
            "structural probes require an IFEMCandidateDependencyGraphV1 input"
        )
    try:
        return IFEMCandidateDependencyGraphV1.model_validate(graph.model_dump(mode="json"))
    except ValueError as error:
        raise IFEMStructuralRoleProbeError(
            "structural probes require a revalidated candidate graph"
        ) from error


def _revalidate_catalog(
    catalog: IFEMStructuralCalibrationCatalogV1,
) -> IFEMStructuralCalibrationCatalogV1:
    if type(catalog) is not IFEMStructuralCalibrationCatalogV1:
        raise IFEMStructuralRoleProbeError(
            "structural probes require an IFEMStructuralCalibrationCatalogV1 input"
        )
    try:
        return IFEMStructuralCalibrationCatalogV1.model_validate(catalog.model_dump(mode="json"))
    except ValueError as error:
        raise IFEMStructuralRoleProbeError(
            "structural probes require a revalidated structural calibration catalog"
        ) from error


def _expected_role_mappings() -> tuple[IFEMStructuralProbeRoleMappingV1, ...]:
    return tuple(
        IFEMStructuralProbeRoleMappingV1(
            catalog_role=role,
            probe_role=_PROBE_ROLE_BY_CATALOG_ROLE[role],
        )
        for role in sorted(IFEMStructuralCalibrationRoleV1, key=str)
    )


def _baseline_signature() -> IFEMStructuralProbeSignatureV1:
    return IFEMStructuralProbeSignatureV1(
        quantifier_order="forall_exists",
        coercivity_constant="strictly_positive",
        continuity_magnitude="absolute_value",
        subspace_topology="closed_required",
        restriction_scope="trial_subspace",
        approximation_target="infimum",
        form_parameter_order="trial_test",
        antecedent_status="satisfiable",
    )


def _mutant_signature(risk: IFEMStructuralRiskV1) -> IFEMStructuralProbeSignatureV1:
    payload = _baseline_signature().model_dump(mode="python")
    replacements: dict[IFEMStructuralRiskV1, str] = {
        IFEMStructuralRiskV1.QUANTIFIER_ORDER: "exists_forall",
        IFEMStructuralRiskV1.POSITIVITY: "nonnegative_allowed",
        IFEMStructuralRiskV1.ABSOLUTE_VALUE: "raw_value",
        IFEMStructuralRiskV1.CLOSED_SUBSPACE: "closedness_omitted",
        IFEMStructuralRiskV1.RESTRICTION_DOMAIN: "ambient_space",
        IFEMStructuralRiskV1.INFIMUM_TO_ATTAINMENT: "attained_minimum",
        IFEMStructuralRiskV1.PARAMETER_REVERSAL: "test_trial",
        IFEMStructuralRiskV1.VACUOUS_HYPOTHESIS: "contradictory",
    }
    payload[_SLOT_BY_RISK[risk].value] = replacements[risk]
    return IFEMStructuralProbeSignatureV1.model_validate(payload)


def _expected_pairs(
    catalog: IFEMStructuralCalibrationCatalogV1,
) -> tuple[IFEMStructuralRoleProbePairV1, ...]:
    return tuple(_pair_from_case(catalog, case) for case in catalog.cases)


def _pair_from_case(
    catalog: IFEMStructuralCalibrationCatalogV1,
    case: IFEMStructuralCalibrationCaseV1,
) -> IFEMStructuralRoleProbePairV1:
    baseline = _baseline_signature()
    mutant = _mutant_signature(case.risk)
    witness = IFEMStructuralWitnessCommitmentV1(
        risk=case.risk,
        witness_kind=_WITNESS_KIND_BY_RISK[case.risk],
        commitment_sha256=_witness_commitment_sha256(case.risk),
    )
    pair_payload: dict[str, object] = {
        "schema_version": "autolean.ifem-structural-role-probe-pair.v1",
        "pair_id": stable_identifier(
            "ifem.structural-role-probe-pair",
            f"{catalog.content_sha256}:{case.case_id}",
        ).model_dump(mode="json"),
        "catalog_case_id": case.case_id,
        "catalog_case_sha256": _sha256_json(case.model_dump(mode="json")),
        "catalog_role": case.role,
        "probe_role": _PROBE_ROLE_BY_CATALOG_ROLE[case.role],
        "risk": case.risk,
        "mutation": case.mutation,
        "candidate_node_ids": case.candidate_node_ids,
        "baseline": baseline.model_dump(mode="json"),
        "mutant": mutant.model_dump(mode="json"),
        "changed_slot": _SLOT_BY_RISK[case.risk],
        "witness": witness.model_dump(mode="json"),
        "authority": IFEMStructuralRoleProbeAuthorityV1().model_dump(mode="json"),
    }
    pair_payload["pair_sha256"] = _sha256_json(pair_payload)
    return IFEMStructuralRoleProbePairV1.model_validate(pair_payload)


def _witness_commitment_sha256(risk: IFEMStructuralRiskV1) -> str:
    commitment = _sha256_json(
        {
            "schema_version": "autolean.ifem-structural-witness-specification.v1",
            "risk": risk,
            "witness_kind": _WITNESS_KIND_BY_RISK[risk],
            "specification": _WITNESS_SPECIFICATIONS[risk],
            "project_synthetic": True,
            "mathematical_validation_claimed": False,
        }
    )
    expected = _WITNESS_COMMITMENT_GOLDENS[risk]
    if commitment != expected:
        raise IFEMStructuralRoleProbeError(
            "witness specification differs from the approved synthetic fixture"
        )
    return commitment


_WITNESS_SPECIFICATIONS: Final[dict[IFEMStructuralRiskV1, dict[str, object]]] = {
    IFEMStructuralRiskV1.QUANTIFIER_ORDER: {
        "universe": (0, 1),
        "relation": "y_equals_x",
        "baseline_order": ("forall_x", "exists_y"),
        "mutant_order": ("exists_y", "forall_x"),
        "refuter": "for_each_fixed_y_choose_the_other_x",
    },
    IFEMStructuralRiskV1.POSITIVITY: {
        "space": "real_line",
        "nontrivial_witness": "one",
        "form": "zero_bilinear_form",
        "baseline_constant_domain": "alpha_strictly_positive",
        "mutant_constant_domain": "alpha_nonnegative",
        "mutant_witness_alpha": "zero",
    },
    IFEMStructuralRiskV1.ABSOLUTE_VALUE: {
        "space": "real_line",
        "evaluation_scope": "singleton_pair_one_one",
        "scope_closed_under_sign_change": False,
        "form": "negative_product",
        "left_argument": "one",
        "right_argument": "one",
        "bound": "zero",
        "raw_value": "minus_one",
        "magnitude": "one",
    },
    IFEMStructuralRiskV1.CLOSED_SUBSPACE: {
        "ambient": "square_summable_real_sequences",
        "subspace": "finitely_supported_sequences",
        "property": "dense_nonclosed",
        "lost_structure": "completeness",
    },
    IFEMStructuralRiskV1.RESTRICTION_DOMAIN: {
        "ambient": "real_plane",
        "subspace": "first_coordinate_axis",
        "outside_witness": "second_basis_vector",
        "property": "ambient_element_not_in_subspace",
    },
    IFEMStructuralRiskV1.INFIMUM_TO_ATTAINMENT: {
        "domain": "open_unit_interval",
        "objective": "identity",
        "infimum": "zero",
        "attained": False,
    },
    IFEMStructuralRiskV1.PARAMETER_REVERSAL: {
        "space": "real_plane",
        "matrix": ((2, 1), (0, 2)),
        "left_argument": "first_basis_vector",
        "right_argument": "second_basis_vector",
        "forward_value": "one",
        "reverse_value": "zero",
        "symmetric_part_positive_definite": True,
        "symmetry_assumed": False,
    },
    IFEMStructuralRiskV1.VACUOUS_HYPOTHESIS: {
        "domain": "real_line",
        "baseline_antecedent": "x_equals_zero",
        "baseline_witness": "zero",
        "mutant_extra_antecedent": "x_not_equal_zero",
        "mutant_satisfiable": False,
        "baseline_theorem_truth": True,
        "mutant_theorem_truth": True,
        "requires_guard_satisfiability_oracle": True,
    },
}


_WITNESS_COMMITMENT_GOLDENS: Final[dict[IFEMStructuralRiskV1, str]] = {
    IFEMStructuralRiskV1.ABSOLUTE_VALUE: (
        "821df9e95555509b728a7f368a020c54fd5c033637d17e23f248b5eac18598a6"
    ),
    IFEMStructuralRiskV1.CLOSED_SUBSPACE: (
        "76788c10a2f6cdc3bd96d8244da17d4a552a32c2a63722f8176b135d2647ddfd"
    ),
    IFEMStructuralRiskV1.INFIMUM_TO_ATTAINMENT: (
        "3497a875734e2c0318f15fb913feed7e359138716e400d2e43393cc9a63f35ce"
    ),
    IFEMStructuralRiskV1.PARAMETER_REVERSAL: (
        "4c0c46191de1e49ecb6f93df28034652d688a0a2d38be528d548f4b0ddf09e5d"
    ),
    IFEMStructuralRiskV1.POSITIVITY: (
        "9f1040daf3b8c54db63f47f44870bebaf1452379d0a01ca86f37ef8786dc747b"
    ),
    IFEMStructuralRiskV1.QUANTIFIER_ORDER: (
        "02e55d2b93eac5a7e8a05433c67433257d2422727542ed22cbf5d14b8d9469e0"
    ),
    IFEMStructuralRiskV1.RESTRICTION_DOMAIN: (
        "1e9dfe455a25f8c58e2455b13612c2a6e2089ad1660676de2e5424c681c1daa2"
    ),
    IFEMStructuralRiskV1.VACUOUS_HYPOTHESIS: (
        "2456683514edd1ba559f5fb6e8f4a97e0da665c05a2387dc92b40bdf2561007f"
    ),
}


def _sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()
