"""Source-free structural calibration contract for the iFEM discovery graph.

This module deliberately records only a closed, project-authored mutation plan.
It does not extract or paraphrase a textbook, construct a Lean declaration, or
create an authority path from Builder to Prover.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Literal, Never, cast

from autolean_contracts import canonical_json_bytes
from autolean_contracts.base import ContractModel
from pydantic import Field, model_validator

from .ifem_candidate_dependency_graph import (
    IFEMCandidateDependencyGraphV1,
    IFEMCandidateGraphSourceBindingV1,
    IFEMCandidateNodeIdV1,
)

IFEM_STRUCTURAL_CALIBRATION_SCHEMA: Final[Literal["autolean.ifem-structural-calibration.v1"]] = (
    "autolean.ifem-structural-calibration.v1"
)
IFEM_STRUCTURAL_CALIBRATION_KIND: Final[Literal["source_free_structural_calibration_plan"]] = (
    "source_free_structural_calibration_plan"
)
_SHA256 = r"^[0-9a-f]{64}$"


class IFEMStructuralCalibrationError(ValueError):
    """A structural calibration plan is malformed or attempts a forbidden handoff."""


class IFEMStructuralCalibrationRoleV1(StrEnum):
    """Closed role vocabulary for this source-free calibration plan."""

    CONVERSION_PROPOSER = "conversion_proposer"
    FIDELITY_REVIEWER = "fidelity_reviewer"
    MUTATION_CRITIC = "mutation_critic"


class IFEMStructuralRiskV1(StrEnum):
    """Closed list of structural risks selected for the iFEM candidate graph."""

    QUANTIFIER_ORDER = "quantifier_order"
    POSITIVITY = "positivity"
    ABSOLUTE_VALUE = "absolute_value"
    CLOSED_SUBSPACE = "closed_subspace"
    RESTRICTION_DOMAIN = "restriction_domain"
    INFIMUM_TO_ATTAINMENT = "infimum_to_attainment"
    PARAMETER_REVERSAL = "parameter_reversal"
    VACUOUS_HYPOTHESIS = "vacuous_hypothesis"


class IFEMStructuralMutationV1(StrEnum):
    """Closed mutations; every mutation is a candidate to reject, never a theorem edit."""

    QUANTIFIER_ORDER_SWAPPED = "quantifier_order_swapped"
    POSITIVITY_REMOVED = "positivity_removed"
    ABSOLUTE_VALUE_DROPPED = "absolute_value_dropped"
    CLOSED_SUBSPACE_REMOVED = "closed_subspace_removed"
    RESTRICTION_DOMAIN_WIDENED = "restriction_domain_widened"
    INFIMUM_REPLACED_BY_ATTAINMENT = "infimum_replaced_by_attainment"
    PARAMETER_ORDER_REVERSED = "parameter_order_reversed"
    VACUOUS_ANTECEDENT_INTRODUCED = "vacuous_antecedent_introduced"


class IFEMStructuralDispositionV1(StrEnum):
    """Closed advisory outcomes; neither one creates semantic or proof authority."""

    REQUEST_SEMANTIC_GAP = "request_semantic_gap"
    REJECT_MUTATION = "reject_mutation"


class IFEMStructuralCaseIdV1(StrEnum):
    """The complete project-authored case registry for this revision."""

    QUANTIFIER_ORDER_CONVERSION = "ifem-structural-quantifier-order-conversion"
    QUANTIFIER_ORDER_REVIEW = "ifem-structural-quantifier-order-review"
    POSITIVITY_CONVERSION = "ifem-structural-positivity-conversion"
    POSITIVITY_CRITIC = "ifem-structural-positivity-critic"
    ABSOLUTE_VALUE_CONVERSION = "ifem-structural-absolute-value-conversion"
    ABSOLUTE_VALUE_REVIEW = "ifem-structural-absolute-value-review"
    CLOSED_SUBSPACE_CONVERSION = "ifem-structural-closed-subspace-conversion"
    CLOSED_SUBSPACE_CRITIC = "ifem-structural-closed-subspace-critic"
    RESTRICTION_DOMAIN_CONVERSION = "ifem-structural-restriction-domain-conversion"
    RESTRICTION_DOMAIN_REVIEW = "ifem-structural-restriction-domain-review"
    INFIMUM_TO_ATTAINMENT_CONVERSION = "ifem-structural-infimum-to-attainment-conversion"
    INFIMUM_TO_ATTAINMENT_CRITIC = "ifem-structural-infimum-to-attainment-critic"
    PARAMETER_REVERSAL_CONVERSION = "ifem-structural-parameter-reversal-conversion"
    PARAMETER_REVERSAL_REVIEW = "ifem-structural-parameter-reversal-review"
    VACUOUS_HYPOTHESIS_CONVERSION = "ifem-structural-vacuous-hypothesis-conversion"
    VACUOUS_HYPOTHESIS_CRITIC = "ifem-structural-vacuous-hypothesis-critic"


class IFEMStructuralCalibrationAuthorityV1(ContractModel):
    """Hard-negative authority boundary for the source-free plan."""

    schema_version: Literal["autolean.ifem-structural-calibration-authority.v1"] = (
        "autolean.ifem-structural-calibration-authority.v1"
    )
    source_text_derived: Literal[False] = False
    source_egress_allowed: Literal[False] = False
    external_model_egress_allowed: Literal[False] = False
    semantic_equivalence_claimed: Literal[False] = False
    lean_statement_created: Literal[False] = False
    formal_graph_created: Literal[False] = False
    execution_graph_created: Literal[False] = False
    statement_contract_created: Literal[False] = False
    freeze_allowed: Literal[False] = False
    prover_handoff_allowed: Literal[False] = False
    promotion_allowed: Literal[False] = False


class IFEMStructuralCalibrationSourceBindingV1(ContractModel):
    """Digest-only link to one revalidated candidate graph and its source bindings."""

    schema_version: Literal["autolean.ifem-structural-calibration-source-binding.v1"] = (
        "autolean.ifem-structural-calibration-source-binding.v1"
    )
    candidate_graph_content_sha256: str = Field(pattern=_SHA256)
    candidate_graph_source_binding: IFEMCandidateGraphSourceBindingV1
    candidate_graph_node_ids: tuple[IFEMCandidateNodeIdV1, ...] = Field(min_length=20)
    candidate_graph_node_set_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_node_set(self) -> IFEMStructuralCalibrationSourceBindingV1:
        expected_ids = _all_candidate_node_ids()
        if self.candidate_graph_node_ids != expected_ids:
            raise ValueError("source binding must name the complete canonical iFEM node set")
        if self.candidate_graph_node_set_sha256 != _node_set_sha256(self.candidate_graph_node_ids):
            raise ValueError("source binding node-set hash does not match its node identifiers")
        return self


class IFEMStructuralCalibrationCaseV1(ContractModel):
    """A closed structural check with symbolic node references only."""

    case_id: IFEMStructuralCaseIdV1
    role: IFEMStructuralCalibrationRoleV1
    risk: IFEMStructuralRiskV1
    mutation: IFEMStructuralMutationV1
    required_disposition: IFEMStructuralDispositionV1
    candidate_node_ids: tuple[IFEMCandidateNodeIdV1, ...] = Field(min_length=2, max_length=3)

    @model_validator(mode="after")
    def validate_case_shape(self) -> IFEMStructuralCalibrationCaseV1:
        if tuple(sorted(self.candidate_node_ids, key=str)) != self.candidate_node_ids:
            raise ValueError("structural case node identifiers must use canonical order")
        if len(set(self.candidate_node_ids)) != len(self.candidate_node_ids):
            raise ValueError("structural case node identifiers must be unique")
        return self


@dataclass(frozen=True, slots=True)
class _CaseSpec:
    case_id: IFEMStructuralCaseIdV1
    role: IFEMStructuralCalibrationRoleV1
    risk: IFEMStructuralRiskV1
    mutation: IFEMStructuralMutationV1
    nodes: tuple[IFEMCandidateNodeIdV1, ...]


_CASE_SPECS: Final[tuple[_CaseSpec, ...]] = (
    _CaseSpec(
        IFEMStructuralCaseIdV1.QUANTIFIER_ORDER_CONVERSION,
        IFEMStructuralCalibrationRoleV1.CONVERSION_PROPOSER,
        IFEMStructuralRiskV1.QUANTIFIER_ORDER,
        IFEMStructuralMutationV1.QUANTIFIER_ORDER_SWAPPED,
        (
            IFEMCandidateNodeIdV1.GALERKIN_SOLUTION_INTERFACE,
            IFEMCandidateNodeIdV1.LAX_MILGRAM_SOLUTION_INTERFACE,
        ),
    ),
    _CaseSpec(
        IFEMStructuralCaseIdV1.QUANTIFIER_ORDER_REVIEW,
        IFEMStructuralCalibrationRoleV1.FIDELITY_REVIEWER,
        IFEMStructuralRiskV1.QUANTIFIER_ORDER,
        IFEMStructuralMutationV1.QUANTIFIER_ORDER_SWAPPED,
        (
            IFEMCandidateNodeIdV1.CEA_QUASI_OPTIMALITY_INFINUM,
            IFEMCandidateNodeIdV1.GALERKIN_SOLUTION_INTERFACE,
        ),
    ),
    _CaseSpec(
        IFEMStructuralCaseIdV1.POSITIVITY_CONVERSION,
        IFEMStructuralCalibrationRoleV1.CONVERSION_PROPOSER,
        IFEMStructuralRiskV1.POSITIVITY,
        IFEMStructuralMutationV1.POSITIVITY_REMOVED,
        (
            IFEMCandidateNodeIdV1.COERCIVITY_PREDICATE,
            IFEMCandidateNodeIdV1.LAX_MILGRAM_SOLUTION_INTERFACE,
        ),
    ),
    _CaseSpec(
        IFEMStructuralCaseIdV1.POSITIVITY_CRITIC,
        IFEMStructuralCalibrationRoleV1.MUTATION_CRITIC,
        IFEMStructuralRiskV1.POSITIVITY,
        IFEMStructuralMutationV1.POSITIVITY_REMOVED,
        (
            IFEMCandidateNodeIdV1.COERCIVITY_PREDICATE,
            IFEMCandidateNodeIdV1.ZERO_FORM_COUNTEREXAMPLE,
        ),
    ),
    _CaseSpec(
        IFEMStructuralCaseIdV1.ABSOLUTE_VALUE_CONVERSION,
        IFEMStructuralCalibrationRoleV1.CONVERSION_PROPOSER,
        IFEMStructuralRiskV1.ABSOLUTE_VALUE,
        IFEMStructuralMutationV1.ABSOLUTE_VALUE_DROPPED,
        (
            IFEMCandidateNodeIdV1.CONTINUITY_BOUND,
            IFEMCandidateNodeIdV1.CONTINUOUS_BILINEAR_FORM,
        ),
    ),
    _CaseSpec(
        IFEMStructuralCaseIdV1.ABSOLUTE_VALUE_REVIEW,
        IFEMStructuralCalibrationRoleV1.FIDELITY_REVIEWER,
        IFEMStructuralRiskV1.ABSOLUTE_VALUE,
        IFEMStructuralMutationV1.ABSOLUTE_VALUE_DROPPED,
        (
            IFEMCandidateNodeIdV1.CONTINUITY_BOUND,
            IFEMCandidateNodeIdV1.RESTRICTED_CONTINUITY,
        ),
    ),
    _CaseSpec(
        IFEMStructuralCaseIdV1.CLOSED_SUBSPACE_CONVERSION,
        IFEMStructuralCalibrationRoleV1.CONVERSION_PROPOSER,
        IFEMStructuralRiskV1.CLOSED_SUBSPACE,
        IFEMStructuralMutationV1.CLOSED_SUBSPACE_REMOVED,
        (
            IFEMCandidateNodeIdV1.CLOSED_SUBSPACE,
            IFEMCandidateNodeIdV1.INHERITED_COMPLETE_STRUCTURE,
        ),
    ),
    _CaseSpec(
        IFEMStructuralCaseIdV1.CLOSED_SUBSPACE_CRITIC,
        IFEMStructuralCalibrationRoleV1.MUTATION_CRITIC,
        IFEMStructuralRiskV1.CLOSED_SUBSPACE,
        IFEMStructuralMutationV1.CLOSED_SUBSPACE_REMOVED,
        (
            IFEMCandidateNodeIdV1.CLOSED_SUBSPACE,
            IFEMCandidateNodeIdV1.SUBMODULE,
        ),
    ),
    _CaseSpec(
        IFEMStructuralCaseIdV1.RESTRICTION_DOMAIN_CONVERSION,
        IFEMStructuralCalibrationRoleV1.CONVERSION_PROPOSER,
        IFEMStructuralRiskV1.RESTRICTION_DOMAIN,
        IFEMStructuralMutationV1.RESTRICTION_DOMAIN_WIDENED,
        (
            IFEMCandidateNodeIdV1.RESTRICTED_BILINEAR_FORM,
            IFEMCandidateNodeIdV1.SUBMODULE,
        ),
    ),
    _CaseSpec(
        IFEMStructuralCaseIdV1.RESTRICTION_DOMAIN_REVIEW,
        IFEMStructuralCalibrationRoleV1.FIDELITY_REVIEWER,
        IFEMStructuralRiskV1.RESTRICTION_DOMAIN,
        IFEMStructuralMutationV1.RESTRICTION_DOMAIN_WIDENED,
        (
            IFEMCandidateNodeIdV1.RESTRICTED_FUNCTIONAL,
            IFEMCandidateNodeIdV1.SUBMODULE,
        ),
    ),
    _CaseSpec(
        IFEMStructuralCaseIdV1.INFIMUM_TO_ATTAINMENT_CONVERSION,
        IFEMStructuralCalibrationRoleV1.CONVERSION_PROPOSER,
        IFEMStructuralRiskV1.INFIMUM_TO_ATTAINMENT,
        IFEMStructuralMutationV1.INFIMUM_REPLACED_BY_ATTAINMENT,
        (
            IFEMCandidateNodeIdV1.CEA_QUASI_OPTIMALITY_INFINUM,
            IFEMCandidateNodeIdV1.GALERKIN_SOLUTION_INTERFACE,
        ),
    ),
    _CaseSpec(
        IFEMStructuralCaseIdV1.INFIMUM_TO_ATTAINMENT_CRITIC,
        IFEMStructuralCalibrationRoleV1.MUTATION_CRITIC,
        IFEMStructuralRiskV1.INFIMUM_TO_ATTAINMENT,
        IFEMStructuralMutationV1.INFIMUM_REPLACED_BY_ATTAINMENT,
        (
            IFEMCandidateNodeIdV1.CEA_QUASI_OPTIMALITY_INFINUM,
            IFEMCandidateNodeIdV1.PROPER_SUBSPACE_EXAMPLE,
        ),
    ),
    _CaseSpec(
        IFEMStructuralCaseIdV1.PARAMETER_REVERSAL_CONVERSION,
        IFEMStructuralCalibrationRoleV1.CONVERSION_PROPOSER,
        IFEMStructuralRiskV1.PARAMETER_REVERSAL,
        IFEMStructuralMutationV1.PARAMETER_ORDER_REVERSED,
        (
            IFEMCandidateNodeIdV1.CONTINUITY_BOUND,
            IFEMCandidateNodeIdV1.INDUCED_DUAL_OPERATOR,
        ),
    ),
    _CaseSpec(
        IFEMStructuralCaseIdV1.PARAMETER_REVERSAL_REVIEW,
        IFEMStructuralCalibrationRoleV1.FIDELITY_REVIEWER,
        IFEMStructuralRiskV1.PARAMETER_REVERSAL,
        IFEMStructuralMutationV1.PARAMETER_ORDER_REVERSED,
        (
            IFEMCandidateNodeIdV1.CONTINUOUS_BILINEAR_FORM,
            IFEMCandidateNodeIdV1.RESTRICTED_BILINEAR_FORM,
        ),
    ),
    _CaseSpec(
        IFEMStructuralCaseIdV1.VACUOUS_HYPOTHESIS_CONVERSION,
        IFEMStructuralCalibrationRoleV1.CONVERSION_PROPOSER,
        IFEMStructuralRiskV1.VACUOUS_HYPOTHESIS,
        IFEMStructuralMutationV1.VACUOUS_ANTECEDENT_INTRODUCED,
        (
            IFEMCandidateNodeIdV1.COERCIVITY_PREDICATE,
            IFEMCandidateNodeIdV1.ZERO_FORM_COUNTEREXAMPLE,
        ),
    ),
    _CaseSpec(
        IFEMStructuralCaseIdV1.VACUOUS_HYPOTHESIS_CRITIC,
        IFEMStructuralCalibrationRoleV1.MUTATION_CRITIC,
        IFEMStructuralRiskV1.VACUOUS_HYPOTHESIS,
        IFEMStructuralMutationV1.VACUOUS_ANTECEDENT_INTRODUCED,
        (
            IFEMCandidateNodeIdV1.CEA_QUASI_OPTIMALITY_INFINUM,
            IFEMCandidateNodeIdV1.ZERO_FORM_COUNTEREXAMPLE,
        ),
    ),
)


def _all_candidate_node_ids() -> tuple[IFEMCandidateNodeIdV1, ...]:
    return tuple(sorted(IFEMCandidateNodeIdV1, key=str))


def _all_roles() -> tuple[IFEMStructuralCalibrationRoleV1, ...]:
    return tuple(sorted(IFEMStructuralCalibrationRoleV1, key=str))


def _all_risks() -> tuple[IFEMStructuralRiskV1, ...]:
    return tuple(sorted(IFEMStructuralRiskV1, key=str))


def _all_mutations() -> tuple[IFEMStructuralMutationV1, ...]:
    return tuple(sorted(IFEMStructuralMutationV1, key=str))


def _node_set_sha256(node_ids: tuple[IFEMCandidateNodeIdV1, ...]) -> str:
    return hashlib.sha256(canonical_json_bytes([str(node_id) for node_id in node_ids])).hexdigest()


def _required_disposition(
    role: IFEMStructuralCalibrationRoleV1,
) -> IFEMStructuralDispositionV1:
    if role is IFEMStructuralCalibrationRoleV1.CONVERSION_PROPOSER:
        return IFEMStructuralDispositionV1.REQUEST_SEMANTIC_GAP
    return IFEMStructuralDispositionV1.REJECT_MUTATION


def _expected_cases() -> tuple[IFEMStructuralCalibrationCaseV1, ...]:
    result = tuple(
        IFEMStructuralCalibrationCaseV1(
            case_id=spec.case_id,
            role=spec.role,
            risk=spec.risk,
            mutation=spec.mutation,
            required_disposition=_required_disposition(spec.role),
            candidate_node_ids=tuple(sorted(spec.nodes, key=str)),
        )
        for spec in _CASE_SPECS
    )
    return tuple(sorted(result, key=lambda item: str(item.case_id)))


class IFEMStructuralCalibrationCatalogV1(ContractModel):
    """A re-renderable source-free structural calibration contract."""

    schema_version: Literal["autolean.ifem-structural-calibration.v1"] = (
        IFEM_STRUCTURAL_CALIBRATION_SCHEMA
    )
    artifact_kind: Literal["source_free_structural_calibration_plan"] = (
        IFEM_STRUCTURAL_CALIBRATION_KIND
    )
    lane_id: Literal["ifem-coercive-galerkin"] = "ifem-coercive-galerkin"
    source_binding: IFEMStructuralCalibrationSourceBindingV1
    calibration_roles: tuple[IFEMStructuralCalibrationRoleV1, ...] = Field(min_length=3)
    risk_families: tuple[IFEMStructuralRiskV1, ...] = Field(min_length=8)
    mutation_families: tuple[IFEMStructuralMutationV1, ...] = Field(min_length=8)
    graph_layers: Literal["candidate_node_references_only"] = "candidate_node_references_only"
    formal_graph: Literal["not_created"] = "not_created"
    execution_graph: Literal["not_created"] = "not_created"
    contains_source_text: Literal[False] = False
    contains_source_excerpt: Literal[False] = False
    contains_lean_statement: Literal[False] = False
    contains_model_input: Literal[False] = False
    authority: IFEMStructuralCalibrationAuthorityV1 = Field(
        default_factory=IFEMStructuralCalibrationAuthorityV1
    )
    cases: tuple[IFEMStructuralCalibrationCaseV1, ...] = Field(min_length=12, max_length=18)
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_catalog(self) -> IFEMStructuralCalibrationCatalogV1:
        if self.calibration_roles != _all_roles():
            raise ValueError("structural calibration roles differ from the closed vocabulary")
        if self.risk_families != _all_risks():
            raise ValueError("structural calibration risks differ from the closed vocabulary")
        if self.mutation_families != _all_mutations():
            raise ValueError("structural calibration mutations differ from the closed vocabulary")
        if self.cases != _expected_cases():
            raise ValueError("structural calibration cases differ from the fixed case registry")
        graph_nodes = set(self.source_binding.candidate_graph_node_ids)
        if any(not set(case.candidate_node_ids) <= graph_nodes for case in self.cases):
            raise ValueError(
                "structural calibration case names a node absent from its graph binding"
            )
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("structural calibration content hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        payload = self.model_dump(mode="json", exclude={"content_sha256"})
        return cast(dict[str, object], payload)

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.content_payload())).hexdigest()

    def assert_not_routable(self) -> Never:
        raise IFEMStructuralCalibrationError(
            "source-free iFEM structural calibration cannot create a statement contract, "
            "freeze a statement, or hand work to Prover"
        )

    def freeze_statement(self) -> Never:
        self.assert_not_routable()

    def handoff_to_prover(self) -> Never:
        self.assert_not_routable()


def _revalidate_candidate_graph(
    graph: IFEMCandidateDependencyGraphV1,
) -> IFEMCandidateDependencyGraphV1:
    if type(graph) is not IFEMCandidateDependencyGraphV1:
        raise IFEMStructuralCalibrationError(
            "structural calibration requires an IFEMCandidateDependencyGraphV1 input"
        )
    try:
        return IFEMCandidateDependencyGraphV1.model_validate(graph.model_dump(mode="json"))
    except ValueError as error:
        raise IFEMStructuralCalibrationError(
            "structural calibration requires a revalidated, non-model-constructed candidate graph"
        ) from error


def build_ifem_structural_calibration_catalog(
    graph: IFEMCandidateDependencyGraphV1,
) -> IFEMStructuralCalibrationCatalogV1:
    """Bind the fixed structural catalog to one revalidated iFEM candidate graph."""

    verified_graph = _revalidate_candidate_graph(graph)
    actual_node_ids = tuple(
        sorted((node.node_id for node in verified_graph.candidate_nodes), key=str)
    )
    if actual_node_ids != _all_candidate_node_ids():
        raise IFEMStructuralCalibrationError(
            "candidate graph does not contain the complete node set required by this catalog"
        )
    source_binding = IFEMStructuralCalibrationSourceBindingV1(
        candidate_graph_content_sha256=verified_graph.content_sha256,
        candidate_graph_source_binding=verified_graph.source_binding,
        candidate_graph_node_ids=actual_node_ids,
        candidate_graph_node_set_sha256=_node_set_sha256(actual_node_ids),
    )
    payload: dict[str, object] = {
        "schema_version": IFEM_STRUCTURAL_CALIBRATION_SCHEMA,
        "artifact_kind": IFEM_STRUCTURAL_CALIBRATION_KIND,
        "lane_id": "ifem-coercive-galerkin",
        "source_binding": source_binding.model_dump(mode="json"),
        "calibration_roles": [str(role) for role in _all_roles()],
        "risk_families": [str(risk) for risk in _all_risks()],
        "mutation_families": [str(mutation) for mutation in _all_mutations()],
        "graph_layers": "candidate_node_references_only",
        "formal_graph": "not_created",
        "execution_graph": "not_created",
        "contains_source_text": False,
        "contains_source_excerpt": False,
        "contains_lean_statement": False,
        "contains_model_input": False,
        "authority": IFEMStructuralCalibrationAuthorityV1().model_dump(mode="json"),
        "cases": [case.model_dump(mode="json") for case in _expected_cases()],
    }
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    try:
        return IFEMStructuralCalibrationCatalogV1.model_validate(payload)
    except ValueError as error:
        raise IFEMStructuralCalibrationError(
            "iFEM structural calibration catalog did not validate"
        ) from error


def _revalidate_catalog(
    catalog: IFEMStructuralCalibrationCatalogV1,
) -> IFEMStructuralCalibrationCatalogV1:
    if type(catalog) is not IFEMStructuralCalibrationCatalogV1:
        raise IFEMStructuralCalibrationError(
            "structural calibration requires an IFEMStructuralCalibrationCatalogV1 input"
        )
    try:
        return IFEMStructuralCalibrationCatalogV1.model_validate(catalog.model_dump(mode="json"))
    except ValueError as error:
        raise IFEMStructuralCalibrationError(
            "structural calibration requires a revalidated, non-model-constructed catalog"
        ) from error


def verify_ifem_structural_calibration_catalog_against_graph(
    catalog: IFEMStructuralCalibrationCatalogV1,
    graph: IFEMCandidateDependencyGraphV1,
) -> IFEMStructuralCalibrationCatalogV1:
    """Rebuild the trusted graph-derived catalog before any downstream use."""

    verified_catalog = _revalidate_catalog(catalog)
    verified_graph = _revalidate_candidate_graph(graph)
    expected = build_ifem_structural_calibration_catalog(verified_graph)
    if verified_catalog != expected:
        raise IFEMStructuralCalibrationError(
            "structural calibration catalog does not bind the supplied candidate graph"
        )
    return verified_catalog


def render_ifem_structural_calibration_catalog(
    catalog: IFEMStructuralCalibrationCatalogV1,
) -> bytes:
    """Serialize only a revalidated catalog, closing ``model_construct`` bypasses."""

    try:
        verified = _revalidate_catalog(catalog)
    except IFEMStructuralCalibrationError as error:
        raise IFEMStructuralCalibrationError(
            "cannot render an invalid or model-constructed structural calibration catalog"
        ) from error
    return canonical_json_bytes(verified.model_dump(mode="json")) + b"\n"
