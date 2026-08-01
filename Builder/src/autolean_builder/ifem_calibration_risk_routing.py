"""Route public D35 calibration aggregates onto an unknown-only iFEM projection.

This is a deliberately non-authoritative, source-free advisory artifact.  It
does not classify any iFEM prerequisite, recover private evaluator state, or
create a statement/proof route.  It merely makes a conservative next
calibration action deterministic from the public D35 risk aggregates and the
already-versioned unknown-only node projection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path
from typing import Final, Literal, Never, Self, cast

from autolean_contracts import canonical_json_bytes
from autolean_contracts.base import ContractModel
from pydantic import Field, model_validator

from .ifem_classification_triage import (
    DEFAULT_CENSUS_PLAN_PATH,
    DEFAULT_CENSUS_RESULT_PATH,
    DEFAULT_GRAPH_PATH,
    DEFAULT_PROFILE_SUMMARY_PATH,
    DEFAULT_READINESS_DECISION_PATH,
    DEFAULT_STRUCTURAL_CORPUS_PATH,
    IFEMClassificationTriageError,
    IFEMUnknownOnlyClassificationTriageV1,
    build_ifem_unknown_only_classification_triage_from_paths,
)
from .ifem_prerequisite_census import IFEMPrerequisiteClassificationV1
from .ifem_structural_calibration import IFEMStructuralMutationV1, IFEMStructuralRiskV1
from .ifem_structural_role_probes import IFEMStructuralProbeRoleV1

ROOT = Path(__file__).resolve().parents[3]
RISK_ROUTING_SCHEMA: Final[Literal["autolean.ifem-calibration-risk-routing.v1"]] = (
    "autolean.ifem-calibration-risk-routing.v1"
)
RISK_ROUTING_PROTOCOL: Final[Literal["autolean.builder-ifem-calibration-risk-routing.v1"]] = (
    "autolean.builder-ifem-calibration-risk-routing.v1"
)
RISK_ROUTING_KIND: Final[Literal["unknown_only_d35_calibration_risk_routing"]] = (
    "unknown_only_d35_calibration_risk_routing"
)
D35_REPORT_SCHEMA: Final[Literal["autolean.ifem-private-evaluator-public-report.v2"]] = (
    "autolean.ifem-private-evaluator-public-report.v2"
)
D35_PROTOCOL_ID: Final[Literal["d35-v3"]] = "d35-v3"
D35_FIXTURE_CONTENT_SHA256: Final = (
    "a6acd9218d8a0e4b9ca5d7933b143172dab8aa851c00328c48a4a32ef97d9001"
)
D35_PROFILE_CONTENT_SHA256: Final = (
    "d8ee725c9dca99884c69a719e8b458d56163fb75e8b91458697c526b39e24a80"
)
D35_REQUEST_POLICY_CONTENT_SHA256: Final = (
    "f39b0e104c5f8012fb2d023f50f5378e36a8eb7cac33b835ab1c34d8738587f8"
)
DEFAULT_D35_REPORT_PATH = (
    ROOT / "docs" / "research" / "ifem-deepseek-role-calibration-2026-07-31-1024-v3.json"
)
_SHA256 = r"^[0-9a-f]{64}$"
_ROLE_CASE_COUNTS: Final[dict[IFEMStructuralProbeRoleV1, int]] = {
    IFEMStructuralProbeRoleV1.STATEMENT_FORMALIZER: 8,
    IFEMStructuralProbeRoleV1.FIDELITY_REVIEWER: 4,
    IFEMStructuralProbeRoleV1.CHEATING_SUPERVISOR: 4,
}
_MUTATION_BY_RISK: Final[dict[IFEMStructuralRiskV1, IFEMStructuralMutationV1]] = {
    IFEMStructuralRiskV1.QUANTIFIER_ORDER: IFEMStructuralMutationV1.QUANTIFIER_ORDER_SWAPPED,
    IFEMStructuralRiskV1.POSITIVITY: IFEMStructuralMutationV1.POSITIVITY_REMOVED,
    IFEMStructuralRiskV1.ABSOLUTE_VALUE: IFEMStructuralMutationV1.ABSOLUTE_VALUE_DROPPED,
    IFEMStructuralRiskV1.CLOSED_SUBSPACE: IFEMStructuralMutationV1.CLOSED_SUBSPACE_REMOVED,
    IFEMStructuralRiskV1.RESTRICTION_DOMAIN: IFEMStructuralMutationV1.RESTRICTION_DOMAIN_WIDENED,
    IFEMStructuralRiskV1.INFIMUM_TO_ATTAINMENT: (
        IFEMStructuralMutationV1.INFIMUM_REPLACED_BY_ATTAINMENT
    ),
    IFEMStructuralRiskV1.PARAMETER_REVERSAL: IFEMStructuralMutationV1.PARAMETER_ORDER_REVERSED,
    IFEMStructuralRiskV1.VACUOUS_HYPOTHESIS: (
        IFEMStructuralMutationV1.VACUOUS_ANTECEDENT_INTRODUCED
    ),
}


class IFEMCalibrationRiskRoutingError(ValueError):
    """A D35 aggregate or unknown-only routing artifact drifted from its boundary."""


class IFEMCalibrationPriorityV1(StrEnum):
    """Closed advisory priority vocabulary; it is not a semantic decision."""

    P0_INCORRECT = "p0_incorrect"
    P1_INVALID = "p1_invalid"
    P2_INDEPENDENT_MACHINE_REVIEW = "p2_independent_machine_review"
    P3_CREATE_CALIBRATION_CASE = "p3_create_calibration_case"


class IFEMRequiredNextCalibrationV1(StrEnum):
    """Closed, non-authoritative next calibration actions."""

    DETERMINISTIC_OR_HIGHER_CAPABILITY_CALIBRATION = (
        "deterministic_or_higher_capability_calibration"
    )
    INDEPENDENT_MACHINE_REVIEW = "independent_machine_review"
    CREATE_CALIBRATION_CASE = "create_calibration_case"


class _D35AuthorityV1(ContractModel):
    """The entire public D35 non-authority contract reproduced without benchmarks imports."""

    schema_version: Literal["autolean.ifem-private-evaluator-authority.v1"]
    raw_output_embedded: Literal[False]
    private_oracle_embedded: Literal[False]
    operator_seed_embedded: Literal[False]
    private_cas_reference_embedded: Literal[False]
    response_identifier_embedded: Literal[False]
    enumerable_oracle_digest_embedded: Literal[False]
    enumerable_output_digest_embedded: Literal[False]
    semantic_equivalence_claimed: Literal[False]
    benchmark_authority: Literal[False]
    statement_contract_created: Literal[False]
    freeze_allowed: Literal[False]
    prover_handoff_allowed: Literal[False]
    promotion_allowed: Literal[False]


class _D35ProtocolBindingV1(ContractModel):
    schema_version: Literal["autolean.ifem-private-evaluator-protocol-binding.v1"]
    protocol_id: Literal["d35-v3"]
    profile_content_sha256: str = Field(pattern=_SHA256)
    request_policy_content_sha256: str = Field(pattern=_SHA256)
    response_contract: Literal["selected_option_only.v2"]


class _D35RoleAggregateV1(ContractModel):
    schema_version: Literal["autolean.ifem-private-evaluator-role-aggregate.v1"]
    role: IFEMStructuralProbeRoleV1
    case_count: int = Field(ge=1, le=16)
    correct_count: int = Field(ge=0, le=16)
    incorrect_count: int = Field(ge=0, le=16)
    abstention_count: int = Field(ge=0, le=16)
    invalid_count: int = Field(ge=0, le=16)

    @model_validator(mode="after")
    def validate_aggregate(self) -> Self:
        if self.case_count != _ROLE_CASE_COUNTS[self.role]:
            raise ValueError("D35 role aggregate has an unexpected case count")
        if (
            self.correct_count + self.incorrect_count + self.abstention_count + self.invalid_count
            != self.case_count
        ):
            raise ValueError("D35 role aggregate does not cover its cases")
        return self


class _D35RiskAggregateV1(ContractModel):
    schema_version: Literal["autolean.ifem-private-evaluator-risk-aggregate.v1"]
    risk: IFEMStructuralRiskV1
    mutation: IFEMStructuralMutationV1
    case_count: Literal[2]
    correct_count: int = Field(ge=0, le=2)
    incorrect_count: int = Field(ge=0, le=2)
    abstention_count: int = Field(ge=0, le=2)
    invalid_count: int = Field(ge=0, le=2)

    @model_validator(mode="after")
    def validate_aggregate(self) -> Self:
        if self.mutation is not _MUTATION_BY_RISK[self.risk]:
            raise ValueError("D35 risk aggregate mutation does not match its risk")
        if (
            self.correct_count + self.incorrect_count + self.abstention_count + self.invalid_count
            != self.case_count
        ):
            raise ValueError("D35 risk aggregate does not cover its cases")
        return self


class _D35TokenUsageV1(ContractModel):
    schema_version: Literal["autolean.ifem-private-evaluator-token-usage-summary.v1"]
    case_count: Literal[16]
    input_tokens_total: int = Field(ge=0)
    cached_input_tokens_total: int = Field(ge=0)
    output_tokens_total: int = Field(ge=0)
    input_tokens_bucket: str
    cached_input_tokens_bucket: str
    output_tokens_bucket: str

    @model_validator(mode="after")
    def validate_summary(self) -> Self:
        if self.cached_input_tokens_total > self.input_tokens_total:
            raise ValueError("D35 cached input cannot exceed input tokens")
        return self


class _D35PublicReportV2(ContractModel):
    """Exact public D35 shape, local to Builder to preserve dependency direction."""

    schema_version: Literal["autolean.ifem-private-evaluator-public-report.v2"]
    fixture_content_sha256: str = Field(pattern=_SHA256)
    case_count: Literal[16]
    private_rebuild_verified: Literal[True]
    witness_validation_recomputed: Literal[True]
    private_manifest_recovered: Literal[True]
    role_aggregates: tuple[_D35RoleAggregateV1, ...] = Field(min_length=3, max_length=3)
    risk_aggregates: tuple[_D35RiskAggregateV1, ...] = Field(min_length=8, max_length=8)
    token_usage: _D35TokenUsageV1
    authority: _D35AuthorityV1
    protocol_binding: _D35ProtocolBindingV1
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        if self.fixture_content_sha256 != D35_FIXTURE_CONTENT_SHA256:
            raise ValueError("D35 report does not bind the frozen fixture")
        if (
            self.protocol_binding.profile_content_sha256 != D35_PROFILE_CONTENT_SHA256
            or self.protocol_binding.request_policy_content_sha256
            != D35_REQUEST_POLICY_CONTENT_SHA256
        ):
            raise ValueError("D35 report does not bind the frozen generation policy")
        expected_roles = tuple(sorted(IFEMStructuralProbeRoleV1, key=str))
        if tuple(item.role for item in self.role_aggregates) != expected_roles:
            raise ValueError("D35 report does not contain complete canonical roles")
        expected_risks = tuple(sorted(IFEMStructuralRiskV1, key=str))
        if tuple(item.risk for item in self.risk_aggregates) != expected_risks:
            raise ValueError("D35 report does not contain all eight canonical risks")
        for attribute in ("correct_count", "incorrect_count", "abstention_count", "invalid_count"):
            if sum(getattr(item, attribute) for item in self.role_aggregates) != sum(
                getattr(item, attribute) for item in self.risk_aggregates
            ):
                raise ValueError("D35 role and risk aggregate totals disagree")
        if sum(item.case_count for item in self.role_aggregates) != self.case_count:
            raise ValueError("D35 role aggregates do not cover sixteen cases")
        if sum(cast(int, item.case_count) for item in self.risk_aggregates) != self.case_count:
            raise ValueError("D35 risk aggregates do not cover sixteen cases")
        if self.authority != _D35AuthorityV1(
            schema_version="autolean.ifem-private-evaluator-authority.v1",
            raw_output_embedded=False,
            private_oracle_embedded=False,
            operator_seed_embedded=False,
            private_cas_reference_embedded=False,
            response_identifier_embedded=False,
            enumerable_oracle_digest_embedded=False,
            enumerable_output_digest_embedded=False,
            semantic_equivalence_claimed=False,
            benchmark_authority=False,
            statement_contract_created=False,
            freeze_allowed=False,
            prover_handoff_allowed=False,
            promotion_allowed=False,
        ):
            raise ValueError("D35 authority flags are not all false")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("D35 report content hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(dict[str, object], self.model_dump(mode="json", exclude={"content_sha256"}))

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.content_payload())).hexdigest()


class IFEMCalibrationRiskRoutingAuthorityV1(ContractModel):
    """All powers deliberately withheld from this priority projection."""

    schema_version: Literal["autolean.ifem-calibration-risk-routing-authority.v1"] = (
        "autolean.ifem-calibration-risk-routing-authority.v1"
    )
    semantic_classification_authorized: Literal[False] = False
    semantic_equivalence_claimed: Literal[False] = False
    benchmark_authority: Literal[False] = False
    statement_contract_created: Literal[False] = False
    formal_graph_created: Literal[False] = False
    execution_graph_created: Literal[False] = False
    freeze_allowed: Literal[False] = False
    prover_handoff_allowed: Literal[False] = False
    promotion_allowed: Literal[False] = False


class IFEMCalibrationRiskRoutingEvidenceV1(ContractModel):
    triage_content_sha256: str = Field(pattern=_SHA256)
    d35_report_file_sha256: str = Field(pattern=_SHA256)
    d35_report_content_sha256: str = Field(pattern=_SHA256)
    d35_report_schema: Literal["autolean.ifem-private-evaluator-public-report.v2"]
    d35_protocol_id: Literal["d35-v3"]
    d35_case_count: Literal[16]
    d35_risk_family_count: Literal[8]


class IFEMCalibrationRiskRoutingNodeV1(ContractModel):
    """A non-semantic calibration route for one already-unknown node."""

    node_id: str = Field(pattern=r"^ifem-[a-z0-9-]+$")
    source_order: int = Field(ge=1)
    candidate_node_kind: Literal["definition", "prerequisite_theorem", "example", "terminal_target"]
    semantic_classification: Literal[IFEMPrerequisiteClassificationV1.UNKNOWN]
    structural_risk_families: tuple[IFEMStructuralRiskV1, ...]
    calibration_priority: IFEMCalibrationPriorityV1
    required_next_calibration: IFEMRequiredNextCalibrationV1

    @model_validator(mode="after")
    def validate_node(self) -> Self:
        if self.structural_risk_families != tuple(
            sorted(set(self.structural_risk_families), key=str)
        ):
            raise ValueError("routing node risk families must be sorted and unique")
        if not self.structural_risk_families and (
            self.calibration_priority is not IFEMCalibrationPriorityV1.P3_CREATE_CALIBRATION_CASE
            or self.required_next_calibration
            is not IFEMRequiredNextCalibrationV1.CREATE_CALIBRATION_CASE
        ):
            raise ValueError("a node without structural risks must create a calibration case")
        return self


class IFEMCalibrationRiskRoutingV1(ContractModel):
    """Canonical D35-to-iFEM advisory routing with no semantic authority."""

    schema_version: Literal["autolean.ifem-calibration-risk-routing.v1"] = RISK_ROUTING_SCHEMA
    protocol: Literal["autolean.builder-ifem-calibration-risk-routing.v1"] = RISK_ROUTING_PROTOCOL
    artifact_kind: Literal["unknown_only_d35_calibration_risk_routing"] = RISK_ROUTING_KIND
    denominator_node_count: Literal[21] = 21
    evidence: IFEMCalibrationRiskRoutingEvidenceV1
    nodes: tuple[IFEMCalibrationRiskRoutingNodeV1, ...] = Field(min_length=21, max_length=21)
    contains_source_text: Literal[False] = False
    contains_lean_names: Literal[False] = False
    contains_lean_types: Literal[False] = False
    contains_raw_model_output: Literal[False] = False
    authority: IFEMCalibrationRiskRoutingAuthorityV1 = Field(
        default_factory=IFEMCalibrationRiskRoutingAuthorityV1
    )
    builder_freeze: Literal["forbidden"] = "forbidden"
    prover_handoff: Literal["forbidden"] = "forbidden"
    content_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_routing(self) -> Self:
        source_orders = tuple(node.source_order for node in self.nodes)
        if source_orders != tuple(sorted(source_orders)) or len(set(source_orders)) != 21:
            raise ValueError("routing nodes must retain unique increasing source order")
        if len({node.node_id for node in self.nodes}) != self.denominator_node_count:
            raise ValueError("routing nodes must have unique identifiers")
        if any(
            node.semantic_classification is not IFEMPrerequisiteClassificationV1.UNKNOWN
            for node in self.nodes
        ):
            raise ValueError("risk routing cannot classify an unknown-only node")
        if self.authority != IFEMCalibrationRiskRoutingAuthorityV1():
            raise ValueError("risk routing authority flags drifted")
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("risk routing content hash does not match its payload")
        return self

    def content_payload(self) -> dict[str, object]:
        return cast(dict[str, object], self.model_dump(mode="json", exclude={"content_sha256"}))

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.content_payload())).hexdigest()

    def assert_not_routable(self) -> Never:
        raise IFEMCalibrationRiskRoutingError(
            "iFEM calibration risk routing cannot classify a proposition, create a statement "
            "contract, freeze a statement, or hand work to Prover"
        )

    def freeze_statement(self) -> Never:
        self.assert_not_routable()

    def handoff_to_prover(self) -> Never:
        self.assert_not_routable()


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IFEMCalibrationRiskRoutingError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _is_link_or_reparse(path: Path, metadata: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return (
        stat.S_ISLNK(metadata.st_mode)
        or bool(getattr(metadata, "st_file_attributes", 0) & reparse_flag)
        or path.is_symlink()
    )


def _physical_parent_identities(path: Path) -> tuple[tuple[int, int], ...]:
    identities: list[tuple[int, int]] = []
    for parent in path.parents:
        metadata = parent.stat(follow_symlinks=False)
        if _is_link_or_reparse(parent, metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise IFEMCalibrationRiskRoutingError(
                "risk routing path parent chain must contain only physical directories"
            )
        identities.append((metadata.st_dev, metadata.st_ino))
    return tuple(identities)


def _read_regular_file(path: Path, *, label: str) -> tuple[bytes, str]:
    if not isinstance(path, Path):
        raise IFEMCalibrationRiskRoutingError(f"{label} path must be a Path")
    try:
        parents_before = _physical_parent_identities(path)
        before = path.lstat()
        if _is_link_or_reparse(path, before) or not stat.S_ISREG(before.st_mode):
            raise IFEMCalibrationRiskRoutingError(f"{label} must be an unlinked regular file")
        raw = path.read_bytes()
        after = path.lstat()
        parents_after = _physical_parent_identities(path)
    except OSError as error:
        raise IFEMCalibrationRiskRoutingError(f"cannot read {label}: {path}") from error
    if (
        _is_link_or_reparse(path, after)
        or not stat.S_ISREG(after.st_mode)
        or (before.st_dev, before.st_ino, before.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
        or parents_before != parents_after
    ):
        raise IFEMCalibrationRiskRoutingError(f"{label} changed while loading")
    return raw, hashlib.sha256(raw).hexdigest()


def _load_d35_public_report(path: Path) -> tuple[_D35PublicReportV2, str]:
    raw, file_sha256 = _read_regular_file(path, label="D35 public report")
    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"), object_pairs_hook=_reject_duplicate_keys
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IFEMCalibrationRiskRoutingError(
            "D35 public report is not strict UTF-8 JSON"
        ) from error
    if not isinstance(payload, dict):
        raise IFEMCalibrationRiskRoutingError("D35 public report must be a JSON object")
    try:
        report = _D35PublicReportV2.model_validate(payload)
    except ValueError as error:
        raise IFEMCalibrationRiskRoutingError("D35 public report is invalid") from error
    if canonical_json_bytes(report.model_dump(mode="json")) + b"\n" != raw:
        raise IFEMCalibrationRiskRoutingError("D35 public report is not canonically rendered")
    return report, file_sha256


def _route_for_risks(
    risks: tuple[IFEMStructuralRiskV1, ...],
    aggregates: dict[IFEMStructuralRiskV1, _D35RiskAggregateV1],
) -> tuple[IFEMCalibrationPriorityV1, IFEMRequiredNextCalibrationV1]:
    if not risks:
        return (
            IFEMCalibrationPriorityV1.P3_CREATE_CALIBRATION_CASE,
            IFEMRequiredNextCalibrationV1.CREATE_CALIBRATION_CASE,
        )
    selected = tuple(aggregates[risk] for risk in risks)
    if any(item.incorrect_count for item in selected):
        return (
            IFEMCalibrationPriorityV1.P0_INCORRECT,
            IFEMRequiredNextCalibrationV1.DETERMINISTIC_OR_HIGHER_CAPABILITY_CALIBRATION,
        )
    if any(item.invalid_count for item in selected):
        return (
            IFEMCalibrationPriorityV1.P1_INVALID,
            IFEMRequiredNextCalibrationV1.DETERMINISTIC_OR_HIGHER_CAPABILITY_CALIBRATION,
        )
    return (
        IFEMCalibrationPriorityV1.P2_INDEPENDENT_MACHINE_REVIEW,
        IFEMRequiredNextCalibrationV1.INDEPENDENT_MACHINE_REVIEW,
    )


def _build_routing(
    triage: IFEMUnknownOnlyClassificationTriageV1,
    report: _D35PublicReportV2,
    *,
    report_file_sha256: str,
) -> IFEMCalibrationRiskRoutingV1:
    if type(triage) is not IFEMUnknownOnlyClassificationTriageV1:
        raise IFEMCalibrationRiskRoutingError("risk routing requires the exact unknown-only triage")
    try:
        verified_triage = IFEMUnknownOnlyClassificationTriageV1.model_validate(
            triage.model_dump(mode="json")
        )
        verified_report = _D35PublicReportV2.model_validate(report.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMCalibrationRiskRoutingError("risk routing input failed revalidation") from error
    aggregates = {item.risk: item for item in verified_report.risk_aggregates}
    nodes: list[IFEMCalibrationRiskRoutingNodeV1] = []
    for source_node in verified_triage.nodes:
        risks = source_node.structural_risk_families
        priority, next_calibration = _route_for_risks(risks, aggregates)
        nodes.append(
            IFEMCalibrationRiskRoutingNodeV1(
                node_id=source_node.node_id,
                source_order=source_node.source_order,
                candidate_node_kind=source_node.candidate_node_kind,
                semantic_classification=source_node.semantic_classification,
                structural_risk_families=risks,
                calibration_priority=priority,
                required_next_calibration=next_calibration,
            )
        )
    payload: dict[str, object] = {
        "schema_version": RISK_ROUTING_SCHEMA,
        "protocol": RISK_ROUTING_PROTOCOL,
        "artifact_kind": RISK_ROUTING_KIND,
        "denominator_node_count": 21,
        "evidence": IFEMCalibrationRiskRoutingEvidenceV1(
            triage_content_sha256=verified_triage.content_sha256,
            d35_report_file_sha256=report_file_sha256,
            d35_report_content_sha256=verified_report.content_sha256,
            d35_report_schema=verified_report.schema_version,
            d35_protocol_id=verified_report.protocol_binding.protocol_id,
            d35_case_count=verified_report.case_count,
            d35_risk_family_count=8,
        ).model_dump(mode="json"),
        "nodes": [node.model_dump(mode="json") for node in nodes],
        "contains_source_text": False,
        "contains_lean_names": False,
        "contains_lean_types": False,
        "contains_raw_model_output": False,
        "authority": IFEMCalibrationRiskRoutingAuthorityV1().model_dump(mode="json"),
        "builder_freeze": "forbidden",
        "prover_handoff": "forbidden",
    }
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    try:
        return IFEMCalibrationRiskRoutingV1.model_validate(payload)
    except ValueError as error:
        raise IFEMCalibrationRiskRoutingError(
            "generated calibration risk routing is invalid"
        ) from error


def build_ifem_calibration_risk_routing_from_paths(
    *,
    d35_report_path: Path = DEFAULT_D35_REPORT_PATH,
    graph_path: Path = DEFAULT_GRAPH_PATH,
    census_plan_path: Path = DEFAULT_CENSUS_PLAN_PATH,
    census_result_path: Path = DEFAULT_CENSUS_RESULT_PATH,
    profile_summary_path: Path = DEFAULT_PROFILE_SUMMARY_PATH,
    structural_corpus_path: Path = DEFAULT_STRUCTURAL_CORPUS_PATH,
    readiness_decision_path: Path = DEFAULT_READINESS_DECISION_PATH,
) -> IFEMCalibrationRiskRoutingV1:
    """Rebuild the 21-node unknown-only input and route one strict public D35 report."""

    try:
        triage = build_ifem_unknown_only_classification_triage_from_paths(
            graph_path=graph_path,
            census_plan_path=census_plan_path,
            census_result_path=census_result_path,
            profile_summary_path=profile_summary_path,
            structural_corpus_path=structural_corpus_path,
            readiness_decision_path=readiness_decision_path,
        )
    except IFEMClassificationTriageError as error:
        raise IFEMCalibrationRiskRoutingError(
            "cannot rebuild the exact unknown-only triage input"
        ) from error
    report, report_file_sha256 = _load_d35_public_report(d35_report_path)
    return _build_routing(triage, report, report_file_sha256=report_file_sha256)


def verify_ifem_calibration_risk_routing_against_paths(
    routing: IFEMCalibrationRiskRoutingV1,
    **paths: Path,
) -> None:
    """Require one artifact to equal a fresh exact replay of all public inputs."""

    if type(routing) is not IFEMCalibrationRiskRoutingV1:
        raise IFEMCalibrationRiskRoutingError("risk routing must use its exact typed model")
    try:
        actual = IFEMCalibrationRiskRoutingV1.model_validate(routing.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMCalibrationRiskRoutingError("risk routing failed self-revalidation") from error
    expected = build_ifem_calibration_risk_routing_from_paths(**paths)
    if actual != expected:
        raise IFEMCalibrationRiskRoutingError(
            "risk routing artifact differs from exact input replay"
        )


def load_ifem_calibration_risk_routing(path: Path) -> IFEMCalibrationRiskRoutingV1:
    """Load one canonical output; use exact replay to establish input provenance."""

    raw, _file_sha256 = _read_regular_file(path, label="calibration risk routing")
    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"), object_pairs_hook=_reject_duplicate_keys
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IFEMCalibrationRiskRoutingError(
            "calibration risk routing is not strict UTF-8 JSON"
        ) from error
    if not isinstance(payload, dict):
        raise IFEMCalibrationRiskRoutingError("calibration risk routing must be a JSON object")
    try:
        routing = IFEMCalibrationRiskRoutingV1.model_validate(payload)
    except ValueError as error:
        raise IFEMCalibrationRiskRoutingError("calibration risk routing is invalid") from error
    if render_ifem_calibration_risk_routing(routing) != raw:
        raise IFEMCalibrationRiskRoutingError(
            "calibration risk routing is not canonically rendered"
        )
    return routing


def render_ifem_calibration_risk_routing(routing: IFEMCalibrationRiskRoutingV1) -> bytes:
    if type(routing) is not IFEMCalibrationRiskRoutingV1:
        raise IFEMCalibrationRiskRoutingError("risk routing must use its exact typed model")
    try:
        verified = IFEMCalibrationRiskRoutingV1.model_validate(routing.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as error:
        raise IFEMCalibrationRiskRoutingError("risk routing failed self-revalidation") from error
    rendered = canonical_json_bytes(verified.model_dump(mode="json")) + b"\n"
    forbidden = (
        b'"candidate_declarations"',
        b'"canonical_type"',
        b'"declaration"',
        b'"source_text"',
        b'"raw_output"',
    )
    if any(field in rendered for field in forbidden):
        raise IFEMCalibrationRiskRoutingError("risk routing rendering leaked a forbidden field")
    return rendered


def _write_once(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError:
        existing, _file_sha256 = _read_regular_file(path, label="existing risk routing output")
        if existing != content:
            raise IFEMCalibrationRiskRoutingError(
                "risk routing output already exists with different bytes"
            ) from None


def materialize_ifem_calibration_risk_routing_from_paths_once(
    output_path: Path,
    **paths: Path,
) -> IFEMCalibrationRiskRoutingV1:
    """Build and write a content-addressed routing artifact without replacement."""

    routing = build_ifem_calibration_risk_routing_from_paths(**paths)
    _write_once(output_path, render_ifem_calibration_risk_routing(routing))
    return routing


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--d35-report", type=Path, default=DEFAULT_D35_REPORT_PATH)
    parser.add_argument("--graph", type=Path, default=DEFAULT_GRAPH_PATH)
    parser.add_argument("--census-plan", type=Path, default=DEFAULT_CENSUS_PLAN_PATH)
    parser.add_argument("--census-result", type=Path, default=DEFAULT_CENSUS_RESULT_PATH)
    parser.add_argument("--profile-summary", type=Path, default=DEFAULT_PROFILE_SUMMARY_PATH)
    parser.add_argument("--structural-corpus", type=Path, default=DEFAULT_STRUCTURAL_CORPUS_PATH)
    parser.add_argument("--readiness-decision", type=Path, default=DEFAULT_READINESS_DECISION_PATH)
    parser.add_argument("--out", type=Path, required=True)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    namespace = parse_arguments(arguments)
    routing = materialize_ifem_calibration_risk_routing_from_paths_once(
        namespace.out,
        d35_report_path=namespace.d35_report,
        graph_path=namespace.graph,
        census_plan_path=namespace.census_plan,
        census_result_path=namespace.census_result,
        profile_summary_path=namespace.profile_summary,
        structural_corpus_path=namespace.structural_corpus,
        readiness_decision_path=namespace.readiness_decision,
    )
    print(routing.content_sha256)
    return 0


__all__ = [
    "DEFAULT_D35_REPORT_PATH",
    "RISK_ROUTING_KIND",
    "RISK_ROUTING_PROTOCOL",
    "RISK_ROUTING_SCHEMA",
    "IFEMCalibrationPriorityV1",
    "IFEMCalibrationRiskRoutingAuthorityV1",
    "IFEMCalibrationRiskRoutingError",
    "IFEMCalibrationRiskRoutingEvidenceV1",
    "IFEMCalibrationRiskRoutingNodeV1",
    "IFEMCalibrationRiskRoutingV1",
    "IFEMRequiredNextCalibrationV1",
    "build_ifem_calibration_risk_routing_from_paths",
    "load_ifem_calibration_risk_routing",
    "main",
    "materialize_ifem_calibration_risk_routing_from_paths_once",
    "render_ifem_calibration_risk_routing",
    "verify_ifem_calibration_risk_routing_against_paths",
]
