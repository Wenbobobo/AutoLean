from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import Field, model_validator

from .attestation import AttestationPurposeV1, AttestationV1
from .base import ContractModel, utc_now
from .graphs import GraphBundleV1
from .hashing import (
    DigestV1,
    HashKindV1,
    StableIdentifierV1,
    digest_model,
    digest_text,
    require_digest_kind,
)

_LEAN_NAMESPACE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_LEAN_DECLARATION = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class PermissionDecisionV1(StrEnum):
    ALLOW = "allow"
    RESTRICTED = "restricted"
    UNKNOWN = "unknown"
    DENY = "deny"


class EndpointClassV1(StrEnum):
    NONE = "none"
    LOCAL = "local"
    APPROVED_EXTERNAL = "approved_external"
    EXTERNAL = "external"


class TaskKindV1(StrEnum):
    KNOWN_THEOREM = "known_theorem"
    LIBRARY_GAP = "library_gap"
    PROOF_RECONSTRUCTION = "proof_reconstruction"
    OPEN_CONJECTURE = "open_conjecture"


class ReleaseTierV1(StrEnum):
    CALIBRATION = "calibration"
    SANDBOX = "sandbox"
    DOWNSTREAM = "downstream"
    UPSTREAM_CANDIDATE = "upstream_candidate"
    CONJECTURE_QUARANTINE = "conjecture_quarantine"


class AxiomProfileV1(StrEnum):
    STRICT = "strict"
    MATHLIB = "mathlib"
    EXPLICIT_ALLOWLIST = "explicit_allowlist"


MATHLIB_AXIOMS_V1: tuple[str, ...] = (
    "Classical.choice",
    "Quot.sound",
    "propext",
)


def validate_axiom_policy_v1(
    profile: AxiomProfileV1,
    axioms_allowlist: tuple[str, ...],
) -> None:
    """Validate the exact V1 axiom policy shared by Builder and verifier."""

    allowed = set(axioms_allowlist)
    if "sorryAx" in allowed:
        raise ValueError("sorryAx is prohibited in every axiom profile")
    if profile is AxiomProfileV1.STRICT and allowed:
        raise ValueError("the strict axiom profile requires an empty allowlist")
    if profile is AxiomProfileV1.MATHLIB:
        unsupported = allowed - set(MATHLIB_AXIOMS_V1)
        if unsupported:
            raise ValueError(
                "the mathlib axiom profile contains non-baseline axioms: "
                + ", ".join(sorted(unsupported))
            )


class FidelityRiskV1(StrEnum):
    L0_REUSE = "l0_reuse"
    L1_SIMPLE = "l1_simple"
    L2_REUSABLE_API = "l2_reusable_api"
    L3_RESEARCH = "l3_research"


class StatementStatusV1(StrEnum):
    DRAFT = "draft"
    UNDER_REVIEW = "under_review"
    FROZEN = "frozen"
    SUPERSEDED = "superseded"


class ProofStatusV1(StrEnum):
    CANDIDATE = "candidate"
    KERNEL_VERIFIED = "kernel_verified"
    REJECTED = "rejected"


class IntegrationStatusV1(StrEnum):
    SANDBOX = "sandbox"
    DOWNSTREAM_READY = "downstream_ready"
    UPSTREAM_REVIEW = "upstream_review"
    MERGED = "merged"


class SourceSpanV1(ContractModel):
    span_id: StableIdentifierV1
    locator: str = Field(min_length=1)
    content_hash: DigestV1
    start_offset: int | None = Field(default=None, ge=0)
    end_offset: int | None = Field(default=None, ge=0)
    permitted_excerpt: str | None = None

    @model_validator(mode="after")
    def validate_span(self) -> SourceSpanV1:
        require_digest_kind(self.content_hash, HashKindV1.SOURCE_SPAN, "content_hash")
        if (
            self.start_offset is not None
            and self.end_offset is not None
            and self.end_offset < self.start_offset
        ):
            raise ValueError("end_offset must not precede start_offset")
        if self.permitted_excerpt is not None:
            expected = digest_text(HashKindV1.SOURCE_SPAN, self.permitted_excerpt)
            if expected != self.content_hash:
                raise ValueError("permitted_excerpt does not match content_hash")
        return self


class SourceRecordV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    source_id: StableIdentifierV1
    work_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    version: str = Field(min_length=1)
    locator: str = Field(min_length=1)
    content_hash: DigestV1
    snapshot_ref: str | None = None
    retrieved_at: datetime = Field(default_factory=utc_now)
    spans: tuple[SourceSpanV1, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_source_hashes(self) -> SourceRecordV1:
        require_digest_kind(self.content_hash, HashKindV1.SOURCE_BYTES, "content_hash")
        span_ids = [span.span_id.value for span in self.spans]
        if len(span_ids) != len(set(span_ids)):
            raise ValueError("source span identifiers must be unique")
        return self


class RightsRecordV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    rights_id: StableIdentifierV1
    source_id: StableIdentifierV1
    source_license: str | None = None
    generated_code_license: str | None = None
    overall_decision: PermissionDecisionV1
    redistribution: PermissionDecisionV1 = PermissionDecisionV1.UNKNOWN
    model_egress: PermissionDecisionV1 = PermissionDecisionV1.UNKNOWN
    training: PermissionDecisionV1 = PermissionDecisionV1.UNKNOWN
    embedding: PermissionDecisionV1 = PermissionDecisionV1.UNKNOWN
    allowed_endpoint_classes: tuple[EndpointClassV1, ...] = ()
    attribution: str | None = None
    restrictions: tuple[str, ...] = ()
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None

    @model_validator(mode="after")
    def validate_allow_decision(self) -> RightsRecordV1:
        if self.overall_decision is PermissionDecisionV1.ALLOW:
            if not self.source_license:
                raise ValueError("an allowed rights decision requires source_license")
            if not self.reviewed_by or not self.reviewed_at:
                raise ValueError("an allowed rights decision requires reviewer and timestamp")
        if self.model_egress is PermissionDecisionV1.ALLOW and not self.allowed_endpoint_classes:
            raise ValueError("allowed model egress requires explicit endpoint classes")
        return self


class AmbiguitySeverityV1(StrEnum):
    INFORMATIONAL = "informational"
    BLOCKING = "blocking"


class AmbiguityV1(ContractModel):
    ambiguity_id: StableIdentifierV1
    description: str = Field(min_length=1)
    severity: AmbiguitySeverityV1
    resolution: str | None = None
    resolved_by: str | None = None

    @model_validator(mode="after")
    def validate_resolution(self) -> AmbiguityV1:
        if (self.resolution is None) != (self.resolved_by is None):
            raise ValueError("resolution and resolved_by must be provided together")
        return self


class MathematicalSpecificationV1(ContractModel):
    informal_statement: str = Field(min_length=1)
    normalized_statement: str = Field(min_length=1)
    assumptions: tuple[str, ...] = ()
    quantifier_order: tuple[str, ...] = ()
    notation_context: tuple[str, ...] = ()
    definitions: tuple[str, ...] = ()
    equality_notions: tuple[str, ...] = ()
    edge_cases: tuple[str, ...] = ()
    ambiguities: tuple[AmbiguityV1, ...] = ()


class OciVerifierExecutionPolicyV1(ContractModel):
    """The V1 OCI verifier policy frozen inside a Lean environment.

    The policy deliberately separates a stable command-policy digest from an individual OCI
    invocation hash.  The latter contains host-specific mount paths and is useful audit evidence,
    but cannot be frozen in a reusable statement contract.  Any change to this V1 wrapper or
    isolation profile requires a new contract revision (or a future protocol version).
    """

    schema_version: Literal["1.0"] = "1.0"
    worker_image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    wrapper_protocol: Literal["autolean.oci-lean-wrapper.v1"] = "autolean.oci-lean-wrapper.v1"
    wrapper_executable: Literal["/opt/autolean/bin/autolean-lean-wrapper"] = (
        "/opt/autolean/bin/autolean-lean-wrapper"
    )
    candidate_path: Literal["/input/Candidate.lean"] = "/input/Candidate.lean"
    type_format: Literal["autolean.lean-pp-expr.v1"] = "autolean.lean-pp-expr.v1"
    network_mode: Literal["none"] = "none"
    read_only_root: Literal[True] = True
    drop_all_capabilities: Literal[True] = True
    no_new_privileges: Literal[True] = True
    source_mount_path: Literal["/source"] = "/source"
    dependencies_mount_path: Literal["/deps"] = "/deps"
    source_mount_read_only: Literal[True] = True
    dependencies_mount_read_only: Literal[True] = True
    candidate_mount_read_only: Literal[True] = True
    workdir: Literal["/work"] = "/work"

    def command_policy_hash(self) -> DigestV1:
        """Return the frozen hash of the wrapper and OCI isolation policy.

        ``worker_image_digest`` is intentionally excluded: it has a separately auditable field
        and changing it is still a semantic contract change through this enclosing model.
        """

        return digest_model(
            HashKindV1.VERIFICATION_COMMAND,
            self,
            exclude={"worker_image_digest"},
        )

    def wrapper_argv(self, expected_declaration: str) -> tuple[str, ...]:
        """Render the only wrapper command shape allowed by this V1 policy."""

        if not expected_declaration or expected_declaration != expected_declaration.strip():
            raise ValueError("expected declaration must be a nonempty canonical identifier")
        if "\x00" in expected_declaration or "\n" in expected_declaration:
            raise ValueError("expected declaration contains a control character")
        return (
            self.wrapper_executable,
            "--protocol",
            self.wrapper_protocol,
            "--candidate",
            self.candidate_path,
            "--declaration",
            expected_declaration,
            "--type-format",
            self.type_format,
        )


class OciVerifierExecutionPolicyV2(ContractModel):
    """The explicit two-phase OCI policy for newly revised Lean environments.

    V2 separates untrusted compilation from the trusted query wrapper. It is intentionally a
    sibling of V1 rather than a mutation or subclass: choosing V2 changes the contract hash and
    therefore requires a new statement-contract revision.
    """

    schema_version: Literal["2.0"] = "2.0"
    worker_image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    wrapper_protocol: Literal["autolean.oci-lean-wrapper.v2"] = "autolean.oci-lean-wrapper.v2"
    wrapper_executable: Literal["/opt/autolean/bin/autolean-lean-wrapper"] = (
        "/opt/autolean/bin/autolean-lean-wrapper"
    )
    candidate_path: Literal["/input/Candidate.lean"] = "/input/Candidate.lean"
    compiler_output_path: Literal["/output/Candidate.olean"] = "/output/Candidate.olean"
    compiled_candidate_path: Literal["/compiled/Candidate.olean"] = "/compiled/Candidate.olean"
    handoff_protocol: Literal["autolean.oci-compile-query-handoff.v1"] = (
        "autolean.oci-compile-query-handoff.v1"
    )
    type_format: Literal["autolean.lean-pp-expr.v1"] = "autolean.lean-pp-expr.v1"
    network_mode: Literal["none"] = "none"
    read_only_root: Literal[True] = True
    drop_all_capabilities: Literal[True] = True
    no_new_privileges: Literal[True] = True
    runtime_user_mode: Literal["host-non-root"] = "host-non-root"
    source_mount_path: Literal["/source"] = "/source"
    dependencies_mount_path: Literal["/deps"] = "/deps"
    source_mount_read_only: Literal[True] = True
    dependencies_mount_read_only: Literal[True] = True
    candidate_mount_read_only: Literal[True] = True
    workdir: Literal["/work"] = "/work"

    def command_policy_hash(self) -> DigestV1:
        """Return the frozen hash of the V2 wrapper and OCI isolation policy."""

        return digest_model(
            HashKindV1.VERIFICATION_COMMAND,
            self,
            exclude={"worker_image_digest"},
        )

    def compile_wrapper_argv(self) -> tuple[str, ...]:
        """Render the untrusted compilation phase command."""

        return (
            self.wrapper_executable,
            "--protocol",
            self.wrapper_protocol,
            "--phase",
            "compile",
            "--candidate",
            self.candidate_path,
            "--output",
            self.compiler_output_path,
        )

    def wrapper_argv(self, expected_declaration: str) -> tuple[str, ...]:
        """Render the trusted query phase command."""

        if not expected_declaration or expected_declaration != expected_declaration.strip():
            raise ValueError("expected declaration must be a nonempty canonical identifier")
        if "\x00" in expected_declaration or "\n" in expected_declaration:
            raise ValueError("expected declaration contains a control character")
        return (
            self.wrapper_executable,
            "--protocol",
            self.wrapper_protocol,
            "--phase",
            "query",
            "--compiled",
            self.compiled_candidate_path,
            "--declaration",
            expected_declaration,
            "--type-format",
            self.type_format,
        )


OciVerifierExecutionPolicy = Annotated[
    OciVerifierExecutionPolicyV1 | OciVerifierExecutionPolicyV2,
    Field(discriminator="schema_version"),
]


class LeanEnvironmentV1(ContractModel):
    lean_version: str = Field(min_length=1)
    mathlib_revision: str = Field(min_length=1)
    verifier_execution_policy: OciVerifierExecutionPolicy
    lake_manifest_hash: DigestV1 | None = None
    environment_hash: DigestV1

    @model_validator(mode="after")
    def validate_hashes(self) -> LeanEnvironmentV1:
        require_digest_kind(self.environment_hash, HashKindV1.ENVIRONMENT, "environment_hash")
        if self.lake_manifest_hash is not None:
            require_digest_kind(
                self.lake_manifest_hash,
                HashKindV1.ENVIRONMENT,
                "lake_manifest_hash",
            )
        return self


class FormalSpecificationV1(ContractModel):
    declaration_name: str = Field(min_length=1)
    namespace: str = Field(min_length=1)
    lean_statement_source: str = Field(min_length=1)
    statement_source_hash: DigestV1
    elaborated_type: str | None = None
    elaborated_type_hash: DigestV1 | None = None
    environment: LeanEnvironmentV1
    imports_allowlist: tuple[str, ...] = ()
    axioms_allowlist: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_content_hashes(self) -> FormalSpecificationV1:
        require_digest_kind(
            self.statement_source_hash,
            HashKindV1.STATEMENT_SOURCE,
            "statement_source_hash",
        )
        expected_statement_hash = digest_text(
            HashKindV1.STATEMENT_SOURCE,
            self.lean_statement_source,
        )
        if expected_statement_hash != self.statement_source_hash:
            raise ValueError("lean_statement_source does not match statement_source_hash")
        if (self.elaborated_type is None) != (self.elaborated_type_hash is None):
            raise ValueError("elaborated_type and elaborated_type_hash must be provided together")
        if self.elaborated_type is not None and self.elaborated_type_hash is not None:
            require_digest_kind(
                self.elaborated_type_hash,
                HashKindV1.ELABORATED_TYPE,
                "elaborated_type_hash",
            )
            expected = digest_text(HashKindV1.ELABORATED_TYPE, self.elaborated_type)
            if expected != self.elaborated_type_hash:
                raise ValueError("elaborated_type does not match elaborated_type_hash")
        return self


class AlignmentTargetV1(ContractModel):
    source_span_id: StableIdentifierV1
    formal_target: str = Field(min_length=1)
    relation: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    reviewer_id: str | None = None


class DependencyKindV1(StrEnum):
    MATHEMATICAL = "mathematical"
    FORMAL_SIGNATURE = "formal_signature"
    FORMAL_BODY = "formal_body"
    TASK = "task"


class DependencyReferenceV1(ContractModel):
    dependency_id: StableIdentifierV1
    kind: DependencyKindV1
    target: str = Field(min_length=1)
    required: bool = True
    rationale: str | None = None


class EditRegionV1(ContractModel):
    artifact_ref: str = Field(min_length=1)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_lines(self) -> EditRegionV1:
        if self.end_line < self.start_line:
            raise ValueError("end_line must not precede start_line")
        return self


class OpenProblemPolicyV1(ContractModel):
    enabled: bool = False
    quarantine_required: bool = True
    required_independent_verifiers: int = Field(default=2, ge=1)
    required_domain_expert_reviews: int = Field(default=1, ge=1)
    require_clean_environment: bool = True
    require_strict_axiom_profile: bool = True
    forbid_post_freeze_statement_change: bool = True


class TaskPolicyV1(ContractModel):
    release_tier: ReleaseTierV1
    fidelity_risk: FidelityRiskV1
    axiom_profile: AxiomProfileV1 = AxiomProfileV1.STRICT
    allowed_edit_regions: tuple[EditRegionV1, ...] = ()
    proof_budget: dict[str, int] = Field(default_factory=dict)
    open_problem: OpenProblemPolicyV1 = Field(default_factory=OpenProblemPolicyV1)

    @model_validator(mode="after")
    def validate_budget(self) -> TaskPolicyV1:
        if any(value < 0 for value in self.proof_budget.values()):
            raise ValueError("proof budget values must be non-negative")
        return self


class ActorKindV1(StrEnum):
    HUMAN = "human"
    MODEL = "model"
    TOOL = "tool"
    SERVICE = "service"


class ProvenanceTraceV1(ContractModel):
    trace_id: StableIdentifierV1
    actor_id: str = Field(min_length=1)
    actor_kind: ActorKindV1
    endpoint_class: EndpointClassV1 = EndpointClassV1.NONE
    provider: str | None = None
    model_name: str | None = None
    model_revision: str | None = None
    config_hash: DigestV1 | None = None
    prompt_hash: DigestV1 | None = None
    tool_hashes: tuple[DigestV1, ...] = ()
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_model_trace(self) -> ProvenanceTraceV1:
        if self.actor_kind is ActorKindV1.MODEL:
            if not self.provider or not self.model_name or not self.model_revision:
                raise ValueError("model provenance requires provider, name, and revision")
            if self.endpoint_class is EndpointClassV1.NONE:
                raise ValueError("model provenance requires an endpoint class")
        if self.config_hash is not None:
            require_digest_kind(self.config_hash, HashKindV1.CONFIG, "config_hash")
        if self.prompt_hash is not None:
            require_digest_kind(self.prompt_hash, HashKindV1.PROMPT, "prompt_hash")
        for tool_hash in self.tool_hashes:
            require_digest_kind(tool_hash, HashKindV1.TOOL, "tool_hashes")
        return self


class FidelityCheckKindV1(StrEnum):
    SOURCE_PRESERVATION = "source_preservation"
    REVERSE_RENDER = "reverse_render"
    INDEPENDENT_TRANSLATION = "independent_translation"
    POSITIVE_EXAMPLE = "positive_example"
    NEGATIVE_EXAMPLE = "negative_example"
    NON_VACUITY = "non_vacuity"
    ESTABLISHED_EQUIVALENCE = "established_equivalence"
    API_REVIEW = "api_review"


class FidelityCheckV1(ContractModel):
    check_id: StableIdentifierV1
    kind: FidelityCheckKindV1
    passed: bool
    evidence: str = Field(min_length=1)
    reviewer_id: str
    independent: bool = False


class MutationKindV1(StrEnum):
    DROP_ASSUMPTION = "drop_assumption"
    SWAP_QUANTIFIERS = "swap_quantifiers"
    WEAKEN_RELATION = "weaken_relation"
    REMOVE_SIDE_CONDITION = "remove_side_condition"
    DROP_NONEMPTY = "drop_nonempty"
    DROP_FINITE = "drop_finite"
    DROP_NOETHERIAN = "drop_noetherian"
    REVERSE_PARAMETERS = "reverse_parameters"
    CHANGE_EQUALITY_NOTION = "change_equality_notion"
    TOTALIZATION_TRAP = "totalization_trap"
    TYPECLASS_COERCION = "typeclass_coercion"
    VACUITY = "vacuity"


class MutationProbeV1(ContractModel):
    probe_id: StableIdentifierV1
    kind: MutationKindV1
    target_path: str = Field(min_length=1)
    expected_failure: str = Field(min_length=1)
    mutated_statement_source: str = Field(min_length=1)


class MutationResultV1(ContractModel):
    probe: MutationProbeV1
    detected: bool
    evidence: str = Field(min_length=1)
    executed_by: str = Field(min_length=1)


class ReviewerRoleV1(StrEnum):
    SEMANTIC_REVIEWER = "semantic_reviewer"
    DOMAIN_EXPERT = "domain_expert"
    LIBRARY_REVIEWER = "library_reviewer"
    INDEPENDENT_VERIFIER = "independent_verifier"
    INTEGRATOR = "integrator"


class DecisionV1(StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"
    REQUEST_CHANGES = "request_changes"


class ReviewerSignoffV1(ContractModel):
    signoff_id: StableIdentifierV1
    reviewer_id: str = Field(min_length=1)
    role: ReviewerRoleV1
    decision: DecisionV1
    independent: bool = True
    rationale: str = Field(min_length=1)
    reviewed_at: datetime = Field(default_factory=utc_now)


class FidelityReportV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    report_id: StableIdentifierV1
    evidence_hash: DigestV1
    risk_level: FidelityRiskV1
    checks: tuple[FidelityCheckV1, ...] = ()
    mutation_results: tuple[MutationResultV1, ...] = ()
    signoffs: tuple[ReviewerSignoffV1, ...] = ()
    generated_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_evidence_hash(self) -> FidelityReportV1:
        require_digest_kind(
            self.evidence_hash,
            HashKindV1.FREEZE_EVIDENCE,
            "evidence_hash",
        )
        return self


class FidelityEvidenceArtifactRefV1(ContractModel):
    """Public content identity for the Builder's canonical fidelity evidence."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_schema: Literal["autolean.builder-fidelity-evidence.v1"] = (
        "autolean.builder-fidelity-evidence.v1"
    )
    digest: DigestV1
    size: int = Field(gt=0)
    media_type: Literal["application/vnd.autolean.builder-fidelity-evidence.v1+json"] = (
        "application/vnd.autolean.builder-fidelity-evidence.v1+json"
    )

    @model_validator(mode="after")
    def validate_digest(self) -> FidelityEvidenceArtifactRefV1:
        require_digest_kind(
            self.digest,
            HashKindV1.FREEZE_EVIDENCE,
            "digest",
        )
        return self


class FreezeRecordV1(ContractModel):
    contract_hash: DigestV1
    source_hash: DigestV1
    source_preparation_id: StableIdentifierV1 | None = None
    source_preparation_hash: DigestV1 | None = None
    statement_source_hash: DigestV1
    elaborated_type_hash: DigestV1 | None = None
    frozen_by: str = Field(min_length=1)
    frozen_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_hash_kinds(self) -> FreezeRecordV1:
        require_digest_kind(self.contract_hash, HashKindV1.CONTRACT, "contract_hash")
        require_digest_kind(self.source_hash, HashKindV1.SOURCE_BYTES, "source_hash")
        if (self.source_preparation_id is None) != (self.source_preparation_hash is None):
            raise ValueError("source preparation ID and hash must be present together")
        if self.source_preparation_id is not None:
            if self.source_preparation_id.namespace != "source-preparation":
                raise ValueError("source_preparation_id must use the source-preparation namespace")
            assert self.source_preparation_hash is not None
            require_digest_kind(
                self.source_preparation_hash,
                HashKindV1.SOURCE_PREPARATION,
                "source_preparation_hash",
            )
        require_digest_kind(
            self.statement_source_hash,
            HashKindV1.STATEMENT_SOURCE,
            "statement_source_hash",
        )
        if self.elaborated_type_hash is not None:
            require_digest_kind(
                self.elaborated_type_hash,
                HashKindV1.ELABORATED_TYPE,
                "elaborated_type_hash",
            )
        return self


class StatementContractV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    contract_id: StableIdentifierV1
    revision: int = Field(ge=1)
    task_kind: TaskKindV1
    source: SourceRecordV1
    rights: RightsRecordV1
    mathematics: MathematicalSpecificationV1
    formal: FormalSpecificationV1
    alignments: tuple[AlignmentTargetV1, ...] = ()
    dependencies: tuple[DependencyReferenceV1, ...] = ()
    policy: TaskPolicyV1
    fidelity: FidelityReportV1 | None = None
    provenance: tuple[ProvenanceTraceV1, ...] = ()
    status: StatementStatusV1 = StatementStatusV1.DRAFT
    freeze: FreezeRecordV1 | None = None

    def semantic_hash(self) -> DigestV1:
        return digest_model(
            HashKindV1.CONTRACT,
            self,
            exclude={"status", "freeze"},
        )

    @model_validator(mode="after")
    def validate_contract(self) -> StatementContractV1:
        if self.rights.source_id != self.source.source_id:
            raise ValueError("rights record must refer to the contract source")
        validate_axiom_policy_v1(
            self.policy.axiom_profile,
            self.formal.axioms_allowlist,
        )
        source_span_ids = {span.span_id.value for span in self.source.spans}
        if any(item.source_span_id.value not in source_span_ids for item in self.alignments):
            raise ValueError("every alignment must reference a known source span")
        if self.task_kind is TaskKindV1.OPEN_CONJECTURE:
            if not self.policy.open_problem.enabled:
                raise ValueError("open conjectures require explicit open_problem enablement")
            if self.policy.release_tier is not ReleaseTierV1.CONJECTURE_QUARANTINE:
                raise ValueError("open conjectures must remain in conjecture quarantine")
            if self.policy.fidelity_risk is not FidelityRiskV1.L3_RESEARCH:
                raise ValueError("open conjectures require L3 fidelity review")
        if self.status is StatementStatusV1.FROZEN:
            if self.freeze is None:
                raise ValueError("frozen contracts require a freeze record")
            if self.freeze.contract_hash != self.semantic_hash():
                raise ValueError("freeze record does not match semantic contract payload")
            if self.freeze.source_hash != self.source.content_hash:
                raise ValueError("freeze record source hash does not match source")
            if self.freeze.statement_source_hash != self.formal.statement_source_hash:
                raise ValueError("freeze record statement hash does not match formal source")
            if self.freeze.elaborated_type_hash != self.formal.elaborated_type_hash:
                raise ValueError("freeze record elaborated hash does not match formal type")
        elif self.freeze is not None:
            raise ValueError("only frozen contracts may contain a freeze record")
        return self


class ProofBoundaryV1(ContractModel):
    """The immutable solver boundary generated from a frozen statement contract.

    It is intentionally narrower than a source workspace: the worker receives an exact
    trusted declaration header and may write only a proof term to ``Proof.lean``.
    """

    schema_version: Literal["1.0"] = "1.0"
    contract_hash: DigestV1
    environment_hash: DigestV1
    trusted_statement_path: Literal["TrustedStatement.lean"] = "TrustedStatement.lean"
    trusted_statement_source: str = Field(min_length=1)
    trusted_statement_hash: DigestV1
    solver_manifest_hash: DigestV1
    allowed_write_paths: tuple[Literal["Proof.lean"], ...] = ("Proof.lean",)
    candidate_path: Literal["Candidate.lean"] = "Candidate.lean"
    comparator_id: Literal["lean-exact-declaration-boundary.v1"] = (
        "lean-exact-declaration-boundary.v1"
    )
    expected_declaration: str = Field(min_length=1)
    expected_elaborated_type_hash: DigestV1
    boundary_hash: DigestV1

    def solver_manifest_payload(self) -> dict[str, object]:
        """Return the complete, hashable manifest payload without its self-hash."""

        return {
            "schema_version": "autolean.solver-workspace-manifest.v1",
            "contract_hash": self.contract_hash.value,
            "environment_hash": self.environment_hash.value,
            "trusted_statement_path": self.trusted_statement_path,
            "trusted_statement_hash": self.trusted_statement_hash.value,
            "allowed_write_paths": list(self.allowed_write_paths),
            "candidate_path": self.candidate_path,
            "comparator_id": self.comparator_id,
            "expected_declaration": self.expected_declaration,
            "expected_elaborated_type_hash": self.expected_elaborated_type_hash.value,
        }

    def render_solver_manifest(self) -> str:
        return (
            json.dumps(
                self.solver_manifest_payload(),
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )

    @model_validator(mode="after")
    def validate_boundary(self) -> ProofBoundaryV1:
        require_digest_kind(self.contract_hash, HashKindV1.CONTRACT, "contract_hash")
        require_digest_kind(self.environment_hash, HashKindV1.ENVIRONMENT, "environment_hash")
        require_digest_kind(
            self.trusted_statement_hash,
            HashKindV1.TRUSTED_STATEMENT,
            "trusted_statement_hash",
        )
        require_digest_kind(
            self.solver_manifest_hash,
            HashKindV1.WORKSPACE_MANIFEST,
            "solver_manifest_hash",
        )
        require_digest_kind(
            self.expected_elaborated_type_hash,
            HashKindV1.ELABORATED_TYPE,
            "expected_elaborated_type_hash",
        )
        require_digest_kind(self.boundary_hash, HashKindV1.PROOF_BOUNDARY, "boundary_hash")
        if self.allowed_write_paths != ("Proof.lean",):
            raise ValueError("V1 proof boundaries permit only the Proof.lean proof slot")
        if "\n:= " in self.trusted_statement_source or ":=" in self.trusted_statement_source:
            raise ValueError("trusted statement source must not contain a proof body")
        if not _LEAN_NAMESPACE.fullmatch(self.expected_declaration.rpartition(".")[0]):
            raise ValueError("proof boundary declaration namespace is invalid")
        if not _LEAN_DECLARATION.fullmatch(self.expected_declaration.rpartition(".")[2]):
            raise ValueError("proof boundary declaration name is invalid")
        if self.trusted_statement_hash != digest_text(
            HashKindV1.TRUSTED_STATEMENT,
            self.trusted_statement_source,
        ):
            raise ValueError("trusted statement source does not match trusted_statement_hash")
        if self.solver_manifest_hash != digest_text(
            HashKindV1.WORKSPACE_MANIFEST,
            self.render_solver_manifest(),
        ):
            raise ValueError("solver manifest does not match solver_manifest_hash")
        if self.boundary_hash != digest_model(
            HashKindV1.PROOF_BOUNDARY,
            self,
            exclude={"boundary_hash"},
        ):
            raise ValueError("proof boundary does not match boundary_hash")
        return self


def render_trusted_statement(contract: StatementContractV1) -> str:
    """Render the exact declaration header a solver/verifier is permitted to compile."""

    statement = contract.formal.lean_statement_source.rstrip()
    if ":=" in statement:
        raise ValueError(
            "frozen Lean statement must be a declaration signature without a proof body"
        )
    namespace = contract.formal.namespace
    if not _LEAN_NAMESPACE.fullmatch(namespace):
        raise ValueError("frozen Lean namespace is not a safe qualified identifier")
    declaration = contract.formal.declaration_name
    if not _LEAN_DECLARATION.fullmatch(declaration):
        raise ValueError("frozen Lean declaration name is not a safe identifier")
    imports = tuple(f"import {item}" for item in contract.formal.imports_allowlist)
    lines = [*imports]
    if lines:
        lines.append("")
    lines.extend((f"namespace {namespace}", "", statement))
    return "\n".join(lines)


def build_proof_boundary(contract: StatementContractV1) -> ProofBoundaryV1:
    """Create the only valid V1 proof boundary for a frozen contract."""

    if contract.status is not StatementStatusV1.FROZEN:
        raise ValueError("only a frozen contract can create a proof boundary")
    elaborated_type_hash = contract.formal.elaborated_type_hash
    if elaborated_type_hash is None:
        raise ValueError("a proof boundary requires an elaborated declaration type")
    trusted_statement_source = render_trusted_statement(contract)
    contract_hash = contract.semantic_hash()
    environment_hash = contract.formal.environment.environment_hash
    trusted_statement_hash = digest_text(HashKindV1.TRUSTED_STATEMENT, trusted_statement_source)
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "contract_hash": contract_hash.model_dump(mode="json"),
        "environment_hash": environment_hash.model_dump(mode="json"),
        "trusted_statement_path": "TrustedStatement.lean",
        "trusted_statement_source": trusted_statement_source,
        "trusted_statement_hash": trusted_statement_hash.model_dump(mode="json"),
        "allowed_write_paths": ["Proof.lean"],
        "candidate_path": "Candidate.lean",
        "comparator_id": "lean-exact-declaration-boundary.v1",
        "expected_declaration": f"{contract.formal.namespace}.{contract.formal.declaration_name}",
        "expected_elaborated_type_hash": elaborated_type_hash.model_dump(mode="json"),
    }
    manifest_payload = {
        "schema_version": "autolean.solver-workspace-manifest.v1",
        "contract_hash": contract_hash.value,
        "environment_hash": environment_hash.value,
        "trusted_statement_path": "TrustedStatement.lean",
        "trusted_statement_hash": trusted_statement_hash.value,
        "allowed_write_paths": ["Proof.lean"],
        "candidate_path": "Candidate.lean",
        "comparator_id": "lean-exact-declaration-boundary.v1",
        "expected_declaration": payload["expected_declaration"],
        "expected_elaborated_type_hash": elaborated_type_hash.value,
    }
    manifest_source = (
        json.dumps(
            manifest_payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    solver_manifest_hash = digest_text(HashKindV1.WORKSPACE_MANIFEST, manifest_source)
    payload["solver_manifest_hash"] = solver_manifest_hash.model_dump(mode="json")
    payload["boundary_hash"] = digest_model(HashKindV1.PROOF_BOUNDARY, payload).model_dump(
        mode="json"
    )
    return ProofBoundaryV1.model_validate(payload)


class FormalizationTaskBundleV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    bundle_id: StableIdentifierV1
    contract: StatementContractV1
    graphs: GraphBundleV1
    graph_snapshot_hash: DigestV1
    proof_boundary: ProofBoundaryV1
    fidelity_evidence: FidelityEvidenceArtifactRefV1 | None = None
    issued_at: datetime = Field(default_factory=utc_now)
    builder_attestation: AttestationV1 | None = None

    def handoff_hash(self) -> DigestV1:
        """Hash the immutable Builder-to-Prover bundle excluding its attached signature.

        The builder attestation signs this value, so including the attestation itself would create
        a circular hash.  The control plane still requires the attestation before registration.
        """

        payload = self.model_dump(
            mode="json",
            exclude={"builder_attestation"},
            exclude_none=False,
        )
        return digest_model(HashKindV1.BUNDLE, payload)

    @model_validator(mode="after")
    def validate_frozen_snapshot(self) -> FormalizationTaskBundleV1:
        if self.contract.status is not StatementStatusV1.FROZEN:
            raise ValueError("only a frozen statement contract can be bridged")
        if self.contract.policy.allowed_edit_regions:
            raise ValueError(
                "V1 bundles do not support line-ranged editable regions; "
                "Proof.lean is the complete write boundary"
            )
        require_digest_kind(
            self.graph_snapshot_hash,
            HashKindV1.GRAPH_SNAPSHOT,
            "graph_snapshot_hash",
        )
        expected = digest_model(HashKindV1.GRAPH_SNAPSHOT, self.graphs)
        if self.graph_snapshot_hash != expected:
            raise ValueError("graph_snapshot_hash does not match graphs")
        boundary = self.proof_boundary
        if boundary.contract_hash != self.contract.semantic_hash():
            raise ValueError("proof boundary does not bind the frozen contract")
        if boundary.environment_hash != self.contract.formal.environment.environment_hash:
            raise ValueError("proof boundary does not bind the contract environment")
        if boundary.expected_elaborated_type_hash != self.contract.formal.elaborated_type_hash:
            raise ValueError("proof boundary does not bind the elaborated declaration type")
        if boundary.expected_declaration != (
            f"{self.contract.formal.namespace}.{self.contract.formal.declaration_name}"
        ):
            raise ValueError("proof boundary comparator targets a different declaration")
        if boundary.trusted_statement_source != render_trusted_statement(self.contract):
            raise ValueError("proof boundary trusted statement differs from the frozen contract")
        if self.contract.fidelity is None:
            if self.fidelity_evidence is not None:
                raise ValueError("fidelity evidence cannot accompany a contract without a report")
        elif self.fidelity_evidence is None:
            raise ValueError("a reviewed contract bundle requires fidelity evidence")
        elif self.fidelity_evidence.digest != self.contract.fidelity.evidence_hash:
            raise ValueError("fidelity artifact digest does not match the reviewed report")
        if (
            self.builder_attestation is not None
            and self.builder_attestation.purpose is not AttestationPurposeV1.BUILDER_FREEZE
        ):
            raise ValueError("bundle attestation must use the builder_freeze authority purpose")
        return self


def freeze_evidence_hash(contract: StatementContractV1) -> DigestV1:
    """Hash the freeze record and fidelity evidence which authorized a Builder handoff."""

    if contract.status is not StatementStatusV1.FROZEN or contract.freeze is None:
        raise ValueError("only a frozen contract has Builder freeze evidence")
    payload = {
        "schema_version": "autolean.freeze-evidence.v1",
        "contract_id": contract.contract_id.value,
        "revision": contract.revision,
        "contract_hash": contract.semantic_hash().value,
        "freeze": contract.freeze.model_dump(mode="json"),
        "fidelity": (
            None if contract.fidelity is None else contract.fidelity.model_dump(mode="json")
        ),
    }
    return digest_model(HashKindV1.FREEZE_EVIDENCE, payload)


def builder_attestation_payload(bundle: FormalizationTaskBundleV1) -> dict[str, object]:
    """Return the exact semantic payload a Builder authority must attest."""

    contract = bundle.contract
    return {
        "schema_version": "autolean.builder-freeze-attestation-payload.v1",
        "bundle_id": bundle.bundle_id.value,
        "bundle_hash": bundle.handoff_hash().value,
        "contract_id": contract.contract_id.value,
        "revision": contract.revision,
        "contract_hash": contract.semantic_hash().value,
        "proof_boundary_hash": bundle.proof_boundary.boundary_hash.value,
        "environment_hash": contract.formal.environment.environment_hash.value,
        "freeze_evidence_hash": freeze_evidence_hash(contract).value,
    }


class AttemptMetricsV1(ContractModel):
    """Non-sensitive accounting attached to one proof-search submission."""

    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cached_input_tokens: int = Field(default=0, ge=0)
    cost_usd: float = Field(default=0.0, ge=0.0)
    elapsed_ms: int = Field(default=0, ge=0)


class ProofSubmissionV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    proof_id: StableIdentifierV1
    contract_id: StableIdentifierV1
    revision: int = Field(ge=1)
    contract_hash: DigestV1
    proof_boundary_hash: DigestV1
    proof_source: str = Field(min_length=1)
    proof_source_hash: DigestV1
    environment_hash: DigestV1
    dependency_manifest: tuple[str, ...] = ()
    provenance: tuple[ProvenanceTraceV1, ...] = ()
    metrics: AttemptMetricsV1 = Field(default_factory=AttemptMetricsV1)
    status: ProofStatusV1 = ProofStatusV1.CANDIDATE
    submitted_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_hashes(self) -> ProofSubmissionV1:
        require_digest_kind(self.contract_hash, HashKindV1.CONTRACT, "contract_hash")
        require_digest_kind(
            self.proof_boundary_hash,
            HashKindV1.PROOF_BOUNDARY,
            "proof_boundary_hash",
        )
        require_digest_kind(self.proof_source_hash, HashKindV1.PROOF_SOURCE, "proof_source_hash")
        require_digest_kind(self.environment_hash, HashKindV1.ENVIRONMENT, "environment_hash")
        if digest_text(HashKindV1.PROOF_SOURCE, self.proof_source) != self.proof_source_hash:
            raise ValueError("proof_source does not match proof_source_hash")
        return self


def proof_dependency_manifest_hash(submission: ProofSubmissionV1) -> DigestV1:
    """Hash the exact declared dependency manifest for verifier-evidence binding."""

    return digest_model(
        HashKindV1.DEPENDENCY_MANIFEST,
        {
            "schema_version": "autolean.proof-dependency-manifest.v1",
            "proof_id": submission.proof_id.value,
            "dependencies": list(submission.dependency_manifest),
        },
    )


class GapKindV1(StrEnum):
    MISSING_DEFINITION = "missing_definition"
    MISSING_LEMMA = "missing_lemma"
    BAD_STATEMENT = "bad_statement"
    AMBIGUOUS_SOURCE = "ambiguous_source"
    API_MISMATCH = "api_mismatch"
    VERSION_DRIFT = "version_drift"
    RESOURCE_EXHAUSTED = "resource_exhausted"


class GapReportV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    report_id: StableIdentifierV1
    contract_id: StableIdentifierV1
    revision: int = Field(ge=1)
    contract_hash: DigestV1
    kind: GapKindV1
    evidence: str = Field(min_length=1)
    minimal_reproducer: str | None = None
    affected_nodes: tuple[StableIdentifierV1, ...] = ()
    suggested_action: str | None = None
    reported_by: str = Field(min_length=1)
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_hash_kind(self) -> GapReportV1:
        require_digest_kind(self.contract_hash, HashKindV1.CONTRACT, "contract_hash")
        return self


class ContractChangeV1(ContractModel):
    path: str = Field(min_length=1)
    operation: Literal["add", "remove", "replace"]
    before: Any | None = None
    after: Any | None = None
    semantic: bool = True


class ContractChangeRequestV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    request_id: StableIdentifierV1
    contract_id: StableIdentifierV1
    old_revision: int = Field(ge=1)
    old_contract_hash: DigestV1
    proposed_changes: tuple[ContractChangeV1, ...] = Field(min_length=1)
    semantic_impact: str = Field(min_length=1)
    evidence: str = Field(min_length=1)
    requested_by: str = Field(min_length=1)
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_hash_kind(self) -> ContractChangeRequestV1:
        require_digest_kind(self.old_contract_hash, HashKindV1.CONTRACT, "old_contract_hash")
        return self


class VerificationArtifactEnvironmentV1(ContractModel):
    """Non-secret frozen environment facts copied into a verifier evidence artifact."""

    environment_hash: DigestV1
    lean_version: str = Field(min_length=1)
    mathlib_revision: str = Field(min_length=1)
    lake_manifest_hash: DigestV1 | None = None

    @model_validator(mode="after")
    def validate_hashes(self) -> VerificationArtifactEnvironmentV1:
        require_digest_kind(self.environment_hash, HashKindV1.ENVIRONMENT, "environment_hash")
        if self.lake_manifest_hash is not None:
            require_digest_kind(
                self.lake_manifest_hash,
                HashKindV1.ENVIRONMENT,
                "lake_manifest_hash",
            )
        return self


class OciVerificationArtifactV1(ContractModel):
    """Sanitized OCI facts whose exact canonical JSON is retained as verification evidence."""

    schema_version: Literal["autolean.oci-execution-evidence.v1"] = (
        "autolean.oci-execution-evidence.v1"
    )
    worker_image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    wrapper_protocol: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    command_policy_hash: DigestV1
    command_hash: DigestV1
    candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trusted_statement_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    bundle_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_hashes(self) -> OciVerificationArtifactV1:
        require_digest_kind(
            self.command_policy_hash,
            HashKindV1.VERIFICATION_COMMAND,
            "command_policy_hash",
        )
        require_digest_kind(self.command_hash, HashKindV1.VERIFICATION_COMMAND, "command_hash")
        return self


class OciExecutionAuthorityV1(ContractModel):
    """Lease and image-owned verifier identity observed for one authoritative OCI run."""

    schema_version: Literal["autolean.oci-execution-authority.v1"] = (
        "autolean.oci-execution-authority.v1"
    )
    status: Literal["lease-bound-pending-gateway"] = "lease-bound-pending-gateway"
    execution_claim_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    worker_id: str = Field(
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$",
    )
    fencing_token: int = Field(gt=0)
    expires_at: datetime
    wrapper_identity_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_expiry(self) -> OciExecutionAuthorityV1:
        if self.expires_at.tzinfo is None:
            raise ValueError("OCI execution authority lease expiry must be timezone-aware")
        return self


class OciVerificationArtifactV2(ContractModel):
    """OCI evidence that binds an observed run to a fenced lease and approved verifier."""

    schema_version: Literal["autolean.oci-execution-evidence.v2"] = (
        "autolean.oci-execution-evidence.v2"
    )
    worker_image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    wrapper_protocol: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    command_policy_hash: DigestV1
    command_hash: DigestV1
    compile_command_hash: DigestV1
    query_command_hash: DigestV1
    sealed_candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    handoff_protocol: Literal["autolean.oci-compile-query-handoff.v1"] = (
        "autolean.oci-compile-query-handoff.v1"
    )
    candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trusted_statement_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    bundle_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_authority: OciExecutionAuthorityV1

    @model_validator(mode="after")
    def validate_hashes(self) -> OciVerificationArtifactV2:
        require_digest_kind(
            self.command_policy_hash,
            HashKindV1.VERIFICATION_COMMAND,
            "command_policy_hash",
        )
        require_digest_kind(self.command_hash, HashKindV1.VERIFICATION_COMMAND, "command_hash")
        require_digest_kind(
            self.compile_command_hash,
            HashKindV1.VERIFICATION_COMMAND,
            "compile_command_hash",
        )
        require_digest_kind(
            self.query_command_hash,
            HashKindV1.VERIFICATION_COMMAND,
            "query_command_hash",
        )
        transcript_hash = hashlib.sha256(
            json.dumps(
                {
                    "schema_version": "autolean.oci-command-transcript.v2",
                    "handoff_protocol": self.handoff_protocol,
                    "compile_command_hash": self.compile_command_hash.value,
                    "query_command_hash": self.query_command_hash.value,
                    "sealed_candidate_sha256": self.sealed_candidate_sha256,
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        if self.command_hash.value != transcript_hash:
            raise ValueError("command_hash does not bind the OCI compile/query handoff")
        return self


class VerificationEvidenceArtifactV1(ContractModel):
    """Canonical content-addressed verifier artifact accepted by the control plane.

    This deliberately excludes proof text, prompt text, workspace paths, raw Lean output, and
    credential references.  It is a bridge record for independently checking that an attested
    report, submitted proof, frozen bundle, and OCI observation all name the same immutable
    objects.
    """

    schema_version: Literal["autolean.verification-evidence-artifact.v1"] = (
        "autolean.verification-evidence-artifact.v1"
    )
    evidence_id: StableIdentifierV1
    bundle_id: StableIdentifierV1
    bundle_hash: DigestV1
    contract_id: StableIdentifierV1
    revision: int = Field(ge=1)
    contract_hash: DigestV1
    proof_id: StableIdentifierV1
    proof_boundary_hash: DigestV1
    proof_submission_artifact_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    dependency_manifest_hash: DigestV1
    verification_report_id: StableIdentifierV1
    verification_observation_hash: DigestV1
    environment: VerificationArtifactEnvironmentV1
    oci: OciVerificationArtifactV1

    @model_validator(mode="after")
    def validate_hashes(self) -> VerificationEvidenceArtifactV1:
        require_digest_kind(self.bundle_hash, HashKindV1.BUNDLE, "bundle_hash")
        require_digest_kind(self.contract_hash, HashKindV1.CONTRACT, "contract_hash")
        require_digest_kind(
            self.proof_boundary_hash,
            HashKindV1.PROOF_BOUNDARY,
            "proof_boundary_hash",
        )
        require_digest_kind(
            self.dependency_manifest_hash,
            HashKindV1.DEPENDENCY_MANIFEST,
            "dependency_manifest_hash",
        )
        require_digest_kind(
            self.verification_observation_hash,
            HashKindV1.VERIFICATION_REPORT,
            "verification_observation_hash",
        )
        return self


class VerificationEvidenceArtifactV2(ContractModel):
    """Canonical verifier artifact required for lease-bound gateway promotion."""

    schema_version: Literal["autolean.verification-evidence-artifact.v2"] = (
        "autolean.verification-evidence-artifact.v2"
    )
    evidence_id: StableIdentifierV1
    bundle_id: StableIdentifierV1
    bundle_hash: DigestV1
    contract_id: StableIdentifierV1
    revision: int = Field(ge=1)
    contract_hash: DigestV1
    proof_id: StableIdentifierV1
    proof_boundary_hash: DigestV1
    proof_submission_artifact_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    dependency_manifest_hash: DigestV1
    verification_report_id: StableIdentifierV1
    verification_observation_hash: DigestV1
    environment: VerificationArtifactEnvironmentV1
    oci: OciVerificationArtifactV2

    @model_validator(mode="after")
    def validate_hashes(self) -> VerificationEvidenceArtifactV2:
        require_digest_kind(self.bundle_hash, HashKindV1.BUNDLE, "bundle_hash")
        require_digest_kind(self.contract_hash, HashKindV1.CONTRACT, "contract_hash")
        require_digest_kind(
            self.proof_boundary_hash,
            HashKindV1.PROOF_BOUNDARY,
            "proof_boundary_hash",
        )
        require_digest_kind(
            self.dependency_manifest_hash,
            HashKindV1.DEPENDENCY_MANIFEST,
            "dependency_manifest_hash",
        )
        require_digest_kind(
            self.verification_observation_hash,
            HashKindV1.VERIFICATION_REPORT,
            "verification_observation_hash",
        )
        return self


class VerificationEvidenceV1(ContractModel):
    """Verifier-owned evidence required before a report can be accepted.

    This model records what an authority claims it actually executed.  It is not proof that an
    OCI runtime ran; the independent verifier attestation and content-addressed evidence artifact
    are the trust boundary.  Missing fields fail closed at the control plane.
    """

    evidence_id: StableIdentifierV1
    environment_hash: DigestV1
    worker_image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    wrapper_protocol: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    lean_version: str = Field(min_length=1)
    mathlib_revision: str = Field(min_length=1)
    lake_manifest_hash: DigestV1 | None = None
    dependency_manifest_hash: DigestV1
    command_policy_hash: DigestV1
    command_hash: DigestV1
    evidence_artifact_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    captured_at: datetime = Field(default_factory=utc_now)

    def evidence_hash(self) -> DigestV1:
        return digest_model(HashKindV1.VERIFICATION_EVIDENCE, self)

    @model_validator(mode="after")
    def validate_evidence_hashes(self) -> VerificationEvidenceV1:
        require_digest_kind(self.environment_hash, HashKindV1.ENVIRONMENT, "environment_hash")
        if self.lake_manifest_hash is not None:
            require_digest_kind(
                self.lake_manifest_hash,
                HashKindV1.ENVIRONMENT,
                "lake_manifest_hash",
            )
        require_digest_kind(
            self.dependency_manifest_hash,
            HashKindV1.DEPENDENCY_MANIFEST,
            "dependency_manifest_hash",
        )
        require_digest_kind(
            self.command_policy_hash,
            HashKindV1.VERIFICATION_COMMAND,
            "command_policy_hash",
        )
        require_digest_kind(
            self.command_hash,
            HashKindV1.VERIFICATION_COMMAND,
            "command_hash",
        )
        if self.captured_at.tzinfo is None:
            raise ValueError("verification evidence timestamp must be timezone-aware")
        return self


class VerificationReportV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    report_id: StableIdentifierV1
    proof_id: StableIdentifierV1
    contract_hash: DigestV1
    proof_boundary_hash: DigestV1
    verifier_id: str = Field(min_length=1)
    independent: bool
    kernel_passed: bool
    build_passed: bool
    dependency_check_passed: bool
    clean_environment: bool
    environment_hash: DigestV1
    axiom_profile: AxiomProfileV1
    observed_axioms: tuple[str, ...] = ()
    details: str = Field(min_length=1)
    verified_at: datetime = Field(default_factory=utc_now)
    evidence: VerificationEvidenceV1 | None = None
    verifier_attestation: AttestationV1 | None = None

    def report_hash(self) -> DigestV1:
        """Hash verifier observations excluding their attached authority signature."""

        payload = self.model_dump(
            mode="json",
            exclude={"verifier_attestation"},
            exclude_none=False,
        )
        return digest_model(HashKindV1.VERIFICATION_REPORT, payload)

    @model_validator(mode="after")
    def validate_hashes(self) -> VerificationReportV1:
        require_digest_kind(self.contract_hash, HashKindV1.CONTRACT, "contract_hash")
        require_digest_kind(
            self.proof_boundary_hash,
            HashKindV1.PROOF_BOUNDARY,
            "proof_boundary_hash",
        )
        require_digest_kind(self.environment_hash, HashKindV1.ENVIRONMENT, "environment_hash")
        if (
            self.verifier_attestation is not None
            and self.verifier_attestation.purpose is not AttestationPurposeV1.VERIFICATION
        ):
            raise ValueError("verification report attestation must use the verification purpose")
        return self


def verification_attestation_payload(
    *,
    bundle_id: str,
    bundle_hash: str,
    proof_submission_artifact_digest: str,
    contract_id: str,
    revision: int,
    contract_hash: DigestV1,
    proof_boundary_hash: DigestV1,
    environment_hash: DigestV1,
    report: VerificationReportV1,
) -> dict[str, object]:
    """Return the complete payload an independent verifier must attest.

    The caller supplies the content-addressed proof submission digest from the control plane.  It
    is intentionally not derived from a worker-controlled path or workspace.
    """

    if not re.fullmatch(r"[0-9a-f]{64}", proof_submission_artifact_digest):
        raise ValueError("proof_submission_artifact_digest must be a lowercase SHA-256 digest")
    if (
        not bundle_id.strip()
        or not re.fullmatch(r"[0-9a-f]{64}", bundle_hash)
        or not contract_id.strip()
        or revision < 1
    ):
        raise ValueError("verification attestation payload has an invalid task binding")
    require_digest_kind(contract_hash, HashKindV1.CONTRACT, "contract_hash")
    require_digest_kind(proof_boundary_hash, HashKindV1.PROOF_BOUNDARY, "proof_boundary_hash")
    require_digest_kind(environment_hash, HashKindV1.ENVIRONMENT, "environment_hash")
    return {
        "schema_version": "autolean.verification-attestation-payload.v1",
        "bundle_id": bundle_id,
        "bundle_hash": bundle_hash,
        "proof_id": report.proof_id.value,
        "proof_submission_artifact_digest": proof_submission_artifact_digest,
        "contract_id": contract_id,
        "revision": revision,
        "contract_hash": contract_hash.value,
        "proof_boundary_hash": proof_boundary_hash.value,
        "environment_hash": environment_hash.value,
        "verification_report_hash": report.report_hash().value,
        "verifier_id": report.verifier_id,
        "verification_evidence_hash": (
            None if report.evidence is None else report.evidence.evidence_hash().value
        ),
    }


class ReviewDecisionV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    review_id: StableIdentifierV1
    artifact_id: StableIdentifierV1
    artifact_kind: str = Field(min_length=1)
    reviewer_id: str = Field(min_length=1)
    role: ReviewerRoleV1
    decision: DecisionV1
    independent: bool
    rationale: str = Field(min_length=1)
    reviewed_at: datetime = Field(default_factory=utc_now)


class EventEnvelopeV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    event_id: StableIdentifierV1
    stream_id: StableIdentifierV1
    sequence: int = Field(ge=0)
    event_type: str = Field(min_length=1)
    actor_id: str = Field(min_length=1)
    occurred_at: datetime = Field(default_factory=utc_now)
    payload: dict[str, Any] = Field(default_factory=dict)
    previous_event_hash: DigestV1 | None = None
    event_hash: DigestV1

    @model_validator(mode="after")
    def validate_event_hash_kinds(self) -> EventEnvelopeV1:
        if self.previous_event_hash is not None:
            require_digest_kind(
                self.previous_event_hash,
                HashKindV1.EVENT,
                "previous_event_hash",
            )
        require_digest_kind(self.event_hash, HashKindV1.EVENT, "event_hash")
        expected = digest_model(HashKindV1.EVENT, self, exclude={"event_hash"})
        if expected != self.event_hash:
            raise ValueError("event_hash does not match event payload")
        return self


class OpenProblemReleaseDecisionV1(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    releasable: bool
    failures: tuple[str, ...] = ()
    contract_hash: DigestV1
    evaluated_at: datetime = Field(default_factory=utc_now)
