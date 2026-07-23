"""Builder-owned gates for moving a mathematical claim into the Prover boundary.

The module intentionally has no dependency on the Prover or the control plane.  The only
cross-engine value it emits is a frozen contract or its immutable task bundle.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum

from autolean_contracts import (
    AttestationPurposeV1,
    AttestationSignerV1,
    ContractChangeRequestV1,
    DecisionV1,
    FidelityCheckKindV1,
    FidelityEvidenceArtifactRefV1,
    FidelityReportV1,
    FidelityRiskV1,
    FormalizationTaskBundleV1,
    GraphBundleV1,
    HashKindV1,
    MutationKindV1,
    ReleaseTierV1,
    ReviewerRoleV1,
    StatementContractV1,
    StatementStatusV1,
    TaskKindV1,
    build_proof_boundary,
    builder_attestation_payload,
    digest_model,
    stable_identifier,
)
from autolean_contracts.models import FreezeRecordV1

from .fidelity_harness import CandidateFormalization, FidelityEvaluation


class BuilderError(Exception):
    """Base error for Builder-only workflow violations."""


class FreezeRejected(BuilderError):
    """Raised when a draft has not earned a frozen statement boundary."""


class BuilderStage(StrEnum):
    INGESTED = "ingested"
    RIGHTS_REVIEWED = "rights_reviewed"
    NORMALIZED = "normalized"
    MATHLIB_MAPPED = "mathlib_mapped"
    CANDIDATES_REVIEWED = "candidates_reviewed"
    FIDELITY_REVIEWED = "fidelity_reviewed"
    FROZEN = "frozen"
    BRIDGED = "bridged"


_STAGE_SUCCESSOR: dict[BuilderStage, BuilderStage] = {
    BuilderStage.INGESTED: BuilderStage.RIGHTS_REVIEWED,
    BuilderStage.RIGHTS_REVIEWED: BuilderStage.NORMALIZED,
    BuilderStage.NORMALIZED: BuilderStage.MATHLIB_MAPPED,
    BuilderStage.MATHLIB_MAPPED: BuilderStage.CANDIDATES_REVIEWED,
    BuilderStage.CANDIDATES_REVIEWED: BuilderStage.FIDELITY_REVIEWED,
    BuilderStage.FIDELITY_REVIEWED: BuilderStage.FROZEN,
    BuilderStage.FROZEN: BuilderStage.BRIDGED,
}


@dataclass(frozen=True, slots=True)
class BuilderCase:
    """An immutable local projection of the Builder's fixed workflow.

    The control plane can persist its transitions as events, but this object makes it impossible
    for a caller to jump directly from ingestion to the Prover boundary.
    """

    contract: StatementContractV1
    stage: BuilderStage = BuilderStage.INGESTED
    candidates: tuple[CandidateFormalization, ...] = ()
    fidelity: FidelityReportV1 | None = None

    def __post_init__(self) -> None:
        if self.stage in {BuilderStage.FROZEN, BuilderStage.BRIDGED}:
            if self.contract.status is not StatementStatusV1.FROZEN:
                raise BuilderError("a frozen Builder stage requires a frozen statement contract")
        elif self.contract.status is not StatementStatusV1.DRAFT:
            raise BuilderError("pre-freeze Builder stages require a draft statement contract")

    def advance(self, next_stage: BuilderStage) -> BuilderCase:
        expected = _STAGE_SUCCESSOR.get(self.stage)
        if expected is not next_stage:
            raise BuilderError(f"invalid Builder transition {self.stage} -> {next_stage}")
        return replace(self, stage=next_stage)

    def with_candidates(self, candidates: tuple[CandidateFormalization, ...]) -> BuilderCase:
        if self.stage is not BuilderStage.MATHLIB_MAPPED:
            raise BuilderError("candidates can only be attached after mathlib mapping")
        return replace(self, candidates=candidates).advance(BuilderStage.CANDIDATES_REVIEWED)

    def with_fidelity(self, report: FidelityReportV1) -> BuilderCase:
        if self.stage is not BuilderStage.CANDIDATES_REVIEWED:
            raise BuilderError("fidelity evidence can only follow candidate review")
        return replace(self, fidelity=report).advance(BuilderStage.FIDELITY_REVIEWED)

    def with_evaluation(self, evaluation: FidelityEvaluation) -> BuilderCase:
        """Attach a complete Harness evaluation without exposing a partial freeze path."""

        if self.stage is not BuilderStage.MATHLIB_MAPPED:
            raise BuilderError("fidelity evaluation can only follow mathlib mapping")
        evaluation.assert_binds(self.contract)
        reviewed_candidates = replace(self, candidates=evaluation.candidates).advance(
            BuilderStage.CANDIDATES_REVIEWED
        )
        return replace(reviewed_candidates, fidelity=evaluation.report).advance(
            BuilderStage.FIDELITY_REVIEWED
        )


class FreezeGate:
    """Conservative semantic admission policy for V1 contracts."""

    _BASE_CHECKS = frozenset(
        {
            FidelityCheckKindV1.SOURCE_PRESERVATION,
            FidelityCheckKindV1.REVERSE_RENDER,
            FidelityCheckKindV1.INDEPENDENT_TRANSLATION,
            FidelityCheckKindV1.POSITIVE_EXAMPLE,
            FidelityCheckKindV1.NEGATIVE_EXAMPLE,
            FidelityCheckKindV1.NON_VACUITY,
        }
    )
    _BASE_MUTATIONS = frozenset(
        {
            MutationKindV1.DROP_ASSUMPTION,
            MutationKindV1.SWAP_QUANTIFIERS,
            MutationKindV1.WEAKEN_RELATION,
            MutationKindV1.REMOVE_SIDE_CONDITION,
            MutationKindV1.DROP_NONEMPTY,
            MutationKindV1.DROP_FINITE,
            MutationKindV1.DROP_NOETHERIAN,
            MutationKindV1.REVERSE_PARAMETERS,
            MutationKindV1.VACUITY,
        }
    )

    def validate(
        self,
        contract: StatementContractV1,
        *,
        candidates: tuple[CandidateFormalization, ...],
        fidelity: FidelityReportV1,
    ) -> None:
        failures: list[str] = []
        if contract.status is not StatementStatusV1.DRAFT:
            failures.append("only a draft contract may be frozen")
        if not contract.source.spans:
            failures.append("a frozen contract requires at least one cited source span")
        if not contract.alignments:
            failures.append("a frozen contract requires source-to-formal alignments")
        if contract.rights.overall_decision.value in {"unknown", "deny"}:
            failures.append("source rights must be reviewed before freezing")
        if not contract.rights.reviewed_by or contract.rights.reviewed_at is None:
            failures.append("source rights require a reviewer and review timestamp")
        blocking = [
            ambiguity
            for ambiguity in contract.mathematics.ambiguities
            if ambiguity.severity.value == "blocking"
            and (ambiguity.resolution is None or ambiguity.resolved_by is None)
        ]
        if blocking:
            failures.append("all blocking mathematical ambiguities must be resolved")
        if contract.formal.elaborated_type is None:
            failures.append("the Lean declaration must be elaborated before freezing")
        if fidelity.risk_level is not contract.policy.fidelity_risk:
            failures.append("fidelity risk level must match task policy")
        failures.extend(self._candidate_failures(contract, candidates))
        failures.extend(self._fidelity_failures(contract, fidelity))
        if failures:
            raise FreezeRejected("; ".join(failures))

    def _candidate_failures(
        self,
        contract: StatementContractV1,
        candidates: tuple[CandidateFormalization, ...],
    ) -> list[str]:
        failures: list[str] = []
        if len({item.candidate_id for item in candidates}) != len(candidates):
            failures.append("candidate identifiers must be unique")
        groups = {item.independence_group for item in candidates}
        if len(groups) < 2:
            failures.append("two independent formalization candidates are required")
        if len({item.actor_id for item in candidates}) < 2:
            failures.append("independent formalization candidates require distinct actors")
        expected = contract.formal.statement_source_hash
        matching_groups = {
            item.independence_group for item in candidates if item.statement_hash == expected
        }
        if len(matching_groups) < 2:
            failures.append(
                "two independent candidate groups must match the selected Lean statement"
            )
        return failures

    def _fidelity_failures(
        self,
        contract: StatementContractV1,
        fidelity: FidelityReportV1,
    ) -> list[str]:
        failures: list[str] = []
        passed_checks = {item.kind for item in fidelity.checks if item.passed}
        missing_checks = self._BASE_CHECKS - passed_checks
        if missing_checks:
            names = ", ".join(sorted(item.value for item in missing_checks))
            failures.append(f"missing successful fidelity checks: {names}")
        independent_translation = [
            item
            for item in fidelity.checks
            if item.kind is FidelityCheckKindV1.INDEPENDENT_TRANSLATION
            and item.passed
            and item.independent
        ]
        if not independent_translation:
            failures.append("independent translation evidence requires an independent reviewer")
        mutation_results = {item.probe.kind: item for item in fidelity.mutation_results}
        for kind in self._BASE_MUTATIONS:
            result = mutation_results.get(kind)
            if result is None or not result.detected:
                failures.append(f"mutation probe was not detected: {kind.value}")
            elif result.probe.mutated_statement_source == contract.formal.lean_statement_source:
                failures.append(f"mutation probe did not change the statement: {kind.value}")
        accepting = [item for item in fidelity.signoffs if item.decision is DecisionV1.ACCEPT]
        independent_roles = {item.role for item in accepting if item.independent}
        if ReviewerRoleV1.SEMANTIC_REVIEWER not in independent_roles:
            failures.append("an independent semantic reviewer must accept the statement")
        if (
            contract.policy.fidelity_risk
            in {FidelityRiskV1.L2_REUSABLE_API, FidelityRiskV1.L3_RESEARCH}
            and ReviewerRoleV1.LIBRARY_REVIEWER not in independent_roles
        ):
            failures.append("reusable APIs require an independent library review")
        if contract.policy.fidelity_risk is FidelityRiskV1.L3_RESEARCH:
            domain_reviews = {
                item.reviewer_id
                for item in accepting
                if item.independent and item.role is ReviewerRoleV1.DOMAIN_EXPERT
            }
            required = contract.policy.open_problem.required_domain_expert_reviews
            if len(domain_reviews) < required:
                failures.append("research-level statements require independent domain signoff")
        if contract.task_kind is TaskKindV1.OPEN_CONJECTURE:
            verifier_reviews = {
                item.reviewer_id
                for item in accepting
                if item.independent and item.role is ReviewerRoleV1.INDEPENDENT_VERIFIER
            }
            required = contract.policy.open_problem.required_independent_verifiers
            if len(verifier_reviews) < required:
                failures.append("open conjectures require independent verifier signoff")
            if contract.policy.release_tier is not ReleaseTierV1.CONJECTURE_QUARANTINE:
                failures.append("open conjectures must remain quarantined")
        return failures


def freeze_contract(
    contract: StatementContractV1,
    *,
    evaluation: FidelityEvaluation,
    frozen_by: str,
    gate: FreezeGate | None = None,
) -> StatementContractV1:
    """Freeze a Harness-reviewed draft without changing its stable ID or revision."""

    if not frozen_by.strip():
        raise BuilderError("frozen_by must not be empty")
    try:
        evaluation.assert_binds(contract)
    except ValueError as error:
        raise FreezeRejected(str(error)) from error
    active_gate = gate or FreezeGate()
    active_gate.validate(
        contract,
        candidates=evaluation.candidates,
        fidelity=evaluation.report,
    )
    reviewed_payload = contract.model_dump(mode="python", round_trip=True)
    reviewed_payload["fidelity"] = evaluation.report
    reviewed = StatementContractV1.model_validate(reviewed_payload)
    record = FreezeRecordV1(
        contract_hash=reviewed.semantic_hash(),
        source_hash=reviewed.source.content_hash,
        statement_source_hash=reviewed.formal.statement_source_hash,
        elaborated_type_hash=reviewed.formal.elaborated_type_hash,
        frozen_by=frozen_by,
    )
    frozen_payload = reviewed.model_dump(mode="python", round_trip=True)
    frozen_payload.update({"status": StatementStatusV1.FROZEN, "freeze": record})
    return StatementContractV1.model_validate(frozen_payload)


def bridge_frozen_contract(
    contract: StatementContractV1,
    graphs: GraphBundleV1,
    *,
    bundle_key: str,
    fidelity_evidence: FidelityEvidenceArtifactRefV1,
    attestor: AttestationSignerV1,
    evidence_identity: str,
    attestation_ttl_seconds: float = 3600,
) -> FormalizationTaskBundleV1:
    """Create the sole immutable Builder-to-Prover handoff with Builder authority.

    The attestor is an operator-owned runtime capability.  It is not part of the returned
    contract or artifact: only the resulting public attestation metadata crosses this boundary.
    """

    if contract.status is not StatementStatusV1.FROZEN:
        raise BuilderError("only a frozen contract may cross the Builder-Prover boundary")
    if not bundle_key.strip():
        raise BuilderError("bundle_key must not be empty")
    if not evidence_identity.strip():
        raise BuilderError("evidence_identity must not be empty")
    if contract.fidelity is None:
        raise BuilderError("only a fidelity-reviewed contract may cross the bridge")
    if fidelity_evidence.digest != contract.fidelity.evidence_hash:
        raise BuilderError("fidelity artifact does not bind the frozen fidelity report")
    unsigned = FormalizationTaskBundleV1(
        bundle_id=stable_identifier("bundle", bundle_key),
        contract=contract,
        graphs=graphs,
        graph_snapshot_hash=digest_model(HashKindV1.GRAPH_SNAPSHOT, graphs),
        proof_boundary=build_proof_boundary(contract),
        fidelity_evidence=fidelity_evidence,
    )
    try:
        attestation = attestor.issue(
            purpose=AttestationPurposeV1.BUILDER_FREEZE,
            payload=builder_attestation_payload(unsigned),
            evidence_identity=evidence_identity,
            ttl_seconds=attestation_ttl_seconds,
        )
    except ValueError as error:
        raise BuilderError("Builder attestation could not be issued") from error
    return unsigned.model_copy(update={"builder_attestation": attestation})


def create_next_revision(
    previous: StatementContractV1,
    replacement: StatementContractV1,
    *,
    request: ContractChangeRequestV1 | None = None,
) -> StatementContractV1:
    """Validate revision lineage while preserving old frozen artifacts forever."""

    if replacement.contract_id != previous.contract_id:
        raise BuilderError("a new contract revision must retain the stable contract ID")
    if replacement.revision != previous.revision + 1:
        raise BuilderError("contract revisions must increase by exactly one")
    if replacement.status is not StatementStatusV1.DRAFT or replacement.freeze is not None:
        raise BuilderError("a replacement revision must begin as an unfrozen draft")
    if request is not None:
        if request.contract_id != previous.contract_id or request.old_revision != previous.revision:
            raise BuilderError("contract change request does not target the previous revision")
        if request.old_contract_hash != previous.semantic_hash():
            raise BuilderError("contract change request does not bind the previous revision")
    return replacement
