"""Auditable harness for Builder-owned statement translation.

The harness deliberately does not decide mathematical equivalence.  It makes all mechanically
checkable bindings explicit, then records the semantic judgements returned by an independent
review authority.  A failed semantic judgement remains evidence and is rejected later by the
Builder freeze gate.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from autolean_contracts import (
    DecisionV1,
    DigestV1,
    FidelityCheckKindV1,
    FidelityCheckV1,
    FidelityReportV1,
    HashKindV1,
    MutationKindV1,
    MutationProbeV1,
    MutationResultV1,
    ReviewerRoleV1,
    ReviewerSignoffV1,
    StableIdentifierV1,
    StatementContractV1,
    canonical_json_bytes,
    digest_bytes,
    digest_text,
    stable_identifier,
)


class FidelityHarnessError(ValueError):
    """The translation evidence is structurally invalid or bound to another contract."""


_REQUIRED_MUTATIONS = frozenset(
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


class EvidenceAuthority(StrEnum):
    AUTOMATIC = "automatic"
    EXPERT = "expert"


class SemanticObligationKind(StrEnum):
    QUANTIFIER_ORDER = "quantifier_order"
    ASSUMPTION = "assumption"
    CONCLUSION = "conclusion"
    SIDE_CONDITION = "side_condition"
    DEFINITION = "definition"
    EDGE_CASE = "edge_case"
    NON_VACUITY = "non_vacuity"


@dataclass(frozen=True, slots=True)
class SourceClaimSpan:
    span_id: StableIdentifierV1
    locator: str
    content_hash: DigestV1
    permitted_excerpt: str

    def __post_init__(self) -> None:
        if not self.locator.strip() or not self.permitted_excerpt.strip():
            raise FidelityHarnessError(
                "statement translation requires a located, permitted source excerpt"
            )
        if self.content_hash != digest_text(
            HashKindV1.SOURCE_SPAN,
            self.permitted_excerpt,
        ):
            raise FidelityHarnessError(
                "statement translation excerpt differs from its public span hash"
            )

    def payload(self) -> dict[str, object]:
        return {
            "span_id": self.span_id.value,
            "locator": self.locator,
            "content_hash": self.content_hash.model_dump(mode="json"),
            "permitted_excerpt": self.permitted_excerpt,
        }


def _assert_source_claims_bind_contract(
    contract: StatementContractV1,
    claims: tuple[SourceClaimSpan, ...],
) -> None:
    contract_spans = {span.span_id: span for span in contract.source.spans}
    claim_spans = {span.span_id: span for span in claims}
    if (
        len(claim_spans) != len(claims)
        or not claim_spans
        or set(claim_spans) != set(contract_spans)
    ):
        raise FidelityHarnessError("private source claims differ from the public contract span set")
    for span_id, claim in claim_spans.items():
        public_span = contract_spans[span_id]
        if (
            claim.locator != public_span.locator
            or claim.content_hash != public_span.content_hash
            or (
                public_span.permitted_excerpt is not None
                and claim.permitted_excerpt != public_span.permitted_excerpt
            )
        ):
            raise FidelityHarnessError(
                "private source claim differs from its public contract span binding"
            )


@dataclass(frozen=True, slots=True)
class SemanticObligation:
    """One reviewer-visible trace from source meaning to normalized and Lean fragments."""

    obligation_id: str
    kind: SemanticObligationKind
    description: str
    source_span_ids: tuple[StableIdentifierV1, ...]
    normalized_fragment: str
    lean_fragment: str
    authority: EvidenceAuthority = EvidenceAuthority.EXPERT

    def __post_init__(self) -> None:
        if not self.obligation_id.strip():
            raise FidelityHarnessError("semantic obligation identifiers must not be empty")
        if not self.description.strip():
            raise FidelityHarnessError("semantic obligation descriptions must not be empty")
        if not self.source_span_ids:
            raise FidelityHarnessError("semantic obligations must cite at least one source span")
        if not self.normalized_fragment.strip() or not self.lean_fragment.strip():
            raise FidelityHarnessError(
                "semantic obligations require normalized and Lean target fragments"
            )
        if self.authority is not EvidenceAuthority.EXPERT:
            raise FidelityHarnessError("semantic obligations always require expert judgement")

    def payload(self) -> dict[str, object]:
        return {
            "obligation_id": self.obligation_id,
            "kind": self.kind.value,
            "description": self.description,
            "source_span_ids": [item.value for item in self.source_span_ids],
            "normalized_fragment": self.normalized_fragment,
            "lean_fragment": self.lean_fragment,
            "authority": self.authority.value,
        }


@dataclass(frozen=True, slots=True)
class TranslationTask:
    contract_id: StableIdentifierV1
    revision: int
    draft_contract_hash: DigestV1
    source_hash: DigestV1
    source_spans: tuple[SourceClaimSpan, ...]
    informal_statement: str
    normalized_statement: str
    normalized_statement_sha256: str
    selected_lean_statement: str
    selected_statement_hash: DigestV1
    obligations: tuple[SemanticObligation, ...]

    @classmethod
    def from_contract(
        cls,
        contract: StatementContractV1,
        obligations: tuple[SemanticObligation, ...],
        *,
        source_claims: tuple[SourceClaimSpan, ...] | None = None,
    ) -> TranslationTask:
        if source_claims is None:
            spans = tuple(
                SourceClaimSpan(
                    span_id=span.span_id,
                    locator=span.locator,
                    content_hash=span.content_hash,
                    permitted_excerpt=span.permitted_excerpt or "",
                )
                for span in contract.source.spans
            )
        else:
            spans = source_claims
        _assert_source_claims_bind_contract(contract, spans)
        task = cls(
            contract_id=contract.contract_id,
            revision=contract.revision,
            draft_contract_hash=contract.semantic_hash(),
            source_hash=contract.source.content_hash,
            source_spans=spans,
            informal_statement=contract.mathematics.informal_statement,
            normalized_statement=contract.mathematics.normalized_statement,
            normalized_statement_sha256=_text_sha256(contract.mathematics.normalized_statement),
            selected_lean_statement=contract.formal.lean_statement_source,
            selected_statement_hash=contract.formal.statement_source_hash,
            obligations=obligations,
        )
        task.validate_obligations(contract)
        return task

    def validate_obligations(self, contract: StatementContractV1) -> None:
        if not self.obligations:
            raise FidelityHarnessError("at least one semantic obligation is required")
        identifiers = [item.obligation_id for item in self.obligations]
        if len(set(identifiers)) != len(identifiers):
            raise FidelityHarnessError("semantic obligation identifiers must be unique")
        known_spans = {item.span_id for item in self.source_spans}
        for obligation in self.obligations:
            if not set(obligation.source_span_ids) <= known_spans:
                raise FidelityHarnessError("semantic obligation cites an unknown source span")
            if obligation.normalized_fragment not in self.normalized_statement:
                raise FidelityHarnessError(
                    f"normalized obligation fragment is absent: {obligation.obligation_id}"
                )
            if obligation.lean_fragment not in self.selected_lean_statement:
                raise FidelityHarnessError(
                    f"Lean obligation fragment is absent: {obligation.obligation_id}"
                )
        kinds = {item.kind for item in self.obligations}
        required = {
            SemanticObligationKind.QUANTIFIER_ORDER,
            SemanticObligationKind.CONCLUSION,
            SemanticObligationKind.NON_VACUITY,
        }
        if contract.mathematics.assumptions:
            required.add(SemanticObligationKind.ASSUMPTION)
        if contract.mathematics.definitions:
            required.add(SemanticObligationKind.DEFINITION)
        if contract.mathematics.edge_cases:
            required.add(SemanticObligationKind.EDGE_CASE)
        missing = required - kinds
        if missing:
            names = ", ".join(sorted(item.value for item in missing))
            raise FidelityHarnessError(f"missing semantic obligation kinds: {names}")

    def payload(self) -> dict[str, object]:
        return {
            "contract_id": self.contract_id.value,
            "revision": self.revision,
            "draft_contract_hash": self.draft_contract_hash.model_dump(mode="json"),
            "source_hash": self.source_hash.model_dump(mode="json"),
            "source_spans": [item.payload() for item in self.source_spans],
            "informal_statement": self.informal_statement,
            "normalized_statement": self.normalized_statement,
            "normalized_statement_sha256": self.normalized_statement_sha256,
            "selected_lean_statement": self.selected_lean_statement,
            "selected_statement_hash": self.selected_statement_hash.model_dump(mode="json"),
            "obligations": [item.payload() for item in self.obligations],
        }


@dataclass(frozen=True, slots=True)
class CandidateFormalization:
    """One independently generated, contract-bound translation candidate."""

    candidate_id: str
    actor_id: str
    independence_group: str
    contract_id: StableIdentifierV1
    revision: int
    draft_contract_hash: DigestV1
    source_hash: DigestV1
    normalized_statement_sha256: str
    lean_statement_source: str
    reverse_rendering: str
    covered_obligation_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        for label, value in (
            ("candidate_id", self.candidate_id),
            ("actor_id", self.actor_id),
            ("independence_group", self.independence_group),
            ("lean_statement_source", self.lean_statement_source),
            ("reverse_rendering", self.reverse_rendering),
        ):
            if not value.strip():
                raise FidelityHarnessError(f"{label} must not be empty")
        if self.revision < 1:
            raise FidelityHarnessError("candidate contract revision must be positive")
        if len(self.normalized_statement_sha256) != 64:
            raise FidelityHarnessError("candidate normalized statement hash is invalid")
        if not self.covered_obligation_ids:
            raise FidelityHarnessError("candidate must declare semantic obligation coverage")

    @property
    def statement_hash(self) -> DigestV1:
        return digest_text(HashKindV1.STATEMENT_SOURCE, self.lean_statement_source)

    @property
    def evidence_hash(self) -> DigestV1:
        return digest_bytes(
            HashKindV1.FREEZE_EVIDENCE,
            canonical_json_bytes(self.payload()),
        )

    def payload(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "actor_id": self.actor_id,
            "independence_group": self.independence_group,
            "contract_id": self.contract_id.value,
            "revision": self.revision,
            "draft_contract_hash": self.draft_contract_hash.model_dump(mode="json"),
            "source_hash": self.source_hash.model_dump(mode="json"),
            "normalized_statement_sha256": self.normalized_statement_sha256,
            "lean_statement_source": self.lean_statement_source,
            "reverse_rendering": self.reverse_rendering,
            "covered_obligation_ids": list(self.covered_obligation_ids),
        }


class TranslationAgent(Protocol):
    actor_id: str
    independence_group: str

    def translate(self, task: TranslationTask) -> CandidateFormalization:
        """Return a candidate bound to the supplied task."""


class MutationSuiteAgent(Protocol):
    actor_id: str

    def generate(
        self,
        task: TranslationTask,
        selected_candidate: CandidateFormalization,
    ) -> tuple[MutationProbeV1, ...]:
        """Return the complete adversarial mutation suite."""


@dataclass(frozen=True, slots=True)
class ObligationReviewVerdict:
    obligation_id: str
    decision: DecisionV1
    rationale: str

    def __post_init__(self) -> None:
        if not self.obligation_id.strip() or not self.rationale.strip():
            raise FidelityHarnessError("obligation verdicts require an id and rationale")

    def payload(self) -> dict[str, str]:
        return {
            "obligation_id": self.obligation_id,
            "decision": self.decision.value,
            "rationale": self.rationale,
        }


@dataclass(frozen=True, slots=True)
class CandidateReviewVerdict:
    candidate_id: str
    candidate_hash: DigestV1
    decision: DecisionV1
    reverse_render_equivalent: bool
    obligation_verdicts: tuple[ObligationReviewVerdict, ...]
    rationale: str

    def __post_init__(self) -> None:
        if not self.candidate_id.strip() or not self.rationale.strip():
            raise FidelityHarnessError("candidate verdicts require an id and rationale")

    def payload(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "candidate_hash": self.candidate_hash.model_dump(mode="json"),
            "decision": self.decision.value,
            "reverse_render_equivalent": self.reverse_render_equivalent,
            "obligation_verdicts": [item.payload() for item in self.obligation_verdicts],
            "rationale": self.rationale,
        }


@dataclass(frozen=True, slots=True)
class MutationReviewVerdict:
    probe_id: StableIdentifierV1
    detected: bool
    rationale: str

    def __post_init__(self) -> None:
        if not self.rationale.strip():
            raise FidelityHarnessError("mutation verdict rationale must not be empty")

    def payload(self) -> dict[str, object]:
        return {
            "probe_id": self.probe_id.value,
            "detected": self.detected,
            "rationale": self.rationale,
        }


@dataclass(frozen=True, slots=True)
class SemanticReviewVerdict:
    review_id: str
    reviewer_id: str
    independent: bool
    decision: DecisionV1
    source_to_normalized_equivalent: bool
    source_to_normalized_evidence: str
    candidate_verdicts: tuple[CandidateReviewVerdict, ...]
    mutation_verdicts: tuple[MutationReviewVerdict, ...]
    positive_example_valid: bool
    positive_example_evidence: str
    negative_example_valid: bool
    negative_example_evidence: str
    non_vacuous: bool
    non_vacuity_evidence: str
    rationale: str

    def __post_init__(self) -> None:
        for label, value in (
            ("review_id", self.review_id),
            ("reviewer_id", self.reviewer_id),
            ("source_to_normalized_evidence", self.source_to_normalized_evidence),
            ("positive_example_evidence", self.positive_example_evidence),
            ("negative_example_evidence", self.negative_example_evidence),
            ("non_vacuity_evidence", self.non_vacuity_evidence),
            ("rationale", self.rationale),
        ):
            if not value.strip():
                raise FidelityHarnessError(f"{label} must not be empty")

    def payload(self) -> dict[str, object]:
        return {
            "review_id": self.review_id,
            "reviewer_id": self.reviewer_id,
            "independent": self.independent,
            "decision": self.decision.value,
            "source_to_normalized_equivalent": self.source_to_normalized_equivalent,
            "source_to_normalized_evidence": self.source_to_normalized_evidence,
            "candidate_verdicts": [item.payload() for item in self.candidate_verdicts],
            "mutation_verdicts": [item.payload() for item in self.mutation_verdicts],
            "positive_example_valid": self.positive_example_valid,
            "positive_example_evidence": self.positive_example_evidence,
            "negative_example_valid": self.negative_example_valid,
            "negative_example_evidence": self.negative_example_evidence,
            "non_vacuous": self.non_vacuous,
            "non_vacuity_evidence": self.non_vacuity_evidence,
            "rationale": self.rationale,
        }


@dataclass(frozen=True, slots=True)
class SemanticReviewPacket:
    task: TranslationTask
    candidates: tuple[CandidateFormalization, ...]
    mutation_probes: tuple[MutationProbeV1, ...]


class SemanticReviewAgent(Protocol):
    reviewer_id: str

    def review(self, packet: SemanticReviewPacket) -> SemanticReviewVerdict:
        """Return explicit expert judgements; the harness does not infer them."""


@dataclass(frozen=True, slots=True)
class AutomaticCheckResult:
    check_name: str
    authority: EvidenceAuthority
    passed: bool
    evidence: str

    def payload(self) -> dict[str, object]:
        return {
            "check_name": self.check_name,
            "authority": self.authority.value,
            "passed": self.passed,
            "evidence": self.evidence,
        }


@dataclass(frozen=True, slots=True)
class FidelityEvaluation:
    task: TranslationTask
    candidates: tuple[CandidateFormalization, ...]
    mutation_agent_id: str
    mutation_probes: tuple[MutationProbeV1, ...]
    review: SemanticReviewVerdict
    automatic_checks: tuple[AutomaticCheckResult, ...]
    additional_signoffs: tuple[ReviewerSignoffV1, ...]
    evidence_hash: DigestV1
    report: FidelityReportV1

    def artifact_payload(self) -> dict[str, object]:
        """Return the canonical evidence artifact whose digest is frozen into the report."""

        return _evaluation_payload(
            self.task,
            self.candidates,
            self.mutation_agent_id,
            self.mutation_probes,
            self.review,
            self.automatic_checks,
            self.additional_signoffs,
        )

    def render_artifact(self) -> bytes:
        return canonical_json_bytes(self.artifact_payload())

    def assert_binds(self, contract: StatementContractV1) -> None:
        if self.task.contract_id != contract.contract_id or self.task.revision != contract.revision:
            raise FidelityHarnessError("fidelity evaluation targets another contract revision")
        if self.task.draft_contract_hash != contract.semantic_hash():
            raise FidelityHarnessError("draft contract changed after fidelity evaluation")
        expected_task = TranslationTask.from_contract(
            contract,
            self.task.obligations,
            source_claims=self.task.source_spans,
        )
        if self.task != expected_task:
            raise FidelityHarnessError(
                "translation task does not reproduce from the draft contract"
            )
        expected_automatic = (
            *_candidate_structure_checks(self.task, self.candidates),
            *_mutation_structure_checks(
                self.task,
                self.mutation_agent_id,
                self.mutation_probes,
            ),
        )
        if self.automatic_checks != expected_automatic:
            raise FidelityHarnessError("automatic check results do not match the evidence")
        _assert_review_structure(
            SemanticReviewPacket(
                task=self.task,
                candidates=self.candidates,
                mutation_probes=self.mutation_probes,
            ),
            self.review,
        )
        _assert_declared_actor_separation(
            self.candidates,
            self.mutation_agent_id,
            self.review,
            self.additional_signoffs,
        )
        expected = _evaluation_hash(
            self.task,
            self.candidates,
            self.mutation_agent_id,
            self.mutation_probes,
            self.review,
            self.automatic_checks,
            self.additional_signoffs,
        )
        if self.evidence_hash != expected:
            raise FidelityHarnessError("fidelity evaluation evidence hash is inconsistent")
        expected_report_id = stable_identifier("builder-fidelity-report", expected.value)
        if self.report.report_id != expected_report_id:
            raise FidelityHarnessError("fidelity report is not bound to harness evidence")
        if self.report.risk_level is not contract.policy.fidelity_risk:
            raise FidelityHarnessError("fidelity report risk differs from the contract policy")
        marker = f"harness_evidence_sha256={expected.value}"
        check_by_kind = {item.kind: item for item in self.report.checks}
        expected_kinds = {
            FidelityCheckKindV1.SOURCE_PRESERVATION,
            FidelityCheckKindV1.REVERSE_RENDER,
            FidelityCheckKindV1.INDEPENDENT_TRANSLATION,
            FidelityCheckKindV1.POSITIVE_EXAMPLE,
            FidelityCheckKindV1.NEGATIVE_EXAMPLE,
            FidelityCheckKindV1.NON_VACUITY,
        }
        if len(check_by_kind) != len(self.report.checks) or set(check_by_kind) != expected_kinds:
            raise FidelityHarnessError("fidelity report check set differs from the harness")
        candidates_accepted = all(
            item.decision is DecisionV1.ACCEPT for item in self.review.candidate_verdicts
        )
        obligations_accepted = all(
            obligation.decision is DecisionV1.ACCEPT
            for candidate in self.review.candidate_verdicts
            for obligation in candidate.obligation_verdicts
        )
        expected_checks = {
            FidelityCheckKindV1.SOURCE_PRESERVATION: (
                self.review.source_to_normalized_equivalent and obligations_accepted,
                self.review.source_to_normalized_evidence,
            ),
            FidelityCheckKindV1.REVERSE_RENDER: (
                all(item.reverse_render_equivalent for item in self.review.candidate_verdicts)
                and candidates_accepted,
                "expert reviewed every reverse rendering",
            ),
            FidelityCheckKindV1.INDEPENDENT_TRANSLATION: (
                candidates_accepted and len(self.candidates) >= 2,
                "expert compared independently generated candidates",
            ),
            FidelityCheckKindV1.POSITIVE_EXAMPLE: (
                self.review.positive_example_valid,
                self.review.positive_example_evidence,
            ),
            FidelityCheckKindV1.NEGATIVE_EXAMPLE: (
                self.review.negative_example_valid,
                self.review.negative_example_evidence,
            ),
            FidelityCheckKindV1.NON_VACUITY: (
                self.review.non_vacuous,
                self.review.non_vacuity_evidence,
            ),
        }
        for kind, (passed, evidence) in expected_checks.items():
            check = check_by_kind[kind]
            expected_check_id = stable_identifier(
                "builder-fidelity-check", f"{expected.value}:{_check_key(kind)}"
            )
            if (
                check.check_id != expected_check_id
                or check.passed is not passed
                or check.evidence != f"{marker}; {evidence}"
                or check.reviewer_id != self.review.reviewer_id
                or check.independent is not self.review.independent
            ):
                raise FidelityHarnessError(
                    f"fidelity report check differs from expert evidence: {kind.value}"
                )
        report_probes = tuple(item.probe for item in self.report.mutation_results)
        if report_probes != self.mutation_probes:
            raise FidelityHarnessError("fidelity report mutation probes differ from the harness")
        review_mutations = {item.probe_id: item for item in self.review.mutation_verdicts}
        for result in self.report.mutation_results:
            verdict = review_mutations[result.probe.probe_id]
            if (
                result.detected is not verdict.detected
                or result.evidence != f"{marker}; {verdict.rationale}"
                or result.executed_by != self.review.reviewer_id
            ):
                raise FidelityHarnessError("mutation results do not match the expert verdict")
        if len(self.report.signoffs) != 1 + len(self.additional_signoffs):
            raise FidelityHarnessError("fidelity report signoff set differs from the harness")
        semantic_signoff = self.report.signoffs[0]
        expected_signoff_id = stable_identifier(
            "builder-semantic-signoff", f"{expected.value}:{self.review.review_id}"
        )
        if (
            semantic_signoff.signoff_id != expected_signoff_id
            or semantic_signoff.reviewer_id != self.review.reviewer_id
            or semantic_signoff.role is not ReviewerRoleV1.SEMANTIC_REVIEWER
            or semantic_signoff.decision is not self.review.decision
            or semantic_signoff.independent is not self.review.independent
            or semantic_signoff.rationale != f"{marker}; {self.review.rationale}"
            or self.report.signoffs[1:] != self.additional_signoffs
        ):
            raise FidelityHarnessError("fidelity report signoffs differ from expert evidence")


class StatementFidelityHarness:
    """Run independent translation, mutation, semantic review, and evidence assembly."""

    def run(
        self,
        contract: StatementContractV1,
        *,
        obligations: tuple[SemanticObligation, ...],
        source_claims: tuple[SourceClaimSpan, ...] | None = None,
        translators: tuple[TranslationAgent, ...],
        mutation_agent: MutationSuiteAgent,
        reviewer: SemanticReviewAgent,
        additional_signoffs: tuple[ReviewerSignoffV1, ...] = (),
    ) -> FidelityEvaluation:
        task = TranslationTask.from_contract(
            contract,
            obligations,
            source_claims=source_claims,
        )
        candidates = tuple(agent.translate(task) for agent in translators)
        automatic_checks = self._validate_candidates(task, translators, candidates)
        probes = mutation_agent.generate(task, candidates[0])
        automatic_checks += self._validate_mutations(task, mutation_agent, probes)
        packet = SemanticReviewPacket(
            task=task,
            candidates=candidates,
            mutation_probes=probes,
        )
        review = reviewer.review(packet)
        self._validate_review_structure(packet, reviewer, review)
        _assert_declared_actor_separation(
            candidates,
            mutation_agent.actor_id,
            review,
            additional_signoffs,
        )
        evidence_hash = _evaluation_hash(
            task,
            candidates,
            mutation_agent.actor_id,
            probes,
            review,
            automatic_checks,
            additional_signoffs,
        )
        report = self._build_report(
            contract,
            candidates=candidates,
            probes=probes,
            review=review,
            evidence_hash=evidence_hash,
            additional_signoffs=additional_signoffs,
        )
        evaluation = FidelityEvaluation(
            task=task,
            candidates=candidates,
            mutation_agent_id=mutation_agent.actor_id,
            mutation_probes=probes,
            review=review,
            automatic_checks=automatic_checks,
            additional_signoffs=additional_signoffs,
            evidence_hash=evidence_hash,
            report=report,
        )
        evaluation.assert_binds(contract)
        return evaluation

    def _validate_candidates(
        self,
        task: TranslationTask,
        translators: tuple[TranslationAgent, ...],
        candidates: tuple[CandidateFormalization, ...],
    ) -> tuple[AutomaticCheckResult, ...]:
        if len(translators) < 2 or len(candidates) != len(translators):
            raise FidelityHarnessError("at least two translation agents are required")
        if len({item.actor_id for item in translators}) != len(translators):
            raise FidelityHarnessError("translation agents must have distinct actor identities")
        if len({item.independence_group for item in translators}) < 2:
            raise FidelityHarnessError("translation agents require two independence groups")
        for agent, candidate in zip(translators, candidates, strict=True):
            if (
                candidate.actor_id != agent.actor_id
                or candidate.independence_group != agent.independence_group
            ):
                raise FidelityHarnessError("candidate misrepresents its generating agent")
        return _candidate_structure_checks(task, candidates)

    def _validate_mutations(
        self,
        task: TranslationTask,
        mutation_agent: MutationSuiteAgent,
        probes: tuple[MutationProbeV1, ...],
    ) -> tuple[AutomaticCheckResult, ...]:
        return _mutation_structure_checks(task, mutation_agent.actor_id, probes)

    def _validate_review_structure(
        self,
        packet: SemanticReviewPacket,
        reviewer: SemanticReviewAgent,
        review: SemanticReviewVerdict,
    ) -> None:
        if review.reviewer_id != reviewer.reviewer_id:
            raise FidelityHarnessError("semantic verdict misrepresents its reviewer")
        if not review.independent:
            raise FidelityHarnessError("semantic review must be independently authored")
        _assert_review_structure(packet, review)

    def _build_report(
        self,
        contract: StatementContractV1,
        *,
        candidates: tuple[CandidateFormalization, ...],
        probes: tuple[MutationProbeV1, ...],
        review: SemanticReviewVerdict,
        evidence_hash: DigestV1,
        additional_signoffs: tuple[ReviewerSignoffV1, ...],
    ) -> FidelityReportV1:
        marker = f"harness_evidence_sha256={evidence_hash.value}"
        candidates_accepted = all(
            item.decision is DecisionV1.ACCEPT for item in review.candidate_verdicts
        )
        obligations_accepted = all(
            obligation.decision is DecisionV1.ACCEPT
            for candidate in review.candidate_verdicts
            for obligation in candidate.obligation_verdicts
        )
        reverse_render_accepted = all(
            item.reverse_render_equivalent for item in review.candidate_verdicts
        )
        checks = (
            FidelityCheckV1(
                check_id=stable_identifier(
                    "builder-fidelity-check",
                    f"{evidence_hash.value}:{_check_key(FidelityCheckKindV1.SOURCE_PRESERVATION)}",
                ),
                kind=FidelityCheckKindV1.SOURCE_PRESERVATION,
                passed=review.source_to_normalized_equivalent and obligations_accepted,
                evidence=f"{marker}; {review.source_to_normalized_evidence}",
                reviewer_id=review.reviewer_id,
                independent=review.independent,
            ),
            FidelityCheckV1(
                check_id=stable_identifier(
                    "builder-fidelity-check",
                    f"{evidence_hash.value}:{_check_key(FidelityCheckKindV1.REVERSE_RENDER)}",
                ),
                kind=FidelityCheckKindV1.REVERSE_RENDER,
                passed=reverse_render_accepted and candidates_accepted,
                evidence=f"{marker}; expert reviewed every reverse rendering",
                reviewer_id=review.reviewer_id,
                independent=review.independent,
            ),
            FidelityCheckV1(
                check_id=stable_identifier(
                    "builder-fidelity-check",
                    f"{evidence_hash.value}:{_check_key(FidelityCheckKindV1.INDEPENDENT_TRANSLATION)}",
                ),
                kind=FidelityCheckKindV1.INDEPENDENT_TRANSLATION,
                passed=candidates_accepted and len(candidates) >= 2,
                evidence=f"{marker}; expert compared independently generated candidates",
                reviewer_id=review.reviewer_id,
                independent=review.independent,
            ),
            FidelityCheckV1(
                check_id=stable_identifier(
                    "builder-fidelity-check",
                    f"{evidence_hash.value}:{_check_key(FidelityCheckKindV1.POSITIVE_EXAMPLE)}",
                ),
                kind=FidelityCheckKindV1.POSITIVE_EXAMPLE,
                passed=review.positive_example_valid,
                evidence=f"{marker}; {review.positive_example_evidence}",
                reviewer_id=review.reviewer_id,
                independent=review.independent,
            ),
            FidelityCheckV1(
                check_id=stable_identifier(
                    "builder-fidelity-check",
                    f"{evidence_hash.value}:{_check_key(FidelityCheckKindV1.NEGATIVE_EXAMPLE)}",
                ),
                kind=FidelityCheckKindV1.NEGATIVE_EXAMPLE,
                passed=review.negative_example_valid,
                evidence=f"{marker}; {review.negative_example_evidence}",
                reviewer_id=review.reviewer_id,
                independent=review.independent,
            ),
            FidelityCheckV1(
                check_id=stable_identifier(
                    "builder-fidelity-check",
                    f"{evidence_hash.value}:{_check_key(FidelityCheckKindV1.NON_VACUITY)}",
                ),
                kind=FidelityCheckKindV1.NON_VACUITY,
                passed=review.non_vacuous,
                evidence=f"{marker}; {review.non_vacuity_evidence}",
                reviewer_id=review.reviewer_id,
                independent=review.independent,
            ),
        )
        mutation_by_id = {item.probe_id: item for item in review.mutation_verdicts}
        mutation_results = tuple(
            MutationResultV1(
                probe=probe,
                detected=mutation_by_id[probe.probe_id].detected,
                evidence=f"{marker}; {mutation_by_id[probe.probe_id].rationale}",
                executed_by=review.reviewer_id,
            )
            for probe in probes
        )
        signoff = ReviewerSignoffV1(
            signoff_id=stable_identifier(
                "builder-semantic-signoff", f"{evidence_hash.value}:{review.review_id}"
            ),
            reviewer_id=review.reviewer_id,
            role=ReviewerRoleV1.SEMANTIC_REVIEWER,
            decision=review.decision,
            independent=review.independent,
            rationale=f"{marker}; {review.rationale}",
        )
        return FidelityReportV1(
            report_id=stable_identifier("builder-fidelity-report", evidence_hash.value),
            evidence_hash=evidence_hash,
            risk_level=contract.policy.fidelity_risk,
            checks=checks,
            mutation_results=mutation_results,
            signoffs=(signoff, *additional_signoffs),
        )


def _candidate_structure_checks(
    task: TranslationTask,
    candidates: tuple[CandidateFormalization, ...],
) -> tuple[AutomaticCheckResult, ...]:
    if len(candidates) < 2:
        raise FidelityHarnessError("at least two translation candidates are required")
    if len({item.candidate_id for item in candidates}) != len(candidates):
        raise FidelityHarnessError("candidate identifiers must be unique")
    if len({item.actor_id for item in candidates}) != len(candidates):
        raise FidelityHarnessError("candidate actor identities must be distinct")
    if len({item.independence_group for item in candidates}) < 2:
        raise FidelityHarnessError("candidates require two independence groups")
    required_obligations = {item.obligation_id for item in task.obligations}
    for candidate in candidates:
        if (
            candidate.contract_id != task.contract_id
            or candidate.revision != task.revision
            or candidate.draft_contract_hash != task.draft_contract_hash
            or candidate.source_hash != task.source_hash
            or candidate.normalized_statement_sha256 != task.normalized_statement_sha256
        ):
            raise FidelityHarnessError("candidate is not bound to the translation task")
        if candidate.statement_hash != task.selected_statement_hash:
            raise FidelityHarnessError(
                "V1 candidates must exactly match the selected Lean statement"
            )
        covered = candidate.covered_obligation_ids
        if len(set(covered)) != len(covered) or set(covered) != required_obligations:
            raise FidelityHarnessError("candidate semantic obligation coverage is incomplete")
    return (
        AutomaticCheckResult(
            check_name="candidate_contract_bindings",
            authority=EvidenceAuthority.AUTOMATIC,
            passed=True,
            evidence="all candidate hashes and revision bindings match the translation task",
        ),
        AutomaticCheckResult(
            check_name="candidate_independence",
            authority=EvidenceAuthority.AUTOMATIC,
            passed=True,
            evidence="candidate actors and independence groups are distinct",
        ),
        AutomaticCheckResult(
            check_name="obligation_coverage",
            authority=EvidenceAuthority.AUTOMATIC,
            passed=True,
            evidence="every candidate declares every required semantic obligation",
        ),
    )


def _mutation_structure_checks(
    task: TranslationTask,
    mutation_agent_id: str,
    probes: tuple[MutationProbeV1, ...],
) -> tuple[AutomaticCheckResult, ...]:
    if not mutation_agent_id.strip():
        raise FidelityHarnessError("mutation agent identity must not be empty")
    kinds = [item.kind for item in probes]
    if len(set(kinds)) != len(kinds):
        raise FidelityHarnessError("mutation suite contains duplicate mutation kinds")
    probe_ids = [item.probe_id for item in probes]
    if len(set(probe_ids)) != len(probe_ids):
        raise FidelityHarnessError("mutation suite contains duplicate probe identifiers")
    missing = _REQUIRED_MUTATIONS - set(kinds)
    if missing:
        names = ", ".join(sorted(item.value for item in missing))
        raise FidelityHarnessError(f"mutation suite is incomplete: {names}")
    mutated_sources = [item.mutated_statement_source for item in probes]
    if any(item == task.selected_lean_statement for item in mutated_sources):
        raise FidelityHarnessError("mutation suite contains an unchanged statement")
    if len(set(mutated_sources)) != len(mutated_sources):
        raise FidelityHarnessError("mutation suite reuses one statement for multiple probes")
    return (
        AutomaticCheckResult(
            check_name="mutation_suite_shape",
            authority=EvidenceAuthority.AUTOMATIC,
            passed=True,
            evidence=(
                f"agent={mutation_agent_id}; all required mutation kinds are unique "
                "and change the statement bytes"
            ),
        ),
    )


def _assert_review_structure(
    packet: SemanticReviewPacket,
    review: SemanticReviewVerdict,
) -> None:
    if not review.independent:
        raise FidelityHarnessError("semantic review must be independently authored")
    candidate_by_id = {item.candidate_id: item for item in packet.candidates}
    verdict_by_id = {item.candidate_id: item for item in review.candidate_verdicts}
    if len(verdict_by_id) != len(review.candidate_verdicts):
        raise FidelityHarnessError("candidate review verdict identifiers must be unique")
    if set(verdict_by_id) != set(candidate_by_id):
        raise FidelityHarnessError("semantic review must cover every candidate exactly once")
    obligation_ids = {item.obligation_id for item in packet.task.obligations}
    for candidate_id, verdict in verdict_by_id.items():
        if verdict.candidate_hash != candidate_by_id[candidate_id].evidence_hash:
            raise FidelityHarnessError("candidate review verdict hash does not match evidence")
        reviewed_obligations = [item.obligation_id for item in verdict.obligation_verdicts]
        if len(set(reviewed_obligations)) != len(reviewed_obligations):
            raise FidelityHarnessError("obligation review verdict identifiers must be unique")
        if set(reviewed_obligations) != obligation_ids:
            raise FidelityHarnessError("expert review must cover every semantic obligation")
    expected_probe_ids = {item.probe_id for item in packet.mutation_probes}
    reviewed_probe_ids = [item.probe_id for item in review.mutation_verdicts]
    if len(set(reviewed_probe_ids)) != len(reviewed_probe_ids):
        raise FidelityHarnessError("mutation review verdict identifiers must be unique")
    if set(reviewed_probe_ids) != expected_probe_ids:
        raise FidelityHarnessError("expert review must cover every mutation probe")


def _assert_declared_actor_separation(
    candidates: tuple[CandidateFormalization, ...],
    mutation_agent_id: str,
    review: SemanticReviewVerdict,
    additional_signoffs: tuple[ReviewerSignoffV1, ...],
) -> None:
    """Reject declared role overlap before relying on external identity authentication."""

    execution_actor_ids = {item.actor_id for item in candidates}
    if mutation_agent_id in execution_actor_ids:
        raise FidelityHarnessError(
            "mutation agent identity must differ from every translation agent"
        )
    execution_actor_ids.add(mutation_agent_id)
    if review.reviewer_id in execution_actor_ids:
        raise FidelityHarnessError(
            "semantic reviewer identity must differ from translation and mutation agents"
        )

    signoff_ids = [item.signoff_id for item in additional_signoffs]
    if len(set(signoff_ids)) != len(signoff_ids):
        raise FidelityHarnessError("additional signoff identifiers must be unique")

    independent_reviewer_ids = [review.reviewer_id]
    for signoff in additional_signoffs:
        if not signoff.independent:
            continue
        if signoff.reviewer_id in execution_actor_ids:
            raise FidelityHarnessError(
                "independent signoff identity must differ from execution agents"
            )
        independent_reviewer_ids.append(signoff.reviewer_id)
    if len(set(independent_reviewer_ids)) != len(independent_reviewer_ids):
        raise FidelityHarnessError("independent review roles require distinct reviewer identities")


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _evaluation_hash(
    task: TranslationTask,
    candidates: tuple[CandidateFormalization, ...],
    mutation_agent_id: str,
    probes: tuple[MutationProbeV1, ...],
    review: SemanticReviewVerdict,
    automatic_checks: tuple[AutomaticCheckResult, ...],
    additional_signoffs: tuple[ReviewerSignoffV1, ...],
) -> DigestV1:
    return digest_bytes(
        HashKindV1.FREEZE_EVIDENCE,
        canonical_json_bytes(
            _evaluation_payload(
                task,
                candidates,
                mutation_agent_id,
                probes,
                review,
                automatic_checks,
                additional_signoffs,
            )
        ),
    )


def _evaluation_payload(
    task: TranslationTask,
    candidates: tuple[CandidateFormalization, ...],
    mutation_agent_id: str,
    probes: tuple[MutationProbeV1, ...],
    review: SemanticReviewVerdict,
    automatic_checks: tuple[AutomaticCheckResult, ...],
    additional_signoffs: tuple[ReviewerSignoffV1, ...],
) -> dict[str, object]:
    return {
        "schema_version": "autolean.builder-fidelity-evidence.v1",
        "task": task.payload(),
        "candidates": [item.payload() for item in candidates],
        "mutation_agent_id": mutation_agent_id,
        "mutation_probes": [item.model_dump(mode="json") for item in probes],
        "review": review.payload(),
        "automatic_checks": [item.payload() for item in automatic_checks],
        "additional_signoffs": [item.model_dump(mode="json") for item in additional_signoffs],
    }


def _check_key(kind: FidelityCheckKindV1) -> str:
    return {
        FidelityCheckKindV1.SOURCE_PRESERVATION: "source",
        FidelityCheckKindV1.REVERSE_RENDER: "reverse",
        FidelityCheckKindV1.INDEPENDENT_TRANSLATION: "independent",
        FidelityCheckKindV1.POSITIVE_EXAMPLE: "positive",
        FidelityCheckKindV1.NEGATIVE_EXAMPLE: "negative",
        FidelityCheckKindV1.NON_VACUITY: "non-vacuity",
    }[kind]
