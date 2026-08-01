"""Prepare blind machine semantic reviews and aggregate only non-promotable evidence.

Builder never executes or authorizes a model here.  This module deliberately does not construct
``ModelWorkBundleV2`` or a provider ``ModelRequest``: doing so without binding the exact outbound
request and the complete egress bytes would create a misleading authorization-ready artifact.
The only execution evidence accepted here is explicitly unverified and every report is advisory.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal

from autolean_contracts import (
    DigestV1,
    HashKindV1,
    MutationKindV1,
    StableIdentifierV1,
    StatementContractV1,
    StatementStatusV1,
    canonical_json_bytes,
    digest_bytes,
    digest_model,
    stable_identifier,
)

from .fidelity_harness import (
    CandidateGenerationTask,
    SemanticReviewPacket,
    TranslationTask,
)

_CANONICAL_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_LEAN_DECLARATION_HEAD = re.compile(r"^\s*(?:theorem|lemma)\s+([^\s(:{]+)")
_LEAN_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_']*")
_MAX_EXTERNAL_RESPONSE_ARTIFACT_BYTES = 1_048_576
_UNTRUSTED_SERIALIZATION = "untrusted_serialization"
_VERIFIED_MACHINE_QUORUM_TOKEN = object()
_DEFAULT_CRITICAL_MUTATIONS = frozenset(
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
_OPTION_LABEL_MARKERS = tuple(
    sorted(
        {
            *(item.value.casefold() for item in MutationKindV1),
            "bad_option",
            "control_option",
            "mutant_option",
            "mutation_option",
        }
    )
)
_ORIGIN_LABEL_PREFIXES = (
    "agent_",
    "candidate_",
    "control_",
    "model_",
    "mutant_",
    "mutation_",
    "origin_",
    "reviewer_",
)
_AUTHORITY_LIMITATIONS = (
    "machine evidence is advisory and is not human or expert authority",
    "failure-domain identities are declared but not operator-attested by current contracts",
    "prepared review tasks are not ModelRequests or ModelWork authorization artifacts",
    "downstream execution must independently authorize the exact outbound request and all egress "
    "bytes",
    "no receipt proves authorization, lease, fencing, persistence, and settlement for this "
    "execution",
    "content blinding uses conservative text screening, not Lean AST alpha-normalization",
    "this report cannot create a signoff, freeze a statement, or bridge to the Prover",
)


class MachineSemanticQuorumError(ValueError):
    """Review preparation or evidence binding failed closed."""


class MachineSemanticReviewRole(StrEnum):
    SOURCE_FIDELITY = "source_fidelity"
    FORMALIZATION_ADVERSARY = "formalization_adversary"
    MUTATION_SENTINEL = "mutation_sentinel"


_REQUIRED_ROLES = frozenset(MachineSemanticReviewRole)
_ROLE_PROTOCOLS: dict[MachineSemanticReviewRole, tuple[str, ...]] = {
    MachineSemanticReviewRole.SOURCE_FIDELITY: (
        "Compare source spans with the normalized mathematical claim.",
        "Check every assumption, quantifier, boundary condition, and example.",
        "Classify each anonymous formal option independently.",
    ),
    MachineSemanticReviewRole.FORMALIZATION_ADVERSARY: (
        "Search for counterexamples, vacuous premises, and boundary-case drift.",
        "Challenge reverse-rendered meaning rather than proof plausibility.",
        "Classify each anonymous formal option independently.",
    ),
    MachineSemanticReviewRole.MUTATION_SENTINEL: (
        "Compare anonymous options for changes in assumptions, binders, and relations.",
        "Do not infer option class from order or expected class proportions.",
        "Classify each anonymous formal option independently.",
    ),
}


class MachineExecutionVerificationState(StrEnum):
    UNVERIFIED_NO_CONTROL_PLANE_RECEIPT = "unverified_no_control_plane_receipt"


class MachineQuorumDisposition(StrEnum):
    UNVERIFIED_EXECUTION_EVIDENCE = "unverified_execution_evidence"


class MachineQuorumReason(StrEnum):
    UNVERIFIED_EXECUTION_EVIDENCE = "unverified_execution_evidence"
    DECLARED_FAILURE_DOMAIN_UNVERIFIED = "declared_failure_domain_unverified"
    CONTENT_BLINDING_UNVERIFIED = "content_blinding_unverified"
    REVIEWER_DISAGREEMENT = "reviewer_disagreement"
    MUTATION_SURVIVED = "mutation_survived"
    CRITICAL_MUTATION_SURVIVED = "critical_mutation_survived"
    SEMANTIC_CONTROL_REJECTED = "semantic_control_rejected"
    SEMANTIC_CHECK_FAILED = "semantic_check_failed"


def _trimmed(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise MachineSemanticQuorumError(f"{label} must be nonempty trimmed text")
    return value


def _canonical_identifier(value: object, *, label: str) -> str:
    text = _trimmed(value, label=label)
    if _CANONICAL_ID.fullmatch(text) is None:
        raise MachineSemanticQuorumError(f"{label} must use canonical lower-case identifier form")
    return text


@dataclass(frozen=True, slots=True)
class MachineSemanticQuorumPolicy:
    """Fixed floor policy; callers may add critical mutations but cannot remove defaults."""

    extra_critical_mutation_kinds: frozenset[MutationKindV1] = frozenset()

    def __post_init__(self) -> None:
        if any(not isinstance(item, MutationKindV1) for item in self.extra_critical_mutation_kinds):
            raise MachineSemanticQuorumError(
                "extra critical mutations must use MutationKindV1 values"
            )

    @property
    def critical_mutation_kinds(self) -> frozenset[MutationKindV1]:
        return _DEFAULT_CRITICAL_MUTATIONS | self.extra_critical_mutation_kinds

    def payload(self) -> dict[str, object]:
        return {
            "minimum_reviewers": 3,
            "minimum_declared_failure_domains": 2,
            "required_roles": sorted(item.value for item in _REQUIRED_ROLES),
            "default_critical_mutation_kinds": sorted(
                item.value for item in _DEFAULT_CRITICAL_MUTATIONS
            ),
            "extra_critical_mutation_kinds": sorted(
                item.value for item in self.extra_critical_mutation_kinds
            ),
        }


@dataclass(frozen=True, slots=True)
class MachineReviewSubject:
    """Selected-formal-field-blind source and mathematical review subject."""

    contract_id: StableIdentifierV1
    revision: int
    contract_hash: DigestV1
    source_record_hash: DigestV1
    rights_record_hash: DigestV1
    generation_subject: CandidateGenerationTask
    subject_fingerprint: DigestV1
    authority: Literal["machine_advisory"] = field(
        default="machine_advisory",
        init=False,
    )

    @classmethod
    def from_contract(
        cls,
        contract: StatementContractV1,
        packet: SemanticReviewPacket,
    ) -> MachineReviewSubject:
        expected_task = TranslationTask.from_contract(
            contract,
            packet.task.obligations,
            source_claims=packet.task.source_spans,
        )
        if packet.task != expected_task:
            raise MachineSemanticQuorumError("review task is detached from the draft contract")
        generation_subject = CandidateGenerationTask.from_contract(contract, expected_task)
        payload = _subject_payload(
            contract.contract_id,
            contract.revision,
            contract.semantic_hash(),
            digest_model(HashKindV1.SOURCE_RECORD, contract.source),
            digest_model(HashKindV1.RIGHTS_RECORD, contract.rights),
            generation_subject,
        )
        return cls(
            contract_id=contract.contract_id,
            revision=contract.revision,
            contract_hash=contract.semantic_hash(),
            source_record_hash=digest_model(HashKindV1.SOURCE_RECORD, contract.source),
            rights_record_hash=digest_model(HashKindV1.RIGHTS_RECORD, contract.rights),
            generation_subject=generation_subject,
            subject_fingerprint=digest_bytes(
                HashKindV1.MODEL_WORK_ITEM,
                canonical_json_bytes(payload),
            ),
        )

    def __post_init__(self) -> None:
        expected = digest_bytes(
            HashKindV1.MODEL_WORK_ITEM,
            canonical_json_bytes(
                _subject_payload(
                    self.contract_id,
                    self.revision,
                    self.contract_hash,
                    self.source_record_hash,
                    self.rights_record_hash,
                    self.generation_subject,
                )
            ),
        )
        if self.subject_fingerprint != expected:
            raise MachineSemanticQuorumError("machine review subject fingerprint is inconsistent")

    def payload(self) -> dict[str, object]:
        return _subject_payload(
            self.contract_id,
            self.revision,
            self.contract_hash,
            self.source_record_hash,
            self.rights_record_hash,
            self.generation_subject,
        )


def _subject_payload(
    contract_id: StableIdentifierV1,
    revision: int,
    contract_hash: DigestV1,
    source_record_hash: DigestV1,
    rights_record_hash: DigestV1,
    generation_subject: CandidateGenerationTask,
) -> dict[str, object]:
    return {
        "schema_version": "autolean.machine-review-subject.v1",
        "authority": "machine_advisory",
        "contract_id": contract_id.value,
        "revision": revision,
        "contract_hash": contract_hash.model_dump(mode="json"),
        "source_record_hash": source_record_hash.model_dump(mode="json"),
        "rights_record_hash": rights_record_hash.model_dump(mode="json"),
        "selected_formal_fields_visible": False,
        "subject": generation_subject.payload(),
    }


@dataclass(frozen=True, slots=True)
class BlindStatementOption:
    option_id: str
    option_fingerprint: DigestV1
    statement_source: str

    def payload(self) -> dict[str, object]:
        return {
            "option_id": self.option_id,
            "option_fingerprint": self.option_fingerprint.model_dump(mode="json"),
            "statement_source": self.statement_source,
        }


@dataclass(frozen=True, slots=True)
class _OptionScoringBinding:
    option_id: str
    option_fingerprint: DigestV1
    origin_group_fingerprint: DigestV1
    origin_fingerprints: tuple[DigestV1, ...]
    expected_preserves_claim: bool
    critical: bool
    mutation_kind: MutationKindV1 | None

    def payload(self) -> dict[str, object]:
        return {
            "option_id": self.option_id,
            "option_fingerprint": self.option_fingerprint.model_dump(mode="json"),
            "origin_group_fingerprint": self.origin_group_fingerprint.model_dump(mode="json"),
            "origin_fingerprints": [
                item.model_dump(mode="json") for item in self.origin_fingerprints
            ],
            "expected_preserves_claim": self.expected_preserves_claim,
            "critical": self.critical,
            "mutation_kind": (None if self.mutation_kind is None else self.mutation_kind.value),
        }


@dataclass(frozen=True, slots=True)
class MachineReviewerSpec:
    reviewer_id: str
    role: MachineSemanticReviewRole
    independence_group: str
    declared_failure_domain_id: str
    role_environment_hash: DigestV1
    run_id: str

    def __post_init__(self) -> None:
        _canonical_identifier(self.reviewer_id, label="reviewer id")
        _canonical_identifier(self.independence_group, label="independence group")
        _canonical_identifier(
            self.declared_failure_domain_id,
            label="declared failure domain id",
        )
        _canonical_identifier(self.run_id, label="review run id")
        if self.role_environment_hash.kind is not HashKindV1.ENVIRONMENT:
            raise MachineSemanticQuorumError(
                "reviewer role environment hash has the wrong digest kind"
            )


@dataclass(frozen=True, slots=True)
class BlindMachineReviewTask:
    """Pure preparation artifact; only :meth:`agent_payload` is reviewer-visible.

    This is not a provider request, execution authorization, or egress decision.  A downstream
    execution layer must construct and authorize its own exact request from the visible payload.
    """

    task_id: StableIdentifierV1
    reviewer_id: str
    role: MachineSemanticReviewRole
    independence_group: str
    declared_failure_domain_id: str
    reviewer_environment_fingerprint: DigestV1
    preparation_run_id: str
    subject: MachineReviewSubject
    options: tuple[BlindStatementOption, ...]
    randomization_commitment: DigestV1
    packet_fingerprint: DigestV1
    review_preparation_fingerprint: DigestV1
    policy: MachineSemanticQuorumPolicy
    scoring_commitment: DigestV1
    task_fingerprint: DigestV1
    authority: Literal["machine_advisory"] = field(
        default="machine_advisory",
        init=False,
    )
    failure_domain_authority: Literal["declared_unverified"] = field(
        default="declared_unverified",
        init=False,
    )
    execution_boundary: Literal["external_unverified"] = field(
        default="external_unverified",
        init=False,
    )
    authorization_ready: Literal[False] = field(default=False, init=False)
    downstream_egress_authorization_required: Literal[True] = field(
        default=True,
        init=False,
    )
    content_blinding_assurance: Literal["limited_text_screening_unverified"] = field(
        default="limited_text_screening_unverified",
        init=False,
    )

    def __post_init__(self) -> None:
        _canonical_identifier(self.reviewer_id, label="reviewer id")
        _canonical_identifier(self.independence_group, label="independence group")
        _canonical_identifier(
            self.declared_failure_domain_id,
            label="declared failure domain id",
        )
        _canonical_identifier(self.preparation_run_id, label="preparation run id")
        if self.reviewer_environment_fingerprint.kind is not HashKindV1.ENVIRONMENT:
            raise MachineSemanticQuorumError(
                "reviewer environment fingerprint has the wrong digest kind"
            )
        if not self.options:
            raise MachineSemanticQuorumError("blind review task requires statement options")
        option_ids = [item.option_id for item in self.options]
        option_fingerprints = [item.option_fingerprint for item in self.options]
        if len(set(option_ids)) != len(option_ids) or len(set(option_fingerprints)) != len(
            option_fingerprints
        ):
            raise MachineSemanticQuorumError("blind option ids and fingerprints must be unique")
        if any(
            item.option_fingerprint
            != digest_bytes(
                HashKindV1.MODEL_WORK_ITEM,
                canonical_json_bytes(
                    {
                        "schema_version": "autolean.blind-statement-option.v1",
                        "option_id": item.option_id,
                        "statement_source": item.statement_source,
                    }
                ),
            )
            for item in self.options
        ):
            raise MachineSemanticQuorumError("blind option fingerprint is inconsistent")
        if self.scoring_commitment.kind is not HashKindV1.MODEL_WORK_ITEM:
            raise MachineSemanticQuorumError("scoring commitment has the wrong digest kind")
        expected_packet = digest_bytes(
            HashKindV1.PROMPT,
            canonical_json_bytes(self.agent_payload()),
        )
        if self.packet_fingerprint != expected_packet:
            raise MachineSemanticQuorumError("blind review packet fingerprint is inconsistent")
        expected_preparation = _review_preparation_fingerprint(
            self.subject.subject_fingerprint,
            expected_packet,
            self.reviewer_id,
            self.role,
            self.reviewer_environment_fingerprint,
            self.preparation_run_id,
        )
        if self.review_preparation_fingerprint != expected_preparation:
            raise MachineSemanticQuorumError("review preparation is detached from the blind packet")
        expected_task = digest_bytes(
            HashKindV1.MODEL_WORK_ITEM,
            canonical_json_bytes(self.audit_payload(include_fingerprint=False)),
        )
        if self.task_fingerprint != expected_task:
            raise MachineSemanticQuorumError("blind review task fingerprint is inconsistent")
        expected_id = stable_identifier(
            "machine-semantic-review-task",
            expected_task.value,
        )
        if self.task_id != expected_id:
            raise MachineSemanticQuorumError("blind review task id is inconsistent")

    def agent_payload(self) -> dict[str, object]:
        return _agent_payload(
            self.reviewer_id,
            self.role,
            self.subject,
            self.options,
            self.randomization_commitment,
        )

    def audit_payload(self, *, include_fingerprint: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": "autolean.blind-machine-review-task-audit.v1",
            "authority": self.authority,
            "failure_domain_authority": self.failure_domain_authority,
            "reviewer_id": self.reviewer_id,
            "role": self.role.value,
            "independence_group": self.independence_group,
            "declared_failure_domain_id": self.declared_failure_domain_id,
            "reviewer_environment_fingerprint": (
                self.reviewer_environment_fingerprint.model_dump(mode="json")
            ),
            "preparation_run_id": self.preparation_run_id,
            "subject_fingerprint": self.subject.subject_fingerprint.model_dump(mode="json"),
            "packet_fingerprint": self.packet_fingerprint.model_dump(mode="json"),
            "review_preparation_fingerprint": self.review_preparation_fingerprint.model_dump(
                mode="json"
            ),
            "policy": self.policy.payload(),
            "execution_boundary": self.execution_boundary,
            "authorization_ready": self.authorization_ready,
            "downstream_egress_authorization_required": (
                self.downstream_egress_authorization_required
            ),
            "content_blinding_assurance": self.content_blinding_assurance,
            "scoring_commitment": self.scoring_commitment.model_dump(mode="json"),
            "randomization_commitment": self.randomization_commitment.model_dump(mode="json"),
        }
        if include_fingerprint:
            payload["task_id"] = self.task_id.value
            payload["task_fingerprint"] = self.task_fingerprint.model_dump(mode="json")
        return payload


@dataclass(frozen=True, slots=True)
class BlindOptionFinding:
    option_id: str
    option_fingerprint: DigestV1
    preserves_claim: bool
    rationale: str

    def __post_init__(self) -> None:
        _trimmed(self.option_id, label="option id")
        _trimmed(self.rationale, label="option finding rationale")

    def payload(self) -> dict[str, object]:
        return {
            "option_id": self.option_id,
            "option_fingerprint": self.option_fingerprint.model_dump(mode="json"),
            "preserves_claim": self.preserves_claim,
            "rationale": self.rationale,
        }


@dataclass(frozen=True, slots=True)
class MachineReviewVerdict:
    reviewer_id: str
    source_to_normalized_equivalent: bool
    positive_example_valid: bool
    negative_example_valid: bool
    non_vacuous: bool
    option_findings: tuple[BlindOptionFinding, ...]
    rationale: str
    authority: Literal["machine_advisory"] = field(
        default="machine_advisory",
        init=False,
    )

    def __post_init__(self) -> None:
        _canonical_identifier(self.reviewer_id, label="reviewer id")
        _trimmed(self.rationale, label="machine review rationale")

    def payload(self) -> dict[str, object]:
        return {
            "schema_version": "autolean.machine-review-verdict.v1",
            "authority": self.authority,
            "reviewer_id": self.reviewer_id,
            "source_to_normalized_equivalent": self.source_to_normalized_equivalent,
            "positive_example_valid": self.positive_example_valid,
            "negative_example_valid": self.negative_example_valid,
            "non_vacuous": self.non_vacuous,
            "option_findings": [item.payload() for item in self.option_findings],
            "rationale": self.rationale,
        }

    @property
    def fingerprint(self) -> DigestV1:
        return digest_bytes(
            HashKindV1.MODEL_WORK_ITEM,
            canonical_json_bytes(self.payload()),
        )


@dataclass(frozen=True, slots=True)
class MachineReviewExecutionEvidence:
    """Structurally bound result with an explicitly unverified execution authority state."""

    task_id: StableIdentifierV1
    task_fingerprint: DigestV1
    packet_fingerprint: DigestV1
    review_preparation_fingerprint: DigestV1
    verdict: MachineReviewVerdict
    external_response_artifact: bytes = field(repr=False)
    external_response_artifact_fingerprint: DigestV1 = field(init=False)
    external_response_artifact_size: int = field(init=False)
    verdict_fingerprint: DigestV1 = field(init=False)
    evidence_fingerprint: DigestV1 = field(init=False)
    verification_state: Literal["unverified_no_control_plane_receipt"] = field(
        default=MachineExecutionVerificationState.UNVERIFIED_NO_CONTROL_PLANE_RECEIPT.value,
        init=False,
    )
    authority: Literal["machine_advisory"] = field(
        default="machine_advisory",
        init=False,
    )
    provider_authorization_present: Literal[False] = field(default=False, init=False)
    execution_receipt_present: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.external_response_artifact, bytes):
            raise MachineSemanticQuorumError("external response artifact must use exact bytes")
        artifact_size = len(self.external_response_artifact)
        if artifact_size < 1 or artifact_size > _MAX_EXTERNAL_RESPONSE_ARTIFACT_BYTES:
            raise MachineSemanticQuorumError(
                "external response artifact exceeds the bounded byte contract"
            )
        if self.external_response_artifact != canonical_json_bytes(self.verdict.payload()):
            raise MachineSemanticQuorumError(
                "external response artifact is not the canonical verdict artifact"
            )
        object.__setattr__(self, "external_response_artifact_size", artifact_size)
        object.__setattr__(
            self,
            "external_response_artifact_fingerprint",
            digest_bytes(
                HashKindV1.MODEL_WORK_ITEM,
                b"autolean.machine-review-response-artifact.v1\x00"
                + self.external_response_artifact,
            ),
        )
        object.__setattr__(self, "verdict_fingerprint", self.verdict.fingerprint)
        object.__setattr__(
            self,
            "evidence_fingerprint",
            digest_bytes(
                HashKindV1.MODEL_WORK_ITEM,
                canonical_json_bytes(self.payload(include_fingerprint=False)),
            ),
        )

    def payload(self, *, include_fingerprint: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": "autolean.machine-review-execution-evidence.v2",
            "authority": self.authority,
            "verification_state": self.verification_state,
            "provider_authorization_present": self.provider_authorization_present,
            "execution_receipt_present": self.execution_receipt_present,
            "task_id": self.task_id.value,
            "task_fingerprint": self.task_fingerprint.model_dump(mode="json"),
            "packet_fingerprint": self.packet_fingerprint.model_dump(mode="json"),
            "review_preparation_fingerprint": (
                self.review_preparation_fingerprint.model_dump(mode="json")
            ),
            "external_response_artifact_size": self.external_response_artifact_size,
            "external_response_artifact_fingerprint": (
                self.external_response_artifact_fingerprint.model_dump(mode="json")
            ),
            "external_response_artifact_base64": base64.b64encode(
                self.external_response_artifact
            ).decode("ascii"),
            "verdict": self.verdict.payload(),
            "verdict_fingerprint": self.verdict_fingerprint.model_dump(mode="json"),
        }
        if include_fingerprint:
            payload["evidence_fingerprint"] = self.evidence_fingerprint.model_dump(mode="json")
        return payload


@dataclass(frozen=True, slots=True)
class MachineScoredOptionFinding:
    """Untrusted post-response scoring serialization; never reviewer-visible."""

    option_id: str
    option_fingerprint: DigestV1
    origin_group_fingerprint: DigestV1
    origin_fingerprints: tuple[DigestV1, ...]
    expected_preserves_claim: bool
    observed_preserves_claim: bool
    critical: bool
    mutation_kind: MutationKindV1 | None
    trust_state: Literal["untrusted_serialization"] = field(
        default="untrusted_serialization",
        init=False,
    )

    def __post_init__(self) -> None:
        _trimmed(self.option_id, label="scored option id")
        if not self.origin_fingerprints or len(set(self.origin_fingerprints)) != len(
            self.origin_fingerprints
        ):
            raise MachineSemanticQuorumError("scored option origins must be nonempty and unique")
        if self.expected_preserves_claim:
            if self.critical or self.mutation_kind is not None:
                raise MachineSemanticQuorumError("semantic controls cannot claim mutation metadata")
        elif self.mutation_kind is None:
            raise MachineSemanticQuorumError(
                "semantic mutants must identify their mutation kind after review"
            )

    def scoring_binding(self) -> _OptionScoringBinding:
        return _OptionScoringBinding(
            option_id=self.option_id,
            option_fingerprint=self.option_fingerprint,
            origin_group_fingerprint=self.origin_group_fingerprint,
            origin_fingerprints=self.origin_fingerprints,
            expected_preserves_claim=self.expected_preserves_claim,
            critical=self.critical,
            mutation_kind=self.mutation_kind,
        )

    def payload(self) -> dict[str, object]:
        return {
            "trust_state": self.trust_state,
            **self.scoring_binding().payload(),
            "observed_preserves_claim": self.observed_preserves_claim,
        }


@dataclass(frozen=True, slots=True)
class MachineReviewerAggregateProfile:
    """Untrusted reviewer-profile serialization pending authoritative replay."""

    reviewer_id: str
    source_to_normalized_equivalent: bool
    positive_example_valid: bool
    negative_example_valid: bool
    non_vacuous: bool
    option_findings: tuple[MachineScoredOptionFinding, ...]
    trust_state: Literal["untrusted_serialization"] = field(
        default="untrusted_serialization",
        init=False,
    )

    def __post_init__(self) -> None:
        _canonical_identifier(self.reviewer_id, label="aggregate reviewer id")
        if not self.option_findings:
            raise MachineSemanticQuorumError("aggregate reviewer profile requires scored options")
        option_ids = [item.option_id for item in self.option_findings]
        groups = [item.origin_group_fingerprint for item in self.option_findings]
        if len(set(option_ids)) != len(option_ids) or len(set(groups)) != len(groups):
            raise MachineSemanticQuorumError(
                "aggregate reviewer option ids and origin groups must be unique"
            )
        if tuple(sorted(option_ids)) != tuple(option_ids):
            raise MachineSemanticQuorumError(
                "aggregate reviewer option findings must use canonical order"
            )

    def payload(self) -> dict[str, object]:
        return {
            "trust_state": self.trust_state,
            "reviewer_id": self.reviewer_id,
            "source_to_normalized_equivalent": self.source_to_normalized_equivalent,
            "positive_example_valid": self.positive_example_valid,
            "negative_example_valid": self.negative_example_valid,
            "non_vacuous": self.non_vacuous,
            "option_findings": [item.payload() for item in self.option_findings],
        }

    def observed_profile_payload(self) -> dict[str, object]:
        return {
            "source_to_normalized_equivalent": self.source_to_normalized_equivalent,
            "positive_example_valid": self.positive_example_valid,
            "negative_example_valid": self.negative_example_valid,
            "non_vacuous": self.non_vacuous,
            "option_findings": [
                {
                    "origin_group_fingerprint": (
                        item.origin_group_fingerprint.model_dump(mode="json")
                    ),
                    "observed_preserves_claim": item.observed_preserves_claim,
                }
                for item in sorted(
                    self.option_findings,
                    key=lambda item: item.origin_group_fingerprint.value,
                )
            ],
        }


@dataclass(frozen=True, slots=True)
class MachineAggregateFindings:
    """Untrusted aggregate serialization; equality is not reviewer independence."""

    profiles: tuple[MachineReviewerAggregateProfile, ...]
    trust_state: Literal["untrusted_serialization"] = field(
        default="untrusted_serialization",
        init=False,
    )
    content_blinding_assurance: Literal["limited_text_screening_unverified"] = field(
        default="limited_text_screening_unverified",
        init=False,
    )

    def __post_init__(self) -> None:
        reviewer_ids = [item.reviewer_id for item in self.profiles]
        if len(reviewer_ids) < 3 or len(set(reviewer_ids)) != len(reviewer_ids):
            raise MachineSemanticQuorumError("aggregate findings require three unique reviewers")
        if tuple(sorted(reviewer_ids)) != tuple(reviewer_ids):
            raise MachineSemanticQuorumError(
                "aggregate findings profiles must use canonical reviewer order"
            )
        scoring_plans = {
            tuple(
                (
                    item.origin_group_fingerprint,
                    item.origin_fingerprints,
                    item.expected_preserves_claim,
                    item.critical,
                    item.mutation_kind,
                )
                for item in sorted(
                    profile.option_findings,
                    key=lambda item: item.origin_group_fingerprint.value,
                )
            )
            for profile in self.profiles
        }
        if len(scoring_plans) != 1:
            raise MachineSemanticQuorumError(
                "aggregate reviewer profiles use different scoring plans"
            )

    @property
    def observed_profile_equality(self) -> bool:
        return (
            len(
                {
                    digest_bytes(
                        HashKindV1.MODEL_WORK_ITEM,
                        canonical_json_bytes(profile.observed_profile_payload()),
                    )
                    for profile in self.profiles
                }
            )
            == 1
        )

    @property
    def mutation_survived(self) -> bool:
        return any(
            not item.expected_preserves_claim and item.observed_preserves_claim
            for profile in self.profiles
            for item in profile.option_findings
        )

    @property
    def critical_mutation_survived(self) -> bool:
        return any(
            item.critical and not item.expected_preserves_claim and item.observed_preserves_claim
            for profile in self.profiles
            for item in profile.option_findings
        )

    @property
    def semantic_control_rejected(self) -> bool:
        return any(
            item.expected_preserves_claim and not item.observed_preserves_claim
            for profile in self.profiles
            for item in profile.option_findings
        )

    @property
    def declared_checks_passed(self) -> bool:
        return all(
            profile.source_to_normalized_equivalent
            and profile.positive_example_valid
            and profile.negative_example_valid
            and profile.non_vacuous
            for profile in self.profiles
        )

    @property
    def untrusted_semantic_all_checks_passed(self) -> bool:
        return (
            self.observed_profile_equality
            and not self.mutation_survived
            and not self.semantic_control_rejected
            and self.declared_checks_passed
        )

    @property
    def reasons(self) -> tuple[MachineQuorumReason, ...]:
        reasons = [
            MachineQuorumReason.UNVERIFIED_EXECUTION_EVIDENCE,
            MachineQuorumReason.DECLARED_FAILURE_DOMAIN_UNVERIFIED,
            MachineQuorumReason.CONTENT_BLINDING_UNVERIFIED,
        ]
        if not self.observed_profile_equality:
            reasons.append(MachineQuorumReason.REVIEWER_DISAGREEMENT)
        if self.mutation_survived:
            reasons.append(MachineQuorumReason.MUTATION_SURVIVED)
        if self.critical_mutation_survived:
            reasons.append(MachineQuorumReason.CRITICAL_MUTATION_SURVIVED)
        if self.semantic_control_rejected:
            reasons.append(MachineQuorumReason.SEMANTIC_CONTROL_REJECTED)
        if not self.declared_checks_passed:
            reasons.append(MachineQuorumReason.SEMANTIC_CHECK_FAILED)
        return tuple(reasons)

    def payload(self) -> dict[str, object]:
        return {
            "trust_state": self.trust_state,
            "content_blinding_assurance": self.content_blinding_assurance,
            "profiles": [item.payload() for item in self.profiles],
        }


def _validate_untrusted_report_structure(
    tasks: tuple[BlindMachineReviewTask, ...],
    findings: MachineAggregateFindings,
    policy: MachineSemanticQuorumPolicy,
) -> None:
    """Reject cheap report forgeries without claiming authoritative reconstruction."""

    if {item.role for item in tasks} < _REQUIRED_ROLES:
        raise MachineSemanticQuorumError("machine quorum report omits a required reviewer role")
    unique_fields: tuple[tuple[str, tuple[object, ...]], ...] = (
        ("reviewer ids", tuple(item.reviewer_id for item in tasks)),
        ("independence groups", tuple(item.independence_group for item in tasks)),
        (
            "reviewer environments",
            tuple(item.reviewer_environment_fingerprint for item in tasks),
        ),
        ("preparation run ids", tuple(item.preparation_run_id for item in tasks)),
    )
    for label, values in unique_fields:
        if len(values) != len(set(values)):
            raise MachineSemanticQuorumError(f"machine quorum report {label} must be unique")
    if len({item.declared_failure_domain_id for item in tasks}) < 2:
        raise MachineSemanticQuorumError(
            "machine quorum report requires two declared failure domains"
        )

    scoring_plan = findings.profiles[0].option_findings
    if not any(item.expected_preserves_claim for item in scoring_plan):
        raise MachineSemanticQuorumError(
            "machine quorum report requires at least one semantic control"
        )
    covered_mutation_kinds = {
        item.mutation_kind
        for item in scoring_plan
        if not item.expected_preserves_claim and item.mutation_kind is not None
    }
    missing = policy.critical_mutation_kinds - covered_mutation_kinds
    if missing:
        names = ", ".join(sorted(item.value for item in missing))
        raise MachineSemanticQuorumError(
            f"machine quorum report omits policy-critical mutation kinds: {names}"
        )
    if any(
        item.critical
        != (
            not item.expected_preserves_claim
            and item.mutation_kind in policy.critical_mutation_kinds
        )
        for item in scoring_plan
    ):
        raise MachineSemanticQuorumError(
            "machine quorum report mutation criticality disagrees with policy"
        )


@dataclass(frozen=True, slots=True)
class MachineQuorumReport:
    """Untrusted serialization until :func:`verify_machine_quorum_report` succeeds."""

    tasks: tuple[BlindMachineReviewTask, ...]
    evidence: tuple[MachineReviewExecutionEvidence, ...]
    findings: MachineAggregateFindings
    contract_id: StableIdentifierV1 = field(init=False)
    revision: int = field(init=False)
    contract_hash: DigestV1 = field(init=False)
    subject_fingerprint: DigestV1 = field(init=False)
    policy: MachineSemanticQuorumPolicy = field(init=False)
    task_fingerprints: tuple[DigestV1, ...] = field(init=False)
    reasons: tuple[MachineQuorumReason, ...] = field(init=False)
    observed_profile_equality: bool = field(init=False)
    untrusted_semantic_all_checks_passed: bool = field(init=False)
    untrusted_semantic_escalation_required: bool = field(init=False)
    authority_verification_required: Literal[True] = field(init=False)
    report_fingerprint: DigestV1 = field(init=False)
    trust_state: Literal["untrusted_serialization"] = field(
        default="untrusted_serialization",
        init=False,
    )
    disposition: Literal["unverified_execution_evidence"] = field(
        default=MachineQuorumDisposition.UNVERIFIED_EXECUTION_EVIDENCE.value,
        init=False,
    )
    authority: Literal["machine_advisory"] = field(
        default="machine_advisory",
        init=False,
    )
    may_freeze: Literal[False] = field(default=False, init=False)
    authority_limitations: tuple[str, ...] = field(
        default=_AUTHORITY_LIMITATIONS,
        init=False,
    )

    def __post_init__(self) -> None:
        if (
            len(self.tasks) < 3
            or tuple(sorted(self.tasks, key=lambda item: item.reviewer_id)) != self.tasks
        ):
            raise MachineSemanticQuorumError(
                "machine quorum report tasks must use canonical reviewer order"
            )
        subjects = {
            (
                item.subject.contract_id,
                item.subject.revision,
                item.subject.contract_hash,
                item.subject.subject_fingerprint,
            )
            for item in self.tasks
        }
        policies = {item.policy for item in self.tasks}
        if len(subjects) != 1 or len(policies) != 1:
            raise MachineSemanticQuorumError(
                "machine quorum report tasks disagree on subject or policy"
            )
        policy = next(iter(policies))
        _validate_untrusted_report_structure(self.tasks, self.findings, policy)
        if tuple(item.task_id for item in self.tasks) != tuple(
            item.task_id for item in self.evidence
        ):
            raise MachineSemanticQuorumError(
                "machine quorum report evidence is not in canonical task order"
            )
        _validate_findings_against_tasks_and_evidence(
            self.tasks,
            self.evidence,
            self.findings,
        )
        contract_id, revision, contract_hash, subject_fingerprint = next(iter(subjects))
        object.__setattr__(self, "contract_id", contract_id)
        object.__setattr__(self, "revision", revision)
        object.__setattr__(self, "contract_hash", contract_hash)
        object.__setattr__(self, "subject_fingerprint", subject_fingerprint)
        object.__setattr__(self, "policy", policy)
        object.__setattr__(
            self,
            "task_fingerprints",
            tuple(item.task_fingerprint for item in self.tasks),
        )
        object.__setattr__(self, "reasons", self.findings.reasons)
        object.__setattr__(
            self,
            "observed_profile_equality",
            self.findings.observed_profile_equality,
        )
        object.__setattr__(
            self,
            "untrusted_semantic_all_checks_passed",
            self.findings.untrusted_semantic_all_checks_passed,
        )
        object.__setattr__(
            self,
            "untrusted_semantic_escalation_required",
            not self.findings.untrusted_semantic_all_checks_passed,
        )
        object.__setattr__(self, "authority_verification_required", True)
        object.__setattr__(
            self,
            "report_fingerprint",
            digest_bytes(
                HashKindV1.MODEL_WORK_ITEM,
                canonical_json_bytes(self.payload(include_fingerprint=False)),
            ),
        )

    def payload(self, *, include_fingerprint: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": "autolean.machine-quorum-report.v2",
            "trust_state": self.trust_state,
            "authority": self.authority,
            "may_freeze": self.may_freeze,
            "disposition": self.disposition,
            "contract_id": self.contract_id.value,
            "revision": self.revision,
            "contract_hash": self.contract_hash.model_dump(mode="json"),
            "subject_fingerprint": self.subject_fingerprint.model_dump(mode="json"),
            "policy": self.policy.payload(),
            "tasks": [
                {
                    "agent_payload": item.agent_payload(),
                    "audit_payload": item.audit_payload(),
                }
                for item in self.tasks
            ],
            "task_fingerprints": [item.model_dump(mode="json") for item in self.task_fingerprints],
            "evidence": [item.payload() for item in self.evidence],
            "findings": self.findings.payload(),
            "reasons": [item.value for item in self.reasons],
            "observed_profile_equality": self.observed_profile_equality,
            "untrusted_semantic_all_checks_passed": (self.untrusted_semantic_all_checks_passed),
            "untrusted_semantic_escalation_required": (self.untrusted_semantic_escalation_required),
            "authority_verification_required": self.authority_verification_required,
            "authority_limitations": list(self.authority_limitations),
        }
        if include_fingerprint:
            payload["report_fingerprint"] = self.report_fingerprint.model_dump(mode="json")
        return payload

    def render_artifact(self) -> bytes:
        return canonical_json_bytes(self.payload())


@dataclass(frozen=True, slots=True, init=False)
class VerifiedMachineQuorumReport:
    """Deterministically replayed report wrapper for downstream semantic routing.

    ``verified`` means that authoritative Builder inputs and exact response bytes reproduced the
    wrapped report. Execution authority remains unverified, the report remains advisory, and this
    private-token constructor is a misuse guard rather than a Python sandbox boundary.
    """

    _report: MachineQuorumReport = field(repr=False)
    verification_fingerprint: DigestV1
    verification_scope: Literal["deterministic_builder_reconstruction"] = field(
        init=False,
    )

    def __init__(
        self,
        report: MachineQuorumReport,
        *,
        _token: object,
    ) -> None:
        if _token is not _VERIFIED_MACHINE_QUORUM_TOKEN:
            raise TypeError(
                "VerifiedMachineQuorumReport must be created by verify_machine_quorum_report"
            )
        object.__setattr__(self, "_report", report)
        object.__setattr__(
            self,
            "verification_scope",
            "deterministic_builder_reconstruction",
        )
        object.__setattr__(
            self,
            "verification_fingerprint",
            digest_bytes(
                HashKindV1.MODEL_WORK_ITEM,
                b"autolean.verified-machine-quorum-report.v1\x00" + report.render_artifact(),
            ),
        )

    @property
    def report(self) -> MachineQuorumReport:
        return self._report

    @property
    def observed_profile_equality(self) -> bool:
        return self._report.observed_profile_equality

    @property
    def semantic_all_checks_passed(self) -> bool:
        return self._report.untrusted_semantic_all_checks_passed

    @property
    def semantic_escalation_required(self) -> bool:
        return self._report.untrusted_semantic_escalation_required

    @property
    def authority(self) -> Literal["machine_advisory"]:
        return self._report.authority

    @property
    def may_freeze(self) -> Literal[False]:
        return self._report.may_freeze

    @property
    def authority_verification_required(self) -> Literal[True]:
        return self._report.authority_verification_required

    def payload(self) -> dict[str, object]:
        return {
            "schema_version": "autolean.verified-machine-quorum-report.v1",
            "verification_scope": self.verification_scope,
            "authority": self.authority,
            "may_freeze": self.may_freeze,
            "authority_verification_required": self.authority_verification_required,
            "report": self._report.payload(),
            "verification_fingerprint": self.verification_fingerprint.model_dump(mode="json"),
        }

    def render_artifact(self) -> bytes:
        return canonical_json_bytes(self.payload())


@dataclass(frozen=True, slots=True)
class _PreparedMachineReviewTask:
    task: BlindMachineReviewTask
    scoring_bindings: tuple[_OptionScoringBinding, ...] = field(repr=False)

    def __post_init__(self) -> None:
        option_by_id = {item.option_id: item for item in self.task.options}
        binding_by_id = {item.option_id: item for item in self.scoring_bindings}
        if (
            len(binding_by_id) != len(self.scoring_bindings)
            or set(option_by_id) != set(binding_by_id)
            or any(
                option_by_id[option_id].option_fingerprint != binding.option_fingerprint
                for option_id, binding in binding_by_id.items()
            )
        ):
            raise MachineSemanticQuorumError(
                "private scoring plan is detached from the public task"
            )
        if self.task.scoring_commitment != _scoring_commitment(self.scoring_bindings):
            raise MachineSemanticQuorumError(
                "private scoring plan does not open the task commitment"
            )


@dataclass(frozen=True, slots=True)
class _PreparedMachineReview:
    entries: tuple[_PreparedMachineReviewTask, ...]

    @property
    def tasks(self) -> tuple[BlindMachineReviewTask, ...]:
        return tuple(item.task for item in self.entries)


def prepare_machine_review_tasks(
    contract: StatementContractV1,
    packet: SemanticReviewPacket,
    *,
    reviewers: tuple[MachineReviewerSpec, ...],
    randomization_seed: bytes,
    policy: MachineSemanticQuorumPolicy | None = None,
) -> tuple[BlindMachineReviewTask, ...]:
    """Prepare stable blind tasks without invoking a model or claiming execution authority."""

    return _prepare_machine_review(
        contract,
        packet,
        reviewers=reviewers,
        randomization_seed=randomization_seed,
        policy=policy,
    ).tasks


def _prepare_machine_review(
    contract: StatementContractV1,
    packet: SemanticReviewPacket,
    *,
    reviewers: tuple[MachineReviewerSpec, ...],
    randomization_seed: bytes,
    policy: MachineSemanticQuorumPolicy | None,
) -> _PreparedMachineReview:
    active_policy = policy or MachineSemanticQuorumPolicy()
    if contract.status is not StatementStatusV1.DRAFT:
        raise MachineSemanticQuorumError("machine review preparation requires a draft contract")
    if not isinstance(randomization_seed, bytes) or len(randomization_seed) < 32:
        raise MachineSemanticQuorumError("randomization seed must contain at least 32 bytes")
    subject = MachineReviewSubject.from_contract(contract, packet)
    if len(subject.generation_subject.source_spans) != 1:
        raise MachineSemanticQuorumError(
            "machine review v1 requires a single explicit source-span projection"
        )
    _validate_candidates_and_mutations(contract, packet, active_policy)
    ordered_reviewers = _validate_and_order_reviewers(packet, reviewers)
    randomization_commitment = digest_bytes(
        HashKindV1.PROMPT,
        b"autolean.machine-review.seed.v1\x00" + randomization_seed,
    )
    option_origins = _option_origins(packet, active_policy)
    entries = tuple(
        _prepare_one_task(
            subject,
            reviewer,
            option_origins,
            randomization_seed,
            randomization_commitment,
            active_policy,
        )
        for reviewer in ordered_reviewers
    )
    return _PreparedMachineReview(entries=entries)


@dataclass(frozen=True, slots=True)
class _OptionOrigin:
    origin_group_fingerprint: DigestV1
    origin_fingerprints: tuple[DigestV1, ...]
    statement_source: str
    expected_preserves_claim: bool
    critical: bool
    mutation_kind: MutationKindV1 | None


def _validate_candidates_and_mutations(
    contract: StatementContractV1,
    packet: SemanticReviewPacket,
    policy: MachineSemanticQuorumPolicy,
) -> None:
    if len(packet.candidates) < 2:
        raise MachineSemanticQuorumError("two independent translation controls are required")
    candidate_ids = [item.candidate_id for item in packet.candidates]
    actor_ids = [item.actor_id for item in packet.candidates]
    if len(set(candidate_ids)) != len(candidate_ids) or len(set(actor_ids)) != len(actor_ids):
        raise MachineSemanticQuorumError("translation candidate and actor ids must be unique")
    if len({item.independence_group for item in packet.candidates}) < 2:
        raise MachineSemanticQuorumError("translation controls need two independence groups")
    obligation_ids = {item.obligation_id for item in packet.task.obligations}
    for candidate in packet.candidates:
        _validate_blind_option_source(
            candidate.lean_statement_source,
            expected_declaration_name=contract.formal.declaration_name,
        )
        if (
            candidate.contract_id != contract.contract_id
            or candidate.revision != contract.revision
            or candidate.draft_contract_hash != contract.semantic_hash()
            or candidate.source_hash != contract.source.content_hash
            or candidate.normalized_statement_sha256 != packet.task.normalized_statement_sha256
            or set(candidate.covered_obligation_ids) != obligation_ids
        ):
            raise MachineSemanticQuorumError(
                "translation control is detached from the exact review subject"
            )
    probe_ids = [item.probe_id for item in packet.mutation_probes]
    if not probe_ids or len(set(probe_ids)) != len(probe_ids):
        raise MachineSemanticQuorumError("mutation probes must be nonempty and uniquely bound")
    available_kinds = {item.kind for item in packet.mutation_probes}
    for probe in packet.mutation_probes:
        _validate_blind_option_source(
            probe.mutated_statement_source,
            expected_declaration_name=contract.formal.declaration_name,
        )
    control_sources = {item.lean_statement_source for item in packet.candidates}
    mutant_sources = [item.mutated_statement_source for item in packet.mutation_probes]
    if len(set(mutant_sources)) != len(mutant_sources):
        raise MachineSemanticQuorumError("byte-identical mutation options are not permitted")
    if control_sources & set(mutant_sources):
        raise MachineSemanticQuorumError("a mutation option duplicates a semantic control")
    missing = policy.critical_mutation_kinds - available_kinds
    if missing:
        names = ", ".join(sorted(item.value for item in missing))
        raise MachineSemanticQuorumError(f"critical mutation suite is incomplete: {names}")


def _validate_blind_option_source(
    source: str,
    *,
    expected_declaration_name: str,
) -> None:
    """Reject v1 option text with obvious origin-label side channels.

    This is a narrow fail-closed screen, not a Lean parser or a claim of full anonymization.
    """

    if not source.strip():
        raise MachineSemanticQuorumError("blind review option source must be nonempty")
    if "--" in source or "/-" in source or "-/" in source:
        raise MachineSemanticQuorumError("blind review option source may not contain comments")
    lowered = source.casefold()
    if any(marker in lowered for marker in _OPTION_LABEL_MARKERS):
        raise MachineSemanticQuorumError(
            "blind review option source contains an origin-revealing label"
        )
    if any(
        token.casefold().startswith(_ORIGIN_LABEL_PREFIXES)
        for token in _LEAN_IDENTIFIER.findall(source)
    ):
        raise MachineSemanticQuorumError(
            "blind review option source contains an origin-revealing identifier"
        )
    match = _LEAN_DECLARATION_HEAD.match(source)
    if match is None:
        raise MachineSemanticQuorumError(
            "blind review v1 requires a named theorem or lemma declaration"
        )
    observed_name = match.group(1)
    if observed_name != expected_declaration_name:
        raise MachineSemanticQuorumError(
            "blind review options must use the contract declaration name"
        )


def _validate_and_order_reviewers(
    packet: SemanticReviewPacket,
    reviewers: tuple[MachineReviewerSpec, ...],
) -> tuple[MachineReviewerSpec, ...]:
    if len(reviewers) < 3 or not {item.role for item in reviewers} >= _REQUIRED_ROLES:
        raise MachineSemanticQuorumError("three required semantic review roles are mandatory")
    fields = {
        "reviewer ids": [item.reviewer_id for item in reviewers],
        "independence groups": [item.independence_group for item in reviewers],
        "role environments": [item.role_environment_hash.value for item in reviewers],
        "run ids": [item.run_id for item in reviewers],
    }
    for label, values in fields.items():
        if len(values) != len(set(values)):
            raise MachineSemanticQuorumError(f"machine reviewer {label} must be unique")
    if len({item.declared_failure_domain_id for item in reviewers}) < 2:
        raise MachineSemanticQuorumError(
            "at least two declared failure domains are required and cannot be downgraded"
        )
    execution_ids = {item.actor_id for item in packet.candidates}
    execution_groups = {item.independence_group for item in packet.candidates}
    if execution_ids & set(fields["reviewer ids"]):
        raise MachineSemanticQuorumError("reviewer identity overlaps a translation actor")
    if execution_groups & set(fields["independence groups"]):
        raise MachineSemanticQuorumError("reviewer group overlaps a translation independence group")
    return tuple(sorted(reviewers, key=lambda item: (item.reviewer_id, item.role.value)))


def _option_origins(
    packet: SemanticReviewPacket,
    policy: MachineSemanticQuorumPolicy,
) -> tuple[_OptionOrigin, ...]:
    control_origins: dict[str, list[DigestV1]] = {}
    for candidate in packet.candidates:
        control_origins.setdefault(candidate.lean_statement_source, []).append(
            candidate.evidence_hash
        )
    controls = tuple(
        _OptionOrigin(
            origin_group_fingerprint=digest_bytes(
                HashKindV1.MODEL_WORK_ITEM,
                canonical_json_bytes(
                    {
                        "schema_version": ("autolean.machine-review-control-origin-group.v1"),
                        "origin_fingerprints": [
                            item.model_dump(mode="json")
                            for item in sorted(
                                origin_fingerprints,
                                key=lambda item: item.value,
                            )
                        ],
                        "statement_source": statement_source,
                    }
                ),
            ),
            origin_fingerprints=tuple(sorted(origin_fingerprints, key=lambda item: item.value)),
            statement_source=statement_source,
            expected_preserves_claim=True,
            critical=False,
            mutation_kind=None,
        )
        for statement_source, origin_fingerprints in sorted(control_origins.items())
    )
    mutant_rows = []
    for probe in sorted(
        packet.mutation_probes,
        key=lambda item: item.probe_id.value,
    ):
        probe_fingerprint = digest_bytes(
            HashKindV1.MODEL_WORK_ITEM,
            canonical_json_bytes(probe.model_dump(mode="json")),
        )
        mutant_rows.append(
            _OptionOrigin(
                origin_group_fingerprint=probe_fingerprint,
                origin_fingerprints=(probe_fingerprint,),
                statement_source=probe.mutated_statement_source,
                expected_preserves_claim=False,
                critical=probe.kind in policy.critical_mutation_kinds,
                mutation_kind=probe.kind,
            )
        )
    mutants = tuple(mutant_rows)
    origins = (*controls, *mutants)
    fingerprints = [item.origin_group_fingerprint.value for item in origins]
    if len(fingerprints) != len(set(fingerprints)):
        raise MachineSemanticQuorumError("review option origins must be uniquely bound")
    return origins


def _prepare_one_task(
    subject: MachineReviewSubject,
    reviewer: MachineReviewerSpec,
    origins: tuple[_OptionOrigin, ...],
    seed: bytes,
    randomization_commitment: DigestV1,
    policy: MachineSemanticQuorumPolicy,
) -> _PreparedMachineReviewTask:
    rows: list[tuple[bytes, BlindStatementOption, _OptionScoringBinding]] = []
    for origin in origins:
        coordinate = (
            f"{reviewer.reviewer_id}:{reviewer.role.value}:{origin.origin_group_fingerprint.value}"
        )
        alias = (
            "option-"
            + hmac.new(
                seed,
                f"autolean.machine-review.option.v1:{coordinate}".encode(),
                hashlib.sha256,
            ).hexdigest()[:32]
        )
        option_fingerprint = digest_bytes(
            HashKindV1.MODEL_WORK_ITEM,
            canonical_json_bytes(
                {
                    "schema_version": "autolean.blind-statement-option.v1",
                    "option_id": alias,
                    "statement_source": origin.statement_source,
                }
            ),
        )
        option = BlindStatementOption(
            option_id=alias,
            option_fingerprint=option_fingerprint,
            statement_source=origin.statement_source,
        )
        binding = _OptionScoringBinding(
            option_id=alias,
            option_fingerprint=option_fingerprint,
            origin_group_fingerprint=origin.origin_group_fingerprint,
            origin_fingerprints=origin.origin_fingerprints,
            expected_preserves_claim=origin.expected_preserves_claim,
            critical=origin.critical,
            mutation_kind=origin.mutation_kind,
        )
        order_key = hmac.new(
            seed,
            f"autolean.machine-review.order.v1:{coordinate}".encode(),
            hashlib.sha256,
        ).digest()
        rows.append((order_key, option, binding))
    rows.sort(key=lambda item: item[0])
    options = tuple(item[1] for item in rows)
    bindings = tuple(item[2] for item in rows)
    scoring_commitment = _scoring_commitment(bindings)
    visible_payload = _agent_payload(
        reviewer.reviewer_id,
        reviewer.role,
        subject,
        options,
        randomization_commitment,
    )
    packet_fingerprint = digest_bytes(
        HashKindV1.PROMPT,
        canonical_json_bytes(visible_payload),
    )
    review_preparation_fingerprint = _review_preparation_fingerprint(
        subject.subject_fingerprint,
        packet_fingerprint,
        reviewer.reviewer_id,
        reviewer.role,
        reviewer.role_environment_hash,
        reviewer.run_id,
    )
    audit_payload = _task_audit_payload(
        reviewer,
        subject,
        packet_fingerprint,
        review_preparation_fingerprint,
        policy,
        scoring_commitment,
        randomization_commitment,
    )
    task_fingerprint = digest_bytes(
        HashKindV1.MODEL_WORK_ITEM,
        canonical_json_bytes(audit_payload),
    )
    task = BlindMachineReviewTask(
        task_id=stable_identifier(
            "machine-semantic-review-task",
            task_fingerprint.value,
        ),
        reviewer_id=reviewer.reviewer_id,
        role=reviewer.role,
        independence_group=reviewer.independence_group,
        declared_failure_domain_id=reviewer.declared_failure_domain_id,
        reviewer_environment_fingerprint=reviewer.role_environment_hash,
        preparation_run_id=reviewer.run_id,
        subject=subject,
        options=options,
        randomization_commitment=randomization_commitment,
        packet_fingerprint=packet_fingerprint,
        review_preparation_fingerprint=review_preparation_fingerprint,
        policy=policy,
        scoring_commitment=scoring_commitment,
        task_fingerprint=task_fingerprint,
    )
    return _PreparedMachineReviewTask(task=task, scoring_bindings=bindings)


def _agent_payload(
    reviewer_id: str,
    role: MachineSemanticReviewRole,
    subject: MachineReviewSubject,
    options: tuple[BlindStatementOption, ...],
    randomization_commitment: DigestV1,
) -> dict[str, object]:
    return {
        "schema_version": "autolean.blind-machine-review-task.v1",
        "authority": "machine_advisory",
        "reviewer_id": reviewer_id,
        "role": role.value,
        "review_protocol": list(_ROLE_PROTOCOLS[role]),
        "subject": subject.payload(),
        "randomization_commitment": randomization_commitment.model_dump(mode="json"),
        "options": [item.payload() for item in options],
    }


def _task_audit_payload(
    reviewer: MachineReviewerSpec,
    subject: MachineReviewSubject,
    packet_fingerprint: DigestV1,
    review_preparation_fingerprint: DigestV1,
    policy: MachineSemanticQuorumPolicy,
    scoring_commitment: DigestV1,
    randomization_commitment: DigestV1,
) -> dict[str, object]:
    return {
        "schema_version": "autolean.blind-machine-review-task-audit.v1",
        "authority": "machine_advisory",
        "failure_domain_authority": "declared_unverified",
        "reviewer_id": reviewer.reviewer_id,
        "role": reviewer.role.value,
        "independence_group": reviewer.independence_group,
        "declared_failure_domain_id": reviewer.declared_failure_domain_id,
        "reviewer_environment_fingerprint": reviewer.role_environment_hash.model_dump(mode="json"),
        "preparation_run_id": reviewer.run_id,
        "subject_fingerprint": subject.subject_fingerprint.model_dump(mode="json"),
        "packet_fingerprint": packet_fingerprint.model_dump(mode="json"),
        "review_preparation_fingerprint": review_preparation_fingerprint.model_dump(mode="json"),
        "policy": policy.payload(),
        "execution_boundary": "external_unverified",
        "authorization_ready": False,
        "downstream_egress_authorization_required": True,
        "content_blinding_assurance": "limited_text_screening_unverified",
        "scoring_commitment": scoring_commitment.model_dump(mode="json"),
        "randomization_commitment": randomization_commitment.model_dump(mode="json"),
    }


def _scoring_commitment(
    bindings: tuple[_OptionScoringBinding, ...],
) -> DigestV1:
    return digest_bytes(
        HashKindV1.MODEL_WORK_ITEM,
        canonical_json_bytes(
            {
                "schema_version": "autolean.machine-review-private-scoring.v1",
                "bindings": [
                    item.payload() for item in sorted(bindings, key=lambda item: item.option_id)
                ],
            }
        ),
    )


def _review_preparation_fingerprint(
    subject_fingerprint: DigestV1,
    packet_fingerprint: DigestV1,
    reviewer_id: str,
    role: MachineSemanticReviewRole,
    reviewer_environment_fingerprint: DigestV1,
    preparation_run_id: str,
) -> DigestV1:
    return digest_bytes(
        HashKindV1.PROMPT,
        canonical_json_bytes(
            {
                "schema_version": "autolean.machine-review-preparation.v1",
                "authorization_ready": False,
                "subject_fingerprint": subject_fingerprint.model_dump(mode="json"),
                "packet_fingerprint": packet_fingerprint.model_dump(mode="json"),
                "reviewer_id": reviewer_id,
                "role": role.value,
                "reviewer_environment_fingerprint": (
                    reviewer_environment_fingerprint.model_dump(mode="json")
                ),
                "preparation_run_id": preparation_run_id,
            }
        ),
    )


def build_unverified_machine_review_evidence(
    task: BlindMachineReviewTask,
    verdict: MachineReviewVerdict,
    *,
    external_response_artifact: bytes,
) -> MachineReviewExecutionEvidence:
    """Bind exact canonical response bytes without claiming execution verification."""

    _validate_verdict(task, verdict)
    return MachineReviewExecutionEvidence(
        task_id=task.task_id,
        task_fingerprint=task.task_fingerprint,
        packet_fingerprint=task.packet_fingerprint,
        review_preparation_fingerprint=task.review_preparation_fingerprint,
        verdict=verdict,
        external_response_artifact=external_response_artifact,
    )


def _validate_verdict(
    task: BlindMachineReviewTask,
    verdict: MachineReviewVerdict,
) -> None:
    if verdict.authority != "machine_advisory":
        raise MachineSemanticQuorumError("machine verdict cannot claim another authority")
    if verdict.reviewer_id != task.reviewer_id:
        raise MachineSemanticQuorumError("machine verdict targets another reviewer")
    option_by_id = {item.option_id: item for item in task.options}
    findings = {item.option_id: item for item in verdict.option_findings}
    if len(findings) != len(verdict.option_findings) or set(findings) != set(option_by_id):
        raise MachineSemanticQuorumError("machine verdict must cover every blind option once")
    if any(
        findings[option_id].option_fingerprint != option.option_fingerprint
        for option_id, option in option_by_id.items()
    ):
        raise MachineSemanticQuorumError("machine verdict changes a blind option fingerprint")


def _task_canonical_bytes(task: BlindMachineReviewTask) -> bytes:
    return canonical_json_bytes(
        {
            "agent_payload": task.agent_payload(),
            "audit_payload": task.audit_payload(),
        }
    )


def _build_aggregate_findings(
    entries: tuple[_PreparedMachineReviewTask, ...],
    evidence_by_task: dict[StableIdentifierV1, MachineReviewExecutionEvidence],
) -> MachineAggregateFindings:
    profiles = []
    for entry in entries:
        task = entry.task
        verdict = evidence_by_task[task.task_id].verdict
        observed_by_option = {item.option_id: item for item in verdict.option_findings}
        profiles.append(
            MachineReviewerAggregateProfile(
                reviewer_id=task.reviewer_id,
                source_to_normalized_equivalent=(verdict.source_to_normalized_equivalent),
                positive_example_valid=verdict.positive_example_valid,
                negative_example_valid=verdict.negative_example_valid,
                non_vacuous=verdict.non_vacuous,
                option_findings=tuple(
                    MachineScoredOptionFinding(
                        option_id=binding.option_id,
                        option_fingerprint=binding.option_fingerprint,
                        origin_group_fingerprint=binding.origin_group_fingerprint,
                        origin_fingerprints=binding.origin_fingerprints,
                        expected_preserves_claim=binding.expected_preserves_claim,
                        observed_preserves_claim=observed_by_option[
                            binding.option_id
                        ].preserves_claim,
                        critical=binding.critical,
                        mutation_kind=binding.mutation_kind,
                    )
                    for binding in sorted(
                        entry.scoring_bindings,
                        key=lambda item: item.option_id,
                    )
                ),
            )
        )
    return MachineAggregateFindings(profiles=tuple(profiles))


def _validate_findings_against_tasks_and_evidence(
    tasks: tuple[BlindMachineReviewTask, ...],
    evidence: tuple[MachineReviewExecutionEvidence, ...],
    findings: MachineAggregateFindings,
) -> None:
    if len(tasks) != len(evidence) or len(tasks) != len(findings.profiles):
        raise MachineSemanticQuorumError(
            "tasks, evidence, and aggregate profiles must have equal cardinality"
        )
    for task, observed, profile in zip(
        tasks,
        evidence,
        findings.profiles,
        strict=True,
    ):
        if profile.reviewer_id != task.reviewer_id:
            raise MachineSemanticQuorumError("aggregate profile targets another reviewer")
        _validate_verdict(task, observed.verdict)
        rebuilt = build_unverified_machine_review_evidence(
            task,
            observed.verdict,
            external_response_artifact=observed.external_response_artifact,
        )
        if rebuilt != observed:
            raise MachineSemanticQuorumError(
                "execution evidence is detached from its prepared task"
            )
        verdict = observed.verdict
        if (
            profile.source_to_normalized_equivalent != verdict.source_to_normalized_equivalent
            or profile.positive_example_valid != verdict.positive_example_valid
            or profile.negative_example_valid != verdict.negative_example_valid
            or profile.non_vacuous != verdict.non_vacuous
        ):
            raise MachineSemanticQuorumError("aggregate profile changes a reviewer-level verdict")
        verdict_by_option = {item.option_id: item for item in verdict.option_findings}
        profile_by_option = {item.option_id: item for item in profile.option_findings}
        if set(verdict_by_option) != set(profile_by_option):
            raise MachineSemanticQuorumError("aggregate profile changes the reviewed option set")
        for option_id, scored in profile_by_option.items():
            verdict_finding = verdict_by_option[option_id]
            if (
                scored.option_fingerprint != verdict_finding.option_fingerprint
                or scored.observed_preserves_claim != verdict_finding.preserves_claim
            ):
                raise MachineSemanticQuorumError(
                    "aggregate profile changes an observed option verdict"
                )
        if task.scoring_commitment != _scoring_commitment(
            tuple(
                item.scoring_binding()
                for item in sorted(
                    profile.option_findings,
                    key=lambda item: item.option_id,
                )
            )
        ):
            raise MachineSemanticQuorumError(
                "aggregate profile does not open the task scoring commitment"
            )


def aggregate_machine_review_evidence(
    contract: StatementContractV1,
    packet: SemanticReviewPacket,
    tasks: tuple[BlindMachineReviewTask, ...],
    evidence: tuple[MachineReviewExecutionEvidence, ...],
    *,
    reviewers: tuple[MachineReviewerSpec, ...],
    randomization_seed: bytes,
    policy: MachineSemanticQuorumPolicy | None = None,
) -> MachineQuorumReport:
    """Rederive preparation, then purely aggregate explicitly unverified evidence."""

    expected = _prepare_machine_review(
        contract,
        packet,
        reviewers=reviewers,
        randomization_seed=randomization_seed,
        policy=policy,
    )
    ordered_tasks = tuple(sorted(tasks, key=lambda item: item.reviewer_id))
    if tuple(_task_canonical_bytes(item) for item in ordered_tasks) != tuple(
        _task_canonical_bytes(item.task) for item in expected.entries
    ):
        raise MachineSemanticQuorumError(
            "supplied review tasks differ from exact rederived preparation"
        )
    evidence_by_task = {item.task_id: item for item in evidence}
    expected_task_ids = {item.task.task_id for item in expected.entries}
    if len(evidence_by_task) != len(evidence) or set(evidence_by_task) != (expected_task_ids):
        raise MachineSemanticQuorumError(
            "execution evidence must cover every rederived task exactly once"
        )
    ordered_evidence = tuple(evidence_by_task[item.task.task_id] for item in expected.entries)
    findings = _build_aggregate_findings(expected.entries, evidence_by_task)
    return MachineQuorumReport(
        tasks=expected.tasks,
        evidence=ordered_evidence,
        findings=findings,
    )


def verify_machine_quorum_report(
    contract: StatementContractV1,
    packet: SemanticReviewPacket,
    reviewers: tuple[MachineReviewerSpec, ...],
    randomization_seed: bytes,
    report: MachineQuorumReport,
    *,
    response_artifacts: Mapping[str, bytes],
    policy: MachineSemanticQuorumPolicy | None = None,
) -> VerifiedMachineQuorumReport:
    """Replay every authoritative input and exact response byte before routing.

    This is the sole supported constructor for :class:`VerifiedMachineQuorumReport`. It verifies
    deterministic Builder reconstruction only; it does not attest model execution, reviewer
    independence, semantic truth, or freeze authority.
    """

    if not isinstance(report, MachineQuorumReport):
        raise MachineSemanticQuorumError(
            "machine quorum verification requires an untrusted report serialization"
        )
    artifact_by_task = dict(response_artifacts)
    expected_task_ids = {item.task_id.value for item in report.tasks}
    if set(artifact_by_task) != expected_task_ids:
        raise MachineSemanticQuorumError(
            "response artifacts must cover every report task exactly once"
        )
    evidence_by_task = {item.task_id.value: item for item in report.evidence}
    rebuilt_evidence: list[MachineReviewExecutionEvidence] = []
    for task in report.tasks:
        observed = evidence_by_task[task.task_id.value]
        artifact = artifact_by_task[task.task_id.value]
        if artifact != observed.external_response_artifact:
            raise MachineSemanticQuorumError(
                "response artifact bytes differ from the untrusted report"
            )
        rebuilt_evidence.append(
            build_unverified_machine_review_evidence(
                task,
                observed.verdict,
                external_response_artifact=artifact,
            )
        )
    rebuilt = aggregate_machine_review_evidence(
        contract,
        packet,
        report.tasks,
        tuple(rebuilt_evidence),
        reviewers=reviewers,
        randomization_seed=randomization_seed,
        policy=policy,
    )
    if rebuilt.render_artifact() != report.render_artifact():
        raise MachineSemanticQuorumError(
            "untrusted machine quorum report differs from authoritative reconstruction"
        )
    return VerifiedMachineQuorumReport(
        rebuilt,
        _token=_VERIFIED_MACHINE_QUORUM_TOKEN,
    )
