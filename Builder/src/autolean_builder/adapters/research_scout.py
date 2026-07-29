"""Proposal-only research-scout protocol with no runtime, graph, or verifier authority.

This module intentionally performs no provider I/O, filesystem I/O, database mutation, contract
creation, FormalGraph mutation, task registration, model authorization, lease, signing, Prover, or
Verifier operation. Callers may stage the returned canonical bytes in an independent CAS, but only
Builder review can decide whether an advisory proposal informs a new draft revision.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from enum import StrEnum
from typing import Literal

from autolean_contracts import ContractModel, canonical_json_bytes
from pydantic import Field, ValidationError, field_validator, model_validator

_ID = re.compile(r"^[a-z][a-z0-9._-]{2,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SECRET = re.compile(
    r"(?i)(?:api[_-]?key|authorization|bearer|client[_-]?secret|password|private[_-]?key|token)"
    r"\s*(?:[:=]|\b)"
)
_HOST_PATH = re.compile(
    r"(?:[A-Za-z]:[\\/]|(?:^|[\s\"'])/(?:home|users|var|etc|tmp|mnt|private|workspace)(?:[\\/]|$))"
)
_PROOF_PLACEHOLDER = re.compile(r"\b(?:sorry|admit|sorryAx|axiom|import)\b")


class ResearchScoutAdapterError(ValueError):
    """An untrusted research-scout envelope violated the proposal-only protocol."""


class ResearchScoutRoleV1(StrEnum):
    CONSTRUCTIVE = "constructive"
    REFUTATIONAL = "refutational"
    TOY_EXAMPLE = "toy_example"
    DECOMPOSITION = "decomposition"
    LITERATURE = "literature"


class ResearchScoutEgressClassV1(StrEnum):
    LOCAL = "local"
    APPROVED_CUSTOM = "approved-custom"


class ResearchScoutProposalKindV1(StrEnum):
    LEMMA = "lemma"
    COUNTEREXAMPLE = "counterexample"
    TOY_EXAMPLE = "toy_example"
    DECOMPOSITION = "decomposition"
    LITERATURE_LEAD = "literature_lead"
    PROOF_CANDIDATE = "proof_candidate"


class ResearchScoutAuthorityV1(StrEnum):
    MACHINE_ADVISORY = "machine_advisory"


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _require_id(value: str, label: str) -> str:
    if _ID.fullmatch(value) is None:
        raise ValueError(f"{label} must be a stable lower-case identifier")
    return value


def _require_sha256(value: str, label: str) -> str:
    if _SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} must be a full lower-case SHA-256 digest")
    return value


def _reject_sensitive_text(value: str, label: str) -> str:
    if not value or "\x00" in value:
        raise ValueError(f"{label} must be non-empty text without NUL")
    if _HOST_PATH.search(value):
        raise ValueError(f"{label} must not contain a host path")
    if _SECRET.search(value):
        raise ValueError(f"{label} must not contain a secret-like value")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ResearchScoutAdapterError("research-scout JSON contains a duplicate key")
        result[key] = value
    return result


def _parse_canonical_json(raw: bytes, model: type[ContractModel], label: str) -> ContractModel:
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ResearchScoutAdapterError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(parsed, Mapping):
        raise ResearchScoutAdapterError(f"{label} must be a JSON object")
    if canonical_json_bytes(parsed) != raw:
        raise ResearchScoutAdapterError(f"{label} must use canonical JSON bytes")
    try:
        return model.model_validate(parsed)
    except ValidationError as error:
        raise ResearchScoutAdapterError(f"{label} violates its typed schema") from error


class ImmutableArtifactCommitmentV1(ContractModel):
    """A content-addressed input reference; it deliberately carries no host path or payload."""

    artifact_id: str
    sha256: str

    @field_validator("artifact_id")
    @classmethod
    def validate_artifact_id(cls, value: str) -> str:
        return _require_id(value, "artifact_id")

    @field_validator("sha256")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        return _require_sha256(value, "artifact SHA-256")


class ResearchScoutSourceRefV1(ContractModel):
    source_id: str
    span_id: str
    hash: str

    @field_validator("source_id", "span_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        return _require_id(value, "source reference identifier")

    @field_validator("hash")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        return _require_sha256(value, "source reference hash")


class ResearchScoutAttemptBudgetV1(ContractModel):
    max_attempts: Literal[1] = 1
    max_output_tokens: int = Field(ge=1, le=4096)


class ResearchScoutRequestProvenanceV1(ContractModel):
    source_ids: tuple[str, ...] = ()
    source_span_ids: tuple[str, ...] = ()
    retrieval_hash: str | None = None

    @field_validator("source_ids", "source_span_ids")
    @classmethod
    def validate_identifiers(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("request provenance identifiers must be unique")
        for item in value:
            _require_id(item, "request provenance identifier")
        return value

    @field_validator("retrieval_hash")
    @classmethod
    def validate_retrieval_hash(cls, value: str | None) -> str | None:
        return None if value is None else _require_sha256(value, "retrieval_hash")


class ResearchScoutRequestV1(ContractModel):
    schema_version: Literal["autolean.research-scout-request.v1"] = (
        "autolean.research-scout-request.v1"
    )
    request_id: str
    mission_id: str
    contract_id: str | None = None
    revision: int = Field(ge=0)
    contract_hash: str | None = None
    graph_snapshot_hash: str
    context_pack_hash: str
    input_artifacts_sha256: str
    role: ResearchScoutRoleV1
    goal: str
    context_artifact_sha256: str
    rights_scope_id: str
    provider_snapshot_id: str
    attempt_budget: ResearchScoutAttemptBudgetV1
    egress_class: ResearchScoutEgressClassV1
    provenance: ResearchScoutRequestProvenanceV1

    @field_validator("request_id", "mission_id", "rights_scope_id", "provider_snapshot_id")
    @classmethod
    def validate_identifiers(cls, value: str) -> str:
        return _require_id(value, "research-scout request identifier")

    @field_validator("contract_id")
    @classmethod
    def validate_contract_id(cls, value: str | None) -> str | None:
        return None if value is None else _require_id(value, "contract_id")

    @field_validator(
        "contract_hash",
        "graph_snapshot_hash",
        "context_pack_hash",
        "input_artifacts_sha256",
        "context_artifact_sha256",
    )
    @classmethod
    def validate_hashes(cls, value: str | None) -> str | None:
        return None if value is None else _require_sha256(value, "research-scout hash")

    @field_validator("goal")
    @classmethod
    def validate_goal(cls, value: str) -> str:
        return _reject_sensitive_text(value, "goal")

    @model_validator(mode="after")
    def validate_contract_binding(self) -> ResearchScoutRequestV1:
        if self.contract_id is None:
            if self.contract_hash is not None or self.revision != 0:
                raise ValueError("a discovery request has no contract hash and uses revision zero")
        elif self.contract_hash is None or self.revision < 1:
            raise ValueError("an existing contract requires its hash and positive revision")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self)


class ResearchScoutInputArtifactsV1(ContractModel):
    """The only accepted input surface besides the typed request envelope."""

    goal: ImmutableArtifactCommitmentV1
    context_pack: ImmutableArtifactCommitmentV1
    context_artifact: ImmutableArtifactCommitmentV1
    graph_snapshot: ImmutableArtifactCommitmentV1
    rights_scope: ImmutableArtifactCommitmentV1
    provider_snapshot: ImmutableArtifactCommitmentV1
    contract: ImmutableArtifactCommitmentV1 | None = None
    source_refs: tuple[ResearchScoutSourceRefV1, ...] = ()
    predecessor_proposal_ids: tuple[str, ...] = ()

    @field_validator("predecessor_proposal_ids")
    @classmethod
    def validate_predecessors(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("predecessor proposal IDs must be unique")
        for item in value:
            _require_sha256(item, "predecessor proposal ID")
        return value

    @model_validator(mode="after")
    def validate_artifact_inventory(self) -> ResearchScoutInputArtifactsV1:
        artifacts: tuple[ImmutableArtifactCommitmentV1, ...] = (
            self.goal,
            self.context_pack,
            self.context_artifact,
            self.graph_snapshot,
            self.rights_scope,
            self.provider_snapshot,
        )
        if self.contract is not None:
            artifacts += (self.contract,)
        if len({item.artifact_id for item in artifacts}) != len(artifacts):
            raise ValueError("immutable artifact IDs must be unique")
        source_keys = {(item.source_id, item.span_id, item.hash) for item in self.source_refs}
        if len(source_keys) != len(self.source_refs):
            raise ValueError("immutable source references must be unique")
        return self

    def computed_sha256(self) -> str:
        """Commit to the complete artifact inventory passed alongside a request."""

        return _sha256(canonical_json_bytes(self))


class ResearchScoutProviderV1(ContractModel):
    provider_id: Literal["deepseek", "fake", "custom"]
    model_id: str

    @field_validator("model_id")
    @classmethod
    def validate_model_id(cls, value: str) -> str:
        _require_id(value, "model_id")
        return _reject_sensitive_text(value, "model_id")


class ResearchScoutUsageV1(ContractModel):
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    cost_micro_usd: int = Field(ge=0)


class ResearchScoutResponseV1(ContractModel):
    schema_version: Literal["autolean.research-scout-response.v1"] = (
        "autolean.research-scout-response.v1"
    )
    request_id: str
    proposal_id: str
    kind: ResearchScoutProposalKindV1
    statement: str
    evidence: str
    dependency_refs: tuple[str | None, ...] = ()
    source_refs: tuple[ResearchScoutSourceRefV1, ...] = ()
    context_pack_hash: str
    provider: ResearchScoutProviderV1
    usage: ResearchScoutUsageV1
    output_sha256: str
    status: Literal["untrusted_proposal"] = "untrusted_proposal"

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, value: str) -> str:
        return _require_id(value, "response request_id")

    @field_validator("proposal_id", "output_sha256", "context_pack_hash")
    @classmethod
    def validate_hashes(cls, value: str) -> str:
        return _require_sha256(value, "response hash")

    @field_validator("statement", "evidence")
    @classmethod
    def validate_text(cls, value: str) -> str:
        return _reject_sensitive_text(value, "response text")

    @field_validator("dependency_refs")
    @classmethod
    def validate_dependencies(cls, value: tuple[str | None, ...]) -> tuple[str | None, ...]:
        present = tuple(item for item in value if item is not None)
        if len(present) != len(set(present)):
            raise ValueError("proposal dependency references must be unique")
        for item in present:
            _require_sha256(item, "proposal dependency reference")
        return value

    @model_validator(mode="after")
    def validate_identity_and_proof_boundary(self) -> ResearchScoutResponseV1:
        expected = self.computed_output_sha256()
        if self.output_sha256 != expected or self.proposal_id != expected:
            raise ValueError(
                "proposal ID and output SHA-256 must bind the canonical proposal payload"
            )
        if self.kind is ResearchScoutProposalKindV1.PROOF_CANDIDATE and _PROOF_PLACEHOLDER.search(
            self.evidence
        ):
            raise ValueError(
                "proof_candidate evidence contains a forbidden proof placeholder or command"
            )
        source_keys = {(item.source_id, item.span_id, item.hash) for item in self.source_refs}
        if len(source_keys) != len(self.source_refs):
            raise ValueError("proposal source references must be unique")
        return self

    def proposal_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"proposal_id", "output_sha256"})

    def computed_output_sha256(self) -> str:
        return _sha256(canonical_json_bytes(self.proposal_payload()))

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self)


class ResearchScoutProposalV1(ContractModel):
    """A typed advisory result. It is never a statement, graph, or proof acceptance record."""

    schema_version: Literal["autolean.research-scout-proposal.v1"] = (
        "autolean.research-scout-proposal.v1"
    )
    proposal_id: str
    kind: ResearchScoutProposalKindV1
    statement: str
    evidence: str
    dependency_refs: tuple[str | None, ...]
    source_refs: tuple[ResearchScoutSourceRefV1, ...]
    request_id: str
    context_pack_hash: str
    provider: ResearchScoutProviderV1
    usage: ResearchScoutUsageV1
    output_sha256: str
    response_cas_sha256: str
    event_kind: Literal["research_hypothesis", "research_observation"]
    authority: Literal[ResearchScoutAuthorityV1.MACHINE_ADVISORY] = (
        ResearchScoutAuthorityV1.MACHINE_ADVISORY
    )
    promotion: Literal[False] = False

    @field_validator("proposal_id", "output_sha256", "response_cas_sha256", "context_pack_hash")
    @classmethod
    def validate_hashes(cls, value: str) -> str:
        return _require_sha256(value, "proposal hash")

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self)


class ResearchScoutAdapterV1:
    """Validate and project untrusted scout envelopes without exercising any authority path."""

    def request_bytes(
        self,
        request: ResearchScoutRequestV1,
        artifacts: ResearchScoutInputArtifactsV1,
    ) -> bytes:
        self._validate_request_artifacts(request, artifacts)
        return request.canonical_bytes()

    def parse_request(
        self,
        raw: bytes,
        artifacts: ResearchScoutInputArtifactsV1,
    ) -> ResearchScoutRequestV1:
        parsed = _parse_canonical_json(raw, ResearchScoutRequestV1, "research-scout request")
        if not isinstance(parsed, ResearchScoutRequestV1):
            raise AssertionError("request model parser returned an unexpected type")
        self._validate_request_artifacts(parsed, artifacts)
        return parsed

    def accept_response(
        self,
        request: ResearchScoutRequestV1,
        artifacts: ResearchScoutInputArtifactsV1,
        raw: bytes,
    ) -> ResearchScoutProposalV1:
        self._validate_request_artifacts(request, artifacts)
        parsed = _parse_canonical_json(raw, ResearchScoutResponseV1, "research-scout response")
        if not isinstance(parsed, ResearchScoutResponseV1):
            raise AssertionError("response model parser returned an unexpected type")
        self._validate_response_binding(request, artifacts, parsed)
        event_kind: Literal["research_hypothesis", "research_observation"]
        if parsed.kind in {
            ResearchScoutProposalKindV1.COUNTEREXAMPLE,
            ResearchScoutProposalKindV1.LITERATURE_LEAD,
        }:
            event_kind = "research_observation"
        else:
            event_kind = "research_hypothesis"
        return ResearchScoutProposalV1(
            proposal_id=parsed.proposal_id,
            kind=parsed.kind,
            statement=parsed.statement,
            evidence=parsed.evidence,
            dependency_refs=parsed.dependency_refs,
            source_refs=parsed.source_refs,
            request_id=parsed.request_id,
            context_pack_hash=parsed.context_pack_hash,
            provider=parsed.provider,
            usage=parsed.usage,
            output_sha256=parsed.output_sha256,
            response_cas_sha256=_sha256(parsed.canonical_bytes()),
            event_kind=event_kind,
        )

    @staticmethod
    def _validate_request_artifacts(
        request: ResearchScoutRequestV1,
        artifacts: ResearchScoutInputArtifactsV1,
    ) -> None:
        if artifacts.goal.sha256 != _sha256(request.goal.encode("utf-8")):
            raise ResearchScoutAdapterError("goal does not match its immutable artifact commitment")
        if request.contract_id is None:
            if artifacts.contract is not None:
                raise ResearchScoutAdapterError(
                    "a discovery request must not carry a contract commitment"
                )
        elif (
            artifacts.contract is None
            or artifacts.contract.artifact_id != request.contract_id
            or artifacts.contract.sha256 != request.contract_hash
        ):
            raise ResearchScoutAdapterError(
                "existing contract does not match its immutable commitment"
            )
        expected = {
            "context pack": (artifacts.context_pack.sha256, request.context_pack_hash),
            "context artifact": (
                artifacts.context_artifact.sha256,
                request.context_artifact_sha256,
            ),
            "graph snapshot": (artifacts.graph_snapshot.sha256, request.graph_snapshot_hash),
            "rights scope": (artifacts.rights_scope.artifact_id, request.rights_scope_id),
            "provider snapshot": (
                artifacts.provider_snapshot.artifact_id,
                request.provider_snapshot_id,
            ),
        }
        for label, (actual, bound) in expected.items():
            if actual != bound:
                raise ResearchScoutAdapterError(f"{label} does not match its immutable commitment")
        provider_prefix = request.provider_snapshot_id.split("-", maxsplit=1)[0]
        if provider_prefix not in {"deepseek", "fake", "custom"}:
            raise ResearchScoutAdapterError(
                "provider snapshot is not on the research-scout allowlist"
            )
        if request.egress_class is ResearchScoutEgressClassV1.LOCAL and provider_prefix != "fake":
            raise ResearchScoutAdapterError("local egress permits only the fake provider snapshot")
        if (
            request.egress_class is ResearchScoutEgressClassV1.APPROVED_CUSTOM
            and provider_prefix == "fake"
        ):
            raise ResearchScoutAdapterError(
                "approved-custom egress cannot use the fake provider snapshot"
            )
        source_ids = tuple(item.source_id for item in artifacts.source_refs)
        span_ids = tuple(item.span_id for item in artifacts.source_refs)
        if (
            request.provenance.source_ids != source_ids
            or request.provenance.source_span_ids != span_ids
        ):
            raise ResearchScoutAdapterError(
                "request provenance does not match immutable source commitments"
            )
        if request.provenance.retrieval_hash is not None and (
            request.provenance.retrieval_hash != artifacts.graph_snapshot.sha256
        ):
            raise ResearchScoutAdapterError(
                "request retrieval hash is not bound to the graph snapshot"
            )
        if request.input_artifacts_sha256 != artifacts.computed_sha256():
            raise ResearchScoutAdapterError(
                "request does not match its immutable input artifact inventory"
            )

    @staticmethod
    def _validate_response_binding(
        request: ResearchScoutRequestV1,
        artifacts: ResearchScoutInputArtifactsV1,
        response: ResearchScoutResponseV1,
    ) -> None:
        if response.request_id != request.request_id:
            raise ResearchScoutAdapterError(
                "response request ID does not match the immutable request"
            )
        if response.context_pack_hash != request.context_pack_hash:
            raise ResearchScoutAdapterError(
                "response context hash does not match the immutable request"
            )
        if response.usage.output_tokens > request.attempt_budget.max_output_tokens:
            raise ResearchScoutAdapterError("response exceeds the immutable output-token budget")
        provider_prefix = request.provider_snapshot_id.split("-", maxsplit=1)[0]
        if response.provider.provider_id != provider_prefix:
            raise ResearchScoutAdapterError(
                "response provider does not match the immutable provider snapshot"
            )
        if (
            request.egress_class is ResearchScoutEgressClassV1.LOCAL
            and response.provider.provider_id != "fake"
        ):
            raise ResearchScoutAdapterError("local egress permits only the fake provider")
        if (
            request.egress_class is ResearchScoutEgressClassV1.APPROVED_CUSTOM
            and response.provider.provider_id == "fake"
        ):
            raise ResearchScoutAdapterError(
                "approved-custom egress cannot substitute the fake provider"
            )
        known_sources = {
            (item.source_id, item.span_id, item.hash) for item in artifacts.source_refs
        }
        response_sources = {
            (item.source_id, item.span_id, item.hash) for item in response.source_refs
        }
        if not response_sources <= known_sources:
            raise ResearchScoutAdapterError(
                "response source reference is absent from immutable commitments"
            )
        unknown_dependencies = {
            item
            for item in response.dependency_refs
            if item is not None and item not in artifacts.predecessor_proposal_ids
        }
        if unknown_dependencies:
            raise ResearchScoutAdapterError("response references an unknown predecessor proposal")
