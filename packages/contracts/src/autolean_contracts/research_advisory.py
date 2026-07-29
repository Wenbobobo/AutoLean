"""Proposal-only public envelopes for research-scout observations.

This schema is deliberately narrower than the Builder's private proposal object.  It is the
only form a proposal may use when it crosses into the append-only control-plane event stream.
It carries stable commitments and public classification only; statement text, evidence text,
prompts, source excerpts, provider endpoints, credentials, and any authority to change a
contract are excluded by construction.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator

from .authorization import validate_model_routing_identifier
from .base import ContractModel
from .hashing import canonical_json_bytes

_IDENTIFIER = re.compile(r"^[a-z][a-z0-9._-]{2,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ResearchAdvisoryEventKindV1(StrEnum):
    """The two non-authoritative research event families visible to a projection."""

    HYPOTHESIS = "research_hypothesis"
    OBSERVATION = "research_observation"


class ResearchAdvisoryProposalKindV1(StrEnum):
    """A proposal taxonomy; it is not a truth or proof-status taxonomy."""

    LEMMA = "lemma"
    COUNTEREXAMPLE = "counterexample"
    TOY_EXAMPLE = "toy_example"
    DECOMPOSITION = "decomposition"
    LITERATURE_LEAD = "literature_lead"
    PROOF_CANDIDATE = "proof_candidate"


class ResearchAdvisoryProviderV1(ContractModel):
    """Public provider identity with no endpoint or credential configuration."""

    provider_id: Literal["deepseek", "fake", "custom"]
    model_id: str = Field(min_length=3, max_length=128)

    @field_validator("model_id")
    @classmethod
    def validate_model_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("research advisory model_id must be a stable lower-case identifier")
        validate_model_routing_identifier(value, label="research advisory model_id")
        return value


class ResearchAdvisorySourceRefV1(ContractModel):
    """A source-span commitment only; source bytes never enter the event envelope."""

    source_id: str = Field(min_length=3, max_length=128)
    span_id: str = Field(min_length=3, max_length=128)
    hash: str = Field(min_length=64, max_length=64)

    @field_validator("source_id", "span_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("research advisory source identifiers must be stable identifiers")
        return value

    @field_validator("hash")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("research advisory source hashes must be SHA-256 digests")
        return value


class ResearchAdvisoryEventV1(ContractModel):
    """Immutable, advisory-only event payload for the local append-only event store.

    It cannot name a contract revision or bundle, therefore it cannot participate in Builder
    freeze, Prover scheduling, verification, release, or any of the three graph projections.
    A later Builder review may independently use the referenced private proposal artifact to
    create a *new* draft.  This record itself remains only an observation of machine output.
    """

    schema_version: Literal["autolean.research-advisory-event.v1"] = (
        "autolean.research-advisory-event.v1"
    )
    proposal_id: str = Field(min_length=64, max_length=64)
    event_kind: ResearchAdvisoryEventKindV1
    proposal_kind: ResearchAdvisoryProposalKindV1
    request_id: str = Field(min_length=3, max_length=128)
    context_pack_hash: str = Field(min_length=64, max_length=64)
    output_sha256: str = Field(min_length=64, max_length=64)
    response_cas_sha256: str = Field(min_length=64, max_length=64)
    dependency_refs: tuple[str, ...] = Field(max_length=256)
    source_refs: tuple[ResearchAdvisorySourceRefV1, ...] = Field(max_length=256)
    provider: ResearchAdvisoryProviderV1
    authority: Literal["machine_advisory"] = "machine_advisory"
    promotion: Literal[False] = False

    @field_validator(
        "proposal_id",
        "context_pack_hash",
        "output_sha256",
        "response_cas_sha256",
    )
    @classmethod
    def validate_hashes(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("research advisory hashes must be SHA-256 digests")
        return value

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("research advisory request_id must be a stable identifier")
        return value

    @field_validator("dependency_refs")
    @classmethod
    def validate_dependencies(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("research advisory dependency references must be unique")
        for item in value:
            if _SHA256.fullmatch(item) is None:
                raise ValueError("research advisory dependency references must be SHA-256 digests")
        return value

    @model_validator(mode="after")
    def validate_advisory_binding(self) -> Self:
        if self.proposal_id != self.output_sha256:
            raise ValueError("research advisory proposal ID must equal its output digest")
        expected_event_kind = (
            ResearchAdvisoryEventKindV1.OBSERVATION
            if self.proposal_kind
            in {
                ResearchAdvisoryProposalKindV1.COUNTEREXAMPLE,
                ResearchAdvisoryProposalKindV1.LITERATURE_LEAD,
            }
            else ResearchAdvisoryEventKindV1.HYPOTHESIS
        )
        if self.event_kind is not expected_event_kind:
            raise ValueError("research advisory event kind conflicts with proposal taxonomy")
        source_keys = {(item.source_id, item.span_id, item.hash) for item in self.source_refs}
        if len(source_keys) != len(self.source_refs):
            raise ValueError("research advisory source references must be unique")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self)
