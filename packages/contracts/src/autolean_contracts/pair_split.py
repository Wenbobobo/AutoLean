"""Public commitments for pair-atomic private held-out partitions.

This module intentionally carries no inputs, labels, witnesses, source locators,
or secret key material.  It lets public consumers verify pair atomicity and
cross-partition leakage closure over operator-keyed opaque commitments.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, model_validator

from .base import ContractModel
from .hashing import canonical_json_bytes

_SHA256 = r"^[0-9a-f]{64}$"
_IDENTIFIER = r"^[a-z0-9][a-z0-9_.:-]{0,127}$"
_PUBLIC_SPLIT_ID = r"^split\.[0-9a-f]{32,64}$"
_PUBLIC_REVISION = r"^rev\.[0-9a-f]{32,64}$"
_PUBLIC_KEY_ID = r"^key\.[0-9a-f]{32,64}$"


class PairSplitPartitionV1(StrEnum):
    """Public partition names; held-out payloads remain operator-private."""

    TRAIN = "train"
    DEV = "dev"
    PRIVATE_HELDOUT = "private_heldout"


class PairSplitAuthorityV1(ContractModel):
    """A split commitment has binding authority only, never semantic authority."""

    schema_version: Literal["autolean.pair-split-authority.v1"] = "autolean.pair-split-authority.v1"
    evidence_class: Literal["private_pair_partition_commitment_only"] = (
        "private_pair_partition_commitment_only"
    )
    payload_disclosed: Literal[False] = False
    oracle_disclosed: Literal[False] = False
    source_text_disclosed: Literal[False] = False
    semantic_equivalence_claimed: Literal[False] = False
    public_partition_authentication_claimed: Literal[False] = False
    private_reverification_required: Literal[True] = True
    model_evaluation_authority: Literal[False] = False
    freeze_authority: Literal[False] = False
    prover_handoff_authority: Literal[False] = False
    release_authority: Literal[False] = False


class AtomicPairCommitmentV1(ContractModel):
    """One indivisible baseline/mutant pair represented only by commitments."""

    schema_version: Literal["autolean.atomic-pair-commitment.v1"] = (
        "autolean.atomic-pair-commitment.v1"
    )
    opaque_pair_id: str = Field(pattern=_IDENTIFIER)
    partition: PairSplitPartitionV1
    source_id_commitment: str = Field(pattern=_SHA256)
    scenario_commitment: str = Field(pattern=_SHA256)
    source_commitment: str = Field(pattern=_SHA256)
    source_span_id_commitment: str = Field(pattern=_SHA256)
    source_span_commitment: str = Field(pattern=_SHA256)
    mutation_commitment: str = Field(pattern=_SHA256)
    witness_commitment: str = Field(pattern=_SHA256)
    rights_commitment: str = Field(pattern=_SHA256)
    private_pair_payload_commitment: str = Field(pattern=_SHA256)
    pair_commitment: str = Field(pattern=_SHA256)
    authority: PairSplitAuthorityV1 = Field(default_factory=PairSplitAuthorityV1)

    @model_validator(mode="after")
    def validate_pair_commitment(self) -> Self:
        expected = hashlib.sha256(
            canonical_json_bytes(self.model_dump(mode="json", exclude={"pair_commitment"}))
        ).hexdigest()
        if self.pair_commitment != expected:
            raise ValueError("atomic pair commitment differs from its public payload")
        return self


class PairLevelSplitCommitmentV1(ContractModel):
    """Public split with pair and transitive identity-leakage closure."""

    schema_version: Literal["autolean.pair-level-split-commitment.v1"] = (
        "autolean.pair-level-split-commitment.v1"
    )
    split_id: str = Field(pattern=_PUBLIC_SPLIT_ID)
    split_revision: str = Field(pattern=_PUBLIC_REVISION)
    commitment_scheme: Literal["hmac-sha256-domain-separated-v1"] = (
        "hmac-sha256-domain-separated-v1"
    )
    nonsecret_key_id: str = Field(pattern=_PUBLIC_KEY_ID)
    private_manifest_commitment: str = Field(pattern=_SHA256)
    pairs: tuple[AtomicPairCommitmentV1, ...] = Field(min_length=3)
    split_sha256: str = Field(pattern=_SHA256)
    authority: PairSplitAuthorityV1 = Field(default_factory=PairSplitAuthorityV1)

    @model_validator(mode="after")
    def validate_split(self) -> Self:
        identities = tuple(pair.opaque_pair_id for pair in self.pairs)
        if identities != tuple(sorted(set(identities))):
            raise ValueError("pair split identifiers must be canonical and unique")
        partitions = {pair.partition for pair in self.pairs}
        if partitions != set(PairSplitPartitionV1):
            raise ValueError("pair split must contain train, dev, and private-heldout pairs")

        # Equality of an opaque identity commitment means the private records
        # share that leakage dimension.  Such records must remain together.
        for field_name in (
            "source_id_commitment",
            "scenario_commitment",
            "source_commitment",
            "source_span_id_commitment",
            "source_span_commitment",
            "mutation_commitment",
            "witness_commitment",
        ):
            observed: dict[str, PairSplitPartitionV1] = {}
            for pair in self.pairs:
                commitment = getattr(pair, field_name)
                prior = observed.setdefault(commitment, pair.partition)
                if prior is not pair.partition:
                    raise ValueError(f"{field_name} cannot cross pair-level split partitions")

        expected = hashlib.sha256(
            canonical_json_bytes(self.model_dump(mode="json", exclude={"split_sha256"}))
        ).hexdigest()
        if self.split_sha256 != expected:
            raise ValueError("pair-level split hash differs from its public payload")
        return self

    def partition(
        self,
        name: PairSplitPartitionV1,
    ) -> tuple[AtomicPairCommitmentV1, ...]:
        if type(self) is not PairLevelSplitCommitmentV1:
            raise ValueError("pair split accessor requires a validated public split")
        try:
            verified = PairLevelSplitCommitmentV1.model_validate(self.model_dump(mode="json"))
        except ValueError as error:
            raise ValueError("pair split accessor requires a validated public split") from error
        if type(name) is not PairSplitPartitionV1:
            raise ValueError("pair split partition must be a typed enum value")
        return tuple(pair for pair in verified.pairs if pair.partition is name)
