"""Operator-private pair manifests and public held-out commitments.

Private inputs, labels, witnesses, and source records remain in this Builder-side
boundary.  Only domain-separated keyed commitments are projected into the public
contracts package.  This module neither persists private data nor authorizes a
model request; storage and one-shot evaluation are later operator concerns.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal, Never, Self

from autolean_contracts import (
    AtomicPairCommitmentV1,
    PairLevelSplitCommitmentV1,
    PairSplitAuthorityV1,
    PairSplitPartitionV1,
    RightsRecordV1,
    SourceRecordV1,
    SourceSpanV1,
    StableIdentifierV1,
    canonical_json_bytes,
)
from autolean_contracts.base import ContractModel
from pydantic import Field, field_validator, model_validator

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")
_DOMAIN = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")
_COMMITMENT_PREFIX = b"autolean.private-pair-commitment.v1\0"
_COMMITMENT_SCHEME = "hmac-sha256-domain-separated-v1"
_PUBLIC_KEY_ID = re.compile(r"^key\.[0-9a-f]{32,64}$")


class PrivatePairSplitError(ValueError):
    """A private pair manifest or its public commitment is invalid."""


class PrivatePairSplitAuthorityV1(ContractModel):
    """Hard-negative authority for the pre-evaluation private manifest."""

    schema_version: Literal["autolean.private-pair-split-authority.v1"] = (
        "autolean.private-pair-split-authority.v1"
    )
    evidence_class: Literal["operator_private_partition_input_only"] = (
        "operator_private_partition_input_only"
    )
    semantic_equivalence_claimed: Literal[False] = False
    model_egress_authorized: Literal[False] = False
    model_evaluation_authorized: Literal[False] = False
    tuning_on_private_heldout_allowed: Literal[False] = False
    statement_contract_created: Literal[False] = False
    freeze_allowed: Literal[False] = False
    prover_handoff_allowed: Literal[False] = False
    promotion_allowed: Literal[False] = False


class _PrivatePairPayloadV1(ContractModel):
    """Shared private payload before or after deterministic partitioning."""

    pair_id: str = Field(pattern=_IDENTIFIER.pattern)
    scenario_family: object
    source: SourceRecordV1
    source_span_id: StableIdentifierV1
    rights: RightsRecordV1
    mutation_template: object
    witness: object
    baseline_payload: object
    mutant_payload: object
    oracle: object
    authority: PrivatePairSplitAuthorityV1 = Field(default_factory=PrivatePairSplitAuthorityV1)

    @field_validator(
        "scenario_family",
        "mutation_template",
        "witness",
        "baseline_payload",
        "mutant_payload",
        "oracle",
    )
    @classmethod
    def validate_json_payload(cls, value: object) -> object:
        try:
            canonical_json_bytes(value)
        except (TypeError, ValueError) as error:
            raise ValueError("private pair fields must contain canonical JSON values") from error
        return value

    @model_validator(mode="after")
    def validate_record(self) -> Self:
        if self.rights.source_id != self.source.source_id:
            raise ValueError("private pair rights do not bind its source record")
        matching_spans = tuple(
            span for span in self.source.spans if span.span_id == self.source_span_id
        )
        if len(matching_spans) != 1:
            raise ValueError("private pair must bind exactly one source span")
        if canonical_json_bytes(self.baseline_payload) == canonical_json_bytes(self.mutant_payload):
            raise ValueError("private pair baseline and mutant payloads must differ")
        return self


class PrivatePairCandidateV1(_PrivatePairPayloadV1):
    """One unpartitioned pair supplied to the deterministic split builder."""

    schema_version: Literal["autolean.private-pair-candidate.v1"] = (
        "autolean.private-pair-candidate.v1"
    )


class PrivatePairRecordV1(_PrivatePairPayloadV1):
    """One indivisible private baseline/mutant record after partitioning."""

    schema_version: Literal["autolean.private-pair-record.v1"] = "autolean.private-pair-record.v1"
    partition: PairSplitPartitionV1


class PrivatePairComponentAllocationV1(ContractModel):
    """Number of leakage-connected components assigned to each partition."""

    schema_version: Literal["autolean.private-pair-component-allocation.v1"] = (
        "autolean.private-pair-component-allocation.v1"
    )
    train: int = Field(ge=1)
    dev: int = Field(ge=1)
    private_heldout: int = Field(ge=1)

    @property
    def total(self) -> int:
        return self.train + self.dev + self.private_heldout


class PrivatePairSplitManifestV1(ContractModel):
    """Complete private split before any held-out model evaluation."""

    schema_version: Literal["autolean.private-pair-split-manifest.v1"] = (
        "autolean.private-pair-split-manifest.v1"
    )
    manifest_id: str = Field(pattern=_IDENTIFIER.pattern)
    manifest_revision: str = Field(min_length=1, max_length=128)
    split_strategy: Literal["sha256-ranked-leakage-components-v1"] = (
        "sha256-ranked-leakage-components-v1"
    )
    split_seed: str = Field(min_length=1, max_length=256)
    component_count: int = Field(ge=3)
    component_allocation: PrivatePairComponentAllocationV1
    records: tuple[PrivatePairRecordV1, ...] = Field(min_length=3)
    authority: PrivatePairSplitAuthorityV1 = Field(default_factory=PrivatePairSplitAuthorityV1)

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        identities = tuple(record.pair_id for record in self.records)
        if identities != tuple(sorted(set(identities))):
            raise ValueError("private pair identifiers must be canonical and unique")
        if {record.partition for record in self.records} != set(PairSplitPartitionV1):
            raise ValueError("private pair manifest must contain every partition")
        components = _identity_components(self.records)
        expected_partitions, expected_allocation = _allocate_components(
            components,
            split_seed=self.split_seed,
        )
        if self.component_count != len(components):
            raise ValueError("private pair component count differs from its identity closure")
        if self.component_allocation != expected_allocation:
            raise ValueError("private pair component allocation differs from its split strategy")
        if any(
            record.partition is not expected_partitions[record.pair_id] for record in self.records
        ):
            raise ValueError("private pair partition differs from deterministic component split")
        for identity_name, identity_of in (
            ("source_id", lambda record: record.source.source_id),
            ("scenario_family", lambda record: record.scenario_family),
            ("source_content", lambda record: record.source.content_hash),
            ("source_span_id", lambda record: record.source_span_id),
            (
                "source_span_content",
                lambda record: _bound_source_span(record).content_hash,
            ),
            ("mutation_template", lambda record: record.mutation_template),
            ("witness", lambda record: record.witness),
        ):
            observed: dict[bytes, PairSplitPartitionV1] = {}
            for record in self.records:
                identity = canonical_json_bytes(identity_of(record))
                prior = observed.setdefault(identity, record.partition)
                if prior is not record.partition:
                    raise ValueError(
                        f"private {identity_name} identity cannot cross split partitions"
                    )
        return self

    def assert_no_tuning_access(self, partition: PairSplitPartitionV1) -> None:
        if type(partition) is not PairSplitPartitionV1:
            raise PrivatePairSplitError("pair split partition must be a typed enum value")
        if partition is PairSplitPartitionV1.PRIVATE_HELDOUT:
            raise PrivatePairSplitError(
                "private-heldout records cannot be read by training, tuning, or prompt selection"
            )


def build_private_pair_split_manifest(
    candidates: tuple[PrivatePairCandidateV1, ...],
    *,
    manifest_id: str,
    manifest_revision: str,
    split_seed: str,
) -> PrivatePairSplitManifestV1:
    """Assign leakage-connected pair components with stable SHA-256 ranking."""

    if not candidates:
        raise PrivatePairSplitError("private pair split requires candidate pairs")
    verified: list[PrivatePairCandidateV1] = []
    for candidate in candidates:
        if type(candidate) is not PrivatePairCandidateV1:
            raise PrivatePairSplitError("private pair split requires PrivatePairCandidateV1 inputs")
        try:
            verified.append(
                PrivatePairCandidateV1.model_validate(candidate.model_dump(mode="json"))
            )
        except ValueError as error:
            raise PrivatePairSplitError(
                "private pair split requires revalidated, non-model-constructed candidates"
            ) from error
    ordered = tuple(sorted(verified, key=lambda candidate: candidate.pair_id))
    pair_ids = tuple(candidate.pair_id for candidate in ordered)
    if pair_ids != tuple(sorted(set(pair_ids))):
        raise PrivatePairSplitError("private pair candidate IDs must be canonical and unique")
    try:
        components = _identity_components(ordered)
        partition_by_pair, allocation = _allocate_components(
            components,
            split_seed=split_seed,
        )
    except ValueError as error:
        raise PrivatePairSplitError(str(error)) from error
    records = tuple(
        PrivatePairRecordV1.model_validate(
            {
                **candidate.model_dump(mode="json", exclude={"schema_version"}),
                "schema_version": "autolean.private-pair-record.v1",
                "partition": partition_by_pair[candidate.pair_id],
            }
        )
        for candidate in ordered
    )
    try:
        return PrivatePairSplitManifestV1(
            manifest_id=manifest_id,
            manifest_revision=manifest_revision,
            split_seed=split_seed,
            component_count=len(components),
            component_allocation=allocation,
            records=records,
        )
    except ValueError as error:
        raise PrivatePairSplitError("deterministic private pair split did not validate") from error


def _identity_components(
    records: tuple[_PrivatePairPayloadV1, ...],
) -> tuple[tuple[_PrivatePairPayloadV1, ...], ...]:
    if len(records) < 3:
        raise ValueError("private pair split requires at least three candidate pairs")
    parent = list(range(len(records)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    first_by_identity: dict[tuple[str, bytes], int] = {}
    for index, record in enumerate(records):
        identities = (
            ("source_id", canonical_json_bytes(record.source.source_id)),
            ("scenario", canonical_json_bytes(record.scenario_family)),
            ("source", canonical_json_bytes(record.source.content_hash)),
            ("source_span_id", canonical_json_bytes(record.source_span_id)),
            ("source_span", canonical_json_bytes(_bound_source_span(record).content_hash)),
            ("mutation", canonical_json_bytes(record.mutation_template)),
            ("witness", canonical_json_bytes(record.witness)),
        )
        for identity in identities:
            prior = first_by_identity.setdefault(identity, index)
            union(prior, index)

    grouped: dict[int, list[_PrivatePairPayloadV1]] = {}
    for index, record in enumerate(records):
        grouped.setdefault(find(index), []).append(record)
    components = tuple(
        sorted(
            (
                tuple(sorted(component, key=lambda record: record.pair_id))
                for component in grouped.values()
            ),
            key=lambda component: tuple(record.pair_id for record in component),
        )
    )
    if len(components) < 3:
        raise ValueError(
            "private pair identities form fewer than three leakage-independent components"
        )
    return components


def _allocate_components(
    components: tuple[tuple[_PrivatePairPayloadV1, ...], ...],
    *,
    split_seed: str,
) -> tuple[dict[str, PairSplitPartitionV1], PrivatePairComponentAllocationV1]:
    if not split_seed or split_seed != split_seed.strip() or len(split_seed) > 256:
        raise ValueError("private pair split seed must be a bounded, trimmed string")
    component_count = len(components)
    heldout_count = max(1, component_count // 4)
    dev_count = max(1, component_count // 4)
    train_count = component_count - heldout_count - dev_count
    if train_count < 1:
        raise ValueError("private pair split lacks an independent train component")

    def rank(component: tuple[_PrivatePairPayloadV1, ...]) -> tuple[bytes, tuple[str, ...]]:
        pair_ids = tuple(record.pair_id for record in component)
        component_identities = tuple(
            sorted(
                (_component_rank_identity(record) for record in component),
                key=canonical_json_bytes,
            )
        )
        digest = hashlib.sha256(
            canonical_json_bytes(
                {
                    "schema_version": "autolean.private-pair-component-rank.v1",
                    "split_seed": split_seed,
                    "component_identities": component_identities,
                }
            )
        ).digest()
        return digest, pair_ids

    ranked = tuple(sorted(components, key=rank))
    partition_by_pair: dict[str, PairSplitPartitionV1] = {}
    for index, component in enumerate(ranked):
        if index < heldout_count:
            partition = PairSplitPartitionV1.PRIVATE_HELDOUT
        elif index < heldout_count + dev_count:
            partition = PairSplitPartitionV1.DEV
        else:
            partition = PairSplitPartitionV1.TRAIN
        for record in component:
            partition_by_pair[record.pair_id] = partition
    return partition_by_pair, PrivatePairComponentAllocationV1(
        train=train_count,
        dev=dev_count,
        private_heldout=heldout_count,
    )


def _component_rank_identity(record: _PrivatePairPayloadV1) -> dict[str, object]:
    span = _bound_source_span(record)
    return {
        "scenario_family": record.scenario_family,
        "source_id": record.source.source_id.model_dump(mode="json"),
        "source_content_hash": record.source.content_hash.model_dump(mode="json"),
        "source_span_id": record.source_span_id.model_dump(mode="json"),
        "source_span_content_hash": span.content_hash.model_dump(mode="json"),
        "mutation_template": record.mutation_template,
        "witness": record.witness,
        "rights": record.rights.model_dump(mode="json"),
    }


class PairCommitmentAuthenticator(ABC):
    """Injected keyed-commitment boundary; production keys stay non-exportable."""

    @property
    @abstractmethod
    def nonsecret_key_id(self) -> str:
        """Return a stable, non-secret key label."""

    @property
    @abstractmethod
    def commitment_scheme(self) -> str:
        """Return the authenticated commitment algorithm identifier."""

    @abstractmethod
    def commit(self, *, domain: str, payload: object) -> str:
        """Return a domain-separated commitment without exposing key material."""

    def __getstate__(self) -> Never:
        raise TypeError("pair commitment authenticator cannot be serialized")

    def __reduce_ex__(self, protocol: Any) -> Never:
        del protocol
        raise TypeError("pair commitment authenticator cannot be serialized")


@dataclass(frozen=True, slots=True)
class LocalHmacPairCommitmentAuthenticatorFixture(PairCommitmentAuthenticator):
    """Deterministic local fixture; production must inject KMS/HSM-backed commitments."""

    key_id: str
    secret: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if _IDENTIFIER.fullmatch(self.key_id) is None:
            raise PrivatePairSplitError("pair commitment key ID is not a safe identifier")
        if not isinstance(self.secret, bytes) or len(self.secret) < 32:
            raise PrivatePairSplitError(
                "test-only pair commitment secret must contain at least 32 bytes"
            )

    @property
    def nonsecret_key_id(self) -> str:
        digest = hmac.new(
            self.secret,
            _COMMITMENT_PREFIX + b"public-key-handle\0" + self.key_id.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return "key." + digest[:48]

    @property
    def commitment_scheme(self) -> str:
        return _COMMITMENT_SCHEME

    def commit(self, *, domain: str, payload: object) -> str:
        if _DOMAIN.fullmatch(domain) is None:
            raise PrivatePairSplitError("pair commitment domain is not a safe identifier")
        preimage = (
            _COMMITMENT_PREFIX + domain.encode("ascii") + b"\0" + canonical_json_bytes(payload)
        )
        return hmac.new(self.secret, preimage, hashlib.sha256).hexdigest()


def commit_private_pair_split(
    manifest: PrivatePairSplitManifestV1,
    *,
    authenticator: PairCommitmentAuthenticator,
) -> PairLevelSplitCommitmentV1:
    """Project one revalidated private manifest into public commitments."""

    verified = _revalidate_manifest(manifest)
    if type(authenticator) is not LocalHmacPairCommitmentAuthenticatorFixture:
        raise PrivatePairSplitError(
            "pair commitment implementation lacks a verified HMAC/KMS adapter"
        )
    key_id = authenticator.nonsecret_key_id
    if _PUBLIC_KEY_ID.fullmatch(key_id) is None:
        raise PrivatePairSplitError("pair commitment authenticator returned an unsafe key ID")
    if authenticator.commitment_scheme != _COMMITMENT_SCHEME:
        raise PrivatePairSplitError(
            "pair commitment authenticator does not attest the required HMAC scheme"
        )

    split_id = (
        "split."
        + authenticator.commit(domain="split-id", payload={"manifest_id": verified.manifest_id})[
            :48
        ]
    )
    split_revision = (
        "rev."
        + authenticator.commit(
            domain="split-revision", payload={"manifest_revision": verified.manifest_revision}
        )[:48]
    )

    public_pairs = tuple(
        sorted(
            (
                _commit_private_record(record, authenticator=authenticator)
                for record in verified.records
            ),
            key=lambda pair: pair.opaque_pair_id,
        )
    )
    payload: dict[str, object] = {
        "schema_version": "autolean.pair-level-split-commitment.v1",
        "split_id": split_id,
        "split_revision": split_revision,
        "commitment_scheme": _COMMITMENT_SCHEME,
        "nonsecret_key_id": key_id,
        "private_manifest_commitment": authenticator.commit(
            domain="private-manifest",
            payload=verified.model_dump(mode="json"),
        ),
        "pairs": [pair.model_dump(mode="json") for pair in public_pairs],
        "authority": PairSplitAuthorityV1().model_dump(mode="json"),
    }
    payload["split_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    try:
        return PairLevelSplitCommitmentV1.model_validate(payload)
    except ValueError as error:
        raise PrivatePairSplitError("public pair split commitment did not validate") from error


def verify_private_pair_split_commitment(
    manifest: PrivatePairSplitManifestV1,
    public: PairLevelSplitCommitmentV1,
    *,
    authenticator: PairCommitmentAuthenticator,
) -> PairLevelSplitCommitmentV1:
    """Recompute a public split from private inputs and compare exact contracts."""

    if type(public) is not PairLevelSplitCommitmentV1:
        raise PrivatePairSplitError("public split is not a PairLevelSplitCommitmentV1")
    try:
        verified_public = PairLevelSplitCommitmentV1.model_validate(public.model_dump(mode="json"))
    except ValueError as error:
        raise PrivatePairSplitError("public pair split commitment is invalid") from error
    expected = commit_private_pair_split(manifest, authenticator=authenticator)
    if verified_public != expected:
        raise PrivatePairSplitError("public pair split differs from its private manifest")
    return verified_public


def _commit_private_record(
    record: PrivatePairRecordV1,
    *,
    authenticator: PairCommitmentAuthenticator,
) -> AtomicPairCommitmentV1:
    span = _bound_source_span(record)
    commit = authenticator.commit
    opaque_digest = commit(domain="pair-id", payload={"pair_id": record.pair_id})
    payload: dict[str, object] = {
        "schema_version": "autolean.atomic-pair-commitment.v1",
        "opaque_pair_id": f"pair.{opaque_digest[:48]}",
        "partition": record.partition,
        "source_id_commitment": commit(
            domain="source-id-identity", payload=record.source.source_id.model_dump(mode="json")
        ),
        "scenario_commitment": commit(domain="scenario-identity", payload=record.scenario_family),
        "source_commitment": commit(
            domain="source-identity", payload=record.source.content_hash.model_dump(mode="json")
        ),
        "source_span_id_commitment": commit(
            domain="source-span-id-identity", payload=record.source_span_id.model_dump(mode="json")
        ),
        "source_span_commitment": commit(
            domain="source-span-identity", payload=span.content_hash.model_dump(mode="json")
        ),
        "mutation_commitment": commit(domain="mutation-identity", payload=record.mutation_template),
        "witness_commitment": commit(domain="witness-identity", payload=record.witness),
        "rights_commitment": commit(
            domain="rights-record", payload=record.rights.model_dump(mode="json")
        ),
        "private_pair_payload_commitment": commit(
            domain="private-pair-payload", payload=record.model_dump(mode="json")
        ),
        "authority": PairSplitAuthorityV1().model_dump(mode="json"),
    }
    payload["pair_commitment"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    try:
        return AtomicPairCommitmentV1.model_validate(payload)
    except ValueError as error:
        raise PrivatePairSplitError("private pair did not produce a valid commitment") from error


def _revalidate_manifest(manifest: PrivatePairSplitManifestV1) -> PrivatePairSplitManifestV1:
    if type(manifest) is not PrivatePairSplitManifestV1:
        raise PrivatePairSplitError("pair split requires a PrivatePairSplitManifestV1 input")
    try:
        return PrivatePairSplitManifestV1.model_validate(manifest.model_dump(mode="json"))
    except ValueError as error:
        raise PrivatePairSplitError(
            "pair split requires a revalidated, non-model-constructed manifest"
        ) from error


def _bound_source_span(record: _PrivatePairPayloadV1) -> SourceSpanV1:
    matching = tuple(span for span in record.source.spans if span.span_id == record.source_span_id)
    if len(matching) != 1:
        raise PrivatePairSplitError("private pair no longer binds exactly one source span")
    return matching[0]
