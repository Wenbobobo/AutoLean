"""Separate operator-private stores for tuning and held-out pair partitions.

The local adapter makes the mount boundary explicit and testable. It does not
claim that a single host process is an isolation authority; production must
provide the two roots to distinct OCI workers with disjoint read mounts.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from contextlib import suppress
from pathlib import Path
from typing import Literal, Self

from autolean_contracts import (
    PairLevelSplitCommitmentV1,
    PairSplitPartitionV1,
    canonical_json_bytes,
)
from autolean_contracts.base import ContractModel
from pydantic import Field, model_validator

from .private_pair_split import (
    PairCommitmentAuthenticator,
    PrivatePairRecordV1,
    PrivatePairSplitError,
    PrivatePairSplitManifestV1,
    _commit_private_record,
    verify_private_pair_split_commitment,
)

_SHA256 = r"^[0-9a-f]{64}$"


class PrivatePairPartitionStoreError(PrivatePairSplitError):
    """A private partition escaped or crossed its assigned store capability."""


class PrivatePairPartitionStoreAuthorityV1(ContractModel):
    """Hard-negative authority for local partition materialization."""

    schema_version: Literal["autolean.private-pair-partition-store-authority.v1"] = (
        "autolean.private-pair-partition-store-authority.v1"
    )
    evidence_class: Literal["operator_private_local_partition_storage_only"] = (
        "operator_private_local_partition_storage_only"
    )
    root_paths_public: Literal[False] = False
    private_payload_public: Literal[False] = False
    tuning_can_read_private_heldout: Literal[False] = False
    production_isolation_claimed: Literal[False] = False
    disjoint_oci_mounts_required: Literal[True] = True
    model_evaluation_authority: Literal[False] = False
    semantic_authority: Literal[False] = False
    freeze_allowed: Literal[False] = False
    prover_handoff_allowed: Literal[False] = False
    promotion_allowed: Literal[False] = False


class PrivatePairPartitionPackV1(ContractModel):
    """Canonical private bytes for one complete split partition."""

    schema_version: Literal["autolean.private-pair-partition-pack.v1"] = (
        "autolean.private-pair-partition-pack.v1"
    )
    public_split_sha256: str = Field(pattern=_SHA256)
    partition: PairSplitPartitionV1
    records: tuple[PrivatePairRecordV1, ...] = Field(min_length=1)
    pack_sha256: str = Field(pattern=_SHA256)
    authority: PrivatePairPartitionStoreAuthorityV1 = Field(
        default_factory=PrivatePairPartitionStoreAuthorityV1
    )

    @model_validator(mode="after")
    def validate_pack(self) -> Self:
        pair_ids = tuple(record.pair_id for record in self.records)
        if pair_ids != tuple(sorted(set(pair_ids))):
            raise ValueError("private partition pack pair IDs must be canonical and unique")
        if any(record.partition is not self.partition for record in self.records):
            raise ValueError("private partition pack contains a record from another partition")
        expected = _sha256_json(self.model_dump(mode="json", exclude={"pack_sha256"}))
        if self.pack_sha256 != expected:
            raise ValueError("private partition pack hash differs from its payload")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"))


class PrivatePairPartitionPackRefV1(ContractModel):
    """Operator-private content address without a filesystem path."""

    schema_version: Literal["autolean.private-pair-partition-pack-ref.v1"] = (
        "autolean.private-pair-partition-pack-ref.v1"
    )
    public_split_sha256: str = Field(pattern=_SHA256)
    partition: PairSplitPartitionV1
    pack_sha256: str = Field(pattern=_SHA256)
    size_bytes: int = Field(ge=2, le=1_073_741_824)
    authority: PrivatePairPartitionStoreAuthorityV1 = Field(
        default_factory=PrivatePairPartitionStoreAuthorityV1
    )


class PrivatePairPartitionMaterializationReceiptV1(ContractModel):
    """Private receipt proving that partitions were written to separate stores."""

    schema_version: Literal["autolean.private-pair-partition-materialization-receipt.v1"] = (
        "autolean.private-pair-partition-materialization-receipt.v1"
    )
    public_split_sha256: str = Field(pattern=_SHA256)
    tuning_refs: tuple[PrivatePairPartitionPackRefV1, ...] = Field(min_length=2, max_length=2)
    heldout_ref: PrivatePairPartitionPackRefV1
    roots_disclosed: Literal[False] = False
    receipt_sha256: str = Field(pattern=_SHA256)
    authority: PrivatePairPartitionStoreAuthorityV1 = Field(
        default_factory=PrivatePairPartitionStoreAuthorityV1
    )

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        if any(item.public_split_sha256 != self.public_split_sha256 for item in self.tuning_refs):
            raise ValueError("tuning receipt refs must bind the same public split")
        if self.heldout_ref.public_split_sha256 != self.public_split_sha256:
            raise ValueError("held-out receipt ref must bind the same public split")
        if tuple(item.partition for item in self.tuning_refs) != (
            PairSplitPartitionV1.TRAIN,
            PairSplitPartitionV1.DEV,
        ):
            raise ValueError("tuning receipt must contain train then dev")
        if self.heldout_ref.partition is not PairSplitPartitionV1.PRIVATE_HELDOUT:
            raise ValueError("held-out receipt must bind the private-heldout partition")
        expected = _sha256_json(self.model_dump(mode="json", exclude={"receipt_sha256"}))
        if self.receipt_sha256 != expected:
            raise ValueError("private partition materialization receipt hash differs")
        return self


class LocalPrivatePairPartitionStore:
    """Local content-addressed store constrained to an explicit partition set."""

    def __init__(
        self,
        root: Path,
        *,
        allowed_partitions: frozenset[PairSplitPartitionV1],
        public_split: PairLevelSplitCommitmentV1,
        authenticator: PairCommitmentAuthenticator,
    ) -> None:
        if not isinstance(root, Path) or not root.is_absolute():
            raise PrivatePairPartitionStoreError("private partition root must be absolute")
        if not isinstance(allowed_partitions, frozenset) or not allowed_partitions:
            raise PrivatePairPartitionStoreError("private partition capability must be nonempty")
        if not all(type(item) is PairSplitPartitionV1 for item in allowed_partitions):
            raise PrivatePairPartitionStoreError(
                "private partition capability requires typed partition values"
            )
        if type(public_split) is not PairLevelSplitCommitmentV1:
            raise PrivatePairPartitionStoreError(
                "private partition capability requires a validated public split"
            )
        if not isinstance(authenticator, PairCommitmentAuthenticator):
            raise PrivatePairPartitionStoreError(
                "private partition capability requires a commitment authenticator"
            )
        try:
            self._public_split = PairLevelSplitCommitmentV1.model_validate(
                public_split.model_dump(mode="json")
            )
        except ValueError as error:
            raise PrivatePairPartitionStoreError(
                "private partition public split is invalid"
            ) from error
        self._authenticator = authenticator
        if root.exists() and root.is_symlink():
            raise PrivatePairPartitionStoreError("private partition root cannot be a symlink")
        root.mkdir(parents=True, exist_ok=True)
        self._root = root.resolve(strict=True)
        if not self._root.is_dir():
            raise PrivatePairPartitionStoreError("private partition root must be a directory")
        self._allowed_partitions = allowed_partitions

    @property
    def allowed_partitions(self) -> frozenset[PairSplitPartitionV1]:
        return self._allowed_partitions

    @property
    def public_split_sha256(self) -> str:
        return self._public_split.split_sha256

    def is_isolated_from(self, other: LocalPrivatePairPartitionStore) -> bool:
        return (
            self._root != other._root
            and self._root not in other._root.parents
            and other._root not in self._root.parents
        )

    def put(self, pack: PrivatePairPartitionPackV1) -> PrivatePairPartitionPackRefV1:
        verified = _revalidate_pack(pack)
        self._require_partition(verified.partition)
        self._require_pack_membership(verified)
        payload = verified.canonical_bytes()
        reference = PrivatePairPartitionPackRefV1(
            public_split_sha256=verified.public_split_sha256,
            partition=verified.partition,
            pack_sha256=verified.pack_sha256,
            size_bytes=len(payload),
        )
        target = self._path(reference)
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            temporary = target.parent / f".{target.name}.{secrets.token_hex(16)}.tmp"
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, target)
            finally:
                with suppress(FileNotFoundError):
                    temporary.unlink()
        if target.read_bytes() != payload:
            raise PrivatePairPartitionStoreError(
                "private partition content address contains different bytes"
            )
        self.read(reference)
        return reference

    def read(self, reference: PrivatePairPartitionPackRefV1) -> PrivatePairPartitionPackV1:
        if type(reference) is not PrivatePairPartitionPackRefV1:
            raise PrivatePairPartitionStoreError("private partition reference has the wrong type")
        try:
            verified_ref = PrivatePairPartitionPackRefV1.model_validate(
                reference.model_dump(mode="json")
            )
        except ValueError as error:
            raise PrivatePairPartitionStoreError(
                "private partition reference is invalid"
            ) from error
        self._require_partition(verified_ref.partition)
        if verified_ref.public_split_sha256 != self.public_split_sha256:
            raise PrivatePairPartitionStoreError("private partition ref binds another public split")
        try:
            payload = self._path(verified_ref).read_bytes()
            pack = PrivatePairPartitionPackV1.model_validate_json(payload)
        except (OSError, ValueError) as error:
            raise PrivatePairPartitionStoreError(
                "private partition pack is unavailable or invalid"
            ) from error
        if (
            len(payload) != verified_ref.size_bytes
            or pack.public_split_sha256 != verified_ref.public_split_sha256
            or pack.partition is not verified_ref.partition
            or pack.pack_sha256 != verified_ref.pack_sha256
            or pack.canonical_bytes() != payload
        ):
            raise PrivatePairPartitionStoreError(
                "private partition pack differs from its content address"
            )
        return pack

    def _require_partition(self, partition: PairSplitPartitionV1) -> None:
        if type(partition) is not PairSplitPartitionV1:
            raise PrivatePairPartitionStoreError("partition must be a typed enum value")
        if partition not in self._allowed_partitions:
            raise PrivatePairPartitionStoreError(
                "partition is outside this private store capability"
            )

    def _require_pack_membership(self, pack: PrivatePairPartitionPackV1) -> None:
        if pack.public_split_sha256 != self.public_split_sha256:
            raise PrivatePairPartitionStoreError(
                "private partition pack binds another public split"
            )
        expected_pairs = tuple(
            pair for pair in self._public_split.pairs if pair.partition is pack.partition
        )
        for record in pack.records:
            try:
                committed = _commit_private_record(record, authenticator=self._authenticator)
            except (PrivatePairSplitError, TypeError, ValueError) as error:
                raise PrivatePairPartitionStoreError(
                    "private partition record commitment could not be rebuilt"
                ) from error
            if not any(pair == committed for pair in expected_pairs):
                raise PrivatePairPartitionStoreError(
                    "private partition record is not a member of the authenticated public split"
                )

    def _path(self, reference: PrivatePairPartitionPackRefV1) -> Path:
        candidate = (
            self._root
            / reference.partition.value
            / reference.pack_sha256[:2]
            / f"{reference.pack_sha256[2:]}.json"
        )
        resolved = candidate.resolve(strict=False)
        if self._root not in resolved.parents:
            raise PrivatePairPartitionStoreError("private partition path escaped its store")
        return resolved


def materialize_private_pair_partition_stores(
    *,
    manifest: PrivatePairSplitManifestV1,
    public: PairLevelSplitCommitmentV1,
    authenticator: PairCommitmentAuthenticator,
    tuning_store: LocalPrivatePairPartitionStore,
    heldout_store: LocalPrivatePairPartitionStore,
) -> PrivatePairPartitionMaterializationReceiptV1:
    """Write train/dev and held-out bytes to disjoint capability roots."""

    if (
        type(tuning_store) is not LocalPrivatePairPartitionStore
        or type(heldout_store) is not LocalPrivatePairPartitionStore
    ):
        raise PrivatePairPartitionStoreError("partition materialization requires local stores")
    if tuning_store.allowed_partitions != frozenset(
        {PairSplitPartitionV1.TRAIN, PairSplitPartitionV1.DEV}
    ):
        raise PrivatePairPartitionStoreError("tuning store must allow exactly train and dev")
    if heldout_store.allowed_partitions != frozenset({PairSplitPartitionV1.PRIVATE_HELDOUT}):
        raise PrivatePairPartitionStoreError("held-out store must allow only private-heldout")
    if tuning_store.public_split_sha256 != heldout_store.public_split_sha256:
        raise PrivatePairPartitionStoreError(
            "tuning and held-out stores bind different public splits"
        )
    if not tuning_store.is_isolated_from(heldout_store):
        raise PrivatePairPartitionStoreError(
            "tuning and held-out roots must be disjoint and non-nested"
        )
    try:
        verified_public = verify_private_pair_split_commitment(
            manifest,
            public,
            authenticator=authenticator,
        )
    except PrivatePairSplitError as error:
        raise PrivatePairPartitionStoreError(
            "private partition materialization inputs are invalid"
        ) from error
    if tuning_store.public_split_sha256 != verified_public.split_sha256:
        raise PrivatePairPartitionStoreError(
            "partition stores are bound to a different public split"
        )
    packs = {
        partition: _build_pack(
            manifest=manifest,
            public_split_sha256=verified_public.split_sha256,
            partition=partition,
        )
        for partition in PairSplitPartitionV1
    }
    tuning_refs = (
        tuning_store.put(packs[PairSplitPartitionV1.TRAIN]),
        tuning_store.put(packs[PairSplitPartitionV1.DEV]),
    )
    heldout_ref = heldout_store.put(packs[PairSplitPartitionV1.PRIVATE_HELDOUT])
    payload: dict[str, object] = {
        "schema_version": "autolean.private-pair-partition-materialization-receipt.v1",
        "public_split_sha256": verified_public.split_sha256,
        "tuning_refs": [item.model_dump(mode="json") for item in tuning_refs],
        "heldout_ref": heldout_ref.model_dump(mode="json"),
        "roots_disclosed": False,
        "authority": PrivatePairPartitionStoreAuthorityV1().model_dump(mode="json"),
    }
    payload["receipt_sha256"] = _sha256_json(payload)
    return PrivatePairPartitionMaterializationReceiptV1.model_validate(payload)


def _build_pack(
    *,
    manifest: PrivatePairSplitManifestV1,
    public_split_sha256: str,
    partition: PairSplitPartitionV1,
) -> PrivatePairPartitionPackV1:
    records = tuple(record for record in manifest.records if record.partition is partition)
    payload: dict[str, object] = {
        "schema_version": "autolean.private-pair-partition-pack.v1",
        "public_split_sha256": public_split_sha256,
        "partition": partition,
        "records": [record.model_dump(mode="json") for record in records],
        "authority": PrivatePairPartitionStoreAuthorityV1().model_dump(mode="json"),
    }
    payload["pack_sha256"] = _sha256_json(payload)
    return PrivatePairPartitionPackV1.model_validate(payload)


def _revalidate_pack(pack: PrivatePairPartitionPackV1) -> PrivatePairPartitionPackV1:
    if type(pack) is not PrivatePairPartitionPackV1:
        raise PrivatePairPartitionStoreError("private partition pack has the wrong type")
    try:
        return PrivatePairPartitionPackV1.model_validate(pack.model_dump(mode="json"))
    except ValueError as error:
        raise PrivatePairPartitionStoreError(
            "private partition pack is invalid or model-constructed"
        ) from error


def _sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()
