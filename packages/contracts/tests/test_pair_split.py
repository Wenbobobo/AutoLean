from __future__ import annotations

import hashlib
from typing import cast

import pytest
from pydantic import ValidationError

from autolean_contracts import (
    AtomicPairCommitmentV1,
    PairLevelSplitCommitmentV1,
    PairSplitAuthorityV1,
    PairSplitPartitionV1,
    canonical_json_bytes,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _pair(
    index: int,
    partition: PairSplitPartitionV1,
    *,
    family: str,
) -> AtomicPairCommitmentV1:
    payload: dict[str, object] = {
        "schema_version": "autolean.atomic-pair-commitment.v1",
        "opaque_pair_id": f"opaque.pair.{index:02d}",
        "partition": partition,
        "source_id_commitment": _digest(f"source-id:{family}"),
        "scenario_commitment": _digest(f"scenario:{family}"),
        "source_commitment": _digest(f"source:{family}"),
        "source_span_id_commitment": _digest(f"span-id:{family}"),
        "source_span_commitment": _digest(f"span:{family}"),
        "mutation_commitment": _digest(f"mutation:{family}"),
        "witness_commitment": _digest(f"witness:{family}"),
        "rights_commitment": _digest("rights:apache-2.0"),
        "private_pair_payload_commitment": _digest(f"private-payload:{index}"),
        "authority": PairSplitAuthorityV1().model_dump(mode="json"),
    }
    payload["pair_commitment"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return AtomicPairCommitmentV1.model_validate(payload)


def _split(
    pairs: tuple[AtomicPairCommitmentV1, ...] | None = None,
) -> PairLevelSplitCommitmentV1:
    selected = pairs or (
        _pair(1, PairSplitPartitionV1.TRAIN, family="train-a"),
        _pair(2, PairSplitPartitionV1.TRAIN, family="train-a"),
        _pair(3, PairSplitPartitionV1.DEV, family="dev-a"),
        _pair(4, PairSplitPartitionV1.DEV, family="dev-a"),
        _pair(5, PairSplitPartitionV1.PRIVATE_HELDOUT, family="heldout-a"),
        _pair(6, PairSplitPartitionV1.PRIVATE_HELDOUT, family="heldout-a"),
    )
    payload: dict[str, object] = {
        "schema_version": "autolean.pair-level-split-commitment.v1",
        "split_id": "split." + _digest("ifem.synthetic.pairs.v1")[:48],
        "split_revision": "rev." + _digest("revision:1")[:48],
        "commitment_scheme": "hmac-sha256-domain-separated-v1",
        "nonsecret_key_id": "key." + _digest("operator.pair-commitment.v1")[:48],
        "private_manifest_commitment": _digest("private-manifest"),
        "pairs": [pair.model_dump(mode="json") for pair in selected],
        "authority": PairSplitAuthorityV1().model_dump(mode="json"),
    }
    payload["split_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return PairLevelSplitCommitmentV1.model_validate(payload)


def test_pair_split_is_public_pair_atomic_and_non_authoritative() -> None:
    split = _split()

    assert len(split.partition(PairSplitPartitionV1.TRAIN)) == 2
    assert len(split.partition(PairSplitPartitionV1.DEV)) == 2
    assert len(split.partition(PairSplitPartitionV1.PRIVATE_HELDOUT)) == 2
    assert not split.authority.payload_disclosed
    assert not split.authority.oracle_disclosed
    assert not split.authority.semantic_equivalence_claimed
    assert not split.authority.public_partition_authentication_claimed
    assert split.authority.private_reverification_required
    assert not split.authority.release_authority
    with pytest.raises(ValueError, match="typed enum"):
        split.partition(cast(PairSplitPartitionV1, "train"))

    rendered = canonical_json_bytes(split)
    for forbidden in (
        b'"baseline_payload"',
        b'"mutant_payload"',
        b'"oracle"',
        b'"witness"',
        b'"source_text"',
        b'"source_locator"',
        b'"prompt"',
        b'"private_root"',
    ):
        assert forbidden not in rendered


@pytest.mark.parametrize(
    "field_name",
    [
        "source_id_commitment",
        "scenario_commitment",
        "source_commitment",
        "source_span_id_commitment",
        "source_span_commitment",
        "mutation_commitment",
        "witness_commitment",
    ],
)
def test_identity_commitments_cannot_cross_partitions(field_name: str) -> None:
    valid = _split()
    pairs = list(valid.pairs)
    dev_payload = pairs[2].model_dump(mode="json")
    dev_payload[field_name] = getattr(pairs[0], field_name)
    dev_payload.pop("pair_commitment")
    dev_payload["pair_commitment"] = hashlib.sha256(canonical_json_bytes(dev_payload)).hexdigest()
    pairs[2] = AtomicPairCommitmentV1.model_validate(dev_payload)

    payload = valid.model_dump(mode="json")
    payload["pairs"] = [pair.model_dump(mode="json") for pair in pairs]
    payload.pop("split_sha256")
    payload["split_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    with pytest.raises(ValidationError, match="cannot cross"):
        PairLevelSplitCommitmentV1.model_validate(payload)


def test_pair_and_split_tampering_fail_after_rehash_attempts() -> None:
    valid = _split()
    pair_payload = valid.pairs[0].model_dump(mode="json")
    pair_payload["pair_commitment"] = "0" * 64
    with pytest.raises(ValidationError, match="atomic pair commitment differs"):
        AtomicPairCommitmentV1.model_validate(pair_payload)

    unsafe_payload = valid.model_dump(mode="python")
    unsafe_authority = valid.authority.model_dump(mode="python")
    unsafe_authority["release_authority"] = True
    unsafe_payload["authority"] = PairSplitAuthorityV1.model_construct(**unsafe_authority)
    unsafe = PairLevelSplitCommitmentV1.model_construct(**unsafe_payload)
    with pytest.raises(ValueError, match="validated public split"):
        unsafe.partition(PairSplitPartitionV1.TRAIN)

    split_payload = valid.model_dump(mode="json")
    split_payload["private_manifest_commitment"] = "1" * 64
    with pytest.raises(ValidationError, match="split hash differs"):
        PairLevelSplitCommitmentV1.model_validate(split_payload)

    unsafe_authority = PairSplitAuthorityV1.model_construct(payload_disclosed=True)
    unsafe_payload = valid.model_dump(mode="python")
    unsafe_payload["authority"] = unsafe_authority
    unsafe = PairLevelSplitCommitmentV1.model_construct(**unsafe_payload)
    with pytest.raises(ValidationError):
        PairLevelSplitCommitmentV1.model_validate(unsafe.model_dump(mode="json"))


def test_pair_ids_must_be_canonical_and_all_partitions_present() -> None:
    valid = _split()
    reversed_payload = valid.model_dump(mode="json")
    reversed_payload["pairs"] = list(reversed(cast(list[object], reversed_payload["pairs"])))
    reversed_payload.pop("split_sha256")
    reversed_payload["split_sha256"] = hashlib.sha256(
        canonical_json_bytes(reversed_payload)
    ).hexdigest()
    with pytest.raises(ValidationError, match="canonical and unique"):
        PairLevelSplitCommitmentV1.model_validate(reversed_payload)

    missing_payload = valid.model_dump(mode="json")
    missing_payload["pairs"] = [
        pair
        for pair in cast(list[dict[str, object]], missing_payload["pairs"])
        if pair["partition"] != PairSplitPartitionV1.PRIVATE_HELDOUT
    ]
    missing_payload.pop("split_sha256")
    missing_payload["split_sha256"] = hashlib.sha256(
        canonical_json_bytes(missing_payload)
    ).hexdigest()
    with pytest.raises(ValidationError, match="must contain"):
        PairLevelSplitCommitmentV1.model_validate(missing_payload)
