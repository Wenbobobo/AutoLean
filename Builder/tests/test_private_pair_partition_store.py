from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from autolean_builder.private_pair_partition_store import (
    LocalPrivatePairPartitionStore,
    PrivatePairPartitionPackV1,
    PrivatePairPartitionStoreAuthorityV1,
    PrivatePairPartitionStoreError,
    materialize_private_pair_partition_stores,
)
from autolean_builder.private_pair_split import (
    LocalHmacPairCommitmentAuthenticatorFixture,
    PrivatePairCandidateV1,
    PrivatePairSplitAuthorityV1,
    PrivatePairSplitManifestV1,
    build_private_pair_split_manifest,
    commit_private_pair_split,
)
from autolean_contracts import (
    HashKindV1,
    PairLevelSplitCommitmentV1,
    PairSplitPartitionV1,
    PermissionDecisionV1,
    RightsRecordV1,
    SourceRecordV1,
    SourceSpanV1,
    canonical_json_bytes,
    digest_text,
    stable_identifier,
)

_KEY = LocalHmacPairCommitmentAuthenticatorFixture(
    key_id="test.partition-store.key.v1",
    secret=b"private-partition-store-test-key-material-00000001",
)


def _candidate(index: int) -> PrivatePairCandidateV1:
    family = f"store-{index}"
    text = f"PRIVATE-STORE-SOURCE-{index}"
    source_id = stable_identifier("private-store-source", family)
    span_id = stable_identifier("private-store-span", family)
    source = SourceRecordV1(
        source_id=source_id,
        work_id=f"private-store-work-{index}",
        title=f"Private store fixture {index}",
        version="1",
        locator=f"operator-private://store/{index}",
        content_hash=digest_text(HashKindV1.SOURCE_BYTES, text),
        retrieved_at=datetime(2026, 7, 30, tzinfo=UTC),
        spans=(
            SourceSpanV1(
                span_id=span_id,
                locator=f"operator-private://store/{index}#statement",
                content_hash=digest_text(HashKindV1.SOURCE_SPAN, text),
                permitted_excerpt=text,
            ),
        ),
    )
    rights = RightsRecordV1(
        rights_id=stable_identifier("private-store-rights", family),
        source_id=source_id,
        source_license="Apache-2.0",
        overall_decision=PermissionDecisionV1.RESTRICTED,
        redistribution=PermissionDecisionV1.ALLOW,
        model_egress=PermissionDecisionV1.DENY,
        allowed_endpoint_classes=(),
        restrictions=("operator-private-only",),
    )
    return PrivatePairCandidateV1(
        pair_id=f"private.store.pair.{index:02d}",
        scenario_family={"scenario": f"PRIVATE-STORE-SCENARIO-{index}"},
        source=source,
        source_span_id=span_id,
        rights=rights,
        mutation_template={"mutation": f"PRIVATE-STORE-MUTATION-{index}"},
        witness={"witness": f"PRIVATE-STORE-WITNESS-{index}"},
        baseline_payload={"candidate": f"PRIVATE-STORE-BASELINE-{index}"},
        mutant_payload={"candidate": f"PRIVATE-STORE-MUTANT-{index}"},
        oracle={"expected": f"PRIVATE-STORE-ORACLE-{index}"},
    )


def _inputs() -> tuple[
    PrivatePairSplitManifestV1,
    PairLevelSplitCommitmentV1,
]:
    manifest = build_private_pair_split_manifest(
        tuple(_candidate(index) for index in range(1, 7)),
        manifest_id="private.store.split.v1",
        manifest_revision="1",
        split_seed="private-store-split-v1",
    )
    public = commit_private_pair_split(manifest, authenticator=_KEY)
    return manifest, public


def _stores(
    tmp_path: Path,
    public_split: PairLevelSplitCommitmentV1,
) -> tuple[LocalPrivatePairPartitionStore, LocalPrivatePairPartitionStore]:
    return (
        LocalPrivatePairPartitionStore(
            (tmp_path / "tuning").resolve(),
            allowed_partitions=frozenset({PairSplitPartitionV1.TRAIN, PairSplitPartitionV1.DEV}),
            public_split=public_split,
            authenticator=_KEY,
        ),
        LocalPrivatePairPartitionStore(
            (tmp_path / "heldout").resolve(),
            allowed_partitions=frozenset({PairSplitPartitionV1.PRIVATE_HELDOUT}),
            public_split=public_split,
            authenticator=_KEY,
        ),
    )


def test_partition_materialization_keeps_heldout_out_of_tuning_root(tmp_path: Path) -> None:
    manifest, public = _inputs()
    tuning_store, heldout_store = _stores(tmp_path, public)
    receipt = materialize_private_pair_partition_stores(
        manifest=manifest,
        public=public,
        authenticator=_KEY,
        tuning_store=tuning_store,
        heldout_store=heldout_store,
    )

    assert tuple(reference.partition for reference in receipt.tuning_refs) == (
        PairSplitPartitionV1.TRAIN,
        PairSplitPartitionV1.DEV,
    )
    assert receipt.heldout_ref.partition is PairSplitPartitionV1.PRIVATE_HELDOUT
    assert all(tuning_store.read(reference).records for reference in receipt.tuning_refs)
    assert heldout_store.read(receipt.heldout_ref).records
    with pytest.raises(PrivatePairPartitionStoreError, match="outside this private store"):
        tuning_store.read(receipt.heldout_ref)
    with pytest.raises(PrivatePairPartitionStoreError, match="outside this private store"):
        heldout_store.read(receipt.tuning_refs[0])

    public_receipt_bytes = canonical_json_bytes(receipt)
    assert str((tmp_path / "tuning").resolve()).encode() not in public_receipt_bytes
    assert str((tmp_path / "heldout").resolve()).encode() not in public_receipt_bytes
    assert b"PRIVATE-STORE" not in public_receipt_bytes
    assert not receipt.authority.production_isolation_claimed
    assert receipt.authority.disjoint_oci_mounts_required


def test_nested_roots_and_wrong_capabilities_are_rejected(tmp_path: Path) -> None:
    manifest, public = _inputs()
    parent = LocalPrivatePairPartitionStore(
        (tmp_path / "private").resolve(),
        allowed_partitions=frozenset({PairSplitPartitionV1.TRAIN, PairSplitPartitionV1.DEV}),
        public_split=public,
        authenticator=_KEY,
    )
    nested = LocalPrivatePairPartitionStore(
        (tmp_path / "private" / "heldout").resolve(),
        allowed_partitions=frozenset({PairSplitPartitionV1.PRIVATE_HELDOUT}),
        public_split=public,
        authenticator=_KEY,
    )
    with pytest.raises(PrivatePairPartitionStoreError, match="disjoint and non-nested"):
        materialize_private_pair_partition_stores(
            manifest=manifest,
            public=public,
            authenticator=_KEY,
            tuning_store=parent,
            heldout_store=nested,
        )

    with pytest.raises(PrivatePairPartitionStoreError, match="typed partition"):
        LocalPrivatePairPartitionStore(
            (tmp_path / "invalid").resolve(),
            allowed_partitions=frozenset({cast(PairSplitPartitionV1, "private_heldout")}),
            public_split=public,
            authenticator=_KEY,
        )


def test_tamper_and_model_construct_fail_closed(tmp_path: Path) -> None:
    manifest, public = _inputs()
    tuning_store, heldout_store = _stores(tmp_path, public)
    receipt = materialize_private_pair_partition_stores(
        manifest=manifest,
        public=public,
        authenticator=_KEY,
        tuning_store=tuning_store,
        heldout_store=heldout_store,
    )
    target = heldout_store._path(receipt.heldout_ref)
    target.write_bytes(target.read_bytes() + b"\n")
    with pytest.raises(PrivatePairPartitionStoreError, match="content address"):
        heldout_store.read(receipt.heldout_ref)

    valid_pack = tuning_store.read(receipt.tuning_refs[0])
    payload = valid_pack.model_dump(mode="python")
    authority = valid_pack.authority.model_dump(mode="python")
    authority["production_isolation_claimed"] = True
    payload["authority"] = PrivatePairPartitionStoreAuthorityV1.model_construct(**authority)
    unsafe = PrivatePairPartitionPackV1.model_construct(**payload)
    with pytest.raises(PrivatePairPartitionStoreError, match="model-constructed"):
        tuning_store.put(unsafe)


def test_repartitioned_self_hashed_pack_is_not_a_member_of_the_public_split(
    tmp_path: Path,
) -> None:
    manifest, public = _inputs()
    tuning_store, heldout_store = _stores(tmp_path, public)
    receipt = materialize_private_pair_partition_stores(
        manifest=manifest,
        public=public,
        authenticator=_KEY,
        tuning_store=tuning_store,
        heldout_store=heldout_store,
    )
    payload = heldout_store.read(receipt.heldout_ref).model_dump(mode="json")
    payload["partition"] = PairSplitPartitionV1.TRAIN.value
    for record in cast(list[object], payload["records"]):
        cast(dict[str, object], record)["partition"] = PairSplitPartitionV1.TRAIN.value
    payload["pack_sha256"] = hashlib.sha256(
        canonical_json_bytes({key: value for key, value in payload.items() if key != "pack_sha256"})
    ).hexdigest()
    relabeled = PrivatePairPartitionPackV1.model_validate(payload)
    with pytest.raises(PrivatePairPartitionStoreError, match="member of the authenticated"):
        tuning_store.put(relabeled)


def test_public_split_rebinding_is_rejected_before_partition_write(tmp_path: Path) -> None:
    manifest, public = _inputs()
    tuning_store, heldout_store = _stores(tmp_path, public)
    payload = public.model_dump(mode="python")
    payload["private_manifest_commitment"] = "f" * 64
    rebound = PairLevelSplitCommitmentV1.model_construct(**payload)
    with pytest.raises(PrivatePairPartitionStoreError, match="invalid"):
        materialize_private_pair_partition_stores(
            manifest=manifest,
            public=rebound,
            authenticator=_KEY,
            tuning_store=tuning_store,
            heldout_store=heldout_store,
        )


def test_manifest_type_annotation_is_not_used_as_runtime_authority() -> None:
    assert PrivatePairSplitAuthorityV1().model_evaluation_authorized is False
