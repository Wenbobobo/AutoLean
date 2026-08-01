from __future__ import annotations

import hashlib
import pickle
from datetime import UTC, datetime
from typing import cast

import pytest
from autolean_builder.private_pair_split import (
    LocalHmacPairCommitmentAuthenticatorFixture,
    PairCommitmentAuthenticator,
    PrivatePairCandidateV1,
    PrivatePairRecordV1,
    PrivatePairSplitAuthorityV1,
    PrivatePairSplitError,
    PrivatePairSplitManifestV1,
    build_private_pair_split_manifest,
    commit_private_pair_split,
    verify_private_pair_split_commitment,
)
from autolean_contracts import (
    EndpointClassV1,
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
from pydantic import ValidationError

_KEY = LocalHmacPairCommitmentAuthenticatorFixture(
    key_id="test.operator.pair-key.v1",
    secret=b"private-pair-test-key-material-0000000000000001",
)


def _source(family: str) -> SourceRecordV1:
    text = f"PRIVATE-SOURCE-{family}"
    source_id = stable_identifier("private-pair-source", family)
    return SourceRecordV1(
        source_id=source_id,
        work_id=f"private-pair-{family}",
        title=f"Private synthetic pair {family}",
        version="1",
        locator=f"operator-private://pair/{family}",
        content_hash=digest_text(HashKindV1.SOURCE_BYTES, text),
        retrieved_at=datetime(2026, 7, 30, tzinfo=UTC),
        spans=(
            SourceSpanV1(
                span_id=stable_identifier("private-pair-span", family),
                locator=f"operator-private://pair/{family}#statement",
                content_hash=digest_text(HashKindV1.SOURCE_SPAN, text),
                permitted_excerpt=text,
            ),
        ),
    )


def _rights(source: SourceRecordV1) -> RightsRecordV1:
    return RightsRecordV1(
        rights_id=stable_identifier("private-pair-rights", source.work_id),
        source_id=source.source_id,
        source_license="Apache-2.0",
        overall_decision=PermissionDecisionV1.RESTRICTED,
        redistribution=PermissionDecisionV1.ALLOW,
        model_egress=PermissionDecisionV1.DENY,
        allowed_endpoint_classes=(),
        restrictions=("operator-private-calibration-only", "no-model-egress"),
    )


def _candidate(index: int, family: str) -> PrivatePairCandidateV1:
    source = _source(family)
    return PrivatePairCandidateV1(
        pair_id=f"private.pair.{index:02d}",
        scenario_family={"scenario": f"PRIVATE-SCENARIO-{family}"},
        source=source,
        source_span_id=source.spans[0].span_id,
        rights=_rights(source),
        mutation_template={"mutation": f"PRIVATE-MUTATION-{family}"},
        witness={"witness": f"PRIVATE-WITNESS-{family}"},
        baseline_payload={"candidate": f"PRIVATE-BASELINE-{index}"},
        mutant_payload={"candidate": f"PRIVATE-MUTANT-{index}"},
        oracle={"expected": f"PRIVATE-ORACLE-{index}"},
    )


def _manifest() -> PrivatePairSplitManifestV1:
    return build_private_pair_split_manifest(
        (
            _candidate(1, "family-a"),
            _candidate(2, "family-a"),
            _candidate(3, "family-b"),
            _candidate(4, "family-b"),
            _candidate(5, "family-c"),
            _candidate(6, "family-c"),
            _candidate(7, "family-d"),
            _candidate(8, "family-d"),
            _candidate(9, "family-e"),
            _candidate(10, "family-e"),
            _candidate(11, "family-f"),
            _candidate(12, "family-f"),
            _candidate(13, "family-g"),
            _candidate(14, "family-g"),
            _candidate(15, "family-h"),
            _candidate(16, "family-h"),
        ),
        manifest_id="ifem.private.synthetic.pairs.v1",
        manifest_revision="1",
        split_seed="ifem-private-pair-test-v1",
    )


def test_private_manifest_projects_only_keyed_commitments() -> None:
    manifest = _manifest()
    first = commit_private_pair_split(manifest, authenticator=_KEY)
    second = commit_private_pair_split(manifest, authenticator=_KEY)

    assert first == second
    assert (
        verify_private_pair_split_commitment(
            manifest,
            first,
            authenticator=_KEY,
        )
        == first
    )
    assert first.nonsecret_key_id == _KEY.nonsecret_key_id
    assert len(first.pairs) == len(manifest.records)
    assert manifest.component_count == 8
    assert manifest.component_allocation.train == 4
    assert manifest.component_allocation.dev == 2
    assert manifest.component_allocation.private_heldout == 2
    assert not first.authority.payload_disclosed
    assert not first.authority.oracle_disclosed

    public_bytes = canonical_json_bytes(first)
    for private_value in (
        b"PRIVATE-SOURCE",
        b"PRIVATE-SCENARIO",
        b"PRIVATE-MUTATION",
        b"PRIVATE-WITNESS",
        b"PRIVATE-BASELINE",
        b"PRIVATE-MUTANT",
        b"PRIVATE-ORACLE",
        b"operator-private://",
        manifest.manifest_id.encode("ascii"),
        _KEY.key_id.encode("ascii"),
        _KEY.secret,
    ):
        assert private_value not in public_bytes
    assert _KEY.secret.decode("ascii") not in repr(_KEY)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(_KEY)


def test_wrong_key_and_private_manifest_tampering_are_rejected() -> None:
    manifest = _manifest()
    public = commit_private_pair_split(manifest, authenticator=_KEY)
    wrong_key = LocalHmacPairCommitmentAuthenticatorFixture(
        key_id=_KEY.key_id,
        secret=b"different-private-pair-test-key-material-000000001",
    )
    with pytest.raises(PrivatePairSplitError, match="differs from its private manifest"):
        verify_private_pair_split_commitment(
            manifest,
            public,
            authenticator=wrong_key,
        )

    records = list(manifest.records)
    changed = records[0].model_dump(mode="json")
    changed["oracle"] = {"expected": "PRIVATE-ORACLE-TAMPERED"}
    records[0] = PrivatePairRecordV1.model_validate(changed)
    changed_manifest = PrivatePairSplitManifestV1(
        manifest_id=manifest.manifest_id,
        manifest_revision=manifest.manifest_revision,
        split_seed=manifest.split_seed,
        component_count=manifest.component_count,
        component_allocation=manifest.component_allocation,
        records=tuple(records),
    )
    with pytest.raises(PrivatePairSplitError, match="differs from its private manifest"):
        verify_private_pair_split_commitment(
            changed_manifest,
            public,
            authenticator=_KEY,
        )


@pytest.mark.parametrize(
    "field_name",
    ["scenario_family", "source", "source_span_id", "mutation_template", "witness"],
)
def test_private_identity_closure_cannot_cross_partitions(field_name: str) -> None:
    manifest = _manifest()
    records = list(manifest.records)
    source_record = records[0]
    target_index = next(
        index
        for index, record in enumerate(records)
        if record.partition is not source_record.partition
    )
    changed = records[target_index].model_dump(mode="python")
    changed[field_name] = getattr(source_record, field_name)
    if field_name == "source":
        changed["source_span_id"] = source_record.source_span_id
        changed["rights"] = _rights(source_record.source)
    elif field_name == "source_span_id":
        # A source-span identifier is only valid inside its own source record.
        changed["source"] = source_record.source
        changed["rights"] = _rights(source_record.source)
    records[target_index] = PrivatePairRecordV1.model_validate(changed)
    with pytest.raises(ValidationError, match=r"component count|partition|cannot cross"):
        PrivatePairSplitManifestV1(
            manifest_id=manifest.manifest_id,
            manifest_revision=manifest.manifest_revision,
            split_seed=manifest.split_seed,
            component_count=manifest.component_count,
            component_allocation=manifest.component_allocation,
            records=tuple(records),
        )


def test_private_heldout_is_inaccessible_to_tuning() -> None:
    manifest = _manifest()
    manifest.assert_no_tuning_access(PairSplitPartitionV1.TRAIN)
    manifest.assert_no_tuning_access(PairSplitPartitionV1.DEV)
    with pytest.raises(PrivatePairSplitError, match="cannot be read"):
        manifest.assert_no_tuning_access(PairSplitPartitionV1.PRIVATE_HELDOUT)
    with pytest.raises(PrivatePairSplitError, match="typed enum"):
        manifest.assert_no_tuning_access(cast(PairSplitPartitionV1, "private_heldout"))


@pytest.mark.parametrize("identity_kind", ["source_id", "source_span_id"])
def test_durable_source_identities_are_in_the_transitive_closure(identity_kind: str) -> None:
    first = _candidate(1, "durable-a")
    second_payload = _candidate(2, "durable-b").model_dump(mode="json")
    second_source = cast(dict[str, object], second_payload["source"])
    if identity_kind == "source_id":
        second_source["source_id"] = first.source.source_id.model_dump(mode="json")
        second_payload["rights"] = _rights(SourceRecordV1.model_validate(second_source)).model_dump(
            mode="json"
        )
    else:
        second_span = cast(list[dict[str, object]], second_source["spans"])[0]
        second_span["span_id"] = first.source_span_id.model_dump(mode="json")
        second_payload["source_span_id"] = first.source_span_id.model_dump(mode="json")
    second = PrivatePairCandidateV1.model_validate(second_payload)

    manifest = build_private_pair_split_manifest(
        (
            first,
            second,
            _candidate(3, "durable-c"),
            _candidate(4, "durable-d"),
        ),
        manifest_id=f"durable.{identity_kind}.pairs.v1",
        manifest_revision="1",
        split_seed=f"durable-{identity_kind}-split-v1",
    )
    partitions = {record.pair_id: record.partition for record in manifest.records}
    assert partitions[first.pair_id] is partitions[second.pair_id]


class _UnattestedSha256Authenticator(PairCommitmentAuthenticator):
    @property
    def nonsecret_key_id(self) -> str:
        return "key." + "a" * 48

    @property
    def commitment_scheme(self) -> str:
        return "hmac-sha256-domain-separated-v1"

    def commit(self, *, domain: str, payload: object) -> str:
        return hashlib.sha256(domain.encode("ascii") + canonical_json_bytes(payload)).hexdigest()


def test_unattested_or_unkeyed_commitment_implementation_is_rejected() -> None:
    with pytest.raises(PrivatePairSplitError, match="verified HMAC/KMS adapter"):
        commit_private_pair_split(
            _manifest(),
            authenticator=_UnattestedSha256Authenticator(),
        )


def test_private_revision_is_projected_as_an_opaque_public_identifier() -> None:
    manifest = _manifest()
    private_revision = "PRIVATE-SOURCE-LEAK"
    changed = PrivatePairSplitManifestV1(
        manifest_id=manifest.manifest_id,
        manifest_revision=private_revision,
        split_seed=manifest.split_seed,
        component_count=manifest.component_count,
        component_allocation=manifest.component_allocation,
        records=manifest.records,
    )
    public = commit_private_pair_split(changed, authenticator=_KEY)
    assert private_revision.encode("ascii") not in canonical_json_bytes(public)
    assert public.split_revision.startswith("rev.")


def test_transitive_identity_closure_is_assigned_atomically() -> None:
    first = _candidate(1, "chain-a")
    second_payload = _candidate(2, "chain-b").model_dump(mode="json")
    second_payload["source"] = first.source.model_dump(mode="json")
    second_payload["source_span_id"] = first.source_span_id.model_dump(mode="json")
    second_payload["rights"] = _rights(first.source).model_dump(mode="json")
    second_payload["witness"] = {"witness": "PRIVATE-WITNESS-BRIDGE"}
    second = PrivatePairCandidateV1.model_validate(second_payload)

    third_payload = _candidate(3, "chain-c").model_dump(mode="json")
    third_payload["witness"] = second_payload["witness"]
    third = PrivatePairCandidateV1.model_validate(third_payload)
    candidates = (
        first,
        second,
        third,
        _candidate(4, "independent-d"),
        _candidate(5, "independent-e"),
    )

    manifest = build_private_pair_split_manifest(
        candidates,
        manifest_id="transitive.private.pairs.v1",
        manifest_revision="1",
        split_seed="transitive-closure-test-v1",
    )
    partition_by_id = {record.pair_id: record.partition for record in manifest.records}
    assert manifest.component_count == 3
    assert len({partition_by_id[f"private.pair.{index:02d}"] for index in (1, 2, 3)}) == 1


def test_split_builder_is_deterministic_and_rejects_too_few_components() -> None:
    candidates = tuple(_candidate(index, f"family-{index}") for index in range(1, 7))
    first = build_private_pair_split_manifest(
        candidates,
        manifest_id="deterministic.private.pairs.v1",
        manifest_revision="1",
        split_seed="deterministic-split-test-v1",
    )
    second = build_private_pair_split_manifest(
        tuple(reversed(candidates)),
        manifest_id="deterministic.private.pairs.v1",
        manifest_revision="1",
        split_seed="deterministic-split-test-v1",
    )
    assert first == second

    one_component = (
        _candidate(1, "shared"),
        _candidate(2, "shared"),
        _candidate(3, "shared"),
    )
    with pytest.raises(PrivatePairSplitError, match="fewer than three"):
        build_private_pair_split_manifest(
            one_component,
            manifest_id="invalid.private.pairs.v1",
            manifest_revision="1",
            split_seed="invalid-split-test-v1",
        )


def test_component_partition_is_invariant_under_pair_id_renaming() -> None:
    candidates = tuple(_candidate(index, f"rename-{index}") for index in range(1, 7))
    first = build_private_pair_split_manifest(
        candidates,
        manifest_id="rename.original.pairs.v1",
        manifest_revision="1",
        split_seed="rename-invariant-split-v1",
    )
    renamed = tuple(
        PrivatePairCandidateV1.model_validate(
            {
                **candidate.model_dump(mode="json"),
                "pair_id": f"renamed.pair.{100 - index:02d}",
            }
        )
        for index, candidate in enumerate(candidates, start=1)
    )
    second = build_private_pair_split_manifest(
        renamed,
        manifest_id="rename.changed.pairs.v1",
        manifest_revision="1",
        split_seed="rename-invariant-split-v1",
    )

    first_by_scenario = {
        canonical_json_bytes(record.scenario_family): record.partition for record in first.records
    }
    second_by_scenario = {
        canonical_json_bytes(record.scenario_family): record.partition for record in second.records
    }
    assert first_by_scenario == second_by_scenario


def test_model_construct_and_public_rebinding_are_rejected() -> None:
    manifest = _manifest()
    payload = manifest.model_dump(mode="python")
    authority_payload = manifest.authority.model_dump(mode="python")
    authority_payload["model_egress_authorized"] = True
    payload["authority"] = PrivatePairSplitAuthorityV1.model_construct(**authority_payload)
    unsafe = PrivatePairSplitManifestV1.model_construct(**payload)
    with pytest.raises(PrivatePairSplitError, match="revalidated"):
        commit_private_pair_split(unsafe, authenticator=_KEY)

    public = commit_private_pair_split(manifest, authenticator=_KEY)
    public_payload = public.model_dump(mode="python")
    public_payload["private_manifest_commitment"] = "f" * 64
    rebound = PairLevelSplitCommitmentV1.model_construct(**public_payload)
    with pytest.raises(PrivatePairSplitError, match="invalid"):
        verify_private_pair_split_commitment(
            manifest,
            rebound,
            authenticator=_KEY,
        )


def test_rights_and_pair_shape_fail_closed() -> None:
    record = _manifest().records[0]
    payload = record.model_dump(mode="json")
    other_source = _source("other")
    payload["rights"] = _rights(other_source).model_dump(mode="json")
    with pytest.raises(ValidationError, match="rights do not bind"):
        PrivatePairRecordV1.model_validate(payload)

    payload = record.model_dump(mode="json")
    payload["mutant_payload"] = cast(dict[str, object], payload["baseline_payload"])
    with pytest.raises(ValidationError, match="must differ"):
        PrivatePairRecordV1.model_validate(payload)

    with pytest.raises(PrivatePairSplitError, match="at least 32 bytes"):
        LocalHmacPairCommitmentAuthenticatorFixture(key_id="test.short", secret=b"short")

    assert EndpointClassV1.APPROVED_EXTERNAL not in record.rights.allowed_endpoint_classes
