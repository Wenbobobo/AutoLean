"""Focused checks for the operator-private source-free seed protocol."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
from collections import Counter
from pathlib import Path

import pytest
from autolean_builder import ifem_next_calibration_case_intents as intents_module
from autolean_builder import ifem_source_free_private_seed as private_seed
from autolean_contracts import PairSplitPartitionV1, canonical_json_bytes

ROOT = Path(__file__).resolve().parents[2]


def _queue() -> intents_module.IFEMNextCalibrationCaseIntentsV1:
    return intents_module.build_ifem_next_calibration_case_intents_from_paths()


def _fixed_entropy(byte: int):  # type: ignore[no-untyped-def]
    def generate(size: int) -> bytes:
        return bytes([byte]) * size

    return generate


def _rehash_item(item: dict[str, object]) -> None:
    item.pop("item_content_sha256", None)
    item["item_content_sha256"] = hashlib.sha256(canonical_json_bytes(item)).hexdigest()


def _rehash_manifest(payload: dict[str, object]) -> dict[str, object]:
    result = copy.deepcopy(payload)
    result.pop("manifest_content_sha256", None)
    result["manifest_content_sha256"] = hashlib.sha256(canonical_json_bytes(result)).hexdigest()
    return result


def _rehash_commitment(payload: dict[str, object]) -> dict[str, object]:
    result = copy.deepcopy(payload)
    result.pop("content_sha256", None)
    result["content_sha256"] = hashlib.sha256(canonical_json_bytes(result)).hexdigest()
    return result


def test_private_nonce_changes_case_ids_partition_mapping_and_commitment() -> None:
    queue = _queue()
    first = private_seed.build_test_private_seed_manifest(
        queue,
        run_nonce=b"a" * 32,
    )
    second = private_seed.build_test_private_seed_manifest(
        queue,
        run_nonce=b"b" * 32,
    )

    assert first.run_id != second.run_id
    assert first.manifest_content_sha256 != second.manifest_content_sha256
    assert {item.case_id for item in first.items}.isdisjoint(
        {item.case_id for item in second.items}
    )
    assert {item.intent_id: item.partition for item in first.items} != {
        item.intent_id: item.partition for item in second.items
    }
    for manifest in (first, second):
        assert len(manifest.items) == 9
        assert Counter(item.partition for item in manifest.items) == {
            PairSplitPartitionV1.TRAIN: 3,
            PairSplitPartitionV1.DEV: 3,
            PairSplitPartitionV1.PRIVATE_HELDOUT: 3,
        }
        assert {item.intent_id for item in manifest.items} == {
            item.intent_id
            for item in queue.intents
            if item.calibration_priority.value == "p3_create_calibration_case"
        }
        private_seed.verify_private_seed_manifest_against_queue(manifest, queue)


def test_public_commitment_redacts_private_mapping_and_withholds_authority(
    tmp_path: Path,
) -> None:
    store = private_seed.LocalSourceFreePrivateSeedStore(
        (tmp_path / "operator-private").resolve(),
        repository_root=ROOT,
        run_label="p3-public-redaction",
    )
    _manifest, commitment = store.commit_for_queue(
        _queue(),
        test_entropy=_fixed_entropy(ord("c")),
    )
    rendered = private_seed.render_private_seed_commitment(commitment)

    for forbidden in (
        b'"case_id"',
        b'"intent_id"',
        b'"node_id"',
        b'"partition"',
        b'"run_nonce_hex"',
        b'"hidden_oracle"',
        b'"baseline"',
        b'"selector"',
        b'"increment"',
    ):
        assert forbidden not in rendered
    assert commitment.default_csprng_path_claimed is False
    assert commitment.entropy_provenance_verified is False
    assert commitment.unpredictability_verified is False
    assert commitment.store_persist_before_projection_observed is True
    assert commitment.store_persistence_attested is False
    assert commitment.case_ids_disclosed is False
    assert commitment.partition_mapping_disclosed is False
    assert commitment.heldout_worker_isolation_claimed is False
    assert commitment.live_model_eligible is False
    assert commitment.authority.heldout_isolation_claimed is False
    assert commitment.authority.freeze_allowed is False
    assert commitment.authority.prover_handoff_allowed is False
    with pytest.raises(private_seed.SourceFreePrivateSeedError, match="cannot classify"):
        commitment.freeze_statement()
    with pytest.raises(private_seed.SourceFreePrivateSeedError, match="cannot classify"):
        commitment.handoff_to_prover()


def test_store_persists_before_projection_and_recovers_without_new_entropy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue = _queue()
    store = private_seed.LocalSourceFreePrivateSeedStore(
        (tmp_path / "operator-private").resolve(),
        repository_root=ROOT,
        run_label="p3-private-seed-test",
    )
    entropy_calls = 0

    def entropy(size: int) -> bytes:
        nonlocal entropy_calls
        entropy_calls += 1
        return b"d" * size

    original_projection = private_seed._build_private_seed_commitment

    def fail_projection(
        _manifest: private_seed.PrivateSourceFreeSeedManifestV2,
    ) -> private_seed.SourceFreePrivateSeedCommitmentV2:
        raise RuntimeError("injected projection interruption")

    monkeypatch.setattr(private_seed, "_build_private_seed_commitment", fail_projection)
    with pytest.raises(RuntimeError, match="projection interruption"):
        store.commit_for_queue(queue, test_entropy=entropy)
    assert store.manifest_path.is_file()
    assert entropy_calls == 1

    monkeypatch.setattr(private_seed, "_build_private_seed_commitment", original_projection)

    def forbidden_entropy(_size: int) -> bytes:
        raise AssertionError("recovery regenerated private entropy")

    manifest, commitment = store.commit_for_queue(
        queue,
        test_entropy=forbidden_entropy,
    )
    assert entropy_calls == 1
    assert commitment.private_manifest_content_sha256 == manifest.manifest_content_sha256
    private_seed.verify_private_seed_manifest_against_queue(manifest, queue)
    private_seed.verify_private_seed_commitment(commitment, manifest)


def test_store_default_claims_only_its_csprng_path_and_is_not_live_eligible(
    tmp_path: Path,
) -> None:
    store = private_seed.LocalSourceFreePrivateSeedStore(
        (tmp_path / "operator-private").resolve(),
        repository_root=ROOT,
        run_label="p3-csprng-test",
    )
    manifest, commitment = store.commit_for_queue(_queue())

    assert manifest.entropy_path_label == "default_store_csprng_path"
    assert commitment.default_csprng_path_claimed is True
    assert commitment.entropy_provenance_verified is False
    assert commitment.unpredictability_verified is False
    assert commitment.live_model_eligible is False
    assert commitment.heldout_worker_isolation_claimed is False


def test_self_rehashed_entropy_label_cannot_claim_verified_provenance(
    tmp_path: Path,
) -> None:
    queue = _queue()
    test_manifest = private_seed.build_test_private_seed_manifest(
        queue,
        run_nonce=b"z" * 32,
    )
    payload = test_manifest.model_dump(mode="json")
    payload["entropy_path_label"] = "default_store_csprng_path"
    relabeled = private_seed.PrivateSourceFreeSeedManifestV2.model_validate(
        _rehash_manifest(payload)
    )
    private_seed.verify_private_seed_manifest_against_queue(relabeled, queue)

    store = private_seed.LocalSourceFreePrivateSeedStore(
        (tmp_path / "operator-private").resolve(),
        repository_root=ROOT,
        run_label="p3-self-relabeled-seed",
    )
    store.manifest_path.write_bytes(relabeled.canonical_bytes())

    def forbidden_entropy(_size: int) -> bytes:
        raise AssertionError("retained manifest recovery requested new entropy")

    persisted, commitment = store.commit_for_queue(
        queue,
        test_entropy=forbidden_entropy,
    )
    assert persisted == relabeled
    assert commitment.default_csprng_path_claimed is True
    assert commitment.entropy_provenance_verified is False
    assert commitment.unpredictability_verified is False
    assert commitment.live_model_eligible is False


@pytest.mark.parametrize(
    "root_factory",
    (
        lambda tmp_path: Path("relative-private-root"),
        lambda _tmp_path: ROOT / ".cache" / "forbidden-private-seed",
    ),
)
def test_store_rejects_relative_or_checkout_internal_roots(
    tmp_path: Path,
    root_factory,  # type: ignore[no-untyped-def]
) -> None:
    with pytest.raises(private_seed.SourceFreePrivateSeedError):
        private_seed.LocalSourceFreePrivateSeedStore(
            root_factory(tmp_path),
            repository_root=ROOT,
            run_label="p3-path-rejection",
        )


def test_store_rejects_linked_private_root_when_supported(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(real, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlink creation is unavailable: {error}")

    with pytest.raises(private_seed.SourceFreePrivateSeedError, match=r"symlink|reparse"):
        private_seed.LocalSourceFreePrivateSeedStore(
            linked.absolute(),
            repository_root=ROOT,
            run_label="p3-linked-root",
        )


def test_rehashed_manifest_and_commitment_tampering_are_rejected(tmp_path: Path) -> None:
    queue = _queue()
    manifest = private_seed.build_test_private_seed_manifest(
        queue,
        run_nonce=b"e" * 32,
    )
    payload = manifest.model_dump(mode="json")
    items = payload["items"]
    assert isinstance(items, list)
    first = items[0]
    assert isinstance(first, dict)
    first["node_id"] = "ifem-rehashed-tamper"
    _rehash_item(first)
    tampered_manifest = private_seed.PrivateSourceFreeSeedManifestV2.model_validate(
        _rehash_manifest(payload)
    )
    with pytest.raises(private_seed.SourceFreePrivateSeedError, match="exact queue replay"):
        private_seed.verify_private_seed_manifest_against_queue(tampered_manifest, queue)

    commitment_store = private_seed.LocalSourceFreePrivateSeedStore(
        (tmp_path / "operator-private").resolve(),
        repository_root=ROOT,
        run_label="p3-tampered-commitment",
    )
    persisted, commitment = commitment_store.commit_for_queue(
        queue,
        test_entropy=_fixed_entropy(ord("e")),
    )
    assert persisted == manifest
    commitment_payload = commitment.model_dump(mode="json")
    commitment_payload["private_manifest_content_sha256"] = "f" * 64
    tampered_commitment = private_seed.SourceFreePrivateSeedCommitmentV2.model_validate(
        _rehash_commitment(commitment_payload)
    )
    with pytest.raises(private_seed.SourceFreePrivateSeedError, match="differs"):
        private_seed.verify_private_seed_commitment(tampered_commitment, manifest)


def test_store_rejects_corrupted_retained_manifest(tmp_path: Path) -> None:
    store = private_seed.LocalSourceFreePrivateSeedStore(
        (tmp_path / "operator-private").resolve(),
        repository_root=ROOT,
        run_label="p3-corrupt-manifest",
    )
    store.commit_for_queue(_queue(), test_entropy=_fixed_entropy(7))
    store.manifest_path.write_bytes(b"not-json\n")

    with pytest.raises(private_seed.SourceFreePrivateSeedError, match="unavailable or invalid"):
        store.load()


@pytest.mark.parametrize("nonce", (b"", b"short", b"x" * 31, b"x" * 33, bytearray(32)))
def test_manifest_rejects_wrong_entropy_shape(nonce: object) -> None:
    with pytest.raises(private_seed.SourceFreePrivateSeedError, match="exactly 32 bytes"):
        private_seed.build_test_private_seed_manifest(
            _queue(),
            run_nonce=nonce,  # type: ignore[arg-type]
        )


def test_private_seed_module_has_no_provider_network_or_prover_dependency() -> None:
    module_path = Path(private_seed.__file__)
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    imported_roots = {
        alias.name.split(".", 1)[0]
        for statement in ast.walk(tree)
        if isinstance(statement, ast.Import)
        for alias in statement.names
    }
    imported_roots.update(
        statement.module.split(".", 1)[0]
        for statement in ast.walk(tree)
        if isinstance(statement, ast.ImportFrom) and statement.module is not None
    )
    assert not imported_roots.intersection(
        {"benchmarks", "http", "httpx", "Prover", "requests", "urllib"}
    )


def test_private_manifest_bytes_are_canonical_json() -> None:
    manifest = private_seed.build_test_private_seed_manifest(
        _queue(),
        run_nonce=b"f" * 32,
    )
    payload = json.loads(manifest.canonical_bytes())
    assert payload["manifest_content_sha256"] == manifest.manifest_content_sha256
    assert canonical_json_bytes(payload) + b"\n" == manifest.canonical_bytes()
