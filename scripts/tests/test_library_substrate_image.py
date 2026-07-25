from __future__ import annotations

import copy
from pathlib import Path
from typing import cast

import pytest

from Library.scripts import library_substrate_image as substrate
from Library.scripts.verify_substrate_fixture import (
    EXPECTED_MATHLIB_REVISION,
    EXPECTED_PROFILE_IDS,
    FIXTURE_ROOT,
    MODULE_BY_NAME,
    SOUND_DECLARATION,
    SOURCE_V2_IMAGE,
    TARGET_DECLARATION,
    ValidatedProfileBoundary,
)


def _runtime_files() -> dict[str, dict[str, object]]:
    return {
        module: {
            "module": module,
            "path": f"lib/lean/{module.replace('.', '/')}.olean",
            "sha256": character * 64,
            "size": 100 + index,
        }
        for index, (module, character) in enumerate(
            zip(tuple(MODULE_BY_NAME)[:3], ("a", "b", "c"), strict=True)
        )
    }


def _kernel_record() -> dict[str, object]:
    canonical_type = "Nat"
    return {
        "canonical_type": canonical_type,
        "canonical_type_sha256": substrate._sha256_bytes(canonical_type.encode()),
        "declaration_kind": "definition",
        "name": "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.fixtureHelper",
        "observed_axioms": [],
        "origin_module": next(iter(MODULE_BY_NAME)),
        "origin_olean_sha256": "a" * 64,
    }


def _auxiliary_record() -> dict[str, object]:
    return {
        "ir_decl_kind": "fdecl",
        "name": "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.fixtureHelper._boxed",
        "origin_module": next(iter(MODULE_BY_NAME)),
        "origin_olean_sha256": "a" * 64,
    }


def _manifest_fixture() -> tuple[dict[str, object], dict[str, str]]:
    files = _runtime_files()
    declarations = [_kernel_record()]
    auxiliary = [_auxiliary_record()]
    auxiliary_sha256 = substrate._sha256_bytes(substrate._canonical_json_compact_bytes(auxiliary))
    hashes = {
        "build_input_sha256": "d" * 64,
        "compiled_tree_sha256": "e" * 64,
        "declaration_inventory_sha256": "f" * 64,
        "ir_auxiliary_names_sha256": auxiliary_sha256,
        "parent_receipt_canonical_sha256": "1" * 64,
        "parent_receipt_file_sha256": "2" * 64,
        "profile_sha256": "3" * 64,
        "runtime_source_checksum_manifest_sha256": "4" * 64,
        "runtime_source_tree_sha256": "4" * 64,
    }
    manifest: dict[str, object] = {
        **hashes,
        "declaration_inventory": {
            "declarations": declarations,
            "ir_auxiliary_names": auxiliary,
            "ir_auxiliary_names_sha256": auxiliary_sha256,
            "schema_version": substrate.DECLARATION_INVENTORY_SCHEMA,
        },
        "mathlib_revision": EXPECTED_MATHLIB_REVISION,
        "parent_image": SOURCE_V2_IMAGE,
        "profile_id": EXPECTED_PROFILE_IDS["independent_reproof"],
        "runtime_files": list(files.values()),
        "runtime_modules": list(tuple(MODULE_BY_NAME)[:3]),
        "schema_version": substrate.RUNTIME_MANIFEST_SCHEMA,
        "task_mode": "independent_reproof",
    }
    return manifest, hashes


def test_stage_build_context_contains_only_runtime_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    modules = tuple(MODULE_BY_NAME)[:3]
    sources = [
        {
            "module": module,
            "path": MODULE_BY_NAME[module].path.removeprefix("source/"),
            "role": MODULE_BY_NAME[module].role,
            "sha256": substrate._sha256(FIXTURE_ROOT / MODULE_BY_NAME[module].path),
            "size": (FIXTURE_ROOT / MODULE_BY_NAME[module].path).stat().st_size,
        }
        for module in modules
    ]
    profile = ValidatedProfileBoundary(
        task_mode="independent_reproof",
        runtime_modules=modules,
        forbidden_modules=(),
        candidate_path="candidates/independent_reproof/Candidate.lean",
    )
    assets = substrate._asset_hashes()
    source_tree_sha256 = substrate._sha256_bytes(substrate._canonical_json_bytes(sources))
    source_checksums = substrate._checksum_manifest_bytes(sources, path_prefix="source/")
    build_input: dict[str, object] = {
        "parent_receipt_canonical_sha256": "1" * 64,
        "parent_receipt_file_sha256": "2" * 64,
        "runtime_source_checksum_manifest_sha256": substrate._sha256_bytes(source_checksums),
        "runtime_source_tree_sha256": source_tree_sha256,
        "runtime_sources": sources,
    }
    monkeypatch.setattr(
        substrate,
        "_build_input",
        lambda: (
            build_input,
            substrate._canonical_json_bytes(build_input),
            profile,
            assets,
            source_tree_sha256,
        ),
    )

    prepared, arguments = substrate.stage_build_context(tmp_path / "context")

    inventory = cast(dict[str, str], prepared["context_inventory"])
    assert len(inventory) == 10
    assert set(path for path in inventory if path.endswith(".lean")) == {
        "helpers/AutoleanLibrarySubstrateInventory.lean",
        *(f"source/{cast(str, source['path'])}" for source in sources),
    }
    assert not any(
        token in path
        for path in inventory
        for token in ("Candidate.lean", "/Targets/", "Controls.lean", "UniversalLK.lean")
    )
    assert arguments["PARENT_RECEIPT_CANONICAL_SHA256"] == "1" * 64
    assert arguments["PARENT_RECEIPT_FILE_SHA256"] == "2" * 64
    assert arguments["RUNTIME_SOURCE_CHECKSUM_MANIFEST_SHA256"] == substrate._sha256_bytes(
        source_checksums
    )


def test_stage_build_context_rejects_source_to_context_toctou(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    modules = tuple(MODULE_BY_NAME)[:3]
    sources, source_tree_sha256 = substrate._runtime_source_records(
        ValidatedProfileBoundary(
            task_mode="independent_reproof",
            runtime_modules=modules,
            forbidden_modules=(),
            candidate_path="candidates/independent_reproof/Candidate.lean",
        )
    )
    source_checksums = substrate._checksum_manifest_bytes(sources, path_prefix="source/")
    profile = ValidatedProfileBoundary(
        task_mode="independent_reproof",
        runtime_modules=modules,
        forbidden_modules=(),
        candidate_path="candidates/independent_reproof/Candidate.lean",
    )
    build_input: dict[str, object] = {
        "parent_receipt_canonical_sha256": "1" * 64,
        "parent_receipt_file_sha256": "2" * 64,
        "runtime_source_checksum_manifest_sha256": substrate._sha256_bytes(source_checksums),
        "runtime_source_tree_sha256": source_tree_sha256,
        "runtime_sources": sources,
    }
    monkeypatch.setattr(
        substrate,
        "_build_input",
        lambda: (
            build_input,
            substrate._canonical_json_bytes(build_input),
            profile,
            substrate._asset_hashes(),
            source_tree_sha256,
        ),
    )
    copy_regular = substrate._copy_regular

    def drift_after_copy(source: Path, destination: Path, *, executable: bool = False) -> None:
        copy_regular(source, destination, executable=executable)
        if destination.name == "Core.lean" and "source" in destination.parts:
            destination.chmod(0o644)
            destination.write_bytes(b"TOCTOU source replacement\n")

    monkeypatch.setattr(substrate, "_copy_regular", drift_after_copy)
    with pytest.raises(substrate.SubstrateImageError, match="actual staged source bytes"):
        substrate.stage_build_context(tmp_path / "context")


def test_build_command_has_frozen_offline_flags(tmp_path: Path) -> None:
    command = substrate._build_command(
        tmp_path,
        {
            "BUILD_INPUT_SHA256": "a" * 64,
            "PARENT_RECEIPT_CANONICAL_SHA256": "b" * 64,
        },
    )

    assert command[:7] == [
        "docker",
        "build",
        "--no-cache",
        "--pull=false",
        "--network=none",
        "--file",
        "Dockerfile.library-substrate",
    ]
    assert command[-1] == str(tmp_path)


def test_child_image_reference_requires_docker_recorded_repo_digest() -> None:
    digest = "autolean/library-substrate@sha256:" + "a" * 64
    assert substrate._child_image_reference({"RepoDigests": [digest]}) == digest
    with pytest.raises(substrate.SubstrateImageError, match="Docker-recorded"):
        substrate._child_image_reference({"RepoDigests": []})
    with pytest.raises(substrate.SubstrateImageError, match="Docker-recorded"):
        substrate._child_image_reference({"RepoDigests": ["autolean/other@sha256:" + "a" * 64]})


@pytest.mark.parametrize(
    "mutation",
    (
        "auxiliary-omitted",
        "auxiliary-origin-drift",
        "auxiliary-hash-drift",
        "auxiliary-kernel-collision",
        "auxiliary-target-collision",
        "auxiliary-invalid-kind",
    ),
)
def test_ir_auxiliary_inventory_rejects_drift_and_collisions(mutation: str) -> None:
    files = _runtime_files()
    record = _auxiliary_record()
    value: object = [record]
    include_origin_hash = True
    kernel_names = frozenset({cast(str, _kernel_record()["name"])})
    if mutation == "auxiliary-omitted":
        value = []
    elif mutation == "auxiliary-origin-drift":
        record["origin_module"] = "AutoLeanLibrary.NotInRuntime"
    elif mutation == "auxiliary-hash-drift":
        record["origin_olean_sha256"] = "9" * 64
    elif mutation == "auxiliary-kernel-collision":
        record["name"] = next(iter(kernel_names))
    elif mutation == "auxiliary-target-collision":
        record["name"] = TARGET_DECLARATION
    elif mutation == "auxiliary-invalid-kind":
        record["ir_decl_kind"] = "boxed"
    else:
        raise AssertionError(mutation)

    with pytest.raises(substrate.SubstrateImageError):
        substrate._validate_ir_auxiliary_records(
            value,
            runtime_files=files,
            include_origin_hash=include_origin_hash,
            kernel_names=kernel_names,
        )


def test_manifest_accepts_split_inventory_and_rejects_forbidden_theorems() -> None:
    manifest, receipt = _manifest_fixture()
    files, declarations, auxiliary = substrate._validate_manifest(manifest, receipt=receipt)
    assert len(files) == 3
    assert [record["name"] for record in declarations] == [
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.fixtureHelper"
    ]
    assert len(auxiliary) == 1

    for forbidden in (TARGET_DECLARATION, SOUND_DECLARATION):
        mutated = copy.deepcopy(manifest)
        inventory = cast(dict[str, object], mutated["declaration_inventory"])
        records = cast(list[dict[str, object]], inventory["declarations"])
        records[0]["name"] = forbidden
        with pytest.raises(substrate.SubstrateImageError, match="forbidden pilot theorem"):
            substrate._validate_manifest(mutated, receipt=receipt)


def test_manifest_rejects_exact_target_type_collision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, receipt = _manifest_fixture()
    record = cast(
        list[dict[str, object]],
        cast(dict[str, object], manifest["declaration_inventory"])["declarations"],
    )[0]
    monkeypatch.setattr(
        substrate,
        "TARGET_TYPE_SHA256",
        cast(str, record["canonical_type_sha256"]),
    )

    with pytest.raises(substrate.SubstrateImageError, match="exact target-type collision"):
        substrate._validate_manifest(manifest, receipt=receipt)


def test_runtime_olean_actual_bytes_reject_synchronized_manifest_and_inventory_forgery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, receipt = _manifest_fixture()
    original_files = _runtime_files()
    forged = copy.deepcopy(manifest)
    forged_receipt = dict(receipt)
    files = cast(list[dict[str, object]], forged["runtime_files"])
    files[1]["sha256"] = "9" * 64
    inventory = cast(dict[str, object], forged["declaration_inventory"])
    declaration = cast(list[dict[str, object]], inventory["declarations"])[0]
    second_module = tuple(MODULE_BY_NAME)[1]
    declaration["origin_module"] = second_module
    declaration["origin_olean_sha256"] = "9" * 64
    auxiliary = cast(list[dict[str, object]], inventory["ir_auxiliary_names"])[0]
    auxiliary["origin_module"] = second_module
    auxiliary["origin_olean_sha256"] = "9" * 64
    auxiliary_sha256 = substrate._sha256_bytes(
        substrate._canonical_json_compact_bytes(
            cast(list[dict[str, object]], inventory["ir_auxiliary_names"])
        )
    )
    inventory["ir_auxiliary_names_sha256"] = auxiliary_sha256
    forged["ir_auxiliary_names_sha256"] = auxiliary_sha256
    forged_receipt["ir_auxiliary_names_sha256"] = auxiliary_sha256
    forged_checksums = substrate._checksum_manifest_bytes(files)
    forged_tree_sha256 = substrate._sha256_bytes(forged_checksums)
    forged["compiled_tree_sha256"] = forged_tree_sha256
    forged_receipt["compiled_tree_sha256"] = forged_tree_sha256
    runtime_files, _, _ = substrate._validate_manifest(forged, receipt=forged_receipt)

    monkeypatch.setattr(
        substrate,
        "_read_image_text",
        lambda _image, _path: forged_checksums.decode("ascii"),
    )

    def actual_metadata(_image: str, path: str, *, label: str) -> tuple[str, int]:
        relative_path = path.removeprefix("/opt/autolean/library-substrate/")
        for record in original_files.values():
            if record["path"] == relative_path:
                return cast(str, record["sha256"]), cast(int, record["size"])
        raise AssertionError(label)

    monkeypatch.setattr(substrate, "_image_file_sha256_and_size", actual_metadata)
    with pytest.raises(substrate.SubstrateImageError, match=r"actual-file closure|bytes differ"):
        substrate._validate_runtime_file_closure(
            "autolean/library-substrate@sha256:" + "a" * 64,
            runtime_files,
            manifest=forged,
            receipt=forged_receipt,
        )


def test_query_wrapper_does_not_claim_v2_gateway_compatibility() -> None:
    wrapper = (substrate.HELPER_ROOT / "autolean-library-substrate-independent-query").read_text(
        encoding="utf-8"
    )

    assert "/opt/autolean/bin/autolean-lean-wrapper" not in wrapper
    assert "autolean.oci-lean-wrapper.v2" not in wrapper
    assert "runtime_manifest_sha256" in wrapper
    assert "image_receipt_sha256" in wrapper
