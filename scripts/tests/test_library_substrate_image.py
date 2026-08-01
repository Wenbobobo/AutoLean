from __future__ import annotations

import copy
import os
import subprocess
from pathlib import Path
from typing import cast

import pytest
from autolean_contracts import OciVerifierExecutionPolicyV2

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
    assert len(inventory) == 14
    assert set(path for path in inventory if path.endswith(".lean")) == {
        "helpers/AutoleanLibrarySubstrateBuilderQuery.lean",
        "helpers/AutoleanLibrarySubstrateInventory.lean",
        "helpers/AutoleanLibrarySubstrateV2Query.lean",
        *(f"source/{cast(str, source['path'])}" for source in sources),
    }
    assert not any(
        token in path
        for path in inventory
        for token in ("Candidate.lean", "/Targets/", "Controls.lean", "UniversalLK.lean")
    )
    assert "helpers/autolean-library-substrate-builder-query" in inventory
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


def test_main_reports_wsl_delegation_failure_without_traceback(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(
        substrate,
        "_delegate_to_wsl",
        lambda _arguments: substrate.fail("WSL delegation unavailable"),
    )

    assert substrate.main(("build",)) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "library-substrate-image: WSL delegation unavailable\n"


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


def test_v2_facade_bindings_reject_receipt_and_manifest_drift() -> None:
    wrapper_sha256 = "a" * 64
    helper_sha256 = "b" * 64
    manifest_file_sha256 = "c" * 64
    build_input: dict[str, object] = {
        "assets": {
            "V2_FACADE_QUERY_HELPER_SHA256": helper_sha256,
            "V2_FACADE_WRAPPER_SHA256": wrapper_sha256,
        },
        "target": {
            "canonical_type_sha256": substrate.TARGET_TYPE_SHA256,
            "declaration": TARGET_DECLARATION,
            "forbidden_ordinary_dependency": SOUND_DECLARATION,
        },
    }
    receipt: dict[str, object] = {
        "runtime_manifest_sha256": manifest_file_sha256,
        "v2_facade_query_helper_sha256": helper_sha256,
        "v2_facade_wrapper_sha256": wrapper_sha256,
    }

    substrate._validate_v2_facade_bindings(
        receipt,
        build_input,
        runtime_manifest_file_sha256=manifest_file_sha256,
        facade_wrapper_sha256=wrapper_sha256,
        facade_query_helper_sha256=helper_sha256,
    )

    receipt_drift = copy.deepcopy(receipt)
    receipt_drift["v2_facade_wrapper_sha256"] = "c" * 64
    with pytest.raises(substrate.SubstrateImageError, match="v2_facade_wrapper_sha256"):
        substrate._validate_v2_facade_bindings(
            receipt_drift,
            build_input,
            runtime_manifest_file_sha256=manifest_file_sha256,
            facade_wrapper_sha256=wrapper_sha256,
            facade_query_helper_sha256=helper_sha256,
        )

    with pytest.raises(substrate.SubstrateImageError, match="runtime manifest"):
        substrate._validate_v2_facade_bindings(
            receipt,
            build_input,
            runtime_manifest_file_sha256="d" * 64,
            facade_wrapper_sha256=wrapper_sha256,
            facade_query_helper_sha256=helper_sha256,
        )


def test_host_asset_binding_rejects_checkout_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assets = {
        "DOCKERFILE_SHA256": "a" * 64,
        "V2_FACADE_QUERY_HELPER_SHA256": "b" * 64,
        "V2_FACADE_WRAPPER_SHA256": "c" * 64,
    }
    monkeypatch.setattr(substrate, "_asset_hashes", lambda: assets)

    substrate._validate_host_asset_binding({"assets": dict(sorted(assets.items()))})

    drifted = dict(assets)
    drifted["V2_FACADE_WRAPPER_SHA256"] = "d" * 64
    with pytest.raises(substrate.SubstrateImageError, match="current host helper assets"):
        substrate._validate_host_asset_binding({"assets": drifted})


def test_builder_query_bindings_reject_receipt_asset_and_runtime_drift() -> None:
    wrapper_sha256 = "a" * 64
    helper_sha256 = "b" * 64
    manifest_sha256 = "c" * 64
    receipt: dict[str, object] = {
        "builder_query_helper_sha256": helper_sha256,
        "builder_query_wrapper_sha256": wrapper_sha256,
        "runtime_manifest_sha256": manifest_sha256,
    }
    build_input: dict[str, object] = {
        "assets": {
            "BUILDER_QUERY_HELPER_SHA256": helper_sha256,
            "BUILDER_QUERY_WRAPPER_SHA256": wrapper_sha256,
        }
    }

    substrate._validate_builder_query_bindings(
        receipt,
        build_input,
        runtime_manifest_file_sha256=manifest_sha256,
        builder_query_wrapper_sha256=wrapper_sha256,
        builder_query_helper_sha256=helper_sha256,
    )

    receipt_drift = dict(receipt)
    receipt_drift["builder_query_helper_sha256"] = "d" * 64
    with pytest.raises(substrate.SubstrateImageError, match="builder_query_helper_sha256"):
        substrate._validate_builder_query_bindings(
            receipt_drift,
            build_input,
            runtime_manifest_file_sha256=manifest_sha256,
            builder_query_wrapper_sha256=wrapper_sha256,
            builder_query_helper_sha256=helper_sha256,
        )

    asset_drift = copy.deepcopy(build_input)
    cast(dict[str, object], asset_drift["assets"])["BUILDER_QUERY_WRAPPER_SHA256"] = "e" * 64
    with pytest.raises(substrate.SubstrateImageError, match="Builder query assets"):
        substrate._validate_builder_query_bindings(
            receipt,
            asset_drift,
            runtime_manifest_file_sha256=manifest_sha256,
            builder_query_wrapper_sha256=wrapper_sha256,
            builder_query_helper_sha256=helper_sha256,
        )

    with pytest.raises(substrate.SubstrateImageError, match="runtime manifest"):
        substrate._validate_builder_query_bindings(
            receipt,
            build_input,
            runtime_manifest_file_sha256="f" * 64,
            builder_query_wrapper_sha256=wrapper_sha256,
            builder_query_helper_sha256=helper_sha256,
        )
    with pytest.raises(substrate.SubstrateImageError, match="assets are unavailable"):
        substrate._validate_builder_query_bindings(
            receipt,
            {},
            runtime_manifest_file_sha256=manifest_sha256,
            builder_query_wrapper_sha256=wrapper_sha256,
            builder_query_helper_sha256=helper_sha256,
        )


def _builder_query_fixture(*, replay: bool) -> tuple[dict[str, object], dict[str, object], str]:
    source_sha256 = "d" * 64
    canonical_type = "Nat → Prop"
    type_sha256 = substrate._sha256_bytes(canonical_type.encode("utf-8"))
    identity: dict[str, object] = {
        "build_input_sha256": "1" * 64,
        "builder_query_helper_sha256": "2" * 64,
        "builder_query_wrapper_sha256": "3" * 64,
        "image": "autolean/library-substrate@sha256:" + "4" * 64,
        "image_receipt_sha256": "5" * 64,
        "parent_image": SOURCE_V2_IMAGE,
        "profile_id": EXPECTED_PROFILE_IDS["independent_reproof"],
        "profile_sha256": "6" * 64,
        "runtime_manifest_sha256": "7" * 64,
    }
    record: dict[str, object] = {
        "candidate_direct_imports": [
            "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.RulePrelude",
            "Init",
        ],
        "candidate_ir_auxiliary_names": [],
        "candidate_kernel_names": [substrate.BUILDER_QUERY_TARGET],
        "candidate_owns_target": True,
        "candidate_source_sha256": source_sha256,
        "canonical_type": canonical_type,
        "canonical_type_sha256": type_sha256,
        "carrier_axiom_excluded_from_type_axioms": True,
        "carrier_kind": "builder_statement_carrier",
        "declaration": substrate.BUILDER_QUERY_TARGET,
        "declaration_kind": "axiom",
        "lean_version": "v4.28.0",
        "loaded_module_closure": sorted((*tuple(MODULE_BY_NAME)[:3], "Candidate", "Init")),
        "mathlib_revision": EXPECTED_MATHLIB_REVISION,
        "proof_eligible": False,
        "replay_expected_type_sha256": type_sha256 if replay else None,
        "replay_mode": replay,
        "replay_verified": replay,
        "schema_version": substrate.BUILDER_QUERY_SCHEMA,
        "substrate_identity": identity,
        "type_observed_axioms": [],
    }
    return record, identity, source_sha256


def test_builder_query_record_is_non_proof_and_replay_is_observational() -> None:
    for replay in (False, True):
        record, identity, source_sha256 = _builder_query_fixture(replay=replay)
        observation = substrate._validate_builder_query_record(
            record,
            expected_identity=identity,
            expected_source_sha256=source_sha256,
            expected_type_sha256=(cast(str, record["canonical_type_sha256"]) if replay else None),
        )
        assert observation["proof_eligible"] is False
        assert observation["replay_mode"] is replay
        assert substrate.SHA256_RE.fullmatch(
            cast(str, observation["query_receipt_canonical_sha256"])
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("proof_eligible", True, "non-proof carrier"),
        ("declaration_kind", "theorem", "non-proof carrier"),
        ("candidate_source_sha256", "8" * 64, "non-proof carrier"),
        ("canonical_type_sha256", "8" * 64, "canonical type hash"),
        (
            "candidate_kernel_names",
            [substrate.BUILDER_QUERY_TARGET, "Candidate.Extra"],
            "exactly one",
        ),
        ("candidate_direct_imports", ["Init"], "direct imports"),
        (
            "loaded_module_closure",
            sorted(
                (
                    *tuple(MODULE_BY_NAME)[:3],
                    "Candidate",
                    "Init",
                    "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.ClosedSound",
                )
            ),
            "loaded module boundary",
        ),
        ("type_observed_axioms", [substrate.BUILDER_QUERY_TARGET], "carrier leaked"),
    ),
)
def test_builder_query_record_rejects_policy_drift(field: str, value: object, message: str) -> None:
    record, identity, source_sha256 = _builder_query_fixture(replay=False)
    record[field] = value
    with pytest.raises(substrate.SubstrateImageError, match=message):
        substrate._validate_builder_query_record(
            record,
            expected_identity=identity,
            expected_source_sha256=source_sha256,
            expected_type_sha256=None,
        )


def test_builder_query_record_rejects_image_identity_and_replay_drift() -> None:
    record, identity, source_sha256 = _builder_query_fixture(replay=True)
    expected_type_sha256 = cast(str, record["canonical_type_sha256"])

    image_drift = copy.deepcopy(record)
    cast(dict[str, object], image_drift["substrate_identity"])["image"] = (
        "autolean/library-substrate@sha256:" + "9" * 64
    )
    with pytest.raises(substrate.SubstrateImageError, match="bound non-proof"):
        substrate._validate_builder_query_record(
            image_drift,
            expected_identity=identity,
            expected_source_sha256=source_sha256,
            expected_type_sha256=expected_type_sha256,
        )

    replay_drift = copy.deepcopy(record)
    replay_drift["replay_expected_type_sha256"] = "8" * 64
    with pytest.raises(substrate.SubstrateImageError, match="replay type expectation"):
        substrate._validate_builder_query_record(
            replay_drift,
            expected_identity=identity,
            expected_source_sha256=source_sha256,
            expected_type_sha256=expected_type_sha256,
        )

    fresh_record, fresh_identity, fresh_source_sha256 = _builder_query_fixture(replay=False)
    fresh_record["replay_mode"] = True
    with pytest.raises(substrate.SubstrateImageError, match="mislabeled as replay"):
        substrate._validate_builder_query_record(
            fresh_record,
            expected_identity=fresh_identity,
            expected_source_sha256=fresh_source_sha256,
            expected_type_sha256=None,
        )

    schema_drift, schema_identity, schema_source_sha256 = _builder_query_fixture(replay=False)
    schema_drift["proof"] = "forbidden"
    with pytest.raises(substrate.SubstrateImageError, match="schema drifted"):
        substrate._validate_builder_query_record(
            schema_drift,
            expected_identity=schema_identity,
            expected_source_sha256=schema_source_sha256,
            expected_type_sha256=None,
        )


def test_builder_query_wrapper_and_helper_keep_the_endpoint_observational() -> None:
    wrapper = (substrate.HELPER_ROOT / "autolean-library-substrate-builder-query").read_text(
        encoding="utf-8"
    )
    helper = (substrate.HELPER_ROOT / "AutoleanLibrarySubstrateBuilderQuery.lean").read_text(
        encoding="utf-8"
    )

    assert "autolean-library-substrate-build-receipt" in wrapper
    assert "BUILDER_QUERY_HELPER_SHA256" in wrapper
    assert "BUILDER_QUERY_WRAPPER_SHA256" in wrapper
    assert "Candidate source changed while being snapshotted" in wrapper
    assert "proof-bearing or executable declaration syntax" in wrapper
    assert 'head -c 4096 "$diagnostic"' in wrapper
    assert '"$scratch/compile.stdout"' in wrapper
    assert '"$scratch/query.stdout"' in wrapper
    assert "did not emit exactly one JSON line" in wrapper
    assert 'cat "$scratch/query.stdout"' in wrapper
    assert "--expected-type-sha256" in wrapper
    assert "| .axiomInfo _ => pure ()" in helper
    assert "Candidate owns declarations other than the requested carrier" in helper
    assert "loaded module closure contains a target or oracle module" in helper
    assert "let typeAxioms ← typeObservedAxioms environment targetInfo" in helper
    assert "carrier axiom leaked into type-level axioms" in helper
    assert ".filter (· != target)" not in helper
    assert '("proof_eligible", Json.bool false)' in helper
    assert '"autolean.library-substrate-builder-query.v1"' in helper
    assert "submit_proof" not in wrapper + helper
    assert "autolean.oci-lean-wrapper.v2" not in wrapper + helper


def test_builder_query_assets_are_bound_by_the_v2_image_receipt() -> None:
    build = (substrate.HELPER_ROOT / "autolean-library-substrate-build").read_text(encoding="utf-8")
    receipt = (substrate.HELPER_ROOT / "autolean-library-substrate-build-receipt").read_text(
        encoding="utf-8"
    )
    independent = (
        substrate.HELPER_ROOT / "autolean-library-substrate-independent-query"
    ).read_text(encoding="utf-8")
    builder_query = (substrate.HELPER_ROOT / "autolean-library-substrate-builder-query").read_text(
        encoding="utf-8"
    )

    assert substrate.IMAGE_RECEIPT_SCHEMA.endswith(".v2")
    for content in (build, receipt, independent, builder_query):
        assert "library-substrate-image-receipt.v2" in content
        assert "library-substrate-image-receipt.v1" not in content
    assert "builder_query_helper_sha256" in build + receipt
    assert "builder_query_wrapper_sha256" in build + receipt


def test_builder_query_command_adds_expected_type_only_for_replay(tmp_path: Path) -> None:
    candidate = tmp_path / "Candidate.lean"
    candidate.write_text(substrate.BUILDER_QUERY_SOURCE, encoding="utf-8")
    image = "autolean/library-substrate@sha256:" + "a" * 64

    fresh = substrate._builder_query_command(
        image, candidate, target=substrate.BUILDER_QUERY_TARGET
    )
    replay = substrate._builder_query_command(
        image,
        candidate,
        target=substrate.BUILDER_QUERY_TARGET,
        expected_type_sha256="b" * 64,
    )

    assert "--expected-type-sha256" not in fresh
    assert replay[-2:] == ["--expected-type-sha256", "b" * 64]
    assert substrate.BUILDER_QUERY_WRAPPER_PATH in fresh
    wrapper_index = fresh.index(substrate.BUILDER_QUERY_WRAPPER_PATH)
    assert fresh[wrapper_index - 1] == image
    asserted_image_index = fresh.index("--image") + 1
    assert fresh[asserted_image_index] == image
    with pytest.raises(substrate.SubstrateImageError, match="lowercase SHA-256"):
        substrate._builder_query_command(
            image,
            candidate,
            target=substrate.BUILDER_QUERY_TARGET,
            expected_type_sha256="not-a-digest",
        )
    with pytest.raises(substrate.SubstrateImageError, match="Docker-recorded"):
        substrate._builder_query_command(
            "autolean/library-substrate:mutable",
            candidate,
            target=substrate.BUILDER_QUERY_TARGET,
        )


def test_builder_query_rejection_evidence_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = tmp_path / "Candidate.lean"
    candidate.write_text(substrate.BUILDER_QUERY_THEOREM_SOURCE, encoding="utf-8")
    image = "autolean/library-substrate@sha256:" + "a" * 64
    marker = "proof-bearing or executable declaration syntax"
    current = {
        "result": subprocess.CompletedProcess(
            args=("docker", "run"),
            returncode=2,
            stdout="",
            stderr=f"autolean-library-substrate-builder-query: {marker}\n",
        )
    }
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: current["result"],
    )

    observation = substrate._expect_builder_query_rejected(
        image,
        candidate,
        label="theorem",
        target=substrate.BUILDER_QUERY_TARGET,
        reason_marker=marker,
    )
    assert observation["returncode"] == 2

    current["result"] = subprocess.CompletedProcess(
        args=("docker", "run"),
        returncode=2,
        stdout="unexpected\n",
        stderr=f"{marker}\n",
    )
    with pytest.raises(substrate.SubstrateImageError, match="emitted stdout"):
        substrate._expect_builder_query_rejected(
            image,
            candidate,
            label="theorem",
            target=substrate.BUILDER_QUERY_TARGET,
            reason_marker=marker,
        )

    current["result"] = subprocess.CompletedProcess(
        args=("docker", "run"),
        returncode=2,
        stdout="",
        stderr=f"{marker}\n" + "x" * (substrate.BUILDER_QUERY_FAILURE_DIAGNOSTIC_LIMIT + 512),
    )
    with pytest.raises(substrate.SubstrateImageError, match="unavailable or unbounded"):
        substrate._expect_builder_query_rejected(
            image,
            candidate,
            label="theorem",
            target=substrate.BUILDER_QUERY_TARGET,
            reason_marker=marker,
        )

    current["result"] = subprocess.CompletedProcess(
        args=("docker", "run"),
        returncode=0,
        stdout="{}\n",
        stderr="",
    )
    with pytest.raises(substrate.SubstrateImageError, match="accepted"):
        substrate._expect_builder_query_rejected(
            image,
            candidate,
            label="theorem",
            target=substrate.BUILDER_QUERY_TARGET,
            reason_marker=marker,
        )


def test_v2_facade_keeps_the_existing_runner_protocol_and_runs_preflight() -> None:
    facade = (substrate.HELPER_ROOT / "autolean-library-substrate-v2-facade").read_text(
        encoding="utf-8"
    )
    independent_query = (
        substrate.HELPER_ROOT / "autolean-library-substrate-independent-query"
    ).read_text(encoding="utf-8")

    assert '"--protocol"' in facade
    assert '"autolean.oci-lean-wrapper.v2"' in facade
    assert '"--candidate"' in facade
    assert '"--compiled"' in facade
    assert '"--type-format"' in facade
    assert '"autolean.lean-pp-expr.v1"' in facade
    assert '"$preflight_query" --phase query' in facade
    assert "phase=$failure_phase failed" in facade
    assert "head -c 4096" in facade
    assert "targetTypeSha256" in independent_query
    assert "forbidden Deriv.sound declaration" in independent_query
    assert (
        "Candidate direct imports differ from the independent substrate profile"
        in independent_query
    )


def test_v2_facade_argv_matches_the_complete_v2_policy() -> None:
    policy = OciVerifierExecutionPolicyV2(worker_image_digest="sha256:" + "a" * 64)

    assert substrate._v2_compile_wrapper_argv() == policy.compile_wrapper_argv()
    assert substrate._v2_query_wrapper_argv() == policy.wrapper_argv(TARGET_DECLARATION)


def test_v2_negative_candidate_sources_have_frozen_hashes() -> None:
    compositional = (
        FIXTURE_ROOT / "candidates" / "compositional_bridge" / "Candidate.lean"
    ).read_bytes()

    assert substrate._sha256_bytes(compositional) == substrate.V2_COMPOSITIONAL_CANDIDATE_SHA256
    assert (
        substrate._sha256_bytes(substrate.V2_TARGET_IMPORT_SOURCE.encode("utf-8"))
        == substrate.V2_TARGET_IMPORT_SOURCE_SHA256
    )
    assert (
        substrate._sha256_bytes(substrate.V2_WRONG_TARGET_TYPE_SOURCE.encode("utf-8"))
        == substrate.V2_WRONG_TARGET_TYPE_SOURCE_SHA256
    )


def test_v2_rejection_observation_requires_exact_phase_reason_rc_and_source() -> None:
    prefix = "autolean-library-substrate-v2-facade: phase=query failed"
    marker = "Candidate target type differs from the historical frozen hash"
    result = subprocess.CompletedProcess(
        args=("docker", "run"),
        returncode=21,
        stdout="",
        stderr=f"{prefix}\nautolean-library-substrate-independent-query: {marker}\n",
    )
    expected_hash = "a" * 64

    observation = substrate._v2_rejection_observation(
        result,
        label="wrong-target-type",
        actual_phase="query",
        expected_phase="query",
        expected_returncode=21,
        reason_marker=marker,
        candidate_source_sha256=expected_hash,
        expected_candidate_source_sha256=expected_hash,
    )

    assert observation == {
        "candidate_source_sha256": expected_hash,
        "reason_marker": marker,
        "rejection_phase": "query",
        "returncode": 21,
        "stderr_summary": result.stderr.strip(),
    }

    with pytest.raises(substrate.SubstrateImageError, match="expected query"):
        substrate._v2_rejection_observation(
            result,
            label="wrong-target-type",
            actual_phase="compile",
            expected_phase="query",
            expected_returncode=21,
            reason_marker=marker,
            candidate_source_sha256=expected_hash,
            expected_candidate_source_sha256=expected_hash,
        )
    with pytest.raises(substrate.SubstrateImageError, match="returned 21, expected 20"):
        substrate._v2_rejection_observation(
            result,
            label="wrong-target-type",
            actual_phase="query",
            expected_phase="query",
            expected_returncode=20,
            reason_marker=marker,
            candidate_source_sha256=expected_hash,
            expected_candidate_source_sha256=expected_hash,
        )
    with pytest.raises(substrate.SubstrateImageError, match="source hash drifted"):
        substrate._v2_rejection_observation(
            result,
            label="wrong-target-type",
            actual_phase="query",
            expected_phase="query",
            expected_returncode=21,
            reason_marker=marker,
            candidate_source_sha256="b" * 64,
            expected_candidate_source_sha256=expected_hash,
        )
    missing_reason = subprocess.CompletedProcess(
        args=result.args,
        returncode=21,
        stdout="",
        stderr=f"{prefix}\nunrelated failure\n",
    )
    with pytest.raises(substrate.SubstrateImageError, match="reason is unavailable"):
        substrate._v2_rejection_observation(
            missing_reason,
            label="wrong-target-type",
            actual_phase="query",
            expected_phase="query",
            expected_returncode=21,
            reason_marker=marker,
            candidate_source_sha256=expected_hash,
            expected_candidate_source_sha256=expected_hash,
        )
    stdout_failure = subprocess.CompletedProcess(
        args=result.args,
        returncode=21,
        stdout="unexpected output\n",
        stderr=result.stderr,
    )
    with pytest.raises(substrate.SubstrateImageError, match="failure emitted stdout"):
        substrate._v2_rejection_observation(
            stdout_failure,
            label="wrong-target-type",
            actual_phase="query",
            expected_phase="query",
            expected_returncode=21,
            reason_marker=marker,
            candidate_source_sha256=expected_hash,
            expected_candidate_source_sha256=expected_hash,
        )
    unbounded_failure = subprocess.CompletedProcess(
        args=result.args,
        returncode=21,
        stdout="",
        stderr=f"{prefix}\n{marker}\n{'x' * 5000}",
    )
    with pytest.raises(substrate.SubstrateImageError, match="reason is unavailable or unbounded"):
        substrate._v2_rejection_observation(
            unbounded_failure,
            label="wrong-target-type",
            actual_phase="query",
            expected_phase="query",
            expected_returncode=21,
            reason_marker=marker,
            candidate_source_sha256=expected_hash,
            expected_candidate_source_sha256=expected_hash,
        )
