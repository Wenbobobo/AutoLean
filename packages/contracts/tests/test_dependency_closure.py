from __future__ import annotations

import copy
import hashlib

import pytest
from pydantic import ValidationError

from autolean_contracts import (
    DEPENDENCY_CLOSURE_MANIFEST_MEDIA_TYPE,
    LEAN_OLEAN_MEDIA_TYPE,
    VERIFICATION_EVIDENCE_MEDIA_TYPE,
    AcceptedDependencyV1,
    DependencyClosureArtifactRefV1,
    DependencyClosureFileV1,
    DependencyClosureManifestV1,
    DependencyClosureModuleV1,
    DependencyClosureRefV1,
    DependencyDeclarationInventoryV1,
    DependencyDeclarationKindV1,
    FormalizationTaskBundleV1,
    HashKindV1,
    build_dependency_closure_ref,
    canonical_json_bytes,
    dependency_tree_hash,
    digest_bytes,
    digest_text,
    parse_dependency_closure_manifest,
    stable_identifier,
    validate_dependency_closure_ref,
)

FOUNDATION = "AutoLeanLibrary.Fixtures.Dag.Foundation"
BRIDGE = "AutoLeanLibrary.Fixtures.Dag.Bridge"
CERTIFICATE = "AutoLeanLibrary.Fixtures.Dag.Certificate"
TARGET_DECLARATION = "AutoLeanLibrary.Fixtures.Dag.capstone"


def fixture_dependency_closure() -> tuple[
    DependencyClosureManifestV1,
    DependencyClosureRefV1,
    dict[str, bytes],
]:
    blobs = {
        FOUNDATION.replace(".", "/") + ".olean": b"fixture Foundation OLean\n",
        BRIDGE.replace(".", "/") + ".olean": b"fixture Bridge OLean\n",
        CERTIFICATE.replace(".", "/") + ".olean": b"fixture Certificate OLean\n",
    }
    files = tuple(
        DependencyClosureFileV1(
            relative_path=relative_path,
            artifact=_artifact(data, LEAN_OLEAN_MEDIA_TYPE),
        )
        for relative_path, data in sorted(blobs.items())
    )
    modules = tuple(
        sorted(
            (
                DependencyClosureModuleV1(
                    module_name=FOUNDATION,
                    olean_path=FOUNDATION.replace(".", "/") + ".olean",
                    direct_imports=("Mathlib.Data.Nat.Basic",),
                ),
                DependencyClosureModuleV1(
                    module_name=BRIDGE,
                    olean_path=BRIDGE.replace(".", "/") + ".olean",
                    direct_imports=(FOUNDATION,),
                ),
                DependencyClosureModuleV1(
                    module_name=CERTIFICATE,
                    olean_path=CERTIFICATE.replace(".", "/") + ".olean",
                    direct_imports=(BRIDGE,),
                ),
            ),
            key=lambda item: item.module_name,
        )
    )
    declaration_rows = (
        (
            "AutoLeanLibrary.Fixtures.Dag.bridge_normalize",
            BRIDGE,
            digest_text(HashKindV1.ELABORATED_TYPE, "forall n, (n + 0) + 0 = n"),
            (),
        ),
        (
            "AutoLeanLibrary.Fixtures.Dag.certificate_normalize",
            CERTIFICATE,
            digest_text(HashKindV1.ELABORATED_TYPE, "forall n, certificate n"),
            ("Classical.choice",),
        ),
        (
            "AutoLeanLibrary.Fixtures.Dag.foundation_add_zero",
            FOUNDATION,
            digest_text(HashKindV1.ELABORATED_TYPE, "forall n, n + 0 = n"),
            (),
        ),
    )
    inventory = tuple(
        DependencyDeclarationInventoryV1(
            declaration_name=name,
            kind=DependencyDeclarationKindV1.THEOREM,
            canonical_type_hash=type_hash,
            observed_axioms=axioms,
            module_name=module,
        )
        for name, module, type_hash, axioms in sorted(declaration_rows)
    )
    accepted = tuple(
        sorted(
            (
                AcceptedDependencyV1(
                    dependency_id=stable_identifier("dependency", name),
                    formal_node_id=stable_identifier("formal-node", name),
                    contract_id=stable_identifier("contract", name),
                    revision=index,
                    contract_hash=digest_text(HashKindV1.CONTRACT, f"{name}:r{index}"),
                    declaration_name=name,
                    canonical_type_hash=type_hash,
                    observed_axioms=axioms,
                    module_name=module,
                    verification_evidence=_artifact(
                        f"verified:{name}:r{index}".encode(),
                        VERIFICATION_EVIDENCE_MEDIA_TYPE,
                    ),
                )
                for index, (name, module, type_hash, axioms) in enumerate(
                    declaration_rows,
                    start=1,
                )
            ),
            key=lambda item: item.dependency_id.value,
        )
    )
    manifest = DependencyClosureManifestV1(
        closure_id=stable_identifier("dependency-closure", "dag-stage-a"),
        environment_hash=digest_text(HashKindV1.ENVIRONMENT, "lean-4.28-mathlib-pinned"),
        tree_hash=dependency_tree_hash(files),
        target_contract_id=stable_identifier("contract", "capstone"),
        target_revision=1,
        target_contract_hash=digest_text(HashKindV1.CONTRACT, "capstone:r1"),
        target_declaration=TARGET_DECLARATION,
        target_canonical_type_hash=digest_text(
            HashKindV1.ELABORATED_TYPE,
            "forall n, capstone n",
        ),
        entry_modules=(CERTIFICATE,),
        files=files,
        modules=modules,
        declaration_inventory=inventory,
        accepted_dependencies=accepted,
    )
    return manifest, build_dependency_closure_ref(manifest), blobs


def _artifact(data: bytes, media_type: str) -> DependencyClosureArtifactRefV1:
    return DependencyClosureArtifactRefV1(
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        media_type=media_type,
    )


def _manifest_payload() -> dict[str, object]:
    manifest, _reference, _blobs = fixture_dependency_closure()
    return copy.deepcopy(manifest.model_dump(mode="json"))


def _reference_for_raw(
    reference: DependencyClosureRefV1,
    raw: bytes,
) -> DependencyClosureRefV1:
    manifest_hash = digest_bytes(HashKindV1.DEPENDENCY_CLOSURE, raw)
    return reference.model_copy(
        update={
            "closure_manifest_hash": manifest_hash,
            "closure_manifest_ref": DependencyClosureArtifactRefV1(
                sha256=manifest_hash.value,
                size=len(raw),
                media_type=DEPENDENCY_CLOSURE_MANIFEST_MEDIA_TYPE,
            ),
        }
    )


def test_three_module_closure_round_trips_canonical_bytes_and_reference() -> None:
    manifest, reference, blobs = fixture_dependency_closure()
    raw = manifest.canonical_bytes()

    assert parse_dependency_closure_manifest(raw) == manifest
    assert validate_dependency_closure_ref(reference, raw) == manifest
    assert reference.tree_hash == dependency_tree_hash(manifest.files)
    assert reference.entry_modules == (CERTIFICATE,)
    assert len(reference.formal_body_dependency_ids) == 3
    assert set(blobs) == {item.relative_path for item in manifest.files}


def test_v1_bundle_contract_is_not_extended_with_an_optional_closure() -> None:
    assert "dependency_closure" not in FormalizationTaskBundleV1.model_fields


def test_noncanonical_manifest_bytes_fail_even_when_their_digest_is_rebound() -> None:
    manifest, reference, _blobs = fixture_dependency_closure()
    raw = manifest.canonical_bytes() + b"\n"
    rebound = _reference_for_raw(reference, raw)

    with pytest.raises(ValueError, match="not canonical"):
        validate_dependency_closure_ref(rebound, raw)


def test_duplicate_json_keys_fail_before_contract_validation() -> None:
    manifest, reference, _blobs = fixture_dependency_closure()
    raw = manifest.canonical_bytes()
    duplicated = raw.replace(
        b'{"accepted_dependencies":',
        b'{"schema_version":"autolean.dependency-closure-manifest.v1","accepted_dependencies":',
        1,
    )
    rebound = _reference_for_raw(reference, duplicated)

    with pytest.raises(ValueError, match="duplicate JSON key"):
        validate_dependency_closure_ref(rebound, duplicated)


@pytest.mark.parametrize(
    "relative_path",
    (
        "../escape.olean",
        "/absolute.olean",
        r"AutoLeanLibrary\Fixture.olean",
        "Mathlib/Injected.olean",
        "AutoLeanLibrary//Duplicate.olean",
        "AutoLeanLibrary/Linked.so",
    ),
)
def test_runtime_paths_are_canonical_autolean_owned_olean_paths(relative_path: str) -> None:
    with pytest.raises(ValidationError):
        DependencyClosureFileV1(
            relative_path=relative_path,
            artifact=_artifact(b"x", LEAN_OLEAN_MEDIA_TYPE),
        )


def test_runtime_file_rejects_link_semantics_fields() -> None:
    payload = {
        "relative_path": "AutoLeanLibrary/Fixture.olean",
        "artifact": _artifact(b"x", LEAN_OLEAN_MEDIA_TYPE).model_dump(mode="json"),
        "role": "lean_olean",
        "symlink_target": "../outside",
    }
    with pytest.raises(ValidationError, match="Extra inputs"):
        DependencyClosureFileV1.model_validate(payload)


def test_manifest_rejects_an_extra_blob_without_a_module() -> None:
    payload = _manifest_payload()
    files = payload["files"]
    assert isinstance(files, list)
    files.append(
        DependencyClosureFileV1(
            relative_path="AutoLeanLibrary/Fixtures/Dag/Extra.olean",
            artifact=_artifact(b"extra", LEAN_OLEAN_MEDIA_TYPE),
        ).model_dump(mode="json")
    )
    files.sort(key=lambda item: item["relative_path"])
    payload["tree_hash"] = dependency_tree_hash(
        tuple(DependencyClosureFileV1.model_validate(item) for item in files)
    ).model_dump(mode="json")

    with pytest.raises(ValidationError, match="exactly match"):
        DependencyClosureManifestV1.model_validate(payload)


def test_manifest_rejects_a_missing_internal_import() -> None:
    payload = _manifest_payload()
    modules = payload["modules"]
    assert isinstance(modules, list)
    bridge = next(item for item in modules if item["module_name"] == BRIDGE)
    bridge["direct_imports"] = ["AutoLeanLibrary.Fixtures.Dag.Missing"]

    with pytest.raises(ValidationError, match="imports an absent AutoLean module"):
        DependencyClosureManifestV1.model_validate(payload)


def test_manifest_rejects_an_internal_import_cycle() -> None:
    payload = _manifest_payload()
    modules = payload["modules"]
    assert isinstance(modules, list)
    foundation = next(item for item in modules if item["module_name"] == FOUNDATION)
    foundation["direct_imports"] = [CERTIFICATE]

    with pytest.raises(ValidationError, match="import cycle"):
        DependencyClosureManifestV1.model_validate(payload)


def test_manifest_rejects_an_unreachable_module() -> None:
    payload = _manifest_payload()
    extra_module = "AutoLeanLibrary.Fixtures.Dag.Unreachable"
    extra_path = extra_module.replace(".", "/") + ".olean"
    files = payload["files"]
    modules = payload["modules"]
    assert isinstance(files, list)
    assert isinstance(modules, list)
    files.append(
        DependencyClosureFileV1(
            relative_path=extra_path,
            artifact=_artifact(b"unreachable", LEAN_OLEAN_MEDIA_TYPE),
        ).model_dump(mode="json")
    )
    files.sort(key=lambda item: item["relative_path"])
    modules.append(
        DependencyClosureModuleV1(
            module_name=extra_module,
            olean_path=extra_path,
            direct_imports=("Mathlib.Data.Nat.Basic",),
        ).model_dump(mode="json")
    )
    modules.sort(key=lambda item: item["module_name"])
    payload["tree_hash"] = dependency_tree_hash(
        tuple(DependencyClosureFileV1.model_validate(item) for item in files)
    ).model_dump(mode="json")

    with pytest.raises(ValidationError, match="unreachable module"):
        DependencyClosureManifestV1.model_validate(payload)


def test_manifest_rejects_non_autolean_declaration_ownership() -> None:
    payload = _manifest_payload()
    payload["target_declaration"] = "Mathlib.Injected.capstone"

    with pytest.raises(ValidationError, match="AutoLean-owned namespace"):
        DependencyClosureManifestV1.model_validate(payload)


def test_manifest_rejects_an_undeclared_theorem_without_an_accepted_binding() -> None:
    payload = _manifest_payload()
    inventory = payload["declaration_inventory"]
    assert isinstance(inventory, list)
    inventory.append(
        DependencyDeclarationInventoryV1(
            declaration_name="AutoLeanLibrary.Fixtures.Dag.undeclared_theorem",
            kind=DependencyDeclarationKindV1.THEOREM,
            canonical_type_hash=digest_text(
                HashKindV1.ELABORATED_TYPE,
                "forall n, undeclared theorem n",
            ),
            module_name=FOUNDATION,
        ).model_dump(mode="json")
    )
    inventory.sort(key=lambda item: item["declaration_name"])

    with pytest.raises(ValidationError, match="every dependency theorem"):
        DependencyClosureManifestV1.model_validate(payload)


def test_manifest_rejects_an_unbound_stronger_theorem_oracle() -> None:
    payload = _manifest_payload()
    inventory = payload["declaration_inventory"]
    assert isinstance(inventory, list)
    inventory.append(
        DependencyDeclarationInventoryV1(
            declaration_name="AutoLeanLibrary.Fixtures.Dag.capstone_stronger_oracle",
            kind=DependencyDeclarationKindV1.THEOREM,
            canonical_type_hash=digest_text(
                HashKindV1.ELABORATED_TYPE,
                "forall n, stronger capstone oracle n",
            ),
            module_name=CERTIFICATE,
        ).model_dump(mode="json")
    )
    inventory.sort(key=lambda item: item["declaration_name"])

    with pytest.raises(ValidationError, match="every dependency theorem"):
        DependencyClosureManifestV1.model_validate(payload)


def test_manifest_allows_only_unbound_non_theorem_definition_helpers() -> None:
    payload = _manifest_payload()
    inventory = payload["declaration_inventory"]
    assert isinstance(inventory, list)
    inventory.append(
        DependencyDeclarationInventoryV1(
            declaration_name="AutoLeanLibrary.Fixtures.Dag.helper_definition",
            kind=DependencyDeclarationKindV1.DEFINITION,
            canonical_type_hash=digest_text(
                HashKindV1.ELABORATED_TYPE,
                "Nat -> Nat",
            ),
            module_name=FOUNDATION,
        ).model_dump(mode="json")
    )
    inventory.sort(key=lambda item: item["declaration_name"])

    manifest = DependencyClosureManifestV1.model_validate(payload)

    assert all(
        dependency.declaration_name != "AutoLeanLibrary.Fixtures.Dag.helper_definition"
        for dependency in manifest.accepted_dependencies
    )


@pytest.mark.parametrize(
    "kind",
    (DependencyDeclarationKindV1.INSTANCE, DependencyDeclarationKindV1.NOTATION),
)
def test_manifest_rejects_ambiguous_unbound_inventory_kinds(
    kind: DependencyDeclarationKindV1,
) -> None:
    payload = _manifest_payload()
    inventory = payload["declaration_inventory"]
    assert isinstance(inventory, list)
    inventory.append(
        DependencyDeclarationInventoryV1(
            declaration_name=f"AutoLeanLibrary.Fixtures.Dag.unsupported_{kind.value}",
            kind=kind,
            canonical_type_hash=digest_text(
                HashKindV1.ELABORATED_TYPE,
                kind.value,
            ),
            module_name=FOUNDATION,
        ).model_dump(mode="json")
    )
    inventory.sort(key=lambda item: item["declaration_name"])

    with pytest.raises(ValidationError, match="permits only definitions and theorem"):
        DependencyClosureManifestV1.model_validate(payload)


def test_manifest_rejects_target_declaration_and_exact_type_alias_pollution() -> None:
    target_payload = _manifest_payload()
    inventory = target_payload["declaration_inventory"]
    assert isinstance(inventory, list)
    inventory[0]["declaration_name"] = TARGET_DECLARATION
    inventory.sort(key=lambda item: item["declaration_name"])
    with pytest.raises(ValidationError, match="target declaration"):
        DependencyClosureManifestV1.model_validate(target_payload)

    alias_payload = _manifest_payload()
    alias_inventory = alias_payload["declaration_inventory"]
    assert isinstance(alias_inventory, list)
    alias_inventory[0]["canonical_type_hash"] = alias_payload["target_canonical_type_hash"]
    with pytest.raises(ValidationError, match="exact-type target alias"):
        DependencyClosureManifestV1.model_validate(alias_payload)


def test_manifest_rejects_target_contract_self_dependency() -> None:
    payload = _manifest_payload()
    accepted = payload["accepted_dependencies"]
    assert isinstance(accepted, list)
    accepted[0]["contract_id"] = payload["target_contract_id"]

    with pytest.raises(ValidationError, match="target contract itself"):
        DependencyClosureManifestV1.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "mutated"),
    (
        ("revision", 99),
        (
            "contract_hash",
            digest_text(HashKindV1.CONTRACT, "wrong-contract").model_dump(mode="json"),
        ),
        (
            "canonical_type_hash",
            digest_text(HashKindV1.ELABORATED_TYPE, "wrong-type").model_dump(mode="json"),
        ),
        ("observed_axioms", ["Classical.choice", "propext"]),
        ("module_name", FOUNDATION),
        (
            "verification_evidence",
            _artifact(b"wrong-evidence", VERIFICATION_EVIDENCE_MEDIA_TYPE).model_dump(mode="json"),
        ),
    ),
)
def test_signed_reference_detects_dependency_field_tampering(
    field: str,
    mutated: object,
) -> None:
    manifest, reference, _blobs = fixture_dependency_closure()
    payload = manifest.model_dump(mode="json")
    accepted = payload["accepted_dependencies"]
    assert isinstance(accepted, list)
    accepted[0][field] = mutated
    raw = canonical_json_bytes(payload)

    with pytest.raises(ValueError, match="dependency closure manifest"):
        validate_dependency_closure_ref(reference, raw)


def test_manifest_cross_checks_type_axioms_and_module_against_inventory() -> None:
    payload = _manifest_payload()
    accepted = payload["accepted_dependencies"]
    assert isinstance(accepted, list)
    accepted[0]["observed_axioms"] = ["propext"]

    with pytest.raises(ValidationError, match="declaration inventory"):
        DependencyClosureManifestV1.model_validate(payload)


def test_reference_rejects_environment_and_manifest_size_drift() -> None:
    manifest, reference, _blobs = fixture_dependency_closure()
    raw = manifest.canonical_bytes()
    wrong_environment = reference.model_copy(
        update={"environment_hash": digest_text(HashKindV1.ENVIRONMENT, "wrong")}
    )
    with pytest.raises(ValueError, match="differs from its canonical manifest"):
        validate_dependency_closure_ref(wrong_environment, raw)

    payload = reference.model_dump(mode="python", round_trip=True)
    artifact = payload["closure_manifest_ref"]
    assert isinstance(artifact, dict)
    artifact["size"] += 1
    wrong_size = DependencyClosureRefV1.model_validate(payload)
    with pytest.raises(ValueError, match="size differs"):
        validate_dependency_closure_ref(wrong_size, raw)


def test_manifest_rejects_file_hash_size_and_tree_tampering() -> None:
    payload = _manifest_payload()
    files = payload["files"]
    assert isinstance(files, list)
    files[0]["artifact"]["sha256"] = "f" * 64
    with pytest.raises(ValidationError, match="tree hash"):
        DependencyClosureManifestV1.model_validate(payload)

    payload = _manifest_payload()
    files = payload["files"]
    assert isinstance(files, list)
    files[0]["artifact"]["size"] += 1
    with pytest.raises(ValidationError, match="tree hash"):
        DependencyClosureManifestV1.model_validate(payload)
