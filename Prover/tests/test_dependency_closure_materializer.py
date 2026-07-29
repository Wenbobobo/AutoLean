from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import pytest
from autolean_contracts import (
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
    HashKindV1,
    build_dependency_closure_ref,
    dependency_tree_hash,
    digest_text,
    stable_identifier,
)
from autolean_prover.execution import (
    ClaimScopedDependencyBlobReader,
    DependencyClosureIntegrityError,
    DependencyClosureMaterializer,
)
from autolean_prover.execution import dependency_closure as closure_materializer

FOUNDATION = "AutoLeanLibrary.Fixtures.Dag.Foundation"
BRIDGE = "AutoLeanLibrary.Fixtures.Dag.Bridge"
CERTIFICATE = "AutoLeanLibrary.Fixtures.Dag.Certificate"


@dataclass
class MappingBlobReader:
    blobs: dict[str, bytes]

    def read_blob(self, reference: DependencyClosureArtifactRefV1) -> bytes:
        return self.blobs[reference.sha256]


@dataclass
class RootMutatingBlobReader:
    blobs: dict[str, bytes]
    root: Path
    outside: Path
    calls: list[str]

    def read_blob(self, reference: DependencyClosureArtifactRefV1) -> bytes:
        self.calls.append(reference.sha256)
        if len(self.calls) == 1:
            try:
                self.root.symlink_to(self.outside, target_is_directory=True)
            except OSError:
                self.root.mkdir()
                (self.root / "reader-owned-marker").write_bytes(b"reader mutation")
        return self.blobs[reference.sha256]


def _fixture() -> tuple[
    DependencyClosureManifestV1,
    DependencyClosureRefV1,
    MappingBlobReader,
    dict[str, bytes],
]:
    runtime_blobs = {
        FOUNDATION.replace(".", "/") + ".olean": b"fixture Foundation OLean\n",
        BRIDGE.replace(".", "/") + ".olean": b"fixture Bridge OLean\n",
        CERTIFICATE.replace(".", "/") + ".olean": b"fixture Certificate OLean\n",
    }
    files = tuple(
        DependencyClosureFileV1(
            relative_path=relative_path,
            artifact=_artifact(data, LEAN_OLEAN_MEDIA_TYPE),
        )
        for relative_path, data in sorted(runtime_blobs.items())
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
            digest_text(HashKindV1.ELABORATED_TYPE, "bridge-type"),
            (),
        ),
        (
            "AutoLeanLibrary.Fixtures.Dag.certificate_normalize",
            CERTIFICATE,
            digest_text(HashKindV1.ELABORATED_TYPE, "certificate-type"),
            ("Classical.choice",),
        ),
        (
            "AutoLeanLibrary.Fixtures.Dag.foundation_add_zero",
            FOUNDATION,
            digest_text(HashKindV1.ELABORATED_TYPE, "foundation-type"),
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
                        f"evidence:{name}".encode(),
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
        closure_id=stable_identifier("dependency-closure", "prover-stage-a"),
        environment_hash=digest_text(HashKindV1.ENVIRONMENT, "pinned-environment"),
        tree_hash=dependency_tree_hash(files),
        target_contract_id=stable_identifier("contract", "capstone"),
        target_revision=1,
        target_contract_hash=digest_text(HashKindV1.CONTRACT, "capstone:r1"),
        target_declaration="AutoLeanLibrary.Fixtures.Dag.capstone",
        target_canonical_type_hash=digest_text(
            HashKindV1.ELABORATED_TYPE,
            "capstone-type",
        ),
        entry_modules=(CERTIFICATE,),
        files=files,
        modules=modules,
        declaration_inventory=inventory,
        accepted_dependencies=accepted,
    )
    reference = build_dependency_closure_ref(manifest)
    blobs = {
        reference.closure_manifest_ref.sha256: manifest.canonical_bytes(),
        **{entry.artifact.sha256: runtime_blobs[entry.relative_path] for entry in manifest.files},
    }
    return manifest, reference, MappingBlobReader(blobs), runtime_blobs


def _artifact(data: bytes, media_type: str) -> DependencyClosureArtifactRefV1:
    return DependencyClosureArtifactRefV1(
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        media_type=media_type,
    )


def test_materializes_three_module_fixture_from_only_manifest_selected_blobs(
    tmp_path: Path,
) -> None:
    manifest, reference, reader, runtime_blobs = _fixture()
    materialized = DependencyClosureMaterializer().materialize(
        reference,
        tmp_path / "deps",
        reader=reader,
    )

    assert materialized.manifest == manifest
    for relative_path, expected in runtime_blobs.items():
        assert (materialized.root / Path(relative_path)).read_bytes() == expected
    materialized.validate_integrity()


def test_claim_scoped_reader_adapter_preserves_narrow_materializer_capability(
    tmp_path: Path,
) -> None:
    manifest, reference, reader, runtime_blobs = _fixture()
    scoped = ClaimScopedDependencyBlobReader(read_claimed_artifact=reader.read_blob)
    materialized = DependencyClosureMaterializer().materialize(
        reference,
        tmp_path / "claim-scoped-deps",
        reader=scoped,
    )

    assert materialized.manifest == manifest
    for relative_path, expected in runtime_blobs.items():
        assert (materialized.root / Path(relative_path)).read_bytes() == expected


def test_missing_or_changed_blob_fails_before_a_complete_tree_is_returned(tmp_path: Path) -> None:
    manifest, reference, reader, _runtime_blobs = _fixture()
    missing = manifest.files[0].artifact.sha256
    del reader.blobs[missing]
    with pytest.raises(DependencyClosureIntegrityError, match="unavailable"):
        DependencyClosureMaterializer().materialize(
            reference,
            tmp_path / "missing",
            reader=reader,
        )

    _manifest, reference, reader, _runtime_blobs = _fixture()
    changed = _manifest.files[0].artifact.sha256
    reader.blobs[changed] = b"changed"
    with pytest.raises(DependencyClosureIntegrityError, match="content reference"):
        DependencyClosureMaterializer().materialize(
            reference,
            tmp_path / "changed",
            reader=reader,
        )


def test_manifest_environment_drift_fails_against_the_reference(tmp_path: Path) -> None:
    manifest, reference, reader, _runtime_blobs = _fixture()
    payload = manifest.model_dump(mode="python", round_trip=True)
    payload["environment_hash"] = digest_text(HashKindV1.ENVIRONMENT, "different")
    drifted = DependencyClosureManifestV1.model_validate(payload)
    raw = drifted.canonical_bytes()
    reader.blobs[reference.closure_manifest_ref.sha256] = raw

    with pytest.raises(DependencyClosureIntegrityError, match="manifest"):
        DependencyClosureMaterializer().materialize(
            reference,
            tmp_path / "environment-drift",
            reader=reader,
        )


def test_nonempty_root_rejects_extra_runtime_content(tmp_path: Path) -> None:
    _manifest, reference, reader, _runtime_blobs = _fixture()
    root = tmp_path / "deps"
    root.mkdir()
    (root / "extra.olean").write_bytes(b"not selected by manifest")

    with pytest.raises(DependencyClosureIntegrityError, match="must not exist"):
        DependencyClosureMaterializer().materialize(reference, root, reader=reader)


def test_reader_root_mutation_is_rejected_before_materializer_writes(
    tmp_path: Path,
) -> None:
    _manifest, reference, reader, _runtime_blobs = _fixture()
    root = tmp_path / "deps"
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_bytes(b"unchanged")
    mutating_reader = RootMutatingBlobReader(
        blobs=reader.blobs,
        root=root,
        outside=outside,
        calls=[],
    )

    with pytest.raises(DependencyClosureIntegrityError, match="must not exist"):
        DependencyClosureMaterializer().materialize(
            reference,
            root,
            reader=mutating_reader,
        )

    assert len(mutating_reader.calls) == len(reader.blobs)
    assert len(set(mutating_reader.calls)) == len(mutating_reader.calls)
    assert sentinel.read_bytes() == b"unchanged"
    assert {path.relative_to(outside).as_posix() for path in outside.rglob("*")} == {"sentinel"}


def test_root_symlink_and_reparse_point_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _manifest, reference, reader, _runtime_blobs = _fixture()
    outside = tmp_path / "outside"
    outside.mkdir()
    linked = tmp_path / "linked-deps"
    try:
        linked.symlink_to(outside, target_is_directory=True)
    except OSError:
        pass
    else:
        with pytest.raises(DependencyClosureIntegrityError, match="symbolic link"):
            DependencyClosureMaterializer().materialize(reference, linked, reader=reader)

    simulated = tmp_path / "simulated-reparse"
    original = closure_materializer._is_link_or_reparse

    def report_reparse(path: Path) -> bool:
        return path.absolute() == simulated.absolute() or original(path)

    monkeypatch.setattr(closure_materializer, "_is_link_or_reparse", report_reparse)
    with pytest.raises(DependencyClosureIntegrityError, match="reparse point"):
        DependencyClosureMaterializer().materialize(reference, simulated, reader=reader)


def test_materialized_tree_detects_replacement_missing_and_extra_files(tmp_path: Path) -> None:
    manifest, reference, reader, _runtime_blobs = _fixture()
    materialized = DependencyClosureMaterializer().materialize(
        reference,
        tmp_path / "deps",
        reader=reader,
    )
    first = materialized.root / Path(manifest.files[0].relative_path)
    first.chmod(0o644)
    first.write_bytes(b"replacement")
    with pytest.raises(DependencyClosureIntegrityError, match="wrong"):
        materialized.validate_integrity()

    first.write_bytes(reader.blobs[manifest.files[0].artifact.sha256])
    first.unlink()
    with pytest.raises(DependencyClosureIntegrityError, match="files differ"):
        materialized.validate_integrity()

    first.parent.mkdir(parents=True, exist_ok=True)
    first.write_bytes(reader.blobs[manifest.files[0].artifact.sha256])
    (materialized.root / "AutoLeanLibrary" / "Extra.olean").write_bytes(b"extra")
    with pytest.raises(DependencyClosureIntegrityError, match="files differ"):
        materialized.validate_integrity()


def test_materialized_tree_detects_a_post_write_symlink(tmp_path: Path) -> None:
    manifest, reference, reader, _runtime_blobs = _fixture()
    materialized = DependencyClosureMaterializer().materialize(
        reference,
        tmp_path / "deps",
        reader=reader,
    )
    first = materialized.root / Path(manifest.files[0].relative_path)
    outside = tmp_path / "outside.olean"
    outside.write_bytes(first.read_bytes())
    first.chmod(0o644)
    first.unlink()
    try:
        first.symlink_to(outside)
    except OSError:
        pytest.skip("symbolic links are unavailable on this Windows configuration")

    with pytest.raises(DependencyClosureIntegrityError, match="link or reparse"):
        materialized.validate_integrity()
