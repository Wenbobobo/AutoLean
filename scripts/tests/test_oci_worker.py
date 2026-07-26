from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from pathlib import Path

import pytest
from autolean_builder import ReferenceManifestV1
from autolean_contracts import (
    AttestationPurposeV1,
    HmacAttestationKeyV1,
    HmacAttestationSignerV1,
    HmacAttestationVerifierV1,
)
from autolean_control_plane import ArtifactStore, ControlPlane, EventStore, LeaseStore

from benchmarks.source_backed_oci_fixture import (
    build_source_backed_oci_fixture,
)
from scripts import oci_worker, oci_worker_canary


def test_worker_build_inputs_and_digests_are_frozen() -> None:
    assert oci_worker.WORKER_FILES == (
        "Dockerfile",
        "AutoleanLeanQuery.lean",
        "autolean-lean-wrapper",
    )
    assert (
        oci_worker.BASE_IMAGE_DIGEST
        == "sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90"
    )
    assert (
        oci_worker.LEAN_ARCHIVE_SHA256
        == "ceb3a3f844f7aebf63245e2b51c28d5b0ed38942c19f93cf3febd520302160bd"
    )


def test_canary_wsl_environment_includes_source_backed_builder_runtime() -> None:
    assert oci_worker.CANARY_RUNTIME_PACKAGES == (
        "autolean-prover",
        "autolean-control-plane",
        "autolean-builder",
    )


def test_wrong_cached_archive_is_preserved_and_rejected(tmp_path: Path) -> None:
    archive = tmp_path / oci_worker.LEAN_ARCHIVE
    archive.write_bytes(b"not the pinned Lean archive")

    with pytest.raises(RuntimeError, match="cached Lean archive digest mismatch"):
        oci_worker._archive(tmp_path)

    assert archive.read_bytes() == b"not the pinned Lean archive"


def test_archive_staging_copies_bytes_and_rechecks_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = tmp_path / "archive"
    staged = tmp_path / "different-filesystem-contract" / "archive"
    staged.parent.mkdir()
    archive.write_bytes(b"pinned archive fixture")
    monkeypatch.setattr(
        oci_worker,
        "LEAN_ARCHIVE_SHA256",
        hashlib.sha256(archive.read_bytes()).hexdigest(),
    )

    oci_worker._stage_archive(archive, staged)

    assert staged.read_bytes() == archive.read_bytes()


def test_direct_canary_command_freezes_the_oci_isolation_profile(tmp_path: Path) -> None:
    candidate = tmp_path / "Candidate.lean"
    candidate.write_text("theorem fixture : True := by trivial\n", encoding="utf-8")
    output = tmp_path / "output"
    output.mkdir()
    compiled = tmp_path / "Candidate.olean"
    compiled.write_bytes(b"compiled")
    image = "autolean/lean-worker@sha256:" + "a" * 64

    compile_command = oci_worker_canary._compile_command(
        image,
        candidate,
        output,
        "autolean-test-compile",
    )
    query_command = oci_worker_canary._query_command(
        image,
        compiled,
        "autolean-test-query",
    )

    for command in (compile_command, query_command):
        assert command[:3] == ["docker", "run", "--name"]
        assert command[command.index("--network") :][:2] == ["--network", "none"]
        assert "--read-only" in command
        assert command[command.index("--cap-drop") :][:2] == ["--cap-drop", "ALL"]
        assert command[command.index("--security-opt") :][:2] == [
            "--security-opt",
            "no-new-privileges",
        ]
        assert "/tmp:rw,noexec,nosuid,size=256m" in command
        assert image in command
        assert "/bin/sh" not in command
        assert "True" not in command
        assert not any("dst=/work" in argument for argument in command)
    assert any(
        "dst=/output" in argument and "readonly" not in argument for argument in compile_command
    )
    assert any(
        "dst=/compiled/Candidate.olean" in argument and "readonly" in argument
        for argument in query_command
    )


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits are authoritative on Linux")
def test_direct_canary_limits_cross_uid_output_access_to_compile_phase(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "Candidate.lean"
    candidate.write_text("theorem fixture : True := by trivial\n", encoding="utf-8")
    observed: dict[str, int] = {}
    output_root: Path | None = None

    def fake_run_phase(
        command: list[str],
        container_name: str,
    ) -> subprocess.CompletedProcess[str]:
        del container_name
        nonlocal output_root
        phase = command[command.index("--phase") + 1]
        if phase == "compile":
            mount = next(value for value in command if "dst=/output" in value)
            source = next(
                field.removeprefix("src=") for field in mount.split(",") if field.startswith("src=")
            )
            output_root = Path(source)
            observed["parent"] = stat.S_IMODE(output_root.parent.stat().st_mode)
            observed["compile"] = stat.S_IMODE(output_root.stat().st_mode)
            (output_root / "Candidate.olean").write_bytes(b"canary-olean")
        else:
            assert output_root is not None
            observed["query"] = stat.S_IMODE(output_root.stat().st_mode)
        return subprocess.CompletedProcess(command, 0, "{}", "")

    monkeypatch.setattr(oci_worker_canary, "_run_phase", fake_run_phase)

    result = oci_worker_canary._direct(
        "autolean/lean-worker@sha256:" + ("a" * 64),
        candidate,
    )

    assert result.returncode == 0
    assert observed == {"parent": 0o700, "compile": 0o733, "query": 0o700}


def test_real_canary_bundle_binds_reviewed_source_image_and_pure_lean_boundary(
    tmp_path: Path,
) -> None:
    digest = "sha256:" + "b" * 64
    builder_key = HmacAttestationKeyV1(
        key_id="source-backed-oci-unit-builder-v1",
        secret=b"source-backed-oci-public-unit-fixture-key",
        allowed_purposes=frozenset({AttestationPurposeV1.BUILDER_FREEZE}),
    )
    database = tmp_path / "control.db"
    plane = ControlPlane(
        events=EventStore(database),
        leases=LeaseStore(database),
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        attestation_verifier=HmacAttestationVerifierV1({builder_key.key_id: builder_key}),
        allow_test_only_non_authoritative_canonical_type_evidence=True,
    )
    fixture = build_source_backed_oci_fixture(
        tmp_path / "source",
        artifact_store=plane.artifacts,
        image_digest=digest,
        attestor=HmacAttestationSignerV1(builder_key),
    )
    replay = build_source_backed_oci_fixture(
        tmp_path / "replay-source",
        artifact_store=ArtifactStore(tmp_path / "replay-artifacts"),
        image_digest=digest,
        attestor=HmacAttestationSignerV1(builder_key),
    )
    bundle = fixture.bundle
    registered = plane.register_bundle(bundle, idempotency_key="register-source-backed")
    replayed = plane.register_bundle(
        replay.bundle,
        idempotency_key="register-source-backed-replay",
    )

    assert plane.allow_test_only_unreviewed_bundles is False
    assert registered.canonical_type_assurance == "scripted_fake"
    assert registered.canonical_type_promotion_authority is False
    assert replayed == registered
    assert bundle.proof_boundary.expected_declaration == oci_worker_canary.DECLARATION
    assert bundle.contract.formal.elaborated_type == "\u2200 (n : Nat), @Eq.{1} Nat n n"
    assert bundle.contract.formal.imports_allowlist == ()
    assert bundle.contract.formal.environment.mathlib_revision == "none-pure-lean-v4.28.0"
    assert bundle.contract.revision == 2
    assert bundle.graphs.mathematical.revision == 2
    assert bundle.graphs.formal.revision == 2
    assert bundle.graphs.execution.revision == 2
    assert bundle.contract.formal.environment.verifier_execution_policy.schema_version == "2.0"
    assert (
        bundle.contract.formal.environment.verifier_execution_policy.worker_image_digest == digest
    )
    assert bundle.contract.freeze is not None
    assert bundle.contract.fidelity is not None
    assert all(
        signoff.reviewed_at <= bundle.contract.freeze.frozen_at
        for signoff in bundle.contract.fidelity.signoffs
    )
    assert bundle.contract.fidelity.generated_at <= bundle.contract.freeze.frozen_at
    assert bundle.contract.freeze.frozen_at <= bundle.issued_at
    assert bundle.contract.fidelity.evidence_hash == fixture.evaluation.evidence_hash
    assert fixture.fidelity_artifact.digest == fixture.evaluation.evidence_hash.value
    derivation = fixture.packet.contract.source.metadata["derivation"]
    assert isinstance(derivation, dict)
    assert derivation["kind"] == "local_pdf_text_extraction"
    assert derivation["parent_sha256"] == fixture.packet.parent_artifact_sha256
    assert derivation["tool_name"] == "pypdf"
    assert derivation["tool_version"] == "6.14.2"
    assert derivation["parent_locator_authority"] == "manifest_bound"
    manifest = ReferenceManifestV1.load(tmp_path / "source" / "manifest.json")
    parent_entry = manifest.require("oci-source-backed-parent-v1")
    derived_entry = manifest.require("oci-source-backed-text-v1")
    assert parent_entry.acquisition_policy.value == "operator_only"
    assert derived_entry.acquisition_policy.value == "local_derivation_only"
    assert derived_entry.download_url is None
    assert fixture.packet.preparation_record().parent_artifact_sha256 == (
        fixture.packet.parent_artifact_sha256
    )
    assert fixture.packet.artifact_sha256 != fixture.packet.parent_artifact_sha256
    assert replay.evaluation.evidence_hash == fixture.evaluation.evidence_hash
    assert replay.bundle.contract.semantic_hash() == bundle.contract.semantic_hash()
    assert replay.bundle.proof_boundary == bundle.proof_boundary
    assert replay.bundle.handoff_hash() == bundle.handoff_hash()


def test_worker_assets_enforce_archive_query_and_non_root_runtime() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    worker = repo_root / "Prover" / "worker"
    dockerfile = (worker / "Dockerfile").read_text(encoding="utf-8")
    helper = (worker / "AutoleanLeanQuery.lean").read_text(encoding="utf-8")
    wrapper = (worker / "autolean-lean-wrapper").read_text(encoding="utf-8")

    assert "sha256sum --check --strict" in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert "apt-get" not in dockerfile
    assert "collectAxioms declaration" in helper
    assert "`pp.all true" in helper
    assert "`pp.notation false" in helper
    assert '>"$scratch/compiler.stdout"' in wrapper
    assert 'result_lines=$(wc -l <"$scratch/query.stdout")' in wrapper
