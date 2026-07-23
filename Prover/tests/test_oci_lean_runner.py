from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path

import pytest
from autolean_contracts import HashKindV1, ProofSubmissionV1, digest_text
from autolean_prover.errors import ValidationError
from autolean_prover.execution import (
    MaterializedWorkspace,
    OciLeanRunner,
    OciWorkerHarness,
    OciWorkerSpec,
    ProcessRequest,
    ProcessResult,
    WorkspaceMaterializer,
)
from autolean_prover.verification import TrustedLeanVerifier

from .helpers import frozen_bundle, stable_id


class RecordingHarness:
    """Fake OCI runtime: records argv and returns only test-controlled wrapper output."""

    def __init__(
        self,
        *,
        stdout: str,
        returncode: int | None = 0,
        timed_out: bool = False,
        output_truncated: bool = False,
        before_result: Callable[[ProcessRequest], None] | None = None,
        reported_argv: tuple[str, ...] | None = None,
    ) -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.timed_out = timed_out
        self.output_truncated = output_truncated
        self.before_result = before_result
        self.reported_argv = reported_argv
        self.request: ProcessRequest | None = None

    def execute(self, request: ProcessRequest) -> ProcessResult:
        self.request = request
        if self.before_result is not None:
            self.before_result(request)
        return ProcessResult(
            argv=request.argv if self.reported_argv is None else self.reported_argv,
            returncode=self.returncode,
            stdout=self.stdout,
            stderr="",
            duration_seconds=0.0,
            timed_out=self.timed_out,
            output_truncated=self.output_truncated,
        )


def _wrapper_record(bundle, **overrides: object) -> str:
    environment = bundle.contract.formal.environment
    canonical_type = bundle.contract.formal.elaborated_type
    assert canonical_type is not None
    payload: dict[str, object] = {
        "schema_version": "autolean.oci-lean-wrapper.v1",
        "declaration": bundle.proof_boundary.expected_declaration,
        "canonical_type": canonical_type,
        "lean_version": environment.lean_version,
        "mathlib_revision": environment.mathlib_revision,
        "lake_manifest_hash": (
            None if environment.lake_manifest_hash is None else environment.lake_manifest_hash.value
        ),
        "observed_axioms": [],
    }
    payload.update(overrides)
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def _submission(bundle, proof: str = "by\n  rfl") -> ProofSubmissionV1:
    return ProofSubmissionV1(
        proof_id=stable_id("oci-proof"),
        contract_id=bundle.contract.contract_id,
        revision=bundle.contract.revision,
        contract_hash=bundle.contract.semantic_hash(),
        proof_boundary_hash=bundle.proof_boundary.boundary_hash,
        proof_source=proof,
        proof_source_hash=digest_text(HashKindV1.PROOF_SOURCE, proof),
        environment_hash=bundle.contract.formal.environment.environment_hash,
    )


def _copy_frozen_source(workspace: MaterializedWorkspace, source: Path) -> None:
    for protected in workspace.protected_files:
        destination = source / protected.path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((workspace.root / protected.path).read_bytes())


def _runner(
    tmp_path: Path,
    workspace: MaterializedWorkspace,
    harness: RecordingHarness,
) -> tuple[OciLeanRunner, OciWorkerSpec, Path]:
    source = tmp_path / "source"
    dependencies = tmp_path / "deps"
    source.mkdir()
    dependencies.mkdir()
    _copy_frozen_source(workspace, source)
    spec = OciWorkerSpec(
        runtime="docker",
        image="registry.invalid/autolean-lean@sha256:" + "a" * 64,
        dependency_root=dependencies,
    )
    runner = OciLeanRunner(
        worker=OciWorkerHarness(harness=harness, spec=spec),
        immutable_source=source,
    )
    return runner, spec, source


def _render_candidate(workspace: MaterializedWorkspace) -> Path:
    workspace.write_proof("by\n  rfl")
    return workspace.render_candidate()


def test_oci_lean_runner_uses_fixed_wrapper_argv_and_emits_execution_evidence(tmp_path) -> None:
    bundle = frozen_bundle()
    workspace = WorkspaceMaterializer().materialize(bundle, tmp_path / "attempt")
    candidate = _render_candidate(workspace)
    harness = RecordingHarness(stdout=_wrapper_record(bundle))
    runner, spec, _source = _runner(tmp_path, workspace, harness)

    evidence = runner.run(candidate, workspace=workspace)

    assert harness.request is not None
    argv = harness.request.argv
    image_index = argv.index(spec.image)
    assert argv[image_index:] == (
        spec.image,
        "/opt/autolean/bin/autolean-lean-wrapper",
        "--protocol",
        "autolean.oci-lean-wrapper.v1",
        "--candidate",
        "/input/Candidate.lean",
        "--declaration",
        bundle.proof_boundary.expected_declaration,
        "--type-format",
        "autolean.lean-pp-expr.v1",
    )
    assert (argv[3], argv[4]) == ("--network", "none")
    assert "--read-only" in argv
    assert f"type=bind,src={candidate.resolve()},dst=/input/Candidate.lean,readonly" in argv
    assert "/bin/sh" not in argv
    assert "by\n  rfl" not in argv
    assert bundle.proof_boundary.expected_elaborated_type_hash.value not in argv
    assert evidence.elaborated_type_evidence is not None
    assert (
        evidence.elaborated_type_evidence.canonical_type == bundle.contract.formal.elaborated_type
    )
    assert evidence.observed_axioms == ()
    assert evidence.oci_execution_evidence is not None
    assert evidence.oci_execution_evidence.worker_image_digest == "sha256:" + "a" * 64
    assert (
        evidence.oci_execution_evidence.command_hash
        == hashlib.sha256(
            json.dumps(argv, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
    )
    assert (
        evidence.oci_execution_evidence.candidate_sha256
        == hashlib.sha256(candidate.read_bytes()).hexdigest()
    )
    assert evidence.oci_execution_evidence.trusted_statement_sha256 == next(
        item.sha256
        for item in workspace.protected_files
        if item.path == bundle.proof_boundary.trusted_statement_path
    )


@pytest.mark.parametrize(
    ("mode", "error_code"),
    [
        ("malformed", "oci_wrapper_output_malformed"),
        ("spoofed_type_hash", "oci_wrapper_output_shape"),
        ("duplicate_field", "oci_wrapper_output_malformed"),
        ("wrong_declaration", "oci_wrapper_declaration_mismatch"),
    ],
)
def test_oci_lean_runner_rejects_malformed_or_spoofed_wrapper_records(
    tmp_path: Path,
    mode: str,
    error_code: str,
) -> None:
    bundle = frozen_bundle()
    workspace = WorkspaceMaterializer().materialize(bundle, tmp_path / "attempt")
    candidate = _render_candidate(workspace)
    stdout = _wrapper_record(bundle)
    if mode == "malformed":
        stdout = "not-json"
    elif mode == "spoofed_type_hash":
        stdout = _wrapper_record(bundle, type_hash="f" * 64)
    elif mode == "duplicate_field":
        prefix = '"schema_version":"autolean.oci-lean-wrapper.v1",'
        stdout = stdout.replace(prefix, prefix + prefix, 1)
    else:
        stdout = _wrapper_record(bundle, declaration="AutoLean.Test.other")
    harness = RecordingHarness(stdout=stdout)
    runner, _spec, _source = _runner(tmp_path, workspace, harness)

    with pytest.raises(ValidationError, match=error_code):
        runner.run(candidate, workspace=workspace)


def test_oci_lean_runner_binds_source_snapshot_to_frozen_workspace_bytes(tmp_path) -> None:
    bundle = frozen_bundle()
    workspace = WorkspaceMaterializer().materialize(bundle, tmp_path / "attempt")
    candidate = _render_candidate(workspace)
    harness = RecordingHarness(stdout=_wrapper_record(bundle))
    runner, _spec, source = _runner(tmp_path, workspace, harness)
    source_statement = source / bundle.proof_boundary.trusted_statement_path
    source_statement.write_text("theorem fixture : True\n", encoding="utf-8")

    with pytest.raises(ValidationError, match="oci_source_snapshot_mismatch"):
        runner.run(candidate, workspace=workspace)
    assert harness.request is None


def test_oci_lean_runner_rejects_a_symlinked_source_snapshot_file(tmp_path) -> None:
    bundle = frozen_bundle()
    workspace = WorkspaceMaterializer().materialize(bundle, tmp_path / "attempt")
    candidate = _render_candidate(workspace)
    harness = RecordingHarness(stdout=_wrapper_record(bundle))
    runner, _spec, source = _runner(tmp_path, workspace, harness)
    source_statement = source / bundle.proof_boundary.trusted_statement_path
    outside = tmp_path / "outside.lean"
    outside.write_bytes(source_statement.read_bytes())
    source_statement.unlink()
    try:
        source_statement.symlink_to(outside)
    except OSError:
        pytest.skip("symbolic links are unavailable on this Windows configuration")

    with pytest.raises(ValidationError, match="oci_source_snapshot_symlink"):
        runner.run(candidate, workspace=workspace)
    assert harness.request is None


def test_oci_lean_runner_detects_candidate_tampering_after_worker_execution(tmp_path) -> None:
    bundle = frozen_bundle()
    workspace = WorkspaceMaterializer().materialize(bundle, tmp_path / "attempt")
    candidate = _render_candidate(workspace)

    def tamper_candidate(_request: ProcessRequest) -> None:
        candidate.write_text("theorem fixture : True\n", encoding="utf-8")

    harness = RecordingHarness(stdout=_wrapper_record(bundle), before_result=tamper_candidate)
    runner, _spec, _source = _runner(tmp_path, workspace, harness)

    with pytest.raises(ValidationError, match="oci_candidate_changed"):
        runner.run(candidate, workspace=workspace)


def test_oci_lean_runner_rejects_a_pre_execution_candidate_statement_replacement(tmp_path) -> None:
    bundle = frozen_bundle()
    workspace = WorkspaceMaterializer().materialize(bundle, tmp_path / "attempt")
    candidate = _render_candidate(workspace)
    candidate.write_text("theorem fixture : True := by trivial\n", encoding="utf-8")
    harness = RecordingHarness(stdout=_wrapper_record(bundle))
    runner, _spec, _source = _runner(tmp_path, workspace, harness)

    with pytest.raises(ValidationError, match="oci_candidate_content_mismatch"):
        runner.run(candidate, workspace=workspace)
    assert harness.request is None


def test_oci_lean_runner_rejects_mismatched_runtime_execution_evidence(tmp_path) -> None:
    bundle = frozen_bundle()
    workspace = WorkspaceMaterializer().materialize(bundle, tmp_path / "attempt")
    candidate = _render_candidate(workspace)
    harness = RecordingHarness(
        stdout=_wrapper_record(bundle),
        reported_argv=("docker", "run", "different-command"),
    )
    runner, _spec, _source = _runner(tmp_path, workspace, harness)

    with pytest.raises(ValidationError, match="oci_runtime_argv_mismatch"):
        runner.run(candidate, workspace=workspace)


def test_oci_lean_runner_is_injectable_and_rejects_a_wrong_frozen_type(tmp_path) -> None:
    bundle = frozen_bundle()
    workspace = WorkspaceMaterializer().materialize(bundle, tmp_path / "attempt")
    harness = RecordingHarness(stdout=_wrapper_record(bundle, canonical_type="True"))
    runner, _spec, _source = _runner(tmp_path, workspace, harness)

    report = TrustedLeanVerifier(runner=runner, verifier_id="oci-fake").verify(
        workspace,
        _submission(bundle),
    )

    assert not report.kernel_passed
    assert not report.build_passed
    assert "elaborated-type hash differs" in report.details


def test_oci_lean_runner_fails_closed_when_worker_tampers_with_protected_file(tmp_path) -> None:
    bundle = frozen_bundle()
    workspace = WorkspaceMaterializer().materialize(bundle, tmp_path / "attempt")
    protected = workspace.root / bundle.proof_boundary.trusted_statement_path

    def tamper_protected(_request: ProcessRequest) -> None:
        protected.chmod(0o644)
        protected.write_text("theorem fixture : True\n", encoding="utf-8")

    harness = RecordingHarness(stdout=_wrapper_record(bundle), before_result=tamper_protected)
    runner, _spec, _source = _runner(tmp_path, workspace, harness)

    report = TrustedLeanVerifier(runner=runner, verifier_id="oci-fake").verify(
        workspace,
        _submission(bundle),
    )

    assert not report.kernel_passed
    assert not report.build_passed
    assert not report.dependency_check_passed
    assert "protected workspace file changed" in report.details
