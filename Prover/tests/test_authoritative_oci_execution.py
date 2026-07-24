from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest
from autolean_contracts import VerificationSigningLeaseBindingV1
from autolean_prover.errors import ConfigurationError, ValidationError
from autolean_prover.execution import (
    FrozenTaskBundleInput,
    ImageOwnedVerifierIdentity,
    OciExecutionClaim,
    OciLeanRunner,
    OciWorkerHarness,
    OciWorkerSpec,
    ProcessRequest,
    ProcessResult,
    WorkspaceMaterializer,
)

from .helpers import frozen_bundle


@dataclass
class FenceValidator:
    current_fence: int
    calls: int = 0

    def assert_current(self, claim: OciExecutionClaim) -> None:
        self.calls += 1
        if claim.lease.fencing_token != self.current_fence:
            raise ValidationError(
                "oci_execution_claim_stale_fence",
                "OCI execution claim fencing token is stale",
            )


class RecordingHarness:
    def __init__(
        self,
        stdout: str,
        *,
        before_result: Callable[[ProcessRequest], None] | None = None,
    ) -> None:
        self.stdout = stdout
        self.before_result = before_result
        self.request: ProcessRequest | None = None
        self.requests: list[ProcessRequest] = []

    def execute(self, request: ProcessRequest) -> ProcessResult:
        if len(request.argv) >= 2 and request.argv[1] == "rm":
            return ProcessResult(
                argv=request.argv,
                returncode=0,
                stdout="",
                stderr="",
                duration_seconds=0.0,
            )
        self.request = request
        self.requests.append(request)
        phase = request.argv[request.argv.index("--phase") + 1]
        if phase == "compile":
            output_mount = next(
                request.argv[index + 1]
                for index, value in enumerate(request.argv[:-1])
                if value == "--mount" and "dst=/output" in request.argv[index + 1]
            )
            source = next(
                field.removeprefix("src=")
                for field in output_mount.split(",")
                if field.startswith("src=")
            )
            (Path(source) / "Candidate.olean").write_bytes(b"authority-test-olean")
        if self.before_result is not None:
            self.before_result(request)
        return ProcessResult(
            argv=request.argv,
            returncode=0,
            stdout=self.stdout if phase == "query" else "",
            stderr="",
            duration_seconds=0.0,
        )


def _identity() -> ImageOwnedVerifierIdentity:
    return ImageOwnedVerifierIdentity(
        wrapper_sha256="c" * 64,
        query_helper_sha256="d" * 64,
    )


def _claim(workspace, identity: ImageOwnedVerifierIdentity, *, fence: int = 7) -> OciExecutionClaim:
    return OciExecutionClaim(
        task_input=workspace.task_input,
        lease=VerificationSigningLeaseBindingV1(
            bundle_id=workspace.bundle.bundle_id,
            worker_id="oci-authority-test",
            fencing_token=fence,
            expires_at=datetime(2035, 1, 1, tzinfo=UTC),
        ),
        image_identity=identity,
        claim_id="oci-authority-claim",
        issued_at=datetime(2030, 1, 1, tzinfo=UTC),
    )


def _wrapper_record(bundle, identity: ImageOwnedVerifierIdentity) -> str:
    environment = bundle.contract.formal.environment
    canonical_type = bundle.contract.formal.elaborated_type
    assert canonical_type is not None
    return json.dumps(
        {
            "schema_version": "autolean.oci-lean-wrapper.v2",
            "declaration": bundle.proof_boundary.expected_declaration,
            "canonical_type": canonical_type,
            "lean_version": environment.lean_version,
            "mathlib_revision": environment.mathlib_revision,
            "lake_manifest_hash": (
                None
                if environment.lake_manifest_hash is None
                else environment.lake_manifest_hash.value
            ),
            "observed_axioms": [],
            "image_identity": identity.payload(),
        },
        ensure_ascii=True,
        separators=(",", ":"),
    )


def _runner(
    tmp_path: Path,
    workspace,
    harness: RecordingHarness,
    claim: OciExecutionClaim,
    validator,
):
    source = tmp_path / "source"
    dependencies = tmp_path / "dependencies"
    source.mkdir()
    dependencies.mkdir()
    for protected in workspace.protected_files:
        destination = source / protected.path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((workspace.root / protected.path).read_bytes())
    spec = OciWorkerSpec(
        runtime="docker",
        image="registry.invalid/autolean-lean@sha256:" + "a" * 64,
        dependency_root=dependencies,
        image_identity=claim.image_identity,
    )
    return OciLeanRunner(
        worker=OciWorkerHarness(harness=harness, spec=spec),
        immutable_source=source,
        execution_claim=claim,
        claim_validator=validator,
    )


def _candidate(workspace) -> Path:
    workspace.write_proof("by\n  rfl")
    return workspace.render_candidate()


def test_lease_bound_execution_binds_frozen_bundle_fence_and_image_identity(tmp_path: Path) -> None:
    workspace = WorkspaceMaterializer().materialize(frozen_bundle(), tmp_path / "attempt")
    identity = _identity()
    claim = _claim(workspace, identity)
    validator = FenceValidator(current_fence=claim.lease.fencing_token)
    harness = RecordingHarness(_wrapper_record(workspace.bundle, identity))

    evidence = _runner(tmp_path, workspace, harness, claim, validator).run(
        _candidate(workspace), workspace=workspace
    )

    execution = evidence.oci_execution_evidence
    assert execution is not None
    assert execution.authority_status == "lease-bound-pending-gateway"
    assert execution.execution_claim_hash == claim.claim_hash()
    assert execution.lease_worker_id == claim.lease.worker_id
    assert execution.lease_fencing_token == claim.lease.fencing_token
    assert execution.lease_expires_at == claim.lease.expires_at
    assert execution.wrapper_identity_hash == identity.identity_hash()
    assert execution.authority_payload()["status"] == "lease-bound-pending-gateway"
    assert validator.calls == 3
    assert harness.request is not None
    assert not any("dst=/opt" in argument for argument in harness.request.argv)


def test_lease_bound_execution_rejects_a_stale_fence_after_the_oci_process_returns(
    tmp_path: Path,
) -> None:
    workspace = WorkspaceMaterializer().materialize(frozen_bundle(), tmp_path / "attempt")
    identity = _identity()
    claim = _claim(workspace, identity)
    validator = FenceValidator(current_fence=claim.lease.fencing_token)

    def replace_lease(_request: ProcessRequest) -> None:
        validator.current_fence += 1

    harness = RecordingHarness(
        _wrapper_record(workspace.bundle, identity),
        before_result=replace_lease,
    )

    with pytest.raises(ValidationError, match="oci_execution_claim_stale_fence"):
        _runner(tmp_path, workspace, harness, claim, validator).run(
            _candidate(workspace), workspace=workspace
        )
    assert validator.calls == 2


def test_execution_claim_rejects_a_different_bundle_snapshot_with_the_same_bundle_id(
    tmp_path: Path,
) -> None:
    original = frozen_bundle()
    original_workspace = WorkspaceMaterializer().materialize(original, tmp_path / "original")
    claim = _claim(original_workspace, _identity())
    mutated = original.model_copy(update={"issued_at": datetime(2031, 1, 1, tzinfo=UTC)})
    assert mutated.bundle_id == original.bundle_id
    assert mutated.handoff_hash() != original.handoff_hash()
    mutated_input = FrozenTaskBundleInput.from_bundle(mutated)

    with pytest.raises(ValidationError, match="oci_execution_claim_bundle_mismatch"):
        claim.assert_authorizes(mutated_input, now=datetime(2031, 1, 1, tzinfo=UTC))


def test_lease_bound_execution_rejects_a_wrapper_identity_different_from_the_claim(
    tmp_path: Path,
) -> None:
    workspace = WorkspaceMaterializer().materialize(frozen_bundle(), tmp_path / "attempt")
    claimed_identity = _identity()
    observed_identity = ImageOwnedVerifierIdentity(
        wrapper_sha256="e" * 64,
        query_helper_sha256=claimed_identity.query_helper_sha256,
    )
    claim = _claim(workspace, claimed_identity)
    harness = RecordingHarness(_wrapper_record(workspace.bundle, observed_identity))

    with pytest.raises(ValidationError, match="oci_wrapper_identity_mismatch"):
        _runner(
            tmp_path,
            workspace,
            harness,
            claim,
            FenceValidator(current_fence=claim.lease.fencing_token),
        ).run(_candidate(workspace), workspace=workspace)


def test_execution_claim_cannot_enable_authoritative_mode_without_a_live_validator(
    tmp_path: Path,
) -> None:
    workspace = WorkspaceMaterializer().materialize(frozen_bundle(), tmp_path / "attempt")
    identity = _identity()
    claim = _claim(workspace, identity)
    source = tmp_path / "source"
    dependencies = tmp_path / "dependencies"
    source.mkdir()
    dependencies.mkdir()

    with pytest.raises(ConfigurationError, match="claim and a live claim validator"):
        OciLeanRunner(
            worker=OciWorkerHarness(
                harness=RecordingHarness(_wrapper_record(workspace.bundle, identity)),
                spec=OciWorkerSpec(
                    runtime="docker",
                    image="registry.invalid/autolean-lean@sha256:" + "a" * 64,
                    dependency_root=dependencies,
                    image_identity=identity,
                ),
            ),
            immutable_source=source,
            execution_claim=claim,
        )


def test_claim_is_not_valid_when_its_lease_has_expired(tmp_path: Path) -> None:
    workspace = WorkspaceMaterializer().materialize(frozen_bundle(), tmp_path / "attempt")
    identity = _identity()
    claim = _claim(workspace, identity)

    with pytest.raises(ValidationError, match="oci_execution_claim_expired"):
        claim.assert_authorizes(workspace.task_input, now=datetime(2035, 1, 1, tzinfo=UTC))
