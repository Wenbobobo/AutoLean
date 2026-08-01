"""Exercise the real pure-Lean worker and the repository OciLeanRunner boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from autolean_contracts import (
    ActorKindV1,
    AttestationPurposeV1,
    FormalizationTaskBundleV1,
    HashKindV1,
    HmacAttestationKeyV1,
    HmacAttestationSignerV1,
    HmacAttestationVerifierV1,
    ProofSubmissionV1,
    ProvenanceTraceV1,
    StableIdentifierV1,
    VerificationEvidenceArtifactV2,
    VerificationSigningLeaseBindingV1,
    VerificationSigningRequestV1,
    digest_text,
    stable_identifier,
)
from autolean_control_plane import (
    ArtifactStore,
    ControlPlane,
    EventStore,
    FixtureHmacIndependentExecutionReceiptAuthenticator,
    IndependentExecutionClassV1,
    IndependentExecutionReceiptV1,
    IndependentExecutionTrustPolicyV1,
    LeaseStore,
    TrustedIndependentExecutionVerifierV1,
    VerifierSigningGateway,
)
from autolean_prover.errors import ValidationError
from autolean_prover.execution import (
    CleanSubprocessHarness,
    ImageOwnedVerifierIdentity,
    MaterializedWorkspace,
    OciExecutionClaim,
    OciLeanRunner,
    OciWorkerHarness,
    OciWorkerSpec,
    WorkspaceMaterializer,
)
from autolean_prover.verification import TrustedLeanVerifier
from autolean_prover.verification_gateway import attest_oci_observation_via_gateway

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from benchmarks.source_backed_oci_fixture import (  # noqa: E402
    CANONICAL_TYPE,
    LEAN_VERSION,
    MATHLIB_REVISION,
    PROTOCOL,
    TYPE_FORMAT,
    build_source_backed_oci_fixture,
)
from benchmarks.source_backed_oci_fixture import (  # noqa: E402
    DECLARATION as _DECLARATION,
)

DECLARATION: Final[str] = _DECLARATION
SEALED_CANDIDATE_MAX_BYTES: Final[int] = 256 * 1024 * 1024
_VERIFIER_KEY: Final[HmacAttestationKeyV1] = HmacAttestationKeyV1(
    key_id="oci-canary-verifier-v1",
    secret=b"local-oci-canary-verifier-key-0123456789",
    allowed_purposes=frozenset({AttestationPurposeV1.VERIFICATION}),
)
_BUILDER_KEY: Final[HmacAttestationKeyV1] = HmacAttestationKeyV1(
    key_id="oci-canary-builder-v1",
    secret=b"local-oci-canary-builder-key-01234567890",
    allowed_purposes=frozenset({AttestationPurposeV1.BUILDER_FREEZE}),
)
_INDEPENDENT_RECEIPT_AUTHENTICATOR: Final[FixtureHmacIndependentExecutionReceiptAuthenticator] = (
    FixtureHmacIndependentExecutionReceiptAuthenticator(
        key_id="oci-canary-independent-execution-v2",
        secret=b"local-oci-canary-independent-execution-key-0123456789",
    )
)
_INDEPENDENT_VERIFIER_ID: Final[str] = "oci-real-canary-independent-wrapper-v2"


def _stable_id(key: str) -> StableIdentifierV1:
    return stable_identifier("oci-real-canary", key)


def _host_non_root_user() -> str:
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    if callable(getuid) and callable(getgid):
        uid = getuid()
        gid = getgid()
        if uid > 0 and gid >= 0:
            return f"{uid}:{gid}"
    return "65532:65532"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _verifier_identity(repo_root: Path) -> ImageOwnedVerifierIdentity:
    worker = repo_root / "Prover" / "worker"
    return ImageOwnedVerifierIdentity(
        wrapper_sha256=_sha256(worker / "autolean-lean-wrapper"),
        query_helper_sha256=_sha256(worker / "AutoleanLeanQuery.lean"),
    )


@dataclass(frozen=True, slots=True)
class _ControlPlaneClaimValidator:
    plane: ControlPlane

    def assert_current(self, claim: OciExecutionClaim) -> None:
        current = self.plane.leases.current(claim.lease.bundle_id.value)
        if current is None or (
            current.holder_id != claim.lease.worker_id
            or current.fencing_token != claim.lease.fencing_token
            or current.expires_at != claim.lease.expires_at
        ):
            raise ValidationError(
                "oci_canary_stale_fence",
                "OCI canary execution claim is no longer backed by the current lease",
            )


@dataclass(frozen=True, slots=True)
class _IndependentOciCanaryVerifier:
    """Second Docker-wrapper execution used only by the real-worker canary.

    It deliberately bypasses the first ``OciLeanRunner`` observation and executes the
    digest-pinned image again.  The returned receipt names only public hashes, never the
    candidate bytes or wrapper output.
    """

    image: str
    image_digest: str
    identity: ImageOwnedVerifierIdentity
    workspace: MaterializedWorkspace
    execution_claim: OciExecutionClaim

    def verify(
        self,
        *,
        request: VerificationSigningRequestV1,
        artifact: VerificationEvidenceArtifactV2,
    ) -> IndependentExecutionReceiptV1:
        candidate = self.workspace.render_candidate()
        # Match the first observation byte-for-byte: the trusted verifier appends this fixed
        # query after rendering the candidate, and its hash is part of the V2 artifact.
        with candidate.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(f"\n#print axioms {self.workspace.candidate_declaration()}\n")
        record = _require_record(_direct(self.image, candidate))
        expected: dict[str, object] = {
            "schema_version": PROTOCOL,
            "declaration": DECLARATION,
            "canonical_type": CANONICAL_TYPE,
            "lean_version": LEAN_VERSION,
            "mathlib_revision": MATHLIB_REVISION,
            "lake_manifest_hash": None,
            "observed_axioms": [],
            "image_identity": self.identity.payload(),
        }
        if record != expected:
            raise RuntimeError("independent OCI wrapper record differs from the frozen canary")
        checks = (
            (artifact.oci.worker_image_digest == self.image_digest, "worker image"),
            (artifact.oci.wrapper_protocol == PROTOCOL, "wrapper protocol"),
            (
                artifact.oci.candidate_sha256 == _sha256(candidate),
                "candidate hash",
            ),
            (
                artifact.oci.trusted_statement_sha256
                == self.workspace.bundle.proof_boundary.trusted_statement_hash.value,
                "trusted statement hash",
            ),
            (
                artifact.oci.bundle_manifest_sha256
                == self.workspace.bundle.proof_boundary.solver_manifest_hash.value,
                "bundle manifest hash",
            ),
            (
                artifact.oci.execution_authority.wrapper_identity_hash
                == self.identity.identity_hash(),
                "image-owned wrapper identity",
            ),
            (
                artifact.oci.execution_authority.execution_claim_hash
                == self.execution_claim.claim_hash(),
                "execution claim hash",
            ),
        )
        for passed, label in checks:
            if not passed:
                raise RuntimeError(f"independent OCI verifier found a different {label}")
        receipt = IndependentExecutionReceiptV1.create(
            receipt_id="oci-real-canary-independent-receipt-v2",
            verifier_id=_INDEPENDENT_VERIFIER_ID,
            checked_at=datetime.now(UTC),
            request_hash=request.request_hash().value,
            evidence_artifact_digest=request.context.evidence_artifact_digest,
            evidence_digest=request.context.verification_evidence_hash.value,
            execution_claim_hash=artifact.oci.execution_authority.execution_claim_hash,
        )
        return _INDEPENDENT_RECEIPT_AUTHENTICATOR.authenticate(receipt)


def _submission(bundle: FormalizationTaskBundleV1, proof: str) -> ProofSubmissionV1:
    return ProofSubmissionV1(
        proof_id=_stable_id("proof"),
        contract_id=bundle.contract.contract_id,
        revision=bundle.contract.revision,
        contract_hash=bundle.contract.semantic_hash(),
        proof_boundary_hash=bundle.proof_boundary.boundary_hash,
        proof_source=proof,
        proof_source_hash=digest_text(HashKindV1.PROOF_SOURCE, proof),
        environment_hash=bundle.contract.formal.environment.environment_hash,
        provenance=(
            ProvenanceTraceV1(
                trace_id=_stable_id("proof-provenance"),
                actor_id="oci-worker-canary",
                actor_kind=ActorKindV1.TOOL,
            ),
        ),
    )


def _docker_base(image: str, container_name: str) -> list[str]:
    return [
        "docker",
        "run",
        "--name",
        container_name,
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "128",
        "--memory",
        "2g",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=256m",
        "--user",
        _host_non_root_user(),
    ]


def _compile_command(
    image: str,
    candidate: Path,
    output: Path,
    container_name: str,
) -> list[str]:
    return [
        *_docker_base(image, container_name),
        "--mount",
        f"type=bind,src={candidate.resolve()},dst=/input/Candidate.lean,readonly",
        "--mount",
        f"type=bind,src={output.resolve()},dst=/output",
        image,
        "/opt/autolean/bin/autolean-lean-wrapper",
        "--protocol",
        PROTOCOL,
        "--phase",
        "compile",
        "--candidate",
        "/input/Candidate.lean",
        "--output",
        "/output/Candidate.olean",
    ]


def _query_command(
    image: str,
    compiled_candidate: Path,
    container_name: str,
    *,
    declaration: str = DECLARATION,
    type_format: str = TYPE_FORMAT,
) -> list[str]:
    return [
        *_docker_base(image, container_name),
        "--mount",
        (f"type=bind,src={compiled_candidate.resolve()},dst=/compiled/Candidate.olean,readonly"),
        image,
        "/opt/autolean/bin/autolean-lean-wrapper",
        "--protocol",
        PROTOCOL,
        "--phase",
        "query",
        "--compiled",
        "/compiled/Candidate.olean",
        "--declaration",
        declaration,
        "--type-format",
        type_format,
    ]


def _ensure_container_stopped(container_name: str) -> None:
    cleanup = subprocess.run(
        ["docker", "rm", "--force", container_name],
        check=False,
        shell=False,
        text=True,
        capture_output=True,
        timeout=30,
    )
    if cleanup.returncode == 0:
        return
    listing = subprocess.run(
        [
            "docker",
            "container",
            "ls",
            "--all",
            "--quiet",
            "--filter",
            f"name=^/{container_name}$",
        ],
        check=False,
        shell=False,
        text=True,
        capture_output=True,
        timeout=30,
    )
    if listing.returncode != 0 or listing.stdout.strip():
        raise RuntimeError("OCI canary could not establish that a phase container stopped")


def _run_phase(command: list[str], container_name: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            check=False,
            shell=False,
            text=True,
            capture_output=True,
            timeout=120,
        )
    finally:
        _ensure_container_stopped(container_name)


def _seal_direct_olean(source_directory: Path, sealed_directory: Path) -> tuple[Path, str]:
    source = source_directory / "Candidate.olean"
    destination = sealed_directory / "Candidate.olean"
    source_metadata = source.lstat()
    if source.is_symlink() or not stat.S_ISREG(source_metadata.st_mode):
        raise RuntimeError("OCI canary compile output is not a regular non-link file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(source, flags)
    digest = hashlib.sha256()
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > SEALED_CANDIDATE_MAX_BYTES
        ):
            raise RuntimeError("OCI canary compile output is not a bounded regular file")
        output_descriptor = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o444,
        )
        copied = 0
        try:
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                copied += len(block)
                if copied > SEALED_CANDIDATE_MAX_BYTES:
                    raise RuntimeError("OCI canary compile output exceeds the verifier limit")
                digest.update(block)
                view = memoryview(block)
                while view:
                    written = os.write(output_descriptor, view)
                    if written <= 0:
                        raise OSError("short Candidate.olean write")
                    view = view[written:]
            os.fsync(output_descriptor)
        finally:
            os.close(output_descriptor)
        after = os.fstat(descriptor)
        if copied != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise RuntimeError("OCI canary compile output changed during host sealing")
    finally:
        os.close(descriptor)
    destination.chmod(0o444)
    if destination.is_symlink() or not stat.S_ISREG(destination.lstat().st_mode):
        raise RuntimeError("OCI canary sealed output is not a regular file")
    return destination, digest.hexdigest()


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            if path.is_dir():
                continue
            raise RuntimeError("OCI canary compiler output contains a non-regular artifact")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _direct(
    image: str,
    candidate: Path,
    *,
    declaration: str = DECLARATION,
    type_format: str = TYPE_FORMAT,
    verify_post_stop_stability: bool = False,
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="autolean-direct-handoff-") as raw_handoff:
        handoff = Path(raw_handoff)
        handoff.chmod(0o700)
        compiler_output = handoff / "compiler-output"
        sealed_directory = handoff / "sealed"
        compiler_output.mkdir(mode=0o700)
        sealed_directory.mkdir(mode=0o700)
        compile_name = f"autolean-canary-compile-{secrets.token_hex(10)}"
        compiler_output.chmod(0o733)
        try:
            compile_result = _run_phase(
                _compile_command(image, candidate, compiler_output, compile_name),
                compile_name,
            )
        finally:
            compiler_output.chmod(0o700)
        if compile_result.returncode != 0:
            return subprocess.CompletedProcess(
                compile_result.args,
                compile_result.returncode,
                "",
                compile_result.stderr,
            )
        if verify_post_stop_stability:
            before = _tree_digest(compiler_output)
            time.sleep(0.2)
            if _tree_digest(compiler_output) != before:
                raise RuntimeError("compile output changed after its OCI container stopped")
        sealed_candidate, _sealed_sha256 = _seal_direct_olean(
            compiler_output,
            sealed_directory,
        )
        query_name = f"autolean-canary-query-{secrets.token_hex(10)}"
        return _run_phase(
            _query_command(
                image,
                sealed_candidate,
                query_name,
                declaration=declaration,
                type_format=type_format,
            ),
            query_name,
        )


def _copy_frozen_source(workspace: MaterializedWorkspace, destination: Path) -> None:
    for protected in workspace.protected_files:
        target = destination / protected.path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((workspace.root / protected.path).read_bytes())


def _require_record(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    if result.returncode != 0:
        raise RuntimeError(f"wrapper failed with status {result.returncode}: {result.stderr[:500]}")
    payload = json.loads(result.stdout)
    if not isinstance(payload, dict):
        raise RuntimeError("wrapper record is not a JSON object")
    return payload


def _run_canaries(repo_root: Path, image: str) -> dict[str, object]:
    if "@sha256:" not in image:
        raise RuntimeError("canary image must use a repository sha256 digest")
    image_digest = image.rsplit("@", maxsplit=1)[1]
    fixtures = repo_root / "Prover" / "worker" / "tests" / "fixtures"
    identity = _verifier_identity(repo_root)

    normal = _require_record(_direct(image, fixtures / "Candidate.lean"))
    if normal != {
        "schema_version": PROTOCOL,
        "declaration": DECLARATION,
        "canonical_type": CANONICAL_TYPE,
        "lean_version": LEAN_VERSION,
        "mathlib_revision": MATHLIB_REVISION,
        "lake_manifest_hash": None,
        "observed_axioms": [],
        "image_identity": identity.payload(),
    }:
        raise RuntimeError(f"unexpected authoritative wrapper record: {normal!r}")

    changed = _require_record(_direct(image, fixtures / "ChangedToTrue.lean"))
    if changed["canonical_type"] != "True":
        raise RuntimeError("changed-to-True canary did not observe the changed declaration type")
    if digest_text(HashKindV1.ELABORATED_TYPE, str(changed["canonical_type"])) == digest_text(
        HashKindV1.ELABORATED_TYPE, CANONICAL_TYPE
    ):
        raise RuntimeError("changed-to-True canary unexpectedly retained the frozen type hash")

    spoof = _direct(image, fixtures / "StdoutSpoof.lean")
    spoof_record = _require_record(spoof)
    if spoof_record != normal or spoof.stdout.count("\n") != 1:
        raise RuntimeError("candidate diagnostic output reached or forged the wrapper channel")

    shadow = _require_record(
        _direct(
            image,
            fixtures / "ShadowModuleInjection.lean",
            verify_post_stop_stability=True,
        )
    )
    if shadow != normal:
        raise RuntimeError("candidate-controlled module shadow influenced the query container")

    persistent_writer = _require_record(
        _direct(
            image,
            fixtures / "PersistentOutputWriter.lean",
            verify_post_stop_stability=True,
        )
    )
    if persistent_writer != normal:
        raise RuntimeError("compile-time persistent writer influenced the query container")

    wrong_declaration = _direct(
        image,
        fixtures / "Candidate.lean",
        declaration="AutoLean.OCI.missing",
    )
    if wrong_declaration.returncode == 0 or wrong_declaration.stdout:
        raise RuntimeError("wrong-declaration canary did not fail closed")

    wrong_profile = _direct(
        image,
        fixtures / "Candidate.lean",
        type_format="autolean.lean-pp-expr.unknown",
    )
    if wrong_profile.returncode == 0 or wrong_profile.stdout:
        raise RuntimeError("unknown helper profile did not fail closed")

    with tempfile.TemporaryDirectory(prefix="autolean-oci-canary-") as raw_root:
        root = Path(raw_root)
        database = root / "control.db"
        plane = ControlPlane(
            events=EventStore(database),
            leases=LeaseStore(database),
            artifacts=ArtifactStore(root / "artifacts"),
            attestation_verifier=HmacAttestationVerifierV1(
                {
                    _BUILDER_KEY.key_id: _BUILDER_KEY,
                    _VERIFIER_KEY.key_id: _VERIFIER_KEY,
                }
            ),
            allow_test_only_non_authoritative_canonical_type_evidence=True,
        )
        if plane.allow_test_only_unreviewed_bundles:
            raise RuntimeError("source-backed OCI canary cannot enable unreviewed bundle admission")
        source_backed = build_source_backed_oci_fixture(
            root / "source-backed-builder",
            artifact_store=plane.artifacts,
            image_digest=image_digest,
            attestor=HmacAttestationSignerV1(_BUILDER_KEY),
        )
        bundle = source_backed.bundle
        registration = plane.register_bundle(bundle, idempotency_key="register")
        if (
            registration.canonical_type_assurance != "scripted_fake"
            or registration.canonical_type_promotion_authority
        ):
            raise RuntimeError(
                "source-backed OCI canary lost its test-only Builder evidence classification"
            )
        receipt = plane.claim(
            bundle.bundle_id.value,
            worker_id="oci-real-canary-worker",
            ttl_seconds=300,
            idempotency_key="claim",
        )
        submission = _submission(bundle, "by\n  rfl")
        proof_event = plane.submit_proof(
            bundle.bundle_id.value,
            lease=receipt.lease,
            submission=submission,
            idempotency_key="submit-proof",
        )
        proof_artifact = proof_event.payload["proof_artifact"]
        proof_artifact_digest = (
            proof_artifact.get("digest") if isinstance(proof_artifact, dict) else None
        )
        if not isinstance(proof_artifact_digest, str):
            raise RuntimeError("control plane did not retain the canary proof artifact")
        lease_binding = VerificationSigningLeaseBindingV1(
            bundle_id=bundle.bundle_id,
            worker_id=receipt.lease.holder_id,
            fencing_token=receipt.lease.fencing_token,
            expires_at=receipt.lease.expires_at,
        )
        workspace = WorkspaceMaterializer().materialize(bundle, root / "attempt")
        source = root / "source"
        dependencies = root / "dependencies"
        source.mkdir()
        dependencies.mkdir()
        _copy_frozen_source(workspace, source)
        harness = CleanSubprocessHarness(
            allowed_executables={"docker"},
            allowed_working_roots={root},
        )
        execution_claim = OciExecutionClaim(
            task_input=workspace.task_input,
            lease=lease_binding,
            image_identity=identity,
            claim_id="oci-real-canary-execution",
            issued_at=datetime.now(UTC),
        )
        runner = OciLeanRunner(
            worker=OciWorkerHarness(
                harness=harness,
                spec=OciWorkerSpec(
                    runtime="docker",
                    image=image,
                    dependency_root=dependencies,
                    memory_limit="2g",
                    pids_limit=128,
                    timeout_seconds=120,
                    image_identity=identity,
                ),
            ),
            immutable_source=source,
            execution_claim=execution_claim,
            claim_validator=_ControlPlaneClaimValidator(plane),
        )
        observation = TrustedLeanVerifier(
            runner=runner,
            verifier_id="oci-real-canary",
        ).observe(workspace, submission)
        execution = observation.oci_execution_evidence
        if not (
            observation.report.kernel_passed
            and observation.report.build_passed
            and observation.report.dependency_check_passed
            and observation.report.clean_environment
            and observation.report.observed_axioms == ()
            and execution is not None
            and execution.worker_image_digest == image_digest
            and execution.authority_status == "lease-bound-pending-gateway"
            and execution.wrapper_identity_hash == identity.identity_hash()
        ):
            raise RuntimeError(
                f"OciLeanRunner canary did not pass: {observation.report.model_dump_json()}"
            )

        gateway = VerifierSigningGateway(
            control_plane=plane,
            signer=HmacAttestationSignerV1(_VERIFIER_KEY),
            verifier=HmacAttestationVerifierV1({_VERIFIER_KEY.key_id: _VERIFIER_KEY}),
            independent_execution_verifier=_IndependentOciCanaryVerifier(
                image=image,
                image_digest=image_digest,
                identity=identity,
                workspace=workspace,
                execution_claim=execution_claim,
            ),
            independent_execution_trust_policy=IndependentExecutionTrustPolicyV1(
                gateway_signing_key_id=_VERIFIER_KEY.key_id,
                execution_class=IndependentExecutionClassV1.TEST_ONLY,
                trusted_verifiers={
                    _INDEPENDENT_VERIFIER_ID: TrustedIndependentExecutionVerifierV1(
                        verifier_id=_INDEPENDENT_VERIFIER_ID,
                        authentication_key_id=_INDEPENDENT_RECEIPT_AUTHENTICATOR.key_id,
                        execution_class=IndependentExecutionClassV1.TEST_ONLY,
                        authenticator=_INDEPENDENT_RECEIPT_AUTHENTICATOR,
                    )
                },
            ),
            approved_image_identities={image_digest: identity.identity_hash()},
        )
        report = attest_oci_observation_via_gateway(
            observation,
            bundle=bundle,
            submission=submission,
            proof_submission_artifact_digest=proof_artifact_digest,
            artifact_sink=lambda payload: plane.artifacts.put_json(dict(payload)).digest,
            lease=lease_binding,
            gateway_client=gateway,
            idempotency_key="sign-verification",
            ttl_seconds=60,
        )
        outcome = plane.verify_submission(
            bundle.bundle_id.value,
            lease=receipt.lease,
            report=report,
            idempotency_key="verify-submission",
        )
        if (
            not outcome.accepted
            or outcome.promotion_state != "not_a_promotion"
            or outcome.execution_authority_class != "test-only-local"
        ):
            raise RuntimeError(f"control plane rejected the OCI canary: {outcome.reasons!r}")
        freeze = bundle.contract.freeze
        if freeze is None or freeze.source_preparation_hash is None:
            raise RuntimeError("source-backed OCI canary lost its source preparation binding")
        with plane.events.connection() as connection:
            receipt_row = connection.execute(
                """
                SELECT execution_receipt_authentication_key_id,
                       execution_receipt_authentication_signature
                FROM verifier_signing_requests
                """
            ).fetchone()
        if (
            receipt_row is None
            or receipt_row["execution_receipt_authentication_key_id"]
            != _INDEPENDENT_RECEIPT_AUTHENTICATOR.key_id
            or not receipt_row["execution_receipt_authentication_signature"]
        ):
            raise RuntimeError("OCI canary did not retain an independently authenticated receipt")

        tampered = WorkspaceMaterializer().materialize(bundle, root / "tampered-attempt")
        tampered.write_proof("by\n  rfl")
        candidate = tampered.render_candidate()
        candidate.write_text(
            "namespace AutoLean.OCI\n\ntheorem fixture : True := by\n  trivial\n",
            encoding="utf-8",
            newline="\n",
        )
        try:
            runner.run(candidate, workspace=tampered)
        except ValidationError as error:
            if "oci_candidate_content_mismatch" not in str(error):
                raise
        else:
            raise RuntimeError("host runner accepted a changed-to-True candidate")

        result: dict[str, object] = {
            "schema_version": "autolean.oci-worker-canary.v2",
            "image": image,
            "image_digest": image_digest,
            "lean_version": LEAN_VERSION,
            "mathlib_revision": MATHLIB_REVISION,
            "mathlib_exercised": False,
            "declaration": DECLARATION,
            "canonical_type": CANONICAL_TYPE,
            "observed_axioms": [],
            "kernel_passed": report.kernel_passed,
            "build_passed": report.build_passed,
            "dependency_check_passed": report.dependency_check_passed,
            "clean_environment": report.clean_environment,
            "wrapper_stdout_spoof_rejected": True,
            "shadow_module_injection_isolated": True,
            "compile_container_persistent_writer_stopped": True,
            "changed_to_true_detected": True,
            "wrong_declaration_rejected": True,
            "unknown_profile_rejected": True,
            "host_candidate_replacement_rejected": True,
            "command_policy_hash": execution.command_policy_hash,
            "command_hash": execution.command_hash,
            "compile_command_hash": execution.compile_command_hash,
            "query_command_hash": execution.query_command_hash,
            "sealed_candidate_sha256": execution.sealed_candidate_sha256,
            "handoff_protocol": execution.handoff_protocol,
            "candidate_sha256": execution.candidate_sha256,
            "trusted_statement_sha256": execution.trusted_statement_sha256,
            "bundle_manifest_sha256": execution.bundle_manifest_sha256,
            "execution_claim_hash": execution.execution_claim_hash,
            "lease_fencing_token": execution.lease_fencing_token,
            "wrapper_identity_hash": execution.wrapper_identity_hash,
            "evidence_artifact_schema": "autolean.verification-evidence-artifact.v2",
            "test_gateway_attestation_created": report.verifier_attestation is not None,
            "independent_receipt_authentication_key_id": _INDEPENDENT_RECEIPT_AUTHENTICATOR.key_id,
            "gateway_execution_class": IndependentExecutionClassV1.TEST_ONLY.value,
            "control_plane_accepted_test_fixture": outcome.accepted,
            "control_plane_promotion_state": outcome.promotion_state,
            "control_plane_execution_authority_class": outcome.execution_authority_class,
            "promotion_attestation_created": False,
            "source_backed_builder_handoff": True,
            "builder_unreviewed_bypass": plane.allow_test_only_unreviewed_bundles,
            "builder_canonical_type_assurance": registration.canonical_type_assurance,
            "builder_canonical_type_promotion_authority": (
                registration.canonical_type_promotion_authority
            ),
            "builder_fidelity_evidence_digest": source_backed.evaluation.evidence_hash.value,
            "source_preparation_hash": freeze.source_preparation_hash.value,
            "bundle_handoff_hash": bundle.handoff_hash().value,
        }

    evidence = repo_root / "release-evidence" / "oci-worker"
    evidence.mkdir(parents=True, exist_ok=True)
    output = evidence / "canary.v2.json"
    rendered = json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    output.write_text(rendered, encoding="utf-8", newline="\n")
    result["evidence_sha256"] = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    arguments = parser.parse_args()
    _run_canaries(Path(__file__).resolve().parents[1], arguments.image)


if __name__ == "__main__":
    main()
