"""Linux OCI command construction for the authoritative Lean worker environment."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import tempfile
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal

from autolean_contracts import OciVerifierExecutionPolicyV2

from autolean_prover.errors import ConfigurationError, ExecutionPolicyError, ValidationError
from autolean_prover.execution.authority import (
    ExecutionClaimValidator,
    ImageOwnedVerifierIdentity,
    OciExecutionClaim,
)
from autolean_prover.execution.base import ExecutionHarness, ProcessRequest, ProcessResult
from autolean_prover.execution.lean_runner import (
    CANONICAL_TYPE_FORMAT,
    OCI_EXECUTION_AUTHORITY_LEASE_PENDING_GATEWAY,
    OCI_EXECUTION_AUTHORITY_LEASE_UNOBSERVED,
    OCI_EXECUTION_AUTHORITY_NON_PRODUCTION,
    ElaboratedTypeEvidence,
    LeanRunEvidence,
    OciExecutionEvidence,
)
from autolean_prover.execution.workspace import MaterializedWorkspace

_IMAGE_DIGEST = re.compile(r"^.+@sha256:[0-9a-f]{64}$")
_WRAPPER_PROTOCOL: Final[str] = "autolean.oci-lean-wrapper.v2"
_WRAPPER_EXECUTABLE: Final[str] = "/opt/autolean/bin/autolean-lean-wrapper"
_CONTAINER_CANDIDATE: Final[str] = "/input/Candidate.lean"
_CONTAINER_COMPILED_CANDIDATE: Final[str] = "/compiled/Candidate.olean"
_CONTAINER_COMPILED_OUTPUT: Final[str] = "/output/Candidate.olean"
_WRAPPER_RESULT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "declaration",
        "canonical_type",
        "lean_version",
        "mathlib_revision",
        "lake_manifest_hash",
        "observed_axioms",
    }
)
_WRAPPER_IDENTITY_FIELD: Final[str] = "image_identity"
_IMAGE_OWNED_PATHS: Final[frozenset[str]] = frozenset(
    {
        "/opt",
        "/opt/autolean",
        "/opt/autolean/bin",
        "/opt/autolean/bin/autolean-lean-wrapper",
        "/opt/autolean/lib",
        "/opt/autolean/lib/AutoleanLeanQuery.lean",
    }
)


def _host_non_root_user() -> str:
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    if callable(getuid) and callable(getgid):
        uid = getuid()
        gid = getgid()
        if uid > 0 and gid >= 0:
            return f"{uid}:{gid}"
    return "65532:65532"


@dataclass(frozen=True, slots=True)
class _WrapperResult:
    declaration: str
    canonical_type: str
    observed_axioms: tuple[str, ...]
    image_identity: ImageOwnedVerifierIdentity | None


@dataclass(frozen=True, slots=True)
class OciWorkerSpec:
    runtime: str
    image: str
    dependency_root: Path
    memory_limit: str = "8g"
    pids_limit: int = 512
    timeout_seconds: float = 900.0
    max_output_bytes: int = 16 * 1024 * 1024
    max_compiled_olean_bytes: int = 256 * 1024 * 1024
    runtime_user: str = dataclass_field(default_factory=_host_non_root_user)
    image_identity: ImageOwnedVerifierIdentity | None = None

    def __post_init__(self) -> None:
        if not self.runtime.strip():
            raise ConfigurationError("OCI runtime must not be empty")
        if not _IMAGE_DIGEST.fullmatch(self.image):
            raise ConfigurationError("OCI worker image must be pinned by a sha256 digest")
        if (
            self.pids_limit <= 0
            or self.timeout_seconds <= 0
            or self.max_output_bytes <= 0
            or self.max_compiled_olean_bytes <= 0
        ):
            raise ConfigurationError("OCI worker resource limits must be positive")
        if re.fullmatch(r"[1-9][0-9]*:[0-9]+", self.runtime_user) is None:
            raise ConfigurationError("OCI worker runtime user must be a numeric non-root identity")


class OciWorkerHarness:
    """Execute a fixed command in a no-network, read-only-root Linux container.

    The worker gets a read-only snapshot at `/source`, read-only dependencies at `/deps`, and a
    verifier-rendered candidate at `/input/Candidate.lean`, or one host-sealed compiled candidate
    at `/compiled/Candidate.olean`. Candidate compilation gets a dedicated `/output` bind, never
    the attempt workspace. Query execution gets no writable host bind at all.
    """

    def __init__(self, *, harness: ExecutionHarness, spec: OciWorkerSpec) -> None:
        self._harness = harness
        self._spec = spec

    @property
    def spec(self) -> OciWorkerSpec:
        """Expose immutable worker configuration for verifier-owned execution evidence."""

        return self._spec

    def build_request(
        self,
        *,
        immutable_source: Path,
        workspace: Path,
        command: tuple[str, ...],
        immutable_candidate: Path | None = None,
        compiled_output_directory: Path | None = None,
        immutable_compiled_candidate: Path | None = None,
        container_name: str | None = None,
    ) -> ProcessRequest:
        if not command:
            raise ExecutionPolicyError("OCI worker command must not be empty")
        source = immutable_source.resolve(strict=True)
        attempt = workspace.resolve(strict=True)
        dependencies = self._spec.dependency_root.resolve(strict=True)
        if immutable_candidate is not None and immutable_compiled_candidate is not None:
            raise ExecutionPolicyError("OCI phase cannot mount source and compiled candidates")
        if compiled_output_directory is not None and immutable_candidate is None:
            raise ExecutionPolicyError("OCI compiled output requires a source candidate")
        if (
            container_name is not None
            and re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,62}", container_name) is None
        ):
            raise ExecutionPolicyError("OCI container name is not a safe fixed identifier")
        name_arguments = () if container_name is None else ("--name", container_name)
        candidate_mount: tuple[str, ...] = ()
        if immutable_candidate is not None:
            if immutable_candidate.is_symlink():
                raise ExecutionPolicyError("immutable OCI candidate must not be a symbolic link")
            candidate = immutable_candidate.resolve(strict=True)
            if not candidate.is_file():
                raise ExecutionPolicyError("immutable OCI candidate must be a regular file")
            candidate_mount = (
                "--mount",
                f"type=bind,src={candidate},dst={_CONTAINER_CANDIDATE},readonly",
            )
        output_mount: tuple[str, ...] = ()
        if compiled_output_directory is not None:
            if compiled_output_directory.is_symlink():
                raise ExecutionPolicyError("OCI compiled output directory must not be a link")
            output = compiled_output_directory.resolve(strict=True)
            if not output.is_dir():
                raise ExecutionPolicyError("OCI compiled output must be a directory")
            output_mount = (
                "--mount",
                f"type=bind,src={output},dst=/output",
            )
        compiled_mount: tuple[str, ...] = ()
        if immutable_compiled_candidate is not None:
            if immutable_compiled_candidate.is_symlink():
                raise ExecutionPolicyError("sealed OCI candidate must not be a symbolic link")
            compiled = immutable_compiled_candidate.resolve(strict=True)
            if not compiled.is_file():
                raise ExecutionPolicyError("sealed OCI candidate must be a regular file")
            compiled_mount = (
                "--mount",
                f"type=bind,src={compiled},dst={_CONTAINER_COMPILED_CANDIDATE},readonly",
            )
        argv = (
            self._spec.runtime,
            "run",
            "--rm",
            *name_arguments,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(self._spec.pids_limit),
            "--memory",
            self._spec.memory_limit,
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=512m",
            "--user",
            self._spec.runtime_user,
            "--mount",
            f"type=bind,src={source},dst=/source,readonly",
            "--mount",
            f"type=bind,src={dependencies},dst=/deps,readonly",
            *candidate_mount,
            *output_mount,
            *compiled_mount,
            "--workdir",
            "/work",
            self._spec.image,
            *command,
        )
        return ProcessRequest(
            argv=argv,
            cwd=attempt,
            timeout_seconds=self._spec.timeout_seconds,
            max_output_bytes=self._spec.max_output_bytes,
        )

    def execute(
        self,
        *,
        immutable_source: Path,
        workspace: Path,
        command: tuple[str, ...],
        immutable_candidate: Path | None = None,
        compiled_output_directory: Path | None = None,
        immutable_compiled_candidate: Path | None = None,
        container_name: str | None = None,
    ) -> ProcessResult:
        try:
            return self._harness.execute(
                self.build_request(
                    immutable_source=immutable_source,
                    workspace=workspace,
                    command=command,
                    immutable_candidate=immutable_candidate,
                    compiled_output_directory=compiled_output_directory,
                    immutable_compiled_candidate=immutable_compiled_candidate,
                    container_name=container_name,
                )
            )
        finally:
            if container_name is not None:
                self._ensure_container_stopped(container_name, workspace)

    @staticmethod
    def new_container_name(phase: str) -> str:
        if re.fullmatch(r"[a-z][a-z0-9-]{0,15}", phase) is None:
            raise ExecutionPolicyError("OCI phase name is not safe")
        return f"autolean-{phase}-{secrets.token_hex(12)}"

    def _ensure_container_stopped(self, container_name: str, workspace: Path) -> None:
        """Do not expose compile output until every process in that container is gone."""

        cleanup = self._harness.execute(
            ProcessRequest(
                argv=(self._spec.runtime, "rm", "--force", container_name),
                cwd=workspace,
                timeout_seconds=30,
                max_output_bytes=1024 * 1024,
            )
        )
        if cleanup.returncode == 0 and not cleanup.timed_out and not cleanup.output_truncated:
            return
        listing = self._harness.execute(
            ProcessRequest(
                argv=(
                    self._spec.runtime,
                    "container",
                    "ls",
                    "--all",
                    "--quiet",
                    "--filter",
                    f"name=^/{container_name}$",
                ),
                cwd=workspace,
                timeout_seconds=30,
                max_output_bytes=1024 * 1024,
            )
        )
        if (
            listing.returncode != 0
            or listing.timed_out
            or listing.output_truncated
            or listing.stdout.strip()
        ):
            raise ExecutionPolicyError(
                "OCI container termination could not be established before artifact handoff"
            )


class OciLeanRunner:
    """Run the fixed verifier wrapper in OCI and parse only its structured evidence.

    The wrapper is part of the digest-pinned image. It must capture Lean child stdout/stderr itself
    and emit exactly one JSON object on its own stdout. This prevents a proof from manufacturing a
    wrapper record through Lean diagnostic output. The host derives declaration and type identity
    only from the frozen proof boundary, never from a model request or a reported type hash.
    """

    def __init__(
        self,
        *,
        worker: OciWorkerHarness,
        immutable_source: Path,
        execution_claim: OciExecutionClaim | None = None,
        claim_validator: ExecutionClaimValidator | None = None,
    ) -> None:
        if immutable_source.is_symlink():
            raise ConfigurationError("immutable OCI source snapshot must not be a symbolic link")
        try:
            source = immutable_source.resolve(strict=True)
        except OSError as error:
            raise ConfigurationError("immutable OCI source snapshot is unavailable") from error
        if not source.is_dir():
            raise ConfigurationError("immutable OCI source snapshot must be a directory")
        if (execution_claim is None) != (claim_validator is None):
            raise ConfigurationError(
                "authoritative OCI execution requires both a claim and a live claim validator"
            )
        if execution_claim is not None and worker.spec.image_identity is None:
            raise ConfigurationError(
                "authoritative OCI execution requires an image-owned verifier identity"
            )
        if (
            execution_claim is not None
            and worker.spec.image_identity != execution_claim.image_identity
        ):
            raise ConfigurationError("OCI worker image identity differs from the execution claim")
        self._worker = worker
        self._immutable_source = source
        self._execution_claim = execution_claim
        self._claim_validator = claim_validator

    def run(self, candidate: Path, *, workspace: MaterializedWorkspace) -> LeanRunEvidence:
        candidate_path = self._validate_candidate(candidate, workspace)
        self._require_v2_policy(workspace)
        workspace.validate_integrity()
        self._validate_execution_claim(workspace)
        self._validate_source_snapshot(workspace)
        before_candidate_hash = self._sha256_file(candidate_path)
        with tempfile.TemporaryDirectory(
            prefix="autolean-oci-handoff-",
            dir=workspace.root.parent,
        ) as raw_handoff_root:
            handoff_root = Path(raw_handoff_root)
            handoff_root.chmod(0o700)
            compiler_output = handoff_root / "compiler-output"
            sealed = handoff_root / "sealed"
            compiler_output.mkdir(mode=0o700)
            sealed.mkdir(mode=0o700)
            compiler_output.chmod(0o733)

            compile_command = self._compile_wrapper_command()
            compile_name = self._worker.new_container_name("compile")
            compile_request = self._worker.build_request(
                immutable_source=self._immutable_source,
                workspace=workspace.root,
                command=compile_command,
                immutable_candidate=candidate_path,
                compiled_output_directory=compiler_output,
                container_name=compile_name,
            )
            self._validate_execution_policy(workspace, compile_request, phase="compile")
            try:
                compile_result = self._worker.execute(
                    immutable_source=self._immutable_source,
                    workspace=workspace.root,
                    command=compile_command,
                    immutable_candidate=candidate_path,
                    compiled_output_directory=compiler_output,
                    container_name=compile_name,
                )
            finally:
                compiler_output.chmod(0o700)
                self._validate_after_phase(
                    workspace,
                    candidate_path=candidate_path,
                    candidate_sha256=before_candidate_hash,
                )
            self._validate_process_result(compile_result, compile_request, phase="compile")
            if (
                compile_result.output_truncated
                or compile_result.timed_out
                or compile_result.returncode != 0
            ):
                execution = self._execution_evidence(
                    workspace,
                    process_argvs=(compile_request.argv,),
                    candidate_sha256=before_candidate_hash,
                    compiled_candidate_sha256=None,
                    observed_identity=None,
                )
                return LeanRunEvidence(
                    returncode=compile_result.returncode,
                    timed_out=compile_result.timed_out,
                    stdout="",
                    stderr=compile_result.stderr,
                    clean_environment=True,
                    oci_execution_evidence=execution,
                )

            sealed_candidate, compiled_candidate_sha256 = self._seal_compiled_candidate(
                compiler_output,
                sealed,
            )
            query_command = self._wrapper_command(workspace)
            query_name = self._worker.new_container_name("query")
            query_request = self._worker.build_request(
                immutable_source=self._immutable_source,
                workspace=workspace.root,
                command=query_command,
                immutable_compiled_candidate=sealed_candidate,
                container_name=query_name,
            )
            self._validate_execution_policy(workspace, query_request, phase="query")
            try:
                query_result = self._worker.execute(
                    immutable_source=self._immutable_source,
                    workspace=workspace.root,
                    command=query_command,
                    immutable_compiled_candidate=sealed_candidate,
                    container_name=query_name,
                )
            finally:
                self._validate_after_phase(
                    workspace,
                    candidate_path=candidate_path,
                    candidate_sha256=before_candidate_hash,
                )
                if self._sha256_file(sealed_candidate) != compiled_candidate_sha256:
                    raise ValidationError(
                        "oci_sealed_candidate_changed",
                        "sealed OCI candidate changed during the query phase",
                    )
            self._validate_process_result(query_result, query_request, phase="query")
            process_argvs = (compile_request.argv, query_request.argv)
            if query_result.output_truncated:
                raise ValidationError(
                    "oci_wrapper_output_truncated",
                    "OCI Lean query wrapper output was truncated",
                )
            if query_result.timed_out or query_result.returncode != 0:
                execution = self._execution_evidence(
                    workspace,
                    process_argvs=process_argvs,
                    candidate_sha256=before_candidate_hash,
                    compiled_candidate_sha256=compiled_candidate_sha256,
                    observed_identity=None,
                )
                return LeanRunEvidence(
                    returncode=query_result.returncode,
                    timed_out=query_result.timed_out,
                    stdout="",
                    stderr=query_result.stderr,
                    clean_environment=True,
                    oci_execution_evidence=execution,
                )

            wrapper = self._parse_wrapper_result(query_result.stdout, workspace)
            execution = self._execution_evidence(
                workspace,
                process_argvs=process_argvs,
                candidate_sha256=before_candidate_hash,
                compiled_candidate_sha256=compiled_candidate_sha256,
                observed_identity=wrapper.image_identity,
            )
            try:
                type_evidence = ElaboratedTypeEvidence(
                    declaration=wrapper.declaration,
                    canonical_type=wrapper.canonical_type,
                )
            except ValueError as error:
                raise ValidationError(
                    "oci_wrapper_type_evidence_invalid",
                    "OCI Lean wrapper emitted invalid elaborated-type evidence",
                ) from error
            return LeanRunEvidence(
                returncode=query_result.returncode,
                timed_out=False,
                stdout=self._axiom_stdout(wrapper.observed_axioms),
                stderr=query_result.stderr,
                clean_environment=True,
                observed_axioms=wrapper.observed_axioms,
                elaborated_type_evidence=type_evidence,
                oci_execution_evidence=execution,
            )

    @staticmethod
    def _validate_candidate(candidate: Path, workspace: MaterializedWorkspace) -> Path:
        try:
            expected = workspace.candidate_path.resolve(strict=True)
            observed = candidate.resolve(strict=True)
        except OSError as error:
            raise ValidationError(
                "oci_candidate_missing",
                "OCI Lean runner candidate is unavailable",
            ) from error
        if candidate.is_symlink() or not candidate.is_file() or observed != expected:
            raise ValidationError(
                "oci_candidate_boundary",
                "OCI Lean runner may compile only the verifier-rendered candidate",
            )
        OciLeanRunner._validate_candidate_content(expected, workspace)
        return expected

    @staticmethod
    def _validate_candidate_content(candidate: Path, workspace: MaterializedWorkspace) -> None:
        """Require the exact host-rendered frozen header plus proof slot.

        ``Candidate.lean`` is an attempt artifact, so a caller could otherwise replace the right
        pathname with a different theorem before the OCI mount is created. The only second form
        accepted is the verifier's deterministic axiom query suffix.
        """

        boundary = workspace.bundle.proof_boundary
        statement = workspace.root / boundary.trusted_statement_path
        try:
            if workspace.proof_path.is_symlink() or not workspace.proof_path.is_file():
                raise ValidationError(
                    "oci_proof_slot_boundary",
                    "OCI Lean runner proof slot is not a regular file",
                )
            header = statement.read_text(encoding="utf-8")
            proof = workspace.proof_path.read_text(encoding="utf-8")
            actual = candidate.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise ValidationError(
                "oci_candidate_unreadable",
                "OCI Lean runner candidate inputs could not be read",
            ) from error
        rendered = f"{header} := {proof.rstrip()}\n"
        axiom_query = f"{rendered}\n#print axioms {boundary.expected_declaration}\n"
        if actual not in {rendered, axiom_query}:
            raise ValidationError(
                "oci_candidate_content_mismatch",
                "OCI Lean runner candidate differs from the frozen statement and proof slot",
            )

    def _validate_source_snapshot(self, workspace: MaterializedWorkspace) -> None:
        """Bind the read-only OCI source mount to the frozen workspace bytes.

        A read-only mount constrains the worker, not another host process. Hashing the exact files
        before and after execution makes the mount an input to this verification attempt rather
        than a merely operator-supplied directory.
        """

        source_root = self._immutable_source
        if source_root.is_symlink() or not source_root.is_dir():
            raise ValidationError(
                "oci_source_snapshot_invalid",
                "immutable OCI source snapshot is no longer a regular directory",
            )
        for protected in workspace.protected_files:
            path = self._source_snapshot_path(protected.path)
            try:
                actual = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError as error:
                raise ValidationError(
                    "oci_source_snapshot_unreadable",
                    "immutable OCI source snapshot file could not be read",
                ) from error
            if actual != protected.sha256:
                raise ValidationError(
                    "oci_source_snapshot_mismatch",
                    "immutable OCI source snapshot does not match the frozen bundle",
                )

    def _source_snapshot_path(self, relative: str) -> Path:
        source_root = self._immutable_source
        logical = source_root / Path(relative)
        relative_path = Path(relative)
        if relative_path.is_absolute() or relative_path.drive or ".." in relative_path.parts:
            raise ValidationError(
                "oci_source_snapshot_escape",
                "immutable OCI source snapshot contains an unsafe protected path",
            )
        cursor = source_root
        for part in relative_path.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise ValidationError(
                    "oci_source_snapshot_symlink",
                    "immutable OCI source snapshot protected path is a symbolic link",
                )
        try:
            resolved = logical.resolve(strict=True)
        except OSError as error:
            raise ValidationError(
                "oci_source_snapshot_missing",
                "immutable OCI source snapshot is missing a protected file",
            ) from error
        if not resolved.is_relative_to(source_root) or not logical.is_file():
            raise ValidationError(
                "oci_source_snapshot_escape",
                "immutable OCI source snapshot protected path escaped its root",
            )
        return logical

    @staticmethod
    def _compile_wrapper_command() -> tuple[str, ...]:
        return (
            _WRAPPER_EXECUTABLE,
            "--protocol",
            _WRAPPER_PROTOCOL,
            "--phase",
            "compile",
            "--candidate",
            _CONTAINER_CANDIDATE,
            "--output",
            _CONTAINER_COMPILED_OUTPUT,
        )

    @staticmethod
    def _wrapper_command(workspace: MaterializedWorkspace) -> tuple[str, ...]:
        declaration = workspace.bundle.proof_boundary.expected_declaration
        return (
            _WRAPPER_EXECUTABLE,
            "--protocol",
            _WRAPPER_PROTOCOL,
            "--phase",
            "query",
            "--compiled",
            _CONTAINER_COMPILED_CANDIDATE,
            "--declaration",
            declaration,
            "--type-format",
            CANONICAL_TYPE_FORMAT,
        )

    def _validate_after_phase(
        self,
        workspace: MaterializedWorkspace,
        *,
        candidate_path: Path,
        candidate_sha256: str,
    ) -> None:
        workspace.validate_integrity()
        self._validate_source_snapshot(workspace)
        if self._sha256_file(candidate_path) != candidate_sha256:
            raise ValidationError(
                "oci_candidate_changed",
                "OCI Lean worker changed the verifier-rendered candidate",
            )
        self._validate_execution_claim(workspace)

    @staticmethod
    def _validate_process_result(
        result: ProcessResult,
        expected: ProcessRequest,
        *,
        phase: str,
    ) -> None:
        if result.argv != expected.argv:
            raise ValidationError(
                "oci_runtime_argv_mismatch",
                f"OCI runtime returned evidence for a different {phase} command",
            )

    def _seal_compiled_candidate(
        self,
        compiler_output: Path,
        sealed_directory: Path,
    ) -> tuple[Path, str]:
        """Copy one stopped-container artifact through a no-follow regular-file descriptor."""

        source = compiler_output / "Candidate.olean"
        destination = sealed_directory / "Candidate.olean"
        try:
            source_metadata = source.lstat()
        except OSError as error:
            raise ValidationError(
                "oci_compiled_candidate_unavailable",
                "compile phase did not produce Candidate.olean",
            ) from error
        if source.is_symlink():
            raise ValidationError(
                "oci_compiled_candidate_unavailable",
                "compile phase Candidate.olean must not be a symbolic link",
            )
        if not stat.S_ISREG(source_metadata.st_mode):
            raise ValidationError(
                "oci_compiled_candidate_not_regular",
                "compile phase output is not a regular Candidate.olean",
            )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        try:
            descriptor = os.open(source, flags)
        except OSError as error:
            raise ValidationError(
                "oci_compiled_candidate_unavailable",
                "compile phase did not produce a no-follow Candidate.olean",
            ) from error
        digest = hashlib.sha256()
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise ValidationError(
                    "oci_compiled_candidate_not_regular",
                    "compile phase output is not a regular Candidate.olean",
                )
            if before.st_size <= 0 or before.st_size > self._worker.spec.max_compiled_olean_bytes:
                raise ValidationError(
                    "oci_compiled_candidate_size",
                    "compile phase Candidate.olean is empty or exceeds the verifier limit",
                )
            output_flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            output_descriptor = os.open(destination, output_flags, 0o444)
            copied = 0
            try:
                while True:
                    block = os.read(descriptor, 1024 * 1024)
                    if not block:
                        break
                    copied += len(block)
                    if copied > self._worker.spec.max_compiled_olean_bytes:
                        raise ValidationError(
                            "oci_compiled_candidate_size",
                            "compile phase Candidate.olean exceeds the verifier limit",
                        )
                    digest.update(block)
                    view = memoryview(block)
                    while view:
                        written = os.write(output_descriptor, view)
                        if written <= 0:
                            raise OSError("short write while sealing Candidate.olean")
                        view = view[written:]
                os.fsync(output_descriptor)
            finally:
                os.close(output_descriptor)
            after = os.fstat(descriptor)
            identity_before = (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            identity_after = (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            if copied != before.st_size or identity_after != identity_before:
                destination.unlink(missing_ok=True)
                raise ValidationError(
                    "oci_compiled_candidate_raced",
                    "compile phase Candidate.olean changed while it was sealed",
                )
        except OSError as error:
            destination.unlink(missing_ok=True)
            raise ValidationError(
                "oci_compiled_candidate_copy_failed",
                "compile phase Candidate.olean could not be sealed",
            ) from error
        finally:
            os.close(descriptor)
        try:
            destination.chmod(0o444)
            destination_metadata = destination.lstat()
        except OSError as error:
            destination.unlink(missing_ok=True)
            raise ValidationError(
                "oci_compiled_candidate_copy_failed",
                "sealed Candidate.olean could not be finalized",
            ) from error
        if not stat.S_ISREG(destination_metadata.st_mode) or destination.is_symlink():
            destination.unlink(missing_ok=True)
            raise ValidationError(
                "oci_compiled_candidate_not_regular",
                "sealed Candidate.olean is not a regular file",
            )
        return destination, digest.hexdigest()

    def _validate_execution_policy(
        self,
        workspace: MaterializedWorkspace,
        request: ProcessRequest,
        *,
        phase: Literal["compile", "query"],
    ) -> None:
        """Refuse to run unless the frozen OCI policy matches the actual fixed invocation.

        The host-specific bind source paths remain outside the policy hash, but every security
        relevant destination, isolation flag, image digest, and wrapper argument is checked
        against the policy embedded in the frozen Lean environment.
        """

        policy = self._require_v2_policy(workspace)
        image = self._worker.spec.image
        image_digest = image.rsplit("@", maxsplit=1)[1]
        if image_digest != policy.worker_image_digest:
            raise ValidationError(
                "oci_worker_image_policy_mismatch",
                "OCI worker image digest differs from the frozen verifier policy",
            )
        expected_wrapper = (
            policy.compile_wrapper_argv()
            if phase == "compile"
            else policy.wrapper_argv(workspace.bundle.proof_boundary.expected_declaration)
        )
        actual_wrapper = (
            self._compile_wrapper_command()
            if phase == "compile"
            else self._wrapper_command(workspace)
        )
        if actual_wrapper != expected_wrapper:
            raise ValidationError(
                "oci_wrapper_command_policy_mismatch",
                "OCI wrapper command differs from the frozen verifier policy",
            )
        argv = request.argv
        if not self._has_option(argv, "--network", policy.network_mode):
            raise ValidationError(
                "oci_network_policy_mismatch",
                "OCI invocation does not satisfy the frozen no-network policy",
            )
        if policy.read_only_root and "--read-only" not in argv:
            raise ValidationError(
                "oci_read_only_root_policy_mismatch",
                "OCI invocation does not satisfy the frozen read-only-root policy",
            )
        if policy.drop_all_capabilities and not self._has_option(argv, "--cap-drop", "ALL"):
            raise ValidationError(
                "oci_capability_policy_mismatch",
                "OCI invocation does not satisfy the frozen capability policy",
            )
        if policy.no_new_privileges and not self._has_option(
            argv, "--security-opt", "no-new-privileges"
        ):
            raise ValidationError(
                "oci_privilege_policy_mismatch",
                "OCI invocation does not satisfy the frozen privilege policy",
            )
        if not self._has_option(argv, "--user", self._worker.spec.runtime_user):
            raise ValidationError(
                "oci_runtime_user_policy_mismatch",
                "OCI invocation does not use the configured numeric non-root host identity",
            )
        required_mounts: list[tuple[str, bool]] = [
            (policy.source_mount_path, policy.source_mount_read_only),
            (policy.dependencies_mount_path, policy.dependencies_mount_read_only),
        ]
        if phase == "compile":
            required_mounts.extend(
                [
                    (policy.candidate_path, policy.candidate_mount_read_only),
                    (policy.compiler_output_path.rpartition("/")[0], False),
                ]
            )
        else:
            required_mounts.append((policy.compiled_candidate_path, True))
        for destination, required in required_mounts:
            if not self._has_mount(argv, destination, readonly=required):
                raise ValidationError(
                    "oci_mount_policy_mismatch",
                    "OCI invocation does not satisfy the frozen mount policy",
                )
        if not self._has_option(argv, "--workdir", policy.workdir):
            raise ValidationError(
                "oci_workdir_policy_mismatch",
                "OCI invocation does not satisfy the frozen working-directory policy",
            )
        try:
            image_index = argv.index(image)
        except ValueError as error:
            raise ValidationError(
                "oci_worker_image_missing",
                "OCI invocation does not contain the configured worker image",
            ) from error
        if argv[image_index + 1 :] != expected_wrapper:
            raise ValidationError(
                "oci_wrapper_command_policy_mismatch",
                "OCI invocation wrapper suffix differs from the frozen verifier policy",
            )
        for image_owned_destination in _IMAGE_OWNED_PATHS:
            if self._has_mount(argv, image_owned_destination, readonly=False):
                raise ValidationError(
                    "oci_image_owned_mount",
                    "OCI invocation may not host-mount an image-owned verifier path",
                )
        allowed_destinations = {
            policy.source_mount_path,
            policy.dependencies_mount_path,
            policy.candidate_path if phase == "compile" else policy.compiled_candidate_path,
            policy.compiler_output_path.rpartition("/")[0] if phase == "compile" else "",
        }
        observed_destinations = self._mount_destinations(argv)
        if observed_destinations != allowed_destinations - {""}:
            raise ValidationError(
                "oci_mount_policy_mismatch",
                "OCI invocation contains an unexpected phase mount",
            )
        if self._has_mount(argv, policy.workdir, readonly=False):
            raise ValidationError(
                "oci_workspace_mount_forbidden",
                "OCI compile/query phases may not mount the attempt workspace",
            )

    @staticmethod
    def _require_v2_policy(workspace: MaterializedWorkspace) -> OciVerifierExecutionPolicyV2:
        policy = workspace.bundle.contract.formal.environment.verifier_execution_policy
        if not isinstance(policy, OciVerifierExecutionPolicyV2):
            raise ValidationError(
                "oci_execution_policy_version_unsupported",
                "the two-phase OCI runner requires an explicit V2 policy and a new "
                "statement-contract revision",
            )
        return policy

    def _validate_execution_claim(self, workspace: MaterializedWorkspace) -> None:
        """Check the immutable bundle claim and its live control-plane fence.

        A local runner cannot establish lease freshness itself.  The injected validator is the
        narrow authority boundary and must reject expired or replaced leases.  It is called both
        sides of ``docker run`` so an old worker cannot emit a promotable result after a new lease
        takes ownership.
        """

        claim = self._execution_claim
        validator = self._claim_validator
        if claim is None:
            return
        if validator is None:
            raise ValidationError(
                "oci_execution_claim_validator_absent",
                "lease-bound OCI execution has no live authority validator",
            )
        claim.assert_authorizes(workspace.task_input, now=datetime.now(UTC))
        try:
            validator.assert_current(claim)
        except ValidationError:
            raise
        except Exception as error:
            raise ValidationError(
                "oci_execution_claim_validator_rejected",
                "OCI execution claim was not confirmed by the authority validator",
            ) from error

    @staticmethod
    def _has_option(argv: tuple[str, ...], option: str, expected: str) -> bool:
        return any(
            argv[index] == option and argv[index + 1] == expected for index in range(len(argv) - 1)
        )

    @staticmethod
    def _has_mount(argv: tuple[str, ...], destination: str, *, readonly: bool) -> bool:
        for index in range(len(argv) - 1):
            if argv[index] != "--mount":
                continue
            fields = frozenset(argv[index + 1].split(","))
            if f"dst={destination}" not in fields:
                continue
            if readonly and "readonly" not in fields:
                continue
            if not readonly and "readonly" in fields:
                continue
            return True
        return False

    @staticmethod
    def _mount_destinations(argv: tuple[str, ...]) -> set[str]:
        destinations: set[str] = set()
        for index in range(len(argv) - 1):
            if argv[index] != "--mount":
                continue
            for field in argv[index + 1].split(","):
                if field.startswith("dst="):
                    destinations.add(field.removeprefix("dst="))
        return destinations

    def _execution_evidence(
        self,
        workspace: MaterializedWorkspace,
        *,
        process_argvs: tuple[tuple[str, ...], ...],
        candidate_sha256: str,
        compiled_candidate_sha256: str | None,
        observed_identity: ImageOwnedVerifierIdentity | None,
    ) -> OciExecutionEvidence:
        protected = {item.path: item.sha256 for item in workspace.protected_files}
        statement_hash = protected.get(workspace.bundle.proof_boundary.trusted_statement_path)
        manifest_hash = protected.get("bundle-manifest.json")
        if statement_hash is None or manifest_hash is None:
            raise ValidationError(
                "oci_workspace_evidence_missing",
                "OCI Lean runner lacks required protected workspace hashes",
            )
        environment = workspace.bundle.contract.formal.environment
        policy = self._require_v2_policy(workspace)
        image = self._worker.spec.image
        image_digest = image.rsplit("@", maxsplit=1)[1]
        if len(process_argvs) not in {1, 2}:
            raise ValidationError(
                "oci_command_transcript_shape",
                "OCI execution evidence must contain compile and optional query commands",
            )
        compile_command_hash = self._argv_hash(process_argvs[0])
        query_command_hash = None if len(process_argvs) == 1 else self._argv_hash(process_argvs[1])
        if (query_command_hash is None) != (compiled_candidate_sha256 is None):
            raise ValidationError(
                "oci_command_transcript_handoff",
                "OCI query evidence is not bound to one sealed compiled candidate",
            )
        command_transcript = {
            "schema_version": "autolean.oci-command-transcript.v2",
            "handoff_protocol": policy.handoff_protocol,
            "compile_command_hash": compile_command_hash,
            "query_command_hash": query_command_hash,
            "sealed_candidate_sha256": compiled_candidate_sha256,
        }
        command_hash = hashlib.sha256(
            json.dumps(
                command_transcript,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        claim = self._execution_claim
        authority_status: Literal[
            "non-production", "lease-bound-unobserved", "lease-bound-pending-gateway"
        ]
        if claim is None:
            authority_status = OCI_EXECUTION_AUTHORITY_NON_PRODUCTION
            claim_hash: str | None = None
            lease_worker_id: str | None = None
            fencing_token: int | None = None
            lease_expires_at: datetime | None = None
            identity_hash: str | None = None
        elif observed_identity is None:
            authority_status = OCI_EXECUTION_AUTHORITY_LEASE_UNOBSERVED
            claim_hash = claim.claim_hash()
            lease_worker_id = claim.lease.worker_id
            fencing_token = claim.lease.fencing_token
            lease_expires_at = claim.lease.expires_at
            identity_hash = None
        else:
            authority_status = OCI_EXECUTION_AUTHORITY_LEASE_PENDING_GATEWAY
            claim_hash = claim.claim_hash()
            lease_worker_id = claim.lease.worker_id
            fencing_token = claim.lease.fencing_token
            lease_expires_at = claim.lease.expires_at
            identity_hash = observed_identity.identity_hash()
        return OciExecutionEvidence(
            worker_image=image,
            worker_image_digest=image_digest,
            environment_hash=environment.environment_hash.value,
            lean_version=environment.lean_version,
            mathlib_revision=environment.mathlib_revision,
            lake_manifest_hash=(
                None
                if environment.lake_manifest_hash is None
                else environment.lake_manifest_hash.value
            ),
            wrapper_protocol=_WRAPPER_PROTOCOL,
            command_policy_hash=policy.command_policy_hash().value,
            command_hash=command_hash,
            compile_command_hash=compile_command_hash,
            query_command_hash=query_command_hash,
            sealed_candidate_sha256=compiled_candidate_sha256,
            candidate_sha256=candidate_sha256,
            trusted_statement_sha256=statement_hash,
            bundle_manifest_sha256=manifest_hash,
            authority_status=authority_status,
            execution_claim_hash=claim_hash,
            lease_worker_id=lease_worker_id,
            lease_fencing_token=fencing_token,
            lease_expires_at=lease_expires_at,
            wrapper_identity_hash=identity_hash,
        )

    @staticmethod
    def _argv_hash(argv: tuple[str, ...]) -> str:
        return hashlib.sha256(
            json.dumps(argv, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    def _parse_wrapper_result(self, raw: str, workspace: MaterializedWorkspace) -> _WrapperResult:
        try:
            payload = json.loads(
                raw,
                object_pairs_hook=OciLeanRunner._unique_json_object,
                parse_constant=OciLeanRunner._reject_nonstandard_json_constant,
            )
        except (json.JSONDecodeError, ValueError) as error:
            raise ValidationError(
                "oci_wrapper_output_malformed",
                "OCI Lean wrapper did not emit one JSON result",
            ) from error
        if not isinstance(payload, dict) or set(payload) not in {
            _WRAPPER_RESULT_FIELDS,
            _WRAPPER_RESULT_FIELDS | {_WRAPPER_IDENTITY_FIELD},
        }:
            raise ValidationError(
                "oci_wrapper_output_shape",
                "OCI Lean wrapper result has an unexpected shape",
            )
        expected_declaration = workspace.bundle.proof_boundary.expected_declaration
        declaration = payload["declaration"]
        canonical_type = payload["canonical_type"]
        if not isinstance(declaration, str):
            raise ValidationError(
                "oci_wrapper_declaration_shape",
                "OCI Lean wrapper declaration must be text",
            )
        if declaration != expected_declaration:
            raise ValidationError(
                "oci_wrapper_declaration_mismatch",
                "OCI Lean wrapper resolved a declaration outside the frozen boundary",
            )
        if not isinstance(canonical_type, str):
            raise ValidationError(
                "oci_wrapper_type_shape",
                "OCI Lean wrapper canonical type must be text",
            )
        environment = workspace.bundle.contract.formal.environment
        for field in ("schema_version", "lean_version", "mathlib_revision"):
            if not isinstance(payload[field], str):
                raise ValidationError(
                    "oci_wrapper_environment_shape",
                    "OCI Lean wrapper environment fields must be text",
                )
        if payload["lake_manifest_hash"] is not None and not isinstance(
            payload["lake_manifest_hash"], str
        ):
            raise ValidationError(
                "oci_wrapper_lake_manifest_shape",
                "OCI Lean wrapper Lake manifest hash must be text or null",
            )
        if payload["schema_version"] != _WRAPPER_PROTOCOL:
            raise ValidationError(
                "oci_wrapper_protocol_mismatch",
                "OCI Lean wrapper reported an unsupported protocol",
            )
        if payload["lean_version"] != environment.lean_version:
            raise ValidationError(
                "oci_wrapper_lean_version_mismatch",
                "OCI Lean wrapper reported a different Lean version",
            )
        if payload["mathlib_revision"] != environment.mathlib_revision:
            raise ValidationError(
                "oci_wrapper_mathlib_mismatch",
                "OCI Lean wrapper reported a different mathlib revision",
            )
        expected_lake_manifest = (
            None if environment.lake_manifest_hash is None else environment.lake_manifest_hash.value
        )
        if payload["lake_manifest_hash"] != expected_lake_manifest:
            raise ValidationError(
                "oci_wrapper_lake_manifest_mismatch",
                "OCI Lean wrapper reported a different Lake manifest",
            )
        image_identity = self._parse_image_identity(payload)
        return _WrapperResult(
            declaration=declaration,
            canonical_type=canonical_type,
            observed_axioms=OciLeanRunner._parse_axioms(payload["observed_axioms"]),
            image_identity=image_identity,
        )

    def _parse_image_identity(
        self, payload: dict[str, object]
    ) -> ImageOwnedVerifierIdentity | None:
        raw_identity = payload.get(_WRAPPER_IDENTITY_FIELD)
        expected = self._worker.spec.image_identity
        if raw_identity is None:
            if expected is not None:
                raise ValidationError(
                    "oci_wrapper_identity_absent",
                    "OCI Lean wrapper did not report the required image-owned identity",
                )
            return None
        observed = ImageOwnedVerifierIdentity.from_wrapper_record(raw_identity)
        if expected is not None and observed != expected:
            raise ValidationError(
                "oci_wrapper_identity_mismatch",
                "OCI Lean wrapper identity differs from the claimed image-owned verifier",
            )
        return observed

    @staticmethod
    def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        payload: dict[str, object] = {}
        for key, value in pairs:
            if key in payload:
                raise ValueError(f"duplicate JSON key: {key}")
            payload[key] = value
        return payload

    @staticmethod
    def _reject_nonstandard_json_constant(value: str) -> object:
        raise ValueError(f"non-standard JSON constant: {value}")

    @staticmethod
    def _parse_axioms(value: object) -> tuple[str, ...]:
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValidationError(
                "oci_wrapper_axioms_shape",
                "OCI Lean wrapper observed axioms must be a list of strings",
            )
        axioms = tuple(value)
        if len(set(axioms)) != len(axioms) or any(
            not item or item != item.strip() or "\x00" in item or "\n" in item or "\r" in item
            for item in axioms
        ):
            raise ValidationError(
                "oci_wrapper_axioms_invalid",
                "OCI Lean wrapper observed axioms are malformed",
            )
        return tuple(sorted(axioms))

    @staticmethod
    def _axiom_stdout(axioms: tuple[str, ...]) -> str:
        return "axioms: [" + ", ".join(axioms) + "]\n"

    @staticmethod
    def _sha256_file(path: Path) -> str:
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as error:
            raise ValidationError(
                "oci_candidate_unreadable",
                "OCI Lean runner candidate could not be read",
            ) from error
