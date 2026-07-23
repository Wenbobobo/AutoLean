"""Linux OCI command construction for the authoritative Lean worker environment."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from autolean_prover.errors import ConfigurationError, ExecutionPolicyError, ValidationError
from autolean_prover.execution.base import ExecutionHarness, ProcessRequest, ProcessResult
from autolean_prover.execution.lean_runner import (
    CANONICAL_TYPE_FORMAT,
    ElaboratedTypeEvidence,
    LeanRunEvidence,
    OciExecutionEvidence,
)
from autolean_prover.execution.workspace import MaterializedWorkspace

_IMAGE_DIGEST = re.compile(r"^.+@sha256:[0-9a-f]{64}$")
_WRAPPER_PROTOCOL: Final[str] = "autolean.oci-lean-wrapper.v1"
_WRAPPER_EXECUTABLE: Final[str] = "/opt/autolean/bin/autolean-lean-wrapper"
_CONTAINER_CANDIDATE: Final[str] = "/input/Candidate.lean"
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


@dataclass(frozen=True, slots=True)
class _WrapperResult:
    declaration: str
    canonical_type: str
    observed_axioms: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OciWorkerSpec:
    runtime: str
    image: str
    dependency_root: Path
    memory_limit: str = "8g"
    pids_limit: int = 512
    timeout_seconds: float = 900.0
    max_output_bytes: int = 16 * 1024 * 1024

    def __post_init__(self) -> None:
        if not self.runtime.strip():
            raise ConfigurationError("OCI runtime must not be empty")
        if not _IMAGE_DIGEST.fullmatch(self.image):
            raise ConfigurationError("OCI worker image must be pinned by a sha256 digest")
        if self.pids_limit <= 0 or self.timeout_seconds <= 0 or self.max_output_bytes <= 0:
            raise ConfigurationError("OCI worker resource limits must be positive")


class OciWorkerHarness:
    """Execute a fixed command in a no-network, read-only-root Linux container.

    The worker gets a read-only snapshot at `/source`, read-only dependencies at `/deps`, and a
    fresh writable attempt directory at `/work`. A verifier-rendered candidate may additionally
    be mounted read-only at `/input/Candidate.lean`; `/input` must exist in the pinned image. The
    host still verifies protected hashes after execution, because a writable worktree is not a
    statement trust boundary.
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
    ) -> ProcessRequest:
        if not command:
            raise ExecutionPolicyError("OCI worker command must not be empty")
        source = immutable_source.resolve(strict=True)
        attempt = workspace.resolve(strict=True)
        dependencies = self._spec.dependency_root.resolve(strict=True)
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
        argv = (
            self._spec.runtime,
            "run",
            "--rm",
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
            "--mount",
            f"type=bind,src={source},dst=/source,readonly",
            "--mount",
            f"type=bind,src={dependencies},dst=/deps,readonly",
            "--mount",
            f"type=bind,src={attempt},dst=/work",
            *candidate_mount,
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
    ) -> ProcessResult:
        return self._harness.execute(
            self.build_request(
                immutable_source=immutable_source,
                workspace=workspace,
                command=command,
                immutable_candidate=immutable_candidate,
            )
        )


class OciLeanRunner:
    """Run the fixed verifier wrapper in OCI and parse only its structured evidence.

    The wrapper is part of the digest-pinned image. It must capture Lean child stdout/stderr itself
    and emit exactly one JSON object on its own stdout. This prevents a proof from manufacturing a
    wrapper record through Lean diagnostic output. The host derives declaration and type identity
    only from the frozen proof boundary, never from a model request or a reported type hash.
    """

    def __init__(self, *, worker: OciWorkerHarness, immutable_source: Path) -> None:
        if immutable_source.is_symlink():
            raise ConfigurationError("immutable OCI source snapshot must not be a symbolic link")
        try:
            source = immutable_source.resolve(strict=True)
        except OSError as error:
            raise ConfigurationError("immutable OCI source snapshot is unavailable") from error
        if not source.is_dir():
            raise ConfigurationError("immutable OCI source snapshot must be a directory")
        self._worker = worker
        self._immutable_source = source

    def run(self, candidate: Path, *, workspace: MaterializedWorkspace) -> LeanRunEvidence:
        candidate_path = self._validate_candidate(candidate, workspace)
        workspace.validate_integrity()
        self._validate_source_snapshot(workspace)
        before_candidate_hash = self._sha256_file(candidate_path)
        command = self._wrapper_command(workspace)
        expected_request = self._worker.build_request(
            immutable_source=self._immutable_source,
            workspace=workspace.root,
            command=command,
            immutable_candidate=candidate_path,
        )
        self._validate_execution_policy(workspace, expected_request)
        try:
            result = self._worker.execute(
                immutable_source=self._immutable_source,
                workspace=workspace.root,
                command=command,
                immutable_candidate=candidate_path,
            )
        finally:
            workspace.validate_integrity()
            self._validate_source_snapshot(workspace)
            after_candidate_hash = self._sha256_file(candidate_path)
            if after_candidate_hash != before_candidate_hash:
                raise ValidationError(
                    "oci_candidate_changed",
                    "OCI Lean worker changed the verifier-rendered candidate",
                )

        execution = self._execution_evidence(
            workspace,
            process_argv=expected_request.argv,
            candidate_sha256=before_candidate_hash,
        )
        if result.argv != expected_request.argv:
            raise ValidationError(
                "oci_runtime_argv_mismatch",
                "OCI runtime returned evidence for a different execution command",
            )
        if result.output_truncated:
            raise ValidationError(
                "oci_wrapper_output_truncated",
                "OCI Lean wrapper output was truncated",
            )
        if result.timed_out or result.returncode != 0:
            return LeanRunEvidence(
                returncode=result.returncode,
                timed_out=result.timed_out,
                stdout="",
                stderr=result.stderr,
                clean_environment=True,
                oci_execution_evidence=execution,
            )

        wrapper = self._parse_wrapper_result(result.stdout, workspace)
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
            returncode=result.returncode,
            timed_out=False,
            stdout=self._axiom_stdout(wrapper.observed_axioms),
            stderr=result.stderr,
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
    def _wrapper_command(workspace: MaterializedWorkspace) -> tuple[str, ...]:
        declaration = workspace.bundle.proof_boundary.expected_declaration
        return (
            _WRAPPER_EXECUTABLE,
            "--protocol",
            _WRAPPER_PROTOCOL,
            "--candidate",
            _CONTAINER_CANDIDATE,
            "--declaration",
            declaration,
            "--type-format",
            CANONICAL_TYPE_FORMAT,
        )

    def _validate_execution_policy(
        self,
        workspace: MaterializedWorkspace,
        request: ProcessRequest,
    ) -> None:
        """Refuse to run unless the frozen OCI policy matches the actual fixed invocation.

        The host-specific bind source paths remain outside the policy hash, but every security
        relevant destination, isolation flag, image digest, and wrapper argument is checked
        against the policy embedded in the frozen Lean environment.
        """

        policy = workspace.bundle.contract.formal.environment.verifier_execution_policy
        image = self._worker.spec.image
        image_digest = image.rsplit("@", maxsplit=1)[1]
        if image_digest != policy.worker_image_digest:
            raise ValidationError(
                "oci_worker_image_policy_mismatch",
                "OCI worker image digest differs from the frozen verifier policy",
            )
        expected_wrapper = policy.wrapper_argv(workspace.bundle.proof_boundary.expected_declaration)
        if self._wrapper_command(workspace) != expected_wrapper:
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
        for destination, required in (
            (policy.source_mount_path, policy.source_mount_read_only),
            (policy.dependencies_mount_path, policy.dependencies_mount_read_only),
            (policy.candidate_path, policy.candidate_mount_read_only),
        ):
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
            return True
        return False

    def _execution_evidence(
        self,
        workspace: MaterializedWorkspace,
        *,
        process_argv: tuple[str, ...],
        candidate_sha256: str,
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
        policy = environment.verifier_execution_policy
        image = self._worker.spec.image
        image_digest = image.rsplit("@", maxsplit=1)[1]
        command_hash = hashlib.sha256(
            json.dumps(process_argv, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
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
            candidate_sha256=candidate_sha256,
            trusted_statement_sha256=statement_hash,
            bundle_manifest_sha256=manifest_hash,
        )

    @staticmethod
    def _parse_wrapper_result(raw: str, workspace: MaterializedWorkspace) -> _WrapperResult:
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
        if not isinstance(payload, dict) or set(payload) != _WRAPPER_RESULT_FIELDS:
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
        return _WrapperResult(
            declaration=declaration,
            canonical_type=canonical_type,
            observed_axioms=OciLeanRunner._parse_axioms(payload["observed_axioms"]),
        )

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
