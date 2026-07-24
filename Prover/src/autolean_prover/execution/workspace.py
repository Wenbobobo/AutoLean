"""Immutable statement snapshots and narrow patch boundaries for proof workers."""

from __future__ import annotations

import hashlib
import re
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from autolean_contracts import FormalizationTaskBundleV1

from autolean_prover.errors import ExecutionPolicyError, ValidationError
from autolean_prover.execution.authority import FrozenTaskBundleInput

_SAFE_RELATIVE = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")


class WorkspaceIntegrityError(ValidationError):
    """A worker changed a protected statement or manifest byte."""


class PatchBoundaryError(ExecutionPolicyError):
    """A patch touches a path outside the declared agent write domain."""


@dataclass(frozen=True, slots=True)
class ProtectedFile:
    path: str
    sha256: str


@dataclass(frozen=True, slots=True)
class MaterializedWorkspace:
    root: Path
    bundle: FormalizationTaskBundleV1
    task_input: FrozenTaskBundleInput
    protected_files: tuple[ProtectedFile, ...]
    allowed_write_paths: frozenset[str]
    proof_path: Path
    candidate_path: Path

    def validate_integrity(self) -> None:
        self.task_input.validate()
        if self.task_input.bundle is not self.bundle:
            raise WorkspaceIntegrityError("workspace bundle is not its frozen execution input")
        for protected in self.protected_files:
            path = self._resolve(protected.path)
            if not path.is_file():
                raise WorkspaceIntegrityError(
                    f"protected workspace file was removed: {protected.path}"
                )
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != protected.sha256:
                raise WorkspaceIntegrityError(f"protected workspace file changed: {protected.path}")

    def validate_patch(self, unified_diff: str) -> None:
        """Allow only an explicit proof-slot path; do not trust a model's path declaration."""

        paths: set[str] = set()
        for line in unified_diff.splitlines():
            if line.startswith("diff --git "):
                parts = line.split()
                if len(parts) != 4:
                    raise PatchBoundaryError("malformed unified diff header")
                paths.update((self._strip_diff_prefix(parts[2]), self._strip_diff_prefix(parts[3])))
            elif line.startswith("--- ") or line.startswith("+++ "):
                raw = line[4:].split("\t", 1)[0]
                if raw != "/dev/null":
                    paths.add(self._strip_diff_prefix(raw))
        if not paths:
            raise PatchBoundaryError("patch contains no file paths")
        for path in paths:
            self._validate_relative_path(path)
            if path not in self.allowed_write_paths:
                raise PatchBoundaryError(f"patch touches protected or undeclared path: {path}")

    def write_proof(self, proof_source: str) -> None:
        if not proof_source.strip():
            raise ValidationError("proof source must not be empty")
        self.validate_integrity()
        proof_path = self._safe_attempt_write_path(
            self.bundle.proof_boundary.allowed_write_paths[0]
        )
        proof_path.write_text(
            proof_source.rstrip() + "\n",
            encoding="utf-8",
            newline="\n",
        )
        self.validate_integrity()

    def render_candidate(self) -> Path:
        """Generate the sole compilable theorem file from trusted header bytes and proof slot."""

        self.validate_integrity()
        proof = self.proof_path.read_text(encoding="utf-8")
        if not proof.strip():
            raise ValidationError("proof slot is empty")
        header = self._resolve(self.bundle.proof_boundary.trusted_statement_path).read_text(
            encoding="utf-8"
        )
        content = f"{header} := {proof.rstrip()}\n"
        candidate_path = self._safe_attempt_write_path(self.bundle.proof_boundary.candidate_path)
        candidate_path.write_text(content, encoding="utf-8", newline="\n")
        self.validate_integrity()
        return candidate_path

    def candidate_declaration(self) -> str:
        return self.bundle.proof_boundary.expected_declaration

    def _resolve(self, relative: str) -> Path:
        self._validate_relative_path(relative)
        path = (self.root / Path(relative)).resolve()
        if not path.is_relative_to(self.root.resolve()):
            raise WorkspaceIntegrityError("workspace path escaped its root")
        return path

    def _safe_attempt_write_path(self, relative: str) -> Path:
        """Reject worker-created links or non-files before a host-side write.

        The worker may freely mutate its attempt directory between model execution and host-side
        proof rendering. A writable slot must therefore be checked again, rather than trusting the
        path created during materialization.
        """

        self._validate_relative_path(relative)
        root = self.root.resolve()
        logical = self.root / Path(relative)
        if logical.parent.resolve() != root:
            raise WorkspaceIntegrityError("attempt write path has an unsafe parent")
        if logical.is_symlink():
            raise WorkspaceIntegrityError("attempt write path must not be a symbolic link")
        if logical.exists() and not logical.is_file():
            raise WorkspaceIntegrityError("attempt write path must be a regular file")
        resolved = logical.resolve()
        if not resolved.is_relative_to(root):
            raise WorkspaceIntegrityError("attempt write path escaped its workspace")
        return logical

    @staticmethod
    def _strip_diff_prefix(raw: str) -> str:
        if raw.startswith("a/") or raw.startswith("b/"):
            return raw[2:]
        return raw

    @staticmethod
    def _validate_relative_path(value: str) -> None:
        if not _SAFE_RELATIVE.fullmatch(value):
            raise PatchBoundaryError(f"unsafe workspace path: {value!r}")
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts:
            raise PatchBoundaryError(f"workspace path escapes root: {value!r}")


class WorkspaceMaterializer:
    """Create an isolated attempt workspace from a frozen contract without copying host state."""

    def materialize(
        self,
        bundle: FormalizationTaskBundleV1,
        root: str | Path,
    ) -> MaterializedWorkspace:
        task_input = FrozenTaskBundleInput.from_bundle(bundle)
        task_input.validate()
        destination = Path(root).resolve()
        if destination.exists() and any(destination.iterdir()):
            raise ExecutionPolicyError("attempt workspace must be empty before materialization")
        destination.mkdir(parents=True, exist_ok=True)
        boundary = bundle.proof_boundary
        source = boundary.trusted_statement_source
        manifest = boundary.render_solver_manifest()
        files = {
            boundary.trusted_statement_path: source.encode("utf-8"),
            "bundle-manifest.json": manifest.encode("utf-8"),
        }
        protected: list[ProtectedFile] = []
        for relative, content in files.items():
            path = destination / relative
            path.write_bytes(content)
            protected.append(
                ProtectedFile(path=relative, sha256=hashlib.sha256(content).hexdigest())
            )
            with suppress(OSError):
                path.chmod(0o444)
        proof_slot = boundary.allowed_write_paths[0]
        proof_path = destination / proof_slot
        proof_path.write_text("", encoding="utf-8")
        return MaterializedWorkspace(
            root=destination,
            bundle=bundle,
            task_input=task_input,
            protected_files=tuple(protected),
            allowed_write_paths=frozenset(boundary.allowed_write_paths),
            proof_path=proof_path,
            candidate_path=destination / boundary.candidate_path,
        )
