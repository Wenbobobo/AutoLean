"""Local-only materialization for a canonical dependency-closure manifest.

This Stage A module deliberately has no control-plane, claim, OCI, cache, or remote-store
authority. A caller supplies a narrow read-only blob reader; every returned byte is rehashed before
it enters a fresh attempt directory.
"""

from __future__ import annotations

import hashlib
import stat
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol

from autolean_contracts import (
    DependencyClosureArtifactRefV1,
    DependencyClosureFileV1,
    DependencyClosureManifestV1,
    DependencyClosureRefV1,
    validate_dependency_closure_ref,
)

from autolean_prover.errors import ValidationError

_MAX_MANIFEST_BYTES = 16 * 1024 * 1024
_MAX_CLOSURE_FILES = 4096
_MAX_CLOSURE_BYTES = 512 * 1024 * 1024


class DependencyClosureIntegrityError(ValidationError):
    """A closure reference, blob, path, or materialized tree failed closed."""


class DependencyClosureBlobReader(Protocol):
    """Read exactly one content-addressed blob without exposing store enumeration or mutation."""

    def read_blob(self, reference: DependencyClosureArtifactRefV1) -> bytes: ...


@dataclass(frozen=True, slots=True)
class ClaimScopedDependencyBlobReader:
    """Adapter for the control-plane claim capability.

    The callback is intentionally the only operation exposed to the materializer. The control
    plane implementation must bind it to a current claim and reject arbitrary CAS reads.
    """

    read_claimed_artifact: Callable[[DependencyClosureArtifactRefV1], bytes]

    def read_blob(self, reference: DependencyClosureArtifactRefV1) -> bytes:
        return self.read_claimed_artifact(reference)


@dataclass(frozen=True, slots=True)
class _DependencyClosureSnapshot:
    manifest: DependencyClosureManifestV1
    files: tuple[tuple[DependencyClosureFileV1, bytes], ...]


@dataclass(frozen=True, slots=True)
class MaterializedDependencyClosure:
    root: Path
    reference: DependencyClosureRefV1
    manifest: DependencyClosureManifestV1

    def validate_integrity(self) -> None:
        """Rehash the complete tree and reject added, missing, linked, or changed entries."""

        _validate_materialized_tree(self.root, self.manifest)
        if self.manifest.tree_hash != self.reference.tree_hash:
            raise DependencyClosureIntegrityError(
                "dependency_closure_reference_tree",
                "materialized manifest tree differs from the closure reference",
            )


class DependencyClosureMaterializer:
    """Write manifest-selected CAS blobs to one fresh, local, read-only dependency root."""

    def materialize(
        self,
        reference: DependencyClosureRefV1,
        root: str | Path,
        *,
        reader: DependencyClosureBlobReader,
    ) -> MaterializedDependencyClosure:
        snapshot = _read_snapshot(reference, reader)
        destination = _prepare_destination(Path(root))
        destination_identity = _directory_identity(destination)

        for entry, data in snapshot.files:
            _assert_destination_unchanged(destination, destination_identity)
            target = _target_path(destination, entry.relative_path)
            _prepare_safe_parent_chain(
                destination,
                target.parent,
                destination_identity,
            )
            _assert_safe_parent_chain(destination, target.parent, destination_identity)
            if target.exists() or target.is_symlink() or _is_link_or_reparse(target):
                raise DependencyClosureIntegrityError(
                    "dependency_closure_target_exists",
                    f"dependency target already exists: {entry.relative_path}",
                )
            try:
                with target.open("xb") as handle:
                    handle.write(data)
                    handle.flush()
                with suppress(OSError):
                    target.chmod(0o444)
            except OSError as error:
                raise DependencyClosureIntegrityError(
                    "dependency_closure_write",
                    f"dependency blob could not be materialized: {entry.relative_path}",
                ) from error
            _assert_safe_parent_chain(destination, target.parent, destination_identity)
            if _is_link_or_reparse(target) or not target.is_file():
                raise DependencyClosureIntegrityError(
                    "dependency_closure_file_changed",
                    f"dependency blob changed during materialization: {entry.relative_path}",
                )
            try:
                _verify_blob(entry, target.read_bytes())
            except OSError as error:
                raise DependencyClosureIntegrityError(
                    "dependency_closure_file_unreadable",
                    f"materialized dependency file is unreadable: {entry.relative_path}",
                ) from error

        materialized = MaterializedDependencyClosure(
            root=destination,
            reference=reference,
            manifest=snapshot.manifest,
        )
        materialized.validate_integrity()
        return materialized


def _read_snapshot(
    reference: DependencyClosureRefV1,
    reader: DependencyClosureBlobReader,
) -> _DependencyClosureSnapshot:
    raw_manifest = _read_blob(
        reader,
        reference.closure_manifest_ref,
        label="manifest",
        max_size=_MAX_MANIFEST_BYTES,
    )
    try:
        manifest = validate_dependency_closure_ref(reference, raw_manifest)
    except ValueError as error:
        raise DependencyClosureIntegrityError(
            "dependency_closure_manifest",
            "dependency closure manifest failed canonical reference validation",
        ) from error
    if len(manifest.files) > _MAX_CLOSURE_FILES:
        raise DependencyClosureIntegrityError(
            "dependency_closure_file_limit",
            "dependency closure exceeds the local file-count limit",
        )
    total_bytes = sum(entry.artifact.size for entry in manifest.files)
    if total_bytes > _MAX_CLOSURE_BYTES:
        raise DependencyClosureIntegrityError(
            "dependency_closure_size_limit",
            "dependency closure exceeds the local snapshot-size limit",
        )

    cached_blobs: dict[str, bytes] = {}
    staged_files: list[tuple[DependencyClosureFileV1, bytes]] = []
    for entry in manifest.files:
        data = cached_blobs.get(entry.artifact.sha256)
        if data is None:
            data = _read_blob(
                reader,
                entry.artifact,
                label=entry.relative_path,
                max_size=_MAX_CLOSURE_BYTES,
            )
            cached_blobs[entry.artifact.sha256] = data
        _verify_blob(entry, data)
        staged_files.append((entry, data))
    return _DependencyClosureSnapshot(
        manifest=manifest,
        files=tuple(staged_files),
    )


def _prepare_destination(root: Path) -> Path:
    logical = root.absolute()
    _assert_existing_directory_chain(logical.parent)
    if _is_link_or_reparse(logical) or logical.exists():
        raise DependencyClosureIntegrityError(
            "dependency_closure_root_exists",
            "dependency closure root must not exist or be a symbolic link or reparse point "
            "after blobs are staged",
        )
    try:
        logical.mkdir()
    except OSError as error:
        raise DependencyClosureIntegrityError(
            "dependency_closure_root_create",
            "dependency closure root could not be created",
        ) from error
    _assert_existing_directory_chain(logical.parent)
    if _is_link_or_reparse(logical) or not logical.is_dir():
        raise DependencyClosureIntegrityError(
            "dependency_closure_root_changed",
            "dependency closure root changed during preparation",
        )
    return logical


def _read_blob(
    reader: DependencyClosureBlobReader,
    reference: DependencyClosureArtifactRefV1,
    *,
    label: str,
    max_size: int,
) -> bytes:
    if reference.size > max_size:
        raise DependencyClosureIntegrityError(
            "dependency_closure_blob_limit",
            f"dependency blob exceeds its local read limit: {label}",
        )
    try:
        data = reader.read_blob(reference)
    except Exception as error:
        raise DependencyClosureIntegrityError(
            "dependency_closure_blob_missing",
            f"dependency blob is unavailable: {label}",
        ) from error
    if not isinstance(data, bytes):
        raise DependencyClosureIntegrityError(
            "dependency_closure_blob_type",
            f"dependency blob reader returned non-bytes content: {label}",
        )
    if len(data) != reference.size or hashlib.sha256(data).hexdigest() != reference.sha256:
        raise DependencyClosureIntegrityError(
            "dependency_closure_blob_mismatch",
            f"dependency blob differs from its content reference: {label}",
        )
    return data


def _verify_blob(entry: DependencyClosureFileV1, data: bytes) -> None:
    if len(data) != entry.artifact.size:
        raise DependencyClosureIntegrityError(
            "dependency_closure_blob_size",
            f"dependency blob has the wrong size: {entry.relative_path}",
        )
    if hashlib.sha256(data).hexdigest() != entry.artifact.sha256:
        raise DependencyClosureIntegrityError(
            "dependency_closure_blob_hash",
            f"dependency blob has the wrong hash: {entry.relative_path}",
        )


def _validate_materialized_tree(root: Path, manifest: DependencyClosureManifestV1) -> None:
    if _is_link_or_reparse(root) or not root.is_dir():
        raise DependencyClosureIntegrityError(
            "dependency_closure_root_integrity",
            "materialized dependency root is not a regular directory",
        )
    actual_files, actual_directories = _scan_tree(root)
    expected_files = {item.relative_path for item in manifest.files}
    expected_directories = _expected_directories(expected_files)
    if actual_files != expected_files:
        raise DependencyClosureIntegrityError(
            "dependency_closure_file_set",
            "materialized dependency files differ from the canonical manifest",
        )
    if actual_directories != expected_directories:
        raise DependencyClosureIntegrityError(
            "dependency_closure_directory_set",
            "materialized dependency directories differ from the canonical manifest",
        )
    for entry in manifest.files:
        path = _target_path(root, entry.relative_path)
        try:
            data = path.read_bytes()
        except OSError as error:
            raise DependencyClosureIntegrityError(
                "dependency_closure_file_unreadable",
                f"materialized dependency file is unreadable: {entry.relative_path}",
            ) from error
        _verify_blob(entry, data)
    if manifest.tree_hash.value != _tree_hash_value(manifest.files):
        raise DependencyClosureIntegrityError(
            "dependency_closure_tree_hash",
            "materialized dependency tree differs from its canonical tree hash",
        )


def _scan_tree(root: Path) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    pending = [root]
    while pending:
        directory = pending.pop()
        if _is_link_or_reparse(directory) or not directory.is_dir():
            raise DependencyClosureIntegrityError(
                "dependency_closure_tree_link",
                "dependency closure contains a linked or non-directory parent",
            )
        try:
            children = tuple(directory.iterdir())
        except OSError as error:
            raise DependencyClosureIntegrityError(
                "dependency_closure_tree_unreadable",
                "dependency closure tree could not be inspected",
            ) from error
        for child in children:
            relative = child.relative_to(root).as_posix()
            if _is_link_or_reparse(child):
                raise DependencyClosureIntegrityError(
                    "dependency_closure_tree_link",
                    f"dependency closure contains a link or reparse point: {relative}",
                )
            if child.is_dir():
                directories.add(relative)
                pending.append(child)
            elif child.is_file():
                files.add(relative)
            else:
                raise DependencyClosureIntegrityError(
                    "dependency_closure_tree_type",
                    f"dependency closure contains a non-regular entry: {relative}",
                )
    return files, directories


def _expected_directories(paths: set[str]) -> set[str]:
    result: set[str] = set()
    for value in paths:
        parent = PurePosixPath(value).parent
        while parent != PurePosixPath("."):
            result.add(parent.as_posix())
            parent = parent.parent
    return result


def _target_path(root: Path, relative: str) -> Path:
    parts = PurePosixPath(relative).parts
    logical = root.joinpath(*parts)
    resolved_parent = logical.parent.resolve()
    if not resolved_parent.is_relative_to(root.resolve()):
        raise DependencyClosureIntegrityError(
            "dependency_closure_path_escape",
            f"dependency runtime path escaped its root: {relative}",
        )
    return logical


def _prepare_safe_parent_chain(
    root: Path,
    parent: Path,
    destination_identity: tuple[int, int],
) -> None:
    current = root
    for part in parent.relative_to(root).parts:
        _assert_destination_unchanged(root, destination_identity)
        candidate = current / part
        if not candidate.exists() and not _is_link_or_reparse(candidate):
            try:
                candidate.mkdir()
            except OSError as error:
                raise DependencyClosureIntegrityError(
                    "dependency_closure_parent_create",
                    "dependency closure parent could not be created",
                ) from error
        if _is_link_or_reparse(candidate) or not candidate.is_dir():
            raise DependencyClosureIntegrityError(
                "dependency_closure_parent_link",
                "dependency closure parent is linked or is not a directory",
            )
        current = candidate


def _assert_safe_parent_chain(
    root: Path,
    parent: Path,
    destination_identity: tuple[int, int],
) -> None:
    _assert_destination_unchanged(root, destination_identity)
    current = root
    for part in parent.relative_to(root).parts:
        current /= part
        if _is_link_or_reparse(current) or not current.is_dir():
            raise DependencyClosureIntegrityError(
                "dependency_closure_parent_link",
                "dependency closure parent is linked or is not a directory",
            )


def _assert_existing_directory_chain(path: Path) -> None:
    current = path
    while True:
        if _is_link_or_reparse(current) or not current.is_dir():
            raise DependencyClosureIntegrityError(
                "dependency_closure_outer_parent",
                "dependency closure parent chain must contain only regular directories",
            )
        if current.parent == current:
            return
        current = current.parent


def _directory_identity(path: Path) -> tuple[int, int]:
    try:
        metadata = path.stat()
    except OSError as error:
        raise DependencyClosureIntegrityError(
            "dependency_closure_root_unreadable",
            "dependency closure root could not be inspected",
        ) from error
    return metadata.st_dev, metadata.st_ino


def _assert_destination_unchanged(
    root: Path,
    destination_identity: tuple[int, int],
) -> None:
    _assert_existing_directory_chain(root.parent)
    if (
        _is_link_or_reparse(root)
        or not root.is_dir()
        or _directory_identity(root) != destination_identity
    ):
        raise DependencyClosureIntegrityError(
            "dependency_closure_root_changed",
            "dependency closure root changed during materialization",
        )


def _is_link_or_reparse(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(metadata.st_mode):
        return True
    reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(metadata, "st_file_attributes", 0)
    return bool(reparse_point and attributes & reparse_point)


def _tree_hash_value(files: tuple[DependencyClosureFileV1, ...]) -> str:
    from autolean_contracts import dependency_tree_hash

    return dependency_tree_hash(files).value
