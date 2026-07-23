from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from .errors import ArtifactCorruption, ArtifactNotFound
from .events import canonical_json

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class ArtifactRef:
    digest: str
    size: int
    algorithm: str = "sha256"

    def __post_init__(self) -> None:
        if self.algorithm != "sha256":
            raise ValueError("only sha256 artifacts are supported")
        if not _SHA256_RE.fullmatch(self.digest):
            raise ValueError("digest must be 64 lowercase hexadecimal characters")
        if self.size < 0:
            raise ValueError("artifact size must be non-negative")

    @property
    def uri(self) -> str:
        return f"sha256:{self.digest}"


class ArtifactStore:
    """Immutable filesystem blob store addressed by SHA-256."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).absolute()
        self.root.mkdir(parents=True, exist_ok=True)
        self._assert_no_link_or_reparse_point(self.root)
        self.blob_root = self.root / "sha256"
        self.blob_root.mkdir(parents=True, exist_ok=True)
        self._assert_safe_store_path(self.blob_root)

    def put_bytes(self, data: bytes) -> ArtifactRef:
        digest = hashlib.sha256(data).hexdigest()
        target = self._path_for_digest(digest)
        reference = ArtifactRef(digest=digest, size=len(data))
        if target.exists():
            self.verify(reference)
            return reference

        target.parent.mkdir(parents=True, exist_ok=True)
        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=target.parent, prefix=".incoming-", delete=False
            ) as handle:
                temp_path = Path(handle.name)
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            with suppress(FileExistsError):
                os.link(temp_path, target)
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
        self.verify(reference)
        return reference

    def put_json(self, value: object) -> ArtifactRef:
        return self.put_bytes(canonical_json(value).encode("utf-8"))

    def put_file(self, source: str | Path, *, chunk_size: int = 1024 * 1024) -> ArtifactRef:
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        source_path = Path(source)
        if self._is_link_or_reparse_point(source_path):
            raise ArtifactCorruption("artifact source must not be a symbolic link or reparse point")
        if not source_path.is_file():
            raise ArtifactNotFound("artifact source does not exist")
        digest = hashlib.sha256()
        size = 0
        temporary_dir = self.root / ".incoming"
        temporary_dir.mkdir(parents=True, exist_ok=True)
        temp_path: Path | None = None
        try:
            with (
                source_path.open("rb") as reader,
                tempfile.NamedTemporaryFile(
                    mode="wb", dir=temporary_dir, prefix="blob-", delete=False
                ) as writer,
            ):
                temp_path = Path(writer.name)
                while chunk := reader.read(chunk_size):
                    digest.update(chunk)
                    size += len(chunk)
                    writer.write(chunk)
                writer.flush()
                os.fsync(writer.fileno())

            reference = ArtifactRef(digest=digest.hexdigest(), size=size)
            target = self._path_for_digest(reference.digest)
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                self.verify(reference)
                temp_path.unlink(missing_ok=True)
                temp_path = None
                return reference
            with suppress(FileExistsError):
                os.link(temp_path, target)
            self.verify(reference)
            return reference
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

    def get_bytes(self, reference: ArtifactRef | str) -> bytes:
        digest = reference.digest if isinstance(reference, ArtifactRef) else reference
        path = self._path_for_digest(digest)
        if not path.is_file():
            raise ArtifactNotFound(f"artifact sha256:{digest} does not exist")
        data = path.read_bytes()
        expected_size = reference.size if isinstance(reference, ArtifactRef) else len(data)
        self._verify_bytes(digest, expected_size, data)
        return data

    def open(self, reference: ArtifactRef | str) -> BinaryIO:
        digest = reference.digest if isinstance(reference, ArtifactRef) else reference
        path = self._path_for_digest(digest)
        if not path.is_file():
            raise ArtifactNotFound(f"artifact sha256:{digest} does not exist")
        if isinstance(reference, ArtifactRef):
            self.verify(reference)
        return path.open("rb")

    def exists(self, reference: ArtifactRef | str) -> bool:
        digest = reference.digest if isinstance(reference, ArtifactRef) else reference
        return self._path_for_digest(digest).is_file()

    def verify(self, reference: ArtifactRef) -> None:
        path = self._path_for_digest(reference.digest)
        if not path.is_file():
            raise ArtifactNotFound(f"artifact {reference.uri} does not exist")
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
        if size != reference.size or digest.hexdigest() != reference.digest:
            raise ArtifactCorruption(f"artifact {reference.uri} failed integrity verification")

    def path_for(self, reference: ArtifactRef | str) -> Path:
        digest = reference.digest if isinstance(reference, ArtifactRef) else reference
        path = self._path_for_digest(digest)
        if not path.is_file():
            raise ArtifactNotFound(f"artifact sha256:{digest} does not exist")
        return path

    def _path_for_digest(self, digest: str) -> Path:
        if not _SHA256_RE.fullmatch(digest):
            raise ValueError("digest must be 64 lowercase hexadecimal characters")
        path = self.blob_root / digest[:2] / digest[2:4] / digest
        self._assert_safe_store_path(path)
        return path

    def _assert_safe_store_path(self, path: Path) -> None:
        """Ensure content-addressed reads never follow a worker-created filesystem link."""

        try:
            relative = path.relative_to(self.root)
        except ValueError as exc:
            raise ArtifactCorruption("artifact path escaped the configured store") from exc
        current = self.root
        self._assert_no_link_or_reparse_point(current)
        for part in relative.parts:
            current /= part
            self._assert_no_link_or_reparse_point(current)

    @staticmethod
    def _is_link_or_reparse_point(path: Path) -> bool:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(metadata.st_mode):
            return True
        reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        attributes = getattr(metadata, "st_file_attributes", 0)
        return bool(reparse_point and attributes & reparse_point)

    @classmethod
    def _assert_no_link_or_reparse_point(cls, path: Path) -> None:
        if cls._is_link_or_reparse_point(path):
            raise ArtifactCorruption(
                "artifact store must not follow symbolic links or reparse points"
            )

    @staticmethod
    def _verify_bytes(digest: str, expected_size: int, data: bytes) -> None:
        if len(data) != expected_size or hashlib.sha256(data).hexdigest() != digest:
            raise ArtifactCorruption(f"artifact sha256:{digest} failed integrity verification")
