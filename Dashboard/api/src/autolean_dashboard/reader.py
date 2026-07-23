from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Protocol

from pydantic import ValidationError

from .models import DashboardSnapshot


class ProjectionReader(Protocol):
    def snapshot(self) -> DashboardSnapshot: ...


class ProjectionUnavailable(RuntimeError):
    """A projection could not be read as a bounded, valid dashboard snapshot."""


class EmptyProjectionReader:
    def snapshot(self) -> DashboardSnapshot:
        return DashboardSnapshot()


class JsonProjectionReader:
    """Read a projection exported by the control plane without workspace access."""

    def __init__(self, path: Path, *, max_bytes: int = 16 * 1024 * 1024) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        # Retain the unresolved path so a symlink cannot silently turn an exported
        # projection into an arbitrary file read by the dashboard process.
        self._path = path.expanduser().absolute()
        self._max_bytes = max_bytes

    def snapshot(self) -> DashboardSnapshot:
        try:
            before = self._path.lstat()
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
                raise ProjectionUnavailable("projection must be a regular file")
            if before.st_size > self._max_bytes:
                raise ProjectionUnavailable("projection exceeds the configured size limit")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self._path, flags)
            with os.fdopen(descriptor, "rb") as handle:
                after_open = os.fstat(handle.fileno())
                if not stat.S_ISREG(after_open.st_mode) or not self._same_file(before, after_open):
                    raise ProjectionUnavailable("projection changed while it was opened")
                if after_open.st_size > self._max_bytes:
                    raise ProjectionUnavailable("projection exceeds the configured size limit")
                raw = handle.read(self._max_bytes + 1)
                after_read = os.fstat(handle.fileno())
                if not self._same_file(after_open, after_read):
                    raise ProjectionUnavailable("projection changed while it was read")
            if len(raw) > self._max_bytes:
                raise ProjectionUnavailable("projection exceeds the configured size limit")
            data = json.loads(raw.decode("utf-8"))
            return DashboardSnapshot.model_validate(data)
        except ProjectionUnavailable:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValidationError) as error:
            # Do not leak filesystem paths, source snippets, or Pydantic internals
            # through an API response. The operator can inspect the local process log.
            raise ProjectionUnavailable("projection is unavailable") from error

    @staticmethod
    def _same_file(before: os.stat_result, after: os.stat_result) -> bool:
        return before.st_dev == after.st_dev and before.st_ino == after.st_ino
