from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

from autolean_prover.errors import ConfigurationError


@dataclass(frozen=True, slots=True)
class ProcessRequest:
    argv: tuple[str, ...]
    cwd: Path
    stdin: str | None = None
    environment: Mapping[str, str] = field(default_factory=dict)
    timeout_seconds: float = 300.0
    max_output_bytes: int = 8 * 1024 * 1024

    def __post_init__(self) -> None:
        if not self.argv or not self.argv[0]:
            raise ConfigurationError("process argv must contain an executable")
        if self.timeout_seconds <= 0:
            raise ConfigurationError("process timeout must be positive")
        if self.max_output_bytes <= 0:
            raise ConfigurationError("max_output_bytes must be positive")
        if any("\x00" in arg for arg in self.argv):
            raise ConfigurationError("process argv cannot contain NUL bytes")


@dataclass(frozen=True, slots=True)
class ProcessResult:
    argv: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    output_truncated: bool = False


@runtime_checkable
class ExecutionHarness(Protocol):
    def execute(self, request: ProcessRequest) -> ProcessResult: ...
