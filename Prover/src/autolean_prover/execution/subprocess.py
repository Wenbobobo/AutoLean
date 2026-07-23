from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Iterable, Mapping
from pathlib import Path

from autolean_prover.errors import ConfigurationError, ExecutionPolicyError
from autolean_prover.execution.base import ProcessRequest, ProcessResult

_DEFAULT_INHERITED_ENVIRONMENT = (
    "PATH",
    "SystemRoot",
    "WINDIR",
    "PATHEXT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
)

_FORBIDDEN_EXPLICIT_ENVIRONMENT = frozenset(
    {
        "BASH_ENV",
        "ENV",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "PYTHONHOME",
        "PYTHONPATH",
    }
)


class CleanSubprocessHarness:
    """Run explicit argv values without a shell and without ambient credential inheritance.

    This class is an execution hygiene boundary, not an operating-system sandbox. Callers must
    still select a sandboxed executable and validate its resulting write set.
    """

    def __init__(
        self,
        *,
        allowed_executables: Iterable[str],
        allowed_working_roots: Iterable[Path],
        inherited_environment: Iterable[str] = _DEFAULT_INHERITED_ENVIRONMENT,
        host_environment: Mapping[str, str] | None = None,
    ) -> None:
        executables = frozenset(allowed_executables)
        roots = tuple(Path(root).resolve() for root in allowed_working_roots)
        if not executables:
            raise ConfigurationError("allowed_executables cannot be empty")
        if not roots:
            raise ConfigurationError("allowed_working_roots cannot be empty")
        self._allowed_executables = executables
        self._allowed_working_roots = roots
        self._inherited_environment = frozenset(inherited_environment)
        self._host_environment = host_environment if host_environment is not None else os.environ

    def execute(self, request: ProcessRequest) -> ProcessResult:
        cwd = self._validate_request(request)
        environment = self._build_environment(request.environment)
        started = time.monotonic()
        try:
            completed = subprocess.run(
                list(request.argv),
                input=request.stdin.encode("utf-8") if request.stdin is not None else None,
                cwd=cwd,
                env=environment,
                capture_output=True,
                check=False,
                shell=False,
                timeout=request.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = self._decode_timeout_output(exc.stdout)
            stderr = self._decode_timeout_output(exc.stderr)
            stdout, stdout_cut = self._limit(stdout, request.max_output_bytes)
            stderr, stderr_cut = self._limit(stderr, request.max_output_bytes)
            return ProcessResult(
                argv=request.argv,
                returncode=None,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=time.monotonic() - started,
                timed_out=True,
                output_truncated=stdout_cut or stderr_cut,
            )

        stdout = completed.stdout.decode("utf-8", errors="replace")
        stderr = completed.stderr.decode("utf-8", errors="replace")
        stdout, stdout_cut = self._limit(stdout, request.max_output_bytes)
        stderr, stderr_cut = self._limit(stderr, request.max_output_bytes)
        return ProcessResult(
            argv=request.argv,
            returncode=completed.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=time.monotonic() - started,
            output_truncated=stdout_cut or stderr_cut,
        )

    def _validate_request(self, request: ProcessRequest) -> Path:
        if request.argv[0] not in self._allowed_executables:
            raise ExecutionPolicyError(f"executable is not allowlisted: {request.argv[0]!r}")
        cwd = request.cwd.resolve(strict=True)
        if not any(cwd.is_relative_to(root) for root in self._allowed_working_roots):
            raise ExecutionPolicyError(f"working directory is outside allowed roots: {cwd}")
        forbidden = _FORBIDDEN_EXPLICIT_ENVIRONMENT.intersection(request.environment)
        if forbidden:
            names = ", ".join(sorted(forbidden))
            raise ExecutionPolicyError(f"explicit environment contains loader controls: {names}")
        if "PATH" in request.environment:
            raise ExecutionPolicyError("explicit environment cannot override PATH")
        return cwd

    def _build_environment(self, explicit: Mapping[str, str]) -> dict[str, str]:
        environment = {
            key: value
            for key, value in self._host_environment.items()
            if key in self._inherited_environment
        }
        for key, value in explicit.items():
            if not key or "=" in key or "\x00" in key or "\x00" in value:
                raise ExecutionPolicyError(f"invalid environment variable name: {key!r}")
            environment[key] = value
        return environment

    @staticmethod
    def _decode_timeout_output(value: str | bytes | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value

    @staticmethod
    def _limit(value: str, max_bytes: int) -> tuple[str, bool]:
        encoded = value.encode("utf-8")
        if len(encoded) <= max_bytes:
            return value, False
        clipped = encoded[:max_bytes].decode("utf-8", errors="ignore")
        return clipped, True
