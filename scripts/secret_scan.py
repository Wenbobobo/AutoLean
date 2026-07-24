"""Scan repository-controlled text files for likely credential material.

The scanner is intentionally small and offline. It reports only relative paths and
rule identifiers; matched text, line contents, and environment values are never emitted.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

MAX_TEXT_BYTES = 2 * 1024 * 1024
EXCLUDED_COMPONENTS = frozenset(
    {
        ".agents",
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".quarantine",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "node_modules",
    }
)
EXCLUDED_PREFIXES = (
    ("benchmarks", "results"),
    ("benchmarks", "vendor"),
)


@dataclass(frozen=True, slots=True)
class SecretRule:
    identifier: str
    pattern: re.Pattern[str]


@dataclass(frozen=True, order=True, slots=True)
class Finding:
    path: str
    rule: str


@dataclass(frozen=True, slots=True)
class ScanResult:
    files_scanned: int
    findings: tuple[Finding, ...]


RULES = (
    SecretRule(
        "private-key-header",
        re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    ),
    SecretRule(
        "openai-api-key",
        re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b"),
    ),
    SecretRule(
        "github-token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    ),
    SecretRule("huggingface-token", re.compile(r"\bhf_[A-Za-z0-9]{20,}\b")),
    SecretRule("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    SecretRule(
        "credential-in-url",
        re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]{8,}@"),
    ),
    SecretRule(
        "literal-credential-assignment",
        re.compile(
            r"""(?ix)
            \b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret)\b
            \s*[:=]\s*
            (?P<quote>["'])
            (?!<|example|placeholder|redacted|test(?:ing)?[-_])
            [^"'\r\n]{12,}
            (?P=quote)
            """
        ),
    ),
)


class SecretScanError(RuntimeError):
    """Repository file discovery or safe reading failed."""


def _require_index_worktree_alignment(root: Path) -> None:
    """Ensure worktree reads describe the exact bytes currently staged in Git."""
    try:
        completed = subprocess.run(
            (
                "git",
                "-C",
                str(root),
                "diff",
                "--quiet",
                "--no-ext-diff",
                "--",
            ),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as error:
        raise SecretScanError("git is required for index/worktree comparison") from error
    if completed.returncode == 1:
        raise SecretScanError(
            "git index and worktree differ; stage or restore tracked changes before secret scan"
        )
    if completed.returncode != 0:
        raise SecretScanError("git index/worktree comparison failed")


def _normalized_relative_path(value: str) -> PurePosixPath:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if not normalized or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise SecretScanError("repository discovery returned an unsafe path")
    return path


def is_excluded(relative: PurePosixPath) -> bool:
    folded = tuple(part.casefold() for part in relative.parts)
    if any(part in EXCLUDED_COMPONENTS for part in folded):
        return True
    return any(folded[: len(prefix)] == prefix for prefix in EXCLUDED_PREFIXES)


def discover_repository_files(root: Path) -> tuple[PurePosixPath, ...]:
    """Return tracked and non-ignored candidate files without traversing ignored trees."""

    try:
        completed = subprocess.run(
            (
                "git",
                "-C",
                str(root),
                "-c",
                "core.quotepath=false",
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
            ),
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
        )
    except OSError as error:
        raise SecretScanError("git is required for repository-controlled file discovery") from error
    if completed.returncode != 0:
        raise SecretScanError("git could not enumerate repository-controlled files")

    paths = {
        _normalized_relative_path(os.fsdecode(raw)) for raw in completed.stdout.split(b"\0") if raw
    }
    return tuple(sorted(path for path in paths if not is_excluded(path)))


def _read_candidate(root: Path, relative: PurePosixPath) -> tuple[str | None, Finding | None]:
    native = root.joinpath(*relative.parts)
    try:
        if native.is_symlink() or not native.is_file():
            return None, Finding(relative.as_posix(), "unsafe-or-nonregular-file")
        size = native.stat().st_size
        if size > MAX_TEXT_BYTES:
            with native.open("rb") as handle:
                prefix = handle.read(8192)
            if b"\0" in prefix:
                return None, None
            return None, Finding(relative.as_posix(), "oversized-text-file")
        content = native.read_bytes()
    except OSError as error:
        raise SecretScanError(
            f"cannot safely inspect repository path: {relative.as_posix()}"
        ) from error

    if b"\0" in content:
        return None, None
    try:
        return content.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, None


def scan_paths(root: Path, paths: tuple[PurePosixPath, ...]) -> ScanResult:
    root = root.resolve()
    findings: set[Finding] = set()
    files_scanned = 0
    for relative in paths:
        if is_excluded(relative):
            continue
        content, structural_finding = _read_candidate(root, relative)
        if structural_finding is not None:
            findings.add(structural_finding)
        if content is None:
            continue
        files_scanned += 1
        for rule in RULES:
            if rule.pattern.search(content) is not None:
                findings.add(Finding(relative.as_posix(), rule.identifier))
    return ScanResult(files_scanned=files_scanned, findings=tuple(sorted(findings)))


def scan_repository(root: Path) -> ScanResult:
    resolved = root.resolve()
    _require_index_worktree_alignment(resolved)
    return scan_paths(resolved, discover_repository_files(resolved))


def report(result: ScanResult) -> str:
    payload: dict[str, object] = {
        "files_scanned": result.files_scanned,
        "status": "blocked" if result.findings else "ok",
    }
    if result.findings:
        payload["findings"] = [
            {"path": finding.path, "rule": finding.rule} for finding in result.findings
        ]
    return json.dumps(payload, ensure_ascii=True, sort_keys=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        result = scan_repository(args.root)
    except SecretScanError as error:
        parser.error(str(error))
    print(report(result))
    if result.findings:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
