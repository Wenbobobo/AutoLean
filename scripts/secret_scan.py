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

from scripts.public_readiness import (
    FORBIDDEN_COMPONENTS,
    FORBIDDEN_NAMES,
    FORBIDDEN_PATH_PREFIXES,
    FORBIDDEN_SUFFIXES,
    MAX_TRACKED_FILE_BYTES,
    OPERATOR_SECRET_FILENAMES,
)

MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_HISTORY_BLOB_BYTES = MAX_TRACKED_FILE_BYTES
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
HISTORY_EXTRA_PROTECTED_PREFIXES = (("library", "evidence"),)
GIT_OBJECT_ID = re.compile(rb"[0-9a-f]{40,64}")


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


def _history_path_rules(relative: PurePosixPath) -> tuple[str, ...]:
    folded = tuple(part.casefold() for part in relative.parts)
    name = relative.name.casefold()
    rules: list[str] = []
    if any(
        folded[: len(prefix)] == prefix
        for prefix in (*FORBIDDEN_PATH_PREFIXES, *HISTORY_EXTRA_PROTECTED_PREFIXES)
    ):
        rules.append("history-protected-path")
    if any(part in FORBIDDEN_COMPONENTS for part in folded):
        rules.append("history-restricted-directory")
    if name in FORBIDDEN_NAMES or name.endswith(".raw-artifact-manifest.json"):
        rules.append("history-private-manifest")
    if len(folded) == 1 and name in OPERATOR_SECRET_FILENAMES:
        rules.append("history-operator-secret-file")
    if name != ".env.example" and (
        name == ".env" or name.endswith(".env") or name.startswith(".env.")
    ):
        rules.append("history-environment-file")
    if any(name.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES):
        rules.append("history-restricted-payload")
    return tuple(rules)


def _run_git(root: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    try:
        completed = subprocess.run(
            ("git", "-C", str(root), *arguments),
            check=False,
            stdin=None if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            input=input_bytes,
        )
    except OSError as error:
        raise SecretScanError("git is required for repository history inspection") from error
    if completed.returncode != 0:
        raise SecretScanError("git repository history inspection failed")
    return completed.stdout


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
        if len(relative.parts) == 1 and relative.name.casefold() in OPERATOR_SECRET_FILENAMES:
            findings.add(Finding(relative.as_posix(), "operator-secret-file"))
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


def _history_root_trees(root: Path) -> tuple[bytes, ...]:
    refs_output = _run_git(root, "for-each-ref", "--format=%(objectname)", "refs/")
    ref_targets: set[bytes] = set()
    for raw in refs_output.splitlines():
        if not GIT_OBJECT_ID.fullmatch(raw):
            raise SecretScanError("git returned an invalid ref target identifier")
        ref_targets.add(raw)
    if not ref_targets:
        return ()

    ordered_targets = tuple(sorted(ref_targets))
    commit_output = _run_git(
        root,
        "cat-file",
        "--batch-check=%(objectname) %(objecttype)",
        input_bytes=b"\n".join(target + b"^{commit}" for target in ordered_targets) + b"\n",
    )
    commit_lines = commit_output.splitlines()
    if len(commit_lines) != len(ordered_targets):
        raise SecretScanError("git returned an incomplete ref target inventory")
    commits: set[bytes] = set()
    for target, line in zip(ordered_targets, commit_lines, strict=True):
        fields = line.split(b" ")
        if fields == [target + b"^{commit}", b"missing"]:
            continue
        if len(fields) != 2 or not GIT_OBJECT_ID.fullmatch(fields[0]) or fields[1] != b"commit":
            raise SecretScanError("git returned an invalid ref target inventory")
        commits.add(fields[0])
    if not commits:
        return ()

    output = _run_git(
        root,
        "rev-list",
        "--stdin",
        "--format=%T",
        "--no-commit-header",
        input_bytes=b"\n".join(sorted(commits)) + b"\n",
    )
    trees: set[bytes] = set()
    for raw in output.splitlines():
        if not GIT_OBJECT_ID.fullmatch(raw):
            raise SecretScanError("git returned an invalid history tree identifier")
        trees.add(raw)
    return tuple(sorted(trees))


def _history_entries(
    root: Path, trees: tuple[bytes, ...]
) -> dict[tuple[bytes, PurePosixPath], set[tuple[bytes, bytes]]]:
    entries: dict[tuple[bytes, PurePosixPath], set[tuple[bytes, bytes]]] = {}
    for tree in trees:
        output = _run_git(
            root,
            "-c",
            "core.quotepath=false",
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            tree.decode("ascii"),
        )
        for record in output.split(b"\0"):
            if not record:
                continue
            metadata, separator, raw_path = record.partition(b"\t")
            fields = metadata.split(b" ")
            if not separator or len(fields) != 3:
                raise SecretScanError("git returned an invalid history tree entry")
            mode, object_type, object_id = fields
            if not GIT_OBJECT_ID.fullmatch(object_id):
                raise SecretScanError("git returned an invalid history object identifier")
            try:
                relative = _normalized_relative_path(os.fsdecode(raw_path))
            except UnicodeError as error:
                raise SecretScanError("git returned an undecodable history path") from error
            entries.setdefault((object_id, relative), set()).add((mode, object_type))
    return entries


def _history_blob_sizes(root: Path, object_ids: tuple[bytes, ...]) -> dict[bytes, int]:
    if not object_ids:
        return {}
    output = _run_git(
        root,
        "cat-file",
        "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        input_bytes=b"\n".join(object_ids) + b"\n",
    )
    lines = output.splitlines()
    if len(lines) != len(object_ids):
        raise SecretScanError("git returned an incomplete history object inventory")
    sizes: dict[bytes, int] = {}
    for expected, line in zip(object_ids, lines, strict=True):
        fields = line.split(b" ")
        if len(fields) != 3 or fields[0] != expected or fields[1] != b"blob":
            raise SecretScanError("git returned an invalid history blob inventory")
        try:
            size = int(fields[2])
        except ValueError as error:
            raise SecretScanError("git returned an invalid history blob size") from error
        if size < 0:
            raise SecretScanError("git returned an invalid history blob size")
        sizes[expected] = size
    return sizes


def _history_blob_rules(
    root: Path, object_ids: tuple[bytes, ...], sizes: dict[bytes, int]
) -> dict[bytes, tuple[str, ...] | None]:
    if not object_ids:
        return {}
    try:
        process = subprocess.Popen(
            ("git", "-C", str(root), "cat-file", "--batch"),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError as error:
        raise SecretScanError("git is required for repository history inspection") from error
    if process.stdin is None or process.stdout is None:
        process.kill()
        raise SecretScanError("git history blob reader could not start")

    matches: dict[bytes, tuple[str, ...] | None] = {}
    try:
        for object_id in object_ids:
            process.stdin.write(object_id + b"\n")
            process.stdin.flush()
            header = process.stdout.readline().rstrip(b"\n")
            fields = header.split(b" ")
            if (
                len(fields) != 3
                or fields[0] != object_id
                or fields[1] != b"blob"
                or fields[2] != str(sizes[object_id]).encode("ascii")
            ):
                raise SecretScanError("git returned an invalid history blob")
            content = process.stdout.read(sizes[object_id])
            if len(content) != sizes[object_id] or process.stdout.read(1) != b"\n":
                raise SecretScanError("git returned an incomplete history blob")
            if b"\0" in content:
                matches[object_id] = None
                continue
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                matches[object_id] = None
                continue
            matches[object_id] = tuple(
                rule.identifier for rule in RULES if rule.pattern.search(text) is not None
            )
        process.stdin.close()
        if process.wait() != 0:
            raise SecretScanError("git history blob reader failed")
    except BaseException:
        if process.poll() is None:
            process.kill()
            process.wait()
        raise
    return matches


def scan_repository_history(root: Path) -> ScanResult:
    """Scan every unique blob/path pair reachable from local Git refs."""

    resolved = root.resolve()
    entries = _history_entries(resolved, _history_root_trees(resolved))
    findings: set[Finding] = set()
    blob_paths: dict[bytes, set[PurePosixPath]] = {}

    for (object_id, relative), kinds in entries.items():
        rendered_path = relative.as_posix()
        for rule in _history_path_rules(relative):
            findings.add(Finding(rendered_path, rule))
        for mode, object_type in kinds:
            if mode == b"120000" and object_type == b"blob":
                findings.add(Finding(rendered_path, "history-symlink"))
            elif mode == b"160000" and object_type == b"commit":
                findings.add(Finding(rendered_path, "history-submodule"))
            elif object_type != b"blob" or mode not in {b"100644", b"100755"}:
                findings.add(Finding(rendered_path, "history-unsafe-entry"))
        if any(object_type == b"blob" for _, object_type in kinds):
            blob_paths.setdefault(object_id, set()).add(relative)

    object_ids = tuple(sorted(blob_paths))
    sizes = _history_blob_sizes(resolved, object_ids)
    readable_ids = tuple(
        object_id for object_id in object_ids if sizes[object_id] <= MAX_HISTORY_BLOB_BYTES
    )
    blob_rules = _history_blob_rules(resolved, readable_ids, sizes)
    files_scanned = 0
    for object_id, paths in blob_paths.items():
        if sizes[object_id] > MAX_HISTORY_BLOB_BYTES:
            for relative in paths:
                findings.add(Finding(relative.as_posix(), "history-oversized-blob"))
            continue
        rules = blob_rules[object_id]
        if rules is None:
            continue
        files_scanned += len(paths)
        for relative in paths:
            for rule in rules:
                findings.add(Finding(relative.as_posix(), rule))

    return ScanResult(files_scanned=files_scanned, findings=tuple(sorted(findings)))


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
    parser.add_argument(
        "--history",
        action="store_true",
        help="scan every blob/path pair reachable from local Git refs",
    )
    args = parser.parse_args()
    try:
        result = scan_repository_history(args.root) if args.history else scan_repository(args.root)
    except SecretScanError as error:
        parser.error(str(error))
    print(report(result))
    if result.findings:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
