"""Fail closed when a Git candidate tree is unsafe or unclear for public release."""

from __future__ import annotations

import json
import os
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MAX_TRACKED_FILE_BYTES = 5 * 1024 * 1024
EXPECTED_LICENSE = "Apache-2.0"

FORBIDDEN_COMPONENTS = frozenset(
    {
        ".artifacts",
        ".quarantine",
        "node_modules",
        "release-evidence",
        "results",
        "source-cache",
        "vendor",
    }
)
FORBIDDEN_SUFFIXES = (
    ".7z",
    ".age",
    ".bin",
    ".db",
    ".db-shm",
    ".db-wal",
    ".docx",
    ".gpg",
    ".jsonl",
    ".key",
    ".log",
    ".onnx",
    ".p12",
    ".pdf",
    ".pem",
    ".pfx",
    ".pptx",
    ".safetensors",
    ".sqlite",
    ".sqlite3",
    ".tar",
    ".tar.gz",
    ".tar.zst",
    ".tgz",
    ".xlsx",
    ".zip",
)


class PublicReadinessError(RuntimeError):
    """The candidate tree does not satisfy the public-release boundary."""


@dataclass(frozen=True)
class CandidateFile:
    path: PurePosixPath
    size: int
    is_symlink: bool = False


@dataclass(frozen=True)
class Finding:
    path: str
    rule: str


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PublicReadinessError(f"{label} must be a mapping")
    return value


def _tracked_and_candidate_paths(root: Path) -> tuple[Path, ...]:
    completed = subprocess.run(
        (
            "git",
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ),
        cwd=root,
        check=False,
        capture_output=True,
    )
    if completed.returncode:
        raise PublicReadinessError("git candidate inventory failed")
    candidates: list[Path] = []
    for raw_path in completed.stdout.split(b"\0"):
        if not raw_path:
            continue
        relative = Path(os.fsdecode(raw_path))
        if relative.is_absolute() or ".." in relative.parts:
            raise PublicReadinessError("git candidate inventory contains an unsafe path")
        candidates.append(relative)
    return tuple(sorted(candidates, key=lambda path: path.as_posix()))


def candidate_files(root: Path) -> tuple[CandidateFile, ...]:
    records: list[CandidateFile] = []
    for relative in _tracked_and_candidate_paths(root):
        absolute = root / relative
        if not absolute.exists() and not absolute.is_symlink():
            raise PublicReadinessError("git candidate inventory contains a missing path")
        stat = absolute.lstat()
        records.append(
            CandidateFile(
                path=PurePosixPath(relative.as_posix()),
                size=stat.st_size,
                is_symlink=absolute.is_symlink(),
            )
        )
    return tuple(records)


def audit_candidates(files: tuple[CandidateFile, ...]) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for candidate in files:
        path = candidate.path
        lowered_parts = tuple(part.casefold() for part in path.parts)
        lowered_name = path.name.casefold()
        rendered_path = path.as_posix()
        if candidate.is_symlink:
            findings.append(Finding(path=rendered_path, rule="symlink_not_public_release_input"))
        if any(part in FORBIDDEN_COMPONENTS for part in lowered_parts):
            findings.append(Finding(path=rendered_path, rule="local_or_restricted_directory"))
        if lowered_name != ".env.example" and (
            lowered_name == ".env"
            or lowered_name.endswith(".env")
            or lowered_name.startswith(".env.")
        ):
            findings.append(Finding(path=rendered_path, rule="environment_file"))
        if any(lowered_name.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES):
            findings.append(Finding(path=rendered_path, rule="restricted_or_binary_payload"))
        if candidate.size > MAX_TRACKED_FILE_BYTES:
            findings.append(Finding(path=rendered_path, rule="oversized_tracked_file"))
    return tuple(sorted(findings, key=lambda finding: (finding.path, finding.rule)))


def _project_license(manifest: Path) -> str:
    with manifest.open("rb") as handle:
        document = _mapping(tomllib.load(handle), str(manifest))
    project = _mapping(document.get("project"), f"{manifest}.project")
    license_record = _mapping(project.get("license"), f"{manifest}.project.license")
    value = license_record.get("text")
    if not isinstance(value, str):
        raise PublicReadinessError(f"{manifest} has no textual license")
    return value


def audit_license_metadata(root: Path) -> int:
    license_path = root / "LICENSE"
    if not license_path.is_file():
        raise PublicReadinessError("root LICENSE is missing")
    license_prefix = license_path.read_text(encoding="utf-8")[:200]
    if "Apache License" not in license_prefix or "Version 2.0" not in license_prefix:
        raise PublicReadinessError("root LICENSE is not the declared Apache-2.0 license")

    root_manifest = root / "pyproject.toml"
    with root_manifest.open("rb") as handle:
        document = _mapping(tomllib.load(handle), "pyproject.toml")
    tool = _mapping(document.get("tool"), "pyproject.toml.tool")
    uv = _mapping(tool.get("uv"), "pyproject.toml.tool.uv")
    workspace = _mapping(uv.get("workspace"), "pyproject.toml.tool.uv.workspace")
    members = workspace.get("members")
    if not isinstance(members, list) or not all(isinstance(item, str) for item in members):
        raise PublicReadinessError("uv workspace members are malformed")

    python_manifests = (
        root_manifest,
        *(root / member / "pyproject.toml" for member in members),
    )
    for manifest in python_manifests:
        if _project_license(manifest) != EXPECTED_LICENSE:
            raise PublicReadinessError(f"{manifest} does not declare {EXPECTED_LICENSE}")

    package_json = root / "Dashboard" / "ui" / "package.json"
    package = json.loads(package_json.read_text(encoding="utf-8"))
    if not isinstance(package, dict) or package.get("license") != EXPECTED_LICENSE:
        raise PublicReadinessError("Dashboard UI does not declare Apache-2.0")
    return len(python_manifests) + 1


def check(root: Path = PROJECT_ROOT) -> dict[str, object]:
    files = candidate_files(root)
    findings = audit_candidates(files)
    if findings:
        rendered = json.dumps(
            {
                "findings": [{"path": finding.path, "rule": finding.rule} for finding in findings],
                "status": "blocked",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        raise PublicReadinessError(rendered)
    manifests = audit_license_metadata(root)
    return {
        "files_scanned": len(files),
        "license_manifests": manifests,
        "status": "ok",
    }


def main() -> None:
    try:
        result = check()
    except PublicReadinessError as error:
        print(
            json.dumps(
                {"reason": str(error), "status": "blocked"},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        raise SystemExit(1) from error
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
