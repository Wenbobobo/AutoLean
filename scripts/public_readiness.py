"""Fail closed when a Git candidate tree is unsafe or unclear for public release."""

from __future__ import annotations

import hashlib
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
PROJECT_SYNTHETIC_FIXTURE_PATH = PurePosixPath(
    "Builder/pilots/local-calibration/project-synthetic-opening-corpus.v1.json"
)
PROJECT_SYNTHETIC_FIXTURE_MANIFEST_PATH = PurePosixPath(
    "Builder/pilots/local-calibration/project-synthetic-opening-corpus.release-manifest.v1.json"
)
PROJECT_SYNTHETIC_FIXTURE_RENDERER_PATH = PurePosixPath(
    "Builder/pilots/local-calibration/render_opening_corpus.py"
)
PROJECT_SYNTHETIC_FIXTURE_LICENSE_SHA256 = (
    "5c9817c129b98e7bb966bca028c43c19107102ef8e03fe799bffb4354f4ef015"
)
PROJECT_SYNTHETIC_FIXTURE_SHA256 = (
    "a8d9ae4faf4d376686e7e209c0ab8bce4c23d0647b81d142244feea9abcd30d7"
)
PROJECT_SYNTHETIC_FIXTURE_SAMPLE_IDS = frozenset(
    {
        "pde-a-transport-sign",
        "pde-a-initial-trace",
        "pde-a-parabolic-regularity",
        "pde-a-weak-uniqueness",
        "pde-a-local-existence",
        "mg-a-infimum-attainment",
        "mg-a-length-geodesic",
        "mg-a-quantifier-order",
        "mg-a-nonempty-vacuity",
        "mg-a-finite-noetherian-compactness",
        "mg-a-endpoint-order",
    }
)

FORBIDDEN_COMPONENTS = frozenset(
    {
        ".artifacts",
        ".cache",
        ".quarantine",
        "node_modules",
        "raw-artifact-manifests",
        "raw-artifacts",
        "raw-outputs",
        "release-evidence",
        "results",
        "source-cache",
        "vendor",
    }
)
FORBIDDEN_PATH_PREFIXES = (
    ("docs", "meeting"),
    ("tmp",),
)
FORBIDDEN_NAMES = frozenset(
    {
        "raw-artifact-manifest.json",
        "raw-output-manifest.json",
    }
)
OPERATOR_SECRET_FILENAMES = frozenset({"llm.txt"})
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
    contains_private_source_excerpt: bool = False
    verified_project_synthetic_fixture: bool = False


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


def _require_index_worktree_alignment(root: Path) -> None:
    """Ensure worktree reads describe the exact bytes currently staged in Git."""
    completed = subprocess.run(
        ("git", "diff", "--quiet", "--no-ext-diff", "--"),
        cwd=root,
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if completed.returncode == 1:
        raise PublicReadinessError(
            "git index and worktree differ; stage or restore tracked changes before release audit"
        )
    if completed.returncode != 0:
        raise PublicReadinessError("git index/worktree comparison failed")


def candidate_files(root: Path) -> tuple[CandidateFile, ...]:
    _require_index_worktree_alignment(root)
    records: list[CandidateFile] = []
    for relative in _tracked_and_candidate_paths(root):
        absolute = root / relative
        if not absolute.exists() and not absolute.is_symlink():
            raise PublicReadinessError("git candidate inventory contains a missing path")
        stat = absolute.lstat()
        contains_private_source_excerpt = (
            not absolute.is_symlink()
            and stat.st_size <= MAX_TRACKED_FILE_BYTES
            and relative.suffix.casefold() == ".json"
            and _json_contains_private_source_excerpt(absolute)
        )
        verified_project_synthetic_fixture = (
            contains_private_source_excerpt
            and _is_verified_project_synthetic_fixture(
                root=root,
                relative=PurePosixPath(relative.as_posix()),
                fixture_path=absolute,
            )
        )
        records.append(
            CandidateFile(
                path=PurePosixPath(relative.as_posix()),
                size=stat.st_size,
                is_symlink=absolute.is_symlink(),
                contains_private_source_excerpt=contains_private_source_excerpt,
                verified_project_synthetic_fixture=verified_project_synthetic_fixture,
            )
        )
    return tuple(records)


def _contains_non_null_private_source_excerpt(value: object) -> bool:
    if isinstance(value, dict):
        if value.get("permitted_excerpt") is not None or value.get("source_text") is not None:
            return True
        return any(_contains_non_null_private_source_excerpt(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_non_null_private_source_excerpt(item) for item in value)
    return False


def _json_contains_private_source_excerpt(path: Path) -> bool:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return _contains_non_null_private_source_excerpt(value)


def _sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _string_mapping(value: object) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def _digest_value(value: object) -> str | None:
    mapping = _string_mapping(value)
    digest = None if mapping is None else mapping.get("value")
    return digest if isinstance(digest, str) else None


def _is_verified_project_synthetic_fixture(
    *,
    root: Path,
    relative: PurePosixPath,
    fixture_path: Path,
) -> bool:
    """Allow excerpts only for the exact repository-synthetic fixture release envelope."""

    if relative != PROJECT_SYNTHETIC_FIXTURE_PATH:
        return False
    try:
        fixture_bytes = fixture_path.read_bytes()
        fixture = _mapping(json.loads(fixture_bytes.decode("utf-8")), "synthetic fixture")
        manifest_path = root.joinpath(*PROJECT_SYNTHETIC_FIXTURE_MANIFEST_PATH.parts)
        manifest = _mapping(
            json.loads(manifest_path.read_text(encoding="utf-8")),
            "synthetic fixture manifest",
        )
        license_path = root / "LICENSE"
        renderer_path = root.joinpath(*PROJECT_SYNTHETIC_FIXTURE_RENDERER_PATH.parts)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, PublicReadinessError):
        return False

    exact_manifest_values = {
        "schema_version": "autolean.project-synthetic-fixture-release-manifest.v1",
        "fixture_path": PROJECT_SYNTHETIC_FIXTURE_PATH.as_posix(),
        "fixture_schema_version": "autolean.builder-local-calibration-fixture-corpus.v1",
        "fixture_record_kind": "local_calibration_fixture",
        "renderer_path": PROJECT_SYNTHETIC_FIXTURE_RENDERER_PATH.as_posix(),
        "repository_license_path": "LICENSE",
        "repository_license_expression": "Apache-2.0",
        "repository_license_sha256": PROJECT_SYNTHETIC_FIXTURE_LICENSE_SHA256,
        "provenance_class": "project_synthetic_fixture",
        "authorship_claim": "generated_for_repository_pending_human_content_review",
        "human_content_review_completed": False,
        "legal_review_claimed": False,
    }
    if any(manifest.get(key) != value for key, value in exact_manifest_values.items()):
        return False
    try:
        fixture_sha256 = hashlib.sha256(fixture_bytes).hexdigest()
        if (
            fixture_sha256 != PROJECT_SYNTHETIC_FIXTURE_SHA256
            or manifest.get("fixture_sha256") != PROJECT_SYNTHETIC_FIXTURE_SHA256
        ):
            return False
        if _sha256_path(license_path) != PROJECT_SYNTHETIC_FIXTURE_LICENSE_SHA256:
            return False
        if manifest.get("renderer_sha256") != _sha256_path(renderer_path):
            return False
    except OSError:
        return False

    binding = _string_mapping(fixture.get("repository_license_binding"))
    if binding is None:
        return False
    exact_fixture_values = {
        "schema_version": "autolean.builder-local-calibration-fixture-corpus.v1",
        "record_kind": "local_calibration_fixture",
        "corpus_id": "project-synthetic-opening-pre-calibration",
        "provenance_class": "project_synthetic_fixture",
        "authorship_claim": "generated_for_repository_pending_human_content_review",
        "human_content_review_completed": False,
        "legal_review_claimed": False,
        "production_rights_cleared": False,
        "promotion_allowed": False,
    }
    if any(fixture.get(key) != value for key, value in exact_fixture_values.items()):
        return False
    exact_binding_values = {
        "schema_version": "autolean.project-synthetic-fixture-license-binding.v1",
        "provenance_class": "project_synthetic_fixture",
        "authorship_claim": "generated_for_repository_pending_human_content_review",
        "repository_license_expression": "Apache-2.0",
        "repository_license_path": "LICENSE",
        "repository_license_sha256": PROJECT_SYNTHETIC_FIXTURE_LICENSE_SHA256,
        "human_content_review_completed": False,
        "legal_review_claimed": False,
    }
    if any(binding.get(key) != value for key, value in exact_binding_values.items()):
        return False

    samples = fixture.get("samples")
    if not isinstance(samples, list) or len(samples) != len(PROJECT_SYNTHETIC_FIXTURE_SAMPLE_IDS):
        return False
    sample_ids = {sample.get("sample_id") for sample in samples if isinstance(sample, dict)}
    if sample_ids != PROJECT_SYNTHETIC_FIXTURE_SAMPLE_IDS:
        return False
    for untyped_sample in samples:
        sample = _string_mapping(untyped_sample)
        if sample is None or not _is_valid_project_synthetic_sample(sample):
            return False
    return True


def _is_valid_project_synthetic_sample(sample: dict[str, Any]) -> bool:
    if (
        sample.get("schema_version") != "autolean.builder-pre-calibration-fixture.v1"
        or sample.get("record_kind") != "pre_calibration_fixture"
        or sample.get("production_ingestion") is not False
        or sample.get("freeze_allowed") is not False
        or sample.get("prover_handoff_allowed") is not False
        or sample.get("production_rights_cleared") is not False
        or sample.get("promotion_allowed") is not False
    ):
        return False
    source_text = sample.get("source_text")
    source = _string_mapping(sample.get("source"))
    rights = _string_mapping(sample.get("rights"))
    authority = _string_mapping(sample.get("authority"))
    if not isinstance(source_text, str) or not source_text or source is None or rights is None:
        return False
    expected_authority = {
        "production_ingestion": False,
        "freeze_allowed": False,
        "prover_handoff_allowed": False,
        "model_egress_allowed": False,
        "production_rights_cleared": False,
        "promotion_allowed": False,
    }
    if authority != expected_authority:
        return False

    source_sha256 = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
    metadata = _string_mapping(source.get("metadata"))
    spans = source.get("spans")
    if (
        _digest_value(source.get("content_hash")) != source_sha256
        or metadata
        != {
            "provenance_class": "project_synthetic_fixture",
            "authorship_claim": "generated_for_repository_pending_human_content_review",
            "human_content_review_completed": False,
            "purpose": "pre_calibration_fixture",
        }
        or not isinstance(spans, list)
        or len(spans) != 1
    ):
        return False
    span = _string_mapping(spans[0])
    if (
        span is None
        or span.get("permitted_excerpt") != source_text
        or span.get("start_offset") != 0
        or span.get("end_offset") != len(source_text.encode("utf-8"))
        or _digest_value(span.get("content_hash")) != source_sha256
    ):
        return False

    restrictions = rights.get("restrictions")
    required_restrictions = {
        "pre-calibration-fixture-only",
        "redistribution-only-exact-project-synthetic-fixture-bytes",
        f"source-bytes-sha256:{source_sha256}",
        "not-production-rights-cleared",
        "no-production-ingestion",
        "no-model-egress",
        "no-prover-handoff",
        "no-promotion",
        "human-content-review-pending",
    }
    return bool(
        rights.get("source_id") == source.get("source_id")
        and rights.get("source_license") == "Apache-2.0"
        and rights.get("generated_code_license") == "Apache-2.0"
        and rights.get("overall_decision") == "restricted"
        and rights.get("redistribution") == "allow"
        and rights.get("model_egress") == "deny"
        and rights.get("training") == "deny"
        and rights.get("embedding") == "deny"
        and rights.get("allowed_endpoint_classes") == []
        and rights.get("reviewed_by") is None
        and rights.get("reviewed_at") is None
        and isinstance(restrictions, list)
        and required_restrictions <= set(restrictions)
    )


def _normalized_path_parts(path: PurePosixPath) -> tuple[str, ...]:
    """Return case-insensitive path components independent of host separators."""
    return tuple(
        part.casefold() for part in str(path).replace("\\", "/").split("/") if part not in {"", "."}
    )


def _has_forbidden_path_prefix(parts: tuple[str, ...]) -> bool:
    return any(
        len(parts) >= len(prefix) and parts[: len(prefix)] == prefix
        for prefix in FORBIDDEN_PATH_PREFIXES
    )


def audit_candidates(files: tuple[CandidateFile, ...]) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for candidate in files:
        path = candidate.path
        lowered_parts = _normalized_path_parts(path)
        lowered_name = path.name.casefold()
        rendered_path = path.as_posix()
        if candidate.is_symlink:
            findings.append(Finding(path=rendered_path, rule="symlink_not_public_release_input"))
        if (
            candidate.contains_private_source_excerpt
            and not candidate.verified_project_synthetic_fixture
        ):
            findings.append(Finding(path=rendered_path, rule="private_source_excerpt"))
        if _has_forbidden_path_prefix(lowered_parts):
            findings.append(Finding(path=rendered_path, rule="operator_only_path_prefix"))
        if any(part in FORBIDDEN_COMPONENTS for part in lowered_parts):
            findings.append(Finding(path=rendered_path, rule="local_or_restricted_directory"))
        if lowered_name in FORBIDDEN_NAMES or lowered_name.endswith(".raw-artifact-manifest.json"):
            findings.append(Finding(path=rendered_path, rule="private_benchmark_manifest"))
        if len(lowered_parts) == 1 and lowered_name in OPERATOR_SECRET_FILENAMES:
            findings.append(Finding(path=rendered_path, rule="operator_secret_file"))
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
