import subprocess
from pathlib import Path, PurePosixPath

import pytest

from scripts.public_readiness import (
    MAX_TRACKED_FILE_BYTES,
    PROJECT_ROOT,
    CandidateFile,
    Finding,
    PublicReadinessError,
    _json_contains_private_source_excerpt,
    audit_candidates,
    audit_license_metadata,
    candidate_files,
    check,
)


def test_candidate_policy_accepts_source_and_reference_manifest() -> None:
    files = (
        CandidateFile(PurePosixPath("Builder/references/sources.v1.json"), 512),
        CandidateFile(PurePosixPath("Dashboard/ui/src/App.tsx"), 1_024),
        CandidateFile(PurePosixPath(".env.example"), 64),
    )

    assert audit_candidates(files) == ()


@pytest.mark.parametrize(
    ("path", "rule"),
    [
        ("Builder/references/source-cache/book.pdf", "local_or_restricted_directory"),
        (".cache/references/book.txt", "local_or_restricted_directory"),
        (".quarantine/archive.gpg", "local_or_restricted_directory"),
        ("benchmarks/results/raw.jsonl", "local_or_restricted_directory"),
        (
            "benchmarks/raw-artifacts/sha256/aa/bb/deadbeef",
            "local_or_restricted_directory",
        ),
        (
            "benchmarks/raw-artifact-manifest.json",
            "private_benchmark_manifest",
        ),
        (
            "benchmarks/raw-artifact-manifests/run.json",
            "local_or_restricted_directory",
        ),
        (
            "benchmarks/raw-outputs/sha256/aa/bb/deadbeef",
            "local_or_restricted_directory",
        ),
        (
            "benchmarks/fake.raw-artifact-manifest.json",
            "private_benchmark_manifest",
        ),
        ("operator.env", "environment_file"),
        ("keys/verifier.pem", "restricted_or_binary_payload"),
    ],
)
def test_candidate_policy_rejects_restricted_payloads(path: str, rule: str) -> None:
    findings = audit_candidates((CandidateFile(PurePosixPath(path), 100),))

    assert rule in {finding.rule for finding in findings}


@pytest.mark.parametrize(
    "path",
    (
        "docs/meeting/photo.jpg",
        "DOCS\\MEETING\\photo.jpg",
        "tmp/pdfs/meeting-evidence.txt",
        "TMP\\pdfs\\meeting-evidence.txt",
    ),
)
def test_candidate_policy_rejects_operator_only_path_prefixes(path: str) -> None:
    findings = audit_candidates((CandidateFile(PurePosixPath(path), 100),))

    assert {finding.rule for finding in findings} == {"operator_only_path_prefix"}


@pytest.mark.parametrize(
    "path",
    (
        "docs/meetingsafe/photo.jpg",
        "docs/meeting-notes/photo.jpg",
        "templates/tmp/fixture.txt",
        "tmpfile/fixture.txt",
    ),
)
def test_candidate_policy_path_prefixes_do_not_match_similar_names(path: str) -> None:
    findings = audit_candidates((CandidateFile(PurePosixPath(path), 100),))

    assert findings == ()


@pytest.mark.parametrize(
    "relative_path",
    ("docs/meeting/photo.jpg", "tmp/pdfs/meeting-evidence.txt"),
)
def test_force_added_operator_only_path_is_in_public_candidate_inventory(
    tmp_path: Path, relative_path: str
) -> None:
    subprocess.run(("git", "init", "--quiet"), cwd=tmp_path, check=True)
    (tmp_path / ".gitignore").write_text("docs/meeting/\ntmp/\n", encoding="utf-8")
    protected_file = tmp_path.joinpath(*PurePosixPath(relative_path).parts)
    protected_file.parent.mkdir(parents=True)
    protected_file.write_bytes(b"test-only protected payload")
    subprocess.run(
        ("git", "add", "--force", ".gitignore", relative_path),
        cwd=tmp_path,
        check=True,
    )

    findings = audit_candidates(candidate_files(tmp_path))

    assert findings == (Finding(path=relative_path, rule="operator_only_path_prefix"),)


@pytest.mark.parametrize(
    "case",
    ("oversized", "private-json"),
)
def test_candidate_inventory_rejects_staged_bytes_hidden_by_worktree(
    tmp_path: Path,
    case: str,
) -> None:
    if case == "oversized":
        relative_path = "docs/allowed.md"
        staged_payload = b"x" * (MAX_TRACKED_FILE_BYTES + 1)
    else:
        relative_path = "records/statement.json"
        staged_payload = b'{"source":{"permitted_excerpt":"private source text"}}'
    subprocess.run(("git", "init", "--quiet"), cwd=tmp_path, check=True)
    candidate = tmp_path.joinpath(*PurePosixPath(relative_path).parts)
    candidate.parent.mkdir(parents=True, exist_ok=True)
    candidate.write_bytes(staged_payload)
    subprocess.run(("git", "add", relative_path), cwd=tmp_path, check=True)
    candidate.write_bytes(b"safe worktree bytes")

    with pytest.raises(PublicReadinessError, match="index and worktree differ"):
        candidate_files(tmp_path)


def test_candidate_inventory_rejects_staged_symlink_hidden_by_regular_file(
    tmp_path: Path,
) -> None:
    subprocess.run(("git", "init", "--quiet"), cwd=tmp_path, check=True)
    candidate = tmp_path / "docs" / "link.md"
    candidate.parent.mkdir(parents=True)
    candidate.write_bytes(b"safe worktree bytes")
    object_id = (
        subprocess.run(
            ("git", "hash-object", "-w", "--stdin"),
            cwd=tmp_path,
            check=True,
            input=b"private-target",
            capture_output=True,
            text=False,
        )
        .stdout.decode("ascii")
        .strip()
    )
    subprocess.run(
        ("git", "update-index", "--add", "--cacheinfo", f"120000,{object_id},docs/link.md"),
        cwd=tmp_path,
        check=True,
    )

    with pytest.raises(PublicReadinessError, match="index and worktree differ"):
        candidate_files(tmp_path)


def test_candidate_policy_rejects_symlink_and_large_file() -> None:
    findings = audit_candidates(
        (
            CandidateFile(PurePosixPath("docs/link.md"), 10, is_symlink=True),
            CandidateFile(PurePosixPath("assets/blob.dat"), MAX_TRACKED_FILE_BYTES + 1),
        )
    )

    assert {finding.rule for finding in findings} == {
        "oversized_tracked_file",
        "symlink_not_public_release_input",
    }


def test_candidate_policy_rejects_private_source_excerpt_json(tmp_path: Path) -> None:
    private_artifact = tmp_path / "fidelity-artifact.json"
    private_artifact.write_text(
        '{"task":{"source_spans":[{"permitted_excerpt":"licensed source prose"}]}}',
        encoding="utf-8",
    )
    public_contract = tmp_path / "statement-contract.json"
    public_contract.write_text(
        '{"source":{"spans":[{"permitted_excerpt":null}]}}',
        encoding="utf-8",
    )

    assert _json_contains_private_source_excerpt(private_artifact) is True
    assert _json_contains_private_source_excerpt(public_contract) is False
    findings = audit_candidates(
        (
            CandidateFile(
                PurePosixPath("artifacts/fidelity-artifact.json"),
                private_artifact.stat().st_size,
                contains_private_source_excerpt=True,
            ),
        )
    )
    assert {finding.rule for finding in findings} == {"private_source_excerpt"}


def test_current_repository_has_consistent_license_metadata() -> None:
    assert audit_license_metadata(PROJECT_ROOT) == 8


def test_current_repository_is_public_release_candidate() -> None:
    result = check()

    assert result["status"] == "ok"
    assert result["license_manifests"] == 8


def test_missing_license_is_blocking(tmp_path: Path) -> None:
    with pytest.raises(PublicReadinessError, match="root LICENSE is missing"):
        audit_license_metadata(tmp_path)
