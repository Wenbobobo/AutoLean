from pathlib import Path, PurePosixPath

import pytest

from scripts.public_readiness import (
    MAX_TRACKED_FILE_BYTES,
    PROJECT_ROOT,
    CandidateFile,
    PublicReadinessError,
    audit_candidates,
    audit_license_metadata,
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
        (".quarantine/archive.gpg", "local_or_restricted_directory"),
        ("benchmarks/results/raw.jsonl", "local_or_restricted_directory"),
        ("operator.env", "environment_file"),
        ("keys/verifier.pem", "restricted_or_binary_payload"),
    ],
)
def test_candidate_policy_rejects_restricted_payloads(path: str, rule: str) -> None:
    findings = audit_candidates((CandidateFile(PurePosixPath(path), 100),))

    assert rule in {finding.rule for finding in findings}


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


def test_current_repository_has_consistent_license_metadata() -> None:
    assert audit_license_metadata(PROJECT_ROOT) == 8


def test_current_repository_is_public_release_candidate() -> None:
    result = check()

    assert result["status"] == "ok"
    assert result["license_manifests"] == 8


def test_missing_license_is_blocking(tmp_path: Path) -> None:
    with pytest.raises(PublicReadinessError, match="root LICENSE is missing"):
        audit_license_metadata(tmp_path)
