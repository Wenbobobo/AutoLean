from __future__ import annotations

import subprocess
from pathlib import Path, PurePosixPath

import pytest

from scripts.secret_scan import SecretScanError, report, scan_paths, scan_repository

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_report_never_contains_the_matched_secret(tmp_path: Path) -> None:
    value = "sk-" + "proj-" + "ThisCredentialMustNeverAppearInOutput123456"
    candidate = tmp_path / "config.txt"
    candidate.write_text(f'api_key = "{value}"\n', encoding="utf-8")

    result = scan_paths(tmp_path, (PurePosixPath("config.txt"),))
    rendered = report(result)

    assert {(finding.path, finding.rule) for finding in result.findings} >= {
        ("config.txt", "openai-api-key"),
        ("config.txt", "literal-credential-assignment"),
    }
    assert value not in rendered


def test_protected_and_generated_trees_are_not_read(tmp_path: Path) -> None:
    paths = (
        PurePosixPath(".quarantine/archive.txt"),
        PurePosixPath(".git/config"),
        PurePosixPath(".venv/token.txt"),
        PurePosixPath("node_modules/package/token.txt"),
        PurePosixPath("benchmarks/vendor/FATE/token.txt"),
        PurePosixPath("benchmarks/results/report.txt"),
    )
    for relative in paths:
        path = tmp_path.joinpath(*relative.parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        value = "hf_" + "ThisCredentialMustNotBeRead123456789"
        path.write_text(f"{value}\n", encoding="utf-8")

    result = scan_paths(tmp_path, paths)

    assert result.files_scanned == 0
    assert result.findings == ()


def test_repository_scan_rejects_staged_secret_hidden_by_worktree(tmp_path: Path) -> None:
    subprocess.run(("git", "init", "--quiet"), cwd=tmp_path, check=True)
    candidate = tmp_path / "config.txt"
    staged_token = "github_" + "pat_" + "ThisCredentialMustRemainStaged123456"
    candidate.write_text(
        f"token = {staged_token}\n",
        encoding="utf-8",
    )
    subprocess.run(("git", "add", "config.txt"), cwd=tmp_path, check=True)
    candidate.write_text("safe worktree bytes\n", encoding="utf-8")

    with pytest.raises(SecretScanError, match="index and worktree differ"):
        scan_repository(tmp_path)


def test_current_repository_has_no_candidate_secrets() -> None:
    result = scan_repository(PROJECT_ROOT)

    assert result.findings == ()
