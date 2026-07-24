from __future__ import annotations

import subprocess
from pathlib import Path, PurePosixPath

import pytest

from scripts.secret_scan import (
    MAX_HISTORY_BLOB_BYTES,
    SecretScanError,
    report,
    scan_paths,
    scan_repository,
    scan_repository_history,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _initialize_repository(path: Path) -> None:
    subprocess.run(("git", "init", "--quiet"), cwd=path, check=True)
    subprocess.run(("git", "config", "user.name", "Test User"), cwd=path, check=True)
    subprocess.run(
        ("git", "config", "user.email", "test@example.invalid"),
        cwd=path,
        check=True,
    )


def _commit_all(path: Path, message: str) -> None:
    subprocess.run(("git", "add", "-A"), cwd=path, check=True)
    subprocess.run(("git", "commit", "--quiet", "-m", message), cwd=path, check=True)


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
    _initialize_repository(tmp_path)
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


def test_history_scan_finds_secret_deleted_from_current_tree(tmp_path: Path) -> None:
    _initialize_repository(tmp_path)
    token = "github_" + "pat_" + "DeletedCredentialInHistory123456789"
    candidate = tmp_path / "old-config.txt"
    candidate.write_text(f"token = {token}\n", encoding="utf-8")
    _commit_all(tmp_path, "add old config")
    candidate.unlink()
    _commit_all(tmp_path, "remove old config")

    history_result = scan_repository_history(tmp_path)
    current_result = scan_repository(tmp_path)

    assert ("old-config.txt", "github-token") in {
        (finding.path, finding.rule) for finding in history_result.findings
    }
    assert token not in report(history_result)
    assert current_result.findings == ()


def test_history_scan_traverses_commit_reachable_only_from_custom_ref(
    tmp_path: Path,
) -> None:
    _initialize_repository(tmp_path)
    (tmp_path / "README.md").write_text("main history\n", encoding="utf-8")
    _commit_all(tmp_path, "main")
    main_branch = subprocess.run(
        ("git", "branch", "--show-current"),
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(("git", "checkout", "--quiet", "-b", "hidden"), cwd=tmp_path, check=True)
    token = "hf_" + "CustomRefOnlyCredential123456789"
    secret = tmp_path / "custom-ref-secret.txt"
    secret.write_text(token, encoding="utf-8")
    _commit_all(tmp_path, "custom ref secret")
    hidden_commit = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(("git", "checkout", "--quiet", main_branch), cwd=tmp_path, check=True)
    subprocess.run(
        ("git", "update-ref", "refs/archive/secret", hidden_commit),
        cwd=tmp_path,
        check=True,
    )
    subprocess.run(("git", "branch", "-D", "hidden"), cwd=tmp_path, check=True, capture_output=True)
    tree_only_token = "sk-" + "proj-" + "TreeRefOnlyCredential123456789"
    tree_only_blob = (
        subprocess.run(
            ("git", "hash-object", "-w", "--stdin"),
            cwd=tmp_path,
            check=True,
            input=tree_only_token.encode("ascii"),
            capture_output=True,
        )
        .stdout.decode("ascii")
        .strip()
    )
    tree_only_tree = subprocess.run(
        ("git", "mktree"),
        cwd=tmp_path,
        check=True,
        input=f"100644 blob {tree_only_blob}\ttree-only-secret.txt\n",
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(
        ("git", "update-ref", "refs/archive/tree-only", tree_only_tree),
        cwd=tmp_path,
        check=True,
    )

    result = scan_repository_history(tmp_path)

    findings = {(finding.path, finding.rule) for finding in result.findings}
    assert ("custom-ref-secret.txt", "huggingface-token") in findings
    assert not any(path == "tree-only-secret.txt" for path, _ in findings)
    assert tree_only_token not in report(result)
    assert token not in report(result)


def test_history_scan_blocks_deleted_restricted_payload_and_environment(
    tmp_path: Path,
) -> None:
    _initialize_repository(tmp_path)
    environment = tmp_path / "operator.env"
    payload = tmp_path / "reference.pdf"
    environment.write_text("placeholder\n", encoding="utf-8")
    payload.write_bytes(b"%PDF-clean-test-payload\n")
    _commit_all(tmp_path, "add restricted files")
    environment.unlink()
    payload.unlink()
    _commit_all(tmp_path, "remove restricted files")

    result = scan_repository_history(tmp_path)
    findings = {(finding.path, finding.rule) for finding in result.findings}

    assert ("operator.env", "history-environment-file") in findings
    assert ("reference.pdf", "history-restricted-payload") in findings


def test_history_scan_blocks_force_added_protected_path(tmp_path: Path) -> None:
    _initialize_repository(tmp_path)
    (tmp_path / ".gitignore").write_text("docs/meeting/\n", encoding="utf-8")
    protected = tmp_path / "docs" / "meeting" / "notes.txt"
    protected.parent.mkdir(parents=True)
    protected.write_text("meeting evidence\n", encoding="utf-8")
    subprocess.run(("git", "add", ".gitignore"), cwd=tmp_path, check=True)
    subprocess.run(
        ("git", "add", "-f", "docs/meeting/notes.txt"),
        cwd=tmp_path,
        check=True,
    )
    subprocess.run(
        ("git", "commit", "--quiet", "-m", "force protected path"),
        cwd=tmp_path,
        check=True,
    )

    result = scan_repository_history(tmp_path)

    assert ("docs/meeting/notes.txt", "history-protected-path") in {
        (finding.path, finding.rule) for finding in result.findings
    }


def test_history_scan_blocks_symlink_submodule_and_large_blob(tmp_path: Path) -> None:
    _initialize_repository(tmp_path)
    (tmp_path / "base.txt").write_text("base\n", encoding="utf-8")
    _commit_all(tmp_path, "base")
    head = (
        subprocess.run(
            ("git", "rev-parse", "HEAD"),
            cwd=tmp_path,
            check=True,
            capture_output=True,
        )
        .stdout.decode("ascii")
        .strip()
    )
    subprocess.run(
        (
            "git",
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{head},vendor/subrepo",
        ),
        cwd=tmp_path,
        check=True,
    )
    target = (
        subprocess.run(
            ("git", "hash-object", "-w", "--stdin"),
            cwd=tmp_path,
            check=True,
            input=b"target.txt",
            capture_output=True,
        )
        .stdout.decode("ascii")
        .strip()
    )
    subprocess.run(
        ("git", "update-index", "--add", "--cacheinfo", f"120000,{target},link"),
        cwd=tmp_path,
        check=True,
    )
    large = tmp_path / "large.txt"
    large.write_bytes(b"x" * (MAX_HISTORY_BLOB_BYTES + 1))
    subprocess.run(("git", "add", "large.txt"), cwd=tmp_path, check=True)
    subprocess.run(
        ("git", "commit", "--quiet", "-m", "unsafe entries"),
        cwd=tmp_path,
        check=True,
    )

    result = scan_repository_history(tmp_path)
    findings = {(finding.path, finding.rule) for finding in result.findings}

    assert ("link", "history-symlink") in findings
    assert ("vendor/subrepo", "history-submodule") in findings
    assert ("large.txt", "history-oversized-blob") in findings


def test_history_scan_accepts_clean_history(tmp_path: Path) -> None:
    _initialize_repository(tmp_path)
    (tmp_path / "README.md").write_text("clean history\n", encoding="utf-8")
    _commit_all(tmp_path, "clean")

    result = scan_repository_history(tmp_path)

    assert result.files_scanned == 1
    assert result.findings == ()


def test_current_repository_has_no_candidate_secrets() -> None:
    result = scan_repository(PROJECT_ROOT)

    assert result.findings == ()
