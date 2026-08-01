from __future__ import annotations

from pathlib import Path

from scripts.provider_policy_guard import check_provider_policy

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _write_required_denylists(root: Path) -> None:
    files = {
        "Prover/src/autolean_prover/providers/policy.py": (
            '_FORBIDDEN_TERMS = ("anthropic", "claude")\n'
        ),
        "packages/contracts/src/autolean_contracts/authorization.py": (
            '_FORBIDDEN_IDENTIFIERS = ("anthropic", "claude")\n'
        ),
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def test_current_repository_keeps_prohibited_provider_policy() -> None:
    assert check_provider_policy(PROJECT_ROOT) == ()


def test_prohibited_provider_reference_is_rejected_from_production_source(
    tmp_path: Path,
) -> None:
    _write_required_denylists(tmp_path)
    path = tmp_path / "Prover/src/autolean_prover/providers/new_provider.py"
    path.write_text('PROVIDER = "claude-compatible"\n', encoding="utf-8")

    findings = check_provider_policy(tmp_path)

    assert any(
        finding.path.endswith("new_provider.py")
        and finding.rule == "prohibited-provider-production-reference"
        for finding in findings
    )


def test_prohibited_provider_dependency_is_rejected(tmp_path: Path) -> None:
    _write_required_denylists(tmp_path)
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["anthropic>=1"]\n',
        encoding="utf-8",
    )

    findings = check_provider_policy(tmp_path)

    assert any(finding.rule == "prohibited-provider-dependency" for finding in findings)


def test_generated_cache_manifests_are_outside_the_provider_policy_surface(
    tmp_path: Path,
) -> None:
    _write_required_denylists(tmp_path)
    cached_manifest = tmp_path / ".cache" / "foreign-environment" / "pyproject.toml"
    cached_manifest.parent.mkdir(parents=True)
    cached_manifest.write_text(
        '[project]\ndependencies = ["anthropic>=1"]\n',
        encoding="utf-8",
    )

    assert check_provider_policy(tmp_path) == ()


def test_required_denylist_cannot_be_removed(tmp_path: Path) -> None:
    _write_required_denylists(tmp_path)
    policy = tmp_path / "Prover/src/autolean_prover/providers/policy.py"
    policy.write_text("_FORBIDDEN_TERMS = ()\n", encoding="utf-8")

    findings = check_provider_policy(tmp_path)

    assert any(
        finding.path.endswith("providers/policy.py")
        and finding.rule == "provider-denylist-missing-or-changed"
        for finding in findings
    )
