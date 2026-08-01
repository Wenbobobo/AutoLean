"""Fail closed when prohibited model-provider support enters production surfaces."""

from __future__ import annotations

import argparse
import ast
import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

FORBIDDEN_IDENTIFIERS = frozenset({"anthropic", "claude"})
REQUIRED_DENYLISTS = {
    PurePosixPath("Prover/src/autolean_prover/providers/policy.py"): "_FORBIDDEN_TERMS",
    PurePosixPath("packages/contracts/src/autolean_contracts/authorization.py"): (
        "_FORBIDDEN_IDENTIFIERS"
    ),
}
PRODUCTION_ROOTS = (
    PurePosixPath("Builder/src"),
    PurePosixPath("Dashboard/api/src"),
    PurePosixPath("Dashboard/ui/src"),
    PurePosixPath("Prover/src"),
    PurePosixPath("benchmarks"),
    PurePosixPath("packages"),
)
SOURCE_SUFFIXES = frozenset({".json", ".py", ".toml", ".ts", ".tsx", ".yaml", ".yml"})
MANIFEST_NAMES = frozenset({"package.json", "pnpm-lock.yaml", "pyproject.toml", "uv.lock"})
SKIPPED_COMPONENTS = frozenset(
    {
        ".agents",
        ".cache",
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".quarantine",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "node_modules",
        "results",
        "tests",
        "vendor",
    }
)


@dataclass(frozen=True, order=True, slots=True)
class PolicyFinding:
    path: str
    rule: str


def _relative(root: Path, path: Path) -> PurePosixPath:
    return PurePosixPath(path.relative_to(root).as_posix())


def _contains_forbidden_identifier(content: str) -> bool:
    folded = content.casefold()
    return any(identifier in folded for identifier in FORBIDDEN_IDENTIFIERS)


def _manifest_paths(root: Path) -> tuple[Path, ...]:
    return tuple(
        sorted(
            path
            for path in root.rglob("*")
            if not any(part.casefold() in SKIPPED_COMPONENTS for part in path.parts)
            and path.is_file()
            and path.name in MANIFEST_NAMES
        )
    )


def _production_paths(root: Path) -> tuple[Path, ...]:
    paths: set[Path] = set()
    for relative_root in PRODUCTION_ROOTS:
        source_root = root.joinpath(*relative_root.parts)
        if not source_root.is_dir():
            continue
        for path in source_root.rglob("*"):
            if (
                path.is_file()
                and path.suffix.casefold() in SOURCE_SUFFIXES
                and not any(part.casefold() in SKIPPED_COMPONENTS for part in path.parts)
            ):
                paths.add(path)
    return tuple(sorted(paths))


def _literal_assignment(path: Path, name: str) -> frozenset[str] | None:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
    except (OSError, UnicodeDecodeError, SyntaxError):
        return None
    for statement in tree.body:
        if not isinstance(statement, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == name for target in statement.targets
        ):
            continue
        try:
            value = ast.literal_eval(statement.value)
        except (ValueError, TypeError):
            return None
        if not isinstance(value, tuple | list | set | frozenset):
            return None
        if not all(isinstance(item, str) for item in value):
            return None
        return frozenset(item.casefold() for item in value)
    return None


def check_provider_policy(root: Path) -> tuple[PolicyFinding, ...]:
    root = root.resolve()
    findings: set[PolicyFinding] = set()

    for path in _manifest_paths(root):
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            findings.add(PolicyFinding(_relative(root, path).as_posix(), "unreadable-manifest"))
            continue
        if _contains_forbidden_identifier(content):
            findings.add(
                PolicyFinding(_relative(root, path).as_posix(), "prohibited-provider-dependency")
            )

    allowed_policy_paths = set(REQUIRED_DENYLISTS)
    for path in _production_paths(root):
        relative = _relative(root, path)
        if relative in allowed_policy_paths:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            findings.add(PolicyFinding(relative.as_posix(), "unreadable-production-source"))
            continue
        if _contains_forbidden_identifier(content):
            findings.add(
                PolicyFinding(relative.as_posix(), "prohibited-provider-production-reference")
            )

    for relative, assignment_name in REQUIRED_DENYLISTS.items():
        path = root.joinpath(*relative.parts)
        if _literal_assignment(path, assignment_name) != FORBIDDEN_IDENTIFIERS:
            findings.add(PolicyFinding(relative.as_posix(), "provider-denylist-missing-or-changed"))

    return tuple(sorted(findings))


def report(findings: tuple[PolicyFinding, ...]) -> str:
    payload: dict[str, object] = {"status": "blocked" if findings else "ok"}
    if findings:
        payload["findings"] = [{"path": finding.path, "rule": finding.rule} for finding in findings]
    return json.dumps(payload, ensure_ascii=True, sort_keys=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    findings = check_provider_policy(args.root)
    print(report(findings))
    if findings:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
