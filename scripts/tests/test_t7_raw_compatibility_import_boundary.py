from __future__ import annotations

import ast
from pathlib import Path, PurePosixPath

_RAW_SYMBOLS = {
    "benchmarks.real_lean_project_dag_rebuild": frozenset({"plan_real_lean_rebuild"}),
    "benchmarks.real_lean_project_dag_execution": frozenset({"RealLeanRebuildExecutionStore"}),
}
_ALLOWED_NON_TEST_IMPORTERS = frozenset(
    {
        PurePosixPath("benchmarks/real_lean_project_dag_execution.py"),
        PurePosixPath("benchmarks/real_lean_project_dag_worker_contract.py"),
        PurePosixPath("scripts/real_lean_changed_source_preflight.py"),
    }
)
_IGNORED_PARTS = frozenset(
    {
        ".agents",
        ".git",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "node_modules",
        "vendor",
    }
)


def _raw_imports(path: Path) -> tuple[str, ...]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _RAW_SYMBOLS:
                    imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module in _RAW_SYMBOLS:
            imported_names = {alias.name for alias in node.names}
            raw_names = _RAW_SYMBOLS[node.module]
            if "*" in imported_names or imported_names & raw_names:
                imports.extend(
                    f"{node.module}.{name}" for name in sorted(imported_names & raw_names)
                )
                if "*" in imported_names:
                    imports.append(f"{node.module}.*")
    return tuple(imports)


def test_raw_t7_compatibility_apis_stay_inside_the_allowlisted_boundary() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    violations: list[str] = []
    for path in repository_root.rglob("*.py"):
        relative = PurePosixPath(path.relative_to(repository_root).as_posix())
        if (
            any(part in _IGNORED_PARTS or part.startswith(".tmp") for part in relative.parts)
            or "tests" in relative.parts
            or relative in _ALLOWED_NON_TEST_IMPORTERS
        ):
            continue
        imports = _raw_imports(path)
        if imports:
            violations.append(f"{relative.as_posix()}: {', '.join(imports)}")

    assert violations == [], (
        "raw T7 planner/store imports must stay in tests, the typed adapter, "
        "or the locked changed-source preflight:\n" + "\n".join(violations)
    )
