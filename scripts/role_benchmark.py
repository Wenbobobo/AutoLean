"""Run and compare offline role benchmarks without network or external model access."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _absolute(path: str, *, label: str) -> Path:
    resolved = Path(path).resolve()
    if not resolved.is_absolute():
        raise ValueError(f"{label} must resolve to an absolute path")
    return resolved


def _write_or_print(payload: str, output: str | None) -> None:
    if output is None:
        sys.stdout.write(payload)
        return
    path = _absolute(output, label="output")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="ascii", newline="\n")


def main() -> None:
    from benchmarks.role_benchmark import (
        RoleBenchmarkHarness,
        RoleBenchmarkStore,
        ScriptedFakeRoleExecutor,
        compare_reports,
        comparison_json,
        load_fake_fixture,
        report_json,
    )

    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="run a strict fake-only fixture")
    run_parser.add_argument("--fixture", required=True)
    run_parser.add_argument("--database", required=True)
    run_parser.add_argument("--run-id", required=True)
    run_parser.add_argument("--output")

    report_parser = subparsers.add_parser("report", help="replay one stored report")
    report_parser.add_argument("--database", required=True)
    report_parser.add_argument("--run-id", required=True)
    report_parser.add_argument("--output")

    compare_parser = subparsers.add_parser("compare", help="paired cell/run comparison")
    compare_parser.add_argument("--database", required=True)
    compare_parser.add_argument("--baseline-run", required=True)
    compare_parser.add_argument("--baseline-cell", required=True)
    compare_parser.add_argument("--candidate-run", required=True)
    compare_parser.add_argument("--candidate-cell", required=True)
    compare_parser.add_argument("--output")

    args = parser.parse_args()
    database = _absolute(args.database, label="database")
    with RoleBenchmarkStore(database) as store:
        if args.command == "run":
            fixture = load_fake_fixture(_absolute(args.fixture, label="fixture"))
            report = RoleBenchmarkHarness().run(
                fixture.matrix,
                executor=ScriptedFakeRoleExecutor(fixture),
                store=store,
                run_id=str(args.run_id),
            )
            _write_or_print(report_json(report), args.output)
        elif args.command == "report":
            _write_or_print(report_json(store.report(str(args.run_id))), args.output)
        else:
            baseline = store.report(str(args.baseline_run))
            candidate = store.report(str(args.candidate_run))
            comparison = compare_reports(
                baseline,
                baseline_cell_id=str(args.baseline_cell),
                candidate=candidate,
                candidate_cell_id=str(args.candidate_cell),
            )
            _write_or_print(comparison_json(comparison), args.output)


if __name__ == "__main__":
    main()
