"""Preflight, run, and compare role benchmarks without implicit model access."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from contextlib import suppress
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

_COMPARE_SUITE_PRESETS: dict[str, tuple[tuple[str, str], ...]] = {
    "calibration-pairs-v3": (
        ("fake.oracle.prover", "fake.mutant.prover"),
        ("fake.oracle.statement-formalizer", "fake.mutant.statement-formalizer"),
        ("fake.oracle.fidelity-reviewer", "fake.mutant.fidelity-reviewer"),
        ("fake.oracle.cheating-supervisor", "fake.mutant.cheating-supervisor"),
        ("fake.oracle.task-allocator", "fake.mutant.task-allocator"),
    ),
}


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
    encoded = payload.replace("\r\n", "\n").encode("ascii")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=".benchmark-output-",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        with suppress(FileExistsError):
            os.link(temporary, path)
        if path.read_bytes() != encoded:
            raise ValueError(f"refusing to replace conflicting benchmark output: {path}") from None
    finally:
        if temporary is not None:
            with suppress(OSError):
                temporary.unlink()


def main() -> None:
    from benchmarks.provider_readiness import (
        build_scripted_fake_readiness,
        load_readiness_json,
        readiness_json,
    )
    from benchmarks.role_benchmark import (
        RoleBenchmarkHarness,
        RoleBenchmarkRawOutputStore,
        RoleBenchmarkStore,
        ScriptedFakeRoleExecutor,
        compare_report_suite,
        compare_reports,
        comparison_json,
        comparison_suite_json,
        load_fake_fixture,
        load_raw_artifact_manifest_json,
        operator_private_benchmark_paths,
        prepare_private_manifest_path,
        raw_artifact_manifest_json,
        report_json,
        validate_report_private_manifest,
    )

    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    readiness_parser = subparsers.add_parser(
        "readiness",
        help="probe the scripted provider separately from execution",
    )
    readiness_parser.add_argument("--fixture", required=True)
    readiness_parser.add_argument("--output")

    run_parser = subparsers.add_parser("run", help="run a strict fake-only fixture")
    run_parser.add_argument("--fixture", required=True)
    run_parser.add_argument("--readiness", required=True)
    run_parser.add_argument("--database", required=True)
    run_parser.add_argument("--run-id", required=True)
    run_parser.add_argument("--output")

    forward_parser = subparsers.add_parser(
        "forward-test",
        help="run the deterministic five-role fake workflow",
    )
    forward_parser.add_argument(
        "--fixture",
        default=str(PROJECT_ROOT / "benchmarks" / "roles" / "fake-smoke.v3.json"),
    )
    forward_parser.add_argument("--output-root", required=True)
    forward_parser.add_argument("--run-id", default="fake-forward-v3")

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

    compare_suite_parser = subparsers.add_parser(
        "compare-suite",
        help="compare multiple paired role cells from one database",
    )
    compare_suite_parser.add_argument("--database", required=True)
    compare_suite_parser.add_argument("--baseline-run", required=True)
    compare_suite_parser.add_argument("--candidate-run", required=True)
    compare_suite_parser.add_argument(
        "--preset",
        choices=tuple(_COMPARE_SUITE_PRESETS),
        help="named suite expanded before any explicit --cell-pair values",
    )
    compare_suite_parser.add_argument(
        "--cell-pair",
        action="append",
        metavar="BASELINE_CELL=CANDIDATE_CELL",
        help="repeatable paired cells appended after --preset; each pair must stay within one role",
    )
    compare_suite_parser.add_argument("--output")

    args = parser.parse_args()
    if args.command == "readiness":
        fixture = load_fake_fixture(_absolute(args.fixture, label="fixture"))
        readiness = build_scripted_fake_readiness(fixture.matrix)
        _write_or_print(readiness_json(readiness), args.output)
        return

    if args.command == "forward-test":
        output_root = _absolute(args.output_root, label="output root")
        output_root.mkdir(parents=True, exist_ok=True)
        fixture = load_fake_fixture(_absolute(args.fixture, label="fixture"))
        readiness = build_scripted_fake_readiness(fixture.matrix)
        executor = ScriptedFakeRoleExecutor(fixture)
        _write_or_print(
            readiness_json(readiness),
            str(output_root / "readiness.json"),
        )
        database = output_root / "roles.sqlite3"
        private_paths = operator_private_benchmark_paths(str(args.run_id))
        private_manifest_path = prepare_private_manifest_path(private_paths)
        raw_store = RoleBenchmarkRawOutputStore(private_paths.raw_output_root)
        with RoleBenchmarkStore(database) as store:
            report = RoleBenchmarkHarness().run(
                fixture.matrix,
                executor=executor,
                store=store,
                raw_output_store=raw_store,
                readiness=readiness,
                run_id=str(args.run_id),
            )
        manifest = raw_store.build_manifest(report.run, report.results)
        validate_report_private_manifest(report, manifest)
        _write_or_print(
            raw_artifact_manifest_json(manifest),
            str(private_manifest_path),
        )
        _write_or_print(report_json(report), str(output_root / "report.json"))
        sys.stdout.write(report_json(report))
        return

    database = _absolute(args.database, label="database")
    with RoleBenchmarkStore(database) as store:
        if args.command == "run":
            fixture = load_fake_fixture(_absolute(args.fixture, label="fixture"))
            readiness = load_readiness_json(
                _absolute(args.readiness, label="readiness").read_text(encoding="ascii")
            )
            executor = ScriptedFakeRoleExecutor(fixture)
            private_paths = operator_private_benchmark_paths(str(args.run_id))
            private_manifest_path = prepare_private_manifest_path(private_paths)
            raw_store = RoleBenchmarkRawOutputStore(private_paths.raw_output_root)
            report = RoleBenchmarkHarness().run(
                fixture.matrix,
                executor=executor,
                store=store,
                raw_output_store=raw_store,
                readiness=readiness,
                run_id=str(args.run_id),
            )
            manifest = raw_store.build_manifest(report.run, report.results)
            validate_report_private_manifest(report, manifest)
            _write_or_print(
                raw_artifact_manifest_json(manifest),
                str(private_manifest_path),
            )
            _write_or_print(report_json(report), args.output)
        elif args.command == "report":
            report = store.report(str(args.run_id))
            private_paths = operator_private_benchmark_paths(str(args.run_id))
            raw_store = RoleBenchmarkRawOutputStore(private_paths.raw_output_root)
            observed = raw_store.build_manifest(report.run, report.results)
            expected = load_raw_artifact_manifest_json(
                private_paths.manifest_path.read_text(encoding="ascii")
            )
            if observed != expected or expected.content_hash() != report.raw_artifact_manifest_hash:
                raise ValueError("raw artifact manifest does not match the stored run")
            validate_report_private_manifest(report, expected)
            _write_or_print(report_json(report), args.output)
        elif args.command == "compare":
            baseline = store.report(str(args.baseline_run))
            candidate = store.report(str(args.candidate_run))
            comparison = compare_reports(
                baseline,
                baseline_cell_id=str(args.baseline_cell),
                candidate=candidate,
                candidate_cell_id=str(args.candidate_cell),
            )
            _write_or_print(comparison_json(comparison), args.output)
        else:
            pairs = list(_COMPARE_SUITE_PRESETS.get(args.preset, ()))
            for raw_pair in args.cell_pair or ():
                left, separator, right = str(raw_pair).partition("=")
                if not separator or not left or not right:
                    raise ValueError("--cell-pair must be BASELINE_CELL=CANDIDATE_CELL")
                pairs.append((left, right))
            if not pairs:
                raise ValueError("compare-suite requires --preset or at least one --cell-pair")
            baseline = store.report(str(args.baseline_run))
            candidate = store.report(str(args.candidate_run))
            suite = compare_report_suite(
                baseline,
                candidate=candidate,
                cell_pairs=pairs,
            )
            _write_or_print(comparison_suite_json(suite), args.output)


if __name__ == "__main__":
    main()
