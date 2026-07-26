"""Run the fixed T7 changed-source propagation case in the pinned source-v2 image.

This operator-local preflight proves a narrow causal loop: the committed baseline
builds, a manifest-bound public API/type change breaks an unchanged downstream
module, and the manifest-bound successor edits rebuild the affected modules while
reusing the unaffected compiled module.  It is not a general dependency analyzer or
an AutoLean acceptance result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.real_lean_project_dag import RealLeanProjectDagV1
from benchmarks.real_lean_project_dag_change import (
    RealLeanChangeCaseError,
    RealLeanChangeCaseV1,
    load_default_real_lean_change_case,
)
from benchmarks.real_lean_project_dag_rebuild import (
    RealLeanRebuildBundleV1,
    plan_real_lean_rebuild,
)
from scripts.real_lean_project_dag_preflight import (
    DEFAULT_WSL_DISTRIBUTION,
    SOURCE_V2_IMAGE,
    RealLeanProjectDagPreflightError,
    _container_path,
    _docker_prefix,
    _module_output_relative,
    _run,
    _sha256,
    _snapshot_fixture,
    docker_clean_build_command,
)

RESULT_SCHEMA: Final[str] = "autolean.real-lean-changed-source-preflight.v1"
TYPE_QUERY_SCHEMA: Final[str] = "autolean.real-lean-score-type-query.v1"
CHANGED_DECLARATION: Final[str] = "AutoLean.ProjectDagPreflight.Arithmetic.score"
_TYPE_QUERY_SOURCE: Final[str] = """\
import AutoLean.ProjectDagPreflight.Arithmetic
import Lean.PrettyPrinter

open Lean

private def canonicalOptions : Options :=
  ((((({} : Options).setBool `pp.all true).setBool `pp.explicit true).setBool
        `pp.universes true).setBool `pp.notation false).set `pp.width (1000000 : Nat)

private def canonicalType (env : Environment) (declaration : Name) : IO String := do
  let some info := env.checked.get.find? declaration
    | throw <| IO.userError s!"declaration not found: {declaration}"
  if info.type.hasMVar then
    throw <| IO.userError "canonical declaration type contains a metavariable"
  let rendered :=
    (← PrettyPrinter.ppExprLegacy env {} {} canonicalOptions info.type).pretty 1000000
  if rendered.isEmpty || rendered.length > 1000000 then
    throw <| IO.userError "canonical declaration type has an invalid size"
  if rendered.any fun char => char == '\\x00' || char == '\\n' || char == '\\r' then
    throw <| IO.userError "canonical declaration type is not one line"
  return rendered

def main : IO Unit := do
  let environment ←
    importModules #[{ module := `AutoLean.ProjectDagPreflight.Arithmetic }] canonicalOptions
  let declaration := `AutoLean.ProjectDagPreflight.Arithmetic.score
  let rendered ← canonicalType environment declaration
  IO.println <| (Json.mkObj [
    ("schema_version", Json.str "autolean.real-lean-score-type-query.v1"),
    ("declaration", Json.str declaration.toString),
    ("canonical_type", Json.str rendered)
  ]).compress
"""
_TYPE_QUERY_SHA256: Final[str] = hashlib.sha256(_TYPE_QUERY_SOURCE.encode("utf-8")).hexdigest()


class RealLeanChangedSourcePreflightError(RuntimeError):
    """The local changed-source preflight did not establish its narrow result."""


@dataclass(frozen=True, slots=True)
class ChangedSourceSnapshot:
    """A temporary source snapshot derived only from the committed baseline and case."""

    root: Path
    source_root: Path
    source_hashes: dict[str, str]


def changed_source_rebuild_bundle(case: RealLeanChangeCaseV1) -> RealLeanRebuildBundleV1:
    """Plan the upstream source change before successor compatibility edits are applied.

    The preflight's fixed case later materializes downstream successor edits.  This
    bundle instead preserves the causal planning boundary: it contains only the
    observed upstream source change and derives every downstream module that must be
    rebuilt.  It remains refused until the real control plane binds a lease and
    fencing token.
    """

    snapshot_hashes = {
        module.module: (
            case.edits_by_module[module.module].successor_source_sha256
            if module.module == case.changed_module
            else module.source_sha256
        )
        for module in case.baseline.module_topological_order()
    }
    bundle = plan_real_lean_rebuild(
        case.baseline,
        snapshot_hashes,
        changed_declaration_ids=case.changed_declaration_ids,
    )
    if bundle.changed_modules != (case.changed_module,):
        raise RealLeanChangedSourcePreflightError("changed-source rebuild bundle is inconsistent")
    if bundle.module_rebuild_plan != case.expected_module_reverse_import_closure:
        raise RealLeanChangedSourcePreflightError(
            "changed-source rebuild bundle closure is inconsistent"
        )
    if bundle.declaration_invalidation_plan != case.expected_declaration_reverse_closure:
        raise RealLeanChangedSourcePreflightError(
            "changed-source rebuild bundle declaration closure is inconsistent"
        )
    return bundle


def _write_regular_file(path: Path, content: bytes, *, read_only: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise RealLeanChangedSourcePreflightError(
            "temporary preflight file could not be written"
        ) from error
    path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH if read_only else stat.S_IRWXU)


def _replace_snapshot_file(path: Path, content: bytes) -> None:
    temporary = path.with_name(f".{path.name}.replacement")
    _write_regular_file(temporary, content, read_only=True)
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        os.replace(temporary, path)
    except OSError as error:
        raise RealLeanChangedSourcePreflightError(
            "changed source snapshot could not be sealed"
        ) from error
    path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)


def _materialize_changed_snapshot(
    case: RealLeanChangeCaseV1,
    destination: Path,
    *,
    successor: bool,
) -> ChangedSourceSnapshot:
    """Create an upstream-only or full-successor source snapshot from baseline bytes."""

    snapshot = _snapshot_fixture(case.baseline, destination)
    hashes: dict[str, str] = {}
    for module in snapshot.module_topological_order():
        source = snapshot.source_path(module)
        rendered = case.apply_to_module(module.module, successor=successor)
        if rendered != source.read_bytes():
            _replace_snapshot_file(source, rendered)
        observed = hashlib.sha256(source.read_bytes()).hexdigest()
        expected = (
            case.edits_by_module[module.module].successor_source_sha256
            if module.module in case.edits_by_module
            and (successor or module.module == case.changed_module)
            else module.source_sha256
        )
        if observed != expected:
            raise RealLeanChangedSourcePreflightError("changed source snapshot hash is unexpected")
        hashes[module.module] = observed
    return ChangedSourceSnapshot(
        root=snapshot.root,
        source_root=snapshot.root / snapshot.source_root,
        source_hashes=hashes,
    )


def _fresh_output_root(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
    return path


def _docker_base(
    *,
    distribution: str,
    mounts: Sequence[str],
    script: str,
) -> tuple[str, ...]:
    command: list[str] = [
        *_docker_prefix(distribution),
        "run",
        "--pull=never",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=64m",
    ]
    for mount in mounts:
        command.extend(("--mount", mount))
    command.extend((SOURCE_V2_IMAGE, "/bin/sh", "-ceu", script))
    return tuple(command)


def _module_source_relative(fixture: RealLeanProjectDagV1, module_name: str) -> PurePosixPath:
    module = fixture.modules_by_name[module_name]
    return PurePosixPath(module.file).relative_to(fixture.source_root)


def docker_compile_modules_command(
    case: RealLeanChangeCaseV1,
    snapshot: ChangedSourceSnapshot,
    reused_output_root: Path,
    output_root: Path,
    modules: Sequence[str],
    *,
    distribution: str = DEFAULT_WSL_DISTRIBUTION,
) -> tuple[str, ...]:
    """Compile only the named module-granularity rebuild plan into a fresh output."""

    known_modules = case.baseline.modules_by_name
    if (
        not modules
        or len(set(modules)) != len(modules)
        or any(module not in known_modules for module in modules)
    ):
        raise RealLeanChangedSourcePreflightError("module rebuild plan is invalid")
    commands = [
        "set -eu",
        "cp -R /reuse/. /output/",
        'lean_path="$(cat /opt/autolean/environment/lean-path)"',
        'export LEAN_PATH="${lean_path}:/output"',
    ]
    for module_name in modules:
        source = PurePosixPath("/input") / _module_source_relative(case.baseline, module_name)
        output = PurePosixPath("/output") / _module_output_relative(module_name)
        commands.extend(
            (
                f"mkdir -p {output.parent.as_posix()}",
                f"lean -R /input -o {output.as_posix()} {source.as_posix()}",
                f"test -s {output.as_posix()}",
            )
        )
    return _docker_base(
        distribution=distribution,
        mounts=(
            f"type=bind,src={_container_path(snapshot.source_root, distribution)},"
            "dst=/input,readonly",
            f"type=bind,src={_container_path(reused_output_root, distribution)},"
            "dst=/reuse,readonly",
            f"type=bind,src={_container_path(output_root, distribution)},dst=/output",
        ),
        script="\n".join(commands),
    )


def docker_type_query_command(
    query_source: Path,
    module_output_root: Path,
    *,
    distribution: str = DEFAULT_WSL_DISTRIBUTION,
) -> tuple[str, ...]:
    """Query the changed declaration type from a compiled OLean environment."""

    script = "\n".join(
        (
            "set -eu",
            'lean_path="$(cat /opt/autolean/environment/lean-path)"',
            'export LEAN_PATH="${lean_path}:/modules"',
            "lean --run /query/ScoreTypeQuery.lean",
        )
    )
    return _docker_base(
        distribution=distribution,
        mounts=(
            f"type=bind,src={_container_path(query_source.parent, distribution)},"
            "dst=/query,readonly",
            f"type=bind,src={_container_path(module_output_root, distribution)},"
            "dst=/modules,readonly",
        ),
        script=script,
    )


def docker_expected_failure_command(
    case: RealLeanChangeCaseV1,
    snapshot: ChangedSourceSnapshot,
    changed_output_root: Path,
    diagnostic_root: Path,
    *,
    distribution: str = DEFAULT_WSL_DISTRIBUTION,
) -> tuple[str, ...]:
    """Compile the unchanged downstream probe against the new upstream OLean."""

    probe = case.failure_probe_module
    source = PurePosixPath("/input") / _module_source_relative(case.baseline, probe)
    output = PurePosixPath("/diagnostic") / _module_output_relative(probe)
    script = "\n".join(
        (
            "set -eu",
            'lean_path="$(cat /opt/autolean/environment/lean-path)"',
            'export LEAN_PATH="${lean_path}:/changed"',
            f"mkdir -p {output.parent.as_posix()}",
            "set +e",
            f"lean -R /input -o {output.as_posix()} {source.as_posix()} "
            ">/diagnostic/probe.stdout 2>/diagnostic/probe.stderr",
            "status=$?",
            "set -e",
            'printf "%s\\n" "$status" > /diagnostic/probe.status',
            'test "$status" -ne 0',
            f"test ! -e {output.as_posix()}",
        )
    )
    return _docker_base(
        distribution=distribution,
        mounts=(
            f"type=bind,src={_container_path(snapshot.source_root, distribution)},"
            "dst=/input,readonly",
            f"type=bind,src={_container_path(changed_output_root, distribution)},"
            "dst=/changed,readonly",
            f"type=bind,src={_container_path(diagnostic_root, distribution)},dst=/diagnostic",
        ),
        script=script,
    )


def _run_required(command: Sequence[str], *, timeout_seconds: int, label: str) -> bytes:
    result = _run(command, timeout_seconds=timeout_seconds)
    if result.returncode != 0:
        diagnostic = (result.stderr or result.stdout).decode("utf-8", errors="replace").strip()
        if len(diagnostic) > 1000:
            diagnostic = diagnostic[-1000:]
        suffix = f": {diagnostic}" if diagnostic else ""
        raise RealLeanChangedSourcePreflightError(f"{label} failed{suffix}")
    return result.stdout


def _query_canonical_type(
    query_source: Path,
    module_output_root: Path,
    *,
    distribution: str,
    timeout_seconds: int,
) -> str:
    command = docker_type_query_command(
        query_source,
        module_output_root,
        distribution=distribution,
    )
    output = _run_required(command, timeout_seconds=timeout_seconds, label="OLean type query")
    try:
        lines = [line for line in output.decode("utf-8").splitlines() if line]
        document = json.loads(lines[-1])
    except (UnicodeDecodeError, IndexError, json.JSONDecodeError) as error:
        raise RealLeanChangedSourcePreflightError("OLean type query output is invalid") from error
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "declaration", "canonical_type"}
        or document["schema_version"] != TYPE_QUERY_SCHEMA
        or document["declaration"] != CHANGED_DECLARATION
        or not isinstance(document["canonical_type"], str)
        or not document["canonical_type"]
    ):
        raise RealLeanChangedSourcePreflightError("OLean type query record is invalid")
    return document["canonical_type"]


def _regular_olean(root: Path, module: str) -> Path:
    output = root / _module_output_relative(module)
    if output.is_symlink() or not output.is_file() or output.stat().st_size == 0:
        raise RealLeanChangedSourcePreflightError("expected compiled OLean is unavailable")
    return output


def _copy_unaffected_oleans(
    case: RealLeanChangeCaseV1,
    baseline_output_root: Path,
    reused_output_root: Path,
) -> list[dict[str, object]]:
    affected = set(case.expected_module_reverse_import_closure)
    records: list[dict[str, object]] = []
    for module in case.baseline.module_topological_order():
        if module.module in affected:
            continue
        source = _regular_olean(baseline_output_root, module.module)
        destination = reused_output_root / _module_output_relative(module.module)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        if _sha256(destination) != _sha256(source):
            raise RealLeanChangedSourcePreflightError("unaffected OLean reuse changed its identity")
        destination.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        records.append(
            {
                "module": module.module,
                "source_sha256": module.source_sha256,
                "baseline_olean_sha256": _sha256(source),
                "reused_olean_sha256": _sha256(destination),
                "reused_from_baseline": True,
                "recompiled": False,
            }
        )
    if not records:
        raise RealLeanChangedSourcePreflightError("change case has no unaffected module to reuse")
    return records


def _validate_expected_failure(
    diagnostic_root: Path, case: RealLeanChangeCaseV1
) -> dict[str, object]:
    try:
        status_text = (diagnostic_root / "probe.status").read_text(encoding="ascii").strip()
        status = int(status_text)
        stdout = (diagnostic_root / "probe.stdout").read_text(encoding="utf-8")
        stderr = (diagnostic_root / "probe.stderr").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise RealLeanChangedSourcePreflightError(
            "downstream failure diagnostic is unavailable"
        ) from error
    if status != 1:
        raise RealLeanChangedSourcePreflightError(
            "unchanged downstream did not return Lean's semantic-error exit code"
        )
    expected_api_mismatch = (
        "Arithmetic.score\nhas type\n  Nat → Nat\nbut is expected to have type\n  Nat"
    )
    diagnostic_output = f"{stdout}\n{stderr}"
    if (
        "/input/AutoLean/ProjectDagPreflight/Relations.lean" not in diagnostic_output
        or expected_api_mismatch not in diagnostic_output
    ):
        diagnostic = diagnostic_output.strip()
        if len(diagnostic) > 1000:
            diagnostic = diagnostic[-1000:]
        raise RealLeanChangedSourcePreflightError(
            f"downstream failure is not the expected old-API incompatibility: {diagnostic}"
        )
    output = diagnostic_root / _module_output_relative(case.failure_probe_module)
    if output.exists():
        raise RealLeanChangedSourcePreflightError("failed downstream compile emitted an OLean")
    return {
        "module": case.failure_probe_module,
        "lean_exit_code": status,
        "old_source_sha256": case.baseline.modules_by_name[case.failure_probe_module].source_sha256,
        "diagnostic_sha256": hashlib.sha256(diagnostic_output.encode("utf-8")).hexdigest(),
        "failure_class": "old_downstream_source_incompatible_with_new_upstream_api",
    }


def changed_source_preflight(
    *,
    distribution: str = DEFAULT_WSL_DISTRIBUTION,
    timeout_seconds: int = 300,
) -> dict[str, object]:
    """Run the baseline, incomplete-change, and successor rebuild phases."""

    if not 1 <= timeout_seconds <= 600:
        raise RealLeanChangedSourcePreflightError("timeout must be between 1 and 600 seconds")
    try:
        case = load_default_real_lean_change_case()
    except RealLeanChangeCaseError as error:
        raise RealLeanChangedSourcePreflightError("changed-source case is invalid") from error
    rebuild_bundle = changed_source_rebuild_bundle(case)
    with tempfile.TemporaryDirectory(prefix="autolean-t7-changed-source-") as raw_workspace:
        workspace = Path(raw_workspace)
        baseline = _snapshot_fixture(case.baseline, workspace / "baseline-snapshot")
        upstream = _materialize_changed_snapshot(
            case, workspace / "upstream-snapshot", successor=False
        )
        successor = _materialize_changed_snapshot(
            case, workspace / "successor-snapshot", successor=True
        )
        query_source = workspace / "query" / "ScoreTypeQuery.lean"
        _write_regular_file(query_source, _TYPE_QUERY_SOURCE.encode("utf-8"), read_only=True)

        baseline_output = _fresh_output_root(workspace / "baseline-output")
        baseline_command = docker_clean_build_command(
            baseline, baseline_output, distribution=distribution
        )
        _run_required(
            baseline_command,
            timeout_seconds=timeout_seconds,
            label="baseline clean build",
        )
        reused_output = _fresh_output_root(workspace / "reused-output")
        unaffected_records = _copy_unaffected_oleans(case, baseline_output, reused_output)

        baseline_type = _query_canonical_type(
            query_source,
            baseline_output,
            distribution=distribution,
            timeout_seconds=timeout_seconds,
        )
        baseline_type_sha256 = hashlib.sha256(baseline_type.encode("utf-8")).hexdigest()
        if baseline_type_sha256 != case.expected_baseline_canonical_type_sha256:
            raise RealLeanChangedSourcePreflightError(
                "baseline OLean canonical type does not match the change case "
                f"(observed {baseline_type_sha256})"
            )

        upstream_output = _fresh_output_root(workspace / "upstream-output")
        upstream_command = docker_compile_modules_command(
            case,
            upstream,
            reused_output,
            upstream_output,
            (case.changed_module,),
            distribution=distribution,
        )
        _run_required(
            upstream_command,
            timeout_seconds=timeout_seconds,
            label="upstream API-change build",
        )
        successor_type = _query_canonical_type(
            query_source,
            upstream_output,
            distribution=distribution,
            timeout_seconds=timeout_seconds,
        )
        successor_type_sha256 = hashlib.sha256(successor_type.encode("utf-8")).hexdigest()
        if successor_type_sha256 != case.expected_successor_canonical_type_sha256:
            raise RealLeanChangedSourcePreflightError(
                "successor OLean canonical type does not match the change case "
                f"(observed {successor_type_sha256})"
            )
        if baseline_type == successor_type:
            raise RealLeanChangedSourcePreflightError(
                "manifest-bound public API change did not change the elaborated type"
            )

        diagnostic_output = _fresh_output_root(workspace / "failure-diagnostic")
        failure_command = docker_expected_failure_command(
            case,
            upstream,
            upstream_output,
            diagnostic_output,
            distribution=distribution,
        )
        _run_required(
            failure_command,
            timeout_seconds=timeout_seconds,
            label="unchanged downstream failure probe",
        )
        failure_record = _validate_expected_failure(diagnostic_output, case)

        successor_output = _fresh_output_root(workspace / "successor-output")
        successor_command = docker_compile_modules_command(
            case,
            successor,
            reused_output,
            successor_output,
            case.expected_module_reverse_import_closure,
            distribution=distribution,
        )
        _run_required(
            successor_command,
            timeout_seconds=timeout_seconds,
            label="successor affected-module rebuild",
        )
        affected_records: list[dict[str, object]] = []
        for module_name in case.expected_module_reverse_import_closure:
            module = case.baseline.modules_by_name[module_name]
            baseline_olean = _regular_olean(baseline_output, module_name)
            successor_olean = _regular_olean(successor_output, module_name)
            if (reused_output / _module_output_relative(module_name)).exists():
                raise RealLeanChangedSourcePreflightError(
                    "affected module was available through the reuse root"
                )
            if _sha256(baseline_olean) == _sha256(successor_olean):
                raise RealLeanChangedSourcePreflightError(
                    "affected module did not emit a new compiled identity"
                )
            affected_records.append(
                {
                    "module": module_name,
                    "baseline_source_sha256": module.source_sha256,
                    "successor_source_sha256": successor.source_hashes[module_name],
                    "baseline_olean_sha256": _sha256(baseline_olean),
                    "successor_olean_sha256": _sha256(successor_olean),
                    "freshly_recompiled": True,
                }
            )

        for record in unaffected_records:
            module_name = str(record["module"])
            if (
                upstream.source_hashes[module_name] != record["source_sha256"]
                or successor.source_hashes[module_name] != record["source_sha256"]
            ):
                raise RealLeanChangedSourcePreflightError(
                    "unaffected source identity changed between snapshots"
                )
            upstream_reuse = _regular_olean(upstream_output, module_name)
            successor_reuse = _regular_olean(successor_output, module_name)
            baseline_hash = str(record["baseline_olean_sha256"])
            if (
                _sha256(upstream_reuse) != baseline_hash
                or _sha256(successor_reuse) != baseline_hash
            ):
                raise RealLeanChangedSourcePreflightError(
                    "unaffected OLean identity was not reused in a rebuild output"
                )
            record["upstream_reused_olean_sha256"] = _sha256(upstream_reuse)
            record["successor_reused_olean_sha256"] = _sha256(successor_reuse)

    return {
        "schema_version": RESULT_SCHEMA,
        "status": "passed",
        "scope": "t7_changed_source_preflight_only",
        "acceptance_result": False,
        "image": SOURCE_V2_IMAGE,
        "baseline_manifest_sha256": case.baseline_manifest_sha256,
        "change_case_manifest_sha256": case.manifest_sha256(),
        "type_query_sha256": _TYPE_QUERY_SHA256,
        "changed_declaration": CHANGED_DECLARATION,
        "baseline_canonical_type": baseline_type,
        "baseline_canonical_type_sha256": baseline_type_sha256,
        "successor_canonical_type": successor_type,
        "successor_canonical_type_sha256": successor_type_sha256,
        "canonical_elaborated_type_changed": True,
        "curated_declaration_invalidation_plan": list(case.expected_declaration_reverse_closure),
        "module_granularity_rebuild_plan": list(case.expected_module_reverse_import_closure),
        "changed_source_rebuild_bundle": rebuild_bundle.to_dict(),
        "incomplete_change_failure": failure_record,
        "unaffected_modules": unaffected_records,
        "affected_modules": affected_records,
        "network_accessed_by_container": False,
        "contract_evidence_created": False,
        "provider_evidence_created": False,
        "lease_evidence_created": False,
        "gateway_evidence_created": False,
        "oci_verifier_evidence_created": False,
        "semantic_review_created": False,
    }


def _canonical_json(document: object) -> bytes:
    rendered = json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return (rendered + "\n").encode("utf-8")


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate", help="validate the committed change case")
    validate.add_argument("--json", action="store_true")
    run = subparsers.add_parser(
        "run",
        help="operator-local preflight; run the changed-source propagation case",
    )
    run.add_argument("--distribution", default=DEFAULT_WSL_DISTRIBUTION)
    run.add_argument("--timeout-seconds", type=int, default=300)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        if args.command == "validate":
            case = load_default_real_lean_change_case()
            rebuild_bundle = changed_source_rebuild_bundle(case)
            result: dict[str, object] = {
                "schema_version": "autolean.real-lean-change-case-validation.v1",
                "status": "passed",
                "scope": "t7_changed_source_preflight_only",
                "acceptance_result": False,
                "change_case_manifest_sha256": case.manifest_sha256(),
                "changed_declaration_ids": list(case.changed_declaration_ids),
                "curated_declaration_invalidation_plan": list(
                    case.expected_declaration_reverse_closure
                ),
                "module_granularity_rebuild_plan": list(
                    case.expected_module_reverse_import_closure
                ),
                "changed_source_rebuild_bundle": rebuild_bundle.to_dict(),
                "canonical_elaborated_type_change_pending_real_query": True,
            }
            if args.json:
                print(_canonical_json(result).decode("utf-8"), end="")
            else:
                print("T7 changed-source case is byte-bound and structurally valid.")
            return 0
        result = changed_source_preflight(
            distribution=args.distribution,
            timeout_seconds=args.timeout_seconds,
        )
    except (RealLeanChangedSourcePreflightError, RealLeanProjectDagPreflightError) as error:
        print(f"real-lean-changed-source-preflight: {error}", file=sys.stderr)
        return 2
    print(_canonical_json(result).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
