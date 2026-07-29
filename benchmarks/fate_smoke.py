"""Answer-free, non-promotable FATE agent-smoke-8 execution protocol.

The first implementation uses a fixed ``aesop`` tactic as a transparent proof-search probe.
It exercises proof-slot materialization and a network-isolated Lean query, but it deliberately
does not claim that a model Agent ran or that the mounted mathlib build is production-attested.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Final, Protocol, cast

from benchmarks.fate import SMOKE, Tier
from benchmarks.fate_adapter import (
    FateAdapter,
    FateFixtureIntegrityError,
    FateFixtureLockV1,
    FatePatchedSourceV1,
)

REPORT_SCHEMA: Final = "autolean.fate-agent-smoke-report.v1"
REPORT_ENVELOPE_SCHEMA: Final = "autolean.fate-agent-smoke-envelope.v1"
SUITE: Final = "agent-smoke-8"
EXPECTED_SOURCE_MANIFEST_SHA256: Final = (
    "dc52f40fdede4c4e2290580d9dfdecb9e017b8cd3ed961e2ad13e9a0accb54a2"
)
EXPECTED_SPLIT_MANIFEST_SHA256: Final = (
    "448027aa486d85ef3e45bf5f46bf65e88c60fcc660d7cb6ef708dd85edad49d4"
)
STATIC_CANDIDATE_POLICY_ID: Final = "autolean.static-aesop-smoke.v1"
_STATIC_PROOF_BODY: Final = "aesop"
WRAPPER_SCHEMA: Final = "autolean.fate-oci-lean-wrapper.v2"
WRAPPER_PROTOCOL: Final = "autolean.fate-oci-lean-wrapper.v2"
TYPE_FORMAT: Final = "autolean.lean-pp-expr.v1"
EXPECTED_LEAN_VERSION: Final = "v4.28.0"
EXPECTED_MATHLIB_REVISION: Final = "8f9d9cff6bd728b17a24e163c9402775d9e6a365"
EXPECTED_M_LAKE_MANIFEST_SHA256: Final = (
    "e6efb741f70db112585a49e84e3d04272a6dcf22549b97af072e0c90b08082b0"
)
ALLOWED_AXIOMS: Final[frozenset[str]] = frozenset({"propext", "Classical.choice", "Quot.sound"})
_TIERS: Final[tuple[Tier, ...]] = ("M", "H", "X")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_LEAN_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_'.]*(?:\.[A-Za-z0-9_'][A-Za-z0-9_']*)*$")


class FateSmokeError(RuntimeError):
    """Fail-closed smoke error carrying only a stable, non-sensitive code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _require_sha256(value: str, code: str) -> None:
    if _SHA256.fullmatch(value) is None:
        raise FateSmokeError(code)


def _is_link_or_junction(path: Path) -> bool:
    is_junction = getattr(os.path, "isjunction", None)
    return path.is_symlink() or bool(is_junction is not None and is_junction(path))


def _has_linked_ancestor(path: Path) -> bool:
    candidate = path.absolute()
    while True:
        if _is_link_or_junction(candidate):
            return True
        parent = candidate.parent
        if parent == candidate:
            return False
        candidate = parent


def _read_regular(path: Path, code: str) -> bytes:
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
    except OSError as error:
        raise FateSmokeError(code) from error
    if not stat.S_ISREG(metadata.st_mode) or _is_link_or_junction(path):
        raise FateSmokeError(code)
    return payload


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-standard JSON constant: {value}")


@dataclass(frozen=True, slots=True)
class FateSmokeCaseV1:
    task_id: str
    split: Tier
    source_path: str
    source_sha256: str
    signature_sha256: str
    declaration: str

    def __post_init__(self) -> None:
        expected_prefix = f"FATE-{self.split}-"
        if not self.task_id.startswith(expected_prefix):
            raise FateSmokeError("smoke_case_id_invalid")
        path = PurePosixPath(self.source_path)
        if path.is_absolute() or ".." in path.parts or "\\" in self.source_path:
            raise FateSmokeError("smoke_case_source_path_invalid")
        _require_sha256(self.source_sha256, "smoke_case_source_hash_invalid")
        _require_sha256(self.signature_sha256, "smoke_case_signature_hash_invalid")
        if _LEAN_NAME.fullmatch(self.declaration) is None:
            raise FateSmokeError("smoke_case_declaration_invalid")


@dataclass(frozen=True, slots=True)
class FateSmokeFixtureV1:
    manifest_sha256: str
    split_manifest_sha256: str
    root_commit: str
    submodules: Mapping[Tier, str]
    toolchain: str
    mathlib_commit: str
    lake_manifest_sha256: Mapping[Tier, str]
    cases: tuple[FateSmokeCaseV1, ...]

    def __post_init__(self) -> None:
        _require_sha256(self.manifest_sha256, "smoke_manifest_hash_invalid")
        _require_sha256(self.split_manifest_sha256, "smoke_split_hash_invalid")
        if _SHA1.fullmatch(self.root_commit) is None:
            raise FateSmokeError("smoke_root_commit_invalid")
        if set(self.submodules) != set(_TIERS) or any(
            _SHA1.fullmatch(value) is None for value in self.submodules.values()
        ):
            raise FateSmokeError("smoke_submodule_commit_invalid")
        if set(self.lake_manifest_sha256) != set(_TIERS) or any(
            _SHA256.fullmatch(value) is None for value in self.lake_manifest_sha256.values()
        ):
            raise FateSmokeError("smoke_lake_manifest_hash_invalid")
        expected_ids = {f"FATE-{tier}-{number}" for tier in _TIERS for number in SMOKE[tier]}
        if len(self.cases) != 8 or {case.task_id for case in self.cases} != expected_ids:
            raise FateSmokeError("smoke_selection_drift")


@dataclass(frozen=True, slots=True)
class FateSmokeRuntimeEvidenceV1:
    image_digest: str
    image_id: str
    runtime_state_sha256: str
    runtime_audit_sha256: str
    dependency_graph_sha256: str
    dependency_build_tree_sha256: str
    dependency_count: int
    wrapper_sha256: str
    query_helper_sha256: str
    command_policy_id: str
    command_policy_sha256: str

    def __post_init__(self) -> None:
        if not self.image_digest.startswith("sha256:") or not self.image_id.startswith("sha256:"):
            raise FateSmokeError("smoke_image_identity_invalid")
        for field in (
            "runtime_state_sha256",
            "runtime_audit_sha256",
            "dependency_graph_sha256",
            "dependency_build_tree_sha256",
            "wrapper_sha256",
            "query_helper_sha256",
            "command_policy_sha256",
        ):
            _require_sha256(getattr(self, field), f"smoke_{field}_invalid")
        if self.dependency_count != 9:
            raise FateSmokeError("smoke_dependency_count_invalid")
        if not self.command_policy_id:
            raise FateSmokeError("smoke_command_policy_id_invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "execution_platform": "WSL2-OCI",
            "image_digest": self.image_digest,
            "image_id": self.image_id,
            "runtime_state_sha256": self.runtime_state_sha256,
            "runtime_audit_sha256": self.runtime_audit_sha256,
            "dependency_graph_sha256": self.dependency_graph_sha256,
            "dependency_build_tree_sha256": self.dependency_build_tree_sha256,
            "dependency_count": self.dependency_count,
            "wrapper_sha256": self.wrapper_sha256,
            "query_helper_sha256": self.query_helper_sha256,
            "command_policy_id": self.command_policy_id,
            "command_policy_sha256": self.command_policy_sha256,
            "network_isolation": "docker_network_none",
            "root_filesystem": "read_only",
            "dependency_mount": "read_only",
            "candidate_mount": "read_only",
            "capabilities": "all_dropped",
            "new_privileges": False,
            "image_contains_mathlib": False,
            "dependency_build_artifacts_attested": False,
            "verifier_program_ownership": "host_mounted_hash_bound",
        }


@dataclass(frozen=True, slots=True)
class FateSmokeObservation:
    returncode: int | None
    stdout: bytes
    stderr: bytes
    elapsed_seconds: float
    command_sha256: str
    timed_out: bool = False

    def __post_init__(self) -> None:
        if self.returncode is not None and (
            not isinstance(self.returncode, int) or isinstance(self.returncode, bool)
        ):
            raise FateSmokeError("smoke_observation_exit_invalid")
        if self.elapsed_seconds < 0:
            raise FateSmokeError("smoke_observation_elapsed_invalid")
        _require_sha256(self.command_sha256, "smoke_observation_command_hash_invalid")
        if self.timed_out and self.returncode is not None:
            raise FateSmokeError("smoke_observation_timeout_invalid")


class FateSmokeCompiler(Protocol):
    def compile(
        self,
        candidate: FatePatchedSourceV1,
        *,
        timeout_seconds: int,
    ) -> FateSmokeObservation: ...


@dataclass(frozen=True, slots=True)
class FateWrapperRecordV1:
    declaration: str
    canonical_type: str
    observed_axioms: tuple[str, ...]
    record_sha256: str


def _parse_wrapper_record(payload: bytes, expected_declaration: str) -> FateWrapperRecordV1:
    if not payload or len(payload) > 2_000_000 or payload.count(b"\n") > 1:
        raise FateSmokeError("smoke_wrapper_output_invalid")
    try:
        raw = json.loads(
            payload,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise FateSmokeError("smoke_wrapper_output_invalid") from error
    expected_keys = {
        "schema_version",
        "declaration",
        "canonical_type",
        "lean_version",
        "mathlib_revision",
        "lake_manifest_hash",
        "observed_axioms",
    }
    if not isinstance(raw, dict) or set(raw) != expected_keys:
        raise FateSmokeError("smoke_wrapper_output_invalid")
    if (
        raw["schema_version"] != WRAPPER_SCHEMA
        or raw["declaration"] != expected_declaration
        or raw["lean_version"] != EXPECTED_LEAN_VERSION
        or raw["mathlib_revision"] != EXPECTED_MATHLIB_REVISION
        or raw["lake_manifest_hash"] != EXPECTED_M_LAKE_MANIFEST_SHA256
    ):
        raise FateSmokeError("smoke_wrapper_binding_mismatch")
    canonical_type = raw["canonical_type"]
    axioms = raw["observed_axioms"]
    if (
        not isinstance(canonical_type, str)
        or not canonical_type
        or len(canonical_type) > 1_000_000
        or any(character in canonical_type for character in "\x00\r\n")
        or not isinstance(axioms, list)
        or any(not isinstance(axiom, str) for axiom in axioms)
    ):
        raise FateSmokeError("smoke_wrapper_output_invalid")
    typed_axioms = cast(list[str], axioms)
    if typed_axioms != sorted(set(typed_axioms)) or any(
        _LEAN_NAME.fullmatch(axiom) is None for axiom in typed_axioms
    ):
        raise FateSmokeError("smoke_wrapper_axioms_invalid")
    canonical_record = {
        "schema_version": raw["schema_version"],
        "declaration": raw["declaration"],
        "canonical_type": canonical_type,
        "lean_version": raw["lean_version"],
        "mathlib_revision": raw["mathlib_revision"],
        "lake_manifest_hash": raw["lake_manifest_hash"],
        "observed_axioms": typed_axioms,
    }
    return FateWrapperRecordV1(
        declaration=expected_declaration,
        canonical_type=canonical_type,
        observed_axioms=tuple(typed_axioms),
        record_sha256=_sha256(_canonical_json(canonical_record)),
    )


def load_verified_smoke_fixture(
    checkout: Path,
    source_manifest_path: Path,
    split_manifest_path: Path,
) -> tuple[FateAdapter, FateSmokeFixtureV1]:
    """Load exactly the pinned eight tasks without reading FATE metadata or any answer source."""

    split_bytes = _read_regular(split_manifest_path, "smoke_split_manifest_unreadable")
    if _sha256(split_bytes) != EXPECTED_SPLIT_MANIFEST_SHA256:
        raise FateSmokeError("smoke_split_manifest_byte_hash_drift")
    try:
        split_raw = json.loads(
            split_bytes,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise FateSmokeError("smoke_split_manifest_invalid") from error
    expected_split = {tier: sorted(SMOKE[tier]) for tier in _TIERS}
    if (
        not isinstance(split_raw, dict)
        or split_raw.get("schema_version") != "autolean.fate-splits.v1"
        or split_raw.get("contains_solutions") is not False
        or split_raw.get("report_tiers_separately") is not True
        or not isinstance(split_raw.get("suites"), dict)
        or cast(dict[str, object], split_raw["suites"]).get(SUITE) != expected_split
    ):
        raise FateSmokeError("smoke_split_manifest_invalid")

    source_manifest_bytes = _read_regular(
        source_manifest_path,
        "smoke_source_manifest_unreadable",
    )
    if _sha256(source_manifest_bytes) != EXPECTED_SOURCE_MANIFEST_SHA256:
        raise FateSmokeError("smoke_source_manifest_byte_hash_drift")
    try:
        adapter = FateAdapter.from_manifest_file(
            checkout,
            source_manifest_path,
            expected_manifest_content_hash=EXPECTED_SOURCE_MANIFEST_SHA256,
        )
    except FateFixtureIntegrityError as error:
        raise FateSmokeError("smoke_fixture_integrity_failed") from error
    lock = FateFixtureLockV1.load()
    cases: list[FateSmokeCaseV1] = []
    for tier in _TIERS:
        for number in sorted(SMOKE[tier]):
            task = adapter.task(f"FATE-{tier}-{number}")
            actual_source = _read_regular(
                checkout.joinpath(*PurePosixPath(task.source_path).parts),
                "smoke_source_unreadable",
            )
            if _sha256(actual_source) != task.source_sha256:
                raise FateSmokeError("smoke_source_worktree_drift")
            cases.append(
                FateSmokeCaseV1(
                    task_id=task.task_id,
                    split=tier,
                    source_path=task.source_path,
                    source_sha256=task.source_sha256,
                    signature_sha256=task.target.signature_sha256,
                    declaration=task.target.qualified_name,
                )
            )
    fixture = FateSmokeFixtureV1(
        manifest_sha256=adapter.manifest.content_hash,
        split_manifest_sha256=EXPECTED_SPLIT_MANIFEST_SHA256,
        root_commit=lock.root_commit,
        submodules=dict(lock.submodules),
        toolchain=lock.toolchain,
        mathlib_commit=lock.mathlib_revision,
        lake_manifest_sha256=dict(lock.lake_manifest_sha256),
        cases=tuple(cases),
    )
    return adapter, fixture


def _case_source(checkout: Path, case: FateSmokeCaseV1) -> Path:
    return checkout.joinpath(*PurePosixPath(case.source_path).parts)


def _case_report(
    case: FateSmokeCaseV1,
    candidate: FatePatchedSourceV1,
    observation: FateSmokeObservation,
) -> dict[str, object]:
    record: FateWrapperRecordV1 | None = None
    protocol_error: str | None = None
    if observation.timed_out:
        result = "timeout"
    elif observation.returncode != 0:
        result = "compile_or_query_failed"
    else:
        try:
            record = _parse_wrapper_record(observation.stdout, case.declaration)
        except FateSmokeError as error:
            protocol_error = error.code
            result = "verifier_protocol_failed"
        else:
            if not set(record.observed_axioms).issubset(ALLOWED_AXIOMS):
                result = "axiom_policy_rejected"
            else:
                result = "compiled_and_queried"

    report: dict[str, object] = {
        "task_id": case.task_id,
        "source_path": case.source_path,
        "source_sha256": case.source_sha256,
        "signature_sha256": case.signature_sha256,
        "declaration": case.declaration,
        "proof_body_sha256": candidate.proof_body_sha256,
        "candidate_sha256": candidate.candidate_sha256,
        "protected_source_bytes_match": True,
        "candidate_contains_sorry": False,
        "command_sha256": observation.command_sha256,
        "elapsed_ms": round(observation.elapsed_seconds * 1000, 3),
        "exit_code": observation.returncode,
        "result": result,
        "stdout_bytes": len(observation.stdout),
        "stdout_sha256": _sha256(observation.stdout),
        "stderr_bytes": len(observation.stderr),
        "stderr_sha256": _sha256(observation.stderr),
    }
    if record is not None:
        report.update(
            {
                "canonical_type_sha256": _sha256(record.canonical_type.encode("utf-8")),
                "observed_axioms": list(record.observed_axioms),
                "axiom_policy_passed": set(record.observed_axioms).issubset(ALLOWED_AXIOMS),
                "wrapper_record_sha256": record.record_sha256,
            }
        )
    if protocol_error is not None:
        report["protocol_error"] = protocol_error
    return report


def execute_static_smoke(
    *,
    fixture: FateSmokeFixtureV1,
    adapter: FateAdapter,
    checkout: Path,
    runtime_evidence: FateSmokeRuntimeEvidenceV1,
    compiler: FateSmokeCompiler,
    timeout_seconds: int,
    clock: Callable[[], str] = _utc_now,
) -> dict[str, object]:
    """Run a transparent one-attempt tactic probe for exactly agent-smoke-8."""

    if not 1 <= timeout_seconds <= 1800:
        raise FateSmokeError("smoke_timeout_invalid")
    expected_ids = {f"FATE-{tier}-{number}" for tier in _TIERS for number in SMOKE[tier]}
    if len(fixture.cases) != 8 or {case.task_id for case in fixture.cases} != expected_ids:
        raise FateSmokeError("smoke_selection_drift")

    started_at = clock()
    tiers: dict[str, object] = {}
    for tier in _TIERS:
        reports: list[dict[str, object]] = []
        for case in (item for item in fixture.cases if item.split == tier):
            source_path = _case_source(checkout, case)
            before = _read_regular(source_path, "smoke_source_unreadable")
            if _sha256(before) != case.source_sha256:
                raise FateSmokeError("smoke_source_changed_before_execution")
            candidate = adapter.materialize_proof(case.task_id, _STATIC_PROOF_BODY)
            observation = compiler.compile(candidate, timeout_seconds=timeout_seconds)
            after = _read_regular(source_path, "smoke_source_unreadable")
            if _sha256(after) != case.source_sha256:
                raise FateSmokeError("smoke_source_changed_during_execution")
            reports.append(_case_report(case, candidate, observation))
        successful = sum(report["result"] == "compiled_and_queried" for report in reports)
        tiers[tier] = {
            "cases": reports,
            "summary": {
                "compiled_and_queried": successful,
                "not_verified": len(reports) - successful,
                "total": len(reports),
            },
        }

    report: dict[str, object] = {
        "schema_version": REPORT_SCHEMA,
        "suite": SUITE,
        "started_at": started_at,
        "finished_at": clock(),
        "evidence_scope": (
            "network_isolated_non_promotable_static_tactic_candidate_compilation_and_query"
        ),
        "candidate_policy": {
            "policy_id": STATIC_CANDIDATE_POLICY_ID,
            "attempts_per_task": 1,
            "task_specific_answers": False,
            "model_or_agent_executed": False,
            "proof_search_executed": True,
            "proof_search_kind": "lean_aesop_tactic",
            "web_accessed": False,
            "answer_sources_loaded": False,
        },
        "fixture": {
            "manifest_sha256": fixture.manifest_sha256,
            "split_manifest_sha256": fixture.split_manifest_sha256,
            "root_commit": fixture.root_commit,
            "submodules": dict(sorted(fixture.submodules.items())),
            "toolchain": fixture.toolchain,
            "mathlib_commit": fixture.mathlib_commit,
            "lake_manifest_sha256": dict(sorted(fixture.lake_manifest_sha256.items())),
        },
        "runtime": runtime_evidence.to_dict(),
        "verifier_boundary": {
            "byte_level_statement_preservation": True,
            "kernel_elaboration_and_type_query": True,
            "axiom_allowlist": sorted(ALLOWED_AXIOMS),
            "signing_gateway_executed": False,
            "production_attestation": False,
            "promotable": False,
            "blockers": [
                "mathlib_not_rebuilt_inside_pinned_image",
                "dependency_build_tree_observed_not_independently_attested",
                "verifier_program_hash_bound_but_not_image_owned",
                "no_lease_bound_signing_gateway_request",
                "no_model_agent_execution",
            ],
        },
        "contains_source_or_answer_text": False,
        "original_sources_contain_sorry": True,
        "candidate_sources_contain_sorry": False,
        "tiers_reported_separately": True,
        "tiers": tiers,
    }
    return report


def report_envelope(report: Mapping[str, object]) -> dict[str, object]:
    report_dict = dict(report)
    return {
        "schema_version": REPORT_ENVELOPE_SCHEMA,
        "report_sha256": _sha256(_canonical_json(report_dict)),
        "report": report_dict,
    }


def validate_report_envelope(envelope: object) -> dict[str, object]:
    if not isinstance(envelope, dict) or set(envelope) != {
        "schema_version",
        "report_sha256",
        "report",
    }:
        raise FateSmokeError("smoke_report_envelope_invalid")
    if envelope["schema_version"] != REPORT_ENVELOPE_SCHEMA:
        raise FateSmokeError("smoke_report_envelope_invalid")
    report_hash = envelope["report_sha256"]
    report = envelope["report"]
    if (
        not isinstance(report_hash, str)
        or not isinstance(report, dict)
        or report.get("schema_version") != REPORT_SCHEMA
        or _sha256(_canonical_json(report)) != report_hash
    ):
        raise FateSmokeError("smoke_report_hash_mismatch")
    return cast(dict[str, object], report)


def write_report_exclusive(
    path: Path,
    envelope: Mapping[str, object],
    *,
    forbidden_root: Path,
) -> Path:
    output = path.absolute()
    if output.exists() or _is_link_or_junction(output):
        raise FateSmokeError("smoke_report_already_exists")
    if _has_linked_ancestor(output.parent):
        raise FateSmokeError("smoke_report_linked_parent_refused")
    if output.resolve().is_relative_to(forbidden_root.resolve()):
        raise FateSmokeError("smoke_report_inside_fate_checkout_refused")
    output.parent.mkdir(parents=True, exist_ok=True)
    if _has_linked_ancestor(output.parent):
        raise FateSmokeError("smoke_report_linked_parent_refused")
    if output.resolve().is_relative_to(forbidden_root.resolve()):
        raise FateSmokeError("smoke_report_inside_fate_checkout_refused")
    payload = _canonical_json(dict(envelope)) + b"\n"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            output,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise FateSmokeError("smoke_report_write_failed") from error
    return output
