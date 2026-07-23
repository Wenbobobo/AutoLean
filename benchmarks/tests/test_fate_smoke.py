from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

import pytest

from benchmarks.fate import SMOKE, FateProblemId, Tier
from benchmarks.fate_adapter import (
    FateAdapter,
    FateFixtureTaskV1,
    FatePatchedSourceV1,
)
from benchmarks.fate_smoke import (
    EXPECTED_M_LAKE_MANIFEST_SHA256,
    EXPECTED_MATHLIB_REVISION,
    REPORT_SCHEMA,
    WRAPPER_SCHEMA,
    FateSmokeCaseV1,
    FateSmokeCompiler,
    FateSmokeError,
    FateSmokeFixtureV1,
    FateSmokeObservation,
    FateSmokeRuntimeEvidenceV1,
    execute_static_smoke,
    load_verified_smoke_fixture,
    report_envelope,
    validate_report_envelope,
    write_report_exclusive,
)

_TIERS: tuple[Tier, ...] = ("M", "H", "X")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _source(number: int) -> bytes:
    return f"import Mathlib\n\ntheorem TargetM{number} : True := by\n  sorry\n".encode()


class FakeAdapter:
    def __init__(self, tasks: dict[str, FateFixtureTaskV1], sources: dict[str, bytes]) -> None:
        self.tasks = tasks
        self.sources = sources

    def materialize_proof(self, task_id: str, proof_body: str) -> FatePatchedSourceV1:
        assert proof_body == "aesop"
        task = self.tasks[task_id]
        original = self.sources[task_id]
        slot = task.proof_slot
        proof = proof_body.encode()
        candidate = original[: slot.byte_start] + proof + original[slot.byte_end :]
        return FatePatchedSourceV1(
            task=task,
            proof_body_sha256=_sha256(proof),
            candidate_sha256=_sha256(candidate),
            source=candidate,
        )


def _fixture(
    tmp_path: Path,
) -> tuple[FateSmokeFixtureV1, FateAdapter, Path, dict[str, FateFixtureTaskV1]]:
    checkout = tmp_path / "FATE"
    tasks: dict[str, FateFixtureTaskV1] = {}
    sources: dict[str, bytes] = {}
    cases: list[FateSmokeCaseV1] = []
    for tier in _TIERS:
        for number in sorted(SMOKE[tier]):
            problem = FateProblemId(tier, number)
            source = _source(number)
            source_path = f"FATE-{tier}/FATE{tier}/{number}.lean"
            task = FateFixtureTaskV1.from_source(problem, source_path, source)
            destination = checkout.joinpath(*source_path.split("/"))
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source)
            tasks[task.task_id] = task
            sources[task.task_id] = source
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
        manifest_sha256="1" * 64,
        split_manifest_sha256="2" * 64,
        root_commit="3" * 40,
        submodules={"M": "4" * 40, "H": "5" * 40, "X": "6" * 40},
        toolchain="leanprover/lean4:v4.28.0",
        mathlib_commit=EXPECTED_MATHLIB_REVISION,
        lake_manifest_sha256={"M": "7" * 64, "H": "8" * 64, "X": "9" * 64},
        cases=tuple(cases),
    )
    return fixture, cast(FateAdapter, FakeAdapter(tasks, sources)), checkout, tasks


def _runtime() -> FateSmokeRuntimeEvidenceV1:
    return FateSmokeRuntimeEvidenceV1(
        image_digest="sha256:" + "a" * 64,
        image_id="sha256:" + "a" * 64,
        runtime_state_sha256="b" * 64,
        runtime_audit_sha256="c" * 64,
        dependency_graph_sha256="d" * 64,
        dependency_build_tree_sha256="e" * 64,
        dependency_count=9,
        wrapper_sha256="f" * 64,
        query_helper_sha256="0" * 64,
        command_policy_id="test-policy",
        command_policy_sha256="1" * 64,
    )


def _wrapper_payload(
    declaration: str,
    *,
    axioms: list[str] | None = None,
) -> bytes:
    return (
        json.dumps(
            {
                "schema_version": WRAPPER_SCHEMA,
                "declaration": declaration,
                "canonical_type": "True",
                "lean_version": "v4.28.0",
                "mathlib_revision": EXPECTED_MATHLIB_REVISION,
                "lake_manifest_hash": EXPECTED_M_LAKE_MANIFEST_SHA256,
                "observed_axioms": axioms or [],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )


class FakeCompiler:
    def __init__(
        self,
        *,
        returncode: int = 0,
        stderr: bytes = b"",
        axioms: list[str] | None = None,
        declaration_override: str | None = None,
        mutate: Path | None = None,
    ) -> None:
        self.returncode = returncode
        self.stderr = stderr
        self.axioms = axioms
        self.declaration_override = declaration_override
        self.mutate = mutate
        self.calls: list[str] = []

    def compile(
        self,
        candidate: FatePatchedSourceV1,
        *,
        timeout_seconds: int,
    ) -> FateSmokeObservation:
        assert timeout_seconds == 20
        self.calls.append(candidate.task.task_id)
        if self.mutate is not None:
            self.mutate.write_bytes(b"changed")
        stdout = (
            _wrapper_payload(
                self.declaration_override or candidate.task.target.qualified_name,
                axioms=self.axioms,
            )
            if self.returncode == 0
            else b""
        )
        return FateSmokeObservation(
            returncode=self.returncode,
            stdout=stdout,
            stderr=self.stderr,
            elapsed_seconds=0.125,
            command_sha256="a" * 64,
        )


def _execute(
    tmp_path: Path,
    compiler: FateSmokeCompiler,
) -> dict[str, object]:
    fixture, adapter, checkout, _ = _fixture(tmp_path)
    times = iter(("2026-07-23T00:00:00.000Z", "2026-07-23T00:00:01.000Z"))
    return execute_static_smoke(
        fixture=fixture,
        adapter=adapter,
        checkout=checkout,
        runtime_evidence=_runtime(),
        compiler=compiler,
        timeout_seconds=20,
        clock=lambda: next(times),
    )


def test_static_smoke_is_separate_answer_free_and_non_promotable(tmp_path: Path) -> None:
    compiler = FakeCompiler()
    report = _execute(tmp_path, compiler)
    rendered = json.dumps(report, sort_keys=True)

    assert report["schema_version"] == REPORT_SCHEMA
    candidate_policy = cast(dict[str, object], report["candidate_policy"])
    assert candidate_policy["proof_search_executed"] is True
    assert candidate_policy["model_or_agent_executed"] is False
    assert candidate_policy["answer_sources_loaded"] is False
    assert candidate_policy["web_accessed"] is False
    verifier = cast(dict[str, object], report["verifier_boundary"])
    assert verifier["signing_gateway_executed"] is False
    assert verifier["promotable"] is False
    tiers = cast(dict[str, dict[str, object]], report["tiers"])
    assert tiers["M"]["summary"] == {
        "compiled_and_queried": 8,
        "not_verified": 0,
        "total": 8,
    }
    assert tiers["H"]["summary"] == {
        "compiled_and_queried": 0,
        "not_verified": 0,
        "total": 0,
    }
    assert tiers["X"]["summary"] == {
        "compiled_and_queried": 0,
        "not_verified": 0,
        "total": 0,
    }
    assert len(compiler.calls) == 8
    assert "theorem TargetM" not in rendered
    assert '"aesop"' not in rendered
    assert "sorry\n" not in rendered


def test_failed_diagnostics_are_hashed_not_retained(tmp_path: Path) -> None:
    report = _execute(
        tmp_path,
        FakeCompiler(returncode=20, stderr=b"secret theorem diagnostic"),
    )
    rendered = json.dumps(report, sort_keys=True)
    tiers = cast(dict[str, dict[str, object]], report["tiers"])
    first = cast(list[dict[str, object]], tiers["M"]["cases"])[0]

    assert first["result"] == "compile_or_query_failed"
    assert first["stderr_bytes"] == len(b"secret theorem diagnostic")
    assert "secret theorem diagnostic" not in rendered


def test_wrapper_declaration_spoof_fails_protocol(tmp_path: Path) -> None:
    report = _execute(
        tmp_path,
        FakeCompiler(declaration_override="Changed.ToTrue"),
    )
    tiers = cast(dict[str, dict[str, object]], report["tiers"])
    first = cast(list[dict[str, object]], tiers["M"]["cases"])[0]

    assert first["result"] == "verifier_protocol_failed"
    assert first["protocol_error"] == "smoke_wrapper_binding_mismatch"
    assert "canonical_type_sha256" not in first


def test_sorry_axiom_is_never_counted_as_success(tmp_path: Path) -> None:
    report = _execute(tmp_path, FakeCompiler(axioms=["sorryAx"]))
    tiers = cast(dict[str, dict[str, object]], report["tiers"])
    first = cast(list[dict[str, object]], tiers["M"]["cases"])[0]

    assert first["result"] == "axiom_policy_rejected"
    assert first["axiom_policy_passed"] is False
    assert tiers["M"]["summary"] == {
        "compiled_and_queried": 0,
        "not_verified": 8,
        "total": 8,
    }


def test_source_change_during_execution_fails_closed(tmp_path: Path) -> None:
    fixture, adapter, checkout, _ = _fixture(tmp_path)
    target = checkout / "FATE-M" / "FATEM" / "1.lean"
    compiler = FakeCompiler(mutate=target)

    with pytest.raises(FateSmokeError, match="smoke_source_changed_during_execution"):
        execute_static_smoke(
            fixture=fixture,
            adapter=adapter,
            checkout=checkout,
            runtime_evidence=_runtime(),
            compiler=compiler,
            timeout_seconds=20,
        )


def test_fixture_rejects_selection_drift(tmp_path: Path) -> None:
    fixture, _, _, _ = _fixture(tmp_path)

    with pytest.raises(FateSmokeError, match="smoke_selection_drift"):
        FateSmokeFixtureV1(
            manifest_sha256=fixture.manifest_sha256,
            split_manifest_sha256=fixture.split_manifest_sha256,
            root_commit=fixture.root_commit,
            submodules=fixture.submodules,
            toolchain=fixture.toolchain,
            mathlib_commit=fixture.mathlib_commit,
            lake_manifest_sha256=fixture.lake_manifest_sha256,
            cases=fixture.cases[:-1],
        )


def test_split_manifest_byte_drift_fails_before_checkout_access(tmp_path: Path) -> None:
    split = tmp_path / "splits.json"
    source_manifest = tmp_path / "source.json"
    split.write_text('{"schema_version":"changed"}', encoding="utf-8")
    source_manifest.write_text("{}", encoding="utf-8")

    with pytest.raises(FateSmokeError, match="smoke_split_manifest_byte_hash_drift"):
        load_verified_smoke_fixture(tmp_path / "missing", source_manifest, split)


def test_report_envelope_detects_uncoordinated_tampering(tmp_path: Path) -> None:
    report = _execute(tmp_path, FakeCompiler())
    envelope = report_envelope(report)
    validate_report_envelope(envelope)
    cast(dict[str, object], envelope["report"])["suite"] = "changed"

    with pytest.raises(FateSmokeError, match="smoke_report_hash_mismatch"):
        validate_report_envelope(envelope)


def test_report_write_is_exclusive_and_outside_checkout(tmp_path: Path) -> None:
    report = _execute(tmp_path, FakeCompiler())
    envelope = report_envelope(report)
    output = tmp_path / "evidence" / "smoke.json"
    checkout = tmp_path / "FATE"

    write_report_exclusive(output, envelope, forbidden_root=checkout)
    assert (
        json.loads(output.read_text(encoding="ascii"))["report_sha256"] == envelope["report_sha256"]
    )
    with pytest.raises(FateSmokeError, match="smoke_report_already_exists"):
        write_report_exclusive(output, envelope, forbidden_root=checkout)
    uncreated_checkout = tmp_path / "uncreated-FATE"
    inside = uncreated_checkout / "reports" / "report.json"
    with pytest.raises(FateSmokeError, match="smoke_report_inside_fate_checkout_refused"):
        write_report_exclusive(inside, envelope, forbidden_root=uncreated_checkout)
    assert not uncreated_checkout.exists()


def test_runtime_evidence_cannot_claim_image_owned_mathlib() -> None:
    rendered = _runtime().to_dict()

    assert rendered["image_contains_mathlib"] is False
    assert rendered["dependency_build_artifacts_attested"] is False
    assert rendered["verifier_program_ownership"] == "host_mounted_hash_bound"
