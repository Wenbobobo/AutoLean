from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import cast

import pytest

from benchmarks.fate import TIER_COUNTS, FateProblemId, Tier
from benchmarks.fate_adapter import (
    FateAdapter,
    FateFixtureIntegrityError,
    FateFixtureLockV1,
    FateFixtureManifestV1,
    FateFixtureTaskV1,
    FatePatchRejected,
    FateTargetV1,
    _git_commit,
    _verify_tracked_tree,
)


def _source(name: str, *, term_slot: bool = False, column_zero: bool = False) -> bytes:
    if term_slot:
        return f"import Mathlib\n\ntheorem {name} : True := sorry\n".encode()
    indentation = "" if column_zero else "  "
    return f"import Mathlib\n\ntheorem {name} : True := by\n{indentation}sorry\n".encode()


def _task(
    tier: str,
    number: int,
    *,
    source: bytes | None = None,
) -> FateFixtureTaskV1:
    problem = FateProblemId(cast(Tier, tier), number)
    source_path = f"FATE-{tier}/FATE{tier}/{number}.lean"
    return FateFixtureTaskV1.from_source(
        problem, source_path, source or _source(f"target_{tier}_{number}")
    )


def _manifest(target: FateFixtureTaskV1) -> FateFixtureManifestV1:
    lock = FateFixtureLockV1.load()
    tasks: list[FateFixtureTaskV1] = []
    for tier in ("M", "H", "X"):
        for number in range(1, TIER_COUNTS[tier] + 1):
            candidate = _task(tier, number)
            tasks.append(target if candidate.task_id == target.task_id else candidate)
    return FateFixtureManifestV1(
        root_commit=lock.root_commit,
        submodules=dict(lock.submodules),
        toolchain=lock.toolchain,
        mathlib_commit=lock.mathlib_revision,
        lake_manifest_sha256=dict(lock.lake_manifest_sha256),
        metadata_json_sha256=dict(lock.metadata_json_sha256),
        tasks=tuple(tasks),
    )


def _adapter(tmp_path: Path, source: bytes, *, tier: str = "M", number: int = 1) -> FateAdapter:
    target = _task(tier, number, source=source)
    source_path = tmp_path / target.source_path
    source_path.parent.mkdir(parents=True)
    source_path.write_bytes(source)
    manifest = _manifest(target)
    canonical_sources = {
        task.source_path: (
            source
            if task.task_id == target.task_id
            else _source(f"target_{task.split}_{task.task_id.rsplit('-', 1)[1]}")
        )
        for task in manifest.tasks
    }
    return FateAdapter(tmp_path, manifest, canonical_sources=canonical_sources)


def _git(cwd: Path, *args: str) -> str:
    completed = subprocess.run(
        ("git", "-C", str(cwd), *args),
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def test_adapter_replaces_only_the_pinned_sorry_token(tmp_path: Path) -> None:
    original = _source("target_M_1")
    adapter = _adapter(tmp_path, original)
    task = adapter.task("FATE-M-1")

    candidate = adapter.materialize_proof("FATE-M-1", "trivial")

    slot = task.proof_slot
    assert candidate.source[: slot.byte_start] == original[: slot.byte_start]
    assert candidate.source[slot.byte_start + len("trivial") :] == original[slot.byte_end :]
    assert b"sorry" not in candidate.source
    assert candidate.task.target.qualified_name == "target_M_1"


def test_adapter_rejects_fate_eval_true_theorem_replacement(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path, _source("target_M_1"))

    with pytest.raises(FatePatchRejected, match="declaration or command"):
        adapter.materialize_proof("FATE-M-1", "theorem target_M_1 : True := by trivial")


@pytest.mark.parametrize(
    "proof_body",
    (
        "exact True.intro\n  axiom unsound : False",
        "exact True.intro\nimport Mathlib",
        "exact sorry",
        "exact admit",
    ),
)
def test_adapter_rejects_commands_and_holes_inside_proof_body(
    tmp_path: Path,
    proof_body: str,
) -> None:
    adapter = _adapter(tmp_path, _source("target_M_1"))

    with pytest.raises(FatePatchRejected):
        adapter.materialize_proof("FATE-M-1", proof_body)


def test_adapter_uses_canonical_snapshot_when_worktree_drifts(tmp_path: Path) -> None:
    source = _source("target_M_1")
    adapter = _adapter(tmp_path, source)
    target_path = tmp_path / "FATE-M" / "FATEM" / "1.lean"
    target_path.write_bytes(source.replace(b": True :=", b": False :="))

    candidate = adapter.materialize_proof("FATE-M-1", "trivial")
    assert b": True := by\n  trivial" in candidate.source
    assert b": False :=" not in candidate.source


def test_task_rejects_path_traversal_and_multiple_proof_slots() -> None:
    with pytest.raises(FateFixtureIntegrityError, match="unsafe or unsupported"):
        FateFixtureTaskV1.from_source(
            FateProblemId("M", 1),
            "FATE-M/FATEM/../1.lean",
            _source("target_M_1"),
        )
    with pytest.raises(FateFixtureIntegrityError, match="exactly one"):
        FateFixtureTaskV1.from_source(
            FateProblemId("M", 1),
            "FATE-M/FATEM/1.lean",
            b"theorem target_M_1 : True := by\n  sorry\n  sorry\n",
        )


def test_term_and_column_zero_slots_remain_narrow(tmp_path: Path) -> None:
    term_source = _source("target_H_67", term_slot=True)
    term_adapter = _adapter(tmp_path / "term", term_source, tier="H", number=67)
    term_task = term_adapter.task("FATE-H-67")
    assert term_task.proof_slot.mode == "term"
    assert (
        b":= by\n  trivial" in term_adapter.materialize_proof("FATE-H-67", "by\n  trivial").source
    )

    zero_source = _source("target_H_93", column_zero=True)
    zero_adapter = _adapter(tmp_path / "zero", zero_source, tier="H", number=93)
    zero_task = zero_adapter.task("FATE-H-93")
    assert zero_task.proof_slot.mode == "tactic"
    assert zero_task.proof_slot.indentation == ""
    with pytest.raises(FatePatchRejected, match="column-zero"):
        zero_adapter.materialize_proof("FATE-H-93", "trivial\nexact True.intro")


def test_term_proof_cannot_dedent_to_an_indented_declaration_scope(tmp_path: Path) -> None:
    source = b"namespace Outer\n\n  theorem target_M_1 : True := sorry\n\nend Outer\n"
    adapter = _adapter(tmp_path, source)

    with pytest.raises(FatePatchRejected, match="remain indented"):
        adapter.materialize_proof("FATE-M-1", "by\n  trivial")


def test_proof_rejects_invisible_unicode_whitespace_before_command_scan(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path, _source("target_M_1"))

    with pytest.raises(FatePatchRejected, match="invisible"):
        adapter.materialize_proof("FATE-M-1", "exact True.intro\n  \u00a0axiom unsound : False")


def test_candidate_writer_rejects_checkout_and_dangling_link_destinations(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path / "checkout", _source("target_M_1"))

    with pytest.raises(FatePatchRejected, match="must not be inside"):
        adapter.write_candidate("FATE-M-1", "trivial", tmp_path / "checkout")

    attempt_root = tmp_path / "attempt"
    attempt_root.mkdir()
    destination = attempt_root / "FATE-M-1.lean"
    outside = tmp_path / "outside.lean"
    try:
        destination.symlink_to(outside)
    except OSError:
        pytest.skip("this Windows environment does not permit symlink creation")
    with pytest.raises(FatePatchRejected, match="destination already exists"):
        adapter.write_candidate("FATE-M-1", "trivial", attempt_root)
    assert not outside.exists()


def test_target_signature_cannot_be_rebased_inside_the_declaration() -> None:
    source = _source("target_M_1")
    task = _task("M", 1, source=source)
    slot = task.proof_slot
    rebased_target = FateTargetV1(
        qualified_name=task.target.qualified_name,
        declaration_start=task.target.declaration_start + 1,
        signature_sha256=hashlib.sha256(
            source[task.target.declaration_start + 1 : slot.byte_start]
        ).hexdigest(),
    )
    rebased = FateFixtureTaskV1(
        task_id=task.task_id,
        split=task.split,
        source_path=task.source_path,
        source_sha256=task.source_sha256,
        proof_slot=slot,
        target=rebased_target,
    )

    with pytest.raises(FateFixtureIntegrityError, match="target declaration identity"):
        rebased.validate_source(source)


def test_manifest_requires_exact_schema_and_bound_content_hash(tmp_path: Path) -> None:
    manifest = _manifest(_task("M", 1))
    path = manifest.write(tmp_path / "manifest.json")
    assert (
        FateFixtureManifestV1.load(
            path,
            expected_content_hash=manifest.content_hash,
        ).content_hash
        == manifest.content_hash
    )
    with pytest.raises(FateFixtureIntegrityError, match="content hash"):
        FateFixtureManifestV1.load(path, expected_content_hash="0" * 64)
    raw = manifest.to_dict()
    raw["untrusted_note"] = "ignored fields would defeat canonical artifact review"
    with pytest.raises(FateFixtureIntegrityError, match="unexpected fields"):
        FateFixtureManifestV1.from_dict(raw)


def test_tracked_tree_comparison_detects_assume_unchanged_source_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "autolean-test@example.invalid")
    _git(repo, "config", "user.name", "AutoLean Test")
    _git(repo, "config", "core.autocrlf", "false")
    source = repo / "trusted.lean"
    source.write_bytes(b"theorem trusted : True := by trivial\n")
    _git(repo, "add", "trusted.lean")
    _git(repo, "commit", "-m", "trusted fixture")
    commit = _git(repo, "rev-parse", "HEAD")

    monkeypatch.setenv("GIT_DIR", str(tmp_path / "malicious-git-dir"))
    assert _git_commit(repo) == commit
    assert _verify_tracked_tree(repo, commit, expected_gitlinks={})
    monkeypatch.delenv("GIT_DIR")

    _git(repo, "update-index", "--assume-unchanged", "trusted.lean")
    source.write_bytes(b"theorem trusted : False := by exact False.elim (by sorry)\n")
    assert _git(repo, "status", "--porcelain") == ""
    with pytest.raises(FateFixtureIntegrityError, match="locked Git blob"):
        _verify_tracked_tree(repo, commit, expected_gitlinks={})


def test_lock_keeps_legacy_version_but_normalizes_worker_toolchain() -> None:
    lock = FateFixtureLockV1.load()
    assert lock.lean_version == "v4.28.0"
    assert lock.toolchain == "leanprover/lean4:v4.28.0"
    with pytest.raises(TypeError):
        cast(dict[Tier, str], lock.submodules)["M"] = "0" * 40
