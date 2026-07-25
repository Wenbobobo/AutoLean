from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest


def _load_script(name: str) -> ModuleType:
    script = Path(__file__).resolve().parents[2] / "Library" / "scripts" / f"{name}.py"
    specification = importlib.util.spec_from_file_location(name, script)
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    assert isinstance(module, ModuleType)
    sys.modules[specification.name] = module
    sys.path.insert(0, str(script.parent))
    try:
        specification.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


VERIFY: Any = _load_script("verify_substrate_fixture")
CANARY: Any = _load_script("run_substrate_canary")
FIXTURE_ROOT = (
    Path(__file__).resolve().parents[2]
    / "Library"
    / "Staging"
    / ("round-02-model-theory-universal-lk-substrate")
)


def _fixture_copy(tmp_path: Path) -> Path:
    destination = tmp_path / "fixture"
    shutil.copytree(FIXTURE_ROOT, destination)
    return destination


def _profile(root: Path, filename: str) -> dict[str, object]:
    value = json.loads((root / "profiles" / filename).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def _write_profile(root: Path, filename: str, value: dict[str, object]) -> None:
    (root / "profiles" / filename).write_text(
        json.dumps(value, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )


def test_committed_source_split_and_profiles_pass() -> None:
    VERIFY.check()


def test_profiles_bind_distinct_runtime_closures_and_same_closed_sound_statement() -> None:
    independent = _profile(FIXTURE_ROOT, "independent_reproof.profile.v1.json")
    compositional = _profile(FIXTURE_ROOT, "compositional_bridge.profile.v1.json")

    assert independent["source_tree"] == compositional["source_tree"]
    assert independent["runtime_modules"] == [
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Core",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.SemanticPrelude",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.RulePrelude",
    ]
    assert compositional["runtime_modules"] == [
        *cast(list[str], independent["runtime_modules"]),
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.DerivSound",
    ]
    independent_policy = cast(dict[str, object], independent["ordinary_dependency_policy"])
    compositional_policy = cast(dict[str, object], compositional["ordinary_dependency_policy"])
    assert independent_policy["state"] == "no_ordinary_dependency"
    assert compositional_policy["state"] == "unadmitted_preflight_dependency"
    assert compositional_policy["unadmitted_dependency_declarations"] == [
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Deriv.sound"
    ]
    independent_candidate = cast(dict[str, object], independent["candidate_source"])
    compositional_candidate = cast(dict[str, object], compositional["candidate_source"])
    assert independent_candidate["statement_sha256"] == compositional_candidate["statement_sha256"]


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("source-drift", "source tree does not bind"),
        ("extra-source", "source module file set differs"),
        ("old-aggregate-import", "retained aggregate or packet import"),
        ("packet-import", "retained aggregate or packet import"),
        ("control-runtime-leak", "runtime module closure drifted"),
        ("target-runtime-leak", "runtime module closure drifted"),
        ("independent-deriv-sound-leak", "runtime module closure drifted"),
        ("compositional-unadmitted-erased", "must mark Deriv.sound as unadmitted"),
        ("candidate-import-leak", "candidate imports differ"),
        ("candidate-statement-drift", "historical namespace, binders, or type"),
    ),
)
def test_split_boundary_mutations_fail_closed(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    root = _fixture_copy(tmp_path)
    independent_name = "independent_reproof.profile.v1.json"
    compositional_name = "compositional_bridge.profile.v1.json"
    core = (
        root
        / "source"
        / "AutoLeanLibrary"
        / "Fixtures"
        / "ModelTheory"
        / "UniversalLK"
        / "Core.lean"
    )
    independent_candidate = root / "candidates" / "independent_reproof" / "Candidate.lean"

    if mutation == "source-drift":
        core.write_text(core.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    elif mutation == "extra-source":
        (core.parent / "Unexpected.lean").write_text("theorem unexpected : True := True.intro\n")
    elif mutation == "old-aggregate-import":
        core.write_text(
            "import AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK\n"
            + core.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
    elif mutation == "packet-import":
        core.write_text(
            "import AutoLeanLibrary.Fixtures.ModelTheory.Packet\n"
            + core.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
    elif mutation == "control-runtime-leak":
        profile = _profile(root, independent_name)
        profile["runtime_modules"] = [
            *cast(list[str], profile["runtime_modules"]),
            "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Controls",
        ]
        _write_profile(root, independent_name, profile)
    elif mutation == "target-runtime-leak":
        profile = _profile(root, compositional_name)
        profile["runtime_modules"] = [
            *cast(list[str], profile["runtime_modules"]),
            "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.ClosedSound",
        ]
        _write_profile(root, compositional_name, profile)
    elif mutation == "independent-deriv-sound-leak":
        profile = _profile(root, independent_name)
        profile["runtime_modules"] = [
            *cast(list[str], profile["runtime_modules"]),
            "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.DerivSound",
        ]
        _write_profile(root, independent_name, profile)
    elif mutation == "compositional-unadmitted-erased":
        profile = _profile(root, compositional_name)
        policy = cast(dict[str, object], profile["ordinary_dependency_policy"])
        policy["unadmitted_dependency_declarations"] = []
        _write_profile(root, compositional_name, profile)
    elif mutation == "candidate-import-leak":
        independent_candidate.write_text(
            "import AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK\n"
            + independent_candidate.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
    elif mutation == "candidate-statement-drift":
        independent_candidate.write_text(
            independent_candidate.read_text(encoding="utf-8").replace("ClosedAny M Δ", "True", 1),
            encoding="utf-8",
        )
    else:
        raise AssertionError(f"unhandled mutation: {mutation}")

    with pytest.raises(SystemExit, match=message):
        VERIFY.check(root)


def test_static_fallback_is_explicit_about_what_it_does_not_prove() -> None:
    result = CANARY.static_fallback("unit_test_no_docker")
    assert result["mode"] == "static_fallback"
    assert result["authority"] == "static-structural-preflight-only"
    assert result["image_inspected"] is False
    assert result["intended_parent_image"] == VERIFY.SOURCE_V2_IMAGE
    assert "image" not in result
    assert "no_lean_compile_observation" in result["non_claims"]
    assert "no_proof_admission" in result["non_claims"]


def test_real_canary_materializes_only_validated_profile_modules(tmp_path: Path) -> None:
    profiles = VERIFY.check()
    independent = profiles["independent_reproof"]
    compositional = profiles["compositional_bridge"]

    assert independent.runtime_modules == (
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Core",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.SemanticPrelude",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.RulePrelude",
    )
    assert compositional.runtime_modules == (
        *independent.runtime_modules,
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.DerivSound",
    )
    runtime = CANARY._materialize_runtime(FIXTURE_ROOT, tmp_path / "work", independent)
    materialized = {path.relative_to(runtime).as_posix() for path in runtime.rglob("*.lean")}
    assert materialized == {
        "AutoLeanLibrary/Fixtures/ModelTheory/UniversalLK/Core.lean",
        "AutoLeanLibrary/Fixtures/ModelTheory/UniversalLK/RulePrelude.lean",
        "AutoLeanLibrary/Fixtures/ModelTheory/UniversalLK/SemanticPrelude.lean",
        "Candidate.lean",
        "DirectDependencyQuery.lean",
    }
    script = CANARY._container_script(independent)
    assert "cp -R /fixture/source/" not in script
    for forbidden in independent.forbidden_modules:
        assert f"import {forbidden}\\n" in script
    assert script.count("forbidden runtime module unexpectedly imported:") == len(
        independent.forbidden_modules
    )


def test_real_canary_validates_and_materializes_only_from_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live_root = _fixture_copy(tmp_path)
    original_copy = CANARY._regular_tree_copy
    real_temporary_directory = tempfile.TemporaryDirectory
    observed: list[tuple[Path, Path, Any]] = []

    def copy_then_corrupt_live(source: Path, destination: Path) -> None:
        assert source == live_root
        original_copy(source, destination)
        (live_root / "profiles" / "independent_reproof.profile.v1.json").write_text(
            "{}\n", encoding="utf-8"
        )

    def fake_run(
        snapshot_root: Path,
        workspace_root: Path,
        profile: Any,
    ) -> dict[str, object]:
        observed.append((snapshot_root, workspace_root, profile))
        assert snapshot_root != live_root
        assert snapshot_root.name == "fixture-snapshot"
        assert workspace_root.name == "workspace"
        assert profile.candidate_path.startswith("candidates/")
        return {"task_mode": profile.task_mode}

    monkeypatch.setattr(CANARY, "FIXTURE_ROOT", live_root)
    monkeypatch.setattr(CANARY, "_docker_available", lambda: (True, "available"))
    monkeypatch.setattr(CANARY, "_require_ext4", lambda _path: None)
    monkeypatch.setattr(CANARY, "_regular_tree_copy", copy_then_corrupt_live)
    monkeypatch.setattr(CANARY, "_run_one_real", fake_run)
    monkeypatch.setattr(CANARY, "_validate_pair", lambda _observations: {"snapshot": True})
    monkeypatch.setattr(
        CANARY.tempfile,
        "TemporaryDirectory",
        lambda *args, **kwargs: real_temporary_directory(prefix=kwargs.get("prefix"), dir=tmp_path),
    )

    result = CANARY.real_canary()

    assert result["pair_validation"] == {"snapshot": True}
    assert [profile.task_mode for _, _, profile in observed] == [
        "independent_reproof",
        "compositional_bridge",
    ]
    assert len({snapshot for snapshot, _, _ in observed}) == 1


def test_snapshot_copy_rejects_symlinks(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    target = source / "target.txt"
    target.write_text("target\n", encoding="utf-8")
    link = source / "linked.txt"
    try:
        os.symlink(target, link)
    except OSError:
        pytest.skip("this Windows environment cannot create a test symlink")

    with pytest.raises(CANARY.CanaryError, match="contains a symlink"):
        CANARY._regular_tree_copy(source, tmp_path / "snapshot")


def test_real_canary_never_pulls_the_pinned_image() -> None:
    command = CANARY._docker_base()

    assert command[:4] == ["docker", "run", "--rm", "--pull=never"]


def test_profile_parser_rejects_unknown_field(tmp_path: Path) -> None:
    root = _fixture_copy(tmp_path)
    profile = _profile(root, "compositional_bridge.profile.v1.json")
    profile["unreviewed_field"] = True
    _write_profile(root, "compositional_bridge.profile.v1.json", profile)

    with pytest.raises(SystemExit, match="profile fields differ"):
        VERIFY.check(root)
