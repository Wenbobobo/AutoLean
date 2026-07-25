from __future__ import annotations

import importlib.util
import json
import shutil
import sys
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
    assert "no_lean_compile_observation" in result["non_claims"]
    assert "no_proof_admission" in result["non_claims"]


def test_real_canary_materializes_only_profile_selected_modules() -> None:
    independent = CANARY._profile_runtime_modules("independent_reproof")
    compositional = CANARY._profile_runtime_modules("compositional_bridge")

    assert independent == (
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Core",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.SemanticPrelude",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.RulePrelude",
    )
    assert compositional == (
        *independent,
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.DerivSound",
    )
    script = CANARY._container_script("independent_reproof", independent)
    assert "cp -R /fixture/source/" not in script
    assert "Targets.ClosedSound" in script
    assert "UniversalLK.Controls" in script


def test_profile_parser_rejects_unknown_field(tmp_path: Path) -> None:
    root = _fixture_copy(tmp_path)
    profile = _profile(root, "compositional_bridge.profile.v1.json")
    profile["unreviewed_field"] = True
    _write_profile(root, "compositional_bridge.profile.v1.json", profile)

    with pytest.raises(SystemExit, match="profile fields differ"):
        VERIFY.check(root)
