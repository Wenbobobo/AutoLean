"""Fail-closed structural checks for the staged target-free UniversalLK split.

This is deliberately a source/profile preflight.  It does not create a
Library runtime image, freeze a contract, or authorize a proof result.  The
optional Lean canary is implemented separately so CI can keep this check
entirely offline and static.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final, NoReturn

LIBRARY_ROOT: Final = Path(__file__).resolve().parents[1]
FIXTURE_ROOT: Final = LIBRARY_ROOT / "Staging" / "round-02-model-theory-universal-lk-substrate"
SOURCE_ROOT: Final = FIXTURE_ROOT / "source"
PROFILE_ROOT: Final = FIXTURE_ROOT / "profiles"
PROFILE_SCHEMA: Final = "autolean.library-substrate-profile.v2"
SOURCE_TREE_SCHEMA: Final = "autolean.library-substrate-source-tree.v2"
EXPECTED_TOOLCHAIN: Final = "leanprover/lean4:v4.28.0"
EXPECTED_MATHLIB_REVISION: Final = "8f9d9cff6bd728b17a24e163c9402775d9e6a365"
SOURCE_V2_IMAGE: Final = (
    "autolean/mathlib-worker@sha256:"
    "3237192cf627a05367c75d46e61ec9034fefe43a4fd0c06139e38c80358648d6"
)
TARGET_DECLARATION: Final = "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Deriv.closed_sound"
SOUND_DECLARATION: Final = "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Deriv.sound"
AGGREGATE_MODULE: Final = "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK"
PACKET_MODULE: Final = "AutoLeanLibrary.Fixtures.ModelTheory.Packet"
SHA256: Final = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class SourceModule:
    path: str
    module: str
    imports: tuple[str, ...]
    role: str


@dataclass(frozen=True)
class ValidatedProfileBoundary:
    """Execution inputs retained from one complete profile validation."""

    task_mode: str
    runtime_modules: tuple[str, ...]
    forbidden_modules: tuple[str, ...]
    candidate_path: str


MODULES: Final = (
    SourceModule(
        "source/AutoLeanLibrary/Fixtures/ModelTheory/UniversalLK/Core.lean",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Core",
        ("Mathlib.ModelTheory.Semantics",),
        "core",
    ),
    SourceModule(
        "source/AutoLeanLibrary/Fixtures/ModelTheory/UniversalLK/SemanticPrelude.lean",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.SemanticPrelude",
        ("AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Core",),
        "semantic_prelude",
    ),
    SourceModule(
        "source/AutoLeanLibrary/Fixtures/ModelTheory/UniversalLK/RulePrelude.lean",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.RulePrelude",
        ("AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.SemanticPrelude",),
        "rule_prelude",
    ),
    SourceModule(
        "source/AutoLeanLibrary/Fixtures/ModelTheory/UniversalLK/Targets/DerivSound.lean",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.DerivSound",
        ("AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.RulePrelude",),
        "unadmitted_dependency",
    ),
    SourceModule(
        "source/AutoLeanLibrary/Fixtures/ModelTheory/UniversalLK/Targets/ClosedSound.lean",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.ClosedSound",
        ("AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.DerivSound",),
        "target_oracle",
    ),
    SourceModule(
        "source/AutoLeanLibrary/Fixtures/ModelTheory/UniversalLK/Controls.lean",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Controls",
        ("AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.SemanticPrelude",),
        "offline_control",
    ),
)
MODULE_BY_NAME: Final = {item.module: item for item in MODULES}
SOURCE_FILES: Final = tuple(item.path for item in MODULES)
PROFILE_FILENAMES: Final = (
    "independent_reproof.profile.v1.json",
    "compositional_bridge.profile.v1.json",
)
EXPECTED_PROFILE_IDS: Final = {
    "independent_reproof": "library-substrate-v1-model-theory-universal-lk-independent-reproof",
    "compositional_bridge": "library-substrate-v1-model-theory-universal-lk-compositional-bridge",
}
EXPECTED_RUNTIME_MODULES: Final = {
    "independent_reproof": tuple(item.module for item in MODULES[:3]),
    "compositional_bridge": tuple(item.module for item in MODULES[:4]),
}
EXPECTED_CANDIDATES: Final = {
    "independent_reproof": "candidates/independent_reproof/Candidate.lean",
    "compositional_bridge": "candidates/compositional_bridge/Candidate.lean",
}
EXPECTED_CANDIDATE_IMPORT: Final = {
    "independent_reproof": "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.RulePrelude",
    "compositional_bridge": "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.DerivSound",
}
EXPECTED_FORBIDDEN_MODULES: Final = {
    "independent_reproof": (
        PACKET_MODULE,
        AGGREGATE_MODULE,
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Controls",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.ClosedSound",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.DerivSound",
    ),
    "compositional_bridge": (
        PACKET_MODULE,
        AGGREGATE_MODULE,
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Controls",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.ClosedSound",
    ),
}


def fail(message: str) -> NoReturn:
    raise SystemExit(f"Substrate fixture verification failed: {message}")


def _canonical_json_bytes(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        fail(f"value is not canonical JSON ({error})")
    return encoded.encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _safe_relative(relative: str) -> Path:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        fail("fixture path is not a safe POSIX relative path")
    return Path(*pure.parts)


def _regular_file(root: Path, relative: str, *, label: str) -> Path:
    candidate = root / _safe_relative(relative)
    if candidate.is_symlink() or not candidate.is_file():
        fail(f"{label} is missing, linked, or not a regular file ({relative})")
    return candidate


def _imports(path: Path) -> tuple[str, ...]:
    return tuple(
        line.removeprefix("import ")
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.startswith("import ")
    )


def _source_entry(module: SourceModule, root: Path) -> dict[str, str]:
    return {
        "module": module.module,
        "path": module.path,
        "role": module.role,
        "sha256": _sha256_bytes(
            _regular_file(root, module.path, label="source module").read_bytes()
        ),
    }


def source_tree(root: Path | None = None) -> dict[str, object]:
    fixture_root = FIXTURE_ROOT if root is None else root
    discovered_root = fixture_root / "source"
    if discovered_root.is_symlink() or not discovered_root.is_dir():
        fail("source root is missing, linked, or not a directory")
    discovered = tuple(
        sorted(
            (
                candidate.relative_to(fixture_root).as_posix()
                for candidate in discovered_root.rglob("*.lean")
                if candidate.is_file() and not candidate.is_symlink()
            ),
            key=lambda value: value.encode("utf-8"),
        )
    )
    if discovered != tuple(sorted(SOURCE_FILES, key=lambda value: value.encode("utf-8"))):
        fail("source module file set differs from the reviewed split")
    files = [_source_entry(module, fixture_root) for module in MODULES]
    digest = hashlib.sha256(SOURCE_TREE_SCHEMA.encode("ascii") + b"\n")
    for entry in files:
        digest.update(_canonical_json_bytes(entry))
        digest.update(b"\n")
    return {"schema_version": SOURCE_TREE_SCHEMA, "sha256": digest.hexdigest(), "files": files}


def _read_profile(path: Path) -> Mapping[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"profile is invalid ({path.name}: {error})")
    if not isinstance(value, dict):
        fail(f"profile root must be an object ({path.name})")
    return value


def _require_exact_keys(value: Mapping[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        fail(f"{label} fields differ from the reviewed schema")


def _require_mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def _require_sorted_unique_strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        fail(f"{label} must be an array of strings")
    result = tuple(value)
    if result != tuple(sorted(set(result), key=lambda item: item.encode("utf-8"))):
        fail(f"{label} must be sorted and unique in UTF-8 byte order")
    return result


def _require_unique_strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        fail(f"{label} must be an array of strings")
    result = tuple(value)
    if len(set(result)) != len(result):
        fail(f"{label} must not contain duplicates")
    return result


def _extract_target_signature(text: str) -> str:
    match = re.search(
        r"theorem Deriv\.closed_sound\s+\{Γ Δ : Side L 0\}\s+"
        r"\(derivation : Deriv L 0 Γ Δ\)\s*:\s*"
        r"ClosedAll M Γ → ClosedAny M Δ\s*:= by",
        text,
    )
    if match is None:
        fail(
            "closed_sound statement no longer preserves the historical namespace, binders, or type"
        )
    return re.sub(r"\s+", " ", match.group(0)).strip()


def target_statement(root: Path | None = None) -> dict[str, str]:
    fixture_root = FIXTURE_ROOT if root is None else root
    target = MODULE_BY_NAME["AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.ClosedSound"]
    signature = _extract_target_signature(
        _regular_file(fixture_root, target.path, label="target reference module").read_text(
            encoding="utf-8"
        )
    )
    return {
        "declaration": TARGET_DECLARATION,
        "statement_sha256": _sha256_bytes(signature.encode("utf-8")),
    }


def candidate_source(task_mode: str, root: Path | None = None) -> dict[str, str]:
    fixture_root = FIXTURE_ROOT if root is None else root
    path = EXPECTED_CANDIDATES[task_mode]
    candidate = _regular_file(fixture_root, path, label="candidate source")
    text = candidate.read_text(encoding="utf-8")
    if _imports(candidate) != (EXPECTED_CANDIDATE_IMPORT[task_mode],):
        fail(f"candidate imports differ from the {task_mode} runtime boundary")
    if _extract_target_signature(text) != _extract_target_signature(
        _regular_file(
            fixture_root,
            MODULE_BY_NAME[
                "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.ClosedSound"
            ].path,
            label="target reference module",
        ).read_text(encoding="utf-8")
    ):
        fail("candidate statement differs from the historical closed_sound statement")
    if task_mode == "independent_reproof" and "derivation.sound" in text:
        fail("independent candidate directly invokes Deriv.sound")
    if task_mode == "compositional_bridge" and "derivation.sound" not in text:
        fail("compositional candidate does not invoke the declared Deriv.sound dependency")
    return {
        "path": path,
        "sha256": _sha256_bytes(candidate.read_bytes()),
        **target_statement(fixture_root),
    }


def _check_source_modules(root: Path) -> None:
    for module in MODULES:
        path = _regular_file(root, module.path, label="source module")
        text = path.read_text(encoding="utf-8")
        imports = _imports(path)
        for forbidden in (AGGREGATE_MODULE, PACKET_MODULE):
            if forbidden in imports:
                fail(f"retained aggregate or packet import is present ({forbidden})")
        if imports != module.imports:
            fail(f"source imports differ from the reviewed split ({module.module})")
        if "namespace AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK" not in text:
            fail(f"source module changed the historical declaration namespace ({module.module})")
        if "AutoLeanStaging" in text:
            fail(f"source module retained a staging declaration namespace ({module.module})")
    if "theorem sound" in _regular_file(root, MODULES[2].path, label="rule prelude").read_text(
        encoding="utf-8"
    ):
        fail("rule prelude leaks Deriv.sound")
    if "theorem Deriv.closed_sound" in "\n".join(
        _regular_file(root, module.path, label="source module").read_text(encoding="utf-8")
        for module in MODULES
        if module.role not in {"target_oracle"}
    ):
        fail("target declaration leaks outside the target reference module")
    controls = _regular_file(root, MODULES[-1].path, label="offline controls").read_text(
        encoding="utf-8"
    )
    if "section RejectionControls" not in controls:
        fail("offline controls are missing their explicit review-only boundary")


def _check_source_tree(value: object, root: Path) -> None:
    source = _require_mapping(value, "source tree")
    _require_exact_keys(source, {"schema_version", "sha256", "files"}, "source tree")
    if source.get("schema_version") != SOURCE_TREE_SCHEMA:
        fail("source tree schema is unsupported")
    digest = source.get("sha256")
    if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
        fail("source tree digest is invalid")
    if source != source_tree(root):
        fail("source tree does not bind the current split modules")


def _check_target_binding(value: object) -> None:
    binding = _require_mapping(value, "target binding")
    _require_exact_keys(
        binding,
        {"state", "statement_contract_id", "statement_contract_revision", "target_declaration"},
        "target binding",
    )
    if binding != {
        "state": "unbound",
        "statement_contract_id": None,
        "statement_contract_revision": None,
        "target_declaration": None,
    }:
        fail("preflight fixture must not bind a target or statement contract")


def _check_environment(value: object) -> None:
    environment = _require_mapping(value, "environment")
    _require_exact_keys(
        environment,
        {
            "lean_toolchain",
            "mathlib_revision",
            "source_v2_parent_image",
            "library_substrate_image_digest",
            "state",
        },
        "environment",
    )
    if environment != {
        "lean_toolchain": EXPECTED_TOOLCHAIN,
        "mathlib_revision": EXPECTED_MATHLIB_REVISION,
        "source_v2_parent_image": SOURCE_V2_IMAGE,
        "library_substrate_image_digest": None,
        "state": "parent_image_canary_only",
    }:
        fail("preflight environment drifted")


def _check_dependency_policy(value: object, task_mode: str) -> None:
    policy = _require_mapping(value, "ordinary dependency policy")
    _require_exact_keys(
        policy,
        {
            "state",
            "formal_body_dependency_records",
            "unadmitted_dependency_declarations",
            "forbidden_declarations",
        },
        "ordinary dependency policy",
    )
    if policy.get("formal_body_dependency_records") != []:
        fail("preflight profile must not declare an accepted theorem dependency")
    unadmitted = _require_sorted_unique_strings(
        policy.get("unadmitted_dependency_declarations"),
        "ordinary dependency policy unadmitted declarations",
    )
    forbidden = _require_sorted_unique_strings(
        policy.get("forbidden_declarations"),
        "ordinary dependency policy forbidden declarations",
    )
    if task_mode == "independent_reproof":
        if policy.get("state") != "no_ordinary_dependency" or unadmitted != ():
            fail("independent profile dependency policy drifted")
        independent_forbidden = tuple(
            sorted(
                (SOUND_DECLARATION, TARGET_DECLARATION),
                key=lambda item: item.encode("utf-8"),
            )
        )
        if forbidden != independent_forbidden:
            fail("independent profile must forbid Deriv.sound and the target")
    else:
        if policy.get("state") != "unadmitted_preflight_dependency" or unadmitted != (
            SOUND_DECLARATION,
        ):
            fail("compositional profile must mark Deriv.sound as unadmitted")
        if forbidden != (TARGET_DECLARATION,):
            fail("compositional profile must forbid the target declaration")


def _check_runtime(value: object, task_mode: str) -> None:
    runtime = _require_unique_strings(value, "runtime modules")
    expected = EXPECTED_RUNTIME_MODULES[task_mode]
    if runtime != expected:
        fail(f"{task_mode} runtime module closure drifted")
    if "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.ClosedSound" in runtime:
        fail("target reference module leaks into runtime closure")
    if "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Controls" in runtime:
        fail("offline controls leak into runtime closure")
    if task_mode == "independent_reproof" and (
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.DerivSound" in runtime
    ):
        fail("DerivSound leaks into independent runtime closure")
    if task_mode == "compositional_bridge" and runtime[-1] != (
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.DerivSound"
    ):
        fail("compositional runtime must add DerivSound as its final closure member")


def check_profile(profile: Mapping[str, object], root: Path) -> None:
    _require_exact_keys(
        profile,
        {
            "schema_version",
            "profile_id",
            "profile_state",
            "task_mode",
            "source_root",
            "source_tree",
            "runtime_modules",
            "runtime_import_closure",
            "candidate_source",
            "forbidden_modules",
            "target_binding",
            "ordinary_dependency_policy",
            "environment",
            "non_claims",
        },
        "profile",
    )
    if profile.get("schema_version") != PROFILE_SCHEMA:
        fail("profile schema is unsupported")
    if profile.get("profile_state") != "preflight_fixture":
        fail("profile must remain a preflight fixture")
    task_mode = profile.get("task_mode")
    if task_mode not in EXPECTED_PROFILE_IDS:
        fail("profile task mode is unsupported")
    if profile.get("profile_id") != EXPECTED_PROFILE_IDS[task_mode]:
        fail("profile identifier does not match the task mode")
    if profile.get("source_root") != "source":
        fail("profile source root drifted")
    _check_source_tree(profile.get("source_tree"), root)
    _check_runtime(profile.get("runtime_modules"), task_mode)
    _check_runtime(profile.get("runtime_import_closure"), task_mode)
    if (
        _require_sorted_unique_strings(profile.get("forbidden_modules"), "forbidden modules")
        != EXPECTED_FORBIDDEN_MODULES[task_mode]
    ):
        fail("profile forbidden module boundary drifted")
    if profile.get("candidate_source") != candidate_source(task_mode, root):
        fail("profile does not bind its candidate source and historical target statement")
    _check_target_binding(profile.get("target_binding"))
    _check_dependency_policy(profile.get("ordinary_dependency_policy"), task_mode)
    _check_environment(profile.get("environment"))
    non_claims = _require_sorted_unique_strings(profile.get("non_claims"), "non-claims")
    for required in (
        "no_frozen_statement_contract",
        "no_library_substrate_image",
        "no_promoted_library_asset",
        "no_proof_admission",
    ):
        if required not in non_claims:
            fail(f"profile must retain non-admission boundary ({required})")


def check(root: Path | None = None) -> dict[str, ValidatedProfileBoundary]:
    fixture_root = FIXTURE_ROOT if root is None else root
    _check_source_modules(fixture_root)
    profile_paths = tuple(fixture_root / "profiles" / filename for filename in PROFILE_FILENAMES)
    if any(path.is_symlink() or not path.is_file() for path in profile_paths):
        fail("profile file is missing, linked, or not a regular file")
    profiles = tuple(_read_profile(path) for path in profile_paths)
    for profile in profiles:
        check_profile(profile, fixture_root)
    modes = tuple(profile["task_mode"] for profile in profiles)
    if modes != ("independent_reproof", "compositional_bridge"):
        fail("profile files do not cover the two reviewed task modes in order")
    if profiles[0]["source_tree"] != profiles[1]["source_tree"]:
        fail("the two profiles must bind the identical staged source tree")
    first = profiles[0]["candidate_source"]
    second = profiles[1]["candidate_source"]
    if (
        not isinstance(first, dict)
        or not isinstance(second, dict)
        or first["statement_sha256"] != second["statement_sha256"]
    ):
        fail("candidate statements are not bound to the same historical closed_sound type")
    validated: dict[str, ValidatedProfileBoundary] = {}
    for profile in profiles:
        task_mode = profile["task_mode"]
        if not isinstance(task_mode, str):
            fail("validated task mode is not a string")
        candidate = _require_mapping(profile["candidate_source"], "candidate source")
        candidate_path = candidate["path"]
        if not isinstance(candidate_path, str):
            fail("validated candidate path is not a string")
        validated[task_mode] = ValidatedProfileBoundary(
            task_mode=task_mode,
            runtime_modules=_require_unique_strings(profile["runtime_modules"], "runtime modules"),
            forbidden_modules=_require_sorted_unique_strings(
                profile["forbidden_modules"], "forbidden modules"
            ),
            candidate_path=candidate_path,
        )
    return validated


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("check", help="validate the complete source split and both profiles")
    subparsers.add_parser("hash-source", help="print canonical source and target bindings")
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    namespace = parse_arguments(arguments)
    if namespace.command == "check":
        check()
        print("target-free UniversalLK substrate split: passed")
        return 0
    if namespace.command == "hash-source":
        print(
            json.dumps(
                {"source_tree": source_tree(), "target_statement": target_statement()},
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    fail("unsupported command")


if __name__ == "__main__":
    raise SystemExit(main())
