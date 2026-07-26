"""Build and exercise the image-owned UniversalLK independent-reproof substrate.

This is an operator-local preflight.  It deliberately stops before contracts,
the signing gateway, provider execution, external dependency capsules, or
admission of any Builder asset.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Final, Literal, NoReturn, cast

if __package__ in {None, ""}:
    repository_root = str(Path(__file__).resolve().parents[2])
    if repository_root not in sys.path:
        sys.path.insert(0, repository_root)

from Library.scripts.verify_substrate_fixture import (
    EXPECTED_MATHLIB_REVISION,
    EXPECTED_PROFILE_IDS,
    FIXTURE_ROOT,
    MODULE_BY_NAME,
    SOUND_DECLARATION,
    SOURCE_V2_IMAGE,
    TARGET_DECLARATION,
    ValidatedProfileBoundary,
    check,
)

WSL_DISTRIBUTION: Final = "Ubuntu-24.04"
IMAGE_TAG: Final = "autolean/library-substrate:4.28.0-universal-lk-builder-query-preflight-v2"
IMAGE_REPOSITORY: Final = "autolean/library-substrate"
IMAGE_DIGEST_RE: Final = re.compile(r"^autolean/library-substrate@sha256:[0-9a-f]{64}$")
SHA256_RE: Final = re.compile(r"^[0-9a-f]{64}$")
TARGET_TYPE_SHA256: Final = "66d1fe3cbd2a62831bf57b9761248bf3fa5d84b95879be25c7e591c48ebeef8a"
EXPECTED_TARGET_AXIOMS: Final = ("Classical.choice", "Quot.sound", "propext")
ALLOWED_RUNTIME_AXIOMS: Final = frozenset(EXPECTED_TARGET_AXIOMS)
PROFILE_PATH: Final = FIXTURE_ROOT / "profiles" / "independent_reproof.profile.v1.json"
CANDIDATE_PATH: Final = FIXTURE_ROOT / "candidates" / "independent_reproof" / "Candidate.lean"
WORKER_ROOT: Final = Path(__file__).resolve().parents[2] / "Prover" / "worker"
DOCKERFILE: Final = WORKER_ROOT / "Dockerfile.library-substrate"
HELPER_ROOT: Final = WORKER_ROOT / "library-substrate"
ASSETS: Final = {
    "AutoleanLibrarySubstrateBuilderQuery.lean": "BUILDER_QUERY_HELPER_SHA256",
    "AutoleanLibrarySubstrateInventory.lean": "INVENTORY_HELPER_SHA256",
    "AutoleanLibrarySubstrateV2Query.lean": "V2_FACADE_QUERY_HELPER_SHA256",
    "autolean-library-substrate-build": "BUILD_TOOL_SHA256",
    "autolean-library-substrate-build-receipt": "RECEIPT_TOOL_SHA256",
    "autolean-library-substrate-builder-query": "BUILDER_QUERY_WRAPPER_SHA256",
    "autolean-library-substrate-independent-query": "QUERY_WRAPPER_SHA256",
    "autolean-library-substrate-v2-facade": "V2_FACADE_WRAPPER_SHA256",
}
RUNTIME_MANIFEST_SCHEMA: Final = "autolean.library-substrate-runtime-manifest.v1"
DECLARATION_INVENTORY_SCHEMA: Final = "autolean.library-substrate-declaration-inventory.v1"
IMAGE_RECEIPT_SCHEMA: Final = "autolean.library-substrate-image-receipt.v2"
QUERY_SCHEMA: Final = "autolean.library-substrate-independent-query.v1"
CANARY_SCHEMA: Final = "autolean.library-substrate-independent-canary.v1"
BUILDER_QUERY_SCHEMA: Final = "autolean.library-substrate-builder-query.v1"
BUILDER_QUERY_CANARY_SCHEMA: Final = "autolean.library-substrate-builder-query-canary.v1"
BUILDER_QUERY_WRAPPER_PATH: Final = (
    "/opt/autolean/library-substrate/bin/autolean-library-substrate-builder-query"
)
BUILDER_QUERY_HELPER_PATH: Final = "/opt/autolean/lib/AutoleanLibrarySubstrateBuilderQuery.lean"
BUILDER_QUERY_FAILURE_DIAGNOSTIC_LIMIT: Final = 4096
RUNTIME_SOURCE_CHECKSUM_FILENAME: Final = "runtime-sources.sha256"
RUNTIME_FILE_CHECKSUM_FILENAME: Final = "runtime-files.sha256"
V2_FACADE_CANARY_SCHEMA: Final = "autolean.library-substrate-v2-facade-canary.v2"
V2_WRAPPER_PATH: Final = "/opt/autolean/bin/autolean-lean-wrapper"
V2_QUERY_HELPER_PATH: Final = "/opt/autolean/lib/AutoleanLeanQuery.lean"
V2_RESULT_SCHEMA: Final = "autolean.oci-lean-wrapper.v2"
V2_LAKE_MANIFEST_SHA256: Final = "e2a93c904f51195d6740cd9abfb35ab155dc0157e0e46642dce0d364b68a9a89"
V2_FACADE_FAILURE_DIAGNOSTIC_LIMIT: Final = 4096
V2_COMPOSITIONAL_CANDIDATE_SHA256: Final = (
    "98cd1d2ae8f48ca368d19c64ddec447185bf13753a8d87dbf79df49bf33a7f78"
)
V2_TARGET_IMPORT_SOURCE: Final = (
    "import AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.ClosedSound\n"
)
V2_TARGET_IMPORT_SOURCE_SHA256: Final = (
    "c1725f40b0091501aaf465cefe318231af157b51ab3ffef9a8669bcb09ee4d4a"
)
V2_WRONG_TARGET_TYPE_SOURCE: Final = """\
import AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.RulePrelude

namespace AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK

theorem Deriv.closed_sound : True := by
  trivial

end AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK
"""
V2_WRONG_TARGET_TYPE_SOURCE_SHA256: Final = (
    "f938b08d4e6d9de5e0288207f68ccc3122a5bd96dc08c885b71ba98a52919323"
)
BUILDER_QUERY_TARGET: Final = "Candidate.ClosedSoundStatement"
BUILDER_QUERY_SOURCE: Final = """\
import AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.RulePrelude

namespace Candidate

open FirstOrder
open FirstOrder.Language
open AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK

universe u

axiom ClosedSoundStatement {L : FirstOrder.Language} {M : Type u} [L.Structure M]
    {Γ Δ : Side L 0} (derivation : Deriv L 0 Γ Δ) :
    ClosedAll M Γ → ClosedAny M Δ

end Candidate
"""
BUILDER_QUERY_THEOREM_SOURCE: Final = """\
import AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.RulePrelude

namespace Candidate

theorem ClosedSoundStatement : True := by
  trivial

end Candidate
"""
BUILDER_QUERY_EXTRA_DECLARATION_SOURCE: Final = BUILDER_QUERY_SOURCE.replace(
    "\nend Candidate\n", "\naxiom ExtraCarrier : True\n\nend Candidate\n"
)
BUILDER_QUERY_FORBIDDEN_IMPORT_SOURCE: Final = """\
import Mathlib

namespace Candidate

axiom ClosedSoundStatement : True

end Candidate
"""
BUILDER_QUERY_TARGET_IMPORT_SOURCE: Final = """\
import AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.ClosedSound

namespace Candidate

axiom ClosedSoundStatement : True

end Candidate
"""
BUILDER_QUERY_MISSING_TARGET_SOURCE: Final = """\
import AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.RulePrelude

namespace Candidate

axiom OtherStatement : True

end Candidate
"""
BUILDER_QUERY_TRUE_SOURCE: Final = """\
import AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.RulePrelude

namespace Candidate

axiom ClosedSoundStatement : True

end Candidate
"""


class SubstrateImageError(RuntimeError):
    """A fail-closed build input, image receipt, or canary error."""


def fail(message: str) -> NoReturn:
    raise SubstrateImageError(message)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _canonical_json_bytes(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise SubstrateImageError("value is not canonical JSON") from error
    return (rendered + "\n").encode("utf-8")


def _canonical_json_compact_bytes(value: object) -> bytes:
    return _canonical_json_bytes(value).removesuffix(b"\n")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            fail(f"JSON contains duplicate key: {key}")
        value[key] = item
    return value


def _json_record(raw: str, *, label: str) -> dict[str, object]:
    lines = raw.splitlines()
    if len(lines) != 1:
        fail(f"{label} did not emit exactly one JSON record")
    try:
        value = json.loads(lines[0], object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise SubstrateImageError(f"{label} did not emit valid JSON") from error
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        fail(f"{label} must be a JSON object")
    return cast(dict[str, object], value)


def _run(
    command: list[str],
    *,
    timeout: int,
    cwd: Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=None if environment is None else dict(environment),
            check=False,
            capture_output=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise SubstrateImageError("subprocess execution failed") from error
    stdout = completed.stdout.decode("utf-8", errors="replace")
    stderr = completed.stderr.decode("utf-8", errors="replace")
    result = subprocess.CompletedProcess(command, completed.returncode, stdout, stderr)
    if result.returncode != 0:
        detail = (result.stdout + "\n" + result.stderr)[-12000:]
        raise SubstrateImageError(f"subprocess failed ({command[0]}): {detail}")
    return result


def _safe_relative(value: str) -> Path:
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        fail("path is not a safe POSIX relative path")
    return Path(*pure.parts)


def _regular_bytes(path: Path, *, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise SubstrateImageError(f"{label} is unavailable") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        fail(f"{label} must be an unlinked regular file")
    value = path.read_bytes()
    after = path.lstat()
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        fail(f"{label} changed while being read")
    return value


def _inspect(image: str) -> dict[str, object]:
    raw = _run(["docker", "image", "inspect", image], timeout=60).stdout
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError as error:
        raise SubstrateImageError("Docker image inspection was not JSON") from error
    if not isinstance(loaded, list) or len(loaded) != 1 or not isinstance(loaded[0], dict):
        fail("Docker returned an unexpected image inspection record")
    return cast(dict[str, object], loaded[0])


def _child_image_reference(inspected: Mapping[str, object]) -> str:
    repo_digests = inspected.get("RepoDigests")
    if not isinstance(repo_digests, list):
        fail("built child image has no repository digest list")
    matching = sorted(
        item
        for item in repo_digests
        if isinstance(item, str)
        and item.startswith(f"{IMAGE_REPOSITORY}@sha256:")
        and IMAGE_DIGEST_RE.fullmatch(item)
    )
    if not matching:
        fail("built child image has no Docker-recorded autolean/library-substrate RepoDigest")
    return matching[0]


def _docker_run_base(*, read_only: bool = True) -> list[str]:
    command = [
        "docker",
        "run",
        "--rm",
        "--pull=never",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "128",
        "--memory",
        "2g",
        "--tmpfs",
        "/tmp:rw,exec,nosuid,nodev,size=256m,mode=1777",
    ]
    if read_only:
        command.append("--read-only")
    return command


def _parent_receipt() -> tuple[dict[str, object], str, str, dict[str, object]]:
    inspected = _inspect(SOURCE_V2_IMAGE)
    repo_digests = inspected.get("RepoDigests")
    if not isinstance(repo_digests, list) or SOURCE_V2_IMAGE not in repo_digests:
        fail("source-v2 parent inspect record does not contain its required RepoDigest")
    output = _run(
        [
            *_docker_run_base(),
            SOURCE_V2_IMAGE,
            "/opt/autolean/bin/autolean-mathlib-build-receipt",
        ],
        timeout=240,
    ).stdout
    receipt = _json_record(output, label="source-v2 parent receipt")
    if (
        receipt.get("schema_version") != "autolean.mathlib-source-build-receipt.v2"
        or receipt.get("mathlib_revision") != EXPECTED_MATHLIB_REVISION
    ):
        fail("source-v2 parent receipt does not match the locked profile")
    canonical = _canonical_json_bytes(receipt)
    raw_hash_output = _run(
        [
            *_docker_run_base(),
            "--entrypoint",
            "/usr/bin/sha256sum",
            SOURCE_V2_IMAGE,
            "/opt/autolean/attestations/mathlib-source-build-receipt.v2.json",
        ],
        timeout=120,
    ).stdout
    raw_hash = raw_hash_output.strip().split(" ", maxsplit=1)[0]
    if not SHA256_RE.fullmatch(raw_hash):
        fail("source-v2 parent receipt file hash is unavailable")
    return receipt, _sha256_bytes(canonical), raw_hash, inspected


def _profile() -> tuple[ValidatedProfileBoundary, dict[str, object]]:
    profiles = check()
    profile = profiles.get("independent_reproof")
    if profile is None or profile.task_mode != "independent_reproof":
        fail("independent_reproof profile was not validated")
    raw = _regular_bytes(PROFILE_PATH, label="independent profile")
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise SubstrateImageError("independent profile is not JSON") from error
    if not isinstance(value, dict):
        fail("independent profile must be an object")
    return profile, cast(dict[str, object], value)


def _runtime_source_records(
    profile: ValidatedProfileBoundary,
    *,
    source_root: Path = FIXTURE_ROOT / "source",
) -> tuple[list[dict[str, object]], str]:
    records: list[dict[str, object]] = []
    for module in profile.runtime_modules:
        source = MODULE_BY_NAME[module]
        relative = _safe_relative(source.path.removeprefix("source/"))
        path = source_root / relative
        content = _regular_bytes(path, label=f"runtime source {module}")
        records.append(
            {
                "module": module,
                "path": relative.as_posix(),
                "role": source.role,
                "sha256": _sha256_bytes(content),
                "size": len(content),
            }
        )
    return records, _sha256_bytes(_canonical_json_bytes(records))


def _checksum_manifest_bytes(
    records: Sequence[Mapping[str, object]], *, path_prefix: str = ""
) -> bytes:
    lines: list[str] = []
    for record in records:
        path = record.get("path")
        digest = record.get("sha256")
        if (
            not isinstance(path, str)
            or not isinstance(digest, str)
            or not SHA256_RE.fullmatch(digest)
        ):
            fail("checksum manifest record is invalid")
        relative = _safe_relative(path).as_posix()
        lines.append(f"{digest}  {path_prefix}{relative}\n")
    return "".join(lines).encode("ascii")


def _validate_runtime_source_binding(
    build_input: Mapping[str, object],
    profile: ValidatedProfileBoundary,
    *,
    source_root: Path,
    source_checksums: bytes,
) -> tuple[list[dict[str, object]], str]:
    records, tree_sha256 = _runtime_source_records(profile, source_root=source_root)
    if build_input.get("runtime_sources") != records:
        fail("runtime source records differ from the actual staged source bytes")
    if build_input.get("runtime_source_tree_sha256") != tree_sha256:
        fail("runtime source tree hash differs from the actual staged source bytes")
    expected_checksums = _checksum_manifest_bytes(records, path_prefix="source/")
    if source_checksums != expected_checksums:
        fail("runtime source checksum manifest differs from the actual staged source bytes")
    checksum_sha256 = _sha256_bytes(source_checksums)
    if build_input.get("runtime_source_checksum_manifest_sha256") != checksum_sha256:
        fail("runtime source checksum manifest is not bound by the build input")
    return records, tree_sha256


def _asset_hashes() -> dict[str, str]:
    values = {"DOCKERFILE_SHA256": _sha256(DOCKERFILE)}
    for filename, argument in ASSETS.items():
        values[argument] = _sha256(HELPER_ROOT / filename)
    return values


def _build_input() -> tuple[
    dict[str, object],
    bytes,
    ValidatedProfileBoundary,
    dict[str, str],
    str,
]:
    profile, profile_record = _profile()
    (
        parent_receipt,
        parent_receipt_sha256,
        parent_receipt_file_sha256,
        parent_inspected,
    ) = _parent_receipt()
    sources, source_tree_sha256 = _runtime_source_records(profile)
    source_checksums = _checksum_manifest_bytes(sources, path_prefix="source/")
    assets = _asset_hashes()
    parent_image_id = parent_inspected.get("Id")
    if not isinstance(parent_image_id, str) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", parent_image_id
    ):
        fail("source-v2 parent has no immutable image ID")
    value: dict[str, object] = {
        "assets": dict(sorted(assets.items())),
        "build_context_policy": {
            "flags": ["--no-cache", "--pull=false", "--network=none"],
            "only_profile_runtime_sources": True,
        },
        "mathlib_revision": EXPECTED_MATHLIB_REVISION,
        "parent_image": SOURCE_V2_IMAGE,
        "parent_image_id": parent_image_id,
        "parent_receipt": parent_receipt,
        "parent_receipt_canonical_sha256": parent_receipt_sha256,
        "parent_receipt_file_sha256": parent_receipt_file_sha256,
        "profile_id": EXPECTED_PROFILE_IDS["independent_reproof"],
        "profile_sha256": _sha256_bytes(_canonical_json_bytes(profile_record)),
        "runtime_modules": list(profile.runtime_modules),
        "runtime_source_checksum_manifest_sha256": _sha256_bytes(source_checksums),
        "runtime_source_tree_sha256": source_tree_sha256,
        "runtime_sources": sources,
        "schema_version": "autolean.library-substrate-build-input.v1",
        "task_mode": "independent_reproof",
        "target": {
            "canonical_type_sha256": TARGET_TYPE_SHA256,
            "declaration": TARGET_DECLARATION,
            "forbidden_ordinary_dependency": SOUND_DECLARATION,
        },
    }
    return value, _canonical_json_bytes(value), profile, assets, source_tree_sha256


def _copy_regular(source: Path, destination: Path, *, executable: bool = False) -> None:
    content = _regular_bytes(source, label=str(source))
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)
    destination.chmod(0o555 if executable else 0o444)


def stage_build_context(root: Path) -> tuple[dict[str, object], dict[str, str]]:
    (
        build_input,
        build_input_bytes,
        profile,
        assets,
        source_tree_sha256,
    ) = _build_input()
    root.mkdir(parents=True, exist_ok=False)
    _copy_regular(DOCKERFILE, root / "Dockerfile.library-substrate")
    for filename in ASSETS:
        _copy_regular(
            HELPER_ROOT / filename,
            root / "helpers" / filename,
            executable=not filename.endswith(".lean"),
        )
    sources = cast(list[dict[str, object]], build_input["runtime_sources"])
    for record in sources:
        relative = cast(str, record["path"])
        source = FIXTURE_ROOT / "source" / _safe_relative(relative)
        _copy_regular(source, root / "source" / _safe_relative(relative))
    (root / "build-input.v1.json").write_bytes(build_input_bytes)
    (root / "build-input.v1.json").chmod(0o444)
    source_checksums = _checksum_manifest_bytes(sources, path_prefix="source/")
    (root / RUNTIME_SOURCE_CHECKSUM_FILENAME).write_bytes(source_checksums)
    (root / RUNTIME_SOURCE_CHECKSUM_FILENAME).chmod(0o444)
    _, staged_source_tree_sha256 = _validate_runtime_source_binding(
        build_input,
        profile,
        source_root=root / "source",
        source_checksums=source_checksums,
    )
    if staged_source_tree_sha256 != source_tree_sha256:
        fail("staged runtime source tree differs from the frozen build input")

    inventory: dict[str, str] = {}
    for candidate in sorted(root.rglob("*")):
        relative = candidate.relative_to(root).as_posix()
        if candidate.is_symlink():
            fail("fresh build context contains a symbolic link")
        if candidate.is_file():
            inventory[relative] = _sha256(candidate)
        elif not candidate.is_dir():
            fail("fresh build context contains a non-regular entry")
    expected = {
        "Dockerfile.library-substrate",
        "build-input.v1.json",
        RUNTIME_SOURCE_CHECKSUM_FILENAME,
        *(f"helpers/{name}" for name in ASSETS),
        *(f"source/{cast(str, item['path'])}" for item in sources),
    }
    if set(inventory) != expected:
        fail("fresh build context inventory is not exact")
    forbidden_fragments = ("/Targets/", "/Controls.", "Candidate.lean", "UniversalLK.lean")
    if any(fragment in f"/{path}" for path in inventory for fragment in forbidden_fragments):
        fail("fresh build context contains a target, control, aggregate, or Candidate source")
    arguments = {
        **assets,
        "BUILD_INPUT_SHA256": _sha256_bytes(build_input_bytes),
        "PARENT_RECEIPT_CANONICAL_SHA256": cast(
            str, build_input["parent_receipt_canonical_sha256"]
        ),
        "PARENT_RECEIPT_FILE_SHA256": cast(str, build_input["parent_receipt_file_sha256"]),
        "RUNTIME_SOURCE_CHECKSUM_MANIFEST_SHA256": cast(
            str, build_input["runtime_source_checksum_manifest_sha256"]
        ),
        "RUNTIME_SOURCE_TREE_SHA256": source_tree_sha256,
    }
    return {
        "build_input": build_input,
        "build_input_sha256": arguments["BUILD_INPUT_SHA256"],
        "context_inventory": inventory,
        "context_inventory_sha256": _sha256_bytes(_canonical_json_bytes(inventory)),
        "profile": {
            "candidate_path": profile.candidate_path,
            "forbidden_modules": list(profile.forbidden_modules),
            "runtime_modules": list(profile.runtime_modules),
            "task_mode": profile.task_mode,
        },
    }, arguments


def _build_command(context: Path, arguments: Mapping[str, str]) -> list[str]:
    command = [
        "docker",
        "build",
        "--no-cache",
        "--pull=false",
        "--network=none",
        "--file",
        "Dockerfile.library-substrate",
        "--tag",
        IMAGE_TAG,
    ]
    for name, value in sorted(arguments.items()):
        command.extend(("--build-arg", f"{name}={value}"))
    command.append(str(context))
    return command


def build() -> dict[str, object]:
    temporary_parent = Path("/tmp")
    with tempfile.TemporaryDirectory(
        prefix="autolean-library-substrate-image-", dir=temporary_parent
    ) as raw:
        context = Path(raw) / "context"
        prepared, arguments = stage_build_context(context)
        _run(
            _build_command(context, arguments),
            timeout=1800,
            cwd=context,
        )
    inspected = _inspect(IMAGE_TAG)
    image = _child_image_reference(inspected)
    image_id = inspected.get("Id")
    if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        fail("built child image has no immutable image ID")
    verified = verify(image)
    return {
        "build_input_sha256": prepared["build_input_sha256"],
        "context_inventory": prepared["context_inventory"],
        "context_inventory_sha256": prepared["context_inventory_sha256"],
        "image": image,
        "image_id": image_id,
        "schema_version": "autolean.library-substrate-image-build.v1",
        "verification": verified,
    }


def _receipt_output(image: str) -> tuple[dict[str, object], str]:
    if not IMAGE_DIGEST_RE.fullmatch(image):
        fail("child receipt verification requires a Docker-recorded repository digest")
    output = _run(
        [
            *_docker_run_base(),
            image,
            "/opt/autolean/library-substrate/bin/autolean-library-substrate-build-receipt",
        ],
        timeout=240,
    ).stdout
    return (
        _json_record(output, label="library substrate image receipt"),
        _sha256_bytes(output.encode("utf-8")),
    )


def _read_image_json(image: str, path: str, *, label: str) -> tuple[dict[str, object], str]:
    output = _read_image_text(image, path)
    record = _json_record(output, label=label)
    return record, _sha256_bytes(output.encode("utf-8"))


def _read_image_text(image: str, path: str) -> str:
    return _run(
        [
            *_docker_run_base(),
            "--entrypoint",
            "/bin/cat",
            image,
            path,
        ],
        timeout=120,
    ).stdout


def _image_file_sha256_and_size(image: str, path: str, *, label: str) -> tuple[str, int]:
    digest_output = _run(
        [
            *_docker_run_base(),
            "--entrypoint",
            "/usr/bin/sha256sum",
            image,
            path,
        ],
        timeout=120,
    ).stdout
    digest_fields = digest_output.strip().split(maxsplit=1)
    if len(digest_fields) != 2 or not SHA256_RE.fullmatch(digest_fields[0]):
        fail(f"{label} hash is unavailable from the fixed child digest")
    size_output = _run(
        [
            *_docker_run_base(),
            "--entrypoint",
            "/usr/bin/wc",
            image,
            "-c",
            path,
        ],
        timeout=120,
    ).stdout
    size_fields = size_output.strip().split(maxsplit=1)
    if len(size_fields) != 2 or not size_fields[0].isdigit() or int(size_fields[0]) <= 0:
        fail(f"{label} size is unavailable from the fixed child digest")
    return digest_fields[0], int(size_fields[0])


def _image_file_sha256(image: str, path: str, *, label: str) -> str:
    output = _run(
        [
            *_docker_run_base(),
            "--entrypoint",
            "/usr/bin/sha256sum",
            image,
            path,
        ],
        timeout=120,
    ).stdout.strip()
    fields = output.split(maxsplit=1)
    if len(fields) != 2 or not SHA256_RE.fullmatch(fields[0]):
        fail(f"{label} hash is unavailable")
    return fields[0]


def _sorted_unique_strings(value: object, *, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        fail(f"{label} must be a string array")
    strings = cast(list[str], value)
    if strings != sorted(set(strings)):
        fail(f"{label} must be sorted and unique")
    return tuple(strings)


def _runtime_files(manifest: Mapping[str, object]) -> dict[str, dict[str, object]]:
    raw = manifest.get("runtime_files")
    if not isinstance(raw, list) or len(raw) != 3:
        fail("runtime manifest must contain exactly three OLean files")
    result: dict[str, dict[str, object]] = {}
    for item in raw:
        if not isinstance(item, dict) or set(item) != {"module", "path", "sha256", "size"}:
            fail("runtime file record schema drifted")
        record = cast(dict[str, object], item)
        module = record["module"]
        path = record["path"]
        digest = record["sha256"]
        size = record["size"]
        if (
            not isinstance(module, str)
            or not isinstance(path, str)
            or not path.endswith(".olean")
            or not SHA256_RE.fullmatch(cast(str, digest))
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
        ):
            fail("runtime file record is invalid")
        if module in result:
            fail("runtime manifest repeats a module")
        result[module] = record
    return result


def _validate_runtime_file_closure(
    image: str,
    runtime_files: Mapping[str, Mapping[str, object]],
    *,
    manifest: Mapping[str, object],
    receipt: Mapping[str, object],
) -> dict[str, dict[str, object]]:
    actual_records: list[dict[str, object]] = []
    actual_files: dict[str, dict[str, object]] = {}
    for module, record in runtime_files.items():
        path = cast(str, record["path"])
        digest, size = _image_file_sha256_and_size(
            image,
            f"/opt/autolean/library-substrate/{path}",
            label=f"runtime OLean {module}",
        )
        if digest != record["sha256"] or size != record["size"]:
            fail(f"runtime OLean bytes differ from manifest for {module}")
        actual = {"module": module, "path": path, "sha256": digest, "size": size}
        actual_records.append(actual)
        actual_files[module] = actual
    actual_checksums = _checksum_manifest_bytes(actual_records)
    checksum_path = f"/opt/autolean/library-substrate/attestations/{RUNTIME_FILE_CHECKSUM_FILENAME}"
    stored_checksums = _read_image_text(image, checksum_path).encode("utf-8")
    if stored_checksums != actual_checksums:
        fail("runtime file checksum manifest differs from fixed-digest OLean bytes")
    checksum_sha256 = _sha256_bytes(actual_checksums)
    if (
        manifest.get("compiled_tree_sha256") != checksum_sha256
        or receipt.get("compiled_tree_sha256") != checksum_sha256
    ):
        fail("runtime file checksum manifest is not bound by manifest and receipt")
    return actual_files


def _validate_declaration_records(
    value: object,
    *,
    runtime_files: Mapping[str, Mapping[str, object]],
    include_origin_hash: bool,
) -> list[dict[str, object]]:
    if not isinstance(value, list) or not value:
        fail("declaration inventory must be a nonempty array")
    records: list[dict[str, object]] = []
    names: list[str] = []
    expected_fields = {
        "canonical_type",
        "declaration_kind",
        "name",
        "observed_axioms",
        "origin_module",
    }
    if include_origin_hash:
        expected_fields |= {"canonical_type_sha256", "origin_olean_sha256"}
    for item in value:
        if not isinstance(item, dict) or set(item) != expected_fields:
            fail("declaration inventory record schema drifted")
        record = cast(dict[str, object], item)
        name = record["name"]
        canonical = record["canonical_type"]
        kind = record["declaration_kind"]
        origin = record["origin_module"]
        if (
            not isinstance(name, str)
            or not name.startswith("AutoLeanLibrary.")
            or not isinstance(canonical, str)
            or not canonical
            or not isinstance(kind, str)
            or kind
            not in {
                "axiom",
                "constructor",
                "definition",
                "inductive",
                "opaque",
                "quotient",
                "recursor",
                "theorem",
            }
            or not isinstance(origin, str)
            or origin not in runtime_files
        ):
            fail("declaration inventory record is invalid")
        axioms = _sorted_unique_strings(
            record["observed_axioms"], label=f"observed axioms for {name}"
        )
        if not set(axioms).issubset(ALLOWED_RUNTIME_AXIOMS):
            fail(f"runtime declaration observes a forbidden axiom: {name}")
        normalized = dict(record)
        normalized["canonical_type_sha256"] = _sha256_bytes(canonical.encode("utf-8"))
        normalized["origin_olean_sha256"] = runtime_files[origin]["sha256"]
        if include_origin_hash and normalized != record:
            fail(f"declaration hash or origin OLean binding is invalid: {name}")
        records.append(normalized)
        names.append(name)
    if names != sorted(set(names)):
        fail("declaration inventory names must be sorted and unique")
    return records


def _validate_ir_auxiliary_records(
    value: object,
    *,
    runtime_files: Mapping[str, Mapping[str, object]],
    include_origin_hash: bool,
    kernel_names: frozenset[str],
) -> list[dict[str, object]]:
    if not isinstance(value, list) or not value:
        fail("IR auxiliary inventory must be a nonempty array")
    expected_fields = {"ir_decl_kind", "name", "origin_module"}
    if include_origin_hash:
        expected_fields |= {"origin_olean_sha256"}
    reserved_identities = {
        TARGET_DECLARATION,
        SOUND_DECLARATION,
        "Candidate",
        "Init",
        "Lean",
        "Mathlib",
        *runtime_files,
        "AutoLeanLibrary.Fixtures.ModelTheory.Packet",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Controls",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.ClosedSound",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.DerivSound",
    }
    records: list[dict[str, object]] = []
    names: list[str] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != expected_fields:
            fail("IR auxiliary record schema drifted")
        record = cast(dict[str, object], item)
        declaration_kind = record["ir_decl_kind"]
        name = record["name"]
        origin = record["origin_module"]
        if (
            declaration_kind not in {"fdecl", "extern"}
            or not isinstance(name, str)
            or not name
            or any(ord(character) < 33 or ord(character) > 126 for character in name)
            or not isinstance(origin, str)
            or origin not in runtime_files
            or name in kernel_names
            or name in reserved_identities
        ):
            fail("IR auxiliary record is invalid or collides with a reserved identity")
        normalized = dict(record)
        normalized["origin_olean_sha256"] = runtime_files[origin]["sha256"]
        if include_origin_hash and normalized != record:
            fail(f"IR auxiliary OLean origin binding is invalid: {name}")
        records.append(normalized)
        names.append(name)
    if names != sorted(set(names)):
        fail("IR auxiliary names must be sorted and unique")
    return records


def _validate_manifest(
    manifest: dict[str, object],
    *,
    receipt: Mapping[str, object],
) -> tuple[
    dict[str, dict[str, object]],
    list[dict[str, object]],
    list[dict[str, object]],
]:
    required = {
        "build_input_sha256",
        "compiled_tree_sha256",
        "declaration_inventory",
        "declaration_inventory_sha256",
        "ir_auxiliary_names_sha256",
        "mathlib_revision",
        "parent_image",
        "parent_receipt_canonical_sha256",
        "parent_receipt_file_sha256",
        "profile_id",
        "profile_sha256",
        "runtime_files",
        "runtime_modules",
        "runtime_source_checksum_manifest_sha256",
        "runtime_source_tree_sha256",
        "schema_version",
        "task_mode",
    }
    if set(manifest) != required:
        fail("runtime manifest schema drifted")
    if (
        manifest["schema_version"] != RUNTIME_MANIFEST_SCHEMA
        or manifest["task_mode"] != "independent_reproof"
        or manifest["profile_id"] != EXPECTED_PROFILE_IDS["independent_reproof"]
        or manifest["parent_image"] != SOURCE_V2_IMAGE
        or manifest["mathlib_revision"] != EXPECTED_MATHLIB_REVISION
    ):
        fail("runtime manifest identity differs from the independent profile")
    for field in (
        "build_input_sha256",
        "compiled_tree_sha256",
        "declaration_inventory_sha256",
        "ir_auxiliary_names_sha256",
        "parent_receipt_canonical_sha256",
        "parent_receipt_file_sha256",
        "profile_sha256",
        "runtime_source_checksum_manifest_sha256",
        "runtime_source_tree_sha256",
    ):
        if not isinstance(manifest[field], str) or not SHA256_RE.fullmatch(
            cast(str, manifest[field])
        ):
            fail(f"runtime manifest {field} is invalid")
        if receipt.get(field) != manifest[field]:
            fail(f"runtime manifest and receipt differ at {field}")
    runtime_files = _runtime_files(manifest)
    modules = manifest["runtime_modules"]
    expected_modules = tuple(MODULE_BY_NAME)[:3]
    runtime_file_records = cast(list[dict[str, object]], manifest["runtime_files"])
    expected_paths = [f"lib/lean/{module.replace('.', '/')}.olean" for module in expected_modules]
    if (
        modules != list(expected_modules)
        or list(runtime_files) != list(expected_modules)
        or [record["path"] for record in runtime_file_records] != expected_paths
    ):
        fail("runtime module closure differs from the frozen independent profile")
    inventory = manifest["declaration_inventory"]
    if not isinstance(inventory, dict) or set(inventory) != {
        "declarations",
        "ir_auxiliary_names",
        "ir_auxiliary_names_sha256",
        "schema_version",
    }:
        fail("declaration inventory envelope drifted")
    if inventory["schema_version"] != DECLARATION_INVENTORY_SCHEMA:
        fail("declaration inventory protocol drifted")
    records = _validate_declaration_records(
        inventory["declarations"],
        runtime_files=runtime_files,
        include_origin_hash=True,
    )
    auxiliary = _validate_ir_auxiliary_records(
        inventory["ir_auxiliary_names"],
        runtime_files=runtime_files,
        include_origin_hash=True,
        kernel_names=frozenset(cast(str, record["name"]) for record in records),
    )
    auxiliary_sha256 = _sha256_bytes(_canonical_json_compact_bytes(auxiliary))
    if (
        inventory["ir_auxiliary_names_sha256"] != auxiliary_sha256
        or manifest["ir_auxiliary_names_sha256"] != auxiliary_sha256
        or receipt.get("ir_auxiliary_names_sha256") != auxiliary_sha256
    ):
        fail("IR auxiliary inventory hash differs across manifest and receipt")
    for record in records:
        if record["name"] in {TARGET_DECLARATION, SOUND_DECLARATION}:
            fail("runtime inventory contains a forbidden pilot theorem")
        if record["canonical_type_sha256"] == TARGET_TYPE_SHA256:
            fail("runtime inventory contains an exact target-type collision")
    return runtime_files, records, auxiliary


def _validate_image_build_input(
    build_input: Mapping[str, object],
    *,
    profile: ValidatedProfileBoundary,
    source_checksums: bytes,
    receipt: Mapping[str, object],
) -> tuple[list[dict[str, object]], str]:
    records, source_tree_sha256 = _validate_runtime_source_binding(
        build_input,
        profile,
        source_root=FIXTURE_ROOT / "source",
        source_checksums=source_checksums,
    )
    source_checksum_sha256 = _sha256_bytes(source_checksums)
    if receipt.get("runtime_source_checksum_manifest_sha256") != source_checksum_sha256:
        fail("image receipt is not bound to the runtime source checksum manifest")
    return records, source_tree_sha256


def _validate_host_asset_binding(build_input: Mapping[str, object]) -> None:
    expected_assets = dict(sorted(_asset_hashes().items()))
    if build_input.get("assets") != expected_assets:
        fail("image-owned build input differs from the current host helper assets")


def _validate_v2_facade_bindings(
    receipt: Mapping[str, object],
    build_input: Mapping[str, object],
    *,
    runtime_manifest_file_sha256: str,
    facade_wrapper_sha256: str,
    facade_query_helper_sha256: str,
) -> None:
    """Bind the standard V2 paths to the same immutable substrate receipt.

    The facade has no protocol extension in its stdout, so its identity must be checked from the
    image-owned receipt/build input before a host canary treats a V2 record as substrate evidence.
    """

    for field, actual in (
        ("v2_facade_wrapper_sha256", facade_wrapper_sha256),
        ("v2_facade_query_helper_sha256", facade_query_helper_sha256),
    ):
        recorded = receipt.get(field)
        if not isinstance(recorded, str) or not SHA256_RE.fullmatch(recorded) or recorded != actual:
            fail(f"image receipt does not bind the {field}")
    assets = build_input.get("assets")
    if not isinstance(assets, dict):
        fail("substrate build input assets are unavailable")
    expected_assets = {
        "V2_FACADE_WRAPPER_SHA256": facade_wrapper_sha256,
        "V2_FACADE_QUERY_HELPER_SHA256": facade_query_helper_sha256,
    }
    if any(assets.get(name) != digest for name, digest in expected_assets.items()):
        fail("substrate build input does not bind the V2 facade assets")
    target = build_input.get("target")
    if target != {
        "canonical_type_sha256": TARGET_TYPE_SHA256,
        "declaration": TARGET_DECLARATION,
        "forbidden_ordinary_dependency": SOUND_DECLARATION,
    }:
        fail("substrate build input target boundary differs from the V2 facade scope")
    if receipt.get("runtime_manifest_sha256") != runtime_manifest_file_sha256:
        fail("V2 facade receipt is not bound to the runtime manifest")


def _validate_builder_query_bindings(
    receipt: Mapping[str, object],
    build_input: Mapping[str, object],
    *,
    runtime_manifest_file_sha256: str,
    builder_query_wrapper_sha256: str,
    builder_query_helper_sha256: str,
) -> None:
    """Bind the non-proof Builder query endpoint to the image receipt and build input."""

    for field, actual in (
        ("builder_query_wrapper_sha256", builder_query_wrapper_sha256),
        ("builder_query_helper_sha256", builder_query_helper_sha256),
    ):
        recorded = receipt.get(field)
        if not isinstance(recorded, str) or not SHA256_RE.fullmatch(recorded) or recorded != actual:
            fail(f"image receipt does not bind the {field}")
    assets = build_input.get("assets")
    if not isinstance(assets, dict):
        fail("substrate build input assets are unavailable")
    expected_assets = {
        "BUILDER_QUERY_WRAPPER_SHA256": builder_query_wrapper_sha256,
        "BUILDER_QUERY_HELPER_SHA256": builder_query_helper_sha256,
    }
    if any(assets.get(name) != digest for name, digest in expected_assets.items()):
        fail("substrate build input does not bind the Builder query assets")
    if receipt.get("runtime_manifest_sha256") != runtime_manifest_file_sha256:
        fail("Builder query receipt is not bound to the runtime manifest")


def verify(image: str) -> dict[str, object]:
    inspected = _inspect(image)
    actual_reference = _child_image_reference(inspected)
    if actual_reference != image:
        fail("requested child image differs from its Docker-recorded repository digest")
    image_id = inspected.get("Id")
    if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        fail("child image has no immutable image ID")
    receipt, image_receipt_sha256 = _receipt_output(image)
    expected_receipt_fields = {
        "build_input_sha256",
        "build_tool_sha256",
        "builder_query_helper_sha256",
        "builder_query_wrapper_sha256",
        "compiled_tree_sha256",
        "declaration_inventory_sha256",
        "dockerfile_sha256",
        "inventory_helper_sha256",
        "ir_auxiliary_names_sha256",
        "parent_image",
        "parent_receipt_canonical_sha256",
        "parent_receipt_file_sha256",
        "profile_id",
        "profile_sha256",
        "query_wrapper_sha256",
        "receipt_tool_sha256",
        "runtime_manifest_sha256",
        "runtime_source_checksum_manifest_sha256",
        "runtime_source_tree_sha256",
        "schema_version",
        "task_mode",
        "v2_facade_query_helper_sha256",
        "v2_facade_wrapper_sha256",
    }
    if set(receipt) != expected_receipt_fields:
        fail("image receipt schema drifted")
    if (
        receipt["schema_version"] != IMAGE_RECEIPT_SCHEMA
        or receipt["task_mode"] != "independent_reproof"
        or receipt["profile_id"] != EXPECTED_PROFILE_IDS["independent_reproof"]
        or receipt["parent_image"] != SOURCE_V2_IMAGE
    ):
        fail("image receipt identity differs from the independent profile")
    for field in expected_receipt_fields - {
        "parent_image",
        "profile_id",
        "schema_version",
        "task_mode",
    }:
        if not isinstance(receipt[field], str) or not SHA256_RE.fullmatch(
            cast(str, receipt[field])
        ):
            fail(f"image receipt {field} is invalid")
    (
        _,
        current_parent_receipt_sha256,
        current_parent_receipt_file_sha256,
        _,
    ) = _parent_receipt()
    if receipt["parent_receipt_canonical_sha256"] != current_parent_receipt_sha256:
        fail("child receipt is not bound to the verified source-v2 parent receipt")
    if receipt["parent_receipt_file_sha256"] != current_parent_receipt_file_sha256:
        fail("child receipt is not bound to the source-v2 receipt file")
    _, current_profile_record = _profile()
    current_profile_sha256 = _sha256_bytes(_canonical_json_bytes(current_profile_record))
    if receipt["profile_sha256"] != current_profile_sha256:
        fail("child receipt is not bound to the current independent profile")
    labels = inspected.get("Config")
    if not isinstance(labels, dict) or not isinstance(labels.get("Labels"), dict):
        fail("child image labels are unavailable")
    label_values = cast(dict[str, object], labels["Labels"])
    if (
        label_values.get("org.autolean.library-substrate.build-input-sha256")
        != receipt["build_input_sha256"]
        or label_values.get("org.autolean.library-substrate.parent-receipt-canonical-sha256")
        != receipt["parent_receipt_canonical_sha256"]
    ):
        fail("child image labels differ from its image-owned receipt")
    manifest, manifest_file_sha256 = _read_image_json(
        image,
        "/opt/autolean/library-substrate/attestations/runtime-manifest.v1.json",
        label="runtime manifest",
    )
    if manifest_file_sha256 != receipt["runtime_manifest_sha256"]:
        fail("runtime manifest file hash differs from the image receipt")
    build_input, build_input_file_sha256 = _read_image_json(
        image,
        "/opt/autolean/library-substrate/attestations/build-input.v1.json",
        label="substrate build input",
    )
    _validate_host_asset_binding(build_input)
    profile, _ = _profile()
    source_checksums = _read_image_text(
        image,
        f"/opt/autolean/library-substrate/attestations/{RUNTIME_SOURCE_CHECKSUM_FILENAME}",
    ).encode("utf-8")
    source_records, source_tree_sha256 = _validate_image_build_input(
        build_input,
        profile=profile,
        source_checksums=source_checksums,
        receipt=receipt,
    )
    if (
        build_input_file_sha256 != receipt["build_input_sha256"]
        or build_input.get("schema_version") != "autolean.library-substrate-build-input.v1"
        or build_input.get("profile_sha256") != current_profile_sha256
        or build_input.get("parent_receipt_canonical_sha256") != current_parent_receipt_sha256
        or build_input.get("parent_receipt_file_sha256") != current_parent_receipt_file_sha256
        or manifest.get("runtime_source_checksum_manifest_sha256")
        != _sha256_bytes(source_checksums)
        or manifest.get("runtime_source_tree_sha256") != source_tree_sha256
        or build_input.get("runtime_sources") != source_records
    ):
        fail("image-owned build input differs from the verified profile and parent")
    facade_wrapper_sha256 = _image_file_sha256(
        image,
        V2_WRAPPER_PATH,
        label="image-owned V2 facade wrapper",
    )
    facade_query_helper_sha256 = _image_file_sha256(
        image,
        V2_QUERY_HELPER_PATH,
        label="image-owned V2 facade query helper",
    )
    _validate_v2_facade_bindings(
        receipt,
        build_input,
        runtime_manifest_file_sha256=manifest_file_sha256,
        facade_wrapper_sha256=facade_wrapper_sha256,
        facade_query_helper_sha256=facade_query_helper_sha256,
    )
    builder_query_wrapper_sha256 = _image_file_sha256(
        image,
        BUILDER_QUERY_WRAPPER_PATH,
        label="image-owned Builder query wrapper",
    )
    builder_query_helper_sha256 = _image_file_sha256(
        image,
        BUILDER_QUERY_HELPER_PATH,
        label="image-owned Builder query helper",
    )
    _validate_builder_query_bindings(
        receipt,
        build_input,
        runtime_manifest_file_sha256=manifest_file_sha256,
        builder_query_wrapper_sha256=builder_query_wrapper_sha256,
        builder_query_helper_sha256=builder_query_helper_sha256,
    )
    runtime_files, records, auxiliary = _validate_manifest(manifest, receipt=receipt)
    verified_runtime_files = _validate_runtime_file_closure(
        image,
        runtime_files,
        manifest=manifest,
        receipt=receipt,
    )
    return {
        "declaration_count": len(records),
        "image": image,
        "image_id": image_id,
        "image_receipt_sha256": image_receipt_sha256,
        "builder_query_identity": {
            "build_input_sha256": receipt["build_input_sha256"],
            "builder_query_helper_sha256": builder_query_helper_sha256,
            "builder_query_wrapper_sha256": builder_query_wrapper_sha256,
            "image": image,
            "image_receipt_sha256": image_receipt_sha256,
            "parent_image": receipt["parent_image"],
            "profile_id": receipt["profile_id"],
            "profile_sha256": receipt["profile_sha256"],
            "runtime_manifest_sha256": receipt["runtime_manifest_sha256"],
        },
        "v2_facade_identity": {
            "query_helper_sha256": facade_query_helper_sha256,
            "wrapper_sha256": facade_wrapper_sha256,
        },
        "parent_receipt_canonical_sha256": current_parent_receipt_sha256,
        "receipt": receipt,
        "runtime_file_count": len(runtime_files),
        "verified_runtime_files": verified_runtime_files,
        "ir_auxiliary_name_count": len(auxiliary),
        "runtime_manifest": manifest,
        "schema_version": "autolean.library-substrate-image-verification.v1",
    }


def _snapshot_candidate(destination: Path) -> tuple[Path, str]:
    content = _regular_bytes(CANDIDATE_PATH, label="independent Candidate source")
    destination.mkdir(parents=True, exist_ok=False)
    candidate = destination / "Candidate.lean"
    candidate.write_bytes(content)
    candidate.chmod(0o444)
    return candidate, _sha256_bytes(content)


def _write_builder_query_source(destination: Path, source: str) -> tuple[Path, str]:
    destination.mkdir(parents=True, exist_ok=False)
    candidate = destination / "Candidate.lean"
    candidate.write_text(source, encoding="utf-8", newline="\n")
    candidate.chmod(0o444)
    content = _regular_bytes(candidate, label="Builder statement carrier source")
    return candidate, _sha256_bytes(content)


def _builder_query_command(
    image: str,
    candidate: Path,
    *,
    target: str,
    expected_type_sha256: str | None = None,
) -> list[str]:
    if not IMAGE_DIGEST_RE.fullmatch(image):
        fail("Builder query requires a Docker-recorded library-substrate RepoDigest")
    command = [
        *_docker_run_base(),
        "--mount",
        f"type=bind,src={candidate.parent},dst=/input,readonly",
        image,
        BUILDER_QUERY_WRAPPER_PATH,
        "--target",
        target,
        "--image",
        image,
    ]
    if expected_type_sha256 is not None:
        if not SHA256_RE.fullmatch(expected_type_sha256):
            fail("Builder query replay expectation is not a lowercase SHA-256")
        command.extend(("--expected-type-sha256", expected_type_sha256))
    return command


def _builder_query_record(
    image: str,
    candidate: Path,
    *,
    target: str,
    expected_type_sha256: str | None = None,
) -> dict[str, object]:
    output = _run(
        _builder_query_command(
            image,
            candidate,
            target=target,
            expected_type_sha256=expected_type_sha256,
        ),
        timeout=300,
    ).stdout
    return _json_record(output, label="Builder statement query")


def _expect_builder_query_rejected(
    image: str,
    candidate: Path,
    *,
    label: str,
    target: str,
    reason_marker: str,
    expected_type_sha256: str | None = None,
) -> dict[str, object]:
    source_sha256 = _sha256_bytes(_regular_bytes(candidate, label=f"Builder query {label} source"))
    try:
        result = subprocess.run(
            _builder_query_command(
                image,
                candidate,
                target=target,
                expected_type_sha256=expected_type_sha256,
            ),
            check=False,
            capture_output=True,
            errors="replace",
            timeout=300,
            text=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise SubstrateImageError("Builder query rejection subprocess failed") from error
    if result.returncode == 0:
        fail(f"Builder query accepted the {label} negative")
    if result.stdout:
        fail(f"Builder query {label} failure emitted stdout")
    if (
        not result.stderr
        or len(result.stderr.encode("utf-8")) > BUILDER_QUERY_FAILURE_DIAGNOSTIC_LIMIT + 512
        or reason_marker not in result.stderr
    ):
        fail(f"Builder query {label} failure reason is unavailable or unbounded")
    return {
        "candidate_source_sha256": source_sha256,
        "reason_marker": reason_marker,
        "returncode": result.returncode,
        "stderr_summary": result.stderr.strip(),
    }


def _compile_candidate(image: str, candidate: Path, output: Path) -> Path:
    output.mkdir()
    output.chmod(0o777)
    command = [
        *_docker_run_base(),
        "--mount",
        f"type=bind,src={candidate.parent},dst=/input,readonly",
        "--mount",
        f"type=bind,src={output},dst=/output",
        image,
        "/opt/autolean/library-substrate/bin/autolean-library-substrate-independent-query",
        "--phase",
        "compile",
        "--target",
        TARGET_DECLARATION,
    ]
    _run(command, timeout=300)
    compiler_output = output / "Candidate.olean"
    if (
        compiler_output.is_symlink()
        or not compiler_output.is_file()
        or compiler_output.stat().st_size <= 0
        or compiler_output.stat().st_size > 64 * 1024 * 1024
    ):
        fail("candidate compiler did not emit a regular Candidate.olean")
    sealed_root = output.parent / "sealed"
    sealed_root.mkdir(mode=0o700)
    sealed = sealed_root / "Candidate.olean"
    sealed.write_bytes(compiler_output.read_bytes())
    sealed.chmod(0o444)
    return sealed


def _query_candidate(image: str, compiled: Path) -> dict[str, object]:
    command = [
        *_docker_run_base(),
        "--mount",
        f"type=bind,src={compiled},dst=/compiled/Candidate.olean,readonly",
        image,
        "/opt/autolean/library-substrate/bin/autolean-library-substrate-independent-query",
        "--phase",
        "query",
        "--target",
        TARGET_DECLARATION,
    ]
    output = _run(command, timeout=300).stdout
    return _json_record(output, label="independent Candidate query")


def _v2_compile_candidate(image: str, candidate: Path, output: Path) -> Path:
    output.mkdir()
    output.chmod(0o777)
    _run(
        [
            *_docker_run_base(),
            "--mount",
            f"type=bind,src={candidate.parent},dst=/input,readonly",
            "--mount",
            f"type=bind,src={output},dst=/output",
            image,
            *_v2_compile_wrapper_argv(),
        ],
        timeout=300,
    )
    compiler_output = output / "Candidate.olean"
    if (
        compiler_output.is_symlink()
        or not compiler_output.is_file()
        or compiler_output.stat().st_size <= 0
        or compiler_output.stat().st_size > 64 * 1024 * 1024
    ):
        fail("V2 facade compiler did not emit a regular Candidate.olean")
    sealed_root = output.parent / "sealed"
    sealed_root.mkdir(mode=0o700)
    sealed = sealed_root / "Candidate.olean"
    sealed.write_bytes(compiler_output.read_bytes())
    sealed.chmod(0o444)
    return sealed


def _v2_query_candidate(image: str, compiled: Path) -> dict[str, object]:
    output = _run(
        [
            *_docker_run_base(),
            "--mount",
            f"type=bind,src={compiled},dst=/compiled/Candidate.olean,readonly",
            image,
            *_v2_query_wrapper_argv(),
        ],
        timeout=300,
    ).stdout
    return _json_record(output, label="V2 facade Candidate query")


def _v2_compile_wrapper_argv() -> tuple[str, ...]:
    return (
        V2_WRAPPER_PATH,
        "--protocol",
        V2_RESULT_SCHEMA,
        "--phase",
        "compile",
        "--candidate",
        "/input/Candidate.lean",
        "--output",
        "/output/Candidate.olean",
    )


def _v2_query_wrapper_argv() -> tuple[str, ...]:
    return (
        V2_WRAPPER_PATH,
        "--protocol",
        V2_RESULT_SCHEMA,
        "--phase",
        "query",
        "--compiled",
        "/compiled/Candidate.olean",
        "--declaration",
        TARGET_DECLARATION,
        "--type-format",
        "autolean.lean-pp-expr.v1",
    )


def _v2_rejection_observation(
    result: subprocess.CompletedProcess[str],
    *,
    label: str,
    actual_phase: Literal["compile", "query"],
    expected_phase: Literal["compile", "query"],
    expected_returncode: int,
    reason_marker: str,
    candidate_source_sha256: str,
    expected_candidate_source_sha256: str,
) -> dict[str, object]:
    if candidate_source_sha256 != expected_candidate_source_sha256:
        fail(f"V2 facade {label} candidate source hash drifted")
    if actual_phase != expected_phase:
        fail(f"V2 facade {label} rejected during {actual_phase}, expected {expected_phase}")
    if result.returncode != expected_returncode:
        fail(f"V2 facade {label} returned {result.returncode}, expected {expected_returncode}")
    if result.stdout:
        fail(f"V2 facade {label} failure emitted stdout")
    prefix = f"autolean-library-substrate-v2-facade: phase={expected_phase} failed"
    stderr = result.stderr
    maximum_bytes = len(prefix.encode("utf-8")) + V2_FACADE_FAILURE_DIAGNOSTIC_LIMIT + 8
    if (
        not stderr
        or len(stderr.encode("utf-8")) > maximum_bytes
        or prefix not in stderr
        or reason_marker not in stderr
    ):
        fail(f"V2 facade {label} failure reason is unavailable or unbounded")
    return {
        "candidate_source_sha256": candidate_source_sha256,
        "reason_marker": reason_marker,
        "rejection_phase": actual_phase,
        "returncode": result.returncode,
        "stderr_summary": stderr.strip(),
    }


def _expect_v2_candidate_rejected(
    image: str,
    candidate: Path,
    *,
    label: str,
    expected_phase: Literal["compile", "query"],
    expected_returncode: int,
    reason_marker: str,
    expected_candidate_source_sha256: str,
) -> dict[str, object]:
    candidate_source_sha256 = _sha256_bytes(
        _regular_bytes(candidate, label=f"V2 facade {label} candidate source")
    )
    with tempfile.TemporaryDirectory(
        prefix="autolean-library-substrate-v2-negative-", dir="/tmp"
    ) as raw:
        output = Path(raw) / "output"
        output.mkdir(mode=0o777)
        output.chmod(0o777)
        compile_result = subprocess.run(
            [
                *_docker_run_base(),
                "--mount",
                f"type=bind,src={candidate.parent},dst=/input,readonly",
                "--mount",
                f"type=bind,src={output},dst=/output",
                image,
                *_v2_compile_wrapper_argv(),
            ],
            check=False,
            capture_output=True,
            errors="replace",
            timeout=300,
            text=True,
        )
        if compile_result.returncode != 0:
            return _v2_rejection_observation(
                compile_result,
                label=label,
                actual_phase="compile",
                expected_phase=expected_phase,
                expected_returncode=expected_returncode,
                reason_marker=reason_marker,
                candidate_source_sha256=candidate_source_sha256,
                expected_candidate_source_sha256=expected_candidate_source_sha256,
            )
        compiler_output = output / "Candidate.olean"
        if (
            compiler_output.is_symlink()
            or not compiler_output.is_file()
            or compiler_output.stat().st_size <= 0
            or compiler_output.stat().st_size > 64 * 1024 * 1024
        ):
            fail(f"V2 facade {label} compile did not emit a regular Candidate.olean")
        sealed_root = Path(raw) / "sealed"
        sealed_root.mkdir(mode=0o700)
        sealed = sealed_root / "Candidate.olean"
        sealed.write_bytes(compiler_output.read_bytes())
        sealed.chmod(0o444)
        query_result = subprocess.run(
            [
                *_docker_run_base(),
                "--mount",
                f"type=bind,src={sealed},dst=/compiled/Candidate.olean,readonly",
                image,
                *_v2_query_wrapper_argv(),
            ],
            check=False,
            capture_output=True,
            errors="replace",
            timeout=300,
            text=True,
        )
    if query_result.returncode == 0:
        fail("V2 facade accepted a candidate that the substrate policy must reject")
    return _v2_rejection_observation(
        query_result,
        label=label,
        actual_phase="query",
        expected_phase=expected_phase,
        expected_returncode=expected_returncode,
        reason_marker=reason_marker,
        candidate_source_sha256=candidate_source_sha256,
        expected_candidate_source_sha256=expected_candidate_source_sha256,
    )


def _validate_v2_facade_record(
    record: Mapping[str, object], *, identity: Mapping[str, str]
) -> dict[str, object]:
    expected_fields = {
        "schema_version",
        "declaration",
        "canonical_type",
        "lean_version",
        "mathlib_revision",
        "lake_manifest_hash",
        "observed_axioms",
        "image_identity",
    }
    if set(record) != expected_fields:
        fail("V2 facade query record schema drifted")
    canonical_type = record.get("canonical_type")
    if (
        not isinstance(canonical_type, str)
        or _sha256_bytes(canonical_type.encode("utf-8")) != TARGET_TYPE_SHA256
    ):
        fail("V2 facade did not preserve the historical target type hash")
    axioms = _sorted_unique_strings(record.get("observed_axioms"), label="V2 facade axioms")
    expected_identity = {
        "schema_version": "autolean.image-owned-verifier-identity.v2",
        "wrapper_path": V2_WRAPPER_PATH,
        "wrapper_sha256": identity["wrapper_sha256"],
        "query_helper_path": V2_QUERY_HELPER_PATH,
        "query_helper_sha256": identity["query_helper_sha256"],
    }
    if (
        record.get("schema_version") != V2_RESULT_SCHEMA
        or record.get("declaration") != TARGET_DECLARATION
        or record.get("lean_version") != "v4.28.0"
        or record.get("mathlib_revision") != EXPECTED_MATHLIB_REVISION
        or record.get("lake_manifest_hash") != V2_LAKE_MANIFEST_SHA256
        or axioms != EXPECTED_TARGET_AXIOMS
        or record.get("image_identity") != expected_identity
    ):
        fail("V2 facade record differs from the fixed independent substrate profile")
    return {
        "canonical_type_sha256": TARGET_TYPE_SHA256,
        "observed_axioms": list(axioms),
        "standard_v2_record": True,
    }


def _validate_query(
    query: dict[str, object],
    *,
    runtime_files: Mapping[str, Mapping[str, object]],
    verified_runtime_files: Mapping[str, Mapping[str, object]],
    manifest_records: list[dict[str, object]],
    manifest_auxiliary: list[dict[str, object]],
    expected_identity: Mapping[str, object],
) -> dict[str, object]:
    if dict(runtime_files) != dict(verified_runtime_files):
        fail("fresh query origin hashes cannot be supplemented before OLean facts close")
    expected = {
        "candidate_direct_imports",
        "candidate_ir_auxiliary_names",
        "candidate_kernel_names",
        "candidate_namespace_disjoint",
        "candidate_owns_target",
        "canonical_type",
        "declaration",
        "direct_proof_dependencies",
        "loaded_module_closure",
        "observed_axioms",
        "runtime_declarations",
        "runtime_ir_auxiliary_names",
        "schema_version",
        "substrate_identity",
    }
    if set(query) != expected:
        fail("Candidate query schema drifted")
    if (
        query["schema_version"] != QUERY_SCHEMA
        or query["candidate_owns_target"] is not True
        or query["candidate_namespace_disjoint"] is not True
        or query["declaration"] != TARGET_DECLARATION
    ):
        fail("Candidate query did not establish sealed-module ownership")
    candidate_kernel_names = _sorted_unique_strings(
        query["candidate_kernel_names"], label="Candidate kernel names"
    )
    candidate_auxiliary_names = _sorted_unique_strings(
        query["candidate_ir_auxiliary_names"], label="Candidate IR auxiliary names"
    )
    if TARGET_DECLARATION not in candidate_kernel_names:
        fail("Candidate kernel ownership omits the target")
    if set(candidate_kernel_names).intersection(candidate_auxiliary_names):
        fail("Candidate kernel and IR ownership overlap")
    runtime_owned_names = {
        *(cast(str, record["name"]) for record in manifest_records),
        *(cast(str, record["name"]) for record in manifest_auxiliary),
    }
    if runtime_owned_names.intersection((*candidate_kernel_names, *candidate_auxiliary_names)):
        fail("Candidate owned names collide with runtime ownership")
    identity = query["substrate_identity"]
    if not isinstance(identity, dict) or set(identity) != {
        "image_receipt_sha256",
        "profile_sha256",
        "query_wrapper_sha256",
        "runtime_manifest_sha256",
    }:
        fail("Candidate query substrate identity drifted")
    if identity != expected_identity:
        fail("Candidate query is not bound to the verified image-owned substrate")
    direct_imports = _sorted_unique_strings(
        query["candidate_direct_imports"], label="Candidate direct imports"
    )
    if direct_imports != (
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.RulePrelude",
        "Init",
    ):
        fail(f"Candidate direct imports differ from the independent profile: {direct_imports}")
    loaded = _sorted_unique_strings(query["loaded_module_closure"], label="loaded module closure")
    for module in (*runtime_files, "Candidate"):
        if module not in loaded:
            fail(f"loaded module closure omits {module}")
    forbidden_modules = {
        "AutoLeanLibrary.Fixtures.ModelTheory.Packet",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Controls",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.ClosedSound",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.DerivSound",
    }
    if forbidden_modules.intersection(loaded):
        fail("loaded module closure contains a forbidden module")
    canonical_type = query["canonical_type"]
    if (
        not isinstance(canonical_type, str)
        or _sha256_bytes(canonical_type.encode("utf-8")) != TARGET_TYPE_SHA256
    ):
        fail("Candidate target type differs from the historical frozen diagnostic")
    axioms = _sorted_unique_strings(query["observed_axioms"], label="target axioms")
    if axioms != EXPECTED_TARGET_AXIOMS:
        fail("Candidate target axiom observation differs from the historical diagnostic")
    dependencies = _sorted_unique_strings(
        query["direct_proof_dependencies"], label="direct proof dependencies"
    )
    if SOUND_DECLARATION in dependencies:
        fail("independent Candidate directly uses Deriv.sound")
    fresh_records = _validate_declaration_records(
        query["runtime_declarations"],
        runtime_files=runtime_files,
        include_origin_hash=False,
    )
    if fresh_records != manifest_records:
        fail("fresh runtime declaration inventory differs from the image manifest")
    fresh_auxiliary = _validate_ir_auxiliary_records(
        query["runtime_ir_auxiliary_names"],
        runtime_files=runtime_files,
        include_origin_hash=False,
        kernel_names=frozenset(cast(str, record["name"]) for record in fresh_records),
    )
    if fresh_auxiliary != manifest_auxiliary:
        fail("fresh IR auxiliary inventory differs from the image manifest")
    return {
        "candidate_direct_imports": list(direct_imports),
        "candidate_ir_auxiliary_names": list(candidate_auxiliary_names),
        "candidate_kernel_names": list(candidate_kernel_names),
        "candidate_namespace_disjoint": True,
        "direct_proof_dependencies": list(dependencies),
        "loaded_module_closure": list(loaded),
        "observed_axioms": list(axioms),
        "runtime_inventory_replayed": True,
        "ir_auxiliary_inventory_replayed": True,
        "target_canonical_type_sha256": TARGET_TYPE_SHA256,
    }


def _validate_builder_query_record(
    record: Mapping[str, object],
    *,
    expected_identity: Mapping[str, object],
    expected_source_sha256: str,
    expected_type_sha256: str | None,
) -> dict[str, object]:
    expected_fields = {
        "candidate_direct_imports",
        "candidate_ir_auxiliary_names",
        "candidate_kernel_names",
        "candidate_owns_target",
        "candidate_source_sha256",
        "canonical_type",
        "canonical_type_sha256",
        "carrier_axiom_excluded_from_type_axioms",
        "carrier_kind",
        "declaration",
        "declaration_kind",
        "lean_version",
        "loaded_module_closure",
        "mathlib_revision",
        "proof_eligible",
        "replay_expected_type_sha256",
        "replay_mode",
        "replay_verified",
        "schema_version",
        "substrate_identity",
        "type_observed_axioms",
    }
    if set(record) != expected_fields:
        fail("Builder statement query schema drifted")
    canonical_type = record.get("canonical_type")
    canonical_type_sha256 = record.get("canonical_type_sha256")
    if (
        not isinstance(canonical_type, str)
        or not isinstance(canonical_type_sha256, str)
        or not SHA256_RE.fullmatch(canonical_type_sha256)
        or _sha256_bytes(canonical_type.encode("utf-8")) != canonical_type_sha256
    ):
        fail("Builder statement query canonical type hash is invalid")
    if (
        record.get("schema_version") != BUILDER_QUERY_SCHEMA
        or record.get("declaration") != BUILDER_QUERY_TARGET
        or record.get("declaration_kind") != "axiom"
        or record.get("carrier_kind") != "builder_statement_carrier"
        or record.get("proof_eligible") is not False
        or record.get("candidate_owns_target") is not True
        or record.get("carrier_axiom_excluded_from_type_axioms") is not True
        or record.get("candidate_source_sha256") != expected_source_sha256
        or record.get("lean_version") != "v4.28.0"
        or record.get("mathlib_revision") != EXPECTED_MATHLIB_REVISION
        or record.get("substrate_identity") != dict(expected_identity)
    ):
        fail("Builder statement query is not a bound non-proof carrier observation")
    candidate_kernel_names = _sorted_unique_strings(
        record.get("candidate_kernel_names"), label="Builder query Candidate kernel names"
    )
    candidate_auxiliary_names = _sorted_unique_strings(
        record.get("candidate_ir_auxiliary_names"),
        label="Builder query Candidate IR auxiliary names",
    )
    if candidate_kernel_names != (BUILDER_QUERY_TARGET,) or candidate_auxiliary_names:
        fail("Builder statement query did not isolate exactly one Candidate-owned carrier")
    direct_imports = _sorted_unique_strings(
        record.get("candidate_direct_imports"), label="Builder query direct imports"
    )
    if direct_imports != (
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.RulePrelude",
        "Init",
    ):
        fail("Builder statement query direct imports differ from the fixed profile")
    loaded = _sorted_unique_strings(
        record.get("loaded_module_closure"), label="Builder query loaded module closure"
    )
    required_modules = {*tuple(MODULE_BY_NAME)[:3], "Candidate"}
    forbidden_modules = {
        "AutoLeanLibrary.Fixtures.ModelTheory.Packet",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Controls",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.ClosedSound",
        "AutoLeanLibrary.Fixtures.ModelTheory.UniversalLK.Targets.DerivSound",
    }
    if not required_modules.issubset(loaded) or forbidden_modules.intersection(loaded):
        fail("Builder statement query loaded module boundary is invalid")
    type_axioms = _sorted_unique_strings(
        record.get("type_observed_axioms"), label="Builder query type-level axioms"
    )
    if BUILDER_QUERY_TARGET in type_axioms:
        fail("Builder statement carrier leaked into the type-level axiom set")
    if expected_type_sha256 is None:
        if (
            record.get("replay_expected_type_sha256") is not None
            or record.get("replay_mode") is not False
            or record.get("replay_verified") is not False
        ):
            fail("fresh Builder statement query was mislabeled as replay")
    elif (
        expected_type_sha256 != canonical_type_sha256
        or record.get("replay_expected_type_sha256") != expected_type_sha256
        or record.get("replay_mode") is not True
        or record.get("replay_verified") is not True
    ):
        fail("Builder statement query did not verify the replay type expectation")
    return {
        "candidate_source_sha256": expected_source_sha256,
        "canonical_type_sha256": canonical_type_sha256,
        "carrier_axiom_excluded_from_type_axioms": True,
        "declaration": BUILDER_QUERY_TARGET,
        "proof_eligible": False,
        "query_receipt_canonical_sha256": _sha256_bytes(_canonical_json_bytes(dict(record))),
        "replay_mode": expected_type_sha256 is not None,
        "type_observed_axioms": list(type_axioms),
    }


def builder_query_canary(image: str) -> dict[str, object]:
    """Exercise the receipt-bound, Builder-only statement observation endpoint.

    ``verify(image)`` first proves that ``image`` is the Docker-recorded child RepoDigest.
    The command builder then uses that same string both as the image Docker executes and as
    the endpoint's asserted image identity.
    """

    verified = verify(image)
    identity = cast(dict[str, object], verified["builder_query_identity"])
    with tempfile.TemporaryDirectory(
        prefix="autolean-library-substrate-builder-query-", dir="/tmp"
    ) as raw:
        root = Path(raw)
        candidate, source_sha256 = _write_builder_query_source(
            root / "accepted", BUILDER_QUERY_SOURCE
        )
        fresh_record = _builder_query_record(image, candidate, target=BUILDER_QUERY_TARGET)
        fresh = _validate_builder_query_record(
            fresh_record,
            expected_identity=identity,
            expected_source_sha256=source_sha256,
            expected_type_sha256=None,
        )
        observed_type_sha256 = cast(str, fresh["canonical_type_sha256"])
        replay_record = _builder_query_record(
            image,
            candidate,
            target=BUILDER_QUERY_TARGET,
            expected_type_sha256=observed_type_sha256,
        )
        replay = _validate_builder_query_record(
            replay_record,
            expected_identity=identity,
            expected_source_sha256=source_sha256,
            expected_type_sha256=observed_type_sha256,
        )

        negative_specs = (
            (
                "theorem_body",
                BUILDER_QUERY_THEOREM_SOURCE,
                BUILDER_QUERY_TARGET,
                "Candidate source contains proof-bearing or executable declaration syntax",
                None,
            ),
            (
                "extra_declaration",
                BUILDER_QUERY_EXTRA_DECLARATION_SOURCE,
                BUILDER_QUERY_TARGET,
                "Candidate owns declarations other than the requested carrier",
                None,
            ),
            (
                "forbidden_import",
                BUILDER_QUERY_FORBIDDEN_IMPORT_SOURCE,
                BUILDER_QUERY_TARGET,
                "Candidate direct imports differ from the Builder statement profile",
                None,
            ),
            (
                "target_oracle_import",
                BUILDER_QUERY_TARGET_IMPORT_SOURCE,
                BUILDER_QUERY_TARGET,
                "phase=compile failed",
                None,
            ),
            (
                "missing_target",
                BUILDER_QUERY_MISSING_TARGET_SOURCE,
                BUILDER_QUERY_TARGET,
                "requested target is not owned by Candidate",
                None,
            ),
            (
                "non_owned_target",
                BUILDER_QUERY_SOURCE,
                TARGET_DECLARATION,
                "target declaration is outside the Candidate namespace",
                None,
            ),
            (
                "statement_true_drift",
                BUILDER_QUERY_TRUE_SOURCE,
                BUILDER_QUERY_TARGET,
                "observed carrier type differs from the replay expectation",
                observed_type_sha256,
            ),
        )
        negatives: dict[str, object] = {}
        for label, source, target, reason, replay_hash in negative_specs:
            negative_candidate, _ = _write_builder_query_source(root / label, source)
            negatives[label] = _expect_builder_query_rejected(
                image,
                negative_candidate,
                label=label,
                target=target,
                reason_marker=reason,
                expected_type_sha256=replay_hash,
            )
    return {
        "authority": "operator-local-builder-observation-preflight-only",
        "fresh_observation": fresh,
        "image": image,
        "image_id": verified["image_id"],
        "negative_cases": negatives,
        "non_claims": [
            "no_bundle_registration",
            "no_contract_or_gateway_integration",
            "no_formal_asset_admission",
            "no_proof_submission_or_acceptance",
            "no_t6_completion",
        ],
        "replay_observation": replay,
        "schema_version": BUILDER_QUERY_CANARY_SCHEMA,
    }


def canary(image: str) -> dict[str, object]:
    verified = verify(image)
    manifest = cast(dict[str, object], verified["runtime_manifest"])
    receipt = cast(dict[str, object], verified["receipt"])
    runtime_files, records, auxiliary = _validate_manifest(manifest, receipt=receipt)
    with tempfile.TemporaryDirectory(
        prefix="autolean-library-substrate-candidate-", dir="/tmp"
    ) as raw:
        root = Path(raw)
        candidate, candidate_sha256 = _snapshot_candidate(root / "source")
        compiled = _compile_candidate(image, candidate, root / "compiled")
        compiled_sha256 = _sha256(compiled)
        query = _query_candidate(image, compiled)
    observation = _validate_query(
        query,
        runtime_files=runtime_files,
        verified_runtime_files=cast(
            dict[str, dict[str, object]], verified["verified_runtime_files"]
        ),
        manifest_records=records,
        manifest_auxiliary=auxiliary,
        expected_identity={
            "image_receipt_sha256": verified["image_receipt_sha256"],
            "profile_sha256": receipt["profile_sha256"],
            "query_wrapper_sha256": receipt["query_wrapper_sha256"],
            "runtime_manifest_sha256": receipt["runtime_manifest_sha256"],
        },
    )
    return {
        "authority": "operator-local-image-owned-preflight-only",
        "candidate_olean_sha256": compiled_sha256,
        "candidate_source_sha256": candidate_sha256,
        "image": image,
        "image_id": verified["image_id"],
        "non_claims": [
            "no_contract_or_gateway_integration",
            "no_external_dependency_capsule",
            "no_formal_asset_admission",
            "no_provider_execution",
            "no_v2_evidence_or_gateway_receipt",
        ],
        "observation": observation,
        "parent_receipt_canonical_sha256": verified["parent_receipt_canonical_sha256"],
        "receipt_canonical_sha256": _sha256_bytes(_canonical_json_bytes(receipt)),
        "schema_version": CANARY_SCHEMA,
        "task_mode": "independent_reproof",
    }


def v2_facade_canary(image: str) -> dict[str, object]:
    """Exercise the unchanged V2 argv and result shape against one recorded child digest."""

    verified = verify(image)
    identity = cast(dict[str, str], verified["v2_facade_identity"])
    with tempfile.TemporaryDirectory(
        prefix="autolean-library-substrate-v2-facade-", dir="/tmp"
    ) as raw:
        root = Path(raw)
        candidate, candidate_sha256 = _snapshot_candidate(root / "independent")
        compiled = _v2_compile_candidate(image, candidate, root / "compiled")
        record = _v2_query_candidate(image, compiled)

        compositional_root = root / "compositional"
        compositional_root.mkdir()
        compositional_candidate = compositional_root / "Candidate.lean"
        compositional_candidate.write_bytes(
            _regular_bytes(
                FIXTURE_ROOT / "candidates" / "compositional_bridge" / "Candidate.lean",
                label="compositional Candidate source",
            )
        )
        compositional_candidate.chmod(0o444)
        compositional_rejection = _expect_v2_candidate_rejected(
            image,
            compositional_candidate,
            label="compositional",
            expected_phase="compile",
            expected_returncode=20,
            reason_marker="Targets/DerivSound.olean",
            expected_candidate_source_sha256=V2_COMPOSITIONAL_CANDIDATE_SHA256,
        )

        target_import_root = root / "target-import"
        target_import_root.mkdir()
        target_import_candidate = target_import_root / "Candidate.lean"
        target_import_candidate.write_text(
            V2_TARGET_IMPORT_SOURCE,
            encoding="utf-8",
            newline="\n",
        )
        target_import_candidate.chmod(0o444)
        target_import_rejection = _expect_v2_candidate_rejected(
            image,
            target_import_candidate,
            label="target-import",
            expected_phase="compile",
            expected_returncode=20,
            reason_marker="Targets/ClosedSound.olean",
            expected_candidate_source_sha256=V2_TARGET_IMPORT_SOURCE_SHA256,
        )

        wrong_target_type_root = root / "wrong-target-type"
        wrong_target_type_root.mkdir()
        wrong_target_type_candidate = wrong_target_type_root / "Candidate.lean"
        wrong_target_type_candidate.write_text(
            V2_WRONG_TARGET_TYPE_SOURCE,
            encoding="utf-8",
            newline="\n",
        )
        wrong_target_type_candidate.chmod(0o444)
        wrong_target_type_rejection = _expect_v2_candidate_rejected(
            image,
            wrong_target_type_candidate,
            label="wrong-target-type",
            expected_phase="query",
            expected_returncode=21,
            reason_marker="Candidate target type differs from the historical frozen hash",
            expected_candidate_source_sha256=V2_WRONG_TARGET_TYPE_SOURCE_SHA256,
        )

    observation = _validate_v2_facade_record(record, identity=identity)
    return {
        "authority": "operator-local-v2-compatible-preflight-only",
        "candidate_source_sha256": candidate_sha256,
        "image": image,
        "image_id": verified["image_id"],
        "negative_cases": {
            "compositional_candidate": compositional_rejection,
            "target_import_candidate": target_import_rejection,
            "wrong_target_type_candidate": wrong_target_type_rejection,
        },
        "non_claims": [
            "no_contract_or_gateway_integration",
            "no_formal_asset_admission",
            "no_provider_execution",
            "no_t6_completion",
        ],
        "observation": observation,
        "schema_version": V2_FACADE_CANARY_SCHEMA,
        "task_mode": "independent_reproof",
    }


def _wsl_path(path: Path) -> str:
    completed = _run(
        ["wsl.exe", "-d", WSL_DISTRIBUTION, "-e", "wslpath", "-a", str(path)],
        timeout=30,
    )
    translated = completed.stdout.strip()
    if not translated:
        fail("WSL path translation returned an empty path")
    return translated


def _delegate_to_wsl(arguments: argparse.Namespace) -> int:
    script = Path(__file__).resolve()
    forwarded = [
        "wsl.exe",
        "-d",
        WSL_DISTRIBUTION,
        "--cd",
        _wsl_path(script.parents[2]),
        "--",
        "python3",
        _wsl_path(script),
        arguments.action,
        "--native",
    ]
    if arguments.image is not None:
        forwarded.extend(("--image", arguments.image))
    return subprocess.run(forwarded, check=False).returncode


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=(
            "build",
            "verify",
            "canary",
            "facade-canary",
            "builder-query-canary",
            "all",
        ),
    )
    parser.add_argument("--image")
    parser.add_argument("--native", action="store_true", help=argparse.SUPPRESS)
    parsed = parser.parse_args(arguments)
    if (
        parsed.action
        in {
            "verify",
            "canary",
            "facade-canary",
            "builder-query-canary",
        }
        and parsed.image is None
    ):
        parser.error(f"{parsed.action} requires --image")
    if parsed.action in {"build", "all"} and parsed.image is not None:
        parser.error(f"{parsed.action} does not accept --image")
    return parsed


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = parse_arguments(arguments)
    if os.name == "nt" and not parsed.native:
        return _delegate_to_wsl(parsed)
    try:
        if parsed.action == "build":
            result = build()
        elif parsed.action == "verify":
            result = verify(cast(str, parsed.image))
        elif parsed.action == "canary":
            result = canary(cast(str, parsed.image))
        elif parsed.action == "facade-canary":
            result = v2_facade_canary(cast(str, parsed.image))
        elif parsed.action == "builder-query-canary":
            result = builder_query_canary(cast(str, parsed.image))
        else:
            build_result = build()
            result = {
                "build": build_result,
                "canary": canary(cast(str, build_result["image"])),
                "builder_query_canary": builder_query_canary(cast(str, build_result["image"])),
                "v2_facade_canary": v2_facade_canary(cast(str, build_result["image"])),
                "schema_version": "autolean.library-substrate-image-all.v1",
            }
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        return 0
    except (SubstrateImageError, SystemExit) as error:
        print(f"library-substrate-image: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
