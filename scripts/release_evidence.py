"""Generate an offline, deterministic dependency and benchmark release inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
import tomllib
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "autolean.release-inventory.v1"
INPUT_PATHS = (
    Path("pyproject.toml"),
    Path("uv.lock"),
    Path("Dashboard/ui/pnpm-lock.yaml"),
    Path("benchmarks/fate.lock.json"),
    Path("benchmarks/fate-splits.v1.json"),
)
_PNPM_HEADER = re.compile(r"^  (?P<key>\S.*):$")
_PNPM_INTEGRITY = re.compile(r"\bintegrity:\s*(?P<value>[^,}\s]+)")


class InventoryError(ValueError):
    """Raised when a declared release input is absent or structurally unexpected."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _mapping(value: object, context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise InventoryError(f"{context} must be a string-keyed mapping")
    return value


def _list(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise InventoryError(f"{context} must be a list")
    return value


def _string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise InventoryError(f"{context} must be a non-empty string")
    return value


def _source_summary(value: object) -> dict[str, str]:
    source = _mapping(value, "uv package source")
    kind = next(
        (
            candidate
            for candidate in ("registry", "editable", "virtual", "git", "path")
            if candidate in source
        ),
        "unknown",
    )
    return {"kind": kind}


def _dependency_summary(value: object, context: str) -> dict[str, str]:
    if isinstance(value, str):
        return {"name": value}
    dependency = _mapping(value, context)
    summary = {"name": _string(dependency.get("name"), f"{context}.name")}
    marker = dependency.get("marker")
    if isinstance(marker, str) and marker:
        summary["marker"] = marker
    return summary


def _artifact_hashes(value: object, context: str) -> list[str]:
    if value is None:
        return []
    records = value if isinstance(value, list) else [value]
    hashes: list[str] = []
    for index, record in enumerate(records):
        artifact = _mapping(record, f"{context}[{index}]")
        digest = artifact.get("hash")
        if isinstance(digest, str) and digest:
            hashes.append(digest)
    return sorted(set(hashes))


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            return _mapping(tomllib.load(handle), path.as_posix())
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise InventoryError(f"cannot read {path.as_posix()}: {error}") from error


def _python_inventory(root: Path) -> dict[str, object]:
    project_file = _read_toml(root / "pyproject.toml")
    lock_file = _read_toml(root / "uv.lock")
    project = _mapping(project_file.get("project"), "pyproject project")
    workspace = _mapping(project_file.get("tool"), "pyproject tool")
    uv = _mapping(workspace.get("uv"), "pyproject tool.uv")
    workspace_config = _mapping(uv.get("workspace"), "pyproject tool.uv.workspace")
    package_entries: list[dict[str, object]] = []
    for index, raw_package in enumerate(_list(lock_file.get("package"), "uv.lock package")):
        package = _mapping(raw_package, f"uv.lock package[{index}]")
        dependencies = sorted(
            (
                _dependency_summary(raw_dependency, f"uv.lock package[{index}].dependencies")
                for raw_dependency in _list(package.get("dependencies", []), "uv dependencies")
            ),
            key=lambda dependency: (dependency["name"], dependency.get("marker", "")),
        )
        package_entries.append(
            {
                "artifact_hashes": sorted(
                    set(
                        _artifact_hashes(package.get("sdist"), "uv sdist")
                        + _artifact_hashes(package.get("wheels"), "uv wheels")
                    )
                ),
                "dependencies": dependencies,
                "name": _string(package.get("name"), f"uv.lock package[{index}].name"),
                "source": _source_summary(package.get("source", {})),
                "version": _string(package.get("version"), f"uv.lock package[{index}].version"),
            }
        )
    package_entries.sort(
        key=lambda package: (
            str(package["name"]),
            str(package["version"]),
            _canonical_json(package),
        )
    )
    manifest = _mapping(lock_file.get("manifest"), "uv.lock manifest")
    return {
        "lock": {
            "manifest_members": sorted(
                _string(member, "uv.lock manifest member")
                for member in _list(manifest.get("members"), "uv.lock manifest members")
            ),
            "requires_python": _string(lock_file.get("requires-python"), "uv.lock requires-python"),
            "revision": lock_file.get("revision"),
            "version": lock_file.get("version"),
        },
        "packages": package_entries,
        "workspace": {
            "license": _mapping(project.get("license"), "pyproject project.license").get("text"),
            "members": sorted(
                _string(member, "pyproject workspace member")
                for member in _list(workspace_config.get("members"), "pyproject workspace members")
            ),
            "name": _string(project.get("name"), "pyproject project.name"),
            "requires_python": _string(
                project.get("requires-python"), "pyproject project.requires-python"
            ),
            "version": _string(project.get("version"), "pyproject project.version"),
        },
    }


def _unquote_pnpm_key(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _pnpm_identity(key: str) -> tuple[str, str]:
    name, separator, version = key.rpartition("@")
    if not separator or not name or not version:
        raise InventoryError(f"unsupported pnpm package key: {key!r}")
    return name, version


def _javascript_inventory(root: Path) -> dict[str, object]:
    path = root / "Dashboard/ui/pnpm-lock.yaml"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise InventoryError(f"cannot read {path.as_posix()}: {error}") from error

    lockfile_version: str | None = None
    inside_packages = False
    current: dict[str, str] | None = None
    packages: list[dict[str, str]] = []

    def finish_current() -> None:
        nonlocal current
        if current is not None:
            packages.append(current)
            current = None

    for line in lines:
        if line.startswith("lockfileVersion:"):
            lockfile_version = line.split(":", 1)[1].strip().strip("'\"")
            continue
        if line == "packages:":
            inside_packages = True
            continue
        if inside_packages and line and not line.startswith(" "):
            finish_current()
            inside_packages = False
        if not inside_packages:
            continue
        header = _PNPM_HEADER.match(line)
        if header is not None:
            finish_current()
            key = _unquote_pnpm_key(header.group("key"))
            name, version = _pnpm_identity(key)
            current = {"id": key, "name": name, "version": version}
            continue
        if current is not None and line.startswith("    resolution:"):
            integrity = _PNPM_INTEGRITY.search(line)
            if integrity is not None:
                current["integrity"] = integrity.group("value")
    finish_current()
    if not lockfile_version:
        raise InventoryError("pnpm lockfile has no lockfileVersion")
    if not packages:
        raise InventoryError("pnpm lockfile has no packages section")
    packages.sort(key=lambda package: package["id"])
    return {"lockfile_version": lockfile_version, "packages": packages}


def _benchmark_inventory(root: Path) -> dict[str, object]:
    path = root / "benchmarks/fate.lock.json"
    split_path = root / "benchmarks/fate-splits.v1.json"
    try:
        lock = _mapping(json.loads(path.read_text(encoding="utf-8")), path.as_posix())
        split_bytes = split_path.read_bytes()
        split_manifest = _mapping(json.loads(split_bytes), split_path.as_posix())
    except (OSError, json.JSONDecodeError) as error:
        raise InventoryError(f"cannot read benchmark locks: {error}") from error
    if (
        split_manifest.get("schema_version") != "autolean.fate-splits.v1"
        or split_manifest.get("contains_solutions") is not False
        or split_manifest.get("report_tiers_separately") is not True
    ):
        raise InventoryError("FATE split manifest has an unsupported evidence boundary")
    tiers = _mapping(lock.get("tiers"), "fate.lock tiers")
    tier_entries: list[dict[str, object]] = []
    for tier_name in sorted(tiers):
        tier = _mapping(tiers[tier_name], f"fate.lock tier {tier_name}")
        tier_entries.append(
            {
                "count": tier.get("count"),
                "lake_manifest_sha256": tier.get("lake_manifest_sha256"),
                "metadata_json_sha256": tier.get("metadata_json_sha256"),
                "revision": tier.get("revision"),
                "tier": tier_name,
            }
        )
    return {
        "lean_version": lock.get("lean_version"),
        "license": lock.get("license"),
        "mathlib_revision": lock.get("mathlib_revision"),
        "revision": lock.get("revision"),
        "schema_version": lock.get("schema_version"),
        "split_manifest_sha256": _sha256_bytes(split_bytes),
        "split_schema_version": split_manifest.get("schema_version"),
        "split_seed": split_manifest.get("seed"),
        "suite": lock.get("suite"),
        "tiers": tier_entries,
    }


def _input_inventory(root: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for relative_path in INPUT_PATHS:
        path = root / relative_path
        try:
            content = path.read_bytes()
        except OSError as error:
            raise InventoryError(
                f"cannot read required input {relative_path.as_posix()}: {error}"
            ) from error
        records.append(
            {
                "bytes": len(content),
                "path": relative_path.as_posix(),
                "sha256": _sha256_bytes(content),
            }
        )
    return records


def build_inventory(root: Path) -> dict[str, object]:
    """Build the release inventory using only the declared, versioned input files."""
    root = root.resolve()
    return {
        "benchmark": _benchmark_inventory(root),
        "inputs": _input_inventory(root),
        "javascript": _javascript_inventory(root),
        "python": _python_inventory(root),
        "schema_version": SCHEMA_VERSION,
    }


def inventory_bytes(root: Path) -> bytes:
    return _canonical_json(build_inventory(root))


def _validate_inventory_bytes(root: Path) -> bytes:
    first = inventory_bytes(root)
    second = inventory_bytes(root)
    if first != second:
        raise InventoryError("release inventory is not deterministic")
    payload = _mapping(json.loads(first), "generated inventory")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise InventoryError("generated inventory has an unexpected schema version")
    input_paths = [record["path"] for record in _list(payload.get("inputs"), "generated inputs")]
    if input_paths != [path.as_posix() for path in INPUT_PATHS]:
        raise InventoryError("generated inventory did not preserve the declared input set")
    root_text = str(root).replace("\\", "/")
    if root_text and root_text in first.decode("utf-8"):
        raise InventoryError("generated inventory leaked an absolute workspace path")
    return first


def _write_atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as handle:
            handle.write(content)
            temporary_name = handle.name
        os.replace(temporary_name, path)
    except OSError as error:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)
        raise InventoryError(f"cannot write {path.as_posix()}: {error}") from error


def _validate_output_path(root: Path, output: Path) -> Path:
    resolved = output.resolve()
    for protected in (root / ".agents", root / ".quarantine"):
        if resolved.is_relative_to(protected.resolve()):
            raise InventoryError(
                "release evidence output may not be written under a protected directory"
            )
    return resolved


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    generate = subcommands.add_parser("generate", help="write a canonical inventory JSON file")
    generate.add_argument("--output", required=True, type=Path)
    generate.add_argument("--root", default=Path(__file__).resolve().parents[1], type=Path)
    check = subcommands.add_parser(
        "check", help="run the no-write determinism and redaction self-check"
    )
    check.add_argument("--root", default=Path(__file__).resolve().parents[1], type=Path)
    args = parser.parse_args()

    root = args.root.resolve()
    try:
        content = _validate_inventory_bytes(root)
        if args.command == "generate":
            _write_atomic(_validate_output_path(root, args.output), content)
        print(
            json.dumps(
                {"inventory_sha256": _sha256_bytes(content), "status": "ok"},
                ensure_ascii=True,
                sort_keys=True,
            )
        )
    except InventoryError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
