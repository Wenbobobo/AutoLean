"""Generate a deterministic SPDX 2.3 JSON SBOM from the release lock inventory.

This generator deliberately describes lock-declared package identities and integrity
metadata. It does not inspect installed packages, source trees, host configuration,
or remote registries.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

from scripts.release_evidence import (
    INPUT_PATHS,
    InventoryError,
    _write_atomic,
    inventory_bytes,
)

SBOM_SCHEMA_VERSION = "autolean.spdx-lock-sbom.v1"
SPDX_VERSION = "SPDX-2.3"
SPDX_DOCUMENT_ID = "SPDXRef-DOCUMENT"
REPRODUCIBLE_CREATION_TIMESTAMP = "1970-01-01T00:00:00Z"
PROVENANCE_PREFIX = "AutoLean Phase 1 lock-input SBOM provenance: "
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_ABSOLUTE_PATH = re.compile(r"^[A-Za-z]:[\\/]")
_SRI_ALGORITHMS: dict[str, tuple[str, int]] = {
    "sha1": ("SHA1", 20),
    "sha256": ("SHA256", 32),
    "sha384": ("SHA384", 48),
    "sha512": ("SHA512", 64),
}


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
    if "\x00" in value:
        raise InventoryError(f"{context} may not contain NUL")
    return value


def _safe_metadata(value: object, context: str) -> str:
    raw = _string(value, context)
    if (
        "\\" in raw
        or raw.startswith(("/", "~", "file://"))
        or _WINDOWS_ABSOLUTE_PATH.match(raw) is not None
        or "://" in raw
    ):
        raise InventoryError(f"{context} may not contain an absolute path or locator")
    return raw


def _safe_relative_path(value: object, context: str) -> str:
    path = _string(value, context)
    candidate = PurePosixPath(path)
    if (
        "\\" in path
        or path.startswith("/")
        or _WINDOWS_ABSOLUTE_PATH.match(path) is not None
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise InventoryError(f"{context} must be a safe relative POSIX path")
    return path


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _inventory_and_digest(root: Path) -> tuple[dict[str, Any], str]:
    content = inventory_bytes(root)
    try:
        inventory = _mapping(json.loads(content), "release inventory")
    except json.JSONDecodeError as error:
        raise InventoryError(f"release inventory was not JSON: {error}") from error
    return inventory, _sha256_bytes(content)


def _spdx_id(prefix: str, identity: object) -> str:
    digest = _sha256_bytes(_canonical_json(identity))[:24]
    return f"SPDXRef-Package-{prefix}-{digest}"


def _sha256_checksum(value: object, context: str) -> dict[str, str]:
    raw = _string(value, context)
    prefix, separator, digest = raw.partition(":")
    if prefix != "sha256" or not separator or _HEX_DIGEST.fullmatch(digest) is None:
        raise InventoryError(f"{context} must be a sha256:<64 lowercase hex> digest")
    return {"algorithm": "SHA256", "checksumValue": digest}


def _sri_checksums(value: object, context: str) -> list[dict[str, str]]:
    integrity = _string(value, context)
    checksums: list[dict[str, str]] = []
    for token in integrity.split():
        algorithm, separator, encoded = token.partition("-")
        spdx_algorithm = _SRI_ALGORITHMS.get(algorithm.lower())
        if not separator or spdx_algorithm is None:
            raise InventoryError(f"{context} contains an unsupported SRI digest")
        try:
            digest = base64.b64decode(encoded, validate=True)
        except binascii.Error as error:
            raise InventoryError(f"{context} contains invalid base64 SRI data") from error
        expected_algorithm, expected_bytes = spdx_algorithm
        if len(digest) != expected_bytes:
            raise InventoryError(f"{context} has an unexpected {algorithm} digest length")
        checksums.append({"algorithm": expected_algorithm, "checksumValue": digest.hex()})
    return _sorted_unique_checksums(checksums)


def _sorted_unique_checksums(values: list[dict[str, str]]) -> list[dict[str, str]]:
    unique = {(value["algorithm"], value["checksumValue"]) for value in values}
    return [
        {"algorithm": algorithm, "checksumValue": checksum}
        for algorithm, checksum in sorted(unique)
    ]


def _package(
    *,
    spdx_id: str,
    name: str,
    version: str,
    purpose: str,
    comment: str,
    checksums: list[dict[str, str]],
) -> dict[str, object]:
    package: dict[str, object] = {
        "SPDXID": spdx_id,
        "copyrightText": "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "name": name,
        "primaryPackagePurpose": purpose,
        "versionInfo": version,
        "comment": comment,
    }
    if checksums:
        package["checksums"] = checksums
    return package


def _python_packages(inventory: dict[str, Any]) -> list[dict[str, object]]:
    python = _mapping(inventory.get("python"), "release inventory.python")
    packages: list[dict[str, object]] = []
    raw_packages = _list(python.get("packages"), "release inventory.python.packages")
    for index, raw_package in enumerate(raw_packages):
        package = _mapping(raw_package, f"release inventory.python.packages[{index}]")
        name = _safe_metadata(package.get("name"), f"python package[{index}].name")
        version = _safe_metadata(package.get("version"), f"python package[{index}].version")
        source = _mapping(package.get("source"), f"python package[{index}].source")
        source_kind = _safe_metadata(source.get("kind"), f"python package[{index}].source.kind")
        checksums = _sorted_unique_checksums(
            [
                _sha256_checksum(value, f"python package[{index}].artifact_hashes")
                for value in _list(
                    package.get("artifact_hashes"), f"python package[{index}].artifact_hashes"
                )
            ]
        )
        identity = {
            "ecosystem": "python",
            "name": name,
            "source_kind": source_kind,
            "version": version,
        }
        packages.append(
            _package(
                spdx_id=_spdx_id("Python", identity),
                name=name,
                version=version,
                purpose="APPLICATION" if source_kind in {"editable", "virtual"} else "LIBRARY",
                comment=f"Locked Python package; source kind: {source_kind}.",
                checksums=checksums,
            )
        )
    return packages


def _javascript_packages(inventory: dict[str, Any]) -> list[dict[str, object]]:
    javascript = _mapping(inventory.get("javascript"), "release inventory.javascript")
    packages: list[dict[str, object]] = []
    for index, raw_package in enumerate(
        _list(javascript.get("packages"), "release inventory.javascript.packages")
    ):
        package = _mapping(raw_package, f"release inventory.javascript.packages[{index}]")
        package_id = _safe_metadata(package.get("id"), f"javascript package[{index}].id")
        name = _safe_metadata(package.get("name"), f"javascript package[{index}].name")
        version = _safe_metadata(package.get("version"), f"javascript package[{index}].version")
        integrity = package.get("integrity")
        checksums = (
            _sri_checksums(integrity, f"javascript package[{index}].integrity")
            if integrity is not None
            else []
        )
        identity = {
            "ecosystem": "javascript",
            "id": package_id,
            "name": name,
            "version": version,
        }
        packages.append(
            _package(
                spdx_id=_spdx_id("JavaScript", identity),
                name=name,
                version=version,
                purpose="LIBRARY",
                comment="Locked JavaScript package from pnpm metadata.",
                checksums=checksums,
            )
        )
    return packages


def _input_provenance(inventory: dict[str, Any], inventory_sha256: str) -> dict[str, object]:
    records: list[dict[str, object]] = []
    for index, raw_record in enumerate(_list(inventory.get("inputs"), "release inventory.inputs")):
        record = _mapping(raw_record, f"release inventory.inputs[{index}]")
        byte_count = record.get("bytes")
        if not isinstance(byte_count, int) or byte_count < 0:
            raise InventoryError(
                f"release inventory.inputs[{index}].bytes must be a non-negative integer"
            )
        records.append(
            {
                "bytes": byte_count,
                "path": _safe_relative_path(
                    record.get("path"), f"release inventory.inputs[{index}].path"
                ),
                "sha256": _sha256_checksum(
                    "sha256:"
                    + _string(record.get("sha256"), f"release inventory.inputs[{index}].sha256"),
                    f"release inventory.inputs[{index}].sha256",
                )["checksumValue"],
            }
        )
    expected_paths = [path.as_posix() for path in INPUT_PATHS]
    if [record["path"] for record in records] != expected_paths:
        raise InventoryError("release inventory did not preserve the declared input set")
    return {
        "declared_lock_inputs": records,
        "inventory_schema_version": _safe_metadata(
            inventory.get("schema_version"), "release inventory.schema_version"
        ),
        "inventory_sha256": inventory_sha256,
        "sbom_schema_version": SBOM_SCHEMA_VERSION,
    }


def build_sbom(root: Path) -> dict[str, object]:
    """Build an SPDX 2.3 document from the canonical release inventory only."""
    inventory, inventory_sha256 = _inventory_and_digest(root)
    provenance = _input_provenance(inventory, inventory_sha256)
    packages = _python_packages(inventory) + _javascript_packages(inventory)
    packages.sort(key=lambda package: str(package["SPDXID"]))
    package_ids = [str(package["SPDXID"]) for package in packages]
    if len(package_ids) != len(set(package_ids)):
        raise InventoryError("SBOM package identity collision")
    return {
        "SPDXID": SPDX_DOCUMENT_ID,
        "comment": PROVENANCE_PREFIX
        + json.dumps(
            {
                "creation_timestamp": "fixed reproducibility marker; not installation evidence",
                "lock_input_provenance": provenance,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ),
        "creationInfo": {
            "created": REPRODUCIBLE_CREATION_TIMESTAMP,
            "creators": ["Tool: AutoLean lock-input SPDX generator"],
        },
        "dataLicense": "CC0-1.0",
        "documentDescribes": package_ids,
        "documentNamespace": f"urn:autolean:spdx:lock-input:{inventory_sha256}",
        "name": "AutoLean Phase 1 lock-input SBOM",
        "packages": packages,
        "relationships": [
            {
                "relatedSpdxElement": package_id,
                "relationshipType": "DESCRIBES",
                "spdxElementId": SPDX_DOCUMENT_ID,
            }
            for package_id in package_ids
        ],
        "spdxVersion": SPDX_VERSION,
    }


def sbom_bytes(root: Path) -> bytes:
    return _canonical_json(build_sbom(root))


def _iter_strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for nested in value for item in _iter_strings(nested)]
    if isinstance(value, dict):
        return [
            item
            for key, nested in value.items()
            for item in (_iter_strings(key) + _iter_strings(nested))
        ]
    return []


def _looks_like_absolute_path(value: str) -> bool:
    return value.startswith(("/", "\\\\", "file://")) or (
        _WINDOWS_ABSOLUTE_PATH.match(value) is not None
    )


def _parse_provenance(document: dict[str, Any]) -> dict[str, Any]:
    comment = _string(document.get("comment"), "SBOM comment")
    if not comment.startswith(PROVENANCE_PREFIX):
        raise InventoryError("SBOM document did not retain lock-input provenance")
    try:
        payload = json.loads(comment.removeprefix(PROVENANCE_PREFIX))
    except json.JSONDecodeError as error:
        raise InventoryError(f"SBOM provenance comment was not JSON: {error}") from error
    return _mapping(payload, "SBOM provenance comment")


def _validate_sbom_bytes(root: Path) -> tuple[bytes, str]:
    first = sbom_bytes(root)
    second = sbom_bytes(root)
    if first != second:
        raise InventoryError("SBOM is not deterministic")
    try:
        document = _mapping(json.loads(first), "generated SBOM")
    except json.JSONDecodeError as error:
        raise InventoryError(f"generated SBOM was not JSON: {error}") from error
    if document.get("spdxVersion") != SPDX_VERSION:
        raise InventoryError("generated SBOM has an unexpected SPDX version")
    provenance = _parse_provenance(document)
    lock_provenance = _mapping(provenance.get("lock_input_provenance"), "SBOM lock provenance")
    inventory, inventory_sha256 = _inventory_and_digest(root)
    if lock_provenance.get("inventory_sha256") != inventory_sha256:
        raise InventoryError("generated SBOM has an incorrect inventory digest")
    expected_inputs = _input_provenance(inventory, inventory_sha256)["declared_lock_inputs"]
    if lock_provenance.get("declared_lock_inputs") != expected_inputs:
        raise InventoryError("generated SBOM did not retain the declared input hashes")
    document_text = first.decode("utf-8")
    root_text = str(root.resolve()).replace("\\", "/")
    if root_text and root_text in document_text:
        raise InventoryError("generated SBOM leaked an absolute workspace path")
    if any(_looks_like_absolute_path(value) for value in _iter_strings(document)):
        raise InventoryError("generated SBOM contains an absolute path or file URI")
    for raw_package in _list(document.get("packages"), "generated SBOM packages"):
        package = _mapping(raw_package, "generated SBOM package")
        if package.get("downloadLocation") != "NOASSERTION":
            raise InventoryError("generated SBOM may not expose package download locations")
        if (
            package.get("licenseConcluded") != "NOASSERTION"
            or package.get("licenseDeclared") != "NOASSERTION"
        ):
            raise InventoryError("generated SBOM may not assert package licensing")
    return first, inventory_sha256


def _validate_output_path(root: Path, output: Path) -> Path:
    resolved_root = root.resolve()
    resolved_output = output.resolve()
    if not resolved_output.is_relative_to(resolved_root):
        raise InventoryError("SBOM output must stay within the workspace root")
    for protected in (resolved_root / ".agents", resolved_root / ".quarantine"):
        if resolved_output.is_relative_to(protected):
            raise InventoryError("SBOM output may not be written under a protected directory")
    return resolved_output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    generate = subcommands.add_parser("generate", help="write a canonical SPDX 2.3 JSON SBOM")
    generate.add_argument("--output", required=True, type=Path)
    generate.add_argument("--root", default=Path(__file__).resolve().parents[1], type=Path)
    check = subcommands.add_parser(
        "check", help="run the no-write determinism and redaction checks"
    )
    check.add_argument("--root", default=Path(__file__).resolve().parents[1], type=Path)
    args = parser.parse_args()

    root = args.root.resolve()
    try:
        content, inventory_sha256 = _validate_sbom_bytes(root)
        if args.command == "generate":
            _write_atomic(_validate_output_path(root, args.output), content)
        print(
            json.dumps(
                {
                    "inventory_sha256": inventory_sha256,
                    "sbom_sha256": _sha256_bytes(content),
                    "spdx_version": SPDX_VERSION,
                    "status": "ok",
                },
                ensure_ascii=True,
                sort_keys=True,
            )
        )
    except InventoryError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
