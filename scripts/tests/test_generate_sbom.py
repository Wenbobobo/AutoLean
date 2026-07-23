from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

import pytest

from scripts.generate_sbom import (
    PROVENANCE_PREFIX,
    REPRODUCIBLE_CREATION_TIMESTAMP,
    SBOM_SCHEMA_VERSION,
    SPDX_DOCUMENT_ID,
    SPDX_VERSION,
    _sri_checksums,
    _validate_output_path,
    build_sbom,
    sbom_bytes,
)
from scripts.release_evidence import build_inventory, inventory_bytes

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _provenance(document: dict[str, Any]) -> dict[str, Any]:
    comment = cast(str, document["comment"])
    assert comment.startswith(PROVENANCE_PREFIX)
    return cast(dict[str, Any], json.loads(comment.removeprefix(PROVENANCE_PREFIX)))


def test_spdx_sbom_is_deterministic_lock_bound_and_redacted() -> None:
    first = sbom_bytes(PROJECT_ROOT)
    second = sbom_bytes(PROJECT_ROOT)

    assert first == second
    document = cast(dict[str, Any], json.loads(first))
    inventory = cast(dict[str, Any], json.loads(inventory_bytes(PROJECT_ROOT)))
    provenance = _provenance(document)
    lock_provenance = cast(dict[str, Any], provenance["lock_input_provenance"])

    assert document["SPDXID"] == SPDX_DOCUMENT_ID
    assert document["spdxVersion"] == SPDX_VERSION
    assert document["creationInfo"]["created"] == REPRODUCIBLE_CREATION_TIMESTAMP
    assert document["documentNamespace"].endswith(lock_provenance["inventory_sha256"])
    assert lock_provenance["sbom_schema_version"] == SBOM_SCHEMA_VERSION
    assert (
        lock_provenance["inventory_sha256"]
        == hashlib.sha256(inventory_bytes(PROJECT_ROOT)).hexdigest()
    )
    assert lock_provenance["declared_lock_inputs"] == inventory["inputs"]
    assert str(PROJECT_ROOT) not in first.decode("utf-8")
    assert "https://" not in first.decode("utf-8")
    assert "file://" not in first.decode("utf-8")


def test_spdx_packages_are_lock_declared_and_do_not_make_license_or_download_claims() -> None:
    document = cast(dict[str, Any], build_sbom(PROJECT_ROOT))
    inventory = cast(dict[str, Any], build_inventory(PROJECT_ROOT))
    packages = cast(list[dict[str, Any]], document["packages"])
    python_names = {package["name"] for package in inventory["python"]["packages"]}
    javascript_names = {package["name"] for package in inventory["javascript"]["packages"]}

    assert {package["name"] for package in packages} == python_names | javascript_names
    assert all(package["downloadLocation"] == "NOASSERTION" for package in packages)
    assert all(package["licenseConcluded"] == "NOASSERTION" for package in packages)
    assert all(package["licenseDeclared"] == "NOASSERTION" for package in packages)
    assert document["documentDescribes"] == sorted(document["documentDescribes"])
    assert len(document["relationships"]) == len(packages)
    assert any(
        checksum["algorithm"] == "SHA512"
        for package in packages
        for checksum in package.get("checksums", [])
    )


def test_sri_integrity_is_normalized_to_spdx_hex_checksum() -> None:
    checksums = _sri_checksums("sha1-Lve95gjOVATpfV8EL5X4nxwjKHE=", "test integrity")

    assert checksums == [
        {"algorithm": "SHA1", "checksumValue": "2ef7bde608ce5404e97d5f042f95f89f1c232871"},
    ]


def test_output_path_cannot_escape_the_workspace(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="workspace root"):
        _validate_output_path(PROJECT_ROOT, tmp_path / "autolean.spdx.json")
