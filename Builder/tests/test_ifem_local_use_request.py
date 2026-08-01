"""Focused boundaries for the pending iFEM local-use request."""

from __future__ import annotations

import ast
import hashlib
import json
import shutil
from pathlib import Path
from typing import cast

import pytest
from autolean_builder import ifem_local_use_request as local_use
from autolean_contracts import canonical_json_bytes


def _manifest_copy(tmp_path: Path) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    destination = tmp_path / "phase-2-active-lanes.v1.json"
    shutil.copyfile(local_use.DEFAULT_DISCOVERY_MANIFEST_PATH, destination)
    return destination


def _read_object(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return cast(dict[str, object], payload)


def _write_object(path: Path, payload: dict[str, object]) -> None:
    path.write_bytes(canonical_json_bytes(payload) + b"\n")


def test_default_request_binds_the_exact_iFEM_local_only_lane() -> None:
    request = local_use.build_ifem_local_use_request_from_manifest()

    assert request.source.lane_id == "ifem-coercive-galerkin"
    assert request.source.source_lock_receipt_sha256 == (
        "74eca6689fe69dcbf2f34ea524a99cacc2054c0a39cfecfb11887c29e13cf239"
    )
    assert request.source.reference_manifest_candidate_sha256 == (
        "4a5d859d77b606d6e485d98bd3e4afc41f6c566c6fb09f5e3dc2b2a539f18398"
    )
    assert request.source.license.expression == "CC-BY-4.0"
    assert request.source.license.license_url == "https://creativecommons.org/licenses/by/4.0/"
    assert request.requested_scope.local_model_processing == "requested_not_authorized"
    assert request.requested_scope.requested_endpoint_class == "local"
    assert request.requested_scope.external_source_text_egress == "forbidden"
    assert request.requested_scope.source_redistribution == "forbidden"
    assert request.requested_scope.source_training == "forbidden"
    assert request.requested_scope.source_embedding == "forbidden"
    assert request.authority.rights_record_created is False
    assert request.authority.rights_decision_authorized is False
    assert request.authority.local_processing_authorized is False
    assert request.authority.external_egress_authorized is False
    assert request.authority.model_execution_authorized is False
    assert request.authority.builder_freeze_authorized is False
    assert request.authority.prover_handoff_authorized is False


def test_request_cannot_be_used_as_rights_or_handoff_authority() -> None:
    request = local_use.build_ifem_local_use_request_from_manifest()

    for operation in (
        request.assert_not_authoritative,
        request.freeze_statement,
        request.handoff_to_prover,
    ):
        with pytest.raises(local_use.IFEMLocalUseRequestError, match="pending a source-rights"):
            operation()


def test_request_replays_the_full_canonical_discovery_manifest(tmp_path: Path) -> None:
    manifest_path = _manifest_copy(tmp_path)
    request = local_use.build_ifem_local_use_request_from_manifest(manifest_path)
    local_use.verify_ifem_local_use_request_against_manifest(request, manifest_path)

    payload = _read_object(manifest_path)
    lanes = cast(list[dict[str, object]], payload["lanes"])
    unrelated_lane = next(lane for lane in lanes if lane["lane_id"] == "pde-a-classical-transport")
    overlap = cast(dict[str, object], unrelated_lane["mathlib_overlap"])
    overlap["discovery_note"] = "Changed after this pending local-use request was rendered."
    _write_object(manifest_path, payload)

    with pytest.raises(
        local_use.IFEMLocalUseRequestError,
        match="differs from exact discovery manifest replay",
    ):
        local_use.verify_ifem_local_use_request_against_manifest(request, manifest_path)


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    (
        ("license_expression", "CC-BY-SA-4.0", "license metadata drifted"),
        ("resolved_revision", "b" * 40, "revision drifted"),
        ("source_lock_receipt_sha256", "b" * 64, "source-lock receipt drifted"),
        (
            "reference_manifest_candidate_sha256",
            "b" * 64,
            "reference-manifest candidate drifted",
        ),
    ),
)
def test_manifest_source_or_license_drift_is_rejected_before_request_creation(
    tmp_path: Path,
    field: str,
    replacement: str,
    message: str,
) -> None:
    manifest_path = _manifest_copy(tmp_path)
    payload = _read_object(manifest_path)
    lanes = cast(list[dict[str, object]], payload["lanes"])
    ifem = next(lane for lane in lanes if lane["lane_id"] == "ifem-coercive-galerkin")
    source = cast(dict[str, object], ifem["source"])
    source[field] = replacement
    _write_object(manifest_path, payload)

    with pytest.raises(local_use.IFEMLocalUseRequestError, match=message):
        local_use.build_ifem_local_use_request_from_manifest(manifest_path)


def test_strict_canonical_write_once_and_replay(tmp_path: Path) -> None:
    manifest_path = _manifest_copy(tmp_path / "inputs")
    output = tmp_path / "ifem-local-use-request.json"

    request = local_use.materialize_ifem_local_use_request_from_manifest_once(output, manifest_path)
    assert (
        local_use.materialize_ifem_local_use_request_from_manifest_once(output, manifest_path)
        == request
    )
    assert local_use.load_ifem_local_use_request(output) == request
    local_use.verify_ifem_local_use_request_against_manifest(request, manifest_path)

    output.write_bytes(b'{"schema_version":"first","schema_version":"second"}\n')
    with pytest.raises(local_use.IFEMLocalUseRequestError, match="duplicate JSON key"):
        local_use.load_ifem_local_use_request(output)

    output.write_bytes(b"different\n")
    with pytest.raises(local_use.IFEMLocalUseRequestError, match="already exists"):
        local_use.materialize_ifem_local_use_request_from_manifest_once(output, manifest_path)


def test_rehashed_request_that_widens_a_prohibition_is_rejected() -> None:
    request = local_use.build_ifem_local_use_request_from_manifest()
    payload = request.model_dump(mode="json")
    scope = cast(dict[str, object], payload["requested_scope"])
    scope["external_source_text_egress"] = "allowed"
    payload["content_sha256"] = hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in payload.items() if key != "content_sha256"}
        )
    ).hexdigest()

    with pytest.raises(ValueError, match="Input should be 'forbidden'"):
        local_use.IFEMLocalUseRequestV1.model_validate(payload)


def test_rendering_has_no_source_text_path_or_prompt_payload_and_no_runtime_dependencies() -> None:
    request = local_use.build_ifem_local_use_request_from_manifest()
    rendered = local_use.render_ifem_local_use_request(request)
    document = json.loads(rendered)
    assert isinstance(document, dict)
    assert document["source_text_included"] is False
    assert document["source_path_included"] is False
    assert document["prompt_included"] is False
    for forbidden in (
        b'"source_text"',
        b'"source_path"',
        b'"prompt"',
        b"intro.md",
        b"primal/",
        b".cache/",
    ):
        assert forbidden not in rendered

    module_path = Path(local_use.__file__)
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    imported_roots = {
        alias.name.split(".", 1)[0]
        for statement in ast.walk(tree)
        if isinstance(statement, ast.Import)
        for alias in statement.names
    }
    imported_roots.update(
        statement.module.split(".", 1)[0]
        for statement in ast.walk(tree)
        if isinstance(statement, ast.ImportFrom) and statement.module is not None
    )
    assert not imported_roots.intersection(
        {"benchmarks", "http", "httpx", "openai", "Prover", "requests", "urllib"}
    )
