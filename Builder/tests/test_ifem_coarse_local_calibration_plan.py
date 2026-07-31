"""Focused boundaries for the text-free iFEM coarse local calibration plan."""

from __future__ import annotations

import ast
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from autolean_builder import ifem_coarse_local_calibration_plan as coarse_plan
from autolean_builder.ifem_local_use_request import build_ifem_local_use_request_from_manifest
from autolean_builder.ifem_notebook_source_span_index import (
    IFEMNotebookCellSourceSpanV1,
    IFEMNotebookSourceSpanIndexV1,
    IFEMSourceLockBindingV1,
    render_ifem_notebook_source_span_index,
)
from autolean_contracts import canonical_json_bytes, stable_identifier

ROOT = Path(__file__).resolve().parents[2]
PLAN_PATH = (
    ROOT
    / "Builder"
    / "pilots"
    / "ifem-source-alignment"
    / "ifem-coarse-local-calibration-plan.v1.json"
)
_OPENING_PATH = "primal/first_example.ipynb"


def _synthetic_text_free_index(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[IFEMNotebookSourceSpanIndexV1, str]:
    spans = tuple(
        IFEMNotebookCellSourceSpanV1(
            span_id=stable_identifier(
                "ifem.notebook-source-span",
                f"{coarse_plan.CURRENT_SOURCE_REVISION}:{_OPENING_PATH}:cell:{cell_index}",
            ),
            source_path=_OPENING_PATH,
            source_reference_id="ifem-test-notebook",
            source_file_sha256="e" * 64,
            source_file_index=0,
            cell_index=cell_index,
            cell_type="markdown",
            cell_content_sha256=f"{cell_index + 1:x}" * 64,
            cell_character_count=100 + cell_index,
        )
        for cell_index in range(4)
    )
    index = IFEMNotebookSourceSpanIndexV1(
        source_lock=IFEMSourceLockBindingV1(
            source_lock_sha256=coarse_plan.CURRENT_SOURCE_LOCK_RECEIPT_SHA256,
            source_revision=coarse_plan.CURRENT_SOURCE_REVISION,
            source_retrieved_at=datetime(2026, 7, 29, tzinfo=UTC),
            source_file_count=1,
            notebook_file_count=1,
        ),
        notebook_cell_count=4,
        spans=spans,
    )
    rendered_sha256 = hashlib.sha256(render_ifem_notebook_source_span_index(index)).hexdigest()
    signatures = tuple(
        (
            span.span_id.value,
            span.source_file_sha256,
            span.source_file_index,
            span.cell_index,
            span.cell_type,
            span.cell_content_sha256,
            span.cell_character_count,
        )
        for span in spans
    )
    monkeypatch.setattr(coarse_plan, "_CURRENT_SOURCE_FILE_COUNT", 1)
    monkeypatch.setattr(coarse_plan, "_CURRENT_NOTEBOOK_FILE_COUNT", 1)
    monkeypatch.setattr(coarse_plan, "_CURRENT_NOTEBOOK_CELL_COUNT", 4)
    monkeypatch.setattr(coarse_plan, "_CURRENT_OPENING_SPAN_SIGNATURES", signatures)
    monkeypatch.setattr(
        coarse_plan,
        "CURRENT_NOTEBOOK_INDEX_CANONICAL_SHA256",
        index.canonical_sha256(),
    )
    monkeypatch.setattr(
        coarse_plan,
        "CURRENT_NOTEBOOK_INDEX_RENDERED_SHA256",
        rendered_sha256,
    )
    return index, rendered_sha256


def _synthetic_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> coarse_plan.IFEMCoarseLocalCalibrationPlanV1:
    index, rendered_sha256 = _synthetic_text_free_index(monkeypatch)
    return coarse_plan.build_ifem_coarse_local_calibration_plan(
        notebook_index=index,
        notebook_index_rendered_sha256=rendered_sha256,
        pending_local_use_request=build_ifem_local_use_request_from_manifest(),
    )


def _rebind_tampered_plan(payload: dict[str, object]) -> None:
    source_lock = cast(dict[str, object], payload["source_lock"])
    notebook_index = cast(dict[str, object], payload["notebook_index"])
    request = cast(dict[str, object], payload["pending_local_use_request"])
    opening_spans = tuple(
        coarse_plan.IFEMCoarseLocalCalibrationSpanBindingV1.model_validate(span)
        for span in cast(list[dict[str, object]], payload["opening_spans"])
    )
    payload["plan_id"] = coarse_plan._plan_id(
        source_lock_sha256=cast(str, source_lock["receipt_sha256"]),
        notebook_index_sha256=cast(str, notebook_index["canonical_sha256"]),
        opening_spans=opening_spans,
        local_use_request_sha256=cast(str, request["content_sha256"]),
    ).model_dump(mode="json")
    payload["content_sha256"] = hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in payload.items() if key != "content_sha256"}
        )
    ).hexdigest()


def test_tracked_plan_is_strict_canonical_and_binds_current_public_identities() -> None:
    plan = coarse_plan.load_ifem_coarse_local_calibration_plan(PLAN_PATH)

    assert plan.content_sha256 == (
        "17072812c03c38463aec3c3569cae15b046dfeb482577ba1f2185cc74df6fe1f"
    )
    assert plan.source_lock.receipt_sha256 == coarse_plan.CURRENT_SOURCE_LOCK_RECEIPT_SHA256
    assert plan.notebook_index.canonical_sha256 == (
        coarse_plan.CURRENT_NOTEBOOK_INDEX_CANONICAL_SHA256
    )
    assert plan.notebook_index.rendered_sha256 == (
        coarse_plan.CURRENT_NOTEBOOK_INDEX_RENDERED_SHA256
    )
    assert plan.pending_local_use_request.content_sha256 == (
        coarse_plan.CURRENT_LOCAL_USE_REQUEST_SHA256
    )
    assert [span.cell_index for span in plan.opening_spans] == [0, 1, 2, 3]
    assert all(span.cell_type == "markdown" for span in plan.opening_spans)
    assert coarse_plan.render_ifem_coarse_local_calibration_plan(plan) == PLAN_PATH.read_bytes()


def test_builds_from_typed_text_free_inputs_without_synthetic_calibration_reuse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _synthetic_plan(monkeypatch)

    assert plan.source_text_present is False
    assert plan.model_input_present is False
    assert plan.executable is False
    assert plan.synthetic_self_calibration_reused is False
    assert plan.selection_state == "coarse_source_containers_not_claim_spans"
    assert plan.blockers == (
        "rights_decision_missing",
        "local_model_processing_not_authorized",
    )
    assert all(value is False for name, value in plan.authority if name != "schema_version")


def test_plan_always_rejects_execution_freeze_and_prover_handoff() -> None:
    plan = coarse_plan.load_ifem_coarse_local_calibration_plan(PLAN_PATH)

    for operation in (
        plan.assert_non_executable,
        plan.freeze_statement,
        plan.handoff_to_prover,
    ):
        with pytest.raises(
            coarse_plan.IFEMCoarseLocalCalibrationPlanError,
            match="blocked before local model processing",
        ):
            operation()


def test_rendered_plan_has_no_payload_provider_endpoint_or_path_surface() -> None:
    rendered = PLAN_PATH.read_bytes()
    document = json.loads(rendered)

    assert isinstance(document, dict)
    for forbidden in (
        b'"source_text"',
        b'"cell_text"',
        b'"source_path"',
        b'"private_path"',
        b'"cache_root"',
        b'"model_input"',
        b'"prompt"',
        b'"provider"',
        b'"provider_id"',
        b'"endpoint"',
        b'"endpoint_url"',
        b"primal/",
        b".cache",
        b"AppData",
        b":\\\\",
    ):
        assert forbidden not in rendered


@pytest.mark.parametrize(
    "forbidden_key",
    ("provider_id", "endpoint_url", "private_path", "source_path", "model_input"),
)
def test_recursive_render_guard_rejects_forbidden_nested_fields(forbidden_key: str) -> None:
    with pytest.raises(
        coarse_plan.IFEMCoarseLocalCalibrationPlanError,
        match="plan rendering exposed",
    ):
        coarse_plan._reject_forbidden_surface({"nested": {forbidden_key: "forbidden"}})


def test_rehashed_authority_or_blocker_widening_is_rejected() -> None:
    plan = coarse_plan.load_ifem_coarse_local_calibration_plan(PLAN_PATH)
    payload = plan.model_dump(mode="json")
    authority = cast(dict[str, object], payload["authority"])
    authority["local_model_processing_authorized"] = True
    blockers = cast(list[str], payload["blockers"])
    blockers.clear()
    payload["content_sha256"] = hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in payload.items() if key != "content_sha256"}
        )
    ).hexdigest()

    with pytest.raises(ValueError):
        coarse_plan.IFEMCoarseLocalCalibrationPlanV1.model_validate(payload)


@pytest.mark.parametrize(
    "tamper",
    (
        "remove_opening_cell",
        "change_pending_rights_hash",
        "add_provider_field",
    ),
)
def test_rehashed_scope_or_execution_surface_tampering_is_rejected(tamper: str) -> None:
    plan = coarse_plan.load_ifem_coarse_local_calibration_plan(PLAN_PATH)
    payload = plan.model_dump(mode="json")
    if tamper == "remove_opening_cell":
        cast(list[dict[str, object]], payload["opening_spans"]).pop()
    elif tamper == "change_pending_rights_hash":
        request = cast(dict[str, object], payload["pending_local_use_request"])
        request["content_sha256"] = "0" * 64
    else:
        payload["provider_id"] = "forbidden-provider"
    _rebind_tampered_plan(payload)

    with pytest.raises(ValueError):
        coarse_plan.IFEMCoarseLocalCalibrationPlanV1.model_validate(payload)


def test_current_input_drift_fails_closed_before_plan_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    index, _ = _synthetic_text_free_index(monkeypatch)

    with pytest.raises(
        coarse_plan.IFEMCoarseLocalCalibrationPlanError,
        match="persisted notebook-index identity does not match",
    ):
        coarse_plan.build_ifem_coarse_local_calibration_plan(
            notebook_index=index,
            notebook_index_rendered_sha256="0" * 64,
            pending_local_use_request=build_ifem_local_use_request_from_manifest(),
        )


def test_loader_rejects_duplicate_keys_noncanonical_bytes_and_nonfinite_json(
    tmp_path: Path,
) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_bytes(b'{"schema_version":"one","schema_version":"two"}\n')
    with pytest.raises(coarse_plan.IFEMCoarseLocalCalibrationPlanError, match="duplicate JSON"):
        coarse_plan.load_ifem_coarse_local_calibration_plan(duplicate)

    noncanonical = tmp_path / "noncanonical.json"
    noncanonical.write_bytes(
        PLAN_PATH.read_bytes().replace(b'{"artifact_kind"', b'{ "artifact_kind"')
    )
    with pytest.raises(
        coarse_plan.IFEMCoarseLocalCalibrationPlanError,
        match="not canonically rendered",
    ):
        coarse_plan.load_ifem_coarse_local_calibration_plan(noncanonical)

    nonfinite = tmp_path / "nonfinite.json"
    nonfinite.write_bytes(b'{"value":NaN}\n')
    with pytest.raises(
        coarse_plan.IFEMCoarseLocalCalibrationPlanError,
        match="non-finite JSON constant",
    ):
        coarse_plan.load_ifem_coarse_local_calibration_plan(nonfinite)
    with pytest.raises(
        coarse_plan.IFEMCoarseLocalCalibrationPlanError,
        match="non-finite JSON constant",
    ):
        coarse_plan._load_notebook_index(b'{"value":Infinity}\n')


def test_write_once_materialization_is_idempotent_and_rejects_conflicts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _synthetic_plan(monkeypatch)
    monkeypatch.setattr(
        coarse_plan,
        "build_current_ifem_coarse_local_calibration_plan",
        lambda **_kwargs: plan,
    )
    monkeypatch.setattr(
        coarse_plan,
        "verify_ifem_coarse_local_calibration_plan_against_current_inputs",
        lambda *_args, **_kwargs: None,
    )
    output = tmp_path / "plan.json"

    assert coarse_plan.materialize_ifem_coarse_local_calibration_plan_once(output) == plan
    first = output.read_bytes()
    assert coarse_plan.materialize_ifem_coarse_local_calibration_plan_once(output) == plan
    assert output.read_bytes() == first

    conflict = tmp_path / "conflict.json"
    conflict.write_bytes(b"different\n")
    with pytest.raises(
        coarse_plan.IFEMCoarseLocalCalibrationPlanError,
        match="already exists with different bytes",
    ):
        coarse_plan.materialize_ifem_coarse_local_calibration_plan_once(conflict)


def test_missing_local_cache_fails_closed_without_creating_an_artifact(tmp_path: Path) -> None:
    missing = tmp_path / "missing"

    with pytest.raises(
        coarse_plan.IFEMCoarseLocalCalibrationPlanError,
        match="cache is absent",
    ):
        coarse_plan.build_current_ifem_coarse_local_calibration_plan(cache_root=missing)
    assert not missing.exists()


def test_confined_reader_rejects_symbolic_links(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_bytes(b"{}\n")
    link = tmp_path / "link.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symbolic-link creation is unavailable in this environment")

    with pytest.raises(
        coarse_plan.IFEMCoarseLocalCalibrationPlanError,
        match="absent or escapes",
    ):
        coarse_plan._read_confined_regular_file(
            link,
            root=tmp_path.resolve(strict=True),
            label="test input",
        )


def test_module_has_no_model_network_prover_or_synthetic_calibration_dependency() -> None:
    module_path = Path(coarse_plan.__file__)
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
        {
            "Prover",
            "http",
            "httpx",
            "openai",
            "requests",
            "self_calibration",
            "socket",
            "urllib",
        }
    )
