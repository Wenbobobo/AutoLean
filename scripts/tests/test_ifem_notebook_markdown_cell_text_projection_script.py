from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import pytest
from autolean_builder import ifem_notebook_markdown_cell_text_projection as projection
from autolean_builder.ifem_notebook_source_span_index import (
    build_ifem_notebook_source_span_index,
    render_ifem_notebook_source_span_index,
)
from autolean_contracts import canonical_json_bytes

from scripts import ifem_notebook_markdown_cell_text_projection as cli
from scripts import ifem_source_lock as source_lock

_LICENSE = b"""Creative Commons Attribution 4.0 International

This work is licensed under the Creative Commons Attribution 4.0 International License.
To view a copy of this license, visit http://creativecommons.org/licenses/by/4.0/
or send a letter to Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.
"""
_SOURCE_PATH = "abstracttheory/Coercive.ipynb"
_PRIVATE_TEXT = "\nPrivate iFEM Markdown calibration source.  \n"


@dataclass(frozen=True, slots=True)
class _CLIInputs:
    cache_root: Path
    cell_sha256: str
    source_lock_sha256: str
    candidate_sha256: str
    index_sha256: str


def _source_bytes(spec: source_lock.SourceFileSpec) -> bytes:
    if spec.path == _SOURCE_PATH:
        cells: list[object] = [{"cell_type": "markdown", "metadata": {}, "source": _PRIVATE_TEXT}]
    elif spec.extension == ".ipynb":
        cells = [{"cell_type": "raw", "metadata": {}, "source": ""}]
    else:
        return f"# fixed source fixture: {spec.reference_id}\n".encode()
    return canonical_json_bytes(
        {
            "cells": cells,
            "metadata": {"fixture": spec.reference_id},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
    )


def _install_inputs(tmp_path: Path) -> _CLIInputs:
    cache_root = tmp_path / "references"
    records: list[source_lock.SourceFileRecord] = []
    for spec in source_lock.SOURCE_FILES:
        raw = _source_bytes(spec)
        record = source_lock._validate_source_bytes(spec, raw)
        target = cache_root / spec.reference_id / f"{record.sha256}{spec.extension}"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        records.append(record)
    receipt = source_lock._receipt_payload(
        records,
        license_sha256=source_lock._validate_license_bytes(_LICENSE),
        retrieved_at="2026-08-01T01:02:03Z",
    )
    lock_root = cache_root / projection.IFEM_LOCK_DIRECTORY
    lock_root.mkdir(parents=True)
    source_lock_path = lock_root / projection.IFEM_SOURCE_LOCK_FILENAME
    source_lock_path.write_bytes(canonical_json_bytes(receipt) + b"\n")
    index = build_ifem_notebook_source_span_index(
        source_lock_path=source_lock_path,
        source_cache_root=cache_root,
    )
    (lock_root / projection.IFEM_NOTEBOOK_SOURCE_SPAN_INDEX_FILENAME).write_bytes(
        render_ifem_notebook_source_span_index(index)
    )
    return _CLIInputs(
        cache_root=cache_root,
        cell_sha256=hashlib.sha256(_PRIVATE_TEXT.encode()).hexdigest(),
        source_lock_sha256=hashlib.sha256(source_lock_path.read_bytes()).hexdigest(),
        candidate_sha256=str(receipt["reference_manifest_candidate_sha256"]),
        index_sha256=index.canonical_sha256(),
    )


def _bind_cli(monkeypatch: pytest.MonkeyPatch, inputs: _CLIInputs) -> None:
    monkeypatch.setattr(cli, "DEFAULT_CACHE_ROOT", inputs.cache_root)
    monkeypatch.setattr(cli, "EXPECTED_SOURCE_LOCK_SHA256", inputs.source_lock_sha256)
    monkeypatch.setattr(cli, "EXPECTED_MANIFEST_CANDIDATE_SHA256", inputs.candidate_sha256)
    monkeypatch.setattr(cli, "EXPECTED_NOTEBOOK_INDEX_CANONICAL_SHA256", inputs.index_sha256)


def _arguments(inputs: _CLIInputs, action: str) -> list[str]:
    return [
        action,
        "--source-path",
        _SOURCE_PATH,
        "--cell-index",
        "0",
        "--expected-cell-sha256",
        inputs.cell_sha256,
    ]


def test_cli_materialize_and_verify_emit_only_the_redacted_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    inputs = _install_inputs(tmp_path)
    _bind_cli(monkeypatch, inputs)

    assert cli.main(_arguments(inputs, "materialize")) == 0
    materialized = capsys.readouterr()
    assert materialized.err == ""
    summary = json.loads(materialized.out)
    assert summary["private_artifact_contains_source_text"] is True
    assert summary["summary_contains_source_text"] is False
    assert summary["model_egress_policy"] == "local_only"
    assert summary["contract_freeze_authorized"] is False
    assert summary["prover_handoff_authorized"] is False
    assert summary["cell_content_sha256"] == inputs.cell_sha256
    assert summary["cell_locator"] == "notebook-cell:0:type:markdown"
    assert "cell_text" not in summary
    assert "private_path" not in summary

    rendered = materialized.out.encode("utf-8")
    for forbidden in (
        _PRIVATE_TEXT.encode("utf-8"),
        str(inputs.cache_root).encode("utf-8"),
        b"private_path",
        b"Coercive.ipynb",
    ):
        assert forbidden not in rendered

    assert cli.main(_arguments(inputs, "verify")) == 0
    verified = capsys.readouterr()
    assert verified.err == ""
    assert verified.out == materialized.out
    private_files = tuple(
        (inputs.cache_root / projection.IFEM_LOCK_DIRECTORY).rglob("*.private.json")
    )
    assert len(private_files) == 1
    private_payload = json.loads(private_files[0].read_text(encoding="utf-8"))
    assert private_payload["cell_text"] == _PRIVATE_TEXT


def test_cli_fails_closed_without_printing_source_or_local_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    inputs = _install_inputs(tmp_path)
    _bind_cli(monkeypatch, inputs)
    arguments = _arguments(inputs, "materialize")
    arguments[-1] = "0" * 64

    assert cli.main(arguments) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "explicit selector" in captured.err
    assert _PRIVATE_TEXT not in captured.err
    assert str(inputs.cache_root) not in captured.err


def test_cli_has_no_arbitrary_output_or_abbreviated_path_options() -> None:
    with pytest.raises(SystemExit) as abbreviated:
        cli.main(["verify", "--source-p", "ignored"])
    assert abbreviated.value.code == 2

    with pytest.raises(SystemExit) as arbitrary_output:
        cli.main(["verify", "--output", "tracked.json"])
    assert arbitrary_output.value.code == 2

    with pytest.raises(SystemExit) as arbitrary_cache:
        cli.main(["verify", "--cache-root", "tracked"])
    assert arbitrary_cache.value.code == 2


def test_cli_is_offline_and_pins_the_published_source_bindings() -> None:
    assert cli.EXPECTED_SOURCE_LOCK_SHA256 == (
        "74eca6689fe69dcbf2f34ea524a99cacc2054c0a39cfecfb11887c29e13cf239"
    )
    assert cli.EXPECTED_MANIFEST_CANDIDATE_SHA256 == (
        "4a5d859d77b606d6e485d98bd3e4afc41f6c566c6fb09f5e3dc2b2a539f18398"
    )
    assert cli.EXPECTED_NOTEBOOK_INDEX_CANONICAL_SHA256 == (
        "3a0d39527481170a647cc8dc23917577e156f9ac42cb126f73759d784f8b03a7"
    )
    assert cli.EXPECTED_SOURCE_FILE_COUNT == 13

    script_path = Path(cli.__file__)
    tree = ast.parse(script_path.read_text(encoding="utf-8"))
    imports = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    )
    assert imports.isdisjoint({"httpx", "requests", "socket", "urllib"})
    assert "autolean_prover" not in imports
