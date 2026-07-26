from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest
from autolean_builder import (
    CanonicalTypeGateError,
    CanonicalTypeQueryAssurance,
    CanonicalTypeQueryRequest,
)
from autolean_contracts import HashKindV1, canonical_json_bytes, digest_text

from scripts import builder_canonical_type_gate, oci_mathlib_worker


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _request(statement: str) -> CanonicalTypeQueryRequest:
    return CanonicalTypeQueryRequest(
        subject_id="fixture-reference",
        statement_source=statement,
        statement_source_hash=digest_text(HashKindV1.STATEMENT_SOURCE, statement),
        declaration="AutoLean.BuilderGate.identity",
        namespace="AutoLean.BuilderGate",
        imports_allowlist=("Mathlib.ModelTheory.Semantics",),
    )


def _query_document(
    *,
    image: str,
    declaration: str,
    canonical_type: str,
    rendered_source: str,
) -> dict[str, object]:
    axioms = [declaration]
    observation = {
        "candidate_direct_imports": ["Mathlib.ModelTheory.Semantics"],
        "candidate_direct_imports_sha256": _sha256(
            canonical_json_bytes(["Mathlib.ModelTheory.Semantics"])
        ),
        "declarations": [
            {
                "canonical_type": canonical_type,
                "canonical_type_sha256": _sha256(canonical_type.encode()),
                "declaration": declaration,
                "observed_axioms": axioms,
                "observed_axioms_sha256": _sha256(canonical_json_bytes(axioms) + b"\n"),
            }
        ],
        "image_identity": {
            "schema_version": "autolean.image-owned-declaration-query-identity.v1",
            "query_helper_sha256": "1" * 64,
            "wrapper_sha256": "2" * 64,
        },
        "module_import_closure": ["Candidate", "Mathlib.ModelTheory.Semantics"],
        "module_import_closure_sha256": _sha256(
            canonical_json_bytes(["Candidate", "Mathlib.ModelTheory.Semantics"])
        ),
    }
    return {
        "build_receipt_canonical_sha256": "3" * 64,
        "execution_policy": {"image": image, "schema_version": "fixture"},
        "execution_policy_sha256": "4" * 64,
        "image": image,
        "observation": observation,
        "schema_version": oci_mathlib_worker.DECLARATION_QUERY_EVIDENCE_SCHEMA,
        "sealed_candidate_sha256": "5" * 64,
        "source_inputs_sha256": "6" * 64,
        "source_snapshot_sha256": _sha256(rendered_source.encode()),
    }


def test_axiom_type_carrier_preserves_header_suffix_and_context() -> None:
    request = _request("lemma identity (n : Nat) : n = n")

    rendered = builder_canonical_type_gate._render_axiom_type_carrier(request)

    assert rendered == (
        "import Mathlib.ModelTheory.Semantics\n\n"
        "namespace AutoLean.BuilderGate\n\n"
        "axiom identity (n : Nat) : n = n\n"
    )
    assert ":= by" not in rendered


def test_complete_declaration_is_observed_without_becoming_a_proof_claim() -> None:
    source = "theorem identity (n : Nat) : n = n := by\n  rfl"

    rendered = builder_canonical_type_gate._render_axiom_type_carrier(_request(source))

    assert source in rendered
    assert "axiom identity" not in rendered


def test_oci_adapter_calls_existing_query_boundary_and_normalizes_facts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_root = tmp_path / "repo"
    (repo_root / "Library").mkdir(parents=True)
    manifest = repo_root / "Library" / "lake-manifest.json"
    manifest.write_bytes(b'{"fixture":"lake-manifest"}\n')
    image = "autolean/mathlib-worker@sha256:" + "a" * 64
    request = _request("theorem identity (n : Nat) : n = n")
    calls: list[tuple[Path, tuple[str, ...], str]] = []

    def fake_query_declarations(
        observed_root: Path,
        source_cache: Path,
        build_resource_cache: Path,
        observed_image: str,
        candidate: Path,
        declarations: tuple[str, ...],
    ) -> dict[str, object]:
        del source_cache, build_resource_cache
        rendered = candidate.read_text(encoding="utf-8")
        calls.append((observed_root, declarations, rendered))
        return _query_document(
            image=observed_image,
            declaration=declarations[0],
            canonical_type="∀ (n : Nat), @Eq.{1} Nat n n",
            rendered_source=rendered,
        )

    monkeypatch.setattr(
        oci_mathlib_worker,
        "query_declarations",
        fake_query_declarations,
    )
    adapter = builder_canonical_type_gate.OciMathlibCanonicalTypeQuery(
        repo_root=repo_root,
        source_cache=tmp_path / "sources",
        build_resource_cache=tmp_path / "resources",
        image=image,
    )

    result = adapter.query(request)

    assert len(calls) == 1
    assert calls[0][0] == repo_root
    assert calls[0][1] == (request.declaration,)
    assert "axiom identity (n : Nat) : n = n" in calls[0][2]
    assert result.environment.assurance is CanonicalTypeQueryAssurance.LOCAL_OCI_PREFREEZE
    assert result.environment.adapter_id == ("scripts.oci_mathlib_worker.query_declarations")
    assert result.environment.worker_image_digest == "sha256:" + "a" * 64
    assert result.environment.lake_manifest_sha256 == _sha256(manifest.read_bytes())
    assert result.query.source_snapshot_sha256 == _sha256(calls[0][2].encode())
    assert result.query.observed_axioms == (request.declaration,)
    expected_query_output = canonical_json_bytes(
        _query_document(
            image=image,
            declaration=request.declaration,
            canonical_type="∀ (n : Nat), @Eq.{1} Nat n n",
            rendered_source=calls[0][2],
        )
    ).decode("ascii")
    assert result.query.query_output_canonical_json == expected_query_output
    assert result.query.query_output_sha256 == _sha256(expected_query_output.encode("ascii"))


def test_oci_adapter_rejects_detached_snapshot_hash() -> None:
    image = "autolean/mathlib-worker@sha256:" + "a" * 64
    declaration = "AutoLean.BuilderGate.identity"
    document = _query_document(
        image=image,
        declaration=declaration,
        canonical_type="∀ (n : Nat), @Eq.{1} Nat n n",
        rendered_source="detached",
    )

    with pytest.raises(CanonicalTypeGateError, match="snapshot differs"):
        builder_canonical_type_gate._normalize_query_result(
            document,
            declaration=declaration,
            expected_image=image,
            lake_manifest_sha256="7" * 64,
            rendered_source="expected",
        )


def test_axiom_type_carrier_rejects_non_declaration_text() -> None:
    with pytest.raises(CanonicalTypeGateError, match="theorem or lemma"):
        builder_canonical_type_gate._render_axiom_type_carrier(_request("#check Nat"))


def test_canary_skip_is_explicitly_prefreeze_and_non_promoting(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    image = "autolean/mathlib-worker@sha256:" + "a" * 64
    monkeypatch.setattr(builder_canonical_type_gate, "_image_available", lambda _image: False)

    assert builder_canonical_type_gate.main(["--image", image, "--native"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["status"] == "skipped"
    assert document["promotion_authority"] is False
    assert document["assurance"] == "none"


def test_windows_delegate_does_not_depend_on_wsl_interactive_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    commands: list[list[str]] = []

    def fake_wsl_path(path: Path) -> str:
        return f"/mnt/c/{path.name}"

    def fake_run(
        command: list[str],
        *,
        check: bool,
        shell: bool,
    ) -> subprocess.CompletedProcess[str]:
        assert check is False
        assert shell is False
        commands.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(oci_mathlib_worker, "_wsl_path", fake_wsl_path)
    monkeypatch.setattr(
        builder_canonical_type_gate,
        "_wsl_home",
        lambda: "/home/autolean",
    )
    monkeypatch.setattr(subprocess, "run", fake_run)
    arguments = builder_canonical_type_gate._parse_args(
        [
            "--image",
            "autolean/mathlib-worker@sha256:" + "a" * 64,
            "--repo-root",
            str(tmp_path / "repo"),
            "--source-cache",
            str(tmp_path / "source"),
            "--build-resource-cache",
            str(tmp_path / "resources"),
        ]
    )

    assert builder_canonical_type_gate._delegate_to_wsl(arguments) == 0
    assert commands == [
        [
            "wsl.exe",
            "-d",
            oci_mathlib_worker.WSL_DISTRIBUTION,
            "--cd",
            "/mnt/c/repo",
            "--",
            "/usr/bin/env",
            "PATH=/home/autolean/.local/bin:/usr/local/bin:/usr/bin:/bin",
            ("UV_PROJECT_ENVIRONMENT=/home/autolean/.cache/autolean/oci-worker-python"),
            (
                "PYTHONPATH=/mnt/c/repo/Builder/src:/mnt/c/repo/packages/contracts/src:"
                "/mnt/c/repo/packages/control_plane/src:/mnt/c/repo/Prover/src"
            ),
            "uv",
            "run",
            "--frozen",
            "--no-sync",
            "python",
            "-m",
            "scripts.builder_canonical_type_gate",
            "--image",
            "autolean/mathlib-worker@sha256:" + "a" * 64,
            "--repo-root",
            "/mnt/c/repo",
            "--source-cache",
            "/mnt/c/source",
            "--build-resource-cache",
            "/mnt/c/resources",
            "--native",
        ]
    ]
