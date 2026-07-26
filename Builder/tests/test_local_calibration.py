from __future__ import annotations

import hashlib
import json
import runpy
import shutil
from pathlib import Path

import pytest
from autolean_builder import (
    LocalCalibrationError,
    LocalCalibrationFixtureCorpusV1,
    load_local_calibration_fixture_corpus,
)

_ROOT = Path(__file__).resolve().parents[2]
_CORPUS_PATH = (
    _ROOT
    / "Builder"
    / "pilots"
    / "local-calibration"
    / ("project-synthetic-opening-corpus.v1.json")
)
_RENDERER_PATH = _ROOT / "Builder" / "pilots" / "local-calibration" / ("render_opening_corpus.py")
_RELEASE_MANIFEST_PATH = (
    _ROOT
    / "Builder"
    / "pilots"
    / "local-calibration"
    / "project-synthetic-opening-corpus.release-manifest.v1.json"
)


def _corpus() -> LocalCalibrationFixtureCorpusV1:
    return load_local_calibration_fixture_corpus(_CORPUS_PATH)


def _payload() -> dict[str, object]:
    value = json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_opening_corpus_has_exactly_five_pde_and_five_metric_geometry_samples() -> None:
    corpus = _corpus()

    assert len(corpus.samples) == 10
    assert sum(sample.domain.value == "pde-a" for sample in corpus.samples) == 5
    assert sum(sample.domain.value == "mg-a" for sample in corpus.samples) == 5
    assert corpus.record_kind == "local_calibration_fixture"
    assert corpus.provenance_class == "project_synthetic_fixture"
    assert corpus.authorship_claim == "generated_for_repository_pending_human_content_review"
    assert corpus.human_content_review_completed is False
    assert corpus.legal_review_claimed is False
    assert corpus.repository_license_binding.repository_license_expression == "Apache-2.0"
    assert corpus.production_rights_cleared is False
    assert corpus.promotion_allowed is False

    for sample in corpus.samples:
        assert sample.source.metadata == {
            "provenance_class": "project_synthetic_fixture",
            "authorship_claim": "generated_for_repository_pending_human_content_review",
            "human_content_review_completed": False,
            "purpose": "pre_calibration_fixture",
        }
        assert sample.record_kind == "pre_calibration_fixture"
        assert sample.rights.source_license == "Apache-2.0"
        assert sample.rights.overall_decision.value == "restricted"
        assert sample.rights.redistribution.value == "allow"
        assert sample.rights.model_egress.value == "deny"
        assert sample.rights.reviewed_by is None
        assert sample.rights.reviewed_at is None
        assert (
            "redistribution-only-exact-project-synthetic-fixture-bytes"
            in sample.rights.restrictions
        )
        assert (
            f"source-bytes-sha256:{sample.source.content_hash.value}" in sample.rights.restrictions
        )
        assert sample.production_ingestion is False
        assert sample.freeze_allowed is False
        assert sample.prover_handoff_allowed is False
        assert sample.production_rights_cleared is False
        assert sample.promotion_allowed is False
        assert sample.authority.production_ingestion is False
        assert sample.authority.freeze_allowed is False
        assert sample.authority.prover_handoff_allowed is False
        assert len(sample.source.spans) == 1
        assert len(sample.illustrative_lean_snippets) == 2
        assert len({item.authoring_path for item in sample.illustrative_lean_snippets}) == 2
        assert (
            len({item.declared_independence_label for item in sample.illustrative_lean_snippets})
            == 2
        )
        assert all(not item.lean_parsed for item in sample.illustrative_lean_snippets)
        assert all(not item.semantic_binding_claimed for item in sample.illustrative_lean_snippets)
        assert all(not item.promotion_allowed for item in sample.illustrative_lean_snippets)
        assert sample.mathematical_specification().normalized_statement == (
            sample.normalized.normalized_statement
        )


def test_renderer_is_deterministic_and_matches_the_committed_corpus() -> None:
    namespace = runpy.run_path(str(_RENDERER_PATH))
    render = namespace["render"]
    assert callable(render)
    rendered = render()
    assert isinstance(rendered, str)
    assert rendered == _CORPUS_PATH.read_text(encoding="utf-8")
    render_release_manifest = namespace["render_release_manifest"]
    assert callable(render_release_manifest)
    rendered_manifest = render_release_manifest(rendered)
    assert rendered_manifest == _RELEASE_MANIFEST_PATH.read_text(encoding="utf-8")


def _copy_fixture_release(root: Path) -> Path:
    target_dir = root / "Builder" / "pilots" / "local-calibration"
    target_dir.mkdir(parents=True)
    target_corpus = target_dir / _CORPUS_PATH.name
    shutil.copy2(_ROOT / "LICENSE", root / "LICENSE")
    shutil.copy2(_CORPUS_PATH, target_corpus)
    shutil.copy2(_RELEASE_MANIFEST_PATH, target_dir / _RELEASE_MANIFEST_PATH.name)
    shutil.copy2(_RENDERER_PATH, target_dir / _RENDERER_PATH.name)
    return target_corpus


def test_loader_binds_exact_corpus_renderer_and_repository_license_bytes(tmp_path: Path) -> None:
    target_corpus = _copy_fixture_release(tmp_path)
    assert load_local_calibration_fixture_corpus(target_corpus).samples

    license_path = tmp_path / "LICENSE"
    license_path.write_bytes(license_path.read_bytes() + b"\n")
    with pytest.raises(LocalCalibrationError, match="LICENSE bytes differ"):
        load_local_calibration_fixture_corpus(target_corpus)

    shutil.copy2(_ROOT / "LICENSE", license_path)
    renderer_path = target_corpus.with_name(_RENDERER_PATH.name)
    renderer_path.write_bytes(renderer_path.read_bytes() + b"\n")
    with pytest.raises(LocalCalibrationError, match="renderer bytes differ"):
        load_local_calibration_fixture_corpus(target_corpus)

    shutil.copy2(_RENDERER_PATH, renderer_path)
    manifest_path = target_corpus.with_name(_RELEASE_MANIFEST_PATH.name)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["fixture_sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(LocalCalibrationError, match="corpus bytes differ"):
        load_local_calibration_fixture_corpus(target_corpus)


def test_loader_rejects_rehashed_alternate_corpus_bytes(tmp_path: Path) -> None:
    target_corpus = _copy_fixture_release(tmp_path)
    target_corpus.write_bytes(target_corpus.read_bytes() + b" ")
    manifest_path = target_corpus.with_name(_RELEASE_MANIFEST_PATH.name)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["fixture_sha256"] = hashlib.sha256(target_corpus.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(LocalCalibrationError, match="corpus bytes differ"):
        load_local_calibration_fixture_corpus(target_corpus)


def test_machine_readable_report_exposes_differences_but_never_a_routable_handoff() -> None:
    report = _corpus().machine_readable_report()

    assert report["sample_count"] == 10
    assert report["record_kind"] == "local_calibration_fixture"
    assert report["provenance_class"] == "project_synthetic_fixture"
    assert report["authorship_claim"] == ("generated_for_repository_pending_human_content_review")
    assert report["production_rights_cleared"] is False
    assert report["promotion_allowed"] is False
    reports = report["reports"]
    assert isinstance(reports, list)
    assert len(reports) == 10
    for entry in reports:
        assert isinstance(entry, dict)
        assert entry["production_ingestion"] is False
        assert entry["freeze_allowed"] is False
        assert entry["prover_handoff_allowed"] is False
        assert entry["production_rights_cleared"] is False
        assert entry["promotion_allowed"] is False
        preview = entry["builder_prover_interface_preview"]
        assert isinstance(preview, dict)
        assert preview["preview_only"] is True
        authority = preview["authority"]
        assert isinstance(authority, dict)
        assert authority["freeze_allowed"] is False
        assert "candidate_statement_sha256" not in preview
        assert preview["illustrative_snippet_snapshot_sha256"]
        fixtures = entry["mutation_fixtures"]
        assert isinstance(fixtures, list)
        assert fixtures
        for fixture in fixtures:
            assert fixture["status"] == "declared_synthetic_mutation_fixture"
            assert fixture["evidence_class"] == "synthetic_fixture_not_semantic_evidence"
            assert fixture["semantic_detection_claimed"] is False
            assert fixture["promotion_allowed"] is False
            assert "detected" not in fixture
            assert "executed_by" not in fixture


def test_required_synthetic_mutation_fixtures_are_declared_without_semantic_authority() -> None:
    required_codes = {
        "TRANSPORT_SIGN_FLIP",
        "STRICT_LENGTH_BOUND_WEAKENED",
        "EPSILON_CURVE_QUANTIFIER_SWAP",
        "DROP_NONEMPTY_MAXIMIZER",
        "DROP_WEAK_REGULARITY",
        "INFIMUM_TO_ATTAINMENT",
        "UNIQUENESS_TO_EXISTENCE",
    }
    seen_codes: set[str] = set()

    strict_fixture_reason = ""
    for sample in _corpus().samples:
        for fixture in sample.mutation_fixtures:
            seen_codes.add(fixture.blocker_code)
            assert fixture.status == "declared_synthetic_mutation_fixture"
            assert fixture.semantic_detection_claimed is False
            assert fixture.promotion_allowed is False
            assert fixture.baseline_fragment != fixture.mutated_fragment
            if fixture.blocker_code == "STRICT_LENGTH_BOUND_WEAKENED":
                strict_fixture_reason = fixture.blocker_reason

    assert required_codes <= seen_codes
    assert "different contract" in strict_fixture_reason
    assert "irrespective" in strict_fixture_reason


def test_transport_fixture_states_profile_verification_without_claiming_uniqueness() -> None:
    sample = next(item for item in _corpus().samples if item.sample_id == "pde-a-transport-sign")

    assert "sufficiently differentiable" in sample.source_text
    assert "define u(t, x) = u0(x - c t)" in sample.source_text
    assert "satisfies u_t + c u_x = 0" in sample.source_text
    assert "u(0, x) = u0(x)" in sample.source_text
    assert "uniqu" not in sample.source_text.lower()
    assert "assuming u solves" not in sample.normalized.normalized_statement


def test_transport_x_plus_ct_rfl_substitution_is_only_snapshot_drift() -> None:
    sample = next(item for item in _corpus().samples if item.sample_id == "pde-a-transport-sign")
    snippet = sample.illustrative_lean_snippets[0]
    sample.assert_illustrative_snapshot_unchanged(
        snippet_id=snippet.snippet_id,
        observed_text=snippet.illustrative_lean_snippet,
    )
    drifted = snippet.illustrative_lean_snippet.replace(
        "x - c * t",
        "x + c * t",
    ).replace(
        "by exact transportProfile_satisfies u0 c h",
        "by rfl",
    )
    assert drifted != snippet.illustrative_lean_snippet

    with pytest.raises(LocalCalibrationError, match=r"snapshot drift.*no semantics"):
        sample.assert_illustrative_snapshot_unchanged(
            snippet_id=snippet.snippet_id,
            observed_text=drifted,
        )


def test_non_authoritative_records_reject_freeze_and_prover_handoff() -> None:
    sample = _corpus().samples[0]

    with pytest.raises(LocalCalibrationError, match="cannot freeze"):
        sample.freeze_builder_statement()
    with pytest.raises(LocalCalibrationError, match="cannot hand off"):
        sample.handoff_to_prover()
    with pytest.raises(LocalCalibrationError, match="cannot be routed"):
        sample.prover_interface_preview().assert_not_routable()


def test_source_rights_snippet_and_authority_tampering_are_rejected() -> None:
    source_tampered = _payload()
    samples = source_tampered["samples"]
    assert isinstance(samples, list)
    samples[0]["source_text"] = "different synthetic fixture statement"
    with pytest.raises(ValueError, match="source text differs"):
        LocalCalibrationFixtureCorpusV1.model_validate(source_tampered)

    rights_tampered = _payload()
    samples = rights_tampered["samples"]
    assert isinstance(samples, list)
    first = samples[0]
    assert isinstance(first, dict)
    rights = first["rights"]
    assert isinstance(rights, dict)
    rights["source_license"] = None
    with pytest.raises(ValueError, match=r"repository Apache-2\.0"):
        LocalCalibrationFixtureCorpusV1.model_validate(rights_tampered)

    snippet_tampered = _payload()
    samples = snippet_tampered["samples"]
    assert isinstance(samples, list)
    first = samples[0]
    assert isinstance(first, dict)
    snippets = first["illustrative_lean_snippets"]
    assert isinstance(snippets, list)
    second = snippets[1]
    assert isinstance(second, dict)
    second["authoring_path"] = snippets[0]["authoring_path"]
    with pytest.raises(ValueError, match="distinct declared authoring paths"):
        LocalCalibrationFixtureCorpusV1.model_validate(snippet_tampered)

    authority_tampered = _payload()
    samples = authority_tampered["samples"]
    assert isinstance(samples, list)
    first = samples[0]
    assert isinstance(first, dict)
    first["freeze_allowed"] = True
    with pytest.raises(ValueError):
        LocalCalibrationFixtureCorpusV1.model_validate(authority_tampered)


def test_fixture_labels_cannot_be_upgraded_to_semantic_rights_or_promotion_evidence() -> None:
    semantic_tampered = _payload()
    samples = semantic_tampered["samples"]
    assert isinstance(samples, list)
    first = samples[0]
    assert isinstance(first, dict)
    fixtures = first["mutation_fixtures"]
    assert isinstance(fixtures, list)
    fixture = fixtures[0]
    assert isinstance(fixture, dict)
    fixture["evidence_class"] = "semantic_detection_evidence"
    fixture["semantic_detection_claimed"] = True
    with pytest.raises(ValueError):
        LocalCalibrationFixtureCorpusV1.model_validate(semantic_tampered)

    rights_cleared = _payload()
    rights_cleared["production_rights_cleared"] = True
    with pytest.raises(ValueError):
        LocalCalibrationFixtureCorpusV1.model_validate(rights_cleared)

    promotable = _payload()
    promotable["promotion_allowed"] = True
    with pytest.raises(ValueError):
        LocalCalibrationFixtureCorpusV1.model_validate(promotable)

    snippet_promotable = _payload()
    samples = snippet_promotable["samples"]
    assert isinstance(samples, list)
    first = samples[0]
    assert isinstance(first, dict)
    snippets = first["illustrative_lean_snippets"]
    assert isinstance(snippets, list)
    snippet = snippets[0]
    assert isinstance(snippet, dict)
    snippet["promotion_allowed"] = True
    with pytest.raises(ValueError):
        LocalCalibrationFixtureCorpusV1.model_validate(snippet_promotable)
