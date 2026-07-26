from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from autolean_builder.fine_span_attachment import (
    FineSourceSpanV2,
    FineSpanAttachmentError,
)

from scripts import model_theory_review as review


def _png(width: int = 8, height: int = 6) -> bytes:
    return (
        b"\x89PNG\r\n\x1a\n"
        + b"\x00\x00\x00\rIHDR"
        + width.to_bytes(4, "big")
        + height.to_bytes(4, "big")
    )


def test_tracked_plan_replays_cross_page_claims() -> None:
    plan = review.load_review_plan()

    assert [
        (
            claim.ambiguity_id,
            claim.span_id,
            claim.pdf_page_1_based,
            claim.printed_page_label,
        )
        for claim in plan.page_claims
    ] == [
        (
            "section-7-5-page-pair-unreconciled",
            "sentence-satisfaction-assignment-independence",
            147,
            "126",
        ),
        (
            "section-7-5-page-pair-unreconciled",
            "sentence-satisfaction-assignment-independence",
            148,
            "127",
        ),
        (
            "universal-right-page-pair-unreconciled",
            "lk-validity-and-soundness-universal-right-case",
            207,
            "186",
        ),
        (
            "universal-right-page-pair-unreconciled",
            "lk-validity-and-soundness-universal-right-case",
            208,
            "187",
        ),
    ]


def test_local_review_gate_replays_sources_and_keeps_gap_unresolved() -> None:
    cache_root = review.ROOT / ".cache" / "references"
    source = (
        cache_root
        / "openlogic-sets-logic-computation-2026-07-12-text-pypdf-6.14.2"
        / "6184495568a4487848e747f25385cb4081be1cd87f77488c9de0046d600cfa6d.txt"
    )
    if not source.exists():
        pytest.skip("official local pypdf 6.14.2 source cache is intentionally absent")

    assert review.verify_local_review_gate(cache_root) == (
        "section-7-5-page-pair-unreconciled",
        "universal-right-page-pair-unreconciled",
    )


def test_local_review_gate_always_replays_tracked_review_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}
    monkeypatch.setattr(review, "verify_materials", lambda *_: (b"%PDF", b"bound text"))

    def record_spans(
        text: bytes,
        spans: tuple[FineSourceSpanV2, ...],
    ) -> tuple[review.SpanPageMap, ...]:
        observed["text"] = text
        observed["spans"] = spans
        return ()

    monkeypatch.setattr(review, "map_spans_to_pages", record_spans)

    assert review.verify_local_review_gate(review.ROOT / ".cache" / "not-needed") == (
        "section-7-5-page-pair-unreconciled",
        "universal-right-page-pair-unreconciled",
    )
    assert observed["text"] == b"bound text"
    assert observed["spans"] == review.load_review_plan().fine_spans.spans


def test_local_review_gate_rejects_a_verdict_without_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_load = review._load_object

    def changed_response(path: Path, label: str) -> tuple[dict[str, object], bytes]:
        payload, raw = original_load(path, label)
        if path != review.ROOT / review.RESPONSE_RELATIVE_PATH:
            return payload, raw
        changed = copy.deepcopy(payload)
        rows = changed["page_ambiguity_reviews"]
        assert isinstance(rows, list)
        first = rows[0]
        assert isinstance(first, dict)
        first["page_ambiguity_verdict"] = "unresolved"
        return changed, raw

    monkeypatch.setattr(review, "_load_object", changed_response)

    with pytest.raises(review.ReviewBuildError, match="non-authoritative T3 evidence"):
        review.verify_local_review_gate(review.ROOT / ".cache" / "not-needed")


def test_local_review_gate_normalizes_rule_matrix_mutation_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[Path] = []
    fine_span_type = type(review.load_review_plan().fine_spans)

    def reject_mutated_matrix(_attachment: object, path: Path) -> None:
        observed.append(path)
        raise FineSpanAttachmentError("independent mutation probe")

    monkeypatch.setattr(fine_span_type, "assert_binds_rule_matrix", reject_mutated_matrix)

    with pytest.raises(review.ReviewBuildError, match="fixed source-rule matrix"):
        review.verify_local_review_gate(review.ROOT / ".cache" / "not-needed")
    assert observed == [review.ROOT / review.RULE_MATRIX_RELATIVE_PATH]


@pytest.mark.parametrize(
    "mutation",
    (
        "stale",
        "minimal",
        "schema_keys",
        "schema_version",
        "authority_keys",
        "authority_value",
        "artifact_kind",
        "matrix_path",
        "context_policy",
        "source_excerpt",
        "local_cache_path",
        "prompt_or_log",
    ),
)
def test_local_review_gate_rejects_review_evidence_drift(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    original_load = review._load_object

    def changed_evidence(path: Path, label: str) -> tuple[dict[str, object], bytes]:
        payload, raw = original_load(path, label)
        if path != review.ROOT / review.REVIEW_EVIDENCE_RELATIVE_PATH:
            return payload, raw
        changed = copy.deepcopy(payload)
        reports = changed["reports"]
        assert isinstance(reports, list)
        if mutation == "minimal":
            changed["reports"] = []
        elif mutation == "schema_keys":
            changed["unexpected_field"] = "drift"
        elif mutation == "schema_version":
            changed["schema_version"] = "stale"
        elif mutation in {"authority_keys", "authority_value"}:
            authority = changed["authority_boundary"]
            assert isinstance(authority, dict)
            if mutation == "authority_keys":
                del authority["may_issue_admission_receipt"]
            else:
                authority["may_issue_admission_receipt"] = True
        elif mutation == "artifact_kind":
            changed["artifact_kind"] = "stale"
        elif mutation == "matrix_path":
            changed["public_source_rule_matrix_path"] = "stale.json"
        elif mutation == "context_policy":
            changed["report_context_policy"] = "stale"
        elif mutation == "source_excerpt":
            changed["contains_source_excerpt"] = True
        elif mutation == "local_cache_path":
            changed["contains_local_cache_path"] = True
        elif mutation == "prompt_or_log":
            changed["contains_prompt_or_raw_log"] = True
        else:
            first = reports[0]
            assert isinstance(first, dict)
            first["reviewer_id"] = "stale-reviewer"
        return changed, raw

    monkeypatch.setattr(review, "_load_object", changed_evidence)

    with pytest.raises(review.ReviewBuildError, match="non-authoritative T3 evidence"):
        review.verify_local_review_gate(review.ROOT / ".cache" / "not-needed")


@pytest.mark.parametrize(
    "extra_field",
    ("admission_receipt", "credentials", "raw_source_excerpt"),
)
def test_local_review_gate_rejects_extra_review_report_fields(
    monkeypatch: pytest.MonkeyPatch,
    extra_field: str,
) -> None:
    original_load = review._load_object

    def changed_evidence(path: Path, label: str) -> tuple[dict[str, object], bytes]:
        payload, raw = original_load(path, label)
        if path != review.ROOT / review.REVIEW_EVIDENCE_RELATIVE_PATH:
            return payload, raw
        changed = copy.deepcopy(payload)
        reports = changed["reports"]
        assert isinstance(reports, list)
        first = reports[0]
        assert isinstance(first, dict)
        first[extra_field] = "forbidden"
        return changed, raw

    monkeypatch.setattr(review, "_load_object", changed_evidence)

    with pytest.raises(review.ReviewBuildError, match="report schema drifted"):
        review.verify_local_review_gate(review.ROOT / ".cache" / "not-needed")


@pytest.mark.parametrize(
    "mutation",
    (
        "packet_path",
        "authority_keys",
        "authority_value",
        "schema_keys",
        "schema_version",
        "span_pending",
        "ambiguity_pending",
        "reviewer_identity",
        "reviewer_credential",
        "reviewer_auth",
        "fragment_review",
        "fin_review",
        "init_axiom_review",
        "overall_review",
        "public_safety",
        "span_notes",
        "span_correction",
        "ambiguity_notes",
        "page_evidence",
        "nested_keys",
    ),
)
def test_local_review_gate_rejects_response_binding_drift(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    original_load = review._load_object

    def changed_response(path: Path, label: str) -> tuple[dict[str, object], bytes]:
        payload, raw = original_load(path, label)
        if path != review.ROOT / review.RESPONSE_RELATIVE_PATH:
            return payload, raw
        changed = copy.deepcopy(payload)
        if mutation == "packet_path":
            binding = changed["packet_binding"]
            assert isinstance(binding, dict)
            binding["packet_path"] = "Builder/pilots/model-theory-admission/stale.json"
        elif mutation == "authority_keys":
            authority = changed["authority_boundary"]
            assert isinstance(authority, dict)
            del authority["may_promote"]
        elif mutation == "authority_value":
            authority = changed["authority_boundary"]
            assert isinstance(authority, dict)
            authority["may_promote"] = True
        elif mutation == "schema_keys":
            changed["unexpected_field"] = "drift"
        elif mutation == "schema_version":
            changed["schema_version"] = "stale"
        elif mutation == "span_pending":
            rows = changed["span_reviews"]
            assert isinstance(rows, list)
            first = rows[0]
            assert isinstance(first, dict)
            first["visual_locator_verdict"] = "accepted"
        elif mutation == "ambiguity_pending":
            rows = changed["page_ambiguity_reviews"]
            assert isinstance(rows, list)
            first = rows[0]
            assert isinstance(first, dict)
            first["page_ambiguity_verdict"] = "resolved"
        elif mutation in {"reviewer_identity", "reviewer_credential", "reviewer_auth"}:
            reviewer = changed["reviewer_record"]
            assert isinstance(reviewer, dict)
            if mutation == "reviewer_identity":
                reviewer["reviewer_id"] = "human:unverified"
            elif mutation == "reviewer_credential":
                reviewer["qualification_note"] = "unverified"
            else:
                reviewer["identity_authenticated"] = True
        elif mutation == "fragment_review":
            fragment = changed["fragment_naming_review"]
            assert isinstance(fragment, dict)
            fragment["proposed_exact_name"] = "unreviewed-name"
        elif mutation == "fin_review":
            fin_review = changed["fin_n_freshness_review"]
            assert isinstance(fin_review, dict)
            fin_review["freshness_encoding_verdict"] = "accepted"
        elif mutation == "init_axiom_review":
            axiom_review = changed["init_axiom_policy_review"]
            assert isinstance(axiom_review, dict)
            axiom_review["accepted_axioms"] = ["Classical.choice"]
        elif mutation == "overall_review":
            overall = changed["overall_review"]
            assert isinstance(overall, dict)
            overall["rationale"] = "unreviewed"
        elif mutation == "public_safety":
            safety = changed["public_safety_confirmation"]
            assert isinstance(safety, dict)
            safety["contains_credentials"] = True
        elif mutation in {"span_notes", "span_correction"}:
            rows = changed["span_reviews"]
            assert isinstance(rows, list)
            first = rows[0]
            assert isinstance(first, dict)
            if mutation == "span_notes":
                first["notes"] = "unreviewed"
            else:
                correction = first["locator_correction"]
                assert isinstance(correction, dict)
                correction["corrected_start_offset"] = 1
        elif mutation in {"ambiguity_notes", "page_evidence"}:
            rows = changed["page_ambiguity_reviews"]
            assert isinstance(rows, list)
            first = rows[0]
            assert isinstance(first, dict)
            if mutation == "ambiguity_notes":
                first["notes"] = "unreviewed"
            else:
                pages = first["page_evidence"]
                assert isinstance(pages, list)
                page = pages[0]
                assert isinstance(page, dict)
                page["pdf_page_1_based"] = 1
        else:
            fragment = changed["fragment_naming_review"]
            assert isinstance(fragment, dict)
            fragment["unexpected_field"] = "drift"
        return changed, raw

    monkeypatch.setattr(review, "_load_object", changed_response)

    with pytest.raises(
        review.ReviewBuildError,
        match=r"authority|non-authoritative T3 evidence",
    ):
        review.verify_local_review_gate(review.ROOT / ".cache" / "not-needed")


@pytest.mark.parametrize("mutation", ("disposition", "authority_keys", "authority_value"))
def test_local_review_gate_rejects_packet_boundary_drift(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    original_load = review._load_object

    def changed_packet(path: Path, label: str) -> tuple[dict[str, object], bytes]:
        payload, raw = original_load(path, label)
        if path != review.ROOT / review.PACKET_RELATIVE_PATH:
            return payload, raw
        changed = copy.deepcopy(payload)
        if mutation == "disposition":
            binding = changed["decision_binding"]
            assert isinstance(binding, dict)
            binding["disposition"] = "admit"
        else:
            authority = changed["authority_boundary"]
            assert isinstance(authority, dict)
            if mutation == "authority_keys":
                del authority["may_promote"]
            else:
                authority["may_promote"] = True
        return changed, raw

    monkeypatch.setattr(review, "_load_object", changed_packet)

    with pytest.raises(
        review.ReviewBuildError,
        match=r"authority|non-authoritative T3 evidence",
    ):
        review.verify_local_review_gate(review.ROOT / ".cache" / "not-needed")


def test_check_cli_reports_explicit_non_admission(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        review,
        "verify_local_review_gate",
        lambda _: ("ambiguity-one", "ambiguity-two"),
    )

    review.main(["check", "--cache-root", "unused"])

    assert json.loads(capsys.readouterr().out) == {
        "admission": "forbidden",
        "disposition": "gap",
        "status": "ok",
        "unresolved_ambiguity_ids": ["ambiguity-one", "ambiguity-two"],
    }


def test_cross_page_mapping_binds_claimed_page_render() -> None:
    text = b"alpha\fbravo"
    span = FineSourceSpanV2(
        span_id="cross-page-span",
        requirement_id="cross-page-requirement",
        segment_id="cross-page-segment",
        start_offset=0,
        end_offset=len(text),
        raw_sha256=hashlib.sha256(text).hexdigest(),
    )
    mapped = review.map_spans_to_pages(text, (span,))
    claim = review.PageClaim("page-pair-unreconciled", span.span_id, 2, "B")
    pages = {
        number: review.RenderedPage(
            number,
            f"pages/page-{number:04d}.png",
            _png(),
            hashlib.sha256(f"page-{number}".encode()).hexdigest(),
        )
        for number in (1, 2)
    }

    evidence = review.build_page_ambiguity_evidence((claim,), mapped, pages)

    assert mapped[0].pdf_page_start == 1
    assert mapped[0].pdf_page_end == 2
    assert evidence == [
        {
            "ambiguity_id": "page-pair-unreconciled",
            "span_id": "cross-page-span",
            "mapped_pdf_page_start_1_based": 1,
            "mapped_pdf_page_end_1_based": 2,
            "page_evidence": [
                {
                    "pdf_page_1_based": 2,
                    "pdf_page_0_based": 1,
                    "printed_page_label": "B",
                    "page_render_sha256": pages[2].sha256,
                }
            ],
        }
    ]

    outside = review.PageClaim("outside", span.span_id, 3, "C")
    pages[3] = review.RenderedPage(3, "pages/page-0003.png", _png(), "0" * 64)
    with pytest.raises(review.ReviewBuildError, match="outside its mapped span"):
        review.build_page_ambiguity_evidence((outside,), mapped, pages)


def test_render_page_uses_selected_executable_without_shell(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    executable = tmp_path / "pdftoppm"
    executable.write_bytes(b"tool")
    pdf = tmp_path / "source.pdf"
    pdf.write_bytes(b"%PDF")
    temporary = tmp_path / "render"
    temporary.mkdir()
    observed: dict[str, object] = {}

    def fake_run(args: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        observed["args"] = args
        observed["shell"] = kwargs["shell"]
        Path(args[-1]).with_suffix(".png").write_bytes(_png())
        return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    tool = review.PdftoppmTool(executable, hashlib.sha256(b"tool").hexdigest(), "test")

    rendered = review.render_page(tool, pdf, 148, temporary)

    assert observed["shell"] is False
    assert observed["args"] == (
        str(executable),
        "-f",
        "148",
        "-l",
        "148",
        "-r",
        str(review.RENDER_DPI),
        "-png",
        "-singlefile",
        str(pdf),
        str(temporary / "page-0148" / "render"),
    )
    assert rendered.page_number == 148
    assert rendered.content == _png()


def test_output_install_preserves_unknown_and_rejects_collision(tmp_path: Path) -> None:
    output = tmp_path / "tmp" / "pdfs" / "model-theory-t3-review"
    assert review._ensure_output(tmp_path, output) == Path("tmp/pdfs/model-theory-t3-review")
    unknown = output / "operator-note.txt"
    unknown.write_bytes(b"retain")
    generated = output / "index.html"

    review._preflight(generated, b"first")
    review._install(generated, b"first")

    assert unknown.read_bytes() == b"retain"
    assert generated.read_bytes() == b"first"
    with pytest.raises(review.ReviewBuildError, match="will not be overwritten"):
        review._preflight(generated, b"second")


def test_cli_has_no_arbitrary_output_or_packet_override() -> None:
    with pytest.raises(SystemExit):
        review.parse_args(
            [
                "build",
                "--cache-root",
                "cache",
                "--output",
                "elsewhere",
            ]
        )


def test_review_index_wraps_long_ids_and_hashes_without_widening_the_page() -> None:
    tracked = review.load_review_plan()
    plan = review.ReviewPlan(
        packet=tracked.packet,
        packet_sha256=tracked.packet_sha256,
        manifest=tracked.manifest,
        fine_spans=tracked.fine_spans,
        pdf_reference_id=tracked.pdf_reference_id,
        text_reference_id=tracked.text_reference_id,
        page_count=tracked.page_count,
        page_claims=(),
    )

    index = review._render_index(plan, (), {}).decode("ascii")

    assert "minmax(min(320px,100%),1fr)" in index
    assert "figure{min-width:0" in index
    assert "h1,h2,p,li,code{overflow-wrap:anywhere}" in index


@pytest.mark.parametrize(
    ("binding_path", "path_key"),
    (
        (("decision_binding",), "path"),
        (("evidence_bindings", "fine_source_spans"), "path"),
        (("evidence_bindings", "pending_review"), "path"),
        (("evidence_bindings", "reference_manifest"), "path"),
        (("evidence_bindings", "implementation"), "path"),
        (("evidence_bindings", "t4_exact_image"), "attachment_path"),
        (("evidence_bindings", "t4_exact_image"), "query_path"),
    ),
)
def test_load_review_plan_rejects_each_bound_path(
    monkeypatch: pytest.MonkeyPatch,
    binding_path: tuple[str, ...],
    path_key: str,
) -> None:
    original_load_object = review._load_object

    def changed_packet(path: Path, label: str) -> tuple[dict[str, object], bytes]:
        packet, raw = original_load_object(path, label)
        if path != review.ROOT / review.PACKET_RELATIVE_PATH:
            return packet, raw
        changed = copy.deepcopy(packet)
        binding: object = changed
        for key in binding_path:
            assert isinstance(binding, dict)
            binding = binding[key]
        assert isinstance(binding, dict)
        binding[path_key] = "unbound/path"
        return changed, raw

    monkeypatch.setattr(review, "_load_object", changed_packet)

    with pytest.raises(review.ReviewBuildError, match="binds an unexpected path"):
        review.load_review_plan()


@pytest.mark.parametrize(
    ("binding_path", "hash_key"),
    (
        (("decision_binding",), "file_sha256"),
        (("evidence_bindings", "fine_source_spans"), "file_sha256"),
        (("evidence_bindings", "pending_review"), "file_sha256"),
        (("evidence_bindings", "reference_manifest"), "file_sha256"),
        (("evidence_bindings", "implementation"), "sha256"),
        (("evidence_bindings", "t4_exact_image"), "attachment_sha256"),
        (("evidence_bindings", "t4_exact_image"), "query_sha256"),
    ),
)
def test_load_review_plan_rejects_each_bound_hash(
    monkeypatch: pytest.MonkeyPatch,
    binding_path: tuple[str, ...],
    hash_key: str,
) -> None:
    original_load_object = review._load_object

    def changed_packet(path: Path, label: str) -> tuple[dict[str, object], bytes]:
        packet, raw = original_load_object(path, label)
        if path != review.ROOT / review.PACKET_RELATIVE_PATH:
            return packet, raw
        changed = copy.deepcopy(packet)
        binding: object = changed
        for key in binding_path:
            assert isinstance(binding, dict)
            binding = binding[key]
        assert isinstance(binding, dict)
        binding[hash_key] = "0" * 64
        return changed, raw

    monkeypatch.setattr(review, "_load_object", changed_packet)

    with pytest.raises(review.ReviewBuildError, match="differs from the packet binding"):
        review.load_review_plan()


@pytest.mark.parametrize(
    "relative_path",
    (
        review.DECISION_RELATIVE_PATH,
        review.FINE_SPANS_RELATIVE_PATH,
        review.PENDING_REVIEW_RELATIVE_PATH,
        review.MANIFEST_RELATIVE_PATH,
        review.IMPLEMENTATION_RELATIVE_PATH,
        review.T4_ATTACHMENT_RELATIVE_PATH,
        review.T4_QUERY_RELATIVE_PATH,
    ),
)
def test_load_review_plan_rejects_each_bound_artifact_drift(
    monkeypatch: pytest.MonkeyPatch,
    relative_path: Path,
) -> None:
    original_read_file = review._read_file
    target = review.ROOT / relative_path

    def changed_artifact(path: Path, label: str) -> bytes:
        content = original_read_file(path, label)
        return content + b"\n" if path == target else content

    monkeypatch.setattr(review, "_read_file", changed_artifact)

    with pytest.raises(review.ReviewBuildError, match="differs from the packet binding"):
        review.load_review_plan()


def _material_plan(pdf: bytes, text: bytes) -> review.ReviewPlan:
    entries = {
        "pdf": SimpleNamespace(sha256=hashlib.sha256(pdf).hexdigest(), size_bytes=len(pdf)),
        "text": SimpleNamespace(sha256=hashlib.sha256(text).hexdigest(), size_bytes=len(text)),
    }
    manifest = cast(Any, SimpleNamespace(require=entries.__getitem__))
    return review.ReviewPlan(
        packet={},
        packet_sha256="0" * 64,
        manifest=manifest,
        fine_spans=cast(Any, SimpleNamespace()),
        pdf_reference_id="pdf",
        text_reference_id="text",
        page_count=len(text.split(b"\f")),
        page_claims=(),
    )


def test_verify_materials_returns_finally_verified_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    pdf_bytes = b"%PDF-finally-verified"
    text_bytes = b"first\fsecond"
    pdf_path = tmp_path / "pdf"
    text_path = tmp_path / "text"
    pdf_path.write_bytes(pdf_bytes)
    text_path.write_bytes(text_bytes)

    class Cache:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def verify(self, reference_id: str) -> SimpleNamespace:
            return SimpleNamespace(
                entry=_material_plan(pdf_bytes, text_bytes).manifest.require(reference_id),
                cache_path={"pdf": pdf_path, "text": text_path}[reference_id],
            )

    monkeypatch.setattr(review, "ReferenceCache", Cache)

    assert review.verify_materials(_material_plan(pdf_bytes, text_bytes), tmp_path) == (
        pdf_bytes,
        text_bytes,
    )


@pytest.mark.parametrize("changed_reference", ("pdf", "text"))
def test_verify_materials_rechecks_each_final_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    changed_reference: str,
) -> None:
    pdf_bytes = b"%PDF-bound"
    text_bytes = b"first\fsecond"
    pdf_path = tmp_path / "pdf"
    text_path = tmp_path / "text"
    pdf_path.write_bytes(pdf_bytes)
    text_path.write_bytes(text_bytes)
    paths = {"pdf": pdf_path, "text": text_path}
    plan = _material_plan(pdf_bytes, text_bytes)

    class Cache:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def verify(self, reference_id: str) -> SimpleNamespace:
            result = SimpleNamespace(
                entry=plan.manifest.require(reference_id), cache_path=paths[reference_id]
            )
            if reference_id == "text":
                paths[changed_reference].write_bytes(b"changed-after-cache-verification")
            return result

    monkeypatch.setattr(review, "ReferenceCache", Cache)

    with pytest.raises(
        review.ReviewBuildError, match="differs from the manifest after verification"
    ):
        review.verify_materials(plan, tmp_path)


def test_build_uses_private_pdf_snapshot_and_manifest_generation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    output_root = repository / "tmp" / "pdfs" / "model-theory-t3-review"
    cache_root = tmp_path / "cache"
    cache_root.mkdir()
    tracked = review.load_review_plan()
    plan = tracked._replace(
        page_count=1,
        page_claims=(review.PageClaim("page-pair", "span", 1, "1"),),
    )
    span = review.SpanPageMap("span", 0, 4, "f" * 64, 1, 1)
    observed_pdf_paths: list[Path] = []

    monkeypatch.setattr(review, "load_review_plan", lambda _: plan)
    monkeypatch.setattr(review, "verify_materials", lambda *_: (b"%PDF-snapshot", b"text"))
    monkeypatch.setattr(review, "map_spans_to_pages", lambda *_: (span,))

    def fake_render(
        tool: review.PdftoppmTool,
        pdf_path: Path,
        page_number: int,
        temporary_root: Path,
    ) -> review.RenderedPage:
        del tool, temporary_root
        observed_pdf_paths.append(pdf_path)
        assert pdf_path.name == "manifest-bound-source.pdf"
        assert pdf_path.read_bytes() == b"%PDF-snapshot"
        content = _png()
        return review.RenderedPage(
            page_number,
            "pages/page-0001.png",
            content,
            hashlib.sha256(content).hexdigest(),
        )

    monkeypatch.setattr(review, "render_page", fake_render)
    first_tool = review.PdftoppmTool(tmp_path / "pdftoppm", "1" * 64, "renderer-v1")
    result = review.build_review_view(
        cache_root,
        "ignored",
        repo_root=repository,
        output_root=output_root,
        tool=first_tool,
    )
    repeat = review.build_review_view(
        cache_root,
        "ignored",
        repo_root=repository,
        output_root=output_root,
        tool=first_tool,
    )
    changed_renderer = review.build_review_view(
        cache_root,
        "ignored",
        repo_root=repository,
        output_root=output_root,
        tool=review.PdftoppmTool(tmp_path / "pdftoppm", "1" * 64, "renderer-v2"),
    )

    assert observed_pdf_paths and all(
        path.parent.parent == output_root for path in observed_pdf_paths
    )
    assert result == repeat
    output = result["output"]
    changed_output = changed_renderer["output"]
    manifest_sha256 = result["review_view_manifest_sha256"]
    assert isinstance(output, str)
    assert isinstance(changed_output, str)
    assert isinstance(manifest_sha256, str)
    assert output != changed_output
    assert manifest_sha256 in output
    review_view_manifest = result["review_view_manifest"]
    changed_review_view_manifest = changed_renderer["review_view_manifest"]
    assert isinstance(review_view_manifest, str)
    assert isinstance(changed_review_view_manifest, str)
    assert (repository / review_view_manifest).is_file()
    assert (repository / changed_review_view_manifest).is_file()


def test_output_rejects_symlink_and_reparse_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    linked = repository / "tmp"
    try:
        os.symlink(external, linked, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlinks are unavailable: {error}")

    with pytest.raises(review.ReviewBuildError, match="symlink or junction"):
        review._ensure_output(repository, linked / "pdfs")

    reparse = repository / "reparse"
    reparse.mkdir()
    monkeypatch.setattr(os.path, "isjunction", lambda path: Path(path) == reparse, raising=False)
    assert review._is_link_or_reparse(reparse)
    with pytest.raises(review.ReviewBuildError, match="symlink or junction"):
        review._require_confined_directory(reparse, repository.resolve())
