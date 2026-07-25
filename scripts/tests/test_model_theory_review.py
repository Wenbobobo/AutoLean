from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest
from autolean_builder.fine_span_attachment import FineSourceSpanV2

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

    assert plan.packet_sha256 == (
        "53eea20e92971ad6e47f1f244649604480d818f3645e97ab0d71a0afef19da6b"
    )
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
            148,
            "127",
        ),
        (
            "universal-right-page-pair-unreconciled",
            "lk-validity-and-soundness-universal-right-case",
            208,
            "187",
        ),
    ]


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
            "pdf_page_1_based": 2,
            "pdf_page_0_based": 1,
            "printed_page_label": "B",
            "page_render_sha256": pages[2].sha256,
            "page_label_region_sha256": None,
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
