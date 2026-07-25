"""Build a local, source-bound visual aid for the model-theory T3 review."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import NamedTuple, cast

from autolean_builder.fine_span_attachment import (
    FineSourceSpanAttachmentV2,
    FineSourceSpanV2,
    FineSpanAttachmentError,
    load_fine_source_span_attachment,
)
from autolean_builder.reference_cache import (
    ReferenceCache,
    ReferenceCacheError,
    ReferenceManifestV1,
)

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_ROOT = ROOT / "tmp" / "pdfs" / "model-theory-t3-review"
PACKET_RELATIVE_PATH = Path("Builder/pilots/model-theory-admission/human-review/packet.v1.json")
FINE_SPANS_RELATIVE_PATH = Path("Builder/pilots/model-theory-admission/fine-source-spans.v2.json")
MANIFEST_RELATIVE_PATH = Path("Builder/references/manifest.v2.json")
PACKET_SCHEMA = "autolean.model-theory-t3-human-review-packet.v1"
VIEW_SCHEMA = "autolean.model-theory-t3-review-view-manifest.v1"
RENDER_DPI = 144
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ReviewBuildError(ValueError):
    pass


class PageClaim(NamedTuple):
    ambiguity_id: str
    span_id: str
    pdf_page_1_based: int
    printed_page_label: str


class ReviewPlan(NamedTuple):
    packet: dict[str, object]
    packet_sha256: str
    manifest: ReferenceManifestV1
    fine_spans: FineSourceSpanAttachmentV2
    pdf_reference_id: str
    text_reference_id: str
    page_count: int
    page_claims: tuple[PageClaim, ...]


class SpanPageMap(NamedTuple):
    span_id: str
    start_offset: int
    end_offset: int
    raw_sha256: str
    pdf_page_start: int
    pdf_page_end: int


class PdftoppmTool(NamedTuple):
    executable: Path
    executable_sha256: str
    version: str


class RenderedPage(NamedTuple):
    page_number: int
    relative_path: str
    content: bytes
    sha256: str


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_file(path: Path, label: str) -> bytes:
    try:
        if not path.is_file() or path.is_symlink():
            raise ReviewBuildError(f"{label} must be a regular non-symlink file")
        return path.read_bytes()
    except OSError as error:
        raise ReviewBuildError(f"cannot read {label}") from error


def _load_object(path: Path, label: str) -> tuple[dict[str, object], bytes]:
    raw = _read_file(path, label)
    try:
        value: object = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReviewBuildError(f"{label} is not valid UTF-8 JSON") from error
    return _object(value, label), raw


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ReviewBuildError(f"{label} must be a string-keyed object")
    return cast(dict[str, object], value)


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise ReviewBuildError(f"{label} must be an array")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReviewBuildError(f"{label} must be a nonempty string")
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReviewBuildError(f"{label} must be an integer")
    return value


def _bound_file(
    repo_root: Path,
    binding: dict[str, object],
    expected_path: Path,
    label: str,
) -> Path:
    if binding.get("path") != expected_path.as_posix():
        raise ReviewBuildError(f"{label} binds an unexpected path")
    path = repo_root / expected_path
    expected = _string(binding.get("file_sha256"), f"{label} hash")
    if not _SHA256.fullmatch(expected) or _sha256(_read_file(path, label)) != expected:
        raise ReviewBuildError(f"{label} differs from the packet binding")
    return path


def _load_page_claims(
    packet: dict[str, object],
    attachment: FineSourceSpanAttachmentV2,
) -> tuple[PageClaim, ...]:
    known_spans = {span.span_id for span in attachment.spans}
    known_ambiguities = {ambiguity.ambiguity_id for ambiguity in attachment.locator_ambiguities}
    rows = _array(packet.get("page_ambiguity_reviews"), "page ambiguity reviews")
    if len(rows) != 2 or len(known_ambiguities) != 2:
        raise ReviewBuildError("the review packet must contain exactly two page ambiguities")
    claims: list[PageClaim] = []
    for raw in rows:
        row = _object(raw, "page ambiguity review")
        ambiguity_id = _string(row.get("ambiguity_id"), "ambiguity ID")
        span_id = _string(row.get("span_id"), "ambiguity span ID")
        if ambiguity_id not in known_ambiguities or span_id not in known_spans:
            raise ReviewBuildError("page ambiguity does not bind fine-span evidence")
        claimed = _object(row.get("claimed_page"), f"claimed page {ambiguity_id}")
        one_based = _integer(claimed.get("pdf_page_1_based"), "claimed PDF page")
        zero_based = _integer(claimed.get("pdf_page_0_based"), "claimed PDF page index")
        printed = _string(claimed.get("printed_page_label"), "claimed printed page")
        if one_based <= 0 or zero_based != one_based - 1:
            raise ReviewBuildError(f"page coordinates are inconsistent: {ambiguity_id}")
        claims.append(
            PageClaim(
                ambiguity_id=ambiguity_id,
                span_id=span_id,
                pdf_page_1_based=one_based,
                printed_page_label=printed,
            )
        )
    return tuple(claims)


def load_review_plan(repo_root: Path = ROOT) -> ReviewPlan:
    packet, packet_raw = _load_object(repo_root / PACKET_RELATIVE_PATH, "review packet")
    if (
        packet.get("schema_version") != PACKET_SCHEMA
        or packet.get("artifact_kind") != "public_safe_advisory_review_packet"
        or packet.get("review_effect") != "advisory_only"
    ):
        raise ReviewBuildError("unsupported review packet boundary")
    authority = _object(packet.get("authority_boundary"), "packet authority boundary")
    if not authority or any(value is not False for value in authority.values()):
        raise ReviewBuildError("review packet contains authority")

    evidence = _object(packet.get("evidence_bindings"), "evidence bindings")
    fine_binding = _object(evidence.get("fine_source_spans"), "fine-span binding")
    fine_path = _bound_file(repo_root, fine_binding, FINE_SPANS_RELATIVE_PATH, "fine-source spans")
    manifest_binding = _object(evidence.get("reference_manifest"), "manifest binding")
    manifest_path = _bound_file(
        repo_root, manifest_binding, MANIFEST_RELATIVE_PATH, "reference manifest"
    )
    try:
        fine_spans = load_fine_source_span_attachment(fine_path)
        manifest = ReferenceManifestV1.load(
            manifest_path,
            expected_sha256=_string(manifest_binding.get("file_sha256"), "reference manifest hash"),
        )
        fine_spans.assert_binds_reference_manifest(manifest)
    except (FineSpanAttachmentError, ReferenceCacheError, ValueError) as error:
        raise ReviewBuildError(f"tracked source binding did not replay: {error}") from error

    pdf_id = _string(manifest_binding.get("pdf_reference_id"), "PDF reference ID")
    text_id = _string(
        manifest_binding.get("derived_text_reference_id"), "derived-text reference ID"
    )
    pdf_entry = manifest.require(pdf_id)
    text_entry = manifest.require(text_id)
    if (
        pdf_id != fine_spans.reference_binding.parent_reference_id
        or text_id != fine_spans.reference_binding.reference_id
        or pdf_entry.sha256 != manifest_binding.get("pdf_sha256")
        or pdf_entry.size_bytes != manifest_binding.get("pdf_size_bytes")
        or text_entry.sha256 != manifest_binding.get("derived_text_sha256")
        or text_entry.size_bytes != manifest_binding.get("derived_text_size_bytes")
    ):
        raise ReviewBuildError("review packet source identity differs from the manifest")
    page_count = _integer(manifest_binding.get("derived_text_page_count"), "page count")
    if page_count <= 0:
        raise ReviewBuildError("derived-text page count must be positive")
    claims = _load_page_claims(packet, fine_spans)
    return ReviewPlan(
        packet=packet,
        packet_sha256=_sha256(packet_raw),
        manifest=manifest,
        fine_spans=fine_spans,
        pdf_reference_id=pdf_id,
        text_reference_id=text_id,
        page_count=page_count,
        page_claims=claims,
    )


def verify_materials(plan: ReviewPlan, cache_root: Path) -> tuple[Path, bytes]:
    try:
        root = cache_root.resolve(strict=True)
        if not root.is_dir():
            raise ReviewBuildError("reference cache root must be a directory")
        cache = ReferenceCache(plan.manifest, root, confinement_root=root)
        pdf = cache.verify(plan.pdf_reference_id)
        text = cache.verify(plan.text_reference_id)
        plan.fine_spans.assert_matches_source_artifact(text.cache_path)
    except (OSError, FineSpanAttachmentError, ReferenceCacheError) as error:
        raise ReviewBuildError(f"reference cache verification failed: {error}") from error
    text_bytes = _read_file(text.cache_path, "manifest-bound derived text")
    try:
        text_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReviewBuildError("manifest-bound derived text is not valid UTF-8") from error
    if len(text_bytes.split(b"\f")) != plan.page_count:
        raise ReviewBuildError("derived-text page count differs from the packet")
    return pdf.cache_path, text_bytes


def map_spans_to_pages(
    text_bytes: bytes,
    spans: tuple[FineSourceSpanV2, ...],
) -> tuple[SpanPageMap, ...]:
    def page_for_offset(offset: int) -> int:
        if offset < 0 or offset >= len(text_bytes) or text_bytes[offset : offset + 1] == b"\f":
            raise ReviewBuildError("span boundary points at a form-feed or outside the source")
        return text_bytes.count(b"\f", 0, offset) + 1

    result: list[SpanPageMap] = []
    for span in spans:
        if span.end_offset > len(text_bytes):
            raise ReviewBuildError(f"source span is out of bounds: {span.span_id}")
        selected = text_bytes[span.start_offset : span.end_offset]
        if _sha256(selected) != span.raw_sha256:
            raise ReviewBuildError(f"source span digest changed: {span.span_id}")
        try:
            selected.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ReviewBuildError(f"source span splits UTF-8: {span.span_id}") from error
        result.append(
            SpanPageMap(
                span_id=span.span_id,
                start_offset=span.start_offset,
                end_offset=span.end_offset,
                raw_sha256=span.raw_sha256,
                pdf_page_start=page_for_offset(span.start_offset),
                pdf_page_end=page_for_offset(span.end_offset - 1),
            )
        )
    return tuple(result)


def resolve_pdftoppm(command: str) -> PdftoppmTool:
    if not command or any(character in command for character in "\x00\r\n"):
        raise ReviewBuildError("pdftoppm command is invalid")
    located = shutil.which(command)
    candidate = Path(located) if located is not None else Path(command)
    try:
        executable = candidate.resolve(strict=True)
    except OSError as error:
        raise ReviewBuildError("pdftoppm executable was not found") from error
    executable_bytes = _read_file(executable, "pdftoppm executable")
    try:
        completed = subprocess.run(
            (str(executable), "-v"),
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=15,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ReviewBuildError("pdftoppm identity check failed") from error
    output = f"{completed.stdout}\n{completed.stderr}"
    version = next(
        (line.strip() for line in output.splitlines() if line.startswith("pdftoppm version ")),
        None,
    )
    if completed.returncode != 0 or version is None:
        raise ReviewBuildError("pdftoppm did not report a supported version")
    return PdftoppmTool(executable, _sha256(executable_bytes), version)


def render_page(
    tool: PdftoppmTool,
    pdf_path: Path,
    page_number: int,
    temporary_root: Path,
) -> RenderedPage:
    page_root = temporary_root / f"page-{page_number:04d}"
    page_root.mkdir(mode=0o700)
    prefix = page_root / "render"
    try:
        completed = subprocess.run(
            (
                str(tool.executable),
                "-f",
                str(page_number),
                "-l",
                str(page_number),
                "-r",
                str(RENDER_DPI),
                "-png",
                "-singlefile",
                str(pdf_path),
                str(prefix),
            ),
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=90,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ReviewBuildError(f"pdftoppm failed for page {page_number}") from error
    output = prefix.with_suffix(".png")
    if completed.returncode != 0 or list(page_root.iterdir()) != [output]:
        raise ReviewBuildError(f"pdftoppm rejected or polluted page {page_number}")
    content = _read_file(output, f"rendered page {page_number}")
    if len(content) < 24 or content[:8] != b"\x89PNG\r\n\x1a\n":
        raise ReviewBuildError(f"pdftoppm emitted a non-PNG for page {page_number}")
    return RenderedPage(
        page_number,
        f"pages/page-{page_number:04d}.png",
        content,
        _sha256(content),
    )


def _ensure_output(repo_root: Path, output_root: Path) -> Path:
    try:
        repository = repo_root.resolve(strict=True)
        relative = output_root.absolute().relative_to(repository)
    except (OSError, ValueError) as error:
        raise ReviewBuildError("review output escapes the repository") from error
    current = repository
    for part in relative.parts:
        current /= part
        if current.exists() and current.is_symlink():
            raise ReviewBuildError("review output contains a symlink")
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / "pages").mkdir(exist_ok=True)
    if not output_root.is_dir() or not (output_root / "pages").is_dir():
        raise ReviewBuildError("review output boundary is not a directory")
    return relative


def _preflight(path: Path, content: bytes) -> None:
    if not path.exists():
        return
    if path.is_symlink() or not path.is_file() or _read_file(path, path.name) != content:
        raise ReviewBuildError(f"review output collision will not be overwritten: {path.name}")


def _install(path: Path, content: bytes) -> None:
    if path.exists():
        return
    try:
        with path.open("xb") as handle:
            handle.write(content)
    except OSError as error:
        raise ReviewBuildError(f"cannot install review output: {path.name}") from error


def build_page_ambiguity_evidence(
    claims: tuple[PageClaim, ...],
    span_pages: tuple[SpanPageMap, ...],
    pages: dict[int, RenderedPage],
) -> list[dict[str, object]]:
    mapped_by_id = {item.span_id: item for item in span_pages}
    evidence: list[dict[str, object]] = []
    for claim in claims:
        try:
            mapped = mapped_by_id[claim.span_id]
            rendered = pages[claim.pdf_page_1_based]
        except KeyError as error:
            raise ReviewBuildError("page ambiguity lacks mapped render evidence") from error
        if not mapped.pdf_page_start <= claim.pdf_page_1_based <= mapped.pdf_page_end:
            raise ReviewBuildError(f"claimed page is outside its mapped span: {claim.ambiguity_id}")
        evidence.append(
            {
                "ambiguity_id": claim.ambiguity_id,
                "span_id": claim.span_id,
                "mapped_pdf_page_start_1_based": mapped.pdf_page_start,
                "mapped_pdf_page_end_1_based": mapped.pdf_page_end,
                "pdf_page_1_based": claim.pdf_page_1_based,
                "pdf_page_0_based": claim.pdf_page_1_based - 1,
                "printed_page_label": claim.printed_page_label,
                "page_render_sha256": rendered.sha256,
                "page_label_region_sha256": None,
            }
        )
    return evidence


def _render_index(
    plan: ReviewPlan,
    span_pages: tuple[SpanPageMap, ...],
    pages: dict[int, RenderedPage],
) -> bytes:
    lines = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8"><meta name="viewport" '
        'content="width=device-width,initial-scale=1">',
        "<title>AutoLean T3 model-theory review</title><style>",
        "body{margin:0;background:#101418;color:#e8edf2;font:15px system-ui,sans-serif}",
        "header,main{max-width:1180px;margin:auto;padding:24px}",
        ".span{min-width:0;border-top:1px solid #46515c;padding:24px 0}",
        ".pages{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(320px,100%),1fr));gap:16px}",
        "figure{min-width:0;margin:0;background:#fff;color:#111;padding:8px}",
        "img{display:block;width:100%;height:auto}",
        "h1,h2,p,li,code{overflow-wrap:anywhere}code{color:#9ed4ff}",
        "</style></head><body>",
        "<header><h1>Model-theory T3 advisory review</h1><p>This view cannot change the gap "
        "decision, freeze a statement, "
        "hand work to Prover, or issue an admission.</p>",
        f"<p>Packet SHA-256 <code>{plan.packet_sha256}</code></p></header><main>",
        "<h2>Span review</h2>",
    ]
    for span in span_pages:
        figures = "".join(
            f'<figure><img src="{pages[number].relative_path}" alt="PDF page {number}">'
            f"<figcaption>PDF page {number}; PNG SHA-256 "
            f"<code>{pages[number].sha256}</code></figcaption></figure>"
            for number in range(span.pdf_page_start, span.pdf_page_end + 1)
        )
        lines.append(
            f'<section class="span"><h2>{html.escape(span.span_id)}</h2>'
            f"<p>UTF-8 bytes {span.start_offset}-{span.end_offset}; SHA-256 "
            f"<code>{span.raw_sha256}</code>; PDF pages "
            f"{span.pdf_page_start}-{span.pdf_page_end}.</p>"
            f'<div class="pages">{figures}</div></section>'
        )
    lines.append("<h2>Unconfirmed page claims</h2><ul>")
    mapped = {item.span_id: item for item in span_pages}
    for claim in plan.page_claims:
        span = mapped[claim.span_id]
        lines.append(
            f"<li><code>{html.escape(claim.ambiguity_id)}</code>: mapped PDF "
            f"{span.pdf_page_start}-{span.pdf_page_end}; claim PDF "
            f"{claim.pdf_page_1_based} / printed {html.escape(claim.printed_page_label)}</li>"
        )
    lines.append(
        "</ul><p>Record verdicts in the tracked response template without source excerpts "
        "or local paths.</p></main></body></html>"
    )
    return ("\n".join(lines) + "\n").encode()


def build_review_view(
    cache_root: Path,
    pdftoppm: str,
    *,
    repo_root: Path = ROOT,
    output_root: Path = OUTPUT_ROOT,
    tool: PdftoppmTool | None = None,
) -> dict[str, object]:
    plan = load_review_plan(repo_root)
    pdf_path, text_bytes = verify_materials(plan, cache_root)
    spans = map_spans_to_pages(text_bytes, plan.fine_spans.spans)
    renderer = tool or resolve_pdftoppm(pdftoppm)
    relative_output = _ensure_output(repo_root, output_root)
    needed_pages = sorted(
        {page for span in spans for page in range(span.pdf_page_start, span.pdf_page_end + 1)}
    )
    with tempfile.TemporaryDirectory(prefix=".render-", dir=output_root) as temporary:
        rendered = {
            page: render_page(renderer, pdf_path, page, Path(temporary)) for page in needed_pages
        }
    ambiguity_evidence = build_page_ambiguity_evidence(plan.page_claims, spans, rendered)
    index = _render_index(plan, spans, rendered)
    manifest: dict[str, object] = {
        "schema_version": VIEW_SCHEMA,
        "packet_id": _string(plan.packet.get("packet_id"), "packet ID"),
        "packet_sha256": plan.packet_sha256,
        "review_effect": "advisory_only",
        "network_used": False,
        "source_binding": {
            "reference_manifest_sha256": plan.manifest.manifest_sha256,
            "pdf_reference_id": plan.pdf_reference_id,
            "pdf_sha256": plan.manifest.require(plan.pdf_reference_id).sha256,
            "derived_text_reference_id": plan.text_reference_id,
            "derived_text_sha256": plan.manifest.require(plan.text_reference_id).sha256,
            "derived_text_page_count": plan.page_count,
            "contains_textbook_excerpt": False,
            "contains_absolute_path": False,
        },
        "renderer": {
            "name": "pdftoppm",
            "version": renderer.version,
            "executable_sha256": renderer.executable_sha256,
            "dpi": RENDER_DPI,
        },
        "span_page_map": [
            {
                "span_id": span.span_id,
                "start_offset": span.start_offset,
                "end_offset": span.end_offset,
                "raw_sha256": span.raw_sha256,
                "pdf_page_start": span.pdf_page_start,
                "pdf_page_end": span.pdf_page_end,
            }
            for span in spans
        ],
        "page_ambiguity_evidence": ambiguity_evidence,
        "rendered_pages": [
            {
                "page_number": page.page_number,
                "path": page.relative_path,
                "sha256": page.sha256,
                "size_bytes": len(page.content),
            }
            for page in (rendered[number] for number in sorted(rendered))
        ],
        "index_html": {"path": "index.html", "sha256": _sha256(index)},
        "authority_boundary": {
            "human_identity_authenticated": False,
            "expert_qualification_authenticated": False,
            "builder_admission_authority_present": False,
            "may_change_boundary_decision": False,
            "may_issue_admission_receipt": False,
            "may_freeze_statement": False,
            "may_handoff_to_prover": False,
            "may_promote": False,
        },
    }
    manifest_bytes = (
        json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode()
    destinations = {output_root / page.relative_path: page.content for page in rendered.values()}
    destinations[output_root / "index.html"] = index
    destinations[output_root / "review-view-manifest.v1.json"] = manifest_bytes
    for path, content in destinations.items():
        _preflight(path, content)
    for path, content in destinations.items():
        _install(path, content)
    return {
        "manifest_sha256": _sha256(manifest_bytes),
        "output": relative_output.as_posix(),
        "rendered_page_count": len(rendered),
        "status": "ok",
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("action", choices=("build",))
    parser.add_argument("--cache-root", required=True, type=Path)
    parser.add_argument("--pdftoppm", default="pdftoppm")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    try:
        arguments = parse_args(argv)
        result = build_review_view(arguments.cache_root, arguments.pdftoppm)
    except ReviewBuildError as error:
        raise SystemExit(f"model-theory-review: {error}") from error
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
