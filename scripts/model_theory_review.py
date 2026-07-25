"""Build a local, source-bound visual aid for the model-theory T3 review."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import shutil
import stat
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
DECISION_RELATIVE_PATH = Path("Builder/pilots/model-theory-admission/decision.v2.json")
FINE_SPANS_RELATIVE_PATH = Path("Builder/pilots/model-theory-admission/fine-source-spans.v2.json")
PENDING_REVIEW_RELATIVE_PATH = Path("Builder/pilots/model-theory-admission/pending-review.md")
MANIFEST_RELATIVE_PATH = Path("Builder/references/manifest.v2.json")
IMPLEMENTATION_RELATIVE_PATH = Path("Library/AutoLeanLibrary/Fixtures/ModelTheory/UniversalLK.lean")
T4_ATTACHMENT_RELATIVE_PATH = Path(
    "Builder/pilots/model-theory-admission/t4-exact-image-attachment.v1.json"
)
T4_QUERY_RELATIVE_PATH = Path("Builder/pilots/model-theory-admission/t4-declaration-query.v1.json")
PACKET_SCHEMA = "autolean.model-theory-t3-human-review-packet.v1"
VIEW_SCHEMA = "autolean.model-theory-t3-review-view-manifest.v1"
RENDER_DPI = 144
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


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
    *,
    path_key: str = "path",
    hash_key: str = "file_sha256",
) -> Path:
    if binding.get(path_key) != expected_path.as_posix():
        raise ReviewBuildError(f"{label} binds an unexpected path")
    path = repo_root / expected_path
    expected = _string(binding.get(hash_key), f"{label} hash")
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
    seen_ambiguities: set[str] = set()
    for raw in rows:
        row = _object(raw, "page ambiguity review")
        ambiguity_id = _string(row.get("ambiguity_id"), "ambiguity ID")
        span_id = _string(row.get("span_id"), "ambiguity span ID")
        if (
            ambiguity_id not in known_ambiguities
            or span_id not in known_spans
            or ambiguity_id in seen_ambiguities
        ):
            raise ReviewBuildError("page ambiguity does not bind fine-span evidence")
        seen_ambiguities.add(ambiguity_id)
        pages = _array(row.get("claimed_pages"), f"claimed pages {ambiguity_id}")
        if len(pages) != 2:
            raise ReviewBuildError(f"page ambiguity must contain a page pair: {ambiguity_id}")
        seen_pages: set[int] = set()
        for claimed_raw in pages:
            claimed = _object(claimed_raw, f"claimed page {ambiguity_id}")
            one_based = _integer(claimed.get("pdf_page_1_based"), "claimed PDF page")
            zero_based = _integer(claimed.get("pdf_page_0_based"), "claimed PDF page index")
            printed = _string(claimed.get("printed_page_label"), "claimed printed page")
            if one_based <= 0 or zero_based != one_based - 1 or one_based in seen_pages:
                raise ReviewBuildError(f"page coordinates are inconsistent: {ambiguity_id}")
            seen_pages.add(one_based)
            claims.append(
                PageClaim(
                    ambiguity_id=ambiguity_id,
                    span_id=span_id,
                    pdf_page_1_based=one_based,
                    printed_page_label=printed,
                )
            )
    if seen_ambiguities != known_ambiguities:
        raise ReviewBuildError("page ambiguities do not bind fine-span evidence exactly")
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
    decision_binding = _object(packet.get("decision_binding"), "decision binding")
    _bound_file(repo_root, decision_binding, DECISION_RELATIVE_PATH, "decision")
    fine_binding = _object(evidence.get("fine_source_spans"), "fine-span binding")
    fine_path = _bound_file(repo_root, fine_binding, FINE_SPANS_RELATIVE_PATH, "fine-source spans")
    pending_binding = _object(evidence.get("pending_review"), "pending-review binding")
    _bound_file(repo_root, pending_binding, PENDING_REVIEW_RELATIVE_PATH, "pending review")
    manifest_binding = _object(evidence.get("reference_manifest"), "manifest binding")
    manifest_path = _bound_file(
        repo_root, manifest_binding, MANIFEST_RELATIVE_PATH, "reference manifest"
    )
    implementation_binding = _object(evidence.get("implementation"), "implementation binding")
    _bound_file(
        repo_root,
        implementation_binding,
        IMPLEMENTATION_RELATIVE_PATH,
        "implementation",
        hash_key="sha256",
    )
    t4_binding = _object(evidence.get("t4_exact_image"), "T4 exact-image binding")
    _bound_file(
        repo_root,
        t4_binding,
        T4_ATTACHMENT_RELATIVE_PATH,
        "T4 attachment",
        path_key="attachment_path",
        hash_key="attachment_sha256",
    )
    _bound_file(
        repo_root,
        t4_binding,
        T4_QUERY_RELATIVE_PATH,
        "T4 query",
        path_key="query_path",
        hash_key="query_sha256",
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


def _verify_material_bytes(
    content: bytes,
    *,
    expected_sha256: str,
    expected_size_bytes: int,
    label: str,
) -> None:
    if len(content) != expected_size_bytes or _sha256(content) != expected_sha256:
        raise ReviewBuildError(f"{label} differs from the manifest after verification")


def verify_materials(plan: ReviewPlan, cache_root: Path) -> tuple[bytes, bytes]:
    try:
        root = cache_root.resolve(strict=True)
        if not root.is_dir():
            raise ReviewBuildError("reference cache root must be a directory")
        cache = ReferenceCache(plan.manifest, root, confinement_root=root)
        pdf = cache.verify(plan.pdf_reference_id)
        text = cache.verify(plan.text_reference_id)
    except (OSError, FineSpanAttachmentError, ReferenceCacheError) as error:
        raise ReviewBuildError(f"reference cache verification failed: {error}") from error
    pdf_bytes = _read_file(pdf.cache_path, "manifest-bound PDF")
    text_bytes = _read_file(text.cache_path, "manifest-bound derived text")
    _verify_material_bytes(
        pdf_bytes,
        expected_sha256=pdf.entry.sha256,
        expected_size_bytes=pdf.entry.size_bytes,
        label="manifest-bound PDF",
    )
    _verify_material_bytes(
        text_bytes,
        expected_sha256=text.entry.sha256,
        expected_size_bytes=text.entry.size_bytes,
        label="manifest-bound derived text",
    )
    try:
        text_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReviewBuildError("manifest-bound derived text is not valid UTF-8") from error
    if len(text_bytes.split(b"\f")) != plan.page_count:
        raise ReviewBuildError("derived-text page count differs from the packet")
    return pdf_bytes, text_bytes


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


def _is_link_or_reparse(path: Path) -> bool:
    try:
        value = path.lstat()
    except OSError as error:
        raise ReviewBuildError(f"cannot inspect review output: {path.name}") from error
    is_junction = getattr(os.path, "isjunction", lambda _: False)
    return (
        path.is_symlink()
        or is_junction(path)
        or stat.S_ISLNK(value.st_mode)
        or bool(int(getattr(value, "st_file_attributes", 0)) & _REPARSE_POINT)
    )


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _relative_output_parts(path: Path, repository: Path) -> tuple[str, ...]:
    try:
        relative = _lexical_absolute(path).relative_to(repository)
    except ValueError as error:
        raise ReviewBuildError("review output escapes the repository") from error
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise ReviewBuildError("review output contains an unsafe component")
    return relative.parts


def _require_confined_directory(path: Path, repository: Path) -> None:
    if _is_link_or_reparse(path):
        raise ReviewBuildError("review output contains a symlink or junction")
    try:
        value = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ReviewBuildError(f"cannot inspect review output: {path.name}") from error
    if not stat.S_ISDIR(value.st_mode):
        raise ReviewBuildError("review output boundary is not a directory")
    try:
        resolved.relative_to(repository)
    except ValueError as error:
        raise ReviewBuildError("review output escapes the repository") from error


def _ensure_output(repo_root: Path, output_root: Path) -> Path:
    try:
        repository = repo_root.resolve(strict=True)
    except OSError as error:
        raise ReviewBuildError("review output escapes the repository") from error
    relative = _relative_output_parts(output_root, repository)
    current = repository
    for part in relative:
        current /= part
        try:
            current.mkdir()
        except FileExistsError:
            pass
        except OSError as error:
            raise ReviewBuildError(f"cannot create review output: {current.name}") from error
        _require_confined_directory(current, repository)
    return Path(*relative)


def _require_destination_parent(path: Path, output_root: Path, repository: Path) -> None:
    try:
        output_resolved = output_root.resolve(strict=True)
        parent_resolved = path.parent.resolve(strict=True)
        parent_resolved.relative_to(output_resolved)
        parent_resolved.relative_to(repository)
    except (OSError, ValueError) as error:
        raise ReviewBuildError("review output destination escapes its version directory") from error
    _require_confined_directory(path.parent, repository)


def _preflight(path: Path, content: bytes) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise ReviewBuildError(f"cannot inspect review output: {path.name}") from error
    if _is_link_or_reparse(path) or not path.is_file() or _read_file(path, path.name) != content:
        raise ReviewBuildError(f"review output collision will not be overwritten: {path.name}")


def _install(path: Path, content: bytes) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise ReviewBuildError(f"cannot inspect review output: {path.name}") from error
    else:
        _preflight(path, content)
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
    evidence_by_ambiguity: dict[str, dict[str, object]] = {}
    for claim in claims:
        try:
            mapped = mapped_by_id[claim.span_id]
            rendered = pages[claim.pdf_page_1_based]
        except KeyError as error:
            raise ReviewBuildError("page ambiguity lacks mapped render evidence") from error
        if not mapped.pdf_page_start <= claim.pdf_page_1_based <= mapped.pdf_page_end:
            raise ReviewBuildError(f"claimed page is outside its mapped span: {claim.ambiguity_id}")
        row = evidence_by_ambiguity.setdefault(
            claim.ambiguity_id,
            {
                "ambiguity_id": claim.ambiguity_id,
                "span_id": claim.span_id,
                "mapped_pdf_page_start_1_based": mapped.pdf_page_start,
                "mapped_pdf_page_end_1_based": mapped.pdf_page_end,
                "page_evidence": [],
            },
        )
        page_evidence = _array(row["page_evidence"], "page ambiguity evidence")
        page_evidence.append(
            {
                "pdf_page_1_based": claim.pdf_page_1_based,
                "pdf_page_0_based": claim.pdf_page_1_based - 1,
                "printed_page_label": claim.printed_page_label,
                "page_render_sha256": rendered.sha256,
            }
        )
    return list(evidence_by_ambiguity.values())


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
            f"{span.pdf_page_start}-{span.pdf_page_end}; claimed PDF "
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
    pdf_bytes, text_bytes = verify_materials(plan, cache_root)
    spans = map_spans_to_pages(text_bytes, plan.fine_spans.spans)
    renderer = tool or resolve_pdftoppm(pdftoppm)
    _ensure_output(repo_root, output_root)
    needed_pages = sorted(
        {page for span in spans for page in range(span.pdf_page_start, span.pdf_page_end + 1)}
    )
    with tempfile.TemporaryDirectory(prefix=".review-build-", dir=output_root) as temporary:
        temporary_root = Path(temporary)
        pdf_snapshot = temporary_root / "manifest-bound-source.pdf"
        try:
            with pdf_snapshot.open("xb") as handle:
                handle.write(pdf_bytes)
        except OSError as error:
            raise ReviewBuildError("cannot create private PDF render snapshot") from error
        rendered = {
            page: render_page(renderer, pdf_snapshot, page, temporary_root) for page in needed_pages
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
    manifest_sha256 = _sha256(manifest_bytes)
    version_root = output_root / manifest_sha256
    relative_output = _ensure_output(repo_root, version_root)
    _ensure_output(repo_root, version_root / "pages")
    try:
        repository = repo_root.resolve(strict=True)
    except OSError as error:
        raise ReviewBuildError("review output escapes the repository") from error
    destinations = {version_root / page.relative_path: page.content for page in rendered.values()}
    destinations[version_root / "index.html"] = index
    destinations[version_root / "review-view-manifest.v1.json"] = manifest_bytes
    for path, content in destinations.items():
        _require_destination_parent(path, version_root, repository)
        _preflight(path, content)
    for path, content in destinations.items():
        _require_destination_parent(path, version_root, repository)
        _install(path, content)
    return {
        "review_view_manifest_sha256": manifest_sha256,
        "output": relative_output.as_posix(),
        "review_view_manifest": (relative_output / "review-view-manifest.v1.json").as_posix(),
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
