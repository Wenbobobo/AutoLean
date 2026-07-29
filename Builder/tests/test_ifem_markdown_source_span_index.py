from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from autolean_builder import ifem_markdown_source_span_index as span_index
from autolean_contracts import HashKindV1, canonical_json_bytes, stable_identifier

_REVISION = "a" * 40
_RETRIEVED_AT = "2026-07-29T11:47:23.423056Z"
_INTRO_REFERENCE_ID = "ifem-test-intro-md-source"
_README_REFERENCE_ID = "ifem-test-readme-source"
_INTRO_PATH = "intro.md"
_README_PATH = "README.md"
_PRIVATE_HEADING = "Private opening heading must never leave the cache"
_PRIVATE_BODY = "Private opening body must never leave the cache."


def _intro_bytes(*, line_ending: str = "\n", text: str | None = None) -> bytes:
    logical = text or (
        f"# {_PRIVATE_HEADING}\n\n{_PRIVATE_BODY}\n\n"
        "## Repeated structural heading\n\nFirst section body.\n\n"
        "## Repeated structural heading\n\nSecond section body.\n"
    )
    return logical.replace("\n", line_ending).encode("utf-8")


def _source_file(reference_id: str, source_path: str, raw: bytes) -> dict[str, object]:
    return {
        "path": source_path,
        "reference_id": reference_id,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
    }


def _install_lock(
    tmp_path: Path,
    *,
    intro_bytes: bytes | None = None,
    lock_bytes: bytes | None = None,
) -> tuple[Path, Path, bytes]:
    cache_root = tmp_path / "cache" / "references"
    cache_root.mkdir(parents=True)
    raw_intro = intro_bytes or _intro_bytes()
    raw_readme = b"Synthetic locked metadata only.\n"
    readme_file = _source_file(_README_REFERENCE_ID, _README_PATH, raw_readme)
    intro_file = _source_file(_INTRO_REFERENCE_ID, _INTRO_PATH, raw_intro)
    for record, raw in ((readme_file, raw_readme), (intro_file, raw_intro)):
        suffix = Path(str(record["path"])).suffix
        target = cache_root / str(record["reference_id"]) / f"{record['sha256']}{suffix}"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    source_lock_path = cache_root / "source-lock" / "source-lock.v1.json"
    source_lock_path.parent.mkdir(parents=True)
    if lock_bytes is None:
        lock_bytes = canonical_json_bytes(
            {
                "acquisition": {
                    "retrieved_at": _RETRIEVED_AT,
                    "source_file_count": 2,
                    "source_size_bytes": len(raw_readme) + len(raw_intro),
                },
                "policy": {
                    "access_policy": "public_open_access",
                    "contract_freeze": "not_authorized",
                    "model_egress_policy": "local_only",
                    "prover_handoff": "not_authorized",
                },
                "reference_manifest_candidate_sha256": "b" * 64,
                "reference_manifest_state": "candidate_entries_not_yet_tracked",
                "schema_version": span_index.IFEM_SOURCE_LOCK_SCHEMA_VERSION,
                "source": {"resolved_revision": _REVISION},
                "source_files": [readme_file, intro_file],
                "state": "acquired_local_only",
            }
        )
    source_lock_path.write_bytes(lock_bytes)
    return source_lock_path, cache_root, raw_intro


def _build(tmp_path: Path, *, intro_bytes: bytes | None = None):
    source_lock_path, cache_root, raw_intro = _install_lock(tmp_path, intro_bytes=intro_bytes)
    return (
        span_index.build_ifem_markdown_source_span_index(
            source_lock_path=source_lock_path,
            source_cache_root=cache_root,
        ),
        source_lock_path,
        cache_root,
        raw_intro,
    )


def test_replays_locked_intro_into_text_free_stable_heading_spans(tmp_path: Path) -> None:
    index, source_lock_path, _, raw_intro = _build(tmp_path)

    assert (
        index.source_lock.source_lock_sha256
        == hashlib.sha256(source_lock_path.read_bytes()).hexdigest()
    )
    assert index.source_lock.source_file_count == 2
    assert index.source_lock.markdown_file_count == 1
    assert index.markdown_heading_count == 3
    assert index.model_egress_policy == "local_only"
    assert index.semantic_review_state == "not_performed"
    assert index.contract_freeze == "not_authorized"
    assert index.prover_handoff == "not_authorized"
    assert index.contains_source_text is False
    assert index.contains_model_input is False
    assert [span.heading_index for span in index.spans] == [0, 1, 2]
    assert [span.heading_level for span in index.spans] == [1, 2, 2]
    assert [(span.start_line, span.end_line) for span in index.spans] == [(1, 11), (5, 8), (9, 11)]
    assert [span.source_file_index for span in index.spans] == [1, 1, 1]
    assert index.spans[1].span_id == stable_identifier(
        "ifem.markdown-source-span", f"{_REVISION}:{_INTRO_PATH}:heading:1"
    )
    assert index.spans[0].source_file_sha256 == hashlib.sha256(raw_intro).hexdigest()

    records = index.source_records()
    assert len(records) == 1
    assert records[0].locator == _INTRO_PATH
    assert records[0].content_hash.kind is HashKindV1.SOURCE_BYTES
    assert [span.content_hash.kind for span in records[0].spans] == [HashKindV1.SOURCE_SPAN] * 3
    assert records[0].metadata == {
        "model_egress_policy": "local_only",
        "source_alignment_only": True,
        "semantic_review_state": "not_performed",
    }


def test_duplicate_headings_are_structurally_disambiguated_without_text(tmp_path: Path) -> None:
    index, _, _, _ = _build(tmp_path)
    repeated = index.spans[1:]

    assert repeated[0].heading_content_sha256 == repeated[1].heading_content_sha256
    assert repeated[0].heading_character_count == repeated[1].heading_character_count
    assert repeated[0].span_id != repeated[1].span_id
    assert repeated[0].heading_index == 1
    assert repeated[1].heading_index == 2
    assert (repeated[0].start_line, repeated[0].end_line) == (5, 8)
    assert (repeated[1].start_line, repeated[1].end_line) == (9, 11)
    assert repeated[0].section_content_sha256 != repeated[1].section_content_sha256


def test_logical_section_digests_canonicalize_lf_and_crlf(tmp_path: Path) -> None:
    lf_index, _, _, _ = _build(tmp_path / "lf", intro_bytes=_intro_bytes(line_ending="\n"))
    crlf_index, _, _, _ = _build(tmp_path / "crlf", intro_bytes=_intro_bytes(line_ending="\r\n"))

    assert [span.source_file_sha256 for span in lf_index.spans] != [
        span.source_file_sha256 for span in crlf_index.spans
    ]
    assert [span.span_id for span in lf_index.spans] == [span.span_id for span in crlf_index.spans]
    assert [span.heading_content_sha256 for span in lf_index.spans] == [
        span.heading_content_sha256 for span in crlf_index.spans
    ]
    assert [span.section_content_sha256 for span in lf_index.spans] == [
        span.section_content_sha256 for span in crlf_index.spans
    ]
    assert [span.section_character_count for span in lf_index.spans] == [
        span.section_character_count for span in crlf_index.spans
    ]
    assert [(span.start_line, span.end_line) for span in lf_index.spans] == [
        (span.start_line, span.end_line) for span in crlf_index.spans
    ]


def test_rendered_index_has_no_source_text_or_cache_path_and_denies_authority(
    tmp_path: Path,
) -> None:
    index, _, cache_root, _ = _build(tmp_path)
    rendered = span_index.render_ifem_markdown_source_span_index(index)
    payload = json.loads(rendered)

    assert _PRIVATE_HEADING.encode("utf-8") not in rendered
    assert _PRIVATE_BODY.encode("utf-8") not in rendered
    assert b"Repeated structural heading" not in rendered
    assert str(cache_root).encode("utf-8") not in rendered
    assert payload["model_egress_policy"] == "local_only"
    assert payload["semantic_review_state"] == "not_performed"
    assert payload["contract_freeze"] == "not_authorized"
    assert payload["prover_handoff"] == "not_authorized"
    assert set(payload) == {
        "artifact_kind",
        "contract_freeze",
        "contains_model_input",
        "contains_source_text",
        "markdown_heading_count",
        "model_egress_policy",
        "prover_handoff",
        "schema_version",
        "semantic_review_state",
        "source_lock",
        "spans",
    }
    assert set(payload["source_lock"]) == {
        "markdown_file_count",
        "source_file_count",
        "source_lock_schema_version",
        "source_lock_sha256",
        "source_retrieved_at",
        "source_revision",
    }
    assert set(payload["spans"][0]) == {
        "end_line",
        "heading_character_count",
        "heading_content_sha256",
        "heading_index",
        "heading_level",
        "section_character_count",
        "section_content_sha256",
        "source_file_index",
        "source_file_sha256",
        "source_path",
        "source_reference_id",
        "span_id",
        "start_line",
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("model_egress_policy", "approved_external"),
        ("contract_freeze", "authorized"),
        ("prover_handoff", "authorized"),
    ],
)
def test_rejects_any_source_lock_egress_or_authority_widening(
    tmp_path: Path, field: str, value: str
) -> None:
    _, source_lock_path, cache_root, _ = _build(tmp_path)
    payload = json.loads(source_lock_path.read_text(encoding="utf-8"))
    payload["policy"][field] = value
    source_lock_path.write_bytes(canonical_json_bytes(payload))

    with pytest.raises(span_index.IFEMMarkdownSourceSpanIndexError, match="authority boundary"):
        span_index.build_ifem_markdown_source_span_index(
            source_lock_path=source_lock_path,
            source_cache_root=cache_root,
        )


def test_rejects_cached_markdown_hash_drift_before_parsing(tmp_path: Path) -> None:
    _, source_lock_path, cache_root, raw_intro = _build(tmp_path)
    source_lock = json.loads(source_lock_path.read_text(encoding="utf-8"))
    intro = next(item for item in source_lock["source_files"] if item["path"] == _INTRO_PATH)
    cached = cache_root / intro["reference_id"] / f"{intro['sha256']}.md"
    cached.write_bytes(b"# Tampered\n")

    with pytest.raises(
        span_index.IFEMMarkdownSourceSpanIndexError, match="does not match source lock"
    ):
        span_index.build_ifem_markdown_source_span_index(
            source_lock_path=source_lock_path,
            source_cache_root=cache_root,
        )
    assert raw_intro != b"# Tampered\n"


def test_rejects_source_path_escape(tmp_path: Path) -> None:
    _, source_lock_path, cache_root, _ = _build(tmp_path)
    payload = json.loads(source_lock_path.read_text(encoding="utf-8"))
    intro = next(item for item in payload["source_files"] if item["path"] == _INTRO_PATH)
    intro["path"] = "../intro.md"
    source_lock_path.write_bytes(canonical_json_bytes(payload))

    with pytest.raises(span_index.IFEMMarkdownSourceSpanIndexError, match="source path is unsafe"):
        span_index.build_ifem_markdown_source_span_index(
            source_lock_path=source_lock_path,
            source_cache_root=cache_root,
        )


def test_exact_replay_is_idempotent_and_confined_to_local_cache(tmp_path: Path) -> None:
    index, source_lock_path, cache_root, _ = _build(tmp_path)
    replayed = span_index.build_ifem_markdown_source_span_index(
        source_lock_path=source_lock_path,
        source_cache_root=cache_root,
    )
    assert span_index.render_ifem_markdown_source_span_index(replayed) == (
        span_index.render_ifem_markdown_source_span_index(index)
    )
    assert replayed.canonical_sha256() == index.canonical_sha256()

    output = cache_root / "source-lock" / "opening-markdown-source-span-index.v1.json"
    span_index.write_ifem_markdown_source_span_index(
        cache_root=cache_root,
        output_path=output,
        index=index,
    )
    first = output.read_bytes()
    span_index.write_ifem_markdown_source_span_index(
        cache_root=cache_root,
        output_path=output,
        index=replayed,
    )
    assert output.read_bytes() == first
    with pytest.raises(span_index.IFEMMarkdownSourceSpanIndexError, match="stay below"):
        span_index.write_ifem_markdown_source_span_index(
            cache_root=cache_root,
            output_path=tmp_path / "tracked-index.json",
            index=index,
        )
