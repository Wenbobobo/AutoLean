from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from autolean_builder import (
    DISCOVERY_STATUS,
    ReferenceCache,
    ReferenceManifestV1,
    TextbookAlignmentError,
    TextbookAlignmentPublicSummaryV1,
    build_textbook_alignment_discovery,
    render_textbook_alignment_private_packet,
    render_textbook_alignment_public_summary,
    write_textbook_alignment_discovery,
)
from autolean_builder import textbook_alignment as alignment
from autolean_contracts import canonical_json_bytes
from pydantic import ValidationError

from scripts import textbook_alignment as textbook_alignment_cli

_PARENT_ID = "synthetic-textbook-pdf"
_TEXT_ID = "synthetic-textbook-text"
_PARENT_BYTES = b"%PDF-1.7\nsynthetic parent only\n"
_TEXT_BYTES = (
    b"Opening synthetic source secret alpha.\n"
    b"Definition pending human extraction.\n"
    b"\x0cSecond synthetic source secret beta.\n"
    b"\x0cThird synthetic source secret gamma.\n"
)


def _entry(
    *,
    reference_id: str,
    data: bytes,
    media_type: str,
    extension: str,
    artifact_kind: str,
    derivation: dict[str, object] | None,
) -> dict[str, object]:
    return {
        "reference_id": reference_id,
        "title": "Synthetic test reference",
        "authors": ["AutoLean tests"],
        "version": "synthetic-v1",
        "citation": "Synthetic test reference; not textbook content.",
        "source_record_url": "https://example.invalid/reference",
        "download_url": f"https://example.invalid/{reference_id}{extension}",
        "allowed_redirect_urls": [],
        "media_type": media_type,
        "file_extension": extension,
        "size_bytes": len(data),
        "max_bytes": len(data) + 16,
        "sha256": hashlib.sha256(data).hexdigest(),
        "retrieved_at": "2026-07-27T00:00:00Z",
        "license": {
            "expression": "CC-BY-4.0",
            "url": "https://creativecommons.org/licenses/by/4.0/",
            "evidence_url": "https://example.invalid/reference",
        },
        "access_policy": "public_open_access",
        "acquisition_policy": "operator_only",
        "model_egress_policy": "local_only",
        "artifact_kind": artifact_kind,
        "derivation": derivation,
        "attribution": "Synthetic test reference by AutoLean tests, CC BY 4.0.",
    }


def _install_fixture(
    checkout: Path,
    *,
    text_bytes: bytes = _TEXT_BYTES,
) -> tuple[Path, str, Path]:
    checkout.mkdir(parents=True, exist_ok=True)
    (checkout / ".git").mkdir(exist_ok=True)
    (checkout / ".gitignore").write_text("/.cache/\n", encoding="utf-8")
    manifest_payload = {
        "schema_version": "autolean.reference-manifest.v1",
        "entries": [
            _entry(
                reference_id=_PARENT_ID,
                data=_PARENT_BYTES,
                media_type="application/pdf",
                extension=".pdf",
                artifact_kind="source_document",
                derivation=None,
            ),
            _entry(
                reference_id=_TEXT_ID,
                data=text_bytes,
                media_type="text/plain",
                extension=".txt",
                artifact_kind="derived_text",
                derivation={
                    "kind": "repository_text_extraction",
                    "parent_reference_id": _PARENT_ID,
                    "parent_sha256": hashlib.sha256(_PARENT_BYTES).hexdigest(),
                    "producer": "Synthetic test producer",
                    "method": "repository_provided_text_bitstream",
                    "tool_name": None,
                    "tool_version": None,
                    "provenance_url": "https://example.invalid/reference",
                    "parent_locator_authority": "human_declared",
                },
            ),
        ],
    }
    manifest_path = checkout / "manifest.json"
    manifest_bytes = canonical_json_bytes(manifest_payload) + b"\n"
    manifest_path.write_bytes(manifest_bytes)
    manifest = ReferenceManifestV1.load(manifest_path)
    cache_root = checkout / ".cache" / "references"
    cache = ReferenceCache(manifest, cache_root, confinement_root=checkout)
    for reference_id, data in ((_PARENT_ID, _PARENT_BYTES), (_TEXT_ID, text_bytes)):
        destination = cache.path_for(reference_id)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    return manifest_path, hashlib.sha256(manifest_bytes).hexdigest(), cache_root


def _build(
    checkout: Path,
    *,
    text_bytes: bytes = _TEXT_BYTES,
    pages: tuple[int, ...] = (1,),
    max_excerpt_bytes: int = 8192,
):
    manifest_path, manifest_sha256, cache_root = _install_fixture(
        checkout,
        text_bytes=text_bytes,
    )
    packet, summary = build_textbook_alignment_discovery(
        manifest_path=manifest_path,
        expected_manifest_sha256=manifest_sha256,
        cache_root=cache_root,
        reference_id=_TEXT_ID,
        page_numbers=pages,
        max_excerpt_bytes=max_excerpt_bytes,
        confinement_root=checkout,
    )
    return packet, summary, manifest_path, cache_root


def test_builds_pending_private_worksheet_and_text_free_public_summary(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    packet, summary, _, _ = _build(checkout, pages=(1, 2), max_excerpt_bytes=64)

    assert packet.status == DISCOVERY_STATUS
    assert packet.external_model_egress_allowed is False
    assert packet.contract_freeze_allowed is False
    assert packet.prover_handoff_allowed is False
    assert packet.semantic_review_claimed is False
    assert packet.form_feed_delimiter_count == 2
    assert len(packet.candidates) == 2
    for candidate in packet.candidates:
        assert candidate.extraction_status == "source_bound_pending_manual_extraction"
        assert candidate.normalized_candidate is None
        assert candidate.lean_like_draft is None
        assert candidate.ambiguities == ()
        assert candidate.positive_examples == ()
        assert candidate.negative_examples == ()
        assert candidate.mathlib_mapping_status == "pending"
        assert candidate.human_review == "pending"
        assert all(item.human_review == "pending" for item in candidate.quantifier_mutations)
        assert all(item.human_review == "pending" for item in candidate.boundary_mutations)

    private_path = checkout / ".cache" / "alignment" / "packet.private.json"
    public_path = checkout / ".cache" / "alignment" / "summary.public.json"
    private_path.parent.mkdir(parents=True, exist_ok=True)
    write_textbook_alignment_discovery(
        checkout_root=checkout,
        packet_path=private_path,
        summary_path=public_path,
        packet=packet,
        summary=summary,
    )
    assert private_path.read_bytes() == render_textbook_alignment_private_packet(packet)
    public_bytes = public_path.read_bytes()
    assert public_bytes == render_textbook_alignment_public_summary(summary)
    assert b"Opening synthetic source secret" not in public_bytes
    assert b"Second synthetic source secret" not in public_bytes
    assert str(checkout).encode() not in public_bytes
    assert b"packet.private.json" not in public_bytes
    assert b"summary.public.json" not in public_bytes
    assert set(json.loads(public_bytes)) == {
        "status",
        "reference_id",
        "parent_sha256",
        "page_locators",
        "candidate_count",
        "candidate_hashes",
    }
    assert summary.candidate_count == 2
    assert all(len(value) == 64 for value in summary.candidate_hashes)


def test_cli_stdout_is_only_the_redacted_summary(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    checkout = tmp_path / "checkout"
    manifest_path, manifest_sha256, cache_root = _install_fixture(checkout)
    private_path = checkout / ".cache" / "alignment" / "packet.private.json"
    public_path = checkout / ".cache" / "alignment" / "summary.public.json"
    private_path.parent.mkdir(parents=True, exist_ok=True)

    result = textbook_alignment_cli.main(
        (
            "--manifest",
            str(manifest_path),
            "--expected-manifest-sha256",
            manifest_sha256,
            "--cache-root",
            str(cache_root),
            "--reference-id",
            _TEXT_ID,
            "--pages",
            "1,2",
            "--max-excerpt-bytes",
            "64",
            "--checkout-root",
            str(checkout),
            "--private-packet",
            str(private_path),
            "--public-summary",
            str(public_path),
        )
    )
    captured = capsys.readouterr()

    assert result == 0
    assert captured.err == ""
    assert "synthetic source secret" not in captured.out
    assert json.loads(captured.out) == json.loads(public_path.read_text(encoding="utf-8"))
    assert set(json.loads(captured.out)) == {
        "status",
        "reference_id",
        "parent_sha256",
        "page_locators",
        "candidate_count",
        "candidate_hashes",
    }


def test_parent_hash_change_is_rejected(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    manifest_path, manifest_sha256, cache_root = _install_fixture(checkout)
    manifest = ReferenceManifestV1.load(manifest_path)
    parent_path = ReferenceCache(
        manifest,
        cache_root,
        confinement_root=checkout,
    ).path_for(_PARENT_ID)
    parent_path.write_bytes(b"X" * len(_PARENT_BYTES))

    with pytest.raises(TextbookAlignmentError, match=r"size mismatch|hash mismatch"):
        build_textbook_alignment_discovery(
            manifest_path=manifest_path,
            expected_manifest_sha256=manifest_sha256,
            cache_root=cache_root,
            reference_id=_TEXT_ID,
            page_numbers=(1,),
            confinement_root=checkout,
        )


def test_manifest_hash_binding_is_required(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    manifest_path, _, cache_root = _install_fixture(checkout)

    with pytest.raises(TextbookAlignmentError, match="differs from the bound SHA"):
        build_textbook_alignment_discovery(
            manifest_path=manifest_path,
            expected_manifest_sha256="0" * 64,
            cache_root=cache_root,
            reference_id=_TEXT_ID,
            page_numbers=(1,),
            confinement_root=checkout,
        )


def test_page_out_of_range_is_rejected(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    with pytest.raises(TextbookAlignmentError, match="outside the derived text"):
        _build(checkout, pages=(4,))


@pytest.mark.parametrize(
    ("destination_kind", "which_output"),
    [
        ("inside_checkout_outside_cache", "private"),
        ("outside_checkout", "private"),
        ("inside_checkout_outside_cache", "public"),
        ("outside_checkout", "public"),
    ],
)
def test_outputs_must_stay_below_checkout_cache(
    tmp_path: Path,
    destination_kind: str,
    which_output: str,
) -> None:
    checkout = tmp_path / "checkout"
    packet, summary, _, _ = _build(checkout)
    cache_private = checkout / ".cache" / "alignment" / "packet.private.json"
    cache_public = checkout / ".cache" / "alignment" / "summary.public.json"
    invalid = (
        checkout / "tracked-output.json"
        if destination_kind == "inside_checkout_outside_cache"
        else tmp_path / "outside-output.json"
    )
    private_path = invalid if which_output == "private" else cache_private
    public_path = invalid if which_output == "public" else cache_public

    with pytest.raises(TextbookAlignmentError, match=r"below checkout \.cache"):
        write_textbook_alignment_discovery(
            checkout_root=checkout,
            packet_path=private_path,
            summary_path=public_path,
            packet=packet,
            summary=summary,
        )


def test_public_schema_and_redaction_guard_reject_text_leak(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    packet, summary, _, _ = _build(checkout)
    public_payload = summary.model_dump(mode="json")
    public_payload["excerpt"] = packet.candidates[0].source_span.excerpt
    leaking_bytes = canonical_json_bytes(public_payload) + b"\n"

    with pytest.raises(ValidationError):
        TextbookAlignmentPublicSummaryV1.model_validate(public_payload)
    with pytest.raises(TextbookAlignmentError, match="strict redacted schema"):
        alignment._assert_public_summary_redacted(packet, leaking_bytes)


def test_empty_selected_sample_is_rejected(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    with pytest.raises(TextbookAlignmentError, match="no nonempty UTF-8 sample"):
        _build(checkout, text_bytes=b" \t\r\n\x0cNonempty second page.", pages=(1,))


def test_no_form_feed_is_logical_opening_page_and_remains_pending(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    text_bytes = b"Opening text without a form-feed delimiter."
    packet, summary, _, _ = _build(
        checkout,
        text_bytes=text_bytes,
        pages=(1,),
        max_excerpt_bytes=16,
    )

    candidate = packet.candidates[0]
    assert packet.form_feed_delimiter_count == 0
    assert candidate.source_span.locator == "form-feed-page:0001#utf8-bytes:0-16"
    assert candidate.source_span.excerpt == "Opening text wit"
    assert candidate.normalized_candidate is None
    assert summary.candidate_count == 1


def test_utf8_excerpt_offsets_never_split_a_multibyte_character(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    packet, _, _, _ = _build(
        checkout,
        text_bytes=" \né数学 statement".encode(),
        pages=(1,),
        max_excerpt_bytes=4,
    )

    span = packet.candidates[0].source_span
    assert span.excerpt == "é"
    assert span.global_byte_start == 2
    assert span.global_byte_end == 4
    assert span.span_sha256 == hashlib.sha256("é".encode()).hexdigest()


def test_same_hash_alias_cannot_replace_the_manifest_bound_parent(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    manifest_path, _, cache_root = _install_fixture(checkout)
    payload = json.loads(manifest_path.read_bytes())
    parent = next(entry for entry in payload["entries"] if entry["reference_id"] == _PARENT_ID)
    alias = {**parent, "reference_id": "synthetic-textbook-pdf-alias"}
    payload["entries"].append(alias)
    manifest_bytes = canonical_json_bytes(payload) + b"\n"
    manifest_path.write_bytes(manifest_bytes)
    manifest = ReferenceManifestV1.load(manifest_path)
    cache = ReferenceCache(manifest, cache_root, confinement_root=checkout)
    alias_path = cache.path_for("synthetic-textbook-pdf-alias")
    alias_path.parent.mkdir(parents=True, exist_ok=True)
    alias_path.write_bytes(_PARENT_BYTES)
    cache.path_for(_PARENT_ID).unlink()

    with pytest.raises(TextbookAlignmentError, match="absent from the local cache"):
        build_textbook_alignment_discovery(
            manifest_path=manifest_path,
            expected_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
            cache_root=cache_root,
            reference_id=_TEXT_ID,
            page_numbers=(1,),
            confinement_root=checkout,
        )


@pytest.mark.parametrize("repository_state", ("not_repository", "cache_not_ignored"))
def test_private_output_requires_a_repository_with_root_ignored_cache(
    tmp_path: Path,
    repository_state: str,
) -> None:
    source_checkout = tmp_path / "source-checkout"
    packet, summary, _, _ = _build(source_checkout)
    checkout = tmp_path / repository_state
    output_root = checkout / ".cache" / "alignment"
    output_root.mkdir(parents=True)
    (checkout / ".gitignore").write_text(
        "/.cache/\n" if repository_state == "not_repository" else "/other/\n",
        encoding="utf-8",
    )
    if repository_state == "cache_not_ignored":
        (checkout / ".git").mkdir()

    expected = (
        "not a Git repository root"
        if repository_state == "not_repository"
        else "must explicitly exclude /.cache/"
    )
    with pytest.raises(TextbookAlignmentError, match=expected):
        write_textbook_alignment_discovery(
            checkout_root=checkout,
            packet_path=output_root / "packet.private.json",
            summary_path=output_root / "summary.public.json",
            packet=packet,
            summary=summary,
        )


def test_cache_symlink_or_reparse_point_is_rejected_when_supported(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    packet, summary, _, _ = _build(checkout)
    original_cache = checkout / ".cache"
    retained_cache = checkout / ".cache-retained"
    original_cache.rename(retained_cache)
    external = tmp_path / "external"
    external.mkdir()
    try:
        original_cache.symlink_to(external, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable on this host")

    with pytest.raises(
        TextbookAlignmentError,
        match=r"not a confined existing directory|real directories",
    ):
        write_textbook_alignment_discovery(
            checkout_root=checkout,
            packet_path=original_cache / "alignment" / "packet.private.json",
            summary_path=original_cache / "alignment" / "summary.public.json",
            packet=packet,
            summary=summary,
        )
    assert tuple(external.iterdir()) == ()


def test_parent_identity_drift_stops_before_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = tmp_path / "checkout"
    packet, _, _, _ = _build(checkout)
    destination = checkout / ".cache" / "alignment" / "packet.private.json"
    destination.parent.mkdir(parents=True)
    repository = alignment._resolve_repository(checkout)
    repository_identity = alignment._directory_identity(
        repository,
        repository,
        "checkout root",
    )
    cache_identity = alignment._directory_identity(
        repository / ".cache",
        repository,
        "checkout cache",
    )
    parent_identity = alignment._directory_identity(
        destination.parent,
        repository,
        "private packet parent",
    )
    real_identity = alignment._directory_identity
    parent_observations = 0

    def drifting_identity(path: Path, root: Path, label: str):
        nonlocal parent_observations
        observed = real_identity(path, root, label)
        if path == destination.parent:
            parent_observations += 1
            if parent_observations >= 2:
                return (observed[0], observed[1] + 1, observed[2], observed[3])
        return observed

    monkeypatch.setattr(alignment, "_directory_identity", drifting_identity)
    with pytest.raises(TextbookAlignmentError, match="identity changed during write"):
        alignment._atomic_install(
            destination,
            render_textbook_alignment_private_packet(packet),
            repository=repository,
            repository_identity=repository_identity,
            cache_identity=cache_identity,
            parent_identity=parent_identity,
        )
    assert not destination.exists()


def test_output_install_is_idempotent_but_refuses_different_content(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    packet, summary, _, _ = _build(checkout)
    output_root = checkout / ".cache" / "alignment"
    output_root.mkdir(parents=True)
    private_path = output_root / "packet.private.json"
    public_path = output_root / "summary.public.json"

    for _ in range(2):
        write_textbook_alignment_discovery(
            checkout_root=checkout,
            packet_path=private_path,
            summary_path=public_path,
            packet=packet,
            summary=summary,
        )
    expected_public = public_path.read_bytes()
    private_path.write_bytes(b"existing conflicting private output\n")

    with pytest.raises(TextbookAlignmentError, match="conflicts with existing file"):
        write_textbook_alignment_discovery(
            checkout_root=checkout,
            packet_path=private_path,
            summary_path=public_path,
            packet=packet,
            summary=summary,
        )
    assert private_path.read_bytes() == b"existing conflicting private output\n"
    assert public_path.read_bytes() == expected_public

    private_path.unlink()
    public_path.write_bytes(b"existing conflicting public output\n")
    with pytest.raises(TextbookAlignmentError, match="conflicts with existing file"):
        write_textbook_alignment_discovery(
            checkout_root=checkout,
            packet_path=private_path,
            summary_path=public_path,
            packet=packet,
            summary=summary,
        )
    assert not private_path.exists()
    assert public_path.read_bytes() == b"existing conflicting public output\n"
