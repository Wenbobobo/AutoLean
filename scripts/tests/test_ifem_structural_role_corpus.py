"""Focused checks for the tracked iFEM structural corpus operator tool."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from autolean_builder.ifem_structural_role_probes import IFEMStructuralRoleProbeError

from scripts import ifem_structural_role_corpus as corpus_tool


def test_inspect_verifies_the_independently_pinned_tracked_revision(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = corpus_tool.main(["inspect"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "contains_source_text": False,
        "content_sha256": corpus_tool.TRACKED_CONTENT_SHA256,
        "file_sha256": corpus_tool.TRACKED_FILE_SHA256,
        "graph_content_sha256": corpus_tool.TRACKED_GRAPH_CONTENT_SHA256,
        "graph_file_sha256": corpus_tool.TRACKED_GRAPH_FILE_SHA256,
        "path": corpus_tool.DEFAULT_OUTPUT.name,
    }


@pytest.mark.parametrize(
    ("argument", "message"),
    (
        ("--expected-file-sha256", "file hash drifted"),
        ("--expected-content-sha256", "content hash drifted"),
    ),
)
def test_inspect_rejects_wrong_independent_hash(
    argument: str,
    message: str,
) -> None:
    with pytest.raises(IFEMStructuralRoleProbeError, match=message):
        corpus_tool.main(["inspect", argument, "0" * 64])


def test_write_once_atomically_installs_revalidates_and_reuses_exact_bytes(
    tmp_path: Path,
) -> None:
    content = corpus_tool.DEFAULT_OUTPUT.read_bytes()
    target = tmp_path / corpus_tool.DEFAULT_OUTPUT.name

    first = corpus_tool._write_once(
        target,
        content,
        expected_content_sha256=corpus_tool.TRACKED_CONTENT_SHA256,
    )
    second = corpus_tool._write_once(
        target,
        content,
        expected_content_sha256=corpus_tool.TRACKED_CONTENT_SHA256,
    )

    assert first == second
    assert target.read_bytes() == content
    assert tuple(tmp_path.iterdir()) == (target,)

    with pytest.raises(IFEMStructuralRoleProbeError, match="file hash drifted"):
        corpus_tool._write_once(
            target,
            content + b" ",
            expected_content_sha256=corpus_tool.TRACKED_CONTENT_SHA256,
        )
    assert target.read_bytes() == content
    assert tuple(tmp_path.iterdir()) == (target,)


def test_write_once_leaves_no_final_or_temporary_file_when_atomic_install_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / corpus_tool.DEFAULT_OUTPUT.name

    def fail_link(
        source: str | bytes | Path,
        destination: str | bytes | Path,
        *,
        follow_symlinks: bool = True,
    ) -> None:
        del source, destination, follow_symlinks
        raise OSError("injected atomic-install failure")

    monkeypatch.setattr(os, "link", fail_link)
    with pytest.raises(IFEMStructuralRoleProbeError, match="atomically installed"):
        corpus_tool._write_once(
            target,
            corpus_tool.DEFAULT_OUTPUT.read_bytes(),
            expected_content_sha256=corpus_tool.TRACKED_CONTENT_SHA256,
        )

    assert not target.exists()
    assert tuple(tmp_path.iterdir()) == ()


def test_inspect_rejects_a_final_symlink_when_supported(tmp_path: Path) -> None:
    link = tmp_path / corpus_tool.DEFAULT_OUTPUT.name
    try:
        link.symlink_to(corpus_tool.DEFAULT_OUTPUT)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symbolic links are unavailable on this host: {error}")

    with pytest.raises(IFEMStructuralRoleProbeError, match="unlinked regular file"):
        corpus_tool.main(["inspect", "--path", str(link)])
