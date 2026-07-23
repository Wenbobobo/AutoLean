from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest
from autolean_control_plane.artifacts import ArtifactStore
from autolean_control_plane.errors import ArtifactCorruption


def test_artifact_store_detects_content_corruption(tmp_path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    reference = store.put_bytes(b"trusted artifact")
    path = store.path_for(reference)
    path.write_bytes(b"tampered artifact")

    with pytest.raises(ArtifactCorruption, match="failed integrity verification"):
        store.get_bytes(reference)


def test_artifact_store_rejects_a_symlinked_blob(tmp_path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    reference = store.put_bytes(b"trusted artifact")
    path = store.path_for(reference)
    outside = tmp_path / "outside.txt"
    outside.write_text("untrusted", encoding="utf-8")
    path.unlink()
    try:
        path.symlink_to(outside)
    except OSError:
        pytest.skip("symbolic links are unavailable on this Windows configuration")

    with pytest.raises(ArtifactCorruption, match="symbolic links"):
        store.get_bytes(reference)


def test_concurrent_identical_puts_never_replace_the_canonical_blob(tmp_path) -> None:
    stores = (ArtifactStore(tmp_path / "artifacts"), ArtifactStore(tmp_path / "artifacts"))
    payload = b"one immutable artifact" * 4096
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = tuple(executor.submit(store.put_bytes, payload) for store in stores)
    references = tuple(future.result() for future in futures)

    assert references[0] == references[1]
    assert stores[0].get_bytes(references[0]) == payload
