from __future__ import annotations

import json
from pathlib import Path

import pytest
from autolean_dashboard.models import DashboardSnapshot
from autolean_dashboard.reader import JsonProjectionReader, ProjectionUnavailable


def test_reader_accepts_a_typed_snapshot(tmp_path: Path) -> None:
    projection = tmp_path / "projection.json"
    expected = DashboardSnapshot()
    projection.write_text(json.dumps(expected.model_dump(mode="json")), encoding="utf-8")

    actual = JsonProjectionReader(projection).snapshot().model_dump(mode="json")
    assert actual == expected.model_dump(mode="json")


def test_reader_rejects_oversized_or_invalid_projection_without_path_leak(tmp_path: Path) -> None:
    projection = tmp_path / "projection.json"
    projection.write_text("0123456789", encoding="utf-8")
    reader = JsonProjectionReader(projection, max_bytes=4)

    with pytest.raises(ProjectionUnavailable) as caught:
        reader.snapshot()
    assert str(projection) not in str(caught.value)

    projection.write_text("not-json", encoding="utf-8")
    with pytest.raises(ProjectionUnavailable) as caught:
        JsonProjectionReader(projection).snapshot()
    assert str(projection) not in str(caught.value)


def test_reader_rejects_a_projection_replaced_with_a_symlink_during_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projection = tmp_path / "projection.json"
    projection.write_text(json.dumps(DashboardSnapshot().model_dump(mode="json")), encoding="utf-8")
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps(DashboardSnapshot().model_dump(mode="json")), encoding="utf-8")
    reader = JsonProjectionReader(projection)
    import autolean_dashboard.reader as reader_module

    original_open = reader_module.os.open

    def replace_with_link(path: str | Path, flags: int) -> int:
        projection.unlink()
        try:
            projection.symlink_to(outside)
        except OSError:
            pytest.skip("symbolic links are unavailable on this Windows configuration")
        return original_open(path, flags)

    monkeypatch.setattr(reader_module.os, "open", replace_with_link)
    with pytest.raises(ProjectionUnavailable):
        reader.snapshot()
