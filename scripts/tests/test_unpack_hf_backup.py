from __future__ import annotations

import json
from pathlib import Path

from scripts.unpack_hf_backup import _write_report


def test_quarantine_report_is_strict_json_with_one_terminal_newline(tmp_path: Path) -> None:
    _write_report(
        tmp_path,
        "aggregate.json",
        {
            "status": "complete",
            "verified_encrypted_archive_count": 4,
            "session_archive_was_not_decrypted": True,
        },
    )

    rendered = (tmp_path / "reports" / "aggregate.json").read_text(encoding="utf-8")
    parsed = json.loads(rendered)

    assert rendered.endswith("\n")
    assert not rendered.endswith("\\n")
    assert parsed["schema_version"] == "autolean.quarantine-unpack.v1"
    assert parsed["session_archive_was_not_decrypted"] is True
    assert "passphrase" not in rendered.casefold()
