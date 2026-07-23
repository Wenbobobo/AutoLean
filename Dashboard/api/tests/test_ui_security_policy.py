from __future__ import annotations

from pathlib import Path


def test_ui_uses_text_and_canvas_rendering_for_untrusted_projection_content() -> None:
    dashboard_root = Path(__file__).resolve().parents[2]
    source_files = tuple((dashboard_root / "ui" / "src").glob("*.tsx"))
    source = "\n".join(path.read_text(encoding="utf-8") for path in source_files)
    graph = (dashboard_root / "ui" / "src" / "GraphView.tsx").read_text(encoding="utf-8")

    assert "dangerouslySetInnerHTML" not in source
    assert 'renderMode: "richText"' in graph
    assert "graphText(" in graph


def test_ui_fetch_policy_omits_credentials_and_rejects_redirects() -> None:
    dashboard_root = Path(__file__).resolve().parents[2]
    api = (dashboard_root / "ui" / "src" / "api.ts").read_text(encoding="utf-8")

    assert 'credentials: "omit"' in api
    assert 'redirect: "error"' in api
    assert 'referrerPolicy: "no-referrer"' in api
    assert '"127.0.0.1", "localhost"' in api


def test_ui_has_explicit_small_screen_and_overflow_guards() -> None:
    dashboard_root = Path(__file__).resolve().parents[2]
    styles = (dashboard_root / "ui" / "src" / "styles.css").read_text(encoding="utf-8")

    assert "overflow-x: auto" in styles
    assert "overflow-wrap: anywhere" in styles
    assert "@media (max-width: 560px)" in styles
