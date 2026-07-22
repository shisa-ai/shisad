"""Theme foundation coverage for terminal and web UI bridges."""

from __future__ import annotations

from pathlib import Path

import pytest

from shisad.ui import theme as theme_module
from shisad.ui.theme import (
    BASE16_SLOTS,
    SEMANTIC_ALIASES,
    ThemeValidationError,
    get_builtin_theme,
    load_theme,
    parse_btop_theme,
    rich_style_map,
    textual_theme_css,
    web_css_variables,
)
from shisad.ui.web import render_web_snapshot


def test_u1_builtin_themes_have_complete_base16_and_semantic_slots() -> None:
    for name in ("shisa-dark", "shisa-light", "shisa-high-contrast"):
        palette = get_builtin_theme(name)

        assert palette.name == name
        assert set(BASE16_SLOTS) == set(palette.base16)
        assert set(SEMANTIC_ALIASES) == set(palette.semantic)
        assert all(value.startswith("#") for value in palette.base16.values())
        assert all(value.startswith("#") for value in palette.semantic.values())


def test_u1_unknown_or_invalid_theme_load_falls_back_safely(tmp_path: Path) -> None:
    invalid_theme = tmp_path / "broken.theme"
    invalid_theme.write_text('theme[main_fg]="not-a-color"\n', encoding="utf-8")
    empty_theme = tmp_path / "empty.theme"
    empty_theme.write_text("# no btop color entries\n", encoding="utf-8")
    undecodable_theme = tmp_path / "undecodable.theme"
    undecodable_theme.write_bytes(b"\xff\xfe\xfa")
    missing_theme = tmp_path / "missing.theme"

    assert load_theme("missing-theme").name == "shisa-dark"
    assert load_theme(path=invalid_theme).name == "shisa-dark"
    assert load_theme(name="shisa-light", path=invalid_theme).name == "shisa-light"
    assert load_theme(name="shisa-light", path=empty_theme).name == "shisa-light"
    assert load_theme(name="shisa-light", path=undecodable_theme).name == "shisa-light"
    assert load_theme(name="shisa-light", path=missing_theme).name == "shisa-light"


def test_u1_btop_theme_import_maps_machine_keys_to_palette() -> None:
    palette = parse_btop_theme(
        """
        # btop-compatible theme file
        theme[main_bg]="#101418"
        theme[main_fg]="#e9eef2"
        theme[inactive_fg]="#71808a"
        theme[meter_bg]="#202a31"
        theme[div_line]="#3a4650"
        theme[title]="#8bd5ff"
        theme[hi_fg]="#c6a0ff"
        theme[selected_bg]="#123456"
        theme[temp_start]="#34d399"
        theme[temp_mid]="#facc15"
        theme[temp_end]="#fb7185"
        """,
        name="btop-test",
    )

    assert palette.name == "btop-test"
    assert palette.base16["base00"] == "#101418"
    assert palette.base16["base05"] == "#e9eef2"
    assert palette.semantic["muted"] == "#71808a"
    assert palette.semantic["panel"] == "#202a31"
    assert palette.semantic["border"] == "#3a4650"
    assert palette.semantic["accent"] == "#8bd5ff"
    assert palette.semantic["danger"] == "#fb7185"


def test_u1_btop_theme_import_rejects_invalid_machine_values() -> None:
    with pytest.raises(ThemeValidationError):
        parse_btop_theme('theme[main_bg]="blue-ish"\n', name="bad")


def test_u1_btop_theme_import_accepts_standard_btop_value_forms() -> None:
    palette = parse_btop_theme(
        """
        theme[main_bg]="#00"
        theme[main_fg]="255 255 255"
        theme[inactive_fg]="#30"
        theme[meter_bg]="#202a31"
        theme[div_line]="#3a4650"
        theme[title]="#A6E22E" # inline comment
        theme[hi_fg]="#ff"
        theme[temp_start]="#50"
        theme[temp_mid]=""
        theme[temp_end]="#F92672"
        """,
        name="btop-standard",
    )

    assert palette.base16["base00"] == "#000000"
    assert palette.base16["base05"] == "#ffffff"
    assert palette.semantic["muted"] == "#303030"
    assert palette.semantic["accent"] == "#a6e22e"
    assert palette.semantic["focus"] == "#ffffff"
    assert palette.semantic["danger"] == "#f92672"


def test_u1_theme_bridge_outputs_and_no_color_suppression() -> None:
    palette = get_builtin_theme("shisa-dark")

    rich_styles = rich_style_map(palette)
    assert rich_styles["shisa.accent"] == f"bold {palette.semantic['accent']}"
    assert rich_styles["shisa.warning"] == palette.semantic["warning"]
    no_color_styles = rich_style_map(palette, color=False)
    assert set(no_color_styles) == set(rich_styles)
    assert not any(no_color_styles.values())

    textual_css = textual_theme_css(palette)
    assert "Screen" in textual_css
    assert palette.semantic["background"] in textual_css
    assert textual_theme_css(palette, color=False) == ""

    web_css = web_css_variables(palette)
    assert f"--bg: {palette.semantic['background']};" in web_css
    assert f"--accent: {palette.semantic['accent']};" in web_css


def test_u1_web_snapshot_uses_theme_css_variables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    palette = get_builtin_theme("shisa-high-contrast")
    monkeypatch.delenv("NO_COLOR", raising=False)

    rendered = render_web_snapshot(
        {
            "sessions": [],
            "pending_actions": [],
            "alerts": [],
            "egress_events": [],
        },
        theme=palette,
    )

    assert f"--bg: {palette.semantic['background']};" in rendered
    assert f"--panel: {palette.semantic['panel']};" in rendered

    monkeypatch.setenv("NO_COLOR", "")
    no_color_rendered = render_web_snapshot(
        {
            "sessions": [],
            "pending_actions": [],
            "alerts": [],
            "egress_events": [],
        },
        theme=palette,
    )
    assert "--bg: Canvas;" in no_color_rendered
    assert "--shadow: none;" in no_color_rendered
    assert palette.semantic["background"] not in no_color_rendered


def test_f6_ui_posture_resolves_theme_no_color_and_reduce_motion_precedence() -> None:
    posture = theme_module.resolve_ui_posture(
        theme_name="shisa-high-contrast",
        reduce_motion=True,
        no_color=True,
        environ={
            "TERM": "xterm-256color",
            "COLORTERM": "truecolor",
            "LANG": "C.UTF-8",
        },
        isatty=True,
    )

    assert posture.palette.name == "shisa-high-contrast"
    assert posture.color_enabled is False
    assert posture.capabilities.no_color is True
    assert posture.capabilities.reduce_motion is True
    assert posture.capabilities.animation_enabled is False


def test_f6_environment_no_color_overrides_selected_light_palette() -> None:
    posture = theme_module.resolve_ui_posture(
        theme_name="shisa-light",
        environ={"NO_COLOR": "", "TERM": "xterm-256color", "LANG": "C.UTF-8"},
        isatty=True,
    )

    assert posture.palette.name == "shisa-light"
    assert posture.color_enabled is False
