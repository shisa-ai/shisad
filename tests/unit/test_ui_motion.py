"""U5 motion and terminal-fallback helper coverage."""

from __future__ import annotations

from shisad.ui.motion import (
    TerminalCapabilities,
    debounce_interval_ms,
    format_key_hints,
    glyph,
    progress_bar,
    spinner_frame,
    spinner_frames,
)


def test_u5_terminal_capabilities_detect_truecolor_unicode_and_animation() -> None:
    caps = TerminalCapabilities.from_env(
        {
            "COLORTERM": "truecolor",
            "TERM": "xterm-256color",
            "LANG": "en_US.UTF-8",
        },
        isatty=True,
    )

    assert caps.color_mode == "truecolor"
    assert caps.unicode is True
    assert caps.interactive is True
    assert caps.animation_enabled is True


def test_u5_terminal_capabilities_collapse_dumb_or_no_color_output() -> None:
    caps = TerminalCapabilities.from_env(
        {
            "NO_COLOR": "1",
            "TERM": "dumb",
            "LANG": "C",
        },
        isatty=True,
    )

    assert caps.color_mode == "none"
    assert caps.unicode is False
    assert caps.interactive is False
    assert caps.animation_enabled is False
    assert spinner_frame(3, capabilities=caps) == "-"
    assert progress_bar(5, 10, width=5, capabilities=caps) == "[##---] 50%"


def test_u5_terminal_capabilities_respect_locale_precedence_for_unicode() -> None:
    caps = TerminalCapabilities.from_env(
        {
            "TERM": "xterm-256color",
            "LC_ALL": "C",
            "LC_CTYPE": "en_US.UTF-8",
            "LANG": "en_US.UTF-8",
        },
        isatty=True,
    )

    assert caps.unicode is False
    assert glyph("success", caps) == "OK"


def test_u5_reduce_motion_uses_static_spinner_but_keeps_capabilities() -> None:
    caps = TerminalCapabilities.from_env(
        {
            "COLORTERM": "24bit",
            "TERM": "xterm-256color",
            "LANG": "C.UTF-8",
            "SHISAD_REDUCE_MOTION": "true",
        },
        isatty=True,
    )

    assert caps.color_mode == "truecolor"
    assert caps.unicode is True
    assert caps.reduce_motion is True
    assert caps.animation_enabled is False
    assert spinner_frame(4, style="braille", capabilities=caps) == "-"


def test_u5_spinner_and_progress_render_unicode_when_supported() -> None:
    caps = TerminalCapabilities.from_env(
        {
            "TERM": "xterm-256color",
            "LANG": "en_US.UTF-8",
        },
        isatty=True,
    )

    assert spinner_frames("arc", capabilities=caps) == ("◜", "◠", "◝", "◞", "◡", "◟")
    assert spinner_frame(7, style="bar", capabilities=caps) == "█"
    assert progress_bar(5, 10, width=5, capabilities=caps) == "[██▌  ] 50%"


def test_u5_glyph_and_key_hint_fallbacks_are_ascii_safe() -> None:
    unicode_caps = TerminalCapabilities.from_env(
        {"TERM": "xterm-256color", "LANG": "C.UTF-8"},
        isatty=True,
    )
    ascii_caps = TerminalCapabilities.from_env({"TERM": "vt100", "LANG": "C"}, isatty=True)

    assert glyph("success", unicode_caps) == "✓"
    assert glyph("success", ascii_caps) == "OK"
    assert format_key_hints([("ctrl+c", "Quit"), ("ctrl+n", "New")], unicode_caps) == (
        "Ctrl+C Quit · Ctrl+N New"
    )
    assert format_key_hints([("ctrl+c", "Quit"), ("ctrl+n", "New")], ascii_caps) == (
        "Ctrl+C Quit | Ctrl+N New"
    )


def test_u5_debounce_interval_respects_reduce_motion_and_noninteractive_output() -> None:
    animated = TerminalCapabilities.from_env(
        {"TERM": "xterm-256color", "LANG": "C.UTF-8"},
        isatty=True,
    )
    reduced = TerminalCapabilities.from_env(
        {
            "TERM": "xterm-256color",
            "LANG": "C.UTF-8",
            "SHISAD_REDUCE_MOTION": "1",
        },
        isatty=True,
    )
    piped = TerminalCapabilities.from_env(
        {"TERM": "xterm-256color", "LANG": "C.UTF-8"},
        isatty=False,
    )

    assert debounce_interval_ms(animated) == 100
    assert debounce_interval_ms(reduced) == 0
    assert debounce_interval_ms(piped) == 0
