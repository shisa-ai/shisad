"""Bounded motion and terminal fallback helpers for UI surfaces."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

ColorMode = Literal["truecolor", "256", "16", "none"]

_TRUTHY = {"1", "true", "yes", "on"}
_FALSY = {"0", "false", "no", "off"}

_SPINNERS: dict[str, tuple[str, ...]] = {
    "braille": ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"),
    "dots": ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"),
    "arc": ("◜", "◠", "◝", "◞", "◡", "◟"),
    "bounce": ("⠁", "⠂", "⠄", "⡀", "⢀", "⠠", "⠐", "⠈"),
    "bar": ("▏", "▎", "▍", "▌", "▋", "▊", "▉", "█", "▉", "▊", "▋", "▌", "▍", "▎", "▏"),
    "moon": ("🌑", "🌒", "🌓", "🌔", "🌕", "🌖", "🌗", "🌘"),
}
_ASCII_SPINNER = ("|", "/", "-", "\\")
_STATIC_SPINNER = "-"

_GLYPHS: dict[str, tuple[str, str]] = {
    "success": ("✓", "OK"),
    "warning": ("⚠", "WARN"),
    "error": ("✕", "ERR"),
    "info": ("•", "*"),
    "separator": ("·", "|"),
}


@dataclass(frozen=True, slots=True)
class TerminalCapabilities:
    """Terminal capabilities used to keep motion and glyphs optional."""

    color_mode: ColorMode = "none"
    unicode: bool = False
    interactive: bool = False
    dumb: bool = True
    reduce_motion: bool = False
    no_color: bool = False

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        isatty: bool | None = None,
    ) -> TerminalCapabilities:
        """Derive bounded terminal capabilities from environment variables."""
        source = os.environ if env is None else env
        term = _env_value(source, "TERM").lower()
        colorterm = _env_value(source, "COLORTERM").lower()
        no_color = "NO_COLOR" in source
        stream_is_tty = sys.stdout.isatty() if isatty is None else bool(isatty)
        dumb = not stream_is_tty or term in {"", "dumb"}
        interactive = stream_is_tty and not dumb
        reduce_motion = _env_flag(source, "SHISAD_REDUCE_MOTION")
        unicode_supported = _unicode_supported(source) and not dumb

        if no_color or dumb:
            color_mode: ColorMode = "none"
        elif colorterm in {"truecolor", "24bit"}:
            color_mode = "truecolor"
        elif "256color" in term:
            color_mode = "256"
        else:
            color_mode = "16"
        return cls(
            color_mode=color_mode,
            unicode=unicode_supported,
            interactive=interactive,
            dumb=dumb,
            reduce_motion=reduce_motion,
            no_color=no_color,
        )

    @property
    def animation_enabled(self) -> bool:
        return self.interactive and not self.dumb and not self.reduce_motion


def spinner_frames(
    style: str = "braille",
    *,
    capabilities: TerminalCapabilities | None = None,
) -> tuple[str, ...]:
    """Return deterministic spinner frames with static/ascii fallbacks."""
    caps = capabilities or TerminalCapabilities.from_env()
    if not caps.animation_enabled:
        return (_STATIC_SPINNER,)
    if not caps.unicode:
        return _ASCII_SPINNER
    return _SPINNERS.get(style.strip().lower(), _SPINNERS["braille"])


def spinner_frame(
    tick: int,
    *,
    style: str = "braille",
    capabilities: TerminalCapabilities | None = None,
) -> str:
    frames = spinner_frames(style, capabilities=capabilities)
    return frames[tick % len(frames)]


def progress_bar(
    value: int | float,
    total: int | float,
    *,
    width: int = 20,
    capabilities: TerminalCapabilities | None = None,
) -> str:
    """Render a bounded progress bar with Unicode and ASCII fallbacks."""
    caps = capabilities or TerminalCapabilities.from_env()
    safe_width = max(1, int(width))
    ratio = _progress_ratio(value, total)
    percent = round(ratio * 100)
    if caps.unicode and not caps.dumb:
        full_cells = int(ratio * safe_width)
        remainder = (ratio * safe_width) - full_cells
        half = remainder >= 0.5 and full_cells < safe_width
        empty_cells = safe_width - full_cells - (1 if half else 0)
        return f"[{'█' * full_cells}{'▌' if half else ''}{' ' * empty_cells}] {percent}%"
    filled = int(ratio * safe_width)
    return f"[{'#' * filled}{'-' * (safe_width - filled)}] {percent}%"


def glyph(name: str, capabilities: TerminalCapabilities | None = None) -> str:
    caps = capabilities or TerminalCapabilities.from_env()
    unicode_value, ascii_value = _GLYPHS.get(name.strip().lower(), ("•", "*"))
    return unicode_value if caps.unicode else ascii_value


def format_key_hints(
    hints: Sequence[tuple[str, str]],
    capabilities: TerminalCapabilities | None = None,
) -> str:
    """Format footer/key hints without requiring Unicode separators."""
    caps = capabilities or TerminalCapabilities.from_env()
    separator = f" {glyph('separator', caps)} "
    return separator.join(f"{_format_key(key)} {label.strip()}" for key, label in hints)


def debounce_interval_ms(
    capabilities: TerminalCapabilities | None = None,
    *,
    default_ms: int = 100,
) -> int:
    caps = capabilities or TerminalCapabilities.from_env()
    if not caps.animation_enabled:
        return 0
    return max(0, int(default_ms))


def _env_value(env: Mapping[str, str], key: str) -> str:
    return str(env.get(key, "")).strip()


def _env_flag(env: Mapping[str, str], key: str) -> bool:
    value = _env_value(env, key).lower()
    if value in _TRUTHY:
        return True
    if value in _FALSY:
        return False
    return False


def _unicode_supported(env: Mapping[str, str]) -> bool:
    locale = next(
        (
            value.lower()
            for value in (_env_value(env, key) for key in ("LC_ALL", "LC_CTYPE", "LANG"))
            if value
        ),
        "",
    )
    return "utf-8" in locale or "utf8" in locale


def _progress_ratio(value: int | float, total: int | float) -> float:
    try:
        numeric_value = float(value)
        numeric_total = float(total)
    except (TypeError, ValueError):
        return 0.0
    if numeric_total <= 0:
        return 0.0
    return min(1.0, max(0.0, numeric_value / numeric_total))


def _format_key(value: str) -> str:
    parts = value.strip().replace("-", "+").split("+")
    return "+".join(part.capitalize() if len(part) > 1 else part.upper() for part in parts)
