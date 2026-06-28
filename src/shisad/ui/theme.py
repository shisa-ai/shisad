"""Theme palette and rendering bridges for shisad UI surfaces."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

BASE16_SLOTS: tuple[str, ...] = tuple(f"base{index:02X}" for index in range(16))
SEMANTIC_ALIASES: tuple[str, ...] = (
    "background",
    "panel",
    "surface",
    "text",
    "muted",
    "accent",
    "success",
    "warning",
    "danger",
    "info",
    "border",
    "focus",
)

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


class ThemeValidationError(ValueError):
    """Raised when a theme payload is incomplete or malformed."""


@dataclass(frozen=True, slots=True)
class ThemePalette:
    """Validated theme palette with base16 slots and semantic aliases."""

    name: str
    base16: Mapping[str, str]
    semantic: Mapping[str, str]
    source: str = "custom"
    transparent_background: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _normalize_name(self.name))
        object.__setattr__(self, "base16", MappingProxyType(_validate_colors(self.base16)))
        object.__setattr__(
            self,
            "semantic",
            MappingProxyType(_validate_colors(self.semantic, semantic=True)),
        )

    def color(self, key: str) -> str:
        """Return a semantic alias or base16 slot by key."""
        normalized = key.strip()
        if normalized in self.semantic:
            return self.semantic[normalized]
        return self.base16[normalized]


def _normalize_name(value: object) -> str:
    name = str(value).strip()
    if not name:
        raise ThemeValidationError("theme name cannot be empty")
    return name


def _normalize_hex(value: object, *, key: str) -> str:
    color = str(value).strip()
    if len(color) != 7 or not color.startswith("#"):
        raise ThemeValidationError(f"{key} must be a #RRGGBB color")
    if any(character not in _HEX_DIGITS for character in color[1:]):
        raise ThemeValidationError(f"{key} must be a #RRGGBB color")
    return color.lower()


def _normalize_btop_color(value: object, *, key: str) -> str:
    color = str(value).strip()
    if len(color) == 7 and color.startswith("#"):
        return _normalize_hex(color, key=key)
    if len(color) == 3 and color.startswith("#"):
        grayscale = color[1:]
        if any(character not in _HEX_DIGITS for character in grayscale):
            raise ThemeValidationError(f"{key} must be a valid btop color")
        return f"#{grayscale}{grayscale}{grayscale}".lower()
    channels = color.split()
    if len(channels) == 3:
        try:
            values = [int(channel, 10) for channel in channels]
        except ValueError as exc:
            raise ThemeValidationError(f"{key} must be a valid btop color") from exc
        if all(0 <= channel <= 255 for channel in values):
            return "#{:02x}{:02x}{:02x}".format(*values)
    raise ThemeValidationError(f"{key} must be a valid btop color")


def _extract_btop_value(raw_value: str, *, key: str) -> str | None:
    value = raw_value.strip()
    if not value:
        return None
    if value[0] in {"'", '"'}:
        quote = value[0]
        end = value.find(quote, 1)
        if end == -1:
            raise ThemeValidationError(f"{key} has an unterminated quoted value")
        value = value[1:end].strip()
    else:
        tokens = value.split()
        if tokens and tokens[0].startswith("#"):
            value = tokens[0]
        elif len(tokens) >= 3:
            value = " ".join(tokens[:3])
        elif tokens:
            value = tokens[0]
    if not value:
        return None
    return _normalize_btop_color(value, key=key)


def _validate_colors(values: Mapping[str, object], *, semantic: bool = False) -> dict[str, str]:
    required = SEMANTIC_ALIASES if semantic else BASE16_SLOTS
    missing = [key for key in required if key not in values]
    if missing:
        label = "semantic alias" if semantic else "base16 slot"
        raise ThemeValidationError(f"missing {label}: {', '.join(missing)}")
    return {key: _normalize_hex(values[key], key=key) for key in required}


def _semantic_from_base16(base16: Mapping[str, str]) -> dict[str, str]:
    return {
        "background": base16["base00"],
        "panel": base16["base01"],
        "surface": base16["base02"],
        "text": base16["base05"],
        "muted": base16["base03"],
        "accent": base16["base0D"],
        "success": base16["base0B"],
        "warning": base16["base0A"],
        "danger": base16["base08"],
        "info": base16["base0C"],
        "border": base16["base02"],
        "focus": base16["base0E"],
    }


_SHISA_DARK_BASE16 = {
    "base00": "#101418",
    "base01": "#172026",
    "base02": "#26323a",
    "base03": "#75838d",
    "base04": "#9aa8b2",
    "base05": "#e6edf2",
    "base06": "#f4f7fa",
    "base07": "#ffffff",
    "base08": "#ff6b7a",
    "base09": "#ff9f43",
    "base0A": "#ffd166",
    "base0B": "#45d483",
    "base0C": "#4dd0e1",
    "base0D": "#7cc7ff",
    "base0E": "#c792ea",
    "base0F": "#d19a66",
}

_SHISA_LIGHT_BASE16 = {
    "base00": "#f7fafc",
    "base01": "#ffffff",
    "base02": "#d8e2ea",
    "base03": "#60707c",
    "base04": "#455866",
    "base05": "#102333",
    "base06": "#071723",
    "base07": "#000000",
    "base08": "#c2415b",
    "base09": "#b45309",
    "base0A": "#9a6700",
    "base0B": "#0f8f55",
    "base0C": "#087990",
    "base0D": "#0b6fae",
    "base0E": "#7c3aed",
    "base0F": "#8a4b1f",
}

_SHISA_HIGH_CONTRAST_BASE16 = {
    "base00": "#000000",
    "base01": "#111111",
    "base02": "#3a3a3a",
    "base03": "#b0b0b0",
    "base04": "#d0d0d0",
    "base05": "#ffffff",
    "base06": "#ffffff",
    "base07": "#ffffff",
    "base08": "#ff4b4b",
    "base09": "#ff9f1a",
    "base0A": "#ffff00",
    "base0B": "#00ff66",
    "base0C": "#00ffff",
    "base0D": "#4db3ff",
    "base0E": "#ff66ff",
    "base0F": "#ffaa66",
}


def _palette_from_base16(
    name: str,
    base16: Mapping[str, str],
    *,
    source: str,
    semantic_overrides: Mapping[str, str] | None = None,
    transparent_background: bool = False,
) -> ThemePalette:
    normalized_base16 = _validate_colors(base16)
    semantic = _semantic_from_base16(normalized_base16)
    if semantic_overrides:
        semantic.update(semantic_overrides)
    return ThemePalette(
        name=name,
        base16=normalized_base16,
        semantic=semantic,
        source=source,
        transparent_background=transparent_background,
    )


_BUILTIN_THEME_DATA: dict[str, Mapping[str, str]] = {
    "shisa-dark": _SHISA_DARK_BASE16,
    "shisa-light": _SHISA_LIGHT_BASE16,
    "shisa-high-contrast": _SHISA_HIGH_CONTRAST_BASE16,
}


def get_builtin_theme(name: str = "shisa-dark") -> ThemePalette:
    """Return a validated built-in palette."""
    normalized = str(name).strip().lower() or "shisa-dark"
    try:
        base16 = _BUILTIN_THEME_DATA[normalized]
    except KeyError as exc:
        raise ThemeValidationError(f"unknown built-in theme: {name}") from exc
    return _palette_from_base16(normalized, base16, source="builtin")


def load_theme(
    name: str | None = None,
    *,
    path: Path | None = None,
    fallback_name: str = "shisa-dark",
) -> ThemePalette:
    """Load a theme by built-in name or btop file path, falling back safely."""
    fallback_theme = _load_builtin_fallback(name or fallback_name, fallback_name)
    try:
        if path is not None:
            return parse_btop_theme(path.read_text(encoding="utf-8"), name=path.stem)
        return get_builtin_theme(name or fallback_name)
    except (OSError, UnicodeDecodeError, ThemeValidationError):
        return fallback_theme


def _load_builtin_fallback(primary_name: str | None, fallback_name: str) -> ThemePalette:
    for candidate in (primary_name, fallback_name, "shisa-dark"):
        if not candidate:
            continue
        try:
            return get_builtin_theme(candidate)
        except ThemeValidationError:
            continue
    return get_builtin_theme("shisa-dark")


def parse_btop_theme(text: str, *, name: str = "btop") -> ThemePalette:
    """Parse the finite btop `theme[key]=value` format into a shisad palette."""
    raw_values: dict[str, str] = {}
    transparent_background = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or not line.startswith("theme["):
            continue
        key_end = line.find("]")
        if key_end <= len("theme["):
            continue
        key = line[len("theme[") : key_end].strip()
        remainder = line[key_end + 1 :].strip()
        if not key or not remainder.startswith("="):
            continue
        value = _extract_btop_value(remainder[1:], key=key)
        if key == "main_bg" and value is None:
            transparent_background = True
            continue
        if value is None:
            continue
        raw_values[key] = value

    if not raw_values:
        raise ThemeValidationError("theme file did not contain btop color entries")

    base16 = dict(_SHISA_DARK_BASE16)

    def pick(*keys: str, fallback: str) -> str:
        for key in keys:
            if key in raw_values:
                return raw_values[key]
        return fallback

    base16.update(
        {
            "base00": pick("main_bg", fallback=base16["base00"]),
            "base01": pick("meter_bg", "proc_box", fallback=base16["base01"]),
            "base02": pick("div_line", "selected_bg", fallback=base16["base02"]),
            "base03": pick("inactive_fg", fallback=base16["base03"]),
            "base05": pick("main_fg", fallback=base16["base05"]),
            "base08": pick("temp_end", "cpu_end", fallback=base16["base08"]),
            "base0A": pick("temp_mid", "cpu_mid", fallback=base16["base0A"]),
            "base0B": pick("temp_start", "cpu_start", fallback=base16["base0B"]),
            "base0C": pick("proc_misc", "selected_bg", fallback=base16["base0C"]),
            "base0D": pick("title", "hi_fg", fallback=base16["base0D"]),
            "base0E": pick("hi_fg", "selected_fg", fallback=base16["base0E"]),
        }
    )
    semantic_overrides = {
        "background": base16["base00"],
        "panel": pick("meter_bg", "proc_box", fallback=base16["base01"]),
        "surface": pick("selected_bg", fallback=base16["base02"]),
        "text": base16["base05"],
        "muted": base16["base03"],
        "accent": pick("title", "hi_fg", fallback=base16["base0D"]),
        "success": base16["base0B"],
        "warning": base16["base0A"],
        "danger": base16["base08"],
        "info": base16["base0C"],
        "border": pick("div_line", fallback=base16["base02"]),
        "focus": base16["base0E"],
    }
    return _palette_from_base16(
        name,
        base16,
        source="btop",
        semantic_overrides=semantic_overrides,
        transparent_background=transparent_background,
    )


def rich_style_map(palette: ThemePalette, *, color: bool = True) -> dict[str, str]:
    """Return Rich style names for theme-aware renderers."""
    if not color:
        return {}
    return {
        "shisa.text": palette.semantic["text"],
        "shisa.muted": palette.semantic["muted"],
        "shisa.accent": f"bold {palette.semantic['accent']}",
        "shisa.success": palette.semantic["success"],
        "shisa.warning": palette.semantic["warning"],
        "shisa.danger": palette.semantic["danger"],
        "shisa.info": palette.semantic["info"],
        "shisa.border": palette.semantic["border"],
        "shisa.focus": f"bold {palette.semantic['focus']}",
    }


def textual_theme_css(palette: ThemePalette, *, color: bool = True) -> str:
    """Return compact TCSS that bridges semantic theme colors into Textual."""
    if not color:
        return ""
    return f"""
Screen {{
    background: {palette.semantic["background"]};
    color: {palette.semantic["text"]};
}}
.shisa-panel {{
    background: {palette.semantic["panel"]};
    border: round {palette.semantic["border"]};
}}
.shisa-panel:focus {{
    border: heavy {palette.semantic["focus"]};
}}
.shisa-muted {{
    color: {palette.semantic["muted"]};
}}
.shisa-accent {{
    color: {palette.semantic["accent"]};
    text-style: bold;
}}
""".strip()


def web_css_variables(palette: ThemePalette) -> str:
    """Return CSS custom properties for static web dashboard rendering."""
    return "\n".join(
        [
            ":root {",
            f"  --bg: {palette.semantic['background']};",
            f"  --panel: {palette.semantic['panel']};",
            f"  --surface: {palette.semantic['surface']};",
            f"  --ink: {palette.semantic['text']};",
            f"  --muted: {palette.semantic['muted']};",
            f"  --accent: {palette.semantic['accent']};",
            f"  --success: {palette.semantic['success']};",
            f"  --warn: {palette.semantic['warning']};",
            f"  --danger: {palette.semantic['danger']};",
            f"  --info: {palette.semantic['info']};",
            f"  --border: {palette.semantic['border']};",
            "}",
        ]
    )
