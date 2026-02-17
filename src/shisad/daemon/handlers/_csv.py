"""CSV export helpers for memory handlers."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

_FORMULA_PREFIXES: tuple[str, ...] = ("=", "+", "-", "@")
_FORMULA_CHECK_STRIP_CHARS = "".join(chr(code) for code in range(0x00, 0x21))


def escape_csv_field(value: Any) -> str:
    text = "" if value is None else str(value)
    # Some spreadsheet importers drop NUL bytes during parsing; remove them up front.
    text = text.replace("\x00", "")
    normalized = text.lstrip(_FORMULA_CHECK_STRIP_CHARS)
    if normalized.startswith(_FORMULA_PREFIXES):
        text = "'" + text
    if any(char in text for char in (",", '"', "\n", "\r")):
        return '"' + text.replace('"', '""') + '"'
    return text


def render_csv_row(values: Sequence[Any]) -> str:
    return ",".join(escape_csv_field(value) for value in values)
