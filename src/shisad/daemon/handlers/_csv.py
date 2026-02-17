"""CSV export helpers for memory handlers."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

_FORMULA_PREFIXES: tuple[str, ...] = ("=", "+", "-", "@")


def escape_csv_field(value: Any) -> str:
    text = "" if value is None else str(value)
    if text and text[0] in _FORMULA_PREFIXES:
        text = "'" + text
    if any(char in text for char in (",", '"', "\n", "\r")):
        return '"' + text.replace('"', '""') + '"'
    return text


def render_csv_row(values: Sequence[Any]) -> str:
    return ",".join(escape_csv_field(value) for value in values)
