"""Shared string coercion helpers for handler runtime paths."""

from __future__ import annotations

from typing import Any


def optional_string(value: Any, *, default: str = "") -> str:
    if value is None:
        return default
    return str(value).strip()
