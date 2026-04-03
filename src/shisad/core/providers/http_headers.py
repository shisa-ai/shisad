"""Header validation helpers for routed provider configuration."""

from __future__ import annotations

import re
from collections.abc import Mapping

_HEADER_TOKEN_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_BLOCKED_EXACT_HEADERS = {
    "host",
    "connection",
    "content-length",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
    "forwarded",
    "via",
}
_MAX_EXTRA_HEADERS = 16
_MAX_HEADER_VALUE_BYTES = 512


def normalize_header_name(name: str) -> str:
    normalized = name.strip().lower()
    if not normalized:
        raise ValueError("header name must not be empty")
    if not _HEADER_TOKEN_RE.fullmatch(normalized):
        raise ValueError(f"header name '{name}' is not RFC 7230 token-safe")
    return normalized


def validate_auth_header_name(name: str) -> str:
    normalized = normalize_header_name(name)
    if _is_blocked_header_name(normalized):
        raise ValueError(f"auth header name '{name}' is blocked")
    if normalized in {"authorization", "content-type", "accept"}:
        raise ValueError(f"auth header name '{name}' is reserved")
    return normalized


def validate_extra_headers(
    headers: Mapping[str, str] | None,
    *,
    selected_auth_header_name: str | None = None,
) -> dict[str, str]:
    if not headers:
        return {}

    auth_header = ""
    if selected_auth_header_name:
        auth_header = normalize_header_name(selected_auth_header_name)

    normalized: dict[str, str] = {}
    for raw_name, raw_value in headers.items():
        name = normalize_header_name(str(raw_name))
        if _is_blocked_header_name(name):
            raise ValueError(f"extra header '{raw_name}' is blocked")
        if name in {"authorization", "content-type", "accept"} or (
            auth_header and name == auth_header
        ):
            raise ValueError(f"extra header '{raw_name}' cannot override auth/system headers")
        if name in normalized:
            raise ValueError(f"duplicate extra header '{raw_name}' after normalization")

        value = str(raw_value)
        if not value.strip():
            raise ValueError(f"extra header '{raw_name}' must not be empty")
        if "\r" in value or "\n" in value:
            raise ValueError(f"extra header '{raw_name}' must not contain CR/LF")
        if len(value.encode("ascii", errors="ignore")) != len(value):
            raise ValueError(f"extra header '{raw_name}' must be printable ASCII")
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
            raise ValueError(f"extra header '{raw_name}' contains control characters")
        if len(value.encode("utf-8")) > _MAX_HEADER_VALUE_BYTES:
            raise ValueError(f"extra header '{raw_name}' exceeds {_MAX_HEADER_VALUE_BYTES} bytes")
        normalized[name] = value

    if len(normalized) > _MAX_EXTRA_HEADERS:
        raise ValueError(f"extra header count exceeds {_MAX_EXTRA_HEADERS}")

    return normalized


def _is_blocked_header_name(name: str) -> bool:
    if name in _BLOCKED_EXACT_HEADERS:
        return True
    return name.startswith("x-forwarded-")
