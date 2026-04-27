"""URL parsing helpers that keep malformed user/content URLs non-fatal."""

from __future__ import annotations

from urllib.parse import ParseResult, urlparse


def safe_urlparse(value: str) -> ParseResult | None:
    """Parse a URL-like value, returning ``None`` for malformed netlocs."""

    try:
        return urlparse(value)
    except ValueError:
        return None


def safe_parsed_hostname(parsed: ParseResult | None, *, strip_trailing_dot: bool = False) -> str:
    """Return a normalized hostname from a parsed URL, or an empty string."""

    if parsed is None:
        return ""
    try:
        host = parsed.hostname or ""
    except ValueError:
        return ""
    host = host.strip().lower()
    if strip_trailing_dot:
        host = host.rstrip(".")
    return host


def safe_url_hostname(value: str, *, strip_trailing_dot: bool = False) -> str:
    """Parse a URL-like value and return its normalized hostname if valid."""

    return safe_parsed_hostname(
        safe_urlparse(value),
        strip_trailing_dot=strip_trailing_dot,
    )
