"""URL parsing helpers that keep malformed user/content URLs non-fatal."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import ParseResult, urlparse


@dataclass(frozen=True, slots=True)
class URLDestination:
    """Structurally validated absolute network destination."""

    parsed: ParseResult
    scheme: str
    host: str
    port: int | None
    has_userinfo: bool


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


def canonicalize_url_host(value: str, *, allow_pattern: bool = False) -> str:
    """Canonicalize a host or host-pattern value without parsing a URL."""

    host = value.strip().lower()
    forbidden = "\\/%#@" if allow_pattern else "\\/%?#@"
    if (
        not host
        or any(ord(char) < 32 or ord(char) == 127 or char.isspace() for char in host)
        or any(char in host for char in forbidden)
    ):
        return ""
    if host.startswith("[") and host.endswith("]") and ":" in host:
        host = host[1:-1]
    elif not allow_pattern and ("[" in host or "]" in host):
        return ""
    if host.endswith("."):
        host = host[:-1]
    if not host or host.endswith("."):
        return ""
    if ":" not in host and (host.startswith(".") or ".." in host):
        return ""
    return host


def safe_url_destination(value: str) -> URLDestination | None:
    """Return a canonical absolute destination, or ``None`` when ambiguous."""

    normalized = value.strip()
    if not normalized or any(ord(char) < 32 or ord(char) == 127 for char in normalized):
        return None

    parsed = safe_urlparse(normalized)
    if parsed is None or not parsed.scheme or not parsed.netloc:
        return None
    if (
        "\\" in parsed.netloc
        or "%" in parsed.netloc
        or any(char.isspace() for char in parsed.netloc)
    ):
        return None

    try:
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        return None

    host = canonicalize_url_host(host)
    if not host:
        return None

    return URLDestination(
        parsed=parsed,
        scheme=parsed.scheme.lower(),
        host=host,
        port=port,
        has_userinfo="@" in parsed.netloc,
    )
