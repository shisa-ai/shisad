"""Shared assistant boundary helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.request import HTTPRedirectHandler

from shisad.core.host_matching import host_matches


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _host_matches(host: str, rule: str) -> bool:
    """Return whether a normalized host matches an allowlist rule.

    Callers are expected to pass a hostname (for example from `urlparse(...).hostname`)
    rather than a raw `host:port` header value.
    """
    return host_matches(host, rule)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _read_limited(payload: Any, *, limit: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    remaining = max(1, limit)
    truncated = False
    while remaining > 0:
        chunk = payload.read(min(16384, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    if payload.read(1):
        truncated = True
    return b"".join(chunks), truncated
