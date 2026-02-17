"""Unit checks for shared assistant boundary helpers."""

from __future__ import annotations

import io
from pathlib import Path

from shisad.assistant.boundary_helpers import (
    _host_matches,
    _is_within,
    _NoRedirectHandler,
    _read_limited,
)


def test_host_matches_supports_exact_and_wildcard_rules() -> None:
    assert _host_matches("docs.example.com", "*.example.com") is True
    assert _host_matches("docs.example.com", "docs.example.com") is True
    assert _host_matches("EXAMPLE.com", "example.com") is True
    assert _host_matches("example.com", "*.example.com") is False
    assert _host_matches("docs.example.com", "") is False


def test_is_within_reports_containment(tmp_path: Path) -> None:
    root = (tmp_path / "root").resolve(strict=False)
    inside = (root / "docs" / "a.md").resolve(strict=False)
    outside = (tmp_path / "elsewhere" / "a.md").resolve(strict=False)

    assert _is_within(inside, root) is True
    assert _is_within(outside, root) is False


def test_read_limited_returns_truncation_signal() -> None:
    payload = io.BytesIO(b"abcdef")
    data, truncated = _read_limited(payload, limit=4)

    assert data == b"abcd"
    assert truncated is True


def test_read_limited_exact_limit_is_not_truncated() -> None:
    payload = io.BytesIO(b"abcd")
    data, truncated = _read_limited(payload, limit=4)

    assert data == b"abcd"
    assert truncated is False


def test_read_limited_under_limit_is_not_truncated() -> None:
    payload = io.BytesIO(b"ab")
    data, truncated = _read_limited(payload, limit=4)

    assert data == b"ab"
    assert truncated is False


def test_no_redirect_handler_always_blocks_redirects() -> None:
    handler = _NoRedirectHandler()

    redirected = handler.redirect_request(
        req=None,
        fp=None,
        code=302,
        msg="Found",
        headers={},
        newurl="https://example.com/next",
    )

    assert redirected is None
