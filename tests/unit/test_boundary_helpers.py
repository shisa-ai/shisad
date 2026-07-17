"""Unit checks for shared assistant boundary helpers."""

from __future__ import annotations

import io
import os
from pathlib import Path

import pytest

from shisad.assistant.boundary_helpers import (
    _host_matches,
    _is_within,
    _NoRedirectHandler,
    _open_nofollow_regular_file,
    _read_limited,
)


def test_host_matches_supports_exact_and_wildcard_rules() -> None:
    assert _host_matches("docs.example.com", "*.example.com") is True
    assert _host_matches("docs.example.com", "docs.example.com") is True
    assert _host_matches("docs.example.com", "*") is True
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


def test_f3_nofollow_regular_file_open_is_nonblocking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "source.txt"
    target.write_text("safe", encoding="utf-8")
    real_open = os.open

    def _require_nonblocking(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == target.name:
            assert flags & os.O_NONBLOCK
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", _require_nonblocking)

    with _open_nofollow_regular_file(target) as handle:
        assert handle.read() == b"safe"


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
