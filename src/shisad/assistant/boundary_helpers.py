"""Shared assistant boundary helpers."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from io import BufferedReader
from pathlib import Path
from typing import Any
from urllib.request import HTTPRedirectHandler

from shisad.core.atomic_state import _open_directory_chain
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


@contextmanager
def _open_nofollow_regular_file(path: Path) -> Iterator[BufferedReader]:
    """Open a regular file through a held, no-follow parent descriptor."""

    parent_fd = -1
    file_fd = -1
    try:
        _absolute, parent_fd, _created = _open_directory_chain(path.parent, create=False)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        file_fd = os.open(path.name, flags, dir_fd=parent_fd)
        file_stat = os.fstat(file_fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise OSError("allowlisted read target is not a regular file")
        with os.fdopen(file_fd, "rb") as handle:
            file_fd = -1
            yield handle
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
