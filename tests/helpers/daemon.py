"""Shared daemon test helpers."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

_DEFAULT_STARTUP_TIMEOUT_SECONDS = 15.0


def _startup_timeout() -> float:
    raw = os.environ.get("SHISAD_TEST_STARTUP_TIMEOUT")
    if raw is not None:
        return float(raw)
    return _DEFAULT_STARTUP_TIMEOUT_SECONDS


async def wait_for_socket(path: Path, timeout: float | None = None) -> None:
    """Poll until *path* exists on disk, or raise :class:`TimeoutError`.

    The default timeout is 15 s, overridable per-call or globally via the
    ``SHISAD_TEST_STARTUP_TIMEOUT`` environment variable (seconds).
    """
    if timeout is None:
        timeout = _startup_timeout()
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if path.exists():
            return
        await asyncio.sleep(0.01)
    raise TimeoutError(f"Timed out waiting for socket {path}")
