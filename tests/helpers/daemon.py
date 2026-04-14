"""Shared daemon test helpers."""

from __future__ import annotations

import asyncio
import contextlib
import os
import textwrap
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator

_DEFAULT_STARTUP_TIMEOUT_SECONDS = 15.0

_DEFAULT_POLICY_TEXT = textwrap.dedent("""\
    version: "1"
    default_deny: true
    default_require_confirmation: false
    default_capabilities:
      - file.read
""")


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


def clear_remote_provider_env(monkeypatch: Any) -> None:
    """Clear all remote-provider env vars so tests run against local fallback.

    Extracted from the duplicated helper in many test files.
    """
    for key in (
        "SHISA_API_KEY",
        "SHISAD_MODEL_API_KEY",
        "SHISAD_MODEL_PLANNER_API_KEY",
        "OPENAI_API_KEY",
        "OPENROUTER_API_KEY",
        "GEMINI_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)
    for var in (
        "SHISAD_MODEL_REMOTE_ENABLED",
        "SHISAD_MODEL_PLANNER_REMOTE_ENABLED",
        "SHISAD_MODEL_EMBEDDINGS_REMOTE_ENABLED",
        "SHISAD_MODEL_MONITOR_REMOTE_ENABLED",
    ):
        monkeypatch.setenv(var, "false")


@dataclass
class DaemonHarness:
    """Running daemon instance with a connected control client."""

    config: Any  # DaemonConfig
    client: Any  # ControlClient
    daemon_task: asyncio.Task[None]
    _started: bool = field(default=True, repr=False)

    async def call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        """Shorthand for ``self.client.call(method, params)``."""
        return await self.client.call(method, params)

    async def reset(self) -> dict[str, Any]:
        """Call ``daemon.reset`` to wipe mutable state between tests."""
        result = await self.client.call("daemon.reset")
        return result

    async def shutdown(self) -> None:
        """Gracefully shut down the daemon and wait for task exit."""
        if not self._started:
            return
        self._started = False
        with suppress(Exception):
            await self.client.call("daemon.shutdown")
        with suppress(Exception):
            await self.client.close()
        with suppress(asyncio.CancelledError, asyncio.TimeoutError):
            await asyncio.wait_for(self.daemon_task, timeout=5.0)


@contextlib.asynccontextmanager
async def daemon_harness(
    tmp_dir: Path,
    *,
    policy_text: str | None = None,
    config_kwargs: dict[str, Any] | None = None,
) -> AsyncIterator[DaemonHarness]:
    """Start a daemon and yield a connected :class:`DaemonHarness`.

    On exit the daemon is shut down.  Use ``harness.reset()`` between tests
    sharing a single daemon to wipe mutable state.

    Parameters
    ----------
    tmp_dir:
        Root temp directory.  ``data/``, ``control.sock``, and ``policy.yaml``
        are created inside it.
    policy_text:
        YAML policy body.  Falls back to a minimal default-deny policy.
    config_kwargs:
        Extra keyword arguments forwarded to ``DaemonConfig()``.
    """
    from shisad.core.api.transport import ControlClient
    from shisad.core.config import DaemonConfig
    from shisad.daemon.runner import run_daemon

    policy_path = tmp_dir / "policy.yaml"
    policy_path.write_text(policy_text or _DEFAULT_POLICY_TEXT, encoding="utf-8")

    merged: dict[str, Any] = {
        "data_dir": tmp_dir / "data",
        "socket_path": tmp_dir / "control.sock",
        "policy_path": policy_path,
        "log_level": "INFO",
    }
    if config_kwargs:
        merged.update(config_kwargs)

    config = DaemonConfig(**merged)
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    harness = DaemonHarness(config=config, client=client, daemon_task=daemon_task)

    try:
        await wait_for_socket(config.socket_path)
        await client.connect()
        yield harness
    finally:
        await harness.shutdown()
