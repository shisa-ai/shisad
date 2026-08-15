"""Bounded background daemon start and readiness presentation."""

from __future__ import annotations

import asyncio
import os
import stat
import subprocess
import sys
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

import click
from pydantic import BaseModel

from shisad.core.api.schema import DaemonStatusResult, DoctorCheckResult
from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig

_KNOWN_READINESS_COMPONENTS = (
    "provider",
    "channels",
    "storage",
    "sandbox",
    "browser",
    "mcp",
    "search",
    "dependencies",
    "policy",
    "realitycheck",
)
_KNOWN_READINESS_STATES = {
    "absent",
    "installed",
    "configured",
    "reachable",
    "authenticated",
    "verified",
    "degraded",
    "blocked",
    "disabled",
    "unavailable",
    "error",
    "running",
    "ok",
}


class BackgroundStartError(RuntimeError):
    """A detached daemon child did not become reachable."""

    def __init__(self, reason: str, *, log_path: Path) -> None:
        super().__init__(reason)
        self.log_path = log_path


@dataclass(frozen=True, slots=True)
class BackgroundStartResult:
    """Safe parent-process evidence for one start attempt."""

    already_running: bool
    pid: int | None
    log_path: Path
    status: DaemonStatusResult
    doctor: DoctorCheckResult | None


def build_background_argv(config: DaemonConfig, *, no_color: bool = False) -> list[str]:
    """Build the detached child argv without carrying secret config fields."""

    argv = [sys.executable, "-m", "shisad.cli.main"]
    if no_color:
        argv.append("--no-color")
    if config.config_path is not None:
        argv.extend(["--config", str(config.config_path)])
    argv.extend(["start", "--foreground"])
    return argv


def _prepare_log_directory(config: DaemonConfig) -> Path:
    if os.name != "posix":
        raise BackgroundStartError(
            "background start is unavailable on this platform",
            log_path=config.data_dir / "logs" / "daemon.log",
        )
    if config.data_dir.is_symlink():
        raise BackgroundStartError(
            "daemon data directory cannot be a symlink for background start",
            log_path=config.data_dir / "logs" / "daemon.log",
        )
    log_dir = config.data_dir / "logs"
    try:
        log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory_stat = log_dir.lstat()
        if not stat.S_ISDIR(directory_stat.st_mode) or log_dir.is_symlink():
            raise OSError("log path is not a directory")
        if hasattr(os, "getuid") and directory_stat.st_uid != os.getuid():
            raise OSError("log directory is not owned by the current user")
        os.chmod(log_dir, 0o700)
    except OSError as exc:
        raise BackgroundStartError(
            f"could not prepare owner-only daemon log directory ({exc.__class__.__name__})",
            log_path=log_dir / "daemon.log",
        ) from exc
    return log_dir / "daemon.log"


def _open_owner_only_log(config: DaemonConfig) -> tuple[Path, BinaryIO]:
    log_path = _prepare_log_directory(config)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(log_path, flags, 0o600)
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise OSError("daemon log is not a regular file")
        if hasattr(os, "getuid") and file_stat.st_uid != os.getuid():
            raise OSError("daemon log is not owned by the current user")
        os.fchmod(descriptor, 0o600)
        stream = os.fdopen(descriptor, "ab", buffering=0)
        descriptor = -1
        return log_path, stream
    except OSError as exc:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        raise BackgroundStartError(
            f"could not open owner-only daemon log ({exc.__class__.__name__})",
            log_path=log_path,
        ) from exc


async def _bounded_rpc_call_async[T: BaseModel](
    config: DaemonConfig,
    method: str,
    params: dict[str, Any] | None,
    *,
    response_model: type[T],
    timeout_seconds: float,
) -> T:
    client = ControlClient(config.socket_path)
    try:
        async with asyncio.timeout(max(0.01, timeout_seconds)):
            await client.connect()
            raw = await client.call(method, params=params or {})
        return response_model.model_validate(raw)
    finally:
        with suppress(OSError, RuntimeError, TimeoutError):
            async with asyncio.timeout(0.1):
                await client.close()


def _bounded_rpc_call[T: BaseModel](
    config: DaemonConfig,
    method: str,
    params: dict[str, Any] | None = None,
    *,
    response_model: type[T],
    timeout_seconds: float,
) -> T:
    """Run one lifecycle RPC with a deadline covering connect and response."""

    return asyncio.run(
        _bounded_rpc_call_async(
            config,
            method,
            params,
            response_model=response_model,
            timeout_seconds=timeout_seconds,
        )
    )


def _try_status(
    config: DaemonConfig,
    rpc_call_fn: Callable[..., Any] | None,
    *,
    timeout_seconds: float,
) -> DaemonStatusResult | None:
    try:
        if rpc_call_fn is None:
            result = _bounded_rpc_call(
                config,
                "daemon.status",
                response_model=DaemonStatusResult,
                timeout_seconds=timeout_seconds,
            )
        else:
            result = rpc_call_fn(
                config,
                "daemon.status",
                response_model=DaemonStatusResult,
            )
    except (click.ClickException, OSError, RuntimeError, TypeError, ValueError):
        return None
    if isinstance(result, DaemonStatusResult):
        return result
    try:
        return DaemonStatusResult.model_validate(result)
    except (TypeError, ValueError):
        return None


def _try_doctor(
    config: DaemonConfig,
    rpc_call_fn: Callable[..., Any] | None,
    *,
    timeout_seconds: float,
) -> DoctorCheckResult | None:
    try:
        params = {"component": "all", "live": False, "timeout_seconds": 3.0}
        if rpc_call_fn is None:
            result = _bounded_rpc_call(
                config,
                "doctor.check",
                params,
                response_model=DoctorCheckResult,
                timeout_seconds=timeout_seconds,
            )
        else:
            result = rpc_call_fn(
                config,
                "doctor.check",
                params,
                response_model=DoctorCheckResult,
            )
    except (click.ClickException, OSError, RuntimeError, TypeError, ValueError):
        return None
    if isinstance(result, DoctorCheckResult):
        return result
    try:
        return DoctorCheckResult.model_validate(result)
    except (TypeError, ValueError):
        return None


def _terminate_spawned_child(process: Any) -> None:
    """Boundedly stop only the exact child handle created by this start call."""

    if process.poll() is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        process.kill()
        with suppress(OSError, subprocess.TimeoutExpired):
            process.wait(timeout=2.0)
    except OSError:
        pass


def start_background_daemon(
    config: DaemonConfig,
    *,
    no_color: bool = False,
    timeout_seconds: float = 10.0,
    rpc_call_fn: Callable[..., Any] | None = None,
    popen_factory: Callable[..., Any] | None = None,
    sleep_fn: Callable[[float], None] | None = None,
    monotonic_fn: Callable[[], float] | None = None,
) -> BackgroundStartResult:
    """Start one detached POSIX daemon and wait for typed RPC readiness."""

    effective_popen = subprocess.Popen if popen_factory is None else popen_factory
    effective_sleep = time.sleep if sleep_fn is None else sleep_fn
    effective_monotonic = time.monotonic if monotonic_fn is None else monotonic_fn
    log_path = config.data_dir / "logs" / "daemon.log"
    deadline = effective_monotonic() + max(0.1, timeout_seconds)

    if config.socket_path.exists():
        remaining = deadline - effective_monotonic()
        existing_status = (
            _try_status(
                config,
                rpc_call_fn,
                timeout_seconds=min(1.0, remaining),
            )
            if remaining > 0
            else None
        )
        if existing_status is not None:
            remaining = deadline - effective_monotonic()
            return BackgroundStartResult(
                already_running=True,
                pid=None,
                log_path=log_path,
                status=existing_status,
                doctor=(
                    _try_doctor(
                        config,
                        rpc_call_fn,
                        timeout_seconds=min(3.0, remaining),
                    )
                    if remaining > 0
                    else None
                ),
            )

    log_path, log_stream = _open_owner_only_log(config)
    try:
        try:
            process = effective_popen(
                build_background_argv(config, no_color=no_color),
                stdin=subprocess.DEVNULL,
                stdout=log_stream,
                stderr=subprocess.STDOUT,
                close_fds=True,
                start_new_session=True,
            )
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            raise BackgroundStartError(
                f"could not launch daemon child ({exc.__class__.__name__})",
                log_path=log_path,
            ) from exc
    finally:
        log_stream.close()

    while True:
        remaining = deadline - effective_monotonic()
        if remaining <= 0:
            break
        status = _try_status(
            config,
            rpc_call_fn,
            timeout_seconds=min(1.0, remaining),
        )
        if status is not None:
            remaining = deadline - effective_monotonic()
            return BackgroundStartResult(
                already_running=False,
                pid=int(process.pid),
                log_path=log_path,
                status=status,
                doctor=(
                    _try_doctor(
                        config,
                        rpc_call_fn,
                        timeout_seconds=min(3.0, remaining),
                    )
                    if remaining > 0
                    else None
                ),
            )
        exit_code = process.poll()
        if exit_code is not None:
            raise BackgroundStartError(
                f"daemon child exited before readiness (exit={int(exit_code)})",
                log_path=log_path,
            )
        effective_sleep(min(0.1, max(0.0, remaining)))

    _terminate_spawned_child(process)
    raise BackgroundStartError(
        "daemon child did not become reachable before the start timeout",
        log_path=log_path,
    )


def _readiness_rows(status: DaemonStatusResult) -> list[str]:
    rows: list[str] = []
    for component in _KNOWN_READINESS_COMPONENTS:
        raw = status.readiness.get(component)
        if not isinstance(raw, dict):
            continue
        state = str(raw.get("status", "")).strip().lower()
        if state not in _KNOWN_READINESS_STATES:
            state = "unknown"
        rows.append(f"{component}={state}")
    return rows


def _health_state(result: BackgroundStartResult, rows: list[str]) -> str:
    states = {row.rsplit("=", 1)[-1] for row in rows}
    doctor_state = str(getattr(result.doctor, "status", "") or "").strip().lower()
    if states.intersection({"blocked", "degraded", "error"}) or doctor_state in {
        "blocked",
        "degraded",
        "error",
    }:
        return "degraded"
    if doctor_state in _KNOWN_READINESS_STATES:
        return doctor_state
    return "running"


def render_background_start(result: BackgroundStartResult) -> list[str]:
    """Render only bounded structural start/readiness facts."""

    if result.already_running:
        daemon_line = "Daemon: already running"
    else:
        daemon_line = f"Daemon: started pid={result.pid}"
    rows = _readiness_rows(result.status)
    health = _health_state(result, rows)
    lines = [daemon_line, f"Health: {health}"]
    if rows:
        lines.append(f"Readiness: {', '.join(rows)}")
    if not result.already_running:
        lines.append(f"Log: {result.log_path}")
    if health == "degraded":
        lines.append("Next: shisad doctor")
    return lines
