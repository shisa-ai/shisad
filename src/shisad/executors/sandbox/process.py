"""Sandbox process-isolation and subprocess execution components."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from shisad.executors.connect_path import ConnectPathProxy, ConnectPathResult
from shisad.executors.sandbox.models import (
    DegradedModePolicy,
    ResourceLimits,
    SandboxBackend,
    SandboxConfig,
    SandboxEnforcement,
    SandboxType,
)

logger = logging.getLogger(__name__)

_BWRAP_BASE_RO_DIRS = ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc")


@dataclass(slots=True)
class ProcessRunResult:
    """Process execution details returned to orchestrator."""

    stdout: str
    stderr: str
    exit_code: int | None
    timed_out: bool
    truncated: bool
    resource_limit_warning: str
    isolation_degraded: bool
    blocked_reason: str
    connect_path_result: ConnectPathResult | None
    connect_path_degraded: bool


class SandboxProcessComponent(Protocol):
    """Protocol for sandbox process execution component."""

    @property
    def bwrap_binary(self) -> str: ...

    @property
    def nsjail_binary(self) -> str: ...

    def build_default_backends(self) -> dict[SandboxType, SandboxBackend]: ...

    def run_process(
        self,
        config: SandboxConfig,
        *,
        backend: SandboxBackend,
        command: list[str],
        env: dict[str, str],
        connect_path_allowed_ips: list[str],
        enforce_connect_path: bool,
    ) -> ProcessRunResult: ...

    def wrap_isolated_command(
        self,
        *,
        backend: SandboxBackend,
        config: SandboxConfig,
        command: list[str],
    ) -> list[str]: ...


class SandboxProcessRunner:
    """Default process runner used by sandbox orchestrator."""

    def __init__(
        self,
        *,
        connect_path_proxy: ConnectPathProxy,
        bwrap_binary: str | None = None,
        nsjail_binary: str | None = None,
    ) -> None:
        self._connect_path_proxy = connect_path_proxy
        self._bwrap = self._detect_usable_bwrap() if bwrap_binary is None else bwrap_binary
        self._nsjail = (shutil.which("nsjail") or "") if nsjail_binary is None else nsjail_binary

    @property
    def bwrap_binary(self) -> str:
        return self._bwrap

    @property
    def nsjail_binary(self) -> str:
        return self._nsjail

    def build_default_backends(self) -> dict[SandboxType, SandboxBackend]:
        container_runtime = self._bwrap
        nsjail_runtime = self._nsjail or self._bwrap
        vm_runtime = self._bwrap
        return {
            SandboxType.CONTAINER: SandboxBackend(
                backend=SandboxType.CONTAINER,
                enforcement=SandboxEnforcement(
                    filesystem=bool(container_runtime),
                    network=bool(container_runtime),
                    env=True,
                    seccomp=bool(container_runtime),
                    resource_limits=True,
                    cgroups=False,
                    dns_control=bool(container_runtime),
                ),
                runtime=container_runtime,
            ),
            SandboxType.NSJAIL: SandboxBackend(
                backend=SandboxType.NSJAIL,
                enforcement=SandboxEnforcement(
                    filesystem=bool(nsjail_runtime),
                    network=bool(nsjail_runtime),
                    env=True,
                    seccomp=bool(nsjail_runtime),
                    resource_limits=True,
                    cgroups=False,
                    dns_control=bool(nsjail_runtime),
                ),
                runtime=nsjail_runtime,
            ),
            SandboxType.VM: SandboxBackend(
                backend=SandboxType.VM,
                enforcement=SandboxEnforcement(
                    filesystem=bool(vm_runtime),
                    network=bool(vm_runtime),
                    env=True,
                    seccomp=False,
                    resource_limits=True,
                    cgroups=False,
                    dns_control=bool(vm_runtime),
                ),
                runtime=vm_runtime,
            ),
        }

    def run_process(
        self,
        config: SandboxConfig,
        *,
        backend: SandboxBackend,
        command: list[str],
        env: dict[str, str],
        connect_path_allowed_ips: list[str],
        enforce_connect_path: bool,
    ) -> ProcessRunResult:
        cwd = config.cwd or None
        truncated = False
        resource_limit_warning = ""
        isolation_degraded = False
        blocked_reason = ""
        connect_path_result: ConnectPathResult | None = None
        connect_path_degraded = False

        run_command = list(command)
        run_env = env
        wrapped_used = False
        fail_closed = (
            config.degraded_mode == DegradedModePolicy.FAIL_CLOSED or config.security_critical
        )
        if backend.runtime:
            wrapped = self.wrap_isolated_command(
                backend=backend,
                config=config,
                command=command,
            )
            if wrapped and wrapped != command:
                run_command = wrapped
                run_env = dict(env)
                cwd = None
                wrapped_used = True
            else:
                isolation_degraded = True
                if fail_closed:
                    blocked_reason = "runtime_isolation_unavailable"
                    return ProcessRunResult(
                        stdout="",
                        stderr="",
                        exit_code=None,
                        timed_out=False,
                        truncated=truncated,
                        resource_limit_warning=resource_limit_warning,
                        isolation_degraded=isolation_degraded,
                        blocked_reason=blocked_reason,
                        connect_path_result=connect_path_result,
                        connect_path_degraded=connect_path_degraded,
                    )
        else:
            isolation_degraded = True
            if fail_closed:
                blocked_reason = "runtime_isolation_unavailable"
                return ProcessRunResult(
                    stdout="",
                    stderr="",
                    exit_code=None,
                    timed_out=False,
                    truncated=truncated,
                    resource_limit_warning=resource_limit_warning,
                    isolation_degraded=isolation_degraded,
                    blocked_reason=blocked_reason,
                    connect_path_result=connect_path_result,
                    connect_path_degraded=connect_path_degraded,
                )

        preexec = self.preexec_limits(config.limits)
        on_started: Callable[[int], str | None] | None = None
        if enforce_connect_path:
            allowed_ips = sorted({item for item in connect_path_allowed_ips if item})

            def _on_started(namespace_pid: int) -> str | None:
                nonlocal connect_path_result, connect_path_degraded
                connect_path_result = self._connect_path_proxy.enforce(
                    allowed_ips=allowed_ips,
                    namespace_pid=namespace_pid,
                )
                if not connect_path_result.enforced:
                    connect_path_degraded = True
                    if fail_closed:
                        return "connect_path_unavailable"
                return None

            on_started = _on_started

        stdout, stderr, exit_code, timed_out, invoke_blocked_reason = self.invoke(
            run_command,
            env=run_env,
            cwd=cwd,
            timeout_seconds=config.limits.timeout_seconds,
            preexec=preexec,
            on_started=on_started,
        )
        if invoke_blocked_reason:
            blocked_reason = invoke_blocked_reason

        if wrapped_used and self.isolation_runtime_failed(exit_code=exit_code, stderr=stderr):
            isolation_degraded = True
            if fail_closed:
                blocked_reason = "runtime_isolation_unavailable"
                return ProcessRunResult(
                    stdout=stdout,
                    stderr=stderr,
                    exit_code=exit_code,
                    timed_out=timed_out,
                    truncated=truncated,
                    resource_limit_warning=resource_limit_warning,
                    isolation_degraded=isolation_degraded,
                    blocked_reason=blocked_reason,
                    connect_path_result=connect_path_result,
                    connect_path_degraded=connect_path_degraded,
                )
            stdout, stderr, exit_code, timed_out, invoke_blocked_reason = self.invoke(
                command,
                env=env,
                cwd=config.cwd or None,
                timeout_seconds=config.limits.timeout_seconds,
                preexec=preexec,
                on_started=on_started,
            )
            if invoke_blocked_reason:
                blocked_reason = invoke_blocked_reason

        max_bytes = max(1, config.limits.output_bytes)
        stdout_bytes = stdout.encode("utf-8", errors="ignore")
        stderr_bytes = stderr.encode("utf-8", errors="ignore")
        if len(stdout_bytes) > max_bytes:
            truncated = True
            stdout = stdout_bytes[:max_bytes].decode("utf-8", errors="ignore")
        if len(stderr_bytes) > max_bytes:
            truncated = True
            stderr = stderr_bytes[:max_bytes].decode("utf-8", errors="ignore")

        limit_warning_prefix = "[shisad sandbox] resource limits degraded:"
        for line in stderr.splitlines():
            if line.startswith(limit_warning_prefix):
                resource_limit_warning = line[len(limit_warning_prefix) :].strip()
                break

        return ProcessRunResult(
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            timed_out=timed_out,
            truncated=truncated,
            resource_limit_warning=resource_limit_warning,
            isolation_degraded=isolation_degraded,
            blocked_reason=blocked_reason,
            connect_path_result=connect_path_result,
            connect_path_degraded=connect_path_degraded,
        )

    def wrap_isolated_command(
        self,
        *,
        backend: SandboxBackend,
        config: SandboxConfig,
        command: list[str],
    ) -> list[str]:
        if backend.runtime == self._bwrap and self._bwrap:
            return self.build_bwrap_command(config=config, command=command)
        if backend.runtime == self._nsjail and self._nsjail:
            return self.build_nsjail_command(config=config, command=command)
        return list(command)

    def build_bwrap_command(self, *, config: SandboxConfig, command: list[str]) -> list[str]:
        args: list[str] = [
            self._bwrap,
            "--die-with-parent",
            "--new-session",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--tmpfs",
            "/run",
            "--unshare-pid",
            "--unshare-uts",
            "--unshare-ipc",
        ]
        if not config.network.allow_network:
            args.append("--unshare-net")
        bind_modes: dict[Path, str] = {}
        for base in _BWRAP_BASE_RO_DIRS:
            base_path = Path(base)
            if base_path.exists():
                bind_modes[base_path] = "ro"

        def _mark_bind(path: Path, mode: str) -> None:
            existing = bind_modes.get(path)
            if existing == "rw":
                return
            bind_modes[path] = mode if existing is None else ("rw" if mode == "rw" else existing)

        for item in config.read_paths:
            candidate = Path(item).expanduser()
            if candidate.exists():
                _mark_bind(candidate, "ro")
        for item in config.write_paths:
            candidate = Path(item).expanduser()
            if candidate.exists():
                _mark_bind(candidate, "rw")
            elif candidate.parent.exists():
                _mark_bind(candidate.parent, "rw")
        if config.cwd:
            cwd_path = Path(config.cwd).expanduser()
            if cwd_path.exists():
                writeable = any(
                    str(cwd_path).startswith(str(Path(path).expanduser()))
                    for path in config.write_paths
                )
                _mark_bind(cwd_path, "rw" if writeable else "ro")

        executable = command[0] if command else ""
        resolved_executable = (
            shutil.which(executable)
            if executable and not Path(executable).exists()
            else executable
        )
        if resolved_executable:
            executable_path = Path(resolved_executable).expanduser()
            if executable_path.exists():
                parent_parent = executable_path.parent.parent
                prefix = parent_parent if parent_parent.exists() else executable_path.parent
                _mark_bind(prefix, "ro")
        for token in command[1:]:
            token_path = Path(token).expanduser()
            if token_path.is_absolute() and token_path.exists():
                _mark_bind(token_path if token_path.is_dir() else token_path.parent, "ro")

        for path, mode in sorted(bind_modes.items(), key=lambda item: len(str(item[0]))):
            if mode == "rw":
                args.extend(["--bind", str(path), str(path)])
            else:
                args.extend(["--ro-bind", str(path), str(path)])

        if config.cwd:
            cwd_path = Path(config.cwd).expanduser()
            if cwd_path.exists():
                args.extend(["--chdir", str(cwd_path)])
            else:
                args.extend(["--chdir", "/tmp"])
        else:
            args.extend(["--chdir", "/tmp"])
        args.extend(["--", *command])
        return args

    def build_nsjail_command(self, *, config: SandboxConfig, command: list[str]) -> list[str]:
        args: list[str] = [
            self._nsjail,
            "--mode",
            "o",
            "--quiet",
            "--time_limit",
            str(max(1, config.limits.timeout_seconds)),
            "--rlimit_as",
            str(max(1, config.limits.memory_mb)),
            "--max_cpus",
            "1",
        ]
        if config.network.allow_network:
            args.extend(["--disable_clone_newnet"])
        for base in _BWRAP_BASE_RO_DIRS:
            base_path = Path(base)
            if base_path.exists():
                args.extend(["--bindmount_ro", f"{base}:{base}"])
        for item in config.read_paths:
            candidate = Path(item).expanduser()
            if candidate.exists():
                args.extend(["--bindmount_ro", f"{candidate}:{candidate}"])
        for item in config.write_paths:
            candidate = Path(item).expanduser()
            if candidate.exists():
                args.extend(["--bindmount", f"{candidate}:{candidate}"])
            elif candidate.parent.exists():
                args.extend(["--bindmount", f"{candidate.parent}:{candidate.parent}"])
        if config.cwd:
            cwd_path = Path(config.cwd).expanduser()
            if cwd_path.exists():
                args.extend(["--cwd", str(cwd_path)])
        args.extend(["--", *command])
        return args

    @staticmethod
    def preexec_limits(limits: ResourceLimits) -> Any:
        try:
            import resource  # pylint: disable=import-outside-toplevel
        except ImportError:
            return None

        def _apply() -> None:
            memory_bytes = limits.memory_mb * 1024 * 1024
            errors: list[str] = []
            try:
                resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
            except (OSError, ValueError) as exc:  # pragma: no cover - platform dependent
                errors.append(f"RLIMIT_AS={exc.__class__.__name__}")
            try:
                resource.setrlimit(resource.RLIMIT_NPROC, (limits.pids, limits.pids))
            except (OSError, ValueError) as exc:  # pragma: no cover - platform dependent
                errors.append(f"RLIMIT_NPROC={exc.__class__.__name__}")
            if errors:
                os.write(
                    2,
                    (
                        "[shisad sandbox] resource limits degraded: "
                        + ",".join(errors)
                        + "\n"
                    ).encode("utf-8", errors="ignore"),
                )

        return _apply

    @staticmethod
    def invoke(
        command: list[str],
        *,
        env: dict[str, str],
        cwd: str | None,
        timeout_seconds: int,
        preexec: Any,
        on_started: Callable[[int], str | None] | None = None,
    ) -> tuple[str, str, int | None, bool, str | None]:
        timed_out = False
        stdout = ""
        stderr = ""
        exit_code: int | None = None
        blocked_reason: str | None = None
        try:
            completed = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                cwd=cwd,
                preexec_fn=preexec,
            )

            if on_started is not None and completed.pid > 0:
                blocked_reason = on_started(completed.pid)
                if blocked_reason:
                    completed.terminate()
                    try:
                        stdout, stderr = completed.communicate(timeout=1)
                    except subprocess.TimeoutExpired:
                        completed.kill()
                        stdout, stderr = completed.communicate()
                    exit_code = completed.returncode
                    return stdout, stderr, exit_code, timed_out, blocked_reason

            try:
                stdout, stderr = completed.communicate(timeout=timeout_seconds)
                exit_code = completed.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                completed.kill()
                timeout_out, timeout_err = completed.communicate()
                stdout = timeout_out or ""
                stderr = timeout_err or ""
                exit_code = None
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = SandboxProcessRunner.to_text(exc.stdout)
            stderr = SandboxProcessRunner.to_text(exc.stderr)
            exit_code = None
        return stdout, stderr, exit_code, timed_out, blocked_reason

    @staticmethod
    def isolation_runtime_failed(*, exit_code: int | None, stderr: str) -> bool:
        if exit_code in {0, None}:
            return False
        lowered = stderr.lower()
        markers = (
            "creating new namespace failed",
            "operation not permitted",
            "permission denied",
            "namespace",
            "cannot create user namespace",
        )
        return any(marker in lowered for marker in markers)

    @staticmethod
    def to_text(value: bytes | str | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="ignore")
        return value

    @staticmethod
    def _detect_usable_bwrap() -> str:
        binary = shutil.which("bwrap") or ""
        if not binary:
            return ""
        probe = [
            binary,
            "--ro-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--",
            "/bin/true",
        ]
        try:
            completed = subprocess.run(
                probe,
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.warning(
                "sandbox.runtime_probe_failed",
                extra={"reason": "bwrap_probe_failed", "error": exc.__class__.__name__},
            )
            return ""
        if completed.returncode != 0:
            return ""
        return binary


__all__ = [
    "ProcessRunResult",
    "SandboxProcessComponent",
    "SandboxProcessRunner",
]
