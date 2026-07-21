"""Sandbox process-isolation and subprocess execution components."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import secrets
import select
import shutil
import signal
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from shisad.core.url_parsing import safe_parsed_hostname, safe_urlparse
from shisad.executors.connect_path import ConnectPathProxy, ConnectPathResult
from shisad.executors.sandbox.models import (
    ContainmentProfile,
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
    host_fallback_used: bool = False
    actual_runtime: str = ""


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
        filesystem_command: list[str] | None = None,
    ) -> list[str]: ...


class SandboxProcessRunner:
    """Default process runner used by sandbox orchestrator."""

    def __init__(
        self,
        *,
        connect_path_proxy: ConnectPathProxy,
        bwrap_binary: str | None = None,
        nsjail_binary: str | None = None,
        pasta_binary: str | None = None,
    ) -> None:
        self._connect_path_proxy = connect_path_proxy
        self._bwrap = self._detect_usable_bwrap() if bwrap_binary is None else bwrap_binary
        self._nsjail = (shutil.which("nsjail") or "") if nsjail_binary is None else nsjail_binary
        self._pasta = (shutil.which("pasta") or "") if pasta_binary is None else pasta_binary

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
        network_runtime = bool(self._bwrap and self._pasta)
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
                    dns_control=network_runtime,
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
                    dns_control=network_runtime,
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
                    dns_control=network_runtime,
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
        host_fallback_used = False
        actual_runtime = ""

        run_command = list(command)
        run_env = env
        wrapped_used = False
        pass_fds: tuple[int, ...] = ()
        namespace_pid_fd: int | None = None
        close_after_spawn_fds: tuple[int, ...] = ()
        owned_fds: list[int] = []
        on_started: Callable[[int], str | None] | None = None
        fail_closed = (
            config.containment_profile == ContainmentProfile.SUPPORTED
            or config.degraded_mode == DegradedModePolicy.FAIL_CLOSED
            or config.security_critical
        )
        execution_marker = f"shisad-exec-marker:{secrets.token_hex(16)}"
        instrumented_command = self._instrument_command(command, execution_marker)
        filesystem_command = list(config.command) if config.command else list(command)
        if not command or not filesystem_command or command[0] != filesystem_command[0]:
            return ProcessRunResult(
                stdout="",
                stderr="",
                exit_code=None,
                timed_out=False,
                truncated=truncated,
                resource_limit_warning=resource_limit_warning,
                isolation_degraded=False,
                blocked_reason="executable_changed_after_authorization",
                connect_path_result=None,
                connect_path_degraded=False,
            )

        if enforce_connect_path:
            allowed_ips = self._ipv4_addresses(connect_path_allowed_ips)
            network_boundary_reason = ""
            network_fds: tuple[int, int, int, int, int, int] | None = None
            if not self._bwrap:
                network_boundary_reason = "bwrap_unavailable"
            elif not self._pasta:
                network_boundary_reason = "pasta_unavailable"
            elif not allowed_ips:
                network_boundary_reason = "empty_allowed_ips"
            else:
                network_fds, network_boundary_reason = self._create_network_boundary_fds(
                    resolv_conf=b"nameserver 127.0.0.1\noptions timeout:1 attempts:1\n",
                    hosts_file=self._network_hosts_file(config, command, allowed_ips),
                )

            if network_boundary_reason:
                isolation_degraded = True
                connect_path_degraded = True
                connect_path_result = ConnectPathResult(
                    enforced=False,
                    method="none",
                    reason=network_boundary_reason,
                )
                if fail_closed:
                    return ProcessRunResult(
                        stdout="",
                        stderr="",
                        exit_code=None,
                        timed_out=False,
                        truncated=truncated,
                        resource_limit_warning=resource_limit_warning,
                        isolation_degraded=isolation_degraded,
                        blocked_reason=(
                            "connect_path_unavailable"
                            if network_boundary_reason == "empty_allowed_ips"
                            else "runtime_isolation_unavailable"
                        ),
                        connect_path_result=connect_path_result,
                        connect_path_degraded=connect_path_degraded,
                    )
                host_fallback_used = True
                actual_runtime = "host"
            else:
                assert network_fds is not None
                (
                    gate_read_fd,
                    gate_write_fd,
                    resolv_read_fd,
                    hosts_read_fd,
                    info_read_fd,
                    info_write_fd,
                ) = network_fds
                owned_fds.extend(network_fds)
                run_command = self.build_bwrap_command(
                    config=config,
                    command=instrumented_command,
                    filesystem_command=filesystem_command,
                    network_block_fd=gate_read_fd,
                    resolv_conf_fd=resolv_read_fd,
                    hosts_file_fd=hosts_read_fd,
                    info_fd=info_write_fd,
                )
                run_env = dict(env)
                cwd = None
                wrapped_used = True
                actual_runtime = "bwrap+pasta"
                pass_fds = (
                    gate_read_fd,
                    resolv_read_fd,
                    hosts_read_fd,
                    info_write_fd,
                )
                namespace_pid_fd = info_read_fd
                close_after_spawn_fds = (info_write_fd,)

                def _on_started(namespace_pid: int) -> str | None:
                    nonlocal connect_path_result, connect_path_degraded
                    if namespace_pid <= 0:
                        connect_path_degraded = True
                        connect_path_result = ConnectPathResult(
                            enforced=False,
                            method="bwrap",
                            reason="sandbox_child_pid_unavailable",
                        )
                        return "connect_path_unavailable"
                    pasta_error = self._attach_pasta_network(namespace_pid)
                    if pasta_error:
                        connect_path_degraded = True
                        connect_path_result = ConnectPathResult(
                            enforced=False,
                            method="pasta",
                            reason=pasta_error,
                        )
                        return "connect_path_unavailable"
                    try:
                        connect_path_result = self._connect_path_proxy.enforce(
                            allowed_ips=allowed_ips,
                            namespace_pid=namespace_pid,
                        )
                    except Exception as exc:
                        connect_path_degraded = True
                        connect_path_result = ConnectPathResult(
                            enforced=False,
                            method="none",
                            reason=f"connect_path_failed:{exc.__class__.__name__}",
                        )
                        return "connect_path_unavailable"
                    if not connect_path_result.enforced:
                        connect_path_degraded = True
                        return "connect_path_unavailable"
                    try:
                        os.write(gate_write_fd, b"1")
                    except OSError as exc:
                        connect_path_degraded = True
                        connect_path_result = ConnectPathResult(
                            enforced=False,
                            method=connect_path_result.method,
                            reason=f"command_gate_failed:{exc.__class__.__name__}",
                        )
                        return "connect_path_unavailable"
                    return None

                on_started = _on_started
        elif backend.runtime:
            wrapped = self.wrap_isolated_command(
                backend=backend,
                config=config,
                command=instrumented_command,
                filesystem_command=filesystem_command,
            )
            if wrapped and wrapped != instrumented_command:
                run_command = wrapped
                run_env = dict(env)
                cwd = None
                wrapped_used = True
                actual_runtime = Path(backend.runtime).name
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
                host_fallback_used = True
                actual_runtime = "host"
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
            host_fallback_used = True
            actual_runtime = "host"

        preexec = self.preexec_limits(config.limits)
        for delegated_fd in close_after_spawn_fds:
            try:
                owned_fds.remove(delegated_fd)
            except ValueError:
                continue
        try:
            stdout, stderr, exit_code, timed_out, invoke_blocked_reason = self.invoke(
                run_command,
                env=run_env,
                cwd=cwd,
                timeout_seconds=config.limits.timeout_seconds,
                preexec=preexec,
                on_started=on_started,
                memory_mb=self._memory_monitor_limit_mb(config.limits),
                pass_fds=pass_fds,
                namespace_pid_fd=namespace_pid_fd,
                close_after_spawn_fds=close_after_spawn_fds,
            )
        finally:
            for fd in owned_fds:
                self._close_fd(fd)
        if invoke_blocked_reason:
            blocked_reason = invoke_blocked_reason

        execution_started = False
        if wrapped_used:
            stderr, execution_started = self._strip_execution_marker(
                stderr,
                execution_marker,
            )
        if wrapped_used and not execution_started:
            isolation_degraded = True
        if wrapped_used and not execution_started and not timed_out:
            if fail_closed:
                blocked_reason = (
                    "connect_path_unavailable"
                    if invoke_blocked_reason == "connect_path_unavailable"
                    else "runtime_isolation_unavailable"
                )
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
                    actual_runtime=actual_runtime,
                )
            host_fallback_used = True
            actual_runtime = "host"
            blocked_reason = ""
            if enforce_connect_path:
                connect_path_degraded = True
                connect_path_result = ConnectPathResult(
                    enforced=False,
                    method=(
                        connect_path_result.method if connect_path_result is not None else "none"
                    ),
                    reason="expert_host_fallback",
                )
            stdout, stderr, exit_code, timed_out, invoke_blocked_reason = self.invoke(
                command,
                env=env,
                cwd=config.cwd or None,
                timeout_seconds=config.limits.timeout_seconds,
                preexec=preexec,
                memory_mb=self._memory_monitor_limit_mb(config.limits),
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
            host_fallback_used=host_fallback_used,
            actual_runtime=actual_runtime,
        )

    def wrap_isolated_command(
        self,
        *,
        backend: SandboxBackend,
        config: SandboxConfig,
        command: list[str],
        filesystem_command: list[str] | None = None,
    ) -> list[str]:
        if backend.runtime == self._bwrap and self._bwrap:
            return self.build_bwrap_command(
                config=config,
                command=command,
                filesystem_command=filesystem_command,
            )
        if backend.runtime == self._nsjail and self._nsjail:
            return self.build_nsjail_command(config=config, command=command)
        return list(command)

    def build_bwrap_command(
        self,
        *,
        config: SandboxConfig,
        command: list[str],
        filesystem_command: list[str] | None = None,
        network_block_fd: int | None = None,
        resolv_conf_fd: int | None = None,
        hosts_file_fd: int | None = None,
        info_fd: int | None = None,
    ) -> list[str]:
        args: list[str] = [
            self._bwrap,
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "ALL",
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
            "--unshare-net",
        ]
        if network_block_fd is not None:
            args.extend(["--block-fd", str(network_block_fd)])
        if info_fd is not None:
            args.extend(["--info-fd", str(info_fd)])
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
            cwd_path = Path(config.cwd).expanduser().resolve(strict=False)
            if cwd_path.exists():
                writeable = any(
                    str(cwd_path).startswith(str(Path(path).expanduser()))
                    for path in config.write_paths
                )
                _mark_bind(cwd_path, "rw" if writeable else "ro")

        mount_command = filesystem_command if filesystem_command is not None else command
        executable_mount = self._executable_mount_target(mount_command)
        if executable_mount is not None:
            _mark_bind(executable_mount, "ro")
        cwd_target = Path(config.cwd).expanduser().resolve(strict=False) if config.cwd else None
        for target in self.filesystem_targets_for_command(mount_command, cwd=config.cwd):
            target_path = Path(target)
            if cwd_target is not None and target_path == cwd_target:
                continue
            _mark_bind(target_path, "ro")

        for path, mode in sorted(bind_modes.items(), key=lambda item: len(str(item[0]))):
            if mode == "rw":
                args.extend(["--bind", str(path), str(path)])
            else:
                args.extend(["--ro-bind", str(path), str(path)])

        if resolv_conf_fd is not None:
            args.extend(["--ro-bind-data", str(resolv_conf_fd), "/etc/resolv.conf"])
        if hosts_file_fd is not None:
            args.extend(["--ro-bind-data", str(hosts_file_fd), "/etc/hosts"])

        if config.cwd:
            cwd_path = Path(config.cwd).expanduser().resolve(strict=False)
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
            "--max_cpus",
            "1",
        ]
        address_space_mb = self.address_space_limit_mb(config.limits)
        if address_space_mb > 0:
            args.extend(["--rlimit_as", str(address_space_mb)])
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
    def filesystem_targets_for_command(command: list[str], *, cwd: str | None) -> list[str]:
        """Return implicit filesystem mounts created for a command."""

        targets: list[str] = []
        if cwd:
            cwd_path = Path(cwd).expanduser().resolve(strict=False)
            if cwd_path.exists():
                targets.append(str(cwd_path))
        executable_mount = SandboxProcessRunner._executable_mount_target(command)
        if executable_mount is not None and not any(
            executable_mount.is_relative_to(Path(base).resolve(strict=False))
            for base in _BWRAP_BASE_RO_DIRS
            if Path(base).exists()
        ):
            targets.append(str(executable_mount))
        for token in command[1:]:
            token_path = Path(token).expanduser()
            if not token_path.is_absolute() or not token_path.exists():
                continue
            resolved = token_path.resolve(strict=False)
            mount_target = resolved if resolved.is_dir() else resolved.parent
            rendered = str(mount_target)
            if rendered not in targets:
                targets.append(rendered)
        return targets

    @staticmethod
    def _executable_mount_target(command: list[str]) -> Path | None:
        executable = command[0] if command else ""
        resolved_executable = (
            shutil.which(executable) if executable and not Path(executable).exists() else executable
        )
        if not resolved_executable:
            return None
        executable_path = Path(resolved_executable).expanduser().resolve(strict=False)
        if not executable_path.exists():
            return None
        parent_parent = executable_path.parent.parent
        return parent_parent if parent_parent.exists() else executable_path.parent

    @staticmethod
    def _instrument_command(command: list[str], marker: str) -> list[str]:
        return [
            "/bin/sh",
            "-c",
            'marker="$1"; shift; printf "%s\\n" "$marker" >&2 || exit 125; exec "$@"',
            "shisad-sandbox",
            marker,
            *command,
        ]

    @staticmethod
    def _strip_execution_marker(stderr: str, marker: str) -> tuple[str, bool]:
        found = False
        kept: list[str] = []
        for line in stderr.splitlines(keepends=True):
            if not found and line.rstrip("\r\n") == marker:
                found = True
                continue
            kept.append(line)
        return "".join(kept), found

    @staticmethod
    def _ipv4_addresses(addresses: list[str]) -> list[str]:
        normalized: set[str] = set()
        for raw in addresses:
            try:
                address = ipaddress.ip_address(raw.strip())
            except ValueError:
                continue
            if isinstance(address, ipaddress.IPv4Address):
                normalized.add(str(address))
        return sorted(normalized)

    def _attach_pasta_network(self, namespace_pid: int) -> str:
        if not self._pasta:
            return "pasta_unavailable"
        namespace_error = self._wait_for_isolated_network_namespace(namespace_pid)
        if namespace_error:
            return namespace_error
        try:
            completed = subprocess.run(
                [
                    self._pasta,
                    "--quiet",
                    "--config-net",
                    "--ipv4-only",
                    "--no-map-gw",
                    "--no-splice",
                    "-D",
                    "none",
                    "-t",
                    "none",
                    "-u",
                    "none",
                    "-T",
                    "none",
                    "-U",
                    "none",
                    str(namespace_pid),
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return f"pasta_failed:{exc.__class__.__name__}"
        if completed.returncode != 0:
            return f"pasta_failed:exit_{completed.returncode}"
        return ""

    @staticmethod
    def _wait_for_isolated_network_namespace(namespace_pid: int) -> str:
        try:
            daemon_namespace = os.readlink(f"/proc/{os.getpid()}/ns/net")
        except OSError:
            return "daemon_network_namespace_unavailable"
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                target_namespace = os.readlink(f"/proc/{namespace_pid}/ns/net")
            except OSError:
                if not Path(f"/proc/{namespace_pid}").exists():
                    return "sandbox_process_exited"
                time.sleep(0.01)
                continue
            if target_namespace != daemon_namespace:
                return ""
            time.sleep(0.01)
        return "isolated_network_namespace_unavailable"

    @staticmethod
    def _close_fd(fd: int) -> None:
        try:
            os.close(fd)
        except OSError:
            return

    @staticmethod
    def _network_hosts_file(
        config: SandboxConfig,
        command: list[str],
        allowed_ips: list[str],
    ) -> bytes:
        candidates = [*config.network_urls, *config.network.allowed_domains]
        for token in command:
            if token.startswith(("http://", "https://")):
                candidates.append(token)
            elif token.startswith("--url="):
                candidates.append(token.split("=", 1)[1])

        hostnames: set[str] = set()
        for candidate in candidates:
            raw = candidate.strip()
            if not raw or any(marker in raw for marker in ("*", "?", "[", "]")):
                continue
            parsed = safe_urlparse(raw if "://" in raw else f"https://{raw}")
            hostname = safe_parsed_hostname(parsed, strip_trailing_dot=True)
            if not hostname or any(character.isspace() for character in hostname):
                continue
            try:
                ipaddress.ip_address(hostname)
            except ValueError:
                pass
            else:
                continue
            try:
                ascii_hostname = hostname.encode("idna").decode("ascii")
            except UnicodeError:
                continue
            labels = ascii_hostname.split(".")
            if any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or any(not (character.isalnum() or character == "-") for character in label)
                for label in labels
            ):
                continue
            hostnames.add(ascii_hostname)

        lines = ["127.0.0.1 localhost"]
        for address in allowed_ips:
            for hostname in sorted(hostnames):
                lines.append(f"{address} {hostname}")
        return ("\n".join(lines) + "\n").encode("ascii")

    @staticmethod
    def _create_network_boundary_fds(
        *,
        resolv_conf: bytes,
        hosts_file: bytes,
    ) -> tuple[tuple[int, int, int, int, int, int] | None, str]:
        owned_fds: list[int] = []
        try:
            gate_read_fd, gate_write_fd = os.pipe()
            owned_fds.extend([gate_read_fd, gate_write_fd])
            resolv_read_fd = SandboxProcessRunner._create_data_fd(
                "shisad-resolv-conf",
                resolv_conf,
            )
            owned_fds.append(resolv_read_fd)
            hosts_read_fd = SandboxProcessRunner._create_data_fd(
                "shisad-hosts",
                hosts_file,
            )
            owned_fds.append(hosts_read_fd)
            info_read_fd, info_write_fd = os.pipe()
            owned_fds.extend([info_read_fd, info_write_fd])
        except OSError as exc:
            for fd in owned_fds:
                SandboxProcessRunner._close_fd(fd)
            return None, f"network_setup_failed:{exc.__class__.__name__}"
        return (
            gate_read_fd,
            gate_write_fd,
            resolv_read_fd,
            hosts_read_fd,
            info_read_fd,
            info_write_fd,
        ), ""

    @staticmethod
    def _create_data_fd(name: str, content: bytes) -> int:
        memfd_create = getattr(os, "memfd_create", None)
        if callable(memfd_create):
            fd = memfd_create(name)
            try:
                SandboxProcessRunner._write_fd(fd, content)
            except OSError:
                SandboxProcessRunner._close_fd(fd)
                raise
            return int(fd)
        with tempfile.TemporaryFile(prefix=f"{name}-") as temporary_file:
            temporary_file.write(content)
            temporary_file.flush()
            temporary_file.seek(0)
            return int(os.dup(temporary_file.fileno()))

    @staticmethod
    def _write_fd(fd: int, content: bytes) -> None:
        remaining = memoryview(content)
        while remaining:
            written = os.write(fd, remaining)
            if written <= 0:
                raise OSError("short write while preparing network policy")
            remaining = remaining[written:]
        os.lseek(fd, 0, os.SEEK_SET)

    @staticmethod
    def _read_bwrap_child_pid(info_fd: int) -> int:
        deadline = time.monotonic() + 2
        payload = bytearray()
        try:
            while len(payload) <= 16 * 1024:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return 0
                readable, _, _ = select.select([info_fd], [], [], remaining)
                if not readable:
                    return 0
                chunk = os.read(info_fd, 4096)
                if not chunk:
                    break
                payload.extend(chunk)
        except (OSError, ValueError):
            return 0
        if not payload or len(payload) > 16 * 1024:
            return 0
        try:
            status = json.loads(bytes(payload))
        except (TypeError, ValueError):
            return 0
        child_pid = status.get("child-pid") if isinstance(status, dict) else None
        if isinstance(child_pid, bool) or not isinstance(child_pid, int) or child_pid <= 0:
            return 0
        return int(child_pid)

    @staticmethod
    def address_space_limit_mb(limits: ResourceLimits) -> int:
        if limits.address_space_mb is not None:
            return max(0, int(limits.address_space_mb))
        return max(0, int(limits.memory_mb))

    @staticmethod
    def _memory_monitor_limit_mb(limits: ResourceLimits) -> int:
        if SandboxProcessRunner.address_space_limit_mb(limits) > 0:
            return 0
        return max(0, int(limits.memory_mb))

    @staticmethod
    def preexec_limits(limits: ResourceLimits) -> Any:
        try:
            import resource  # pylint: disable=import-outside-toplevel
        except ImportError:
            return None

        def _apply() -> None:
            errors: list[str] = []
            address_space_mb = SandboxProcessRunner.address_space_limit_mb(limits)
            if address_space_mb > 0:
                memory_bytes = address_space_mb * 1024 * 1024
                try:
                    resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
                except (OSError, ValueError) as exc:  # pragma: no cover - platform dependent
                    errors.append(f"RLIMIT_AS={exc.__class__.__name__}")
            if limits.pids > 0:
                try:
                    resource.setrlimit(resource.RLIMIT_NPROC, (limits.pids, limits.pids))
                except (OSError, ValueError) as exc:  # pragma: no cover - platform dependent
                    errors.append(f"RLIMIT_NPROC={exc.__class__.__name__}")
            if errors:
                os.write(
                    2,
                    (
                        "[shisad sandbox] resource limits degraded: " + ",".join(errors) + "\n"
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
        memory_mb: int = 0,
        pass_fds: tuple[int, ...] = (),
        namespace_pid_fd: int | None = None,
        close_after_spawn_fds: tuple[int, ...] = (),
    ) -> tuple[str, str, int | None, bool, str | None]:
        timed_out = False
        stdout = ""
        stderr = ""
        exit_code: int | None = None
        blocked_reason: str | None = None
        completed: Any | None = None
        try:
            try:
                completed = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    env=env,
                    cwd=cwd,
                    preexec_fn=preexec,
                    pass_fds=pass_fds,
                )
            finally:
                for fd in close_after_spawn_fds:
                    SandboxProcessRunner._close_fd(fd)

            if on_started is not None and completed.pid > 0:
                namespace_pid = completed.pid
                if namespace_pid_fd is not None:
                    namespace_pid = SandboxProcessRunner._read_bwrap_child_pid(namespace_pid_fd)
                try:
                    blocked_reason = on_started(namespace_pid)
                except BaseException as exc:
                    # The callback guards a command blocked before its first effect. Kill the
                    # wrapper before any caller-owned gate FD can be closed during unwinding.
                    SandboxProcessRunner._kill_process_tree(completed)
                    try:
                        stdout, stderr = completed.communicate(timeout=1)
                    except subprocess.TimeoutExpired:
                        SandboxProcessRunner._kill_process_tree(completed)
                        stdout, stderr = completed.communicate()
                    exit_code = completed.returncode
                    if not isinstance(exc, Exception):
                        raise
                    callback_error = f"process start callback failed: {exc.__class__.__name__}"
                    separator = "" if not stderr or stderr.endswith("\n") else "\n"
                    stderr = f"{stderr}{separator}{callback_error}"
                    blocked_reason = f"process_start_callback_failed:{exc.__class__.__name__}"
                    return stdout, stderr, exit_code, timed_out, blocked_reason
                if blocked_reason:
                    SandboxProcessRunner._terminate_process_tree(completed)
                    try:
                        stdout, stderr = completed.communicate(timeout=1)
                    except subprocess.TimeoutExpired:
                        SandboxProcessRunner._kill_process_tree(completed)
                        stdout, stderr = completed.communicate()
                    exit_code = completed.returncode
                    return stdout, stderr, exit_code, timed_out, blocked_reason

            stdout, stderr, exit_code, timed_out, blocked_reason = (
                SandboxProcessRunner._communicate_with_limits(
                    completed,
                    timeout_seconds=timeout_seconds,
                    memory_mb=memory_mb,
                )
            )
        except subprocess.TimeoutExpired as exc:
            if completed is not None:
                SandboxProcessRunner._kill_and_reap(completed)
            timed_out = True
            stdout = SandboxProcessRunner.to_text(exc.stdout)
            stderr = SandboxProcessRunner.to_text(exc.stderr)
            exit_code = None
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            if completed is not None:
                SandboxProcessRunner._kill_and_reap(completed)
            stderr = f"process launch failed: {exc.__class__.__name__}"
            blocked_reason = f"process_launch_failed:{exc.__class__.__name__}"
        return stdout, stderr, exit_code, timed_out, blocked_reason

    @staticmethod
    def _communicate_with_limits(
        process: Any,
        *,
        timeout_seconds: int,
        memory_mb: int,
    ) -> tuple[str, str, int | None, bool, str | None]:
        deadline = time.monotonic() + max(0, int(timeout_seconds))
        memory_limit_bytes = max(0, int(memory_mb or 0)) * 1024 * 1024
        while True:
            if memory_limit_bytes > 0:
                rss_bytes = SandboxProcessRunner._process_tree_rss_bytes(process.pid)
                if rss_bytes > memory_limit_bytes:
                    SandboxProcessRunner._kill_process_tree(process)
                    try:
                        stdout, stderr = process.communicate(timeout=1)
                    except subprocess.TimeoutExpired:
                        SandboxProcessRunner._kill_process_tree(process)
                        stdout, stderr = process.communicate()
                    stderr = SandboxProcessRunner._append_stderr_line(
                        stderr,
                        f"[shisad sandbox] resource limit exceeded: memory_mb={memory_mb}",
                    )
                    return stdout or "", stderr, None, False, "resource_limit_exceeded"

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                SandboxProcessRunner._kill_process_tree(process)
                stdout, stderr = process.communicate()
                return stdout or "", stderr or "", None, True, None
            try:
                poll_timeout = min(0.2, max(0.01, remaining))
                stdout, stderr = process.communicate(timeout=poll_timeout)
                return stdout or "", stderr or "", process.returncode, False, None
            except subprocess.TimeoutExpired:
                continue

    @staticmethod
    def _append_stderr_line(stderr: str | bytes | None, line: str) -> str:
        text = SandboxProcessRunner.to_text(stderr)
        separator = "" if not text or text.endswith("\n") else "\n"
        return f"{text}{separator}{line}\n"

    @staticmethod
    def _terminate_process_tree(process: Any) -> None:
        SandboxProcessRunner._signal_process_tree(process, signal.SIGTERM)
        try:
            process.terminate()
        except ProcessLookupError:
            return

    @staticmethod
    def _kill_process_tree(process: Any) -> None:
        kill_signal = SandboxProcessRunner._process_kill_signal()
        if kill_signal is not None:
            SandboxProcessRunner._signal_process_tree(process, kill_signal)
        try:
            process.kill()
        except ProcessLookupError:
            return

    @staticmethod
    def _kill_and_reap(process: Any) -> None:
        SandboxProcessRunner._kill_process_tree(process)
        try:
            process.wait(timeout=1)
        except (OSError, subprocess.SubprocessError, ValueError):
            return

    @staticmethod
    def _process_kill_signal() -> signal.Signals | None:
        sigkill = getattr(signal, "SIGKILL", None)
        return sigkill if isinstance(sigkill, signal.Signals) else None

    @staticmethod
    def _signal_process_tree(process: Any, signum: int) -> None:
        root_pid = int(getattr(process, "pid", 0) or 0)
        for pid in reversed(SandboxProcessRunner._process_tree_pids(root_pid)):
            try:
                os.kill(pid, signum)
            except (OSError, ProcessLookupError, PermissionError):
                continue

    @staticmethod
    def _process_tree_pids(root_pid: int) -> list[int]:
        if root_pid <= 0:
            return []
        seen: set[int] = set()
        pending = [root_pid]
        ordered: list[int] = []
        while pending:
            pid = pending.pop()
            if pid in seen:
                continue
            seen.add(pid)
            ordered.append(pid)
            pending.extend(SandboxProcessRunner._child_pids(pid))
        return ordered

    @staticmethod
    def _child_pids(pid: int) -> list[int]:
        try:
            raw = (Path("/proc") / str(pid) / "task" / str(pid) / "children").read_text(
                encoding="utf-8"
            )
        except OSError:
            return []
        children: list[int] = []
        for token in raw.split():
            try:
                children.append(int(token))
            except ValueError:
                continue
        return children

    @staticmethod
    def _process_tree_rss_bytes(root_pid: int) -> int:
        return sum(
            SandboxProcessRunner._process_rss_bytes(pid)
            for pid in SandboxProcessRunner._process_tree_pids(root_pid)
        )

    @staticmethod
    def _process_rss_bytes(pid: int) -> int:
        try:
            parts = (Path("/proc") / str(pid) / "statm").read_text(encoding="utf-8").split()
            resident_pages = int(parts[1])
        except (OSError, IndexError, ValueError):
            return 0
        try:
            page_size = int(os.sysconf("SC_PAGE_SIZE"))
        except (OSError, ValueError):
            page_size = 4096
        return resident_pages * page_size

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
