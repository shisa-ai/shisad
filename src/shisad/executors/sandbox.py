"""Sandbox orchestrator for tool execution."""

from __future__ import annotations

import asyncio
import base64
import os
import re
import shutil
import subprocess
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from functools import partial
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from shisad.core.session import CheckpointStore, Session
from shisad.executors.mounts import FilesystemAccessDecision, FilesystemPolicy, MountManager
from shisad.executors.proxy import EgressProxy, NetworkPolicy, ProxyDecision
from shisad.security.credentials import is_placeholder

_ESCAPE_SIGNAL_TOKENS = {
    "unshare",
    "nsenter",
    "setns",
    "mount",
    "chroot",
    "ptrace",
}
_NETWORK_EXECUTABLES = {
    "curl",
    "wget",
    "nc",
    "ncat",
    "telnet",
    "ping",
    "nslookup",
    "dig",
    "host",
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "ftp",
    "socat",
}
_DOMAIN_TOKEN_RE = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?::\d+)?$")
_SHELL_REDIRECT_RE = re.compile(r"(^|[^>])>([^>]|$)")
_PLACEHOLDER_RE = re.compile(r"SHISAD_SECRET_PLACEHOLDER_[A-Fa-f0-9]{32}")
_BWRAP_BASE_RO_DIRS = ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc")
_CHECKPOINT_FILE_SNAPSHOT_LIMIT = 1_000_000


class SandboxType(StrEnum):
    """Sandbox backend type."""

    CONTAINER = "container"
    NSJAIL = "nsjail"
    VM = "vm"


class DegradedModePolicy(StrEnum):
    """Behavior when requested controls cannot be fully enforced."""

    FAIL_CLOSED = "fail_closed"
    FAIL_OPEN = "fail_open"


class ResourceLimits(BaseModel):
    """Execution resource limits."""

    cpu_shares: int = 256
    memory_mb: int = 512
    timeout_seconds: int = 60
    output_bytes: int = 1_000_000
    pids: int = 100


class EnvironmentPolicy(BaseModel):
    """Allowed process environment surface."""

    allowed_keys: list[str] = Field(default_factory=lambda: ["PATH", "LANG", "TERM", "HOME"])
    denied_prefixes: list[str] = Field(
        default_factory=lambda: [
            "LD_",
            "DYLD_",
            "PYTHONSTARTUP",
            "PYTHONPATH",
            "PROMPT_COMMAND",
            "BASH_ENV",
        ]
    )
    max_keys: int = 32
    max_total_bytes: int = 8192


class SandboxEnforcement(BaseModel):
    """Backend enforcement capability report."""

    filesystem: bool = True
    network: bool = True
    env: bool = True
    seccomp: bool = True
    resource_limits: bool = True
    cgroups: bool = False
    dns_control: bool = True


class SandboxConfig(BaseModel):
    """Tool execution request for sandbox runtime."""

    tool_name: str
    command: list[str]
    sandbox_type: SandboxType | None = None
    session_id: str = ""
    read_paths: list[str] = Field(default_factory=list)
    write_paths: list[str] = Field(default_factory=list)
    network_urls: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    cwd: str = ""
    filesystem: FilesystemPolicy = Field(default_factory=FilesystemPolicy)
    network: NetworkPolicy = Field(default_factory=NetworkPolicy)
    environment: EnvironmentPolicy = Field(default_factory=EnvironmentPolicy)
    limits: ResourceLimits = Field(default_factory=ResourceLimits)
    degraded_mode: DegradedModePolicy = DegradedModePolicy.FAIL_CLOSED
    security_critical: bool = True
    approved_by_pep: bool = False
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str = ""


class SandboxInstance(BaseModel):
    """Sandbox execution instance metadata."""

    instance_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    backend: SandboxType
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SandboxResult(BaseModel):
    """Sandbox execution result."""

    allowed: bool
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    truncated: bool = False
    reason: str = ""
    backend: SandboxType | None = None
    checkpoint_id: str = ""
    escape_detected: bool = False
    degraded_controls: list[str] = Field(default_factory=list)
    fs_decisions: list[FilesystemAccessDecision] = Field(default_factory=list)
    network_decisions: list[ProxyDecision] = Field(default_factory=list)
    rollback_files_restored: int = 0


class SandboxBackend:
    """Backend adapter with declared enforcement capabilities."""

    def __init__(
        self,
        *,
        backend: SandboxType,
        enforcement: SandboxEnforcement,
        runtime: str = "",
    ) -> None:
        self.backend = backend
        self.enforcement = enforcement
        self.runtime = runtime

    def create(self, _config: SandboxConfig) -> SandboxInstance:
        return SandboxInstance(backend=self.backend)

    def destroy(self, _instance: SandboxInstance) -> None:
        return


class SandboxOrchestrator:
    """Selects and executes sandboxed tool calls with policy enforcement."""

    def __init__(
        self,
        *,
        proxy: EgressProxy,
        checkpoint_store: CheckpointStore | None = None,
        audit_hook: Callable[[dict[str, object]], None] | None = None,
    ) -> None:
        self._proxy = proxy
        self._checkpoint_store = checkpoint_store
        self._audit_hook = audit_hook
        self._bwrap = self._detect_usable_bwrap()
        self._nsjail = shutil.which("nsjail") or ""
        container_runtime = self._bwrap
        nsjail_runtime = self._nsjail or self._bwrap
        vm_runtime = self._bwrap
        self._backends: dict[SandboxType, SandboxBackend] = {
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

    async def execute_async(
        self,
        config: SandboxConfig,
        *,
        session: Session | None = None,
    ) -> SandboxResult:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, partial(self.execute, config, session=session))

    def execute(
        self,
        config: SandboxConfig,
        *,
        session: Session | None = None,
    ) -> SandboxResult:
        if not config.command:
            return SandboxResult(allowed=False, reason="invalid_command")
        backend_type = self._select_backend(config)
        backend = self._backends[backend_type]
        degraded_controls = self._degraded_controls(config, backend.enforcement)
        if degraded_controls and (
            config.degraded_mode == DegradedModePolicy.FAIL_CLOSED or config.security_critical
        ):
            self._audit(
                "sandbox.degraded",
                {
                    "tool_name": config.tool_name,
                    "backend": backend_type.value,
                    "controls": degraded_controls,
                },
            )
            return SandboxResult(
                allowed=False,
                reason="degraded_enforcement",
                backend=backend_type,
                degraded_controls=degraded_controls,
            )

        env, env_err, dropped_env_keys = self._build_environment(config.environment, config.env)
        if env_err is not None:
            return SandboxResult(
                allowed=False,
                reason=env_err,
                backend=backend_type,
                degraded_controls=degraded_controls,
            )
        if dropped_env_keys:
            self._audit(
                "sandbox.env_sanitized",
                {
                    "tool_name": config.tool_name,
                    "dropped_keys": dropped_env_keys,
                    "session_id": config.session_id,
                },
            )

        mount_manager = MountManager(config.filesystem)
        fs_decisions: list[FilesystemAccessDecision] = []
        for path in config.read_paths:
            decision = mount_manager.check_access(path, write=False)
            fs_decisions.append(decision)
            if not decision.allowed:
                self._audit(
                    "sandbox.fs_deny",
                    {"tool_name": config.tool_name, "path": path, "reason": decision.reason},
                )
                return SandboxResult(
                    allowed=False,
                    reason=f"filesystem:{decision.reason}",
                    backend=backend_type,
                    fs_decisions=fs_decisions,
                    degraded_controls=degraded_controls,
                )
        for path in config.write_paths:
            decision = mount_manager.check_access(path, write=True)
            fs_decisions.append(decision)
            if not decision.allowed:
                self._audit(
                    "sandbox.fs_deny",
                    {"tool_name": config.tool_name, "path": path, "reason": decision.reason},
                )
                return SandboxResult(
                    allowed=False,
                    reason=f"filesystem:{decision.reason}",
                    backend=backend_type,
                    fs_decisions=fs_decisions,
                    degraded_controls=degraded_controls,
                )

        network_decisions: list[ProxyDecision] = []
        network_urls = list(config.network_urls)
        network_urls.extend(self._extract_network_targets(config.command))
        if not network_urls and not config.network.allow_network and self._command_attempts_network(
            config.command
        ):
            return SandboxResult(
                allowed=False,
                reason="network:network_disabled",
                backend=backend_type,
                fs_decisions=fs_decisions,
                network_decisions=network_decisions,
                degraded_controls=degraded_controls,
            )

        for url in network_urls:
            network_decision = self._proxy.authorize_request(
                tool_name=config.tool_name,
                url=url,
                policy=config.network,
                headers=config.request_headers,
                body=config.request_body,
                approved_by_pep=config.approved_by_pep,
            )
            if network_decision.injected_headers:
                network_decision = network_decision.model_copy(
                    update={
                        "injected_headers": {
                            key: "[redacted]"
                            for key in network_decision.injected_headers
                        }
                    }
                )
            network_decisions.append(network_decision)
            if not network_decision.allowed:
                return SandboxResult(
                    allowed=False,
                    reason=f"network:{network_decision.reason}",
                    backend=backend_type,
                    fs_decisions=fs_decisions,
                    network_decisions=network_decisions,
                    degraded_controls=degraded_controls,
                )

        command, env, inject_err = self._inject_credentials(
            command=config.command,
            env=env,
            network_decisions=network_decisions,
            approved_by_pep=config.approved_by_pep,
        )
        if inject_err is not None:
            return SandboxResult(
                allowed=False,
                reason=f"network:{inject_err}",
                backend=backend_type,
                fs_decisions=fs_decisions,
                network_decisions=network_decisions,
                degraded_controls=degraded_controls,
            )

        for url, prior in zip(network_urls, network_decisions, strict=False):
            revalidated = self._proxy.authorize_request(
                tool_name=config.tool_name,
                url=url,
                policy=config.network,
                approved_by_pep=config.approved_by_pep,
                expected_addresses=list(prior.resolved_addresses),
            )
            if not revalidated.allowed:
                return SandboxResult(
                    allowed=False,
                    reason=f"network:{revalidated.reason}",
                    backend=backend_type,
                    fs_decisions=fs_decisions,
                    network_decisions=network_decisions,
                    degraded_controls=degraded_controls,
                )

        escape_reason = self._escape_signal_reason(command)
        if escape_reason is not None:
            self._audit(
                "sandbox.escape_detected",
                {
                    "tool_name": config.tool_name,
                    "reason": escape_reason,
                    "session_id": config.session_id,
                },
            )
            return SandboxResult(
                allowed=False,
                reason=escape_reason,
                backend=backend_type,
                escape_detected=True,
                fs_decisions=fs_decisions,
                network_decisions=network_decisions,
                degraded_controls=degraded_controls,
            )

        checkpoint_id = ""
        if (
            self._checkpoint_store is not None
            and session is not None
            and self.is_destructive(config.command)
        ):
            checkpoint = self._checkpoint_store.create(
                session,
                state={
                    "session": session.model_dump(mode="json"),
                    "tool_name": config.tool_name,
                    "command": list(command),
                    "write_paths": list(config.write_paths),
                    "filesystem_snapshot": self._capture_filesystem_snapshot(config.write_paths),
                    "created_at": datetime.now(UTC).isoformat(),
                },
            )
            checkpoint_id = checkpoint.checkpoint_id
            self._audit(
                "sandbox.pre_checkpoint",
                {
                    "session_id": config.session_id,
                    "checkpoint_id": checkpoint_id,
                    "tool_name": config.tool_name,
                },
            )

        instance = backend.create(config)
        try:
            process = self._run_process(
                config,
                backend=backend,
                command=command,
                env=env,
            )
        finally:
            backend.destroy(instance)

        if process["resource_limit_warning"]:
            warning = process["resource_limit_warning"]
            degraded_controls = sorted({*degraded_controls, "resource_limits"})
            self._audit(
                "sandbox.resource_limit_degraded",
                {
                    "tool_name": config.tool_name,
                    "warning": warning,
                    "session_id": config.session_id,
                },
            )
        if process["isolation_degraded"]:
            degraded_controls = sorted({*degraded_controls, "runtime_isolation"})
            self._audit(
                "sandbox.runtime_degraded",
                {
                    "tool_name": config.tool_name,
                    "backend": backend_type.value,
                    "session_id": config.session_id,
                },
            )
        if process["blocked_reason"]:
            return SandboxResult(
                allowed=False,
                reason=process["blocked_reason"],
                backend=backend_type,
                checkpoint_id=checkpoint_id,
                fs_decisions=fs_decisions,
                network_decisions=network_decisions,
                degraded_controls=degraded_controls,
            )

        return SandboxResult(
            allowed=True,
            exit_code=process["exit_code"],
            stdout=process["stdout"],
            stderr=process["stderr"],
            timed_out=process["timed_out"],
            truncated=process["truncated"],
            reason="allowed",
            backend=backend_type,
            checkpoint_id=checkpoint_id,
            fs_decisions=fs_decisions,
            network_decisions=network_decisions,
            degraded_controls=degraded_controls,
        )

    def _run_process(
        self,
        config: SandboxConfig,
        *,
        backend: SandboxBackend,
        command: list[str],
        env: dict[str, str],
    ) -> dict[str, Any]:
        cwd = config.cwd or None
        truncated = False
        resource_limit_warning = ""
        isolation_degraded = False
        blocked_reason = ""

        run_command = list(command)
        run_env = env
        wrapped_used = False
        fail_closed = (
            config.degraded_mode == DegradedModePolicy.FAIL_CLOSED or config.security_critical
        )
        if backend.runtime:
            wrapped = self._wrap_isolated_command(
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
                    return {
                        "stdout": "",
                        "stderr": "",
                        "exit_code": None,
                        "timed_out": False,
                        "truncated": truncated,
                        "resource_limit_warning": resource_limit_warning,
                        "isolation_degraded": isolation_degraded,
                        "blocked_reason": blocked_reason,
                    }
        else:
            isolation_degraded = True
            if fail_closed:
                blocked_reason = "runtime_isolation_unavailable"
                return {
                    "stdout": "",
                    "stderr": "",
                    "exit_code": None,
                    "timed_out": False,
                    "truncated": truncated,
                    "resource_limit_warning": resource_limit_warning,
                    "isolation_degraded": isolation_degraded,
                    "blocked_reason": blocked_reason,
                }

        preexec = self._preexec_limits(config.limits)
        stdout, stderr, exit_code, timed_out = self._invoke(
            run_command,
            env=run_env,
            cwd=cwd,
            timeout_seconds=config.limits.timeout_seconds,
            preexec=preexec,
        )

        if wrapped_used and self._isolation_runtime_failed(exit_code=exit_code, stderr=stderr):
            isolation_degraded = True
            if fail_closed:
                blocked_reason = "runtime_isolation_unavailable"
                return {
                    "stdout": stdout,
                    "stderr": stderr,
                    "exit_code": exit_code,
                    "timed_out": timed_out,
                    "truncated": truncated,
                    "resource_limit_warning": resource_limit_warning,
                    "isolation_degraded": isolation_degraded,
                    "blocked_reason": blocked_reason,
                }
            stdout, stderr, exit_code, timed_out = self._invoke(
                command,
                env=env,
                cwd=config.cwd or None,
                timeout_seconds=config.limits.timeout_seconds,
                preexec=preexec,
            )

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

        return {
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "truncated": truncated,
            "resource_limit_warning": resource_limit_warning,
            "isolation_degraded": isolation_degraded,
            "blocked_reason": blocked_reason,
        }

    @staticmethod
    def _invoke(
        command: list[str],
        *,
        env: dict[str, str],
        cwd: str | None,
        timeout_seconds: int,
        preexec: Any,
    ) -> tuple[str, str, int | None, bool]:
        timed_out = False
        stdout = ""
        stderr = ""
        exit_code: int | None = None
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                env=env,
                cwd=cwd,
                preexec_fn=preexec,
                check=False,
            )
            stdout = completed.stdout
            stderr = completed.stderr
            exit_code = completed.returncode
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = SandboxOrchestrator._to_text(exc.stdout)
            stderr = SandboxOrchestrator._to_text(exc.stderr)
            exit_code = None
        return stdout, stderr, exit_code, timed_out

    @staticmethod
    def _isolation_runtime_failed(*, exit_code: int | None, stderr: str) -> bool:
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

    def _select_backend(self, config: SandboxConfig) -> SandboxType:
        if config.sandbox_type is not None:
            return config.sandbox_type
        if config.network.allow_network or config.network_urls:
            return SandboxType.CONTAINER
        if config.write_paths or config.read_paths:
            return SandboxType.NSJAIL
        return SandboxType.NSJAIL

    def _degraded_controls(
        self,
        config: SandboxConfig,
        enforcement: SandboxEnforcement,
    ) -> list[str]:
        required: set[str] = {"filesystem", "network", "env", "resource_limits"}
        if config.network.allow_network or config.network_urls:
            required.add("dns_control")
        if config.security_critical:
            required.add("seccomp")

        degraded: list[str] = []
        capability_map = {
            "filesystem": enforcement.filesystem,
            "network": enforcement.network,
            "env": enforcement.env,
            "seccomp": enforcement.seccomp,
            "resource_limits": enforcement.resource_limits,
            "cgroups": enforcement.cgroups,
            "dns_control": enforcement.dns_control,
        }
        for control in sorted(required):
            if not capability_map.get(control, False):
                degraded.append(control)
        return degraded

    def _build_environment(
        self,
        policy: EnvironmentPolicy,
        requested: dict[str, str],
    ) -> tuple[dict[str, str], str | None, list[str]]:
        defaults: dict[str, str] = {}
        for key in policy.allowed_keys:
            if key in os.environ:
                defaults[key] = os.environ[key]

        sanitized = dict(defaults)
        dropped_keys: list[str] = []
        for key, value in requested.items():
            if key not in policy.allowed_keys:
                dropped_keys.append(key)
                continue
            if any(key.startswith(prefix) for prefix in policy.denied_prefixes):
                return {}, f"env_key_denied:{key}", dropped_keys
            sanitized[key] = value

        if len(sanitized) > policy.max_keys:
            return {}, "env_too_many_keys", dropped_keys
        total_bytes = 0
        for key, value in sanitized.items():
            total_bytes += len(key.encode("utf-8")) + len(value.encode("utf-8")) + 1
        if total_bytes > policy.max_total_bytes:
            return {}, "env_too_large", dropped_keys
        return sanitized, None, dropped_keys

    @staticmethod
    def _preexec_limits(limits: ResourceLimits) -> Any:
        try:
            import resource  # pylint: disable=import-outside-toplevel
        except Exception:
            return None

        def _apply() -> None:
            memory_bytes = limits.memory_mb * 1024 * 1024
            errors: list[str] = []
            try:
                resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
            except Exception as exc:  # pragma: no cover - platform dependent
                errors.append(f"RLIMIT_AS={exc.__class__.__name__}")
            try:
                resource.setrlimit(resource.RLIMIT_NPROC, (limits.pids, limits.pids))
            except Exception as exc:  # pragma: no cover - platform dependent
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
    def is_destructive(command: list[str]) -> bool:
        if not command:
            return False
        executable = Path(command[0]).name
        if executable in {"rm", "rmdir", "truncate", "dd", "shred"}:
            return True
        if executable in {"mv", "chmod", "chown"}:
            return True
        if executable == "cp" and len(command) >= 3 and command[1] == "/dev/null":
            return True
        if executable == "sed" and any(arg == "-i" or arg.startswith("-i") for arg in command[1:]):
            return True
        if executable == "tee" and "-a" not in command[1:]:
            return True
        if executable == "git":
            if len(command) < 2:
                return False
            subcommand = command[1]
            args = command[2:]
            if subcommand == "reset" and any(
                arg == "--hard" or arg.startswith("--hard=") for arg in command[2:]
            ):
                return True
            if subcommand == "clean":
                flag_tokens = [arg for arg in args if arg.startswith("-")]
                if any("f" in token for token in flag_tokens) or "--force" in args:
                    return True
            if subcommand == "push" and any(
                arg in {"-f", "--force", "--force-with-lease"} or arg.startswith("--force")
                for arg in command[2:]
            ):
                return True
        return executable in {"sh", "bash", "zsh"} and any(
            _SHELL_REDIRECT_RE.search(token) for token in command[1:]
        )

    @staticmethod
    def _escape_signal_reason(command: list[str]) -> str | None:
        lowered = " ".join(command).lower()
        for token in _ESCAPE_SIGNAL_TOKENS:
            if re.search(rf"\b{re.escape(token)}\b", lowered):
                return f"escape_signal:{token}"
        return None

    @staticmethod
    def _extract_network_targets(command: list[str]) -> list[str]:
        targets: list[str] = []
        for token in command:
            if token.startswith(("http://", "https://")):
                targets.append(token)
                continue
            if token.startswith("--url="):
                targets.append(token.split("=", 1)[1])
                continue
            if token.startswith(("ftp://", "ftps://")):
                targets.append(token.replace("ftp://", "https://", 1))
                continue
            if "=" in token:
                _, rhs = token.split("=", 1)
                if rhs.startswith(("http://", "https://")):
                    targets.append(rhs)
                    continue
            if _DOMAIN_TOKEN_RE.match(token):
                host = token
                if "://" in host:
                    parsed = urlparse(host)
                    host = parsed.hostname or ""
                if host:
                    targets.append(f"https://{host}/")
        if command and Path(command[0]).name in {"nslookup", "dig", "host"} and len(command) >= 2:
            host = command[-1].strip()
            if host and "://" not in host:
                targets.append(f"https://{host}/")
        deduped: list[str] = []
        seen: set[str] = set()
        for target in targets:
            if target not in seen:
                deduped.append(target)
                seen.add(target)
        return deduped

    @staticmethod
    def _command_attempts_network(command: list[str]) -> bool:
        if not command:
            return False
        executable = Path(command[0]).name
        if executable in _NETWORK_EXECUTABLES:
            return True
        return any(
            token.startswith(("http://", "https://", "ftp://", "ftps://"))
            or _DOMAIN_TOKEN_RE.match(token)
            for token in command[1:]
        )

    @staticmethod
    def _to_text(value: bytes | str | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="ignore")
        return value

    def _audit(self, action: str, payload: dict[str, object]) -> None:
        if self._audit_hook is None:
            return
        self._audit_hook({"action": action, **payload})

    def _inject_credentials(
        self,
        *,
        command: list[str],
        env: dict[str, str],
        network_decisions: list[ProxyDecision],
        approved_by_pep: bool,
    ) -> tuple[list[str], dict[str, str], str | None]:
        hosts = [d.destination_host for d in network_decisions if d.allowed and d.destination_host]
        if not hosts:
            return list(command), dict(env), None

        resolved_cache: dict[str, str] = {}

        def _resolve_placeholder(value: str) -> tuple[str | None, str | None]:
            if value in resolved_cache:
                return resolved_cache[value], None
            if not is_placeholder(value):
                return None, None
            if not approved_by_pep:
                return None, "pep_not_approved"
            for host in hosts:
                resolved = self._proxy.resolve_placeholder(
                    placeholder=value,
                    host=host,
                    approved_by_pep=approved_by_pep,
                )
                if resolved is not None:
                    resolved_cache[value] = resolved
                    return resolved, None
            return None, "credential_host_mismatch"

        transformed_command: list[str] = []
        for token in command:
            replaced = token
            if is_placeholder(token):
                resolved, reason = _resolve_placeholder(token)
                if resolved is None:
                    return [], {}, reason or "credential_host_mismatch"
                replaced = resolved
            else:
                for placeholder in _PLACEHOLDER_RE.findall(token):
                    resolved, reason = _resolve_placeholder(placeholder)
                    if resolved is None:
                        return [], {}, reason or "credential_host_mismatch"
                    replaced = replaced.replace(placeholder, resolved)
            transformed_command.append(replaced)

        transformed_env: dict[str, str] = {}
        for key, value in env.items():
            replaced = value
            if is_placeholder(value):
                resolved, reason = _resolve_placeholder(value)
                if resolved is None:
                    return [], {}, reason or "credential_host_mismatch"
                replaced = resolved
            else:
                for placeholder in _PLACEHOLDER_RE.findall(value):
                    resolved, reason = _resolve_placeholder(placeholder)
                    if resolved is None:
                        return [], {}, reason or "credential_host_mismatch"
                    replaced = replaced.replace(placeholder, resolved)
            transformed_env[key] = replaced
        return transformed_command, transformed_env, None

    def _wrap_isolated_command(
        self,
        *,
        backend: SandboxBackend,
        config: SandboxConfig,
        command: list[str],
    ) -> list[str]:
        if backend.runtime == self._bwrap and self._bwrap:
            return self._build_bwrap_command(config=config, command=command)
        if backend.runtime == self._nsjail and self._nsjail:
            return self._build_nsjail_command(config=config, command=command)
        return list(command)

    def _build_bwrap_command(self, *, config: SandboxConfig, command: list[str]) -> list[str]:
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

    def _build_nsjail_command(self, *, config: SandboxConfig, command: list[str]) -> list[str]:
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
        except Exception:
            return ""
        if completed.returncode != 0:
            return ""
        return binary

    @staticmethod
    def _capture_filesystem_snapshot(paths: list[str]) -> list[dict[str, Any]]:
        snapshots: list[dict[str, Any]] = []
        seen: set[str] = set()
        for raw in paths:
            candidate = Path(raw).expanduser()
            normalized = str(candidate)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            entry: dict[str, Any] = {"path": normalized, "existed": candidate.exists()}
            if candidate.exists() and candidate.is_file():
                try:
                    data = candidate.read_bytes()
                    if len(data) > _CHECKPOINT_FILE_SNAPSHOT_LIMIT:
                        entry["snapshot_skipped"] = "file_too_large"
                    else:
                        entry["content_b64"] = base64.b64encode(data).decode("utf-8")
                except Exception:
                    entry["snapshot_skipped"] = "read_error"
            snapshots.append(entry)
        return snapshots
