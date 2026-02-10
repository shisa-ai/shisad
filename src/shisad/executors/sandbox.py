"""Sandbox orchestrator for tool execution."""

from __future__ import annotations

import contextlib
import os
import re
import subprocess
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from shisad.core.session import CheckpointStore, Session
from shisad.executors.mounts import FilesystemAccessDecision, FilesystemPolicy, MountManager
from shisad.executors.proxy import EgressProxy, NetworkPolicy, ProxyDecision

_DESTRUCTIVE_GIT_ARGS = {
    ("reset", "--hard"),
    ("clean", "-fd"),
    ("clean", "-xdf"),
}
_ESCAPE_SIGNAL_TOKENS = {
    "unshare",
    "nsenter",
    "setns",
    "mount",
    "chroot",
    "ptrace",
}


class SandboxType(StrEnum):
    """Sandbox backend type."""

    CONTAINER = "container"
    NSJAIL = "nsjail"


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
    approved_by_pep: bool = True


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


class SandboxBackend:
    """Backend adapter with declared enforcement capabilities."""

    def __init__(self, *, backend: SandboxType, enforcement: SandboxEnforcement) -> None:
        self.backend = backend
        self.enforcement = enforcement

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
        self._backends: dict[SandboxType, SandboxBackend] = {
            SandboxType.CONTAINER: SandboxBackend(
                backend=SandboxType.CONTAINER,
                enforcement=SandboxEnforcement(
                    filesystem=True,
                    network=True,
                    env=True,
                    seccomp=True,
                    resource_limits=True,
                    cgroups=False,
                    dns_control=True,
                ),
            ),
            SandboxType.NSJAIL: SandboxBackend(
                backend=SandboxType.NSJAIL,
                enforcement=SandboxEnforcement(
                    filesystem=True,
                    network=False,
                    env=True,
                    seccomp=True,
                    resource_limits=True,
                    cgroups=False,
                    dns_control=False,
                ),
            ),
        }

    def execute(
        self,
        config: SandboxConfig,
        *,
        session: Session | None = None,
    ) -> SandboxResult:
        backend_type = self._select_backend(config)
        backend = self._backends[backend_type]
        degraded_controls = self._degraded_controls(config, backend.enforcement)
        if degraded_controls and config.degraded_mode == DegradedModePolicy.FAIL_CLOSED:
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

        env, env_err = self._build_environment(config.environment, config.env)
        if env_err is not None:
            return SandboxResult(
                allowed=False,
                reason=env_err,
                backend=backend_type,
                degraded_controls=degraded_controls,
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
                approved_by_pep=config.approved_by_pep,
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

        escape_reason = self._escape_signal_reason(config.command)
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
                    "command": list(config.command),
                    "write_paths": list(config.write_paths),
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
            process = self._run_process(config, env=env)
        finally:
            backend.destroy(instance)

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

    def _run_process(self, config: SandboxConfig, *, env: dict[str, str]) -> dict[str, Any]:
        cwd = config.cwd or None
        timed_out = False
        truncated = False
        stdout = ""
        stderr = ""
        exit_code: int | None = None

        preexec = self._preexec_limits(config.limits)
        try:
            completed = subprocess.run(
                config.command,
                capture_output=True,
                text=True,
                timeout=config.limits.timeout_seconds,
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
            stdout = self._to_text(exc.stdout)
            stderr = self._to_text(exc.stderr)
            exit_code = None

        max_bytes = max(1, config.limits.output_bytes)
        stdout_bytes = stdout.encode("utf-8", errors="ignore")
        stderr_bytes = stderr.encode("utf-8", errors="ignore")
        if len(stdout_bytes) > max_bytes:
            truncated = True
            stdout = stdout_bytes[:max_bytes].decode("utf-8", errors="ignore")
        if len(stderr_bytes) > max_bytes:
            truncated = True
            stderr = stderr_bytes[:max_bytes].decode("utf-8", errors="ignore")

        return {
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "truncated": truncated,
        }

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
        required: set[str] = {"env", "resource_limits"}
        if config.read_paths or config.write_paths:
            required.add("filesystem")
        if config.network.allow_network or config.network_urls:
            required.update({"network", "dns_control"})
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
    ) -> tuple[dict[str, str], str | None]:
        defaults: dict[str, str] = {}
        for key in policy.allowed_keys:
            if key in os.environ:
                defaults[key] = os.environ[key]

        sanitized = dict(defaults)
        for key, value in requested.items():
            if key not in policy.allowed_keys:
                continue
            if any(key.startswith(prefix) for prefix in policy.denied_prefixes):
                return {}, f"env_key_denied:{key}"
            sanitized[key] = value

        if len(sanitized) > policy.max_keys:
            return {}, "env_too_many_keys"
        total_bytes = 0
        for key, value in sanitized.items():
            total_bytes += len(key.encode("utf-8")) + len(value.encode("utf-8")) + 1
        if total_bytes > policy.max_total_bytes:
            return {}, "env_too_large"
        return sanitized, None

    @staticmethod
    def _preexec_limits(limits: ResourceLimits) -> Any:
        try:
            import resource  # pylint: disable=import-outside-toplevel
        except Exception:
            return None

        def _apply() -> None:
            memory_bytes = limits.memory_mb * 1024 * 1024
            with contextlib.suppress(Exception):
                resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
            with contextlib.suppress(Exception):
                resource.setrlimit(resource.RLIMIT_NPROC, (limits.pids, limits.pids))

        return _apply

    @staticmethod
    def is_destructive(command: list[str]) -> bool:
        if not command:
            return False
        executable = Path(command[0]).name
        if executable in {"rm", "rmdir", "truncate", "dd"}:
            return True
        if executable == "mv":
            return True
        if executable == "git":
            for first, second in _DESTRUCTIVE_GIT_ARGS:
                if len(command) >= 3 and command[1] == first and command[2] == second:
                    return True
            return len(command) >= 3 and command[1] == "reset" and command[2].startswith("--hard")
        return False

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
        if command and Path(command[0]).name in {"nslookup", "dig", "host"} and len(command) >= 2:
            host = command[-1].strip()
            if host and "://" not in host:
                targets.append(f"https://{host}/")
        return targets

    @staticmethod
    def _command_attempts_network(command: list[str]) -> bool:
        if not command:
            return False
        executable = Path(command[0]).name
        return executable in {
            "curl",
            "wget",
            "nc",
            "ncat",
            "telnet",
            "ping",
            "nslookup",
            "dig",
            "host",
        }

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
