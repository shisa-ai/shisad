"""Sandbox runtime models and backend metadata."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from shisad.executors.connect_path import ConnectPathResult
from shisad.executors.mounts import FilesystemAccessDecision, FilesystemPolicy
from shisad.executors.proxy import NetworkPolicy, ProxyDecision


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
    origin: dict[str, str] = Field(default_factory=dict)


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
    connect_path: ConnectPathResult | None = None
    action_hash: str = ""
    origin: dict[str, str] = Field(default_factory=dict)


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


__all__ = [
    "DegradedModePolicy",
    "EnvironmentPolicy",
    "ResourceLimits",
    "SandboxBackend",
    "SandboxConfig",
    "SandboxEnforcement",
    "SandboxInstance",
    "SandboxResult",
    "SandboxType",
]
