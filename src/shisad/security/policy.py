"""Policy system for shisad.

Loads and validates YAML policy bundles that define tool permissions,
egress rules, and filesystem access controls. Policy files are trusted
configuration — loaded from designated paths only, with hash verification
to detect tampering.
"""

from __future__ import annotations

import hashlib
import logging
import signal
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, model_validator

from shisad.core.types import Capability, ToolName

logger = logging.getLogger(__name__)


# --- Policy bundle schema ---


class ToolPolicy(BaseModel):
    """Per-tool policy entry."""

    capabilities_required: list[Capability] = Field(default_factory=list)
    require_confirmation: bool = False
    allowed_args: dict[str, Any] | None = None
    description: str = ""


class EgressRule(BaseModel):
    """Egress allowlist entry."""

    host: str
    ports: list[int] = Field(default_factory=lambda: [443])
    protocols: list[str] = Field(default_factory=lambda: ["https"])


class FilesystemRule(BaseModel):
    """Filesystem access rule."""

    path: str
    mode: str = "read"  # "read" | "write" | "deny"


class RiskPolicy(BaseModel):
    """Risk scoring thresholds and policy version metadata."""

    version: str = "v1"
    auto_approve_threshold: float = 0.45
    block_threshold: float = 0.85


class RateLimitPolicy(BaseModel):
    """Rate limiting defaults for per-tool/per-user/per-session counters."""

    window_seconds: int = 60
    per_tool: int = 15
    per_user: int = 40
    per_session: int = 30
    burst_multiplier: float = 2.0
    burst_window_seconds: int | None = None


class SandboxToolOverrideNetwork(BaseModel):
    allow_network: bool = False
    allowed_domains: list[str] = Field(default_factory=list)
    deny_private_ranges: bool = True
    deny_ip_literals: bool = True


class SandboxToolOverrideFilesystem(BaseModel):
    mounts: list[dict[str, str]] = Field(default_factory=list)
    denylist: list[str] = Field(default_factory=list)


class SandboxToolOverrideEnvironment(BaseModel):
    allowed_keys: list[str] = Field(default_factory=list)
    denied_prefixes: list[str] = Field(default_factory=list)
    max_keys: int | None = None
    max_total_bytes: int | None = None


class SandboxToolOverrideLimits(BaseModel):
    cpu_shares: int | None = None
    memory_mb: int | None = None
    timeout_seconds: int | None = None
    output_bytes: int | None = None
    pids: int | None = None


class SandboxToolOverride(BaseModel):
    sandbox_type: str | None = None
    network: SandboxToolOverrideNetwork | None = None
    filesystem: SandboxToolOverrideFilesystem | None = None
    environment: SandboxToolOverrideEnvironment | None = None
    limits: SandboxToolOverrideLimits | None = None
    degraded_mode: str | None = None
    security_critical: bool | None = None


class SandboxPolicy(BaseModel):
    """Sandbox policy defaults and per-tool overrides."""

    default_backend: str = "nsjail"
    network_backend: str = "container"
    fail_closed_security_critical: bool = True
    tool_overrides: dict[ToolName, SandboxToolOverride] = Field(default_factory=dict)
    env_allowlist: list[str] = Field(default_factory=lambda: ["PATH", "LANG", "TERM", "HOME"])
    env_max_keys: int = 32
    env_max_total_bytes: int = 8192
    dependency_source_allowlist: list[str] = Field(
        default_factory=lambda: ["shisa-registry", "local"]
    )

    @model_validator(mode="before")
    @classmethod
    def _migrate_legacy_tool_overrides(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        overrides = value.get("tool_overrides")
        if not isinstance(overrides, dict):
            return value
        migrated: dict[str, Any] = {}
        for key, item in overrides.items():
            if isinstance(item, str):
                logger.warning(
                    "Deprecated sandbox.tool_overrides scalar for tool '%s'; "
                    "interpreting as sandbox_type override",
                    key,
                )
                migrated[str(key)] = {"sandbox_type": item}
            else:
                migrated[str(key)] = item
        value["tool_overrides"] = migrated
        return value


class SkillPolicy(BaseModel):
    """Skill install/review policy controls."""

    require_review_on_update: bool = True
    require_signature_for_auto_install: bool = True
    trusted_key_ids: list[str] = Field(default_factory=list)
    dependency_source_allowlist: list[str] = Field(
        default_factory=lambda: ["shisa-registry", "local"]
    )


class PolicyBundle(BaseModel):
    """Top-level policy bundle matching docs/SECURITY.md Section 4.2."""

    version: str = "1"

    # Defaults
    default_deny: bool = True
    default_require_confirmation: bool = True

    # Tool permissions
    tools: dict[ToolName, ToolPolicy] = Field(default_factory=dict)

    # Egress allowlist
    egress: list[EgressRule] = Field(default_factory=list)

    # Filesystem rules
    filesystem: list[FilesystemRule] = Field(default_factory=list)

    # Session capabilities (default grants)
    default_capabilities: list[Capability] = Field(default_factory=list)
    session_tool_allowlist: list[ToolName] = Field(
        default_factory=list,
        description="Optional per-session default tool allowlist.",
    )

    # M2 controls
    risk_policy: RiskPolicy = Field(default_factory=RiskPolicy)
    rate_limits: RateLimitPolicy = Field(default_factory=RateLimitPolicy)
    sandbox: SandboxPolicy = Field(default_factory=SandboxPolicy)
    skills: SkillPolicy = Field(default_factory=SkillPolicy)
    yara_required: bool = False
    safe_output_domains: list[str] = Field(default_factory=list)


# --- Policy loader ---


class PolicyLoader:
    """Loads policy bundles from trusted paths with integrity verification.

    Hot-reload is supported via SIGHUP — the daemon signals a reload,
    never the agent. The agent cannot trigger a policy reload from
    the data plane.
    """

    def __init__(self, policy_path: Path) -> None:
        self._policy_path = policy_path
        self._policy: PolicyBundle = PolicyBundle()
        self._file_hash: str = ""

    @property
    def policy(self) -> PolicyBundle:
        return self._policy

    @property
    def file_hash(self) -> str:
        return self._file_hash

    def load(self) -> PolicyBundle:
        """Load and validate the policy bundle from disk.

        Raises:
            FileNotFoundError: If the policy file doesn't exist.
            ValueError: If the YAML is invalid or fails schema validation.
        """
        if not self._policy_path.exists():
            logger.warning("Policy file not found at %s, using defaults", self._policy_path)
            self._policy = PolicyBundle()
            self._file_hash = ""
            return self._policy

        raw = self._policy_path.read_bytes()
        self._file_hash = hashlib.sha256(raw).hexdigest()

        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in policy file: {e}") from e

        if data is None:
            self._policy = PolicyBundle()
            return self._policy

        self._policy = PolicyBundle.model_validate(data)
        logger.info(
            "Policy loaded: %s (hash: %s…)",
            self._policy_path,
            self._file_hash[:12],
        )
        return self._policy

    def verify_integrity(self) -> bool:
        """Check if the on-disk policy still matches the loaded hash."""
        if not self._policy_path.exists():
            return self._file_hash == ""
        current_hash = hashlib.sha256(self._policy_path.read_bytes()).hexdigest()
        return current_hash == self._file_hash

    def register_reload_signal(self) -> None:
        """Register SIGHUP handler for hot-reload.

        Only the daemon process should call this. The reload is signal-based,
        not agent-triggered, to prevent control-plane tampering via the data plane.
        """

        def _reload_handler(signum: int, frame: Any) -> None:
            logger.info("SIGHUP received, reloading policy")
            try:
                self.load()
            except Exception:
                logger.exception("Failed to reload policy, keeping previous")

        signal.signal(signal.SIGHUP, _reload_handler)
