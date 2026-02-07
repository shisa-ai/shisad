"""Configuration system for shisad.

Pydantic BaseSettings with env var overrides. Config is loaded once at startup
and treated as read-only at runtime (immutability principle).
"""

from __future__ import annotations

from pathlib import Path
from typing import Self

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class DaemonConfig(BaseSettings):
    """Daemon process configuration."""

    model_config = SettingsConfigDict(env_prefix="SHISAD_")

    # Paths
    data_dir: Path = Field(
        default=Path.home() / ".local" / "share" / "shisad",
        description="Root directory for shisad data (audit logs, sessions, etc.)",
    )
    socket_path: Path = Field(
        default=Path("/run/shisad/control.sock"),
        description="Unix domain socket path for the control API",
    )
    policy_path: Path = Field(
        default=Path("/etc/shisad/policy.yaml"),
        description="Path to the trusted policy bundle",
    )

    # Runtime
    log_level: str = Field(default="INFO", description="Logging level")

    @model_validator(mode="after")
    def _ensure_data_dir(self) -> Self:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self


class SecurityConfig(BaseSettings):
    """Security-specific configuration."""

    model_config = SettingsConfigDict(env_prefix="SHISAD_SECURITY_")

    # PEP defaults
    default_deny: bool = Field(
        default=True,
        description="Default-deny for unknown tools",
    )
    require_confirmation_for_writes: bool = Field(
        default=True,
        description="Require user confirmation for write/send operations",
    )

    # Egress
    egress_default_deny: bool = Field(
        default=True,
        description="Block all outbound requests unless explicitly allowed",
    )

    # Credential broker
    credential_store_path: Path = Field(
        default=Path.home() / ".local" / "share" / "shisad" / "credentials.enc",
        description="Path to the encrypted credential store",
    )

    # Audit
    audit_log_path: Path | None = Field(
        default=None,
        description="Override audit log path (default: data_dir/audit.jsonl)",
    )


class ModelConfig(BaseSettings):
    """Model provider configuration."""

    model_config = SettingsConfigDict(env_prefix="SHISAD_MODEL_")

    # Provider
    base_url: str = Field(
        default="https://api.openai.com/v1",
        description="Base URL for the OpenAI-compatible API",
    )
    model_id: str = Field(
        default="gpt-4o",
        description="Model identifier (provider/model format)",
    )

    # Endpoint security
    allow_http_localhost: bool = Field(
        default=True,
        description="Allow HTTP (non-TLS) for localhost endpoints only",
    )
    block_private_ranges: bool = Field(
        default=True,
        description="Block SSRF to private network ranges (10.x, 172.16.x, 192.168.x)",
    )

    # Logging
    log_prompts: bool = Field(
        default=False,
        description="Log full prompts (debug only; never log credentials)",
    )


class ShisadConfig(BaseSettings):
    """Top-level configuration aggregating all config sections."""

    model_config = SettingsConfigDict(env_prefix="SHISAD_")

    daemon: DaemonConfig = Field(default_factory=DaemonConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    model: ModelConfig = Field(default_factory=ModelConfig)
