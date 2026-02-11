"""Configuration system for shisad.

Pydantic BaseSettings with env var overrides. Config is loaded once at startup
and treated as read-only at runtime (immutability principle).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator
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
    checkpoint_trigger: Literal[
        "before_side_effects",
        "before_any_tool",
        "never",
    ] = Field(
        default="before_side_effects",
        description="When to create checkpoints during tool execution.",
    )

    # Trace recording
    trace_enabled: bool = Field(
        default=False,
        description="Enable training-ready LLM trace recording.",
    )

    # Optional Matrix runtime channel
    matrix_enabled: bool = Field(default=False, description="Enable Matrix channel runtime.")
    matrix_homeserver: str = Field(default="", description="Matrix homeserver URL.")
    matrix_user_id: str = Field(default="", description="Matrix user id for bot account.")
    matrix_access_token: str = Field(default="", description="Matrix access token.")
    matrix_room_id: str = Field(default="", description="Default Matrix room id.")
    matrix_e2ee: bool = Field(default=True, description="Enable Matrix E2EE when available.")
    matrix_trusted_users: list[str] = Field(
        default_factory=list,
        description="Matrix users considered verified/trusted for policy decisions.",
    )
    matrix_room_workspace_map: dict[str, str] = Field(
        default_factory=dict,
        description="Map Matrix room ids to workspace ids.",
    )

    @field_validator("matrix_trusted_users", mode="before")
    @classmethod
    def _parse_matrix_trusted_users(cls, value: object) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return []
            if stripped.startswith("["):
                parsed = json.loads(stripped)
                if isinstance(parsed, list):
                    return [str(item) for item in parsed]
                raise ValueError("SHISAD_MATRIX_TRUSTED_USERS JSON must be a list")
            return [entry.strip() for entry in stripped.split(",") if entry.strip()]
        return value

    @field_validator("matrix_room_workspace_map", mode="before")
    @classmethod
    def _parse_matrix_room_workspace_map(cls, value: object) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return {}
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                return {str(key): str(item) for key, item in parsed.items()}
            raise ValueError("SHISAD_MATRIX_ROOM_WORKSPACE_MAP JSON must be an object")
        return value

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
        default="https://api.shisa.ai/openai/v1",
        description="Base URL for the OpenAI-compatible API",
    )
    model_id: str = Field(
        default="shisa-ai/shisa-v2.1-unphi4-14b",
        description="Model identifier (provider/model format)",
    )
    planner_model_id: str = Field(
        default="shisa-ai/shisa-v2.1-unphi4-14b",
        description="Model ID for planner component",
    )
    embeddings_model_id: str = Field(
        default="text-embedding-3-small",
        description="Model ID for embeddings component",
    )
    monitor_model_id: str = Field(
        default="shisa-ai/shisa-v2.1-unphi4-14b",
        description="Model ID for monitor component",
    )
    pinned_monitor_model_id: str = Field(
        default="shisa-ai/shisa-v2.1-unphi4-14b",
        description="Pinned model id for security-critical monitor route.",
    )
    pinned_planner_model_id: str = Field(
        default="shisa-ai/shisa-v2.1-unphi4-14b",
        description="Pinned model id for planner route used in security-sensitive analyses.",
    )
    enforce_security_route_pinning: bool = Field(
        default=True,
        description="Require pinned model IDs for security-critical routes.",
    )
    api_key: str | None = Field(
        default=None,
        description="Optional API key override (falls back to SHISA_API_KEY).",
    )

    planner_base_url: str | None = Field(
        default=None,
        description="Optional base URL override for planner model provider",
    )
    embeddings_base_url: str | None = Field(
        default=None,
        description="Optional base URL override for embeddings provider",
    )
    monitor_base_url: str | None = Field(
        default=None,
        description="Optional base URL override for monitor provider",
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
    endpoint_allowlist: list[str] = Field(
        default_factory=list,
        description=(
            "Optional endpoint allowlist (host globs or URL prefixes). "
            "When non-empty, all model endpoints must match one rule."
        ),
    )

    # Logging
    log_prompts: bool = Field(
        default=False,
        description="Log full prompts (debug only; never log credentials)",
    )

    @field_validator("endpoint_allowlist", mode="before")
    @classmethod
    def _parse_endpoint_allowlist(cls, value: object) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return []
            if stripped.startswith("["):
                parsed = json.loads(stripped)
                if isinstance(parsed, list):
                    return [str(item) for item in parsed]
                raise ValueError("SHISAD_MODEL_ENDPOINT_ALLOWLIST JSON must be a list")
            return [entry.strip() for entry in stripped.split(",") if entry.strip()]
        return value


class ShisadConfig(BaseSettings):
    """Top-level configuration aggregating all config sections."""

    model_config = SettingsConfigDict(env_prefix="SHISAD_")

    daemon: DaemonConfig = Field(default_factory=DaemonConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    model: ModelConfig = Field(default_factory=ModelConfig)
