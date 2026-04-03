"""Configuration system for shisad.

Pydantic BaseSettings with env var overrides. Config is loaded once at startup
and treated as read-only at runtime (immutability principle).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal, Self
from urllib.parse import urlparse

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from shisad.core.providers.capabilities import (
    AuthMode,
    EndpointFamily,
    ProviderCapabilities,
    ProviderPreset,
    RequestParameters,
)
from shisad.core.providers.http_headers import validate_auth_header_name, validate_extra_headers


def _default_selfmod_allowed_signers_path() -> Path:
    return Path(__file__).resolve().parents[3] / "config" / "selfmod" / "allowed_signers"


_WILDCARD_HOST_TOKENS = {"*", "?", "[", "]"}


def _destination_host_pattern(destination: str) -> str:
    raw = destination.strip().lower()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    return (parsed.hostname or raw).lower()


def _contains_wildcard_host_pattern(destination: str) -> bool:
    host_pattern = _destination_host_pattern(destination)
    return bool(host_pattern and any(token in host_pattern for token in _WILDCARD_HOST_TOKENS))


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
    selfmod_allowed_signers_path: Path = Field(
        default_factory=_default_selfmod_allowed_signers_path,
        description="Path to the trusted SSH allowed_signers file for self-mod artifacts.",
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

    # Optional Discord runtime channel
    discord_enabled: bool = Field(default=False, description="Enable Discord channel runtime.")
    discord_bot_token: str = Field(default="", description="Discord bot token.")
    discord_default_channel_id: str = Field(
        default="",
        description="Default Discord channel id for outbound sends.",
    )
    discord_trusted_users: list[str] = Field(
        default_factory=list,
        description="Discord users considered verified/trusted for policy decisions.",
    )
    discord_guild_workspace_map: dict[str, str] = Field(
        default_factory=dict,
        description="Map Discord guild ids to workspace ids.",
    )

    # Optional Telegram runtime channel
    telegram_enabled: bool = Field(default=False, description="Enable Telegram channel runtime.")
    telegram_bot_token: str = Field(default="", description="Telegram bot token.")
    telegram_default_chat_id: str = Field(
        default="",
        description="Default Telegram chat id for outbound sends.",
    )
    telegram_trusted_users: list[str] = Field(
        default_factory=list,
        description="Telegram users considered verified/trusted for policy decisions.",
    )
    telegram_chat_workspace_map: dict[str, str] = Field(
        default_factory=dict,
        description="Map Telegram chat ids to workspace ids.",
    )

    # Optional Slack runtime channel
    slack_enabled: bool = Field(default=False, description="Enable Slack channel runtime.")
    slack_bot_token: str = Field(default="", description="Slack bot token.")
    slack_app_token: str = Field(default="", description="Slack Socket Mode app token.")
    slack_default_channel_id: str = Field(
        default="",
        description="Default Slack channel id for outbound sends.",
    )
    slack_trusted_users: list[str] = Field(
        default_factory=list,
        description="Slack users considered verified/trusted for policy decisions.",
    )
    slack_team_workspace_map: dict[str, str] = Field(
        default_factory=dict,
        description="Map Slack team ids to workspace ids.",
    )

    # Default-deny channel pairing/allowlist configuration.
    channel_identity_allowlist: dict[str, list[str]] = Field(
        default_factory=dict,
        description=(
            "Map channel -> list of allowlisted external user ids for default-deny pairing."
        ),
    )

    # Assistant primitives (M2)
    assistant_persona_tone: Literal["strict", "neutral", "friendly"] = Field(
        default="neutral",
        description="Assistant persona tone profile for planner responses.",
    )
    assistant_persona_custom_text: str = Field(
        default="",
        description="Trusted custom persona guidance appended as style-only instructions.",
    )
    context_window: int = Field(
        default=20,
        ge=1,
        description=(
            "Number of prior transcript entries included in planner context before "
            "older entries are compacted into a summary prefix."
        ),
    )
    summarize_interval: int = Field(
        default=10,
        ge=1,
        description=(
            "Number of new transcript entries required before running conversation "
            "summarization to durable memory."
        ),
    )
    planner_memory_top_k: int = Field(
        default=5,
        ge=1,
        description=(
            "Maximum number of retrieved memory snippets injected into planner context per turn."
        ),
    )
    web_search_enabled: bool = Field(
        default=True,
        description="Enable web search primitive.",
    )
    web_search_backend_url: str = Field(
        default="",
        description="Reference search backend URL (SearxNG for v0.3).",
    )
    web_fetch_enabled: bool = Field(
        default=True,
        description="Enable web fetch primitive.",
    )
    web_allowed_domains: list[str] = Field(
        default_factory=list,
        description="Allowlisted web domains for web search/fetch egress.",
    )
    web_timeout_seconds: float = Field(
        default=10.0,
        ge=0.1,
        description="Timeout for web search/fetch HTTP calls.",
    )
    web_max_fetch_bytes: int = Field(
        default=262144,
        ge=1024,
        description="Maximum bytes fetched for web page content.",
    )
    browser_enabled: bool = Field(
        default=False,
        description="Enable browser automation surface.",
    )
    browser_command: str = Field(
        default="playwright-cli",
        description="Browser automation command (for example 'playwright-cli').",
    )
    browser_allowed_domains: list[str] = Field(
        default_factory=list,
        description="Allowlisted domains for browser automation egress.",
    )
    browser_timeout_seconds: float = Field(
        default=20.0,
        ge=1.0,
        description="Timeout for sandboxed browser CLI actions.",
    )
    browser_require_hardened_isolation: bool = Field(
        default=True,
        description=(
            "Require hardened browser runtime isolation. Browser commands fail closed "
            "when the hardened sandbox/runtime isolation path is unavailable."
        ),
    )
    browser_max_read_bytes: int = Field(
        default=262144,
        ge=1024,
        description="Maximum bytes returned for browser page text/snapshots.",
    )
    assistant_fs_roots: list[Path] = Field(
        default_factory=list,
        description="Allowlisted roots for fs/git assistant primitives.",
    )
    assistant_max_read_bytes: int = Field(
        default=65536,
        ge=1024,
        description="Maximum bytes returned by fs.read.",
    )
    assistant_git_timeout_seconds: float = Field(
        default=10.0,
        ge=0.1,
        description="Timeout in seconds for git.* helper subprocess calls.",
    )
    realitycheck_enabled: bool = Field(
        default=False,
        description="Enable Reality Check integration surface.",
    )
    realitycheck_repo_root: Path = Field(
        default=Path.home() / "github" / "lhl" / "realitycheck",
        description="Path to Reality Check repository root.",
    )
    realitycheck_data_roots: list[Path] = Field(
        default_factory=lambda: [Path.home() / "github" / "lhl" / "realitycheck-data"],
        description="Allowlisted data roots for Reality Check local reads.",
    )
    realitycheck_endpoint_enabled: bool = Field(
        default=False,
        description="Enable optional Reality Check endpoint usage.",
    )
    realitycheck_endpoint_url: str = Field(
        default="",
        description="Optional Reality Check endpoint URL used when endpoint mode is enabled.",
    )
    realitycheck_allowed_domains: list[str] = Field(
        default_factory=list,
        description="Allowlisted domains for optional Reality Check endpoint egress.",
    )
    realitycheck_timeout_seconds: float = Field(
        default=10.0,
        ge=0.1,
        description="Timeout for Reality Check endpoint requests.",
    )
    realitycheck_max_read_bytes: int = Field(
        default=131072,
        ge=1024,
        description="Maximum bytes returned by Reality Check local read operations.",
    )
    realitycheck_search_max_files: int = Field(
        default=10000,
        ge=1,
        description="Maximum number of local Reality Check files scanned per search.",
    )
    coding_repo_root: Path = Field(
        default_factory=Path.cwd,
        description="Git repository root used for coding-agent worktree isolation.",
    )
    coding_agent_default_preference: list[str] = Field(
        default_factory=lambda: ["codex", "claude", "opencode"],
        description=(
            "Default coding-agent preference chain when a task does not specify one. "
            "Shipped default order: codex -> claude -> opencode."
        ),
    )
    coding_agent_default_fallbacks: list[str] = Field(
        default_factory=list,
        description="Default fallback agents appended after explicit task preference.",
    )
    coding_agent_registry_overrides: dict[str, str] = Field(
        default_factory=dict,
        description=("Optional trusted operator overrides for the coding-agent registry commands."),
    )
    coding_agent_timeout_seconds: float = Field(
        default=900.0,
        ge=0.1,
        description="Default timeout for coding-agent TASK invocations.",
    )

    @staticmethod
    def _parse_list_field(value: object, *, field_name: str) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return []
            if stripped.startswith("["):
                parsed = json.loads(stripped)
                if isinstance(parsed, list):
                    return [str(item) for item in parsed]
                raise ValueError(f"{field_name} JSON must be a list")
            return [entry.strip() for entry in stripped.split(",") if entry.strip()]
        return value

    @staticmethod
    def _parse_map_field(value: object, *, field_name: str) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return {}
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                return {str(key): str(item) for key, item in parsed.items()}
            raise ValueError(f"{field_name} JSON must be an object")
        return value

    @staticmethod
    def _parse_path_list_field(value: object, *, field_name: str) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return []
            if stripped.startswith("["):
                parsed = json.loads(stripped)
                if not isinstance(parsed, list):
                    raise ValueError(f"{field_name} JSON must be a list")
                return [Path(str(item)).expanduser() for item in parsed if str(item).strip()]
            return [
                Path(entry.strip()).expanduser() for entry in stripped.split(",") if entry.strip()
            ]
        if isinstance(value, list):
            return [Path(str(item)).expanduser() for item in value if str(item).strip()]
        return value

    @field_validator("matrix_trusted_users", mode="before")
    @classmethod
    def _parse_matrix_trusted_users(cls, value: object) -> object:
        return cls._parse_list_field(value, field_name="SHISAD_MATRIX_TRUSTED_USERS")

    @field_validator("matrix_room_workspace_map", mode="before")
    @classmethod
    def _parse_matrix_room_workspace_map(cls, value: object) -> object:
        return cls._parse_map_field(value, field_name="SHISAD_MATRIX_ROOM_WORKSPACE_MAP")

    @field_validator("discord_trusted_users", mode="before")
    @classmethod
    def _parse_discord_trusted_users(cls, value: object) -> object:
        return cls._parse_list_field(value, field_name="SHISAD_DISCORD_TRUSTED_USERS")

    @field_validator("discord_guild_workspace_map", mode="before")
    @classmethod
    def _parse_discord_guild_workspace_map(cls, value: object) -> object:
        return cls._parse_map_field(value, field_name="SHISAD_DISCORD_GUILD_WORKSPACE_MAP")

    @field_validator("telegram_trusted_users", mode="before")
    @classmethod
    def _parse_telegram_trusted_users(cls, value: object) -> object:
        return cls._parse_list_field(value, field_name="SHISAD_TELEGRAM_TRUSTED_USERS")

    @field_validator("telegram_chat_workspace_map", mode="before")
    @classmethod
    def _parse_telegram_chat_workspace_map(cls, value: object) -> object:
        return cls._parse_map_field(value, field_name="SHISAD_TELEGRAM_CHAT_WORKSPACE_MAP")

    @field_validator("slack_trusted_users", mode="before")
    @classmethod
    def _parse_slack_trusted_users(cls, value: object) -> object:
        return cls._parse_list_field(value, field_name="SHISAD_SLACK_TRUSTED_USERS")

    @field_validator("slack_team_workspace_map", mode="before")
    @classmethod
    def _parse_slack_team_workspace_map(cls, value: object) -> object:
        return cls._parse_map_field(value, field_name="SHISAD_SLACK_TEAM_WORKSPACE_MAP")

    @field_validator("channel_identity_allowlist", mode="before")
    @classmethod
    def _parse_channel_identity_allowlist(cls, value: object) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return {}
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                normalized: dict[str, list[str]] = {}
                for channel, entries in parsed.items():
                    channel_key = str(channel).strip()
                    if not channel_key:
                        continue
                    if isinstance(entries, list):
                        normalized[channel_key] = [
                            str(item).strip() for item in entries if str(item).strip()
                        ]
                        continue
                    if isinstance(entries, str):
                        normalized[channel_key] = [
                            piece.strip() for piece in entries.split(",") if piece.strip()
                        ]
                        continue
                    raise ValueError(
                        "SHISAD_CHANNEL_IDENTITY_ALLOWLIST values must be list[str] "
                        "or comma-separated string"
                    )
                return normalized
            raise ValueError("SHISAD_CHANNEL_IDENTITY_ALLOWLIST JSON must be an object")
        return value

    @field_validator("web_allowed_domains", mode="before")
    @classmethod
    def _parse_web_allowed_domains(cls, value: object) -> object:
        return cls._parse_list_field(value, field_name="SHISAD_WEB_ALLOWED_DOMAINS")

    @field_validator("browser_allowed_domains", mode="before")
    @classmethod
    def _parse_browser_allowed_domains(cls, value: object) -> object:
        return cls._parse_list_field(value, field_name="SHISAD_BROWSER_ALLOWED_DOMAINS")

    @field_validator("assistant_fs_roots", mode="before")
    @classmethod
    def _parse_assistant_fs_roots(cls, value: object) -> object:
        return cls._parse_path_list_field(value, field_name="SHISAD_ASSISTANT_FS_ROOTS")

    @field_validator("coding_repo_root", mode="before")
    @classmethod
    def _parse_coding_repo_root(cls, value: object) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return Path.cwd()
            return Path(stripped).expanduser()
        if isinstance(value, Path):
            return value.expanduser()
        return value

    @field_validator("coding_agent_default_preference", mode="before")
    @classmethod
    def _parse_coding_agent_default_preference(cls, value: object) -> object:
        return cls._parse_list_field(
            value,
            field_name="SHISAD_CODING_AGENT_DEFAULT_PREFERENCE",
        )

    @field_validator("coding_agent_default_fallbacks", mode="before")
    @classmethod
    def _parse_coding_agent_default_fallbacks(cls, value: object) -> object:
        return cls._parse_list_field(
            value,
            field_name="SHISAD_CODING_AGENT_DEFAULT_FALLBACKS",
        )

    @field_validator("coding_agent_registry_overrides", mode="before")
    @classmethod
    def _parse_coding_agent_registry_overrides(cls, value: object) -> object:
        return cls._parse_map_field(
            value,
            field_name="SHISAD_CODING_AGENT_REGISTRY_OVERRIDES",
        )

    @field_validator("realitycheck_repo_root", mode="before")
    @classmethod
    def _parse_realitycheck_repo_root(cls, value: object) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return Path()
            return Path(stripped).expanduser()
        if isinstance(value, Path):
            return value.expanduser()
        return value

    @field_validator("realitycheck_data_roots", mode="before")
    @classmethod
    def _parse_realitycheck_data_roots(cls, value: object) -> object:
        return cls._parse_path_list_field(value, field_name="SHISAD_REALITYCHECK_DATA_ROOTS")

    @field_validator("realitycheck_allowed_domains", mode="before")
    @classmethod
    def _parse_realitycheck_allowed_domains(cls, value: object) -> object:
        return cls._parse_list_field(value, field_name="SHISAD_REALITYCHECK_ALLOWED_DOMAINS")

    @model_validator(mode="after")
    def _ensure_data_dir(self) -> Self:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self

    @model_validator(mode="after")
    def _validate_browser_hardened_scope(self) -> Self:
        if not self.browser_enabled or not self.browser_require_hardened_isolation:
            return self
        browser_scope = (
            list(self.browser_allowed_domains)
            if self.browser_allowed_domains
            else list(self.web_allowed_domains)
        )
        wildcard_scope = [item for item in browser_scope if _contains_wildcard_host_pattern(item)]
        if wildcard_scope:
            raise ValueError(
                "browser_require_hardened_isolation does not support wildcard browser scope "
                f"entries: {', '.join(sorted(wildcard_scope))}"
            )
        return self


class SecurityConfig(BaseSettings):
    """Security-specific configuration."""

    model_config = SettingsConfigDict(env_prefix="SHISAD_SECURITY_")

    # PEP defaults
    # Legacy compatibility knob retained for env/schema stability.
    # Runtime enforcement posture is sourced from PolicyBundle.default_deny.
    default_deny: bool = Field(
        default=False,
        description="Legacy default-deny setting (runtime uses policy bundle defaults).",
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
        default=False,
        description="If enabled, require pinned model IDs for security-critical routes.",
    )
    api_key: str | None = Field(
        default=None,
        description="Optional global API key override (SHISAD_MODEL_API_KEY).",
    )
    remote_enabled: bool = Field(
        default=False,
        description="Global default remote-provider enablement.",
    )

    planner_provider_preset: ProviderPreset | None = Field(
        default=None,
        description="Optional provider preset for planner route.",
    )
    embeddings_provider_preset: ProviderPreset | None = Field(
        default=None,
        description="Optional provider preset for embeddings route.",
    )
    monitor_provider_preset: ProviderPreset | None = Field(
        default=None,
        description="Optional provider preset for monitor route.",
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

    planner_remote_enabled: bool | None = Field(
        default=None,
        description="Optional planner remote toggle (None inherits global).",
    )
    embeddings_remote_enabled: bool | None = Field(
        default=None,
        description="Optional embeddings remote toggle (None inherits global).",
    )
    monitor_remote_enabled: bool | None = Field(
        default=None,
        description="Optional monitor remote toggle (None inherits global).",
    )

    planner_api_key: str | None = Field(
        default=None,
        description="Optional route-local planner API key override.",
    )
    embeddings_api_key: str | None = Field(
        default=None,
        description="Optional route-local embeddings API key override.",
    )
    monitor_api_key: str | None = Field(
        default=None,
        description="Optional route-local monitor API key override.",
    )

    planner_auth_mode: AuthMode | None = Field(
        default=None,
        description="Route auth mode override for planner route.",
    )
    embeddings_auth_mode: AuthMode | None = Field(
        default=None,
        description="Route auth mode override for embeddings route.",
    )
    monitor_auth_mode: AuthMode | None = Field(
        default=None,
        description="Route auth mode override for monitor route.",
    )

    planner_auth_header_name: str | None = Field(
        default=None,
        description="Route auth header name when planner_auth_mode=header.",
    )
    embeddings_auth_header_name: str | None = Field(
        default=None,
        description="Route auth header name when embeddings_auth_mode=header.",
    )
    monitor_auth_header_name: str | None = Field(
        default=None,
        description="Route auth header name when monitor_auth_mode=header.",
    )

    planner_extra_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Optional planner route custom headers.",
    )
    embeddings_extra_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Optional embeddings route custom headers.",
    )
    monitor_extra_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Optional monitor route custom headers.",
    )

    planner_endpoint_family: EndpointFamily | None = Field(
        default=None,
        description="Planner endpoint family override.",
    )
    embeddings_endpoint_family: EndpointFamily | None = Field(
        default=None,
        description="Embeddings endpoint family override.",
    )
    monitor_endpoint_family: EndpointFamily | None = Field(
        default=None,
        description="Monitor endpoint family override.",
    )

    planner_request_parameter_profile: str | None = Field(
        default=None,
        description="Planner request-parameter profile override.",
    )
    embeddings_request_parameter_profile: str | None = Field(
        default=None,
        description="Embeddings request-parameter profile override.",
    )
    monitor_request_parameter_profile: str | None = Field(
        default=None,
        description="Monitor request-parameter profile override.",
    )

    planner_capabilities: ProviderCapabilities = Field(
        default_factory=ProviderCapabilities,
        description="Capability declaration for planner route.",
    )
    planner_schema_strict_mode: bool = Field(
        default=True,
        description=(
            "Enable strict planner structured-output schema validation. "
            "When true, malformed structured tool-call payloads are rejected."
        ),
    )
    embeddings_capabilities: ProviderCapabilities = Field(
        default_factory=lambda: ProviderCapabilities(supports_tool_calls=False),
        description="Capability declaration for embeddings route.",
    )
    monitor_capabilities: ProviderCapabilities = Field(
        default_factory=lambda: ProviderCapabilities(
            supports_tool_calls=False,
            supports_structured_output=True,
        ),
        description="Capability declaration for monitor route.",
    )
    planner_request_parameters: RequestParameters = Field(
        default_factory=RequestParameters,
        description="Allowlisted request parameters for planner route.",
    )
    embeddings_request_parameters: RequestParameters = Field(
        default_factory=RequestParameters,
        description="Allowlisted request parameters for embeddings route.",
    )
    monitor_request_parameters: RequestParameters = Field(
        default_factory=RequestParameters,
        description="Allowlisted request parameters for monitor route.",
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

    @staticmethod
    def _parse_optional_header_name(value: object) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return None
            return stripped
        return value

    @staticmethod
    def _parse_optional_secret(value: object) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return None
            return stripped
        return value

    @staticmethod
    def _parse_optional_bool(value: object) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return None
        return value

    @staticmethod
    def _parse_header_map(value: object, *, field_name: str) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return {}
            parsed = json.loads(stripped)
            if not isinstance(parsed, dict):
                raise ValueError(f"{field_name} JSON must be an object")
            return {str(key): str(item) for key, item in parsed.items()}
        if isinstance(value, dict):
            return {str(key): str(item) for key, item in value.items()}
        return value

    @staticmethod
    def _parse_nested_model(value: object, *, field_name: str) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return {}
            parsed = json.loads(stripped)
            if not isinstance(parsed, dict):
                raise ValueError(f"{field_name} JSON must be an object")
            return parsed
        return value

    @field_validator(
        "planner_capabilities",
        "embeddings_capabilities",
        "monitor_capabilities",
        mode="before",
    )
    @classmethod
    def _parse_capabilities(cls, value: object, info: object) -> object:
        field_name = f"SHISAD_MODEL_{str(getattr(info, 'field_name', '')).upper()}"
        return cls._parse_nested_model(value, field_name=field_name)

    @field_validator(
        "planner_request_parameters",
        "embeddings_request_parameters",
        "monitor_request_parameters",
        mode="before",
    )
    @classmethod
    def _parse_request_parameters(cls, value: object, info: object) -> object:
        field_name = f"SHISAD_MODEL_{str(getattr(info, 'field_name', '')).upper()}"
        return cls._parse_nested_model(value, field_name=field_name)

    @field_validator(
        "planner_api_key",
        "embeddings_api_key",
        "monitor_api_key",
        mode="before",
    )
    @classmethod
    def _parse_route_api_keys(cls, value: object) -> object:
        return cls._parse_optional_secret(value)

    @field_validator(
        "planner_remote_enabled",
        "embeddings_remote_enabled",
        "monitor_remote_enabled",
        mode="before",
    )
    @classmethod
    def _parse_route_remote_enabled(cls, value: object) -> object:
        return cls._parse_optional_bool(value)

    @field_validator(
        "planner_auth_header_name",
        "embeddings_auth_header_name",
        "monitor_auth_header_name",
        mode="before",
    )
    @classmethod
    def _parse_route_auth_header_names(cls, value: object) -> object:
        return cls._parse_optional_header_name(value)

    @field_validator(
        "planner_extra_headers",
        "embeddings_extra_headers",
        "monitor_extra_headers",
        mode="before",
    )
    @classmethod
    def _parse_route_extra_headers(cls, value: object, info: object) -> object:
        field_name = f"SHISAD_MODEL_{str(getattr(info, 'field_name', '')).upper()}"
        return cls._parse_header_map(value, field_name=field_name)

    @model_validator(mode="after")
    def _validate_route_header_configuration(self) -> Self:
        for route in ("planner", "embeddings", "monitor"):
            auth_mode = getattr(self, f"{route}_auth_mode")
            auth_header_name = getattr(self, f"{route}_auth_header_name")
            extra_headers = getattr(self, f"{route}_extra_headers")

            if auth_header_name and auth_mode != AuthMode.HEADER:
                raise ValueError(
                    f"{route}_auth_header_name is only supported when {route}_auth_mode=header"
                )
            if auth_mode == AuthMode.HEADER and not auth_header_name:
                raise ValueError(
                    f"{route}_auth_header_name is required when {route}_auth_mode=header"
                )
            if auth_mode == AuthMode.HEADER and auth_header_name:
                validate_auth_header_name(auth_header_name)

            selected_auth_header_name: str | None = None
            if auth_mode == AuthMode.BEARER:
                selected_auth_header_name = "Authorization"
            elif auth_mode == AuthMode.HEADER:
                selected_auth_header_name = auth_header_name
            validate_extra_headers(
                extra_headers,
                selected_auth_header_name=selected_auth_header_name,
            )

        return self


class ShisadConfig(BaseSettings):
    """Top-level configuration aggregating all config sections."""

    model_config = SettingsConfigDict(env_prefix="SHISAD_")

    daemon: DaemonConfig = Field(default_factory=DaemonConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    model: ModelConfig = Field(default_factory=ModelConfig)
