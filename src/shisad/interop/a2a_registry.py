"""A2A config models, key loading, and remote-agent registry."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from shisad.interop.a2a_envelope import (
    fingerprint_for_public_key,
    load_private_key_from_path,
    load_public_key_from_path,
    load_public_key_from_pem,
    normalize_a2a_agent_id,
    normalize_a2a_intent,
)


class A2aIdentityConfig(BaseModel):
    """Local daemon A2A identity material."""

    model_config = ConfigDict(frozen=True)

    agent_id: str
    private_key_path: Path
    public_key_path: Path

    @field_validator("agent_id", mode="before")
    @classmethod
    def _validate_agent_id(cls, value: object) -> str:
        return normalize_a2a_agent_id(value)

    @field_validator("private_key_path", "public_key_path", mode="before")
    @classmethod
    def _expand_paths(cls, value: object) -> Path:
        return Path(str(value)).expanduser()


class A2aListenConfig(BaseModel):
    """Inbound listener configuration for the local daemon."""

    model_config = ConfigDict(frozen=True)

    transport: Literal["socket", "http"] = "socket"
    host: str = "127.0.0.1"
    port: int = Field(default=9820, ge=0, le=65535)
    path: str = "/a2a"

    @field_validator("host", mode="before")
    @classmethod
    def _validate_host(cls, value: object) -> str:
        candidate = str(value).strip()
        if not candidate:
            raise ValueError("A2A listen host cannot be empty")
        return candidate

    @field_validator("path", mode="before")
    @classmethod
    def _validate_path(cls, value: object) -> str:
        candidate = str(value).strip() or "/a2a"
        if not candidate.startswith("/"):
            candidate = "/" + candidate
        return candidate


class A2aRateLimitsConfig(BaseModel):
    """Runtime A2A rate-limit defaults."""

    model_config = ConfigDict(frozen=True)

    max_per_minute: int = Field(default=60, ge=1)
    max_per_hour: int = Field(default=600, ge=1)


class A2aAgentConfig(BaseModel):
    """Static config entry for a known remote agent."""

    model_config = ConfigDict(frozen=True)

    agent_id: str
    fingerprint: str
    address: str
    public_key: str | None = None
    public_key_path: Path | None = None
    transport: Literal["socket", "http"] = "socket"
    trust_level: str = "untrusted"
    allowed_intents: list[str] | None = None

    @field_validator("agent_id", mode="before")
    @classmethod
    def _validate_agent_id(cls, value: object) -> str:
        return normalize_a2a_agent_id(value)

    @field_validator("fingerprint", mode="before")
    @classmethod
    def _validate_fingerprint(cls, value: object) -> str:
        candidate = str(value).strip().lower()
        if not candidate.startswith("sha256:") or len(candidate) != 71:
            raise ValueError("A2A fingerprint must use sha256:<64-hex>")
        fingerprint = candidate.removeprefix("sha256:")
        int(fingerprint, 16)
        return candidate

    @field_validator("address", mode="before")
    @classmethod
    def _validate_address(cls, value: object) -> str:
        candidate = str(value).strip()
        if not candidate:
            raise ValueError("A2A agent address cannot be empty")
        return candidate

    @field_validator("trust_level", mode="before")
    @classmethod
    def _normalize_trust_level(cls, value: object) -> str:
        normalized = str(value).strip().lower() or "untrusted"
        if normalized == "trusted_cli":
            raise ValueError("A2A agents cannot use trust_level 'trusted_cli'")
        return normalized

    @field_validator("public_key_path", mode="before")
    @classmethod
    def _expand_public_key_path(cls, value: object) -> Path | None:
        if value in {None, ""}:
            return None
        return Path(str(value)).expanduser()

    @field_validator("allowed_intents", mode="before")
    @classmethod
    def _parse_allowed_intents(cls, value: object) -> object:
        if value is None:
            return None
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return []
            return [part.strip() for part in stripped.split(",") if part.strip()]
        return value

    @field_validator("allowed_intents")
    @classmethod
    def _normalize_allowed_intents(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        normalized: list[str] = []
        seen: set[str] = set()
        for raw in value:
            candidate = normalize_a2a_intent(raw)
            if candidate in seen:
                continue
            seen.add(candidate)
            normalized.append(candidate)
        return normalized

    @model_validator(mode="after")
    def _validate_key_source(self) -> A2aAgentConfig:
        if not self.public_key and self.public_key_path is None:
            raise ValueError("A2A agents require public_key or public_key_path")
        if self.transport == "socket":
            host, separator, port_text = self.address.rpartition(":")
            if not host or separator != ":":
                raise ValueError("A2A socket addresses must use host:port")
            port = int(port_text)
            if port <= 0 or port > 65535:
                raise ValueError("A2A socket port must be between 1 and 65535")
        else:
            parsed = urlparse(self.address)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError("A2A HTTP addresses must be full http(s) URLs")
            try:
                parsed_host = parsed.hostname
                _port = parsed.port
            except ValueError as exc:
                raise ValueError(
                    "A2A HTTP addresses must use bracketed IPv6 literals when needed"
                ) from exc
            if not parsed_host:
                raise ValueError("A2A HTTP addresses must be full http(s) URLs")
        return self


class A2aConfig(BaseModel):
    """Top-level A2A daemon configuration."""

    model_config = ConfigDict(frozen=True)

    enabled: bool = False
    identity: A2aIdentityConfig | None = None
    listen: A2aListenConfig = Field(default_factory=A2aListenConfig)
    agents: list[A2aAgentConfig] = Field(default_factory=list)
    rate_limits: A2aRateLimitsConfig = Field(default_factory=A2aRateLimitsConfig)

    @model_validator(mode="after")
    def _validate_unique_agents(self) -> A2aConfig:
        seen: set[str] = set()
        seen_fingerprints: set[str] = set()
        for agent in self.agents:
            if agent.agent_id in seen:
                raise ValueError("A2A agent ids must be unique")
            seen.add(agent.agent_id)
            if agent.fingerprint in seen_fingerprints:
                raise ValueError("A2A agent fingerprints must be unique")
            seen_fingerprints.add(agent.fingerprint)
        return self


@dataclass(frozen=True, slots=True)
class A2aLocalIdentity:
    """Loaded local daemon A2A identity."""

    agent_id: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    fingerprint: str
    private_key_path: Path
    public_key_path: Path


@dataclass(frozen=True, slots=True)
class A2aAgentEntry:
    """Runtime-resolved remote agent registry entry."""

    agent_id: str
    address: str
    public_key: Ed25519PublicKey
    fingerprint: str
    transport: Literal["socket", "http"]
    trust_level: str
    allowed_intents: tuple[str, ...] | None


def load_local_identity(config: A2aIdentityConfig) -> A2aLocalIdentity:
    """Load and cross-check the local daemon A2A identity."""

    private_key = load_private_key_from_path(config.private_key_path)
    public_key = load_public_key_from_path(config.public_key_path)
    derived_public_key = private_key.public_key()
    derived_fingerprint = fingerprint_for_public_key(derived_public_key)
    loaded_fingerprint = fingerprint_for_public_key(public_key)
    if derived_fingerprint != loaded_fingerprint:
        raise ValueError("A2A public_key_path does not match private_key_path")
    return A2aLocalIdentity(
        agent_id=config.agent_id,
        private_key=private_key,
        public_key=public_key,
        fingerprint=derived_fingerprint,
        private_key_path=config.private_key_path,
        public_key_path=config.public_key_path,
    )


class A2aRegistry:
    """Static runtime registry of verified remote A2A agents."""

    def __init__(self, entries: list[A2aAgentEntry]) -> None:
        self._entries = {entry.agent_id: entry for entry in entries}

    @classmethod
    def from_config(cls, config: A2aConfig) -> A2aRegistry:
        entries: list[A2aAgentEntry] = []
        seen_fingerprints: set[str] = set()
        for agent in config.agents:
            if agent.public_key_path is not None:
                public_key = load_public_key_from_path(agent.public_key_path)
            else:
                assert agent.public_key is not None
                public_key = load_public_key_from_pem(agent.public_key)
            actual_fingerprint = fingerprint_for_public_key(public_key)
            if actual_fingerprint != agent.fingerprint:
                raise ValueError(
                    f"A2A fingerprint mismatch for agent '{agent.agent_id}': "
                    f"expected {agent.fingerprint}, got {actual_fingerprint}"
                )
            if actual_fingerprint in seen_fingerprints:
                raise ValueError("A2A agent fingerprints must be unique")
            seen_fingerprints.add(actual_fingerprint)
            entries.append(
                A2aAgentEntry(
                    agent_id=agent.agent_id,
                    address=agent.address,
                    public_key=public_key,
                    fingerprint=actual_fingerprint,
                    transport=agent.transport,
                    trust_level=agent.trust_level,
                    allowed_intents=(
                        tuple(agent.allowed_intents) if agent.allowed_intents is not None else None
                    ),
                )
            )
        return cls(entries)

    def list_agents(self) -> list[A2aAgentEntry]:
        """Return all configured registry entries."""

        return list(self._entries.values())

    def resolve(self, agent_id: str) -> A2aAgentEntry | None:
        """Return the registry entry for *agent_id* if configured."""

        return self._entries.get(str(agent_id).strip())

    def require(self, agent_id: str) -> A2aAgentEntry:
        """Resolve *agent_id* or raise when it is not configured."""

        entry = self.resolve(agent_id)
        if entry is None:
            raise KeyError(f"Unknown A2A agent: {agent_id}")
        return entry
