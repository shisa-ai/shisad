"""Credential broker — proxy-level secret injection.

Implements the Deno Sandbox-inspired pattern: secrets never exist in the
agent runtime. The agent works with placeholder strings; real credentials
are injected only at the egress proxy boundary for pre-approved hosts.

    Planner → PEP → Tool Executor → Egress Proxy → Network
                     (placeholder)   (injects real secret
                                      only for approved hosts)
"""

from __future__ import annotations

import hashlib
import logging
from typing import Protocol

from pydantic import BaseModel, Field

from shisad.core.host_matching import host_matches
from shisad.core.types import CredentialRef

logger = logging.getLogger(__name__)

# Placeholder prefix — these strings are inert and useless if exfiltrated
_PLACEHOLDER_PREFIX = "SHISAD_SECRET_PLACEHOLDER_"


class CredentialConfig(BaseModel):
    """Configuration for a single credential."""

    allowed_hosts: list[str] = Field(
        description="Hosts where this credential may be injected (supports glob patterns)"
    )
    scopes: list[str] = Field(
        default_factory=list,
        description="OAuth scopes or permission labels",
    )
    header_name: str = Field(
        default="Authorization",
        description="HTTP header to inject the credential into",
    )
    header_prefix: str = Field(
        default="Bearer ",
        description="Prefix before the credential value in the header",
    )


class CredentialEntry(BaseModel):
    """Internal storage for a credential (never exposed to agent)."""

    ref: CredentialRef
    value: str  # The actual secret — never leaves the broker
    config: CredentialConfig


class CredentialStore(Protocol):
    """Protocol for credential storage backends."""

    def get_placeholder(self, ref: CredentialRef) -> str:
        """Get the placeholder string for a credential reference."""
        ...

    def register(self, ref: CredentialRef, value: str, config: CredentialConfig) -> None:
        """Register a credential."""
        ...

    def resolve(self, placeholder: str, destination_host: str) -> str | None:
        """Resolve a placeholder to the real value, if the host is allowed."""
        ...

    def has_credential(self, ref: CredentialRef) -> bool:
        """Check if a credential is registered."""
        ...

    def allowed_hosts(self, ref: CredentialRef) -> list[str]:
        """Get the allowed hosts for a credential."""
        ...


def generate_placeholder(ref: CredentialRef) -> str:
    """Generate a deterministic placeholder for a credential reference.

    The placeholder is a hash of the ref — deterministic so the same ref
    always produces the same placeholder, but not reversible to the ref
    (defense in depth: even placeholder enumeration doesn't leak ref names).
    """
    ref_hash = hashlib.sha256(ref.encode()).hexdigest()[:32]
    return f"{_PLACEHOLDER_PREFIX}{ref_hash}"


def is_placeholder(value: str) -> bool:
    """Check if a string is a credential placeholder."""
    return value.startswith(_PLACEHOLDER_PREFIX)


class InMemoryCredentialStore:
    """In-memory credential store for MVP.

    Production deployments should use OS keychain or encrypted file storage.
    This implementation never exposes raw secrets to the agent process.
    """

    def __init__(self) -> None:
        self._credentials: dict[CredentialRef, CredentialEntry] = {}
        self._placeholders: dict[str, CredentialRef] = {}  # placeholder → ref

    def register(self, ref: CredentialRef, value: str, config: CredentialConfig) -> None:
        """Register a credential with its configuration."""
        entry = CredentialEntry(ref=ref, value=value, config=config)
        self._credentials[ref] = entry
        placeholder = generate_placeholder(ref)
        self._placeholders[placeholder] = ref
        logger.info("Registered credential: %s (hosts: %s)", ref, config.allowed_hosts)

    def get_placeholder(self, ref: CredentialRef) -> str:
        """Get the placeholder string for a credential.

        This is the only value the agent ever sees.
        """
        if ref not in self._credentials:
            raise KeyError(f"Unknown credential: {ref}")
        return generate_placeholder(ref)

    def has_credential(self, ref: CredentialRef) -> bool:
        """Check if a credential is registered."""
        return ref in self._credentials

    def allowed_hosts(self, ref: CredentialRef) -> list[str]:
        """Get the allowed hosts for a credential."""
        entry = self._credentials.get(ref)
        if entry is None:
            return []
        return entry.config.allowed_hosts

    def resolve(self, placeholder: str, destination_host: str) -> str | None:
        """Resolve a placeholder to the real credential value.

        Returns None if:
        - The placeholder is unknown
        - The destination host is not in the credential's allowed hosts

        This method is called by the egress proxy, never by the agent.
        """
        ref = self._placeholders.get(placeholder)
        if ref is None:
            return None

        entry = self._credentials.get(ref)
        if entry is None:
            return None

        # Check host allowlist
        if not self._host_allowed(destination_host, entry.config.allowed_hosts):
            logger.warning(
                "Credential %s not allowed for host %s (allowed: %s)",
                ref,
                destination_host,
                entry.config.allowed_hosts,
            )
            return None

        return entry.value

    @staticmethod
    def _host_allowed(host: str, allowed: list[str]) -> bool:
        """Check if a host matches any pattern in the allowlist."""
        return any(host_matches(host, pattern) for pattern in allowed)
