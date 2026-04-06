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
import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, Field, ValidationError

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


class RecoveryCodeRecord(BaseModel):
    """Single recovery code entry for an approval factor."""

    code_hash: str
    consumed_at: datetime | None = None
    consumed_confirmation_id: str = ""


class ApprovalFactorRecord(BaseModel):
    """Durable approval-factor state stored in the control-plane factor store."""

    credential_id: str
    user_id: str
    method: str
    principal_id: str
    secret_b32: str = ""
    webauthn_attested_credential_data_b64: str = ""
    webauthn_sign_count: int = 0
    webauthn_rp_id: str = ""
    webauthn_transports: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_verified_at: datetime | None = None
    last_used_at: datetime | None = None
    used_time_steps: dict[str, str] = Field(default_factory=dict)
    recovery_codes: list[RecoveryCodeRecord] = Field(default_factory=list)


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


class ApprovalFactorStore(Protocol):
    """Protocol for durable approval-factor storage."""

    def set_approval_store_path(self, path: Path) -> None:
        """Bind the store to a durable approval-factor path and load state."""
        ...

    def register_approval_factor(self, factor: ApprovalFactorRecord) -> None:
        """Persist a newly enrolled approval factor."""
        ...

    def list_approval_factors(
        self,
        *,
        user_id: str | None = None,
        method: str | None = None,
    ) -> list[ApprovalFactorRecord]:
        """List persisted approval factors."""
        ...

    def get_approval_factor(self, credential_id: str) -> ApprovalFactorRecord | None:
        """Fetch one approval factor by credential id."""
        ...

    def update_approval_factor(self, factor: ApprovalFactorRecord) -> None:
        """Persist an updated approval factor record."""
        ...

    def revoke_approval_factor(
        self,
        *,
        user_id: str | None = None,
        method: str | None = None,
        credential_id: str | None = None,
    ) -> int:
        """Delete matching approval factors and return the removed count."""
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
        self._approval_store_path: Path | None = None
        self._approval_factors: dict[str, ApprovalFactorRecord] = {}

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

    def set_approval_store_path(self, path: Path) -> None:
        """Bind durable approval-factor storage to a JSON file."""
        self._approval_store_path = Path(path)
        self._load_approval_factors()

    def register_approval_factor(self, factor: ApprovalFactorRecord) -> None:
        """Persist a newly enrolled approval factor."""
        self._approval_factors[factor.credential_id] = factor.model_copy(deep=True)
        self._persist_approval_factors()

    def list_approval_factors(
        self,
        *,
        user_id: str | None = None,
        method: str | None = None,
    ) -> list[ApprovalFactorRecord]:
        """List approval factors, optionally filtered by user and method."""
        rows = [
            factor.model_copy(deep=True)
            for factor in self._approval_factors.values()
            if (user_id is None or factor.user_id == user_id)
            and (method is None or factor.method == method)
        ]
        rows.sort(key=lambda item: (item.created_at, item.user_id, item.method, item.credential_id))
        return rows

    def get_approval_factor(self, credential_id: str) -> ApprovalFactorRecord | None:
        """Fetch one approval factor by credential id."""
        factor = self._approval_factors.get(str(credential_id))
        if factor is None:
            return None
        return factor.model_copy(deep=True)

    def update_approval_factor(self, factor: ApprovalFactorRecord) -> None:
        """Persist an updated approval factor record."""
        if factor.credential_id not in self._approval_factors:
            raise KeyError(f"Unknown approval factor: {factor.credential_id}")
        self._approval_factors[factor.credential_id] = factor.model_copy(deep=True)
        self._persist_approval_factors()

    def revoke_approval_factor(
        self,
        *,
        user_id: str | None = None,
        method: str | None = None,
        credential_id: str | None = None,
    ) -> int:
        """Delete matching approval factors and return the removed count."""
        removed = 0
        candidates = [
            factor_id
            for factor_id, factor in self._approval_factors.items()
            if (credential_id is None or factor.credential_id == credential_id)
            and (user_id is None or factor.user_id == user_id)
            and (method is None or factor.method == method)
        ]
        for factor_id in candidates:
            removed += 1
            self._approval_factors.pop(factor_id, None)
        if removed:
            self._persist_approval_factors()
        return removed

    @staticmethod
    def _host_allowed(host: str, allowed: list[str]) -> bool:
        """Check if a host matches any pattern in the allowlist."""
        return any(host_matches(host, pattern) for pattern in allowed)

    def _load_approval_factors(self) -> None:
        path = self._approval_store_path
        if path is None or not path.exists():
            self._approval_factors = {}
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("approval-factor store payload must be an object")
            schema_version = str(payload.get("schema_version", "")).strip()
            if schema_version != "shisad.approval_factor_store.v1":
                raise ValueError(
                    "unsupported approval-factor store schema_version: "
                    f"{schema_version}"
                )
            factors = payload.get("approval_factors", [])
            if not isinstance(factors, list):
                raise ValueError("approval_factors must be a list")
            loaded: dict[str, ApprovalFactorRecord] = {}
            for item in factors:
                if not isinstance(item, dict):
                    raise ValueError("approval_factors entries must be objects")
                factor = ApprovalFactorRecord.model_validate(item)
                loaded[factor.credential_id] = factor
            self._approval_factors = loaded
        except (OSError, ValidationError, ValueError, json.JSONDecodeError):
            logger.warning(
                "Failed to load approval-factor store %s; quarantining corrupt state and "
                "starting with an empty factor set",
                path,
                exc_info=True,
            )
            self._quarantine_approval_store(path)
            self._approval_factors = {}

    def _persist_approval_factors(self) -> None:
        path = self._approval_store_path
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.parent.chmod(0o700)
        except OSError:
            logger.debug("Unable to chmod approval-factor store directory: %s", path.parent)
        payload = {
            "schema_version": "shisad.approval_factor_store.v1",
            "approval_factors": [
                factor.model_dump(mode="json")
                for factor in self.list_approval_factors()
            ],
        }
        tmp_path = path.with_suffix(f"{path.suffix}.tmp")
        tmp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            logger.debug("Unable to chmod approval-factor store file: %s", path)

    @staticmethod
    def _quarantine_approval_store(path: Path) -> None:
        if not path.exists():
            return
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        target = path.with_name(f"{path.name}.corrupt.{stamp}")
        counter = 1
        while target.exists():
            target = path.with_name(f"{path.name}.corrupt.{stamp}.{counter}")
            counter += 1
        try:
            os.replace(path, target)
            os.chmod(target, 0o600)
        except OSError:
            logger.warning(
                "Failed to quarantine corrupt approval-factor store %s",
                path,
                exc_info=True,
            )
