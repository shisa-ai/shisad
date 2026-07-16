"""Credential broker — proxy-level secret injection.

Implements the Deno Sandbox-inspired pattern: secrets never exist in the
agent runtime. The agent works with placeholder strings; real credentials
are injected only at the egress proxy boundary for pre-approved hosts.

    Planner → PEP → Tool Executor → Egress Proxy → Network
                     (placeholder)   (injects real secret
                                      only for approved hosts)
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import secrets
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, Field, ValidationError

from shisad.core.atomic_state import (
    AtomicWriteError,
    AtomicWriteFaultInjector,
    StateLoadResult,
    StateLoadStatus,
    StatePersistenceDegradedError,
    atomic_write_bytes,
    decode_versioned_json_snapshot,
    encode_versioned_json_snapshot,
    read_owner_only_regular_file,
    validate_owner_controlled_parent_ancestry,
)
from shisad.core.host_matching import host_matches
from shisad.core.types import CredentialRef

logger = logging.getLogger(__name__)

# Placeholder prefix — these strings are inert and useless if exfiltrated
_PLACEHOLDER_PREFIX = "SHISAD_SECRET_PLACEHOLDER_"
_LOCAL_FIDO2_RP_SUFFIX = ".approver.shisad.invalid"
_APPROVAL_STORE_VERSION = 3
_LEGACY_APPROVAL_STORE_SCHEMAS = {
    "shisad.approval_factor_store.v1",
    "shisad.approval_factor_store.v2",
}


class _ApprovalStorePayloadError(ValueError):
    """Semantic approval snapshot failure with a stable operator reason."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _normalize_local_fido2_realm_id(value: str) -> str:
    normalized = "".join(ch for ch in value.strip().lower() if ch.isalnum())
    if not normalized:
        raise ValueError("local_fido2 realm id must contain at least one alphanumeric character")
    return normalized


def _local_fido2_realm_id_from_rp_id(rp_id: str) -> str | None:
    candidate = rp_id.strip().lower()
    if not candidate.endswith(_LOCAL_FIDO2_RP_SUFFIX):
        return None
    prefix = candidate[: -len(_LOCAL_FIDO2_RP_SUFFIX)]
    if not prefix or any(not char.isalnum() for char in prefix):
        return None
    return prefix


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


class SignerKeyRecord(BaseModel):
    """Durable signer-key metadata stored alongside approval factors."""

    credential_id: str
    user_id: str
    backend: str
    principal_id: str
    algorithm: str
    device_type: str
    public_key_pem: str
    signing_scheme: str = "raw"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_verified_at: datetime | None = None
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None


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

    def approval_state_load_result(self) -> StateLoadResult:
        """Return the typed result from the current durable-state load."""
        ...

    def approval_state_status(self) -> dict[str, Any]:
        """Return bounded operator diagnostics for the approval authority."""
        ...

    def get_or_create_local_fido2_realm_id(self, *, seed: str = "") -> str:
        """Resolve the durable local-helper realm id for local_fido2 credentials."""
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

    def register_signer_key(self, record: SignerKeyRecord) -> None:
        """Persist a newly registered signer key."""
        ...

    def list_signer_keys(
        self,
        *,
        user_id: str | None = None,
        backend: str | None = None,
        include_revoked: bool = False,
    ) -> list[SignerKeyRecord]:
        """List signer keys, optionally filtered by user/backend."""
        ...

    def get_signer_key(self, credential_id: str) -> SignerKeyRecord | None:
        """Fetch one signer key by credential id."""
        ...

    def update_signer_key(self, record: SignerKeyRecord) -> None:
        """Persist an updated signer-key record."""
        ...

    def revoke_signer_key(self, *, credential_id: str) -> int:
        """Mark a signer key revoked and return the affected-row count."""
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
        self._signer_keys: dict[str, SignerKeyRecord] = {}
        self._local_fido2_realm_id: str | None = None
        self._approval_state_fault_injector: AtomicWriteFaultInjector | None = None
        self._approval_persistence_degradation: AtomicWriteError | None = None
        self._approval_load_result = StateLoadResult(StateLoadStatus.MISSING)
        self._durable_approval_factors: dict[str, ApprovalFactorRecord] = {}
        self._durable_signer_keys: dict[str, SignerKeyRecord] = {}
        self._durable_local_fido2_realm_id: str | None = None

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
        self._approval_persistence_degradation = None
        self._load_approval_factors()

    @property
    def approval_state_degraded(self) -> bool:
        return self._approval_persistence_degradation is not None or (
            self._approval_load_result.status
            in {StateLoadStatus.CORRUPT, StateLoadStatus.UNSUPPORTED_SCHEMA}
        )

    def approval_state_load_result(self) -> StateLoadResult:
        """Return the typed outcome of binding the durable approval authority."""
        return self._approval_load_result

    def reset_approval_state(self) -> tuple[int, int, int]:
        """Durably reset approval factors, signer keys, and rollback authority."""

        factor_count = len(self._approval_factors)
        signer_count = len(self._signer_keys)
        path = self._approval_store_path
        artifact_count = 0
        corrupt_artifacts: list[Path] = []
        if path is not None:
            try:
                path.lstat()
            except FileNotFoundError:
                pass
            else:
                artifact_count += 1
            corrupt_artifacts = list(path.parent.glob(f"{path.name}.corrupt.*"))
            artifact_count += len(corrupt_artifacts)
            encoded = encode_versioned_json_snapshot(
                {
                    "approval_factors": [],
                    "signer_keys": [],
                },
                version=_APPROVAL_STORE_VERSION,
            )
            try:
                atomic_write_bytes(
                    path,
                    encoded,
                    fault_injector=self._approval_state_fault_injector,
                    require_safe_parent_ancestry=True,
                )
            except AtomicWriteError as exc:
                self._approval_persistence_degradation = exc
                raise

        self._set_empty_approval_state()
        self._approval_persistence_degradation = None
        self._approval_load_result = StateLoadResult(
            StateLoadStatus.OK if path is not None else StateLoadStatus.MISSING,
            schema_version=_APPROVAL_STORE_VERSION if path is not None else None,
        )
        self._record_durable_approval_state()
        for artifact in corrupt_artifacts:
            artifact.unlink(missing_ok=True)
        return factor_count, signer_count, artifact_count

    def approval_state_status(self) -> dict[str, Any]:
        """Return actionable, bounded diagnostics without exposing factor data."""
        result = self._approval_load_result
        problems: list[str] = []
        remediation = ""
        stage = ""
        reason = result.reason
        if result.status == StateLoadStatus.CORRUPT:
            problems.append("approval_store_corrupt")
        elif result.status == StateLoadStatus.UNSUPPORTED_SCHEMA:
            problems.append("approval_store_unsupported_schema")
        degradation = self._approval_persistence_degradation
        if degradation is not None:
            problems.append("approval_store_publication_commit_uncertain")
            stage = degradation.stage.value
            reason = "prior_publication_commit_uncertain"
        if problems:
            remediation = (
                "Restore the retained approval store from a trusted backup, or explicitly "
                "audit and reset the complete approval authority before restarting shisad."
            )
        return {
            "status": "degraded" if problems else "ok",
            "problems": problems,
            "path": str(self._approval_store_path or ""),
            "load_status": result.status.value,
            "reason": reason,
            "schema_version": result.schema_version,
            "legacy": result.legacy,
            "fail_closed": bool(problems),
            "stage": stage,
            "remediation": remediation,
        }

    def _require_approval_state_available(self, *, transition: str) -> None:
        load_result = self._approval_load_result
        if load_result.status in {
            StateLoadStatus.CORRUPT,
            StateLoadStatus.UNSUPPORTED_SCHEMA,
        }:
            reason = load_result.reason or load_result.status.value
            raise StatePersistenceDegradedError(
                authority="approval_factors",
                transition=transition,
                stage="load",
                reason=reason,
            )
        degradation = self._approval_persistence_degradation
        if degradation is None:
            return
        raise StatePersistenceDegradedError(
            authority="approval_factors",
            transition=transition,
            stage=degradation.stage.value,
            reason="prior_publication_commit_uncertain",
        )

    @staticmethod
    def _clone_approval_factors(
        factors: dict[str, ApprovalFactorRecord],
    ) -> dict[str, ApprovalFactorRecord]:
        return {
            credential_id: factor.model_copy(deep=True) for credential_id, factor in factors.items()
        }

    @staticmethod
    def _clone_signer_keys(
        signer_keys: dict[str, SignerKeyRecord],
    ) -> dict[str, SignerKeyRecord]:
        return {
            credential_id: record.model_copy(deep=True)
            for credential_id, record in signer_keys.items()
        }

    def _record_durable_approval_state(self) -> None:
        self._durable_approval_factors = self._clone_approval_factors(self._approval_factors)
        self._durable_signer_keys = self._clone_signer_keys(self._signer_keys)
        self._durable_local_fido2_realm_id = self._local_fido2_realm_id

    def _restore_durable_approval_state(self) -> None:
        self._approval_factors = self._clone_approval_factors(self._durable_approval_factors)
        self._signer_keys = self._clone_signer_keys(self._durable_signer_keys)
        self._local_fido2_realm_id = self._durable_local_fido2_realm_id

    def get_or_create_local_fido2_realm_id(self, *, seed: str = "") -> str:
        """Return the durable local-helper realm id used for local_fido2 rpIds."""
        self._require_approval_state_available(transition="get_or_create_realm")
        existing = (self._local_fido2_realm_id or "").strip()
        if existing:
            return existing
        derived = self._derive_local_fido2_realm_id_from_records(self._approval_factors.values())
        if derived is not None:
            self._local_fido2_realm_id = derived
            return derived
        try:
            realm_id = _normalize_local_fido2_realm_id(seed)
        except ValueError:
            realm_id = secrets.token_hex(16)
        self._local_fido2_realm_id = realm_id
        return realm_id

    def register_approval_factor(self, factor: ApprovalFactorRecord) -> None:
        """Persist a newly enrolled approval factor."""
        self._require_approval_state_available(transition="register_factor")
        self._approval_factors[factor.credential_id] = factor.model_copy(deep=True)
        self._persist_approval_factors()

    def list_approval_factors(
        self,
        *,
        user_id: str | None = None,
        method: str | None = None,
    ) -> list[ApprovalFactorRecord]:
        """List approval factors, optionally filtered by user and method."""
        self._require_approval_state_available(transition="list_factors")
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
        self._require_approval_state_available(transition="get_factor")
        factor = self._approval_factors.get(str(credential_id))
        if factor is None:
            return None
        return factor.model_copy(deep=True)

    def update_approval_factor(self, factor: ApprovalFactorRecord) -> None:
        """Persist an updated approval factor record."""
        self._require_approval_state_available(transition="update_factor")
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
        self._require_approval_state_available(transition="revoke_factor")
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

    def register_signer_key(self, record: SignerKeyRecord) -> None:
        """Persist a newly registered signer key."""
        self._require_approval_state_available(transition="register_signer")
        if record.credential_id in self._signer_keys:
            raise KeyError(f"Signer key already exists: {record.credential_id}")
        self._signer_keys[record.credential_id] = record.model_copy(deep=True)
        self._persist_approval_factors()

    def list_signer_keys(
        self,
        *,
        user_id: str | None = None,
        backend: str | None = None,
        include_revoked: bool = False,
    ) -> list[SignerKeyRecord]:
        """List signer keys, optionally filtered by user/backend."""
        self._require_approval_state_available(transition="list_signers")
        rows = [
            record.model_copy(deep=True)
            for record in self._signer_keys.values()
            if (user_id is None or record.user_id == user_id)
            and (backend is None or record.backend == backend)
            and (include_revoked or record.revoked_at is None)
        ]
        rows.sort(
            key=lambda item: (item.created_at, item.user_id, item.backend, item.credential_id)
        )
        return rows

    def get_signer_key(self, credential_id: str) -> SignerKeyRecord | None:
        """Fetch one signer key by credential id."""
        self._require_approval_state_available(transition="get_signer")
        record = self._signer_keys.get(str(credential_id))
        if record is None:
            return None
        return record.model_copy(deep=True)

    def update_signer_key(self, record: SignerKeyRecord) -> None:
        """Persist an updated signer-key record."""
        self._require_approval_state_available(transition="update_signer")
        if record.credential_id not in self._signer_keys:
            raise KeyError(f"Unknown signer key: {record.credential_id}")
        self._signer_keys[record.credential_id] = record.model_copy(deep=True)
        self._persist_approval_factors()

    def revoke_signer_key(self, *, credential_id: str) -> int:
        """Mark a signer key revoked and return the affected-row count."""
        self._require_approval_state_available(transition="revoke_signer")
        record = self._signer_keys.get(str(credential_id))
        if record is None or record.revoked_at is not None:
            return 0
        updated = record.model_copy(deep=True)
        updated.revoked_at = datetime.now(UTC)
        self._signer_keys[updated.credential_id] = updated
        self._persist_approval_factors()
        return 1

    @staticmethod
    def _host_allowed(host: str, allowed: list[str]) -> bool:
        """Check if a host matches any pattern in the allowlist."""
        return any(host_matches(host, pattern) for pattern in allowed)

    def _set_empty_approval_state(self) -> None:
        self._approval_factors = {}
        self._signer_keys = {}
        self._local_fido2_realm_id = None
        self._record_durable_approval_state()

    def _set_approval_load_failure(self, result: StateLoadResult) -> None:
        self._approval_load_result = result
        self._set_empty_approval_state()
        logger.warning(
            "Approval-factor store load is fail-closed: path=%s status=%s reason=%s",
            self._approval_store_path,
            result.status.value,
            result.reason,
        )

    @staticmethod
    def _decode_approval_payload(
        payload: Any,
        *,
        allow_missing_signer_keys: bool = False,
    ) -> tuple[
        dict[str, ApprovalFactorRecord],
        dict[str, SignerKeyRecord],
        str | None,
    ]:
        if not isinstance(payload, dict):
            raise _ApprovalStorePayloadError("invalid_payload")
        if "approval_factors" not in payload:
            raise _ApprovalStorePayloadError("missing_approval_factors")
        factors = payload["approval_factors"]
        if not isinstance(factors, list):
            raise _ApprovalStorePayloadError("invalid_approval_factors")
        loaded: dict[str, ApprovalFactorRecord] = {}
        try:
            for item in factors:
                if not isinstance(item, dict):
                    raise _ApprovalStorePayloadError("invalid_approval_factors")
                factor = ApprovalFactorRecord.model_validate(item)
                if factor.credential_id in loaded:
                    raise _ApprovalStorePayloadError("duplicate_approval_factor")
                loaded[factor.credential_id] = factor
        except ValidationError as exc:
            raise _ApprovalStorePayloadError("invalid_approval_factors") from exc

        if "signer_keys" not in payload and not allow_missing_signer_keys:
            raise _ApprovalStorePayloadError("missing_signer_keys")
        signer_payload = payload.get("signer_keys", [])
        if not isinstance(signer_payload, list):
            raise _ApprovalStorePayloadError("invalid_signer_keys")
        signer_keys: dict[str, SignerKeyRecord] = {}
        try:
            for item in signer_payload:
                if not isinstance(item, dict):
                    raise _ApprovalStorePayloadError("invalid_signer_keys")
                record = SignerKeyRecord.model_validate(item)
                if record.credential_id in signer_keys:
                    raise _ApprovalStorePayloadError("duplicate_signer_key")
                signer_keys[record.credential_id] = record
        except ValidationError as exc:
            raise _ApprovalStorePayloadError("invalid_signer_keys") from exc

        local_fido2_realm_id_raw = str(payload.get("local_fido2_realm_id", "")).strip()
        realm_id: str | None
        try:
            if local_fido2_realm_id_raw:
                realm_id = _normalize_local_fido2_realm_id(local_fido2_realm_id_raw)
            else:
                realm_id = InMemoryCredentialStore._derive_local_fido2_realm_id_from_records(
                    loaded.values()
                )
        except ValueError as exc:
            raise _ApprovalStorePayloadError("invalid_local_fido2_realm") from exc
        return loaded, signer_keys, realm_id

    def _load_approval_factors(self) -> None:
        path = self._approval_store_path
        if path is None:
            self._approval_load_result = StateLoadResult(StateLoadStatus.MISSING)
            self._set_empty_approval_state()
            return
        try:
            validate_owner_controlled_parent_ancestry(path)
        except OSError:
            self._set_approval_load_failure(
                StateLoadResult(StateLoadStatus.CORRUPT, reason="read_error")
            )
            return
        try:
            path.lstat()
            exists = True
        except FileNotFoundError:
            exists = False
        except OSError:
            self._set_approval_load_failure(
                StateLoadResult(StateLoadStatus.CORRUPT, reason="target_status_error")
            )
            return
        if not exists:
            try:
                prior_corrupt = next(
                    path.parent.glob(f"{path.name}.corrupt.*"),
                    None,
                )
            except OSError:
                self._set_approval_load_failure(
                    StateLoadResult(StateLoadStatus.CORRUPT, reason="artifact_scan_error")
                )
                return
            if prior_corrupt is not None:
                self._set_approval_load_failure(
                    StateLoadResult(
                        StateLoadStatus.CORRUPT,
                        reason="prior_corrupt_artifact_present",
                    )
                )
                return
            self._approval_load_result = StateLoadResult(StateLoadStatus.MISSING)
            self._set_empty_approval_state()
            return

        try:
            raw_bytes = read_owner_only_regular_file(path)
        except OSError:
            self._set_approval_load_failure(
                StateLoadResult(StateLoadStatus.CORRUPT, reason="read_error")
            )
            return
        if raw_bytes is None:
            self._set_approval_load_failure(
                StateLoadResult(StateLoadStatus.CORRUPT, reason="read_error")
            )
            return

        try:
            raw_payload = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError, RecursionError):
            self._set_approval_load_failure(
                StateLoadResult(StateLoadStatus.CORRUPT, reason="invalid_json")
            )
            return

        has_legacy_marker = isinstance(raw_payload, dict) and "schema_version" in raw_payload
        envelope_markers = (
            {"version", "checksum", "payload"}.intersection(raw_payload)
            if isinstance(raw_payload, dict)
            else set()
        )
        if has_legacy_marker and envelope_markers:
            self._set_approval_load_failure(
                StateLoadResult(
                    StateLoadStatus.CORRUPT,
                    reason="ambiguous_snapshot_format",
                )
            )
            return
        legacy = has_legacy_marker
        allow_missing_signer_keys = False
        if legacy:
            schema = str(raw_payload.get("schema_version", "")).strip()
            if schema not in _LEGACY_APPROVAL_STORE_SCHEMAS:
                version: int | None = None
                if schema.startswith("shisad.approval_factor_store.v"):
                    with contextlib.suppress(ValueError):
                        version = int(schema.rsplit("v", 1)[1])
                self._set_approval_load_failure(
                    StateLoadResult(
                        StateLoadStatus.UNSUPPORTED_SCHEMA,
                        reason="unsupported_schema",
                        schema_version=version,
                    )
                )
                return
            payload = raw_payload
            result = StateLoadResult(StateLoadStatus.OK, legacy=True)
            allow_missing_signer_keys = schema == "shisad.approval_factor_store.v1"
        else:
            result, payload = decode_versioned_json_snapshot(
                raw_bytes,
                supported_version=_APPROVAL_STORE_VERSION,
            )
            if result.status != StateLoadStatus.OK:
                self._set_approval_load_failure(result)
                return

        try:
            loaded, signer_keys, realm_id = self._decode_approval_payload(
                payload,
                allow_missing_signer_keys=allow_missing_signer_keys,
            )
        except _ApprovalStorePayloadError as exc:
            self._set_approval_load_failure(
                StateLoadResult(
                    StateLoadStatus.CORRUPT,
                    reason=exc.reason,
                    schema_version=result.schema_version,
                    legacy=result.legacy,
                )
            )
            return
        self._approval_factors = loaded
        self._signer_keys = signer_keys
        self._local_fido2_realm_id = realm_id
        self._approval_load_result = result
        self._record_durable_approval_state()

    def _persist_approval_factors(self) -> None:
        path = self._approval_store_path
        if path is None:
            return
        self._require_approval_state_available(transition="persist")
        try:
            payload: dict[str, Any] = {
                "approval_factors": [
                    factor.model_dump(mode="json") for factor in self.list_approval_factors()
                ],
                "signer_keys": [
                    record.model_dump(mode="json")
                    for record in self.list_signer_keys(include_revoked=True)
                ],
            }
            if self._local_fido2_realm_id:
                payload["local_fido2_realm_id"] = self._local_fido2_realm_id
            encoded = encode_versioned_json_snapshot(
                payload,
                version=_APPROVAL_STORE_VERSION,
            )
        except (TypeError, ValueError):
            self._restore_durable_approval_state()
            raise
        try:
            atomic_write_bytes(
                path,
                encoded,
                fault_injector=self._approval_state_fault_injector,
                require_safe_parent_ancestry=True,
            )
        except AtomicWriteError as exc:
            if exc.publication_may_have_committed:
                self._approval_persistence_degradation = exc
            else:
                self._restore_durable_approval_state()
            raise
        self._approval_load_result = StateLoadResult(
            StateLoadStatus.OK,
            schema_version=_APPROVAL_STORE_VERSION,
        )
        self._record_durable_approval_state()

    @staticmethod
    def _derive_local_fido2_realm_id_from_records(
        records: Iterable[ApprovalFactorRecord],
    ) -> str | None:
        derived_ids: set[str] = set()
        saw_local_fido2 = False
        for factor in records:
            if factor.method != "local_fido2":
                continue
            saw_local_fido2 = True
            derived = _local_fido2_realm_id_from_rp_id(factor.webauthn_rp_id)
            if derived is None:
                raise ValueError("local_fido2 factor is missing a parseable webauthn_rp_id")
            derived_ids.add(derived)
        if not saw_local_fido2:
            return None
        if len(derived_ids) != 1:
            raise ValueError("local_fido2 factors use inconsistent webauthn_rp_id values")
        return next(iter(derived_ids))
