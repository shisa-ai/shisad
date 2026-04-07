"""Shared approval protocol types and helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import math
import os
import secrets
from collections import defaultdict
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum, StrEnum
from pathlib import Path
from typing import Any, Literal, Protocol
from urllib.parse import quote, urlparse

from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestedCredentialData,
    AuthenticationResponse,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    RegistrationResponse,
    UserVerificationRequirement,
)
from pydantic import BaseModel, Field, ValidationError, model_validator

from shisad.core.tools.schema import ToolDefinition
from shisad.security.credentials import ApprovalFactorRecord, ApprovalFactorStore

logger = logging.getLogger(__name__)


def _default_origin_port(scheme: str) -> int | None:
    normalized = scheme.strip().lower()
    if normalized == "http":
        return 80
    if normalized == "https":
        return 443
    return None


def _format_origin_host(host: str) -> str:
    normalized = host.strip().lower()
    if ":" in normalized:
        return f"[{normalized}]"
    return normalized


def _canonicalize_webauthn_origin(
    origin: str,
    *,
    require_canonical_input: bool = False,
) -> str | None:
    parsed = urlparse(origin.strip())
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").strip().lower()
    if not scheme or not host:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    default_port = _default_origin_port(scheme)
    if default_port is None:
        return None
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        return None
    if require_canonical_input:
        if parsed.path:
            return None
    elif parsed.path not in {"", "/"}:
        return None
    if port is None or port == default_port:
        canonical = f"{scheme}://{_format_origin_host(host)}"
    else:
        canonical = f"{scheme}://{_format_origin_host(host)}:{port}"
    if require_canonical_input and origin.strip() != canonical:
        return None
    return canonical


def _origin_matches(candidate: str, expected: str) -> bool:
    candidate_origin = _canonicalize_webauthn_origin(
        candidate,
        require_canonical_input=True,
    )
    expected_origin = _canonicalize_webauthn_origin(expected)
    return candidate_origin is not None and candidate_origin == expected_origin


class ConfirmationLevel(StrEnum):
    SOFTWARE = "software"
    REAUTHENTICATED = "reauthenticated"
    BOUND_APPROVAL = "bound_approval"
    SIGNED_AUTHORIZATION = "signed_authorization"
    TRUSTED_DISPLAY_AUTHORIZATION = "trusted_display_authorization"

    @property
    def priority(self) -> int:
        return {
            ConfirmationLevel.SOFTWARE: 0,
            ConfirmationLevel.REAUTHENTICATED: 1,
            ConfirmationLevel.BOUND_APPROVAL: 2,
            ConfirmationLevel.SIGNED_AUTHORIZATION: 3,
            ConfirmationLevel.TRUSTED_DISPLAY_AUTHORIZATION: 4,
        }[self]


class BindingScope(StrEnum):
    NONE = "none"
    ACTION_DIGEST = "action_digest"
    APPROVAL_ENVELOPE = "approval_envelope"
    FULL_INTENT = "full_intent"


class ReviewSurface(StrEnum):
    HOST_RENDERED = "host_rendered"
    SECONDARY_APP = "secondary_app"
    BROWSER_RENDERED = "browser_rendered"
    PROVIDER_UI = "provider_ui"
    TRUSTED_DEVICE_DISPLAY = "trusted_device_display"
    OPAQUE_DEVICE = "opaque_device"


class ConfirmationCapabilities(BaseModel):
    """Capability flags advertised by confirmation backends."""

    principal_binding: bool = False
    approval_binding: bool = False
    action_digest_binding: bool = False
    full_intent_signature: bool = False
    trusted_display: bool = False
    third_party_verifiable: bool = False
    blind_sign_detection: bool = False

    model_config = {"frozen": True}

    def covers(self, required: ConfirmationCapabilities) -> bool:
        return all(
            not getattr(required, field_name) or getattr(self, field_name)
            for field_name in type(self).model_fields
        )

    def merge(self, other: ConfirmationCapabilities) -> ConfirmationCapabilities:
        payload = {
            field_name: bool(getattr(self, field_name) or getattr(other, field_name))
            for field_name in type(self).model_fields
        }
        return ConfirmationCapabilities.model_validate(payload)


class ConfirmationFallbackPolicy(BaseModel):
    """Explicit fallback rules for approval routing."""

    mode: Literal["deny", "allow_levels"] = "deny"
    allow_levels: list[ConfirmationLevel] = Field(default_factory=list)

    @model_validator(mode="after")
    def _normalize(self) -> ConfirmationFallbackPolicy:
        if self.mode != "allow_levels":
            self.allow_levels = []
            return self
        deduped: list[ConfirmationLevel] = []
        for level in self.allow_levels:
            if level not in deduped:
                deduped.append(level)
        self.allow_levels = deduped
        return self


class ConfirmationRequirement(BaseModel):
    """Runtime-normalized confirmation requirements."""

    level: ConfirmationLevel = ConfirmationLevel.SOFTWARE
    methods: list[str] = Field(default_factory=list)
    allowed_principals: list[str] = Field(default_factory=list)
    allowed_credentials: list[str] = Field(default_factory=list)
    require_capabilities: ConfirmationCapabilities = Field(
        default_factory=ConfirmationCapabilities
    )
    fallback: ConfirmationFallbackPolicy = Field(default_factory=ConfirmationFallbackPolicy)
    timeout_seconds: int | None = None
    routeable: bool = Field(default=True, exclude=True)
    route_reason: str = Field(default="", exclude=True)

    @model_validator(mode="after")
    def _normalize(self) -> ConfirmationRequirement:
        def _dedupe(values: list[str]) -> list[str]:
            rows: list[str] = []
            for value in values:
                text = str(value).strip()
                if text and text not in rows:
                    rows.append(text)
            return rows

        self.methods = _dedupe(self.methods)
        self.allowed_principals = _dedupe(self.allowed_principals)
        self.allowed_credentials = _dedupe(self.allowed_credentials)
        if self.timeout_seconds is not None:
            self.timeout_seconds = max(1, int(self.timeout_seconds))
        return self


class RiskConfirmationLevelRule(BaseModel):
    """Risk-threshold -> confirmation-level escalation mapping."""

    threshold: float = Field(ge=0.0, le=1.0)
    level: ConfirmationLevel

    model_config = {"frozen": True}


class ApprovalEnvelope(BaseModel):
    """Canonical approval request bound to a pending action."""

    schema_version: str = "shisad.approval.v1"
    approval_id: str
    pending_action_id: str
    workspace_id: str
    daemon_id: str
    session_id: str
    required_level: ConfirmationLevel
    policy_reason: str = ""
    action_digest: str
    allowed_principals: list[str] = Field(default_factory=list)
    allowed_credentials: list[str] = Field(default_factory=list)
    expires_at: datetime | None = None
    nonce: str
    intent_envelope_hash: str | None = None
    action_summary: str = ""

    model_config = {"frozen": True}

    def core_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"action_summary"})


class ConfirmationEvidence(BaseModel):
    """Verified evidence returned by a confirmation backend."""

    schema_version: str = "shisad.confirmation_evidence.v1"
    level: ConfirmationLevel
    method: str
    backend_id: str = ""
    approver_principal_id: str = ""
    credential_id: str = ""
    binding_scope: BindingScope = BindingScope.NONE
    review_surface: ReviewSurface = ReviewSurface.HOST_RENDERED
    third_party_verifiable: bool = False
    approval_envelope_hash: str = ""
    action_digest: str = ""
    decision_nonce: str = ""
    fallback_used: bool = False
    evidence_payload: dict[str, Any] = Field(default_factory=dict)
    evidence_hash: str = ""
    intent_envelope_hash: str = ""
    signature: str = ""
    signer_key_id: str = ""
    blind_sign_detected: bool = False
    verified_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


def legacy_software_confirmation_requirement() -> ConfirmationRequirement:
    return ConfirmationRequirement(level=ConfirmationLevel.SOFTWARE)


def merge_confirmation_requirements(
    requirements: list[ConfirmationRequirement],
) -> ConfirmationRequirement | None:
    if not requirements:
        return None

    max_level = max(requirements, key=lambda item: item.level.priority).level
    selected = [item for item in requirements if item.level == max_level]
    conflicts: list[str] = []

    def _merge_list(field_name: str) -> list[str]:
        non_empty = [
            list(getattr(item, field_name))
            for item in requirements
            if getattr(item, field_name)
        ]
        if not non_empty:
            return []
        current = list(non_empty[0])
        for values in non_empty[1:]:
            current = [value for value in current if value in values]
        if not current:
            conflicts.append(field_name)
        return current

    capabilities = ConfirmationCapabilities()
    for requirement in requirements:
        capabilities = capabilities.merge(requirement.require_capabilities)

    fallback_mode = "deny"
    fallback_levels: list[ConfirmationLevel] = []
    allow_fallbacks = [
        item.fallback for item in selected if item.fallback.mode == "allow_levels"
    ]
    if allow_fallbacks and len(allow_fallbacks) == len(selected):
        fallback_levels = list(allow_fallbacks[0].allow_levels)
        for fallback in allow_fallbacks[1:]:
            fallback_levels = [level for level in fallback_levels if level in fallback.allow_levels]
        if fallback_levels:
            fallback_mode = "allow_levels"

    methods = _merge_list("methods")
    allowed_principals = _merge_list("allowed_principals")
    allowed_credentials = _merge_list("allowed_credentials")
    timeouts = [item.timeout_seconds for item in requirements if item.timeout_seconds is not None]
    route_reason = (
        "confirmation_requirement_conflict:" + ",".join(conflicts) if conflicts else ""
    )
    return ConfirmationRequirement(
        level=max_level,
        methods=methods,
        allowed_principals=allowed_principals,
        allowed_credentials=allowed_credentials,
        require_capabilities=capabilities,
        fallback=ConfirmationFallbackPolicy(mode=fallback_mode, allow_levels=fallback_levels),
        timeout_seconds=min(timeouts) if timeouts else None,
        routeable=not conflicts,
        route_reason=route_reason,
    )


def confirmation_requirement_payload(requirement: ConfirmationRequirement) -> dict[str, Any]:
    payload = requirement.model_dump(mode="json")
    payload["routeable"] = requirement.routeable
    payload["route_reason"] = requirement.route_reason
    return payload


def canonical_json_dumps(value: Any) -> str:
    """Serialize a JSON payload deterministically for approval hashing."""

    def _normalize(candidate: Any) -> Any:
        if isinstance(candidate, BaseModel):
            return _normalize(candidate.model_dump(mode="json"))
        if isinstance(candidate, datetime):
            if candidate.tzinfo is None or candidate.utcoffset() is None:
                raise ValueError("naive datetimes are not allowed in canonical JSON")
            return candidate.astimezone(UTC).isoformat().replace("+00:00", "Z")
        if isinstance(candidate, dict):
            return {
                str(key): _normalize(val)
                for key, val in sorted(candidate.items(), key=lambda item: str(item[0]))
            }
        if isinstance(candidate, (list, tuple)):
            return [_normalize(item) for item in candidate]
        if isinstance(candidate, float) and not math.isfinite(candidate):
            raise ValueError("non-finite floats are not allowed in canonical JSON")
        if isinstance(candidate, os.PathLike):
            return os.fspath(candidate)
        return candidate

    normalized = _normalize(value)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_sha256(value: Any) -> str:
    return f"sha256:{hashlib.sha256(canonical_json_dumps(value).encode('utf-8')).hexdigest()}"


def _quarantine_state_file(path: Path, *, label: str) -> None:
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
        with suppress(OSError):
            os.chmod(target, 0o600)
    except OSError:
        logger.warning("Failed to quarantine corrupt %s state file %s", label, path, exc_info=True)


def new_approval_nonce() -> str:
    return "b64:" + base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")


def resolve_confirmation_destinations(
    *,
    tool_definition: ToolDefinition,
    arguments: dict[str, Any],
) -> list[str]:
    """Resolve destination/path sinks for action-digest binding."""

    resolved: set[str] = set()

    def _add_url(candidate: str) -> None:
        text = candidate.strip()
        if not text:
            return
        parsed = urlparse(text if "://" in text else f"https://{text}")
        host = (parsed.hostname or "").strip().lower()
        if not host:
            return
        resolved.add(host)

    def _add_path(candidate: str) -> None:
        text = candidate.strip()
        if text:
            resolved.add(os.path.abspath(text))

    for destination in tool_definition.destinations:
        _add_url(str(destination))

    for key, value in arguments.items():
        if isinstance(value, str):
            if key in {"url", "destination", "recipient"}:
                _add_url(value)
            elif key == "credential_ref":
                continue
            elif key == "path" or key.endswith("_path") or key in {"cwd", "repo"}:
                _add_path(value)
        elif isinstance(value, list):
            for item in value:
                if not isinstance(item, str):
                    continue
                if key in {"network_urls", "urls"}:
                    _add_url(item)
                elif key in {"paths", "read_paths", "write_paths"} or key.endswith("_paths"):
                    _add_path(item)

    return sorted(resolved)


def compute_action_digest(
    *,
    tool_definition: ToolDefinition,
    arguments: dict[str, Any],
    destinations: list[str] | None = None,
) -> str:
    payload = {
        "schema_version": "shisad.action_digest.v1",
        "tool_name": str(tool_definition.name),
        "tool_schema_hash": f"sha256:{tool_definition.schema_hash()}",
        "arguments": dict(arguments),
        "destinations": sorted(
            {str(item).strip() for item in (destinations or []) if str(item).strip()}
        ),
    }
    return canonical_sha256(payload)


def approval_envelope_hash(envelope: ApprovalEnvelope | dict[str, Any]) -> str:
    payload = envelope.core_payload() if isinstance(envelope, ApprovalEnvelope) else dict(envelope)
    payload.pop("action_summary", None)
    return canonical_sha256(payload)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def approval_envelope_hash_bytes(envelope_hash: str) -> bytes:
    prefix = "sha256:"
    if not envelope_hash.startswith(prefix):
        raise ValueError("approval envelope hash must use sha256: prefix")
    digest = envelope_hash[len(prefix) :].strip()
    if len(digest) != 64:
        raise ValueError("approval envelope hash must contain 32 raw digest bytes")
    try:
        return bytes.fromhex(digest)
    except ValueError as exc:
        raise ValueError("approval envelope hash is not valid hex") from exc


def webauthn_jsonify(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): webauthn_jsonify(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [webauthn_jsonify(item) for item in value]
    if isinstance(value, bytes):
        return _b64url_encode(value)
    if isinstance(value, Enum):
        return value.value
    return value


def generate_totp_secret(*, num_bytes: int = 20) -> str:
    raw = secrets.token_bytes(max(20, int(num_bytes)))
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def build_totp_otpauth_uri(
    *,
    issuer: str,
    user_id: str,
    secret_b32: str,
    principal_id: str,
    digits: int = 6,
    period_seconds: int = 30,
) -> str:
    label = quote(f"{issuer}:{user_id}")
    issuer_value = quote(issuer)
    principal_value = quote(principal_id)
    return (
        f"otpauth://totp/{label}"
        f"?secret={secret_b32}"
        f"&issuer={issuer_value}"
        f"&algorithm=SHA1"
        f"&digits={digits}"
        f"&period={period_seconds}"
        f"&principal={principal_value}"
    )


def _normalize_recovery_code(value: str) -> str:
    return "".join(ch for ch in value.strip().upper() if ch.isalnum())


def hash_recovery_code(value: str) -> str:
    normalized = _normalize_recovery_code(value)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def generate_recovery_codes(*, count: int = 8) -> list[str]:
    alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    rows: list[str] = []
    for _ in range(max(1, int(count))):
        token = "".join(secrets.choice(alphabet) for _unused in range(8))
        rows.append(f"{token[:4]}-{token[4:]}")
    return rows


def _totp_counter(*, now: datetime, period_seconds: int) -> int:
    return int(now.astimezone(UTC).timestamp() // period_seconds)


def generate_totp_code(
    secret_b32: str,
    *,
    now: datetime | None = None,
    digits: int = 6,
    period_seconds: int = 30,
) -> str:
    current = now or datetime.now(UTC)
    counter = _totp_counter(now=current, period_seconds=period_seconds)
    secret = base64.b32decode(secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8))
    mac = hmac.new(secret, counter.to_bytes(8, byteorder="big"), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    truncated = (
        ((mac[offset] & 0x7F) << 24)
        | (mac[offset + 1] << 16)
        | (mac[offset + 2] << 8)
        | mac[offset + 3]
    )
    code = truncated % (10**digits)
    return f"{code:0{digits}d}"


def _match_totp_window(
    *,
    secret_b32: str,
    code: str,
    now: datetime,
    digits: int = 6,
    period_seconds: int = 30,
    window: int = 1,
) -> int | None:
    expected = str(code).strip()
    base_counter = _totp_counter(now=now, period_seconds=period_seconds)
    for offset in range(-window, window + 1):
        candidate_time = now + timedelta(seconds=offset * period_seconds)
        candidate_code = generate_totp_code(
            secret_b32,
            now=candidate_time,
            digits=digits,
            period_seconds=period_seconds,
        )
        if hmac.compare_digest(candidate_code, expected):
            return base_counter + offset
    return None


def match_totp_window(
    *,
    secret_b32: str,
    code: str,
    now: datetime,
    digits: int = 6,
    period_seconds: int = 30,
    window: int = 1,
) -> int | None:
    return _match_totp_window(
        secret_b32=secret_b32,
        code=code,
        now=now,
        digits=digits,
        period_seconds=period_seconds,
        window=window,
    )


class ConfirmationVerificationError(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ApprovalRoutingError(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _approval_binding_inputs(pending_action: Any) -> tuple[str, str]:
    envelope_hash = str(getattr(pending_action, "approval_envelope_hash", "")).strip()
    if not envelope_hash:
        envelope = getattr(pending_action, "approval_envelope", None)
        if envelope is not None:
            envelope_hash = approval_envelope_hash(envelope)
    if not envelope_hash:
        raise ConfirmationVerificationError("approval_envelope_missing")
    action_digest = str(
        getattr(
            getattr(pending_action, "approval_envelope", None),
            "action_digest",
            "",
        )
    ).strip()
    if not action_digest:
        raise ConfirmationVerificationError("action_digest_missing")
    return envelope_hash, action_digest


class ConfirmationBackend(Protocol):
    backend_id: str
    method: str
    level: ConfirmationLevel
    binding_scope: BindingScope
    review_surface: ReviewSurface
    available_principals: set[str]
    available_credentials: set[str]
    capabilities: ConfirmationCapabilities
    third_party_verifiable: bool

    def is_available_for(self, *, user_id: str) -> bool:
        ...

    def principals_for_user(self, *, user_id: str) -> set[str]:
        ...

    def credentials_for_user(self, *, user_id: str) -> set[str]:
        ...

    def verify(
        self,
        *,
        pending_action: Any,
        params: dict[str, Any],
        now: datetime | None = None,
    ) -> ConfirmationEvidence:
        ...


class SoftwareConfirmationBackend:
    def __init__(self) -> None:
        self.backend_id = "software.default"
        self.method = "software"
        self.level = ConfirmationLevel.SOFTWARE
        self.binding_scope = BindingScope.NONE
        self.review_surface = ReviewSurface.HOST_RENDERED
        self.available_principals: set[str] = set()
        self.available_credentials: set[str] = set()
        self.capabilities = ConfirmationCapabilities()
        self.third_party_verifiable = False

    def is_available_for(self, *, user_id: str) -> bool:
        _ = user_id
        return True

    def principals_for_user(self, *, user_id: str) -> set[str]:
        _ = user_id
        return set()

    def credentials_for_user(self, *, user_id: str) -> set[str]:
        _ = user_id
        return set()

    def verify(
        self,
        *,
        pending_action: Any,
        params: dict[str, Any],
        now: datetime | None = None,
    ) -> ConfirmationEvidence:
        _ = now
        requested_method = str(
            params.get("approval_method")
            or params.get("method")
            or self.method
        ).strip()
        if requested_method and requested_method != self.method:
            raise ConfirmationVerificationError("confirmation_method_mismatch")

        decision_nonce = str(params.get("decision_nonce", "")).strip()
        if getattr(pending_action, "allowed_principals", ()):
            raise ConfirmationVerificationError("confirmation_principal_binding_unavailable")
        if getattr(pending_action, "allowed_credentials", ()):
            raise ConfirmationVerificationError("confirmation_credential_binding_unavailable")

        principal_id = ""
        envelope_hash, action_digest = _approval_binding_inputs(pending_action)
        payload = {
            "schema_version": "shisad.confirmation_evidence.v1",
            "backend_id": self.backend_id,
            "method": self.method,
            "confirmation_id": str(getattr(pending_action, "confirmation_id", "")),
            "decision_nonce": decision_nonce,
            "approval_envelope_hash": envelope_hash,
            "action_digest": action_digest,
            "approver_principal_id": principal_id,
            "fallback_used": bool(getattr(pending_action, "fallback_used", False)),
        }
        return ConfirmationEvidence(
            level=self.level,
            method=self.method,
            backend_id=self.backend_id,
            approver_principal_id=principal_id,
            binding_scope=self.binding_scope,
            review_surface=self.review_surface,
            third_party_verifiable=self.third_party_verifiable,
            approval_envelope_hash=envelope_hash,
            action_digest=str(payload["action_digest"]),
            decision_nonce=decision_nonce,
            fallback_used=bool(payload["fallback_used"]),
            evidence_payload=payload,
            evidence_hash=canonical_sha256(payload),
        )


class TOTPBackend:
    def __init__(
        self,
        *,
        credential_store: ApprovalFactorStore,
        issuer: str = "shisad",
    ) -> None:
        self.backend_id = "totp.default"
        self.method = "totp"
        self.level = ConfirmationLevel.REAUTHENTICATED
        self.binding_scope = BindingScope.NONE
        self.review_surface = ReviewSurface.HOST_RENDERED
        self.available_principals: set[str] = set()
        self.available_credentials: set[str] = set()
        self.capabilities = ConfirmationCapabilities(principal_binding=True)
        self.third_party_verifiable = False
        self._credential_store = credential_store
        self._issuer = issuer

    def is_available_for(self, *, user_id: str) -> bool:
        return bool(self._candidate_factors(user_id=user_id))

    def principals_for_user(self, *, user_id: str) -> set[str]:
        return {factor.principal_id for factor in self._candidate_factors(user_id=user_id)}

    def credentials_for_user(self, *, user_id: str) -> set[str]:
        return {factor.credential_id for factor in self._candidate_factors(user_id=user_id)}

    def enrollment_uri(
        self,
        *,
        user_id: str,
        principal_id: str,
        secret_b32: str,
    ) -> str:
        return build_totp_otpauth_uri(
            issuer=self._issuer,
            user_id=user_id,
            secret_b32=secret_b32,
            principal_id=principal_id,
        )

    def verify(
        self,
        *,
        pending_action: Any,
        params: dict[str, Any],
        now: datetime | None = None,
    ) -> ConfirmationEvidence:
        current = now or datetime.now(UTC)
        requested_method = str(
            params.get("approval_method")
            or params.get("method")
            or self.method
        ).strip() or self.method
        if requested_method not in {self.method, "recovery_code"}:
            raise ConfirmationVerificationError("confirmation_method_mismatch")

        decision_nonce = str(params.get("decision_nonce", "")).strip()
        proof = params.get("proof")
        proof_payload = proof if isinstance(proof, dict) else {}
        user_id = str(getattr(pending_action, "user_id", "")).strip()
        if not user_id:
            raise ConfirmationVerificationError("confirmation_user_missing")

        factors = self._matching_factors(
            user_id=user_id,
            pending_action=pending_action,
            requested_credential_id=str(params.get("credential_id", "")).strip(),
        )
        if not factors:
            raise ConfirmationVerificationError("confirmation_credential_missing")

        envelope_hash, action_digest = _approval_binding_inputs(pending_action)

        if requested_method == "recovery_code":
            recovery_code = str(proof_payload.get("recovery_code", "")).strip()
            if not recovery_code:
                raise ConfirmationVerificationError("missing_recovery_code")
            factor = self._consume_recovery_code(
                factors=factors,
                recovery_code=recovery_code,
                confirmation_id=str(getattr(pending_action, "confirmation_id", "")),
                now=current,
            )
        else:
            totp_code = str(
                proof_payload.get("totp_code")
                or proof_payload.get("code")
                or ""
            ).strip()
            if not totp_code:
                raise ConfirmationVerificationError("missing_totp_code")
            factor = self._verify_totp_code(
                factors=factors,
                totp_code=totp_code,
                confirmation_id=str(getattr(pending_action, "confirmation_id", "")),
                now=current,
            )

        if (
            getattr(pending_action, "allowed_principals", ())
            and factor.principal_id not in getattr(pending_action, "allowed_principals", ())
        ):
            raise ConfirmationVerificationError("confirmation_principal_not_allowed")
        if (
            getattr(pending_action, "allowed_credentials", ())
            and factor.credential_id not in getattr(pending_action, "allowed_credentials", ())
        ):
            raise ConfirmationVerificationError("confirmation_credential_not_allowed")

        payload = {
            "schema_version": "shisad.confirmation_evidence.v1",
            "backend_id": self.backend_id,
            "method": requested_method,
            "confirmation_id": str(getattr(pending_action, "confirmation_id", "")),
            "decision_nonce": decision_nonce,
            "approval_envelope_hash": envelope_hash,
            "action_digest": action_digest,
            "approver_principal_id": factor.principal_id,
            "credential_id": factor.credential_id,
            "fallback_used": bool(getattr(pending_action, "fallback_used", False)),
        }
        return ConfirmationEvidence(
            level=self.level,
            method=requested_method,
            backend_id=self.backend_id,
            approver_principal_id=factor.principal_id,
            credential_id=factor.credential_id,
            binding_scope=self.binding_scope,
            review_surface=self.review_surface,
            third_party_verifiable=self.third_party_verifiable,
            approval_envelope_hash=envelope_hash,
            action_digest=action_digest,
            decision_nonce=decision_nonce,
            fallback_used=bool(payload["fallback_used"]),
            evidence_payload=payload,
            evidence_hash=canonical_sha256(payload),
        )

    def _candidate_factors(self, *, user_id: str) -> list[ApprovalFactorRecord]:
        return self._credential_store.list_approval_factors(user_id=user_id, method=self.method)

    def _matching_factors(
        self,
        *,
        user_id: str,
        pending_action: Any,
        requested_credential_id: str,
    ) -> list[ApprovalFactorRecord]:
        candidates = self._candidate_factors(user_id=user_id)
        allowed_credentials = [
            item.strip()
            for item in getattr(pending_action, "allowed_credentials", ())
            if str(item).strip()
        ]
        if requested_credential_id:
            candidates = [
                factor for factor in candidates if factor.credential_id == requested_credential_id
            ]
        if allowed_credentials:
            allowed = set(allowed_credentials)
            candidates = [factor for factor in candidates if factor.credential_id in allowed]
        allowed_principals = [
            item.strip()
            for item in getattr(pending_action, "allowed_principals", ())
            if str(item).strip()
        ]
        if allowed_principals:
            allowed = set(allowed_principals)
            candidates = [factor for factor in candidates if factor.principal_id in allowed]
        return candidates

    def _verify_totp_code(
        self,
        *,
        factors: list[ApprovalFactorRecord],
        totp_code: str,
        confirmation_id: str,
        now: datetime,
    ) -> ApprovalFactorRecord:
        matches: list[tuple[ApprovalFactorRecord, int]] = []
        for factor in factors:
            step = _match_totp_window(secret_b32=factor.secret_b32, code=totp_code, now=now)
            if step is None:
                continue
            previous = factor.used_time_steps.get(str(step), "")
            if previous and previous != confirmation_id:
                raise ConfirmationVerificationError("totp_code_reused")
            matches.append((factor, step))
        if not matches:
            raise ConfirmationVerificationError("invalid_totp_code")
        if len(matches) > 1:
            raise ConfirmationVerificationError("confirmation_credential_ambiguous")
        factor, matched_step = matches[0]
        updated = factor.model_copy(deep=True)
        updated.used_time_steps = {
            key: value
            for key, value in updated.used_time_steps.items()
            if abs(int(key) - matched_step) <= 3
        }
        updated.used_time_steps[str(matched_step)] = confirmation_id
        updated.last_verified_at = now
        updated.last_used_at = now
        self._credential_store.update_approval_factor(updated)
        return updated

    def _consume_recovery_code(
        self,
        *,
        factors: list[ApprovalFactorRecord],
        recovery_code: str,
        confirmation_id: str,
        now: datetime,
    ) -> ApprovalFactorRecord:
        hashed = hash_recovery_code(recovery_code)
        consumed_match = False
        for factor in factors:
            for record in factor.recovery_codes:
                if not hmac.compare_digest(record.code_hash, hashed):
                    continue
                if (
                    record.consumed_at is not None
                    and record.consumed_confirmation_id != confirmation_id
                ):
                    consumed_match = True
                    continue
                updated = factor.model_copy(deep=True)
                for entry in updated.recovery_codes:
                    if hmac.compare_digest(entry.code_hash, hashed):
                        entry.consumed_at = now
                        entry.consumed_confirmation_id = confirmation_id
                        break
                updated.last_verified_at = now
                updated.last_used_at = now
                self._credential_store.update_approval_factor(updated)
                return updated
        if consumed_match:
            raise ConfirmationVerificationError("recovery_code_reused")
        raise ConfirmationVerificationError("invalid_recovery_code")


class WebAuthnBackend:
    def __init__(
        self,
        *,
        credential_store: ApprovalFactorStore,
        approval_origin: str,
        rp_id: str,
        rp_name: str = "shisad",
    ) -> None:
        self.backend_id = "webauthn.default"
        self.method = "webauthn"
        self.level = ConfirmationLevel.BOUND_APPROVAL
        self.binding_scope = BindingScope.APPROVAL_ENVELOPE
        self.review_surface = ReviewSurface.BROWSER_RENDERED
        self.available_principals: set[str] = set()
        self.available_credentials: set[str] = set()
        self.capabilities = ConfirmationCapabilities(
            principal_binding=True,
            approval_binding=True,
        )
        self.third_party_verifiable = False
        self._credential_store = credential_store
        self._approval_origin = (
            _canonicalize_webauthn_origin(approval_origin) or approval_origin.strip()
        )
        self._rp_id = rp_id.strip()
        self._server = Fido2Server(
            PublicKeyCredentialRpEntity(id=self._rp_id, name=rp_name),
            verify_origin=lambda origin: _origin_matches(origin, self._approval_origin),
        )

    @property
    def approval_origin(self) -> str:
        return self._approval_origin

    @property
    def rp_id(self) -> str:
        return self._rp_id

    def is_available_for(self, *, user_id: str) -> bool:
        return bool(self._candidate_factors(user_id=user_id))

    def principals_for_user(self, *, user_id: str) -> set[str]:
        return {factor.principal_id for factor in self._candidate_factors(user_id=user_id)}

    def credentials_for_user(self, *, user_id: str) -> set[str]:
        return {factor.credential_id for factor in self._candidate_factors(user_id=user_id)}

    def registration_begin(
        self,
        *,
        user_id: str,
        principal_id: str,
        credential_id: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        user = PublicKeyCredentialUserEntity(
            id=f"{user_id}:{credential_id}".encode(),
            name=user_id,
            display_name=principal_id or user_id,
        )
        existing_credentials = self._registered_attested_credentials(user_id=user_id)
        options, state = self._server.register_begin(
            user,
            credentials=existing_credentials or None,
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        public_key = dict(options).get("publicKey", {})
        return (
            webauthn_jsonify(public_key) if isinstance(public_key, dict) else {},
            webauthn_jsonify(state) if isinstance(state, dict) else {},
        )

    def registration_complete(
        self,
        *,
        credential_id: str,
        user_id: str,
        principal_id: str,
        created_at: datetime,
        state: dict[str, Any],
        response_payload: dict[str, Any],
    ) -> ApprovalFactorRecord:
        try:
            response = RegistrationResponse.from_dict(response_payload)
        except Exception as exc:  # pragma: no cover - library-specific decode failures
            raise ConfirmationVerificationError("invalid_webauthn_registration") from exc
        try:
            auth_data = self._server.register_complete(dict(state), response)
        except Exception as exc:  # pragma: no cover - library-specific verify failures
            raise ConfirmationVerificationError("invalid_webauthn_registration") from exc

        credential_data = getattr(auth_data, "credential_data", None)
        if credential_data is None:
            raise ConfirmationVerificationError("webauthn_credential_data_missing")
        attested = AttestedCredentialData(bytes(credential_data))
        existing = self._factor_for_attested_data(bytes(attested))
        if existing is not None:
            raise ConfirmationVerificationError("webauthn_credential_already_registered")

        raw_transports = response_payload.get("transports", [])
        transports = (
            [str(item).strip() for item in raw_transports if str(item).strip()]
            if isinstance(raw_transports, list)
            else []
        )
        return ApprovalFactorRecord(
            credential_id=credential_id,
            user_id=user_id,
            method=self.method,
            principal_id=principal_id,
            created_at=created_at,
            webauthn_attested_credential_data_b64=_b64url_encode(bytes(attested)),
            webauthn_sign_count=int(getattr(auth_data, "counter", 0) or 0),
            webauthn_rp_id=self._rp_id,
            webauthn_transports=transports,
        )

    def approval_request_options(self, *, pending_action: Any) -> dict[str, Any]:
        envelope_hash, _action_digest = _approval_binding_inputs(pending_action)
        challenge = approval_envelope_hash_bytes(envelope_hash)
        user_id = str(getattr(pending_action, "user_id", "")).strip()
        if not user_id:
            raise ConfirmationVerificationError("confirmation_user_missing")
        factors = self._matching_factors(
            user_id=user_id,
            pending_action=pending_action,
            requested_credential_id=str(getattr(pending_action, "credential_id", "")).strip(),
        )
        credentials: list[AttestedCredentialData] = []
        for candidate in factors:
            credential = self._attested_credential_data(candidate)
            if credential is not None:
                credentials.append(credential)
        if not credentials:
            raise ConfirmationVerificationError("confirmation_credential_missing")
        options, _state = self._server.authenticate_begin(
            credentials=credentials,
            challenge=challenge,
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        public_key = dict(options).get("publicKey", {})
        return webauthn_jsonify(public_key) if isinstance(public_key, dict) else {}

    def verify(
        self,
        *,
        pending_action: Any,
        params: dict[str, Any],
        now: datetime | None = None,
    ) -> ConfirmationEvidence:
        current = now or datetime.now(UTC)
        requested_method = str(
            params.get("approval_method")
            or params.get("method")
            or self.method
        ).strip() or self.method
        if requested_method != self.method:
            raise ConfirmationVerificationError("confirmation_method_mismatch")

        decision_nonce = str(params.get("decision_nonce", "")).strip()
        proof = params.get("proof")
        proof_payload = proof if isinstance(proof, dict) else {}
        response_payload = proof_payload.get("credential")
        if isinstance(response_payload, dict):
            assertion_payload = response_payload
        else:
            assertion_payload = proof_payload
        if not isinstance(assertion_payload, dict) or not assertion_payload:
            raise ConfirmationVerificationError("missing_webauthn_assertion")

        user_id = str(getattr(pending_action, "user_id", "")).strip()
        if not user_id:
            raise ConfirmationVerificationError("confirmation_user_missing")

        factors = self._matching_factors(
            user_id=user_id,
            pending_action=pending_action,
            requested_credential_id=str(params.get("credential_id", "")).strip(),
        )
        credentials: list[AttestedCredentialData] = []
        for candidate in factors:
            credential = self._attested_credential_data(candidate)
            if credential is not None:
                credentials.append(credential)
        if not credentials:
            raise ConfirmationVerificationError("confirmation_credential_missing")

        envelope_hash, action_digest = _approval_binding_inputs(pending_action)
        challenge = approval_envelope_hash_bytes(envelope_hash)
        try:
            _options, state = self._server.authenticate_begin(
                credentials=credentials,
                challenge=challenge,
                user_verification=UserVerificationRequirement.REQUIRED,
            )
            response = AuthenticationResponse.from_dict(assertion_payload)
            matched = self._server.authenticate_complete(state, credentials, response)
        except Exception as exc:  # pragma: no cover - library-specific verify failures
            raise ConfirmationVerificationError("invalid_webauthn_assertion") from exc

        factor = self._factor_for_attested_data(bytes(matched), factors=factors)
        if factor is None:
            raise ConfirmationVerificationError("confirmation_credential_missing")
        if (
            getattr(pending_action, "allowed_principals", ())
            and factor.principal_id not in getattr(pending_action, "allowed_principals", ())
        ):
            raise ConfirmationVerificationError("confirmation_principal_not_allowed")
        if (
            getattr(pending_action, "allowed_credentials", ())
            and factor.credential_id not in getattr(pending_action, "allowed_credentials", ())
        ):
            raise ConfirmationVerificationError("confirmation_credential_not_allowed")

        counter = int(getattr(response.response.authenticator_data, "counter", 0) or 0)
        if factor.webauthn_sign_count > 0 and counter > 0 and counter <= factor.webauthn_sign_count:
            raise ConfirmationVerificationError("webauthn_sign_count_rollback")

        updated = factor.model_copy(deep=True)
        if counter > updated.webauthn_sign_count:
            updated.webauthn_sign_count = counter
        updated.last_verified_at = current
        updated.last_used_at = current
        self._credential_store.update_approval_factor(updated)

        payload = {
            "schema_version": "shisad.confirmation_evidence.v1",
            "backend_id": self.backend_id,
            "method": self.method,
            "confirmation_id": str(getattr(pending_action, "confirmation_id", "")),
            "decision_nonce": decision_nonce,
            "approval_envelope_hash": envelope_hash,
            "action_digest": action_digest,
            "approver_principal_id": updated.principal_id,
            "credential_id": updated.credential_id,
            "rp_id": self._rp_id,
            "origin": self._approval_origin,
            "sign_count": counter,
            "fallback_used": bool(getattr(pending_action, "fallback_used", False)),
        }
        return ConfirmationEvidence(
            level=self.level,
            method=self.method,
            backend_id=self.backend_id,
            approver_principal_id=updated.principal_id,
            credential_id=updated.credential_id,
            binding_scope=self.binding_scope,
            review_surface=self.review_surface,
            third_party_verifiable=self.third_party_verifiable,
            approval_envelope_hash=envelope_hash,
            action_digest=action_digest,
            decision_nonce=decision_nonce,
            fallback_used=bool(payload["fallback_used"]),
            evidence_payload=payload,
            evidence_hash=canonical_sha256(payload),
        )

    def _candidate_factors(self, *, user_id: str) -> list[ApprovalFactorRecord]:
        return self._credential_store.list_approval_factors(user_id=user_id, method=self.method)

    def _registered_attested_credentials(self, *, user_id: str) -> list[AttestedCredentialData]:
        credentials: list[AttestedCredentialData] = []
        for factor in self._candidate_factors(user_id=user_id):
            credential = self._attested_credential_data(factor)
            if credential is not None:
                credentials.append(credential)
        return credentials

    def _matching_factors(
        self,
        *,
        user_id: str,
        pending_action: Any,
        requested_credential_id: str,
    ) -> list[ApprovalFactorRecord]:
        candidates = self._candidate_factors(user_id=user_id)
        allowed_credentials = [
            item.strip()
            for item in getattr(pending_action, "allowed_credentials", ())
            if str(item).strip()
        ]
        if requested_credential_id:
            candidates = [
                factor for factor in candidates if factor.credential_id == requested_credential_id
            ]
        if allowed_credentials:
            allowed = set(allowed_credentials)
            candidates = [factor for factor in candidates if factor.credential_id in allowed]
        allowed_principals = [
            item.strip()
            for item in getattr(pending_action, "allowed_principals", ())
            if str(item).strip()
        ]
        if allowed_principals:
            allowed = set(allowed_principals)
            candidates = [factor for factor in candidates if factor.principal_id in allowed]
        return candidates

    @staticmethod
    def _attested_credential_data(
        factor: ApprovalFactorRecord,
    ) -> AttestedCredentialData | None:
        raw = factor.webauthn_attested_credential_data_b64.strip()
        if not raw:
            return None
        try:
            return AttestedCredentialData(_b64url_decode(raw))
        except ValueError:
            return None

    def _factor_for_attested_data(
        self,
        raw_attested_credential_data: bytes,
        *,
        factors: list[ApprovalFactorRecord] | None = None,
    ) -> ApprovalFactorRecord | None:
        rows = (
            list(factors)
            if factors is not None
            else self._credential_store.list_approval_factors(method=self.method)
        )
        encoded = _b64url_encode(raw_attested_credential_data)
        for factor in rows:
            if factor.webauthn_attested_credential_data_b64.strip() == encoded:
                return factor
        return None


@dataclass(slots=True)
class ResolvedConfirmationBackend:
    backend: ConfirmationBackend
    fallback_used: bool = False


class ConfirmationBackendRegistry:
    """Deterministic confirmation-backend lookup and policy filtering."""

    def __init__(self) -> None:
        self._backends: dict[str, ConfirmationBackend] = {}

    def register(self, backend: ConfirmationBackend) -> None:
        self._backends[str(backend.backend_id)] = backend

    def get_backend(self, backend_id: str) -> ConfirmationBackend | None:
        return self._backends.get(backend_id)

    def resolve(
        self,
        requirement: ConfirmationRequirement,
        *,
        user_id: str = "",
    ) -> ResolvedConfirmationBackend | None:
        if not requirement.routeable:
            return None
        direct = self._resolve_for_levels([requirement.level], requirement, user_id=user_id)
        if direct is not None:
            return direct
        if requirement.fallback.mode != "allow_levels":
            return None
        fallback = self._resolve_for_levels(
            requirement.fallback.allow_levels,
            requirement,
            user_id=user_id,
        )
        if fallback is None:
            return None
        return ResolvedConfirmationBackend(backend=fallback.backend, fallback_used=True)

    def _resolve_for_levels(
        self,
        levels: list[ConfirmationLevel],
        requirement: ConfirmationRequirement,
        *,
        user_id: str,
    ) -> ResolvedConfirmationBackend | None:
        for level in levels:
            candidates = [
                backend
                for backend in self._backends.values()
                if backend.level == level
                and backend.is_available_for(user_id=user_id)
                and backend.capabilities.covers(requirement.require_capabilities)
                and (
                    not requirement.allowed_principals
                    or (
                        backend.capabilities.principal_binding
                        and bool(
                            set(requirement.allowed_principals)
                            & backend.principals_for_user(user_id=user_id)
                        )
                    )
                )
                and (
                    not requirement.allowed_credentials
                    or bool(
                        set(requirement.allowed_credentials)
                        & backend.credentials_for_user(user_id=user_id)
                    )
                )
            ]
            selected = self._select_backend(candidates, methods=requirement.methods)
            if selected is not None:
                return ResolvedConfirmationBackend(backend=selected, fallback_used=False)
        return None

    @staticmethod
    def _select_backend(
        candidates: list[ConfirmationBackend],
        *,
        methods: list[str],
    ) -> ConfirmationBackend | None:
        if not candidates:
            return None
        if methods:
            for method in methods:
                matching = [backend for backend in candidates if backend.method == method]
                if len(matching) == 1:
                    return matching[0]
                if len(matching) > 1:
                    return None
            return None
        if len(candidates) == 1:
            return candidates[0]
        return None


def confirmation_evidence_satisfies_requirement(
    *,
    requirement: ConfirmationRequirement,
    evidence: ConfirmationEvidence,
    backend: ConfirmationBackend,
) -> bool:
    if not requirement.routeable:
        return False

    if (
        evidence.level.priority < requirement.level.priority
        and (
            requirement.fallback.mode != "allow_levels"
            or not evidence.fallback_used
            or evidence.level not in requirement.fallback.allow_levels
        )
    ):
        return False
    if requirement.methods and evidence.method not in requirement.methods:
        return False
    if requirement.allowed_principals:
        if not backend.capabilities.principal_binding:
            return False
        if evidence.approver_principal_id not in requirement.allowed_principals:
            return False
    if (
        requirement.allowed_credentials
        and evidence.credential_id not in requirement.allowed_credentials
    ):
        return False
    return backend.capabilities.covers(requirement.require_capabilities)


def approval_audit_fields(evidence: ConfirmationEvidence | None) -> dict[str, Any]:
    if evidence is None:
        return {
            "approval_level": "",
            "approval_method": "",
            "approval_approver_principal_id": "",
            "approval_credential_id": "",
            "approval_binding_scope": "",
            "approval_review_surface": "",
            "approval_third_party_verifiable": False,
            "approval_evidence_hash": "",
            "approval_fallback_used": False,
            "approval_intent_envelope_hash": "",
            "approval_signature": "",
            "approval_signer_key_id": "",
        }
    return {
        "approval_level": evidence.level.value,
        "approval_method": evidence.method,
        "approval_approver_principal_id": evidence.approver_principal_id,
        "approval_credential_id": evidence.credential_id,
        "approval_binding_scope": evidence.binding_scope.value,
        "approval_review_surface": evidence.review_surface.value,
        "approval_third_party_verifiable": bool(evidence.third_party_verifiable),
        "approval_evidence_hash": evidence.evidence_hash,
        "approval_fallback_used": bool(evidence.fallback_used),
        "approval_intent_envelope_hash": evidence.intent_envelope_hash,
        "approval_signature": evidence.signature,
        "approval_signer_key_id": evidence.signer_key_id,
    }


@dataclass(slots=True)
class _FailureState:
    failures: int = 0
    locked_until: datetime | None = None


class ConfirmationMethodLockoutTracker:
    """Per-user, per-method failed-attempt lockout state."""

    def __init__(
        self,
        *,
        max_failures: int = 5,
        lockout_seconds: int = 900,
        state_path: Path | None = None,
    ) -> None:
        self._max_failures = max(1, int(max_failures))
        self._lockout_seconds = max(1, int(lockout_seconds))
        self._state: dict[tuple[str, str], _FailureState] = defaultdict(_FailureState)
        self._state_path = Path(state_path) if state_path is not None else None
        self._load()

    def status(self, *, user_id: str, method: str, now: datetime | None = None) -> float | None:
        now = now or datetime.now(UTC)
        state = self._state[(user_id, method)]
        if state.locked_until is None:
            return None
        if state.locked_until <= now:
            state.locked_until = None
            state.failures = 0
            self._persist()
            return None
        return max(0.0, (state.locked_until - now).total_seconds())

    def record_failure(self, *, user_id: str, method: str, now: datetime | None = None) -> None:
        now = now or datetime.now(UTC)
        state = self._state[(user_id, method)]
        if state.locked_until is not None and state.locked_until > now:
            return
        state.failures += 1
        if state.failures >= self._max_failures:
            state.locked_until = now + timedelta(seconds=self._lockout_seconds)
            state.failures = 0
        self._persist()

    def record_success(self, *, user_id: str, method: str) -> None:
        state = self._state[(user_id, method)]
        state.failures = 0
        state.locked_until = None
        self._persist()

    def _load(self) -> None:
        path = self._state_path
        if path is None or not path.exists():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("lockout payload must be an object")
            schema_version = str(payload.get("schema_version", "")).strip()
            if schema_version != "shisad.confirmation_lockout.v1":
                raise ValueError(
                    "unsupported confirmation lockout schema_version: "
                    f"{schema_version}"
                )
            entries = payload.get("entries", [])
            if not isinstance(entries, list):
                raise ValueError("confirmation lockout entries must be a list")
            loaded: defaultdict[tuple[str, str], _FailureState] = defaultdict(_FailureState)
            for item in entries:
                if not isinstance(item, dict):
                    raise ValueError("confirmation lockout entries must be objects")
                user_id = str(item.get("user_id", "")).strip()
                method = str(item.get("method", "")).strip()
                if not user_id or not method:
                    continue
                locked_until_raw = item.get("locked_until")
                locked_until: datetime | None = None
                if isinstance(locked_until_raw, str) and locked_until_raw.strip():
                    locked_until = datetime.fromisoformat(
                        locked_until_raw.replace("Z", "+00:00")
                    ).astimezone(UTC)
                loaded[(user_id, method)] = _FailureState(
                    failures=max(0, int(item.get("failures", 0) or 0)),
                    locked_until=locked_until,
                )
            self._state = loaded
        except (OSError, ValidationError, ValueError, json.JSONDecodeError):
            logger.warning(
                "Failed to load confirmation lockout state %s; quarantining corrupt state and "
                "starting empty",
                path,
                exc_info=True,
            )
            _quarantine_state_file(path, label="confirmation_lockout")
            self._state = defaultdict(_FailureState)

    def _persist(self) -> None:
        path = self._state_path
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        with suppress(OSError):
            path.parent.chmod(0o700)
        payload = {
            "schema_version": "shisad.confirmation_lockout.v1",
            "entries": [
                {
                    "user_id": user_id,
                    "method": method,
                    "failures": state.failures,
                    "locked_until": (
                        state.locked_until.astimezone(UTC).isoformat().replace("+00:00", "Z")
                        if state.locked_until is not None
                        else None
                    ),
                }
                for (user_id, method), state in sorted(self._state.items())
                if state.failures or state.locked_until is not None
            ],
        }
        tmp_path = path.with_suffix(f"{path.suffix}.tmp")
        tmp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
        with suppress(OSError):
            os.chmod(path, 0o600)
