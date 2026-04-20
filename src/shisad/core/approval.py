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
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum, StrEnum
from pathlib import Path
from typing import Any, Literal, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed as _Prehashed
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
from shisad.security.credentials import (
    ApprovalFactorRecord,
    ApprovalFactorStore,
    SignerKeyRecord,
)

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
    if parsed.path not in {"", "/"}:
        return None
    if port is None or port == default_port:
        canonical = f"{scheme}://{_format_origin_host(host)}"
    else:
        canonical = f"{scheme}://{_format_origin_host(host)}:{port}"
    return canonical


def _normalize_signed_webauthn_origin(origin: str) -> str | None:
    raw = origin.strip()
    canonical = _canonicalize_webauthn_origin(raw)
    if canonical is None:
        return None
    parsed = urlparse(raw)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").strip().lower()
    if not scheme or not host:
        return None
    default_port = _default_origin_port(scheme)
    if default_port is None:
        return None
    allowed_inputs = {canonical, f"{canonical}/"}
    try:
        port = parsed.port
    except ValueError:
        return None
    if port == default_port:
        explicit_default = f"{scheme}://{_format_origin_host(host)}:{default_port}"
        allowed_inputs.add(explicit_default)
        allowed_inputs.add(f"{explicit_default}/")
    if raw not in allowed_inputs:
        return None
    return canonical


def _origin_matches(candidate: str, expected: str) -> bool:
    candidate_origin = _normalize_signed_webauthn_origin(candidate)
    expected_origin = _canonicalize_webauthn_origin(expected)
    return candidate_origin is not None and candidate_origin == expected_origin


def local_fido2_rp_id(daemon_id: str) -> str:
    normalized = "".join(ch for ch in daemon_id.strip().lower() if ch.isalnum())
    if not normalized:
        raise ValueError("daemon_id is required for local_fido2 rp_id derivation")
    return f"{normalized}.approver.shisad.invalid"


def local_fido2_origin(daemon_id: str) -> str:
    return f"https://{local_fido2_rp_id(daemon_id)}"


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
    require_capabilities: ConfirmationCapabilities = Field(default_factory=ConfirmationCapabilities)
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


class IntentAction(BaseModel):
    """Human-readable signable action payload."""

    tool: str
    display_summary: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    destinations: list[str] = Field(default_factory=list)

    model_config = {"frozen": True}


class IntentPolicyContext(BaseModel):
    """Policy metadata bound into authorization-grade signatures."""

    required_level: ConfirmationLevel
    confirmation_reason: str = ""
    matched_rule: str = ""
    action_digest: str = ""

    model_config = {"frozen": True}


class IntentEnvelope(BaseModel):
    """Canonical full-intent payload for authorization-grade methods."""

    schema_version: str = "shisad.intent.v1"
    intent_id: str
    agent_id: str
    workspace_id: str
    session_id: str
    created_at: datetime
    expires_at: datetime | None = None
    action: IntentAction
    policy_context: IntentPolicyContext
    nonce: str

    model_config = {"frozen": True}


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
            list(getattr(item, field_name)) for item in requirements if getattr(item, field_name)
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
    allow_fallbacks = [item.fallback for item in selected if item.fallback.mode == "allow_levels"]
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
    route_reason = "confirmation_requirement_conflict:" + ",".join(conflicts) if conflicts else ""
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


def intent_envelope_hash(envelope: IntentEnvelope | dict[str, Any]) -> str:
    payload = (
        envelope.model_dump(mode="json") if isinstance(envelope, IntentEnvelope) else dict(envelope)
    )
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

    def is_available_for(self, *, user_id: str) -> bool: ...

    def principals_for_user(self, *, user_id: str) -> set[str]: ...

    def credentials_for_user(self, *, user_id: str) -> set[str]: ...

    def verify(
        self,
        *,
        pending_action: Any,
        params: dict[str, Any],
        now: datetime | None = None,
    ) -> ConfirmationEvidence: ...


class SignerKeyInfo(BaseModel):
    """Registered signer metadata exposed to signer backends."""

    key_id: str
    user_id: str
    principal_id: str
    algorithm: str
    device_type: str
    public_key_pem: str
    signing_scheme: str = "raw"
    created_at: datetime
    last_verified_at: datetime | None = None
    last_used_at: datetime | None = None
    revoked: bool = False


class SignatureResult(BaseModel):
    """Signer-backend response for one intent-signing request."""

    status: Literal["approved", "rejected", "expired", "error"]
    signature: str = ""
    signer_key_id: str = ""
    signed_at: datetime | None = None
    review_surface: ReviewSurface | None = None
    blind_sign_detected: bool = False
    reason: str = ""


class SignerBackend(Protocol):
    """Authorization-grade backend that returns signatures over an intent envelope."""

    backend_id: str
    method: str
    level: ConfirmationLevel
    review_surface: ReviewSurface
    capabilities: ConfirmationCapabilities
    third_party_verifiable: bool

    def list_registered_keys(
        self,
        *,
        user_id: str,
        include_revoked: bool = False,
    ) -> list[SignerKeyInfo]: ...

    def request_signature(
        self,
        *,
        envelope: IntentEnvelope,
        signer_key_id: str,
        timeout: timedelta,
    ) -> SignatureResult: ...

    def verify_signature(
        self,
        *,
        envelope: IntentEnvelope,
        signature: str,
        signer_key: SignerKeyInfo,
    ) -> bool: ...

    def record_key_use(self, *, signer_key_id: str, when: datetime) -> None: ...


def _normalize_signature_value(value: str) -> str:
    text = value.strip()
    if not text:
        return ""
    if text.startswith("base64:"):
        return text
    return "base64:" + text


def _decode_signature_value(value: str) -> bytes:
    normalized = _normalize_signature_value(value)
    prefix = "base64:"
    if not normalized.startswith(prefix):
        raise ValueError("signature must use base64: prefix")
    return base64.b64decode(normalized[len(prefix) :].encode("ascii"))


def _signer_level_for_result(
    *,
    default_level: ConfirmationLevel,
    review_surface: ReviewSurface,
    blind_sign_detected: bool,
) -> ConfirmationLevel:
    if blind_sign_detected or review_surface == ReviewSurface.OPAQUE_DEVICE:
        return ConfirmationLevel.BOUND_APPROVAL
    if (
        review_surface == ReviewSurface.TRUSTED_DEVICE_DISPLAY
        and default_level.priority >= ConfirmationLevel.TRUSTED_DISPLAY_AUTHORIZATION.priority
    ):
        return ConfirmationLevel.TRUSTED_DISPLAY_AUTHORIZATION
    if default_level.priority >= ConfirmationLevel.SIGNED_AUTHORIZATION.priority:
        return ConfirmationLevel.SIGNED_AUTHORIZATION
    return default_level


def _clamp_signer_review_surface(
    *,
    default: ReviewSurface,
    reported: ReviewSurface | None,
) -> ReviewSurface:
    """Clamp backend-reported review surfaces to the daemon's proven ceiling."""

    if reported is None:
        return default
    if reported == ReviewSurface.OPAQUE_DEVICE:
        return ReviewSurface.OPAQUE_DEVICE
    if reported == ReviewSurface.TRUSTED_DEVICE_DISPLAY:
        return (
            ReviewSurface.TRUSTED_DEVICE_DISPLAY
            if default == ReviewSurface.TRUSTED_DEVICE_DISPLAY
            else default
        )
    if default == ReviewSurface.TRUSTED_DEVICE_DISPLAY:
        return reported
    return default


def _eth_personal_sign_digest(message: bytes) -> bytes:
    """Compute the Ethereum personal-sign digest for ECDSA verification.

    Ethereum's ``eth_sign`` / ``personal_sign`` hashes the message as::

        keccak256("\\x19Ethereum Signed Message:\\n" + len(message) + message)

    The result is a 32-byte digest suitable for ``Prehashed(SHA256())``
    verification (both keccak-256 and SHA-256 produce 32-byte digests).
    """
    from shisad.core._keccak import keccak_256

    prefix = b"\x19Ethereum Signed Message:\n" + str(len(message)).encode()
    return keccak_256(prefix + message)


# ---------------------------------------------------------------------------
# EIP-712 typed-data digest (used by the Ledger signer backend)
# ---------------------------------------------------------------------------

# Fixed EIP-712 domain for shisad intent signing.
_EIP712_DOMAIN = {"name": "shisad", "version": "1", "chainId": 0}

# EIP-712 type definitions for the shisad IntentEnvelope.
# Keep in sync with contrib/ledger-bridge/src/format.ts::buildTypedData().
_EIP712_TYPES: dict[str, list[tuple[str, str]]] = {
    "EIP712Domain": [("name", "string"), ("version", "string"), ("chainId", "uint256")],
    "IntentAction": [("tool", "string"), ("summary", "string"), ("destinations", "string")],
    "PolicyContext": [("level", "string"), ("digest", "string")],
    "IntentEnvelope": [
        ("intentId", "string"),
        ("action", "IntentAction"),
        ("policy", "PolicyContext"),
        ("fullIntentHash", "string"),
        ("nonce", "string"),
    ],
}


def _eip712_encode_type(primary: str) -> str:
    """Encode the type string for ``hashType`` per EIP-712.

    For a struct with referenced sub-structs, the encoding is::

        PrimaryType(field1Type field1Name, ...) ++ ReferencedType1(...) ++ ...

    Referenced types are sorted alphabetically and deduplicated.
    """
    deps: set[str] = set()

    def _collect(name: str) -> None:
        for _, field_type in _EIP712_TYPES.get(name, []):
            if field_type in _EIP712_TYPES and field_type != name and field_type not in deps:
                deps.add(field_type)
                _collect(field_type)

    _collect(primary)

    def _fmt(name: str) -> str:
        fields = ",".join(f"{ft} {fn}" for fn, ft in _EIP712_TYPES[name])
        return f"{name}({fields})"

    return _fmt(primary) + "".join(_fmt(d) for d in sorted(deps))


def _eip712_type_hash(primary: str) -> bytes:
    """Compute the keccak-256 type hash for a named EIP-712 struct.

    Since ``_EIP712_TYPES`` is static, the result is cached.
    """
    from shisad.core._keccak import keccak_256

    return keccak_256(_eip712_encode_type(primary).encode())


# Precomputed type hashes for static EIP-712 types.
_EIP712_TYPE_HASHES: dict[str, bytes] = {}


def _get_type_hash(primary: str) -> bytes:
    cached = _EIP712_TYPE_HASHES.get(primary)
    if cached is not None:
        return cached
    h = _eip712_type_hash(primary)
    _EIP712_TYPE_HASHES[primary] = h
    return h


def _eip712_hash_struct(primary: str, data: dict[str, object]) -> bytes:
    """Compute ``hashStruct(primaryType, data)`` per EIP-712."""
    from shisad.core._keccak import keccak_256

    if primary not in _EIP712_TYPES:
        raise ValueError(f"unsupported EIP-712 primary type: {primary}")

    encoded = _get_type_hash(primary)
    for field_name, field_type in _EIP712_TYPES[primary]:
        label = f"{primary}.{field_name}"
        value = data.get(field_name)
        if field_type == "string":
            if not isinstance(value, str):
                raise ValueError(f"EIP-712 field {label} must be a string")
            encoded += keccak_256(str(value or "").encode())
        elif field_type == "uint256":
            if isinstance(value, bool) or not isinstance(value, (int, str, bytes)):
                raise ValueError(f"EIP-712 field {label} must be uint256-compatible")
            try:
                numeric = int(value or 0)
            except ValueError as exc:
                raise ValueError(f"EIP-712 field {label} must be uint256-compatible") from exc
            if numeric < 0 or numeric >= 2**256:
                raise ValueError(f"EIP-712 field {label} is outside uint256 range")
            encoded += numeric.to_bytes(32, "big")
        elif field_type in _EIP712_TYPES:
            if not isinstance(value, dict):
                raise ValueError(f"EIP-712 field {label} must be a struct")
            encoded += _eip712_hash_struct(field_type, value)
        else:
            raise ValueError(f"unsupported EIP-712 field type for {label}: {field_type}")
    return keccak_256(encoded)


def _eip712_digest(envelope: IntentEnvelope) -> bytes:
    """Compute the EIP-712 signing digest for a shisad IntentEnvelope.

    Returns the 32-byte keccak-256 digest::

        keccak256("\\x19\\x01" + domainSeparator + hashStruct(primaryType, message))

    Compatible with ``Prehashed(SHA256())`` ECDSA verification (32-byte digest).
    """
    from shisad.core._keccak import keccak_256

    domain_sep = _eip712_hash_struct("EIP712Domain", _EIP712_DOMAIN)
    message_data: dict[str, object] = {
        "intentId": envelope.intent_id,
        "action": {
            "tool": envelope.action.tool,
            "summary": envelope.action.display_summary,
            "destinations": ", ".join(envelope.action.destinations) or "[none]",
        },
        "policy": {
            "level": envelope.policy_context.required_level.value
            if hasattr(envelope.policy_context.required_level, "value")
            else str(envelope.policy_context.required_level),
            "digest": envelope.policy_context.action_digest,
        },
        "fullIntentHash": intent_envelope_hash(envelope),
        "nonce": envelope.nonce,
    }
    struct_hash = _eip712_hash_struct("IntentEnvelope", message_data)
    return keccak_256(b"\x19\x01" + domain_sep + struct_hash)


def _signer_key_info_from_record(record: SignerKeyRecord) -> SignerKeyInfo:
    return SignerKeyInfo(
        key_id=record.credential_id,
        user_id=record.user_id,
        principal_id=record.principal_id,
        algorithm=record.algorithm,
        device_type=record.device_type,
        public_key_pem=record.public_key_pem,
        signing_scheme=record.signing_scheme,
        created_at=record.created_at,
        last_verified_at=record.last_verified_at,
        last_used_at=record.last_used_at,
        revoked=record.revoked_at is not None,
    )


class _HttpSignerBackend:
    """Base class for HTTP-based signer backends (KMS, Ledger bridge, etc.)."""

    def __init__(
        self,
        *,
        credential_store: ApprovalFactorStore,
        endpoint_url: str,
        bearer_token: str = "",
        request_timeout: timedelta | None = None,
        backend_id: str,
        method: str,
        level: ConfirmationLevel,
        review_surface: ReviewSurface,
        capabilities: ConfirmationCapabilities,
        third_party_verifiable: bool,
    ) -> None:
        self.backend_id = backend_id
        self.method = method
        self.level = level
        self.review_surface = review_surface
        self.capabilities = capabilities
        self.third_party_verifiable = third_party_verifiable
        self._credential_store = credential_store
        self._endpoint_url = endpoint_url.strip()
        self._bearer_token = bearer_token.strip()
        self._request_timeout = request_timeout or timedelta(seconds=30)

    def list_registered_keys(
        self,
        *,
        user_id: str,
        include_revoked: bool = False,
    ) -> list[SignerKeyInfo]:
        rows = self._credential_store.list_signer_keys(
            user_id=user_id,
            backend=self.method,
            include_revoked=include_revoked,
        )
        return [_signer_key_info_from_record(item) for item in rows]

    def request_signature(
        self,
        *,
        envelope: IntentEnvelope,
        signer_key_id: str,
        timeout: timedelta,
    ) -> SignatureResult:
        if not self._endpoint_url:
            return SignatureResult(status="error", reason="signer_backend_unconfigured")
        payload = {
            "schema_version": "shisad.sign_request.v1",
            "backend": self.method,
            "signer_key_id": signer_key_id,
            "intent_envelope_hash": intent_envelope_hash(envelope),
            "intent_envelope": envelope.model_dump(mode="json"),
            "timeout_seconds": max(1, int(timeout.total_seconds())),
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self._bearer_token:
            headers["Authorization"] = f"Bearer {self._bearer_token}"
        request = Request(
            self._endpoint_url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        timeout_seconds = max(
            1.0,
            min(timeout.total_seconds(), self._request_timeout.total_seconds()),
        )
        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                body = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            reason = "signer_backend_http_error"
            with suppress(Exception):
                payload = json.loads(exc.read().decode("utf-8"))
                reason = str(payload.get("reason") or payload.get("error") or reason)
            return SignatureResult(status="error", reason=reason)
        except URLError:
            return SignatureResult(status="error", reason="signer_backend_unreachable")
        except TimeoutError:
            return SignatureResult(status="expired", reason="signer_backend_timeout")
        except json.JSONDecodeError:
            return SignatureResult(status="error", reason="signer_backend_invalid_response")
        except OSError:
            return SignatureResult(status="error", reason="signer_backend_io_error")

        if not isinstance(body, dict):
            return SignatureResult(status="error", reason="signer_backend_invalid_response")
        status = str(body.get("status", "")).strip()
        if status not in {"approved", "rejected", "expired", "error"}:
            return SignatureResult(status="error", reason="signer_backend_invalid_status")
        reported_review_surface: ReviewSurface | None = None
        if "review_surface" in body:
            review_surface_raw = str(body.get("review_surface", "")).strip()
            if review_surface_raw:
                try:
                    reported_review_surface = ReviewSurface(review_surface_raw)
                except ValueError:
                    return SignatureResult(
                        status="error",
                        reason="signer_backend_invalid_response",
                    )
        clamped_review_surface = _clamp_signer_review_surface(
            default=self.review_surface,
            reported=reported_review_surface,
        )
        signed_at: datetime | None = None
        signed_at_raw = str(body.get("signed_at", "")).strip()
        if signed_at_raw:
            try:
                signed_at = datetime.fromisoformat(signed_at_raw.replace("Z", "+00:00")).astimezone(
                    UTC
                )
            except ValueError:
                return SignatureResult(
                    status="error",
                    reason="signer_backend_invalid_response",
                )
        blind_sign_raw = body.get("blind_sign_detected", False)
        if not isinstance(blind_sign_raw, bool):
            return SignatureResult(status="error", reason="signer_backend_invalid_response")
        return SignatureResult(
            status=status,
            signature=_normalize_signature_value(str(body.get("signature", ""))),
            signer_key_id=str(body.get("signer_key_id", "")).strip(),
            signed_at=signed_at,
            review_surface=clamped_review_surface,
            blind_sign_detected=blind_sign_raw,
            reason=str(body.get("reason", "")).strip(),
        )

    def verify_signature(
        self,
        *,
        envelope: IntentEnvelope,
        signature: str,
        signer_key: SignerKeyInfo,
    ) -> bool:
        try:
            public_key = serialization.load_pem_public_key(
                signer_key.public_key_pem.encode("utf-8")
            )
            signed_bytes = _decode_signature_value(signature)
            message = canonical_json_dumps(envelope).encode("utf-8")
            algorithm = signer_key.algorithm.strip().lower()
            if algorithm == "ed25519":
                if not isinstance(public_key, ed25519.Ed25519PublicKey):
                    return False
                public_key.verify(signed_bytes, message)
                return True
            if algorithm == "ecdsa-secp256k1":
                if not isinstance(public_key, ec.EllipticCurvePublicKey):
                    return False
                if public_key.curve.name.lower() != "secp256k1":
                    return False
                scheme = signer_key.signing_scheme.strip().lower()
                if scheme == "eip712":
                    digest = _eip712_digest(envelope)
                    public_key.verify(
                        signed_bytes, digest, ec.ECDSA(_Prehashed(hashes.SHA256()))
                    )
                elif scheme == "eth_personal_sign":
                    digest = _eth_personal_sign_digest(message)
                    public_key.verify(
                        signed_bytes, digest, ec.ECDSA(_Prehashed(hashes.SHA256()))
                    )
                else:
                    public_key.verify(signed_bytes, message, ec.ECDSA(hashes.SHA256()))
                return True
        except (InvalidSignature, TypeError, ValueError):
            return False
        return False

    def record_key_use(self, *, signer_key_id: str, when: datetime) -> None:
        record = self._credential_store.get_signer_key(signer_key_id)
        if record is None:
            return
        updated = record.model_copy(deep=True)
        updated.last_verified_at = when
        updated.last_used_at = when
        self._credential_store.update_signer_key(updated)


class EnterpriseKmsSignerBackend(_HttpSignerBackend):
    """Enterprise-style HTTPS signer backend for provider-UI approvals."""

    def __init__(
        self,
        *,
        credential_store: ApprovalFactorStore,
        endpoint_url: str,
        bearer_token: str = "",
        request_timeout: timedelta | None = None,
    ) -> None:
        super().__init__(
            credential_store=credential_store,
            endpoint_url=endpoint_url,
            bearer_token=bearer_token,
            request_timeout=request_timeout,
            backend_id="kms.default",
            method="kms",
            level=ConfirmationLevel.SIGNED_AUTHORIZATION,
            review_surface=ReviewSurface.PROVIDER_UI,
            capabilities=ConfirmationCapabilities(
                principal_binding=True,
                full_intent_signature=True,
                third_party_verifiable=True,
            ),
            third_party_verifiable=True,
        )


class LedgerSignerBackend(_HttpSignerBackend):
    """Ledger hardware device signer backend for L4 trusted-display approvals.

    Communicates with a Ledger DMK bridge service (Node.js) that handles
    USB/BLE transport to the device.  The bridge implements the same HTTP
    sign-request/response contract as the KMS backend.
    """

    def __init__(
        self,
        *,
        credential_store: ApprovalFactorStore,
        endpoint_url: str,
        bearer_token: str = "",
        request_timeout: timedelta | None = None,
    ) -> None:
        super().__init__(
            credential_store=credential_store,
            endpoint_url=endpoint_url,
            bearer_token=bearer_token,
            request_timeout=request_timeout,
            backend_id="ledger.default",
            method="ledger",
            level=ConfirmationLevel.TRUSTED_DISPLAY_AUTHORIZATION,
            review_surface=ReviewSurface.TRUSTED_DEVICE_DISPLAY,
            capabilities=ConfirmationCapabilities(
                principal_binding=True,
                full_intent_signature=True,
                third_party_verifiable=True,
                trusted_display=True,
                blind_sign_detection=True,
            ),
            third_party_verifiable=True,
        )


class SignerConfirmationAdapter:
    """Expose a signer backend through the generic confirmation-backend interface."""

    def __init__(self, signer_backend: SignerBackend) -> None:
        self._signer_backend = signer_backend
        self.backend_id = signer_backend.backend_id
        self.method = signer_backend.method
        self.level = signer_backend.level
        self.binding_scope = BindingScope.FULL_INTENT
        self.review_surface = signer_backend.review_surface
        self.available_principals: set[str] = set()
        self.available_credentials: set[str] = set()
        self.capabilities = signer_backend.capabilities
        self.third_party_verifiable = signer_backend.third_party_verifiable

    def is_available_for(self, *, user_id: str) -> bool:
        return bool(self._signer_backend.list_registered_keys(user_id=user_id))

    def principals_for_user(self, *, user_id: str) -> set[str]:
        return {
            item.principal_id
            for item in self._signer_backend.list_registered_keys(user_id=user_id)
            if not item.revoked
        }

    def credentials_for_user(self, *, user_id: str) -> set[str]:
        return {
            item.key_id
            for item in self._signer_backend.list_registered_keys(user_id=user_id)
            if not item.revoked
        }

    def verify(
        self,
        *,
        pending_action: Any,
        params: dict[str, Any],
        now: datetime | None = None,
    ) -> ConfirmationEvidence:
        current = now or datetime.now(UTC)
        requested_method = (
            str(params.get("approval_method") or params.get("method") or self.method).strip()
            or self.method
        )
        if requested_method != self.method:
            raise ConfirmationVerificationError("confirmation_method_mismatch")

        decision_nonce = str(params.get("decision_nonce", "")).strip()
        user_id = str(getattr(pending_action, "user_id", "")).strip()
        if not user_id:
            raise ConfirmationVerificationError("confirmation_user_missing")
        intent_envelope = getattr(pending_action, "intent_envelope", None)
        if isinstance(intent_envelope, Mapping):
            intent = IntentEnvelope.model_validate(intent_envelope)
        elif isinstance(intent_envelope, IntentEnvelope):
            intent = intent_envelope
        else:
            raise ConfirmationVerificationError("intent_envelope_missing")
        expected_intent_hash = str(
            getattr(getattr(pending_action, "approval_envelope", None), "intent_envelope_hash", "")
        ).strip()
        actual_intent_hash = intent_envelope_hash(intent)
        if expected_intent_hash and expected_intent_hash != actual_intent_hash:
            raise ConfirmationVerificationError("intent_envelope_hash_mismatch")

        signer_key = self._matching_signer_key(
            user_id=user_id,
            pending_action=pending_action,
            requested_credential_id=str(params.get("credential_id", "")).strip(),
        )
        expires_at = getattr(pending_action, "expires_at", None)
        timeout = (
            max(timedelta(seconds=1), expires_at - current)
            if isinstance(expires_at, datetime)
            else timedelta(seconds=300)
        )
        result = self._signer_backend.request_signature(
            envelope=intent,
            signer_key_id=signer_key.key_id,
            timeout=timeout,
        )
        if result.status != "approved":
            reason = (
                result.reason
                or {
                    "rejected": "signer_rejected",
                    "expired": "signer_backend_timeout",
                    "error": "signer_backend_error",
                }[result.status]
            )
            raise ConfirmationVerificationError(reason)
        if result.signer_key_id and result.signer_key_id != signer_key.key_id:
            raise ConfirmationVerificationError("signer_key_mismatch")
        if not result.signature:
            raise ConfirmationVerificationError("missing_signer_signature")
        if not self._signer_backend.verify_signature(
            envelope=intent,
            signature=result.signature,
            signer_key=signer_key,
        ):
            raise ConfirmationVerificationError("invalid_signer_signature")
        self._signer_backend.record_key_use(signer_key_id=signer_key.key_id, when=current)

        envelope_hash, action_digest = _approval_binding_inputs(pending_action)
        review_surface = result.review_surface or self.review_surface
        level = _signer_level_for_result(
            default_level=self.level,
            review_surface=review_surface,
            blind_sign_detected=bool(result.blind_sign_detected),
        )
        payload = {
            "schema_version": "shisad.confirmation_evidence.v1",
            "backend_id": self.backend_id,
            "method": self.method,
            "confirmation_id": str(getattr(pending_action, "confirmation_id", "")),
            "decision_nonce": decision_nonce,
            "approval_envelope_hash": envelope_hash,
            "action_digest": action_digest,
            "approver_principal_id": signer_key.principal_id,
            "credential_id": signer_key.key_id,
            "intent_envelope_hash": actual_intent_hash,
            "signature": result.signature,
            "signer_key_id": signer_key.key_id,
            "review_surface": review_surface.value,
            "blind_sign_detected": bool(result.blind_sign_detected),
            "fallback_used": bool(getattr(pending_action, "fallback_used", False)),
        }
        return ConfirmationEvidence(
            level=level,
            method=self.method,
            backend_id=self.backend_id,
            approver_principal_id=signer_key.principal_id,
            credential_id=signer_key.key_id,
            binding_scope=self.binding_scope,
            review_surface=review_surface,
            third_party_verifiable=self.third_party_verifiable,
            approval_envelope_hash=envelope_hash,
            action_digest=action_digest,
            decision_nonce=decision_nonce,
            fallback_used=bool(payload["fallback_used"]),
            evidence_payload=payload,
            evidence_hash=canonical_sha256(payload),
            intent_envelope_hash=actual_intent_hash,
            signature=result.signature,
            signer_key_id=signer_key.key_id,
            blind_sign_detected=bool(result.blind_sign_detected),
            verified_at=result.signed_at or current,
        )

    def _matching_signer_key(
        self,
        *,
        user_id: str,
        pending_action: Any,
        requested_credential_id: str,
    ) -> SignerKeyInfo:
        active = self._signer_backend.list_registered_keys(user_id=user_id)
        revoked = self._signer_backend.list_registered_keys(user_id=user_id, include_revoked=True)
        revoked_ids = {item.key_id for item in revoked if item.revoked}
        allowed_credentials = [
            item.strip()
            for item in getattr(pending_action, "allowed_credentials", ())
            if str(item).strip()
        ]
        candidates = list(active)
        if requested_credential_id:
            if requested_credential_id in revoked_ids:
                raise ConfirmationVerificationError("signer_key_revoked")
            candidates = [item for item in candidates if item.key_id == requested_credential_id]
        if allowed_credentials:
            allowed = set(allowed_credentials)
            candidates = [item for item in candidates if item.key_id in allowed]
        allowed_principals = [
            item.strip()
            for item in getattr(pending_action, "allowed_principals", ())
            if str(item).strip()
        ]
        if allowed_principals:
            allowed = set(allowed_principals)
            candidates = [item for item in candidates if item.principal_id in allowed]
        if not candidates:
            if allowed_credentials and set(allowed_credentials) & revoked_ids:
                raise ConfirmationVerificationError("signer_key_revoked")
            raise ConfirmationVerificationError("confirmation_credential_missing")
        if len(candidates) > 1:
            raise ConfirmationVerificationError("confirmation_credential_ambiguous")
        return candidates[0]


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
            params.get("approval_method") or params.get("method") or self.method
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
        requested_method = (
            str(params.get("approval_method") or params.get("method") or self.method).strip()
            or self.method
        )
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
                proof_payload.get("totp_code") or proof_payload.get("code") or ""
            ).strip()
            if not totp_code:
                raise ConfirmationVerificationError("missing_totp_code")
            factor = self._verify_totp_code(
                factors=factors,
                totp_code=totp_code,
                confirmation_id=str(getattr(pending_action, "confirmation_id", "")),
                now=current,
            )

        if getattr(pending_action, "allowed_principals", ()) and factor.principal_id not in getattr(
            pending_action, "allowed_principals", ()
        ):
            raise ConfirmationVerificationError("confirmation_principal_not_allowed")
        if getattr(
            pending_action, "allowed_credentials", ()
        ) and factor.credential_id not in getattr(pending_action, "allowed_credentials", ()):
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
        requested_method = (
            str(params.get("approval_method") or params.get("method") or self.method).strip()
            or self.method
        )
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
        if getattr(pending_action, "allowed_principals", ()) and factor.principal_id not in getattr(
            pending_action, "allowed_principals", ()
        ):
            raise ConfirmationVerificationError("confirmation_principal_not_allowed")
        if getattr(
            pending_action, "allowed_credentials", ()
        ) and factor.credential_id not in getattr(pending_action, "allowed_credentials", ()):
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
        factors = self._credential_store.list_approval_factors(user_id=user_id, method=self.method)
        expected_rp_id = self._rp_id.strip()
        if not expected_rp_id:
            return factors
        return [
            factor
            for factor in factors
            if not factor.webauthn_rp_id.strip() or factor.webauthn_rp_id == expected_rp_id
        ]

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


class LocalFido2Backend(WebAuthnBackend):
    def __init__(
        self,
        *,
        credential_store: ApprovalFactorStore,
        daemon_id: str,
    ) -> None:
        realm_id = credential_store.get_or_create_local_fido2_realm_id(seed=daemon_id)
        super().__init__(
            credential_store=credential_store,
            approval_origin=local_fido2_origin(realm_id),
            rp_id=local_fido2_rp_id(realm_id),
            rp_name="shisad approver",
        )
        self.backend_id = "approver.local_fido2"
        self.method = "local_fido2"
        self.review_surface = ReviewSurface.HOST_RENDERED


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
    _ = backend
    if not requirement.routeable:
        return False

    if evidence.level.priority < requirement.level.priority and (
        requirement.fallback.mode != "allow_levels"
        or not evidence.fallback_used
        or evidence.level not in requirement.fallback.allow_levels
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
    return confirmation_evidence_capabilities(evidence).covers(requirement.require_capabilities)


def confirmation_evidence_capabilities(evidence: ConfirmationEvidence) -> ConfirmationCapabilities:
    """Derive the effective runtime capabilities proven by one evidence record."""

    return ConfirmationCapabilities(
        principal_binding=bool(evidence.approver_principal_id),
        approval_binding=evidence.binding_scope
        in {BindingScope.APPROVAL_ENVELOPE, BindingScope.FULL_INTENT},
        action_digest_binding=evidence.binding_scope
        in {
            BindingScope.ACTION_DIGEST,
            BindingScope.APPROVAL_ENVELOPE,
            BindingScope.FULL_INTENT,
        }
        and bool(evidence.action_digest),
        full_intent_signature=evidence.binding_scope == BindingScope.FULL_INTENT
        and bool(evidence.signature),
        trusted_display=evidence.review_surface == ReviewSurface.TRUSTED_DEVICE_DISPLAY
        and not evidence.blind_sign_detected,
        third_party_verifiable=bool(evidence.third_party_verifiable),
        blind_sign_detection=bool(evidence.blind_sign_detected)
        or evidence.review_surface == ReviewSurface.OPAQUE_DEVICE,
    )


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
                    f"unsupported confirmation lockout schema_version: {schema_version}"
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
