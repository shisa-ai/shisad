"""A2A envelope schema, signing helpers, and replay protection."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import uuid
from collections import OrderedDict
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator

A2A_PROTOCOL_VERSION = "shisad-a2a/0.1"
DEFAULT_REPLAY_WINDOW_SECONDS = 300
_A2A_AGENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_A2A_INTENT_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def normalize_a2a_agent_id(value: object) -> str:
    candidate = str(value).strip()
    if not candidate or not _A2A_AGENT_ID_RE.fullmatch(candidate):
        raise ValueError("A2A agent_id must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    return candidate


def normalize_a2a_intent(value: object) -> str:
    candidate = str(value).strip().lower()
    if not candidate or not _A2A_INTENT_RE.fullmatch(candidate):
        raise ValueError("A2A intent names must match ^[a-z][a-z0-9_]{0,63}$")
    return candidate


def _normalize_timestamp(value: object) -> str:
    parsed = parse_a2a_timestamp(value)
    normalized = parsed.replace(microsecond=0)
    return normalized.isoformat().replace("+00:00", "Z")


class A2aSender(BaseModel):
    """Authenticated sender identity carried in an A2A envelope."""

    model_config = ConfigDict(frozen=True)

    agent_id: str
    public_key_fingerprint: str

    @field_validator("agent_id", mode="before")
    @classmethod
    def _validate_agent_id(cls, value: object) -> str:
        return normalize_a2a_agent_id(value)

    @field_validator("public_key_fingerprint", mode="before")
    @classmethod
    def _validate_fingerprint(cls, value: object) -> str:
        candidate = str(value).strip().lower()
        if not candidate.startswith("sha256:") or len(candidate) != 71:
            raise ValueError("A2A public_key_fingerprint must use sha256:<64-hex>")
        fingerprint = candidate.removeprefix("sha256:")
        int(fingerprint, 16)
        return candidate


class A2aRecipient(BaseModel):
    """Destination identity carried in an A2A envelope."""

    model_config = ConfigDict(frozen=True)

    agent_id: str

    @field_validator("agent_id", mode="before")
    @classmethod
    def _validate_agent_id(cls, value: object) -> str:
        return normalize_a2a_agent_id(value)


class A2aEnvelope(BaseModel):
    """Signed A2A request/response envelope."""

    model_config = ConfigDict(populate_by_name=True, frozen=True)

    version: str = A2A_PROTOCOL_VERSION
    message_id: str
    sender: A2aSender = Field(alias="from")
    recipient: A2aRecipient = Field(alias="to")
    timestamp: str
    type: Literal["request", "response", "notification"]
    intent: str
    payload: dict[str, Any]
    signature: str = ""

    @field_validator("message_id", mode="before")
    @classmethod
    def _validate_message_id(cls, value: object) -> str:
        candidate = str(value).strip()
        if not candidate:
            raise ValueError("A2A message_id cannot be empty")
        return candidate

    @field_validator("timestamp", mode="before")
    @classmethod
    def _validate_timestamp(cls, value: object) -> str:
        return _normalize_timestamp(value)

    @field_validator("intent", mode="before")
    @classmethod
    def _validate_intent(cls, value: object) -> str:
        return normalize_a2a_intent(value)


def _write_bytes_exclusive(path: Path, data: bytes, *, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    handle = None
    try:
        handle = os.fdopen(fd, "wb")
        with handle:
            handle.write(data)
    except Exception:
        if handle is None:
            with suppress(OSError):
                os.close(fd)
        with suppress(OSError):
            path.unlink(missing_ok=True)
        raise


def parse_a2a_timestamp(value: object) -> datetime:
    """Parse an A2A timestamp into a UTC-aware datetime."""

    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        if not text:
            raise ValueError("A2A timestamp cannot be empty")
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def serialize_private_key_pem(private_key: Ed25519PrivateKey) -> bytes:
    """Serialize an Ed25519 private key as PEM PKCS8."""

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serialize_public_key_pem(public_key: Ed25519PublicKey) -> bytes:
    """Serialize an Ed25519 public key as PEM SubjectPublicKeyInfo."""

    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate an Ed25519 keypair."""

    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def fingerprint_for_public_key(public_key: Ed25519PublicKey) -> str:
    """Compute the canonical sha256 fingerprint for an Ed25519 public key."""

    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def load_private_key_from_path(path: Path) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a PEM path."""

    loaded = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise TypeError("A2A private key must be an Ed25519 key")
    return loaded


def load_public_key_from_path(path: Path) -> Ed25519PublicKey:
    """Load an Ed25519 public key from a PEM path."""

    return load_public_key_from_pem(path.read_bytes())


def load_public_key_from_pem(data: bytes | str) -> Ed25519PublicKey:
    """Load an Ed25519 public key from PEM bytes/text."""

    payload = data.encode("utf-8") if isinstance(data, str) else data
    loaded = serialization.load_pem_public_key(payload)
    if not isinstance(loaded, Ed25519PublicKey):
        raise TypeError("A2A public key must be an Ed25519 key")
    return loaded


def write_ed25519_keypair(private_key_path: Path, public_key_path: Path) -> str:
    """Generate and persist an Ed25519 keypair, returning the public fingerprint."""

    private_key, public_key = generate_ed25519_keypair()
    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    private_bytes = serialize_private_key_pem(private_key)
    public_bytes = serialize_public_key_pem(public_key)
    try:
        _write_bytes_exclusive(private_key_path, private_bytes, mode=0o600)
        try:
            _write_bytes_exclusive(public_key_path, public_bytes, mode=0o644)
        except Exception:
            private_key_path.unlink(missing_ok=True)
            raise
    except FileExistsError as exc:
        raise FileExistsError(
            f"A2A key output already exists: {exc.filename or private_key_path}"
        ) from exc
    return fingerprint_for_public_key(public_key)


def create_envelope(
    *,
    from_agent_id: str,
    from_fingerprint: str,
    to_agent_id: str,
    message_type: Literal["request", "response", "notification"],
    intent: str,
    payload: dict[str, Any],
    message_id: str | None = None,
    timestamp: datetime | None = None,
) -> A2aEnvelope:
    """Create an unsigned A2A envelope."""

    return A2aEnvelope(
        message_id=message_id or uuid.uuid4().hex,
        sender=A2aSender(agent_id=from_agent_id, public_key_fingerprint=from_fingerprint),
        recipient=A2aRecipient(agent_id=to_agent_id),
        timestamp=_normalize_timestamp(timestamp or datetime.now(UTC)),
        type=message_type,
        intent=intent,
        payload=dict(payload),
        signature="",
    )


def canonical_envelope_json(envelope: A2aEnvelope) -> str:
    """Return the canonical JSON string signed by the A2A transport."""

    payload = envelope.model_dump(mode="json", by_alias=True)
    payload["signature"] = ""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sign_envelope(envelope: A2aEnvelope, private_key: Ed25519PrivateKey) -> bytes:
    """Sign an envelope's canonical JSON representation."""

    return private_key.sign(canonical_envelope_json(envelope).encode("utf-8"))


def attach_signature(envelope: A2aEnvelope, signature: bytes) -> A2aEnvelope:
    """Return a copy of *envelope* with a base64 signature attached."""

    return envelope.model_copy(
        update={"signature": base64.b64encode(signature).decode("ascii")},
    )


def verify_envelope(envelope: A2aEnvelope, public_key: Ed25519PublicKey) -> bool:
    """Verify an envelope signature with the sender's Ed25519 public key."""

    signature_text = str(envelope.signature).strip()
    if not signature_text:
        return False
    try:
        signature = base64.b64decode(signature_text.encode("ascii"), validate=True)
    except (ValueError, TypeError):
        return False
    try:
        public_key.verify(signature, canonical_envelope_json(envelope).encode("utf-8"))
    except InvalidSignature:
        return False
    return True


@dataclass(frozen=True, slots=True)
class ReplayCheckResult:
    """Replay-window admission result for an A2A message."""

    allowed: bool
    reason: str = ""


class ReplayCache:
    """Bounded in-memory replay cache keyed by message_id."""

    def __init__(
        self,
        *,
        window_seconds: int = DEFAULT_REPLAY_WINDOW_SECONDS,
        max_entries: int = 4096,
    ) -> None:
        self._window = timedelta(seconds=max(1, int(window_seconds)))
        self._max_entries = max(1, int(max_entries))
        self._entries: OrderedDict[str, datetime] = OrderedDict()

    def check(
        self,
        envelope: A2aEnvelope,
        *,
        now: datetime | None = None,
    ) -> ReplayCheckResult:
        """Validate timestamp freshness and reject duplicate message ids."""

        current = (now or datetime.now(UTC)).astimezone(UTC)
        self._prune(current)
        try:
            message_time = parse_a2a_timestamp(envelope.timestamp)
        except ValueError:
            return ReplayCheckResult(allowed=False, reason="invalid_timestamp")
        if abs((current - message_time).total_seconds()) > self._window.total_seconds():
            return ReplayCheckResult(allowed=False, reason="timestamp_out_of_window")
        if envelope.message_id in self._entries:
            return ReplayCheckResult(allowed=False, reason="replay_detected")
        self._entries[envelope.message_id] = message_time + self._window
        if len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)
        return ReplayCheckResult(allowed=True)

    def _prune(self, now: datetime) -> None:
        expired = [
            message_id for message_id, expires_at in self._entries.items() if expires_at < now
        ]
        for message_id in expired:
            self._entries.pop(message_id, None)
