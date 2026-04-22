"""Opaque ingress-context handles for v0.7 memory writes."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from shisad.core.types import TaintLabel
from shisad.memory.trust import (
    ChannelTrust,
    ConfirmationStatus,
    SourceOrigin,
    TrustGateViolation,
    validate_trust_triple,
)

ScopeKind = Literal["user", "project", "session", "channel", "workspace"]


class DerivationPath(StrEnum):
    """Declared path from ingress payload to write payload."""

    DIRECT = "direct"
    EXTRACTED = "extracted"
    SUMMARY = "summary"


def digest_content(content: str | bytes) -> str:
    """Stable SHA-256 digest for ingress payload binding."""

    payload = content.encode("utf-8") if isinstance(content, str) else content
    return hashlib.sha256(payload).hexdigest()


class IngressContext(BaseModel):
    """Opaque runtime-issued provenance handle."""

    model_config = ConfigDict(frozen=True)

    handle_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    source_origin: SourceOrigin
    channel_trust: ChannelTrust
    confirmation_status: ConfirmationStatus
    taint_labels: list[TaintLabel] = Field(default_factory=list)
    scope: ScopeKind
    source_id: str
    content_digest: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class IngressContextRegistry:
    """In-memory registry for minted ingress handles."""

    def __init__(self) -> None:
        self._handles: dict[str, IngressContext] = {}

    def mint(
        self,
        *,
        source_origin: SourceOrigin,
        channel_trust: ChannelTrust,
        confirmation_status: ConfirmationStatus,
        scope: ScopeKind,
        source_id: str,
        content: str | bytes,
        taint_labels: list[TaintLabel] | None = None,
    ) -> IngressContext:
        """Create and register a validated ingress handle."""

        validate_trust_triple(source_origin, channel_trust, confirmation_status)
        context = IngressContext(
            source_origin=source_origin,
            channel_trust=channel_trust,
            confirmation_status=confirmation_status,
            taint_labels=list(taint_labels or []),
            scope=scope,
            source_id=source_id,
            content_digest=digest_content(content),
        )
        self._handles[context.handle_id] = context
        return context

    def resolve(self, handle_id: str) -> IngressContext:
        """Resolve a previously minted handle or raise."""

        try:
            return self._handles[handle_id]
        except KeyError as exc:
            raise TrustGateViolation(f"unknown ingress context: {handle_id}") from exc

    def validate_binding(
        self,
        handle: str | IngressContext,
        *,
        content: str | bytes | None = None,
        content_digest: str | None = None,
        derivation_path: DerivationPath = DerivationPath.DIRECT,
        parent_digest: str | None = None,
    ) -> str:
        """Validate that a write payload is still bound to its ingress source."""

        context = self.resolve(handle) if isinstance(handle, str) else handle
        resolved_digest = content_digest or (
            digest_content(content) if content is not None else None
        )
        if resolved_digest is None:
            raise ValueError("content or content_digest is required for binding validation")

        if derivation_path is DerivationPath.DIRECT:
            if resolved_digest != context.content_digest:
                raise TrustGateViolation("content digest does not match ingress context")
            return resolved_digest

        if parent_digest != context.content_digest:
            raise TrustGateViolation("derivation parent does not match ingress context")
        return resolved_digest


def mint_explicit_user_memory_ingress_context(
    registry: IngressContextRegistry,
    *,
    channel: str,
    trust_level: str,
    session_id: str,
    message_id: str,
    content: str,
    transcript_entry_id: str = "",
    taint_labels: list[TaintLabel] | None = None,
    scope: ScopeKind = "user",
) -> IngressContext | None:
    """Mint the canonical explicit-user-memory handle for a turn payload."""

    user_turn_text = content.strip()
    if not user_turn_text:
        return None

    normalized_channel = channel.strip().lower() or "cli"
    source_origin: SourceOrigin = "user_direct"
    channel_trust: ChannelTrust = "command"
    confirmation_status: ConfirmationStatus = "user_asserted"
    source_id = transcript_entry_id.strip() or session_id.strip()

    if normalized_channel != "cli":
        normalized_trust = trust_level.strip().lower()
        confirmation_status = "auto_accepted"
        if not transcript_entry_id.strip():
            source_id = (
                f"{normalized_channel}:{message_id.strip()}"
                if message_id.strip()
                else f"{normalized_channel}:{session_id.strip()}"
            )
        if normalized_trust in {"trusted", "verified", "internal", "owner"}:
            channel_trust = "owner_observed"
        else:
            source_origin = "external_message"
            channel_trust = (
                "shared_participant"
                if normalized_trust in {"public", "trusted_guest"}
                else "external_incoming"
            )

    return registry.mint(
        source_origin=source_origin,
        channel_trust=channel_trust,
        confirmation_status=confirmation_status,
        scope=scope,
        source_id=source_id,
        content=user_turn_text,
        taint_labels=list(taint_labels or []),
    )
