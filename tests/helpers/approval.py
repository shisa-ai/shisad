"""Shared helpers for building real PendingAction fixtures in tests.

ADV-L4: several approval/signer/TOTP test files had diverged `_pending_action`
helpers returning `SimpleNamespace` to avoid constructing the full dataclass.
Because production backends access pending_action attributes through
`getattr(..., default)`, those stubs worked — but any new required field on
`PendingAction` (or a verify path that reads a field without a default) would
let tests pass for the wrong reason.

This helper produces a real `PendingAction` with sensible defaults so tests
stay sensitive to dataclass drift.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from shisad.core.approval import (
    ApprovalEnvelope,
    ConfirmationCapabilities,
    ConfirmationLevel,
    IntentEnvelope,
)
from shisad.core.types import Capability, SessionId, ToolName, UserId, WorkspaceId
from shisad.daemon.handlers._impl import PendingAction


def make_pending_action(
    *,
    confirmation_id: str = "c-1",
    user_id: str = "alice",
    tool_name: str = "shell.exec",
    arguments: dict[str, Any] | None = None,
    approval_envelope: ApprovalEnvelope | None = None,
    approval_envelope_hash: str = "",
    intent_envelope: IntentEnvelope | None = None,
    allowed_principals: list[str] | None = None,
    allowed_credentials: list[str] | None = None,
    required_level: ConfirmationLevel = ConfirmationLevel.SOFTWARE,
    required_methods: list[str] | None = None,
    required_capabilities: ConfirmationCapabilities | None = None,
    selected_backend_id: str = "",
    selected_backend_method: str = "",
    fallback_used: bool = False,
    decision_nonce: str = "nonce-test",
    capabilities: set[Capability] | None = None,
) -> PendingAction:
    """Return a real ``PendingAction`` using minimal overrides.

    Keeps callers close to the dataclass surface so adding a required field on
    ``PendingAction`` immediately fails every caller rather than silently
    passing via a ``SimpleNamespace`` attribute-default.
    """

    return PendingAction(
        confirmation_id=confirmation_id,
        decision_nonce=decision_nonce,
        session_id=SessionId("session-1"),
        user_id=UserId(user_id),
        workspace_id=WorkspaceId("workspace-1"),
        tool_name=ToolName(tool_name),
        arguments=dict(arguments or {}),
        reason="manual",
        capabilities=set(capabilities or {Capability.HTTP_REQUEST}),
        created_at=datetime.now(UTC),
        approval_envelope=approval_envelope,
        approval_envelope_hash=approval_envelope_hash,
        intent_envelope=intent_envelope,
        allowed_principals=list(allowed_principals or []),
        allowed_credentials=list(allowed_credentials or []),
        required_level=required_level,
        required_methods=list(required_methods or []),
        required_capabilities=required_capabilities or ConfirmationCapabilities(),
        selected_backend_id=selected_backend_id,
        selected_backend_method=selected_backend_method,
        fallback_used=fallback_used,
    )
