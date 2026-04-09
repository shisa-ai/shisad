"""Unit checks for chat-based confirmation classification and routing."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from shisad.core.transcript import TranscriptStore
from shisad.core.types import Capability, SessionId, SessionMode, ToolName, UserId, WorkspaceId
from shisad.daemon.handlers._impl import PendingAction
from shisad.daemon.handlers._impl_session import (
    ChatConfirmationIntent,
    SessionImplMixin,
    _classify_chat_confirmation_intent,
    _resolve_chat_confirmation_indexes,
)
from shisad.security.control_plane.sidecar import ControlPlaneUnavailableError
from shisad.security.firewall import FirewallResult
from shisad.security.firewall.output import OutputFirewallResult


def test_m6_crc_classifier_handles_affirmative_negative_reference_and_passthrough() -> None:
    assert _classify_chat_confirmation_intent("yes") == ChatConfirmationIntent(
        action="confirm",
        target="single",
        index=None,
    )
    assert _classify_chat_confirmation_intent("go ahead") == ChatConfirmationIntent(
        action="confirm",
        target="single",
        index=None,
    )
    assert _classify_chat_confirmation_intent("confirm 2") == ChatConfirmationIntent(
        action="confirm",
        target="index",
        index=2,
    )
    assert _classify_chat_confirmation_intent("yes to all") == ChatConfirmationIntent(
        action="confirm",
        target="all",
        index=None,
    )
    assert _classify_chat_confirmation_intent("reject 1") == ChatConfirmationIntent(
        action="reject",
        target="index",
        index=1,
    )
    assert _classify_chat_confirmation_intent("no to all") == ChatConfirmationIntent(
        action="reject",
        target="all",
        index=None,
    )
    assert _classify_chat_confirmation_intent("what tools do you have?") == ChatConfirmationIntent(
        action="none",
        target="none",
        index=None,
    )


def test_m6_crc_routing_clean_session_auto_confirms_single_pending() -> None:
    intent = ChatConfirmationIntent(action="confirm", target="single", index=None)
    resolved = _resolve_chat_confirmation_indexes(
        intent=intent,
        pending_count=1,
        tainted_session=False,
    )
    assert resolved == [0]


def test_m6_crc_routing_requires_reference_for_tainted_or_multi_pending() -> None:
    intent = ChatConfirmationIntent(action="confirm", target="single", index=None)
    assert (
        _resolve_chat_confirmation_indexes(
            intent=intent,
            pending_count=1,
            tainted_session=True,
        )
        == []
    )
    assert (
        _resolve_chat_confirmation_indexes(
            intent=intent,
            pending_count=2,
            tainted_session=False,
        )
        == []
    )
    explicit = ChatConfirmationIntent(action="confirm", target="index", index=2)
    assert _resolve_chat_confirmation_indexes(
        intent=explicit,
        pending_count=2,
        tainted_session=True,
    ) == [1]


class _ChatConfirmationHarness(SessionImplMixin):
    def __init__(self, tmp_path) -> None:
        self._pending_actions: dict[str, PendingAction] = {}
        self._output_firewall = SimpleNamespace(inspect=self._inspect_output)
        self._lockdown_manager = SimpleNamespace(
            user_notification=lambda _sid: "",
            state_for=lambda _sid: SimpleNamespace(level=SimpleNamespace(value="none")),
        )
        self._transcript_root = tmp_path / "sessions"
        self._transcript_store = TranscriptStore(self._transcript_root)
        self._event_bus = SimpleNamespace(publish=self._noop_publish)
        self._control_plane = SimpleNamespace(active_plan_hash=self._active_plan_hash)

    async def _noop_publish(self, _event: object) -> None:
        return None

    @staticmethod
    def _inspect_output(text: str, context: object) -> OutputFirewallResult:
        _ = context
        return OutputFirewallResult(sanitized_text=text)

    @staticmethod
    def _active_plan_hash(_session_id: str) -> str:
        raise ControlPlaneUnavailableError(reason_code="control_plane.unavailable")

    def _session_has_tainted_history(self, _sid: SessionId) -> bool:
        return False

    async def do_action_confirm(self, params: dict[str, object]) -> dict[str, object]:
        pending = self._pending_actions[str(params["confirmation_id"])]
        pending.status = "approved"
        pending.status_reason = "chat_confirmation"
        return {"confirmed": True, "status": "approved"}

    async def do_action_reject(self, params: dict[str, object]) -> dict[str, object]:
        pending = self._pending_actions[str(params["confirmation_id"])]
        pending.status = "rejected"
        pending.status_reason = "chat_confirmation"
        return {"rejected": True, "status": "rejected"}


@pytest.mark.asyncio
async def test_h1_chat_confirmation_response_degrades_when_plan_hash_lookup_fails(tmp_path) -> None:
    harness = _ChatConfirmationHarness(tmp_path)
    pending = PendingAction(
        confirmation_id="c-1",
        decision_nonce="nonce-1",
        session_id=SessionId("sess-chat"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws-1"),
        tool_name=ToolName("web.search"),
        arguments={"query": "hello"},
        reason="manual",
        capabilities={Capability.HTTP_REQUEST},
        created_at=datetime.now(UTC),
    )
    harness._pending_actions[pending.confirmation_id] = pending

    result = await SessionImplMixin._maybe_handle_chat_confirmation(
        harness,
        sid=SessionId("sess-chat"),
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws-1"),
        session_mode=SessionMode.DEFAULT,
        trust_level="trusted",
        trusted_input=True,
        is_internal_ingress=False,
        content="yes",
        firewall_result=FirewallResult(sanitized_text="yes", original_hash="0" * 64),
    )

    assert result is not None
    assert result["response"].startswith("confirmed 1")
    assert result["plan_hash"] == ""


@pytest.mark.asyncio
@pytest.mark.parametrize("content", ["shisad action confirm c-1", "c-1"])
async def test_h1_chat_confirmation_does_not_treat_cli_command_or_id_as_approval(
    tmp_path,
    content: str,
) -> None:
    harness = _ChatConfirmationHarness(tmp_path)
    pending = PendingAction(
        confirmation_id="c-1",
        decision_nonce="nonce-1",
        session_id=SessionId("sess-chat"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws-1"),
        tool_name=ToolName("web.search"),
        arguments={"query": "hello"},
        reason="manual",
        capabilities={Capability.HTTP_REQUEST},
        created_at=datetime.now(UTC),
    )
    harness._pending_actions[pending.confirmation_id] = pending

    result = await SessionImplMixin._maybe_handle_chat_confirmation(
        harness,
        sid=SessionId("sess-chat"),
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws-1"),
        session_mode=SessionMode.DEFAULT,
        trust_level="trusted",
        trusted_input=True,
        is_internal_ingress=False,
        content=content,
        firewall_result=FirewallResult(sanitized_text=content, original_hash="0" * 64),
    )

    assert result is None
    assert harness._pending_actions["c-1"].status == "pending"
