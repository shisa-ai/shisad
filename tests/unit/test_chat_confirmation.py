"""Unit checks for chat-based confirmation classification and routing."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from shisad.channels.base import DeliveryTarget
from shisad.core.transcript import TranscriptStore
from shisad.core.types import Capability, SessionId, SessionMode, ToolName, UserId, WorkspaceId
from shisad.daemon.handlers._impl import PendingAction
from shisad.daemon.handlers._impl_session import (
    ChatConfirmationIntent,
    ChatTotpSubmission,
    SessionImplMixin,
    _classify_chat_confirmation_intent,
    _parse_chat_totp_submission,
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
    assert _classify_chat_confirmation_intent("1") == ChatConfirmationIntent(
        action="confirm",
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


def test_u9_chat_totp_parser_handles_bare_code_targeted_code_and_passthrough() -> None:
    assert _parse_chat_totp_submission("123456") == ChatTotpSubmission(
        confirmation_id=None,
        code="123456",
    )
    assert _parse_chat_totp_submission("confirm c-1 123456") == ChatTotpSubmission(
        confirmation_id="c-1",
        code="123456",
    )
    assert _parse_chat_totp_submission("approve abc123 654321") == ChatTotpSubmission(
        confirmation_id="abc123",
        code="654321",
    )
    assert _parse_chat_totp_submission("confirm 1") is None
    assert _parse_chat_totp_submission("there are 123456 reasons") is None


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


def test_chat_pending_confirmation_summary_retains_bulk_guidance() -> None:
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

    summary = SessionImplMixin._chat_pending_confirmation_summary(
        pending_rows=[pending],
        tainted_session=False,
    )

    assert "yes to all" in summary.lower()
    assert "no to all" in summary.lower()


def test_chat_pending_confirmation_summary_adds_totp_guidance_when_totp_is_pending() -> None:
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
        selected_backend_id="totp.default",
        selected_backend_method="totp",
    )

    summary = SessionImplMixin._chat_pending_confirmation_summary(
        pending_rows=[pending],
        tainted_session=False,
    )

    assert "6-digit code" in summary
    assert "confirm confirmation_id 123456" in summary.lower()
    assert "shisad action confirm confirmation_id --totp-code 123456" in summary.lower()
    assert "confirmation id: c-1" in summary.lower()
    assert "reply with 'confirm n'" not in summary.lower()
    assert "yes to all" not in summary.lower()


class _ChatConfirmationHarness(SessionImplMixin):
    def __init__(self, tmp_path) -> None:
        self._pending_actions: dict[str, PendingAction] = {}
        self.confirm_calls: list[dict[str, object]] = []
        self.reject_calls: list[dict[str, object]] = []
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
        self.confirm_calls.append(dict(params))
        pending = self._pending_actions[str(params["confirmation_id"])]
        pending.status = "approved"
        pending.status_reason = "chat_confirmation"
        return {"confirmed": True, "status": "approved"}

    async def do_action_reject(self, params: dict[str, object]) -> dict[str, object]:
        self.reject_calls.append(dict(params))
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
    assert result["checkpoint_ids"] == []
    assert result["checkpoints_created"] == 0


@pytest.mark.asyncio
async def test_lt3_chat_confirmation_reports_failed_batch_confirmation_reason(tmp_path) -> None:
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

    async def fail_confirm(params: dict[str, object]) -> dict[str, object]:
        failed = harness._pending_actions[str(params["confirmation_id"])]
        failed.status = "failed"
        failed.status_reason = "approval_envelope_missing"
        return {
            "confirmed": False,
            "status": "failed",
            "status_reason": "approval_envelope_missing",
        }

    harness.do_action_confirm = fail_confirm  # type: ignore[method-assign]

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
        content="yes to all",
        firewall_result=FirewallResult(sanitized_text="yes to all", original_hash="0" * 64),
    )

    assert result is not None
    response = str(result["response"]).lower()
    assert "confirmation failed for 1" in response
    assert "approval_envelope_missing" in response
    assert "confirmed 1" not in response
    assert result["executed_actions"] == 0
    assert result["blocked_actions"] == 1
    assert result["pending_confirmation_ids"] == []


@pytest.mark.asyncio
async def test_u5_chat_confirmation_accepts_clean_trusted_cli_default_session(tmp_path) -> None:
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
        trust_level="trusted_cli",
        trusted_input=False,
        is_internal_ingress=False,
        content="confirm 1",
        firewall_result=FirewallResult(sanitized_text="confirm 1", original_hash="0" * 64),
    )

    assert result is not None
    assert result["response"].startswith("confirmed 1")
    assert harness.confirm_calls


@pytest.mark.asyncio
async def test_lt2_chat_confirmation_accepts_bare_pending_number(tmp_path) -> None:
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
        content="1",
        firewall_result=FirewallResult(sanitized_text="1", original_hash="0" * 64),
    )

    assert result is not None
    assert result["response"].startswith("confirmed 1")
    assert harness.confirm_calls


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("content", "suggestion"),
    [
        ("comfirm 1", "confirm 1"),
        ("rejct 1", "reject 1"),
        ("comfirm", "confirm"),
        ("rejcet", "reject"),
    ],
)
async def test_lt2_chat_confirmation_typo_returns_suggestion_without_planner_pass_through(
    tmp_path,
    content: str,
    suggestion: str,
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

    assert result is not None
    response = str(result["response"]).lower()
    assert f"did you mean '{suggestion}'" in response
    assert "no action was taken" in response
    assert harness.confirm_calls == []
    assert harness._pending_actions["c-1"].status == "pending"
    assert result["pending_confirmation_ids"] == ["c-1"]


@pytest.mark.asyncio
async def test_lt2_chat_confirmation_bad_index_returns_error_without_planner_pass_through(
    tmp_path,
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
        content="confirm 2",
        firewall_result=FirewallResult(sanitized_text="confirm 2", original_hash="0" * 64),
    )

    assert result is not None
    response = str(result["response"]).lower()
    assert "confirmation index 2 is not pending" in response
    assert "no action was taken" in response
    assert harness.confirm_calls == []
    assert harness._pending_actions["c-1"].status == "pending"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "content",
    [
        "shisad action confirm c-1",
        "shisactl action confirm c-1",
        "shisad action confirm c-1 --nonce nonce-1 --reason approved",
        "shisactl action confirm c-1 --nonce nonce-1 --reason approved",
        "shisad action confirm c-1 --recovery-code abcd-1234",
        "shisad action reject c-1 --nonce nonce-1 --reason manual_reject",
        "shisactl action reject c-1 --nonce nonce-1 --reason manual_reject",
        "shisad action pending --session sess-chat --status pending --limit 10 --raw",
        "shisactl action pending --session sess-chat --status pending --limit 10 --raw",
        "shisad action purge --status failed --session sess-chat --limit 10 --dry-run",
        "shisactl action purge --status failed --session sess-chat --limit 10 --dry-run",
        "shisad action purge --status pending --older-than-days 7",
        "shisactl action purge --status pending --older-than-days 7",
        "shisad action purge --help",
        "shisactl action purge --help",
        "CLI fallback: run 'shisad action pending' to inspect pending approvals.",
        "CLI fallback: run 'shisactl action pending' to inspect pending approvals.",
        "```shisad action pending```",
        "```shisactl action pending```",
        "```\nshisad action confirm c-1 --nonce nonce-1\n```",
        "```\nshisactl action confirm c-1 --nonce nonce-1\n```",
        "```text\nshisad action reject c-1 --nonce nonce-1\n```",
        "shisad action --help",
        "shisactl action --help",
        "shisad action confirm --help",
        "shisactl action confirm --help",
        "shisad action pending --help",
        "shisactl action pending --help",
        "run 'shisad action confirm c-1'",
        "run 'shisactl action confirm c-1'",
        "Then run 'shisad action reject c-1'",
        "Then run 'shisactl action reject c-1'",
        "Review all pending: shisad action pending",
        "Review all pending: shisactl action pending",
        "c-1",
    ],
)
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

    assert result is not None
    response = str(result["response"]).lower()
    assert "no action was taken" in response
    assert "use 'confirm n'" in response
    assert harness._pending_actions["c-1"].status == "pending"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "content",
    [
        'What does "shisad action pending" show?',
        'Should I run "shisad action reject c-1" now?',
        "shisad action reject c-1 now?",
        "shisad action pending --session sess-chat what does this show?",
        "shisad action confirm c-1 --reason approved now?",
        '"shisad action reject c-1" now?',
        "`shisad action pending --session sess-chat` what does this show?",
    ],
)
async def test_h1_chat_confirmation_cli_command_mentions_still_reach_planner(
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


@pytest.mark.asyncio
async def test_u9_chat_totp_bare_code_confirms_single_pending_totp_action(tmp_path) -> None:
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
        selected_backend_id="totp.default",
        selected_backend_method="totp",
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
        content="123456",
        firewall_result=FirewallResult(sanitized_text="123456", original_hash="0" * 64),
    )

    assert result is not None
    assert "confirmed c-1" in str(result["response"]).lower()
    assert "123456" not in str(result["response"])
    assert result["pending_confirmation_ids"] == []
    assert harness.confirm_calls == [
        {
            "confirmation_id": "c-1",
            "decision_nonce": "nonce-1",
            "approval_method": "totp",
            "proof": {"totp_code": "123456"},
            "reason": "chat_totp_confirmation",
        }
    ]


@pytest.mark.asyncio
async def test_u9_chat_totp_bare_code_confirms_trusted_internal_channel_ingress(tmp_path) -> None:
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
        selected_backend_id="totp.default",
        selected_backend_method="totp",
    )
    harness._pending_actions[pending.confirmation_id] = pending

    result = await SessionImplMixin._maybe_handle_chat_confirmation(
        harness,
        sid=SessionId("sess-chat"),
        channel="discord",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws-1"),
        session_mode=SessionMode.DEFAULT,
        trust_level="trusted",
        trusted_input=True,
        is_internal_ingress=True,
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
        stored_delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
        content="123456",
        firewall_result=FirewallResult(sanitized_text="123456", original_hash="0" * 64),
    )

    assert result is not None
    assert "confirmed c-1" in str(result["response"]).lower()
    assert harness.confirm_calls == [
        {
            "confirmation_id": "c-1",
            "decision_nonce": "nonce-1",
            "approval_method": "totp",
            "proof": {"totp_code": "123456"},
            "reason": "chat_totp_confirmation",
        }
    ]


@pytest.mark.asyncio
async def test_u9_chat_totp_internal_ingress_rejects_mismatched_stored_delivery_target(
    tmp_path,
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
        selected_backend_id="totp.default",
        selected_backend_method="totp",
    )
    harness._pending_actions[pending.confirmation_id] = pending

    result = await SessionImplMixin._maybe_handle_chat_confirmation(
        harness,
        sid=SessionId("sess-chat"),
        channel="discord",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws-1"),
        session_mode=SessionMode.DEFAULT,
        trust_level="trusted",
        trusted_input=True,
        is_internal_ingress=True,
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-2"),
        stored_delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
        content="123456",
        firewall_result=FirewallResult(sanitized_text="123456", original_hash="0" * 64),
    )

    assert result is not None
    response = str(result["response"]).lower()
    assert "different chat target" in response
    assert "original approval thread/channel" in response
    assert "shisad action pending" in response
    assert "shisad action confirm confirmation_id --totp-code 123456" in response
    assert "confirmation id: c-1" not in response
    assert "pending confirmations." not in response
    assert "web.search" not in response
    assert result["blocked_actions"] == 1
    assert result["executed_actions"] == 0
    assert result["pending_confirmation_ids"] == []
    assert harness.confirm_calls == []
    assert harness._pending_actions["c-1"].status == "pending"


@pytest.mark.asyncio
async def test_u9_chat_totp_internal_ingress_scopes_targeted_confirmation_to_pending_target(
    tmp_path,
) -> None:
    harness = _ChatConfirmationHarness(tmp_path)
    first = PendingAction(
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
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
        selected_backend_id="totp.default",
        selected_backend_method="totp",
    )
    second = PendingAction(
        confirmation_id="c-2",
        decision_nonce="nonce-2",
        session_id=SessionId("sess-chat"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws-1"),
        tool_name=ToolName("web.search"),
        arguments={"query": "world"},
        reason="manual",
        capabilities={Capability.HTTP_REQUEST},
        created_at=datetime.now(UTC),
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-2"),
        selected_backend_id="totp.default",
        selected_backend_method="totp",
    )
    harness._pending_actions[first.confirmation_id] = first
    harness._pending_actions[second.confirmation_id] = second

    wrong_thread = await SessionImplMixin._maybe_handle_chat_confirmation(
        harness,
        sid=SessionId("sess-chat"),
        channel="discord",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws-1"),
        session_mode=SessionMode.DEFAULT,
        trust_level="trusted",
        trusted_input=True,
        is_internal_ingress=True,
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
        stored_delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
        content="confirm c-2 123456",
        firewall_result=FirewallResult(
            sanitized_text="confirm c-2 123456",
            original_hash="0" * 64,
        ),
    )

    assert wrong_thread is not None
    assert "different chat target" in str(wrong_thread["response"]).lower()
    assert wrong_thread["executed_actions"] == 0
    assert wrong_thread["pending_confirmation_ids"] == []
    assert harness.confirm_calls == []
    assert harness._pending_actions["c-2"].status == "pending"

    right_thread = await SessionImplMixin._maybe_handle_chat_confirmation(
        harness,
        sid=SessionId("sess-chat"),
        channel="discord",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws-1"),
        session_mode=SessionMode.DEFAULT,
        trust_level="trusted",
        trusted_input=True,
        is_internal_ingress=True,
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-2"),
        stored_delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
        content="confirm c-2 123456",
        firewall_result=FirewallResult(
            sanitized_text="confirm c-2 123456",
            original_hash="0" * 64,
        ),
    )

    assert right_thread is not None
    response = str(right_thread["response"]).lower()
    assert "confirmed c-2" in response
    assert "c-1" not in response
    assert right_thread["pending_confirmation_ids"] == []
    assert harness.confirm_calls == [
        {
            "confirmation_id": "c-2",
            "decision_nonce": "nonce-2",
            "approval_method": "totp",
            "proof": {"totp_code": "123456"},
            "reason": "chat_totp_confirmation",
        }
    ]
    assert harness._pending_actions["c-1"].status == "pending"
    assert harness._pending_actions["c-2"].status == "approved"


@pytest.mark.asyncio
@pytest.mark.parametrize("content", ["reject 1", "no to all"])
async def test_u9_chat_totp_internal_ingress_scopes_rejects_to_visible_target(
    tmp_path,
    content: str,
) -> None:
    harness = _ChatConfirmationHarness(tmp_path)
    first = PendingAction(
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
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
        selected_backend_id="totp.default",
        selected_backend_method="totp",
    )
    second = PendingAction(
        confirmation_id="c-2",
        decision_nonce="nonce-2",
        session_id=SessionId("sess-chat"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws-1"),
        tool_name=ToolName("web.search"),
        arguments={"query": "world"},
        reason="manual",
        capabilities={Capability.HTTP_REQUEST},
        created_at=datetime.now(UTC),
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-2"),
        selected_backend_id="totp.default",
        selected_backend_method="totp",
    )
    harness._pending_actions[first.confirmation_id] = first
    harness._pending_actions[second.confirmation_id] = second

    result = await SessionImplMixin._maybe_handle_chat_confirmation(
        harness,
        sid=SessionId("sess-chat"),
        channel="discord",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws-1"),
        session_mode=SessionMode.DEFAULT,
        trust_level="trusted",
        trusted_input=True,
        is_internal_ingress=True,
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-2"),
        stored_delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
        content=content,
        firewall_result=FirewallResult(sanitized_text=content, original_hash="0" * 64),
    )

    assert result is not None
    response = str(result["response"]).lower()
    assert "rejected 1 (web.search): rejected" in response
    assert "different chat target" not in response
    assert "c-1" not in response
    assert result["confirmation_required_actions"] == 0
    assert result["pending_confirmation_ids"] == []
    assert harness._pending_actions["c-1"].status == "pending"
    assert harness._pending_actions["c-2"].status == "rejected"


@pytest.mark.asyncio
@pytest.mark.parametrize("content", ["reject 1", "no to all"])
async def test_u9_chat_totp_internal_ingress_mismatched_reject_intent_uses_reject_recovery_guidance(
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
        selected_backend_id="totp.default",
        selected_backend_method="totp",
    )
    harness._pending_actions[pending.confirmation_id] = pending

    result = await SessionImplMixin._maybe_handle_chat_confirmation(
        harness,
        sid=SessionId("sess-chat"),
        channel="discord",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws-1"),
        session_mode=SessionMode.DEFAULT,
        trust_level="trusted",
        trusted_input=True,
        is_internal_ingress=True,
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-2"),
        stored_delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
        content=content,
        firewall_result=FirewallResult(sanitized_text=content, original_hash="0" * 64),
    )

    assert result is not None
    response = str(result["response"]).lower()
    assert "different chat target" in response
    assert "original approval thread/channel" in response
    assert "shisad action pending" in response
    assert "shisad action reject confirmation_id" in response
    assert "shisad action confirm confirmation_id --totp-code 123456" not in response
    assert "confirmation id: c-1" not in response
    assert result["blocked_actions"] == 1
    assert result["executed_actions"] == 0
    assert result["pending_confirmation_ids"] == []
    assert harness.confirm_calls == []
    assert harness._pending_actions["c-1"].status == "pending"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("content", "suggestion"),
    [
        ("rejct 1", "reject 1"),
        ("rejcet", "reject"),
    ],
)
async def test_lt2_chat_totp_internal_ingress_reject_typo_returns_suggestion(
    tmp_path,
    content: str,
    suggestion: str,
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
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
        selected_backend_id="totp.default",
        selected_backend_method="totp",
    )
    harness._pending_actions[pending.confirmation_id] = pending

    result = await SessionImplMixin._maybe_handle_chat_confirmation(
        harness,
        sid=SessionId("sess-chat"),
        channel="discord",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws-1"),
        session_mode=SessionMode.DEFAULT,
        trust_level="trusted",
        trusted_input=True,
        is_internal_ingress=True,
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
        stored_delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
        content=content,
        firewall_result=FirewallResult(sanitized_text=content, original_hash="0" * 64),
    )

    assert result is not None
    response = str(result["response"]).lower()
    assert f"did you mean '{suggestion}'" in response
    assert "no action was taken" in response
    assert harness.confirm_calls == []
    assert harness.reject_calls == []
    assert harness._pending_actions["c-1"].status == "pending"


@pytest.mark.asyncio
async def test_u9_chat_totp_internal_ingress_without_target_is_ignored(tmp_path) -> None:
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
        selected_backend_id="totp.default",
        selected_backend_method="totp",
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
        is_internal_ingress=True,
        content="123456",
        firewall_result=FirewallResult(sanitized_text="123456", original_hash="0" * 64),
    )

    assert result is None
    assert harness.confirm_calls == []
    assert harness._pending_actions["c-1"].status == "pending"


@pytest.mark.asyncio
async def test_u9_chat_totp_internal_ingress_mismatched_non_confirmation_message_is_ignored(
    tmp_path,
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
        selected_backend_id="totp.default",
        selected_backend_method="totp",
    )
    harness._pending_actions[pending.confirmation_id] = pending

    result = await SessionImplMixin._maybe_handle_chat_confirmation(
        harness,
        sid=SessionId("sess-chat"),
        channel="discord",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws-1"),
        session_mode=SessionMode.DEFAULT,
        trust_level="trusted",
        trusted_input=True,
        is_internal_ingress=True,
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-2"),
        stored_delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
        content="still there?",
        firewall_result=FirewallResult(
            sanitized_text="still there?",
            original_hash="0" * 64,
        ),
    )

    assert result is None
    assert harness.confirm_calls == []
    assert harness._pending_actions["c-1"].status == "pending"


@pytest.mark.asyncio
@pytest.mark.parametrize("content", ["yes", "confirm 1", "comfirm 1", "yes to all"])
async def test_u9_chat_internal_channel_ingress_does_not_reopen_non_totp_proofless_approval(
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
        selected_backend_id="software.default",
        selected_backend_method="software",
    )
    harness._pending_actions[pending.confirmation_id] = pending

    result = await SessionImplMixin._maybe_handle_chat_confirmation(
        harness,
        sid=SessionId("sess-chat"),
        channel="discord",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws-1"),
        session_mode=SessionMode.DEFAULT,
        trust_level="trusted",
        trusted_input=True,
        is_internal_ingress=True,
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
        content=content,
        firewall_result=FirewallResult(sanitized_text=content, original_hash="0" * 64),
    )

    assert result is not None
    response = str(result["response"]).lower()
    assert "not accepted without proof" in response
    assert "no action was taken" in response
    assert harness.confirm_calls == []
    assert harness._pending_actions["c-1"].status == "pending"


@pytest.mark.asyncio
@pytest.mark.parametrize("content", ["reject 1", "no to all"])
async def test_u9_chat_internal_channel_ingress_allows_rejecting_totp_pending_actions(
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
        selected_backend_id="totp.default",
        selected_backend_method="totp",
    )
    harness._pending_actions[pending.confirmation_id] = pending

    result = await SessionImplMixin._maybe_handle_chat_confirmation(
        harness,
        sid=SessionId("sess-chat"),
        channel="discord",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws-1"),
        session_mode=SessionMode.DEFAULT,
        trust_level="trusted",
        trusted_input=True,
        is_internal_ingress=True,
        delivery_target=DeliveryTarget(channel="discord", recipient="chan-1"),
        content=content,
        firewall_result=FirewallResult(sanitized_text=content, original_hash="0" * 64),
    )

    assert result is not None
    assert "rejected 1" in str(result["response"]).lower()
    assert result["pending_confirmation_ids"] == []
    assert harness.confirm_calls == []
    assert harness._pending_actions["c-1"].status == "rejected"


@pytest.mark.asyncio
async def test_u9_chat_totp_bare_code_is_ignored_without_active_totp_prompt(tmp_path) -> None:
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
        selected_backend_id="software.default",
        selected_backend_method="software",
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
        content="123456",
        firewall_result=FirewallResult(sanitized_text="123456", original_hash="0" * 64),
    )

    assert result is None
    assert harness.confirm_calls == []
    assert harness._pending_actions["c-1"].status == "pending"


@pytest.mark.asyncio
async def test_u9_chat_totp_bare_code_requires_confirmation_id_when_multiple_totp_actions_exist(
    tmp_path,
) -> None:
    harness = _ChatConfirmationHarness(tmp_path)
    first = PendingAction(
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
        selected_backend_id="totp.default",
        selected_backend_method="totp",
    )
    second = PendingAction(
        confirmation_id="c-2",
        decision_nonce="nonce-2",
        session_id=SessionId("sess-chat"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws-1"),
        tool_name=ToolName("web.search"),
        arguments={"query": "world"},
        reason="manual",
        capabilities={Capability.HTTP_REQUEST},
        created_at=datetime.now(UTC),
        selected_backend_id="totp.default",
        selected_backend_method="totp",
    )
    harness._pending_actions[first.confirmation_id] = first
    harness._pending_actions[second.confirmation_id] = second

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
        content="123456",
        firewall_result=FirewallResult(sanitized_text="123456", original_hash="0" * 64),
    )

    assert result is not None
    response = str(result["response"]).lower()
    assert "multiple totp confirmations are pending" in response
    assert "confirm confirmation_id 123456" in response
    assert "c-1" in response
    assert "c-2" in response
    assert harness.confirm_calls == []
    assert result["pending_confirmation_ids"] == ["c-1", "c-2"]


@pytest.mark.asyncio
async def test_u9_chat_totp_confirm_id_code_targets_specific_pending_action(tmp_path) -> None:
    harness = _ChatConfirmationHarness(tmp_path)
    first = PendingAction(
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
        selected_backend_id="totp.default",
        selected_backend_method="totp",
    )
    second = PendingAction(
        confirmation_id="c-2",
        decision_nonce="nonce-2",
        session_id=SessionId("sess-chat"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws-1"),
        tool_name=ToolName("web.search"),
        arguments={"query": "world"},
        reason="manual",
        capabilities={Capability.HTTP_REQUEST},
        created_at=datetime.now(UTC),
        selected_backend_id="totp.default",
        selected_backend_method="totp",
    )
    harness._pending_actions[first.confirmation_id] = first
    harness._pending_actions[second.confirmation_id] = second

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
        content="confirm c-2 123456",
        firewall_result=FirewallResult(
            sanitized_text="confirm c-2 123456",
            original_hash="0" * 64,
        ),
    )

    assert result is not None
    response = str(result["response"]).lower()
    assert "confirmed c-2" in response
    assert "6-digit code" in response
    assert result["pending_confirmation_ids"] == ["c-1"]
    assert harness.confirm_calls == [
        {
            "confirmation_id": "c-2",
            "decision_nonce": "nonce-2",
            "approval_method": "totp",
            "proof": {"totp_code": "123456"},
            "reason": "chat_totp_confirmation",
        }
    ]
    assert result["checkpoint_ids"] == []
    assert result["checkpoints_created"] == 0


@pytest.mark.asyncio
async def test_u9_chat_totp_confirm_n_does_not_attempt_proofless_approval(tmp_path) -> None:
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
        selected_backend_id="totp.default",
        selected_backend_method="totp",
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
        content="confirm 1",
        firewall_result=FirewallResult(sanitized_text="confirm 1", original_hash="0" * 64),
    )

    assert result is not None
    response = str(result["response"]).lower()
    assert "6-digit code flow" in response
    assert "missing_totp_code" not in response
    assert harness.confirm_calls == []
    assert result["pending_confirmation_ids"] == ["c-1"]


@pytest.mark.asyncio
@pytest.mark.parametrize("content", ["confirm 1", "yes to all"])
async def test_u9_chat_totp_proofless_recovery_lists_confirmation_ids_for_multi_totp_sessions(
    tmp_path,
    content: str,
) -> None:
    harness = _ChatConfirmationHarness(tmp_path)
    first = PendingAction(
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
        selected_backend_id="totp.default",
        selected_backend_method="totp",
    )
    second = PendingAction(
        confirmation_id="c-2",
        decision_nonce="nonce-2",
        session_id=SessionId("sess-chat"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws-1"),
        tool_name=ToolName("web.search"),
        arguments={"query": "world"},
        reason="manual",
        capabilities={Capability.HTTP_REQUEST},
        created_at=datetime.now(UTC),
        selected_backend_id="totp.default",
        selected_backend_method="totp",
    )
    harness._pending_actions[first.confirmation_id] = first
    harness._pending_actions[second.confirmation_id] = second

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

    assert result is not None
    response = str(result["response"]).lower()
    assert "6-digit code flow" in response
    assert "confirm confirmation_id 123456" in response
    assert "confirmation id: c-1" in response
    assert "confirmation id: c-2" in response
    assert harness.confirm_calls == []
    assert result["pending_confirmation_ids"] == ["c-1", "c-2"]


@pytest.mark.asyncio
async def test_u9_chat_totp_confirm_id_code_rejects_unknown_confirmation_id(tmp_path) -> None:
    harness = _ChatConfirmationHarness(tmp_path)
    first = PendingAction(
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
        selected_backend_id="totp.default",
        selected_backend_method="totp",
    )
    second = PendingAction(
        confirmation_id="c-2",
        decision_nonce="nonce-2",
        session_id=SessionId("sess-chat"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws-1"),
        tool_name=ToolName("web.search"),
        arguments={"query": "world"},
        reason="manual",
        capabilities={Capability.HTTP_REQUEST},
        created_at=datetime.now(UTC),
        selected_backend_id="totp.default",
        selected_backend_method="totp",
    )
    harness._pending_actions[first.confirmation_id] = first
    harness._pending_actions[second.confirmation_id] = second

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
        content="confirm c-9 123456",
        firewall_result=FirewallResult(
            sanitized_text="confirm c-9 123456",
            original_hash="0" * 64,
        ),
    )

    assert result is not None
    response = str(result["response"]).lower()
    assert "totp confirmation id not found for this session" in response
    assert "confirm confirmation_id 123456" in response
    assert "c-1" in response
    assert "c-2" in response
    assert harness.confirm_calls == []
    assert result["pending_confirmation_ids"] == ["c-1", "c-2"]
