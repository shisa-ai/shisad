"""F7C chosen-channel confirmation completion journeys."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from shisad.channels.base import DeliveryTarget
from shisad.core.approval import ConfirmationLevel
from shisad.core.transcript import TranscriptStore
from shisad.core.types import Capability, SessionId, SessionMode, ToolName, UserId, WorkspaceId
from shisad.daemon.handlers._impl import HandlerImplementation, PendingAction
from shisad.daemon.handlers._impl_session import (
    SessionImplMixin,
    _daemon_pending_confirmation_response_text,
)
from shisad.daemon.handlers._pending_approval import pending_action_state_view
from shisad.security.control_plane.sidecar import ControlPlaneUnavailableError
from shisad.security.firewall import FirewallResult
from shisad.security.firewall.output import OutputFirewallResult

_CHANNELS = ("discord", "slack", "telegram", "matrix")


class _BehavioralConfirmationHarness(SessionImplMixin):
    def __init__(self, transcript_root) -> None:
        self._pending_actions: dict[str, PendingAction] = {}
        self.confirm_calls: list[dict[str, object]] = []
        self.reject_calls: list[dict[str, object]] = []
        self._output_firewall = SimpleNamespace(inspect=self._inspect_output)
        self._lockdown_manager = SimpleNamespace(
            user_notification=lambda _sid: "",
            state_for=lambda _sid: SimpleNamespace(level=SimpleNamespace(value="none")),
        )
        self._transcript_root = transcript_root
        self._transcript_store = TranscriptStore(transcript_root)
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
        if not pending_action_state_view(pending).is_live_pending:
            pending.status = "failed"
            pending.status_reason = "approval_expired"
            return {
                "confirmed": False,
                "status": "failed",
                "status_reason": "approval_expired",
                "reason": "approval_expired",
            }
        pending.status = "approved"
        pending.status_reason = "chat_confirmation"
        return {
            "confirmed": True,
            "status": "approved",
            "tool_outputs": [
                {
                    "tool_name": str(pending.tool_name),
                    "success": True,
                    "payload": {"ok": True, "path": "README.md"},
                    "taint_labels": [],
                }
            ],
        }

    async def do_action_reject(self, params: dict[str, object]) -> dict[str, object]:
        self.reject_calls.append(dict(params))
        pending = self._pending_actions[str(params["confirmation_id"])]
        pending.status = "rejected"
        pending.status_reason = "chat_confirmation"
        return {"rejected": True, "status": "rejected"}


def _pending(
    *,
    channel: str,
    suffix: str,
    method: str = "software",
    expires_at: datetime | None = None,
) -> PendingAction:
    required_level = (
        ConfirmationLevel.REAUTHENTICATED if method == "totp" else ConfirmationLevel.SOFTWARE
    )
    pending = PendingAction(
        confirmation_id=f"c-{channel}-{suffix}",
        decision_nonce=f"nonce-{channel}-{suffix}",
        session_id=SessionId(f"session-{channel}"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("workspace-1"),
        tool_name=ToolName("fs.read"),
        arguments={"path": "README.md"},
        reason="requires_confirmation",
        capabilities={Capability.FILE_READ},
        created_at=datetime.now(UTC),
        expires_at=expires_at,
        safe_preview=(
            "ACTION CONFIRMATION\n"
            "Review: Read file: README.md\n"
            "Action: fs.read\n"
            "Risk Level: MEDIUM\n"
            "PARAMETERS:\n"
            "  path: README.md"
        ),
        delivery_target=DeliveryTarget(
            channel=channel,
            recipient=f"target-{channel}",
            workspace_hint=f"provider-workspace-{channel}",
        ),
        required_level=required_level,
        selected_backend_id=f"{method}.default",
        selected_backend_method=method,
        allowed_channel_principals=["alice"],
    )
    return pending


async def _submit(
    harness: _BehavioralConfirmationHarness,
    pending: PendingAction,
    *,
    content: str,
    principal: str = "alice",
    target: DeliveryTarget | None = None,
) -> dict[str, object] | None:
    return await SessionImplMixin._maybe_handle_chat_confirmation(
        harness,
        sid=pending.session_id,
        channel=str(pending.delivery_target.channel),
        user_id=pending.user_id,
        workspace_id=pending.workspace_id,
        session_mode=SessionMode.DEFAULT,
        trust_level="trusted",
        trusted_input=True,
        is_internal_ingress=True,
        delivery_target=target or pending.delivery_target,
        content=content,
        firewall_result=FirewallResult(sanitized_text=content, original_hash="0" * 64),
        channel_metadata={"channel_principal_id": principal},
    )


@pytest.mark.asyncio
async def test_f7c_supported_channel_approval_completion(tmp_path) -> None:
    """Every supported chosen channel can display, approve, TOTP, and reject."""

    for channel in _CHANNELS:
        harness = _BehavioralConfirmationHarness(tmp_path / channel)
        software = _pending(channel=channel, suffix="software")
        harness._pending_actions[software.confirmation_id] = software
        public = HandlerImplementation._pending_to_dict(
            software,
            public=True,
            selected_backend_available=True,
        )
        capability = public["channel_capability"]
        assert capability["surface"] == channel
        assert capability["carried_methods"] == ["software", "totp"]
        card = _daemon_pending_confirmation_response_text(
            pending_confirmation_ids=[software.confirmation_id],
            pending_actions={software.confirmation_id: software},
            pending_index_by_id={software.confirmation_id: 1},
            pending_public_preview_by_id={software.confirmation_id: software.safe_preview},
            binding_pending_rows=[software],
            allow_chat_approval=False,
            delivery_channel=channel,
            pending_channel_capability_by_id={software.confirmation_id: capability},
        )
        assert "Read file: README.md" in card
        assert "reject" in card.casefold()

        result = await _submit(
            harness,
            software,
            content=f"confirm {software.confirmation_id}",
        )
        assert result is not None
        assert software.status == "approved"
        assert harness.confirm_calls[-1]["decision_nonce"] == software.decision_nonce

        totp = _pending(channel=channel, suffix="totp", method="totp")
        harness._pending_actions[totp.confirmation_id] = totp
        result = await _submit(
            harness,
            totp,
            content=f"confirm {totp.confirmation_id} 123456",
        )
        assert result is not None
        assert totp.status == "approved"
        assert harness.confirm_calls[-1]["proof"] == {"totp_code": "123456"}

        rejected = _pending(channel=channel, suffix="reject")
        harness._pending_actions[rejected.confirmation_id] = rejected
        result = await _submit(
            harness,
            rejected,
            content=f"reject {rejected.confirmation_id}",
        )
        assert result is not None
        assert rejected.status == "rejected"
        assert harness.reject_calls[-1]["decision_nonce"] == rejected.decision_nonce


@pytest.mark.asyncio
async def test_f7c_supported_channel_restart_and_binding(tmp_path) -> None:
    """Persisted identity survives restart-shaped reload while bindings stay exact."""

    for channel in _CHANNELS:
        original = _pending(
            channel=channel,
            suffix="restart",
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )
        durable = HandlerImplementation._pending_to_dict(original)
        restarted = deepcopy(original)
        assert restarted.confirmation_id == durable["confirmation_id"]
        assert restarted.decision_nonce == durable["decision_nonce"]
        assert restarted.expires_at is not None
        assert restarted.expires_at.isoformat() == durable["expires_at"]
        assert restarted.delivery_target is not None
        assert restarted.delivery_target.model_dump(mode="json") == durable["delivery_target"]

        harness = _BehavioralConfirmationHarness(tmp_path / f"{channel}-restart")
        harness._pending_actions[restarted.confirmation_id] = restarted
        wrong_target = restarted.delivery_target.model_copy(update={"recipient": "other-target"})
        denied = await _submit(
            harness,
            restarted,
            content=f"confirm {restarted.confirmation_id}",
            target=wrong_target,
        )
        assert denied is not None
        assert restarted.status == "pending"
        assert harness.confirm_calls == []

        accepted = await _submit(
            harness,
            restarted,
            content=f"confirm {restarted.confirmation_id}",
        )
        assert accepted is not None
        assert restarted.status == "approved"
        assert len(harness.confirm_calls) == 1

        expired = _pending(
            channel=channel,
            suffix="expired",
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
        harness._pending_actions[expired.confirmation_id] = expired
        denied = await _submit(
            harness,
            expired,
            content=f"confirm {expired.confirmation_id}",
        )
        assert denied is not None
        assert expired.status == "failed"
        assert expired.status_reason == "approval_expired"
        assert (
            sum(
                call["confirmation_id"] == expired.confirmation_id for call in harness.confirm_calls
            )
            == 1
        )
