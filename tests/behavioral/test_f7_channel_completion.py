"""F7C chosen-channel confirmation completion journeys."""

from __future__ import annotations

import os
import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from shisad.channels.base import InMemoryChannel
from shisad.channels.delivery import ChannelDeliveryService
from shisad.core.api.schema import (
    ActionPendingParams,
    AuditQueryParams,
    ChannelIngestParams,
    TwoFactorRegisterBeginParams,
    TwoFactorRegisterConfirmParams,
)
from shisad.core.approval import generate_totp_code
from shisad.core.config import DaemonConfig
from shisad.core.planner import (
    ActionProposal,
    EvaluatedProposal,
    Planner,
    PlannerOutput,
    PlannerResult,
)
from shisad.core.request_context import RequestContext
from shisad.core.types import ToolName
from shisad.daemon.control_handlers import DaemonControlHandlers
from shisad.daemon.services import DaemonServices

_CHANNELS = ("discord", "slack", "telegram", "matrix")
_REPO_ROOT = Path(__file__).resolve().parents[2]
_README_PATH = _REPO_ROOT / "README.md"


def _authenticated_local_context() -> RequestContext:
    return RequestContext(rpc_peer={"uid": os.getuid(), "gid": os.getgid(), "pid": os.getpid()})


def _channel_user(channel: str) -> str:
    return f"alice-{channel}"


def _channel_workspace(channel: str) -> str:
    return f"workspace-{channel}"


def _channel_target(channel: str) -> str:
    return f"target-{channel}"


def _completion_policy() -> str:
    return (
        textwrap.dedent(
            """
            version: "1"
            default_require_confirmation: false
            default_capabilities:
              - file.read
            tools:
              fs.read:
                capabilities_required:
                  - file.read
                confirmation:
                  level: software
                  methods:
                    - software
              fs.list:
                capabilities_required:
                  - file.read
                confirmation:
                  level: reauthenticated
                  methods:
                    - totp
            """
        ).strip()
        + "\n"
    )


def _configure_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> DaemonConfig:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_completion_policy(), encoding="utf-8")
    return DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        assistant_fs_roots=[_REPO_ROOT],
        log_level="INFO",
    )


def _install_confirmation_planner(monkeypatch: pytest.MonkeyPatch) -> None:
    call_count = 0

    async def _planner(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        nonlocal call_count
        _ = (tools, persona_tone_override)
        call_count += 1
        totp = "queue totp" in user_content.casefold()
        tool_name = ToolName("fs.list" if totp else "fs.read")
        arguments = {"path": str(_REPO_ROOT if totp else _README_PATH)}
        proposal = ActionProposal(
            action_id=f"f7c-channel-{call_count}",
            tool_name=tool_name,
            arguments=arguments,
            reasoning="exercise the real chosen-channel confirmation path",
            data_sources=[],
        )
        decision = self._pep.evaluate(proposal.tool_name, proposal.arguments, context)
        return PlannerResult(
            output=PlannerOutput(
                assistant_response="pending chosen-channel approval",
                actions=[proposal],
            ),
            evaluated=[EvaluatedProposal(proposal=proposal, decision=decision)],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _planner)


async def _attach_memory_channels(
    services: DaemonServices,
) -> dict[str, InMemoryChannel]:
    services.delivery.close()
    channels = {name: InMemoryChannel(name) for name in _CHANNELS}
    for channel in channels.values():
        await channel.connect()
    services.channels.clear()
    services.channels.update(channels)
    services.delivery = ChannelDeliveryService(
        channels,
        state_root=services.config.data_dir / "channels" / "delivery",
        transcript_store=services.transcript_store,
    )
    services.control_handlers._impl._delivery = services.delivery
    return channels


def _trust_channel_identities(services: DaemonServices, *, include_attackers: bool = False) -> None:
    for channel in _CHANNELS:
        services.identity_map.configure_channel_trust(channel=channel, trust_level="trusted")
        services.identity_map.allow_identity(
            channel=channel,
            external_user_id=_channel_user(channel),
        )
        if include_attackers:
            services.identity_map.allow_identity(
                channel=channel,
                external_user_id=f"mallory-{channel}",
            )


async def _ingest(
    handlers: DaemonControlHandlers,
    ctx: RequestContext,
    *,
    channel: str,
    content: str,
    message_id: str,
    recipient: str | None = None,
    external_user_id: str | None = None,
) -> Any:
    return await handlers.handle_channel_ingest(
        ChannelIngestParams(
            message={
                "channel": channel,
                "external_user_id": external_user_id or _channel_user(channel),
                "workspace_hint": _channel_workspace(channel),
                "content": content,
                "message_id": message_id,
                "reply_target": recipient or _channel_target(channel),
            }
        ),
        ctx,
    )


async def _assert_durable_delivery(
    services: DaemonServices,
    channels: dict[str, InMemoryChannel],
    response: Any,
    *,
    channel: str,
    recipient: str | None = None,
) -> str:
    expected_recipient = recipient or _channel_target(channel)
    delivery = dict(response.delivery)
    assert delivery["attempted"] is True
    assert delivery["sent"] is True
    assert delivery["state"] == "delivered"
    assert delivery["target"]["channel"] == channel
    assert delivery["target"]["recipient"] == expected_recipient
    reservation_id = str(delivery["reservation_id"])
    record = services.delivery.record(reservation_id)
    assert record is not None
    assert record.state == "delivered"
    assert record.intent.kind == "channel_result"
    assert record.intent.target.channel == channel
    assert record.intent.target.recipient == expected_recipient
    assert record.receipt is not None
    assert record.receipt.delivery_id == record.delivery_id
    envelope = await channels[channel].pop_outgoing_delivery()
    assert envelope.target.channel == channel
    assert envelope.target.recipient == expected_recipient
    assert envelope.content == response.response
    return reservation_id


@pytest.mark.asyncio
async def test_f7c_supported_channel_approval_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every chosen channel uses canonical execution and durable result delivery."""

    config = _configure_runtime(tmp_path, monkeypatch)
    _install_confirmation_planner(monkeypatch)
    services = await DaemonServices.build(config)
    try:
        channels = await _attach_memory_channels(services)
        _trust_channel_identities(services)
        handlers = DaemonControlHandlers(services=services)
        ctx = _authenticated_local_context()

        for channel in _CHANNELS:
            user_id = _channel_user(channel)
            started = await handlers.handle_two_factor_register_begin(
                TwoFactorRegisterBeginParams(
                    method="totp",
                    user_id=user_id,
                    name=f"{channel}-operator",
                ),
                ctx,
            )
            enrolled = await handlers.handle_two_factor_register_confirm(
                TwoFactorRegisterConfirmParams(
                    enrollment_id=started.enrollment_id,
                    verify_code=generate_totp_code(str(started.secret)),
                ),
                ctx,
            )
            assert enrolled.registered is True

            software = await _ingest(
                handlers,
                ctx,
                channel=channel,
                content=f"queue software approval on {channel}",
                message_id=f"{channel}-software-queue",
            )
            assert software.confirmation_required_actions == 1
            software_id = str(software.pending_confirmation_ids[0])
            software_text = str(software.response)
            assert "Read file:" in software_text
            assert "reject" in software_text.casefold()
            await _assert_durable_delivery(
                services,
                channels,
                software,
                channel=channel,
            )

            confirmed = await _ingest(
                handlers,
                ctx,
                channel=channel,
                content=f"confirm {software_id}",
                message_id=f"{channel}-software-confirm",
            )
            assert confirmed.executed_actions == 1
            assert confirmed.confirmation_required_actions == 0
            assert any(
                str(output.get("tool_name", "")) == "fs.read" and bool(output.get("success", False))
                for output in confirmed.tool_outputs
            )
            await _assert_durable_delivery(
                services,
                channels,
                confirmed,
                channel=channel,
            )
            software_terminal = await handlers.handle_action_pending(
                ActionPendingParams(confirmation_id=software_id),
                ctx,
            )
            assert software_terminal.actions[0].lifecycle_state == "executed"

            totp = await _ingest(
                handlers,
                ctx,
                channel=channel,
                content=f"queue totp approval on {channel}",
                message_id=f"{channel}-totp-queue",
            )
            assert totp.confirmation_required_actions == 1
            totp_id = str(totp.pending_confirmation_ids[0])
            assert "6-digit" in str(totp.response)
            await _assert_durable_delivery(
                services,
                channels,
                totp,
                channel=channel,
            )

            totp_confirmed = await _ingest(
                handlers,
                ctx,
                channel=channel,
                content=f"confirm {totp_id} {generate_totp_code(str(started.secret))}",
                message_id=f"{channel}-totp-confirm",
            )
            assert totp_confirmed.executed_actions == 1
            assert any(
                str(output.get("tool_name", "")) == "fs.list" and bool(output.get("success", False))
                for output in totp_confirmed.tool_outputs
            )
            await _assert_durable_delivery(
                services,
                channels,
                totp_confirmed,
                channel=channel,
            )

            rejection = await _ingest(
                handlers,
                ctx,
                channel=channel,
                content=f"queue rejected approval on {channel}",
                message_id=f"{channel}-reject-queue",
            )
            rejection_id = str(rejection.pending_confirmation_ids[0])
            await _assert_durable_delivery(
                services,
                channels,
                rejection,
                channel=channel,
            )
            rejected = await _ingest(
                handlers,
                ctx,
                channel=channel,
                content=f"reject {rejection_id}",
                message_id=f"{channel}-reject",
            )
            assert rejected.executed_actions == 0
            assert rejected.blocked_actions >= 1
            await _assert_durable_delivery(
                services,
                channels,
                rejected,
                channel=channel,
            )
            rejection_terminal = await handlers.handle_action_pending(
                ActionPendingParams(confirmation_id=rejection_id),
                ctx,
            )
            assert rejection_terminal.actions[0].lifecycle_state == "rejected"
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_f7c_supported_channel_restart_and_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real persisted actions and F7B deliveries remain exact across restart."""

    config = _configure_runtime(tmp_path, monkeypatch)
    _install_confirmation_planner(monkeypatch)
    ctx = _authenticated_local_context()
    live_by_channel: dict[str, dict[str, str]] = {}
    expired_by_channel: dict[str, str] = {}

    first = await DaemonServices.build(config)
    try:
        first_channels = await _attach_memory_channels(first)
        _trust_channel_identities(first)
        first_handlers = DaemonControlHandlers(services=first)
        for channel in _CHANNELS:
            live = await _ingest(
                first_handlers,
                ctx,
                channel=channel,
                content=f"queue software restart approval on {channel}",
                message_id=f"{channel}-restart-live-queue",
            )
            live_id = str(live.pending_confirmation_ids[0])
            await _assert_durable_delivery(
                first,
                first_channels,
                live,
                channel=channel,
            )
            live_row = (
                await first_handlers.handle_action_pending(
                    ActionPendingParams(confirmation_id=live_id),
                    ctx,
                )
            ).actions[0]
            live_by_channel[channel] = {
                "confirmation_id": live_id,
                "decision_nonce": live_row.decision_nonce,
                "action_id": live_row.action_id,
                "result_id": live_row.result_id,
                "session_id": live_row.session_id,
            }

            expiring = await _ingest(
                first_handlers,
                ctx,
                channel=channel,
                content=f"queue software expiring approval on {channel}",
                message_id=f"{channel}-restart-expiring-queue",
            )
            expiring_ids = {
                str(item) for item in expiring.pending_confirmation_ids if str(item) != live_id
            }
            assert len(expiring_ids) == 1
            expired_by_channel[channel] = expiring_ids.pop()
            await _assert_durable_delivery(
                first,
                first_channels,
                expiring,
                channel=channel,
            )
    finally:
        await first.shutdown()

    result_deliveries: dict[str, str] = {}
    restarted = await DaemonServices.build(config)
    try:
        restarted_channels = await _attach_memory_channels(restarted)
        _trust_channel_identities(restarted, include_attackers=True)
        restarted_handlers = DaemonControlHandlers(services=restarted)

        for channel in _CHANNELS:
            expected = live_by_channel[channel]
            confirmation_id = expected["confirmation_id"]
            loaded = (
                await restarted_handlers.handle_action_pending(
                    ActionPendingParams(confirmation_id=confirmation_id),
                    ctx,
                )
            ).actions[0]
            assert loaded.lifecycle_state == "pending"
            assert loaded.decision_nonce == expected["decision_nonce"]
            assert loaded.action_id == expected["action_id"]
            assert loaded.result_id == expected["result_id"]
            assert loaded.session_id == expected["session_id"]
            assert loaded.user_id == _channel_user(channel)
            assert loaded.workspace_id == _channel_workspace(channel)
            assert loaded.origin_channel == channel
            assert loaded.delivery_target == {
                "channel": channel,
                "recipient": _channel_target(channel),
                "thread_id": "",
                "workspace_hint": _channel_workspace(channel),
            }

            cross_principal = await _ingest(
                restarted_handlers,
                ctx,
                channel=channel,
                content=f"confirm {confirmation_id}",
                message_id=f"{channel}-restart-cross-principal",
                external_user_id=f"mallory-{channel}",
            )
            assert cross_principal.executed_actions == 0
            await _assert_durable_delivery(
                restarted,
                restarted_channels,
                cross_principal,
                channel=channel,
            )

            wrong_recipient = f"other-{channel}"
            wrong_target = await _ingest(
                restarted_handlers,
                ctx,
                channel=channel,
                content=f"approve {confirmation_id}",
                message_id=f"{channel}-restart-wrong-target",
                recipient=wrong_recipient,
            )
            assert wrong_target.executed_actions == 0
            await _assert_durable_delivery(
                restarted,
                restarted_channels,
                wrong_target,
                channel=channel,
                recipient=wrong_recipient,
            )
            still_pending = await restarted_handlers.handle_action_pending(
                ActionPendingParams(confirmation_id=confirmation_id),
                ctx,
            )
            assert still_pending.actions[0].lifecycle_state == "pending"

            accepted = await _ingest(
                restarted_handlers,
                ctx,
                channel=channel,
                content=f"confirm {confirmation_id} please",
                message_id=f"{channel}-restart-confirm",
            )
            assert accepted.executed_actions == 1
            result_id = str(accepted.action_followup_identity["result_id"])
            assert result_id
            expected["result_id"] = result_id
            result_deliveries[channel] = await _assert_durable_delivery(
                restarted,
                restarted_channels,
                accepted,
                channel=channel,
            )

            duplicate = await _ingest(
                restarted_handlers,
                ctx,
                channel=channel,
                content=f"confirm {confirmation_id} please",
                message_id=f"{channel}-restart-duplicate",
            )
            assert duplicate.executed_actions == 0
            assert duplicate.delivery["reason"] == "inbound_replay_blocked"
            terminal = await restarted_handlers.handle_action_pending(
                ActionPendingParams(confirmation_id=confirmation_id),
                ctx,
            )
            assert terminal.actions[0].lifecycle_state == "executed"
            assert terminal.actions[0].result_id == expected["result_id"]

            expired_id = expired_by_channel[channel]
            expired_pending = restarted_handlers._impl._pending_actions[expired_id]
            expired_pending.expires_at = datetime.now(UTC) - timedelta(seconds=1)
            expired = await _ingest(
                restarted_handlers,
                ctx,
                channel=channel,
                content=f"confirm {expired_id}",
                message_id=f"{channel}-restart-expired",
            )
            assert expired.executed_actions == 0
            await _assert_durable_delivery(
                restarted,
                restarted_channels,
                expired,
                channel=channel,
            )
            expired_row = await restarted_handlers.handle_action_pending(
                ActionPendingParams(confirmation_id=expired_id),
                ctx,
            )
            assert expired_row.actions[0].lifecycle_state == "expired"

            executed_events = await restarted_handlers.handle_audit_query(
                AuditQueryParams(
                    event_type="ToolExecuted",
                    session_id=expected["session_id"],
                    limit=100,
                ),
                ctx,
            )
            matching_results = [
                event
                for event in executed_events.events
                if str(event.get("data", {}).get("result_id", "")) == expected["result_id"]
            ]
            assert len(matching_results) == 1
    finally:
        await restarted.shutdown()

    final = await DaemonServices.build(config)
    try:
        final_channels = await _attach_memory_channels(final)
        _trust_channel_identities(final)
        final_handlers = DaemonControlHandlers(services=final)
        for channel in _CHANNELS:
            expected = live_by_channel[channel]
            terminal = await final_handlers.handle_action_pending(
                ActionPendingParams(confirmation_id=expected["confirmation_id"]),
                ctx,
            )
            assert terminal.actions[0].lifecycle_state == "executed"
            assert terminal.actions[0].result_id == expected["result_id"]
            expired = await final_handlers.handle_action_pending(
                ActionPendingParams(confirmation_id=expired_by_channel[channel]),
                ctx,
            )
            assert expired.actions[0].lifecycle_state == "expired"
            result_record = final.delivery.record(result_deliveries[channel])
            assert result_record is not None
            assert result_record.state == "delivered"
            assert result_record.intent.target.channel == channel
            assert result_record.receipt is not None

        assert await final.delivery.recover() == []
        assert all(channel.pending_outgoing() == 0 for channel in final_channels.values())
    finally:
        await final.shutdown()
