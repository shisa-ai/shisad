"""Unit checks for admin handler wrappers."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from shisad.channels.base import direct_replay_identity
from shisad.channels.state import ChannelStateStore, ReplayOutcome
from shisad.core.api.schema import (
    ChannelIngestParams,
    ChannelPairingProposalParams,
    ChannelReplayRebaselineParams,
    DoctorCheckParams,
    LockdownSetParams,
    NoParams,
)
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers.admin import AdminHandlers


class _StubImpl:
    async def do_daemon_status(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"status": "running", "sessions_active": 0}

    async def do_policy_explain(self, payload: dict[str, object]) -> dict[str, object]:
        return {
            "session_id": str(payload.get("session_id", "")),
            "tool_name": "shell_exec",
            "action": str(payload.get("action", "")),
            "effective_policy": {},
            "control_plane": {},
            "contributors": {},
        }

    async def do_daemon_shutdown(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"status": "shutting_down"}

    async def do_doctor_check(self, payload: dict[str, object]) -> dict[str, object]:
        return {
            "status": "ok",
            "component": str(payload.get("component", "all")),
            "checks": {"realitycheck": {"status": "disabled"}},
            "error": "",
        }

    async def do_lockdown_set(self, payload: dict[str, object]) -> dict[str, object]:
        return {"session_id": str(payload["session_id"]), "level": "caution", "reason": "manual"}

    async def do_risk_calibrate(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"version": "v1", "thresholds": {}}

    async def do_channel_ingest(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"session_id": "s1", "response": "ok", "ingress_risk": 0.1}

    async def do_channel_pairing_propose(self, _payload: dict[str, object]) -> dict[str, object]:
        return {
            "proposal_id": "p1",
            "proposal_path": "/tmp/p1.json",
            "generated_at": "2026-02-15T00:00:00+00:00",
            "entries": [],
            "invalid_entries": [],
            "count": 0,
            "config_patch": {},
            "applied": False,
        }


@pytest.mark.asyncio
async def test_admin_status_and_lockdown_wrappers() -> None:
    handlers = AdminHandlers(_StubImpl(), internal_ingress_marker=object())  # type: ignore[arg-type]
    status = await handlers.handle_daemon_status(NoParams(), RequestContext())
    doctor = await handlers.handle_doctor_check(
        DoctorCheckParams(component="realitycheck"),
        RequestContext(),
    )
    lockdown = await handlers.handle_lockdown_set(
        LockdownSetParams(session_id="s1"),
        RequestContext(),
    )
    assert status.status == "running"
    assert doctor.component == "realitycheck"
    assert lockdown.session_id == "s1"


@pytest.mark.asyncio
async def test_channel_ingest_wrapper(tmp_path) -> None:
    impl = _StubImpl()
    impl._services = SimpleNamespace(channel_state_store=ChannelStateStore(tmp_path / "state"))
    handlers = AdminHandlers(impl, internal_ingress_marker=object())  # type: ignore[arg-type]
    result = await handlers.handle_channel_ingest(
        ChannelIngestParams(
            message={
                "channel": "cli",
                "external_user_id": "alice",
                "workspace_hint": "w1",
                "content": "hi",
                "message_id": "direct-wrapper-1",
            }
        ),
        RequestContext(),
    )
    assert result.ingress_risk == 0.1


@pytest.mark.asyncio
async def test_direct_channel_ingest_replay_scope_is_server_derived(tmp_path) -> None:
    impl = _StubImpl()
    store = ChannelStateStore(tmp_path / "state")
    impl._services = SimpleNamespace(channel_state_store=store)
    handlers = AdminHandlers(impl, internal_ingress_marker=object())  # type: ignore[arg-type]
    first = ChannelIngestParams(
        message={
            "channel": "discord",
            "external_user_id": "alice",
            "workspace_hint": "claimed-guild-1",
            "content": "hi",
            "message_id": "direct-1",
            "reply_target": "claimed-channel-1",
            "metadata": {"discord_guild_id": "forged-guild"},
        }
    )
    peer = RequestContext(rpc_peer={"pid": 10, "uid": 1000, "gid": 1000})

    result = await handlers.handle_channel_ingest(first, peer)
    assert result.ingress_risk == 0.1
    identity = direct_replay_identity(message_id="direct-1", rpc_peer=peer.rpc_peer)
    assert store.outcome(identity=identity) == ReplayOutcome.TERMINAL

    forged_scope = first.model_copy(
        update={
            "message": first.message.model_copy(
                update={
                    "channel": "telegram",
                    "workspace_hint": "different",
                    "reply_target": "different",
                    "metadata": {"provider": "telegram", "account_id": "forged"},
                }
            )
        }
    )
    with pytest.raises(Exception, match="replay"):
        await handlers.handle_channel_ingest(forged_scope, peer)

    other_peer = RequestContext(rpc_peer={"pid": 20, "uid": 1001, "gid": 1001})
    assert (await handlers.handle_channel_ingest(first, other_peer)).ingress_risk == 0.1


@pytest.mark.asyncio
async def test_channel_pairing_proposal_wrapper() -> None:
    handlers = AdminHandlers(_StubImpl(), internal_ingress_marker=object())  # type: ignore[arg-type]
    result = await handlers.handle_channel_pairing_propose(
        ChannelPairingProposalParams(limit=5),
        RequestContext(),
    )
    assert result.proposal_id == "p1"


@pytest.mark.asyncio
async def test_channel_replay_rebaseline_requires_confirmation_and_is_scope_local(
    tmp_path,
) -> None:
    impl = _StubImpl()
    state_root = tmp_path / "state"
    state_root.mkdir()
    (state_root / "discord.state.json").write_text(
        json.dumps({"channel": "discord", "seen_message_ids": ["m-1"]}),
        encoding="utf-8",
    )
    store = ChannelStateStore(state_root)
    impl._services = SimpleNamespace(channel_state_store=store)
    handlers = AdminHandlers(impl, internal_ingress_marker=object())  # type: ignore[arg-type]
    store.mark_seen(channel="discord", message_id="m-1")
    store.mark_seen(channel="matrix", message_id="m-2")

    with pytest.raises(ValueError, match="confirm"):
        await handlers.handle_channel_replay_rebaseline(
            ChannelReplayRebaselineParams(channel="discord"),
            RequestContext(),
        )
    result = await handlers.handle_channel_replay_rebaseline(
        ChannelReplayRebaselineParams(channel="discord", confirm=True),
        RequestContext(),
    )

    assert result.status == "rebaselined"
    assert result.channel == "discord"
    assert result.files_removed >= 1
    assert store.has_seen(channel="discord", message_id="m-1") is False
    assert store.has_seen(channel="matrix", message_id="m-2") is True
    with pytest.raises(ValueError, match="ambiguous legacy"):
        await handlers.handle_channel_replay_rebaseline(
            ChannelReplayRebaselineParams(channel="matrix", confirm=True),
            RequestContext(),
        )
