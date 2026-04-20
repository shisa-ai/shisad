"""Focused channel receive-pump integration coverage."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from shisad.channels.base import InMemoryChannel
from shisad.channels.discord import DiscordChannel
from shisad.channels.discord_policy import DiscordChannelRule
from shisad.channels.matrix import MatrixChannel
from shisad.channels.slack import SlackChannel
from shisad.channels.telegram import TelegramChannel
from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.core.planner import (
    ActionProposal,
    EvaluatedProposal,
    Planner,
    PlannerOutput,
    PlannerResult,
)
from shisad.core.types import PEPDecisionKind, ToolName
from shisad.daemon.runner import run_daemon
from tests.helpers.daemon import wait_for_socket as _wait_for_socket


@pytest.fixture
def model_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")


@dataclass(frozen=True)
class _PumpCase:
    channel_name: str
    channel_cls: type[Any]
    config_overrides: dict[str, object]
    workspace_hint: str
    allowed_user: str
    blocked_user: str


_CASES: tuple[_PumpCase, ...] = (
    _PumpCase(
        channel_name="matrix",
        channel_cls=MatrixChannel,
        config_overrides={
            "matrix_enabled": True,
            "matrix_homeserver": "https://matrix.example.org",
            "matrix_user_id": "@bot:example.org",
            "matrix_access_token": "token",
            "matrix_room_id": "!room:example.org",
        },
        workspace_hint="!room:example.org",
        allowed_user="@alice:example.org",
        blocked_user="@mallory:example.org",
    ),
    _PumpCase(
        channel_name="discord",
        channel_cls=DiscordChannel,
        config_overrides={
            "discord_enabled": True,
            "discord_bot_token": "token",
        },
        workspace_hint="guild-1",
        allowed_user="discord-allow",
        blocked_user="discord-blocked",
    ),
    _PumpCase(
        channel_name="telegram",
        channel_cls=TelegramChannel,
        config_overrides={
            "telegram_enabled": True,
            "telegram_bot_token": "token",
        },
        workspace_hint="chat-1",
        allowed_user="telegram-allow",
        blocked_user="telegram-blocked",
    ),
    _PumpCase(
        channel_name="slack",
        channel_cls=SlackChannel,
        config_overrides={
            "slack_enabled": True,
            "slack_bot_token": "xoxb-token",
            "slack_app_token": "xapp-token",
        },
        workspace_hint="team-1",
        allowed_user="slack-allow",
        blocked_user="slack-blocked",
    ),
)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", _CASES, ids=[item.channel_name for item in _CASES])
async def test_m3_channel_pump_enforces_allowlist_routes_session_and_emits_audit(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: _PumpCase,
) -> None:
    async def _fake_connect(self: InMemoryChannel) -> None:
        await InMemoryChannel.connect(self)
        await self.inject(case.blocked_user, "blocked inbound message", case.workspace_hint)
        await self.inject(case.allowed_user, "allowed inbound message", case.workspace_hint)

    monkeypatch.setattr(case.channel_cls, "connect", _fake_connect)

    config_kwargs: dict[str, object] = {
        "data_dir": tmp_path / "data",
        "socket_path": tmp_path / "control.sock",
        "policy_path": tmp_path / "policy.yaml",
        "log_level": "INFO",
        "channel_identity_allowlist": {case.channel_name: [case.allowed_user]},
    }
    config_kwargs.update(case.config_overrides)
    config = DaemonConfig(**config_kwargs)

    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()

        allowed_sessions: list[dict[str, Any]] = []
        blocked_sessions: list[dict[str, Any]] = []
        pairing_matches: list[dict[str, Any]] = []
        delivery_matches: list[dict[str, Any]] = []
        received_total = 0
        for _ in range(80):
            sessions = await client.call("session.list")
            session_rows = sessions.get("sessions", [])
            if isinstance(session_rows, list):
                allowed_sessions = [
                    item
                    for item in session_rows
                    if isinstance(item, dict)
                    and item.get("channel") == case.channel_name
                    and item.get("user_id") == case.allowed_user
                ]
                blocked_sessions = [
                    item
                    for item in session_rows
                    if isinstance(item, dict)
                    and item.get("channel") == case.channel_name
                    and item.get("user_id") == case.blocked_user
                ]

            received = await client.call(
                "audit.query",
                {
                    "event_type": "SessionMessageReceived",
                    "actor": case.allowed_user,
                    "limit": 20,
                },
            )
            received_total = int(received.get("total", 0))

            pairing = await client.call(
                "audit.query",
                {
                    "event_type": "ChannelPairingRequested",
                    "actor": "channel_ingest",
                    "limit": 20,
                },
            )
            pairing_rows = pairing.get("events", [])
            if isinstance(pairing_rows, list):
                pairing_matches = [
                    item.get("data", {})
                    for item in pairing_rows
                    if isinstance(item, dict)
                    and isinstance(item.get("data"), dict)
                    and item["data"].get("channel") == case.channel_name
                    and item["data"].get("external_user_id") == case.blocked_user
                ]

            delivery = await client.call(
                "audit.query",
                {
                    "event_type": "ChannelDeliveryAttempted",
                    "actor": "channel_delivery",
                    "limit": 20,
                },
            )
            delivery_rows = delivery.get("events", [])
            if isinstance(delivery_rows, list):
                delivery_matches = [
                    item.get("data", {})
                    for item in delivery_rows
                    if isinstance(item, dict)
                    and isinstance(item.get("data"), dict)
                    and item["data"].get("channel") == case.channel_name
                ]

            if (
                len(allowed_sessions) == 1
                and not blocked_sessions
                and received_total >= 1
                and pairing_matches
                and delivery_matches
            ):
                break
            await asyncio.sleep(0.05)

        assert len(allowed_sessions) == 1
        assert blocked_sessions == []
        assert received_total >= 1
        assert pairing_matches
        assert delivery_matches
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_m75_discord_public_channel_policy_allows_guest_without_pairing(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fake_connect(self: InMemoryChannel) -> None:
        await InMemoryChannel.connect(self)

    monkeypatch.setattr(DiscordChannel, "connect", _fake_connect)

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        log_level="INFO",
        discord_enabled=True,
        discord_bot_token="token",
        discord_channel_rules=[
            DiscordChannelRule(
                guild_id="guild-1",
                channels=["public"],
                mode="mention-only",
                public_enabled=True,
                public_tools=["web.search"],
            )
        ],
    )
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        result = await client.call(
            "channel.ingest",
            {
                "message": {
                    "channel": "discord",
                    "external_user_id": "visitor",
                    "workspace_hint": "guild-1",
                    "content": "hello from the public channel",
                    "message_id": "m75-public-1",
                    "reply_target": "public",
                }
            },
        )

        assert "not allowlisted" not in result["response"]
        assert result["trust_level"] == "public"
        assert result["channel_policy"]["trust_level"] == "public"
        assert result["channel_policy"]["allowed_tools"] == ["web.search"]
        assert result["channel_policy"]["ephemeral_session"] is True

        pairing = await client.call(
            "audit.query",
            {
                "event_type": "ChannelPairingRequested",
                "actor": "channel_ingest",
                "limit": 20,
            },
        )
        assert int(pairing.get("total", 0)) == 0

        sessions = await client.call("session.list")
        assert all(
            not (
                isinstance(item, dict)
                and item.get("channel") == "discord"
                and item.get("user_id") == "visitor"
            )
            for item in sessions.get("sessions", [])
        )
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_m75_discord_public_channel_policy_does_not_grant_dm_wildcard(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fake_connect(self: InMemoryChannel) -> None:
        await InMemoryChannel.connect(self)

    monkeypatch.setattr(DiscordChannel, "connect", _fake_connect)

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        log_level="INFO",
        discord_enabled=True,
        discord_bot_token="token",
        discord_channel_rules=[
            DiscordChannelRule(
                guild_id="*",
                mode="mention-only",
                public_enabled=True,
                public_tools=[],
            )
        ],
    )
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        result = await client.call(
            "channel.ingest",
            {
                "message": {
                    "channel": "discord",
                    "external_user_id": "dm-visitor",
                    "workspace_hint": "discord",
                    "content": "hello from a DM",
                    "message_id": "m75-public-dm-wildcard",
                    "reply_target": "dm-1",
                    "metadata": {
                        "discord_guild_id": "",
                        "discord_channel_id": "dm-1",
                        "interaction_type": "direct",
                    },
                }
            },
        )

        assert "not allowlisted" in result["response"]
        assert result["channel_policy"]["public_access"] is False
        assert result["delivery"]["reason"] == "identity_not_allowlisted"
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_m75_discord_public_channel_tool_allowlist_grants_only_public_tools(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fake_connect(self: InMemoryChannel) -> None:
        await InMemoryChannel.connect(self)

    calls = {"search": 0}
    planner_mode = {"tool": "web.search"}

    def _fake_search(self: object, *, query: str, limit: int = 5) -> dict[str, object]:
        _ = (self, query, limit)
        calls["search"] += 1
        return {
            "ok": True,
            "operation": "web_search",
            "results": [{"title": "Shisa docs", "url": "https://example.com/shisa"}],
        }

    async def _planner_public_tool(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        **_kwargs: object,
    ) -> PlannerResult:
        _ = user_content
        tool_names = {
            str(tool.get("function", {}).get("name", ""))
            for tool in tools or []
            if isinstance(tool.get("function"), dict)
        }
        assert tool_names == {"web_search"}
        if planner_mode["tool"] == "web.search":
            proposal = ActionProposal(
                action_id="m75-public-web-search",
                tool_name=ToolName("web.search"),
                arguments={"query": "shisa docs", "limit": 1},
                reasoning="exercise public web search grant",
                data_sources=[],
            )
            decision = self._pep.evaluate(proposal.tool_name, proposal.arguments, context)
            assert decision.kind == PEPDecisionKind.ALLOW
            response = "Searching public web."
        else:
            proposal = ActionProposal(
                action_id="m75-public-fs-read",
                tool_name=ToolName("fs.read"),
                arguments={"path": "/tmp/owner-private.txt", "max_bytes": 64},
                reasoning="private tool must not be available in a public channel",
                data_sources=[],
            )
            decision = self._pep.evaluate(proposal.tool_name, proposal.arguments, context)
            assert decision.kind == PEPDecisionKind.REJECT
            response = "Trying private read."
        return PlannerResult(
            output=PlannerOutput(actions=[proposal], assistant_response=response),
            evaluated=[EvaluatedProposal(proposal=proposal, decision=decision)],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(DiscordChannel, "connect", _fake_connect)
    monkeypatch.setattr("shisad.assistant.web.WebToolkit.search", _fake_search)
    monkeypatch.setattr(Planner, "propose", _planner_public_tool)

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        log_level="INFO",
        discord_enabled=True,
        discord_bot_token="token",
        discord_channel_rules=[
            DiscordChannelRule(
                guild_id="guild-1",
                channels=["public"],
                mode="mention-only",
                public_enabled=True,
                public_tools=["web.search", "fs.read"],
            )
        ],
    )
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        allowed = await client.call(
            "channel.ingest",
            {
                "message": {
                    "channel": "discord",
                    "external_user_id": "visitor",
                    "workspace_hint": "guild-1",
                    "content": "search public docs",
                    "message_id": "m75-public-tool-1",
                    "reply_target": "public",
                }
            },
        )
        assert allowed["channel_policy"]["allowed_tools"] == ["web.search"]
        assert allowed["confirmation_required_actions"] >= 1
        assert allowed["executed_actions"] == 0
        assert allowed["blocked_actions"] == 0
        assert calls["search"] == 0

        planner_mode["tool"] = "fs.read"
        rejected = await client.call(
            "channel.ingest",
            {
                "message": {
                    "channel": "discord",
                    "external_user_id": "visitor-2",
                    "workspace_hint": "guild-1",
                    "content": "read private file",
                    "message_id": "m75-public-tool-2",
                    "reply_target": "public",
                }
            },
        )
        assert rejected["channel_policy"]["allowed_tools"] == ["web.search"]
        assert rejected["executed_actions"] == 0
        assert rejected["blocked_actions"] == 1
        assert calls["search"] == 0
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_m75_discord_read_along_marks_proactive_and_enforces_cooldown(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fake_connect(self: InMemoryChannel) -> None:
        await InMemoryChannel.connect(self)

    monkeypatch.setattr(DiscordChannel, "connect", _fake_connect)

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        log_level="INFO",
        discord_enabled=True,
        discord_bot_token="token",
        discord_channel_rules=[
            DiscordChannelRule(
                guild_id="guild-1",
                channels=["public"],
                mode="read-along",
                public_enabled=True,
                relevance_keywords=["release"],
                cooldown_seconds=300,
                proactive_marker="[proactive]",
            )
        ],
    )
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        first = await client.call(
            "channel.ingest",
            {
                "message": {
                    "channel": "discord",
                    "external_user_id": "visitor",
                    "workspace_hint": "guild-1",
                    "content": "release checklist question",
                    "message_id": "m75-readalong-1",
                    "reply_target": "public",
                    "metadata": {
                        "interaction_type": "observed",
                        "engagement_mode": "read-along",
                        "proactive_eligible": True,
                        "matched_relevance_keywords": ["release"],
                    },
                }
            },
        )
        assert first["delivery"]["attempted"] is True
        assert first["response"].startswith("[proactive] ")
        assert first["channel_policy"]["proactive"] is True

        second = await client.call(
            "channel.ingest",
            {
                "message": {
                    "channel": "discord",
                    "external_user_id": "visitor-2",
                    "workspace_hint": "guild-1",
                    "content": "another release checklist question",
                    "message_id": "m75-readalong-2",
                    "reply_target": "public",
                    "metadata": {
                        "interaction_type": "observed",
                        "engagement_mode": "read-along",
                        "proactive_eligible": True,
                        "matched_relevance_keywords": ["release"],
                    },
                }
            },
        )
        assert second["delivery"]["attempted"] is False
        assert second["delivery"]["reason"] == "proactive_cooldown"
        assert second["channel_policy"]["proactive"] is False
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_m75_discord_owner_observation_session_is_not_reused(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fake_connect(self: InMemoryChannel) -> None:
        await InMemoryChannel.connect(self)

    monkeypatch.setattr(DiscordChannel, "connect", _fake_connect)

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        log_level="INFO",
        discord_enabled=True,
        discord_bot_token="token",
        channel_identity_allowlist={"discord": ["owner-user"]},
        discord_trusted_users={"owner-user"},
        discord_channel_rules=[
            DiscordChannelRule(
                guild_id="guild-1",
                channels=["private-readalong"],
                mode="passive-observe",
                public_enabled=False,
            )
        ],
    )
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        observed = await client.call(
            "channel.ingest",
            {
                "message": {
                    "channel": "discord",
                    "external_user_id": "owner-user",
                    "workspace_hint": "guild-1",
                    "content": "observed owner chatter",
                    "message_id": "m75-owner-observed",
                    "reply_target": "private-readalong",
                    "metadata": {
                        "interaction_type": "observed",
                        "engagement_mode": "passive-observe",
                        "proactive_eligible": False,
                        "passive_reason": "passive_observe",
                    },
                }
            },
        )
        assert observed["delivery"]["attempted"] is False
        assert observed["channel_policy"]["ephemeral_session"] is True

        sessions_after_observation = await client.call("session.list")
        assert all(
            not (
                isinstance(item, dict)
                and item.get("channel") == "discord"
                and item.get("user_id") == "owner-user"
            )
            for item in sessions_after_observation.get("sessions", [])
        )

        direct = await client.call(
            "channel.ingest",
            {
                "message": {
                    "channel": "discord",
                    "external_user_id": "owner-user",
                    "workspace_hint": "guild-1",
                    "content": "now I am addressing the bot",
                    "message_id": "m75-owner-direct",
                    "reply_target": "private-readalong",
                }
            },
        )
        assert direct["trust_level"] == "owner"
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)
