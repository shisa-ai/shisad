"""M2 channel trust + matrix integration tests."""

from __future__ import annotations

import pytest

from shisad.channels.base import InMemoryChannel
from shisad.channels.identity import ChannelIdentityMap
from shisad.channels.matrix import MatrixChannel, MatrixConfig
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, PEPDecisionKind, ToolName, UserId, WorkspaceId
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import EgressRule, PolicyBundle, RiskPolicy


def test_channel_identity_map_applies_per_channel_default_trust() -> None:
    identity_map = ChannelIdentityMap(default_trust={"matrix": "trusted"})
    identity_map.bind(
        channel="matrix",
        external_user_id="@alice:example.org",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws-main"),
    )
    identity = identity_map.resolve(channel="matrix", external_user_id="@alice:example.org")
    assert identity is not None
    assert identity.trust_level == "trusted"

    identity_map.configure_channel_trust(channel="matrix", trust_level="untrusted")
    identity_map.bind(
        channel="matrix",
        external_user_id="@bob:example.org",
        user_id=UserId("bob"),
        workspace_id=WorkspaceId("ws-main"),
    )
    bob = identity_map.resolve(channel="matrix", external_user_id="@bob:example.org")
    assert bob is not None
    assert bob.trust_level == "untrusted"


def test_channel_trust_level_influences_pep_risk_outcome() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("http_request"),
            description="HTTP request",
            parameters=[ToolParameter(name="url", type="string", required=True)],
            capabilities_required=[Capability.HTTP_REQUEST],
            require_confirmation=False,
        )
    )
    policy = PolicyBundle(
        default_require_confirmation=False,
        egress=[EgressRule(host="api.example.com", protocols=["https"], ports=[443])],
        risk_policy=RiskPolicy(auto_approve_threshold=0.4, block_threshold=0.9),
    )
    pep = PEP(policy, registry)

    untrusted = pep.evaluate(
        ToolName("http_request"),
        {"url": "https://api.example.com/v1/send"},
        PolicyContext(
            capabilities={Capability.HTTP_REQUEST},
            trust_level="untrusted",
        ),
    )
    trusted = pep.evaluate(
        ToolName("http_request"),
        {"url": "https://api.example.com/v1/send"},
        PolicyContext(
            capabilities={Capability.HTTP_REQUEST},
            trust_level="trusted",
        ),
    )

    assert untrusted.kind == PEPDecisionKind.REQUIRE_CONFIRMATION
    assert trusted.kind == PEPDecisionKind.ALLOW


@pytest.mark.asyncio
async def test_inmemory_channel_offline_buffer_heartbeat_and_health() -> None:
    channel = InMemoryChannel(name="test", max_buffer=8)
    await channel.send("queued-while-offline")
    assert channel.pending_outgoing() == 1

    await channel.connect()
    health = channel.health_status()
    assert health["connected"] is True
    assert health["last_heartbeat"] is not None
    assert channel.pending_outgoing() == 1
    assert await channel.pop_outgoing() == "queued-while-offline"

    await channel.heartbeat()
    assert channel.health_status()["heartbeat_age_seconds"] is not None
    await channel.disconnect()


@pytest.mark.asyncio
async def test_inmemory_channel_reconnect_exponential_backoff() -> None:
    channel = InMemoryChannel(
        name="test",
        reconnect_backoff_base=0.001,
        reconnect_backoff_max=0.002,
    )
    attempts = {"count": 0}

    async def flaky_operation() -> str:
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise ConnectionError("transient")
        return "ok"

    result = await channel.run_with_reconnect(flaky_operation, attempts=4)
    assert result == "ok"
    assert attempts["count"] == 3


@pytest.mark.asyncio
async def test_matrix_channel_fallback_and_workspace_mapping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shisad.channels import matrix as matrix_module

    monkeypatch.setattr(matrix_module, "nio", None)

    channel = MatrixChannel(
        MatrixConfig(
            homeserver="https://matrix.example.org",
            user_id="@bot:example.org",
            access_token="token",
            room_id="!room:example.org",
            room_workspace_map={"!room:example.org": "workspace-1"},
            trusted_users={"@alice:example.org"},
        )
    )

    await channel.connect()
    await channel.inject(
        external_user_id="@alice:example.org",
        content="hello from matrix",
        workspace_hint="!room:example.org",
    )
    message = await channel.receive()

    assert message.channel == "matrix"
    assert message.external_user_id == "@alice:example.org"
    assert channel.workspace_for_room("!room:example.org") == "workspace-1"
    assert channel.is_user_verified("@alice:example.org")
    await channel.disconnect()
