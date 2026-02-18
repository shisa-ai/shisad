"""Session creation allowlist defaults regression coverage."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from shisad.channels.identity import ChannelIdentityMap
from shisad.core.session import SessionManager
from shisad.core.types import SessionId, ToolName
from shisad.daemon.handlers._impl_session import SessionImplMixin
from shisad.security.policy import PolicyBundle, ToolPolicy


class _EventCollector:
    def __init__(self) -> None:
        self.events: list[object] = []

    async def publish(self, event: object) -> None:
        self.events.append(event)


class _SessionCreateHarness:
    def __init__(self, policy: PolicyBundle) -> None:
        self._policy_loader = SimpleNamespace(policy=policy)
        self._identity_map = ChannelIdentityMap()
        self._internal_ingress_marker = object()
        self._session_manager = SessionManager()
        self._event_bus = _EventCollector()

    @staticmethod
    def _is_admin_rpc_peer(params: Any) -> bool:
        _ = params
        return False


@pytest.mark.asyncio
async def test_m7_session_create_default_deny_false_does_not_seed_tool_allowlist() -> None:
    harness = _SessionCreateHarness(
        PolicyBundle(
            default_deny=False,
            tools={ToolName("other_tool"): ToolPolicy()},
            session_tool_allowlist=[],
        )
    )
    result = await SessionImplMixin.do_session_create(harness, {"channel": "cli"})  # type: ignore[arg-type]
    session = harness._session_manager.get(SessionId(str(result["session_id"])))
    assert session is not None
    assert "tool_allowlist" not in session.metadata


@pytest.mark.asyncio
async def test_m7_session_create_default_deny_true_seeds_policy_tool_allowlist() -> None:
    harness = _SessionCreateHarness(
        PolicyBundle(
            default_deny=True,
            tools={ToolName("other_tool"): ToolPolicy()},
            session_tool_allowlist=[],
        )
    )
    result = await SessionImplMixin.do_session_create(harness, {"channel": "cli"})  # type: ignore[arg-type]
    session = harness._session_manager.get(SessionId(str(result["session_id"])))
    assert session is not None
    assert session.metadata.get("tool_allowlist") == ["other_tool"]


@pytest.mark.asyncio
async def test_m7_session_create_prefers_explicit_session_tool_allowlist() -> None:
    harness = _SessionCreateHarness(
        PolicyBundle(
            default_deny=False,
            tools={ToolName("other_tool"): ToolPolicy()},
            session_tool_allowlist=[ToolName("explicit_tool")],
        )
    )
    result = await SessionImplMixin.do_session_create(harness, {"channel": "cli"})  # type: ignore[arg-type]
    session = harness._session_manager.get(SessionId(str(result["session_id"])))
    assert session is not None
    assert session.metadata.get("tool_allowlist") == ["explicit_tool"]
