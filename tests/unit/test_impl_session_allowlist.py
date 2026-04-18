"""Session creation allowlist defaults regression coverage."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from shisad.channels.identity import ChannelIdentityMap
from shisad.core.session import Session, SessionManager
from shisad.core.types import SessionId, SessionRole, TaintLabel, ToolName
from shisad.daemon.handlers._impl_session import (
    SessionImplMixin,
    _looks_like_admin_cleanroom_request,
    _planner_manifest_includes_report_anomaly,
)
from shisad.security.policy import PolicyBundle, ToolPolicy


class _EventCollector:
    def __init__(self) -> None:
        self.events: list[object] = []

    async def publish(self, event: object) -> None:
        self.events.append(event)


class _SessionCreateHarness:
    def __init__(self, policy: PolicyBundle, *, admin_peer: bool = False) -> None:
        self._policy_loader = SimpleNamespace(policy=policy)
        self._identity_map = ChannelIdentityMap()
        self._internal_ingress_marker = object()
        self._session_manager = SessionManager()
        self._event_bus = _EventCollector()
        self._admin_peer = admin_peer

    def _is_admin_rpc_peer(self, params: Any) -> bool:
        _ = params
        return self._admin_peer


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


@pytest.mark.asyncio
async def test_m2_session_create_allows_tone_override_for_admin_peer() -> None:
    harness = _SessionCreateHarness(
        PolicyBundle(default_deny=False, session_tool_allowlist=[]),
        admin_peer=True,
    )
    result = await SessionImplMixin.do_session_create(
        harness,
        {"channel": "cli", "tone": "friendly"},
    )  # type: ignore[arg-type]
    session = harness._session_manager.get(SessionId(str(result["session_id"])))
    assert session is not None
    assert session.metadata.get("assistant_tone") == "friendly"


@pytest.mark.asyncio
async def test_m2_session_create_rejects_tone_override_for_non_admin_peer() -> None:
    harness = _SessionCreateHarness(
        PolicyBundle(default_deny=False, session_tool_allowlist=[]),
        admin_peer=False,
    )
    with pytest.raises(
        ValueError,
        match="session tone override requires trusted admin control API",
    ):
        await SessionImplMixin.do_session_create(
            harness,
            {"channel": "cli", "tone": "friendly"},
        )  # type: ignore[arg-type]


def test_m1_clean_orchestrator_manifest_omits_report_anomaly() -> None:
    session = Session(role=SessionRole.ORCHESTRATOR)

    assert (
        _planner_manifest_includes_report_anomaly(
            session=session,
            trust_level="trusted",
            policy_taint_labels=set(),
        )
        is False
    )


def test_s9_soul_update_intent_triggers_admin_cleanroom_reroute() -> None:
    assert _looks_like_admin_cleanroom_request("update my SOUL.md to prefer shorter replies")
    assert _looks_like_admin_cleanroom_request("please change assistant persona")


@pytest.mark.parametrize(
    ("role", "trust_level", "taints"),
    [
        (SessionRole.ORCHESTRATOR, "untrusted", set()),
        (SessionRole.ORCHESTRATOR, "trusted", {TaintLabel.UNTRUSTED}),
        (SessionRole.SUBAGENT, "trusted", set()),
    ],
)
def test_m1_nonclean_or_split_contexts_keep_report_anomaly(
    role: SessionRole,
    trust_level: str,
    taints: set[TaintLabel],
) -> None:
    session = Session(role=role)

    assert (
        _planner_manifest_includes_report_anomaly(
            session=session,
            trust_level=trust_level,
            policy_taint_labels=taints,
        )
        is True
    )
