"""S8 default posture coverage (all tools enabled by default)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from shisad.channels.identity import ChannelIdentityMap
from shisad.core.config import DaemonConfig, SecurityConfig
from shisad.core.session import SessionManager
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, PEPDecisionKind, SessionId, TaintLabel, ToolName
from shisad.daemon.handlers._impl_session import SessionImplMixin
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import EgressRule, PolicyBundle, ToolPolicy


def _register_tool(
    registry: ToolRegistry,
    *,
    name: str,
    capabilities: list[Capability],
    parameters: list[ToolParameter] | None = None,
    require_confirmation: bool = False,
) -> None:
    registry.register(
        ToolDefinition(
            name=ToolName(name),
            description=f"{name} tool",
            parameters=parameters or [],
            capabilities_required=capabilities,
            require_confirmation=require_confirmation,
        )
    )


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

    def _is_admin_rpc_peer(self, params: Any) -> bool:
        _ = params
        return False


def test_s8_policy_bundle_defaults_flip_to_permissive_posture() -> None:
    policy = PolicyBundle()
    assert policy.default_deny is False
    assert policy.default_require_confirmation is False


def test_s8_policy_bundle_default_capabilities_include_entire_enum() -> None:
    policy = PolicyBundle()
    expected = set(Capability)
    assert set(policy.default_capabilities) == expected
    assert len(policy.default_capabilities) == len(expected)


def test_s8_config_defaults_align_with_new_policy_posture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SHISAD_WEB_FETCH_ENABLED", raising=False)
    monkeypatch.delenv("SHISAD_SECURITY_DEFAULT_DENY", raising=False)
    assert DaemonConfig().web_fetch_enabled is True
    assert DaemonConfig().browser_require_hardened_isolation is True
    assert SecurityConfig().default_deny is False


def test_s8_pep_effective_tool_allowlist_is_none_with_default_policy() -> None:
    registry = ToolRegistry()
    _register_tool(registry, name="list_files", capabilities=[Capability.FILE_READ])

    pep = PEP(PolicyBundle(), registry)
    ctx = PolicyContext(capabilities={Capability.FILE_READ})
    assert pep._effective_tool_allowlist(ctx) is None


def test_s8_pep_allows_registered_tool_not_listed_in_policy_tools() -> None:
    registry = ToolRegistry()
    _register_tool(registry, name="list_files", capabilities=[Capability.FILE_READ])

    pep = PEP(
        PolicyBundle(
            default_require_confirmation=False,
            tools={ToolName("other_tool"): ToolPolicy()},
        ),
        registry,
    )
    decision = pep.evaluate(
        ToolName("list_files"),
        {},
        PolicyContext(capabilities={Capability.FILE_READ}),
    )
    assert decision.kind == PEPDecisionKind.ALLOW


def test_s8_pep_still_requires_confirmation_for_confirmed_tools() -> None:
    registry = ToolRegistry()
    _register_tool(
        registry,
        name="local_write",
        capabilities=[Capability.FILE_WRITE],
        require_confirmation=True,
    )
    pep = PEP(PolicyBundle(), registry)
    decision = pep.evaluate(
        ToolName("local_write"),
        {},
        PolicyContext(capabilities={Capability.FILE_WRITE}),
    )
    assert decision.kind == PEPDecisionKind.REQUIRE_CONFIRMATION


def test_s8_pep_still_requires_confirmation_for_taint_write_sink() -> None:
    registry = ToolRegistry()
    _register_tool(registry, name="file.write", capabilities=[Capability.FILE_WRITE])
    pep = PEP(PolicyBundle(), registry)

    clean = pep.evaluate(
        ToolName("file.write"),
        {},
        PolicyContext(capabilities={Capability.FILE_WRITE}, trust_level="trusted"),
    )
    assert clean.kind == PEPDecisionKind.ALLOW

    tainted = pep.evaluate(
        ToolName("file.write"),
        {},
        PolicyContext(
            capabilities={Capability.FILE_WRITE},
            taint_labels={TaintLabel.UNTRUSTED},
            trust_level="trusted",
        ),
    )
    assert tainted.kind == PEPDecisionKind.REQUIRE_CONFIRMATION


def test_s8_pep_high_risk_runtime_aliases_require_confirmation() -> None:
    registry = ToolRegistry()
    _register_tool(registry, name="shell.exec", capabilities=[Capability.SHELL_EXEC])
    _register_tool(registry, name="file.write", capabilities=[Capability.FILE_WRITE])
    pep = PEP(PolicyBundle(), registry)

    shell = pep.evaluate(
        ToolName("shell.exec"),
        {},
        PolicyContext(capabilities={Capability.SHELL_EXEC}),
    )
    file_write = pep.evaluate(
        ToolName("file.write"),
        {},
        PolicyContext(capabilities={Capability.FILE_WRITE}),
    )
    assert shell.kind == PEPDecisionKind.REQUIRE_CONFIRMATION
    assert file_write.kind == PEPDecisionKind.REQUIRE_CONFIRMATION


def test_s8_pep_still_requires_confirmation_for_risk_threshold() -> None:
    registry = ToolRegistry()
    _register_tool(
        registry,
        name="http.request",
        capabilities=[Capability.HTTP_REQUEST],
        parameters=[ToolParameter(name="url", type="string", required=True)],
    )
    pep = PEP(
        PolicyBundle(
            egress=[EgressRule(host="api.good.com", protocols=["https"], ports=[443])]
        ),
        registry,
    )
    decision = pep.evaluate(
        ToolName("http.request"),
        {"url": "https://api.good.com/path"},
        PolicyContext(capabilities={Capability.HTTP_REQUEST}),
    )
    assert decision.kind == PEPDecisionKind.REQUIRE_CONFIRMATION


def test_s8_pep_still_blocks_egress_without_allowlist_entries() -> None:
    registry = ToolRegistry()
    _register_tool(
        registry,
        name="http.request",
        capabilities=[Capability.HTTP_REQUEST],
        parameters=[ToolParameter(name="url", type="string", required=True)],
    )
    pep = PEP(PolicyBundle(), registry)
    decision = pep.evaluate(
        ToolName("http.request"),
        {"url": "https://api.good.com/path"},
        PolicyContext(capabilities={Capability.HTTP_REQUEST}),
    )
    assert decision.kind == PEPDecisionKind.REJECT
    assert "allowlisted" in decision.reason.lower()


@pytest.mark.asyncio
async def test_s8_session_create_default_policy_does_not_seed_tool_allowlist() -> None:
    harness = _SessionCreateHarness(PolicyBundle())
    result = await SessionImplMixin.do_session_create(harness, {"channel": "cli"})  # type: ignore[arg-type]
    session = harness._session_manager.get(SessionId(str(result["session_id"])))
    assert session is not None
    assert "tool_allowlist" not in session.metadata
    assert session.capabilities == set(Capability)


def test_s8_explicit_restrictive_policy_blocks_unlisted_tools() -> None:
    registry = ToolRegistry()
    _register_tool(registry, name="allowed_tool", capabilities=[Capability.FILE_READ])
    _register_tool(registry, name="blocked_tool", capabilities=[Capability.FILE_READ])

    pep = PEP(
        PolicyBundle(
            default_deny=True,
            default_require_confirmation=False,
            tools={ToolName("allowed_tool"): ToolPolicy()},
        ),
        registry,
    )
    decision = pep.evaluate(
        ToolName("blocked_tool"),
        {},
        PolicyContext(capabilities={Capability.FILE_READ}),
    )
    assert decision.kind == PEPDecisionKind.REJECT
    assert "allowlist" in decision.reason.lower()


def test_s8_explicit_session_allowlist_overrides_permissive_defaults() -> None:
    registry = ToolRegistry()
    _register_tool(registry, name="allowed_tool", capabilities=[Capability.FILE_READ])
    _register_tool(registry, name="blocked_tool", capabilities=[Capability.FILE_READ])

    pep = PEP(
        PolicyBundle(
            default_deny=False,
            default_require_confirmation=False,
            session_tool_allowlist=[ToolName("allowed_tool")],
        ),
        registry,
    )
    allowed = pep.evaluate(
        ToolName("allowed_tool"),
        {},
        PolicyContext(capabilities={Capability.FILE_READ}),
    )
    blocked = pep.evaluate(
        ToolName("blocked_tool"),
        {},
        PolicyContext(capabilities={Capability.FILE_READ}),
    )
    assert allowed.kind == PEPDecisionKind.ALLOW
    assert blocked.kind == PEPDecisionKind.REJECT
