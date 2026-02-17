"""M1.T11-T14: upgraded PEP checks."""

from __future__ import annotations

from contextlib import suppress

from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, PEPDecisionKind, ToolName
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import EgressRule, PolicyBundle


def _registry_for_dlp() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("submit_data"),
            description="Submit payload",
            parameters=[ToolParameter(name="payload", type="string", required=True)],
            capabilities_required=[Capability.FILE_READ],
        )
    )
    return registry


def test_m1_t11_pep_argument_dlp_detects_api_key_patterns() -> None:
    pep = PEP(PolicyBundle(default_require_confirmation=False), _registry_for_dlp())
    decision = pep.evaluate(
        ToolName("submit_data"),
        {"payload": "token sk-abc123def456ghi789"},
        PolicyContext(capabilities={Capability.FILE_READ}),
    )
    assert decision.kind == PEPDecisionKind.REJECT
    assert "dlp" in decision.reason.lower()


def test_m1_t12_pep_argument_dlp_detects_oauth_patterns() -> None:
    pep = PEP(PolicyBundle(default_require_confirmation=False), _registry_for_dlp())
    decision = pep.evaluate(
        ToolName("submit_data"),
        {"payload": "Bearer ya29.A0ARrdaMXXXXXXXXXXXXXXXXXXXXXX"},
        PolicyContext(capabilities={Capability.FILE_READ}),
    )
    assert decision.kind == PEPDecisionKind.REJECT
    assert "dlp" in decision.reason.lower()


def test_m1_t13_egress_allowlist_blocks_non_allowlisted_domains() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("http_request"),
            description="HTTP call",
            parameters=[ToolParameter(name="url", type="string", required=True)],
            capabilities_required=[Capability.HTTP_REQUEST],
        )
    )

    policy = PolicyBundle(
        default_require_confirmation=False,
        egress=[EgressRule(host="*.good.com")],
    )
    pep = PEP(policy, registry)

    decision = pep.evaluate(
        ToolName("http_request"),
        {"url": "https://evil.com/exfil"},
        PolicyContext(capabilities={Capability.HTTP_REQUEST}),
    )
    assert decision.kind == PEPDecisionKind.REJECT
    assert "allowlisted" in decision.reason.lower()


def test_m1_egress_allowlist_enforces_protocol() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("http_request"),
            description="HTTP call",
            parameters=[ToolParameter(name="url", type="string", required=True)],
            capabilities_required=[Capability.HTTP_REQUEST],
        )
    )
    policy = PolicyBundle(
        default_require_confirmation=False,
        egress=[EgressRule(host="api.good.com", protocols=["https"], ports=[443])],
    )
    pep = PEP(policy, registry)

    decision = pep.evaluate(
        ToolName("http_request"),
        {"url": "http://api.good.com/path"},
        PolicyContext(capabilities={Capability.HTTP_REQUEST}),
    )
    assert decision.kind == PEPDecisionKind.REJECT


def test_m1_egress_allowlist_enforces_port() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("http_request"),
            description="HTTP call",
            parameters=[ToolParameter(name="url", type="string", required=True)],
            capabilities_required=[Capability.HTTP_REQUEST],
        )
    )
    policy = PolicyBundle(
        default_require_confirmation=False,
        egress=[EgressRule(host="api.good.com", protocols=["https"], ports=[443])],
    )
    pep = PEP(policy, registry)

    decision = pep.evaluate(
        ToolName("http_request"),
        {"url": "https://api.good.com:8443/path"},
        PolicyContext(capabilities={Capability.HTTP_REQUEST}),
    )
    assert decision.kind == PEPDecisionKind.REJECT


def test_m1_t14_tool_metadata_poisoning_cannot_alter_tool_schema() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("search"),
            description="Search tool",
            parameters=[ToolParameter(name="query", type="string", required=True)],
            capabilities_required=[Capability.HTTP_REQUEST],
        )
    )

    fetched = registry.get_tool(ToolName("search"))
    assert fetched is not None

    # Attempt to mutate fetched tool metadata does not affect registry state.
    with suppress(Exception):
        fetched.parameters.append(ToolParameter(name="pwn", type="string", required=False))

    errors = registry.validate_call(ToolName("search"), {"query": "ok", "pwn": "x"})
    assert any("Unexpected argument" in error for error in errors)


def test_m2_pep_enforces_egress_for_tools_with_static_destination_metadata() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("web_search"),
            description="Search via configured backend",
            parameters=[ToolParameter(name="query", type="string", required=True)],
            capabilities_required=[Capability.HTTP_REQUEST],
            destinations=["search.example"],
        )
    )

    blocked_policy = PolicyBundle(
        default_require_confirmation=False,
        egress=[EgressRule(host="api.good.com", protocols=["https"], ports=[443])],
    )
    blocked = PEP(blocked_policy, registry).evaluate(
        ToolName("web_search"),
        {"query": "roadmap"},
        PolicyContext(capabilities={Capability.HTTP_REQUEST}),
    )
    assert blocked.kind == PEPDecisionKind.REJECT

    allowed_policy = PolicyBundle(
        default_require_confirmation=False,
        egress=[EgressRule(host="search.example", protocols=["https"], ports=[443])],
    )
    allowed = PEP(allowed_policy, registry).evaluate(
        ToolName("web_search"),
        {"query": "roadmap"},
        PolicyContext(capabilities={Capability.HTTP_REQUEST}),
    )
    assert allowed.kind in {PEPDecisionKind.ALLOW, PEPDecisionKind.REQUIRE_CONFIRMATION}


def test_m3_pep_static_destination_metadata_preserves_protocol_and_port() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("web_search"),
            description="Search via configured backend",
            parameters=[ToolParameter(name="query", type="string", required=True)],
            capabilities_required=[Capability.HTTP_REQUEST],
            destinations=["http://search.example:8080"],
        )
    )

    blocked_policy = PolicyBundle(
        default_require_confirmation=False,
        egress=[EgressRule(host="search.example", protocols=["https"], ports=[443])],
    )
    blocked = PEP(blocked_policy, registry).evaluate(
        ToolName("web_search"),
        {"query": "roadmap"},
        PolicyContext(capabilities={Capability.HTTP_REQUEST}),
    )
    assert blocked.kind == PEPDecisionKind.REJECT

    allowed_policy = PolicyBundle(
        default_require_confirmation=False,
        egress=[EgressRule(host="search.example", protocols=["http"], ports=[8080])],
    )
    allowed = PEP(allowed_policy, registry).evaluate(
        ToolName("web_search"),
        {"query": "roadmap"},
        PolicyContext(capabilities={Capability.HTTP_REQUEST}),
    )
    assert allowed.kind in {PEPDecisionKind.ALLOW, PEPDecisionKind.REQUIRE_CONFIRMATION}


def test_m6_pep_rejects_malformed_url_port_without_raising() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("http_request"),
            description="HTTP call",
            parameters=[ToolParameter(name="url", type="string", required=True)],
            capabilities_required=[Capability.HTTP_REQUEST],
        )
    )
    policy = PolicyBundle(
        default_require_confirmation=False,
        egress=[EgressRule(host="api.good.com", protocols=["https"], ports=[443])],
    )
    pep = PEP(policy, registry)

    decision = pep.evaluate(
        ToolName("http_request"),
        {"url": "https://api.good.com:99999/path"},
        PolicyContext(capabilities={Capability.HTTP_REQUEST}),
    )
    assert decision.kind == PEPDecisionKind.REJECT
    assert "malformed" in decision.reason.lower()
