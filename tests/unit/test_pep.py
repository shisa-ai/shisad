"""M0.T4-T5: PEP rejects unknown tools and invalid schemas."""

from __future__ import annotations

from shisad.core.approval import ConfirmationLevel, ConfirmationRequirement
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import (
    Capability,
    PEPDecisionKind,
    TaintLabel,
    ToolName,
    UserId,
    WorkspaceId,
)
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import EgressRule, PolicyBundle, ToolPolicy


def _make_pep() -> tuple[PEP, ToolRegistry]:
    """Create a PEP with a simple tool registered."""
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("test_tool"),
            description="A test tool",
            parameters=[
                ToolParameter(name="query", type="string", required=True),
                ToolParameter(name="limit", type="integer", required=False),
            ],
            capabilities_required=[Capability.HTTP_REQUEST],
        )
    )
    policy = PolicyBundle(default_require_confirmation=False)
    return PEP(policy, registry), registry


class TestPepRejectsUnknownTools:
    """M0.T4: PEP rejects unknown tools."""

    def test_unknown_tool_rejected(self) -> None:
        pep, _ = _make_pep()
        ctx = PolicyContext(capabilities={Capability.HTTP_REQUEST})
        decision = pep.evaluate(ToolName("nonexistent"), {}, ctx)
        assert decision.kind == PEPDecisionKind.REJECT
        assert "Unknown tool" in decision.reason

    def test_known_tool_allowed(self) -> None:
        pep, _ = _make_pep()
        ctx = PolicyContext(capabilities={Capability.HTTP_REQUEST})
        decision = pep.evaluate(ToolName("test_tool"), {"query": "hello"}, ctx)
        assert decision.kind == PEPDecisionKind.ALLOW


class TestPepSchemaValidation:
    """M0.T5: PEP rejects invalid tool argument schemas."""

    def test_missing_required_arg_rejected(self) -> None:
        pep, _ = _make_pep()
        ctx = PolicyContext(capabilities={Capability.HTTP_REQUEST})
        decision = pep.evaluate(ToolName("test_tool"), {}, ctx)
        assert decision.kind == PEPDecisionKind.REJECT
        assert "Missing required" in decision.reason

    def test_extra_arg_rejected(self) -> None:
        pep, _ = _make_pep()
        ctx = PolicyContext(capabilities={Capability.HTTP_REQUEST})
        decision = pep.evaluate(ToolName("test_tool"), {"query": "hello", "unknown": "bad"}, ctx)
        assert decision.kind == PEPDecisionKind.REJECT
        assert "Unexpected argument" in decision.reason

    def test_wrong_type_rejected(self) -> None:
        pep, _ = _make_pep()
        ctx = PolicyContext(capabilities={Capability.HTTP_REQUEST})
        decision = pep.evaluate(
            ToolName("test_tool"), {"query": "hello", "limit": "not_an_int"}, ctx
        )
        assert decision.kind == PEPDecisionKind.REJECT
        assert "expected type" in decision.reason

    def test_missing_capability_rejected(self) -> None:
        pep, _ = _make_pep()
        ctx = PolicyContext(capabilities=set())  # No capabilities
        decision = pep.evaluate(ToolName("test_tool"), {"query": "hello"}, ctx)
        assert decision.kind == PEPDecisionKind.REJECT
        assert "Missing capabilities" in decision.reason


class TestPepToolAllowlist:
    """M0.7.3: tool allowlist checks."""

    def test_context_tool_allowlist_rejects_not_allowed_tool(self) -> None:
        pep, _ = _make_pep()
        ctx = PolicyContext(
            capabilities={Capability.HTTP_REQUEST},
            tool_allowlist={ToolName("different_tool")},
        )
        decision = pep.evaluate(ToolName("test_tool"), {"query": "hello"}, ctx)
        assert decision.kind == PEPDecisionKind.REJECT
        assert "allowlist" in decision.reason.lower()


class TestPepAllowedArgsPolicy:
    """Policy-level allowed_args constraints."""

    def test_allowed_args_policy_blocks_unapproved_argument_values(self) -> None:
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name=ToolName("test_tool"),
                description="A test tool",
                parameters=[ToolParameter(name="query", type="string", required=True)],
                capabilities_required=[Capability.HTTP_REQUEST],
            )
        )
        policy = PolicyBundle(
            default_require_confirmation=False,
            tools={
                ToolName("test_tool"): ToolPolicy(
                    capabilities_required=[Capability.HTTP_REQUEST],
                    require_confirmation=False,
                    allowed_args={"query": "approved"},
                )
            },
        )
        pep = PEP(policy, registry)
        ctx = PolicyContext(capabilities={Capability.HTTP_REQUEST})

        allowed = pep.evaluate(ToolName("test_tool"), {"query": "approved"}, ctx)
        assert allowed.kind == PEPDecisionKind.ALLOW

        blocked = pep.evaluate(ToolName("test_tool"), {"query": "something_else"}, ctx)
        assert blocked.kind == PEPDecisionKind.REJECT
        assert "allowed_args" in blocked.reason

    def test_policy_tool_allowlist_rejects_unlisted_tool(self) -> None:
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name=ToolName("test_tool"),
                description="A test tool",
                parameters=[ToolParameter(name="query", type="string", required=True)],
                capabilities_required=[Capability.HTTP_REQUEST],
            )
        )
        policy = PolicyBundle(
            default_deny=True,
            default_require_confirmation=False,
            tools={
                ToolName("other_tool"): ToolPolicy(
                    capabilities_required=[],
                    require_confirmation=False,
                )
            },
        )
        pep = PEP(policy, registry)
        ctx = PolicyContext(capabilities={Capability.HTTP_REQUEST})
        decision = pep.evaluate(ToolName("test_tool"), {"query": "hello"}, ctx)
        assert decision.kind == PEPDecisionKind.REJECT
        assert "allowlist" in decision.reason.lower()

    def test_default_deny_false_allows_unlisted_tool_when_no_session_allowlist(self) -> None:
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name=ToolName("test_tool"),
                description="A test tool",
                parameters=[ToolParameter(name="query", type="string", required=True)],
                capabilities_required=[Capability.HTTP_REQUEST],
            )
        )
        policy = PolicyBundle(
            default_deny=False,
            default_require_confirmation=False,
            tools={
                ToolName("other_tool"): ToolPolicy(
                    capabilities_required=[],
                    require_confirmation=False,
                )
            },
        )
        pep = PEP(policy, registry)
        ctx = PolicyContext(capabilities={Capability.HTTP_REQUEST})
        decision = pep.evaluate(ToolName("test_tool"), {"query": "hello"}, ctx)
        assert decision.kind == PEPDecisionKind.ALLOW


class TestPepReasonCodes:
    """H3: structured reject reason codes for deny-signal wiring."""

    def test_missing_capabilities_reject_has_reason_code(self) -> None:
        pep, _ = _make_pep()
        ctx = PolicyContext(capabilities=set())
        decision = pep.evaluate(ToolName("test_tool"), {"query": "hello"}, ctx)
        assert decision.kind == PEPDecisionKind.REJECT
        assert decision.reason_code == "pep:missing_capabilities"

    def test_tool_allowlist_reject_has_reason_code(self) -> None:
        pep, _ = _make_pep()
        ctx = PolicyContext(
            capabilities={Capability.HTTP_REQUEST},
            tool_allowlist={ToolName("different_tool")},
        )
        decision = pep.evaluate(ToolName("test_tool"), {"query": "hello"}, ctx)
        assert decision.kind == PEPDecisionKind.REJECT
        assert decision.reason_code == "pep:tool_not_permitted"

    def test_unattributed_destination_reject_has_reason_code(self) -> None:
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name=ToolName("http_request"),
                description="HTTP",
                parameters=[ToolParameter(name="url", type="string", required=True)],
                capabilities_required=[Capability.HTTP_REQUEST],
            )
        )
        pep = PEP(
            PolicyBundle(
                default_require_confirmation=False,
                egress=[EgressRule(host="api.allowed.com", protocols=["https"], ports=[443])],
            ),
            registry,
        )
        decision = pep.evaluate(
            ToolName("http_request"),
            {"url": "https://evil.example/upload"},
            PolicyContext(capabilities={Capability.HTTP_REQUEST}),
        )
        assert decision.kind == PEPDecisionKind.REJECT
        assert decision.reason_code == "pep:destination_unattributed"


class TestPepConfirmationPolicy:
    """A0 confirmation policy foundation coverage."""

    def test_tool_policy_confirmation_level_requires_confirmation(self) -> None:
        _, registry = _make_pep()
        pep = PEP(
            PolicyBundle.model_validate(
                {
                    "default_require_confirmation": False,
                    "tools": {
                        "test_tool": {
                            "confirmation": {
                                "level": "bound_approval",
                            }
                        }
                    },
                }
            ),
            registry,
        )
        ctx = PolicyContext(capabilities={Capability.HTTP_REQUEST})
        decision = pep.evaluate(ToolName("test_tool"), {"query": "hello"}, ctx)
        assert decision.kind == PEPDecisionKind.REQUIRE_CONFIRMATION
        assert decision.confirmation_requirement is not None
        assert decision.confirmation_requirement["level"] == "bound_approval"

    def test_legacy_require_confirmation_migrates_to_software_level(self) -> None:
        bundle = PolicyBundle.model_validate(
            {
                "tools": {
                    "test_tool": {
                        "require_confirmation": True,
                    }
                }
            }
        )
        tool_policy = bundle.tools[ToolName("test_tool")]
        assert tool_policy.confirmation is not None
        assert tool_policy.confirmation.level == ConfirmationLevel.SOFTWARE

    def test_mcp_tool_confirmation_survives_trusted_cli_bypass(self) -> None:
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name=ToolName("mcp.docs.lookup-doc"),
                description="Lookup remote docs.",
                parameters=[ToolParameter(name="query", type="string", required=True)],
                registration_source="mcp",
                registration_source_id="docs",
                upstream_tool_name="lookup-doc",
            )
        )
        pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
        decision = pep.evaluate(
            ToolName("mcp.docs.lookup-doc"),
            {"query": "roadmap"},
            PolicyContext(
                capabilities=set(),
                trust_level="trusted",
                trusted_cli_confirmation_bypass=True,
            ),
        )

        assert decision.kind == PEPDecisionKind.REQUIRE_CONFIRMATION
        assert decision.confirmation_requirement is not None
        assert decision.confirmation_requirement["level"] == "software"

    def test_unallowlisted_mcp_tool_requires_confirmation(self) -> None:
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name=ToolName("mcp.docs.lookup-doc"),
                description="Lookup remote docs.",
                parameters=[ToolParameter(name="query", type="string", required=True)],
                registration_source="mcp",
                registration_source_id="docs",
                upstream_tool_name="lookup-doc",
            )
        )
        pep = PEP(PolicyBundle(default_require_confirmation=False), registry)

        decision = pep.evaluate(
            ToolName("mcp.docs.lookup-doc"),
            {"query": "roadmap"},
            PolicyContext(capabilities=set(), trust_level="trusted"),
        )

        assert decision.kind == PEPDecisionKind.REQUIRE_CONFIRMATION
        assert decision.reason_code == "pep:confirmation_required"
        assert decision.confirmation_requirement is not None
        assert decision.confirmation_requirement["level"] == "software"

    def test_allowlisted_mcp_tool_bypasses_default_confirmation(self) -> None:
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name=ToolName("mcp.docs.lookup-doc"),
                description="Lookup remote docs.",
                parameters=[ToolParameter(name="query", type="string", required=True)],
                registration_source="mcp",
                registration_source_id="docs",
                upstream_tool_name="lookup-doc",
            )
        )
        pep = PEP(
            PolicyBundle(default_require_confirmation=False),
            registry,
            mcp_trusted_servers={"docs"},
        )

        decision = pep.evaluate(
            ToolName("mcp.docs.lookup-doc"),
            {"query": "roadmap"},
            PolicyContext(capabilities=set(), trust_level="trusted"),
        )

        assert decision.kind == PEPDecisionKind.ALLOW

    def test_risk_confirmation_levels_escalate_to_highest_threshold(self) -> None:
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name=ToolName("http.request"),
                description="Issue an HTTP request.",
                parameters=[ToolParameter(name="url", type="string", required=True)],
                capabilities_required=[Capability.HTTP_REQUEST],
            )
        )
        pep = PEP(
            PolicyBundle.model_validate(
                {
                    "default_require_confirmation": False,
                    "risk_policy": {
                        "auto_approve_threshold": 0.95,
                        "block_threshold": 0.99,
                        "confirmation_levels": [
                            {"threshold": 0.2, "level": "software"},
                            {"threshold": 0.25, "level": "bound_approval"},
                        ],
                    },
                }
            ),
            registry,
        )
        decision = pep.evaluate(
            ToolName("http.request"),
            {"url": "https://good.example/upload"},
            PolicyContext(
                capabilities={Capability.HTTP_REQUEST},
                user_goal_host_patterns={"good.example"},
                trust_level="trusted",
            ),
        )
        assert decision.kind == PEPDecisionKind.REQUIRE_CONFIRMATION
        assert decision.confirmation_requirement is not None
        assert decision.confirmation_requirement["level"] == "bound_approval"

    def test_explicit_high_tier_fallback_survives_lower_tier_default_confirmation(self) -> None:
        _, registry = _make_pep()
        pep = PEP(
            PolicyBundle.model_validate(
                {
                    "default_require_confirmation": True,
                    "tools": {
                        "test_tool": {
                            "confirmation": {
                                "level": "bound_approval",
                                "fallback": {
                                    "mode": "allow_levels",
                                    "allow_levels": ["software"],
                                },
                            }
                        }
                    },
                }
            ),
            registry,
        )
        ctx = PolicyContext(capabilities={Capability.HTTP_REQUEST})
        decision = pep.evaluate(ToolName("test_tool"), {"query": "hello"}, ctx)

        assert decision.kind == PEPDecisionKind.REQUIRE_CONFIRMATION
        assert decision.confirmation_requirement is not None
        requirement = ConfirmationRequirement.model_validate(decision.confirmation_requirement)
        assert requirement.level == ConfirmationLevel.BOUND_APPROVAL
        assert requirement.fallback.mode == "allow_levels"
        assert requirement.fallback.allow_levels == [ConfirmationLevel.SOFTWARE]


class TestPepResourceAuthorization:
    """SEC-H1: PEP object-level resource authorization (step 5)."""

    @staticmethod
    def _registry_with_path_tool() -> ToolRegistry:
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name=ToolName("file.read"),
                description="Read a file from the workspace.",
                parameters=[
                    ToolParameter(
                        name="path",
                        type="string",
                        required=True,
                        semantic_type="workspace_path",
                    ),
                ],
                capabilities_required=[Capability.FILE_READ],
            )
        )
        return registry

    def test_resource_authorizer_rejection_produces_resource_authorization_failed(self) -> None:
        registry = self._registry_with_path_tool()
        pep = PEP(PolicyBundle(default_require_confirmation=False), registry)

        def deny_all(_value: str, _workspace: WorkspaceId, _user: UserId) -> bool:
            return False

        decision = pep.evaluate(
            ToolName("file.read"),
            {"path": "src/shisad/main.py"},
            PolicyContext(
                capabilities={Capability.FILE_READ},
                resource_authorizer=deny_all,
                workspace_id=WorkspaceId("ws1"),
                user_id=UserId("alice"),
            ),
        )

        assert decision.kind == PEPDecisionKind.REJECT
        assert decision.reason_code == "pep:resource_authorization_failed"
        assert "'path'" in decision.reason

    def test_resource_authorizer_allowance_lets_call_through(self) -> None:
        registry = self._registry_with_path_tool()
        pep = PEP(PolicyBundle(default_require_confirmation=False), registry)

        def allow_all(_value: str, _workspace: WorkspaceId, _user: UserId) -> bool:
            return True

        decision = pep.evaluate(
            ToolName("file.read"),
            {"path": "src/shisad/main.py"},
            PolicyContext(
                capabilities={Capability.FILE_READ},
                resource_authorizer=allow_all,
            ),
        )
        assert decision.kind == PEPDecisionKind.ALLOW

    def test_resource_authorizer_defaults_are_applied_when_arg_missing(self) -> None:
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name=ToolName("fs.list"),
                description="List directory contents.",
                parameters=[
                    ToolParameter(
                        name="path",
                        type="string",
                        required=False,
                        semantic_type="workspace_path",
                    ),
                ],
                capabilities_required=[Capability.FILE_READ],
            )
        )
        pep = PEP(PolicyBundle(default_require_confirmation=False), registry)

        seen: list[str] = []

        def record_arg(value: str, _workspace: WorkspaceId, _user: UserId) -> bool:
            seen.append(value)
            return False

        decision = pep.evaluate(
            ToolName("fs.list"),
            {},
            PolicyContext(
                capabilities={Capability.FILE_READ},
                resource_authorizer=record_arg,
            ),
        )

        # _RESOURCE_ARG_DEFAULTS["fs.list"] = {"path": "."}
        assert seen == ["."]
        assert decision.kind == PEPDecisionKind.REJECT
        assert decision.reason_code == "pep:resource_authorization_failed"

    def test_resource_authorizer_is_skipped_when_unset(self) -> None:
        registry = self._registry_with_path_tool()
        pep = PEP(PolicyBundle(default_require_confirmation=False), registry)

        decision = pep.evaluate(
            ToolName("file.read"),
            {"path": "src/shisad/main.py"},
            PolicyContext(
                capabilities={Capability.FILE_READ},
                resource_authorizer=None,
            ),
        )
        assert decision.kind == PEPDecisionKind.ALLOW

    def test_resource_authorizer_ignores_session_id_argument(self) -> None:
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name=ToolName("session.note"),
                description="Post a note against a session.",
                parameters=[
                    ToolParameter(name="session_id", type="string", required=True),
                    ToolParameter(name="note", type="string", required=True),
                ],
                capabilities_required=[],
            )
        )
        pep = PEP(PolicyBundle(default_require_confirmation=False), registry)

        seen: list[str] = []

        def authorizer(value: str, _workspace: WorkspaceId, _user: UserId) -> bool:
            seen.append(value)
            return False

        decision = pep.evaluate(
            ToolName("session.note"),
            {"session_id": "sess-1", "note": "hello"},
            PolicyContext(
                capabilities=set(),
                resource_authorizer=authorizer,
            ),
        )
        # session_id is in _RESOURCE_ARG_ALLOWLIST; authorizer must not be consulted.
        assert seen == []
        assert decision.kind == PEPDecisionKind.ALLOW


class TestPepReportAnomalyBypass:
    """SEC-M1: report_anomaly bypasses risk/confirmation but still needs registration."""

    def test_unregistered_report_anomaly_is_still_rejected_as_unknown_tool(self) -> None:
        registry = ToolRegistry()
        pep = PEP(PolicyBundle(default_require_confirmation=False), registry)

        decision = pep.evaluate(
            ToolName("report_anomaly"),
            {"reason": "possible_prompt_injection"},
            PolicyContext(capabilities=set()),
        )
        assert decision.kind == PEPDecisionKind.REJECT
        assert decision.reason_code == "pep:unknown_tool"

    def test_registered_report_anomaly_allowed_when_risk_would_otherwise_block(self) -> None:
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name=ToolName("report_anomaly"),
                description="Report a suspected attack.",
                parameters=[
                    ToolParameter(name="reason", type="string", required=True),
                ],
                capabilities_required=[],
            )
        )
        # block_threshold=0.0 would block everything else; risk-scoring still runs.
        pep = PEP(
            PolicyBundle.model_validate(
                {
                    "default_require_confirmation": True,
                    "risk_policy": {
                        "auto_approve_threshold": 0.0,
                        "block_threshold": 0.01,
                        "confirmation_levels": [],
                    },
                }
            ),
            registry,
        )

        decision = pep.evaluate(
            ToolName("report_anomaly"),
            {"reason": "possible_prompt_injection"},
            PolicyContext(
                capabilities=set(),
                taint_labels={TaintLabel.UNTRUSTED},
            ),
        )

        assert decision.kind == PEPDecisionKind.ALLOW


class TestPepTaintSinkBlock:
    """SEC-M2: taint sink BLOCK path (credential-taint reaching any tool)."""

    def test_user_credentials_taint_blocks_tool_with_reason_code(self) -> None:
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name=ToolName("file.write"),
                description="Write a file.",
                parameters=[
                    ToolParameter(
                        name="path",
                        type="string",
                        required=True,
                        semantic_type="workspace_path",
                    ),
                    ToolParameter(name="content", type="string", required=True),
                ],
                capabilities_required=[Capability.FILE_WRITE],
            )
        )
        pep = PEP(PolicyBundle(default_require_confirmation=False), registry)

        decision = pep.evaluate(
            ToolName("file.write"),
            {"path": "out.txt", "content": "hello"},
            PolicyContext(
                capabilities={Capability.FILE_WRITE},
                taint_labels={TaintLabel.USER_CREDENTIALS},
            ),
        )

        assert decision.kind == PEPDecisionKind.REJECT
        assert decision.reason_code == "pep:taint_sink_block"
        assert "taint sink" in decision.reason.lower()


class TestPepEgressNullProtocolAndPortGuard:
    """SEC-LM2: unresolved protocol/port must not silently match a permissive rule."""

    def test_host_arg_without_protocol_or_port_is_not_allowlisted(self) -> None:
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name=ToolName("probe.host"),
                description="Reach out to a host.",
                parameters=[
                    ToolParameter(name="host", type="string", required=True),
                ],
                capabilities_required=[Capability.HTTP_REQUEST],
            )
        )
        # Rule matches host exactly but declares no protocols/ports; without the
        # `None` guards the rule would silently authorize this call.
        pep = PEP(
            PolicyBundle(
                default_require_confirmation=False,
                egress=[EgressRule(host="api.good.com")],
            ),
            registry,
        )

        decision = pep.evaluate(
            ToolName("probe.host"),
            {"host": "api.good.com"},
            PolicyContext(capabilities={Capability.HTTP_REQUEST}),
        )

        # Fail-closed: the rule is skipped because protocol is None, and no
        # user-goal pattern attributes the host either.
        assert decision.kind == PEPDecisionKind.REJECT
        assert decision.reason_code == "pep:destination_unattributed"
