"""I1 MCP interop coverage for transport, registry bridge, and runtime execution."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from shisad.core.config import DaemonConfig, McpHttpServerConfig, McpStdioServerConfig
from shisad.core.events import ToolApproved, ToolExecuted
from shisad.core.session import Session, SessionManager
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import SessionId, ToolName, UserId, WorkspaceId
from shisad.daemon.handlers._impl import HandlerImplementation
from shisad.daemon.handlers._impl_session import _build_planner_tool_context
from shisad.interop.mcp_client import McpClientManager
from shisad.interop.mcp_tools import McpDiscoveredTool, mcp_tool_to_registry_entry
from shisad.security.control_plane.schema import ActionKind, ControlDecision, RiskTier
from tests.helpers.mcp import reserve_local_port, running_http_mcp_server, write_mock_mcp_server


class _EventCollector:
    def __init__(self) -> None:
        self.events: list[object] = []

    async def publish(self, event: object) -> None:
        self.events.append(event)


class _ExecutionRecorder:
    def __init__(self) -> None:
        self.results: list[bool] = []

    def record_execution(self, *, action: object, success: bool) -> None:
        _ = action
        self.results.append(success)


class _NoopRateLimiter:
    def consume(self, *, session_id: str, user_id: str, tool_name: str) -> None:
        _ = (session_id, user_id, tool_name)


class _McpManagerStub:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = dict(payload)
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    async def call_tool(
        self,
        server_name: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        self.calls.append((server_name, tool_name, dict(arguments)))
        return dict(self._payload)


class _McpExecutionHarness:
    def __init__(self, *, payload: dict[str, Any]) -> None:
        self._session_manager = SessionManager()
        self._session = self._session_manager.create(
            channel="cli",
            user_id=UserId("alice"),
            workspace_id=WorkspaceId("ws-1"),
            metadata={"trust_level": "trusted"},
        )
        self._config = SimpleNamespace(checkpoint_trigger="never")
        self._rate_limiter = _NoopRateLimiter()
        self._event_bus = _EventCollector()
        self._control_plane = _ExecutionRecorder()
        self._mcp_manager = _McpManagerStub(payload)
        self._registry = SimpleNamespace(
            get_tool=lambda _tool_name: ToolDefinition(
                name=ToolName("mcp.docs.lookup-doc"),
                description="Lookup external docs.",
                parameters=[
                    ToolParameter(name="query", type="string", required=True),
                    ToolParameter(name="limit", type="integer", required=False),
                ],
                registration_source="mcp",
                registration_source_id="docs",
                upstream_tool_name="lookup-doc",
            )
        )

    @property
    def session_id(self) -> SessionId:
        return self._session.id

    def _origin_for(
        self,
        *,
        session: Session,
        actor: str,
        skill_name: str = "",
        task_id: str = "",
    ) -> Any:
        from shisad.security.control_plane.schema import Origin

        return Origin(
            session_id=str(session.id),
            user_id=str(session.user_id),
            workspace_id=str(session.workspace_id),
            actor=actor,
            channel=str(session.channel),
            trust_level=str(session.metadata.get("trust_level", "untrusted")),
            skill_name=skill_name,
            task_id=task_id,
        )

    @staticmethod
    def _sanitize_tool_output_text(raw: str) -> str:
        return raw


class _ControlPlaneStub:
    async def active_plan_hash(self, _sid: str) -> str:
        return ""

    async def begin_precontent_plan(self, **_kwargs: object) -> str:
        return "plan-1"

    async def evaluate_action(self, **_kwargs: object) -> object:
        return SimpleNamespace(
            decision=ControlDecision.ALLOW,
            reason_codes=[],
            trace_result=SimpleNamespace(
                allowed=True,
                reason_code="",
                risk_tier=RiskTier.LOW,
            ),
            consensus=SimpleNamespace(votes=[]),
            action=SimpleNamespace(
                action_kind=ActionKind.SHELL_EXEC,
                resource_id="mcp.docs.lookup-doc",
                resource_ids=[],
                origin=SimpleNamespace(model_dump=lambda mode="json": {}),
            ),
        )

    async def record_execution(self, *, action: object, success: bool) -> None:
        _ = (action, success)


class _McpToolExecuteHarness:
    def __init__(self, *, payload: dict[str, Any]) -> None:
        self._session_manager = SessionManager()
        self._session = self._session_manager.create(
            channel="cli",
            user_id=UserId("alice"),
            workspace_id=WorkspaceId("ws-1"),
            metadata={"trust_level": "trusted"},
        )
        self._registry = ToolRegistry()
        self._registry.register(
            ToolDefinition(
                name=ToolName("mcp.docs.lookup-doc"),
                description="Lookup external docs.",
                parameters=[
                    ToolParameter(name="query", type="string", required=True),
                    ToolParameter(name="limit", type="integer", required=False),
                ],
                registration_source="mcp",
                registration_source_id="docs",
                upstream_tool_name="lookup-doc",
            )
        )
        self._event_bus = _EventCollector()
        self._config = SimpleNamespace(
            assistant_fs_roots=[Path.cwd()],
            checkpoint_trigger="never",
        )
        self._rate_limiter = _NoopRateLimiter()
        self._mcp_manager = _McpManagerStub(payload)
        self._skill_manager = SimpleNamespace(
            authorize_runtime=lambda **_kwargs: SimpleNamespace(
                allowed=True,
                reason="",
                violations=[],
            )
        )
        self._policy_loader = SimpleNamespace(
            policy=SimpleNamespace(
                tools={},
                default_require_confirmation=False,
                sandbox=SimpleNamespace(fail_closed_security_critical=False),
                control_plane=SimpleNamespace(
                    trace=SimpleNamespace(ttl_seconds=300, max_actions=8, allow_amendment=True),
                    egress=SimpleNamespace(wildcard_rollout_phase="monitor"),
                ),
            )
        )
        self._lockdown_manager = SimpleNamespace(
            apply_capability_restrictions=lambda _sid, capabilities: capabilities
        )
        self._control_plane = _ControlPlaneStub()

    @property
    def session_id(self) -> SessionId:
        return self._session.id

    def _origin_for(
        self,
        *,
        session: Session,
        actor: str,
        skill_name: str = "",
        task_id: str = "",
    ) -> Any:
        from shisad.security.control_plane.schema import Origin

        return Origin(
            session_id=str(session.id),
            user_id=str(session.user_id),
            workspace_id=str(session.workspace_id),
            actor=actor,
            channel=str(session.channel),
            trust_level=str(session.metadata.get("trust_level", "untrusted")),
            skill_name=skill_name,
            task_id=task_id,
        )

    async def _prepare_browser_tool_arguments(
        self,
        *,
        session: Session,
        tool_name: ToolName,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        _ = (session, tool_name)
        return dict(arguments)

    def _risk_tier_for_tool_execute(
        self,
        *,
        network_enabled: bool,
        write_paths: list[str],
        security_critical: bool,
    ) -> RiskTier:
        _ = (network_enabled, write_paths, security_critical)
        return RiskTier.LOW

    def _build_merged_policy(self, **_kwargs: object) -> object:
        return SimpleNamespace(
            network=SimpleNamespace(allow_network=False, allowed_domains=[]),
            security_critical=False,
        )

    async def _publish_control_plane_evaluation(self, **_kwargs: object) -> None:
        return None

    @staticmethod
    def _merge_tool_arguments(params: dict[str, Any] | Any) -> dict[str, Any]:
        return HandlerImplementation._merge_tool_arguments(params)

    def _operator_confirmation_requirement(self, **kwargs: Any) -> Any:
        return HandlerImplementation._operator_confirmation_requirement(self, **kwargs)  # type: ignore[arg-type]

    async def _execute_approved_action(self, **kwargs: Any) -> Any:
        return await HandlerImplementation._execute_approved_action(self, **kwargs)  # type: ignore[arg-type]

    def _tool_execute_result_from_execution(self, **kwargs: Any) -> dict[str, Any]:
        return HandlerImplementation._tool_execute_result_from_execution(self, **kwargs)  # type: ignore[arg-type]

    @staticmethod
    def _sanitize_tool_output_text(raw: str) -> str:
        return raw


def test_i1_daemon_config_accepts_json_encoded_mcp_servers() -> None:
    config = DaemonConfig(
        mcp_servers=(
            '[{"name":"docs","transport":"stdio","command":["python","server.py"]},'
            '{"name":"wiki","transport":"http","url":"http://127.0.0.1:9000/mcp"}]'
        )
    )

    assert len(config.mcp_servers) == 2
    assert isinstance(config.mcp_servers[0], McpStdioServerConfig)
    assert config.mcp_servers[0].command == ["python", "server.py"]
    assert isinstance(config.mcp_servers[1], McpHttpServerConfig)
    assert config.mcp_servers[1].url == "http://127.0.0.1:9000/mcp"


def test_i1_daemon_config_rejects_duplicate_mcp_server_names() -> None:
    with pytest.raises(ValidationError, match="unique"):
        DaemonConfig(
            mcp_servers=[
                {"name": "docs", "transport": "stdio", "command": ["python", "server.py"]},
                {"name": "docs", "transport": "http", "url": "http://127.0.0.1:9000/mcp"},
            ]
        )


def test_i1_tool_registry_rejects_external_registration_metadata_in_local_files(
    tmp_path: Path,
) -> None:
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    (tools_dir / "lookup-doc.json").write_text(
        json.dumps(
            {
                "name": "lookup.doc",
                "description": "Lookup docs.",
                "registration_source": "mcp",
                "registration_source_id": "docs",
            }
        ),
        encoding="utf-8",
    )

    registry = ToolRegistry()

    with pytest.raises(ValueError, match="external registration metadata"):
        registry.load_from_directory(tools_dir)


def test_i1_mcp_tool_translation_preserves_upstream_name_and_namespace() -> None:
    entry = mcp_tool_to_registry_entry(
        McpDiscoveredTool(
            name="lookup-doc",
            description="Lookup remote documentation.",
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                    "limit": {"type": "integer"},
                },
                "required": ["query"],
            },
        ),
        server_name="docs",
    )

    assert entry.name == ToolName("mcp.docs.lookup-doc")
    assert entry.registration_source == "mcp"
    assert entry.registration_source_id == "docs"
    assert entry.upstream_tool_name == "lookup-doc"
    assert entry.require_confirmation is True
    assert [parameter.name for parameter in entry.parameters] == ["query", "limit"]
    assert entry.parameters[0].required is True
    assert entry.parameters[1].required is False


def test_i1_mcp_tool_translation_preserves_non_string_enum_values() -> None:
    entry = mcp_tool_to_registry_entry(
        McpDiscoveredTool(
            name="pick-mode",
            description="Pick a mode.",
            input_schema={
                "type": "object",
                "properties": {
                    "mode": {
                        "type": "integer",
                        "enum": [1, 2],
                    }
                },
                "required": ["mode"],
            },
        ),
        server_name="docs",
    )
    registry = ToolRegistry()
    registry.register(entry)

    assert entry.parameters[0].enum == [1, 2]
    assert registry.validate_call(entry.name, {"mode": 1}) == []
    assert registry.validate_call(entry.name, {"mode": "1"}) == [
        "Argument 'mode': expected type 'integer', got 'str'"
    ]


def test_i1_tool_registry_rejects_provider_alias_collisions() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("mcp.alpha.beta.lookup"),
            description="First tool",
            registration_source="mcp",
            registration_source_id="alpha.beta",
            upstream_tool_name="lookup",
        )
    )

    with pytest.raises(ValueError, match="provider alias collision"):
        registry.register(
            ToolDefinition(
                name=ToolName("mcp.alpha_beta.lookup"),
                description="Second tool",
                registration_source="mcp",
                registration_source_id="alpha_beta",
                upstream_tool_name="lookup",
            )
        )


def test_i1_planner_context_marks_mcp_tools_as_external_and_untrusted() -> None:
    context = _build_planner_tool_context(
        registry_tools=[
            ToolDefinition(
                name=ToolName("mcp.docs.lookup-doc"),
                description="Lookup external docs.",
                parameters=[ToolParameter(name="query", type="string", required=True)],
                registration_source="mcp",
                registration_source_id="docs",
                upstream_tool_name="lookup-doc",
            )
        ],
        capabilities=set(),
        tool_allowlist=None,
        trust_level="trusted",
    )

    assert "trusted runtime manifest" not in context
    assert "external/untrusted" in context
    assert "mcp.docs.lookup-doc" in context
    assert "upstream tool: lookup-doc" in context


@pytest.mark.asyncio
async def test_i1_mcp_stdio_manager_discovers_registers_calls_and_unregisters(
    tmp_path: Path,
) -> None:
    server_script = write_mock_mcp_server(tmp_path / "mock_mcp_server.py")
    registry = ToolRegistry()
    manager = McpClientManager(
        server_configs=[
            McpStdioServerConfig(
                name="docs",
                command=[sys.executable, str(server_script)],
                timeout_seconds=10.0,
            )
        ],
        tool_registry=registry,
    )

    await manager.connect_all()
    try:
        discovered = await manager.discover_tools("docs")
        assert [tool.name for tool in discovered] == ["lookup-doc", "sleepy", "env-snapshot"]

        runtime_tool = registry.get_tool(ToolName("mcp.docs.lookup-doc"))
        assert runtime_tool is not None
        assert runtime_tool.registration_source == "mcp"
        assert runtime_tool.registration_source_id == "docs"
        assert runtime_tool.upstream_tool_name == "lookup-doc"

        result = await manager.call_tool(
            "docs",
            "lookup-doc",
            {"query": "roadmap", "limit": 4},
        )
        assert result["ok"] is True
        assert result["structured_content"] == {
            "answer": "echo:roadmap",
            "limit": 4,
            "query": "roadmap",
        }
        assert result["content"][0]["type"] == "text"
        assert "roadmap" in result["content"][0]["text"]
    finally:
        await manager.shutdown()

    assert registry.has_tool(ToolName("mcp.docs.lookup-doc")) is False


@pytest.mark.asyncio
async def test_i1_mcp_http_manager_discovers_tools(tmp_path: Path) -> None:
    server_script = write_mock_mcp_server(tmp_path / "mock_mcp_server.py")
    port = reserve_local_port()
    registry = ToolRegistry()

    with running_http_mcp_server(server_script, port=port):
        manager = McpClientManager(
            server_configs=[
                McpHttpServerConfig(
                    name="docs-http",
                    url=f"http://127.0.0.1:{port}/mcp",
                    timeout_seconds=10.0,
                )
            ],
            tool_registry=registry,
        )
        await manager.connect_all()
        try:
            discovered = await manager.discover_tools("docs-http")
            assert [tool.name for tool in discovered] == ["lookup-doc", "sleepy", "env-snapshot"]
            assert registry.has_tool(ToolName("mcp.docs-http.lookup-doc")) is True
        finally:
            await manager.shutdown()


@pytest.mark.asyncio
async def test_i1_mcp_connection_failure_is_actionable() -> None:
    manager = McpClientManager(
        server_configs=[
            McpStdioServerConfig(
                name="broken-stdio",
                command=["definitely-not-a-command"],
                timeout_seconds=1.0,
            )
        ]
    )

    with pytest.raises(RuntimeError, match="broken-stdio"):
        await manager.connect_all()


@pytest.mark.asyncio
async def test_i1_mcp_call_timeout_is_actionable(tmp_path: Path) -> None:
    server_script = write_mock_mcp_server(tmp_path / "mock_mcp_server.py")
    manager = McpClientManager(
        server_configs=[
            McpStdioServerConfig(
                name="docs",
                command=[sys.executable, str(server_script)],
                timeout_seconds=10.0,
            )
        ]
    )

    await manager.connect_all()
    try:
        with pytest.raises(RuntimeError, match="timed out"):
            await manager.call_tool(
                "docs",
                "sleepy",
                {"query": "roadmap", "delay_seconds": 15.0},
            )
    finally:
        await manager.shutdown()


@pytest.mark.asyncio
async def test_i1_mcp_stdio_manager_does_not_inherit_secret_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "super-secret-key")
    server_script = write_mock_mcp_server(tmp_path / "mock_mcp_server.py")
    manager = McpClientManager(
        server_configs=[
            McpStdioServerConfig(
                name="docs",
                command=[sys.executable, str(server_script)],
                env={"MCP_VISIBLE_FLAG": "visible"},
                timeout_seconds=10.0,
            )
        ]
    )

    await manager.connect_all()
    try:
        secret_result = await manager.call_tool(
            "docs",
            "env-snapshot",
            {"name": "OPENAI_API_KEY"},
        )
        override_result = await manager.call_tool(
            "docs",
            "env-snapshot",
            {"name": "MCP_VISIBLE_FLAG"},
        )
    finally:
        await manager.shutdown()

    assert secret_result["structured_content"] == {"name": "OPENAI_API_KEY", "value": None}
    assert override_result["structured_content"] == {"name": "MCP_VISIBLE_FLAG", "value": "visible"}


@pytest.mark.asyncio
async def test_i1_execute_approved_action_uses_upstream_mcp_tool_name() -> None:
    harness = _McpExecutionHarness(
        payload={
            "ok": True,
            "structured_content": {"answer": "echo:roadmap"},
            "content": [{"type": "text", "text": "echo:roadmap"}],
        }
    )

    result = await HandlerImplementation._execute_approved_action(
        harness,  # type: ignore[arg-type]
        sid=harness.session_id,
        user_id=UserId("alice"),
        tool_name=ToolName("mcp.docs.lookup-doc"),
        arguments={"query": "roadmap"},
        capabilities=set(),
        approval_actor="control_api",
    )

    assert result.success is True
    assert result.tool_output is not None
    payload = json.loads(result.tool_output.content)
    assert payload["structured_content"] == {"answer": "echo:roadmap"}
    assert harness._mcp_manager.calls == [("docs", "lookup-doc", {"query": "roadmap"})]
    assert harness._control_plane.results == [True]
    assert any(isinstance(event, ToolApproved) for event in harness._event_bus.events)
    assert any(
        isinstance(event, ToolExecuted) and event.success for event in harness._event_bus.events
    )


@pytest.mark.asyncio
async def test_i1_tool_execute_path_strips_reserved_keys_before_mcp_call() -> None:
    harness = _McpToolExecuteHarness(
        payload={
            "ok": True,
            "structured_content": {"answer": "echo:roadmap", "limit": 4, "query": "roadmap"},
            "content": [{"type": "text", "text": "echo:roadmap"}],
        }
    )

    result = await HandlerImplementation.do_tool_execute(
        harness,  # type: ignore[arg-type]
        {
            "session_id": str(harness.session_id),
            "tool_name": "mcp.docs.lookup-doc",
            "command": ["mcp"],
            "arguments": {"query": "roadmap", "limit": 4},
            "security_critical": False,
            "degraded_mode": "fail_open",
        },
    )

    assert result["allowed"] is True
    payload = json.loads(str(result["stdout"]))
    assert payload["structured_content"] == {
        "answer": "echo:roadmap",
        "limit": 4,
        "query": "roadmap",
    }
    assert harness._mcp_manager.calls == [("docs", "lookup-doc", {"query": "roadmap", "limit": 4})]
