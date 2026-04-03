"""Unit checks for shared execution helper extraction (M4 RF.3.5.3)."""

from __future__ import annotations

import json

import pytest

from shisad.core.events import ToolExecuted
from shisad.core.tools.schema import ToolDefinition
from shisad.core.types import SessionId, TaintLabel, ToolName
from shisad.daemon.handlers._impl import HandlerImplementation
from shisad.daemon.handlers._tool_exec_helpers import execute_structured_tool
from shisad.executors.mounts import FilesystemPolicy
from shisad.executors.proxy import NetworkPolicy
from shisad.executors.sandbox import (
    DegradedModePolicy,
    EnvironmentPolicy,
    ResourceLimits,
    SandboxConfig,
    SandboxType,
)
from shisad.governance.merge import PolicyMerge, ToolExecutionPolicy, normalize_patch
from shisad.security.control_plane.schema import Origin


def _floor_policy() -> ToolExecutionPolicy:
    return ToolExecutionPolicy(
        sandbox_type=SandboxType.NSJAIL,
        network=NetworkPolicy(
            allow_network=True,
            allowed_domains=["example.com"],
            deny_private_ranges=True,
            deny_ip_literals=True,
        ),
        filesystem=FilesystemPolicy(mounts=[{"path": "/repo", "mode": "ro"}]),
        environment=EnvironmentPolicy(
            allowed_keys=["PATH"],
            denied_prefixes=["SECRET_"],
            max_keys=8,
            max_total_bytes=4096,
        ),
        limits=ResourceLimits(
            cpu_shares=128,
            memory_mb=256,
            timeout_seconds=10,
            output_bytes=2048,
            pids=32,
        ),
        degraded_mode=DegradedModePolicy.FAIL_CLOSED,
        security_critical=True,
    )


def test_m4_rf353_build_merged_policy_matches_direct_policy_merge() -> None:
    floor = _floor_policy()
    calls: list[tuple[str, bool]] = []

    class _Harness:
        def _compute_tool_policy_floor(
            self,
            *,
            tool_name: ToolName,
            tool_definition: ToolDefinition | None,
            operator_surface: bool = False,
        ) -> ToolExecutionPolicy:
            _ = tool_definition
            calls.append((str(tool_name), operator_surface))
            return floor

    harness = _Harness()
    tool = ToolDefinition(name=ToolName("shell.exec"), description="shell")
    arguments = {
        "command": ["echo", "ok"],
        "network": {"allowed_domains": ["example.com", "other.example"]},
        "degraded_mode": "fail_open",
        "security_critical": False,
    }
    merged = HandlerImplementation._build_merged_policy(  # type: ignore[misc]
        harness,  # type: ignore[arg-type]
        tool_name=ToolName("shell.exec"),
        arguments=arguments,
        tool_definition=tool,
        operator_surface=True,
    )
    expected = PolicyMerge.merge(server=floor, caller=normalize_patch(arguments))
    assert merged.model_dump(mode="json") == expected.model_dump(mode="json")
    assert calls == [("shell.exec", True)]


def test_m4_rf353_build_sandbox_config_keeps_runtime_parity_fields() -> None:
    merged = _floor_policy()
    params = {
        "command": ["echo", "ok"],
        "read_paths": ["/repo/README.md"],
        "write_paths": [],
        "network_urls": ["https://example.com"],
        "env": {"PATH": "/usr/bin"},
        "request_headers": {"accept": "application/json"},
        "request_body": "",
        "cwd": "/repo",
    }
    origin = Origin(
        session_id="s-1",
        user_id="alice",
        workspace_id="ws-1",
        actor="planner",
        trust_level="trusted",
        channel="cli",
    )

    config = HandlerImplementation._build_sandbox_config(
        sid="s-1",
        tool_name="shell.exec",
        params=params,
        merged_policy=merged,
        origin=origin,
        approved_by_pep=True,
    )
    expected = SandboxConfig(
        session_id="s-1",
        tool_name="shell.exec",
        command=["echo", "ok"],
        read_paths=["/repo/README.md"],
        write_paths=[],
        network_urls=["https://example.com"],
        env={"PATH": "/usr/bin"},
        request_headers={"accept": "application/json"},
        request_body="",
        cwd="/repo",
        sandbox_type=merged.sandbox_type,
        security_critical=merged.security_critical,
        approved_by_pep=True,
        filesystem=merged.filesystem,
        network=merged.network,
        environment=merged.environment,
        limits=merged.limits,
        degraded_mode=merged.degraded_mode,
        origin=origin.model_dump(mode="json"),
    )
    assert isinstance(config, SandboxConfig)
    assert config.model_dump(mode="json") == expected.model_dump(mode="json")


@pytest.mark.asyncio
async def test_h1_execute_structured_tool_awaits_async_record_execution_callback() -> None:
    events: list[object] = []
    recorded: list[bool] = []

    async def _emit(event: object) -> None:
        events.append(event)

    async def _record(success: bool) -> None:
        recorded.append(success)

    result = await execute_structured_tool(
        session_id=SessionId("sess-h1"),
        tool_name=ToolName("web.fetch"),
        payload={"ok": True, "content": "body", "taint_labels": ["untrusted"]},
        default_error="web_fetch_failed",
        actor="tool_runtime",
        emit_event=_emit,
        record_execution=_record,
        sanitize_output=lambda raw: raw,
        taint_labels={TaintLabel.UNTRUSTED},
    )

    assert result.success is True
    assert json.loads(result.content)["ok"] is True
    assert recorded == [True]
    assert any(isinstance(event, ToolExecuted) for event in events)
    assert result.taint_labels == {TaintLabel.UNTRUSTED}
