"""v0.4 M2 delegated TASK-session isolation integration checks."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.core.planner import Planner, PlannerOutput, PlannerResult
from shisad.daemon.runner import run_daemon


async def _wait_for_socket(path: Path, timeout: float = 2.0) -> None:
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if path.exists():
            return
        await asyncio.sleep(0.01)
    raise TimeoutError(f"Timed out waiting for socket {path}")


async def _start_daemon(
    tmp_path: Path,
    *,
    policy_text: str,
) -> tuple[asyncio.Task[None], ControlClient]:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(policy_text, encoding="utf-8")
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        log_level="INFO",
    )
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    await _wait_for_socket(config.socket_path)
    await client.connect()
    return daemon_task, client


async def _shutdown_daemon(daemon_task: asyncio.Task[None], client: ControlClient) -> None:
    with suppress(Exception):
        await client.call("daemon.shutdown")
    await client.close()
    await asyncio.wait_for(daemon_task, timeout=3)


async def _wait_for_event(
    client: ControlClient,
    *,
    event_type: str,
    predicate: Any,
    timeout: float = 4.0,
) -> dict[str, Any]:
    end = asyncio.get_running_loop().time() + timeout
    latest: list[dict[str, Any]] = []
    while asyncio.get_running_loop().time() < end:
        result = await client.call("audit.query", {"event_type": event_type, "limit": 50})
        latest = [dict(event) for event in result.get("events", [])]
        for event in latest:
            if predicate(event):
                return event
        await asyncio.sleep(0.1)
    raise AssertionError(f"Timed out waiting for {event_type}: {latest}")


def _policy_with_caps(
    *caps: str,
    tool_allowlist: tuple[str, ...] = (),
) -> str:
    lines = [
        'version: "1"',
        "default_require_confirmation: false",
        "default_capabilities:",
        *[f"  - {cap}" for cap in caps],
    ]
    if tool_allowlist:
        lines.append("session_tool_allowlist:")
        lines.extend(f"  - {tool}" for tool in tool_allowlist)
    return "\n".join(lines) + "\n"


@pytest.mark.asyncio
async def test_m2_task_session_isolates_command_context_and_returns_structured_handoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_inputs: list[str] = []

    async def _planner(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (self, context, tools, persona_tone_override)
        captured_inputs.append(user_content)
        return PlannerResult(
            output=PlannerOutput(assistant_response="Task summary ready.", actions=[]),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _planner)
    daemon_task, client = await _start_daemon(
        tmp_path,
        policy_text=_policy_with_caps("memory.read", "file.read"),
    )
    try:
        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = str(created["session_id"])

        await client.call(
            "session.message",
            {"session_id": sid, "content": "hello from command history"},
        )
        await client.call(
            "memory.ingest",
            {
                "source_id": "m2-canary",
                "source_type": "external",
                "collection": "project_docs",
                "content": "MEMORY CANARY: delegated TASK sessions must not see this",
            },
        )

        result = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "run delegated review",
                "task": {
                    "enabled": True,
                    "task_description": "Review README.md in isolation.",
                    "file_refs": ["README.md"],
                    "capabilities": ["file.read"],
                },
            },
        )

        task_result = dict(result.get("task_result") or {})
        completed_event = await _wait_for_event(
            client,
            event_type="TaskSessionCompleted",
            predicate=lambda item: str(item.get("session_id", "")).strip()
            == str(task_result.get("task_session_id", "")).strip(),
        )

        assert task_result["success"] is True
        assert task_result["handoff_mode"] == "summary_only"
        assert task_result["raw_log_ref"]
        assert completed_event["data"]["parent_session_id"] == sid
        assert "hello from command history" not in captured_inputs[-1]
        assert "MEMORY CANARY" not in captured_inputs[-1]
        assert "MEMORY CONTEXT" not in captured_inputs[-1]
        assert "README.md" in captured_inputs[-1]

        sessions = await client.call("session.list")
        active_ids = {str(item["id"]) for item in sessions["sessions"]}
        assert str(task_result["task_session_id"]) not in active_ids
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_m2_raw_task_handoff_marks_command_degraded_and_recovery_checkpoint_is_rollbackable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _planner(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (self, context, tools, persona_tone_override)
        return PlannerResult(
            output=PlannerOutput(
                assistant_response="RAW TASK LOG\n--- a/README.md\n+++ b/README.md\n+secret",
                actions=[],
            ),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _planner)
    daemon_task, client = await _start_daemon(
        tmp_path,
        policy_text=_policy_with_caps("file.read"),
    )
    try:
        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "admin", "workspace_id": "ops"},
        )
        sid = str(created["session_id"])

        delegated = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "debug the raw task output",
                "task": {
                    "enabled": True,
                    "task_description": "Return the raw task log.",
                    "file_refs": ["README.md"],
                    "capabilities": ["file.read"],
                    "handoff_mode": "raw_passthrough",
                },
            },
        )
        task_result = dict(delegated.get("task_result") or {})
        checkpoint_id = str(task_result.get("recovery_checkpoint_id", "")).strip()
        assert checkpoint_id

        degraded_event = await _wait_for_event(
            client,
            event_type="CommandContextDegraded",
            predicate=lambda item: str(item.get("session_id", "")).strip() == sid,
        )
        assert degraded_event["data"]["recovery_checkpoint_id"] == checkpoint_id

        sessions = await client.call("session.list")
        session_row = next(item for item in sessions["sessions"] if item["id"] == sid)
        assert session_row["command_context"] == "degraded"
        assert session_row["recovery_checkpoint_id"] == checkpoint_id

        set_mode = await client.call(
            "session.set_mode",
            {"session_id": sid, "mode": "admin_cleanroom"},
        )
        assert set_mode["changed"] is False
        assert set_mode["reason"] == "command_context_degraded"

        delegated_again = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "debug the raw task output again",
                "task": {
                    "enabled": True,
                    "task_description": "Return the raw task log again.",
                    "file_refs": ["README.md"],
                    "capabilities": ["file.read"],
                    "handoff_mode": "raw_passthrough",
                },
            },
        )
        task_result_again = dict(delegated_again.get("task_result") or {})
        assert task_result_again["recovery_checkpoint_id"] == checkpoint_id

        degraded_events = await client.call(
            "audit.query",
            {"event_type": "CommandContextDegraded", "session_id": sid, "limit": 10},
        )
        matching_events = [
            event
            for event in degraded_events.get("events", [])
            if str(event.get("session_id", "")).strip() == sid
        ]
        assert len(matching_events) == 1

        rolled_back = await client.call("session.rollback", {"checkpoint_id": checkpoint_id})
        assert rolled_back["rolled_back"] is True

        sessions_after = await client.call("session.list")
        restored_row = next(item for item in sessions_after["sessions"] if item["id"] == sid)
        assert restored_row["command_context"] == "clean"
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_m2_task_session_timeout_cleans_up_ephemeral_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _slow_planner(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (self, user_content, context, tools, persona_tone_override)
        await asyncio.sleep(0.2)
        return PlannerResult(
            output=PlannerOutput(assistant_response="late result", actions=[]),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _slow_planner)
    daemon_task, client = await _start_daemon(
        tmp_path,
        policy_text=_policy_with_caps("file.read"),
    )
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = str(created["session_id"])
        result = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "run delegated task with timeout",
                "task": {
                    "enabled": True,
                    "task_description": "Take too long.",
                    "capabilities": ["file.read"],
                    "timeout_sec": 0.05,
                },
            },
        )

        task_result = dict(result.get("task_result") or {})
        assert task_result["success"] is False
        assert task_result["reason"] == "task_timeout"

        sessions = await client.call("session.list")
        active_ids = {str(item["id"]) for item in sessions["sessions"]}
        assert str(task_result["task_session_id"]) not in active_ids
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_m2_task_session_inherits_parent_allowlist_and_has_distinct_session_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    planner_entered = asyncio.Event()
    release_task = asyncio.Event()
    observed_tool_names: list[str] = []

    async def _planner(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (self, user_content, context, persona_tone_override)
        observed_tool_names[:] = [
            str(item.get("function", {}).get("name", ""))
            for item in (tools or [])
        ]
        planner_entered.set()
        await release_task.wait()
        return PlannerResult(
            output=PlannerOutput(assistant_response="task finished", actions=[]),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _planner)
    daemon_task, client = await _start_daemon(
        tmp_path,
        policy_text=_policy_with_caps(
            "file.read",
            "http.request",
            tool_allowlist=("fs.read",),
        ),
    )
    observer = ControlClient(tmp_path / "control.sock")
    await observer.connect()
    try:
        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = str(created["session_id"])

        message_task = asyncio.create_task(
            client.call(
                "session.message",
                {
                    "session_id": sid,
                    "content": "run delegated review",
                    "task": {
                        "enabled": True,
                        "task_description": "Review README.md in isolation.",
                        "file_refs": ["README.md"],
                        "capabilities": ["file.read", "http.request"],
                    },
                },
            )
        )

        started = await _wait_for_event(
            observer,
            event_type="TaskSessionStarted",
            predicate=lambda item: str(item.get("data", {}).get("parent_session_id", "")).strip()
            == sid,
        )
        task_sid = str(started.get("session_id", "")).strip()
        await asyncio.wait_for(planner_entered.wait(), timeout=2.0)

        sessions = await observer.call("session.list")
        parent_row = next(item for item in sessions["sessions"] if item["id"] == sid)
        task_row = next(item for item in sessions["sessions"] if item["id"] == task_sid)

        assert task_row["parent_session_id"] == sid
        assert task_row["session_key"] != parent_row["session_key"]
        assert set(observed_tool_names) == {"fs_read"}

        release_task.set()
        result = await message_task
        task_result = dict(result.get("task_result") or {})
        assert task_result["success"] is True
    finally:
        release_task.set()
        await observer.close()
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_m1_report_anomaly_manifest_tracks_orchestrator_vs_subagent_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_tool_names: list[str] = []
    task_tool_names: list[str] = []
    planner_entered = asyncio.Event()
    release_task = asyncio.Event()

    async def _planner(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (self, context, persona_tone_override)
        observed_tool_names = [
            str(item.get("function", {}).get("name", ""))
            for item in (tools or [])
        ]
        if "TASK REQUEST:" in user_content:
            task_tool_names[:] = observed_tool_names
            planner_entered.set()
            await release_task.wait()
        else:
            command_tool_names[:] = observed_tool_names
        return PlannerResult(
            output=PlannerOutput(assistant_response="task finished", actions=[]),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _planner)
    daemon_task, client = await _start_daemon(
        tmp_path,
        policy_text=_policy_with_caps("file.read"),
    )
    observer = ControlClient(tmp_path / "control.sock")
    await observer.connect()
    try:
        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = str(created["session_id"])

        _ = await client.call(
            "session.message",
            {"session_id": sid, "content": "hello"},
        )
        assert "report_anomaly" not in command_tool_names

        message_task = asyncio.create_task(
            client.call(
                "session.message",
                {
                    "session_id": sid,
                    "content": "run delegated review",
                    "task": {
                        "enabled": True,
                        "task_description": "Review README.md in isolation.",
                        "file_refs": ["README.md"],
                        "capabilities": ["file.read"],
                    },
                },
            )
        )

        started = await _wait_for_event(
            observer,
            event_type="TaskSessionStarted",
            predicate=lambda item: str(item.get("data", {}).get("parent_session_id", "")).strip()
            == sid,
        )
        task_sid = str(started.get("session_id", "")).strip()
        await asyncio.wait_for(planner_entered.wait(), timeout=2.0)

        sessions = await observer.call("session.list")
        parent_row = next(item for item in sessions["sessions"] if item["id"] == sid)
        task_row = next(item for item in sessions["sessions"] if item["id"] == task_sid)

        assert parent_row["role"] == "orchestrator"
        assert task_row["role"] == "subagent"
        assert "report_anomaly" in task_tool_names

        release_task.set()
        result = await message_task
        task_result = dict(result.get("task_result") or {})
        assert task_result["success"] is True
    finally:
        release_task.set()
        await observer.close()
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_m2_task_summary_obeys_output_firewall(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _planner(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (self, user_content, context, tools, persona_tone_override)
        return PlannerResult(
            output=PlannerOutput(
                assistant_response="See https://docs.python.org/3/ for details.",
                actions=[],
            ),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _planner)
    daemon_task, client = await _start_daemon(
        tmp_path,
        policy_text=_policy_with_caps("file.read"),
    )
    try:
        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = str(created["session_id"])
        result = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "run delegated summary",
                "task": {
                    "enabled": True,
                    "task_description": "Summarize README.md with a link.",
                    "file_refs": ["README.md"],
                    "capabilities": ["file.read"],
                },
            },
        )

        task_result = dict(result.get("task_result") or {})
        assert result["response"].startswith("[CONFIRMATION REQUIRED] ")
        assert task_result["summary"].startswith("[CONFIRMATION REQUIRED] ")
        assert "https://docs.python.org/3/" in task_result["summary"]
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_m2_task_session_cannot_reroute_to_admin_cleanroom(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _planner(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (self, context, tools, persona_tone_override)
        return PlannerResult(
            output=PlannerOutput(assistant_response="task stayed isolated", actions=[]),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _planner)
    daemon_task, client = await _start_daemon(
        tmp_path,
        policy_text=_policy_with_caps("file.read"),
    )
    try:
        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "admin", "workspace_id": "ops"},
        )
        sid = str(created["session_id"])
        result = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "install the signed behavior pack and update assistant behavior",
                "task": {
                    "enabled": True,
                    "task_description": (
                        "install the signed behavior pack and update assistant behavior"
                    ),
                    "capabilities": ["file.read"],
                },
            },
        )

        task_result = dict(result.get("task_result") or {})
        assert task_result["task_session_mode"] == "task"
        assert result["session_mode"] == "default"
        assert result["proposal_only"] is False
        assert task_result["success"] is True
    finally:
        await _shutdown_daemon(daemon_task, client)
