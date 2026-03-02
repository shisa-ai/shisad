"""M4 task-ledger scaffold and delegation-advisory integration checks."""

from __future__ import annotations

import asyncio
import textwrap
from contextlib import suppress
from pathlib import Path

import pytest

from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.core.planner import (
    ActionProposal,
    EvaluatedProposal,
    Planner,
    PlannerOutput,
    PlannerResult,
)
from shisad.core.types import ToolName
from shisad.daemon.runner import run_daemon


async def _wait_for_socket(path: Path, timeout: float = 2.0) -> None:
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if path.exists():
            return
        await asyncio.sleep(0.01)
    raise TimeoutError(f"Timed out waiting for socket {path}")


@pytest.mark.asyncio
async def test_m4_cs6_task_ledger_status_metadata_is_in_planner_scaffold(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")

    captured_inputs: list[str] = []

    async def _capture_propose(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
    ) -> PlannerResult:
        _ = (self, context, tools)
        captured_inputs.append(user_content)
        return PlannerResult(
            output=PlannerOutput(actions=[], assistant_response="ok"),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _capture_propose)

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: "1"
            default_require_confirmation: false
            default_capabilities:
              - memory.read
            """
        ).strip()
        + "\n"
    )
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        log_level="INFO",
    )

    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()

        first_task = await client.call(
            "task.create",
            {
                "schedule": {
                    "kind": "event",
                    "expression": "message.received",
                    "event_type": "message.received",
                    "event_filter": {},
                },
                "name": "daily-summary",
                "goal": "summarize daily updates",
                "policy_snapshot_ref": "policy-1",
                "created_by": "alice",
                "workspace_id": "ws1",
            },
        )
        second_task = await client.call(
            "task.create",
            {
                "schedule": {
                    "kind": "interval",
                    "expression": "1h",
                },
                "name": "weekly-digest",
                "goal": "digest weekly changes",
                "policy_snapshot_ref": "policy-1",
                "created_by": "alice",
                "workspace_id": "ws1",
            },
        )
        runs = await client.call(
            "task.trigger_event",
            {"event_type": "message.received", "payload": "ping"},
        )
        assert runs["queued_confirmations"] >= 1

        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = created["session_id"]
        await client.call(
            "session.message",
            {
                "session_id": sid,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "content": "what's the current status?",
            },
        )
        assert captured_inputs
        prompt = captured_inputs[-1]
        assert "task_status_total=2" in prompt
        assert "task_confirmation_needed_total=1" in prompt
        assert f"task_id={first_task['id']}" in prompt
        assert f"task_id={second_task['id']}" in prompt
        assert "trust=TRUSTED provenance=task:" in prompt
        assert "trust=SEMI_TRUSTED provenance=task:" in prompt
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_m4_cs6_task_ledger_snapshot_is_scoped_by_user_and_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")

    captured_inputs: list[str] = []

    async def _capture_propose(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
    ) -> PlannerResult:
        _ = (self, context, tools)
        captured_inputs.append(user_content)
        return PlannerResult(
            output=PlannerOutput(actions=[], assistant_response="ok"),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _capture_propose)

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: "1"
            default_require_confirmation: false
            default_capabilities:
              - memory.read
            """
        ).strip()
        + "\n"
    )
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        log_level="INFO",
    )

    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()

        alice_ws1 = await client.call(
            "task.create",
            {
                "schedule": {
                    "kind": "event",
                    "expression": "message.received",
                    "event_type": "message.received",
                    "event_filter": {},
                },
                "name": "alice-ws1-task",
                "goal": "goal one",
                "policy_snapshot_ref": "policy-1",
                "created_by": "alice",
                "workspace_id": "ws1",
            },
        )
        alice_ws2 = await client.call(
            "task.create",
            {
                "schedule": {
                    "kind": "event",
                    "expression": "message.received",
                    "event_type": "message.received",
                    "event_filter": {},
                },
                "name": "alice-ws2-task",
                "goal": "goal two",
                "policy_snapshot_ref": "policy-1",
                "created_by": "alice",
                "workspace_id": "ws2",
            },
        )
        bob_ws1 = await client.call(
            "task.create",
            {
                "schedule": {
                    "kind": "event",
                    "expression": "message.received",
                    "event_type": "message.received",
                    "event_filter": {},
                },
                "name": "bob-ws1-task",
                "goal": "goal three",
                "policy_snapshot_ref": "policy-1",
                "created_by": "bob",
                "workspace_id": "ws1",
            },
        )

        alice_session = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        await client.call(
            "session.message",
            {
                "session_id": alice_session["session_id"],
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "content": "show task status",
            },
        )
        assert captured_inputs
        alice_prompt = captured_inputs[-1]
        assert f"task_id={alice_ws1['id']}" in alice_prompt
        assert f"task_id={alice_ws2['id']}" not in alice_prompt
        assert f"task_id={bob_ws1['id']}" not in alice_prompt
        assert "task_status_total=1" in alice_prompt

        bob_session = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "bob", "workspace_id": "ws1"},
        )
        await client.call(
            "session.message",
            {
                "session_id": bob_session["session_id"],
                "channel": "cli",
                "user_id": "bob",
                "workspace_id": "ws1",
                "content": "show task status",
            },
        )
        bob_prompt = captured_inputs[-1]
        assert f"task_id={bob_ws1['id']}" in bob_prompt
        assert f"task_id={alice_ws1['id']}" not in bob_prompt
        assert f"task_id={alice_ws2['id']}" not in bob_prompt
        assert "task_status_total=1" in bob_prompt
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_m4_cs9_delegation_advisory_emits_telemetry_without_enforcement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")

    async def _multi_tool_propose(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
    ) -> PlannerResult:
        _ = (user_content, tools)
        proposal_one = ActionProposal(
            action_id="m4-delegate-1",
            tool_name=ToolName("retrieve_rag"),
            arguments={"query": "one", "top_k": 1},
            reasoning="collect first evidence",
            data_sources=[],
        )
        proposal_two = ActionProposal(
            action_id="m4-delegate-2",
            tool_name=ToolName("retrieve_rag"),
            arguments={"query": "two", "top_k": 1},
            reasoning="collect second evidence",
            data_sources=[],
        )
        decision_one = self._pep.evaluate(proposal_one.tool_name, proposal_one.arguments, context)
        decision_two = self._pep.evaluate(proposal_two.tool_name, proposal_two.arguments, context)
        return PlannerResult(
            output=PlannerOutput(
                actions=[proposal_one, proposal_two],
                assistant_response="Gathering evidence.",
            ),
            evaluated=[
                EvaluatedProposal(proposal=proposal_one, decision=decision_one),
                EvaluatedProposal(proposal=proposal_two, decision=decision_two),
            ],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _multi_tool_propose)

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: "1"
            default_require_confirmation: false
            default_capabilities:
              - memory.read
            """
        ).strip()
        + "\n"
    )
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        log_level="INFO",
    )

    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()

        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = created["session_id"]

        reply = await client.call(
            "session.message",
            {
                "session_id": sid,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "content": "collect two quick memory lookups",
            },
        )
        assert reply["session_id"] == sid
        telemetry = await client.call(
            "audit.query",
            {"event_type": "TaskDelegationAdvisory", "session_id": sid, "limit": 5},
        )
        assert telemetry["total"] >= 1
        latest = telemetry["events"][0]["data"]
        assert latest["delegate"] is True
        assert latest["action_count"] == 2
        assert "multi_action_batch" in latest["reason_codes"]
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)
