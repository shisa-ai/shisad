"""v0.4 M2 delegated TASK-session isolation integration checks."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

import shisad.daemon.handlers._impl_session as session_impl
import shisad.daemon.services as daemon_services
from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.core.events import EventBus, TaskSessionCompleted
from shisad.core.planner import (
    ActionProposal,
    EvaluatedProposal,
    Planner,
    PlannerOutput,
    PlannerResult,
)
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.transcript import TranscriptStore
from shisad.core.types import Capability, PEPDecision, PEPDecisionKind, ToolName
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


def _complete_close_gate_result() -> PlannerResult:
    return PlannerResult(
        output=PlannerOutput(
            assistant_response=(
                "SELF_CHECK_STATUS: COMPLETE\n"
                "SELF_CHECK_REASON: complete\n"
                "SELF_CHECK_NOTES: The task output completed the delegated request."
            ),
            actions=[],
        ),
        evaluated=[],
        attempts=1,
        provider_response=None,
        messages_sent=(),
    )


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
        if "TASK CLOSE-GATE SELF-CHECK" in user_content:
            return _complete_close_gate_result()
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
            predicate=lambda item: (
                str(item.get("session_id", "")).strip()
                == str(task_result.get("task_session_id", "")).strip()
            ),
        )

        assert task_result["success"] is True
        assert task_result["handoff_mode"] == "summary_only"
        assert task_result["raw_log_ref"]
        assert task_result["summary_checkpoint_ref"]
        assert task_result["self_check_status"] == "complete"
        assert task_result["self_check_ref"]
        assert task_result["taint_labels"] == ["untrusted"]
        assert completed_event["data"]["parent_session_id"] == sid
        assert completed_event["data"]["summary_checkpoint_ref"]
        assert completed_event["data"]["self_check_status"] == "complete"
        assert completed_event["data"]["self_check_ref"]
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
async def test_m4_task_summary_firewall_checkpoint_is_mandatory(
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
        if "TASK CLOSE-GATE SELF-CHECK" in user_content:
            return _complete_close_gate_result()
        return PlannerResult(
            output=PlannerOutput(assistant_response="Task summary ready.", actions=[]),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _planner)
    monkeypatch.setattr(
        session_impl.SessionImplMixin,
        "_build_task_summary_firewall_checkpoint",
        lambda *args, **kwargs: None,
    )
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
            predicate=lambda item: (
                str(item.get("session_id", "")).strip()
                == str(task_result.get("task_session_id", "")).strip()
            ),
        )

        assert task_result["success"] is False
        assert task_result["reason"] == "task_summary_firewall_checkpoint_failed"
        assert task_result["summary_checkpoint_ref"] in ("", None)
        assert "summary firewall" in task_result["summary"].lower()
        assert completed_event["data"]["reason"] == "task_summary_firewall_checkpoint_failed"
        assert completed_event["data"]["summary_checkpoint_ref"] == ""
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_m3_delegated_task_session_enforces_credential_scope_during_pep_evaluation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_build_tool_registry = daemon_services._build_tool_registry
    captured_decisions: list[str] = []

    def _build_tool_registry(*args: Any, **kwargs: Any):
        registry, alarm_tool = original_build_tool_registry(*args, **kwargs)
        registry.register(
            ToolDefinition(
                name=ToolName("email.fetch"),
                description="Fetch email with an explicit credential ref.",
                parameters=[
                    ToolParameter(name="url", type="string", required=True, semantic_type="url"),
                    ToolParameter(
                        name="credential_ref",
                        type="string",
                        required=True,
                        semantic_type="credential_ref",
                    ),
                ],
                capabilities_required=[Capability.HTTP_REQUEST],
                destinations=["mail.example.com"],
            )
        )
        return registry, alarm_tool

    async def _planner(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (user_content, tools, persona_tone_override)
        if "TASK CLOSE-GATE SELF-CHECK" in user_content:
            return _complete_close_gate_result()
        proposal = ActionProposal(
            action_id="a1",
            tool_name=ToolName("email.fetch"),
            arguments={
                "url": "https://mail.example.com/api/messages",
                "credential_ref": "mail_send",
            },
            reasoning="Validate delegated credential scope.",
        )
        decision = self._pep.evaluate(proposal.tool_name, proposal.arguments, context)
        captured_decisions.append(f"{decision.kind.value}:{decision.reason}")
        return PlannerResult(
            output=PlannerOutput(
                assistant_response="Delegated credential check finished.",
                actions=[proposal],
            ),
            evaluated=[EvaluatedProposal(proposal=proposal, decision=decision)],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(daemon_services, "_build_tool_registry", _build_tool_registry)
    monkeypatch.setattr(Planner, "propose", _planner)
    daemon_task, client = await _start_daemon(
        tmp_path,
        policy_text=_policy_with_caps("http.request"),
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
                "content": "run delegated mail review",
                "task": {
                    "enabled": True,
                    "task_description": "Fetch mail in isolation.",
                    "capabilities": ["http.request"],
                    "credential_refs": ["mail_read"],
                },
            },
        )

        task_result = dict(result.get("task_result") or {})

        assert task_result["task_session_id"]
        assert captured_decisions == [
            "reject:credential_ref 'mail_send' is out of scope for this task/session"
        ]
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_m4_task_approval_nonce_and_provenance_stay_bound_to_origin_task(
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
        if "TASK CLOSE-GATE SELF-CHECK" in user_content:
            return _complete_close_gate_result()
        proposal = ActionProposal(
            action_id="a1",
            tool_name=ToolName("message.send"),
            arguments={
                "channel": "session",
                "recipient": "session-target",
                "message": "queue a confirmation-bound delivery",
            },
            reasoning="Require confirmation for this delegated side effect.",
        )
        return PlannerResult(
            output=PlannerOutput(
                assistant_response="Delegated task queued a confirmation-bound delivery.",
                actions=[proposal],
            ),
            evaluated=[
                EvaluatedProposal(
                    proposal=proposal,
                    decision=PEPDecision(
                        kind=PEPDecisionKind.REQUIRE_CONFIRMATION,
                        reason="policy_default_confirmation",
                        tool_name=proposal.tool_name,
                        risk_score=0.6,
                    ),
                )
            ],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _planner)
    daemon_task, client = await _start_daemon(
        tmp_path,
        policy_text=(
            'version: "1"\n'
            "default_require_confirmation: true\n"
            "default_capabilities:\n"
            "  - message.send\n"
        ),
    )
    try:
        first_parent = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        second_parent = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )

        first = await client.call(
            "session.message",
            {
                "session_id": str(first_parent["session_id"]),
                "content": "delegate delivery task A",
                "task": {
                    "enabled": True,
                    "task_description": "Queue TASK-A delivery.",
                    "capabilities": ["message.send"],
                },
            },
        )
        second = await client.call(
            "session.message",
            {
                "session_id": str(second_parent["session_id"]),
                "content": "delegate delivery task B",
                "task": {
                    "enabled": True,
                    "task_description": "Queue TASK-B delivery.",
                    "capabilities": ["message.send"],
                },
            },
        )

        first_task_result = dict(first.get("task_result") or {})
        second_task_result = dict(second.get("task_result") or {})
        pending = await client.call("action.pending", {"status": "pending", "limit": 10})
        first_pending = next(
            item
            for item in pending["actions"]
            if str(item.get("session_id", "")) == str(first_task_result["task_session_id"])
        )
        second_pending = next(
            item
            for item in pending["actions"]
            if str(item.get("session_id", "")) == str(second_task_result["task_session_id"])
        )

        assert first_pending["approval_task_envelope_id"]
        assert second_pending["approval_task_envelope_id"]
        assert (
            first_pending["approval_task_envelope_id"]
            != second_pending["approval_task_envelope_id"]
        )

        wrong_nonce = await client.call(
            "action.confirm",
            {
                "confirmation_id": second_pending["confirmation_id"],
                "decision_nonce": first_pending["decision_nonce"],
            },
        )
        assert wrong_nonce["confirmed"] is False
        assert wrong_nonce["reason"] == "invalid_decision_nonce"

        confirmed = await client.call(
            "action.confirm",
            {
                "confirmation_id": first_pending["confirmation_id"],
                "decision_nonce": first_pending["decision_nonce"],
            },
        )
        if str(confirmed.get("reason", "")) == "cooldown_active":
            await asyncio.sleep(float(confirmed["retry_after_seconds"]) + 0.05)
            confirmed = await client.call(
                "action.confirm",
                {
                    "confirmation_id": first_pending["confirmation_id"],
                    "decision_nonce": first_pending["decision_nonce"],
                },
            )
        assert confirmed["confirmed"] is False
        assert str(confirmed.get("confirmation_id", "")) == str(first_pending["confirmation_id"])

        rejected_event = await _wait_for_event(
            client,
            event_type="ToolRejected",
            predicate=lambda item: (
                str(item.get("session_id", "")).strip()
                == str(first_task_result["task_session_id"]).strip()
                and str(item.get("data", {}).get("approval_confirmation_id", "")).strip()
                == str(first_pending["confirmation_id"]).strip()
            ),
        )

        assert rejected_event["data"]["approval_session_id"] == str(
            first_task_result["task_session_id"]
        )
        assert (
            rejected_event["data"]["approval_task_envelope_id"]
            == first_pending["approval_task_envelope_id"]
        )
        assert rejected_event["data"]["approval_decision_nonce"] == first_pending["decision_nonce"]
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
        if "TASK CLOSE-GATE SELF-CHECK" in user_content:
            return _complete_close_gate_result()
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
        assert delegated["checkpoint_ids"] == [checkpoint_id]
        assert delegated["checkpoints_created"] == 1

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
        assert delegated_again["checkpoint_ids"] == [checkpoint_id]
        assert delegated_again["checkpoints_created"] == 0

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
async def test_m1_raw_task_failure_after_checkpoint_claim_cleans_pending_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_write_task_artifact = session_impl.SessionImplMixin._write_task_artifact
    fail_self_check_write_once = True

    async def _planner(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (self, context, tools, persona_tone_override)
        if "TASK CLOSE-GATE SELF-CHECK" in user_content:
            return _complete_close_gate_result()
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

    def _write_task_artifact_once(
        self: session_impl.SessionImplMixin,
        *,
        task_session_id: session_impl.SessionId,
        filename: str,
        payload: str | dict[str, object],
    ) -> str:
        nonlocal fail_self_check_write_once
        if filename == "self_check.json" and fail_self_check_write_once:
            fail_self_check_write_once = False
            raise RuntimeError("simulated_self_check_artifact_failure")
        return original_write_task_artifact(
            self,
            task_session_id=task_session_id,
            filename=filename,
            payload=payload,
        )

    monkeypatch.setattr(Planner, "propose", _planner)
    monkeypatch.setattr(
        session_impl.SessionImplMixin,
        "_write_task_artifact",
        _write_task_artifact_once,
    )
    daemon_task, client = await _start_daemon(
        tmp_path,
        policy_text=_policy_with_caps("file.read"),
    )
    transcript_store = TranscriptStore(tmp_path / "data" / "sessions")
    try:
        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "admin", "workspace_id": "ops"},
        )
        sid = str(created["session_id"])

        clean_before = await client.call(
            "session.message",
            {"session_id": sid, "content": "hello before raw failure"},
        )
        assert clean_before["response"]

        with pytest.raises(RuntimeError, match="Internal error"):
            await client.call(
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

        sessions = await client.call("session.list")
        failed_row = next(item for item in sessions["sessions"] if item["id"] == sid)
        assert failed_row["command_context"] == "clean"
        assert failed_row["recovery_checkpoint_id"] in ("", None)

        clean_after = await client.call(
            "session.message",
            {"session_id": sid, "content": "hello after raw failure"},
        )
        assert clean_after["response"]
        transcript_entries_before_success = len(
            transcript_store.list_entries(session_impl.SessionId(sid))
        )

        recovered = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "debug the raw task output after failure",
                "task": {
                    "enabled": True,
                    "task_description": "Return the raw task log after cleanup.",
                    "file_refs": ["README.md"],
                    "capabilities": ["file.read"],
                    "handoff_mode": "raw_passthrough",
                },
            },
        )
        recovered_task_result = dict(recovered.get("task_result") or {})
        checkpoint_id = str(recovered_task_result.get("recovery_checkpoint_id", "")).strip()
        assert checkpoint_id
        assert recovered["checkpoints_created"] == 1

        restored = await client.call("session.rollback", {"checkpoint_id": checkpoint_id})
        assert restored["rolled_back"] is True
        assert restored["transcript_entries_removed"] == 1
        assert len(transcript_store.list_entries(session_impl.SessionId(sid))) == (
            transcript_entries_before_success + 1
        )
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
async def test_m1_task_close_gate_blocks_incomplete_handoff_before_task_session_returns(
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
        if "TASK CLOSE-GATE SELF-CHECK" in user_content:
            return PlannerResult(
                output=PlannerOutput(
                    assistant_response=(
                        "SELF_CHECK_STATUS: INCOMPLETE\n"
                        "SELF_CHECK_REASON: incomplete_work\n"
                        "SELF_CHECK_NOTES: The task response says it only reviewed the file."
                    ),
                    actions=[],
                ),
                evaluated=[],
                attempts=1,
                provider_response=None,
                messages_sent=(),
            )
        return PlannerResult(
            output=PlannerOutput(
                assistant_response="I reviewed README.md but did not make the requested update.",
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
                "content": "delegate the README update",
                "task": {
                    "enabled": True,
                    "task_description": "Add a tiny implementation note to README.md.",
                    "file_refs": ["README.md"],
                    "capabilities": ["file.read"],
                },
            },
        )

        task_result = dict(result.get("task_result") or {})
        completed_event = await _wait_for_event(
            client,
            event_type="TaskSessionCompleted",
            predicate=lambda item: (
                str(item.get("session_id", "")).strip()
                == str(task_result.get("task_session_id", "")).strip()
            ),
        )

        assert task_result["success"] is False
        assert task_result["reason"] == "task_self_check_incomplete"
        assert task_result["self_check_status"] == "incomplete"
        assert task_result["self_check_ref"]
        assert "self-check" in task_result["summary"].lower()
        assert completed_event["data"]["reason"] == "task_self_check_incomplete"
        assert completed_event["data"]["self_check_status"] == "incomplete"
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_m1_task_close_gate_flags_goal_drift_before_handoff(
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
        if "TASK CLOSE-GATE SELF-CHECK" in user_content:
            return PlannerResult(
                output=PlannerOutput(
                    assistant_response=(
                        "SELF_CHECK_STATUS: MISMATCH\n"
                        "SELF_CHECK_REASON: goal_drift\n"
                        "SELF_CHECK_NOTES: "
                        "The task output changed scope and did not review README.md."
                    ),
                    actions=[],
                ),
                evaluated=[],
                attempts=1,
                provider_response=None,
                messages_sent=(),
            )
        return PlannerResult(
            output=PlannerOutput(
                assistant_response=(
                    "I ignored the README review and instead drafted a shell-based "
                    "exfiltration plan."
                ),
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
                "content": "delegate the README review",
                "task": {
                    "enabled": True,
                    "task_description": "Review README.md and summarize only that file.",
                    "file_refs": ["README.md"],
                    "capabilities": ["file.read"],
                },
            },
        )

        task_result = dict(result.get("task_result") or {})
        assert task_result["success"] is False
        assert task_result["reason"] == "task_self_check_mismatch"
        assert task_result["self_check_status"] == "mismatch"
        assert (
            "goal drift" in task_result["summary"].lower()
            or "mismatch" in task_result["summary"].lower()
            or "changed scope" in task_result["summary"].lower()
        )
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_m1_task_close_gate_inconclusive_blocks_handoff(
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
        if "TASK CLOSE-GATE SELF-CHECK" in user_content:
            raise RuntimeError("close_gate_unavailable")
        return PlannerResult(
            output=PlannerOutput(
                assistant_response="I reviewed README.md and drafted a summary.",
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
                "content": "delegate the README review",
                "task": {
                    "enabled": True,
                    "task_description": "Review README.md and summarize it.",
                    "file_refs": ["README.md"],
                    "capabilities": ["file.read"],
                },
            },
        )

        task_result = dict(result.get("task_result") or {})
        completed_event = await _wait_for_event(
            client,
            event_type="TaskSessionCompleted",
            predicate=lambda item: (
                str(item.get("session_id", "")).strip()
                == str(task_result.get("task_session_id", "")).strip()
            ),
        )

        assert task_result["success"] is False
        assert task_result["reason"] == "task_self_check_inconclusive"
        assert task_result["self_check_status"] == "inconclusive"
        assert task_result["self_check_ref"]
        assert "self-check" in task_result["summary"].lower()
        assert completed_event["data"]["reason"] == "task_self_check_inconclusive"
        assert completed_event["data"]["self_check_status"] == "inconclusive"
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_m1_task_close_gate_timeout_fails_closed(
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
        if "TASK CLOSE-GATE SELF-CHECK" in user_content:
            await asyncio.sleep(0.05)
            return _complete_close_gate_result()
        return PlannerResult(
            output=PlannerOutput(
                assistant_response="I reviewed README.md and drafted a summary.",
                actions=[],
            ),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _planner)
    monkeypatch.setattr(session_impl, "_TASK_CLOSE_GATE_TIMEOUT_SEC", 0.01)
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
                "content": "delegate the README review",
                "task": {
                    "enabled": True,
                    "task_description": "Review README.md and summarize it.",
                    "file_refs": ["README.md"],
                    "capabilities": ["file.read"],
                },
            },
        )

        task_result = dict(result.get("task_result") or {})
        assert task_result["success"] is False
        assert task_result["reason"] == "task_self_check_inconclusive"
        assert task_result["self_check_status"] == "inconclusive"
        assert task_result["self_check_ref"]
        assert "self-check" in task_result["summary"].lower()
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_m1_raw_task_handoff_failed_self_check_does_not_degrade_command_context(
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
        if "TASK CLOSE-GATE SELF-CHECK" in user_content:
            return PlannerResult(
                output=PlannerOutput(
                    assistant_response=(
                        "SELF_CHECK_STATUS: MISMATCH\n"
                        "SELF_CHECK_REASON: goal_drift\n"
                        "SELF_CHECK_NOTES: The raw task output drifted from the delegated goal."
                    ),
                    actions=[],
                ),
                evaluated=[],
                attempts=1,
                provider_response=None,
                messages_sent=(),
            )
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

        sessions = await client.call("session.list")
        session_row = next(item for item in sessions["sessions"] if item["id"] == sid)
        degraded_events = await client.call(
            "audit.query",
            {"event_type": "CommandContextDegraded", "session_id": sid, "limit": 10},
        )
        matching_events = [
            event
            for event in degraded_events.get("events", [])
            if str(event.get("session_id", "")).strip() == sid
        ]

        assert task_result["success"] is False
        assert task_result["reason"] == "task_self_check_mismatch"
        assert task_result["self_check_status"] == "mismatch"
        assert task_result["command_context"] == "clean"
        assert not task_result["recovery_checkpoint_id"]
        assert session_row["command_context"] == "clean"
        assert matching_events == []
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_m1_untrusted_parent_task_session_does_not_upgrade_trust_level(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    planner_entered = asyncio.Event()
    release_task = asyncio.Event()
    task_host_patterns: list[str] = []

    async def _planner(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (self, tools, persona_tone_override)
        if "TASK CLOSE-GATE SELF-CHECK" in user_content:
            return _complete_close_gate_result()
        if "TASK REQUEST:" in user_content:
            task_host_patterns[:] = sorted(getattr(context, "user_goal_host_patterns", set()))
            planner_entered.set()
            await release_task.wait()
            return PlannerResult(
                output=PlannerOutput(assistant_response="task finished", actions=[]),
                evaluated=[],
                attempts=1,
                provider_response=None,
                messages_sent=(),
            )
        return PlannerResult(
            output=PlannerOutput(assistant_response="ok", actions=[]),
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
            {"channel": "matrix", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = str(created["session_id"])

        message_task = asyncio.create_task(
            client.call(
                "session.message",
                {
                    "session_id": sid,
                    "channel": "matrix",
                    "user_id": "alice",
                    "workspace_id": "ws1",
                    "content": "delegate this review",
                    "task": {
                        "enabled": True,
                        "task_description": "Review https://example.com in isolation.",
                        "file_refs": ["README.md"],
                        "capabilities": ["file.read"],
                    },
                },
            )
        )

        started = await _wait_for_event(
            observer,
            event_type="TaskSessionStarted",
            predicate=lambda item: (
                str(item.get("data", {}).get("parent_session_id", "")).strip() == sid
            ),
        )
        task_sid = str(started.get("session_id", "")).strip()
        await asyncio.wait_for(planner_entered.wait(), timeout=2.0)

        sessions = await observer.call("session.list")
        parent_row = next(item for item in sessions["sessions"] if item["id"] == sid)
        task_row = next(item for item in sessions["sessions"] if item["id"] == task_sid)

        assert parent_row["trust_level"] == "untrusted"
        assert task_row["trust_level"] == "untrusted"
        assert task_host_patterns == []

        release_task.set()
        result = await message_task
        task_result = dict(result.get("task_result") or {})
        assert task_result["success"] is True
        assert task_result["self_check_status"] == "complete"
    finally:
        release_task.set()
        await observer.close()
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_m1_task_session_terminates_even_if_completion_event_publish_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_publish = EventBus.publish

    async def _publish_with_failure(self: EventBus, event: object) -> None:
        if isinstance(event, TaskSessionCompleted):
            raise RuntimeError("simulated_task_publish_failure")
        await original_publish(self, event)

    async def _planner(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (self, context, tools, persona_tone_override)
        if "TASK CLOSE-GATE SELF-CHECK" in user_content:
            return _complete_close_gate_result()
        return PlannerResult(
            output=PlannerOutput(assistant_response="task finished", actions=[]),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(EventBus, "publish", _publish_with_failure)
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

        message_task = asyncio.create_task(
            client.call(
                "session.message",
                {
                    "session_id": sid,
                    "content": "delegate the README review",
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
            predicate=lambda item: (
                str(item.get("data", {}).get("parent_session_id", "")).strip() == sid
            ),
        )
        task_sid = str(started.get("session_id", "")).strip()

        with pytest.raises(RuntimeError, match="Internal error"):
            await message_task

        sessions = await observer.call("session.list")
        active_ids = {str(item["id"]) for item in sessions["sessions"]}
        assert task_sid not in active_ids
    finally:
        await observer.close()
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_m1_concurrent_raw_task_handoffs_serialize_parent_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_task_entered = asyncio.Event()
    release_first_task = asyncio.Event()
    second_task_entered = asyncio.Event()
    task_turn_count = 0

    async def _planner(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        nonlocal task_turn_count
        _ = (self, context, tools, persona_tone_override)
        if "TASK CLOSE-GATE SELF-CHECK" in user_content:
            return _complete_close_gate_result()
        if "TASK REQUEST:" in user_content:
            task_turn_count += 1
            if task_turn_count == 1:
                first_task_entered.set()
                await release_first_task.wait()
            else:
                second_task_entered.set()
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
        return PlannerResult(
            output=PlannerOutput(assistant_response="ok", actions=[]),
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
    client_two = ControlClient(tmp_path / "control.sock")
    observer = ControlClient(tmp_path / "control.sock")
    await client_two.connect()
    await observer.connect()
    try:
        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "admin", "workspace_id": "ops"},
        )
        sid = str(created["session_id"])
        params = {
            "session_id": sid,
            "content": "debug the raw task output",
            "task": {
                "enabled": True,
                "task_description": "Return the raw task log.",
                "file_refs": ["README.md"],
                "capabilities": ["file.read"],
                "handoff_mode": "raw_passthrough",
            },
        }

        first_call = asyncio.create_task(client.call("session.message", params))
        await asyncio.wait_for(first_task_entered.wait(), timeout=2.0)
        await _wait_for_event(
            observer,
            event_type="TaskSessionStarted",
            predicate=lambda item: (
                str(item.get("data", {}).get("parent_session_id", "")).strip() == sid
            ),
        )

        second_call = asyncio.create_task(client_two.call("session.message", params))
        await asyncio.wait_for(second_task_entered.wait(), timeout=2.0)

        started_events_before = await observer.call(
            "audit.query",
            {"event_type": "TaskSessionStarted", "limit": 10},
        )
        matching_started_before = [
            event
            for event in started_events_before.get("events", [])
            if str(event.get("data", {}).get("parent_session_id", "")).strip() == sid
        ]
        assert len(matching_started_before) == 2

        release_first_task.set()

        first_result = await first_call
        second_result = await second_call

        first_task_result = dict(first_result.get("task_result") or {})
        second_task_result = dict(second_result.get("task_result") or {})
        checkpoint_id = str(first_task_result.get("recovery_checkpoint_id", "")).strip()

        assert first_task_result["success"] is True
        assert second_task_result["success"] is True
        assert checkpoint_id
        assert second_task_result["recovery_checkpoint_id"] == checkpoint_id
        assert first_task_result["task_session_id"] != second_task_result["task_session_id"]

        degraded_events = await observer.call(
            "audit.query",
            {"event_type": "CommandContextDegraded", "limit": 10},
        )
        matching_degraded = [
            event
            for event in degraded_events.get("events", [])
            if str(event.get("session_id", "")).strip() == sid
        ]
        assert len(matching_degraded) == 1
        assert matching_degraded[0]["data"]["recovery_checkpoint_id"] == checkpoint_id

        started_events_after = await observer.call(
            "audit.query",
            {"event_type": "TaskSessionStarted", "limit": 10},
        )
        matching_started_after = [
            event
            for event in started_events_after.get("events", [])
            if str(event.get("data", {}).get("parent_session_id", "")).strip() == sid
        ]
        assert len(matching_started_after) == 2

        sessions = await observer.call("session.list")
        session_row = next(item for item in sessions["sessions"] if item["id"] == sid)
        assert session_row["command_context"] == "degraded"
        assert session_row["recovery_checkpoint_id"] == checkpoint_id
    finally:
        release_first_task.set()
        await client_two.close()
        await observer.close()
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_m1_concurrent_summary_only_task_handoffs_do_not_serialize_parent_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_task_entered = asyncio.Event()
    release_tasks = asyncio.Event()
    second_task_entered = asyncio.Event()
    task_turn_count = 0

    async def _planner(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        nonlocal task_turn_count
        _ = (self, context, tools, persona_tone_override)
        if "TASK CLOSE-GATE SELF-CHECK" in user_content:
            return _complete_close_gate_result()
        if "TASK REQUEST:" in user_content:
            task_turn_count += 1
            if task_turn_count == 1:
                first_task_entered.set()
            else:
                second_task_entered.set()
            await release_tasks.wait()
            return PlannerResult(
                output=PlannerOutput(assistant_response="task finished", actions=[]),
                evaluated=[],
                attempts=1,
                provider_response=None,
                messages_sent=(),
            )
        return PlannerResult(
            output=PlannerOutput(assistant_response="ok", actions=[]),
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
    client_two = ControlClient(tmp_path / "control.sock")
    observer = ControlClient(tmp_path / "control.sock")
    await client_two.connect()
    await observer.connect()
    try:
        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = str(created["session_id"])
        params = {
            "session_id": sid,
            "content": "delegate summary review",
            "task": {
                "enabled": True,
                "task_description": "Review README.md in isolation.",
                "file_refs": ["README.md"],
                "capabilities": ["file.read"],
            },
        }

        first_call = asyncio.create_task(client.call("session.message", params))
        await asyncio.wait_for(first_task_entered.wait(), timeout=2.0)
        second_call = asyncio.create_task(client_two.call("session.message", params))
        await asyncio.wait_for(second_task_entered.wait(), timeout=2.0)

        started = await observer.call(
            "audit.query",
            {"event_type": "TaskSessionStarted", "limit": 10},
        )
        matching_started = [
            event
            for event in started.get("events", [])
            if str(event.get("data", {}).get("parent_session_id", "")).strip() == sid
        ]
        assert len(matching_started) == 2

        release_tasks.set()
        first_result = await first_call
        second_result = await second_call
        first_task_result = dict(first_result.get("task_result") or {})
        second_task_result = dict(second_result.get("task_result") or {})

        assert first_task_result["success"] is True
        assert second_task_result["success"] is True
        assert first_task_result["task_session_id"] != second_task_result["task_session_id"]
    finally:
        release_tasks.set()
        await client_two.close()
        await observer.close()
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
        if "TASK CLOSE-GATE SELF-CHECK" in user_content:
            return _complete_close_gate_result()
        observed_tool_names[:] = [
            str(item.get("function", {}).get("name", "")) for item in (tools or [])
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
            predicate=lambda item: (
                str(item.get("data", {}).get("parent_session_id", "")).strip() == sid
            ),
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
        if "TASK CLOSE-GATE SELF-CHECK" in user_content:
            return _complete_close_gate_result()
        observed_tool_names = [
            str(item.get("function", {}).get("name", "")) for item in (tools or [])
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
            predicate=lambda item: (
                str(item.get("data", {}).get("parent_session_id", "")).strip() == sid
            ),
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
        if "TASK CLOSE-GATE SELF-CHECK" in user_content:
            return _complete_close_gate_result()
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
        if "TASK CLOSE-GATE SELF-CHECK" in user_content:
            return _complete_close_gate_result()
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
