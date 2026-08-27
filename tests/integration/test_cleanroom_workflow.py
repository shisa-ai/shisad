"""M4 integration coverage for clean-room workflow and pairing proposals."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from contextlib import suppress
from pathlib import Path

import pytest

from shisad.core.api.transport import ControlClient, JsonRpcCallError
from shisad.core.atomic_state import AtomicWriteError, AtomicWriteStage
from shisad.core.config import DaemonConfig
from shisad.core.planner import (
    ActionProposal,
    EvaluatedProposal,
    Planner,
    PlannerOutput,
    PlannerResult,
)
from shisad.core.providers.base import Message, ProviderResponse
from shisad.core.transcript import TranscriptStore
from shisad.core.types import PEPDecision, PEPDecisionKind, ToolName
from shisad.daemon.runner import run_daemon
from tests.helpers.daemon import ingest_memory_via_ingress
from tests.helpers.daemon import wait_for_socket as _wait_for_socket


@pytest.fixture
def model_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")


async def _start_daemon(
    tmp_path: Path,
    **kwargs: object,
) -> tuple[asyncio.Task[None], ControlClient, DaemonConfig]:
    config_kwargs: dict[str, object] = {
        "data_dir": tmp_path / "data",
        "socket_path": tmp_path / "control.sock",
        "policy_path": tmp_path / "policy.yaml",
        "log_level": "INFO",
    }
    config_kwargs.update(kwargs)
    config = DaemonConfig(**config_kwargs)
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    await _wait_for_socket(config.socket_path)
    await client.connect()
    return daemon_task, client, config


def _fake_browser_command() -> str:
    fixture = Path(__file__).resolve().parents[1] / "fixtures" / "fake_playwright_cli.py"
    return f"{sys.executable} {fixture}"


async def _shutdown(daemon_task: asyncio.Task[None], client: ControlClient) -> None:
    with suppress(Exception):
        await client.call("daemon.shutdown")
    await client.close()
    await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_m4_cleanroom_mode_transition_rejects_tainted_history(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client, config = await _start_daemon(tmp_path)
    try:
        # Integration harness must stay hermetic even if operator channel env is set.
        assert config.discord_enabled is False
        assert config.telegram_enabled is False
        created = await client.call("session.create", {"channel": "cli", "user_id": "alice"})
        sid = created["session_id"]
        _ = await client.call(
            "session.message",
            {"session_id": sid, "content": "api key sk-ABCDEFGHIJKLMNOPQRSTUV123456"},
        )
        mode_update = await client.call(
            "session.set_mode",
            {"session_id": sid, "mode": "admin_cleanroom"},
        )
        assert mode_update["changed"] is False
        assert mode_update["reason"] == "tainted_transcript_history"
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m6_cleanroom_transition_rejects_tool_output_tainted_history(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _propose_web_fetch(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
    ) -> PlannerResult:
        _ = (self, user_content, context, tools)
        proposal = ActionProposal(
            action_id="a1",
            tool_name=ToolName("retrieve_rag"),
            arguments={"query": "evidence", "limit": 1},
            reasoning="Retrieve evidence from memory index.",
            data_sources=[],
        )
        return PlannerResult(
            output=PlannerOutput(assistant_response="Fetched.", actions=[proposal]),
            evaluated=[
                EvaluatedProposal(
                    proposal=proposal,
                    decision=PEPDecision(
                        kind=PEPDecisionKind.ALLOW,
                        reason="test-allow",
                        tool_name=ToolName("retrieve_rag"),
                        risk_score=0.1,
                    ),
                )
            ],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _propose_web_fetch)
    daemon_task, client, _config = await _start_daemon(tmp_path)
    try:
        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = created["session_id"]
        _ = await ingest_memory_via_ingress(
            client,
            source_id="evidence-1",
            source_type="external",
            # Under S8 defaults, sessions have side-effect capabilities and
            # retrieve_rag excludes external_web by policy. Use project_docs
            # to keep retrieval taint propagation deterministic in this test.
            collection="project_docs",
            content="evidence payload from external source",
        )
        reply = await client.call(
            "session.message",
            {"session_id": sid, "content": "fetch the source"},
        )
        assert "Fetched." in str(reply.get("response", ""))
        tool_outputs = reply.get("tool_outputs")
        assert isinstance(tool_outputs, list)
        assert any(
            isinstance(record, dict)
            and record.get("tool_name") == "retrieve_rag"
            and record.get("success") is True
            and "untrusted" in list(record.get("taint_labels") or [])
            for record in tool_outputs
        )
        mode_update = await client.call(
            "session.set_mode",
            {"session_id": sid, "mode": "admin_cleanroom"},
        )
        assert mode_update["changed"] is False
        assert mode_update["reason"] == "tainted_transcript_history"
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m4_cleanroom_session_message_is_proposal_only_and_rejects_tainted_payload(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client, _config = await _start_daemon(tmp_path)
    try:
        created = await client.call(
            "session.create",
            {
                "channel": "cli",
                "user_id": "admin",
                "workspace_id": "ops",
                "mode": "admin_cleanroom",
            },
        )
        sid = created["session_id"]

        clean = await client.call(
            "session.message",
            {"session_id": sid, "content": "review pending pairing proposals"},
        )
        assert clean["session_mode"] == "admin_cleanroom"
        assert clean["proposal_only"] is True
        assert clean["executed_actions"] == 0

        tainted = await client.call(
            "session.message",
            {"session_id": sid, "content": "api key sk-ABCDEFGHIJKLMNOPQRSTUV123456"},
        )
        assert tainted["proposal_only"] is True
        assert any(
            "cleanroom_tainted_payload" in reason
            for reason in tainted.get("cleanroom_block_reasons", [])
        )
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_g1_cleanroom_tainted_payload_early_return_skips_transcript_and_response_audit(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client, config = await _start_daemon(tmp_path)
    try:
        created = await client.call(
            "session.create",
            {
                "channel": "cli",
                "user_id": "admin",
                "workspace_id": "ops",
                "mode": "admin_cleanroom",
            },
        )
        sid = created["session_id"]
        transcript_store = TranscriptStore(config.data_dir / "sessions")
        result = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "api key sk-ABCDEFGHIJKLMNOPQRSTUV123456",
            },
        )

        entries = transcript_store.list_entries(sid)
        received_events = await client.call(
            "audit.query",
            {
                "event_type": "SessionMessageReceived",
                "session_id": sid,
                "limit": 10,
            },
        )
        responded_events = await client.call(
            "audit.query",
            {
                "event_type": "SessionMessageResponded",
                "session_id": sid,
                "limit": 10,
            },
        )

        assert result["proposal_only"] is True
        assert any(
            "cleanroom_tainted_payload" in reason
            for reason in result.get("cleanroom_block_reasons", [])
        )
        assert entries == []
        assert received_events["total"] == 1
        assert responded_events["total"] == 0
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_gh33_cleanroom_sensitive_browser_proposal_redacts_public_metadata(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sensitive_text = "cleanroom alpha bravo ledger password"

    async def _propose_sensitive_browser_type(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (self, user_content, context, tools, persona_tone_override)
        proposal = ActionProposal(
            action_id="browser-secret",
            tool_name=ToolName("browser.type_text"),
            arguments={
                "target": "#name",
                "is_sensitive": True,
                "description": sensitive_text,
            },
            reasoning="Draft a browser write proposal.",
            data_sources=[],
        )
        sibling_proposal = ActionProposal(
            action_id="sibling-echo",
            tool_name=ToolName("note.create"),
            arguments={"content": sensitive_text},
            reasoning="Sibling proposal echoing the sensitive browser text.",
            data_sources=[],
        )
        return PlannerResult(
            output=PlannerOutput(
                assistant_response="Prepared sensitive browser proposal.",
                actions=[proposal, sibling_proposal],
            ),
            evaluated=[
                EvaluatedProposal(
                    proposal=proposal,
                    decision=PEPDecision(
                        kind=PEPDecisionKind.ALLOW,
                        reason="test-allow",
                        tool_name=ToolName("browser.type_text"),
                        risk_score=0.1,
                    ),
                ),
                EvaluatedProposal(
                    proposal=sibling_proposal,
                    decision=PEPDecision(
                        kind=PEPDecisionKind.ALLOW,
                        reason="test-allow",
                        tool_name=ToolName("note.create"),
                        risk_score=0.1,
                    ),
                ),
            ],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _propose_sensitive_browser_type)

    async def _browser_ready(**_kwargs: object) -> dict[str, object]:
        return {
            "enabled": True,
            "status": "ok",
            "problems": [],
            "protocol": {"supported": True, "probe": "test", "reason": ""},
        }

    monkeypatch.setattr("shisad.daemon.services._browser_startup_status", _browser_ready)
    (tmp_path / "policy.yaml").write_text(
        'version: "1"\nsandbox:\n  containment_profile: expert_host_fallback\n',
        encoding="utf-8",
    )
    daemon_task, client, config = await _start_daemon(
        tmp_path,
        browser_enabled=True,
        browser_command=_fake_browser_command(),
        browser_allowed_domains=["127.0.0.1", "localhost"],
        browser_require_hardened_isolation=False,
    )
    try:
        created = await client.call(
            "session.create",
            {
                "channel": "cli",
                "user_id": "admin",
                "workspace_id": "ops",
                "mode": "admin_cleanroom",
            },
        )
        sid = created["session_id"]

        result = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "prepare the browser proposal for review",
            },
        )

        assert result["session_mode"] == "admin_cleanroom"
        assert result["proposal_only"] is True
        assert result["executed_actions"] == 0
        assert result["proposals"]
        assert len(result["proposals"]) == 2
        proposal = result["proposals"][0]
        assert proposal["tool_name"] == "browser.type_text"
        assert "text" not in proposal["arguments"]
        assert proposal["arguments"]["description"] == "[sensitive text redacted]"
        sibling_proposal = result["proposals"][1]
        assert sibling_proposal["tool_name"] == "note.create"
        assert sibling_proposal["arguments"] == {}
        assert sensitive_text not in json.dumps(result, sort_keys=True)
        assert "[sensitive text redacted]" in json.dumps(result, sort_keys=True)

        transcript_store = TranscriptStore(config.data_dir / "sessions")
        transcript_payload = "\n".join(
            entry.content_preview for entry in transcript_store.list_entries(sid)
        )
        assert sensitive_text not in transcript_payload
        assert "[sensitive text redacted]" in transcript_payload

        audit_text = (config.data_dir / "audit.jsonl").read_text(encoding="utf-8")
        assert sensitive_text not in audit_text
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_gh33_cleanroom_trace_redacts_sensitive_browser_text(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sensitive_text = "cleanroom trace alpha bravo ledger"

    async def _propose_sensitive_browser_type(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (self, context, tools, persona_tone_override)
        proposal = ActionProposal(
            action_id="browser-secret-trace",
            tool_name=ToolName("browser.type_text"),
            arguments={
                "target": "#password",
                "is_sensitive": True,
                "text": sensitive_text,
                "description": sensitive_text,
            },
            reasoning="Draft a sensitive browser write proposal.",
            data_sources=[],
        )
        return PlannerResult(
            output=PlannerOutput(
                assistant_response="Prepared sensitive browser proposal.",
                actions=[proposal],
            ),
            evaluated=[
                EvaluatedProposal(
                    proposal=proposal,
                    decision=PEPDecision(
                        kind=PEPDecisionKind.ALLOW,
                        reason="test-allow",
                        tool_name=ToolName("browser.type_text"),
                        risk_score=0.1,
                    ),
                )
            ],
            attempts=1,
            provider_response=ProviderResponse(
                message=Message(
                    role="assistant",
                    content=f"Planner response mentioned {sensitive_text}.",
                ),
                model="test-planner",
                finish_reason="stop",
                usage={},
            ),
            messages_sent=(
                Message(role="user", content=user_content),
                Message(
                    role="assistant",
                    content=f"Proposing browser.type_text with {sensitive_text}.",
                    tool_calls=[
                        {
                            "type": "function",
                            "function": {
                                "name": "browser_type_text",
                                "arguments": json.dumps(
                                    {
                                        "target": "#password",
                                        "is_sensitive": True,
                                        "text": sensitive_text,
                                    },
                                    sort_keys=True,
                                ),
                            },
                        }
                    ],
                ),
            ),
        )

    monkeypatch.setattr(Planner, "propose", _propose_sensitive_browser_type)

    daemon_task, client, config = await _start_daemon(tmp_path, trace_enabled=True)
    try:
        created = await client.call(
            "session.create",
            {
                "channel": "cli",
                "user_id": "admin",
                "workspace_id": "ops",
                "mode": "admin_cleanroom",
            },
        )
        sid = created["session_id"]

        result = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": f"prepare the browser proposal for {sensitive_text}",
            },
        )

        assert result["proposal_only"] is True
        trace_path = config.data_dir / "traces" / f"{sid}.jsonl"
        trace_text = trace_path.read_text(encoding="utf-8")
        trace_row = json.loads(trace_text.splitlines()[0])
        assert sensitive_text not in trace_text
        assert trace_row["user_content"] == "[sensitive text redacted]"
        assert trace_row["llm_response"] == "[sensitive text redacted]"
        assert all(
            message["content"] == "[sensitive text redacted]"
            for message in trace_row["messages_sent"]
        )
        assert "[sensitive text redacted]" in trace_text
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m1_trusted_cli_admin_intent_reroutes_to_fresh_cleanroom_and_auto_drops(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_inputs: list[str] = []

    async def _capture_cleanroom_prompt(
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
            output=PlannerOutput(assistant_response="Admin proposal ready.", actions=[]),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _capture_cleanroom_prompt)

    daemon_task, client, config = await _start_daemon(tmp_path)
    try:
        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "admin", "workspace_id": "ops"},
        )
        sid = str(created["session_id"])

        _ = await client.call(
            "session.message",
            {"session_id": sid, "content": "hello from the default session"},
        )
        _ = await ingest_memory_via_ingress(
            client,
            source_id="sudo-memory",
            source_type="external",
            collection="project_docs",
            content="MEMORY CANARY: prior secret context",
        )

        sudo = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "install the signed behavior pack and update assistant behavior",
            },
        )

        assert sudo["session_mode"] == "admin_cleanroom"
        assert sudo["proposal_only"] is True
        assert captured_inputs
        assert "hello from the default session" not in captured_inputs[-1]
        assert "MEMORY CANARY" not in captured_inputs[-1]
        assert "MEMORY CONTEXT" not in captured_inputs[-1]
        assert "TASK LEDGER" not in captured_inputs[-1]

        sessions = await client.call("session.list")
        rows = [item for item in sessions["sessions"] if item["state"] == "active"]
        assert len(rows) == 1
        assert rows[0]["id"] == sid
        assert rows[0]["mode"] == "default"

        terminated = await client.call(
            "audit.query",
            {"event_type": "SessionTerminated", "limit": 20},
        )
        assert terminated["total"] >= 1

        transcript_store = TranscriptStore(config.data_dir / "sessions")
        original_entries = transcript_store.list_entries(sid)
        assert any(
            "hello from the default session" in entry.content_preview for entry in original_entries
        )
        assert not any(
            "install the signed behavior pack" in entry.content_preview
            for entry in original_entries
        )
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m1_trusted_cli_normal_message_does_not_trigger_cleanroom(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client, _config = await _start_daemon(tmp_path)
    try:
        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "admin", "workspace_id": "ops"},
        )
        sid = str(created["session_id"])

        reply = await client.call(
            "session.message",
            {"session_id": sid, "content": "What is a skill bundle?"},
        )

        assert reply["session_id"] == sid
        assert reply["session_mode"] == "default"
        assert reply["proposal_only"] is False
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m4_pairing_proposal_uses_pairing_request_artifacts(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client, _config = await _start_daemon(tmp_path)
    try:
        ingest = await client.call(
            "channel.ingest",
            {
                "message": {
                    "channel": "discord",
                    "external_user_id": "attacker-user",
                    "workspace_hint": "guild-1",
                    "content": "hello",
                }
            },
        )
        assert "Pairing request recorded" in ingest["response"]

        proposal = await client.call(
            "channel.pairing_propose",
            {"channel": "discord", "workspace_hint": "guild-1", "limit": 20},
        )
        assert proposal["applied"] is False
        assert proposal["count"] == 1
        assert "discord" in proposal["config_patch"]
        assert "attacker-user" in proposal["config_patch"]["discord"]
        proposal_path = Path(proposal["proposal_path"])
        assert proposal_path.exists()
        proposal_payload = json.loads(proposal_path.read_text(encoding="utf-8"))
        assert proposal_payload["schema"] == 1
        assert proposal_payload["owner_uid"] == os.getuid()
        assert proposal_payload["workspace_hint"] == "guild-1"
        assert proposal_payload["applied"] is False
        assert proposal_path.stat().st_mode & 0o777 == 0o600

        artifacts = list((_config.data_dir / "channels" / "pairing_requests").rglob("*.jsonl"))
        assert len(artifacts) == 1
        artifact_payload = json.loads(artifacts[0].read_text(encoding="utf-8"))
        assert artifact_payload["schema"] == 1
        assert artifact_payload["owner_uid"] == os.getuid()
        assert artifact_payload["workspace_hint"] == "guild-1"
        assert artifacts[0].stat().st_mode & 0o777 == 0o600
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_o4f_pairing_list_and_cleanup_are_scoped_dry_run_first_and_restart_safe(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client, config = await _start_daemon(tmp_path)
    try:
        for index, workspace in enumerate(("guild-1", "guild-2"), start=1):
            await client.call(
                "channel.ingest",
                {
                    "message": {
                        "channel": "discord",
                        "external_user_id": "shared-user",
                        "workspace_hint": workspace,
                        "content": f"hello {index}",
                    }
                },
            )
        listed = await client.call(
            "channel.pairing_list",
            {"workspace_hint": "guild-1", "channel": "discord", "limit": 100},
        )
        assert listed["count"] == 1
        assert listed["entries"][0]["workspace_hint"] == "guild-1"
        assert "path" not in json.dumps(listed)

        cleanup_params = {
            "workspace_hint": "guild-1",
            "channel": "discord",
            "before": "2100-01-01T00:00:00+00:00",
            "write": False,
        }
        dry = await client.call("channel.pairing_cleanup", cleanup_params)
        assert dry["dry_run"] is True
        assert dry["matched_count"] == 1
        assert dry["removed_count"] == 0
        list_params = {
            "workspace_hint": "guild-1",
            "channel": "discord",
            "limit": 100,
        }
        assert (await client.call("channel.pairing_list", list_params))["count"] == 1

        applied = await client.call(
            "channel.pairing_cleanup",
            {**cleanup_params, "write": True},
        )
        assert applied["dry_run"] is False
        assert applied["complete"] is True
        assert applied["removed_count"] == 1
        assert (await client.call("channel.pairing_list", list_params))["count"] == 0
        other = await client.call(
            "channel.pairing_list",
            {"workspace_hint": "guild-2", "channel": "discord", "limit": 100},
        )
        assert other["count"] == 1
        assert "ChannelPairingRequestsCleaned" in (config.data_dir / "audit.jsonl").read_text(
            encoding="utf-8"
        )
    finally:
        await _shutdown(daemon_task, client)

    restarted_task, restarted_client, _ = await _start_daemon(tmp_path)
    try:
        after_restart = await restarted_client.call(
            "channel.pairing_list",
            {"workspace_hint": "guild-1", "channel": "discord", "limit": 100},
        )
        assert after_restart["count"] == 0
    finally:
        await _shutdown(restarted_task, restarted_client)


@pytest.mark.asyncio
async def test_o4f_pairing_admission_enforces_scope_quota_before_publication(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("shisad.daemon.handlers._impl._PAIRING_REQUEST_MAX_FILES", 1)
    daemon_task, client, config = await _start_daemon(tmp_path)
    try:
        await client.call(
            "channel.ingest",
            {
                "message": {
                    "channel": "discord",
                    "external_user_id": "first-user",
                    "workspace_hint": "guild-1",
                    "content": "hello",
                }
            },
        )
        with pytest.raises(JsonRpcCallError, match="pairing_request_quota_exceeded"):
            await client.call(
                "channel.ingest",
                {
                    "message": {
                        "channel": "discord",
                        "external_user_id": "second-user",
                        "workspace_hint": "guild-1",
                        "content": "hello",
                    }
                },
            )
        artifacts = list((config.data_dir / "channels" / "pairing_requests").rglob("*.jsonl"))
        assert len(artifacts) == 1
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_o4f_pairing_cleanup_reports_partial_failure_and_recovers_on_rerun(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_task, client, config = await _start_daemon(tmp_path)
    try:
        for index, external_user in enumerate(("remove-user", "retry-user"), start=1):
            await client.call(
                "channel.ingest",
                {
                    "message": {
                        "channel": "discord",
                        "external_user_id": external_user,
                        "workspace_hint": "guild-1",
                        "content": f"pairing attempt {index}",
                    }
                },
            )
        artifacts = list((config.data_dir / "channels" / "pairing_requests").rglob("*.jsonl"))
        failing = next(
            path
            for path in artifacts
            if json.loads(path.read_text(encoding="utf-8"))["external_user_id"] == "retry-user"
        )
        real_unlink = Path.unlink
        failed_once = False

        def _fail_one_unlink(path: Path, *args: object, **kwargs: object) -> None:
            nonlocal failed_once
            if path == failing and not failed_once:
                failed_once = True
                raise OSError("simulated cleanup failure")
            real_unlink(path, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", _fail_one_unlink)
        params = {
            "workspace_hint": "guild-1",
            "channel": "discord",
            "before": "2100-01-01T00:00:00+00:00",
            "write": True,
            "limit": 100,
        }
        partial = await client.call("channel.pairing_cleanup", params)
        assert partial["complete"] is False
        assert partial["removed_count"] == 1
        assert partial["failed_count"] == 1
        assert partial["remaining_count"] == 1
        assert partial["failures"][0]["external_user_id"] == "retry-user"
        assert "path" not in json.dumps(partial)

        recovered = await client.call("channel.pairing_cleanup", params)
        assert recovered["complete"] is True
        assert recovered["removed_count"] == 1
        assert recovered["failed_count"] == 0
        assert recovered["remaining_count"] == 0
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_f7c_pairing_keeps_same_external_identity_separate_by_workspace(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client, _config = await _start_daemon(tmp_path)
    try:
        for workspace, content in (("guild-1", "hello one"), ("guild-2", "hello two")):
            ingest = await client.call(
                "channel.ingest",
                {
                    "message": {
                        "channel": "discord",
                        "external_user_id": "shared-external-user",
                        "workspace_hint": workspace,
                        "content": content,
                    }
                },
            )
            assert "Pairing request recorded" in ingest["response"]

        with pytest.raises(JsonRpcCallError, match="workspace_hint"):
            await client.call("channel.pairing_propose", {"channel": "discord", "limit": 20})

        proposals = []
        for workspace in ("guild-1", "guild-2"):
            proposal = await client.call(
                "channel.pairing_propose",
                {"channel": "discord", "workspace_hint": workspace, "limit": 20},
            )
            assert proposal["count"] == 1
            assert proposal["entries"] == [
                {
                    "channel": "discord",
                    "external_user_id": "shared-external-user",
                    "workspace_hint": workspace,
                    "reason": "identity_not_allowlisted",
                }
            ]
            proposals.append(Path(proposal["proposal_path"]))

        assert proposals[0].parent != proposals[1].parent
        artifacts = list((_config.data_dir / "channels" / "pairing_requests").rglob("*.jsonl"))
        assert len(artifacts) == 2
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_f7c_pairing_publication_failure_is_not_acknowledged(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_task, client, config = await _start_daemon(tmp_path)

    def _fail_atomic_write(path: Path, _payload: bytes, **_kwargs: object) -> object:
        raise AtomicWriteError(
            path=path,
            stage=AtomicWriteStage.WRITE,
            publication_may_have_committed=False,
        )

    monkeypatch.setattr("shisad.daemon.handlers._impl.atomic_write_bytes", _fail_atomic_write)
    try:
        with pytest.raises(JsonRpcCallError, match="pairing_request_publication_failed"):
            await client.call(
                "channel.ingest",
                {
                    "message": {
                        "channel": "discord",
                        "external_user_id": "unpersisted-user",
                        "workspace_hint": "guild-1",
                        "content": "hello",
                    }
                },
            )

        artifact_root = config.data_dir / "channels" / "pairing_requests"
        assert not artifact_root.exists() or not any(artifact_root.rglob("*.jsonl"))
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_f7c_pairing_proposal_publication_failure_writes_no_partial_artifact(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_task, client, config = await _start_daemon(tmp_path)
    try:
        ingest = await client.call(
            "channel.ingest",
            {
                "message": {
                    "channel": "discord",
                    "external_user_id": "proposal-fault-user",
                    "workspace_hint": "guild-1",
                    "content": "hello",
                }
            },
        )
        assert "Pairing request recorded" in ingest["response"]

        def _fail_atomic_write(path: Path, _payload: bytes, **_kwargs: object) -> object:
            raise AtomicWriteError(
                path=path,
                stage=AtomicWriteStage.WRITE,
                publication_may_have_committed=False,
            )

        monkeypatch.setattr(
            "shisad.daemon.handlers._impl_admin.atomic_write_bytes",
            _fail_atomic_write,
        )
        with pytest.raises(JsonRpcCallError, match="pairing_proposal_publication_failed"):
            await client.call(
                "channel.pairing_propose",
                {"channel": "discord", "workspace_hint": "guild-1", "limit": 20},
            )

        proposal_root = config.data_dir / "proposals" / "channel_pairing"
        assert not proposal_root.exists() or not any(proposal_root.rglob("*.json"))
    finally:
        await _shutdown(daemon_task, client)
