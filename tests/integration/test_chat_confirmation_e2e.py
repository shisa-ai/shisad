"""M6 CRC integration coverage for chat-based confirmation resolution."""

from __future__ import annotations

import asyncio
import textwrap
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from shisad.core.api.schema import (
    ActionPendingParams,
    AuditQueryParams,
    ChannelIngestParams,
    TwoFactorRegisterBeginParams,
    TwoFactorRegisterConfirmParams,
)
from shisad.core.api.transport import ControlClient
from shisad.core.approval import generate_totp_code
from shisad.core.audit import AuditLog
from shisad.core.config import DaemonConfig
from shisad.core.planner import (
    ActionProposal,
    EvaluatedProposal,
    Planner,
    PlannerOutput,
    PlannerResult,
)
from shisad.core.request_context import RequestContext
from shisad.core.transcript import TranscriptStore
from shisad.core.types import SessionId, ToolName
from shisad.daemon.control_handlers import DaemonControlHandlers
from shisad.daemon.runner import run_daemon
from shisad.daemon.services import DaemonServices

REPO_ROOT = Path(__file__).resolve().parents[2]
README_PATH = REPO_ROOT / "README.md"


async def _wait_for_socket(path: Path, timeout: float = 5.0) -> None:
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if path.exists():
            return
        await asyncio.sleep(0.01)
    raise TimeoutError(f"Timed out waiting for socket {path}")


def _install_totp_fs_read_planner(
    monkeypatch: pytest.MonkeyPatch,
    *,
    target_path: Path,
    marker: str,
) -> None:
    async def _planner_fs_read(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (user_content, tools, persona_tone_override)
        proposal = ActionProposal(
            action_id=f"u9-chat-{marker}",
            tool_name=ToolName("fs.read"),
            arguments={
                "path": str(target_path),
                "max_bytes": 4096,
            },
            reasoning="exercise chat TOTP confirmation path",
            data_sources=[],
        )
        decision = self._pep.evaluate(proposal.tool_name, proposal.arguments, context)
        return PlannerResult(
            output=PlannerOutput(
                assistant_response="pending reauthenticated approval",
                actions=[proposal],
            ),
            evaluated=[EvaluatedProposal(proposal=proposal, decision=decision)],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _planner_fs_read)


def _totp_fs_read_policy() -> str:
    return (
        textwrap.dedent(
            """
            version: "1"
            default_require_confirmation: false
            default_capabilities:
              - file.read
            tools:
              fs.read:
                capabilities_required:
                  - file.read
                confirmation:
                  level: reauthenticated
                  methods:
                    - totp
            """
        ).strip()
        + "\n"
    )


def _software_retrieve_confirmation_policy() -> str:
    return (
        textwrap.dedent(
            """
            version: "1"
            default_require_confirmation: true
            default_capabilities:
              - memory.read
            tools:
              retrieve_rag:
                capabilities_required:
                  - memory.read
                confirmation:
                  level: software
            """
        ).strip()
        + "\n"
    )


def _install_lt2_retrieve_planner(
    monkeypatch: pytest.MonkeyPatch,
    *,
    planner_calls: list[str],
) -> None:
    async def _planner_retrieve(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (tools, persona_tone_override)
        planner_calls.append(user_content)
        proposal = ActionProposal(
            action_id=f"lt2-retrieve-{len(planner_calls)}",
            tool_name=ToolName("retrieve_rag"),
            arguments={
                "query": user_content[:120],
                "limit": 5,
            },
            reasoning="exercise LT2 confirmation command routing",
            data_sources=["memory_index"],
        )
        decision = self._pep.evaluate(proposal.tool_name, proposal.arguments, context)
        return PlannerResult(
            output=PlannerOutput(
                assistant_response="pending software approval",
                actions=[proposal],
            ),
            evaluated=[EvaluatedProposal(proposal=proposal, decision=decision)],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _planner_retrieve)


@pytest.mark.asyncio
async def test_lt2_session_message_confirmation_commands_do_not_reenter_planner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")
    planner_calls: list[str] = []
    _install_lt2_retrieve_planner(monkeypatch, planner_calls=planner_calls)

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_software_retrieve_confirmation_policy(), encoding="utf-8")
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        assistant_fs_roots=[REPO_ROOT],
        log_level="INFO",
    )
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    transcript_store = TranscriptStore(config.data_dir / "sessions")

    async def _send(session_id: str, content: str) -> dict[str, object]:
        return await client.call(
            "session.message",
            {
                "session_id": session_id,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "content": content,
            },
        )

    async def _pending_count(session_id: str) -> int:
        pending = await client.call(
            "action.pending",
            {"session_id": session_id, "status": "pending", "limit": 10},
        )
        return int(pending["count"])

    async def _queue_pending(session_id: str, content: str) -> dict[str, object]:
        before_calls = len(planner_calls)
        reply = await _send(session_id, content)
        assert len(planner_calls) == before_calls + 1
        assert int(reply["confirmation_required_actions"]) >= 1
        assert reply["lockdown_level"] == "normal"
        response_text = str(reply.get("response", "")).lower()
        assert "confirm 1" in response_text
        assert "[lockdown notice]" not in response_text
        entries = transcript_store.list_entries(SessionId(session_id))
        assert entries[-1].metadata.get("system_generated_pending_confirmations") is True
        return reply

    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = str(created["session_id"])
        await _queue_pending(sid, "queue approval one")

        before_calls = len(planner_calls)
        typo = await _send(sid, "comfirm 1")
        assert len(planner_calls) == before_calls
        typo_response = str(typo.get("response", "")).lower()
        assert "did you mean 'confirm 1'" in typo_response
        assert "no action was taken" in typo_response
        assert "[lockdown notice]" not in typo_response
        assert typo["lockdown_level"] == "normal"
        entries = transcript_store.list_entries(SessionId(sid))
        assert entries[-1].metadata.get("system_generated_pending_confirmations") is not True
        assert await _pending_count(sid) == 1

        reject_typo = await _send(sid, "rejct 1")
        assert len(planner_calls) == before_calls
        reject_typo_response = str(reject_typo.get("response", "")).lower()
        assert "did you mean 'reject 1'" in reject_typo_response
        assert "no action was taken" in reject_typo_response
        assert "[lockdown notice]" not in reject_typo_response
        assert reject_typo["lockdown_level"] == "normal"
        assert await _pending_count(sid) == 1

        single_word_typo = await _send(sid, "comfirm")
        assert len(planner_calls) == before_calls
        single_word_typo_response = str(single_word_typo.get("response", "")).lower()
        assert "did you mean 'confirm'" in single_word_typo_response
        assert "no action was taken" in single_word_typo_response
        assert "[lockdown notice]" not in single_word_typo_response
        assert single_word_typo["lockdown_level"] == "normal"
        assert await _pending_count(sid) == 1

        bad_index = await _send(sid, "confirm 2")
        assert len(planner_calls) == before_calls
        bad_index_response = str(bad_index.get("response", "")).lower()
        assert "confirmation index 2 is not pending" in bad_index_response
        assert "no action was taken" in bad_index_response
        assert "[lockdown notice]" not in bad_index_response
        assert bad_index["lockdown_level"] == "normal"
        entries = transcript_store.list_entries(SessionId(sid))
        assert entries[-1].metadata.get("system_generated_pending_confirmations") is not True
        assert await _pending_count(sid) == 1

        pending = await client.call(
            "action.pending",
            {"session_id": sid, "status": "pending", "limit": 10},
        )
        confirmation_id = str(pending["actions"][0]["confirmation_id"])
        for invalid_command in (
            f"shisad action confirm {confirmation_id}",
            f"run 'shisad action confirm {confirmation_id}'",
            f"Then run 'shisad action reject {confirmation_id}'",
            "Review all pending: shisad action pending",
            confirmation_id,
        ):
            invalid = await _send(sid, invalid_command)
            assert len(planner_calls) == before_calls
            invalid_response = str(invalid.get("response", "")).lower()
            assert "no action was taken" in invalid_response
            assert "[lockdown notice]" not in invalid_response
            assert invalid["lockdown_level"] == "normal"
            assert await _pending_count(sid) == 1

        bare_index = await _send(sid, "1")
        assert len(planner_calls) == before_calls
        bare_response = str(bare_index.get("response", "")).lower()
        assert "confirmed 1" in bare_response
        assert "[lockdown notice]" not in bare_response
        assert bare_index["lockdown_level"] == "normal"
        assert await _pending_count(sid) == 0

        await _queue_pending(sid, "queue approval two")
        before_confirm_calls = len(planner_calls)
        confirmed = await _send(sid, "confirm 1")
        assert len(planner_calls) == before_confirm_calls
        confirm_response = str(confirmed.get("response", "")).lower()
        assert "confirmed 1" in confirm_response
        assert "[lockdown notice]" not in confirm_response
        assert confirmed["lockdown_level"] == "normal"
        assert await _pending_count(sid) == 0
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_m6_crc_chat_yes_resolves_pending_confirmation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: "1"
            default_require_confirmation: true
            default_capabilities:
              - memory.read
            tools:
              retrieve_rag:
                capabilities_required:
                  - memory.read
                confirmation:
                  level: software
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        assistant_fs_roots=[REPO_ROOT],
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
        first = await client.call(
            "session.message",
            {
                "session_id": sid,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "content": "retrieve: project roadmap",
            },
        )
        assert first["confirmation_required_actions"] >= 1
        assert first["pending_confirmation_ids"]
        response_text = str(first.get("response", "")).lower()
        assert "confirm 1" in response_text
        assert "yes to all" not in response_text
        assert "shisad action confirm" in response_text

        second = await client.call(
            "session.message",
            {
                "session_id": sid,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "content": "yes",
            },
        )
        assert "control api" not in str(second.get("response", "")).lower()

        pending = await client.call(
            "action.pending",
            {"session_id": sid, "status": "pending", "limit": 10},
        )
        assert pending["count"] == 0
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_m6_crc_chat_reject_resolves_pending_confirmation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: "1"
            default_require_confirmation: true
            default_capabilities:
              - memory.read
            tools:
              retrieve_rag:
                capabilities_required:
                  - memory.read
                confirmation:
                  level: software
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        assistant_fs_roots=[REPO_ROOT],
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
        first = await client.call(
            "session.message",
            {
                "session_id": sid,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "content": "retrieve: project roadmap",
            },
        )
        assert first["confirmation_required_actions"] >= 1

        second = await client.call(
            "session.message",
            {
                "session_id": sid,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "content": "reject 1",
            },
        )
        assert "rejected 1" in str(second.get("response", "")).lower()

        pending = await client.call(
            "action.pending",
            {"session_id": sid, "status": "pending", "limit": 10},
        )
        assert pending["count"] == 0
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_g1_chat_confirmation_early_return_persists_assistant_transcript_and_audit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: "1"
            default_require_confirmation: true
            default_capabilities:
              - memory.read
            tools:
              retrieve_rag:
                capabilities_required:
                  - memory.read
                confirmation:
                  level: software
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        assistant_fs_roots=[REPO_ROOT],
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
        transcript_store = TranscriptStore(config.data_dir / "sessions")
        audit_log = AuditLog(config.data_dir / "audit.jsonl")

        first = await client.call(
            "session.message",
            {
                "session_id": sid,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "content": "retrieve: project roadmap",
            },
        )
        assert first["confirmation_required_actions"] >= 1
        before_entries = transcript_store.list_entries(sid)
        before_responded = audit_log.query(
            event_type="SessionMessageResponded",
            session_id=sid,
            limit=10,
        )

        second = await client.call(
            "session.message",
            {
                "session_id": sid,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "content": "yes",
            },
        )

        after_entries = transcript_store.list_entries(sid)
        after_responded = audit_log.query(
            event_type="SessionMessageResponded",
            session_id=sid,
            limit=10,
        )

        assert len(after_entries) == len(before_entries) + 2
        assert after_entries[-2].role == "user"
        assert after_entries[-2].content_preview == "yes"
        assert after_entries[-1].role == "assistant"
        assert after_entries[-1].content_preview == second["response"]
        assert len(after_responded) == len(before_responded) + 1
        assert after_responded[-1]["data"]["executed_actions"] == second["executed_actions"]
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_u9_chat_totp_bare_code_confirms_single_pending_action(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")
    target = README_PATH
    _install_totp_fs_read_planner(monkeypatch, target_path=target, marker="single")

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_totp_fs_read_policy(), encoding="utf-8")
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        assistant_fs_roots=[REPO_ROOT],
        log_level="INFO",
    )
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        started = await client.call(
            "2fa.register_begin",
            {"method": "totp", "user_id": "alice", "name": "ops-laptop"},
        )
        enrolled = await client.call(
            "2fa.register_confirm",
            {
                "enrollment_id": started["enrollment_id"],
                "verify_code": generate_totp_code(str(started["secret"])),
            },
        )
        assert enrolled["registered"] is True

        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = created["session_id"]
        first = await client.call(
            "session.message",
            {
                "session_id": sid,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "content": "run the queued action",
            },
        )
        assert first["confirmation_required_actions"] >= 1
        response_text = str(first.get("response", "")).lower()
        assert "6-digit code" in response_text
        assert str(first["pending_confirmation_ids"][0]).lower() in response_text
        assert "shisad action confirm" in response_text
        assert "--totp-code 123456" in response_text

        code = generate_totp_code(str(started["secret"]))
        second = await client.call(
            "session.message",
            {
                "session_id": sid,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "content": code,
            },
        )

        assert second["executed_actions"] == 1
        assert second["confirmation_required_actions"] == 0
        assert second["blocked_actions"] == 0
        assert "confirmed" in str(second.get("response", "")).lower()
        assert code not in str(second.get("response", ""))

        pending = await client.call(
            "action.pending",
            {"session_id": sid, "status": "pending", "limit": 10},
        )
        assert pending["count"] == 0

        approved = await client.call(
            "audit.query",
            {"event_type": "ToolApproved", "session_id": sid, "limit": 20},
        )
        assert any(
            str(event.get("data", {}).get("approval_method", "")) == "totp"
            and str(event.get("data", {}).get("tool_name", "")) == "fs.read"
            for event in approved.get("events", [])
        )
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_u9_channel_ingest_totp_code_confirms_trusted_chat_reply(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")
    target = README_PATH
    _install_totp_fs_read_planner(monkeypatch, target_path=target, marker="channel-ingest")

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_totp_fs_read_policy(), encoding="utf-8")
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        assistant_fs_roots=[REPO_ROOT],
        log_level="INFO",
    )
    services = await DaemonServices.build(config)
    try:
        services.identity_map.configure_channel_trust(channel="discord", trust_level="trusted")
        services.identity_map.allow_identity(channel="discord", external_user_id="alice")
        handlers = DaemonControlHandlers(services=services)
        ctx = RequestContext()

        started = await handlers.handle_two_factor_register_begin(
            TwoFactorRegisterBeginParams(method="totp", user_id="alice", name="ops-laptop"),
            ctx,
        )
        enrolled = await handlers.handle_two_factor_register_confirm(
            TwoFactorRegisterConfirmParams(
                enrollment_id=started.enrollment_id,
                verify_code=generate_totp_code(str(started.secret)),
            ),
            ctx,
        )
        assert enrolled.registered is True

        first = await handlers.handle_channel_ingest(
            ChannelIngestParams(
                message={
                    "channel": "discord",
                    "external_user_id": "alice",
                    "workspace_hint": "guild-1",
                    "content": "run the queued action",
                    "message_id": "m-1",
                    "reply_target": "chan-1",
                }
            ),
            ctx,
        )
        assert first.confirmation_required_actions >= 1
        response_text = str(first.response).lower()
        assert "6-digit code" in response_text
        assert str(first.pending_confirmation_ids[0]).lower() in response_text
        assert "shisad action confirm" in response_text
        assert "--totp-code 123456" in response_text

        code = generate_totp_code(str(started.secret))
        second = await handlers.handle_channel_ingest(
            ChannelIngestParams(
                message={
                    "channel": "discord",
                    "external_user_id": "alice",
                    "workspace_hint": "guild-1",
                    "content": code,
                    "message_id": "m-2",
                    "reply_target": "chan-1",
                }
            ),
            ctx,
        )

        assert second.executed_actions == 1
        assert second.confirmation_required_actions == 0
        assert second.blocked_actions == 0
        assert "confirmed" in str(second.response).lower()
        assert code not in str(second.response)

        pending = await handlers.handle_action_pending(
            ActionPendingParams(session_id=first.session_id, status="pending", limit=10),
            ctx,
        )
        assert pending.count == 0

        approved = await handlers.handle_audit_query(
            AuditQueryParams(event_type="ToolApproved", session_id=first.session_id, limit=20),
            ctx,
        )
        assert any(
            str(event.get("data", {}).get("approval_method", "")) == "totp"
            and str(event.get("data", {}).get("tool_name", "")) == "fs.read"
            for event in approved.events
        )
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_u9_channel_ingest_totp_code_mismatched_reply_target_does_not_rebind_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")
    target = README_PATH

    async def _planner_for_mismatch_test(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (tools, persona_tone_override)
        if "run the queued action" not in user_content:
            return PlannerResult(
                output=PlannerOutput(
                    assistant_response="no new action requested",
                    actions=[],
                ),
                evaluated=[],
                attempts=1,
                provider_response=None,
                messages_sent=(),
            )
        proposal = ActionProposal(
            action_id="u9-chat-channel-mismatch",
            tool_name=ToolName("fs.read"),
            arguments={
                "path": str(target),
                "max_bytes": 4096,
            },
            reasoning="exercise channel-ingest delivery-target binding",
            data_sources=[],
        )
        decision = self._pep.evaluate(proposal.tool_name, proposal.arguments, context)
        return PlannerResult(
            output=PlannerOutput(
                assistant_response="pending reauthenticated approval",
                actions=[proposal],
            ),
            evaluated=[EvaluatedProposal(proposal=proposal, decision=decision)],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _planner_for_mismatch_test)

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_totp_fs_read_policy(), encoding="utf-8")
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        assistant_fs_roots=[REPO_ROOT],
        log_level="INFO",
    )
    services = await DaemonServices.build(config)
    try:
        services.identity_map.configure_channel_trust(channel="discord", trust_level="trusted")
        services.identity_map.allow_identity(channel="discord", external_user_id="alice")
        handlers = DaemonControlHandlers(services=services)
        ctx = RequestContext()

        started = await handlers.handle_two_factor_register_begin(
            TwoFactorRegisterBeginParams(method="totp", user_id="alice", name="ops-laptop"),
            ctx,
        )
        enrolled = await handlers.handle_two_factor_register_confirm(
            TwoFactorRegisterConfirmParams(
                enrollment_id=started.enrollment_id,
                verify_code=generate_totp_code(str(started.secret)),
            ),
            ctx,
        )
        assert enrolled.registered is True

        first = await handlers.handle_channel_ingest(
            ChannelIngestParams(
                message={
                    "channel": "discord",
                    "external_user_id": "alice",
                    "workspace_hint": "guild-1",
                    "content": "run the queued action",
                    "message_id": "m-1",
                    "reply_target": "chan-1",
                }
            ),
            ctx,
        )
        assert first.confirmation_required_actions >= 1

        primed = await handlers.handle_channel_ingest(
            ChannelIngestParams(
                message={
                    "channel": "discord",
                    "external_user_id": "alice",
                    "workspace_hint": "guild-1",
                    "content": "still there?",
                    "message_id": "m-2",
                    "reply_target": "chan-2",
                }
            ),
            ctx,
        )
        assert "no new action requested" in str(primed.response).lower()
        primed_target = services.session_manager.get(first.session_id).metadata.get(
            "delivery_target"
        )
        assert isinstance(primed_target, dict)
        assert primed_target.get("channel") == "discord"
        assert primed_target.get("recipient") == "chan-1"

        wrong_target_code = generate_totp_code(str(started.secret))
        mismatched = await handlers.handle_channel_ingest(
            ChannelIngestParams(
                message={
                    "channel": "discord",
                    "external_user_id": "alice",
                    "workspace_hint": "guild-1",
                    "content": wrong_target_code,
                    "message_id": "m-3",
                    "reply_target": "chan-2",
                }
            ),
            ctx,
        )
        assert mismatched.executed_actions == 0
        assert mismatched.confirmation_required_actions == 0
        assert mismatched.pending_confirmation_ids == []
        response = str(mismatched.response).lower()
        assert "different chat target" in response
        assert "original approval thread/channel" in response
        assert "shisad action pending" in response
        assert "shisad action confirm confirmation_id --totp-code 123456" in response
        assert "confirmation id:" not in response
        assert "pending confirmations." not in response
        mismatched_target = services.session_manager.get(first.session_id).metadata.get(
            "delivery_target"
        )
        assert isinstance(mismatched_target, dict)
        assert mismatched_target.get("channel") == "discord"
        assert mismatched_target.get("recipient") == "chan-1"
        pending = await handlers.handle_action_pending(
            ActionPendingParams(session_id=first.session_id, status="pending", limit=10),
            ctx,
        )
        assert pending.count == 1

        valid_target_code = generate_totp_code(str(started.secret))
        second = await handlers.handle_channel_ingest(
            ChannelIngestParams(
                message={
                    "channel": "discord",
                    "external_user_id": "alice",
                    "workspace_hint": "guild-1",
                    "content": valid_target_code,
                    "message_id": "m-4",
                    "reply_target": "chan-1",
                }
            ),
            ctx,
        )

        assert second.executed_actions == 1
        assert second.confirmation_required_actions == 0
        assert "confirmed" in str(second.response).lower()

        pending = await handlers.handle_action_pending(
            ActionPendingParams(session_id=first.session_id, status="pending", limit=10),
            ctx,
        )
        assert pending.count == 0
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_u9_channel_ingest_rejects_totp_pending_action_via_trusted_chat_reply(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")
    target = README_PATH
    _install_totp_fs_read_planner(monkeypatch, target_path=target, marker="channel-reject")

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_totp_fs_read_policy(), encoding="utf-8")
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        assistant_fs_roots=[REPO_ROOT],
        log_level="INFO",
    )
    services = await DaemonServices.build(config)
    try:
        services.identity_map.configure_channel_trust(channel="discord", trust_level="trusted")
        services.identity_map.allow_identity(channel="discord", external_user_id="alice")
        handlers = DaemonControlHandlers(services=services)
        ctx = RequestContext()

        started = await handlers.handle_two_factor_register_begin(
            TwoFactorRegisterBeginParams(method="totp", user_id="alice", name="ops-laptop"),
            ctx,
        )
        enrolled = await handlers.handle_two_factor_register_confirm(
            TwoFactorRegisterConfirmParams(
                enrollment_id=started.enrollment_id,
                verify_code=generate_totp_code(str(started.secret)),
            ),
            ctx,
        )
        assert enrolled.registered is True

        first = await handlers.handle_channel_ingest(
            ChannelIngestParams(
                message={
                    "channel": "discord",
                    "external_user_id": "alice",
                    "workspace_hint": "guild-1",
                    "content": "run the queued action",
                    "message_id": "m-1",
                    "reply_target": "chan-1",
                }
            ),
            ctx,
        )
        assert first.confirmation_required_actions >= 1

        for offset, invalid_content in enumerate(
            (
                "confirm 1",
                "comfirm 1",
                "Then run 'shisad action reject confirmation_id'",
                "Review all pending: shisad action pending",
            ),
            start=2,
        ):
            invalid = await handlers.handle_channel_ingest(
                ChannelIngestParams(
                    message={
                        "channel": "discord",
                        "external_user_id": "alice",
                        "workspace_hint": "guild-1",
                        "content": invalid_content,
                        "message_id": f"m-{offset}",
                        "reply_target": "chan-1",
                    }
                ),
                ctx,
            )
            invalid_response = str(invalid.response).lower()
            assert invalid.executed_actions == 0
            assert invalid.confirmation_required_actions == 1
            if "shisad action" in invalid_content:
                assert "cli action commands must be run from a shell" in invalid_response
            else:
                assert "not accepted without proof" in invalid_response
            assert "no action was taken" in invalid_response
            pending = await handlers.handle_action_pending(
                ActionPendingParams(session_id=first.session_id, status="pending", limit=10),
                ctx,
            )
            assert pending.count == 1

        second = await handlers.handle_channel_ingest(
            ChannelIngestParams(
                message={
                    "channel": "discord",
                    "external_user_id": "alice",
                    "workspace_hint": "guild-1",
                    "content": "reject 1",
                    "message_id": "m-6",
                    "reply_target": "chan-1",
                }
            ),
            ctx,
        )

        assert second.executed_actions == 0
        assert second.blocked_actions >= 1
        assert "rejected 1" in str(second.response).lower()

        pending = await handlers.handle_action_pending(
            ActionPendingParams(session_id=first.session_id, status="pending", limit=10),
            ctx,
        )
        assert pending.count == 0

        rejected = await handlers.handle_audit_query(
            AuditQueryParams(event_type="ToolRejected", session_id=first.session_id, limit=20),
            ctx,
        )
        assert any(
            str(event.get("data", {}).get("tool_name", "")) == "fs.read"
            for event in rejected.events
        )
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_u9_channel_ingest_scopes_totp_confirmation_to_pending_delivery_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")
    target = README_PATH
    _install_totp_fs_read_planner(
        monkeypatch,
        target_path=target,
        marker="channel-thread-binding",
    )

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_totp_fs_read_policy(), encoding="utf-8")
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        assistant_fs_roots=[REPO_ROOT],
        log_level="INFO",
    )
    services = await DaemonServices.build(config)
    try:
        services.identity_map.configure_channel_trust(channel="discord", trust_level="trusted")
        services.identity_map.allow_identity(channel="discord", external_user_id="alice")
        handlers = DaemonControlHandlers(services=services)
        ctx = RequestContext()

        started = await handlers.handle_two_factor_register_begin(
            TwoFactorRegisterBeginParams(method="totp", user_id="alice", name="ops-laptop"),
            ctx,
        )
        enrolled = await handlers.handle_two_factor_register_confirm(
            TwoFactorRegisterConfirmParams(
                enrollment_id=started.enrollment_id,
                verify_code=generate_totp_code(str(started.secret)),
            ),
            ctx,
        )
        assert enrolled.registered is True

        first = await handlers.handle_channel_ingest(
            ChannelIngestParams(
                message={
                    "channel": "discord",
                    "external_user_id": "alice",
                    "workspace_hint": "guild-1",
                    "content": "queue the first action",
                    "message_id": "m-1",
                    "reply_target": "chan-1",
                }
            ),
            ctx,
        )
        assert first.confirmation_required_actions >= 1
        first_id = str(first.pending_confirmation_ids[0])

        second = await handlers.handle_channel_ingest(
            ChannelIngestParams(
                message={
                    "channel": "discord",
                    "external_user_id": "alice",
                    "workspace_hint": "guild-1",
                    "content": "queue the second action",
                    "message_id": "m-2",
                    "reply_target": "chan-2",
                }
            ),
            ctx,
        )
        assert second.confirmation_required_actions >= 1
        second_id = str(second.pending_confirmation_ids[0])
        assert first.session_id == second.session_id
        assert first_id != second_id
        second_response = str(second.response).lower()
        assert "reply with the 6-digit code" in second_response
        assert "reject 1" in second_response
        assert "reject 2" not in second_response
        assert f"confirm {second_id} 123456".lower() not in second_response
        assert first_id.lower() not in second_response

        pending = await handlers.handle_action_pending(
            ActionPendingParams(session_id=first.session_id, status="pending", limit=10),
            ctx,
        )
        assert pending.count == 2

        wrong_thread = await handlers.handle_channel_ingest(
            ChannelIngestParams(
                message={
                    "channel": "discord",
                    "external_user_id": "alice",
                    "workspace_hint": "guild-1",
                    "content": f"confirm {second_id} {generate_totp_code(str(started.secret))}",
                    "message_id": "m-3",
                    "reply_target": "chan-1",
                }
            ),
            ctx,
        )

        assert wrong_thread.executed_actions == 0
        assert wrong_thread.confirmation_required_actions == 1
        assert wrong_thread.pending_confirmation_ids == []
        wrong_response = str(wrong_thread.response).lower()
        assert "different chat target" in wrong_response
        assert second_id.lower() not in wrong_response

        pending = await handlers.handle_action_pending(
            ActionPendingParams(session_id=first.session_id, status="pending", limit=10),
            ctx,
        )
        assert pending.count == 2

        right_thread = await handlers.handle_channel_ingest(
            ChannelIngestParams(
                message={
                    "channel": "discord",
                    "external_user_id": "alice",
                    "workspace_hint": "guild-1",
                    "content": f"confirm {second_id} {generate_totp_code(str(started.secret))}",
                    "message_id": "m-4",
                    "reply_target": "chan-2",
                }
            ),
            ctx,
        )

        assert right_thread.executed_actions == 1
        assert right_thread.confirmation_required_actions == 0
        assert right_thread.pending_confirmation_ids == []
        right_response = str(right_thread.response).lower()
        assert f"confirmed {second_id}".lower() in right_response
        assert first_id.lower() not in right_response

        pending = await handlers.handle_action_pending(
            ActionPendingParams(session_id=first.session_id, status="pending", limit=10),
            ctx,
        )
        assert pending.count == 1
        assert pending.actions[0].confirmation_id == first_id
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_u9_channel_ingest_scopes_totp_reject_index_to_visible_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")
    target = README_PATH
    _install_totp_fs_read_planner(
        monkeypatch,
        target_path=target,
        marker="channel-thread-reject",
    )

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_totp_fs_read_policy(), encoding="utf-8")
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        assistant_fs_roots=[REPO_ROOT],
        log_level="INFO",
    )
    services = await DaemonServices.build(config)
    try:
        services.identity_map.configure_channel_trust(channel="discord", trust_level="trusted")
        services.identity_map.allow_identity(channel="discord", external_user_id="alice")
        handlers = DaemonControlHandlers(services=services)
        ctx = RequestContext()

        started = await handlers.handle_two_factor_register_begin(
            TwoFactorRegisterBeginParams(method="totp", user_id="alice", name="ops-laptop"),
            ctx,
        )
        enrolled = await handlers.handle_two_factor_register_confirm(
            TwoFactorRegisterConfirmParams(
                enrollment_id=started.enrollment_id,
                verify_code=generate_totp_code(str(started.secret)),
            ),
            ctx,
        )
        assert enrolled.registered is True

        first = await handlers.handle_channel_ingest(
            ChannelIngestParams(
                message={
                    "channel": "discord",
                    "external_user_id": "alice",
                    "workspace_hint": "guild-1",
                    "content": "queue the first action",
                    "message_id": "m-1",
                    "reply_target": "chan-1",
                }
            ),
            ctx,
        )
        first_id = str(first.pending_confirmation_ids[0])

        second = await handlers.handle_channel_ingest(
            ChannelIngestParams(
                message={
                    "channel": "discord",
                    "external_user_id": "alice",
                    "workspace_hint": "guild-1",
                    "content": "queue the second action",
                    "message_id": "m-2",
                    "reply_target": "chan-2",
                }
            ),
            ctx,
        )
        second_id = str(second.pending_confirmation_ids[0])

        reject = await handlers.handle_channel_ingest(
            ChannelIngestParams(
                message={
                    "channel": "discord",
                    "external_user_id": "alice",
                    "workspace_hint": "guild-1",
                    "content": "reject 1",
                    "message_id": "m-3",
                    "reply_target": "chan-2",
                }
            ),
            ctx,
        )

        assert reject.executed_actions == 0
        assert reject.blocked_actions >= 1
        assert reject.confirmation_required_actions == 0
        assert reject.pending_confirmation_ids == []
        response = str(reject.response).lower()
        assert "rejected 1" in response
        assert "different chat target" not in response
        assert first_id.lower() not in response

        pending = await handlers.handle_action_pending(
            ActionPendingParams(session_id=first.session_id, status="pending", limit=10),
            ctx,
        )
        assert pending.count == 1
        assert pending.actions[0].confirmation_id == first_id
        assert pending.actions[0].confirmation_id != second_id
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_u9_channel_ingest_wrong_target_reject_uses_reject_cli_recovery_guidance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")
    target = README_PATH
    _install_totp_fs_read_planner(
        monkeypatch,
        target_path=target,
        marker="channel-wrong-target-reject",
    )

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_totp_fs_read_policy(), encoding="utf-8")
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        assistant_fs_roots=[REPO_ROOT],
        log_level="INFO",
    )
    services = await DaemonServices.build(config)
    try:
        services.identity_map.configure_channel_trust(channel="discord", trust_level="trusted")
        services.identity_map.allow_identity(channel="discord", external_user_id="alice")
        handlers = DaemonControlHandlers(services=services)
        ctx = RequestContext()

        started = await handlers.handle_two_factor_register_begin(
            TwoFactorRegisterBeginParams(method="totp", user_id="alice", name="ops-laptop"),
            ctx,
        )
        enrolled = await handlers.handle_two_factor_register_confirm(
            TwoFactorRegisterConfirmParams(
                enrollment_id=started.enrollment_id,
                verify_code=generate_totp_code(str(started.secret)),
            ),
            ctx,
        )
        assert enrolled.registered is True

        first = await handlers.handle_channel_ingest(
            ChannelIngestParams(
                message={
                    "channel": "discord",
                    "external_user_id": "alice",
                    "workspace_hint": "guild-1",
                    "content": "run the queued action",
                    "message_id": "m-1",
                    "reply_target": "chan-1",
                }
            ),
            ctx,
        )
        assert first.confirmation_required_actions >= 1

        wrong_target_reject = await handlers.handle_channel_ingest(
            ChannelIngestParams(
                message={
                    "channel": "discord",
                    "external_user_id": "alice",
                    "workspace_hint": "guild-1",
                    "content": "reject 1",
                    "message_id": "m-2",
                    "reply_target": "chan-2",
                }
            ),
            ctx,
        )

        assert wrong_target_reject.executed_actions == 0
        assert wrong_target_reject.confirmation_required_actions == 0
        assert wrong_target_reject.pending_confirmation_ids == []
        response = str(wrong_target_reject.response).lower()
        assert "different chat target" in response
        assert "original approval thread/channel" in response
        assert "shisad action pending" in response
        assert "shisad action reject confirmation_id" in response
        assert "shisad action confirm confirmation_id --totp-code 123456" not in response
        assert "confirmation id:" not in response

        pending = await handlers.handle_action_pending(
            ActionPendingParams(session_id=first.session_id, status="pending", limit=10),
            ctx,
        )
        assert pending.count == 1
        stored_target = services.session_manager.get(first.session_id).metadata.get(
            "delivery_target"
        )
        assert isinstance(stored_target, dict)
        assert stored_target.get("channel") == "discord"
        assert stored_target.get("recipient") == "chan-1"
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_u9_chat_totp_expired_code_attempts_trigger_lockout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")
    target = README_PATH
    _install_totp_fs_read_planner(monkeypatch, target_path=target, marker="lockout")

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_totp_fs_read_policy(), encoding="utf-8")
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        assistant_fs_roots=[REPO_ROOT],
        log_level="INFO",
    )
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        started = await client.call(
            "2fa.register_begin",
            {"method": "totp", "user_id": "alice", "name": "ops-laptop"},
        )
        enrolled = await client.call(
            "2fa.register_confirm",
            {
                "enrollment_id": started["enrollment_id"],
                "verify_code": generate_totp_code(str(started["secret"])),
            },
        )
        assert enrolled["registered"] is True

        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = created["session_id"]
        first = await client.call(
            "session.message",
            {
                "session_id": sid,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "content": "run the queued action",
            },
        )
        assert first["confirmation_required_actions"] >= 1

        expired_code = generate_totp_code(
            str(started["secret"]),
            now=datetime.now(UTC) - timedelta(minutes=10),
        )
        for _ in range(5):
            attempt = await client.call(
                "session.message",
                {
                    "session_id": sid,
                    "channel": "cli",
                    "user_id": "alice",
                    "workspace_id": "ws1",
                    "content": expired_code,
                },
            )
            assert "invalid_totp_code" in str(attempt.get("response", "")).lower()
            assert attempt["executed_actions"] == 0

        valid_code = generate_totp_code(str(started["secret"]))
        locked = await client.call(
            "session.message",
            {
                "session_id": sid,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "content": valid_code,
            },
        )
        assert locked["executed_actions"] == 0
        assert "confirmation_method_locked_out" in str(locked.get("response", "")).lower()
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_u9_chat_totp_reused_code_is_rejected_for_later_pending_action(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")
    target = README_PATH
    _install_totp_fs_read_planner(monkeypatch, target_path=target, marker="reuse")

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_totp_fs_read_policy(), encoding="utf-8")
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        assistant_fs_roots=[REPO_ROOT],
        log_level="INFO",
    )
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        started = await client.call(
            "2fa.register_begin",
            {"method": "totp", "user_id": "alice", "name": "ops-laptop"},
        )
        enrolled = await client.call(
            "2fa.register_confirm",
            {
                "enrollment_id": started["enrollment_id"],
                "verify_code": generate_totp_code(str(started["secret"])),
            },
        )
        assert enrolled["registered"] is True

        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = created["session_id"]
        code = generate_totp_code(str(started["secret"]))

        first = await client.call(
            "session.message",
            {
                "session_id": sid,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "content": "run the queued action",
            },
        )
        assert first["confirmation_required_actions"] >= 1
        approved = await client.call(
            "session.message",
            {
                "session_id": sid,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "content": code,
            },
        )
        assert approved["executed_actions"] == 1

        second = await client.call(
            "session.message",
            {
                "session_id": sid,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "content": "run the queued action again",
            },
        )
        assert second["confirmation_required_actions"] >= 1
        reused = await client.call(
            "session.message",
            {
                "session_id": sid,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "content": code,
            },
        )
        assert reused["executed_actions"] == 0
        assert "totp_code_reused" in str(reused.get("response", "")).lower()
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)
