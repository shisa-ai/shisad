"""M6 CRC integration coverage for chat-based confirmation resolution."""

from __future__ import annotations

import asyncio
import textwrap
from contextlib import suppress
from pathlib import Path

import pytest

from shisad.core.api.transport import ControlClient
from shisad.core.audit import AuditLog
from shisad.core.config import DaemonConfig
from shisad.core.transcript import TranscriptStore
from shisad.daemon.runner import run_daemon


async def _wait_for_socket(path: Path, timeout: float = 5.0) -> None:
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if path.exists():
            return
        await asyncio.sleep(0.01)
    raise TimeoutError(f"Timed out waiting for socket {path}")


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
            """
        ).strip()
        + "\n",
        encoding="utf-8",
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
            """
        ).strip()
        + "\n",
        encoding="utf-8",
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
            """
        ).strip()
        + "\n",
        encoding="utf-8",
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
