"""Tests for daemon.reset RPC and DaemonHarness."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from tests.helpers.daemon import clear_remote_provider_env, daemon_harness


@pytest.mark.asyncio
async def test_daemon_reset_clears_sessions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """daemon.reset wipes sessions so a subsequent list returns empty."""
    clear_remote_provider_env(monkeypatch)

    async with daemon_harness(tmp_path) as harness:
        # Create two sessions.
        await harness.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        await harness.call(
            "session.create",
            {"channel": "cli", "user_id": "bob", "workspace_id": "ws1"},
        )

        status_before = await harness.call("daemon.status")
        assert status_before["sessions_active"] == 2

        # Reset.
        result = await harness.reset()
        assert result["status"] == "reset"
        assert result["quiescent"] is True
        assert all(result["invariants"].values())
        assert result["cleared"]["sessions"] == 2

        # Post-reset: no sessions.
        status_after = await harness.call("daemon.status")
        assert status_after["sessions_active"] == 0


@pytest.mark.asyncio
async def test_daemon_reset_clears_audit_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """daemon.reset resets the audit log chain so new entries start fresh."""
    clear_remote_provider_env(monkeypatch)

    async with daemon_harness(tmp_path) as harness:
        # Create a session to generate audit entries.
        await harness.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )

        status_before = await harness.call("daemon.status")
        assert status_before["audit_entries"] >= 1

        # Reset.
        result = await harness.reset()
        assert result["quiescent"] is True
        assert all(result["invariants"].values())
        assert result["cleared"]["audit_entries"] >= 1

        # Post-reset: audit count resets.
        status_after = await harness.call("daemon.status")
        assert status_after["audit_entries"] == 0


@pytest.mark.asyncio
async def test_daemon_reset_allows_new_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After reset the daemon accepts new sessions and messages normally."""
    clear_remote_provider_env(monkeypatch)

    async with daemon_harness(tmp_path) as harness:
        # First round of work.
        created_1 = await harness.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid_1 = created_1["session_id"]
        reply_1 = await harness.call(
            "session.message",
            {
                "session_id": sid_1,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "content": "hello",
            },
        )
        assert reply_1["response"]

        # Reset.
        result = await harness.reset()
        assert result["quiescent"] is True
        assert all(result["invariants"].values())

        # Second round of work — must succeed.
        created_2 = await harness.call(
            "session.create",
            {"channel": "cli", "user_id": "bob", "workspace_id": "ws2"},
        )
        sid_2 = created_2["session_id"]
        assert sid_2 != sid_1  # Different session.

        reply_2 = await harness.call(
            "session.message",
            {
                "session_id": sid_2,
                "channel": "cli",
                "user_id": "bob",
                "workspace_id": "ws2",
                "content": "world",
            },
        )
        assert reply_2["response"]

        # Only one session active after the second round.
        status = await harness.call("daemon.status")
        assert status["sessions_active"] == 1


@pytest.mark.asyncio
async def test_daemon_harness_context_manager_lifecycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """daemon_harness starts the daemon and shuts it down on context exit."""
    clear_remote_provider_env(monkeypatch)

    task_ref: asyncio.Task[None] | None = None

    async with daemon_harness(tmp_path) as harness:
        task_ref = harness.daemon_task
        assert not task_ref.done()

        status = await harness.call("daemon.status")
        assert status["status"] == "running"

    # After exiting the context, the task should be done.
    assert task_ref is not None
    assert task_ref.done()


@pytest.mark.asyncio
async def test_daemon_reset_is_not_registered_without_test_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)

    async with daemon_harness(tmp_path, config_kwargs={"test_mode": False}) as harness:
        with pytest.raises(RuntimeError, match=r"RPC error -32601|Method not found"):
            await harness.call("daemon.reset")
