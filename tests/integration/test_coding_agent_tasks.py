"""v0.4 M3 coding-agent TASK-session integration checks."""

from __future__ import annotations

import asyncio
import json
import sys
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
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
    config_overrides: dict[str, Any] | None = None,
) -> tuple[asyncio.Task[None], ControlClient, DaemonConfig]:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(policy_text, encoding="utf-8")
    config_kwargs: dict[str, Any] = {
        "data_dir": tmp_path / "data",
        "socket_path": tmp_path / "control.sock",
        "policy_path": policy_path,
        "log_level": "INFO",
    }
    if config_overrides:
        config_kwargs.update(config_overrides)
    config = DaemonConfig(**config_kwargs)
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    await _wait_for_socket(config.socket_path)
    await client.connect()
    return daemon_task, client, config


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


def _policy_with_caps(*caps: str) -> str:
    lines = [
        'version: "1"',
        "default_require_confirmation: false",
        "default_capabilities:",
        *[f"  - {cap}" for cap in caps],
    ]
    return "\n".join(lines) + "\n"


def _fake_coding_agent_command(agent_name: str) -> str:
    script = Path(__file__).resolve().parents[1] / "fixtures" / "fake_acp_agent.py"
    return f"{sys.executable} {script} --agent-name {agent_name}"


def _broken_protocol_agent_command() -> str:
    script = Path(__file__).resolve().parents[1] / "fixtures" / "fake_acp_agent.py"
    return (
        f"{sys.executable} {script} --agent-name broken --fail-initialize"
    )


@pytest.mark.asyncio
async def test_m3_coding_task_runs_in_worktree_and_emits_coding_audit_events(
    tmp_path: Path,
) -> None:
    readme_before = Path("README.md").read_text(encoding="utf-8")
    daemon_task, client, _config = await _start_daemon(
        tmp_path,
        policy_text=_policy_with_caps("file.read", "file.write", "shell.exec", "http.request"),
        config_overrides={
            "coding_repo_root": Path.cwd(),
            "coding_agent_registry_overrides": {
                "codex": _fake_coding_agent_command("codex"),
            },
        },
    )
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = str(created["session_id"])
        result = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "run the coding agent",
                "task": {
                    "enabled": True,
                    "executor": "coding_agent",
                    "task_description": "Add a tiny implementation note to README.md.",
                    "file_refs": ["README.md"],
                    "capabilities": [
                        "file.read",
                        "file.write",
                        "shell.exec",
                        "http.request",
                    ],
                    "preferred_agent": "codex",
                    "task_kind": "implement",
                },
            },
        )

        task_result = dict(result.get("task_result") or {})
        assert task_result["success"] is True
        assert task_result["agent"] == "codex"
        assert task_result["proposal_ref"]
        assert task_result["raw_log_ref"]
        assert Path("README.md").read_text(encoding="utf-8") == readme_before

        proposal_payload = json.loads(Path(task_result["proposal_ref"]).read_text(encoding="utf-8"))
        assert "Fake ACP edit from codex" in proposal_payload["diff"]
        assert proposal_payload["files_changed"] == ["README.md"]

        selected_event = await _wait_for_event(
            client,
            event_type="CodingAgentSelected",
            predicate=lambda item: str(item.get("session_id", "")).strip()
            == str(task_result["task_session_id"]),
        )
        started_event = await _wait_for_event(
            client,
            event_type="CodingAgentSessionStarted",
            predicate=lambda item: str(item.get("session_id", "")).strip()
            == str(task_result["task_session_id"]),
        )
        completed_event = await _wait_for_event(
            client,
            event_type="CodingAgentSessionCompleted",
            predicate=lambda item: str(item.get("session_id", "")).strip()
            == str(task_result["task_session_id"]),
        )

        assert selected_event["data"]["selected_agent"] == "codex"
        assert started_event["data"]["agent"] == "codex"
        assert completed_event["data"]["agent"] == "codex"
        assert completed_event["data"]["success"] is True
        assert completed_event["data"]["files_changed"] == ["README.md"]
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_m3_coding_task_timeout_returns_partial_failure_without_repo_mutation(
    tmp_path: Path,
) -> None:
    readme_before = Path("README.md").read_text(encoding="utf-8")
    daemon_task, client, _config = await _start_daemon(
        tmp_path,
        policy_text=_policy_with_caps("file.read", "file.write", "shell.exec"),
        config_overrides={
            "coding_repo_root": Path.cwd(),
            "coding_agent_registry_overrides": {
                "opencode": _fake_coding_agent_command("opencode"),
            },
        },
    )
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = str(created["session_id"])
        result = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "run the slow coding agent",
                "task": {
                    "enabled": True,
                    "executor": "coding_agent",
                    "task_description": "Implement slowly.\nSLEEP: 0.25",
                    "file_refs": ["README.md"],
                    "capabilities": ["file.read", "file.write", "shell.exec"],
                    "preferred_agent": "opencode",
                    "task_kind": "implement",
                    "timeout_sec": 0.05,
                },
            },
        )

        task_result = dict(result.get("task_result") or {})
        assert task_result["success"] is False
        assert task_result["reason"] == "task_timeout"
        assert "timed out" in task_result["summary"].lower()
        assert Path("README.md").read_text(encoding="utf-8") == readme_before
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_m3_coding_task_denies_missing_capability_scope(tmp_path: Path) -> None:
    readme_before = Path("README.md").read_text(encoding="utf-8")
    daemon_task, client, _config = await _start_daemon(
        tmp_path,
        policy_text=_policy_with_caps("file.read"),
        config_overrides={
            "coding_repo_root": Path.cwd(),
            "coding_agent_registry_overrides": {
                "codex": _fake_coding_agent_command("codex"),
            },
        },
    )
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = str(created["session_id"])
        result = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "run a coding task without write or shell scope",
                "task": {
                    "enabled": True,
                    "executor": "coding_agent",
                    "task_description": "Implement a README.md change.",
                    "file_refs": ["README.md"],
                    "capabilities": ["file.read"],
                    "preferred_agent": "codex",
                    "task_kind": "implement",
                },
            },
        )

        task_result = dict(result.get("task_result") or {})
        assert task_result["success"] is False
        assert task_result["reason"] == "coding_agent_capability_denied"
        assert "missing capabilities" in task_result["summary"].lower()
        assert Path("README.md").read_text(encoding="utf-8") == readme_before
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_m3_coding_task_falls_back_after_runtime_protocol_failure(
    tmp_path: Path,
) -> None:
    daemon_task, client, _config = await _start_daemon(
        tmp_path,
        policy_text=_policy_with_caps("file.read", "file.write", "shell.exec"),
        config_overrides={
            "coding_repo_root": Path.cwd(),
            "coding_agent_registry_overrides": {
                "codex": _broken_protocol_agent_command(),
                "claude": _fake_coding_agent_command("claude"),
            },
        },
    )
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = str(created["session_id"])
        result = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "fallback if the selected adapter exits during handshake",
                "task": {
                    "enabled": True,
                    "executor": "coding_agent",
                    "task_description": "Implement a tiny README.md tweak.",
                    "file_refs": ["README.md"],
                    "capabilities": ["file.read", "file.write", "shell.exec"],
                    "preferred_agent": "codex",
                    "fallback_agents": ["claude"],
                    "task_kind": "implement",
                },
            },
        )

        task_result = dict(result.get("task_result") or {})
        assert task_result["success"] is True
        assert task_result["agent"] == "claude"
        assert task_result["proposal_ref"]
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_m3_coding_task_worktree_failure_is_actionable_and_emits_completion(
    tmp_path: Path,
) -> None:
    daemon_task, client, _config = await _start_daemon(
        tmp_path,
        policy_text=_policy_with_caps("file.read", "file.write", "shell.exec"),
        config_overrides={
            "coding_repo_root": tmp_path,
            "coding_agent_registry_overrides": {
                "codex": _fake_coding_agent_command("codex"),
            },
        },
    )
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = str(created["session_id"])
        result = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "run the coding agent against a bad repo root",
                "task": {
                    "enabled": True,
                    "executor": "coding_agent",
                    "task_description": "Implement a README.md change.",
                    "file_refs": ["README.md"],
                    "capabilities": ["file.read", "file.write", "shell.exec"],
                    "preferred_agent": "codex",
                    "task_kind": "implement",
                },
            },
        )

        task_result = dict(result.get("task_result") or {})
        assert task_result["success"] is False
        assert task_result["reason"] == "worktree_setup_failed"
        assert "git repository" in task_result["summary"].lower()

        started_event = await _wait_for_event(
            client,
            event_type="CodingAgentSessionStarted",
            predicate=lambda item: str(item.get("session_id", "")).strip()
            == str(task_result["task_session_id"]),
        )
        completed_event = await _wait_for_event(
            client,
            event_type="CodingAgentSessionCompleted",
            predicate=lambda item: str(item.get("session_id", "")).strip()
            == str(task_result["task_session_id"])
            and item["data"].get("reason") == "worktree_setup_failed",
        )

        assert started_event["data"]["worktree_path"]
        assert completed_event["data"]["success"] is False
    finally:
        await _shutdown_daemon(daemon_task, client)
