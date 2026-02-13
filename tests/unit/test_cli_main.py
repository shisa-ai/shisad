"""Unit coverage for CLI command wiring through shared RPC helpers."""

from __future__ import annotations

import asyncio
from pathlib import Path

import click
import pytest
from click.testing import CliRunner, Result

from shisad.cli import main as cli_main
from shisad.core.config import DaemonConfig


def _config(tmp_path: Path) -> DaemonConfig:
    return DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )


def _invoke_ok(runner: CliRunner, args: list[str]) -> Result:
    result = runner.invoke(cli_main.cli, args)
    assert result.exit_code == 0, result.output
    return result


def test_cli_commands_route_through_rpc_wrapper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    config.socket_path.touch()
    skill_path = tmp_path / "skill"
    skill_path.mkdir()
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)

    calls: list[tuple[str, dict[str, object] | None]] = []
    payloads: dict[str, dict[str, object]] = {
        "daemon.shutdown": {"status": "shutting_down"},
        "daemon.status": {"status": "running"},
        "session.create": {"session_id": "s-1"},
        "session.message": {"session_id": "s-1", "response": "hello"},
        "session.list": {"sessions": [{"id": "s-1", "state": "active", "user_id": "alice"}]},
        "session.restore": {"restored": True, "session_id": "s-1", "checkpoint_id": "cp-1"},
        "session.rollback": {"rolled_back": True, "session_id": "s-1", "checkpoint_id": "cp-1"},
        "action.pending": {
            "actions": [
                {
                    "confirmation_id": "c-1",
                    "status": "pending",
                    "tool_name": "curl",
                    "reason": "manual_review",
                    "safe_preview": "preview payload",
                }
            ],
            "count": 1,
        },
        "action.confirm": {"confirmed": True, "confirmation_id": "c-1"},
        "action.reject": {"rejected": True, "confirmation_id": "c-1"},
        "dashboard.audit_explorer": {
            "events": [
                {
                    "timestamp": "2026-02-13T00:00:00Z",
                    "event_type": "SessionCreated",
                    "session_id": "s-1",
                    "actor": "cli",
                }
            ],
            "hash_chain": {"valid": True, "entries_checked": 1},
        },
        "dashboard.egress_review": {
            "events": [
                {
                    "timestamp": "2026-02-13T00:00:00Z",
                    "data": {
                        "destination_host": "example.com",
                        "allowed": False,
                        "reason": "blocked",
                    },
                }
            ]
        },
        "dashboard.skill_provenance": {
            "timeline": [{"skill_name": "demo", "versions": ["1.0.0"]}]
        },
        "dashboard.alerts": {
            "alerts": [
                {
                    "event_id": "evt-1",
                    "event_type": "AlertRaised",
                    "acknowledged_reason": "manual",
                }
            ]
        },
        "dashboard.mark_false_positive": {"marked": True, "event_id": "evt-1", "reason": "manual"},
        "confirmation.metrics": {"metrics": [{"user_id": "alice"}], "count": 1},
        "memory.list": {
            "entries": [{"id": "m-1", "entry_type": "fact", "key": "favorite_color"}],
            "count": 1,
        },
        "memory.write": {"kind": "allow", "entry": {"id": "m-1"}},
        "memory.rotate_key": {
            "rotated": True,
            "active_key_id": "k-1",
            "reencrypt_existing": True,
        },
        "task.list": {"tasks": [{"id": "t-1", "name": "backup", "enabled": True}]},
        "skill.list": {
            "skills": [
                {"name": "demo", "version": "1.0.0", "state": "published", "author": "alice"}
            ]
        },
        "skill.review": {"signature": "trusted"},
        "skill.install": {"allowed": True, "status": "installed"},
        "skill.revoke": {"revoked": True, "skill_name": "demo", "reason": "manual"},
        "policy.explain": {
            "session_id": "s-1",
            "tool_name": "shell_exec",
            "action": "run",
            "effective_policy": {},
            "control_plane": {},
            "contributors": {},
        },
    }

    def _fake_rpc_call(
        _config: DaemonConfig,
        method: str,
        params: dict[str, object] | None = None,
        *,
        response_model: type[object] | None = None,
    ) -> object:
        calls.append((method, params))
        payload = payloads[method]
        if response_model is None:
            return payload
        return response_model.model_validate(payload)  # type: ignore[attr-defined]

    monkeypatch.setattr(cli_main, "rpc_call", _fake_rpc_call)
    runner = CliRunner()

    assert "Shutdown signal sent" in _invoke_ok(runner, ["stop"]).output
    assert "Status: running" in _invoke_ok(runner, ["status"]).output
    assert "Session created: s-1" in _invoke_ok(
        runner,
        ["session", "create", "--user", "alice", "--workspace", "ws-1"],
    ).output
    assert "hello" in _invoke_ok(runner, ["session", "message", "s-1", "hi"]).output
    assert "state=active" in _invoke_ok(runner, ["session", "list"]).output
    assert "Restored session s-1" in _invoke_ok(runner, ["session", "restore", "cp-1"]).output
    assert "Rolled back session s-1" in _invoke_ok(runner, ["session", "rollback", "cp-1"]).output
    assert "preview payload" in _invoke_ok(
        runner,
        ["action", "pending", "--session", "s-1", "--status", "pending", "--limit", "5"],
    ).output
    _invoke_ok(runner, ["action", "confirm", "c-1", "--nonce", "n-1", "--reason", "ok"])
    _invoke_ok(runner, ["action", "reject", "c-1", "--reason", "deny"])
    assert "hash_chain valid=True checked=1" in _invoke_ok(
        runner,
        ["dashboard", "audit", "--limit", "1"],
    ).output
    assert "host=example.com" in _invoke_ok(runner, ["dashboard", "egress", "--limit", "1"]).output
    assert "demo versions=1.0.0" in _invoke_ok(
        runner,
        ["dashboard", "skill-provenance", "--limit", "1"],
    ).output
    assert "evt-1 AlertRaised" in _invoke_ok(runner, ["dashboard", "alerts", "--limit", "1"]).output
    _invoke_ok(runner, ["dashboard", "mark-fp", "evt-1", "--reason", "manual"])
    _invoke_ok(runner, ["confirmation", "metrics", "--user", "alice", "--window", "120"])
    assert "m-1 fact favorite_color" in _invoke_ok(
        runner,
        ["memory", "list", "--limit", "1"],
    ).output
    _invoke_ok(
        runner,
        [
            "memory",
            "write",
            "--type",
            "fact",
            "--key",
            "favorite_color",
            "--value",
            "blue",
            "--origin",
            "user",
            "--source-id",
            "cli",
        ],
    )
    _invoke_ok(runner, ["memory", "rotate-key"])
    assert "t-1 backup enabled=True" in _invoke_ok(runner, ["task", "list"]).output
    assert "demo@1.0.0" in _invoke_ok(runner, ["skill", "list"]).output
    _invoke_ok(runner, ["skill", "review", str(skill_path)])
    _invoke_ok(runner, ["skill", "install", str(skill_path), "--approve-untrusted"])
    _invoke_ok(runner, ["skill", "revoke", "demo", "--reason", "manual"])
    _invoke_ok(
        runner,
        ["policy", "explain", "--session", "s-1", "--action", "run", "--tool", "shell_exec"],
    )

    assert ("session.create", {"user_id": "alice", "workspace_id": "ws-1"}) in calls
    assert ("memory.rotate_key", {"reencrypt_existing": True}) in calls
    assert ("dashboard.alerts", {"limit": 1}) in calls


def test_events_subscribe_uses_rpc_run_wrapper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)
    captured: dict[str, object] = {}

    class _FakeClient:
        async def subscribe_events(self, params: dict[str, object]) -> None:
            captured["params"] = params

        async def read_event(self) -> dict[str, object]:
            return {"event_type": "SessionCreated", "session_id": "s-1"}

    def _fake_rpc_run(
        _config: DaemonConfig,
        operation: object,
        *,
        action: str,
    ) -> None:
        captured["action"] = action
        asyncio.run(operation(_FakeClient()))  # type: ignore[misc]

    monkeypatch.setattr(cli_main, "rpc_run", _fake_rpc_run)
    runner = CliRunner()

    result = runner.invoke(
        cli_main.cli,
        [
            "events",
            "subscribe",
            "--event-type",
            "SessionCreated",
            "--session",
            "s-1",
            "--count",
            "1",
        ],
    )

    assert result.exit_code == 0
    assert "SessionCreated" in result.output
    assert captured["action"] == "events.subscribe"
    assert captured["params"] == {"event_types": ["SessionCreated"], "session_id": "s-1"}


def test_session_restore_not_found_exits_nonzero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)

    def _fake_rpc_call(
        _config: DaemonConfig,
        _method: str,
        _params: dict[str, object] | None = None,
        *,
        response_model: type[object] | None = None,
    ) -> object:
        payload = {"restored": False, "checkpoint_id": "cp-missing", "session_id": None}
        if response_model is None:
            return payload
        return response_model.model_validate(payload)  # type: ignore[attr-defined]

    monkeypatch.setattr(cli_main, "rpc_call", _fake_rpc_call)
    runner = CliRunner()

    result = runner.invoke(cli_main.cli, ["session", "restore", "cp-missing"])
    assert result.exit_code == 1
    assert "Checkpoint not found: cp-missing" in result.output


def test_status_progress_reports_failure_instead_of_done(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    config.socket_path.touch()
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)

    def _fake_rpc_call(
        _config: DaemonConfig,
        _method: str,
        _params: dict[str, object] | None = None,
        *,
        response_model: type[object] | None = None,
    ) -> object:
        _ = response_model
        raise click.ClickException("daemon unavailable")

    monkeypatch.setattr(cli_main, "rpc_call", _fake_rpc_call)
    runner = CliRunner()

    result = runner.invoke(cli_main.cli, ["status"])
    assert result.exit_code == 1
    assert "Querying daemon status failed" in result.output
    assert "Querying daemon status done" not in result.output
