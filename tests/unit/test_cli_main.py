"""Unit coverage for CLI command wiring through shared RPC helpers."""

from __future__ import annotations

import asyncio
import builtins
import sys
from pathlib import Path
from types import SimpleNamespace

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
        "doctor.check": {
            "status": "ok",
            "component": "realitycheck",
            "checks": {"realitycheck": {"status": "disabled"}},
            "error": "",
        },
        "session.create": {"session_id": "s-1"},
        "session.message": {"session_id": "s-1", "response": "hello"},
        "session.set_mode": {
            "session_id": "s-1",
            "mode": "admin_cleanroom",
            "changed": True,
            "reason": "",
        },
        "session.grant_capabilities": {
            "session_id": "s-1",
            "granted": True,
            "capabilities": ["http.request"],
        },
        "session.list": {"sessions": [{"id": "s-1", "state": "active", "user_id": "alice"}]},
        "session.restore": {"restored": True, "session_id": "s-1", "checkpoint_id": "cp-1"},
        "session.rollback": {"rolled_back": True, "session_id": "s-1", "checkpoint_id": "cp-1"},
        "action.pending": {
            "actions": [
                {
                    "confirmation_id": "c-1",
                    "decision_nonce": "n-1",
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
        "channel.pairing_propose": {
            "proposal_id": "proposal-1",
            "proposal_path": "/tmp/proposal-1.json",
            "generated_at": "2026-02-15T00:00:00+00:00",
            "entries": [],
            "invalid_entries": [],
            "count": 0,
            "config_patch": {},
            "applied": False,
        },
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
        "note.create": {"kind": "allow", "entry": {"id": "n-1"}},
        "note.list": {
            "entries": [{"id": "n-1", "entry_type": "note", "key": "meeting"}],
            "count": 1,
        },
        "note.get": {"entry": {"id": "n-1", "entry_type": "note", "key": "meeting"}},
        "note.delete": {"deleted": True, "entry_id": "n-1"},
        "note.verify": {"verified": True, "entry_id": "n-1"},
        "note.export": {"format": "json", "data": '[{"id":"n-1"}]'},
        "todo.create": {"kind": "allow", "entry": {"id": "td-1"}},
        "todo.list": {
            "entries": [
                {
                    "id": "td-1",
                    "entry_type": "todo",
                    "value": {"title": "Ship M2", "status": "open"},
                }
            ],
            "count": 1,
        },
        "todo.get": {
            "entry": {"id": "td-1", "entry_type": "todo", "value": {"title": "Ship M2"}}
        },
        "todo.delete": {"deleted": True, "entry_id": "td-1"},
        "todo.verify": {"verified": True, "entry_id": "td-1"},
        "todo.export": {"format": "json", "data": '[{"id":"td-1"}]'},
        "web.search": {
            "ok": True,
            "query": "shisad",
            "backend": "https://search.example",
            "results": [],
        },
        "web.fetch": {"ok": True, "url": "https://example.com", "content": "page"},
        "realitycheck.search": {
            "ok": True,
            "query": "roadmap",
            "mode": "local",
            "results": [],
            "taint_labels": ["untrusted"],
            "evidence": {"operation": "realitycheck.search"},
            "error": "",
        },
        "realitycheck.read": {
            "ok": True,
            "path": "/tmp/source.md",
            "content": "hello",
            "truncated": False,
            "sha256": "abc123",
            "taint_labels": ["untrusted"],
            "evidence": {"operation": "realitycheck.read"},
            "error": "",
        },
        "fs.list": {"ok": True, "path": ".", "entries": [], "count": 0},
        "fs.read": {"ok": True, "path": "README.md", "content": "hello"},
        "fs.write": {
            "ok": False,
            "path": "README.md",
            "written": False,
            "confirmation_required": True,
            "error": "explicit_confirmation_required",
        },
        "git.status": {"ok": True, "repo_path": ".", "output": "## main"},
        "git.diff": {"ok": True, "repo_path": ".", "output": "", "truncated": False},
        "git.log": {"ok": True, "repo_path": ".", "output": "abc init"},
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
            "tool_name": "shell.exec",
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
    _invoke_ok(runner, ["doctor", "check", "--component", "realitycheck"])
    assert "Session created: s-1" in _invoke_ok(
        runner,
        ["session", "create", "--user", "alice", "--workspace", "ws-1"],
    ).output
    assert "hello" in _invoke_ok(runner, ["session", "message", "s-1", "hi"]).output
    _invoke_ok(runner, ["session", "mode", "s-1", "--mode", "admin_cleanroom"])
    _invoke_ok(
        runner,
        [
            "session",
            "grant-capabilities",
            "s-1",
            "--capability",
            "http.request",
            "--reason",
            "unit-test",
        ],
    )
    assert "state=active" in _invoke_ok(runner, ["session", "list"]).output
    assert "Restored session s-1" in _invoke_ok(runner, ["session", "restore", "cp-1"]).output
    assert "Rolled back session s-1" in _invoke_ok(runner, ["session", "rollback", "cp-1"]).output
    assert "preview payload" in _invoke_ok(
        runner,
        ["action", "pending", "--session", "s-1", "--status", "pending", "--limit", "5"],
    ).output
    assert "nonce=n-1" in _invoke_ok(
        runner,
        ["action", "pending", "--session", "s-1", "--status", "pending", "--limit", "5"],
    ).output
    _invoke_ok(runner, ["action", "confirm", "c-1", "--reason", "ok"])
    _invoke_ok(runner, ["action", "reject", "c-1", "--reason", "deny"])
    _invoke_ok(runner, ["channel", "pairing-propose", "--limit", "5"])
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
    _invoke_ok(runner, ["note", "create", "--key", "meeting", "--content", "prep"])
    assert "n-1 meeting" in _invoke_ok(runner, ["note", "list", "--limit", "5"]).output
    _invoke_ok(runner, ["note", "get", "n-1"])
    _invoke_ok(runner, ["note", "verify", "n-1"])
    _invoke_ok(runner, ["note", "export", "--format", "json"])
    _invoke_ok(runner, ["note", "delete", "n-1"])
    _invoke_ok(
        runner,
        [
            "todo",
            "create",
            "--title",
            "Ship M2",
            "--details",
            "review ready",
            "--status",
            "open",
            "--due-date",
            "2026-02-16",
        ],
    )
    assert "td-1 open Ship M2" in _invoke_ok(runner, ["todo", "list", "--limit", "5"]).output
    _invoke_ok(runner, ["todo", "get", "td-1"])
    _invoke_ok(runner, ["todo", "verify", "td-1"])
    _invoke_ok(runner, ["todo", "export", "--format", "json"])
    _invoke_ok(runner, ["todo", "delete", "td-1"])
    _invoke_ok(runner, ["web", "search", "shisad", "--limit", "1"])
    _invoke_ok(runner, ["web", "fetch", "https://example.com"])
    _invoke_ok(runner, ["realitycheck", "search", "roadmap", "--limit", "1", "--mode", "local"])
    _invoke_ok(runner, ["realitycheck", "read", "sources/a.md", "--max-bytes", "64"])
    _invoke_ok(runner, ["fs", "list", ".", "--limit", "1"])
    _invoke_ok(runner, ["fs", "read", "README.md", "--max-bytes", "10"])
    _invoke_ok(runner, ["fs", "write", "README.md", "--content", "x"])
    _invoke_ok(runner, ["git", "status", "--repo", "."])
    _invoke_ok(runner, ["git", "diff", "--repo", ".", "--ref", "HEAD~1", "--max-lines", "10"])
    _invoke_ok(runner, ["git", "log", "--repo", ".", "--limit", "3"])
    assert "t-1 backup enabled=True" in _invoke_ok(runner, ["task", "list"]).output
    assert "demo@1.0.0" in _invoke_ok(runner, ["skill", "list"]).output
    _invoke_ok(runner, ["skill", "review", str(skill_path)])
    _invoke_ok(runner, ["skill", "install", str(skill_path), "--approve-untrusted"])
    _invoke_ok(runner, ["skill", "revoke", "demo", "--reason", "manual"])
    _invoke_ok(
        runner,
        ["policy", "explain", "--session", "s-1", "--action", "run", "--tool", "shell.exec"],
    )

    assert (
        "session.create",
        {"user_id": "alice", "workspace_id": "ws-1", "mode": "default"},
    ) in calls
    assert any(
        method == "action.pending"
        and isinstance(params, dict)
        and params.get("include_ui") is False
        and params.get("confirmation_id") == "c-1"
        and params.get("limit") == 1
        and params.get("status") == "pending"
        for method, params in calls
    )
    assert (
        "session.grant_capabilities",
        {"session_id": "s-1", "capabilities": ["http.request"], "reason": "unit-test"},
    ) in calls
    assert ("memory.rotate_key", {"reencrypt_existing": True}) in calls
    assert ("doctor.check", {"component": "realitycheck"}) in calls
    assert ("realitycheck.read", {"path": "sources/a.md", "max_bytes": 64}) in calls
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


def test_start_debug_routes_to_autoreload_with_debug_log_level(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)

    captured: dict[str, DaemonConfig] = {}

    def _fake_debug_start(effective_config: DaemonConfig) -> None:
        captured["config"] = effective_config

    def _fake_foreground_start(_: DaemonConfig) -> None:
        raise AssertionError("foreground start path should not be used in --debug mode")

    monkeypatch.setattr(cli_main, "_run_daemon_with_autoreload_sync", _fake_debug_start)
    monkeypatch.setattr(cli_main, "_run_daemon_foreground", _fake_foreground_start)

    runner = CliRunner()
    result = runner.invoke(cli_main.cli, ["start", "--debug"])
    assert result.exit_code == 0, result.output
    assert captured["config"].log_level == "DEBUG"
    assert "only supported mode" not in result.output


def test_start_default_routes_to_foreground_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)

    captured: dict[str, DaemonConfig] = {}

    def _fake_foreground_start(effective_config: DaemonConfig) -> None:
        captured["config"] = effective_config

    def _fake_debug_start(_: DaemonConfig) -> None:
        raise AssertionError("debug/autoreload path should not be used without --debug")

    monkeypatch.setattr(cli_main, "_run_daemon_foreground", _fake_foreground_start)
    monkeypatch.setattr(cli_main, "_run_daemon_with_autoreload_sync", _fake_debug_start)

    runner = CliRunner()
    result = runner.invoke(cli_main.cli, ["start"])
    assert result.exit_code == 0, result.output
    assert captured["config"].log_level == config.log_level
    assert "only supported mode" in result.output


async def test_run_daemon_with_autoreload_restarts_when_source_changes(tmp_path: Path) -> None:
    watched_file = tmp_path / "watched.py"
    watched_file.write_text("value = 1\n", encoding="utf-8")
    config = _config(tmp_path)

    starts: list[int] = []
    first_started = asyncio.Event()
    first_cancelled = asyncio.Event()

    async def _fake_daemon(_config: DaemonConfig) -> None:
        starts.append(len(starts) + 1)
        if len(starts) == 1:
            first_started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                first_cancelled.set()
                raise

    task = asyncio.create_task(
        cli_main._run_daemon_with_autoreload(
            config=config,
            watch_roots=(tmp_path,),
            poll_interval=0.01,
            daemon_runner=_fake_daemon,
        )
    )

    await asyncio.wait_for(first_started.wait(), timeout=1.0)
    watched_file.write_text("value = 2\n", encoding="utf-8")
    await asyncio.wait_for(first_cancelled.wait(), timeout=1.0)
    await asyncio.wait_for(task, timeout=1.0)

    assert starts == [1, 2]


async def test_run_daemon_with_autoreload_exits_without_restart_when_daemon_stops(
    tmp_path: Path,
) -> None:
    watched_file = tmp_path / "watched.py"
    watched_file.write_text("value = 1\n", encoding="utf-8")
    config = _config(tmp_path)

    starts: list[int] = []

    async def _fake_daemon(_config: DaemonConfig) -> None:
        starts.append(len(starts) + 1)

    await cli_main._run_daemon_with_autoreload(
        config=config,
        watch_roots=(tmp_path,),
        poll_interval=0.01,
        daemon_runner=_fake_daemon,
    )

    assert starts == [1]


def test_chat_command_runs_textual_app(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)
    captured: dict[str, object] = {}

    class _FakeApp:
        def __init__(
            self,
            *,
            socket_path: Path,
            user_id: str,
            workspace_id: str,
            session_id: str | None,
        ) -> None:
            captured["socket_path"] = socket_path
            captured["user_id"] = user_id
            captured["workspace_id"] = workspace_id
            captured["session_id"] = session_id

        def run(self) -> None:
            captured["ran"] = True

    monkeypatch.setitem(sys.modules, "shisad.ui.chat", SimpleNamespace(ChatApp=_FakeApp))
    runner = CliRunner()

    result = runner.invoke(
        cli_main.cli,
        ["chat", "--session", "sess-123", "--user", "alice", "--workspace", "ws-a"],
    )

    assert result.exit_code == 0, result.output
    assert captured["socket_path"] == config.socket_path
    assert captured["user_id"] == "alice"
    assert captured["workspace_id"] == "ws-a"
    assert captured["session_id"] == "sess-123"
    assert captured["ran"] is True


def test_chat_command_reports_missing_textual_dependency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)
    real_import = builtins.__import__

    def _fake_import(
        name: str,
        globals_obj: dict[str, object] | None = None,
        locals_obj: dict[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name == "shisad.ui.chat":
            raise ModuleNotFoundError("No module named 'textual'", name="textual")
        return real_import(name, globals_obj, locals_obj, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    runner = CliRunner()

    result = runner.invoke(cli_main.cli, ["chat"])
    assert result.exit_code == 1
    assert "textual is required for chat TUI" in result.output


def test_chat_command_surfaces_non_textual_import_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)
    real_import = builtins.__import__

    def _fake_import(
        name: str,
        globals_obj: dict[str, object] | None = None,
        locals_obj: dict[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name == "shisad.ui.chat":
            raise ImportError("boom: broken chat module")
        return real_import(name, globals_obj, locals_obj, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    runner = CliRunner()

    result = runner.invoke(cli_main.cli, ["chat"])
    assert result.exit_code == 1
    assert "chat TUI import failed" in result.output
