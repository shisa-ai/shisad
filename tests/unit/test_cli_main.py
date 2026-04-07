"""Unit coverage for CLI command wiring through shared RPC helpers."""

from __future__ import annotations

import asyncio
import builtins
import sys
from datetime import UTC, datetime, timedelta
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
        "session.terminate": {
            "session_id": "s-1",
            "terminated": True,
            "reason": "manual",
        },
        "session.grant_capabilities": {
            "session_id": "s-1",
            "granted": True,
            "capabilities": ["http.request"],
        },
        "session.list": {
            "sessions": [
                {
                    "id": "s-1",
                    "state": "active",
                    "mode": "default",
                    "user_id": "alice",
                    "workspace_id": "ws-1",
                    "lockdown_level": "normal",
                    "created_at": "2026-03-01T00:00:00+00:00",
                    "channel": "cli",
                }
            ]
        },
        "session.restore": {"restored": True, "session_id": "s-1", "checkpoint_id": "cp-1"},
        "session.export": {
            "exported": True,
            "session_id": "s-1",
            "archive_path": "/tmp/s-1.shisad-session.zip",
            "sha256": "abc123",
            "transcript_entries": 2,
            "checkpoint_count": 1,
            "reason": "",
        },
        "session.import": {
            "imported": True,
            "session_id": "s-2",
            "original_session_id": "s-1",
            "archive_path": "/tmp/s-1.shisad-session.zip",
            "checkpoint_ids": ["cp-2"],
            "transcript_entries": 2,
            "checkpoint_count": 1,
            "reason": "",
        },
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
        "lockdown.set": {"session_id": "s-1", "level": "normal", "reason": "manual"},
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
        "admin.selfmod.propose": {
            "proposal_id": "selfmod-proposal-1",
            "artifact_type": "skill_bundle",
            "name": "calendar-helper",
            "version": "1.0.0",
            "artifact_path": str(skill_path),
            "valid": True,
            "warnings": ["new_tool_surface"],
            "capability_diff": {"added": {"tools": ["skill.calendar-helper.lookup"]}},
            "reason": "",
        },
        "admin.selfmod.apply": {
            "applied": True,
            "proposal_id": "selfmod-proposal-1",
            "change_id": "change-1",
            "requires_confirmation": False,
            "warnings": ["new_tool_surface"],
            "capability_diff": {"added": {"tools": ["skill.calendar-helper.lookup"]}},
            "active_version": "1.0.0",
            "reason": "",
        },
        "admin.selfmod.rollback": {
            "rolled_back": True,
            "change_id": "change-1",
            "artifact_type": "skill_bundle",
            "name": "calendar-helper",
            "restored_version": "0.9.0",
            "active_version": "0.9.0",
            "reason": "",
        },
        "dev.implement": {
            "operation": "implement",
            "success": True,
            "summary": "codex completed mode=build",
            "files_changed": ["README.md"],
            "cost": 0.42,
            "agent": "codex",
            "duration_ms": 1200,
            "proposal_ref": "/tmp/proposal.json",
            "raw_log_ref": "/tmp/raw-log.json",
            "task_session_id": "task-1",
            "task_session_mode": "task",
            "handoff_mode": "summary_only",
            "command_context": "clean",
            "reason": "",
        },
        "dev.review": {
            "operation": "review",
            "success": True,
            "summary": "claude completed mode=plan",
            "findings": ["claude completed mode=plan"],
            "files_changed": ["README.md"],
            "cost": 0.42,
            "agent": "claude",
            "duration_ms": 900,
            "proposal_ref": "/tmp/review-proposal.json",
            "raw_log_ref": "/tmp/review-raw-log.json",
            "task_session_id": "task-2",
            "task_session_mode": "task",
            "handoff_mode": "summary_only",
            "command_context": "clean",
            "reason": "",
        },
        "dev.remediate": {
            "operation": "remediate",
            "success": True,
            "summary": "codex completed mode=build",
            "files_changed": ["README.md"],
            "cost": 0.42,
            "agent": "codex",
            "duration_ms": 1000,
            "proposal_ref": "/tmp/remediate-proposal.json",
            "raw_log_ref": "/tmp/remediate-raw-log.json",
            "task_session_id": "task-3",
            "task_session_mode": "task",
            "handoff_mode": "summary_only",
            "command_context": "clean",
            "reason": "",
        },
        "dev.close": {
            "milestone": "M4",
            "implementation_path": "/tmp/IMPLEMENTATION.md",
            "ready": False,
            "section_found": True,
            "runtime_wiring_recorded": True,
            "validation_recorded": False,
            "docs_parity_recorded": False,
            "worklog_updated": False,
            "review_status_recorded": False,
            "punchlist_complete": False,
            "acceptance_checklist_complete": False,
            "missing_evidence": [
                "validation_evidence_missing",
                "docs_parity_evidence_missing",
            ],
            "unchecked_items": ["Validation evidence recorded."],
            "open_finding_ids": [],
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
            "timeline": [
                {
                    "skill_name": "demo",
                    "versions": ["1.0.0"],
                    "events": [
                        {
                            "timestamp": "2026-02-13T00:00:00Z",
                            "event_type": "SkillToolRegistrationDropped",
                            "tool_name": "skill.demo.lookup",
                            "reason_code": "skill:tool_schema_drift",
                            "registration_source": "inventory_reload",
                            "expected_hash_prefix": "abc123def456",
                            "actual_hash_prefix": "fed654cba321",
                        }
                    ],
                }
            ]
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
        "todo.get": {"entry": {"id": "td-1", "entry_type": "todo", "value": {"title": "Ship M2"}}},
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
    assert (
        "Session created: s-1"
        in _invoke_ok(
            runner,
            ["session", "create", "--user", "alice", "--workspace", "ws-1"],
        ).output
    )
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
    assert "workspace=ws-1" in _invoke_ok(runner, ["session", "list"]).output
    assert "lockdown=normal" in _invoke_ok(runner, ["session", "list"]).output
    _invoke_ok(runner, ["session", "terminate", "s-1", "--reason", "manual"])
    _invoke_ok(runner, ["session", "prune", "--user", "alice"])
    assert "Restored session s-1" in _invoke_ok(runner, ["session", "restore", "cp-1"]).output
    assert (
        "Exported session s-1"
        in _invoke_ok(
            runner,
            ["session", "export", "s-1", "/tmp/s-1.shisad-session.zip"],
        ).output
    )
    assert (
        "Imported archive /tmp/s-1.shisad-session.zip as session s-2"
        in _invoke_ok(
            runner,
            ["session", "import", "/tmp/s-1.shisad-session.zip"],
        ).output
    )
    assert "Rolled back session s-1" in _invoke_ok(runner, ["session", "rollback", "cp-1"]).output
    assert (
        "preview payload"
        in _invoke_ok(
            runner,
            ["action", "pending", "--session", "s-1", "--status", "pending", "--limit", "5"],
        ).output
    )
    assert (
        "nonce=n-1"
        in _invoke_ok(
            runner,
            ["action", "pending", "--session", "s-1", "--status", "pending", "--limit", "5"],
        ).output
    )
    _invoke_ok(runner, ["action", "confirm", "c-1", "--reason", "ok"])
    _invoke_ok(runner, ["action", "reject", "c-1", "--reason", "deny"])
    _invoke_ok(runner, ["lockdown", "resume", "s-1", "--reason", "manual"])
    _invoke_ok(
        runner,
        ["lockdown", "set", "s-1", "--action", "quarantine", "--reason", "manual"],
    )
    _invoke_ok(runner, ["channel", "pairing-propose", "--limit", "5"])
    assert (
        "selfmod-proposal-1"
        in _invoke_ok(
            runner,
            ["admin", "selfmod", "propose", str(skill_path)],
        ).output
    )
    assert (
        "change-1"
        in _invoke_ok(
            runner,
            ["admin", "selfmod", "apply", "selfmod-proposal-1", "--yes"],
        ).output
    )
    assert (
        "restored_version=0.9.0"
        in _invoke_ok(
            runner,
            ["admin", "selfmod", "rollback", "change-1"],
        ).output
    )
    _invoke_ok(
        runner,
        [
            "dev",
            "implement",
            "Add",
            "a",
            "README",
            "note",
            "--agent",
            "codex",
            "--file-ref",
            "README.md",
            "--fallback-agent",
            "claude",
            "--capability",
            "file.read",
            "--capability",
            "file.write",
            "--max-turns",
            "4",
            "--max-budget-usd",
            "2.5",
            "--model",
            "fast-model",
            "--reasoning-effort",
            "medium",
            "--timeout-sec",
            "30",
        ],
    )
    _invoke_ok(
        runner,
        [
            "dev",
            "review",
            "Review",
            "README.md",
            "--agent",
            "claude",
            "--mode",
            "readonly",
            "--file-ref",
            "README.md",
        ],
    )
    _invoke_ok(
        runner,
        [
            "dev",
            "remediate",
            "Fix",
            "README",
            "issues",
            "--agent",
            "codex",
            "--file-ref",
            "README.md",
        ],
    )
    _invoke_ok(
        runner,
        [
            "dev",
            "close",
            "M4",
            "--implementation-doc",
            "/tmp/IMPLEMENTATION.md",
        ],
    )
    assert (
        "hash_chain valid=True checked=1"
        in _invoke_ok(
            runner,
            ["dashboard", "audit", "--limit", "1"],
        ).output
    )
    assert "host=example.com" in _invoke_ok(runner, ["dashboard", "egress", "--limit", "1"]).output
    assert (
        "demo versions=1.0.0"
        in _invoke_ok(
            runner,
            ["dashboard", "skill-provenance", "--limit", "1"],
        ).output
    )
    assert (
        "reason=skill:tool_schema_drift"
        in _invoke_ok(
            runner,
            ["dashboard", "skill-provenance", "--limit", "1"],
        ).output
    )
    assert "evt-1 AlertRaised" in _invoke_ok(runner, ["dashboard", "alerts", "--limit", "1"]).output
    _invoke_ok(runner, ["dashboard", "mark-fp", "evt-1", "--reason", "manual"])
    _invoke_ok(runner, ["confirmation", "metrics", "--user", "alice", "--window", "120"])
    assert (
        "m-1 fact favorite_color"
        in _invoke_ok(
            runner,
            ["memory", "list", "--limit", "1"],
        ).output
    )
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
    assert any(
        method == "session.terminate"
        and isinstance(params, dict)
        and params.get("session_id") == "s-1"
        and params.get("reason") == "manual"
        and params.get("channel") == "cli"
        and params.get("user_id") == "alice"
        and params.get("workspace_id") == "ws-1"
        for method, params in calls
    )
    assert any(
        method == "session.terminate"
        and isinstance(params, dict)
        and params.get("session_id") == "s-1"
        and params.get("reason") == "prune"
        for method, params in calls
    )
    assert ("lockdown.set", {"session_id": "s-1", "action": "resume", "reason": "manual"}) in calls
    assert (
        "lockdown.set",
        {"session_id": "s-1", "action": "quarantine", "reason": "manual"},
    ) in calls
    assert ("memory.rotate_key", {"reencrypt_existing": True}) in calls
    assert ("doctor.check", {"component": "realitycheck"}) in calls
    assert ("realitycheck.read", {"path": "sources/a.md", "max_bytes": 64}) in calls
    assert ("dashboard.alerts", {"limit": 1}) in calls
    assert ("admin.selfmod.propose", {"artifact_path": str(skill_path)}) in calls
    assert (
        "admin.selfmod.apply",
        {"proposal_id": "selfmod-proposal-1", "confirm": True},
    ) in calls
    assert ("admin.selfmod.rollback", {"change_id": "change-1"}) in calls
    assert (
        "dev.implement",
        {
            "task": "Add a README note",
            "file_refs": ["README.md"],
            "agent": "codex",
            "fallback_agents": ["claude"],
            "capabilities": ["file.read", "file.write"],
            "max_turns": 4,
            "max_budget_usd": 2.5,
            "model": "fast-model",
            "reasoning_effort": "medium",
            "timeout_sec": 30.0,
        },
    ) in calls
    assert (
        "dev.review",
        {
            "scope": "Review README.md",
            "file_refs": ["README.md"],
            "agent": "claude",
            "mode": "readonly",
        },
    ) in calls
    assert (
        "dev.remediate",
        {
            "findings": "Fix README issues",
            "file_refs": ["README.md"],
            "agent": "codex",
        },
    ) in calls
    assert (
        "dev.close",
        {"milestone": "M4", "implementation_path": "/tmp/IMPLEMENTATION.md"},
    ) in calls
    assert (
        "session.export",
        {"session_id": "s-1", "path": "/tmp/s-1.shisad-session.zip"},
    ) in calls
    assert (
        "session.import",
        {"archive_path": "/tmp/s-1.shisad-session.zip"},
    ) in calls


def test_session_message_command_renders_evidence_stub_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)
    monkeypatch.setattr(
        cli_main,
        "rpc_call",
        lambda *_args, **_kwargs: cli_main.SessionMessageResult.model_validate(
            {
                "session_id": "s-1",
                "response": (
                    "Need to inspect the fetched page.\n\n"
                    "Tool results summary:\n"
                    "- web.fetch: success=True, ok=True\n"
                    "  output: [EVIDENCE ref=ev-61f3d4c48f54ff92 "
                    "source=web.fetch:example.com taint=UNTRUSTED size=88 "
                    'summary="Example Domain" '
                    'Use evidence.read("ev-61f3d4c48f54ff92") for full content, or '
                    'evidence.promote("ev-61f3d4c48f54ff92") to add it to the conversation.]'
                ),
            }
        ),
    )
    runner = CliRunner()

    result = runner.invoke(cli_main.cli, ["session", "message", "s-1", "fetch example"])

    assert result.exit_code == 0, result.output
    assert "[EVIDENCE ref=" not in result.output
    assert "[Evidence ev-61f3d4c48f54ff92]" in result.output
    assert 'inspect: evidence.read("ev-61f3d4c48f54ff92")' in result.output


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
        payload = {
            "restored": False,
            "checkpoint_id": "cp-missing",
            "session_id": None,
            "reason": "not_found",
        }
        if response_model is None:
            return payload
        return response_model.model_validate(payload)  # type: ignore[attr-defined]

    monkeypatch.setattr(cli_main, "rpc_call", _fake_rpc_call)
    runner = CliRunner()

    result = runner.invoke(cli_main.cli, ["session", "restore", "cp-missing"])
    assert result.exit_code == 1
    assert "Checkpoint not found: cp-missing" in result.output


def test_session_restore_surfaces_structured_failure_reason(
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
        payload = {
            "restored": False,
            "checkpoint_id": "cp-bad",
            "session_id": None,
            "reason": "invalid_lockdown_payload",
        }
        if response_model is None:
            return payload
        return response_model.model_validate(payload)  # type: ignore[attr-defined]

    monkeypatch.setattr(cli_main, "rpc_call", _fake_rpc_call)
    runner = CliRunner()

    result = runner.invoke(cli_main.cli, ["session", "restore", "cp-bad"])
    assert result.exit_code == 1
    assert "Session restore failed: invalid_lockdown_payload" in result.output


def test_session_rollback_surfaces_structured_failure_reason(
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
        payload = {
            "rolled_back": False,
            "checkpoint_id": "cp-bad",
            "session_id": None,
            "files_restored": 0,
            "files_deleted": 0,
            "transcript_entries_removed": 0,
            "restore_errors": [],
            "reason": "invalid_lockdown_payload",
        }
        if response_model is None:
            return payload
        return response_model.model_validate(payload)  # type: ignore[attr-defined]

    monkeypatch.setattr(cli_main, "rpc_call", _fake_rpc_call)
    runner = CliRunner()

    result = runner.invoke(cli_main.cli, ["session", "rollback", "cp-bad"])
    assert result.exit_code == 1
    assert "Session rollback failed: invalid_lockdown_payload" in result.output


def test_session_prune_all_requires_confirm(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)
    runner = CliRunner()

    result = runner.invoke(cli_main.cli, ["session", "prune", "--all"])

    assert result.exit_code != 0
    assert "--confirm is required with --all" in result.output


def test_session_prune_filters_by_older_than(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)
    calls: list[tuple[str, dict[str, object] | None]] = []
    now = datetime.now(UTC)
    old_created = (now - timedelta(days=10)).isoformat()
    new_created = (now - timedelta(hours=6)).isoformat()

    def _fake_rpc_call(
        _config: DaemonConfig,
        method: str,
        params: dict[str, object] | None = None,
        *,
        response_model: type[object] | None = None,
    ) -> object:
        calls.append((method, params))
        if method == "session.list":
            payload = {
                "sessions": [
                    {
                        "id": "old",
                        "state": "active",
                        "channel": "cli",
                        "user_id": "alice",
                        "workspace_id": "w1",
                        "created_at": old_created,
                    },
                    {
                        "id": "new",
                        "state": "active",
                        "channel": "cli",
                        "user_id": "alice",
                        "workspace_id": "w1",
                        "created_at": new_created,
                    },
                ]
            }
            if response_model is None:
                return payload
            return response_model.model_validate(payload)  # type: ignore[attr-defined]
        if method == "session.terminate":
            payload = {
                "session_id": str(params.get("session_id", "")) if isinstance(params, dict) else "",
                "terminated": True,
                "reason": "prune",
            }
            if response_model is None:
                return payload
            return response_model.model_validate(payload)  # type: ignore[attr-defined]
        raise AssertionError(f"unexpected method {method}")

    monkeypatch.setattr(cli_main, "rpc_call", _fake_rpc_call)
    runner = CliRunner()

    result = runner.invoke(cli_main.cli, ["session", "prune", "--older-than", "24h"])
    assert result.exit_code == 0, result.output
    assert any(
        method == "session.terminate"
        and isinstance(params, dict)
        and params.get("session_id") == "old"
        and params.get("reason") == "prune"
        and params.get("channel") == "cli"
        and params.get("user_id") == "alice"
        and params.get("workspace_id") == "w1"
        for method, params in calls
    )
    assert not any(
        method == "session.terminate"
        and isinstance(params, dict)
        and params.get("session_id") == "new"
        for method, params in calls
    )


def test_session_prune_older_than_handles_offset_naive_created_at(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)
    calls: list[tuple[str, dict[str, object] | None]] = []
    now = datetime.now(UTC)
    naive_old_created = (now - timedelta(days=10)).replace(tzinfo=None).isoformat()
    aware_new_created = (now - timedelta(hours=6)).isoformat()

    def _fake_rpc_call(
        _config: DaemonConfig,
        method: str,
        params: dict[str, object] | None = None,
        *,
        response_model: type[object] | None = None,
    ) -> object:
        calls.append((method, params))
        if method == "session.list":
            payload = {
                "sessions": [
                    {
                        "id": "naive-old",
                        "state": "active",
                        "channel": "cli",
                        "user_id": "alice",
                        "workspace_id": "w1",
                        "created_at": naive_old_created,
                    },
                    {
                        "id": "aware-new",
                        "state": "active",
                        "channel": "cli",
                        "user_id": "alice",
                        "workspace_id": "w1",
                        "created_at": aware_new_created,
                    },
                ]
            }
            if response_model is None:
                return payload
            return response_model.model_validate(payload)  # type: ignore[attr-defined]
        if method == "session.terminate":
            payload = {
                "session_id": str(params.get("session_id", "")) if isinstance(params, dict) else "",
                "terminated": True,
                "reason": "prune",
            }
            if response_model is None:
                return payload
            return response_model.model_validate(payload)  # type: ignore[attr-defined]
        raise AssertionError(f"unexpected method {method}")

    monkeypatch.setattr(cli_main, "rpc_call", _fake_rpc_call)
    runner = CliRunner()

    result = runner.invoke(cli_main.cli, ["session", "prune", "--older-than", "24h"])
    assert result.exit_code == 0, result.output
    assert any(
        method == "session.terminate"
        and isinstance(params, dict)
        and params.get("session_id") == "naive-old"
        for method, params in calls
    )
    assert not any(
        method == "session.terminate"
        and isinstance(params, dict)
        and params.get("session_id") == "aware-new"
        for method, params in calls
    )


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


def test_restart_default_shuts_down_then_starts_foreground(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    config.socket_path.touch()
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)

    shutdown_calls: list[tuple[str, dict[str, object] | None]] = []
    captured: dict[str, DaemonConfig] = {}

    def _fake_rpc_call(
        _config: DaemonConfig,
        method: str,
        params: dict[str, object] | None = None,
        *,
        response_model: type[object] | None = None,
    ) -> object:
        shutdown_calls.append((method, params))
        payload = {"status": "shutting_down"}
        if response_model is None:
            return payload
        return response_model.model_validate(payload)  # type: ignore[attr-defined]

    def _fake_foreground_start(effective_config: DaemonConfig) -> None:
        captured["config"] = effective_config

    def _fake_debug_start(_: DaemonConfig) -> None:
        raise AssertionError("debug/autoreload path should not be used without --debug")

    monkeypatch.setattr(cli_main, "rpc_call", _fake_rpc_call)
    monkeypatch.setattr(cli_main, "_run_daemon_foreground", _fake_foreground_start)
    monkeypatch.setattr(cli_main, "_run_daemon_with_autoreload_sync", _fake_debug_start)

    runner = CliRunner()
    result = runner.invoke(cli_main.cli, ["restart"])

    assert result.exit_code == 0, result.output
    assert shutdown_calls == [("daemon.shutdown", None)]
    assert captured["config"] is config


def test_restart_fresh_config_reloads_before_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    initial_config = _config(tmp_path)
    initial_config.socket_path.touch()
    refreshed_config = _config(tmp_path).model_copy(update={"log_level": "WARNING"})
    config_calls = {"count": 0}

    def _fake_get_config() -> DaemonConfig:
        config_calls["count"] += 1
        if config_calls["count"] == 1:
            return initial_config
        return refreshed_config

    captured: dict[str, DaemonConfig] = {}

    def _fake_rpc_call(
        _config: DaemonConfig,
        method: str,
        params: dict[str, object] | None = None,
        *,
        response_model: type[object] | None = None,
    ) -> object:
        assert _config is initial_config
        assert method == "daemon.shutdown"
        assert params is None
        payload = {"status": "shutting_down"}
        if response_model is None:
            return payload
        return response_model.model_validate(payload)  # type: ignore[attr-defined]

    def _fake_foreground_start(effective_config: DaemonConfig) -> None:
        captured["config"] = effective_config

    def _fake_debug_start(_: DaemonConfig) -> None:
        raise AssertionError("debug/autoreload path should not be used without --debug")

    monkeypatch.setattr(cli_main, "_get_config", _fake_get_config)
    monkeypatch.setattr(cli_main, "rpc_call", _fake_rpc_call)
    monkeypatch.setattr(cli_main, "_run_daemon_foreground", _fake_foreground_start)
    monkeypatch.setattr(cli_main, "_run_daemon_with_autoreload_sync", _fake_debug_start)

    runner = CliRunner()
    result = runner.invoke(cli_main.cli, ["restart", "--fresh-config"])

    assert result.exit_code == 0, result.output
    assert config_calls["count"] == 2
    assert captured["config"] is refreshed_config


def test_restart_fresh_config_creates_backup_before_reload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    initial_config = _config(tmp_path)
    initial_config.socket_path.touch()
    refreshed_config = _config(tmp_path).model_copy(update={"log_level": "WARNING"})
    config_calls = {"count": 0}
    captured_backup: dict[str, DaemonConfig] = {}
    captured_start: dict[str, DaemonConfig] = {}

    def _fake_get_config() -> DaemonConfig:
        config_calls["count"] += 1
        if config_calls["count"] == 1:
            return initial_config
        return refreshed_config

    def _fake_rpc_call(
        _config: DaemonConfig,
        method: str,
        params: dict[str, object] | None = None,
        *,
        response_model: type[object] | None = None,
    ) -> object:
        assert _config is initial_config
        assert method == "daemon.shutdown"
        assert params is None
        payload = {"status": "shutting_down"}
        if response_model is None:
            return payload
        return response_model.model_validate(payload)  # type: ignore[attr-defined]

    def _fake_backup(config: DaemonConfig) -> Path:
        captured_backup["config"] = config
        return tmp_path / "config-backups" / "20260302-120000.json"

    def _fake_start(config: DaemonConfig, foreground: bool, debug: bool) -> None:
        assert foreground is False
        assert debug is False
        captured_start["config"] = config

    monkeypatch.setattr(cli_main, "_get_config", _fake_get_config)
    monkeypatch.setattr(cli_main, "rpc_call", _fake_rpc_call)
    monkeypatch.setattr(cli_main, "_backup_config_snapshot", _fake_backup)
    monkeypatch.setattr(cli_main, "_start_daemon", _fake_start)

    runner = CliRunner()
    result = runner.invoke(cli_main.cli, ["restart", "--fresh-config"])

    assert result.exit_code == 0, result.output
    assert captured_backup["config"] is initial_config
    assert captured_start["config"] is refreshed_config


def test_backup_config_snapshot_writes_timestamped_file(tmp_path: Path) -> None:
    config = _config(tmp_path).model_copy(
        update={
            "discord_bot_token": "secret-token",
            "web_search_backend_url": "https://search.example",
        }
    )
    backup = cli_main._backup_config_snapshot(config)

    assert backup.parent == config.data_dir / "config-backups"
    assert backup.name.endswith(".json")
    stem = backup.stem
    assert len(stem) == 15
    assert stem[8] == "-"
    assert stem.replace("-", "").isdigit()
    assert backup.exists()

    raw = backup.read_text(encoding="utf-8")
    assert "secret-token" in raw
    assert "search.example" in raw


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


async def test_run_daemon_with_autoreload_debug_reloads_config_between_restarts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    watched_file = tmp_path / "watched.py"
    watched_file.write_text("value = 1\n", encoding="utf-8")
    config = _config(tmp_path).model_copy(
        update={
            "log_level": "DEBUG",
            "data_dir": tmp_path / "data-initial",
        }
    )
    refreshed = _config(tmp_path).model_copy(
        update={
            "log_level": "INFO",
            "data_dir": tmp_path / "data-refreshed",
        }
    )
    monkeypatch.setattr(cli_main, "_get_config", lambda: refreshed)

    seen_data_dirs: list[Path] = []
    seen_log_levels: list[str] = []
    first_started = asyncio.Event()
    first_cancelled = asyncio.Event()

    async def _fake_daemon(run_config: DaemonConfig) -> None:
        seen_data_dirs.append(run_config.data_dir)
        seen_log_levels.append(run_config.log_level)
        if len(seen_data_dirs) == 1:
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

    assert seen_data_dirs == [tmp_path / "data-initial", tmp_path / "data-refreshed"]
    assert seen_log_levels == ["DEBUG", "DEBUG"]


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
            reuse_bound_session: bool,
        ) -> None:
            captured["socket_path"] = socket_path
            captured["user_id"] = user_id
            captured["workspace_id"] = workspace_id
            captured["session_id"] = session_id
            captured["reuse_bound_session"] = reuse_bound_session

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
    assert captured["reuse_bound_session"] is True
    assert captured["ran"] is True


def test_chat_command_new_forces_fresh_session_binding(
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
            reuse_bound_session: bool,
        ) -> None:
            captured["socket_path"] = socket_path
            captured["user_id"] = user_id
            captured["workspace_id"] = workspace_id
            captured["session_id"] = session_id
            captured["reuse_bound_session"] = reuse_bound_session

        def run(self) -> None:
            captured["ran"] = True

    monkeypatch.setitem(sys.modules, "shisad.ui.chat", SimpleNamespace(ChatApp=_FakeApp))
    runner = CliRunner()

    result = runner.invoke(
        cli_main.cli,
        ["chat", "--new", "--user", "alice", "--workspace", "ws-a"],
    )

    assert result.exit_code == 0, result.output
    assert captured["socket_path"] == config.socket_path
    assert captured["user_id"] == "alice"
    assert captured["workspace_id"] == "ws-a"
    assert captured["session_id"] is None
    assert captured["reuse_bound_session"] is False
    assert captured["ran"] is True


def test_chat_command_rejects_new_and_session_together(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)
    runner = CliRunner()

    result = runner.invoke(cli_main.cli, ["chat", "--new", "--session", "sess-123"])
    assert result.exit_code == 1
    assert "--new cannot be used together with --session" in result.output


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


def test_action_confirm_includes_totp_proof_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)
    calls: list[tuple[str, dict[str, object] | None]] = []

    def _fake_rpc_call(
        effective_config: DaemonConfig,
        method: str,
        params: dict[str, object] | None = None,
        *,
        response_model: type[object] | None = None,
    ) -> object:
        assert effective_config is config
        calls.append((method, params))
        if method == "action.pending":
            payload = {
                "actions": [
                    {
                        "confirmation_id": "c-1",
                        "decision_nonce": "n-1",
                        "status": "pending",
                        "tool_name": "shell.exec",
                        "reason": "manual",
                    }
                ],
                "count": 1,
            }
        else:
            assert method == "action.confirm"
            payload = {
                "confirmed": True,
                "confirmation_id": "c-1",
                "status": "approved",
                "approval_level": "reauthenticated",
                "approval_method": "totp",
            }
        if response_model is None:
            return payload
        return response_model.model_validate(payload)  # type: ignore[attr-defined]

    monkeypatch.setattr(cli_main, "rpc_call", _fake_rpc_call)
    runner = CliRunner()

    result = runner.invoke(cli_main.cli, ["action", "confirm", "c-1", "--totp-code", "123456"])

    assert result.exit_code == 0, result.output
    assert calls[0][0] == "action.pending"
    assert calls[1] == (
        "action.confirm",
        {
            "confirmation_id": "c-1",
            "decision_nonce": "n-1",
            "reason": "",
            "approval_method": "totp",
            "proof": {"totp_code": "123456"},
        },
    )


def test_action_confirm_rejects_conflicting_totp_method_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)

    def _fake_rpc_call(
        effective_config: DaemonConfig,
        method: str,
        params: dict[str, object] | None = None,
        *,
        response_model: type[object] | None = None,
    ) -> object:
        assert effective_config is config
        assert method == "action.pending"
        payload = {
            "actions": [
                {
                    "confirmation_id": "c-1",
                    "decision_nonce": "n-1",
                    "status": "pending",
                    "tool_name": "shell.exec",
                    "reason": "manual",
                }
            ],
            "count": 1,
        }
        if response_model is None:
            return payload
        return response_model.model_validate(payload)  # type: ignore[attr-defined]

    monkeypatch.setattr(cli_main, "rpc_call", _fake_rpc_call)
    runner = CliRunner()

    result = runner.invoke(
        cli_main.cli,
        [
            "action",
            "confirm",
            "c-1",
            "--approval-method",
            "software",
            "--totp-code",
            "123456",
        ],
    )

    assert result.exit_code == 1
    assert "--approval-method conflicts with --totp-code" in result.output


def test_action_confirm_rejects_conflicting_recovery_method_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)

    def _fake_rpc_call(
        effective_config: DaemonConfig,
        method: str,
        params: dict[str, object] | None = None,
        *,
        response_model: type[object] | None = None,
    ) -> object:
        assert effective_config is config
        assert method == "action.pending"
        payload = {
            "actions": [
                {
                    "confirmation_id": "c-1",
                    "decision_nonce": "n-1",
                    "status": "pending",
                    "tool_name": "shell.exec",
                    "reason": "manual",
                }
            ],
            "count": 1,
        }
        if response_model is None:
            return payload
        return response_model.model_validate(payload)  # type: ignore[attr-defined]

    monkeypatch.setattr(cli_main, "rpc_call", _fake_rpc_call)
    runner = CliRunner()

    result = runner.invoke(
        cli_main.cli,
        [
            "action",
            "confirm",
            "c-1",
            "--approval-method",
            "totp",
            "--recovery-code",
            "ABCD-EFGH",
        ],
    )

    assert result.exit_code == 1
    assert "--approval-method conflicts with --recovery-code" in result.output


def test_two_factor_register_prompts_for_verification_and_confirms(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)
    calls: list[tuple[str, dict[str, object] | None]] = []

    def _fake_rpc_call(
        effective_config: DaemonConfig,
        method: str,
        params: dict[str, object] | None = None,
        *,
        response_model: type[object] | None = None,
    ) -> object:
        assert effective_config is config
        calls.append((method, params))
        if method == "2fa.register_begin":
            payload = {
                "started": True,
                "enrollment_id": "enroll-1",
                "user_id": "alice",
                "method": "totp",
                "principal_id": "ops-laptop",
                "credential_id": "totp-1",
                "secret": "SECRETBASE32",
                "otpauth_uri": "otpauth://totp/shisad:alice?secret=SECRETBASE32",
                "expires_at": "2026-04-06T12:10:00Z",
            }
        else:
            assert method == "2fa.register_confirm"
            payload = {
                "registered": True,
                "user_id": "alice",
                "method": "totp",
                "principal_id": "ops-laptop",
                "credential_id": "totp-1",
                "recovery_codes": ["RCODE-1", "RCODE-2"],
            }
        if response_model is None:
            return payload
        return response_model.model_validate(payload)  # type: ignore[attr-defined]

    monkeypatch.setattr(cli_main, "rpc_call", _fake_rpc_call)
    runner = CliRunner()

    result = runner.invoke(
        cli_main.cli,
        ["2fa", "register", "--method", "totp", "--user", "alice", "--name", "ops-laptop"],
        input="123456\n",
    )

    assert result.exit_code == 0, result.output
    assert calls == [
        (
            "2fa.register_begin",
            {"method": "totp", "user_id": "alice", "name": "ops-laptop"},
        ),
        (
            "2fa.register_confirm",
            {"enrollment_id": "enroll-1", "verify_code": "123456"},
        ),
    ]
    assert "SECRETBASE32" in result.output
    assert "RCODE-1" in result.output


def test_action_pending_renders_webauthn_link_and_qr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)

    def _fake_rpc_call(
        effective_config: DaemonConfig,
        method: str,
        params: dict[str, object] | None = None,
        *,
        response_model: type[object] | None = None,
    ) -> object:
        assert effective_config is config
        assert method == "action.pending"
        assert params == {
            "session_id": None,
            "status": None,
            "limit": 50,
            "include_ui": True,
        }
        payload = {
            "actions": [
                {
                    "confirmation_id": "c-1",
                    "decision_nonce": "n-1",
                    "status": "pending",
                    "tool_name": "shell.exec",
                    "reason": "manual",
                    "approval_url": "https://approve.example.com/approve/c-1?token=abc",
                    "approval_qr_ascii": "##\n##",
                }
            ],
            "count": 1,
        }
        if response_model is None:
            return payload
        return response_model.model_validate(payload)  # type: ignore[attr-defined]

    monkeypatch.setattr(cli_main, "rpc_call", _fake_rpc_call)
    runner = CliRunner()

    result = runner.invoke(cli_main.cli, ["action", "pending"])

    assert result.exit_code == 0, result.output
    assert "approval_url=https://approve.example.com/approve/c-1?token=abc" in result.output
    assert "approval_qr:" in result.output


def test_action_pending_sanitizes_terminal_preview_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)

    def _fake_rpc_call(
        effective_config: DaemonConfig,
        method: str,
        params: dict[str, object] | None = None,
        *,
        response_model: type[object] | None = None,
    ) -> object:
        assert effective_config is config
        assert method == "action.pending"
        payload = {
            "actions": [
                {
                    "confirmation_id": "c-\x1b[31m1",
                    "decision_nonce": "n-\x1b]2;bad\x07",
                    "status": "pending",
                    "tool_name": "shell.exec\x1b[31m",
                    "reason": "manual_review",
                    "safe_preview": "preview line\rsecond line\x1b[31m",
                }
            ],
            "count": 1,
        }
        if response_model is None:
            return payload
        return response_model.model_validate(payload)  # type: ignore[attr-defined]

    monkeypatch.setattr(cli_main, "rpc_call", _fake_rpc_call)
    runner = CliRunner()

    result = runner.invoke(cli_main.cli, ["action", "pending"])

    assert result.exit_code == 0, result.output
    assert "\x1b" not in result.output
    assert "c-1 nonce=n-" in result.output
    assert "tool=shell.exec" in result.output
    assert "preview line\nsecond line" in result.output


def test_action_confirm_webauthn_opens_browser_and_waits_for_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)
    calls: list[tuple[str, dict[str, object] | None]] = []
    pending_responses = [
        {
            "actions": [
                {
                    "confirmation_id": "c-1",
                    "decision_nonce": "n-1",
                    "status": "pending",
                    "tool_name": "shell.exec",
                    "reason": "manual",
                    "required_level": "bound_approval",
                    "selected_backend_method": "webauthn",
                    "approval_url": "https://approve.example.com/approve/c-1?token=abc",
                    "approval_qr_ascii": "##\n##",
                }
            ],
            "count": 1,
        },
        {
            "actions": [
                {
                    "confirmation_id": "c-1",
                    "decision_nonce": "n-1",
                    "status": "approved",
                    "status_reason": "",
                    "tool_name": "shell.exec",
                    "reason": "manual",
                    "required_level": "bound_approval",
                    "selected_backend_method": "webauthn",
                }
            ],
            "count": 1,
        },
    ]
    launched: list[tuple[str, bool]] = []

    def _fake_rpc_call(
        effective_config: DaemonConfig,
        method: str,
        params: dict[str, object] | None = None,
        *,
        response_model: type[object] | None = None,
    ) -> object:
        assert effective_config is config
        calls.append((method, params))
        assert method == "action.pending"
        payload = pending_responses.pop(0)
        if response_model is None:
            return payload
        return response_model.model_validate(payload)  # type: ignore[attr-defined]

    def _fake_launch(url: str, locate: bool = False) -> bool:
        launched.append((url, locate))
        return True

    monkeypatch.setattr(cli_main, "rpc_call", _fake_rpc_call)
    monkeypatch.setattr(click, "launch", _fake_launch)
    runner = CliRunner()

    result = runner.invoke(cli_main.cli, ["action", "confirm", "c-1"])

    assert result.exit_code == 0, result.output
    assert launched == [("https://approve.example.com/approve/c-1?token=abc", False)]
    assert all(method != "action.confirm" for method, _params in calls)
    assert '"status": "approved"' in result.output
    assert '"approval_method": "webauthn"' in result.output


def test_two_factor_register_webauthn_opens_browser_and_waits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)
    calls: list[tuple[str, dict[str, object] | None]] = []
    launched: list[tuple[str, bool]] = []

    def _fake_rpc_call(
        effective_config: DaemonConfig,
        method: str,
        params: dict[str, object] | None = None,
        *,
        response_model: type[object] | None = None,
    ) -> object:
        assert effective_config is config
        calls.append((method, params))
        if method == "2fa.register_begin":
            payload = {
                "started": True,
                "enrollment_id": "enroll-1",
                "user_id": "alice",
                "method": "webauthn",
                "principal_id": "ops-phone",
                "credential_id": "webauthn-1",
                "registration_url": "https://approve.example.com/register/enroll-1?token=abc",
                "approval_origin": "https://approve.example.com",
                "rp_id": "approve.example.com",
                "expires_at": "2026-04-06T12:10:00Z",
            }
        else:
            assert method == "2fa.list"
            payload = {
                "entries": [
                    {
                        "user_id": "alice",
                        "method": "webauthn",
                        "principal_id": "ops-phone",
                        "credential_id": "webauthn-1",
                        "created_at": "2026-04-06T12:05:00Z",
                        "last_verified_at": None,
                        "last_used_at": None,
                        "recovery_codes_remaining": 0,
                    }
                ],
                "count": 1,
            }
        if response_model is None:
            return payload
        return response_model.model_validate(payload)  # type: ignore[attr-defined]

    def _fake_launch(url: str, locate: bool = False) -> bool:
        launched.append((url, locate))
        return True

    monkeypatch.setattr(cli_main, "rpc_call", _fake_rpc_call)
    monkeypatch.setattr(click, "launch", _fake_launch)
    runner = CliRunner()

    result = runner.invoke(
        cli_main.cli,
        ["2fa", "register", "--method", "webauthn", "--user", "alice", "--name", "ops-phone"],
    )

    assert result.exit_code == 0, result.output
    assert launched == [("https://approve.example.com/register/enroll-1?token=abc", False)]
    assert (
        "2fa.register_begin",
        {"method": "webauthn", "user_id": "alice", "name": "ops-phone"},
    ) in calls
    assert ("2fa.list", {"user_id": "alice", "method": "webauthn"}) in calls
    assert all(method != "2fa.register_confirm" for method, _params in calls)
    assert "Approval origin: https://approve.example.com" in result.output
    assert "Registered webauthn factor webauthn-1 for alice" in result.output


def test_approval_setup_prints_caddy_template(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)
    runner = CliRunner()

    result = runner.invoke(
        cli_main.cli,
        ["approval", "setup", "--provider", "caddy", "--origin", "https://approve.example.com"],
    )

    assert result.exit_code == 0, result.output
    assert "export SHISAD_APPROVAL_ORIGIN=https://approve.example.com" in result.output
    assert "export SHISAD_APPROVAL_RP_ID=approve.example.com" in result.output
    assert "export SHISAD_APPROVAL_BIND_HOST=127.0.0.1" in result.output
    assert "export SHISAD_APPROVAL_BIND_PORT=8787" in result.output
    assert "Caddyfile:" in result.output
    assert "approve.example.com {" in result.output
    assert "reverse_proxy 127.0.0.1:8787" in result.output


def test_approval_setup_prints_tailscale_guidance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)
    runner = CliRunner()

    result = runner.invoke(
        cli_main.cli,
        ["approval", "setup", "--provider", "tailscale", "--origin", "https://ops-demo.ts.net"],
    )

    assert result.exit_code == 0, result.output
    assert "Tailscale Guidance:" in result.output
    assert "Use https://ops-demo.ts.net as the HTTPS tailnet origin." in result.output
    assert "http://127.0.0.1:8787" in result.output
