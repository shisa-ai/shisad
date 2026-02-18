"""Integration sweep for facade routing across split handler modules."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from pathlib import Path

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


@pytest.mark.asyncio
async def test_facade_routes_across_handler_groups(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
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
        assert created["session_id"]

        status = await client.call("daemon.status")
        assert status["status"] == "running"
        doctor_all = await client.call("doctor.check", {"component": "all"})
        assert doctor_all["status"] in {"ok", "degraded"}
        checks = doctor_all.get("checks", {})
        assert "dependencies" in checks
        assert "policy" in checks
        assert "channels" in checks
        assert "sandbox" in checks
        assert "realitycheck" in checks
        assert checks["dependencies"]["status"] in {"ok", "misconfigured"}
        assert checks["policy"]["status"] in {"ok", "degraded", "misconfigured"}
        assert checks["channels"]["status"] in {"ok", "degraded", "misconfigured", "disabled"}
        assert checks["sandbox"]["status"] in {"ok", "degraded", "misconfigured"}

        unsupported = await client.call("doctor.check", {"component": "not-a-component"})
        assert unsupported["status"] == "error"
        assert unsupported["error"] == "unsupported_component"

        memory = await client.call("memory.list", {"limit": 10})
        assert "entries" in memory

        skills = await client.call("skill.list")
        assert "skills" in skills

        tasks = await client.call("task.list")
        assert "tasks" in tasks

        pending = await client.call("action.pending", {"limit": 10})
        assert "actions" in pending

        dashboard = await client.call("dashboard.alerts", {"limit": 10})
        assert "alerts" in dashboard
        assert "total" in dashboard
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_note_and_todo_list_limits_are_type_aware(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
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

        await client.call(
            "note.create",
            {"key": "n1", "content": "note-one", "source_id": sid, "user_confirmed": True},
        )
        await client.call(
            "todo.create",
            {"title": "todo-one", "source_id": sid, "user_confirmed": True},
        )
        await client.call(
            "note.create",
            {"key": "n2", "content": "note-two", "source_id": sid, "user_confirmed": True},
        )
        await client.call(
            "todo.create",
            {"title": "todo-two", "source_id": sid, "user_confirmed": True},
        )

        notes = await client.call("note.list", {"limit": 2})
        todos = await client.call("todo.list", {"limit": 2})

        assert notes["count"] == 2
        assert len(notes["entries"]) == 2
        assert all(item.get("entry_type") == "note" for item in notes["entries"])
        assert todos["count"] == 2
        assert len(todos["entries"]) == 2
        assert all(item.get("entry_type") == "todo" for item in todos["entries"])
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_doctor_component_requests_are_isolated_from_other_component_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")

    from shisad.daemon.handlers import _impl as impl_module

    def _raise_policy_check(_self: object) -> dict[str, object]:
        raise RuntimeError("simulated doctor failure")

    monkeypatch.setattr(
        impl_module.HandlerImplementation,
        "_doctor_policy_status",
        _raise_policy_check,
    )

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        log_level="INFO",
    )

    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)

    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()

        reality_only = await client.call("doctor.check", {"component": "realitycheck"})
        assert reality_only["status"] in {"ok", "degraded"}
        assert set(reality_only["checks"].keys()) == {"realitycheck"}

        policy_only = await client.call("doctor.check", {"component": "policy"})
        assert policy_only["status"] == "degraded"
        assert policy_only["checks"]["policy"]["status"] == "error"
        assert "component_failed:RuntimeError" in policy_only["checks"]["policy"]["problems"]
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_doctor_policy_reports_permissive_posture_without_false_degraded_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "\n".join(
            [
                'version: "1"',
                "default_deny: false",
                "default_require_confirmation: false",
            ]
        )
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

        policy_only = await client.call("doctor.check", {"component": "policy"})
        payload = policy_only["checks"]["policy"]
        assert payload["status"] == "ok"
        assert "default_deny_disabled" not in payload.get("problems", [])
        assert payload.get("posture") == "permissive"
        assert "default_deny_disabled" in payload.get("posture_notes", [])
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)
