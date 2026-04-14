"""Integration sweep for facade routing across split handler modules."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio

from tests.helpers.daemon import (
    SharedDaemonController,
    clear_remote_provider_env,
    daemon_harness,
    shared_daemon_controller,
)

pytestmark = pytest.mark.asyncio(loop_scope="module")

_REMOTE_PROVIDER_ENV = {
    "SHISAD_MODEL_BASE_URL": "https://api.example.com/v1",
    "SHISAD_MODEL_PLANNER_BASE_URL": "https://planner.example.com/v1",
    "SHISAD_MODEL_EMBEDDINGS_BASE_URL": "https://embed.example.com/v1",
    "SHISAD_MODEL_MONITOR_BASE_URL": "https://monitor.example.com/v1",
}

_DEFAULT_POLICY_TEXT = "{}\n"
_PERMISSIVE_POLICY_TEXT = (
    "\n".join(
        [
            'version: "1"',
            "default_deny: false",
            "default_require_confirmation: false",
        ]
    )
    + "\n"
)


def _set_example_model_env(monkeypatch: pytest.MonkeyPatch) -> None:
    clear_remote_provider_env(monkeypatch)
    for key, value in _REMOTE_PROVIDER_ENV.items():
        monkeypatch.setenv(key, value)


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def shared_handler_daemon(
    tmp_path_factory: pytest.TempPathFactory,
) -> AsyncIterator[SharedDaemonController]:
    env_patch = pytest.MonkeyPatch()
    _set_example_model_env(env_patch)
    tmp_dir = tmp_path_factory.mktemp("handler-integration-daemon")
    try:
        async with shared_daemon_controller(
            tmp_dir,
            policy_text=_DEFAULT_POLICY_TEXT,
            config_kwargs={"log_level": "INFO"},
        ) as controller:
            yield controller
    finally:
        env_patch.undo()


@pytest_asyncio.fixture(loop_scope="module")
async def recycled_handler_daemon(
    shared_handler_daemon: SharedDaemonController,
) -> AsyncIterator[SharedDaemonController]:
    yield shared_handler_daemon
    await shared_handler_daemon.recycle()


async def test_facade_routes_across_handler_groups(
    recycled_handler_daemon: SharedDaemonController,
) -> None:
    created = await recycled_handler_daemon.call(
        "session.create",
        {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
    )
    assert created["session_id"]

    status = await recycled_handler_daemon.call("daemon.status")
    assert status["status"] == "running"
    doctor_all = await recycled_handler_daemon.call("doctor.check", {"component": "all"})
    assert doctor_all["status"] in {"ok", "degraded"}
    checks = doctor_all.get("checks", {})
    assert "dependencies" in checks
    assert "provider" in checks
    assert "policy" in checks
    assert "channels" in checks
    assert "sandbox" in checks
    assert "realitycheck" in checks
    assert checks["dependencies"]["status"] in {"ok", "misconfigured"}
    assert checks["provider"]["status"] in {"ok", "misconfigured"}
    assert checks["policy"]["status"] in {"ok", "degraded", "misconfigured"}
    assert checks["channels"]["status"] in {"ok", "degraded", "misconfigured", "disabled"}
    assert checks["sandbox"]["status"] in {"ok", "degraded", "misconfigured"}

    unsupported = await recycled_handler_daemon.call(
        "doctor.check",
        {"component": "not-a-component"},
    )
    assert unsupported["status"] == "error"
    assert unsupported["error"] == "unsupported_component"

    memory = await recycled_handler_daemon.call("memory.list", {"limit": 10})
    assert "entries" in memory

    skills = await recycled_handler_daemon.call("skill.list")
    assert "skills" in skills

    tasks = await recycled_handler_daemon.call("task.list")
    assert "tasks" in tasks

    pending = await recycled_handler_daemon.call("action.pending", {"limit": 10})
    assert "actions" in pending

    dashboard = await recycled_handler_daemon.call("dashboard.alerts", {"limit": 10})
    assert "alerts" in dashboard
    assert "total" in dashboard


async def test_note_and_todo_list_limits_are_type_aware(
    recycled_handler_daemon: SharedDaemonController,
) -> None:
    created = await recycled_handler_daemon.call(
        "session.create",
        {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
    )
    sid = created["session_id"]

    await recycled_handler_daemon.call(
        "note.create",
        {"key": "n1", "content": "note-one", "source_id": sid, "user_confirmed": True},
    )
    await recycled_handler_daemon.call(
        "todo.create",
        {"title": "todo-one", "source_id": sid, "user_confirmed": True},
    )
    await recycled_handler_daemon.call(
        "note.create",
        {"key": "n2", "content": "note-two", "source_id": sid, "user_confirmed": True},
    )
    await recycled_handler_daemon.call(
        "todo.create",
        {"title": "todo-two", "source_id": sid, "user_confirmed": True},
    )

    notes = await recycled_handler_daemon.call("note.list", {"limit": 2})
    todos = await recycled_handler_daemon.call("todo.list", {"limit": 2})

    assert notes["count"] == 2
    assert len(notes["entries"]) == 2
    assert all(item.get("entry_type") == "note" for item in notes["entries"])
    assert todos["count"] == 2
    assert len(todos["entries"]) == 2
    assert all(item.get("entry_type") == "todo" for item in todos["entries"])


async def test_doctor_component_requests_are_isolated_from_other_component_failures(
    recycled_handler_daemon: SharedDaemonController,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shisad.daemon.handlers import _impl as impl_module

    def _raise_policy_check(_self: object) -> dict[str, object]:
        raise RuntimeError("simulated doctor failure")

    monkeypatch.setattr(
        impl_module.HandlerImplementation,
        "_doctor_policy_status",
        _raise_policy_check,
    )

    reality_only = await recycled_handler_daemon.call("doctor.check", {"component": "realitycheck"})
    assert reality_only["status"] in {"ok", "degraded"}
    assert set(reality_only["checks"].keys()) == {"realitycheck"}

    policy_only = await recycled_handler_daemon.call("doctor.check", {"component": "policy"})
    assert policy_only["status"] == "degraded"
    assert policy_only["checks"]["policy"]["status"] == "error"
    assert "component_failed:RuntimeError" in policy_only["checks"]["policy"]["problems"]


async def test_doctor_policy_reports_permissive_posture_without_false_degraded_status(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_example_model_env(monkeypatch)

    async with daemon_harness(
        tmp_path,
        policy_text=_PERMISSIVE_POLICY_TEXT,
        config_kwargs={"log_level": "INFO"},
    ) as harness:
        policy_only = await harness.call("doctor.check", {"component": "policy"})
        payload = policy_only["checks"]["policy"]
        assert payload["status"] == "ok"
        assert "default_deny_disabled" not in payload.get("problems", [])
        assert payload.get("posture") == "permissive"
        assert "default_deny_disabled" in payload.get("posture_notes", [])
