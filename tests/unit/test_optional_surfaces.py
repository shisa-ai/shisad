"""M6 optional TUI/Web surface sanity coverage."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from shisad.ui.tui import TuiSnapshot, render_plain
from shisad.ui.web import render_web_snapshot


def test_tui_plain_renderer_includes_confirmation_panel() -> None:
    snapshot = TuiSnapshot(
        sessions=[{"id": "s1", "user_id": "u1", "lockdown_level": "normal"}],
        pending_actions=[
            {
                "confirmation_id": "c1",
                "tool_name": "http_request",
                "status": "pending",
                "risk_level": "high",
                "required_proof_tier": "T0_identity",
                "selected_backend_method": "totp",
                "channel_capability": {
                    "approval_route": "host_cli",
                    "can_carry": False,
                    "can_collect_selected_method": True,
                    "can_carry_t1_stepup": True,
                    "requires_second_factor": True,
                    "cannot_carry_reason": "selected_method_requires_T1_stepup",
                },
                "safe_preview": (
                    "ACTION CONFIRMATION\n"
                    "Action: http_request\n"
                    "PARAMETERS:\n"
                    "  url: https://example.test"
                ),
                "warnings": ["Contains tainted data"],
            }
        ],
        plan_steps=[
            {
                "id": "step-1",
                "order": 1,
                "title": "Current request",
                "status": "in_progress",
                "current": True,
            }
        ],
        tasks=[
            {
                "id": "t1",
                "status": "enabled",
                "enabled": True,
                "schedule_kind": "interval",
                "schedule_summary": "every 5 minutes",
                "delivery_channel": "discord",
                "pending_confirmations": [{"confirmation_id": "c-task"}],
                "pending_confirmation_count": 1,
            }
        ],
        channel_health=[
            {
                "channel": "discord",
                "enabled": True,
                "available": True,
                "connected": True,
            }
        ],
        alerts=[{"event_type": "AnomalyReported", "acknowledged_reason": ""}],
        audit_events=[{"timestamp": "2026-02-11T00:00:00+09:00", "event_type": "ToolRejected"}],
    )
    rendered = render_plain(snapshot)
    assert "PENDING CONFIRMATIONS" in rendered
    assert "c1 tool=http_request status=pending" in rendered
    assert "risk=high proof=T0_identity method=totp route=host_cli" in rendered
    assert "approve: c c1 <totp-code>" in rendered
    assert "approve: cannot carry" not in rendered
    assert "Action: http_request" in rendered
    assert "url: https://example.test" in rendered
    assert "warnings=1: Contains tainted data" in rendered
    assert "WORK BREAKDOWN:" in rendered
    assert "> [in_progress] 1. Current request" in rendered
    assert "TASKS:" in rendered
    assert "t1 status=enabled enabled=True schedule=interval delivery=discord" in rendered
    assert "waiting_on_approval confirmation=c-task" in rendered
    assert "CHANNEL HEALTH:" in rendered


def test_u3_tui_plain_renderer_includes_summary_and_explicit_empty_states() -> None:
    rendered = render_plain(TuiSnapshot())

    assert "SUMMARY:" in rendered
    assert (
        "sessions=0 lockdown=0 pending_confirmations=0 tasks=0 enabled_tasks=0 "
        "channels=0 connected_channels=0 alerts=0 acknowledged_alerts=0 audit_events=0"
    ) in rendered
    assert "SESSIONS:\n  no active sessions" in rendered
    assert "PENDING CONFIRMATIONS:\n  no pending confirmations" in rendered
    assert "WORK BREAKDOWN:\n  no active plan" in rendered
    assert "TASKS:\n  no background tasks" in rendered
    assert "CHANNEL HEALTH:\n  no configured channels" in rendered
    assert "ALERTS:\n  no active alerts" in rendered
    assert "AUDIT EVENTS:\n  no recent audit events" in rendered


def test_t1_tui_plain_renderer_uses_structured_plan_step_rows() -> None:
    snapshot = TuiSnapshot(
        plan_steps=[
            {
                "id": "step-2",
                "order": 2,
                "title": "Patch UI",
                "status": "in_progress",
                "current": True,
                "depends_on": ["step-1"],
            },
            {
                "id": "step-1",
                "order": 1,
                "title": "Inspect runtime",
                "status": "done",
                "current": False,
            },
            {
                "id": "step-3",
                "order": 3,
                "title": "Wait for approval",
                "status": "blocked",
                "current": True,
                "blocked_reason": "pending_confirmation",
            },
            {
                "id": "step-4",
                "order": 4,
                "title": "Mystery status",
                "status": "unexpected",
                "current": True,
            },
        ]
    )

    rendered = render_plain(snapshot)

    assert "WORK BREAKDOWN:" in rendered
    assert "  [done] 1. Inspect runtime" in rendered
    assert "  > [in_progress] 2. Patch UI depends_on=step-1" in rendered
    assert "  > [blocked] 3. Wait for approval blocked=pending_confirmation" in rendered
    assert "  [unknown] 4. Mystery status" in rendered


def test_t1_tui_plain_renderer_scopes_multiple_session_plan_rows() -> None:
    snapshot = TuiSnapshot(
        plan_steps=[
            {
                "id": "step-b",
                "session_id": "sess-b",
                "order": 1,
                "title": "Second session",
                "status": "blocked",
                "current": True,
                "blocked_reason": "pending_confirmation",
            },
            {
                "id": "step-a",
                "session_id": "sess-a",
                "order": 1,
                "title": "First session",
                "status": "in_progress",
                "current": True,
            },
        ]
    )

    rendered = render_plain(snapshot)

    assert "  > [in_progress] 1. First session session=sess-a" in rendered
    assert (
        "  > [blocked] 1. Second session session=sess-b blocked=pending_confirmation"
        in rendered
    )


def test_u3_tui_plain_summary_counts_derive_from_structured_rows() -> None:
    snapshot = TuiSnapshot(
        sessions=[
            {"id": "s1", "user_id": "u1", "lockdown_level": "normal"},
            {"id": "s2", "user_id": "u2", "lockdown_level": "caution"},
        ],
        pending_actions=[
            {"confirmation_id": "c1", "tool_name": "fs.write", "status": "pending"},
            {"confirmation_id": "c2", "tool_name": "http.request", "status": "pending"},
        ],
        tasks=[
            {"id": "t1", "enabled": True, "schedule_kind": "interval"},
            {"id": "t2", "enabled": False, "schedule_kind": "manual"},
        ],
        channel_health=[
            {"channel": "discord", "enabled": True, "available": True, "connected": True},
            {"channel": "slack", "enabled": True, "available": True, "connected": False},
        ],
        alerts=[
            {"event_type": "AnomalyReported", "acknowledged_reason": ""},
            {"event_type": "AlertRaised", "acknowledged_reason": "known false positive"},
        ],
        audit_events=[{"event_type": "SessionMessageReceived"}],
    )

    rendered = render_plain(snapshot)

    assert (
        "sessions=2 lockdown=1 pending_confirmations=2 tasks=2 enabled_tasks=1 "
        "channels=2 connected_channels=1 alerts=1 acknowledged_alerts=1 audit_events=1"
    ) in rendered
    assert "s2 user=u2 lockdown=caution" in rendered
    assert "t2 status=disabled enabled=False schedule=manual" in rendered
    assert "slack enabled=True available=True connected=False status=degraded" in rendered
    assert "active AnomalyReported ack=" in rendered
    assert "acknowledged AlertRaised ack=known false positive" in rendered


def test_u3_tui_plain_treats_disabled_channels_and_acknowledged_alerts_as_inactive() -> None:
    snapshot = TuiSnapshot(
        channel_health=[
            {
                "channel": "discord",
                "enabled": False,
                "available": False,
                "connected": False,
            },
            {
                "channel": "slack",
                "enabled": False,
                "available": False,
                "connected": False,
            },
        ],
        alerts=[
            {
                "event_type": "AlertRaised",
                "acknowledged_reason": "known false positive",
            }
        ],
    )

    rendered = render_plain(snapshot)

    assert (
        "sessions=0 lockdown=0 pending_confirmations=0 tasks=0 enabled_tasks=0 "
        "channels=0 connected_channels=0 alerts=0 acknowledged_alerts=1 audit_events=0"
    ) in rendered
    assert "CHANNEL HEALTH:\n  no configured channels" in rendered
    assert "discord enabled=False" not in rendered
    assert (
        "ALERTS:\n  no active alerts\n  acknowledged AlertRaised ack=known false positive"
        in rendered
    )


def test_web_snapshot_renderer_includes_key_sections() -> None:
    html = render_web_snapshot(
        {
            "sessions": [{"id": "s1"}],
            "pending_actions": [{"confirmation_id": "c1"}],
            "alerts": [{"event_type": "AnomalyReported"}],
            "egress_events": [{"event_type": "ProxyRequestEvaluated"}],
        }
    )
    assert "API-first dashboard snapshot" in html
    assert "Pending confirmations" in html
    assert "Egress events" in html


@pytest.mark.asyncio
async def test_tui_fetch_snapshot_uses_control_client(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeClient:
        def __init__(self, socket_path: Path) -> None:
            self.socket_path = socket_path
            self.connected = False
            self.closed = False
            self.calls: list[tuple[str, dict[str, object] | None]] = []

        async def connect(self) -> None:
            self.connected = True

        async def call(
            self, method: str, params: dict[str, object] | None = None
        ) -> dict[str, object]:
            self.calls.append((method, params))
            mapping = {
                "session.list": {
                    "sessions": [{"id": "s1", "user_id": "u1", "workspace_id": "ws1"}]
                },
                "action.pending": {
                    "actions": [
                        {
                            "confirmation_id": "c1",
                            "action_id": "c1",
                            "status": "pending",
                            "risk_level": "medium",
                            "required_proof_tier": "T0_identity",
                            "selected_backend_method": "software",
                            "channel_capability": {
                                "approval_route": "host_cli",
                                "can_carry": True,
                            },
                            "safe_preview": "ACTION CONFIRMATION",
                            "warnings": ["Contains tainted data"],
                        }
                    ]
                },
                "plan.steps": {
                    "steps": [
                        {
                            "id": "step-1",
                            "session_id": "s1",
                            "order": 1,
                            "title": "Current request",
                            "status": "in_progress",
                            "current": True,
                        }
                    ],
                    "count": 1,
                },
                "task.status_snapshot": {
                    "tasks": [
                        {
                            "task_id": "t1",
                            "title": "task one",
                            "status": "enabled",
                            "schedule_kind": "recurring_interval",
                            "schedule_summary": "every 5 minutes",
                            "delivery_channel": "discord",
                            "last_triggered_at": "2026-06-29T00:00:00+00:00",
                        }
                    ],
                    "count": 1,
                    "scope_status": "scoped",
                },
                "daemon.status": {
                    "channels": {
                        "discord": {
                            "enabled": True,
                            "available": True,
                            "connected": True,
                        }
                    }
                },
                "dashboard.alerts": {"alerts": [{"event_type": "AlertRaised"}]},
                "dashboard.audit_explorer": {"events": [{"event_type": "AuditLogged"}]},
            }
            return mapping[method]

        async def close(self) -> None:
            self.closed = True

    created: list[_FakeClient] = []

    def _factory(socket_path: Path) -> _FakeClient:
        client = _FakeClient(socket_path)
        created.append(client)
        return client

    monkeypatch.setattr("shisad.ui.tui.ControlClient", _factory)
    from shisad.ui.tui import fetch_snapshot

    snapshot = await fetch_snapshot(Path("/tmp/control.sock"))
    assert snapshot.sessions[0]["id"] == "s1"
    assert snapshot.pending_actions[0]["confirmation_id"] == "c1"
    assert snapshot.pending_actions[0]["status"] == "pending"
    assert snapshot.pending_actions[0]["required_proof_tier"] == "T0_identity"
    assert snapshot.pending_actions[0]["selected_backend_method"] == "software"
    assert snapshot.pending_actions[0]["channel_capability"]["can_carry"] is True
    assert snapshot.pending_actions[0]["warnings"] == ["Contains tainted data"]
    assert snapshot.plan_steps[0]["id"] == "step-1"
    assert snapshot.plan_steps[0]["status"] == "in_progress"
    assert snapshot.plan_steps[0]["current"] is True
    assert snapshot.tasks[0]["id"] == "t1"
    assert snapshot.tasks[0]["status"] == "enabled"
    assert snapshot.tasks[0]["schedule_kind"] == "recurring_interval"
    assert snapshot.tasks[0]["schedule_summary"] == "every 5 minutes"
    assert snapshot.channel_health[0]["channel"] == "discord"
    assert snapshot.channel_health[0]["connected"] is True
    assert snapshot.channel_health[0]["status"] == "ok"
    assert snapshot.alerts[0]["event_type"] == "AlertRaised"
    assert snapshot.audit_events[0]["event_type"] == "AuditLogged"
    assert created[0].connected is True
    assert created[0].closed is True
    assert (
        "task.status_snapshot",
        {"user_id": "u1", "workspace_id": "ws1", "limit": 20},
    ) in created[0].calls
    assert all(method != "task.list" for method, _params in created[0].calls)


def test_tui_render_rich_fallbacks_to_plain_without_rich(monkeypatch: pytest.MonkeyPatch) -> None:
    from shisad.ui import tui as tui_module

    snapshot = TuiSnapshot()

    def _raise_import(name: str):  # type: ignore[no-untyped-def]
        _ = name
        raise ImportError("rich not installed")

    monkeypatch.setattr(tui_module.importlib, "import_module", _raise_import)
    rendered = tui_module.render_rich(snapshot)
    assert rendered == render_plain(snapshot)


def test_tui_render_rich_uses_rich_modules_when_available(monkeypatch: pytest.MonkeyPatch) -> None:
    from shisad.ui import tui as tui_module

    created_consoles: list[object] = []

    class _FakeConsole:
        def __init__(self, *, record: bool = False) -> None:
            self.record = record
            self.panels: list[object] = []
            created_consoles.append(self)

        def print(self, panel: object) -> None:
            self.panels.append(panel)

        def export_text(self) -> str:
            return "rich-output"

    class _FakePanel:
        @staticmethod
        def fit(table: object) -> tuple[str, object]:
            return ("panel", table)

    class _FakeTable:
        def __init__(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            self.title = str(kwargs.get("title", ""))
            self.rows: list[tuple[str, ...]] = []
            self.styles: list[str] = []

        def add_column(self, *_args: object, **_kwargs: object) -> None:
            return

        def add_row(self, *row: str, **kwargs: object) -> None:
            self.rows.append(tuple(row))
            self.styles.append(str(kwargs.get("style", "")))

    modules = {
        "rich.console": SimpleNamespace(Console=_FakeConsole),
        "rich.panel": SimpleNamespace(Panel=_FakePanel),
        "rich.table": SimpleNamespace(Table=_FakeTable),
    }

    monkeypatch.setattr(tui_module.importlib, "import_module", lambda name: modules[name])
    snapshot = TuiSnapshot(
        sessions=[{"id": "s1", "user_id": "u1", "lockdown_level": "normal"}],
        pending_actions=[
            {
                "confirmation_id": "c1",
                "tool_name": "http_request",
                "status": "pending",
                "risk_level": "high",
                "required_proof_tier": "T0_identity",
                "selected_backend_method": "totp",
                "channel_capability": {
                    "approval_route": "host_cli",
                    "can_carry": False,
                    "can_collect_selected_method": True,
                    "can_carry_t1_stepup": True,
                    "requires_second_factor": True,
                    "cannot_carry_reason": "selected_method_requires_T1_stepup",
                },
                "safe_preview": "ACTION CONFIRMATION\nAction: http_request\nPARAMETERS:\n  q: hi",
                "warnings": ["Contains tainted data"],
            }
        ],
        plan_steps=[
            {
                "id": "step-1",
                "order": 1,
                "title": "Current request",
                "status": "blocked",
                "current": True,
                "blocked_reason": "pending_confirmation",
            }
        ],
        tasks=[
            {
                "id": "t1",
                "enabled": True,
                "schedule_kind": "interval",
                "delivery_channel": "discord",
                "pending_confirmations": [{"confirmation_id": "c1"}],
                "pending_confirmation_count": 1,
            }
        ],
        channel_health=[
            {
                "channel": "discord",
                "enabled": True,
                "available": True,
                "connected": True,
                "status": "ok",
            },
            {
                "channel": "matrix",
                "enabled": True,
                "available": True,
                "connected": False,
                "status": "degraded",
            },
            {
                "channel": "telegram",
                "enabled": True,
                "available": False,
                "connected": False,
                "status": "misconfigured",
            },
            {
                "channel": "slack",
                "enabled": False,
                "available": False,
                "connected": False,
                "status": "disabled",
            }
        ],
        alerts=[
            {"event_type": "AlertRaised", "acknowledged_reason": ""},
            {"event_type": "AlertRaised", "acknowledged_reason": "known false positive"},
        ],
        audit_events=[
            {
                "timestamp": "2026-02-15T00:00:00+00:00",
                "event_type": "AuditLogged",
                "session_id": "s1",
            }
        ],
    )
    rendered = tui_module.render_rich(snapshot)
    assert rendered == "rich-output"
    assert len(created_consoles) == 1
    panel_tables = [panel[1] for panel in created_consoles[0].panels if isinstance(panel, tuple)]
    assert any(getattr(table, "title", "") == "Audit Events" for table in panel_tables)
    sessions_table = next(
        table for table in panel_tables if getattr(table, "title", "") == "Sessions"
    )
    pending_table = next(
        table for table in panel_tables if getattr(table, "title", "") == "Pending Confirmations"
    )
    tasks_table = next(table for table in panel_tables if getattr(table, "title", "") == "Tasks")
    plan_table = next(
        table for table in panel_tables if getattr(table, "title", "") == "Work Breakdown"
    )
    channels_table = next(
        table for table in panel_tables if getattr(table, "title", "") == "Channel Health"
    )
    alerts_table = next(table for table in panel_tables if getattr(table, "title", "") == "Alerts")
    summary_table = next(
        table for table in panel_tables if getattr(table, "title", "") == "Summary"
    )
    summary_text = "\n".join(" ".join(row) for row in summary_table.rows)
    assert "pending_confirmations 1" in summary_text
    assert "channels 3" in summary_text
    assert "connected_channels 1" in summary_text
    assert "alerts 1" in summary_text
    assert "acknowledged_alerts 1" in summary_text
    pending_text = "\n".join(" ".join(row) for row in pending_table.rows)
    assert "risk=high proof=T0_identity method=totp route=host_cli" in pending_text
    assert "approve: c c1 <totp-code>" in pending_text
    assert "approve: cannot carry" not in pending_text
    assert "Action: http_request" in pending_text
    assert "warnings=1: Contains tainted data" in pending_text
    plan_text = "\n".join(" ".join(row) for row in plan_table.rows)
    task_text = "\n".join(" ".join(row) for row in tasks_table.rows)
    assert "step-1 1 Current request blocked yes pending_confirmation" in plan_text
    assert "confirmation=c1 proof=T0_identity method=totp route=host_cli" in task_text
    assert sessions_table.styles == ["green"]
    assert pending_table.styles == ["yellow"]
    assert plan_table.styles == ["yellow"]
    assert tasks_table.styles == ["green"]
    assert channels_table.styles == ["green", "yellow", "red"]
    assert alerts_table.styles == ["red", "dim"]


@pytest.mark.asyncio
async def test_tui_fetch_snapshot_tolerates_partial_rpc_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeClient:
        def __init__(self, socket_path: Path) -> None:
            self.socket_path = socket_path
            self.connected = False
            self.closed = False

        async def connect(self) -> None:
            self.connected = True

        async def call(
            self, method: str, params: dict[str, object] | None = None
        ) -> dict[str, object]:
            _ = params
            if method == "dashboard.audit_explorer":
                raise RuntimeError("simulated failure")
            mapping = {
                "session.list": {"sessions": [{"id": "s1"}]},
                "action.pending": {"actions": [{"confirmation_id": "c1", "status": "pending"}]},
                "plan.steps": {"steps": []},
                "daemon.status": {"channels": {}},
                "dashboard.alerts": {"alerts": [{"event_type": "AlertRaised"}]},
            }
            return mapping[method]

        async def close(self) -> None:
            self.closed = True

    created: list[_FakeClient] = []

    def _factory(socket_path: Path) -> _FakeClient:
        client = _FakeClient(socket_path)
        created.append(client)
        return client

    monkeypatch.setattr("shisad.ui.tui.ControlClient", _factory)
    from shisad.ui.tui import fetch_snapshot

    snapshot = await fetch_snapshot(Path("/tmp/control.sock"))
    assert snapshot.sessions[0]["id"] == "s1"
    assert snapshot.pending_actions[0]["confirmation_id"] == "c1"
    assert snapshot.alerts[0]["event_type"] == "AlertRaised"
    assert snapshot.audit_events == []
    assert created[0].connected is True
    assert created[0].closed is True


@pytest.mark.asyncio
async def test_t2_tui_fetch_snapshot_fails_closed_without_unique_task_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeClient:
        def __init__(self, socket_path: Path) -> None:
            self.socket_path = socket_path
            self.calls: list[tuple[str, dict[str, object] | None]] = []

        async def connect(self) -> None:
            return

        async def call(
            self, method: str, params: dict[str, object] | None = None
        ) -> dict[str, object]:
            self.calls.append((method, params))
            if method == "session.list":
                return {
                    "sessions": [
                        {"id": "s1", "user_id": "u1", "workspace_id": "ws1"},
                        {"id": "s2", "user_id": "u2", "workspace_id": "ws1"},
                    ]
                }
            if method == "action.pending":
                return {"actions": []}
            if method == "plan.steps":
                return {"steps": []}
            if method == "daemon.status":
                return {"channels": {}}
            if method == "dashboard.alerts":
                return {"alerts": []}
            if method == "dashboard.audit_explorer":
                return {"events": []}
            raise AssertionError(f"unexpected TUI task/global call: {method}")

        async def close(self) -> None:
            return

    created: list[_FakeClient] = []

    def _factory(socket_path: Path) -> _FakeClient:
        client = _FakeClient(socket_path)
        created.append(client)
        return client

    monkeypatch.setattr("shisad.ui.tui.ControlClient", _factory)
    from shisad.ui.tui import fetch_snapshot

    snapshot = await fetch_snapshot(Path("/tmp/control.sock"))

    assert snapshot.tasks == []
    assert all(
        method not in {"task.list", "task.status_snapshot"} for method, _params in created[0].calls
    )


@pytest.mark.asyncio
async def test_tui_run_once_respects_rich_output_toggle(monkeypatch: pytest.MonkeyPatch) -> None:
    from shisad.ui import tui as tui_module

    async def _fake_fetch_snapshot(_socket_path: Path) -> TuiSnapshot:
        return TuiSnapshot()

    monkeypatch.setattr(tui_module, "fetch_snapshot", _fake_fetch_snapshot)
    monkeypatch.setattr(tui_module, "render_rich", lambda snapshot: "RICH")
    monkeypatch.setattr(tui_module, "render_plain", lambda snapshot: "PLAIN")
    assert await tui_module.run_once(Path("/tmp/control.sock"), rich_output=True) == "RICH"
    assert await tui_module.run_once(Path("/tmp/control.sock"), rich_output=False) == "PLAIN"


@pytest.mark.asyncio
async def test_tui_interactive_command_routing(monkeypatch: pytest.MonkeyPatch) -> None:
    from shisad.ui import tui as tui_module

    async def _fake_fetch_snapshot(_socket_path: Path) -> TuiSnapshot:
        return TuiSnapshot()

    decisions: list[tuple[str, str]] = []

    async def _fake_decision(_socket_path: Path, method: str, confirmation_id: str) -> None:
        decisions.append((method, confirmation_id))

    inputs = iter(["r", "c conf-1", "x conf-2", "unknown", "q"])
    monkeypatch.setattr(tui_module, "fetch_snapshot", _fake_fetch_snapshot)
    monkeypatch.setattr(tui_module, "_decision", _fake_decision)
    monkeypatch.setattr(tui_module, "render_plain", lambda snapshot: "snapshot")
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))
    monkeypatch.setattr("builtins.print", lambda *args, **kwargs: None)

    await tui_module.run_interactive(Path("/tmp/control.sock"))
    assert decisions == [("action.confirm", "conf-1"), ("action.reject", "conf-2")]


@pytest.mark.asyncio
async def test_tui_decision_handles_missing_and_present_confirmation_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shisad.ui import tui as tui_module

    printed: list[str] = []
    monkeypatch.setattr(
        "builtins.print",
        lambda *args, **kwargs: printed.append(" ".join(map(str, args))),
    )
    await tui_module._decision(Path("/tmp/control.sock"), "action.confirm", "")
    assert "confirmation_id required" in printed[0]

    class _FakeClient:
        def __init__(self, _socket_path: Path) -> None:
            self.calls: list[tuple[str, dict[str, object]]] = []

        async def connect(self) -> None:
            return

        async def call(self, method: str, payload: dict[str, object]) -> dict[str, object]:
            self.calls.append((method, payload))
            if method == "action.pending":
                return {
                    "actions": [
                        {
                            "confirmation_id": "conf-1",
                            "decision_nonce": "nonce-1",
                        }
                    ],
                    "count": 1,
                }
            return {"ok": True, "method": method, "payload": payload}

        async def close(self) -> None:
            return

    created: list[_FakeClient] = []

    def _factory(socket_path: Path) -> _FakeClient:
        client = _FakeClient(socket_path)
        created.append(client)
        return client

    async def _fake_sleep(_seconds: float) -> None:
        return

    monkeypatch.setattr(tui_module, "ControlClient", _factory)
    monkeypatch.setattr(asyncio, "sleep", _fake_sleep)
    await tui_module._decision(Path("/tmp/control.sock"), "action.confirm", "conf-1")
    assert created[0].calls == [
        (
            "action.pending",
            {
                "confirmation_id": "conf-1",
                "status": "pending",
                "limit": 1,
                "include_ui": False,
            },
        ),
        ("action.confirm", {"confirmation_id": "conf-1", "decision_nonce": "nonce-1"}),
    ]


@pytest.mark.asyncio
async def test_tui_decision_confirm_uses_single_allowed_channel_principal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shisad.ui import tui as tui_module

    monkeypatch.setattr("builtins.print", lambda *args, **kwargs: None)

    class _FakeClient:
        def __init__(self, _socket_path: Path) -> None:
            self.calls: list[tuple[str, dict[str, object]]] = []

        async def connect(self) -> None:
            return

        async def call(self, method: str, payload: dict[str, object]) -> dict[str, object]:
            self.calls.append((method, payload))
            if method == "action.pending":
                return {
                    "actions": [
                        {
                            "confirmation_id": "conf-1",
                            "decision_nonce": "nonce-1",
                            "allowed_channel_principals": ["alice"],
                        }
                    ],
                    "count": 1,
                }
            return {"ok": True, "method": method, "payload": payload}

        async def close(self) -> None:
            return

    created: list[_FakeClient] = []

    def _factory(socket_path: Path) -> _FakeClient:
        client = _FakeClient(socket_path)
        created.append(client)
        return client

    async def _fake_sleep(_seconds: float) -> None:
        return

    monkeypatch.setattr(tui_module, "ControlClient", _factory)
    monkeypatch.setattr(asyncio, "sleep", _fake_sleep)
    await tui_module._decision(Path("/tmp/control.sock"), "action.confirm", "conf-1")
    assert created[0].calls[-1] == (
        "action.confirm",
        {
            "confirmation_id": "conf-1",
            "decision_nonce": "nonce-1",
            "principal_id": "alice",
        },
    )


@pytest.mark.asyncio
async def test_tui_decision_confirm_can_send_totp_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shisad.ui import tui as tui_module

    monkeypatch.setattr("builtins.print", lambda *args, **kwargs: None)

    class _FakeClient:
        def __init__(self, _socket_path: Path) -> None:
            self.calls: list[tuple[str, dict[str, object]]] = []

        async def connect(self) -> None:
            return

        async def call(self, method: str, payload: dict[str, object]) -> dict[str, object]:
            self.calls.append((method, payload))
            if method == "action.pending":
                return {
                    "actions": [
                        {
                            "confirmation_id": "conf-1",
                            "decision_nonce": "nonce-1",
                            "selected_backend_method": "totp",
                            "allowed_channel_principals": ["alice"],
                        }
                    ],
                    "count": 1,
                }
            return {"ok": True, "method": method, "payload": payload}

        async def close(self) -> None:
            return

    created: list[_FakeClient] = []

    def _factory(socket_path: Path) -> _FakeClient:
        client = _FakeClient(socket_path)
        created.append(client)
        return client

    async def _fake_sleep(_seconds: float) -> None:
        return

    monkeypatch.setattr(tui_module, "ControlClient", _factory)
    monkeypatch.setattr(asyncio, "sleep", _fake_sleep)
    await tui_module._decision(
        Path("/tmp/control.sock"),
        "action.confirm",
        "conf-1",
        totp_code="123456",
    )
    assert created[0].calls[-1] == (
        "action.confirm",
        {
            "confirmation_id": "conf-1",
            "decision_nonce": "nonce-1",
            "principal_id": "alice",
            "approval_method": "totp",
            "proof": {"totp_code": "123456"},
        },
    )


@pytest.mark.asyncio
async def test_tui_decision_reject_fetches_decision_nonce(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shisad.ui import tui as tui_module

    printed: list[str] = []
    monkeypatch.setattr(
        "builtins.print",
        lambda *args, **kwargs: printed.append(" ".join(map(str, args))),
    )

    class _FakeClient:
        def __init__(self, _socket_path: Path) -> None:
            self.calls: list[tuple[str, dict[str, object]]] = []

        async def connect(self) -> None:
            return

        async def call(self, method: str, payload: dict[str, object]) -> dict[str, object]:
            self.calls.append((method, payload))
            if method == "action.pending":
                return {
                    "actions": [
                        {
                            "confirmation_id": "conf-2",
                            "decision_nonce": "nonce-2",
                            "allowed_channel_principals": ["alice"],
                        }
                    ],
                    "count": 1,
                }
            return {"ok": True, "method": method, "payload": payload}

        async def close(self) -> None:
            return

    created: list[_FakeClient] = []

    def _factory(socket_path: Path) -> _FakeClient:
        client = _FakeClient(socket_path)
        created.append(client)
        return client

    async def _fake_sleep(_seconds: float) -> None:
        return

    monkeypatch.setattr(tui_module, "ControlClient", _factory)
    monkeypatch.setattr(asyncio, "sleep", _fake_sleep)
    await tui_module._decision(Path("/tmp/control.sock"), "action.reject", "conf-2")
    assert created[0].calls == [
        (
            "action.pending",
            {
                "confirmation_id": "conf-2",
                "status": "pending",
                "limit": 1,
                "include_ui": False,
            },
        ),
        (
            "action.reject",
            {
                "confirmation_id": "conf-2",
                "decision_nonce": "nonce-2",
                "principal_id": "alice",
            },
        ),
    ]
    assert not any("decision_nonce not found" in line for line in printed)


@pytest.mark.asyncio
async def test_tui_decision_fails_when_targeted_nonce_lookup_misses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shisad.ui import tui as tui_module

    printed: list[str] = []
    monkeypatch.setattr(
        "builtins.print",
        lambda *args, **kwargs: printed.append(" ".join(map(str, args))),
    )

    class _FakeClient:
        def __init__(self, _socket_path: Path) -> None:
            self.calls: list[tuple[str, dict[str, object]]] = []

        async def connect(self) -> None:
            return

        async def call(self, method: str, payload: dict[str, object]) -> dict[str, object]:
            self.calls.append((method, payload))
            if method == "action.pending":
                return {"actions": [{"confirmation_id": "other", "decision_nonce": "nonce-x"}]}
            return {"ok": True, "method": method, "payload": payload}

        async def close(self) -> None:
            return

    created: list[_FakeClient] = []

    def _factory(socket_path: Path) -> _FakeClient:
        client = _FakeClient(socket_path)
        created.append(client)
        return client

    async def _fake_sleep(_seconds: float) -> None:
        return

    monkeypatch.setattr(tui_module, "ControlClient", _factory)
    monkeypatch.setattr(asyncio, "sleep", _fake_sleep)
    await tui_module._decision(Path("/tmp/control.sock"), "action.confirm", "conf-1")
    assert any("decision_nonce not found for confirmation_id" in line for line in printed)
    assert created[0].calls == [
        (
            "action.pending",
            {
                "confirmation_id": "conf-1",
                "status": "pending",
                "limit": 1,
                "include_ui": False,
            },
        ),
    ]


@pytest.mark.asyncio
async def test_web_fetch_and_write_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from shisad.ui import web as web_module

    class _FakeClient:
        def __init__(self, _socket_path: Path) -> None:
            self.calls: list[tuple[str, dict[str, object] | None]] = []

        async def connect(self) -> None:
            return

        async def call(
            self, method: str, params: dict[str, object] | None = None
        ) -> dict[str, object]:
            self.calls.append((method, params))
            mapping = {
                "session.list": {"sessions": [{"id": "s1"}]},
                "action.pending": {"actions": [{"confirmation_id": "c1"}]},
                "dashboard.alerts": {"alerts": [{"event_type": "AlertRaised"}]},
                "dashboard.egress_review": {"events": [{"destination_host": "api.good.com"}]},
            }
            return mapping[method]

        async def close(self) -> None:
            return

    monkeypatch.setattr(web_module, "ControlClient", _FakeClient)
    snapshot = await web_module.fetch_web_snapshot(Path("/tmp/control.sock"))
    assert snapshot["sessions"][0]["id"] == "s1"
    assert snapshot["pending_actions"][0]["confirmation_id"] == "c1"
    assert snapshot["alerts"][0]["event_type"] == "AlertRaised"
    assert snapshot["egress_events"][0]["destination_host"] == "api.good.com"

    output_path = tmp_path / "ui" / "snapshot.html"
    result = await web_module.write_web_snapshot(
        socket_path=Path("/tmp/control.sock"),
        output_path=output_path,
    )
    assert result == output_path
    assert output_path.exists()
    assert "shisad API-first dashboard snapshot" in output_path.read_text(encoding="utf-8")
