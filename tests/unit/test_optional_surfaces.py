"""M6 optional TUI/Web surface sanity coverage."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from shisad.ui import theme as theme_module
from shisad.ui.tui import TuiSnapshot, render_plain
from shisad.ui.web import render_web_snapshot


def _operator_session_row(
    session_id: str = "s1",
    user_id: str = "u1",
    workspace_id: str = "ws1",
) -> dict[str, object]:
    return {
        "id": session_id,
        "state": "active",
        "role": "orchestrator",
        "channel": "cli",
        "mode": "default",
        "user_id": user_id,
        "workspace_id": workspace_id,
    }


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


def test_f1_tui_pending_status_style_uses_canonical_lifecycle() -> None:
    from shisad.ui import tui as tui_module

    assert tui_module._pending_status_style("executed") == "shisa.success"
    assert tui_module._pending_status_style("superseded") == "shisa.danger"
    assert tui_module._pending_status_style("outcome_unknown") == "shisa.danger"


def test_f6_tui_rich_no_color_keeps_semantic_styles_renderable() -> None:
    from shisad.ui import tui as tui_module

    posture = theme_module.resolve_ui_posture(
        no_color=True,
        environ={"TERM": "xterm-256color", "LANG": "C.UTF-8"},
        isatty=True,
    )
    snapshot = TuiSnapshot(
        sessions=[{"id": "s1", "user_id": "u1", "lockdown_level": "normal"}],
    )

    rendered = tui_module.render_rich(snapshot, ui_posture=posture)

    assert "s1" in rendered
    assert "u1" in rendered
    assert "\x1b[" not in rendered


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


def test_t2_task_approval_hint_respects_surface_carry_gate() -> None:
    snapshot = TuiSnapshot(
        pending_actions=[
            {
                "confirmation_id": "c-browser",
                "tool_name": "message.send",
                "status": "pending",
                "required_proof_tier": "bound_approval",
                "selected_backend_method": "webauthn",
                "channel_capability": {
                    "approval_route": "browser",
                    "can_carry": False,
                    "can_collect_selected_method": False,
                    "can_reject": True,
                    "cannot_carry_reason": "browser_ceremony_required",
                },
            }
        ],
        tasks=[
            {
                "id": "task-browser",
                "status": "enabled",
                "schedule_kind": "event",
                "pending_confirmations": [{"confirmation_id": "c-browser"}],
                "pending_confirmation_count": 1,
            }
        ],
    )

    rendered = render_plain(snapshot)

    assert "waiting_on_approval confirmation=c-browser" in rendered
    assert "approve_unavailable=browser_ceremony_required" in rendered
    assert "approve_hint=c c-browser" not in rendered
    assert "reject_hint=x c-browser" in rendered


def test_t2_task_approval_hint_labels_recovery_code_truthfully() -> None:
    snapshot = TuiSnapshot(
        pending_actions=[
            {
                "confirmation_id": "c-recovery",
                "tool_name": "message.send",
                "status": "pending",
                "required_proof_tier": "T1_stepup",
                "selected_backend_method": "recovery_code",
                "channel_capability": {
                    "approval_route": "host_cli",
                    "can_carry": True,
                    "can_collect_selected_method": True,
                    "requires_second_factor": True,
                },
            }
        ],
        tasks=[
            {
                "id": "task-recovery",
                "status": "enabled",
                "schedule_kind": "event",
                "pending_confirmations": [{"confirmation_id": "c-recovery"}],
                "pending_confirmation_count": 1,
            }
        ],
    )

    rendered = render_plain(snapshot)

    assert "approve_hint=c c-recovery <recovery-code>" in rendered
    assert "<totp-code>" not in rendered


def test_t3_plain_task_panels_are_basic_terminal_safe_and_structured() -> None:
    snapshot = TuiSnapshot(
        pending_actions=[
            {
                "confirmation_id": "c-task-identity",
                "tool_name": "message.send",
                "status": "pending",
                "required_proof_tier": "T0_identity",
                "selected_backend_method": "software",
                "channel_capability": {
                    "approval_route": "host_cli",
                    "can_carry": True,
                    "can_collect_selected_method": True,
                    "can_reject": True,
                },
            },
            {
                "confirmation_id": "c-task-stepup",
                "tool_name": "fs.read",
                "status": "pending",
                "required_proof_tier": "T1_stepup",
                "selected_backend_method": "totp",
                "channel_capability": {
                    "approval_route": "host_cli",
                    "can_carry": True,
                    "can_collect_selected_method": True,
                    "requires_second_factor": True,
                    "can_reject": True,
                },
            },
        ],
        plan_steps=[
            {
                "id": "step-1",
                "order": 1,
                "title": "Inspect state",
                "status": "done",
            },
            {
                "id": "step-2",
                "order": 2,
                "title": "Approve task action",
                "status": "blocked",
                "current": True,
                "blocked_reason": "pending_confirmation",
                "depends_on": ["step-1"],
            },
        ],
        tasks=[
            {
                "id": "task-visible",
                "status": "enabled",
                "schedule_kind": "event",
                "schedule_summary": "event-triggered: message.received",
                "delivery_channel": "discord",
                "pending_confirmations": [
                    {
                        "confirmation_id": "c-task-identity",
                        "task_id": "task-visible",
                        "tool_name": "message.send",
                        "trigger_payload": "do not render raw trigger payload",
                    },
                    {
                        "confirmation_id": "c-task-stepup",
                        "task_id": "task-visible",
                        "tool_name": "fs.read",
                    },
                ],
                "pending_confirmation_count": 2,
            }
        ],
    )

    rendered = render_plain(snapshot)

    assert "\x1b[" not in rendered
    assert "WORK BREAKDOWN:" in rendered
    assert "  [done] 1. Inspect state" in rendered
    assert (
        "  > [blocked] 2. Approve task action depends_on=step-1 blocked=pending_confirmation"
    ) in rendered
    assert "TASKS:" in rendered
    assert "task-visible status=enabled enabled=True schedule=event delivery=discord" in rendered
    assert "summary=event-triggered: message.received" in rendered
    assert "waiting_on_approval confirmation=c-task-identity" in rendered
    assert "approve_hint=c c-task-identity" in rendered
    assert "waiting_on_approval confirmation=c-task-stepup" in rendered
    assert "approve_hint=c c-task-stepup <totp-code>" in rendered
    assert "reject_hint=x c-task-stepup" in rendered
    assert "do not render raw trigger payload" not in rendered


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
    assert "  > [blocked] 1. Second session session=sess-b blocked=pending_confirmation" in rendered


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


def test_f6_web_snapshot_uses_inert_json_node_and_escapes_script_termination() -> None:
    hostile = '</script><script>document.body.dataset.pwned="yes"</script>&'
    posture = theme_module.resolve_ui_posture(
        theme_name="shisa-light",
        reduce_motion=True,
        environ={"TERM": "dumb"},
        isatty=False,
    )

    rendered = render_web_snapshot(
        {
            "sessions": [{"id": hostile}],
            "pending_actions": [],
            "alerts": [],
            "egress_events": [],
        },
        ui_posture=posture,
    )

    assert '<script type="application/json" id="snapshot-data">' in rendered
    assert 'JSON.parse(document.getElementById("snapshot-data").textContent)' in rendered
    assert hostile not in rendered
    assert "\\u003c/script\\u003e" in rendered
    assert 'data-reduce-motion="true"' in rendered
    assert posture.palette.semantic["background"] in rendered


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
                "session.list": {"sessions": [_operator_session_row()]},
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
                    "user_id": "u1",
                    "workspace_id": "ws1",
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
        {"session_id": "s1", "limit": 20},
    ) in created[0].calls
    assert all(method != "task.list" for method, _params in created[0].calls)


@pytest.mark.asyncio
async def test_t2_tui_fetch_snapshot_rejects_mismatched_task_snapshot_scope(
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
                return {"sessions": [_operator_session_row("s1", "u1", "ws1")]}
            if method == "action.pending":
                return {"actions": []}
            if method == "plan.steps":
                return {"steps": []}
            if method == "task.status_snapshot":
                return {
                    "tasks": [{"task_id": "task-racy", "status": "enabled"}],
                    "count": 1,
                    "user_id": "u2",
                    "workspace_id": "ws1",
                    "scope_status": "scoped",
                }
            if method == "daemon.status":
                return {"channels": {}}
            if method == "dashboard.alerts":
                return {"alerts": []}
            if method == "dashboard.audit_explorer":
                return {"events": []}
            raise AssertionError(f"unexpected TUI call: {method}")

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
    assert (
        "task.status_snapshot",
        {"session_id": "s1", "limit": 20},
    ) in created[0].calls


@pytest.mark.asyncio
async def test_t2_tui_fetch_snapshot_enriches_visible_task_confirmation_metadata(
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
                return {"sessions": [_operator_session_row()]}
            if method == "action.pending":
                if params and params.get("confirmation_id") == "c-task-visible":
                    return {
                        "actions": [
                            {
                                "confirmation_id": "c-task-visible",
                                "status": "pending",
                                "required_proof_tier": "T1_stepup",
                                "selected_backend_method": "recovery_code",
                                "channel_capability": {
                                    "approval_route": "host_cli",
                                    "can_carry": True,
                                    "can_collect_selected_method": True,
                                    "requires_second_factor": True,
                                    "can_reject": True,
                                },
                            }
                        ],
                        "count": 1,
                    }
                return {
                    "actions": [
                        {"confirmation_id": f"global-{index}", "status": "pending"}
                        for index in range(20)
                    ],
                    "count": 21,
                }
            if method == "plan.steps":
                return {"steps": []}
            if method == "task.status_snapshot":
                return {
                    "tasks": [
                        {
                            "task_id": "task-visible",
                            "status": "enabled",
                            "schedule_kind": "event",
                            "pending_confirmations": [
                                {"confirmation_id": "c-task-visible", "task_id": "task-visible"}
                            ],
                            "pending_confirmation_count": 1,
                        }
                    ],
                    "count": 1,
                    "user_id": "u1",
                    "workspace_id": "ws1",
                    "scope_status": "scoped",
                }
            if method == "daemon.status":
                return {"channels": {}}
            if method == "dashboard.alerts":
                return {"alerts": []}
            if method == "dashboard.audit_explorer":
                return {"events": []}
            raise AssertionError(f"unexpected TUI call: {method}")

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
    rendered = render_plain(snapshot)

    assert len(snapshot.pending_actions) == 20
    assert "confirmation=c-task-visible" in rendered
    assert "method=recovery_code" in rendered
    assert "approve_hint=c c-task-visible <recovery-code>" in rendered
    assert "confirmation_metadata_unavailable" not in rendered
    assert (
        "action.pending",
        {
            "confirmation_id": "c-task-visible",
            "status": "pending",
            "limit": 1,
            "include_ui": True,
        },
    ) in created[0].calls


@pytest.mark.asyncio
async def test_t2_tui_fetch_snapshot_bounds_task_confirmation_metadata_enrichment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    confirmation_ids = [f"c-task-{index}" for index in range(25)]

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
                return {"sessions": [_operator_session_row()]}
            if method == "action.pending":
                confirmation_id = str((params or {}).get("confirmation_id", "")).strip()
                if confirmation_id:
                    return {
                        "actions": [
                            {
                                "confirmation_id": confirmation_id,
                                "status": "pending",
                                "required_proof_tier": "T0_identity",
                                "selected_backend_method": "software",
                                "channel_capability": {
                                    "approval_route": "host_cli",
                                    "can_carry": True,
                                    "can_reject": True,
                                },
                            }
                        ],
                        "count": 1,
                    }
                return {"actions": [], "count": 25}
            if method == "plan.steps":
                return {"steps": []}
            if method == "task.status_snapshot":
                return {
                    "tasks": [
                        {
                            "task_id": "task-visible",
                            "status": "enabled",
                            "schedule_kind": "event",
                            "pending_confirmations": [
                                {"confirmation_id": confirmation_id, "task_id": "task-visible"}
                                for confirmation_id in confirmation_ids
                            ],
                            "pending_confirmation_count": len(confirmation_ids),
                        }
                    ],
                    "count": 1,
                    "user_id": "u1",
                    "workspace_id": "ws1",
                    "scope_status": "scoped",
                }
            if method == "daemon.status":
                return {"channels": {}}
            if method == "dashboard.alerts":
                return {"alerts": []}
            if method == "dashboard.audit_explorer":
                return {"events": []}
            raise AssertionError(f"unexpected TUI call: {method}")

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
    rendered = render_plain(snapshot)
    exact_calls = [
        params
        for method, params in created[0].calls
        if method == "action.pending" and params and params.get("confirmation_id")
    ]

    assert len(exact_calls) == 20
    assert "pending_count=25 rendered=20" in rendered
    assert "confirmation=c-task-0 proof=T0_identity method=software" in rendered
    assert "confirmation=c-task-24" not in rendered


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
        def __init__(
            self,
            *,
            record: bool = False,
            theme: object | None = None,
            no_color: bool = False,
        ) -> None:
            self.record = record
            self.theme = theme
            self.no_color = no_color
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

    class _FakeTheme:
        def __init__(self, styles: dict[str, str]) -> None:
            self.styles = styles

    modules = {
        "rich.console": SimpleNamespace(Console=_FakeConsole),
        "rich.panel": SimpleNamespace(Panel=_FakePanel),
        "rich.table": SimpleNamespace(Table=_FakeTable),
        "rich.theme": SimpleNamespace(Theme=_FakeTheme),
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
                "next_run_at": "2026-06-29T12:01:00+00:00",
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
            },
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
    rendered = tui_module.render_rich(
        snapshot,
        ui_posture=theme_module.resolve_ui_posture(environ={}),
    )
    assert rendered == "rich-output"
    assert len(created_consoles) == 1
    assert created_consoles[0].theme.styles["shisa.success"]  # type: ignore[union-attr]
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
    assert "2026-06-29T12:01:00+00:00" in task_text
    assert "confirmation=c1 proof=T0_identity method=totp route=host_cli" in task_text
    assert sessions_table.styles == ["shisa.success"]
    assert pending_table.styles == ["shisa.warning"]
    assert plan_table.styles == ["shisa.warning"]
    assert tasks_table.styles == ["shisa.success"]
    assert channels_table.styles == ["shisa.success", "shisa.warning", "shisa.danger"]
    assert alerts_table.styles == ["shisa.danger", "shisa.muted"]


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
                        _operator_session_row("s1", "u1", "ws1"),
                        _operator_session_row("s2", "u2", "ws1"),
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
    monkeypatch.setattr(tui_module, "render_rich", lambda snapshot, **_kwargs: "RICH")
    monkeypatch.setattr(tui_module, "render_plain", lambda snapshot: "PLAIN")
    assert await tui_module.run_once(Path("/tmp/control.sock"), rich_output=True) == "RICH"
    assert await tui_module.run_once(Path("/tmp/control.sock"), rich_output=False) == "PLAIN"


@pytest.mark.asyncio
async def test_tui_interactive_command_routing(monkeypatch: pytest.MonkeyPatch) -> None:
    from shisad.ui import tui as tui_module

    async def _fake_fetch_snapshot(_socket_path: Path) -> TuiSnapshot:
        return TuiSnapshot()

    decisions: list[tuple[str, str, bool]] = []

    async def _fake_decision(
        _socket_path: Path,
        method: str,
        confirmation_id: str,
        *,
        proof_code: str = "",
        output_json: bool = False,
    ) -> None:
        assert not proof_code
        decisions.append((method, confirmation_id, output_json))

    inputs = iter(["r", "c conf-1 --json", "x conf-2", "unknown", "q"])
    monkeypatch.setattr(tui_module, "fetch_snapshot", _fake_fetch_snapshot)
    monkeypatch.setattr(tui_module, "_decision", _fake_decision)
    monkeypatch.setattr(tui_module, "render_plain", lambda snapshot: "snapshot")
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))
    monkeypatch.setattr("builtins.print", lambda *args, **kwargs: None)

    await tui_module.run_interactive(Path("/tmp/control.sock"))
    assert decisions == [
        ("action.confirm", "conf-1", True),
        ("action.reject", "conf-2", False),
    ]


@pytest.mark.asyncio
async def test_t3_tui_interactive_task_approval_carries_identity_and_stepup_commands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shisad.ui import tui as tui_module

    async def _fake_fetch_snapshot(_socket_path: Path) -> TuiSnapshot:
        return TuiSnapshot(
            pending_actions=[
                {
                    "confirmation_id": "c-task-identity",
                    "status": "pending",
                    "required_proof_tier": "T0_identity",
                    "selected_backend_method": "software",
                    "channel_capability": {
                        "approval_route": "host_cli",
                        "can_carry": True,
                        "can_reject": True,
                    },
                },
                {
                    "confirmation_id": "c-task-stepup",
                    "status": "pending",
                    "required_proof_tier": "T1_stepup",
                    "selected_backend_method": "totp",
                    "channel_capability": {
                        "approval_route": "host_cli",
                        "can_carry": True,
                        "can_collect_selected_method": True,
                        "requires_second_factor": True,
                        "can_reject": True,
                    },
                },
            ],
            tasks=[
                {
                    "id": "task-visible",
                    "status": "enabled",
                    "schedule_kind": "event",
                    "pending_confirmations": [
                        {"confirmation_id": "c-task-identity"},
                        {"confirmation_id": "c-task-stepup"},
                    ],
                    "pending_confirmation_count": 2,
                }
            ],
        )

    decisions: list[tuple[str, str, str]] = []

    async def _fake_decision(
        _socket_path: Path,
        method: str,
        confirmation_id: str,
        *,
        proof_code: str = "",
        totp_code: str = "",
    ) -> None:
        decisions.append((method, confirmation_id, proof_code or totp_code))

    inputs = iter(["c c-task-identity", "c c-task-stepup 654321", "x c-task-identity", "q"])
    printed: list[str] = []
    monkeypatch.setattr(tui_module, "fetch_snapshot", _fake_fetch_snapshot)
    monkeypatch.setattr(tui_module, "_decision", _fake_decision)
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))
    monkeypatch.setattr(
        "builtins.print",
        lambda *args, **kwargs: printed.append(" ".join(map(str, args))),
    )

    await tui_module.run_interactive(Path("/tmp/control.sock"))

    assert decisions == [
        ("action.confirm", "c-task-identity", ""),
        ("action.confirm", "c-task-stepup", "654321"),
        ("action.reject", "c-task-identity", ""),
    ]
    output = "\n".join(printed)
    assert "[r]efresh  [c]onfirm <id> [proof-code] [--json]" in output
    assert "waiting_on_approval confirmation=c-task-stepup" in output
    assert "approve_hint=c c-task-stepup <totp-code>" in output


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
async def test_i5a_tui_confirm_uses_semantic_output_and_explicit_json_details(
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
                            "confirmation_id": "conf-safe",
                            "decision_nonce": "nonce-safe",
                        }
                    ],
                    "count": 1,
                }
            return {
                "confirmed": False,
                "confirmation_id": "conf-safe",
                "status": "failed",
                "status_reason": "web_search_backend_unconfigured",
                "checkpoint_id": "checkpoint-safe",
                "failure": {
                    "code": "web_search_backend_unconfigured",
                    "summary": (
                        "Your approval was received, but web search couldn't run because "
                        "it isn't set up."
                    ),
                    "safe_next_action": "Set up web search, then retry your request.",
                    "approval_outcome": "accepted",
                    "execution_outcome": "failed",
                },
            }

        async def close(self) -> None:
            return

    monkeypatch.setattr(tui_module, "ControlClient", _FakeClient)

    async def _fake_sleep(_seconds: float) -> None:
        return

    monkeypatch.setattr(asyncio, "sleep", _fake_sleep)
    await tui_module._decision(
        Path("/tmp/control.sock"),
        "action.confirm",
        "conf-safe",
    )

    semantic_output = "\n".join(printed)
    assert "Your approval was received" in semantic_output
    assert "Set up web search, then retry your request." in semantic_output
    assert "checkpoint=checkpoint-safe" in semantic_output
    assert "web_search_backend_unconfigured" not in semantic_output
    assert '"status_reason"' not in semantic_output

    printed.clear()
    await tui_module._decision(
        Path("/tmp/control.sock"),
        "action.confirm",
        "conf-safe",
        output_json=True,
    )
    details_output = "\n".join(printed)
    assert '"status_reason": "web_search_backend_unconfigured"' in details_output
    assert '"checkpoint_id": "checkpoint-safe"' in details_output


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
async def test_tui_decision_confirm_can_send_recovery_code_proof(
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
                            "selected_backend_method": "recovery_code",
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
        proof_code="ABCD-EFGH",
    )
    assert created[0].calls[-1] == (
        "action.confirm",
        {
            "confirmation_id": "conf-1",
            "decision_nonce": "nonce-1",
            "principal_id": "alice",
            "approval_method": "recovery_code",
            "proof": {"recovery_code": "ABCD-EFGH"},
        },
    )


@pytest.mark.asyncio
async def test_t3_task_inline_approval_uses_workstream_a_for_identity_and_stepup(
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
                confirmation_id = str(payload.get("confirmation_id", ""))
                selected_method = "totp" if confirmation_id == "c-task-stepup" else "software"
                return {
                    "actions": [
                        {
                            "confirmation_id": confirmation_id,
                            "decision_nonce": f"nonce-{confirmation_id}",
                            "selected_backend_method": selected_method,
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
        "c-task-identity",
    )
    await tui_module._decision(
        Path("/tmp/control.sock"),
        "action.confirm",
        "c-task-stepup",
        proof_code="654321",
    )

    assert created[0].calls[-1] == (
        "action.confirm",
        {
            "confirmation_id": "c-task-identity",
            "decision_nonce": "nonce-c-task-identity",
            "principal_id": "alice",
        },
    )
    assert created[1].calls[-1] == (
        "action.confirm",
        {
            "confirmation_id": "c-task-stepup",
            "decision_nonce": "nonce-c-task-stepup",
            "principal_id": "alice",
            "approval_method": "totp",
            "proof": {"totp_code": "654321"},
        },
    )
    assert all(method != "task.confirm" for client in created for method, _payload in client.calls)


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
@pytest.mark.parametrize("method", ["action.confirm", "action.reject"])
async def test_f1_tui_decision_retries_unfiltered_nonce_lookup_after_expiry(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
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

        async def call(self, called_method: str, payload: dict[str, object]) -> dict[str, object]:
            self.calls.append((called_method, payload))
            if called_method == "action.pending":
                if payload.get("status") == "pending":
                    return {"actions": [], "count": 0}
                return {
                    "actions": [
                        {
                            "confirmation_id": "conf-expired",
                            "decision_nonce": "nonce-expired",
                            "lifecycle_state": "expired",
                        }
                    ],
                    "count": 1,
                }
            if called_method == "action.confirm":
                return {
                    "confirmed": False,
                    "confirmation_id": "conf-expired",
                    "reason": "approval_expired",
                }
            return {
                "rejected": False,
                "confirmation_id": "conf-expired",
                "reason": "approval_expired",
            }

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

    await tui_module._decision(Path("/tmp/control.sock"), method, "conf-expired")

    assert created[0].calls == [
        (
            "action.pending",
            {
                "confirmation_id": "conf-expired",
                "status": "pending",
                "limit": 1,
                "include_ui": False,
            },
        ),
        (
            "action.pending",
            {
                "confirmation_id": "conf-expired",
                "limit": 1,
                "include_ui": False,
            },
        ),
        (
            method,
            {
                "confirmation_id": "conf-expired",
                "decision_nonce": "nonce-expired",
            },
        ),
    ]
    assert not any("decision_nonce not found" in line for line in printed)
    assert any("approval_expired" in line for line in printed)


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["action.confirm", "action.reject"])
@pytest.mark.parametrize("status_reason", ["task_disabled", "max_runs_reached"])
async def test_f1_tui_decision_surfaces_cancelled_terminal_state_without_nonce(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    status_reason: str,
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

        async def call(
            self,
            called_method: str,
            payload: dict[str, object],
        ) -> dict[str, object]:
            self.calls.append((called_method, payload))
            if called_method == "action.pending":
                if payload.get("status") == "pending":
                    return {"actions": [], "count": 0}
                return {
                    "actions": [
                        {
                            "confirmation_id": "conf-cancelled",
                            "decision_nonce": "",
                            "status": "cancelled",
                            "status_reason": status_reason,
                            "lifecycle_state": "cancelled",
                        }
                    ],
                    "count": 1,
                }
            if called_method == "action.confirm":
                return {
                    "confirmed": False,
                    "confirmation_id": "conf-cancelled",
                    "reason": "already_cancelled",
                    "status": "cancelled",
                    "status_reason": status_reason,
                }
            return {
                "rejected": False,
                "confirmation_id": "conf-cancelled",
                "reason": "already_cancelled",
                "status": "cancelled",
                "status_reason": status_reason,
            }

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

    await tui_module._decision(Path("/tmp/control.sock"), method, "conf-cancelled")

    assert created[0].calls == [
        (
            "action.pending",
            {
                "confirmation_id": "conf-cancelled",
                "status": "pending",
                "limit": 1,
                "include_ui": False,
            },
        ),
        (
            "action.pending",
            {
                "confirmation_id": "conf-cancelled",
                "limit": 1,
                "include_ui": False,
            },
        ),
        (
            method,
            {
                "confirmation_id": "conf-cancelled",
                "decision_nonce": "",
            },
        ),
    ]
    assert not any("decision_nonce not found" in line for line in printed)
    assert any("already_cancelled" in line for line in printed)
    assert any(status_reason in line for line in printed)


@pytest.mark.asyncio
async def test_f1_tui_expired_stepup_confirmation_reaches_locked_daemon_preflight(
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
                if payload.get("status") == "pending":
                    return {"actions": [], "count": 0}
                return {
                    "actions": [
                        {
                            "confirmation_id": "conf-expired-stepup",
                            "decision_nonce": "nonce-expired-stepup",
                            "lifecycle_state": "expired",
                            "selected_backend_method": "totp",
                            "allowed_channel_principals": ["alice"],
                        }
                    ],
                    "count": 1,
                }
            return {
                "confirmed": False,
                "confirmation_id": "conf-expired-stepup",
                "reason": "approval_expired",
            }

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
        "conf-expired-stepup",
    )

    assert created[0].calls[-1] == (
        "action.confirm",
        {
            "confirmation_id": "conf-expired-stepup",
            "decision_nonce": "nonce-expired-stepup",
            "principal_id": "alice",
        },
    )
    assert not any("totp-code required" in line for line in printed)
    assert any("approval_expired" in line for line in printed)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("selected_method", "required_label"),
    [("totp", "totp-code"), ("recovery_code", "recovery-code")],
)
async def test_f1_tui_live_stepup_without_proof_still_prompts_locally(
    monkeypatch: pytest.MonkeyPatch,
    selected_method: str,
    required_label: str,
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
                            "confirmation_id": "conf-live-stepup",
                            "decision_nonce": "nonce-live-stepup",
                            "lifecycle_state": "pending",
                            "selected_backend_method": selected_method,
                            "allowed_channel_principals": ["alice"],
                        }
                    ],
                    "count": 1,
                }
            return {"ok": True}

        async def close(self) -> None:
            return

    created: list[_FakeClient] = []

    def _factory(socket_path: Path) -> _FakeClient:
        client = _FakeClient(socket_path)
        created.append(client)
        return client

    monkeypatch.setattr(tui_module, "ControlClient", _factory)

    await tui_module._decision(
        Path("/tmp/control.sock"),
        "action.confirm",
        "conf-live-stepup",
    )

    assert created[0].calls == [
        (
            "action.pending",
            {
                "confirmation_id": "conf-live-stepup",
                "status": "pending",
                "limit": 1,
                "include_ui": False,
            },
        )
    ]
    assert any(f"{required_label} required" in line for line in printed)


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
        (
            "action.pending",
            {
                "confirmation_id": "conf-1",
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


@pytest.mark.asyncio
async def test_f6_web_snapshot_classifies_output_publication_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from shisad.ui import web as web_module

    async def _fake_fetch_snapshot(_socket_path: Path) -> dict[str, object]:
        return {
            "sessions": [],
            "pending_actions": [],
            "alerts": [],
            "egress_events": [],
        }

    blocked_parent = tmp_path / "not-a-directory"
    blocked_parent.write_text("occupied\n", encoding="utf-8")
    monkeypatch.setattr(web_module, "fetch_web_snapshot", _fake_fetch_snapshot)

    with pytest.raises(web_module.WebSnapshotWriteError, match="FileExistsError"):
        await web_module.write_web_snapshot(
            socket_path=Path("/tmp/control.sock"),
            output_path=blocked_parent / "snapshot.html",
        )
