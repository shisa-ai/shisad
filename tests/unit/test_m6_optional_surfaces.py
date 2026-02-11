"""M6 optional TUI/Web surface sanity coverage."""

from __future__ import annotations

from shisad.ui.tui import TuiSnapshot, render_plain
from shisad.ui.web import render_web_snapshot


def test_tui_plain_renderer_includes_confirmation_panel() -> None:
    snapshot = TuiSnapshot(
        sessions=[{"id": "s1", "user_id": "u1", "lockdown_level": "normal"}],
        pending_actions=[
            {
                "confirmation_id": "c1",
                "tool_name": "http_request",
                "reason": "requires_confirmation",
            }
        ],
        alerts=[{"event_type": "AnomalyReported", "acknowledged_reason": ""}],
        audit_events=[{"timestamp": "2026-02-11T00:00:00+09:00", "event_type": "ToolRejected"}],
    )
    rendered = render_plain(snapshot)
    assert "PENDING CONFIRMATIONS" in rendered
    assert "c1 tool=http_request" in rendered


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
