"""M6.T1-T4 confirmation safety and analytics coverage."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from shisad.ui.confirmation import (
    ConfirmationAnalytics,
    ConfirmationWarningGenerator,
    render_structured_confirmation,
    safe_summary,
)


def test_m6_t1_safe_summary_generator_escapes_user_content() -> None:
    summary = safe_summary(
        action="send_email",
        risk_level="medium",
        arguments={"body": "<script>alert(1)</script>\nhello", "to": "bob@example.com"},
    )
    body_row = dict(summary.parameters)["body"]
    assert "<script>" not in body_row
    assert "&lt;script&gt;" in body_row
    assert "\\n" in body_row


def test_m6_t2_structured_viewer_renders_action_correctly() -> None:
    summary = safe_summary(
        action="send_email",
        risk_level="medium",
        arguments={"to": "bob@example.com", "subject": "Meeting follow-up"},
    )
    rendered = render_structured_confirmation(
        summary,
        warnings=["First-time recipient/destination"],
    )
    assert "ACTION CONFIRMATION" in rendered
    assert "Action: send_email" in rendered
    assert "Risk Level: MEDIUM" in rendered
    assert "First-time recipient/destination" in rendered


def test_m6_t3_warning_generator_detects_first_time_recipient() -> None:
    generator = ConfirmationWarningGenerator()
    warnings = generator.generate(
        user_id="u-1",
        tool_name="send_email",
        arguments={"to": "alice@external.example"},
        taint_labels=["untrusted"],
    )
    assert "First-time recipient/destination" in warnings
    assert "External destination" in warnings
    assert "Contains tainted data" in warnings
    assert "High-value action" in warnings


def test_m6_t4_confirmation_analytics_detects_rubber_stamping() -> None:
    analytics = ConfirmationAnalytics()
    base = datetime.now(UTC) - timedelta(minutes=10)
    for index in range(12):
        created = base + timedelta(seconds=index * 30)
        decided = created + timedelta(seconds=max(1, 15 - index))
        analytics.record(
            user_id="u-1",
            decision="approve",
            created_at=created,
            decided_at=decided,
        )
    metrics = analytics.metrics(user_id="u-1", window_seconds=3600)
    assert metrics["decisions"] == 12
    assert metrics["rubber_stamping"] is True
    assert metrics["fatigue_detected"] is True
