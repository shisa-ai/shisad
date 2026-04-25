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


def test_gh12_shell_exec_confirmation_preview_includes_literal_command() -> None:
    summary = safe_summary(
        action="shell.exec",
        risk_level="medium",
        arguments={
            "command": ["find", ".", "-maxdepth", "2", "-iname", "*install*log*"],
            "read_paths": ["."],
        },
    )
    rendered = render_structured_confirmation(summary)

    assert "command: find . -maxdepth 2 -iname '*install*log*'" in rendered
    assert "command: [6 items]" not in rendered


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


# SEC-LM3: boundary cases for the rubber-stamping thresholds.
#
# Production thresholds (shisad/ui/confirmation.py):
#   rubber_stamping: len(records) >= 10 and approve_rate >= 0.9
#   fatigue_detected: len(records) >= 6 and response-time slope <= -0.25
#
# The prior test pushed well past both thresholds, so threshold drift would
# have stayed invisible. These tests pin the exact boundary behavior in both
# directions so bumping either threshold breaks the test and forces a review.


def _record_decisions(
    analytics: ConfirmationAnalytics,
    *,
    user_id: str,
    decisions: list[str],
    base: datetime,
    response_seconds: float = 10.0,
) -> None:
    for index, decision in enumerate(decisions):
        created = base + timedelta(seconds=index * 30)
        decided = created + timedelta(seconds=response_seconds)
        analytics.record(
            user_id=user_id,
            decision=decision,
            created_at=created,
            decided_at=decided,
        )


def test_sec_lm3_rubber_stamping_fires_at_10_records_and_approve_rate_0_9() -> None:
    analytics = ConfirmationAnalytics()
    base = datetime.now(UTC) - timedelta(minutes=10)
    # Exactly 10 records, approve_rate = 0.9 (9 approve + 1 reject).
    _record_decisions(
        analytics,
        user_id="u-boundary",
        decisions=["approve"] * 9 + ["reject"],
        base=base,
    )

    metrics = analytics.metrics(user_id="u-boundary", window_seconds=3600)

    assert metrics["decisions"] == 10
    assert metrics["approve_rate"] == 0.9
    assert metrics["rubber_stamping"] is True


def test_sec_lm3_rubber_stamping_silent_at_9_records_even_when_all_approve() -> None:
    analytics = ConfirmationAnalytics()
    base = datetime.now(UTC) - timedelta(minutes=10)
    _record_decisions(
        analytics,
        user_id="u-too-few",
        decisions=["approve"] * 9,
        base=base,
    )

    metrics = analytics.metrics(user_id="u-too-few", window_seconds=3600)

    assert metrics["decisions"] == 9
    assert metrics["approve_rate"] == 1.0
    assert metrics["rubber_stamping"] is False


def test_sec_lm3_rubber_stamping_silent_at_10_records_with_approve_rate_just_below() -> None:
    analytics = ConfirmationAnalytics()
    base = datetime.now(UTC) - timedelta(minutes=10)
    # 10 records, approve_rate = 0.8 (8 approve + 2 reject) -> just below 0.9.
    _record_decisions(
        analytics,
        user_id="u-just-below",
        decisions=["approve"] * 8 + ["reject"] * 2,
        base=base,
    )

    metrics = analytics.metrics(user_id="u-just-below", window_seconds=3600)

    assert metrics["decisions"] == 10
    assert metrics["approve_rate"] == 0.8
    assert metrics["rubber_stamping"] is False


def test_sec_lm3_fatigue_silent_when_slope_is_flat() -> None:
    analytics = ConfirmationAnalytics()
    base = datetime.now(UTC) - timedelta(minutes=10)
    # 8 records with a flat response-time profile -> no slope -> no fatigue.
    for index in range(8):
        created = base + timedelta(seconds=index * 30)
        decided = created + timedelta(seconds=10)
        analytics.record(
            user_id="u-flat",
            decision="approve",
            created_at=created,
            decided_at=decided,
        )

    metrics = analytics.metrics(user_id="u-flat", window_seconds=3600)

    assert metrics["decisions"] == 8
    assert metrics["fatigue_detected"] is False


def test_sec_lm3_fatigue_silent_when_fewer_than_six_records() -> None:
    analytics = ConfirmationAnalytics()
    base = datetime.now(UTC) - timedelta(minutes=10)
    # 5 records with a steep negative slope still below the sample threshold.
    for index in range(5):
        created = base + timedelta(seconds=index * 30)
        decided = created + timedelta(seconds=max(1, 15 - index * 3))
        analytics.record(
            user_id="u-too-few-fatigue",
            decision="approve",
            created_at=created,
            decided_at=decided,
        )

    metrics = analytics.metrics(user_id="u-too-few-fatigue", window_seconds=3600)

    assert metrics["decisions"] == 5
    assert metrics["fatigue_detected"] is False
