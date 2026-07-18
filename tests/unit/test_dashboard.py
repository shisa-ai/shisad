"""M6.2 dashboard explorer coverage."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

from shisad.core.audit import AuditLog
from shisad.core.events import (
    AnomalyReported,
    ControlPlaneNetworkObserved,
    LockdownChanged,
    ProxyRequestEvaluated,
    SessionCreated,
    SkillInstalled,
    SkillToolRegistrationDropped,
)
from shisad.core.types import SessionId, ToolName, UserId
from shisad.ui.dashboard import DashboardQuery, SecurityDashboard


async def _seed(log: AuditLog) -> None:
    now = datetime(2026, 2, 11, 12, 30, tzinfo=UTC)
    await log.persist(
        ProxyRequestEvaluated(
            session_id=SessionId("s1"),
            actor="proxy",
            timestamp=now,
            tool_name=ToolName("http_request"),
            destination_host="evil.example",
            destination_port=443,
            protocol="https",
            request_size=128,
            allowed=False,
            reason="blocked",
        )
    )
    await log.persist(
        ControlPlaneNetworkObserved(
            session_id=SessionId("s1"),
            actor="control_plane",
            timestamp=now,
            tool_name=ToolName("http_request"),
            destination_host="suspicious.example",
            destination_port=443,
            protocol="https",
            request_size=64,
            allowed=True,
            reason="flagged_anomaly",
        )
    )
    await log.persist(
        SkillInstalled(
            session_id=SessionId("s1"),
            actor="skill_manager",
            timestamp=now,
            skill_name="calendar-helper",
            version="1.2.0",
            source_repo="https://github.com/example/calendar-helper",
            manifest_hash="abc123",
            status="installed",
            allowed=True,
            signature_status="trusted",
            findings_count=0,
            artifact_state="published",
        )
    )
    await log.persist(
        SkillToolRegistrationDropped(
            actor="skill_manager",
            timestamp=now,
            skill_name="calendar-helper",
            version="1.2.0",
            tool_name=ToolName("skill.calendar-helper.lookup"),
            reason_code="skill:tool_schema_drift",
            registration_source="inventory_reload",
            expected_hash_prefix="abc123def456",
            actual_hash_prefix="fed654cba321",
        )
    )
    await log.persist(
        AnomalyReported(
            session_id=SessionId("s1"),
            actor="monitor",
            timestamp=now,
            severity="warning",
            description="suspicious tool chain",
            recommended_action="review",
        )
    )
    await log.persist(
        LockdownChanged(
            session_id=SessionId("s1"),
            actor="lockdown",
            timestamp=now,
            level="caution",
            reason="monitor_reject",
            trigger="monitor_reject",
        )
    )


def test_m6_dashboard_queries(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl")
    asyncio.run(_seed(audit))

    dashboard = SecurityDashboard(audit_log=audit, marks_path=tmp_path / "marks.json")
    explorer = dashboard.audit_explorer(
        DashboardQuery(text_search="tool chain", event_type="AnomalyReported", limit=20)
    )
    assert explorer["total"] == 1

    egress = dashboard.blocked_or_flagged_egress(limit=20)
    assert egress["total"] >= 2

    provenance = dashboard.skill_provenance(limit=20)
    assert provenance["total"] == 2

    alerts = dashboard.alerts(limit=20)
    assert alerts["total"] >= 2
    first_event_id = str(alerts["alerts"][0]["event_id"])
    dashboard.mark_false_positive(event_id=first_event_id, reason="known test event")
    refreshed = dashboard.alerts(limit=20)
    marked = next(item for item in refreshed["alerts"] if item["event_id"] == first_event_id)
    assert marked["acknowledged_reason"] == "known test event"


def test_h5_skill_provenance_returns_recent_drift_events_despite_older_noise(
    tmp_path: Path,
) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl")
    now = datetime(2026, 2, 11, 12, 30, tzinfo=UTC)

    async def _seed_noise() -> None:
        for index in range(200):
            await audit.persist(
                SessionCreated(
                    session_id=SessionId(f"noise-{index}"),
                    user_id=UserId("u-noise"),
                    actor="noise",
                    timestamp=now + timedelta(seconds=index),
                )
            )
        await audit.persist(
            SkillToolRegistrationDropped(
                actor="skill_manager",
                timestamp=now + timedelta(seconds=500),
                skill_name="calendar-helper",
                version="1.2.0",
                tool_name=ToolName("skill.calendar-helper.lookup"),
                reason_code="skill:tool_schema_drift",
                registration_source="inventory_reload",
                expected_hash_prefix="abc123def456",
                actual_hash_prefix="fed654cba321",
            )
        )

    asyncio.run(_seed_noise())

    dashboard = SecurityDashboard(audit_log=audit, marks_path=tmp_path / "marks.json")
    provenance = dashboard.skill_provenance(limit=50)

    assert provenance["total"] == 1
    assert provenance["events"][0]["event_type"] == "SkillToolRegistrationDropped"
    assert provenance["events"][0]["data"]["reason_code"] == "skill:tool_schema_drift"
