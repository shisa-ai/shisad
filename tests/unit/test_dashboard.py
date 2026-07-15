"""M6.2 dashboard explorer coverage."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from shisad.core.atomic_state import (
    AtomicWriteError,
    AtomicWriteStage,
    StateLoadStatus,
    StatePersistenceDegradedError,
    encode_versioned_json_snapshot,
)
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

    restarted = SecurityDashboard(audit_log=audit, marks_path=tmp_path / "marks.json")
    restarted_mark = next(
        item for item in restarted.alerts(limit=20)["alerts"] if item["event_id"] == first_event_id
    )
    assert restarted_mark["acknowledged_reason"] == "known test event"
    assert restarted.state_load_result.status == StateLoadStatus.OK


def test_f3_dashboard_corrupt_marks_are_retained_and_block_mutation(tmp_path: Path) -> None:
    path = tmp_path / "dashboard" / "false_positives.json"
    path.parent.mkdir(parents=True)
    corrupt_bytes = b'{"version":1,"payload":'
    path.write_bytes(corrupt_bytes)

    dashboard = SecurityDashboard(audit_log=AuditLog(tmp_path / "audit.jsonl"), marks_path=path)

    assert dashboard.state_load_result.status == StateLoadStatus.CORRUPT
    assert dashboard.state_degraded is True
    assert dashboard.state_status()["problems"] == ["dashboard_marks_corrupt"]
    with pytest.raises(StatePersistenceDegradedError, match="dashboard_marks"):
        dashboard.mark_false_positive(event_id="evt-1", reason="known")
    assert path.read_bytes() == corrupt_bytes


def test_f3_dashboard_future_marks_are_typed_and_retained(tmp_path: Path) -> None:
    path = tmp_path / "dashboard" / "false_positives.json"
    path.parent.mkdir(parents=True)
    future_bytes = encode_versioned_json_snapshot({"evt-1": "known"}, version=99)
    path.write_bytes(future_bytes)

    dashboard = SecurityDashboard(audit_log=AuditLog(tmp_path / "audit.jsonl"), marks_path=path)

    assert dashboard.state_load_result.status == StateLoadStatus.UNSUPPORTED_SCHEMA
    assert dashboard.state_load_result.schema_version == 99
    assert dashboard.state_degraded is True
    assert path.read_bytes() == future_bytes


def test_f3_dashboard_marks_symlink_is_rejected_without_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "dashboard" / "false_positives.json"
    path.parent.mkdir(parents=True)
    outside = tmp_path / "outside.json"
    outside.write_text('{"evt-1":"outside"}', encoding="utf-8")
    path.symlink_to(outside)

    dashboard = SecurityDashboard(audit_log=AuditLog(tmp_path / "audit.jsonl"), marks_path=path)

    assert dashboard.state_load_result.status == StateLoadStatus.CORRUPT
    assert dashboard.state_load_result.reason == "invalid_marks_target"
    with pytest.raises(StatePersistenceDegradedError, match="dashboard_marks"):
        dashboard.mark_false_positive(event_id="evt-2", reason="reviewed")
    assert outside.read_text(encoding="utf-8") == '{"evt-1":"outside"}'


def test_f3_dashboard_legacy_marks_migrate_on_next_mutation(tmp_path: Path) -> None:
    path = tmp_path / "dashboard" / "false_positives.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"evt-1": "legacy"}), encoding="utf-8")

    dashboard = SecurityDashboard(audit_log=AuditLog(tmp_path / "audit.jsonl"), marks_path=path)

    assert dashboard.state_load_result.status == StateLoadStatus.OK
    assert dashboard.state_load_result.legacy is True
    dashboard.mark_false_positive(event_id="evt-2", reason="reviewed")
    envelope = json.loads(path.read_text(encoding="utf-8"))
    assert envelope["version"] == 1
    assert envelope["payload"] == {"evt-1": "legacy", "evt-2": "reviewed"}


@pytest.mark.parametrize(
    ("fault_stage", "durable_new_mark"),
    [
        (AtomicWriteStage.TEMP_OPEN, False),
        (AtomicWriteStage.WRITE, False),
        (AtomicWriteStage.FILE_FSYNC, False),
        (AtomicWriteStage.REPLACE, False),
        (AtomicWriteStage.PARENT_FSYNC, True),
    ],
)
def test_f3_dashboard_mark_fault_is_old_or_new_and_retains_live_view(
    tmp_path: Path,
    fault_stage: AtomicWriteStage,
    durable_new_mark: bool,
) -> None:
    path = tmp_path / "dashboard" / "false_positives.json"
    dashboard = SecurityDashboard(audit_log=AuditLog(tmp_path / "audit.jsonl"), marks_path=path)
    dashboard.mark_false_positive(event_id="evt-old", reason="old")

    def _inject(stage: AtomicWriteStage) -> None:
        if stage == fault_stage:
            raise OSError(f"fault:{stage.value}")

    dashboard._state_fault_injector = _inject
    with pytest.raises(AtomicWriteError):
        dashboard.mark_false_positive(event_id="evt-new", reason="new")

    assert "evt-new" not in dashboard._marks
    assert dashboard.state_degraded is (fault_stage == AtomicWriteStage.PARENT_FSYNC)
    restarted = SecurityDashboard(audit_log=AuditLog(tmp_path / "audit.jsonl"), marks_path=path)
    assert ("evt-new" in restarted._marks) is durable_new_mark


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
