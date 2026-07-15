"""F3 authoritative state durability and corruption contracts."""

from __future__ import annotations

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
from shisad.core.types import Capability, UserId
from shisad.scheduler.manager import SchedulerManager
from shisad.scheduler.schema import Schedule
from shisad.ui.dashboard import SecurityDashboard


def _create_scheduler_task(scheduler: SchedulerManager, *, name: str = "digest") -> str:
    task = scheduler.create_task(
        name=name,
        goal="summarize updates",
        schedule=Schedule.from_event("message.received"),
        capability_snapshot={Capability.MEMORY_READ},
        policy_snapshot_ref="policy-v1",
        created_by=UserId("alice"),
    )
    return task.id


@pytest.mark.parametrize(
    ("fault_stage", "published_disabled"),
    [
        (AtomicWriteStage.TEMP_OPEN, False),
        (AtomicWriteStage.WRITE, False),
        (AtomicWriteStage.FILE_FSYNC, False),
        (AtomicWriteStage.REPLACE, False),
        (AtomicWriteStage.PARENT_FSYNC, True),
    ],
)
def test_authoritative_snapshot_fault_is_old_or_new_never_silent_empty(
    tmp_path: Path,
    fault_stage: AtomicWriteStage,
    published_disabled: bool,
) -> None:
    storage = tmp_path / "scheduler"
    scheduler = SchedulerManager(storage_dir=storage)
    task_id = _create_scheduler_task(scheduler)

    def _inject(stage: AtomicWriteStage) -> None:
        if stage == fault_stage:
            raise OSError(f"fault:{stage.value}")

    scheduler._state_fault_injector = _inject
    with pytest.raises(AtomicWriteError) as raised:
        scheduler.disable_task(task_id)

    assert raised.value.stage == fault_stage
    assert scheduler.state_degraded is (fault_stage == AtomicWriteStage.PARENT_FSYNC)
    live = scheduler.get_task(task_id)
    assert live is not None
    assert live.enabled is (not published_disabled)

    restarted = SchedulerManager(storage_dir=storage)
    durable = restarted.get_task(task_id)
    assert durable is not None
    assert durable.enabled is (not published_disabled)
    assert restarted.state_load_result("tasks").status == StateLoadStatus.OK


def test_scheduler_corrupt_snapshot_is_retained_and_blocks_empty_authority(
    tmp_path: Path,
) -> None:
    storage = tmp_path / "scheduler"
    storage.mkdir(parents=True)
    tasks_path = storage / "tasks.json"
    corrupt_bytes = b'{"version":1,"payload":'
    tasks_path.write_bytes(corrupt_bytes)

    scheduler = SchedulerManager(storage_dir=storage)

    assert scheduler.state_load_result("tasks").status == StateLoadStatus.CORRUPT
    assert scheduler.state_degraded is True
    with pytest.raises(StatePersistenceDegradedError, match=r"scheduler\.tasks"):
        scheduler.list_tasks()
    with pytest.raises(StatePersistenceDegradedError, match=r"scheduler\.tasks"):
        _create_scheduler_task(scheduler, name="must-not-overwrite-corruption")
    assert tasks_path.read_bytes() == corrupt_bytes


def test_scheduler_versioned_snapshot_detects_checksum_tampering(tmp_path: Path) -> None:
    storage = tmp_path / "scheduler"
    scheduler = SchedulerManager(storage_dir=storage)
    _create_scheduler_task(scheduler)
    tasks_path = storage / "tasks.json"
    envelope = json.loads(tasks_path.read_text(encoding="utf-8"))
    assert envelope["version"] == 1
    assert isinstance(envelope["checksum"], str)
    envelope["payload"][0]["name"] = "tampered-without-checksum"
    tasks_path.write_text(json.dumps(envelope), encoding="utf-8")
    tampered_bytes = tasks_path.read_bytes()

    restarted = SchedulerManager(storage_dir=storage)

    result = restarted.state_load_result("tasks")
    assert result.status == StateLoadStatus.CORRUPT
    assert result.reason == "checksum_mismatch"
    assert tasks_path.read_bytes() == tampered_bytes
    with pytest.raises(StatePersistenceDegradedError, match=r"scheduler\.tasks"):
        restarted.get_task("missing")


def test_scheduler_unsupported_schema_is_typed_and_retained(tmp_path: Path) -> None:
    storage = tmp_path / "scheduler"
    storage.mkdir(parents=True)
    tasks_path = storage / "tasks.json"
    unsupported_bytes = json.dumps(
        {"version": 99, "checksum": "unused", "payload": []}
    ).encode()
    tasks_path.write_bytes(unsupported_bytes)

    scheduler = SchedulerManager(storage_dir=storage)

    result = scheduler.state_load_result("tasks")
    assert result.status == StateLoadStatus.UNSUPPORTED_SCHEMA
    assert result.schema_version == 99
    assert scheduler.state_degraded is True
    assert tasks_path.read_bytes() == unsupported_bytes


def test_checksum_valid_semantically_invalid_task_row_is_corrupt(tmp_path: Path) -> None:
    storage = tmp_path / "scheduler"
    scheduler = SchedulerManager(storage_dir=storage)
    _create_scheduler_task(scheduler)
    tasks_path = storage / "tasks.json"
    envelope = json.loads(tasks_path.read_text(encoding="utf-8"))
    payload = envelope["payload"]
    payload[0]["_confirmation_outcome_dedup"] = {"": True}
    invalid_bytes = encode_versioned_json_snapshot(payload)
    tasks_path.write_bytes(invalid_bytes)

    restarted = SchedulerManager(storage_dir=storage)

    result = restarted.state_load_result("tasks")
    assert result.status == StateLoadStatus.CORRUPT
    assert result.reason == "invalid_task_outcome_dedup"
    assert tasks_path.read_bytes() == invalid_bytes


def test_corrupt_pending_confirmation_snapshot_never_becomes_fresh(
    tmp_path: Path,
) -> None:
    storage = tmp_path / "scheduler"
    scheduler = SchedulerManager(storage_dir=storage)
    task_id = _create_scheduler_task(scheduler)
    scheduler.queue_confirmation(
        task_id,
        {"confirmation_id": "confirm-1", "status": "pending"},
    )
    pending_path = storage / "pending_confirmations.json"
    corrupt_bytes = b"\xff"
    pending_path.write_bytes(corrupt_bytes)

    restarted = SchedulerManager(storage_dir=storage)

    assert (
        restarted.state_load_result("pending_confirmations").status
        == StateLoadStatus.CORRUPT
    )
    with pytest.raises(
        StatePersistenceDegradedError,
        match=r"scheduler\.pending_confirmations",
    ):
        restarted.pending_confirmations(task_id)
    with pytest.raises(
        StatePersistenceDegradedError,
        match=r"scheduler\.pending_confirmations",
    ):
        restarted.queue_confirmation(
            task_id,
            {"confirmation_id": "confirm-2", "status": "pending"},
        )
    assert pending_path.read_bytes() == corrupt_bytes


@pytest.mark.parametrize(
    ("fault_stage", "published_second_confirmation"),
    [
        (AtomicWriteStage.FILE_FSYNC, False),
        (AtomicWriteStage.PARENT_FSYNC, True),
    ],
)
def test_pending_confirmation_fault_is_old_or_new_and_never_fresh(
    tmp_path: Path,
    fault_stage: AtomicWriteStage,
    published_second_confirmation: bool,
) -> None:
    storage = tmp_path / "scheduler"
    scheduler = SchedulerManager(storage_dir=storage)
    task_id = _create_scheduler_task(scheduler)
    scheduler.queue_confirmation(
        task_id,
        {"confirmation_id": "confirm-1", "status": "pending"},
    )

    def _inject(stage: AtomicWriteStage) -> None:
        if stage == fault_stage:
            raise OSError(f"fault:{stage.value}")

    scheduler._state_fault_injector = _inject
    with pytest.raises(AtomicWriteError):
        scheduler.queue_confirmation(
            task_id,
            {"confirmation_id": "confirm-2", "status": "pending"},
        )

    live_ids = {
        str(row.get("confirmation_id", ""))
        for row in scheduler._pending_confirmations[task_id]
    }
    assert ("confirm-2" in live_ids) is published_second_confirmation

    restarted = SchedulerManager(storage_dir=storage)
    durable_ids = {
        str(row.get("confirmation_id", ""))
        for row in restarted.pending_confirmations(task_id)
    }
    assert ("confirm-2" in durable_ids) is published_second_confirmation
    assert "confirm-1" in durable_ids


def test_pending_confirmation_serialization_failure_restores_durable_view(
    tmp_path: Path,
) -> None:
    storage = tmp_path / "scheduler"
    scheduler = SchedulerManager(storage_dir=storage)
    task_id = _create_scheduler_task(scheduler)
    scheduler.queue_confirmation(
        task_id,
        {"confirmation_id": "confirm-1", "status": "pending"},
    )
    pending_path = storage / "pending_confirmations.json"
    durable_bytes = pending_path.read_bytes()

    with pytest.raises(TypeError):
        scheduler.queue_confirmation(
            task_id,
            {
                "confirmation_id": "confirm-unserializable",
                "status": "pending",
                "value": object(),
            },
        )

    live_ids = {
        str(row.get("confirmation_id", ""))
        for row in scheduler._pending_confirmations[task_id]
    }
    assert live_ids == {"confirm-1"}
    assert pending_path.read_bytes() == durable_bytes


@pytest.mark.parametrize(
    "fault_stage",
    [
        AtomicWriteStage.TEMP_OPEN,
        AtomicWriteStage.WRITE,
        AtomicWriteStage.FILE_FSYNC,
        AtomicWriteStage.REPLACE,
        AtomicWriteStage.PARENT_FSYNC,
    ],
)
@pytest.mark.parametrize("success", [True, False])
def test_confirmation_outcome_task_fault_retries_exactly_once(
    tmp_path: Path,
    fault_stage: AtomicWriteStage,
    success: bool,
) -> None:
    storage = tmp_path / "scheduler"
    scheduler = SchedulerManager(storage_dir=storage)
    task_id = _create_scheduler_task(scheduler)
    scheduler.queue_confirmation(
        task_id,
        {"confirmation_id": "confirm-outcome", "status": "pending"},
    )

    def _inject(stage: AtomicWriteStage) -> None:
        if stage == fault_stage:
            raise OSError(f"fault:{stage.value}")

    scheduler._state_fault_injector = _inject
    with pytest.raises(AtomicWriteError):
        scheduler.record_confirmation_outcome(
            task_id,
            confirmation_id="confirm-outcome",
            success=success,
        )

    if fault_stage == AtomicWriteStage.PARENT_FSYNC:
        recovered = SchedulerManager(storage_dir=storage)
    else:
        assert (
            scheduler.confirmation_outcome(
                task_id,
                confirmation_id="confirm-outcome",
            )
            is None
        )
        pre_retry = scheduler.get_task(task_id)
        assert pre_retry is not None
        assert pre_retry.success_count == 0
        assert pre_retry.failure_count == 0
        scheduler._state_fault_injector = None
        recovered = scheduler

    assert recovered.record_confirmation_outcome(
        task_id,
        confirmation_id="confirm-outcome",
        success=success,
    )
    task = recovered.get_task(task_id)
    assert task is not None
    assert task.success_count == int(success)
    assert task.failure_count == int(not success)
    assert (
        recovered.confirmation_outcome(
            task_id,
            confirmation_id="confirm-outcome",
        )
        is success
    )

    restarted = SchedulerManager(storage_dir=storage)
    durable = restarted.get_task(task_id)
    assert durable is not None
    assert durable.success_count == int(success)
    assert durable.failure_count == int(not success)
    assert (
        restarted.confirmation_outcome(
            task_id,
            confirmation_id="confirm-outcome",
        )
        is success
    )


def test_expiry_task_fault_restores_pending_transition_for_retry(tmp_path: Path) -> None:
    storage = tmp_path / "scheduler"
    scheduler = SchedulerManager(storage_dir=storage)
    task_id = _create_scheduler_task(scheduler)
    scheduler.queue_confirmation(
        task_id,
        {
            "confirmation_id": "confirm-expired",
            "status": "pending",
            "expires_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
        },
    )

    def _fail_task_fsync(stage: AtomicWriteStage) -> None:
        if stage == AtomicWriteStage.FILE_FSYNC:
            raise OSError("fault:file_fsync")

    scheduler._state_fault_injector = _fail_task_fsync
    with pytest.raises(AtomicWriteError):
        scheduler.pending_confirmations(task_id)

    scheduler._state_fault_injector = None
    assert scheduler.pending_confirmations(task_id) == []
    task = scheduler.get_task(task_id)
    assert task is not None
    assert task.success_count == 0
    assert task.failure_count == 1
    assert (
        scheduler.confirmation_outcome(
            task_id,
            confirmation_id="confirm-expired",
        )
        is False
    )

    restarted = SchedulerManager(storage_dir=storage)
    durable = restarted.get_task(task_id)
    assert durable is not None
    assert durable.success_count == 0
    assert durable.failure_count == 1
    assert (
        restarted.confirmation_outcome(
            task_id,
            confirmation_id="confirm-expired",
        )
        is False
    )


def test_auxiliary_state_corruption_is_visible_and_retained(tmp_path: Path) -> None:
    marks_path = tmp_path / "dashboard" / "false_positives.json"
    marks_path.parent.mkdir(parents=True)
    corrupt_bytes = b'{"version":1,"checksum":"bad","payload":{"evt":"known"}}\n'
    marks_path.write_bytes(corrupt_bytes)

    dashboard = SecurityDashboard(
        audit_log=AuditLog(tmp_path / "audit.jsonl"),
        marks_path=marks_path,
    )

    assert dashboard.state_load_result.status == StateLoadStatus.CORRUPT
    assert dashboard.state_status()["status"] == "degraded"
    with pytest.raises(StatePersistenceDegradedError, match="dashboard_marks"):
        dashboard.mark_false_positive(event_id="evt-2", reason="reviewed")
    assert marks_path.read_bytes() == corrupt_bytes
