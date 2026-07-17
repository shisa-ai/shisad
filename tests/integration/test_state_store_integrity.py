"""F3 authoritative state durability and corruption contracts."""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import shisad.core.atomic_state as atomic_state
from shisad.core.atomic_state import (
    AtomicWriteError,
    AtomicWriteStage,
    StateLoadStatus,
    StatePersistenceDegradedError,
    encode_versioned_json_snapshot,
)
from shisad.core.audit import AuditLog
from shisad.core.types import Capability, UserId, WorkspaceId
from shisad.scheduler.manager import SchedulerManager
from shisad.scheduler.schema import Schedule
from shisad.security.control_plane.engine import ControlPlaneEngine
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


def _empty_scheduler_snapshot(authority: str) -> bytes:
    if authority == "tasks":
        return encode_versioned_json_snapshot([])
    if authority == "pending_confirmations":
        return encode_versioned_json_snapshot({})
    raise AssertionError(f"unknown scheduler authority: {authority}")


@pytest.mark.parametrize(
    ("authority", "file_name"),
    [
        ("tasks", "tasks.json"),
        ("pending_confirmations", "pending_confirmations.json"),
    ],
)
@pytest.mark.parametrize("link_shape", ["existing", "dangling"])
def test_scheduler_snapshot_reopen_rejects_symlink_final_inode(
    tmp_path: Path,
    authority: str,
    file_name: str,
    link_shape: str,
) -> None:
    storage = tmp_path / "scheduler"
    storage.mkdir(mode=0o700)
    snapshot_path = storage / file_name
    outside_path = tmp_path / f"outside-{file_name}"
    outside_bytes = _empty_scheduler_snapshot(authority)
    if link_shape == "existing":
        outside_path.write_bytes(outside_bytes)
        outside_path.chmod(0o600)
    snapshot_path.symlink_to(outside_path)

    scheduler = SchedulerManager(storage_dir=storage)

    result = scheduler.state_load_result(authority)
    assert result.status == StateLoadStatus.CORRUPT
    assert result.reason == "read_error"
    assert snapshot_path.is_symlink()
    if link_shape == "existing":
        assert outside_path.read_bytes() == outside_bytes
    else:
        assert not outside_path.exists()


@pytest.mark.parametrize(
    ("authority", "file_name"),
    [
        ("tasks", "tasks.json"),
        ("pending_confirmations", "pending_confirmations.json"),
    ],
)
def test_scheduler_snapshot_reopen_rejects_permissive_mode(
    tmp_path: Path,
    authority: str,
    file_name: str,
) -> None:
    storage = tmp_path / "scheduler"
    storage.mkdir(mode=0o700)
    snapshot_path = storage / file_name
    snapshot_bytes = _empty_scheduler_snapshot(authority)
    snapshot_path.write_bytes(snapshot_bytes)
    snapshot_path.chmod(0o644)

    scheduler = SchedulerManager(storage_dir=storage)

    result = scheduler.state_load_result(authority)
    assert result.status == StateLoadStatus.CORRUPT
    assert result.reason == "read_error"
    assert stat.S_IMODE(snapshot_path.stat().st_mode) == 0o644
    assert snapshot_path.read_bytes() == snapshot_bytes


@pytest.mark.parametrize(
    ("authority", "file_name"),
    [
        ("tasks", "tasks.json"),
        ("pending_confirmations", "pending_confirmations.json"),
    ],
)
def test_scheduler_snapshot_reopen_rejects_foreign_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authority: str,
    file_name: str,
) -> None:
    storage = tmp_path / "scheduler"
    storage.mkdir(mode=0o700)
    snapshot_path = storage / file_name
    snapshot_bytes = _empty_scheduler_snapshot(authority)
    snapshot_path.write_bytes(snapshot_bytes)
    snapshot_path.chmod(0o600)
    original_fstat = os.fstat

    def _foreign_regular_fstat(fd: int) -> os.stat_result:
        result = original_fstat(fd)
        if not stat.S_ISREG(result.st_mode):
            return result
        values = list(result)
        values[4] = result.st_uid + 1
        return os.stat_result(values)

    monkeypatch.setattr(atomic_state.os, "fstat", _foreign_regular_fstat)

    scheduler = SchedulerManager(storage_dir=storage)

    result = scheduler.state_load_result(authority)
    assert result.status == StateLoadStatus.CORRUPT
    assert result.reason == "read_error"
    assert snapshot_path.read_bytes() == snapshot_bytes


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
    tasks_path.chmod(0o600)

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


@pytest.mark.parametrize(
    "binding",
    [
        "capability",
        "policy",
        "owner",
        "workspace",
        "provenance",
        "credential",
        "resource_ids",
        "resource_prefixes",
        "resource_authority",
        "untrusted_payload_action",
    ],
)
def test_f3_scheduler_rejects_retained_task_envelope_binding_mismatch(
    tmp_path: Path,
    binding: str,
) -> None:
    storage = tmp_path / "scheduler"
    scheduler = SchedulerManager(storage_dir=storage)
    scheduler.create_task(
        name="bound-task",
        goal="send the retained report",
        schedule=Schedule.from_event("report.ready"),
        capability_snapshot={Capability.MESSAGE_SEND},
        policy_snapshot_ref="policy-v1",
        created_by=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
        credential_refs=["credential:mail"],
        resource_scope_ids=["thread:ops"],
        resource_scope_prefixes=["artifact:report:"],
    )
    tasks_path = storage / "tasks.json"
    snapshot = json.loads(tasks_path.read_text(encoding="utf-8"))
    task_row = snapshot["payload"][0]
    if binding == "capability":
        task_row["capability_snapshot"] = []
    elif binding == "policy":
        task_row["policy_snapshot_ref"] = "policy-other"
    elif binding == "owner":
        task_row["created_by"] = "mallory"
    elif binding == "workspace":
        task_row["workspace_id"] = "ws-other"
    elif binding == "provenance":
        task_row["task_envelope"]["orchestrator_provenance"] = "scheduler:mallory:ws1"
    elif binding == "credential":
        task_row["credential_refs"] = ["credential:other"]
    elif binding == "resource_ids":
        task_row["resource_scope_ids"] = ["thread:other"]
    elif binding == "resource_prefixes":
        task_row["resource_scope_prefixes"] = ["artifact:other:"]
    elif binding == "resource_authority":
        task_row["resource_scope_authority"] = "command_clean"
    else:
        task_row["untrusted_payload_action"] = "reject"
    mismatched_bytes = encode_versioned_json_snapshot(snapshot["payload"])
    tasks_path.write_bytes(mismatched_bytes)

    restarted = SchedulerManager(storage_dir=storage)

    result = restarted.state_load_result("tasks")
    assert result.status == StateLoadStatus.CORRUPT
    assert result.reason == f"task_envelope_{binding}_mismatch"
    assert restarted._tasks == {}
    with pytest.raises(StatePersistenceDegradedError, match=r"scheduler\.tasks"):
        restarted.list_tasks()
    assert tasks_path.read_bytes() == mismatched_bytes


def test_scheduler_unsupported_schema_is_typed_and_retained(tmp_path: Path) -> None:
    storage = tmp_path / "scheduler"
    storage.mkdir(parents=True)
    tasks_path = storage / "tasks.json"
    unsupported_bytes = json.dumps({"version": 99, "checksum": "unused", "payload": []}).encode()
    tasks_path.write_bytes(unsupported_bytes)
    tasks_path.chmod(0o600)

    scheduler = SchedulerManager(storage_dir=storage)

    result = scheduler.state_load_result("tasks")
    assert result.status == StateLoadStatus.UNSUPPORTED_SCHEMA
    assert result.schema_version == 99
    assert scheduler.state_degraded is True
    assert tasks_path.read_bytes() == unsupported_bytes


@pytest.mark.parametrize("snapshot_kind", ["current", "legacy"])
@pytest.mark.parametrize(
    "mutation",
    [
        "task_extra",
        "task_internal_alias",
        "envelope_extra",
        "schedule_extra",
        "created_at",
        "last_triggered_at",
    ],
)
def test_scheduler_rejects_unknown_or_naive_retained_task_fields(
    tmp_path: Path,
    snapshot_kind: str,
    mutation: str,
) -> None:
    storage = tmp_path / "scheduler"
    scheduler = SchedulerManager(storage_dir=storage)
    _create_scheduler_task(scheduler)
    tasks_path = storage / "tasks.json"
    payload = json.loads(tasks_path.read_text(encoding="utf-8"))["payload"]
    row = payload[0]
    if mutation == "task_extra":
        row["unexpected_authority"] = "ignored"
    elif mutation == "task_internal_alias":
        row["confirmation_outcome_dedup"] = {"confirmation-1": True}
    elif mutation == "envelope_extra":
        row["task_envelope"]["unexpected_authority"] = "ignored"
    elif mutation == "schedule_extra":
        row["schedule"]["unexpected_authority"] = "ignored"
    else:
        row[mutation] = datetime.now(UTC).replace(tzinfo=None).isoformat()
    retained = (
        encode_versioned_json_snapshot(payload)
        if snapshot_kind == "current"
        else json.dumps(payload, sort_keys=True).encode()
    )
    tasks_path.write_bytes(retained)

    restarted = SchedulerManager(storage_dir=storage)

    result = restarted.state_load_result("tasks")
    assert result.status == StateLoadStatus.CORRUPT
    assert result.reason == "invalid_task_row"
    assert restarted._tasks == {}
    assert tasks_path.read_bytes() == retained


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


@pytest.mark.parametrize(
    "schedule",
    [
        {"kind": "cron", "expression": "* * *", "event_type": None, "event_filter": {}},
        {
            "kind": "interval",
            "expression": "not-an-interval",
            "event_type": None,
            "event_filter": {},
        },
        {"kind": "event", "expression": "", "event_type": "", "event_filter": {}},
    ],
)
def test_checksum_valid_task_with_invalid_schedule_is_corrupt(
    tmp_path: Path,
    schedule: dict[str, object],
) -> None:
    storage = tmp_path / "scheduler"
    scheduler = SchedulerManager(storage_dir=storage)
    _create_scheduler_task(scheduler)
    tasks_path = storage / "tasks.json"
    envelope = json.loads(tasks_path.read_text(encoding="utf-8"))
    payload = envelope["payload"]
    payload[0]["schedule"] = schedule
    invalid_bytes = encode_versioned_json_snapshot(payload)
    tasks_path.write_bytes(invalid_bytes)

    restarted = SchedulerManager(storage_dir=storage)

    result = restarted.state_load_result("tasks")
    assert result.status == StateLoadStatus.CORRUPT
    assert result.reason == "invalid_task_schedule"
    assert tasks_path.read_bytes() == invalid_bytes


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("trigger_count", -1),
        ("success_count", "1"),
        ("failure_count", True),
        ("max_runs", -1),
    ],
)
def test_checksum_valid_task_with_invalid_run_counter_is_corrupt(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    storage = tmp_path / "scheduler"
    scheduler = SchedulerManager(storage_dir=storage)
    _create_scheduler_task(scheduler)
    tasks_path = storage / "tasks.json"
    envelope = json.loads(tasks_path.read_text(encoding="utf-8"))
    payload = envelope["payload"]
    payload[0][field] = value
    invalid_bytes = encode_versioned_json_snapshot(payload)
    tasks_path.write_bytes(invalid_bytes)

    restarted = SchedulerManager(storage_dir=storage)

    result = restarted.state_load_result("tasks")
    assert result.status == StateLoadStatus.CORRUPT
    assert result.reason == "invalid_task_counters"
    assert tasks_path.read_bytes() == invalid_bytes


@pytest.mark.parametrize("snapshot_kind", ["current", "legacy"])
def test_retained_task_requires_native_enabled_boolean(
    tmp_path: Path,
    snapshot_kind: str,
) -> None:
    storage = tmp_path / "scheduler"
    scheduler = SchedulerManager(storage_dir=storage)
    _create_scheduler_task(scheduler)
    tasks_path = storage / "tasks.json"
    envelope = json.loads(tasks_path.read_text(encoding="utf-8"))
    payload = envelope["payload"]
    payload[0]["enabled"] = "yes"
    invalid_bytes = (
        encode_versioned_json_snapshot(payload)
        if snapshot_kind == "current"
        else json.dumps(payload).encode("utf-8")
    )
    tasks_path.write_bytes(invalid_bytes)

    restarted = SchedulerManager(storage_dir=storage)

    result = restarted.state_load_result("tasks")
    assert result.status == StateLoadStatus.CORRUPT
    assert result.reason == "invalid_task_enabled"
    assert restarted.state_degraded is True
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

    assert restarted.state_load_result("pending_confirmations").status == StateLoadStatus.CORRUPT
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
    ("case", "reason"),
    [
        ("empty_confirmation_id", "invalid_pending_row"),
        ("mismatched_task_id", "invalid_pending_row"),
        ("missing_identity", "invalid_pending_row"),
        ("mismatched_identity", "invalid_pending_row"),
        ("string_recorded", "invalid_pending_row"),
        ("string_success", "invalid_pending_row"),
        ("unknown_task", "unknown_pending_task"),
        ("duplicate_confirmation", "duplicate_pending_confirmation"),
    ],
)
def test_pending_confirmation_semantic_corruption_is_retained(
    tmp_path: Path,
    case: str,
    reason: str,
) -> None:
    storage = tmp_path / "scheduler"
    scheduler = SchedulerManager(storage_dir=storage)
    task_id = _create_scheduler_task(scheduler)
    scheduler.queue_confirmation(
        task_id,
        {
            "confirmation_id": "confirm-1",
            "task_id": task_id,
            "status": "pending",
            "run_outcome_recorded": False,
            "run_outcome_success": False,
        },
    )
    pending_path = storage / "pending_confirmations.json"
    envelope = json.loads(pending_path.read_text(encoding="utf-8"))
    payload = envelope["payload"]
    row = payload[task_id][0]
    if case == "empty_confirmation_id":
        row["confirmation_id"] = ""
    elif case == "mismatched_task_id":
        row["task_id"] = "other-task"
    elif case == "missing_identity":
        row.pop("identity")
    elif case == "mismatched_identity":
        row["identity"]["confirmation_id"] = "other-confirmation"
    elif case == "string_recorded":
        row["run_outcome_recorded"] = "false"
    elif case == "string_success":
        row["run_outcome_success"] = "false"
    elif case == "unknown_task":
        payload["unknown-task"] = payload.pop(task_id)
    else:
        assert case == "duplicate_confirmation"
        payload[task_id].append(dict(row))
    invalid_bytes = encode_versioned_json_snapshot(payload)
    pending_path.write_bytes(invalid_bytes)

    restarted = SchedulerManager(storage_dir=storage)

    result = restarted.state_load_result("pending_confirmations")
    assert result.status == StateLoadStatus.CORRUPT
    assert result.reason == reason
    assert pending_path.read_bytes() == invalid_bytes


@pytest.mark.parametrize("task_tombstone", [None, False])
def test_pending_confirmation_recorded_outcome_requires_matching_task_tombstone(
    tmp_path: Path,
    task_tombstone: bool | None,
) -> None:
    storage = tmp_path / "scheduler"
    scheduler = SchedulerManager(storage_dir=storage)
    task_id = _create_scheduler_task(scheduler)
    scheduler.queue_confirmation(
        task_id,
        {
            "confirmation_id": "confirm-recorded",
            "task_id": task_id,
            "status": "failed",
            "run_outcome_recorded": False,
            "run_outcome_success": False,
        },
    )
    if task_tombstone is not None:
        tasks_path = storage / "tasks.json"
        tasks_envelope = json.loads(tasks_path.read_text(encoding="utf-8"))
        tasks_payload = tasks_envelope["payload"]
        tasks_payload[0]["_confirmation_outcome_dedup"] = {"confirm-recorded": task_tombstone}
        tasks_path.write_bytes(encode_versioned_json_snapshot(tasks_payload))
    pending_path = storage / "pending_confirmations.json"
    pending_envelope = json.loads(pending_path.read_text(encoding="utf-8"))
    pending_payload = pending_envelope["payload"]
    pending_row = pending_payload[task_id][0]
    pending_row["run_outcome_recorded"] = True
    pending_row["run_outcome_success"] = True
    invalid_bytes = encode_versioned_json_snapshot(pending_payload)
    pending_path.write_bytes(invalid_bytes)

    restarted = SchedulerManager(storage_dir=storage)

    assert restarted.state_load_result("tasks").status == StateLoadStatus.OK
    pending_result = restarted.state_load_result("pending_confirmations")
    assert pending_result.status == StateLoadStatus.CORRUPT
    assert pending_result.reason == "invalid_pending_outcome_state"
    assert pending_path.read_bytes() == invalid_bytes


def test_legacy_pending_confirmation_rejects_string_boolean(tmp_path: Path) -> None:
    storage = tmp_path / "scheduler"
    scheduler = SchedulerManager(storage_dir=storage)
    task_id = _create_scheduler_task(scheduler)
    pending_path = storage / "pending_confirmations.json"
    legacy_payload = {
        task_id: [
            {
                "confirmation_id": "confirm-legacy",
                "task_id": task_id,
                "identity": {
                    "confirmation_id": "confirm-legacy",
                    "task_id": task_id,
                },
                "status": "pending",
                "run_outcome_recorded": "false",
            }
        ]
    }
    invalid_bytes = json.dumps(legacy_payload).encode("utf-8")
    pending_path.write_bytes(invalid_bytes)
    pending_path.chmod(0o600)

    restarted = SchedulerManager(storage_dir=storage)

    result = restarted.state_load_result("pending_confirmations")
    assert result.status == StateLoadStatus.CORRUPT
    assert result.reason == "invalid_pending_row"
    assert result.legacy is True
    assert pending_path.read_bytes() == invalid_bytes


def test_legacy_scheduler_tasks_reject_duplicate_members_before_execution(
    tmp_path: Path,
) -> None:
    storage = tmp_path / "scheduler"
    scheduler = SchedulerManager(storage_dir=storage)
    task_id = _create_scheduler_task(scheduler)
    tasks_path = storage / "tasks.json"
    envelope = json.loads(tasks_path.read_text(encoding="utf-8"))
    row_json = json.dumps(envelope["payload"][0], separators=(",", ":"))
    duplicated_row = row_json.replace(
        '"enabled":true',
        '"enabled":false,"enabled":true',
        1,
    )
    assert duplicated_row != row_json
    ambiguous_bytes = f"[{duplicated_row}]".encode()
    tasks_path.write_bytes(ambiguous_bytes)

    restarted = SchedulerManager(storage_dir=storage)

    result = restarted.state_load_result("tasks")
    assert result.status == StateLoadStatus.CORRUPT
    assert result.reason == "invalid_json"
    with pytest.raises(StatePersistenceDegradedError, match="invalid_json"):
        restarted.get_task(task_id)
    assert tasks_path.read_bytes() == ambiguous_bytes


@pytest.mark.parametrize(
    "action",
    [
        {},
        {"confirmation_id": "confirm-1", "task_id": "other-task"},
        {
            "confirmation_id": "confirm-1",
            "identity": {"confirmation_id": "other-confirmation"},
        },
    ],
)
def test_queue_confirmation_rejects_invalid_identity_before_publication(
    tmp_path: Path,
    action: dict[str, object],
) -> None:
    storage = tmp_path / "scheduler"
    scheduler = SchedulerManager(storage_dir=storage)
    task_id = _create_scheduler_task(scheduler)

    with pytest.raises(ValueError, match="pending confirmation"):
        scheduler.queue_confirmation(task_id, action)

    assert not (storage / "pending_confirmations.json").exists()


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
        str(row.get("confirmation_id", "")) for row in scheduler._pending_confirmations[task_id]
    }
    assert ("confirm-2" in live_ids) is published_second_confirmation

    restarted = SchedulerManager(storage_dir=storage)
    durable_ids = {
        str(row.get("confirmation_id", "")) for row in restarted.pending_confirmations(task_id)
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
        str(row.get("confirmation_id", "")) for row in scheduler._pending_confirmations[task_id]
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
    marks_path.chmod(0o600)

    dashboard = SecurityDashboard(
        audit_log=AuditLog(tmp_path / "audit.jsonl"),
        marks_path=marks_path,
    )

    assert dashboard.state_load_result.status == StateLoadStatus.CORRUPT
    assert dashboard.state_status()["status"] == "degraded"
    with pytest.raises(StatePersistenceDegradedError, match="dashboard_marks"):
        dashboard.mark_false_positive(event_id="evt-2", reason="reviewed")
    assert marks_path.read_bytes() == corrupt_bytes


def test_control_plane_state_corruption_is_typed_aggregated_and_retained(
    tmp_path: Path,
) -> None:
    control_plane_dir = tmp_path / "control_plane"
    control_plane_dir.mkdir(parents=True)
    retained = {
        "history.jsonl": b'{"session_id":"torn"',
        "plans.json": b'{"version":1,"payload":',
        "network_baseline.json": b'{"version":1,"payload":',
        "audit.jsonl": b'{"event_type":"torn"',
    }
    for name, raw_bytes in retained.items():
        (control_plane_dir / name).write_bytes(raw_bytes)

    engine = ControlPlaneEngine.build(data_dir=tmp_path, workspace_roots=[tmp_path])
    status = engine.state_status()

    assert status["status"] == "degraded"
    assert status["fail_closed"] is True
    assert {name: domain["load_status"] for name, domain in status["domains"].items()} == {
        "history": "corrupt",
        "trace": "corrupt",
        "network": "corrupt",
        "audit": "corrupt",
    }
    assert status["domains"]["network"]["learning_enabled"] is False
    for name, raw_bytes in retained.items():
        assert (control_plane_dir / name).read_bytes() == raw_bytes
