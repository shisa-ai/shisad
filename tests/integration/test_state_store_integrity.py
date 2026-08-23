"""F3 finite-store integrity and component-local degradation journeys."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

import shisad.core.data_backup as data_backup_module
import shisad.scheduler.manager as scheduler_module
from shisad.core.atomic_state import (
    AtomicWriteError,
    AtomicWriteStage,
    StatePersistenceDegradedError,
    write_state,
)
from shisad.core.types import Capability, UserId
from shisad.scheduler.manager import SchedulerManager
from shisad.scheduler.schema import Schedule, ScheduledTask


def _create_task(manager: SchedulerManager, *, name: str = "digest") -> ScheduledTask:
    return manager.create_task(
        name=name,
        goal="summarize updates",
        schedule=Schedule.from_event("message.received"),
        capability_snapshot={Capability.MEMORY_READ},
        policy_snapshot_ref="policy-v1",
        created_by=UserId("alice"),
    )


def _assert_state_envelope(path: Path) -> dict[str, object]:
    envelope = json.loads(path.read_text(encoding="utf-8"))
    assert set(envelope) == {"schema", "sha256", "payload"}
    assert envelope["schema"] == 1
    assert isinstance(envelope["sha256"], str)
    return envelope


def test_o4cp_supported_platform_root_handle_round_trip(tmp_path: Path) -> None:
    source = tmp_path / "source"
    state = source / "nested" / "state.json"
    state.parent.mkdir(parents=True)
    state.write_bytes(b'\x00{"durable":true}\n')
    archive = tmp_path / "snapshot.shisad-backup"
    restored = tmp_path / "restored"

    backup = data_backup_module.create_data_backup(source, archive)
    restore = data_backup_module.restore_data_backup(archive, restored)

    assert backup.verified is True
    assert restore.verified is True
    assert (restored / "nested" / "state.json").read_bytes() == state.read_bytes()


@pytest.mark.skipif(os.name != "nt", reason="native Windows reparse contract")
def test_drh1_native_windows_backup_rejects_a_directory_junction(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "state.json").write_bytes(b"outside")
    junction = source / "junction"
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
        check=True,
        capture_output=True,
        text=True,
    )
    archive = tmp_path / "snapshot.shisad-backup"

    with pytest.raises(
        data_backup_module.DataBackupError,
        match=r"reparse|unsafe|special|scan|travers|inspect",
    ):
        data_backup_module.create_data_backup(source, archive)

    assert not archive.exists()


def test_scheduler_first_use_restart_and_pending_state_use_state_envelopes(
    tmp_path: Path,
) -> None:
    storage = tmp_path / "tasks"
    first = SchedulerManager(storage_dir=storage)
    created = _create_task(first)
    first.queue_confirmation(
        created.id,
        {
            "task_id": created.id,
            "event_type": "message.received",
            "trigger_payload": "hello",
            "plan_commitment": created.commitment_hash(),
            "payload_taint": "UNTRUSTED",
            "status": "pending",
        },
    )

    tasks_envelope = _assert_state_envelope(storage / "tasks.json")
    pending_envelope = _assert_state_envelope(storage / "pending_confirmations.json")
    restarted = SchedulerManager(storage_dir=storage)

    assert isinstance(tasks_envelope["payload"], list)
    assert isinstance(pending_envelope["payload"], dict)
    assert restarted.get_task(created.id) is not None
    assert restarted.pending_confirmations(created.id)[0]["task_id"] == created.id
    assert restarted.state_health()["status"] == "ok"


def test_scheduler_exact_legacy_json_migrates_before_activation(tmp_path: Path) -> None:
    storage = tmp_path / "tasks"
    storage.mkdir()
    seed = SchedulerManager()
    created = _create_task(seed, name="legacy")
    task_payload = created.model_dump(mode="json")
    (storage / "tasks.json").write_text(json.dumps([task_payload]), encoding="utf-8")
    (storage / "pending_confirmations.json").write_text("{}", encoding="utf-8")

    migrated = SchedulerManager(storage_dir=storage)

    assert migrated.get_task(created.id) is not None
    _assert_state_envelope(storage / "tasks.json")
    _assert_state_envelope(storage / "pending_confirmations.json")


def test_scheduler_rejects_duplicate_task_ids_in_valid_envelope(tmp_path: Path) -> None:
    storage = tmp_path / "tasks"
    seed = SchedulerManager()
    payload = _create_task(seed).model_dump(mode="json")
    storage.mkdir()
    tasks_path = storage / "tasks.json"
    write_state(tasks_path, [payload, payload])
    before = tasks_path.read_bytes()

    scheduler = SchedulerManager(storage_dir=storage)

    assert scheduler.state_health()["status"] == "corrupt"
    assert tasks_path.read_bytes() == before
    with pytest.raises(StatePersistenceDegradedError):
        scheduler.list_tasks()


@pytest.mark.parametrize(
    "raw",
    [
        b"{not-json",
        b'{"schema":2,"sha256":"future","payload":[]}',
        b'{"schema":1,"sha256":"wrong","payload":[]}',
    ],
)
def test_scheduler_corrupt_or_future_state_is_preserved_and_blocks_only_scheduler(
    tmp_path: Path,
    raw: bytes,
) -> None:
    storage = tmp_path / "tasks"
    storage.mkdir()
    tasks_path = storage / "tasks.json"
    tasks_path.write_bytes(raw)

    scheduler = SchedulerManager(storage_dir=storage)

    assert scheduler.state_health()["status"] in {"corrupt", "unsupported"}
    assert tasks_path.read_bytes() == raw
    with pytest.raises(StatePersistenceDegradedError):
        scheduler.list_tasks()
    with pytest.raises(StatePersistenceDegradedError):
        _create_task(scheduler)
    assert "chat" in scheduler.state_health()["remains_usable"]


def test_scheduler_publication_failure_preserves_prior_snapshot_and_blocks_component(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = tmp_path / "tasks"
    scheduler = SchedulerManager(storage_dir=storage)
    original = _create_task(scheduler, name="original")
    tasks_path = storage / "tasks.json"
    before = tasks_path.read_bytes()

    def _fail_write(*_args: object, **_kwargs: object) -> object:
        raise AtomicWriteError(
            path=tasks_path,
            stage=AtomicWriteStage.FILE_FSYNC,
            publication_may_have_committed=False,
        )

    monkeypatch.setattr(scheduler_module, "write_state", _fail_write)

    with pytest.raises(StatePersistenceDegradedError):
        _create_task(scheduler, name="uncommitted")

    assert tasks_path.read_bytes() == before
    assert scheduler.state_health()["status"] == "corrupt"
    restarted = SchedulerManager(storage_dir=storage)
    assert [task.id for task in restarted.list_tasks()] == [original.id]
