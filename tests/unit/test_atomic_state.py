"""Fault-boundary checks for restrictive atomic state publication."""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from shisad.core import atomic_state
from shisad.core.atomic_state import (
    AtomicWriteError,
    AtomicWriteStage,
    DurableAppendError,
    DurableAppendStage,
    StateLoadStatus,
    atomic_write_bytes,
    decode_versioned_json_snapshot,
    durable_append_bytes,
    encode_versioned_json_snapshot,
)
from shisad.core.types import Capability, SessionId, ToolName, UserId, WorkspaceId
from shisad.daemon.handlers._impl import HandlerImplementation, PendingAction


@pytest.mark.parametrize(
    ("fault_stage", "published_new", "publication_may_have_committed"),
    [
        (AtomicWriteStage.TEMP_OPEN, False, False),
        (AtomicWriteStage.WRITE, False, False),
        (AtomicWriteStage.FILE_FSYNC, False, False),
        (AtomicWriteStage.REPLACE, False, False),
        (AtomicWriteStage.PARENT_FSYNC, True, True),
    ],
)
def test_atomic_write_fault_is_old_or_new_with_typed_commit_uncertainty(
    tmp_path: Path,
    fault_stage: AtomicWriteStage,
    published_new: bool,
    publication_may_have_committed: bool,
) -> None:
    target = tmp_path / "state" / "pending_actions.json"
    target.parent.mkdir()
    target.write_bytes(b"old")

    def _inject(stage: AtomicWriteStage) -> None:
        if stage == fault_stage:
            raise OSError(f"fault:{stage.value}")

    with pytest.raises(AtomicWriteError) as raised:
        atomic_write_bytes(target, b"new", fault_injector=_inject)

    assert raised.value.stage == fault_stage
    assert raised.value.publication_may_have_committed is publication_may_have_committed
    assert target.read_bytes() == (b"new" if published_new else b"old")
    assert list(target.parent.glob(f".{target.name}.*.tmp")) == []


def test_atomic_write_uses_owner_only_modes_under_permissive_umask(tmp_path: Path) -> None:
    target = tmp_path / "state" / "pending_actions.json"
    previous_umask = os.umask(0)
    try:
        atomic_write_bytes(target, b"payload")
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert target.read_bytes() == b"payload"


def test_atomic_write_fsyncs_each_new_parent_directory_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "channels" / "control" / "state.json"
    real_fsync_directory = atomic_state._fsync_directory_path
    fsynced: list[Path] = []

    def _record_fsync(path: Path) -> None:
        fsynced.append(path)
        real_fsync_directory(path)

    monkeypatch.setattr(atomic_state, "_fsync_directory_path", _record_fsync)

    atomic_write_bytes(target, b"payload")

    assert fsynced == [
        target.parent,
        tmp_path,
        tmp_path / "channels",
    ]


def test_atomic_write_retries_short_os_writes_until_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "pending_actions.json"
    real_write = atomic_state.os.write
    write_sizes: list[int] = []

    def _short_write(fd: int, payload: bytes | memoryview) -> int:
        chunk = bytes(payload[: max(1, len(payload) // 2)])
        written = real_write(fd, chunk)
        write_sizes.append(written)
        return written

    monkeypatch.setattr(atomic_state.os, "write", _short_write)

    atomic_write_bytes(target, b"complete-payload")

    assert len(write_sizes) > 1
    assert target.read_bytes() == b"complete-payload"


def test_atomic_write_rejects_non_regular_existing_target(tmp_path: Path) -> None:
    target = tmp_path / "pending_actions.json"
    target.mkdir()

    with pytest.raises(AtomicWriteError) as raised:
        atomic_write_bytes(target, b"payload")

    assert raised.value.stage == AtomicWriteStage.TARGET_VALIDATE
    assert raised.value.publication_may_have_committed is False


def test_atomic_write_rejects_symlinked_existing_parent_ancestor(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    outside = tmp_path / "outside"
    outside_parent = outside / "nested"
    outside_parent.mkdir(parents=True)
    sentinel = outside_parent / "sentinel.txt"
    sentinel.write_bytes(b"outside")
    (data_dir / "redirect").symlink_to(outside, target_is_directory=True)
    target = data_dir / "redirect" / "nested" / "state.json"

    with pytest.raises(AtomicWriteError) as raised:
        atomic_write_bytes(target, b"payload")

    assert raised.value.stage == AtomicWriteStage.DIRECTORY_PREPARE
    assert raised.value.publication_may_have_committed is False
    assert sentinel.read_bytes() == b"outside"
    assert not (outside_parent / "state.json").exists()


def test_atomic_write_types_target_lstat_errors_as_uncommitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "pending_actions.json"
    real_lstat = Path.lstat

    def _deny_target(path: Path) -> os.stat_result:
        if path == target:
            raise PermissionError("injected target lstat denial")
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", _deny_target)

    with pytest.raises(AtomicWriteError) as raised:
        atomic_write_bytes(target, b"payload")

    assert raised.value.stage == AtomicWriteStage.TARGET_VALIDATE
    assert raised.value.publication_may_have_committed is False
    assert not target.exists()


@pytest.mark.parametrize(
    ("fault_stage", "payload_may_exist", "target_exists"),
    [
        (DurableAppendStage.FILE_OPEN, False, False),
        (DurableAppendStage.WRITE, False, False),
        (DurableAppendStage.FILE_FSYNC, True, True),
        (DurableAppendStage.PARENT_FSYNC, True, True),
    ],
)
def test_durable_append_fault_reports_commit_uncertainty(
    tmp_path: Path,
    fault_stage: DurableAppendStage,
    payload_may_exist: bool,
    target_exists: bool,
) -> None:
    target = tmp_path / "channels" / "pairing_requests.jsonl"

    def _inject(stage: DurableAppendStage) -> None:
        if stage == fault_stage:
            raise OSError(f"fault:{stage.value}")

    with pytest.raises(DurableAppendError) as raised:
        durable_append_bytes(target, b'{"id":"one"}\n', fault_injector=_inject)

    assert raised.value.stage == fault_stage
    assert raised.value.publication_may_have_committed is payload_may_exist
    assert target.exists() is target_exists
    if payload_may_exist:
        assert target.read_bytes() == b'{"id":"one"}\n'


def test_durable_append_is_owner_only_and_preserves_complete_rows(
    tmp_path: Path,
) -> None:
    target = tmp_path / "channels" / "pairing_requests.jsonl"
    previous_umask = os.umask(0)
    try:
        durable_append_bytes(target, b'{"id":"one"}\n')
        durable_append_bytes(target, b'{"id":"two"}\n')
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert target.read_bytes() == b'{"id":"one"}\n{"id":"two"}\n'


def test_durable_append_fsyncs_each_new_parent_directory_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "channels" / "control" / "events.jsonl"
    real_fsync_directory = atomic_state._fsync_directory_path
    fsynced: list[Path] = []

    def _record_fsync(path: Path) -> None:
        fsynced.append(path)
        real_fsync_directory(path)

    monkeypatch.setattr(atomic_state, "_fsync_directory_path", _record_fsync)

    durable_append_bytes(target, b'{"id":"one"}\n')

    assert fsynced == [
        target.parent,
        tmp_path,
        tmp_path / "channels",
    ]


def test_durable_append_rejects_symlink_target(tmp_path: Path) -> None:
    outside = tmp_path / "outside.jsonl"
    outside.write_bytes(b"outside\n")
    target = tmp_path / "channels" / "pairing_requests.jsonl"
    target.parent.mkdir()
    target.symlink_to(outside)

    with pytest.raises(DurableAppendError) as raised:
        durable_append_bytes(target, b'{"id":"one"}\n')

    assert raised.value.stage == DurableAppendStage.TARGET_VALIDATE
    assert raised.value.publication_may_have_committed is False
    assert outside.read_bytes() == b"outside\n"


def test_durable_append_rejects_symlinked_existing_parent_ancestor(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    outside = tmp_path / "outside"
    outside_parent = outside / "nested"
    outside_parent.mkdir(parents=True)
    sentinel = outside_parent / "sentinel.txt"
    sentinel.write_bytes(b"outside")
    (data_dir / "redirect").symlink_to(outside, target_is_directory=True)
    target = data_dir / "redirect" / "nested" / "events.jsonl"

    with pytest.raises(DurableAppendError) as raised:
        durable_append_bytes(target, b'{"id":"one"}\n')

    assert raised.value.stage == DurableAppendStage.DIRECTORY_PREPARE
    assert raised.value.publication_may_have_committed is False
    assert sentinel.read_bytes() == b"outside"
    assert not (outside_parent / "events.jsonl").exists()


def test_durable_append_can_durably_create_an_empty_log(tmp_path: Path) -> None:
    target = tmp_path / "control" / "empty.jsonl"

    durable_append_bytes(target, b"")

    assert target.exists()
    assert target.read_bytes() == b""
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_durable_append_fsyncs_parent_for_existing_file(tmp_path: Path) -> None:
    target = tmp_path / "control" / "pairing_requests.jsonl"
    durable_append_bytes(target, b'{"id":"one"}\n')

    def _inject(stage: DurableAppendStage) -> None:
        if stage == DurableAppendStage.PARENT_FSYNC:
            raise OSError("fault:parent_fsync")

    with pytest.raises(DurableAppendError) as raised:
        durable_append_bytes(target, b'{"id":"two"}\n', fault_injector=_inject)

    assert raised.value.stage == DurableAppendStage.PARENT_FSYNC
    assert raised.value.publication_may_have_committed is True
    assert target.read_bytes() == b'{"id":"one"}\n{"id":"two"}\n'


def test_versioned_json_snapshot_round_trips_with_checksum() -> None:
    encoded = encode_versioned_json_snapshot({"rows": [{"id": "one"}]})

    result, payload = decode_versioned_json_snapshot(encoded)

    assert result.status == StateLoadStatus.OK
    assert result.schema_version == 1
    assert payload == {"rows": [{"id": "one"}]}


def test_versioned_json_snapshot_reports_unsupported_schema_before_payload_use() -> None:
    result, payload = decode_versioned_json_snapshot(
        b'{"version":2,"checksum":"unused","payload":{"unsafe":true}}'
    )

    assert result.status == StateLoadStatus.UNSUPPORTED_SCHEMA
    assert result.schema_version == 2
    assert payload is None


def test_versioned_json_snapshot_checksum_detects_version_only_tampering() -> None:
    envelope = json.loads(
        encode_versioned_json_snapshot({"rows": []}, version=2).decode("utf-8")
    )
    envelope["version"] = 1

    result, payload = decode_versioned_json_snapshot(
        json.dumps(envelope).encode("utf-8")
    )

    assert result.status == StateLoadStatus.CORRUPT
    assert result.reason == "checksum_mismatch"
    assert payload is None


@pytest.mark.parametrize("non_finite", [b"NaN", b"Infinity", b"-Infinity"])
def test_versioned_json_snapshot_reports_non_finite_payload_as_corrupt(
    non_finite: bytes,
) -> None:
    result, payload = decode_versioned_json_snapshot(
        b'{"version":1,"checksum":"unused","payload":' + non_finite + b"}"
    )

    assert result.status == StateLoadStatus.CORRUPT
    assert result.reason == "invalid_payload"
    assert payload is None


@pytest.mark.parametrize(
    ("raw_bytes", "reason"),
    [
        (
            b'{"version":1,"checksum":"\\u00e9","payload":{}}',
            "invalid_checksum",
        ),
        (
            b'{"version":1,"checksum":"unused","payload":{"text":"\\ud800"}}',
            "invalid_payload",
        ),
    ],
)
def test_versioned_json_snapshot_malformed_unicode_is_typed_corrupt(
    raw_bytes: bytes,
    reason: str,
) -> None:
    result, payload = decode_versioned_json_snapshot(raw_bytes)

    assert result.status == StateLoadStatus.CORRUPT
    assert result.reason == reason
    assert payload is None


def test_versioned_json_snapshot_recursive_payload_is_typed_corrupt() -> None:
    raw_bytes = (
        b'{"version":1,"checksum":"unused","payload":'
        + (b"[" * 10000)
        + b"0"
        + (b"]" * 10000)
        + b"}"
    )

    result, payload = decode_versioned_json_snapshot(raw_bytes)

    assert result.status == StateLoadStatus.CORRUPT
    assert result.reason == "invalid_json"
    assert payload is None


def test_pending_actions_snapshot_uses_atomic_writer_fault_boundary(tmp_path: Path) -> None:
    created_at = datetime.now(UTC)
    pending = PendingAction(
        confirmation_id="c-atomic-pending",
        decision_nonce="nonce-atomic-pending",
        session_id=SessionId("s-atomic-pending"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("web.search"),
        arguments={"query": "atomic state"},
        reason="manual",
        capabilities={Capability.HTTP_REQUEST},
        created_at=created_at,
        expires_at=created_at + timedelta(hours=1),
    )
    handler = object.__new__(HandlerImplementation)
    handler._pending_actions = {pending.confirmation_id: pending}
    handler._pending_actions_file = tmp_path / "pending_actions.json"

    def _fail_file_fsync(stage: AtomicWriteStage) -> None:
        if stage == AtomicWriteStage.FILE_FSYNC:
            raise OSError("injected pending snapshot fsync fault")

    handler._pending_state_fault_injector = _fail_file_fsync

    with pytest.raises(AtomicWriteError) as raised:
        handler._persist_pending_actions()

    assert raised.value.stage == AtomicWriteStage.FILE_FSYNC
    assert raised.value.publication_may_have_committed is False
    assert not handler._pending_actions_file.exists()
