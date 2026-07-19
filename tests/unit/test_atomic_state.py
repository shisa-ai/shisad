"""Fault-boundary checks for restrictive atomic state publication."""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from shisad.core import atomic_state, storage_platform
from shisad.core.atomic_state import (
    AtomicWriteError,
    AtomicWriteStage,
    StateLoadStatus,
    atomic_write_bytes,
    load_state,
    write_state,
)
from shisad.core.types import Capability, SessionId, ToolName, UserId, WorkspaceId
from shisad.daemon.handlers._impl import HandlerImplementation, PendingAction


class _ExampleState(BaseModel):
    name: str
    count: int


def _legacy_example(raw: bytes) -> dict[str, Any]:
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict) or set(payload) != {"name", "count"}:
        raise ValueError("not the exact legacy example shape")
    return payload


def test_state_file_missing_valid_and_exact_canonical_envelope(tmp_path: Path) -> None:
    path = tmp_path / "state.json"

    missing = load_state(path, _ExampleState)
    capability = write_state(path, _ExampleState(name="café", count=2))
    loaded = load_state(path, _ExampleState)

    assert missing.status is StateLoadStatus.MISSING
    assert missing.value is None
    assert loaded.status is StateLoadStatus.OK
    assert loaded.value == _ExampleState(name="café", count=2)
    envelope = json.loads(path.read_text(encoding="utf-8"))
    assert list(envelope) == ["payload", "schema", "sha256"]
    assert envelope["schema"] == 1
    assert envelope["payload"] == {"count": 2, "name": "café"}
    assert len(envelope["sha256"]) == 64
    assert capability.parent_sync in {"supported", "unsupported"}
    assert capability.permissions in {"supported", "unsupported"}


@pytest.mark.parametrize(
    ("raw", "expected_status"),
    [
        (b"{not-json", StateLoadStatus.CORRUPT),
        (
            b'{"payload":{"count":1,"name":"ok"},"schema":1,"sha256":"bad"}',
            StateLoadStatus.CORRUPT,
        ),
        (
            b'{"payload":{"count":1,"name":"ok"},"schema":2,"sha256":"ignored"}',
            StateLoadStatus.UNSUPPORTED_SCHEMA,
        ),
        (
            b'{"payload":{"count":1,"name":"ok","name":"shadow"},"schema":1,"sha256":"ignored"}',
            StateLoadStatus.CORRUPT,
        ),
        (
            b'{"payload":{"count":NaN,"name":"ok"},"schema":1,"sha256":"ignored"}',
            StateLoadStatus.CORRUPT,
        ),
    ],
)
def test_state_file_rejects_corrupt_future_duplicate_and_nonfinite_bytes(
    tmp_path: Path,
    raw: bytes,
    expected_status: StateLoadStatus,
) -> None:
    path = tmp_path / "state.json"
    path.write_bytes(raw)

    result = load_state(path, _ExampleState)

    assert result.status is expected_status
    assert result.value is None
    assert path.read_bytes() == raw


def test_state_file_rejects_model_mismatch_after_valid_checksum(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    write_state(path, {"name": "missing-count"})
    before = path.read_bytes()

    result = load_state(path, _ExampleState)

    assert result.status is StateLoadStatus.CORRUPT
    assert result.value is None
    assert path.read_bytes() == before


def test_state_file_exact_legacy_migration_publishes_before_value_becomes_active(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.json"
    path.write_text('{"name":"legacy","count":7}', encoding="utf-8")

    migrated = load_state(path, _ExampleState, legacy_decoder=_legacy_example)
    restarted = load_state(path, _ExampleState)

    assert migrated.status is StateLoadStatus.OK
    assert migrated.value == _ExampleState(name="legacy", count=7)
    assert restarted.status is StateLoadStatus.OK
    assert json.loads(path.read_text(encoding="utf-8"))["schema"] == 1


def test_state_file_failed_legacy_publication_preserves_bytes_and_degrades(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "state.json"
    legacy = b'{"name":"legacy","count":7}'
    path.write_bytes(legacy)

    def _fail_write(*_args: object, **_kwargs: object) -> object:
        raise AtomicWriteError(
            path=path,
            stage=AtomicWriteStage.FILE_FSYNC,
            publication_may_have_committed=False,
        )

    monkeypatch.setattr(atomic_state, "write_state", _fail_write)

    result = load_state(path, _ExampleState, legacy_decoder=_legacy_example)

    assert result.status is StateLoadStatus.CORRUPT
    assert result.value is None
    assert "legacy" in result.reason
    assert path.read_bytes() == legacy


def test_state_file_closes_temp_handle_before_replace_for_windows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "state.json"
    real_mkstemp = atomic_state.tempfile.mkstemp
    real_replace = atomic_state.os.replace
    temp_fd = -1

    def _capture_mkstemp(*args: object, **kwargs: object) -> tuple[int, str]:
        nonlocal temp_fd
        temp_fd, temp_name = real_mkstemp(*args, **kwargs)
        return temp_fd, temp_name

    def _assert_closed_replace(source: str | Path, target: str | Path) -> None:
        with pytest.raises(OSError):
            os.fstat(temp_fd)
        real_replace(source, target)

    monkeypatch.setattr(atomic_state.tempfile, "mkstemp", _capture_mkstemp)
    monkeypatch.setattr(atomic_state.os, "replace", _assert_closed_replace)

    write_state(path, _ExampleState(name="portable", count=1))

    assert load_state(path, _ExampleState).status is StateLoadStatus.OK


def test_state_file_nonfinite_write_never_changes_target(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    write_state(path, {"value": 1.0})
    before = path.read_bytes()

    with pytest.raises((TypeError, ValueError)):
        write_state(path, {"value": float("nan")})

    assert path.read_bytes() == before


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
        capability = atomic_write_bytes(target, b"payload")
    finally:
        os.umask(previous_umask)

    if os.name == "posix":
        assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        assert capability.permissions == "supported"
    else:
        assert capability.permissions == "unsupported"
    assert target.read_bytes() == b"payload"


def test_atomic_write_reports_real_permission_failure_without_blocking_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "state.json"

    def _deny_chmod(*_args: object, **_kwargs: object) -> None:
        raise PermissionError("permission tightening denied")

    monkeypatch.setattr(storage_platform.os, "chmod", _deny_chmod)

    capability = atomic_write_bytes(target, b"payload")

    assert capability.permissions == "failed"
    assert target.read_bytes() == b"payload"


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
