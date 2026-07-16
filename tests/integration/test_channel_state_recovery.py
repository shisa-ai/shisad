"""F3 channel replay-state durability and recovery contracts."""

from __future__ import annotations

import asyncio
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from shisad.channels.state import ChannelStateStore, ReplayOutcome
from shisad.core.atomic_state import (
    AtomicWriteStage,
    DurableAppendStage,
    StateLoadStatus,
    StatePersistenceDegradedError,
    encode_versioned_json_snapshot,
)
from shisad.daemon.event_wiring import channel_receive_pump


def test_channel_replay_corrupt_snapshot_is_retained_and_blocks_fresh_admission(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    root.mkdir()
    state_path = root / "discord.state.json"
    corrupt = b'{"version":1,"payload":'
    state_path.write_bytes(corrupt)

    store = ChannelStateStore(root)

    assert store.state_load_result("discord").status == StateLoadStatus.CORRUPT
    with pytest.raises(StatePersistenceDegradedError, match="channel_replay:discord"):
        store.reserve(channel="discord", message_id="m-new")
    assert state_path.read_bytes() == corrupt


def test_channel_replay_truncated_journal_is_retained_and_blocks_fresh_admission(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    root.mkdir()
    journal_path = root / "matrix.state.journal"
    corrupt = b'{"version":1,"payload":'
    journal_path.write_bytes(corrupt)

    store = ChannelStateStore(root)

    assert store.state_load_result("matrix").status == StateLoadStatus.CORRUPT
    with pytest.raises(StatePersistenceDegradedError, match="channel_replay:matrix"):
        store.reserve(channel="matrix", message_id="m-new")
    assert journal_path.read_bytes() == corrupt


def test_channel_replay_non_directory_root_blocks_reads_without_following_target(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    root.write_bytes(b"retained-not-a-directory")
    store = ChannelStateStore(root)

    assert store.state_load_result("discord").status == StateLoadStatus.CORRUPT
    with pytest.raises(StatePersistenceDegradedError, match="root_not_directory"):
        store.has_seen(channel="discord", message_id="m-1")
    assert root.read_bytes() == b"retained-not-a-directory"


@pytest.mark.parametrize(
    "stage",
    [
        DurableAppendStage.DIRECTORY_PREPARE,
        DurableAppendStage.FILE_OPEN,
        DurableAppendStage.WRITE,
        DurableAppendStage.FILE_FSYNC,
        DurableAppendStage.PARENT_FSYNC,
    ],
)
def test_channel_replay_reservation_fault_blocks_scope_without_dispatch_authority(
    tmp_path: Path,
    stage: DurableAppendStage,
) -> None:
    store = ChannelStateStore(tmp_path / "state")

    def _fail(actual: DurableAppendStage) -> None:
        if actual == stage:
            raise OSError(f"fault:{stage.value}")

    store._append_fault_injector = _fail
    with pytest.raises(StatePersistenceDegradedError, match="reserve"):
        store.reserve(channel="slack", message_id="m-1")

    status = store.state_status("slack")
    assert status["status"] == "degraded"
    assert status["stage"] == stage.value
    store._append_fault_injector = None
    with pytest.raises(StatePersistenceDegradedError, match="channel_replay:slack"):
        store.reserve(channel="slack", message_id="m-2")


def test_channel_replay_terminal_failure_retains_reserved_authority_across_restart(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    store = ChannelStateStore(root)
    assert store.reserve(channel="telegram", message_id="m-1") is False

    def _fail_terminal(stage: DurableAppendStage) -> None:
        if stage == DurableAppendStage.FILE_FSYNC:
            raise OSError("terminal fsync failed")

    store._append_fault_injector = _fail_terminal
    with pytest.raises(StatePersistenceDegradedError, match="terminal"):
        store.mark_terminal(channel="telegram", message_id="m-1")

    assert store.outcome(channel="telegram", message_id="m-1") == ReplayOutcome.UNCERTAIN
    restarted = ChannelStateStore(root)
    assert restarted.reserve(channel="telegram", message_id="m-1") is True


@pytest.mark.parametrize(
    "stage",
    [
        AtomicWriteStage.TEMP_OPEN,
        AtomicWriteStage.WRITE,
        AtomicWriteStage.FILE_FSYNC,
        AtomicWriteStage.REPLACE,
        AtomicWriteStage.PARENT_FSYNC,
    ],
)
def test_channel_replay_snapshot_failure_keeps_durable_journal_authority(
    tmp_path: Path,
    stage: AtomicWriteStage,
) -> None:
    root = tmp_path / "state"
    store = ChannelStateStore(root, journal_compact_every=1)

    def _fail_snapshot(actual: AtomicWriteStage) -> None:
        if actual == stage:
            raise OSError(f"snapshot fault:{stage.value}")

    store._snapshot_fault_injector = _fail_snapshot
    assert store.reserve(channel="discord", message_id="m-1") is False

    journal_path = root / "discord.state.journal"
    assert journal_path.read_bytes()
    restarted = ChannelStateStore(root, journal_compact_every=1)
    assert restarted.reserve(channel="discord", message_id="m-1") is True


@pytest.mark.parametrize(
    "stage",
    [
        AtomicWriteStage.TEMP_OPEN,
        AtomicWriteStage.WRITE,
        AtomicWriteStage.FILE_FSYNC,
        AtomicWriteStage.REPLACE,
        AtomicWriteStage.PARENT_FSYNC,
    ],
)
def test_channel_replay_journal_truncate_failure_keeps_snapshot_authority(
    tmp_path: Path,
    stage: AtomicWriteStage,
) -> None:
    root = tmp_path / "state"
    store = ChannelStateStore(root, journal_compact_every=1)

    def _fail_truncate(actual: AtomicWriteStage) -> None:
        if actual == stage:
            raise OSError(f"truncate fault:{stage.value}")

    store._truncate_fault_injector = _fail_truncate
    assert store.reserve(channel="matrix", message_id="m-1") is False

    assert (root / "matrix.state.json").exists()
    restarted = ChannelStateStore(root, journal_compact_every=1)
    assert restarted.reserve(channel="matrix", message_id="m-1") is True


def test_channel_replay_checksum_tamper_and_future_schema_are_retained(
    tmp_path: Path,
) -> None:
    for channel, raw in (
        (
            "discord",
            encode_versioned_json_snapshot(
                {
                    "channel": "discord",
                    "records": [],
                    "recent_message_ids": ["tampered-after-checksum"],
                }
            ).replace(b"tampered-after-checksum", b"changed-after-checksum"),
        ),
        (
            "matrix",
            b'{"version":99,"checksum":"unused","payload":{}}\n',
        ),
    ):
        root = tmp_path / channel
        root.mkdir()
        state_path = root / f"{channel}.state.json"
        state_path.write_bytes(raw)
        store = ChannelStateStore(root)

        expected = (
            StateLoadStatus.CORRUPT
            if channel == "discord"
            else StateLoadStatus.UNSUPPORTED_SCHEMA
        )
        assert store.state_load_result(channel).status == expected
        with pytest.raises(StatePersistenceDegradedError):
            store.reserve(channel=channel, message_id="m-new")
        assert state_path.read_bytes() == raw


def test_channel_replay_files_are_owner_only_under_permissive_umask(tmp_path: Path) -> None:
    root = tmp_path / "state"
    previous_umask = os.umask(0)
    try:
        store = ChannelStateStore(root, journal_compact_every=1)
        assert store.reserve(channel="discord", message_id="m-1") is False
        store.mark_terminal(channel="discord", message_id="m-1")
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE((root / "discord.state.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((root / "discord.state.journal").stat().st_mode) == 0o600


def test_channel_replay_root_first_create_parent_fsync_failure_blocks_admission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "state"
    store = ChannelStateStore(root)

    def _fail_parent_fsync(path: Path) -> None:
        assert path == tmp_path
        raise OSError("root parent fsync failed")

    monkeypatch.setattr(store, "_fsync_directory", _fail_parent_fsync)
    with pytest.raises(StatePersistenceDegradedError, match="directory_prepare"):
        store.reserve(channel="matrix", message_id="m-1")
    assert not (root / "matrix.state.journal").exists()


def test_channel_replay_concurrent_reservation_has_one_fresh_winner(tmp_path: Path) -> None:
    root = tmp_path / "state"
    store = ChannelStateStore(root)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(
                lambda _index: store.reserve(channel="discord", message_id="m-shared"),
                range(16),
            )
        )

    assert results.count(False) == 1
    assert results.count(True) == 15
    assert ChannelStateStore(root).reserve(channel="discord", message_id="m-shared") is True


@pytest.mark.asyncio
async def test_channel_replay_reserves_before_dispatch_and_records_handler_uncertainty(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    store = ChannelStateStore(root)
    shutdown = asyncio.Event()
    message = SimpleNamespace(
        channel="discord",
        external_user_id="u-1",
        workspace_hint="guild-1",
        content="hello",
        message_id="m-1",
        reply_target="channel-1",
        thread_id="",
        metadata={},
    )

    class _Channel:
        async def receive(self) -> Any:
            return message

    class _Handler:
        calls = 0

        async def handle_channel_ingest(self, _params: Any, _ctx: Any) -> None:
            self.calls += 1
            assert store.outcome(channel="discord", message_id="m-1") == ReplayOutcome.RESERVED
            shutdown.set()
            raise RuntimeError("effect outcome unknown")

    handler = _Handler()
    await channel_receive_pump(
        channel_name="discord",
        channel=_Channel(),  # type: ignore[arg-type]
        shutdown_event=shutdown,
        handlers=handler,  # type: ignore[arg-type]
        state_store=store,
    )

    assert handler.calls == 1
    assert store.outcome(channel="discord", message_id="m-1") == ReplayOutcome.UNCERTAIN
    restarted = ChannelStateStore(root)
    assert restarted.reserve(channel="discord", message_id="m-1") is True
