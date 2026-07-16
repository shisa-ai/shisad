"""F3 channel replay-state durability and recovery contracts."""

from __future__ import annotations

import asyncio
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event, Thread
from types import SimpleNamespace
from typing import Any

import pytest

from shisad.channels.base import ReplayEventVariant, ReplayIdentity
from shisad.channels.state import ChannelStateStore, ReplayOutcome
from shisad.core import atomic_state
from shisad.core.atomic_state import (
    AtomicWriteStage,
    DurableAppendStage,
    StateLoadStatus,
    StatePersistenceDegradedError,
    encode_versioned_json_snapshot,
)
from shisad.daemon.event_wiring import channel_receive_pump


def _identity(
    *,
    provider: str = "discord",
    account_id: str = "acct-1",
    tenant_id: str = "guild-1",
    delivery_id: str = "channel-1",
    message_id: str = "m-1",
) -> ReplayIdentity:
    return ReplayIdentity(
        provider=provider,
        account_id=account_id,
        tenant_id=tenant_id,
        delivery_id=delivery_id,
        event_variant=ReplayEventVariant.ORDINARY_MESSAGE,
        message_id=message_id,
    )


def test_provider_scoped_replay_identity_distinguishes_delivery_domains(
    tmp_path: Path,
) -> None:
    store = ChannelStateStore(tmp_path / "state", journal_compact_every=2)
    first = _identity(delivery_id="channel-1", message_id="same-raw-id")
    second = _identity(delivery_id="channel-2", message_id="same-raw-id")

    assert store.reserve(identity=first) is False
    store.mark_terminal(identity=first)
    assert store.reserve(identity=first) is True
    assert store.reserve(identity=second) is False
    store.mark_terminal(identity=second)

    restarted = ChannelStateStore(tmp_path / "state", journal_compact_every=2)
    assert restarted.reserve(identity=first) is True
    assert restarted.reserve(identity=second) is True


def test_replay_eviction_never_turns_old_ingress_fresh(tmp_path: Path) -> None:
    root = tmp_path / "state"
    store = ChannelStateStore(root, max_seen_ids=2048, journal_compact_every=128)
    identities = [_identity(message_id=f"m-{index:04d}") for index in range(2050)]

    for identity in identities:
        assert store.reserve(identity=identity) is False
        store.mark_terminal(identity=identity)

    snapshot = store.snapshot("discord")
    assert snapshot["seen_count"] == 2048
    assert len(snapshot["recent_identity_keys"]) == 2048
    assert "seen_message_ids" not in snapshot
    assert snapshot["authoritative_count"] == 2050
    restarted = ChannelStateStore(root, max_seen_ids=2048, journal_compact_every=128)
    assert restarted.reserve(identity=identities[0]) is True
    assert restarted.reserve(identity=identities[-1]) is True


def test_unscoped_v1_state_blocks_unknown_identity_until_explicit_rebaseline(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    root.mkdir()
    state_path = root / "discord.state.json"
    state_path.write_bytes(
        encode_versioned_json_snapshot(
            {
                "channel": "discord",
                "records": [
                    {
                        "channel": "discord",
                        "message_id": "legacy-known",
                        "outcome": "terminal",
                    }
                ],
                "recent_message_ids": ["legacy-known"],
            },
            version=1,
        )
    )
    original = state_path.read_bytes()
    store = ChannelStateStore(root)

    assert store.reserve(identity=_identity(message_id="legacy-known")) is True
    with pytest.raises(StatePersistenceDegradedError, match="rebaseline"):
        store.reserve(identity=_identity(message_id="unknown"))
    assert store.state_status("discord")["reason"] == "legacy_scope_ambiguous_rebaseline_required"
    assert store.state_status("discord")["remediation"] == (
        "shisad channel replay-rebaseline --channel discord --confirm"
    )
    assert state_path.read_bytes() == original

    store.rebaseline("discord")
    assert store.reserve(identity=_identity(message_id="unknown")) is False


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


@pytest.mark.parametrize("version", [1, 99])
def test_channel_replay_envelope_candidate_never_downgrades_to_legacy(
    tmp_path: Path,
    version: int,
) -> None:
    root = tmp_path / "state"
    root.mkdir()
    state_path = root / "discord.state.json"
    raw = (
        b'{"version":'
        + str(version).encode("ascii")
        + b',"checksum":"invalid","payload":{"channel":"discord",'
        b'"records":[],"recent_message_ids":[]},"channel":"discord",'
        b'"seen_message_ids":[]}'
    )
    state_path.write_bytes(raw)

    store = ChannelStateStore(root)

    expected = StateLoadStatus.CORRUPT if version == 1 else StateLoadStatus.UNSUPPORTED_SCHEMA
    assert store.state_load_result("discord").status == expected
    with pytest.raises(StatePersistenceDegradedError):
        store.reserve(channel="discord", message_id="m-new")
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
    real_fsync_directory = atomic_state._fsync_directory_path

    def _fail_parent_fsync(path: Path) -> None:
        if path == tmp_path:
            raise OSError("root parent fsync failed")
        real_fsync_directory(path)

    monkeypatch.setattr(atomic_state, "_fsync_directory_path", _fail_parent_fsync)
    with pytest.raises(StatePersistenceDegradedError, match="parent_fsync"):
        store.reserve(channel="matrix", message_id="m-1")
    assert (root / "matrix.state.journal").exists()


def test_channel_replay_production_depth_fsyncs_every_new_ancestor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    root = data_dir / "channels" / "state"
    store = ChannelStateStore(root)
    real_fsync_directory = atomic_state._fsync_directory_path
    fsynced: list[Path] = []

    def _record_fsync(path: Path) -> None:
        fsynced.append(path)
        real_fsync_directory(path)

    monkeypatch.setattr(atomic_state, "_fsync_directory_path", _record_fsync)

    assert store.reserve(channel="discord", message_id="m-1") is False

    assert fsynced[:3] == [root, data_dir, data_dir / "channels"]
    assert ChannelStateStore(root).reserve(channel="discord", message_id="m-1") is True


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


def test_channel_replay_reset_serializes_with_inflight_reservation(tmp_path: Path) -> None:
    root = tmp_path / "state"
    store = ChannelStateStore(root)
    append_entered = Event()
    release_append = Event()
    reset_started = Event()
    reset_finished = Event()
    reservation_results: list[bool] = []
    reset_results: list[tuple[int, int]] = []

    def _barrier(stage: DurableAppendStage) -> None:
        if stage == DurableAppendStage.WRITE:
            append_entered.set()
            assert release_append.wait(timeout=2.0)

    store._append_fault_injector = _barrier

    def _reserve() -> None:
        reservation_results.append(store.reserve(channel="discord", message_id="m-1"))

    def _reset() -> None:
        reset_started.set()
        reset_results.append(store.reset_state())
        reset_finished.set()

    reservation = Thread(target=_reserve)
    reset = Thread(target=_reset)
    reservation.start()
    assert append_entered.wait(timeout=1.0)
    reset.start()
    assert reset_started.wait(timeout=1.0)
    assert reset_finished.wait(timeout=0.1) is False

    release_append.set()
    reservation.join(timeout=2.0)
    reset.join(timeout=2.0)

    assert reservation.is_alive() is False
    assert reset.is_alive() is False
    assert reservation_results == [False]
    assert reset_results == [(1, 1)]
    assert store.runtime_cache_empty() is True
    assert list(root.iterdir()) == []


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

        def replay_identity(self, _message: Any) -> ReplayIdentity:
            return _identity(message_id="m-1")

    class _Handler:
        calls = 0

        async def handle_channel_ingest(self, _params: Any, _ctx: Any) -> None:
            self.calls += 1
            assert store.outcome(identity=_identity(message_id="m-1")) == ReplayOutcome.RESERVED
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
    assert store.outcome(identity=_identity(message_id="m-1")) == ReplayOutcome.UNCERTAIN
    restarted = ChannelStateStore(root)
    assert restarted.reserve(identity=_identity(message_id="m-1")) is True
