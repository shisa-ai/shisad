"""F7A durable inbound replay reservation and recovery matrix."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from shisad.channels import state as channel_state


def _identity(
    *,
    provider: str = "matrix",
    account_id: str = '["https://matrix.example.org","@bot:example.org"]',
    scope_id: str = '["!room:example.org"]',
    event_kind: str = "message",
    event_id: str = "$event-1",
) -> object:
    return channel_state.ReplayIdentity(
        provider=provider,
        account_id=account_id,
        scope_id=scope_id,
        event_kind=event_kind,
        event_id=event_id,
    )


@pytest.mark.parametrize("state", ["reserved", "terminal", "uncertain"])
def test_f7a_every_durable_state_blocks_after_restart(tmp_path: Path, state: str) -> None:
    root = tmp_path / "state"
    identity = _identity(event_id=f"$event-{state}")
    store = channel_state.ChannelStateStore(root)
    assert store.reserve(identity) is True
    if state == "terminal":
        store.mark_terminal(identity)
    elif state == "uncertain":
        store.mark_uncertain(identity)

    restarted = channel_state.ChannelStateStore(root)
    assert restarted.state_for(identity) == state
    assert restarted.reserve(identity) is False


def test_f7a_concurrent_reservation_has_one_winner(tmp_path: Path) -> None:
    root = tmp_path / "state"
    # First-open validation is covered separately; this node isolates reservation contention.
    bootstrap = _identity(provider="slack", account_id="app-1", event_id="bootstrap")
    assert channel_state.ChannelStateStore(root).reserve(bootstrap) is True
    identity = _identity(provider="slack", account_id="app-1", event_id="1.23")

    def _reserve() -> bool:
        return channel_state.ChannelStateStore(root).reserve(identity)

    with ThreadPoolExecutor(max_workers=8) as executor:
        outcomes = list(executor.map(lambda _index: _reserve(), range(16)))

    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 15
    assert channel_state.ChannelStateStore(root).record_count() == 2


def test_f7a_exact_legacy_import_is_conservative_atomic_and_preserves_bytes(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    root.mkdir(parents=True)
    snapshot = root / "matrix.state.json"
    journal = root / "matrix.state.journal"
    snapshot.write_bytes(
        json.dumps(
            {"channel": "matrix", "seen_message_ids": ["$legacy-snapshot"]},
            separators=(",", ":"),
        ).encode("utf-8")
    )
    journal.write_bytes(b'"$legacy-journal"\nraw-legacy-id\n')
    before = {snapshot: snapshot.read_bytes(), journal: journal.read_bytes()}

    store = channel_state.ChannelStateStore(root)
    for event_id in ("$legacy-snapshot", "$legacy-journal", "raw-legacy-id"):
        first_scope = _identity(event_id=event_id)
        other_scope = _identity(scope_id='["!other:example.org"]', event_id=event_id)
        assert store.reserve(first_scope) is False
        assert store.state_for(first_scope) == "legacy"
        assert store.reserve(other_scope) is False

    assert {path: path.read_bytes() for path in before} == before
    assert store.reserve(_identity(event_id="$fresh")) is True


def test_f7a_malformed_legacy_input_blocks_without_partial_import(tmp_path: Path) -> None:
    root = tmp_path / "state"
    root.mkdir(parents=True)
    snapshot = root / "slack.state.json"
    journal = root / "slack.state.journal"
    snapshot.write_text(
        json.dumps({"channel": "slack", "seen_message_ids": ["known-id"]}),
        encoding="utf-8",
    )
    journal.write_text('"unterminated\n', encoding="utf-8")
    before = {snapshot: snapshot.read_bytes(), journal: journal.read_bytes()}

    store = channel_state.ChannelStateStore(root)
    with pytest.raises(channel_state.ChannelReplayStateError, match="legacy"):
        store.reserve(
            _identity(
                provider="slack",
                account_id="app-1",
                scope_id='["team-1","channel-1"]',
                event_id="known-id",
            )
        )

    assert store.record_count() == 0
    assert {path: path.read_bytes() for path in before} == before


def test_f7a_duplicate_legacy_snapshot_members_are_ambiguous(tmp_path: Path) -> None:
    root = tmp_path / "state"
    root.mkdir(parents=True)
    (root / "matrix.state.json").write_text(
        '{"channel":"matrix","channel":"matrix","seen_message_ids":["$event-1"]}',
        encoding="utf-8",
    )

    store = channel_state.ChannelStateStore(root)
    with pytest.raises(channel_state.ChannelReplayStateError, match=r"(?i)legacy"):
        store.reserve(_identity())


def test_f7a_broken_legacy_symlink_is_not_treated_as_missing(tmp_path: Path) -> None:
    root = tmp_path / "state"
    root.mkdir(parents=True)
    (root / "matrix.state.json").symlink_to(root / "missing-target")

    store = channel_state.ChannelStateStore(root)
    with pytest.raises(channel_state.ChannelReplayStateError, match=r"(?i)unsafe|legacy"):
        store.reserve(_identity())


def test_f7a_broken_database_symlink_is_rejected_before_open(tmp_path: Path) -> None:
    root = tmp_path / "state"
    root.mkdir(parents=True)
    (root / "replay.sqlite3").symlink_to(root / "missing-database")

    store = channel_state.ChannelStateStore(root)
    with pytest.raises(channel_state.ChannelReplayStateError, match=r"(?i)unsafe|symlink"):
        store.reserve(_identity())


@pytest.mark.parametrize("database_kind", ["corrupt", "unsupported"])
def test_f7a_corrupt_or_unsupported_database_fails_closed(
    tmp_path: Path,
    database_kind: str,
) -> None:
    root = tmp_path / "state"
    root.mkdir(parents=True)
    database = root / "replay.sqlite3"
    if database_kind == "corrupt":
        database.write_bytes(b"not a sqlite database")
    else:
        with sqlite3.connect(database) as connection:
            connection.execute("PRAGMA user_version = 99")

    store = channel_state.ChannelStateStore(root)
    with pytest.raises(
        channel_state.ChannelReplayStateError,
        match=rf"(?i){database_kind}",
    ):
        store.reserve(_identity())


@pytest.mark.parametrize("database_kind", ["empty", "unversioned"])
def test_f7a_existing_unversioned_database_is_never_initialized_as_fresh(
    tmp_path: Path,
    database_kind: str,
) -> None:
    root = tmp_path / "state"
    root.mkdir(parents=True)
    database = root / "replay.sqlite3"
    if database_kind == "empty":
        database.touch()
    else:
        with sqlite3.connect(database) as connection:
            connection.execute("VACUUM")

    store = channel_state.ChannelStateStore(root)
    with pytest.raises(channel_state.ChannelReplayStateError, match=r"(?i)unversioned|schema"):
        store.reserve(_identity())
    assert database.exists()


def test_f7a_reservation_open_failure_is_typed_and_never_fresh(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = channel_state.ChannelStateStore(tmp_path / "state")

    def _fail_connect(*_args: object, **_kwargs: object) -> object:
        raise sqlite3.OperationalError("injected open failure")

    monkeypatch.setattr(channel_state.sqlite3, "connect", _fail_connect)
    with pytest.raises(channel_state.ChannelReplayStateError, match=r"open|reservation"):
        store.reserve(_identity())


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode evidence")
def test_f7a_replay_database_is_owner_only_under_permissive_umask(tmp_path: Path) -> None:
    previous = os.umask(0)
    try:
        store = channel_state.ChannelStateStore(tmp_path / "state")
        assert store.reserve(_identity()) is True
    finally:
        os.umask(previous)

    assert stat.S_IMODE(store.root_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(store.database_path.stat().st_mode) == 0o600


def test_f7a_schema_uses_exact_composite_key_and_finite_states(tmp_path: Path) -> None:
    store = channel_state.ChannelStateStore(tmp_path / "state")
    assert store.reserve(_identity()) is True

    with sqlite3.connect(store.database_path) as connection:
        version = connection.execute("PRAGMA user_version").fetchone()
        columns = connection.execute("PRAGMA table_info(replay_reservations)").fetchall()
        sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='replay_reservations'"
        ).fetchone()

    assert version == (1,)
    assert [row[1] for row in columns[:6]] == [
        "provider",
        "account_id",
        "scope_id",
        "event_kind",
        "event_id",
        "state",
    ]
    assert [row[5] for row in columns[:5]] == [1, 2, 3, 4, 5]
    assert sql is not None
    assert all(name in sql[0] for name in ("reserved", "terminal", "uncertain"))


def test_f7a_same_version_unknown_schema_is_not_accepted(tmp_path: Path) -> None:
    root = tmp_path / "state"
    store = channel_state.ChannelStateStore(root)
    assert store.reserve(_identity()) is True
    with sqlite3.connect(store.database_path) as connection:
        connection.execute("CREATE TABLE unexpected_state(value TEXT)")

    reopened = channel_state.ChannelStateStore(root)
    with pytest.raises(channel_state.ChannelReplayStateError, match=r"(?i)unsupported|schema"):
        reopened.reserve(_identity(event_id="$event-2"))


@pytest.mark.parametrize(
    ("table", "trigger_body"),
    [
        ("replay_reservations", "DELETE FROM replay_reservations;"),
        ("legacy_replay_blockers", "SELECT RAISE(IGNORE);"),
        ("legacy_replay_imports", "DELETE FROM legacy_replay_blockers;"),
    ],
)
def test_f7a_unknown_trigger_is_rejected_for_every_replay_table(
    tmp_path: Path,
    table: str,
    trigger_body: str,
) -> None:
    root = tmp_path / "state"
    store = channel_state.ChannelStateStore(root)
    assert store.reserve(_identity()) is True
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            f"CREATE TRIGGER hostile_{table} AFTER INSERT ON {table} BEGIN {trigger_body} END"
        )

    reopened = channel_state.ChannelStateStore(root)
    with pytest.raises(channel_state.ChannelReplayStateError, match=r"(?i)unsupported|schema"):
        reopened.reserve(_identity(event_id="$event-trigger"))


def test_f7a_invalid_row_blocks_without_committing_legacy_import(tmp_path: Path) -> None:
    root = tmp_path / "state"
    store = channel_state.ChannelStateStore(root)
    assert store.reserve(_identity()) is True
    (root / "discord.state.journal").write_text('"legacy-discord"\n', encoding="utf-8")
    with sqlite3.connect(store.database_path) as connection:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(
            """
            INSERT INTO replay_reservations (
                provider, account_id, scope_id, event_kind, event_id,
                state, created_at, updated_at
            ) VALUES ('discord', 'bot-1', '["guild","channel"]', 'message',
                      'bad-event', 'invalid', 'now', 'now')
            """
        )

    invalid = _identity(
        provider="discord",
        account_id="bot-1",
        scope_id='["guild","channel"]',
        event_id="bad-event",
    )
    with pytest.raises(channel_state.ChannelReplayStateError, match=r"(?i)corrupt|state"):
        store.state_for(invalid)

    with sqlite3.connect(store.database_path) as connection:
        imported = connection.execute(
            "SELECT 1 FROM legacy_replay_imports WHERE provider = 'discord'"
        ).fetchone()
        blockers = connection.execute(
            "SELECT COUNT(*) FROM legacy_replay_blockers WHERE provider = 'discord'"
        ).fetchone()
    assert imported is None
    assert blockers == (0,)


def test_f7a_reset_rejects_replaced_root_symlink_without_touching_target(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    store = channel_state.ChannelStateStore(root)
    root.mkdir()
    root.rmdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    root.symlink_to(outside, target_is_directory=True)

    with pytest.raises(channel_state.ChannelReplayStateError, match=r"(?i)symlink|unsafe"):
        store.reset()
    assert sentinel.read_text(encoding="utf-8") == "keep"
