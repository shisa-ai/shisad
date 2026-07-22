"""Durable, provider-scoped replay reservation for channel ingress."""

from __future__ import annotations

import contextlib
import json
import shutil
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from shisad.core.errors import ChannelError
from shisad.core.storage_platform import sync_parent_directory, tighten_permissions

_SCHEMA_VERSION = 1
_DATABASE_NAME = "replay.sqlite3"
_IDENTITY_FIELDS = ("provider", "account_id", "scope_id", "event_kind", "event_id")
_REPLAY_STATES = ("reserved", "terminal", "uncertain")

ReplayState = Literal["reserved", "terminal", "uncertain", "legacy"]


class ChannelReplayIdentityError(ChannelError):
    """Trusted channel ingress did not supply a usable structural identity."""

    default_reason_code = "channel.replay_identity_invalid"
    default_message = "Channel replay identity is invalid; the event was not processed."
    expose_message = True


class ChannelReplayStateError(ChannelError):
    """Durable replay state could not safely decide whether an event is fresh."""

    default_reason_code = "channel.replay_state_unavailable"
    default_message = "Channel replay state is unavailable; the event was not processed."
    expose_message = True


@dataclass(frozen=True, slots=True)
class ReplayIdentity:
    """Daemon-owned uniqueness tuple for one provider ingress event."""

    provider: str
    account_id: str
    scope_id: str
    event_kind: str
    event_id: str

    def __post_init__(self) -> None:
        for field_name in _IDENTITY_FIELDS:
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ChannelReplayIdentityError(
                    f"Channel replay identity field {field_name} must be a non-empty string."
                )
            object.__setattr__(self, field_name, value.strip())

    @classmethod
    def from_mapping(cls, value: object) -> ReplayIdentity:
        if not isinstance(value, Mapping):
            raise ChannelReplayIdentityError("Missing trusted channel replay identity metadata.")
        if set(value) != set(_IDENTITY_FIELDS):
            raise ChannelReplayIdentityError(
                "Trusted channel replay identity metadata has unexpected or missing fields."
            )
        normalized: dict[str, str] = {}
        for field_name in _IDENTITY_FIELDS:
            field_value = value.get(field_name)
            if not isinstance(field_value, str):
                raise ChannelReplayIdentityError(
                    f"Trusted channel replay identity field {field_name} must be a string."
                )
            normalized[field_name] = field_value
        return cls(
            provider=normalized["provider"],
            account_id=normalized["account_id"],
            scope_id=normalized["scope_id"],
            event_kind=normalized["event_kind"],
            event_id=normalized["event_id"],
        )

    def as_dict(self) -> dict[str, str]:
        return {field_name: getattr(self, field_name) for field_name in _IDENTITY_FIELDS}

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        return (
            self.provider,
            self.account_id,
            self.scope_id,
            self.event_kind,
            self.event_id,
        )


def structural_replay_id(*parts: object) -> str:
    """Encode a finite provider uniqueness domain without delimiter ambiguity."""

    normalized = [str(part).strip() for part in parts]
    if not normalized or not any(normalized):
        raise ChannelReplayIdentityError("Replay identity scope has no structural value.")
    return json.dumps(normalized, ensure_ascii=True, separators=(",", ":"))


def replay_identity_metadata(identity: ReplayIdentity) -> dict[str, dict[str, str]]:
    """Build the reserved adapter metadata envelope for the common handler."""

    return {"replay_identity": identity.as_dict()}


class ChannelStateStore:
    """SQLite authority for durable pre-dispatch channel replay reservation."""

    def __init__(self, root_dir: Path) -> None:
        self._root_dir = root_dir
        self._database_path = root_dir / _DATABASE_NAME

    @property
    def root_dir(self) -> Path:
        return self._root_dir

    @property
    def database_path(self) -> Path:
        return self._database_path

    def reserve(self, identity: ReplayIdentity) -> bool:
        """Durably reserve *identity*; return false for any existing blocker."""

        connection = self._open_database()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._import_legacy_for_provider(connection, identity.provider)
            legacy = connection.execute(
                "SELECT 1 FROM legacy_replay_blockers WHERE provider = ? AND event_id = ?",
                (identity.provider, identity.event_id),
            ).fetchone()
            if legacy is not None:
                connection.commit()
                return False
            timestamp = _utc_now()
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO replay_reservations (
                    provider, account_id, scope_id, event_kind, event_id,
                    state, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'reserved', ?, ?)
                """,
                (*identity.key, timestamp, timestamp),
            )
            inserted = cursor.rowcount == 1
            connection.commit()
            return inserted
        except ChannelReplayStateError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            raise _sqlite_error("reservation", exc) from exc
        finally:
            connection.close()

    def mark_terminal(self, identity: ReplayIdentity) -> None:
        self._mark_state(identity, "terminal")

    def mark_uncertain(self, identity: ReplayIdentity) -> None:
        self._mark_state(identity, "uncertain")

    def state_for(self, identity: ReplayIdentity) -> ReplayState | None:
        connection = self._open_database()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._import_legacy_for_provider(connection, identity.provider)
            row = connection.execute(
                """
                SELECT state FROM replay_reservations
                WHERE provider = ? AND account_id = ? AND scope_id = ?
                  AND event_kind = ? AND event_id = ?
                """,
                identity.key,
            ).fetchone()
            if row is not None:
                state = str(row[0])
                if state not in _REPLAY_STATES:
                    raise ChannelReplayStateError("Corrupt replay reservation state value.")
                connection.commit()
                return state  # type: ignore[return-value]
            legacy = connection.execute(
                "SELECT 1 FROM legacy_replay_blockers WHERE provider = ? AND event_id = ?",
                (identity.provider, identity.event_id),
            ).fetchone()
            connection.commit()
            return "legacy" if legacy is not None else None
        except ChannelReplayStateError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            raise _sqlite_error("state lookup", exc) from exc
        finally:
            connection.close()

    def record_count(self) -> int:
        if not self._database_path.exists() and not self._database_path.is_symlink():
            return 0
        connection = self._open_database()
        try:
            reservations = int(
                connection.execute("SELECT COUNT(*) FROM replay_reservations").fetchone()[0]
            )
            legacy = int(
                connection.execute("SELECT COUNT(*) FROM legacy_replay_blockers").fetchone()[0]
            )
            return reservations + legacy
        except sqlite3.Error as exc:
            raise _sqlite_error("record count", exc) from exc
        finally:
            connection.close()

    def provider_count(self) -> int:
        if not self._database_path.exists() and not self._database_path.is_symlink():
            return 0
        connection = self._open_database()
        try:
            row = connection.execute(
                """
                SELECT COUNT(*) FROM (
                    SELECT provider FROM replay_reservations
                    UNION
                    SELECT provider FROM legacy_replay_blockers
                )
                """
            ).fetchone()
            return int(row[0])
        except sqlite3.Error as exc:
            raise _sqlite_error("provider count", exc) from exc
        finally:
            connection.close()

    def is_empty(self) -> bool:
        if self._root_dir.is_symlink() or self._database_path.is_symlink():
            return False
        if not self._root_dir.exists():
            return True
        legacy_files = tuple(self._root_dir.glob("*.state.json")) + tuple(
            self._root_dir.glob("*.state.journal")
        )
        if legacy_files:
            return False
        if not self._database_path.exists():
            return True
        try:
            return self.record_count() == 0
        except ChannelReplayStateError:
            return False

    def reset(self) -> dict[str, int]:
        """Clear the replay domain for the explicit test-only daemon reset."""

        self._prepare_root()
        records = 0
        providers = 0
        with contextlib.suppress(ChannelReplayStateError):
            records = self.record_count()
            providers = self.provider_count()
        files = 0
        if self._root_dir.exists():
            try:
                for child in tuple(self._root_dir.iterdir()):
                    files += 1
                    if child.is_dir() and not child.is_symlink():
                        shutil.rmtree(child)
                    else:
                        child.unlink()
            except OSError as exc:
                raise ChannelReplayStateError(
                    f"Channel replay reset failed: {exc.__class__.__name__}."
                ) from exc
        if not self.is_empty():
            raise ChannelReplayStateError("Channel replay reset did not leave empty state.")
        return {"records": records, "providers": providers, "files": files}

    def _mark_state(
        self,
        identity: ReplayIdentity,
        state: Literal["terminal", "uncertain"],
    ) -> None:
        connection = self._open_database()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE replay_reservations SET state = ?, updated_at = ?
                WHERE provider = ? AND account_id = ? AND scope_id = ?
                  AND event_kind = ? AND event_id = ? AND state = 'reserved'
                """,
                (state, _utc_now(), *identity.key),
            )
            if cursor.rowcount != 1:
                existing = connection.execute(
                    """
                    SELECT state FROM replay_reservations
                    WHERE provider = ? AND account_id = ? AND scope_id = ?
                      AND event_kind = ? AND event_id = ?
                    """,
                    identity.key,
                ).fetchone()
                if existing is None:
                    raise ChannelReplayStateError(
                        "Replay state transition has no durable reservation."
                    )
                if str(existing[0]) != state:
                    raise ChannelReplayStateError(
                        f"Replay state cannot transition from {existing[0]} to {state}."
                    )
            connection.commit()
        except ChannelReplayStateError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            raise _sqlite_error(f"{state} update", exc) from exc
        finally:
            connection.close()

    def _prepare_root(self) -> None:
        try:
            if self._root_dir.is_symlink():
                raise ChannelReplayStateError("Unsafe symlink channel replay root.")
            self._root_dir.mkdir(parents=True, exist_ok=True)
            if not self._root_dir.is_dir():
                raise ChannelReplayStateError("Channel replay root is not a directory.")
            if tighten_permissions(self._root_dir, 0o700) == "failed":
                raise ChannelReplayStateError("Channel replay root permissions could not be set.")
            if (self._database_path.exists() or self._database_path.is_symlink()) and (
                self._database_path.is_symlink() or not self._database_path.is_file()
            ):
                raise ChannelReplayStateError("Unsafe channel replay database path.")
        except OSError as exc:
            raise ChannelReplayStateError(
                f"Channel replay root preparation failed: {exc.__class__.__name__}."
            ) from exc

    def _open_database(self) -> sqlite3.Connection:
        self._prepare_root()
        first_create = not self._database_path.exists()
        try:
            connection = sqlite3.connect(self._database_path, timeout=5.0)
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA synchronous = FULL")
            if tighten_permissions(self._database_path, 0o600) == "failed":
                raise ChannelReplayStateError(
                    "Channel replay database permissions could not be set."
                )
            self._initialize_schema(connection, allow_create=first_create)
            if first_create:
                sync_parent_directory(self._root_dir)
            return connection
        except ChannelReplayStateError:
            if "connection" in locals():
                connection.close()
            raise
        except (OSError, sqlite3.Error) as exc:
            if "connection" in locals():
                connection.close()
            raise _sqlite_error("open", exc) from exc

    def _initialize_schema(
        self,
        connection: sqlite3.Connection,
        *,
        allow_create: bool,
    ) -> None:
        try:
            connection.execute("BEGIN IMMEDIATE")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version == 0:
                if not allow_create:
                    raise ChannelReplayStateError(
                        "Unsupported unversioned channel replay database schema."
                    )
                existing = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    ).fetchall()
                    if not str(row[0]).startswith("sqlite_")
                }
                if existing:
                    raise ChannelReplayStateError(
                        "Unsupported unversioned channel replay database schema."
                    )
                connection.execute(
                    """
                    CREATE TABLE replay_reservations (
                        provider TEXT NOT NULL CHECK(length(trim(provider)) > 0),
                        account_id TEXT NOT NULL CHECK(length(trim(account_id)) > 0),
                        scope_id TEXT NOT NULL CHECK(length(trim(scope_id)) > 0),
                        event_kind TEXT NOT NULL CHECK(length(trim(event_kind)) > 0),
                        event_id TEXT NOT NULL CHECK(length(trim(event_id)) > 0),
                        state TEXT NOT NULL
                            CHECK(state IN ('reserved', 'terminal', 'uncertain')),
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        PRIMARY KEY (
                            provider, account_id, scope_id, event_kind, event_id
                        )
                    ) WITHOUT ROWID
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE legacy_replay_blockers (
                        provider TEXT NOT NULL,
                        event_id TEXT NOT NULL,
                        imported_at TEXT NOT NULL,
                        PRIMARY KEY (provider, event_id)
                    ) WITHOUT ROWID
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE legacy_replay_imports (
                        provider TEXT PRIMARY KEY,
                        imported_at TEXT NOT NULL
                    ) WITHOUT ROWID
                    """
                )
                connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            elif version != _SCHEMA_VERSION:
                raise ChannelReplayStateError(
                    f"Unsupported channel replay database schema version {version}."
                )
            self._validate_schema(connection)
            connection.commit()
        except ChannelReplayStateError:
            connection.rollback()
            raise
        except sqlite3.DatabaseError as exc:
            connection.rollback()
            raise _sqlite_error("schema validation", exc) from exc

    @staticmethod
    def _validate_schema(connection: sqlite3.Connection) -> None:
        objects = {
            (str(row[0]), str(row[1]))
            for row in connection.execute("SELECT type, name FROM sqlite_master").fetchall()
            if not str(row[1]).startswith("sqlite_")
        }
        expected_objects = {
            ("table", "replay_reservations"),
            ("table", "legacy_replay_blockers"),
            ("table", "legacy_replay_imports"),
        }
        if objects != expected_objects:
            raise ChannelReplayStateError("Unsupported channel replay database schema.")
        expected_columns = {
            "replay_reservations": [
                ("provider", "TEXT", 1, 1),
                ("account_id", "TEXT", 1, 2),
                ("scope_id", "TEXT", 1, 3),
                ("event_kind", "TEXT", 1, 4),
                ("event_id", "TEXT", 1, 5),
                ("state", "TEXT", 1, 0),
                ("created_at", "TEXT", 1, 0),
                ("updated_at", "TEXT", 1, 0),
            ],
            "legacy_replay_blockers": [
                ("provider", "TEXT", 1, 1),
                ("event_id", "TEXT", 1, 2),
                ("imported_at", "TEXT", 1, 0),
            ],
            "legacy_replay_imports": [
                ("provider", "TEXT", 1, 1),
                ("imported_at", "TEXT", 1, 0),
            ],
        }
        for table, expected in expected_columns.items():
            columns = connection.execute(f"PRAGMA table_info({table})").fetchall()
            actual = [
                (str(row[1]), str(row[2]).upper(), int(row[3]), int(row[5])) for row in columns
            ]
            if actual != expected:
                raise ChannelReplayStateError(f"Corrupt channel replay {table} schema.")
        integrity = connection.execute("PRAGMA quick_check").fetchall()
        if integrity != [("ok",)]:
            raise ChannelReplayStateError("Corrupt channel replay database integrity check.")

    def _import_legacy_for_provider(
        self,
        connection: sqlite3.Connection,
        provider: str,
    ) -> None:
        imported = connection.execute(
            "SELECT 1 FROM legacy_replay_imports WHERE provider = ?",
            (provider,),
        ).fetchone()
        if imported is not None:
            return

        if provider not in {"discord", "matrix", "slack", "telegram"}:
            connection.execute(
                "INSERT INTO legacy_replay_imports(provider, imported_at) VALUES (?, ?)",
                (provider, _utc_now()),
            )
            return

        snapshot_path = self._legacy_path(provider, ".state.json")
        journal_path = self._legacy_path(provider, ".state.journal")
        ids: set[str] = set()
        if snapshot_path.exists() or snapshot_path.is_symlink():
            ids.update(self._read_legacy_snapshot(snapshot_path, provider))
        if journal_path.exists() or journal_path.is_symlink():
            ids.update(self._read_legacy_journal(journal_path))
        timestamp = _utc_now()
        connection.executemany(
            """
            INSERT OR IGNORE INTO legacy_replay_blockers(provider, event_id, imported_at)
            VALUES (?, ?, ?)
            """,
            [(provider, event_id, timestamp) for event_id in sorted(ids)],
        )
        connection.execute(
            "INSERT INTO legacy_replay_imports(provider, imported_at) VALUES (?, ?)",
            (provider, timestamp),
        )

    def _legacy_path(self, provider: str, suffix: str) -> Path:
        return self._root_dir / f"{provider}{suffix}"

    @staticmethod
    def _read_legacy_snapshot(path: Path, provider: str) -> set[str]:
        _require_regular_legacy_file(path)
        try:
            payload = json.loads(
                path.read_text(encoding="utf-8"),
                object_pairs_hook=_reject_duplicate_json_members,
            )
        except (OSError, UnicodeError, ValueError) as exc:
            raise ChannelReplayStateError(
                f"Malformed legacy replay snapshot for {provider}."
            ) from exc
        if not isinstance(payload, dict) or set(payload) != {"channel", "seen_message_ids"}:
            raise ChannelReplayStateError(f"Malformed legacy replay snapshot for {provider}.")
        if payload.get("channel") != provider or not isinstance(
            payload.get("seen_message_ids"), list
        ):
            raise ChannelReplayStateError(f"Ambiguous legacy replay snapshot for {provider}.")
        return _normalize_legacy_ids(payload["seen_message_ids"], source="snapshot")

    @staticmethod
    def _read_legacy_journal(path: Path) -> set[str]:
        _require_regular_legacy_file(path)
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise ChannelReplayStateError("Malformed legacy replay journal.") from exc
        if raw and not raw.endswith("\n"):
            raise ChannelReplayStateError("Truncated legacy replay journal.")
        ids: list[str] = []
        for line in raw.splitlines():
            token = line.strip()
            if not token:
                raise ChannelReplayStateError("Malformed legacy replay journal blank entry.")
            if token.startswith('"'):
                try:
                    candidate = json.loads(token)
                except json.JSONDecodeError as exc:
                    raise ChannelReplayStateError("Malformed legacy replay journal JSON.") from exc
                if not isinstance(candidate, str):
                    raise ChannelReplayStateError("Malformed legacy replay journal value.")
            else:
                candidate = token
            ids.append(candidate)
        return _normalize_legacy_ids(ids, source="journal")


def _normalize_legacy_ids(values: object, *, source: str) -> set[str]:
    if not isinstance(values, list):
        raise ChannelReplayStateError(f"Malformed legacy replay {source} IDs.")
    normalized: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise ChannelReplayStateError(f"Malformed legacy replay {source} ID.")
        normalized.add(value.strip())
    return normalized


def _require_regular_legacy_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ChannelReplayStateError("Unsafe legacy channel replay state path.")


def _reject_duplicate_json_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError(f"duplicate JSON member: {key}")
        payload[key] = value
    return payload


def _sqlite_error(action: str, exc: BaseException) -> ChannelReplayStateError:
    detail = str(exc).lower()
    kind = "corrupt " if "malformed" in detail or "not a database" in detail else ""
    return ChannelReplayStateError(
        f"Channel replay {action} failed for {kind}database: {exc.__class__.__name__}."
    )


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()
