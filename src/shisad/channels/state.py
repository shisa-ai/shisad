"""Persisted replay-guard state for channel ingress."""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import stat
from collections import deque
from enum import StrEnum
from pathlib import Path
from threading import RLock
from typing import Any

from shisad.core.atomic_state import (
    AtomicWriteError,
    AtomicWriteFaultInjector,
    DurableAppendError,
    DurableAppendFaultInjector,
    DurableAppendStage,
    StateLoadResult,
    StateLoadStatus,
    StatePersistenceDegradedError,
    atomic_write_bytes,
    decode_versioned_json_snapshot,
    durable_append_bytes,
    encode_versioned_json_snapshot,
)

logger = logging.getLogger(__name__)


class ReplayOutcome(StrEnum):
    """Durable ingress outcomes that must never become fresh automatically."""

    RESERVED = "reserved"
    TERMINAL = "terminal"
    UNCERTAIN = "uncertain"


class ChannelStateStore:
    """Stores authoritative channel replay state under ``SHISAD_DATA_DIR``."""

    _SCHEMA_VERSION = 1

    def __init__(
        self,
        root_dir: Path,
        *,
        max_seen_ids: int = 2048,
        journal_compact_every: int = 256,
    ) -> None:
        self._root_dir = Path(root_dir)
        self._max_seen_ids = max(max_seen_ids, 32)
        self._journal_compact_every = max(journal_compact_every, 1)
        self._records: dict[str, dict[str, ReplayOutcome]] = {}
        self._seen_ids: dict[str, deque[str]] = {}
        self._seen_id_sets: dict[str, set[str]] = {}
        self._journal_appends_since_compaction: dict[str, int] = {}
        self._compaction_warning_logged: set[str] = set()
        self._loaded_channels: set[str] = set()
        self._load_results: dict[str, StateLoadResult] = {}
        self._degradation: dict[str, dict[str, str]] = {}
        self._lock = RLock()
        self._append_fault_injector: DurableAppendFaultInjector | None = None
        self._snapshot_fault_injector: AtomicWriteFaultInjector | None = None
        self._truncate_fault_injector: AtomicWriteFaultInjector | None = None

    def has_seen(self, *, channel: str, message_id: str) -> bool:
        with self._lock:
            msg_id = self._normalize_message_id(message_id)
            if msg_id is None:
                return False
            self._ensure_loaded(channel)
            self._raise_if_degraded(channel)
            return msg_id in self._records[channel]

    def mark_seen(self, *, channel: str, message_id: str) -> None:
        """Compatibility helper that records a completed ingress durably."""

        with self._lock:
            msg_id = self._normalize_message_id(message_id)
            if msg_id is None:
                return
            if self.reserve(channel=channel, message_id=msg_id):
                return
            self.mark_terminal(channel=channel, message_id=msg_id)

    def is_replay(self, *, channel: str, message_id: str) -> bool:
        with self._lock:
            msg_id = self._normalize_message_id(message_id)
            if msg_id is None:
                return False
            if self.reserve(channel=channel, message_id=msg_id):
                return True
            self.mark_terminal(channel=channel, message_id=msg_id)
            return False

    def reserve(self, *, channel: str, message_id: str) -> bool:
        """Durably reserve a fresh identity before dispatch.

        Returns ``True`` when the identity is already known and therefore must
        not be dispatched. Any persistence uncertainty degrades the channel and
        raises instead of granting fresh admission.
        """

        with self._lock:
            msg_id = self._required_message_id(message_id)
            self._ensure_loaded(channel)
            self._raise_if_degraded(channel)
            if msg_id in self._records[channel]:
                return True
            try:
                self._append_journal_entry(channel, msg_id, ReplayOutcome.RESERVED)
            except DurableAppendError as exc:
                self._degrade(
                    channel,
                    transition="reserve",
                    stage=exc.stage.value,
                    reason=(
                        "reservation_commit_uncertain"
                        if exc.publication_may_have_committed
                        else "reservation_not_committed"
                    ),
                )
                self._raise_if_degraded(channel)
            self._records[channel][msg_id] = ReplayOutcome.RESERVED
            self._record_recent_id(channel, msg_id)
            self._after_journal_append(channel)
            return False

    def mark_terminal(self, *, channel: str, message_id: str) -> None:
        """Durably mark a reserved ingress as having a terminal handler result."""

        with self._lock:
            self._record_outcome(channel, message_id, ReplayOutcome.TERMINAL)

    def mark_uncertain(self, *, channel: str, message_id: str) -> None:
        """Durably retain an ingress whose handler/effect outcome is uncertain."""

        with self._lock:
            self._record_outcome(channel, message_id, ReplayOutcome.UNCERTAIN)

    def outcome(self, *, channel: str, message_id: str) -> ReplayOutcome | None:
        with self._lock:
            msg_id = self._normalize_message_id(message_id)
            if msg_id is None:
                return None
            self._ensure_loaded(channel)
            return self._records[channel].get(msg_id)

    def state_load_result(self, channel: str) -> StateLoadResult:
        with self._lock:
            self._ensure_loaded(channel)
            return self._load_results[channel]

    def state_status(self, channel: str) -> dict[str, Any]:
        with self._lock:
            self._ensure_loaded(channel)
            degradation = self._degradation.get(channel)
            load_result = self._load_results[channel]
            if degradation is not None:
                return {"status": "degraded", **degradation}
            return {
                "status": load_result.status.value,
                "reason": load_result.reason,
                "stage": "load",
                "transition": "load",
            }

    def snapshot(self, channel: str) -> dict[str, Any]:
        with self._lock:
            self._ensure_loaded(channel)
            self._raise_if_degraded(channel)
            ids = list(self._seen_ids[channel])
            outcomes = self._records[channel]
            return {
                "channel": channel,
                "seen_message_ids": ids,
                "seen_count": len(ids),
                "authoritative_count": len(outcomes),
                "outcome_counts": {
                    outcome.value: sum(1 for value in outcomes.values() if value == outcome)
                    for outcome in ReplayOutcome
                },
                "max_seen_ids": self._max_seen_ids,
            }

    @property
    def root_dir(self) -> Path:
        return self._root_dir

    @property
    def loaded_channel_count(self) -> int:
        with self._lock:
            return len(self._loaded_channels)

    def clear_runtime_cache(self) -> None:
        """Forget loaded state after the caller has durably reset its files."""

        with self._lock:
            self._records.clear()
            self._seen_ids.clear()
            self._seen_id_sets.clear()
            self._journal_appends_since_compaction.clear()
            self._compaction_warning_logged.clear()
            self._loaded_channels.clear()
            self._load_results.clear()
            self._degradation.clear()

    def runtime_cache_empty(self) -> bool:
        with self._lock:
            return not (
                self._records
                or self._seen_ids
                or self._seen_id_sets
                or self._loaded_channels
                or self._degradation
            )

    def _record_outcome(
        self,
        channel: str,
        message_id: str,
        outcome: ReplayOutcome,
    ) -> None:
        msg_id = self._required_message_id(message_id)
        self._ensure_loaded(channel)
        self._raise_if_degraded(channel)
        if msg_id not in self._records[channel]:
            raise ValueError("replay outcome requires a durable reservation")
        if self._records[channel][msg_id] == outcome:
            return
        try:
            self._append_journal_entry(channel, msg_id, outcome)
        except DurableAppendError as exc:
            self._records[channel][msg_id] = ReplayOutcome.UNCERTAIN
            self._degrade(
                channel,
                transition=outcome.value,
                stage=exc.stage.value,
                reason=(
                    "outcome_commit_uncertain"
                    if exc.publication_may_have_committed
                    else "outcome_not_committed"
                ),
            )
            self._raise_if_degraded(channel)
        self._records[channel][msg_id] = outcome
        self._record_recent_id(channel, msg_id)
        self._after_journal_append(channel)

    def _ensure_loaded(self, channel: str) -> None:
        if channel in self._loaded_channels:
            return
        records: dict[str, ReplayOutcome] = {}
        recent: deque[str] = deque()
        recent_set: set[str] = set()

        root_result = self._validate_existing_root()
        if root_result.status not in {StateLoadStatus.OK, StateLoadStatus.MISSING}:
            self._publish_loaded_channel(
                channel,
                records=records,
                recent=recent,
                recent_set=recent_set,
                journal_lines=0,
                load_result=root_result,
            )
            self._degrade(
                channel,
                transition="load",
                stage="load",
                reason=root_result.reason or root_result.status.value,
            )
            return

        snapshot_result, snapshot_rows, snapshot_recent = self._load_snapshot(
            self._state_path(channel),
            channel=channel,
        )
        journal_result, journal_rows = self._load_journal(
            self._journal_path(channel),
            channel=channel,
        )
        load_result = self._combine_load_results(snapshot_result, journal_result)
        if load_result.status in {StateLoadStatus.OK, StateLoadStatus.MISSING}:
            for message_id, outcome in snapshot_rows:
                records[message_id] = outcome
            for message_id in snapshot_recent:
                self._record_recent_value(recent, recent_set, message_id)
            for message_id, outcome in journal_rows:
                records[message_id] = outcome
                self._record_recent_value(recent, recent_set, message_id)

        self._publish_loaded_channel(
            channel,
            records=records,
            recent=recent,
            recent_set=recent_set,
            journal_lines=len(journal_rows),
            load_result=load_result,
        )
        if load_result.status not in {StateLoadStatus.OK, StateLoadStatus.MISSING}:
            self._degrade(
                channel,
                transition="load",
                stage="load",
                reason=load_result.reason or load_result.status.value,
            )
            return
        if len(journal_rows) >= self._journal_compact_every:
            self._attempt_compaction(channel, trigger="load")

    def _publish_loaded_channel(
        self,
        channel: str,
        *,
        records: dict[str, ReplayOutcome],
        recent: deque[str],
        recent_set: set[str],
        journal_lines: int,
        load_result: StateLoadResult,
    ) -> None:
        self._records[channel] = records
        self._seen_ids[channel] = recent
        self._seen_id_sets[channel] = recent_set
        self._journal_appends_since_compaction[channel] = journal_lines
        self._load_results[channel] = load_result
        self._loaded_channels.add(channel)

    def _load_snapshot(
        self,
        path: Path,
        *,
        channel: str,
    ) -> tuple[StateLoadResult, list[tuple[str, ReplayOutcome]], list[str]]:
        file_result, raw = self._read_private_bytes(path)
        if file_result.status != StateLoadStatus.OK or raw is None:
            return file_result, [], []
        decoded, payload = decode_versioned_json_snapshot(
            raw,
            supported_version=self._SCHEMA_VERSION,
        )
        if decoded.status == StateLoadStatus.OK:
            parsed = self._parse_snapshot_payload(payload, channel=channel)
            if parsed is None:
                return (
                    StateLoadResult(StateLoadStatus.CORRUPT, reason="invalid_snapshot_payload"),
                    [],
                    [],
                )
            rows, recent = parsed
            return decoded, rows, recent

        legacy = self._parse_legacy_snapshot(raw, channel=channel)
        if legacy is not None:
            return (
                StateLoadResult(StateLoadStatus.OK, legacy=True),
                [(message_id, ReplayOutcome.TERMINAL) for message_id in legacy],
                legacy,
            )
        return decoded, [], []

    def _load_journal(
        self,
        path: Path,
        *,
        channel: str,
    ) -> tuple[StateLoadResult, list[tuple[str, ReplayOutcome]]]:
        file_result, raw = self._read_private_bytes(path)
        if file_result.status != StateLoadStatus.OK or raw is None:
            return file_result, []
        if not raw:
            return StateLoadResult(StateLoadStatus.OK), []
        if not raw.endswith(b"\n"):
            return StateLoadResult(StateLoadStatus.CORRUPT, reason="truncated_journal"), []
        rows: list[tuple[str, ReplayOutcome]] = []
        legacy = False
        for raw_line in raw.splitlines():
            if not raw_line.strip():
                continue
            line = raw_line.strip()
            if line.startswith(b"{"):
                decoded, payload = decode_versioned_json_snapshot(
                    line,
                    supported_version=self._SCHEMA_VERSION,
                )
                if decoded.status != StateLoadStatus.OK:
                    return decoded, []
                parsed = self._parse_journal_payload(payload, channel=channel)
                if parsed is None:
                    return (
                        StateLoadResult(
                            StateLoadStatus.CORRUPT,
                            reason="invalid_journal_payload",
                        ),
                        [],
                    )
                rows.append(parsed)
                continue
            legacy_value = self._parse_legacy_journal_line(line)
            if legacy_value is None:
                return StateLoadResult(StateLoadStatus.CORRUPT, reason="invalid_journal"), []
            rows.append((legacy_value, ReplayOutcome.TERMINAL))
            legacy = True
        return StateLoadResult(StateLoadStatus.OK, legacy=legacy), rows

    def _parse_snapshot_payload(
        self,
        payload: Any,
        *,
        channel: str,
    ) -> tuple[list[tuple[str, ReplayOutcome]], list[str]] | None:
        if not isinstance(payload, dict) or payload.get("channel") != channel:
            return None
        raw_records = payload.get("records")
        raw_recent = payload.get("recent_message_ids")
        if not isinstance(raw_records, list) or not isinstance(raw_recent, list):
            return None
        records: list[tuple[str, ReplayOutcome]] = []
        for row in raw_records:
            parsed = self._parse_journal_payload(row, channel=channel)
            if parsed is None:
                return None
            records.append(parsed)
        recent: list[str] = []
        for value in raw_recent:
            if not isinstance(value, str):
                return None
            normalized = self._normalize_message_id(value)
            if normalized is None:
                return None
            recent.append(normalized)
        return records, recent

    def _parse_journal_payload(
        self,
        payload: Any,
        *,
        channel: str,
    ) -> tuple[str, ReplayOutcome] | None:
        if not isinstance(payload, dict) or payload.get("channel") != channel:
            return None
        raw_message_id = payload.get("message_id")
        raw_outcome = payload.get("outcome")
        if not isinstance(raw_message_id, str) or not isinstance(raw_outcome, str):
            return None
        message_id = self._normalize_message_id(raw_message_id)
        if message_id is None:
            return None
        with contextlib.suppress(ValueError):
            return message_id, ReplayOutcome(raw_outcome)
        return None

    def _parse_legacy_snapshot(self, raw: bytes, *, channel: str) -> list[str] | None:
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError, RecursionError):
            return None
        if not isinstance(payload, dict) or payload.get("channel") != channel:
            return None
        raw_ids = payload.get("seen_message_ids")
        if not isinstance(raw_ids, list):
            return None
        normalized: list[str] = []
        for item in raw_ids:
            if not isinstance(item, str):
                return None
            value = self._normalize_message_id(item)
            if value is None:
                return None
            normalized.append(value)
        return normalized

    def _parse_legacy_journal_line(self, line: bytes) -> str | None:
        try:
            token = line.decode("utf-8")
        except UnicodeError:
            return None
        candidate: Any = token
        if token.startswith('"'):
            try:
                candidate = json.loads(token)
            except json.JSONDecodeError:
                return None
        if not isinstance(candidate, str):
            return None
        return self._normalize_message_id(candidate)

    def _read_private_bytes(self, path: Path) -> tuple[StateLoadResult, bytes | None]:
        try:
            path_stat = path.lstat()
        except FileNotFoundError:
            return StateLoadResult(StateLoadStatus.MISSING), None
        except OSError:
            return StateLoadResult(StateLoadStatus.CORRUPT, reason="state_lstat_failed"), None
        if not stat.S_ISREG(path_stat.st_mode):
            return StateLoadResult(StateLoadStatus.CORRUPT, reason="state_not_regular"), None
        if hasattr(os, "getuid") and path_stat.st_uid != os.getuid():
            return StateLoadResult(StateLoadStatus.CORRUPT, reason="state_wrong_owner"), None
        fd = -1
        try:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags)
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                path_stat.st_dev,
                path_stat.st_ino,
            ):
                raise OSError("replay state identity changed during open")
            os.fchmod(fd, 0o600)
            chunks: list[bytes] = []
            while True:
                chunk = os.read(fd, 64 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            return StateLoadResult(StateLoadStatus.OK), b"".join(chunks)
        except OSError:
            return StateLoadResult(StateLoadStatus.CORRUPT, reason="state_read_failed"), None
        finally:
            if fd >= 0:
                with contextlib.suppress(OSError):
                    os.close(fd)

    def _validate_existing_root(self) -> StateLoadResult:
        try:
            root_stat = self._root_dir.lstat()
        except FileNotFoundError:
            return StateLoadResult(StateLoadStatus.MISSING)
        except OSError:
            return StateLoadResult(StateLoadStatus.CORRUPT, reason="root_lstat_failed")
        if not stat.S_ISDIR(root_stat.st_mode):
            return StateLoadResult(StateLoadStatus.CORRUPT, reason="root_not_directory")
        if hasattr(os, "getuid") and root_stat.st_uid != os.getuid():
            return StateLoadResult(StateLoadStatus.CORRUPT, reason="root_wrong_owner")
        try:
            self._root_dir.chmod(0o700)
        except OSError:
            return StateLoadResult(StateLoadStatus.CORRUPT, reason="root_mode_failed")
        return StateLoadResult(StateLoadStatus.OK)

    def _ensure_root(self) -> None:
        root_result = self._validate_existing_root()
        if root_result.status == StateLoadStatus.OK:
            return
        if root_result.status != StateLoadStatus.MISSING:
            raise DurableAppendError(
                path=self._root_dir,
                stage=DurableAppendStage.DIRECTORY_PREPARE,
                publication_may_have_committed=False,
            )
        try:
            self._root_dir.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            self._root_dir.mkdir(mode=0o700)
            self._root_dir.chmod(0o700)
            self._fsync_directory(self._root_dir.parent)
        except OSError as exc:
            raise DurableAppendError(
                path=self._root_dir,
                stage=DurableAppendStage.DIRECTORY_PREPARE,
                publication_may_have_committed=False,
            ) from exc

    def _append_journal_entry(
        self,
        channel: str,
        message_id: str,
        outcome: ReplayOutcome,
    ) -> None:
        self._ensure_root()
        payload = {
            "channel": channel,
            "message_id": message_id,
            "outcome": outcome.value,
        }
        envelope = json.loads(
            encode_versioned_json_snapshot(
                payload,
                version=self._SCHEMA_VERSION,
            )
        )
        encoded = (
            json.dumps(
                envelope,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
        durable_append_bytes(
            self._journal_path(channel),
            encoded,
            fault_injector=self._append_fault_injector,
        )

    def _after_journal_append(self, channel: str) -> None:
        appended = self._journal_appends_since_compaction.get(channel, 0) + 1
        self._journal_appends_since_compaction[channel] = appended
        if appended >= self._journal_compact_every:
            self._attempt_compaction(channel, trigger="append")

    def _attempt_compaction(self, channel: str, *, trigger: str) -> bool:
        try:
            self._compact_channel(channel)
        except (AtomicWriteError, OSError) as exc:
            if channel not in self._compaction_warning_logged:
                logger.warning(
                    "Channel replay-state compaction failed; retaining journal authority "
                    "(channel=%s, trigger=%s, error=%s)",
                    channel,
                    trigger,
                    exc.__class__.__name__,
                )
                self._compaction_warning_logged.add(channel)
            return False
        self._compaction_warning_logged.discard(channel)
        self._journal_appends_since_compaction[channel] = 0
        return True

    def _compact_channel(self, channel: str) -> None:
        self._persist_snapshot(channel)
        self._truncate_journal(channel)

    def _persist_snapshot(self, channel: str) -> None:
        records = self._records.get(channel)
        recent = self._seen_ids.get(channel)
        if records is None or recent is None:
            return
        payload = {
            "channel": channel,
            "records": [
                {
                    "channel": channel,
                    "message_id": message_id,
                    "outcome": outcome.value,
                }
                for message_id, outcome in records.items()
            ],
            "recent_message_ids": list(recent),
        }
        atomic_write_bytes(
            self._state_path(channel),
            encode_versioned_json_snapshot(payload, version=self._SCHEMA_VERSION),
            fault_injector=self._snapshot_fault_injector,
        )

    def _truncate_journal(self, channel: str) -> None:
        atomic_write_bytes(
            self._journal_path(channel),
            b"",
            fault_injector=self._truncate_fault_injector,
        )

    def _record_recent_id(self, channel: str, message_id: str) -> None:
        self._record_recent_value(
            self._seen_ids[channel],
            self._seen_id_sets[channel],
            message_id,
        )

    def _record_recent_value(
        self,
        ids: deque[str],
        id_set: set[str],
        message_id: str,
    ) -> None:
        if message_id in id_set:
            return
        ids.append(message_id)
        id_set.add(message_id)
        while len(ids) > self._max_seen_ids:
            evicted = ids.popleft()
            id_set.discard(evicted)

    def _degrade(self, channel: str, *, transition: str, stage: str, reason: str) -> None:
        self._degradation[channel] = {
            "transition": transition,
            "stage": stage,
            "reason": reason,
        }

    def _raise_if_degraded(self, channel: str) -> None:
        degradation = self._degradation.get(channel)
        if degradation is None:
            return
        raise StatePersistenceDegradedError(
            authority=f"channel_replay:{channel}",
            transition=degradation["transition"],
            stage=degradation["stage"],
            reason=degradation["reason"],
        )

    def _state_path(self, channel: str) -> Path:
        return self._root_dir / f"{self._channel_file_stem(channel)}.state.json"

    def _journal_path(self, channel: str) -> Path:
        return self._root_dir / f"{self._channel_file_stem(channel)}.state.journal"

    def _channel_file_stem(self, channel: str) -> str:
        raw = channel if channel else "unknown"
        legacy = self._legacy_channel_file_stem(raw)
        if raw == legacy:
            return legacy
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
        return f"{legacy}-{digest}"

    @staticmethod
    def _legacy_channel_file_stem(channel: str) -> str:
        safe = "".join(ch for ch in channel if ch.isalnum() or ch in {"-", "_"}).strip("_-")
        return safe or "unknown"

    @staticmethod
    def _required_message_id(value: str) -> str:
        message_id = ChannelStateStore._normalize_message_id(value)
        if message_id is None:
            raise ValueError("replay message_id cannot be empty")
        return message_id

    @staticmethod
    def _normalize_message_id(value: str) -> str | None:
        message_id = value.strip()
        return message_id or None

    @staticmethod
    def _combine_load_results(
        snapshot: StateLoadResult,
        journal: StateLoadResult,
    ) -> StateLoadResult:
        for result in (snapshot, journal):
            if result.status == StateLoadStatus.UNSUPPORTED_SCHEMA:
                return result
        for result in (snapshot, journal):
            if result.status == StateLoadStatus.CORRUPT:
                return result
        if snapshot.status == StateLoadStatus.MISSING and journal.status == StateLoadStatus.MISSING:
            return StateLoadResult(StateLoadStatus.MISSING)
        return StateLoadResult(
            StateLoadStatus.OK,
            legacy=snapshot.legacy or journal.legacy,
        )

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path, flags)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
