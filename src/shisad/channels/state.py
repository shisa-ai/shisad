"""Persisted replay-guard state for channel ingress."""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import stat
from collections import deque
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from threading import RLock
from typing import Any

from pydantic import ValidationError

from shisad.channels.base import ReplayEventVariant, ReplayIdentity
from shisad.core.atomic_state import (
    AtomicWriteError,
    AtomicWriteFaultInjector,
    DurableAppendError,
    DurableAppendFaultInjector,
    StateLoadResult,
    StateLoadStatus,
    StatePersistenceDegradedError,
    atomic_write_bytes,
    atomic_write_bytes_with_identity,
    decode_versioned_json_snapshot,
    durable_append_bytes,
    encode_versioned_json_snapshot,
    ensure_owner_only_directory,
    read_owned_regular_file,
    read_owned_regular_file_with_identity,
    remove_owner_controlled_directory_contents,
    remove_owner_controlled_file_entries,
    validate_directory_ancestry,
)

logger = logging.getLogger(__name__)


class ReplayOutcome(StrEnum):
    """Durable ingress outcomes that must never become fresh automatically."""

    RESERVED = "reserved"
    TERMINAL = "terminal"
    UNCERTAIN = "uncertain"


@dataclass(frozen=True, slots=True)
class _ReplayRecord:
    identity: ReplayIdentity
    outcome: ReplayOutcome


class ChannelStateStore:
    """Stores authoritative channel replay state under ``SHISAD_DATA_DIR``."""

    _SCHEMA_VERSION = 2

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
        self._records: dict[str, dict[str, _ReplayRecord]] = {}
        self._legacy_message_ids: dict[str, set[str]] = {}
        self._seen_ids: dict[str, deque[str]] = {}
        self._seen_id_sets: dict[str, set[str]] = {}
        self._journal_appends_since_compaction: dict[str, int] = {}
        self._compaction_warning_logged: set[str] = set()
        self._loaded_channels: set[str] = set()
        self._load_results: dict[str, StateLoadResult] = {}
        self._degradation: dict[str, dict[str, str]] = {}
        self._loaded_root_identities: dict[str, tuple[int, int]] = {}
        self._journal_identities: dict[str, tuple[int, int]] = {}
        self._lock = RLock()
        self._append_fault_injector: DurableAppendFaultInjector | None = None
        self._snapshot_fault_injector: AtomicWriteFaultInjector | None = None
        self._truncate_fault_injector: AtomicWriteFaultInjector | None = None

    def has_seen(self, *, channel: str, message_id: str) -> bool:
        with self._lock:
            identity = self._optional_compatibility_identity(channel, message_id)
            if identity is None:
                return False
            channel = identity.provider
            self._ensure_loaded(channel)
            if self._is_known(channel, identity):
                return True
            self._raise_if_degraded(channel)
            return False

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

    def reserve(
        self,
        *,
        identity: ReplayIdentity | None = None,
        channel: str = "",
        message_id: str = "",
    ) -> bool:
        """Durably reserve a fresh identity before dispatch.

        Returns ``True`` when the identity is already known and therefore must
        not be dispatched. Any persistence uncertainty degrades the channel and
        raises instead of granting fresh admission.
        """

        with self._lock:
            resolved = self._resolve_identity(
                identity=identity,
                channel=channel,
                message_id=message_id,
            )
            channel = resolved.provider
            self._ensure_loaded(channel)
            if self._is_known(channel, resolved):
                return True
            self._raise_if_degraded(channel)
            try:
                self._append_journal_entry(channel, resolved, ReplayOutcome.RESERVED)
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
            key = self._identity_key(resolved)
            self._records[channel][key] = _ReplayRecord(resolved, ReplayOutcome.RESERVED)
            self._record_recent_id(channel, key)
            self._after_journal_append(channel)
            return False

    def mark_terminal(
        self,
        *,
        identity: ReplayIdentity | None = None,
        channel: str = "",
        message_id: str = "",
    ) -> None:
        """Durably mark a reserved ingress as having a terminal handler result."""

        with self._lock:
            self._record_outcome(
                self._resolve_identity(
                    identity=identity,
                    channel=channel,
                    message_id=message_id,
                ),
                ReplayOutcome.TERMINAL,
            )

    def mark_uncertain(
        self,
        *,
        identity: ReplayIdentity | None = None,
        channel: str = "",
        message_id: str = "",
    ) -> None:
        """Durably retain an ingress whose handler/effect outcome is uncertain."""

        with self._lock:
            self._record_outcome(
                self._resolve_identity(
                    identity=identity,
                    channel=channel,
                    message_id=message_id,
                ),
                ReplayOutcome.UNCERTAIN,
            )

    def outcome(
        self,
        *,
        identity: ReplayIdentity | None = None,
        channel: str = "",
        message_id: str = "",
    ) -> ReplayOutcome | None:
        with self._lock:
            try:
                resolved = self._resolve_identity(
                    identity=identity,
                    channel=channel,
                    message_id=message_id,
                )
            except ValueError:
                return None
            channel = resolved.provider
            self._ensure_loaded(channel)
            record = self._records[channel].get(self._identity_key(resolved))
            return record.outcome if record is not None else None

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
                status = {"status": "degraded", **degradation}
                if degradation["reason"] == "legacy_scope_ambiguous_rebaseline_required":
                    status["remediation"] = (
                        "shisad channel replay-rebaseline "
                        f"--channel {channel} --confirm"
                    )
                return status
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
            records = self._records[channel]
            return {
                "channel": channel,
                "recent_identity_keys": ids,
                "seen_count": len(ids),
                "authoritative_count": len(records) + len(self._legacy_message_ids[channel]),
                "outcome_counts": {
                    outcome.value: sum(
                        1 for record in records.values() if record.outcome == outcome
                    )
                    for outcome in ReplayOutcome
                },
                "legacy_ambiguous_count": len(self._legacy_message_ids[channel]),
                "max_seen_ids": self._max_seen_ids,
            }

    @property
    def root_dir(self) -> Path:
        return self._root_dir

    def reset_state(self) -> tuple[int, int]:
        """Serialize explicit test reset with all replay readers and writers."""

        with self._lock:
            channel_count = len(self._loaded_channels)
            file_count = remove_owner_controlled_directory_contents(
                self._root_dir,
                allow_nested_directories=False,
                unlink_non_directory=True,
            )
            self._clear_runtime_cache_locked()
            return channel_count, file_count

    def rebaseline(self, channel: str) -> int:
        """Explicitly discard one ambiguous replay scope after operator review."""

        with self._lock:
            self._ensure_loaded(channel)
            degradation = self._degradation.get(channel)
            if (
                degradation is None
                or degradation.get("reason")
                != "legacy_scope_ambiguous_rebaseline_required"
            ):
                raise ValueError(
                    "replay rebaseline is only available for ambiguous legacy state"
                )
            expected_root_identity = self._loaded_root_identities.get(channel)
            if expected_root_identity is None:
                self._degrade(
                    channel,
                    transition="rebaseline",
                    stage="directory_identity",
                    reason="rebaseline_root_identity_unavailable",
                )
                self._raise_if_degraded(channel)
            try:
                removed = remove_owner_controlled_file_entries(
                    self._root_dir,
                    (
                        self._state_path(channel).name,
                        self._journal_path(channel).name,
                    ),
                    expected_directory_identity=expected_root_identity,
                )
            except OSError:
                self._degrade(
                    channel,
                    transition="rebaseline",
                    stage="directory_identity",
                    reason="rebaseline_root_identity_changed",
                )
                self._raise_if_degraded(channel)
            self._clear_channel_cache_locked(channel)
            return removed

    def runtime_cache_empty(self) -> bool:
        with self._lock:
            return not (
                self._records
                or self._legacy_message_ids
                or self._seen_ids
                or self._seen_id_sets
                or self._loaded_channels
                or self._degradation
            )

    def _clear_runtime_cache_locked(self) -> None:
        self._records.clear()
        self._legacy_message_ids.clear()
        self._seen_ids.clear()
        self._seen_id_sets.clear()
        self._journal_appends_since_compaction.clear()
        self._compaction_warning_logged.clear()
        self._loaded_channels.clear()
        self._load_results.clear()
        self._degradation.clear()
        self._loaded_root_identities.clear()
        self._journal_identities.clear()

    def _clear_channel_cache_locked(self, channel: str) -> None:
        self._records.pop(channel, None)
        self._legacy_message_ids.pop(channel, None)
        self._seen_ids.pop(channel, None)
        self._seen_id_sets.pop(channel, None)
        self._journal_appends_since_compaction.pop(channel, None)
        self._compaction_warning_logged.discard(channel)
        self._loaded_channels.discard(channel)
        self._load_results.pop(channel, None)
        self._degradation.pop(channel, None)
        self._loaded_root_identities.pop(channel, None)
        self._journal_identities.pop(channel, None)

    def _record_outcome(
        self,
        identity: ReplayIdentity,
        outcome: ReplayOutcome,
    ) -> None:
        channel = identity.provider
        key = self._identity_key(identity)
        self._ensure_loaded(channel)
        self._raise_if_degraded(channel)
        if key not in self._records[channel]:
            raise ValueError("replay outcome requires a durable reservation")
        if self._records[channel][key].outcome == outcome:
            return
        try:
            self._append_journal_entry(channel, identity, outcome)
        except DurableAppendError as exc:
            self._records[channel][key] = _ReplayRecord(identity, ReplayOutcome.UNCERTAIN)
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
        self._records[channel][key] = _ReplayRecord(identity, outcome)
        self._record_recent_id(channel, key)
        self._after_journal_append(channel)

    def _ensure_loaded(self, channel: str) -> None:
        if channel in self._loaded_channels:
            return
        records: dict[str, _ReplayRecord] = {}
        legacy_message_ids: set[str] = set()
        recent: deque[str] = deque()
        recent_set: set[str] = set()

        root_result = self._validate_existing_root()
        if root_result.status not in {StateLoadStatus.OK, StateLoadStatus.MISSING}:
            self._publish_loaded_channel(
                channel,
                records=records,
                legacy_message_ids=legacy_message_ids,
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

        snapshot_result, snapshot_rows, snapshot_recent, snapshot_legacy = self._load_snapshot(
            self._state_path(channel),
            channel=channel,
        )
        journal_result, journal_rows, journal_legacy, journal_identity = self._load_journal(
            self._journal_path(channel),
            channel=channel,
        )
        load_result = self._combine_load_results(snapshot_result, journal_result)
        if load_result.status in {StateLoadStatus.OK, StateLoadStatus.MISSING}:
            for record in snapshot_rows:
                records[self._identity_key(record.identity)] = record
            for key in snapshot_recent:
                self._record_recent_value(recent, recent_set, key)
            for record in journal_rows:
                key = self._identity_key(record.identity)
                records[key] = record
                self._record_recent_value(recent, recent_set, key)
            legacy_message_ids.update(snapshot_legacy)
            legacy_message_ids.update(journal_legacy)

        self._publish_loaded_channel(
            channel,
            records=records,
            legacy_message_ids=legacy_message_ids,
            recent=recent,
            recent_set=recent_set,
            journal_lines=len(journal_rows),
            load_result=load_result,
            journal_identity=journal_identity,
        )
        if load_result.status not in {StateLoadStatus.OK, StateLoadStatus.MISSING}:
            self._degrade(
                channel,
                transition="load",
                stage="load",
                reason=load_result.reason or load_result.status.value,
            )
            return
        if load_result.legacy:
            self._degrade(
                channel,
                transition="load",
                stage="migration",
                reason="legacy_scope_ambiguous_rebaseline_required",
            )
            return
        if len(journal_rows) >= self._journal_compact_every:
            self._attempt_compaction(channel, trigger="load")

    def _publish_loaded_channel(
        self,
        channel: str,
        *,
        records: dict[str, _ReplayRecord],
        legacy_message_ids: set[str],
        recent: deque[str],
        recent_set: set[str],
        journal_lines: int,
        load_result: StateLoadResult,
        journal_identity: tuple[int, int] | None = None,
    ) -> None:
        self._records[channel] = records
        self._legacy_message_ids[channel] = legacy_message_ids
        self._seen_ids[channel] = recent
        self._seen_id_sets[channel] = recent_set
        self._journal_appends_since_compaction[channel] = journal_lines
        self._load_results[channel] = load_result
        self._loaded_channels.add(channel)
        if journal_identity is not None:
            self._journal_identities[channel] = journal_identity
        if self._root_dir.exists():
            root_stat = self._root_dir.stat(follow_symlinks=False)
            self._loaded_root_identities[channel] = (root_stat.st_dev, root_stat.st_ino)

    def _load_snapshot(
        self,
        path: Path,
        *,
        channel: str,
    ) -> tuple[StateLoadResult, list[_ReplayRecord], list[str], set[str]]:
        file_result, raw = self._read_private_bytes(path)
        if file_result.status != StateLoadStatus.OK or raw is None:
            return file_result, [], [], set()
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
                    set(),
                )
            rows, recent = parsed
            return decoded, rows, recent, set()

        if self._is_envelope_candidate(raw):
            if (
                decoded.status == StateLoadStatus.UNSUPPORTED_SCHEMA
                and decoded.schema_version == 1
            ):
                old_decoded, old_payload = decode_versioned_json_snapshot(
                    raw,
                    supported_version=1,
                )
                legacy = self._parse_v1_snapshot_payload(old_payload, channel=channel)
                if old_decoded.status == StateLoadStatus.OK and legacy is not None:
                    return (
                        StateLoadResult(
                            StateLoadStatus.OK,
                            schema_version=1,
                            legacy=True,
                        ),
                        [],
                        [],
                        legacy,
                    )
                if old_decoded.status != StateLoadStatus.OK:
                    return old_decoded, [], [], set()
                return (
                    StateLoadResult(StateLoadStatus.CORRUPT, reason="invalid_v1_snapshot"),
                    [],
                    [],
                    set(),
                )
            return decoded, [], [], set()
        unversioned_legacy = self._parse_legacy_snapshot(raw, channel=channel)
        if unversioned_legacy is not None:
            return (
                StateLoadResult(StateLoadStatus.OK, legacy=True),
                [],
                [],
                set(unversioned_legacy),
            )
        return decoded, [], [], set()

    def _load_journal(
        self,
        path: Path,
        *,
        channel: str,
    ) -> tuple[StateLoadResult, list[_ReplayRecord], set[str], tuple[int, int] | None]:
        file_result, raw, file_identity = self._read_private_bytes_with_identity(path)
        if file_result.status != StateLoadStatus.OK or raw is None:
            return file_result, [], set(), file_identity
        if not raw:
            return StateLoadResult(StateLoadStatus.OK), [], set(), file_identity
        if not raw.endswith(b"\n"):
            return (
                StateLoadResult(StateLoadStatus.CORRUPT, reason="truncated_journal"),
                [],
                set(),
                file_identity,
            )
        rows: list[_ReplayRecord] = []
        legacy_message_ids: set[str] = set()
        for line_number, raw_line in enumerate(raw.splitlines(), start=1):
            if not raw_line.strip():
                return (
                    StateLoadResult(
                        StateLoadStatus.CORRUPT,
                        reason=f"blank_journal_row:{line_number}",
                    ),
                    [],
                    set(),
                    file_identity,
                )
            line = raw_line.strip()
            if line.startswith(b"{"):
                decoded, payload = decode_versioned_json_snapshot(
                    line,
                    supported_version=self._SCHEMA_VERSION,
                )
                if (
                    decoded.status == StateLoadStatus.UNSUPPORTED_SCHEMA
                    and decoded.schema_version == 1
                ):
                    old_decoded, old_payload = decode_versioned_json_snapshot(
                        line,
                        supported_version=1,
                    )
                    legacy_value = self._parse_v1_journal_payload(
                        old_payload,
                        channel=channel,
                    )
                    if old_decoded.status != StateLoadStatus.OK:
                        return old_decoded, [], set(), file_identity
                    if legacy_value is None:
                        return (
                            StateLoadResult(
                                StateLoadStatus.CORRUPT,
                                reason="invalid_v1_journal_payload",
                            ),
                            [],
                            set(),
                            file_identity,
                        )
                    legacy_message_ids.add(legacy_value)
                    continue
                if decoded.status != StateLoadStatus.OK:
                    return decoded, [], set(), file_identity
                parsed = self._parse_journal_payload(payload, channel=channel)
                if parsed is None:
                    return (
                        StateLoadResult(
                            StateLoadStatus.CORRUPT,
                            reason="invalid_journal_payload",
                        ),
                        [],
                        set(),
                        file_identity,
                    )
                rows.append(parsed)
                continue
            legacy_value = self._parse_legacy_journal_line(line)
            if legacy_value is None:
                return (
                    StateLoadResult(StateLoadStatus.CORRUPT, reason="invalid_journal"),
                    [],
                    set(),
                    file_identity,
                )
            legacy_message_ids.add(legacy_value)
        return (
            StateLoadResult(StateLoadStatus.OK, legacy=bool(legacy_message_ids)),
            rows,
            legacy_message_ids,
            file_identity,
        )

    def _parse_snapshot_payload(
        self,
        payload: Any,
        *,
        channel: str,
    ) -> tuple[list[_ReplayRecord], list[str]] | None:
        if not isinstance(payload, dict) or payload.get("channel") != channel:
            return None
        raw_records = payload.get("records")
        raw_recent = payload.get("recent_identity_keys")
        if not isinstance(raw_records, list) or not isinstance(raw_recent, list):
            return None
        records: list[_ReplayRecord] = []
        for row in raw_records:
            parsed = self._parse_journal_payload(row, channel=channel)
            if parsed is None:
                return None
            records.append(parsed)
        recent: list[str] = []
        for value in raw_recent:
            if not isinstance(value, str):
                return None
            normalized = value.strip()
            if not normalized:
                return None
            recent.append(normalized)
        return records, recent

    def _parse_journal_payload(
        self,
        payload: Any,
        *,
        channel: str,
    ) -> _ReplayRecord | None:
        if not isinstance(payload, dict) or payload.get("channel") != channel:
            return None
        raw_identity = payload.get("identity")
        raw_outcome = payload.get("outcome")
        if not isinstance(raw_identity, dict) or not isinstance(raw_outcome, str):
            return None
        try:
            identity = ReplayIdentity.model_validate(raw_identity)
        except ValidationError:
            return None
        if identity.provider != channel:
            return None
        with contextlib.suppress(ValueError):
            return _ReplayRecord(identity, ReplayOutcome(raw_outcome))
        return None

    def _parse_v1_snapshot_payload(self, payload: Any, *, channel: str) -> set[str] | None:
        if not isinstance(payload, dict) or payload.get("channel") != channel:
            return None
        raw_records = payload.get("records")
        raw_recent = payload.get("recent_message_ids")
        if not isinstance(raw_records, list) or not isinstance(raw_recent, list):
            return None
        message_ids: set[str] = set()
        for row in raw_records:
            value = self._parse_v1_journal_payload(row, channel=channel)
            if value is None:
                return None
            message_ids.add(value)
        for value in raw_recent:
            if not isinstance(value, str):
                return None
            normalized = self._normalize_message_id(value)
            if normalized is None:
                return None
            message_ids.add(normalized)
        return message_ids

    def _parse_v1_journal_payload(self, payload: Any, *, channel: str) -> str | None:
        if not isinstance(payload, dict) or payload.get("channel") != channel:
            return None
        raw_message_id = payload.get("message_id")
        raw_outcome = payload.get("outcome")
        if not isinstance(raw_message_id, str) or not isinstance(raw_outcome, str):
            return None
        with contextlib.suppress(ValueError):
            ReplayOutcome(raw_outcome)
            return self._normalize_message_id(raw_message_id)
        return None

    def _parse_legacy_snapshot(self, raw: bytes, *, channel: str) -> list[str] | None:
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError, RecursionError):
            return None
        if (
            not isinstance(payload, dict)
            or set(payload) != {"channel", "seen_message_ids"}
            or payload.get("channel") != channel
        ):
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

    @staticmethod
    def _is_envelope_candidate(raw: bytes) -> bool:
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError, RecursionError):
            return False
        return isinstance(payload, dict) and bool(
            {"version", "checksum", "payload"}.intersection(payload)
        )

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
        try:
            raw_bytes = read_owned_regular_file(path, normalize_mode=0o600)
        except OSError:
            return StateLoadResult(StateLoadStatus.CORRUPT, reason="state_read_failed"), None
        if raw_bytes is None:
            return StateLoadResult(StateLoadStatus.CORRUPT, reason="state_read_failed"), None
        return StateLoadResult(StateLoadStatus.OK), raw_bytes

    def _read_private_bytes_with_identity(
        self,
        path: Path,
    ) -> tuple[StateLoadResult, bytes | None, tuple[int, int] | None]:
        try:
            raw_bytes, file_identity = read_owned_regular_file_with_identity(
                path,
                normalize_mode=0o600,
            )
        except OSError:
            return (
                StateLoadResult(StateLoadStatus.CORRUPT, reason="state_read_failed"),
                None,
                None,
            )
        if raw_bytes is None:
            return StateLoadResult(StateLoadStatus.MISSING), None, None
        return StateLoadResult(StateLoadStatus.OK), raw_bytes, file_identity

    def _validate_existing_root(self) -> StateLoadResult:
        try:
            root_stat = self._root_dir.lstat()
        except FileNotFoundError:
            return StateLoadResult(StateLoadStatus.MISSING)
        except OSError:
            return StateLoadResult(StateLoadStatus.CORRUPT, reason="root_lstat_failed")
        if not stat.S_ISDIR(root_stat.st_mode):
            return StateLoadResult(StateLoadStatus.CORRUPT, reason="root_not_directory")
        try:
            root_exists = validate_directory_ancestry(self._root_dir)
        except OSError:
            return StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="invalid_root_ancestry",
            )
        if not root_exists:
            return StateLoadResult(StateLoadStatus.MISSING)
        if hasattr(os, "getuid") and root_stat.st_uid != os.getuid():
            return StateLoadResult(StateLoadStatus.CORRUPT, reason="root_wrong_owner")
        try:
            ensure_owner_only_directory(self._root_dir)
        except OSError:
            return StateLoadResult(StateLoadStatus.CORRUPT, reason="root_mode_failed")
        return StateLoadResult(StateLoadStatus.OK)

    def _append_journal_entry(
        self,
        channel: str,
        identity: ReplayIdentity,
        outcome: ReplayOutcome,
    ) -> None:
        payload = {
            "channel": channel,
            "identity": identity.model_dump(mode="json"),
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
        expected_identity = self._journal_identities.get(channel)
        self._journal_identities[channel] = durable_append_bytes(
            self._journal_path(channel),
            encoded,
            fault_injector=self._append_fault_injector,
            expected_identity=expected_identity,
            require_missing=expected_identity is None,
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
                    "identity": record.identity.model_dump(mode="json"),
                    "outcome": record.outcome.value,
                }
                for _key, record in sorted(records.items())
            ],
            "recent_identity_keys": list(recent),
        }
        atomic_write_bytes(
            self._state_path(channel),
            encode_versioned_json_snapshot(payload, version=self._SCHEMA_VERSION),
            fault_injector=self._snapshot_fault_injector,
        )

    def _truncate_journal(self, channel: str) -> None:
        self._journal_identities[channel] = atomic_write_bytes_with_identity(
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
    def _identity_key(identity: ReplayIdentity) -> str:
        encoded = json.dumps(
            identity.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _is_known(self, channel: str, identity: ReplayIdentity) -> bool:
        return (
            self._identity_key(identity) in self._records[channel]
            or identity.message_id in self._legacy_message_ids[channel]
        )

    @classmethod
    def _resolve_identity(
        cls,
        *,
        identity: ReplayIdentity | None,
        channel: str,
        message_id: str,
    ) -> ReplayIdentity:
        if identity is not None:
            if channel and channel.strip() != identity.provider:
                raise ValueError("replay identity provider does not match channel")
            if message_id and message_id.strip() != identity.message_id:
                raise ValueError("replay identity message_id does not match message")
            return identity
        resolved = cls._optional_compatibility_identity(channel, message_id)
        if resolved is None:
            raise ValueError("replay message_id cannot be empty")
        return resolved

    @staticmethod
    def _optional_compatibility_identity(
        channel: str,
        message_id: str,
    ) -> ReplayIdentity | None:
        normalized_channel = channel.strip()
        normalized_message_id = ChannelStateStore._normalize_message_id(message_id)
        if not normalized_channel or normalized_message_id is None:
            return None
        provider = normalized_channel
        if channel != normalized_channel:
            suffix = hashlib.sha256(channel.encode("utf-8")).hexdigest()[:16]
            provider = f"{normalized_channel}-compat-{suffix}"
        return ReplayIdentity(
            provider=provider,
            account_id="compatibility",
            tenant_id="compatibility",
            delivery_id="compatibility",
            event_variant=ReplayEventVariant.COMPATIBILITY,
            message_id=normalized_message_id,
        )

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
    def _fsync_directory_entry(path: Path) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path, flags)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
