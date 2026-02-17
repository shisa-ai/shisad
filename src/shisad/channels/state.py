"""Persisted replay-guard state for channel ingress."""

from __future__ import annotations

import hashlib
import json
import logging
import os
from collections import deque
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ChannelStateStore:
    """Stores channel cursor/replay state under SHISAD_DATA_DIR."""

    def __init__(
        self,
        root_dir: Path,
        *,
        max_seen_ids: int = 2048,
        journal_compact_every: int = 256,
    ) -> None:
        self._root_dir = root_dir
        self._root_dir.mkdir(parents=True, exist_ok=True)
        self._max_seen_ids = max(max_seen_ids, 32)
        self._journal_compact_every = max(journal_compact_every, 1)
        self._seen_ids: dict[str, deque[str]] = {}
        self._seen_id_sets: dict[str, set[str]] = {}
        self._journal_appends_since_compaction: dict[str, int] = {}
        self._compaction_warning_logged: set[str] = set()
        self._loaded_channels: set[str] = set()

    def has_seen(self, *, channel: str, message_id: str) -> bool:
        msg_id = self._normalize_message_id(message_id)
        if msg_id is None:
            return False
        self._ensure_loaded(channel)
        return msg_id in self._seen_id_sets[channel]

    def mark_seen(self, *, channel: str, message_id: str) -> None:
        msg_id = self._normalize_message_id(message_id)
        if msg_id is None:
            return
        self._ensure_loaded(channel)
        id_set = self._seen_id_sets[channel]
        if msg_id in id_set:
            return
        self._append_journal_entry(channel, msg_id)
        ids = self._seen_ids[channel]
        self._record_seen_id(ids, id_set, msg_id)
        appended = self._journal_appends_since_compaction.get(channel, 0) + 1
        self._journal_appends_since_compaction[channel] = appended
        if appended >= self._journal_compact_every:
            self._attempt_compaction(channel, trigger="mark_seen")

    def is_replay(self, *, channel: str, message_id: str) -> bool:
        if self.has_seen(channel=channel, message_id=message_id):
            return True
        self.mark_seen(channel=channel, message_id=message_id)
        return False

    def snapshot(self, channel: str) -> dict[str, Any]:
        self._ensure_loaded(channel)
        ids = list(self._seen_ids[channel])
        return {
            "channel": channel,
            "seen_message_ids": ids,
            "seen_count": len(ids),
            "max_seen_ids": self._max_seen_ids,
        }

    def _ensure_loaded(self, channel: str) -> None:
        if channel in self._loaded_channels:
            return
        state_path = self._state_path(channel)
        journal_path = self._journal_path(channel)
        ids: deque[str] = deque()
        id_set: set[str] = set()

        journal_lines = 0
        for item in self._load_snapshot_ids(state_path):
            self._record_seen_id(ids, id_set, item)
        for item in self._load_journal_ids(journal_path):
            journal_lines += 1
            self._record_seen_id(ids, id_set, item)

        self._seen_ids[channel] = ids
        self._seen_id_sets[channel] = id_set
        self._journal_appends_since_compaction[channel] = journal_lines
        self._loaded_channels.add(channel)

        if journal_lines >= self._journal_compact_every:
            self._attempt_compaction(channel, trigger="load")

    def _load_snapshot_ids(self, path: Path) -> list[str]:
        if not path.exists():
            return []
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return []
        if not isinstance(payload, dict):
            return []
        raw = payload.get("seen_message_ids", [])
        if not isinstance(raw, list):
            return []
        normalized: list[str] = []
        for item in raw:
            if not isinstance(item, str):
                continue
            value = self._normalize_message_id(item)
            if value is not None:
                normalized.append(value)
        return normalized

    def _load_journal_ids(self, path: Path) -> list[str]:
        if not path.exists():
            return []
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            return []
        ids: list[str] = []
        for line in lines:
            token = line.strip()
            if not token:
                continue
            candidate: object = token
            try:
                candidate = json.loads(token)
            except json.JSONDecodeError:
                candidate = token
            if not isinstance(candidate, str):
                continue
            value = self._normalize_message_id(candidate)
            if value is not None:
                ids.append(value)
        return ids

    def _record_seen_id(self, ids: deque[str], id_set: set[str], message_id: str) -> None:
        msg_id = message_id.strip()
        if not msg_id or msg_id in id_set:
            return
        ids.append(msg_id)
        id_set.add(msg_id)
        while len(ids) > self._max_seen_ids:
            evicted = ids.popleft()
            id_set.discard(evicted)

    def _append_journal_entry(self, channel: str, message_id: str) -> None:
        path = self._journal_path(channel)
        encoded = json.dumps(message_id, ensure_ascii=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"{encoded}\n")
            handle.flush()
            os.fsync(handle.fileno())

    def _attempt_compaction(self, channel: str, *, trigger: str) -> bool:
        try:
            self._compact_channel(channel)
        except OSError as exc:
            if channel in self._compaction_warning_logged:
                return False
            logger.warning(
                "Channel replay-state compaction failed; deferring snapshot update "
                "(channel=%s, trigger=%s, error=%s)",
                channel,
                trigger,
                exc.__class__.__name__,
            )
            self._compaction_warning_logged.add(channel)
            return False
        else:
            self._compaction_warning_logged.discard(channel)
            return True

    def _compact_channel(self, channel: str) -> None:
        self._persist_snapshot(channel)
        self._truncate_journal(channel)
        self._journal_appends_since_compaction[channel] = 0

    def _persist_snapshot(self, channel: str) -> None:
        ids = self._seen_ids.get(channel)
        if ids is None:
            return
        payload = {
            "channel": channel,
            "seen_message_ids": list(ids),
        }
        path = self._state_path(channel)
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, indent=2))
            handle.flush()
            os.fsync(handle.fileno())
        tmp_path.replace(path)

    def _truncate_journal(self, channel: str) -> None:
        path = self._journal_path(channel)
        if not path.exists():
            return
        with path.open("w", encoding="utf-8") as handle:
            handle.write("")
            handle.flush()
            os.fsync(handle.fileno())

    def _state_path(self, channel: str) -> Path:
        return self._root_dir / f"{self._channel_file_stem(channel)}.state.json"

    def _journal_path(self, channel: str) -> Path:
        return self._root_dir / f"{self._channel_file_stem(channel)}.state.journal"

    def _channel_file_stem(self, channel: str) -> str:
        raw = channel.strip() or "unknown"
        legacy = self._legacy_channel_file_stem(raw)
        # Preserve legacy filenames for already-safe channel names.
        if raw == legacy:
            return legacy
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
        return f"{legacy}-{digest}"

    def _legacy_channel_file_stem(self, channel: str) -> str:
        safe = "".join(ch for ch in channel if ch.isalnum() or ch in {"-", "_"}).strip("_-")
        if not safe:
            safe = "unknown"
        return safe

    @staticmethod
    def _normalize_message_id(value: str) -> str | None:
        message_id = value.strip()
        if not message_id:
            return None
        return message_id
