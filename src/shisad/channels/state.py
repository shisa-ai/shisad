"""Persisted replay-guard state for channel ingress."""

from __future__ import annotations

import json
import os
from collections import deque
from contextlib import suppress
from pathlib import Path
from typing import Any


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
        self._loaded_channels: set[str] = set()

    def has_seen(self, *, channel: str, message_id: str) -> bool:
        msg_id = message_id.strip()
        if not msg_id:
            return False
        self._ensure_loaded(channel)
        return msg_id in self._seen_id_sets[channel]

    def mark_seen(self, *, channel: str, message_id: str) -> None:
        msg_id = message_id.strip()
        if not msg_id:
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
            with suppress(OSError):
                self._compact_channel(channel)

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

        for item in self._load_snapshot_ids(state_path):
            self._record_seen_id(ids, id_set, item)

        journal_lines = 0
        for item in self._load_journal_ids(journal_path):
            journal_lines += 1
            self._record_seen_id(ids, id_set, item)

        self._seen_ids[channel] = ids
        self._seen_id_sets[channel] = id_set
        self._journal_appends_since_compaction[channel] = journal_lines
        self._loaded_channels.add(channel)

        if journal_lines >= self._journal_compact_every:
            with suppress(OSError):
                self._compact_channel(channel)

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
        return [item.strip() for item in raw if isinstance(item, str) and item.strip()]

    def _load_journal_ids(self, path: Path) -> list[str]:
        if not path.exists():
            return []
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            return []
        return [line.strip() for line in lines if line.strip()]

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
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"{message_id}\n")
            handle.flush()
            os.fsync(handle.fileno())

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
        safe = "".join(ch for ch in channel if ch.isalnum() or ch in {"-", "_"}).strip("_-")
        if not safe:
            safe = "unknown"
        return self._root_dir / f"{safe}.state.json"

    def _journal_path(self, channel: str) -> Path:
        safe = "".join(ch for ch in channel if ch.isalnum() or ch in {"-", "_"}).strip("_-")
        if not safe:
            safe = "unknown"
        return self._root_dir / f"{safe}.state.journal"
