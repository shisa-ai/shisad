"""Persisted replay-guard state for channel ingress."""

from __future__ import annotations

import json
from collections import deque
from pathlib import Path
from typing import Any


class ChannelStateStore:
    """Stores channel cursor/replay state under SHISAD_DATA_DIR."""

    def __init__(self, root_dir: Path, *, max_seen_ids: int = 2048) -> None:
        self._root_dir = root_dir
        self._root_dir.mkdir(parents=True, exist_ok=True)
        self._max_seen_ids = max(max_seen_ids, 32)
        self._seen_ids: dict[str, deque[str]] = {}
        self._loaded_channels: set[str] = set()

    def has_seen(self, *, channel: str, message_id: str) -> bool:
        msg_id = message_id.strip()
        if not msg_id:
            return False
        self._ensure_loaded(channel)
        ids = self._seen_ids[channel]
        return msg_id in ids

    def mark_seen(self, *, channel: str, message_id: str) -> None:
        msg_id = message_id.strip()
        if not msg_id:
            return
        self._ensure_loaded(channel)
        ids = self._seen_ids[channel]
        if msg_id in ids:
            return
        ids.append(msg_id)
        self._persist(channel)

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
        path = self._state_path(channel)
        ids: deque[str] = deque(maxlen=self._max_seen_ids)
        if path.exists():
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                payload = {}
            if isinstance(payload, dict):
                raw = payload.get("seen_message_ids", [])
                if isinstance(raw, list):
                    for item in raw:
                        if isinstance(item, str) and item.strip():
                            ids.append(item.strip())
        self._seen_ids[channel] = ids
        self._loaded_channels.add(channel)

    def _persist(self, channel: str) -> None:
        ids = self._seen_ids.get(channel)
        if ids is None:
            return
        payload = {
            "channel": channel,
            "seen_message_ids": list(ids),
        }
        path = self._state_path(channel)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _state_path(self, channel: str) -> Path:
        safe = "".join(ch for ch in channel if ch.isalnum() or ch in {"-", "_"}).strip("_-")
        if not safe:
            safe = "unknown"
        return self._root_dir / f"{safe}.state.json"
