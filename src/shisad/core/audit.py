"""Audit log with hash chaining.

Append-only JSONL file where each entry includes the hash of the previous
entry, forming a tamper-evident chain. The audit log is the persistence
backend for the event bus.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from collections import deque
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError, model_validator

from shisad.core.events import BaseEvent

logger = logging.getLogger(__name__)

# Genesis hash — the seed for the first entry in the chain
_GENESIS_HASH = hashlib.sha256(b"shisad-audit-genesis").hexdigest()


class AuditEntry(BaseModel):
    """A single entry in the audit log."""

    event_id: str
    timestamp: str
    event_type: str
    actor: str
    action: str
    target: str
    decision: str
    reasoning: str
    session_id: str | None
    data: dict[str, Any]
    data_hash: str
    previous_event_hash: str
    previous_hash: str

    @model_validator(mode="before")
    @classmethod
    def _normalize_previous_hashes(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        if "previous_event_hash" not in value and "previous_hash" in value:
            value["previous_event_hash"] = value["previous_hash"]
        if "previous_hash" not in value and "previous_event_hash" in value:
            value["previous_hash"] = value["previous_event_hash"]
        return value


class AuditLog:
    """Append-only audit log with hash chaining.

    Each entry includes a hash of the previous entry, creating a
    tamper-evident chain. Insertion, modification, or deletion of
    entries is detectable via verify_chain().
    """

    def __init__(self, log_path: Path) -> None:
        self._log_path = log_path
        self._previous_hash = _GENESIS_HASH
        self._entry_count = 0

        # Resume chain from existing log if present
        if self._log_path.exists():
            self._resume_chain()

    @property
    def log_path(self) -> Path:
        return self._log_path

    @property
    def entry_count(self) -> int:
        return self._entry_count

    async def persist(self, event: BaseEvent) -> None:
        """Persist an event to the audit log (EventPersister protocol)."""
        data = event.model_dump(mode="json")
        data_json = json.dumps(data, sort_keys=True)
        data_hash = hashlib.sha256(data_json.encode()).hexdigest()
        action, target, decision, reasoning = self._derive_entry_metadata(event, data)

        entry = AuditEntry(
            event_id=event.event_id,
            timestamp=event.timestamp.isoformat(),
            event_type=type(event).__name__,
            actor=event.actor,
            action=action,
            target=target,
            decision=decision,
            reasoning=reasoning,
            session_id=event.session_id,
            data=data,
            data_hash=data_hash,
            previous_event_hash=self._previous_hash,
            previous_hash=self._previous_hash,
        )

        entry_json = entry.model_dump_json()

        # Compute this entry's hash (used as previous_hash for next entry)
        entry_hash = hashlib.sha256(entry_json.encode()).hexdigest()

        # Append to log
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_secure_permissions()
        with self._log_path.open("a", encoding="utf-8") as f:
            f.write(entry_json + "\n")
        self._ensure_secure_permissions()

        self._previous_hash = entry_hash
        self._entry_count += 1

    def verify_chain(self) -> tuple[bool, int, str]:
        """Verify the integrity of the entire audit log chain.

        Returns:
            (is_valid, entries_checked, error_message)
        """
        if not self._log_path.exists():
            return (True, 0, "")

        previous_hash = _GENESIS_HASH
        count = 0

        with self._log_path.open() as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = AuditEntry.model_validate_json(line)
                except ValidationError as e:
                    return (False, count, f"Line {line_num}: invalid entry: {e}")

                # Check chain link
                if entry.previous_event_hash != previous_hash:
                    return (
                        False,
                        count,
                        f"Line {line_num}: chain break — expected previous_hash "
                        f"{previous_hash[:12]}…, got {entry.previous_event_hash[:12]}…",
                    )

                # Check data integrity
                data_json = json.dumps(entry.data, sort_keys=True)
                expected_data_hash = hashlib.sha256(data_json.encode()).hexdigest()
                if entry.data_hash != expected_data_hash:
                    return (
                        False,
                        count,
                        f"Line {line_num}: data hash mismatch for event {entry.event_id}",
                    )

                # Compute this entry's hash for the next link
                previous_hash = hashlib.sha256(line.encode()).hexdigest()
                count += 1

        return (True, count, "")

    def query(
        self,
        *,
        since: datetime | None = None,
        event_type: str | None = None,
        session_id: str | None = None,
        actor: str | None = None,
        limit: int = 100,
        tail: bool = False,
    ) -> list[dict[str, Any]]:
        """Query audit log entries with filters."""
        if not self._log_path.exists():
            return []

        max_results = max(1, int(limit))
        if tail:
            results: list[dict[str, Any]] | deque[dict[str, Any]] = deque(maxlen=max_results)
        else:
            results = []

        with self._log_path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                entry = AuditEntry.model_validate_json(line)

                # Apply filters
                if event_type is not None and entry.event_type != event_type:
                    continue
                if session_id is not None and entry.session_id != session_id:
                    continue
                if actor is not None and entry.actor != actor:
                    continue
                if since is not None:
                    entry_time = datetime.fromisoformat(entry.timestamp)
                    if entry_time.tzinfo is None:
                        entry_time = entry_time.replace(tzinfo=UTC)
                    if entry_time < since:
                        continue

                results.append(entry.model_dump())

                if not tail and len(results) >= max_results:
                    break

        return list(results)

    def _resume_chain(self) -> None:
        """Resume the hash chain from an existing log file."""
        previous_hash = _GENESIS_HASH
        count = 0

        with self._log_path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                previous_hash = hashlib.sha256(line.encode()).hexdigest()
                count += 1

        self._previous_hash = previous_hash
        self._entry_count = count
        logger.info("Resumed audit chain: %d entries, last hash %s…", count, previous_hash[:12])

    def _ensure_secure_permissions(self) -> None:
        """Best-effort restrictive file mode for audit logs."""
        if not self._log_path.exists():
            return
        os.chmod(self._log_path, 0o600)

    @staticmethod
    def _derive_entry_metadata(
        event: BaseEvent,
        data: dict[str, Any],
    ) -> tuple[str, str, str, str]:
        event_type = type(event).__name__
        action = event_type
        target = str(data.get("tool_name") or data.get("session_id") or "")
        decision = ""
        reasoning = ""

        decision_value = data.get("decision")
        if isinstance(decision_value, str):
            decision = decision_value
        if event_type == "ToolApproved":
            decision = "allow"
        elif event_type == "ToolRejected":
            decision = "reject"
        elif event_type == "A2aIngressEvaluated":
            decision = "allow" if str(data.get("outcome", "")).strip() == "accepted" else "reject"
            target = str(data.get("sender_agent_id") or data.get("message_id") or target)

        reason_value = data.get("reason")
        if isinstance(reason_value, str):
            reasoning = reason_value
        elif isinstance(data.get("description"), str):
            reasoning = str(data["description"])

        return (action, target, decision, reasoning)

    @staticmethod
    def parse_since(
        value: str | None,
        *,
        now: datetime | None = None,
    ) -> datetime | None:
        """Parse relative or absolute `since` filter values.

        Supported formats:
        - Relative: `30s`, `15m`, `2h`, `7d`
        - Absolute: ISO timestamp (`2026-02-09T12:00:00Z`) or date (`2026-02-09`)
        """
        if value is None:
            return None

        text = value.strip()
        if not text:
            return None

        current = now or datetime.now(UTC)
        rel_match = re.fullmatch(r"(?P<num>\d+)(?P<unit>[smhd])", text)
        if rel_match:
            amount = int(rel_match.group("num"))
            unit = rel_match.group("unit")
            delta_map = {
                "s": timedelta(seconds=amount),
                "m": timedelta(minutes=amount),
                "h": timedelta(hours=amount),
                "d": timedelta(days=amount),
            }
            return current - delta_map[unit]

        normalized = text.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise ValueError(
                f"Invalid --since value '{value}'. Use 1h/30m/7d or ISO datetime."
            ) from exc

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed
