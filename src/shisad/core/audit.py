"""Audit log with hash chaining.

Append-only JSONL file where each entry includes the hash of the previous
entry, forming a tamper-evident chain. The audit log is the persistence
backend for the event bus.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError, model_validator

from shisad.core.audit_segments import (
    AuditIntegrityError,
    AuditSegmentStore,
    AuditUnavailableError,
)
from shisad.core.events import BaseEvent

# Genesis hash — the seed for the first entry in the chain
_GENESIS_HASH = hashlib.sha256(b"shisad-audit-genesis").hexdigest()
MAX_SEGMENT_BYTES = 32 * 1024 * 1024
MAX_ARCHIVES = 4


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

    def __init__(
        self,
        log_path: Path,
        *,
        on_unavailable: Callable[[], None] | None = None,
        _read_only: bool = False,
    ) -> None:
        self._log_path = log_path
        self._previous_hash = _GENESIS_HASH
        self._entry_count = 0
        self._event_hashes: dict[str, str] = {}
        self._segments = AuditSegmentStore(
            log_path,
            stream="main",
            genesis_hash=_GENESIS_HASH,
            verify_row=self._verify_row,
            max_segment_bytes=MAX_SEGMENT_BYTES,
            max_archives=MAX_ARCHIVES,
            on_unavailable=on_unavailable,
            admit=not _read_only,
        )
        self._resume_chain()

    @property
    def log_path(self) -> Path:
        return self._log_path

    @property
    def entry_count(self) -> int:
        return self._entry_count

    @property
    def lifecycle_status(self) -> dict[str, Any]:
        return self._segments.lifecycle_status

    async def persist(self, event: BaseEvent) -> None:
        """Persist an event to the audit log (EventPersister protocol)."""
        self._segments.ensure_available()
        data = event.model_dump(mode="json")
        data_json = json.dumps(data, sort_keys=True)
        data_hash = hashlib.sha256(data_json.encode()).hexdigest()
        event_id = str(event.event_id)
        existing_hash = self._event_hashes.get(event_id)
        if existing_hash is not None:
            if existing_hash != data_hash:
                raise ValueError("audit_event_id_payload_conflict")
            return
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

        try:
            self._segments.append(entry_json, entry_hash)
        except AuditUnavailableError:
            raise
        except Exception:
            self._segments.mark_unavailable("audit.append_failed")
            raise

        self._previous_hash = entry_hash
        self._entry_count += 1
        self._event_hashes[event_id] = data_hash

    def verify_chain(self) -> tuple[bool, int, str]:
        """Verify the integrity of the entire audit log chain.

        Returns:
            (is_valid, entries_checked, error_message)
        """
        try:
            verified = self._segments.verify()
        except (AuditIntegrityError, OSError, UnicodeError, ValueError) as exc:
            return (False, self._entry_count, str(exc))
        return (True, verified.entry_count, "")

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
        valid, _count, error = self.verify_chain()
        if not valid:
            raise AuditIntegrityError(error)

        max_results = max(1, int(limit))
        if tail:
            results: list[dict[str, Any]] | deque[dict[str, Any]] = deque(maxlen=max_results)
        else:
            results = []

        for line in self._segments.iter_rows():
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
        """Build the idempotency index from already-verified retained rows."""
        self._event_hashes.clear()
        for line in self._segments.iter_rows():
            entry = AuditEntry.model_validate_json(line)
            existing_hash = self._event_hashes.get(entry.event_id)
            if existing_hash is not None and existing_hash != entry.data_hash:
                raise AuditIntegrityError("audit_event_id_payload_conflict")
            self._event_hashes[entry.event_id] = entry.data_hash
        verified = self._segments.verification
        self._entry_count = verified.entry_count
        self._previous_hash = (
            verified.segments[-1].terminal_hash if verified.segments else _GENESIS_HASH
        )

    @staticmethod
    def _verify_row(payload: str, previous_hash: str) -> str:
        try:
            entry = AuditEntry.model_validate_json(payload)
        except ValidationError as exc:
            raise AuditIntegrityError("invalid entry") from exc
        if entry.previous_event_hash != previous_hash or entry.previous_hash != previous_hash:
            raise AuditIntegrityError("chain break")
        data_json = json.dumps(entry.data, sort_keys=True)
        expected_data_hash = hashlib.sha256(data_json.encode()).hexdigest()
        if entry.data_hash != expected_data_hash:
            raise AuditIntegrityError(f"data hash mismatch for event {entry.event_id}")
        return hashlib.sha256(payload.encode()).hexdigest()

    def reset_for_test(self) -> None:
        self._segments.reset_for_test()
        self._previous_hash = _GENESIS_HASH
        self._entry_count = 0
        self._event_hashes.clear()

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
