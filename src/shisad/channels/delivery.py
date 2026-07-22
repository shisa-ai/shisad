"""Durable outbound delivery lifecycle shared by runtime channels."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import sqlite3
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from shisad.channels.base import (
    Channel,
    DeliveryReconciliationStatus,
    DeliveryRecoveryKind,
    DeliveryTarget,
    ProviderDeliveryReceipt,
)
from shisad.core.storage_platform import sync_parent_directory, tighten_permissions
from shisad.core.transcript import TranscriptStore
from shisad.core.types import SessionId

logger = logging.getLogger(__name__)

_SCHEMA_VERSION = 1
_MAX_MESSAGE_BYTES = 64 * 1024
_KINDS = frozenset({"channel_result", "message_send", "approval_capability"})
_TERMINAL = ("delivered", "failed_pre_effect", "outcome_unknown", "superseded", "cancelled")


class DeliveryStateError(RuntimeError): ...


@dataclass(frozen=True, slots=True)
class DeliveryIntent:
    source_id: str
    kind: str
    target: DeliveryTarget
    generation: int = 0
    predecessor_id: str = ""
    message_prefix: str = ""


@dataclass(frozen=True, slots=True)
class CapabilityDeliveryIntent:
    confirmation_id: str
    target: DeliveryTarget
    expires_at: datetime
    generation: int = 0
    predecessor_id: str = ""


@dataclass(frozen=True, slots=True)
class CapabilityPayload:
    message: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class DeliveryRecord:
    reservation_id: str
    delivery_id: str
    intent: DeliveryIntent
    payload: str
    payload_digest: str
    metadata: dict[str, Any]
    confirmation_id: str
    expires_at: datetime | None
    state: str
    receipt: ProviderDeliveryReceipt | None
    reason: str


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    attempted: bool
    sent: bool
    reason: str = ""
    target: DeliveryTarget | None = None
    reservation_id: str = ""
    delivery_id: str = ""
    state: str = ""
    outcome_unknown: bool = False
    receipt_id: str = ""

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["target"] = self.target.model_dump(mode="json") if self.target else {}
        return payload


def _canonical(value: Mapping[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _expiry(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _intent_payload(
    intent: DeliveryIntent,
    *,
    confirmation_id: str = "",
    expires_at: datetime | None = None,
) -> dict[str, Any]:
    return {
        "source_id": intent.source_id.strip(),
        "kind": intent.kind.strip(),
        "target": intent.target.model_dump(mode="json"),
        "generation": int(intent.generation),
        "predecessor_id": intent.predecessor_id.strip(),
        "message_prefix": intent.message_prefix,
        "confirmation_id": confirmation_id.strip(),
        "expires_at": _expiry(expires_at).isoformat() if expires_at else "",
    }


def _validated_intent(intent: DeliveryIntent) -> DeliveryIntent:
    normalized = replace(
        intent,
        source_id=intent.source_id.strip(),
        kind=intent.kind.strip(),
        predecessor_id=intent.predecessor_id.strip(),
    )
    if not normalized.source_id or normalized.kind not in _KINDS:
        raise DeliveryStateError("delivery source identity or kind is invalid")
    if not normalized.target.channel.strip() or not normalized.target.recipient.strip():
        raise DeliveryStateError("delivery target is incomplete")
    if normalized.generation < 0:
        raise DeliveryStateError("delivery generation cannot be negative")
    return normalized


class _DeliveryStore:
    def __init__(self, root: Path) -> None:
        self.database_path = root / "outbox.sqlite3"
        if root.is_symlink() or self.database_path.is_symlink():
            raise DeliveryStateError("delivery state path cannot be a symlink")
        existed = self.database_path.exists()
        if existed and self.database_path.stat().st_size == 0:
            raise DeliveryStateError("existing delivery database is empty or unversioned")
        root_existed = root.exists()
        root.mkdir(parents=True, exist_ok=True)
        if tighten_permissions(root, 0o700) == "failed":
            raise DeliveryStateError("delivery state directory is not owner-only")
        if not root_existed:
            sync_parent_directory(root.parent)
        try:
            self._db = sqlite3.connect(self.database_path, timeout=5.0)
            self._db.row_factory = sqlite3.Row
            self._db.execute("PRAGMA synchronous = FULL")
            if not existed:
                self._db.execute(
                    """
                    CREATE TABLE deliveries (
                        reservation_id TEXT PRIMARY KEY,
                        delivery_id TEXT UNIQUE,
                        intent_json TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        payload_digest TEXT NOT NULL,
                        metadata_json TEXT NOT NULL,
                        state TEXT NOT NULL,
                        receipt_json TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                self._db.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
                self._db.commit()
                sync_parent_directory(root)
            self._validate()
        except (sqlite3.Error, DeliveryStateError) as exc:
            with contextlib.suppress(Exception):
                self._db.close()
            if isinstance(exc, DeliveryStateError):
                raise
            raise DeliveryStateError("delivery database initialization failed") from exc
        if tighten_permissions(self.database_path, 0o600) == "failed":
            self._db.close()
            raise DeliveryStateError("delivery database is not owner-only")

    def _validate(self) -> None:
        version = int(self._db.execute("PRAGMA user_version").fetchone()[0])
        columns = self._db.execute("PRAGMA table_info(deliveries)").fetchall()
        objects = {
            (str(row[0]), str(row[1]))
            for row in self._db.execute(
                "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            )
        }
        if (
            version != _SCHEMA_VERSION
            or objects != {("table", "deliveries")}
            or " ".join(str(row[1]) for row in columns)
            != (
                "reservation_id delivery_id intent_json payload payload_digest metadata_json "
                "state receipt_json reason created_at updated_at"
            )
            or int(columns[0][5]) != 1
            or sum(int(row[2]) for row in self._db.execute("PRAGMA index_list(deliveries)")) != 2
        ):
            raise DeliveryStateError("delivery database schema is unsupported")
        if str(self._db.execute("PRAGMA quick_check").fetchone()[0]) != "ok":
            raise DeliveryStateError("delivery database integrity check failed")
        for row in self._db.execute("SELECT * FROM deliveries"):
            self._decode(row)

    def reserve(
        self,
        intent: DeliveryIntent,
        *,
        confirmation_id: str = "",
        expires_at: datetime | None = None,
    ) -> DeliveryRecord:
        intent = _validated_intent(intent)
        intent_payload = _intent_payload(
            intent, confirmation_id=confirmation_id, expires_at=expires_at
        )
        serialized = _canonical(intent_payload)
        intent_payload["message_prefix"] = ""
        reservation_id = (
            f"dres-{_hash('shisad.delivery.reservation.v1\0' + _canonical(intent_payload))}"
        )
        capability = intent.kind == "approval_capability"
        if capability and (not confirmation_id.strip() or expires_at is None):
            raise DeliveryStateError("capability delivery intent is incomplete")
        payload_digest = _hash(serialized) if capability else ""
        delivery_id = f"dly-{_hash(reservation_id + '\0' + payload_digest)}" if capability else None
        now = datetime.now(UTC).isoformat()
        try:
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute(
                "INSERT OR IGNORE INTO deliveries VALUES (?, ?, ?, '', ?, '{}', ?, '{}', '', ?, ?)",
                (
                    reservation_id,
                    delivery_id,
                    serialized,
                    payload_digest,
                    "prepared" if capability else "preparing",
                    now,
                    now,
                ),
            )
            self._db.commit()
        except sqlite3.Error as exc:
            self._db.rollback()
            raise DeliveryStateError("delivery reservation failed") from exc
        record = self.record(reservation_id)
        if record is None or record.intent != intent:
            raise DeliveryStateError("delivery reservation identity conflict")
        return record

    def prepare(
        self,
        reservation_id: str,
        *,
        message: str,
        metadata: Mapping[str, Any] | None,
    ) -> DeliveryRecord:
        if not message or len(message.encode()) > _MAX_MESSAGE_BYTES:
            raise DeliveryStateError("delivery payload is empty or too large")
        current = self.record(reservation_id)
        if current is None or current.intent.kind == "approval_capability":
            raise DeliveryStateError("ordinary delivery reservation is unavailable")
        digest = _hash(message)
        delivery_id = f"dly-{_hash(reservation_id + '\0' + digest)}"
        metadata_json = _canonical(dict(metadata or {}))
        if current.state != "preparing":
            if (
                current.delivery_id != delivery_id
                or current.payload_digest != digest
                or current.metadata != dict(metadata or {})
            ):
                raise DeliveryStateError("delivery payload conflicts with durable identity")
            return current
        self._update(
            reservation_id,
            allowed={"preparing"},
            fields={
                "delivery_id": delivery_id,
                "payload": message,
                "payload_digest": digest,
                "metadata_json": metadata_json,
                "state": "prepared",
            },
        )
        return self._required(reservation_id)

    def claim_attempt(self, reservation_id: str) -> DeliveryRecord | None:
        changed = self._update(
            reservation_id,
            allowed={"prepared"},
            fields={"state": "attempt_started"},
            required=False,
        )
        return self.record(reservation_id) if changed else None

    def mark_delivered(
        self,
        reservation_id: str,
        receipt: ProviderDeliveryReceipt,
    ) -> DeliveryRecord:
        record = self._required(reservation_id)
        if (
            not receipt.provider.strip()
            or not receipt.receipt_id.strip()
            or receipt.provider != record.intent.target.channel
            or receipt.delivery_id not in {"", record.delivery_id}
        ):
            raise DeliveryStateError("delivery receipt identity is invalid")
        receipt = replace(receipt, delivery_id=record.delivery_id)
        self._transition(
            reservation_id,
            "delivered",
            "provider_acknowledged",
            allowed={"attempt_started"},
            receipt=receipt,
        )
        return self._required(reservation_id)

    def mark_failed_pre_effect(self, reservation_id: str, reason: str) -> DeliveryRecord:
        self._transition(
            reservation_id, "failed_pre_effect", reason, allowed={"preparing", "prepared"}
        )
        return self._required(reservation_id)

    def mark_outcome_unknown(self, reservation_id: str, reason: str) -> DeliveryRecord:
        self._transition(reservation_id, "outcome_unknown", reason, allowed={"attempt_started"})
        return self._required(reservation_id)

    def mark_cancelled(self, reservation_id: str, reason: str) -> DeliveryRecord:
        self._transition(reservation_id, "cancelled", reason, allowed={"prepared"})
        return self._required(reservation_id)

    def mark_superseded(self, reservation_id: str, successor_id: str) -> DeliveryRecord:
        self._transition(
            reservation_id,
            "superseded",
            f"superseded_by:{successor_id}",
            allowed={"attempt_started", "outcome_unknown", "prepared"},
        )
        return self._required(reservation_id)

    def _transition(
        self,
        reservation_id: str,
        state: str,
        reason: str,
        *,
        allowed: set[str],
        receipt: ProviderDeliveryReceipt | None = None,
    ) -> None:
        receipt_json = _canonical(asdict(receipt)) if receipt else "{}"
        self._update(
            reservation_id,
            allowed=allowed,
            fields={"state": state, "reason": reason, "receipt_json": receipt_json},
        )

    def _update(
        self,
        reservation_id: str,
        *,
        allowed: set[str],
        fields: Mapping[str, Any],
        required: bool = True,
    ) -> bool:
        permitted = {
            "delivery_id",
            "payload",
            "payload_digest",
            "metadata_json",
            "state",
            "receipt_json",
            "reason",
        }
        if not fields or not set(fields).issubset(permitted):
            raise DeliveryStateError("delivery state update is invalid")
        assignments = ", ".join(f"{key} = ?" for key in fields)
        placeholders = ",".join("?" for _ in allowed)
        values = [*fields.values(), datetime.now(UTC).isoformat(), reservation_id, *sorted(allowed)]
        try:
            self._db.execute("BEGIN IMMEDIATE")
            cursor = self._db.execute(
                f"UPDATE deliveries SET {assignments}, updated_at = ? "
                f"WHERE reservation_id = ? AND state IN ({placeholders})",
                values,
            )
            self._db.commit()
        except sqlite3.Error as exc:
            self._db.rollback()
            raise DeliveryStateError("delivery state transition failed") from exc
        if required and cursor.rowcount != 1:
            raise DeliveryStateError("delivery state transition was rejected")
        return cursor.rowcount == 1

    def record(self, reservation_id: str) -> DeliveryRecord | None:
        try:
            row = self._db.execute(
                "SELECT * FROM deliveries WHERE reservation_id = ?", (reservation_id,)
            ).fetchone()
        except sqlite3.Error as exc:
            raise DeliveryStateError("delivery record read failed") from exc
        return self._decode(row) if row else None

    def records(self, *states: str) -> list[DeliveryRecord]:
        try:
            if states:
                placeholders = ",".join("?" for _ in states)
                rows = self._db.execute(
                    f"SELECT * FROM deliveries WHERE state IN ({placeholders}) ORDER BY created_at",
                    states,
                ).fetchall()
            else:
                rows = self._db.execute("SELECT * FROM deliveries ORDER BY created_at").fetchall()
        except sqlite3.Error as exc:
            raise DeliveryStateError("delivery records read failed") from exc
        return [self._decode(row) for row in rows]

    def reset(self) -> int:
        try:
            self._db.execute("BEGIN IMMEDIATE")
            count = int(self._db.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0])
            self._db.execute("DELETE FROM deliveries")
            self._db.commit()
            return count
        except sqlite3.Error as exc:
            self._db.rollback()
            raise DeliveryStateError("delivery reset failed") from exc

    def close(self) -> None:
        self._db.close()

    def _required(self, reservation_id: str) -> DeliveryRecord:
        record = self.record(reservation_id)
        if record is None:
            raise DeliveryStateError("delivery record is missing")
        return record

    @staticmethod
    def _decode(row: sqlite3.Row) -> DeliveryRecord:
        try:
            raw_intent = json.loads(str(row["intent_json"]))
            raw_metadata = json.loads(str(row["metadata_json"]))
            raw_receipt = json.loads(str(row["receipt_json"]))
            if not all(isinstance(item, dict) for item in (raw_intent, raw_metadata, raw_receipt)):
                raise TypeError("delivery JSON field is not a mapping")
            intent = DeliveryIntent(
                source_id=str(raw_intent["source_id"]),
                kind=str(raw_intent["kind"]),
                target=DeliveryTarget.model_validate(raw_intent["target"]),
                generation=int(raw_intent["generation"]),
                predecessor_id=str(raw_intent["predecessor_id"]),
                message_prefix=str(raw_intent["message_prefix"]),
            )
            expiry_raw = str(raw_intent["expires_at"])
            confirmation_id = str(raw_intent["confirmation_id"])
            expires_at = datetime.fromisoformat(expiry_raw) if expiry_raw else None
            receipt = (
                ProviderDeliveryReceipt(
                    provider=str(raw_receipt["provider"]),
                    receipt_id=str(raw_receipt["receipt_id"]),
                    delivery_id=str(raw_receipt.get("delivery_id", "")),
                )
                if raw_receipt
                else None
            )
            state = str(row["state"])
            if state not in {"preparing", "prepared", "attempt_started", *_TERMINAL}:
                raise ValueError("unknown delivery state")
            reservation_id = str(row["reservation_id"])
            delivery_id = str(row["delivery_id"] or "")
            payload = str(row["payload"])
            payload_digest = str(row["payload_digest"])
            intent_payload = _intent_payload(
                intent, confirmation_id=confirmation_id, expires_at=expires_at
            )
            serialized = _canonical(intent_payload)
            intent_payload["message_prefix"] = ""
            expected_reservation = (
                f"dres-{_hash('shisad.delivery.reservation.v1\0' + _canonical(intent_payload))}"
            )
            expected_digest = (
                _hash(serialized)
                if intent.kind == "approval_capability"
                else (_hash(payload) if delivery_id else "")
            )
            expected_delivery = (
                f"dly-{_hash(reservation_id + '\0' + expected_digest)}" if expected_digest else ""
            )
            if (
                reservation_id != expected_reservation
                or payload_digest != expected_digest
                or delivery_id != expected_delivery
                or (bool(receipt) != (state == "delivered"))
                or (state == "preparing" and bool(delivery_id))
                or (state not in {"preparing", "failed_pre_effect"} and not delivery_id)
                or (
                    receipt is not None
                    and (
                        not receipt.provider.strip()
                        or not receipt.receipt_id.strip()
                        or receipt.delivery_id != delivery_id
                    )
                )
                or (bool(delivery_id) and not payload and intent.kind != "approval_capability")
                or (intent.kind == "approval_capability" and (payload or raw_metadata))
                or (state == "preparing" and intent.kind == "approval_capability")
                or (state in {"superseded", "cancelled"} and intent.kind != "approval_capability")
                or (
                    intent.kind == "approval_capability"
                    and (
                        not confirmation_id
                        or expires_at is None
                        or intent.source_id != f"confirmation:{confirmation_id}"
                    )
                )
                or (
                    intent.kind != "approval_capability"
                    and (confirmation_id or expires_at is not None)
                )
            ):
                raise ValueError("delivery row identity is inconsistent")
            return DeliveryRecord(
                reservation_id=reservation_id,
                delivery_id=delivery_id,
                intent=_validated_intent(intent),
                payload=payload,
                payload_digest=payload_digest,
                metadata={str(key): value for key, value in raw_metadata.items()},
                confirmation_id=confirmation_id,
                expires_at=expires_at,
                state=state,
                receipt=receipt,
                reason=str(row["reason"]),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise DeliveryStateError("delivery row is malformed") from exc


class ChannelDeliveryService:
    def __init__(
        self,
        channels: Mapping[str, Channel],
        *,
        state_root: Path,
        transcript_store: TranscriptStore | None = None,
    ) -> None:
        self._channels = dict(channels)
        self._transcripts = transcript_store
        self._state_error = ""
        self._active_attempts = 0
        try:
            self._store: _DeliveryStore | None = _DeliveryStore(state_root)
        except (DeliveryStateError, OSError) as exc:
            self._store = None
            self._state_error = str(exc)
            logger.error("Outbound delivery state degraded: %s", exc)

    def reserve(self, intent: DeliveryIntent) -> DeliveryRecord:
        return self._require_store().reserve(intent)

    def prepare(
        self,
        reservation_id: str,
        *,
        message: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> DeliveryRecord:
        store = self._require_store()
        record = store.record(reservation_id)
        if record is None:
            raise DeliveryStateError("delivery reservation was not found")
        return store.prepare(
            reservation_id,
            message=f"{record.intent.message_prefix}{message}",
            metadata=metadata,
        )

    def record(self, reservation_id: str) -> DeliveryRecord | None:
        return self._require_store().record(reservation_id)

    async def send(
        self,
        *,
        intent: DeliveryIntent,
        message: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> DeliveryResult:
        try:
            reserved = self.reserve(intent)
            prepared = self.prepare(reserved.reservation_id, message=message, metadata=metadata)
        except DeliveryStateError:
            return self._unavailable(intent.target)
        return await self.send_prepared(prepared.reservation_id)

    async def send_prepared(self, reservation_id: str) -> DeliveryResult:
        try:
            store = self._require_store()
            record = store.record(reservation_id)
        except DeliveryStateError:
            return self._unavailable()
        if record is None:
            return DeliveryResult(False, False, "delivery_not_found")
        if record.state != "prepared":
            return self._result(record)
        blocked = self._pre_effect_block(record)
        if blocked:
            try:
                return self._result(store.mark_failed_pre_effect(reservation_id, blocked))
            except DeliveryStateError:
                return self._unavailable(record.intent.target)
        try:
            claimed = store.claim_attempt(reservation_id)
        except DeliveryStateError:
            return self._unavailable(record.intent.target)
        return (
            await self._perform(claimed) if claimed else self._result(store.record(reservation_id))
        )

    async def send_capability(
        self,
        *,
        intent: CapabilityDeliveryIntent,
        resolver: Callable[..., Awaitable[CapabilityPayload | None]],
        rotate: bool = False,
    ) -> DeliveryResult:
        expiry = _expiry(intent.expires_at)
        ordinary = DeliveryIntent(
            source_id=f"confirmation:{intent.confirmation_id.strip()}",
            kind="approval_capability",
            target=intent.target,
            generation=intent.generation,
            predecessor_id=intent.predecessor_id,
        )
        try:
            store = self._require_store()
            record = store.reserve(
                ordinary,
                confirmation_id=intent.confirmation_id,
                expires_at=expiry,
            )
        except DeliveryStateError:
            return self._unavailable(intent.target)
        if expiry <= datetime.now(UTC):
            return self._result(store.mark_cancelled(record.reservation_id, "capability_expired"))
        if record.state != "prepared":
            return self._result(record)
        try:
            payload = await resolver(intent, rotate=rotate)
        except Exception:
            logger.exception("Capability delivery resolution failed")
            payload = None
        if payload is None:
            return self._result(store.mark_cancelled(record.reservation_id, "capability_not_live"))
        payload_expiry = _expiry(payload.expires_at)
        if (
            payload_expiry <= datetime.now(UTC)
            or payload_expiry > expiry
            or not payload.message
            or len(payload.message.encode()) > _MAX_MESSAGE_BYTES
        ):
            return self._result(
                store.mark_cancelled(record.reservation_id, "capability_payload_invalid")
            )
        blocked = self._pre_effect_block(record)
        if blocked:
            return self._result(store.mark_failed_pre_effect(record.reservation_id, blocked))
        claimed = store.claim_attempt(record.reservation_id)
        if claimed:
            return await self._perform(claimed, transient_message=payload.message)
        return self._result(store.record(record.reservation_id))

    async def recover(
        self,
        *,
        capability_resolver: Callable[..., Awaitable[CapabilityPayload | None]] | None = None,
    ) -> list[DeliveryResult]:
        try:
            store = self._require_store()
            self._reconcile_preparing(store)
            records = store.records("prepared", "attempt_started")
        except DeliveryStateError as exc:
            self._store, self._state_error = None, str(exc)
            return [self._unavailable()]
        results: list[DeliveryResult] = []
        for record in records:
            try:
                if record.state == "prepared":
                    if record.intent.kind != "approval_capability":
                        results.append(await self.send_prepared(record.reservation_id))
                    elif capability_resolver:
                        results.append(
                            await self.send_capability(
                                intent=self._capability_intent(record),
                                resolver=capability_resolver,
                                rotate=True,
                            )
                        )
                    continue
                if record.intent.kind == "approval_capability" and capability_resolver:
                    successor = store.reserve(
                        replace(
                            record.intent,
                            generation=record.intent.generation + 1,
                            predecessor_id=record.delivery_id,
                        ),
                        confirmation_id=record.confirmation_id,
                        expires_at=record.expires_at,
                    )
                    store.mark_superseded(record.reservation_id, successor.delivery_id)
                    results.append(
                        await self.send_capability(
                            intent=self._capability_intent(successor),
                            resolver=capability_resolver,
                            rotate=True,
                        )
                    )
                elif record.intent.kind == "approval_capability":
                    unresolved = store.mark_outcome_unknown(
                        record.reservation_id, "capability_resolver_unavailable"
                    )
                    results.append(self._result(unresolved))
                else:
                    results.append(await self._recover_attempt(record))
            except DeliveryStateError as exc:
                with contextlib.suppress(Exception):
                    store.close()
                self._store = None
                self._state_error = str(exc)
                return [*results, self._unavailable(record.intent.target)]
        return results

    def reset(self) -> int:
        if self._active_attempts:
            raise DeliveryStateError("delivery reset refused while an attempt is active")
        return self._require_store().reset()

    def close(self) -> None:
        if self._store is not None:
            self._store.close()

    def health_status(self) -> dict[str, dict[str, Any]]:
        status: dict[str, dict[str, Any]] = {}
        for name, channel in self._channels.items():
            try:
                channel_status = channel.health_status()
                capability = channel.delivery_recovery_capability()
                channel_status["delivery_recovery"] = {
                    "kind": capability.kind.value,
                    "guarantee_id": capability.guarantee_id,
                }
            except Exception:
                channel_status = {"connected": False, "error": "health_status_failed"}
            status[name] = channel_status
        if self._store is None:
            status["_outbox"] = {"status": "degraded", "reason": self._state_error}
            return status
        try:
            counts: dict[str, int] = {}
            unresolved: list[str] = []
            for record in self._store.records():
                counts[record.state] = counts.get(record.state, 0) + 1
                if record.state in {"preparing", "prepared", "attempt_started", "outcome_unknown"}:
                    unresolved.append(record.delivery_id or record.reservation_id)
            status["_outbox"] = {
                "status": "ok",
                "states": counts,
                "unresolved_ids": unresolved,
            }
        except DeliveryStateError as exc:
            status["_outbox"] = {"status": "degraded", "reason": str(exc)}
        return status

    async def _perform(
        self,
        record: DeliveryRecord,
        *,
        transient_message: str | None = None,
    ) -> DeliveryResult:
        store = self._require_store()
        message = transient_message if transient_message is not None else record.payload
        self._active_attempts += 1
        try:
            if record.intent.target.channel == "session":
                receipt = self._append_local(record, message)
            else:
                channel = self._channels[record.intent.target.channel]
                metadata = dict(record.metadata)
                metadata["shisad_delivery_id"] = record.delivery_id
                capability = channel.delivery_recovery_capability()
                if (
                    capability.kind is DeliveryRecoveryKind.EXACT_IDEMPOTENCY_KEY
                    and capability.guarantee_id.endswith(".v1")
                ):
                    metadata["shisad_idempotency_key"] = record.delivery_id
                receipt = await channel.send(
                    message, target=record.intent.target, metadata=metadata
                ) or ProviderDeliveryReceipt(
                    provider=record.intent.target.channel,
                    receipt_id=f"provider-call-returned:{record.delivery_id}",
                    delivery_id=record.delivery_id,
                )
        except asyncio.CancelledError:
            with contextlib.suppress(Exception):
                store.mark_outcome_unknown(record.reservation_id, "cancelled_after_attempt")
            raise
        except Exception:
            logger.exception("Outbound provider attempt has unknown outcome")
            try:
                return self._result(
                    store.mark_outcome_unknown(record.reservation_id, "provider_attempt_failed")
                )
            except DeliveryStateError:
                return self._uncertain(record, "receipt_state_unavailable")
        else:
            try:
                return self._result(store.mark_delivered(record.reservation_id, receipt))
            except Exception:
                return self._uncertain(record, "receipt_persistence_failed", receipt.receipt_id)
        finally:
            self._active_attempts -= 1

    async def _recover_attempt(self, record: DeliveryRecord) -> DeliveryResult:
        store = self._require_store()
        if record.intent.target.channel == "session":
            receipt = self._local_receipt(record)
            return (
                self._result(store.mark_delivered(record.reservation_id, receipt))
                if receipt
                else await self._perform(record)
            )
        channel = self._channels.get(record.intent.target.channel)
        if channel is None:
            return self._result(
                store.mark_outcome_unknown(record.reservation_id, "channel_not_available")
            )
        try:
            capability = channel.delivery_recovery_capability()
        except Exception:
            capability = None
        if (
            capability
            and capability.guarantee_id.endswith(".v1")
            and capability.kind is DeliveryRecoveryKind.EXACT_IDEMPOTENCY_KEY
        ):
            return await self._perform(record)
        if (
            capability
            and capability.guarantee_id.endswith(".v1")
            and capability.kind is DeliveryRecoveryKind.AUTHORITATIVE_RECONCILIATION
        ):
            try:
                reconciled = await channel.reconcile_delivery(
                    delivery_id=record.delivery_id, target=record.intent.target
                )
            except Exception:
                reconciled = None
            if (
                reconciled
                and reconciled.status is DeliveryReconciliationStatus.DELIVERED
                and reconciled.receipt
            ):
                try:
                    return self._result(
                        store.mark_delivered(record.reservation_id, reconciled.receipt)
                    )
                except DeliveryStateError:
                    return self._uncertain(record, "reconciliation_receipt_invalid")
            if reconciled and reconciled.status is DeliveryReconciliationStatus.ABSENT:
                return await self._perform(record)
        return self._result(
            store.mark_outcome_unknown(record.reservation_id, "informed_recovery_required")
        )

    def _reconcile_preparing(self, store: _DeliveryStore) -> None:
        for record in store.records("preparing"):
            match = self._transcript_result(record)
            if not match or len(match.encode()) > _MAX_MESSAGE_BYTES:
                store.mark_failed_pre_effect(
                    record.reservation_id, "result_unavailable_or_invalid_before_restart"
                )
            else:
                store.prepare(
                    record.reservation_id,
                    message=match,
                    metadata={},
                )

    def _transcript_result(self, record: DeliveryRecord) -> str | None:
        if self._transcripts is None:
            return None
        expected_target = record.intent.target.model_dump(mode="json")
        for session_id in self._transcripts.list_session_ids():
            for entry in self._transcripts.list_entries(session_id):
                if (
                    entry.role == "assistant"
                    and not entry.metadata.get("_archive_imported")
                    and str(entry.metadata.get("outbound_delivery_reservation_id", ""))
                    == record.reservation_id
                    and entry.metadata.get("delivery_target") == expected_target
                ):
                    return self._transcripts.entry_content(entry)
        return None

    def _append_local(self, record: DeliveryRecord, message: str) -> ProviderDeliveryReceipt:
        existing = self._local_receipt(record)
        if existing:
            return existing
        if self._transcripts is None:
            raise DeliveryStateError("session transcript delivery is unavailable")
        metadata = dict(record.metadata)
        metadata.update(
            {
                "channel": "session",
                "delivery_target": record.intent.target.model_dump(mode="json"),
                "outbound_delivery_id": record.delivery_id,
            }
        )
        entry = self._transcripts.append(
            SessionId(record.intent.target.recipient),
            role="assistant",
            content=message,
            taint_labels=set(),
            metadata=metadata,
            durable=True,
        )
        return ProviderDeliveryReceipt("session", entry.entry_id, record.delivery_id)

    def _local_receipt(self, record: DeliveryRecord) -> ProviderDeliveryReceipt | None:
        if self._transcripts is None:
            return None
        entries = self._transcripts.list_entries(SessionId(record.intent.target.recipient))
        for entry in entries:
            if entry.metadata.get("_archive_imported"):
                continue
            if str(entry.metadata.get("outbound_delivery_id", "")) == record.delivery_id:
                return ProviderDeliveryReceipt("session", entry.entry_id, record.delivery_id)
        return None

    def _pre_effect_block(self, record: DeliveryRecord) -> str:
        channel_name = record.intent.target.channel
        if channel_name == "session":
            return "" if self._transcripts else "session_delivery_unavailable"
        channel = self._channels.get(channel_name)
        if channel is None:
            return "channel_not_available"
        try:
            status = channel.health_status()
        except Exception:
            return "channel_health_unavailable"
        if status.get("available", getattr(channel, "available", True)) is False:
            return "channel_dependency_unavailable"
        if status.get("connected", getattr(channel, "connected", True)) is False:
            return "channel_not_connected"
        return ""

    @staticmethod
    def _capability_intent(record: DeliveryRecord) -> CapabilityDeliveryIntent:
        if record.expires_at is None:
            raise DeliveryStateError("capability expiry is missing")
        return CapabilityDeliveryIntent(
            confirmation_id=record.confirmation_id,
            target=record.intent.target,
            expires_at=record.expires_at,
            generation=record.intent.generation,
            predecessor_id=record.intent.predecessor_id,
        )

    def _require_store(self) -> _DeliveryStore:
        if self._store is None:
            raise DeliveryStateError(self._state_error or "delivery state unavailable")
        return self._store

    @staticmethod
    def _unavailable(target: DeliveryTarget | None = None) -> DeliveryResult:
        return DeliveryResult(False, False, "delivery_state_unavailable", target, state="degraded")

    @staticmethod
    def _result(record: DeliveryRecord | None) -> DeliveryResult:
        if record is None:
            return DeliveryResult(False, False, "delivery_not_found")
        return DeliveryResult(
            attempted=record.state
            in {"attempt_started", "delivered", "outcome_unknown", "superseded"},
            sent=record.state == "delivered",
            reason=record.reason or record.state,
            target=record.intent.target,
            reservation_id=record.reservation_id,
            delivery_id=record.delivery_id,
            state=record.state,
            outcome_unknown=record.state in {"attempt_started", "outcome_unknown"},
            receipt_id=record.receipt.receipt_id if record.receipt else "",
        )

    @staticmethod
    def _uncertain(
        record: DeliveryRecord,
        reason: str,
        receipt_id: str = "",
    ) -> DeliveryResult:
        return DeliveryResult(
            True,
            False,
            reason,
            record.intent.target,
            record.reservation_id,
            record.delivery_id,
            "attempt_started",
            True,
            receipt_id,
        )
