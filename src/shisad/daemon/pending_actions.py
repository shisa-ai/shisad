"""Service-owned pending-action record store and durable schema boundary."""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, fields, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from shisad.core.action_state import (
    PendingActionTransitionKind,
    PendingActionTransitionRule,
    pending_action_transition_rule,
)
from shisad.core.approval import (
    quarantine_state_file,
    safe_compare_text,
)
from shisad.core.atomic_state import (
    AtomicWriteError,
    AtomicWriteFaultInjector,
    AtomicWriteStage,
    StatePersistenceDegradedError,
    atomic_write_bytes,
)
from shisad.core.pending_action import (
    PENDING_ACTION_RECORD_SCHEMA_VERSION,
    PendingActionRecord,
)
from shisad.core.types import SessionId


class PendingActionStoreLoadStatus(StrEnum):
    MISSING = "missing"
    CURRENT = "current"
    LEGACY = "legacy"
    CORRUPT = "corrupt"
    UNSUPPORTED_SCHEMA = "unsupported_schema"


@dataclass(frozen=True, slots=True)
class PendingActionStoreLoadResult:
    status: PendingActionStoreLoadStatus
    payloads: tuple[dict[str, Any], ...] = ()
    reason: str = ""
    quarantined_path: Path | None = None


class PendingActionPayloadError(AtomicWriteError):
    """A current payload was rejected before atomic publication began."""

    def __init__(self, *, path: Path, reason: str) -> None:
        self.reason = reason
        super().__init__(
            path=path,
            stage=AtomicWriteStage.WRITE,
            publication_may_have_committed=False,
        )


class _RejectedPendingJSON(ValueError):
    pass


def _reject_nonfinite(value: str) -> None:
    raise _RejectedPendingJSON(f"non-finite JSON number: {value}")


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, member in pairs:
        if key in value:
            raise _RejectedPendingJSON(f"duplicate JSON member: {key}")
        value[key] = member
    return value


class PendingActionStore:
    """Own one daemon's pending records, session index, and durable path."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.actions: dict[str, PendingActionRecord] = {}
        self.by_session: dict[SessionId, list[str]] = {}

    def add(self, record: PendingActionRecord) -> None:
        confirmation_id = record.confirmation_id.strip()
        if not confirmation_id or confirmation_id != record.confirmation_id:
            raise ValueError("pending action confirmation ID is not canonical")
        if confirmation_id in self.actions:
            raise ValueError(f"duplicate pending action confirmation ID: {confirmation_id}")
        self.actions[confirmation_id] = record
        self.by_session.setdefault(record.session_id, []).append(confirmation_id)

    def remove(self, confirmation_id: str) -> PendingActionRecord | None:
        record = self.actions.pop(confirmation_id, None)
        if record is None:
            return None
        remaining = [
            candidate
            for candidate in self.by_session.get(record.session_id, ())
            if candidate != confirmation_id
        ]
        if remaining:
            self.by_session[record.session_id] = remaining
        else:
            self.by_session.pop(record.session_id, None)
        return record

    @staticmethod
    def assert_maps_index_parity(
        actions: Mapping[str, PendingActionRecord],
        by_session: Mapping[SessionId, Sequence[str]],
    ) -> None:
        expected: dict[SessionId, list[str]] = {}
        for confirmation_id, record in actions.items():
            if confirmation_id != record.confirmation_id or not confirmation_id.strip():
                raise ValueError("pending action map identity mismatch")
            expected.setdefault(record.session_id, []).append(confirmation_id)
        actual = {session_id: list(values) for session_id, values in by_session.items() if values}
        if actual != expected:
            raise ValueError("pending action session index mismatch")

    def assert_index_parity(self) -> None:
        self.assert_maps_index_parity(self.actions, self.by_session)

    def write_payloads(
        self,
        payloads: Sequence[Mapping[str, Any]],
        *,
        fault_injector: AtomicWriteFaultInjector | None = None,
    ) -> None:
        try:
            rows = [dict(payload) for payload in payloads]
        except (TypeError, ValueError) as exc:
            raise PendingActionPayloadError(path=self.path, reason=str(exc)) from exc
        status, reason = self._classify_rows(rows, allow_legacy=False)
        if status is not PendingActionStoreLoadStatus.CURRENT:
            raise PendingActionPayloadError(
                path=self.path,
                reason=reason or "pending action payload is not current",
            )
        try:
            encoded = json.dumps(rows, indent=2, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, UnicodeEncodeError) as exc:
            raise PendingActionPayloadError(path=self.path, reason=str(exc)) from exc
        atomic_write_bytes(
            self.path,
            encoded,
            fault_injector=fault_injector,
        )

    def load_payloads(self) -> PendingActionStoreLoadResult:
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return PendingActionStoreLoadResult(status=PendingActionStoreLoadStatus.MISSING)
        except OSError as exc:
            return self.quarantine_unusable(
                PendingActionStoreLoadStatus.CORRUPT,
                f"pending state read failed: {exc}",
            )
        try:
            decoded = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_members,
                parse_constant=_reject_nonfinite,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, _RejectedPendingJSON) as exc:
            return self.quarantine_unusable(PendingActionStoreLoadStatus.CORRUPT, str(exc))
        if not isinstance(decoded, list) or not all(isinstance(row, dict) for row in decoded):
            return self.quarantine_unusable(
                PendingActionStoreLoadStatus.CORRUPT,
                "pending state must be a list of records",
            )
        rows = [dict(row) for row in decoded]
        status, reason = self._classify_rows(rows, allow_legacy=True)
        if status in {
            PendingActionStoreLoadStatus.CORRUPT,
            PendingActionStoreLoadStatus.UNSUPPORTED_SCHEMA,
        }:
            return self.quarantine_unusable(status, reason)
        return PendingActionStoreLoadResult(status=status, payloads=tuple(rows))

    def quarantine_unusable(
        self,
        status: PendingActionStoreLoadStatus,
        reason: str,
    ) -> PendingActionStoreLoadResult:
        if status not in {
            PendingActionStoreLoadStatus.CORRUPT,
            PendingActionStoreLoadStatus.UNSUPPORTED_SCHEMA,
        }:
            raise ValueError("only unusable pending state may be quarantined")
        quarantined = quarantine_state_file(self.path, label="pending_action")
        return PendingActionStoreLoadResult(
            status=status,
            reason=reason,
            quarantined_path=quarantined,
        )

    @staticmethod
    def _classify_rows(
        rows: Sequence[Mapping[str, Any]],
        *,
        allow_legacy: bool,
    ) -> tuple[PendingActionStoreLoadStatus, str]:
        legacy = False
        confirmation_ids: set[str] = set()
        for row in rows:
            schema_is_missing = "record_schema_version" not in row
            version = row.get("record_schema_version")
            if schema_is_missing:
                if not allow_legacy:
                    return (
                        PendingActionStoreLoadStatus.CORRUPT,
                        "pending action record schema is missing",
                    )
                legacy = True
            elif type(version) is not int or version < 1:
                return (
                    PendingActionStoreLoadStatus.CORRUPT,
                    "pending action record schema is invalid",
                )
            elif version > PENDING_ACTION_RECORD_SCHEMA_VERSION:
                return (
                    PendingActionStoreLoadStatus.UNSUPPORTED_SCHEMA,
                    f"unsupported pending action record schema: {version}",
                )
            elif version != PENDING_ACTION_RECORD_SCHEMA_VERSION:
                return (
                    PendingActionStoreLoadStatus.CORRUPT,
                    f"invalid pending action record schema: {version}",
                )

            confirmation_id = row.get("confirmation_id")
            if isinstance(confirmation_id, str) and confirmation_id.strip():
                if confirmation_id in confirmation_ids:
                    return (
                        PendingActionStoreLoadStatus.CORRUPT,
                        f"duplicate pending action confirmation ID: {confirmation_id}",
                    )
                confirmation_ids.add(confirmation_id)
            if schema_is_missing:
                continue
            session_id = row.get("session_id")
            identity = row.get("identity")
            if (
                not isinstance(confirmation_id, str)
                or confirmation_id != confirmation_id.strip()
                or not confirmation_id
                or not isinstance(session_id, str)
                or session_id != session_id.strip()
                or not session_id
                or not isinstance(identity, Mapping)
                or identity.get("confirmation_id") != confirmation_id
                or identity.get("session_id") != session_id
            ):
                return (
                    PendingActionStoreLoadStatus.CORRUPT,
                    "pending action current-record identity mismatch",
                )
        return (
            PendingActionStoreLoadStatus.LEGACY if legacy else PendingActionStoreLoadStatus.CURRENT,
            "",
        )


class PendingActionTransitionError(ValueError):
    """A lifecycle request failed before any accepted state mutation."""

    def __init__(
        self,
        reason: str,
        *,
        operation: PendingActionTransitionKind | str = "",
        detail: str = "",
    ) -> None:
        self.reason = reason
        self.operation = str(operation)
        self.detail = detail
        suffix = f": {detail}" if detail else ""
        super().__init__(f"{reason} ({self.operation}){suffix}")


def _transition_error(
    reason: str,
    operation: PendingActionTransitionKind | str,
    detail: str = "",
) -> PendingActionTransitionError:
    return PendingActionTransitionError(reason, operation=operation, detail=detail)


@dataclass(frozen=True, slots=True)
class PendingActionTransitionGuard:
    """Expected immutable and one-shot bindings for one transition."""

    expected_record_schema_version: int
    expected_confirmation_id: str
    expected_session_id: str
    expected_user_id: str
    expected_workspace_id: str
    expected_action_id: str
    expected_decision_nonce: str | None = None
    expected_evidence_hash: str | None = None
    expected_approver_principal_id: str | None = None
    expected_execution_attempt_id: str | None = None
    expected_result_id: str | None = None
    expected_recovery_authority_mac: str | None = None

    @classmethod
    def for_record(
        cls,
        record: PendingActionRecord,
        *,
        decision_nonce: str | None = None,
        evidence_hash: str | None = None,
        approver_principal_id: str | None = None,
        execution_attempt_id: str | None = None,
        result_id: str | None = None,
        recovery_authority_mac: str | None = None,
    ) -> PendingActionTransitionGuard:
        return cls(
            expected_record_schema_version=PENDING_ACTION_RECORD_SCHEMA_VERSION,
            expected_confirmation_id=str(record.confirmation_id),
            expected_session_id=str(record.session_id),
            expected_user_id=str(record.user_id),
            expected_workspace_id=str(record.workspace_id),
            expected_action_id=str(record.action_id),
            expected_decision_nonce=decision_nonce,
            expected_evidence_hash=evidence_hash,
            expected_approver_principal_id=approver_principal_id,
            expected_execution_attempt_id=execution_attempt_id,
            expected_result_id=result_id,
            expected_recovery_authority_mac=recovery_authority_mac,
        )


@dataclass(frozen=True, slots=True)
class PendingActionMutationSnapshot:
    """Exact shallow record state before a lifecycle persistence boundary."""

    values: tuple[object, ...]

    @classmethod
    def capture(cls, record: PendingActionRecord) -> PendingActionMutationSnapshot:
        return cls(tuple(getattr(record, item.name) for item in fields(record)))

    def restore(self, record: PendingActionRecord) -> None:
        for item, value in zip(fields(record), self.values, strict=True):
            setattr(record, item.name, value)


def capture_pending_action_mutation(
    record: PendingActionRecord,
) -> PendingActionMutationSnapshot:
    return PendingActionMutationSnapshot.capture(record)


def restore_pending_action_mutation(
    record: PendingActionRecord,
    snapshot: PendingActionMutationSnapshot,
) -> None:
    snapshot.restore(record)


PendingSchedulerAccountingMode = Literal["failure", "shadow_only", "ambiguous"]


class PendingActionMutationKind(StrEnum):
    START = "start"
    DECISION = "decision"
    STAGE2 = "stage2"
    EXECUTION = "execution"
    RECOVERY = "recovery"
    SCHEDULER = "scheduler"
    PERSISTENCE = "persistence"


@dataclass(frozen=True, slots=True)
class PendingActionMutation:
    kind: PendingActionMutationKind
    values: Mapping[str, object]


PendingActionPersistencePreparer = Callable[
    [Sequence[PendingActionRecord]],
    Sequence[tuple[PendingActionRecord, PendingActionMutation]],
]


@dataclass(frozen=True, slots=True)
class PendingActionTransitionRequest:
    """One validated lifecycle mutation and its compatibility accounting mode."""

    record: PendingActionRecord
    operation: PendingActionTransitionKind
    reason: str
    guard: PendingActionTransitionGuard
    rollback_snapshot: PendingActionMutationSnapshot | None = None
    scheduler_accounting_mode: PendingSchedulerAccountingMode | None = None
    mutation: PendingActionMutation | None = None
    retain_target_on_error: bool = False
    canonicalize_recovery_event_identity: bool = False


@dataclass(frozen=True, slots=True)
class PendingActionTransitionResult:
    record: PendingActionRecord
    operation: PendingActionTransitionKind
    source_status: str
    target_status: str
    changed: bool


@dataclass(frozen=True, slots=True)
class PendingActionUpdateRequest:
    record: PendingActionRecord
    mutation: PendingActionMutation
    guard: PendingActionTransitionGuard
    rollback_snapshot: PendingActionMutationSnapshot | None = None


@dataclass(frozen=True, slots=True)
class _PreparedPendingTransition:
    request: PendingActionTransitionRequest
    rule: PendingActionTransitionRule
    source_status: str
    reason: str
    changed: bool
    mutation_values: tuple[tuple[str, object], ...] = ()
    terminal_key: tuple[object, ...] = ()


def _mutation_fields(specification: str) -> frozenset[str]:
    return frozenset(specification.split())


_SCHEDULER_MUTATION_FIELDS = _mutation_fields(
    "recovery_accounting_pending recovery_effect_invoked recovery_scheduler_accounted "
    "recovery_scheduler_posture_captured recovery_scheduler_restore_enabled "
    "scheduler_accounting_pending scheduler_accounting_mode status_reason"
)
_RECOVERY_EVENT_MUTATION_FIELDS = _mutation_fields(
    "recovery_event_identity_untrusted recovery_event_identity_untrusted_at "
    "recovery_anonymous_accounting_id recovery_event_identity_trusted_at "
    "recovery_anonymous_accounting_id_trusted"
)
_RECOVERY_AUTHORITY_MUTATION_FIELDS = _mutation_fields(
    "approval_evidence_hash approval_task_envelope_id delivery_target "
    "execution_authorization_kind confirmation_evidence preflight_action merged_policy "
    "pep_context pep_elevation retry_descriptor"
)
_PENDING_ACTION_MUTATION_FIELDS: dict[PendingActionMutationKind, frozenset[str]] = {
    PendingActionMutationKind.START: _mutation_fields(
        "action_digest approval_evidence_hash confirmation_evidence execution_attempt_id "
        "result_id stage2_correlation_id stage2_previous_plan_hash stage2_plan_hash "
        "recovery_scheduler_posture_captured recovery_scheduler_restore_enabled"
    ),
    PendingActionMutationKind.DECISION: _mutation_fields(
        "approval_evidence_hash confirmation_evidence"
    ),
    PendingActionMutationKind.STAGE2: _mutation_fields("stage2_plan_hash status_reason"),
    PendingActionMutationKind.EXECUTION: (_SCHEDULER_MUTATION_FIELDS - {"status_reason"})
    | {"provider_operation_id"},
    PendingActionMutationKind.RECOVERY: _SCHEDULER_MUTATION_FIELDS
    | _RECOVERY_AUTHORITY_MUTATION_FIELDS
    | _mutation_fields(
        "retry_generation recovery_started_at recovery_result provider_operation_id"
    ),
    PendingActionMutationKind.SCHEDULER: _SCHEDULER_MUTATION_FIELDS,
    PendingActionMutationKind.PERSISTENCE: _RECOVERY_EVENT_MUTATION_FIELDS
    | {"result_id", "recovery_authority_mac"},
}

_PENDING_ACTION_TRANSITION_MUTATION_KINDS = {
    PendingActionTransitionKind.START: {PendingActionMutationKind.START},
    PendingActionTransitionKind.APPROVE: {PendingActionMutationKind.EXECUTION},
    PendingActionTransitionKind.REJECT: {PendingActionMutationKind.DECISION},
    PendingActionTransitionKind.FAIL: {
        PendingActionMutationKind.DECISION,
        PendingActionMutationKind.EXECUTION,
    },
    PendingActionTransitionKind.OUTCOME_UNKNOWN: {
        PendingActionMutationKind.EXECUTION,
        PendingActionMutationKind.RECOVERY,
        PendingActionMutationKind.SCHEDULER,
    },
    PendingActionTransitionKind.RECOVER_APPROVE: {PendingActionMutationKind.RECOVERY},
    PendingActionTransitionKind.RECOVER_FAIL: {PendingActionMutationKind.RECOVERY},
    PendingActionTransitionKind.INVALIDATE_RECOVERY: {
        PendingActionMutationKind.RECOVERY,
        PendingActionMutationKind.SCHEDULER,
    },
}
_PENDING_ACTION_STATUS_REASONS = {
    PendingActionMutationKind.STAGE2: {"confirmation_execution_started"},
    PendingActionMutationKind.SCHEDULER: {"legacy_scheduler_accounting_intent_unknown"},
    PendingActionMutationKind.RECOVERY: {
        "structural_retry_started",
        "stable_idempotency_key_retry_started",
    },
}


class PendingActionLifecycleService:
    """Own queue/index and finite durable mutations over one pending store."""

    def __init__(self, store: PendingActionStore) -> None:
        self.store = store
        self.degradation: dict[str, str] | None = None
        self._persistence_preparer: PendingActionPersistencePreparer | None = None
        self._queue_keys = {
            confirmation_id: self._queue_key(record)
            for confirmation_id, record in store.actions.items()
        }

    def bind_persistence_preparer(
        self,
        preparer: PendingActionPersistencePreparer,
    ) -> None:
        self._persistence_preparer = preparer

    def adopt_degradation(self, degradation: Mapping[str, Any] | None) -> None:
        if degradation is None:
            return
        self.degradation = {
            "transition": str(degradation.get("transition", "")),
            "stage": str(degradation.get("stage", "")),
            "reason": str(degradation.get("reason", "pending_state_persistence_degraded")),
        }

    def clear_degradation(self) -> None:
        self.degradation = None

    def reset(self) -> None:
        self.store.actions.clear()
        self.store.by_session.clear()
        self._queue_keys.clear()
        self.clear_degradation()

    def adopt_loaded(
        self,
        records: Sequence[PendingActionRecord],
    ) -> tuple[PendingActionRecord, ...]:
        self._raise_if_degraded()
        self._assert_store_index_parity("load")
        adopted = tuple(records)
        if not adopted and not self.store.actions:
            return ()
        staged = PendingActionStore(self.store.path)
        for record in adopted:
            confirmation_id = str(record.confirmation_id)
            if confirmation_id in staged.actions or confirmation_id in self.store.actions:
                raise _transition_error("duplicate_loaded_identity", "load", confirmation_id)
            self._validate_loaded_record(record)
            staged.add(record)
        if self.store.actions:
            raise _transition_error("loaded_store_not_empty", "load")
        staged.assert_index_parity()
        keys = {cid: self._queue_key(item) for cid, item in staged.actions.items()}
        self._restore_store_topology(staged.actions, staged.by_session, keys)
        return adopted

    def persist_adopted(self, *, persist: Callable[[], None]) -> None:
        self._raise_if_degraded()
        self._assert_store_index_parity("load")
        self._persist_with_rollback(
            self._capture_store_mutations(),
            label="load",
            persist=persist,
        )

    def update(
        self,
        request: PendingActionUpdateRequest,
        *,
        persist: Callable[[], None],
    ) -> bool:
        self._raise_if_degraded()
        self._assert_store_index_parity("update")
        record = request.record
        owned = self.store.actions.get(record.confirmation_id)
        if owned is not record:
            raise _transition_error("unowned_record", "update", record.confirmation_id)
        self._validate_guard_identity(record, request.guard, "update")
        kind, values = self._prepare_mutation(
            record,
            request.mutation,
            operation="update",
        )
        if kind.value in ["start", "decision", "persistence"]:
            raise PendingActionTransitionError("mutation_kind_invalid", operation="update")
        self._validate_update_guard(record, request.guard, kind)
        if not values:
            return False
        source_snapshots = self._capture_store_mutations()
        if request.rollback_snapshot is not None:
            source_snapshots[record.confirmation_id] = request.rollback_snapshot
        self._apply_mutation(record, values)
        self._persist_with_rollback(source_snapshots, label=kind.value, persist=persist)
        return True

    def purge(
        self,
        records: Sequence[PendingActionRecord],
        *,
        persist: Callable[[], None],
    ) -> tuple[PendingActionRecord, ...]:
        self._raise_if_degraded()
        self._assert_store_index_parity("purge")
        selected = tuple(records)
        if len({id(record) for record in selected}) != len(selected):
            raise _transition_error("duplicate_purge_record", "purge")
        for record in selected:
            if self.store.actions.get(record.confirmation_id) is not record:
                raise _transition_error("unowned_record", "purge", record.confirmation_id)
        if not selected:
            return ()

        source_actions = dict(self.store.actions)
        source_by_session = self._copy_session_index()
        source_queue_keys = dict(self._queue_keys)
        source_snapshots = self._capture_store_mutations()
        for record in selected:
            removed = self.store.remove(record.confirmation_id)
            if removed is not record:
                raise RuntimeError("pending purge lost record identity")
            self._queue_keys.pop(record.confirmation_id, None)
        try:
            self._persist(persist)
        except AtomicWriteError as write_error:
            target_actions = dict(self.store.actions)
            target_by_session = self._copy_session_index()
            target_queue_keys = dict(self._queue_keys)
            target_snapshots = self._capture_store_mutations()
            self._restore_store_topology(
                source_actions,
                source_by_session,
                source_queue_keys,
            )
            self._restore_store_mutations(source_snapshots)
            if write_error.publication_may_have_committed:
                try:
                    self._persist(persist)
                except AtomicWriteError as rollback_error:
                    self._restore_store_topology(
                        target_actions,
                        target_by_session,
                        target_queue_keys,
                    )
                    self._restore_store_mutations(target_snapshots)
                    self._degrade("purge", rollback_error)
                    raise rollback_error from write_error
                self._restore_store_mutations(source_snapshots)
            raise
        return selected

    def queue(
        self,
        record: PendingActionRecord,
        *,
        persist: Callable[[], None],
    ) -> PendingActionTransitionResult:
        self._raise_if_degraded()
        operation = self._validate_queue_record(record)
        self._assert_store_index_parity(operation)
        queue_key = self._queue_key(record)
        existing = self.store.actions.get(record.confirmation_id)
        if existing is not None:
            stored_key = self._queue_keys.setdefault(
                existing.confirmation_id,
                self._queue_key(existing),
            )
            if queue_key == stored_key == self._queue_key(existing):
                return PendingActionTransitionResult(
                    record=existing,
                    operation=operation,
                    source_status="",
                    target_status=existing.status,
                    changed=False,
                )
            raise _transition_error("duplicate_queue_identity", operation, record.confirmation_id)
        source_snapshots = self._capture_store_mutations()
        record_snapshot = capture_pending_action_mutation(record)
        self.store.add(record)
        try:
            self._persist(persist)
        except AtomicWriteError as write_error:
            target_snapshots = self._capture_store_mutations()
            removed = self.store.remove(record.confirmation_id)
            if removed is not record:
                raise RuntimeError("pending queue rollback lost record identity") from write_error
            self._restore_store_mutations(source_snapshots)
            restore_pending_action_mutation(record, record_snapshot)
            if write_error.publication_may_have_committed:
                try:
                    self._persist(persist)
                except AtomicWriteError as rollback_error:
                    self.store.add(record)
                    self._restore_store_mutations(target_snapshots)
                    self._queue_keys[record.confirmation_id] = queue_key
                    self._degrade("queue", rollback_error)
                    raise rollback_error from write_error
                self._restore_store_mutations(source_snapshots)
            raise
        self._queue_keys[record.confirmation_id] = queue_key
        return PendingActionTransitionResult(
            record=record,
            operation=operation,
            source_status="",
            target_status=record.status,
            changed=True,
        )

    def transition(
        self,
        request: PendingActionTransitionRequest,
        *,
        persist: Callable[[], None],
    ) -> PendingActionTransitionResult:
        return self.transition_many((request,), persist=persist)[0]

    def transition_many(
        self,
        requests: Sequence[PendingActionTransitionRequest],
        *,
        persist: Callable[[], None],
    ) -> tuple[PendingActionTransitionResult, ...]:
        self._raise_if_degraded()
        if not requests:
            return ()
        self._assert_store_index_parity("batch")
        record_ids = [id(request.record) for request in requests]
        if len(record_ids) != len(set(record_ids)):
            raise _transition_error("duplicate_batch_record", "batch")
        prepared = tuple(self._prepare_transition(request) for request in requests)
        changed = tuple(item for item in prepared if item.changed)
        if not changed:
            return tuple(self._result(item) for item in prepared)

        source_snapshots = self._capture_store_mutations()
        for item in changed:
            if item.request.rollback_snapshot is not None:
                source_snapshots[item.request.record.confirmation_id] = (
                    item.request.rollback_snapshot
                )
        for item in changed:
            self._apply_transition(item)
        try:
            self._persist(persist)
        except AtomicWriteError as write_error:
            target_snapshots = self._capture_store_mutations()
            retained = tuple(item for item in changed if item.request.retain_target_on_error)
            if retained and write_error.publication_may_have_committed:
                self._restore_store_mutations(target_snapshots)
                try:
                    self._persist(persist)
                except AtomicWriteError as target_error:
                    self._degrade(
                        self._degradation_label(retained[0].request.operation),
                        target_error,
                    )
                    raise target_error from write_error
                self._remember_terminal_operations(changed)
                raise
            self._restore_store_mutations(source_snapshots)
            if write_error.publication_may_have_committed:
                try:
                    self._persist(persist)
                except AtomicWriteError as rollback_error:
                    self._restore_store_mutations(target_snapshots)
                    transition = (
                        self._degradation_label(changed[0].request.operation)
                        if len(changed) == 1
                        else "terminal"
                    )
                    self._degrade(transition, rollback_error)
                    raise rollback_error from write_error
                self._restore_store_mutations(source_snapshots)
            raise
        self._remember_terminal_operations(changed)
        return tuple(self._result(item) for item in prepared)

    def _prepare_transition(
        self,
        request: PendingActionTransitionRequest,
    ) -> _PreparedPendingTransition:
        operation = PendingActionTransitionKind(request.operation)
        if operation in {
            PendingActionTransitionKind.QUEUE_PENDING,
            PendingActionTransitionKind.QUEUE_EXECUTING,
        }:
            raise _transition_error("queue_operation_requires_queue", operation)
        record = request.record
        owned = self.store.actions.get(record.confirmation_id)
        if owned is not record:
            raise _transition_error("unowned_record", operation, record.confirmation_id)
        self._validate_guard_identity(record, request.guard, operation)
        rule = pending_action_transition_rule(operation)
        reason = self._resolved_reason(request, rule)
        source_status = str(record.status)
        mutation_kind = None
        mutation_key: PendingActionMutation | None = None
        mutation_values: tuple[tuple[str, object], ...] = ()
        guard_record = record
        if request.mutation is not None:
            try:
                mutation_key = deepcopy(request.mutation)
            except Exception as exc:
                raise _transition_error("mutation_values_invalid", operation) from exc
            mutation_kind, prepared_values = self._prepare_mutation(
                record,
                request.mutation,
                operation=operation,
            )
            allowed_kinds = _PENDING_ACTION_TRANSITION_MUTATION_KINDS.get(
                operation,
                set(),
            )
            if mutation_kind not in allowed_kinds:
                raise _transition_error("mutation_kind_invalid", operation, mutation_kind.value)
            if mutation_kind.value == "decision" and source_status != "pending":
                raise PendingActionTransitionError("mutation_kind_invalid", operation=operation)
            if "status_reason" in prepared_values:
                raise _transition_error("transition_reason_mutation_forbidden", operation)
            if prepared_values:
                guard_record = replace(record)
                self._apply_mutation(guard_record, prepared_values)
            mutation_values = tuple(prepared_values.items())
        marker_intent = request.canonicalize_recovery_event_identity
        if type(marker_intent) is not bool or (
            marker_intent
            and (
                operation is not PendingActionTransitionKind.INVALIDATE_RECOVERY
                or mutation_kind is not PendingActionMutationKind.RECOVERY
            )
        ):
            raise _transition_error("recovery_marker_intent_invalid", operation)
        repeat = (
            source_status == rule.target_status
            and str(record.status_reason) == reason
            and not mutation_values
        )
        if source_status not in rule.allowed_sources and not repeat:
            raise _transition_error(
                "illegal_transition", operation, f"{source_status}->{rule.target_status}"
            )
        self._validate_guard_authority(
            guard_record,
            request.guard,
            operation,
            recovery=mutation_kind is PendingActionMutationKind.RECOVERY
            and operation is not PendingActionTransitionKind.INVALIDATE_RECOVERY,
        )
        if (
            request.scheduler_accounting_mode is not None
            and request.scheduler_accounting_mode not in {"failure", "shadow_only", "ambiguous"}
        ):
            raise _transition_error("invalid_scheduler_accounting_mode", operation)
        if request.retain_target_on_error and operation not in {
            PendingActionTransitionKind.APPROVE,
            PendingActionTransitionKind.FAIL,
            PendingActionTransitionKind.OUTCOME_UNKNOWN,
            PendingActionTransitionKind.RECOVER_APPROVE,
            PendingActionTransitionKind.RECOVER_FAIL,
            PendingActionTransitionKind.INVALIDATE_RECOVERY,
        }:
            raise _transition_error("retain_target_invalid", operation)
        terminal_key = (
            "terminal",
            operation,
            request.scheduler_accounting_mode,
            mutation_key,
            marker_intent,
        )
        stored_key = self._queue_keys.get(record.confirmation_id)
        loaded_repeat = (
            stored_key is None or stored_key == self._queue_key(record)
        ) and self._durable_terminal_repeat_matches(record, operation, mutation_kind)
        if repeat and stored_key != terminal_key and not loaded_repeat:
            raise _transition_error("terminal_repeat_mismatch", operation)
        return _PreparedPendingTransition(
            request=request,
            rule=rule,
            source_status=source_status,
            reason=reason,
            changed=not repeat,
            mutation_values=mutation_values,
            terminal_key=terminal_key,
        )

    @staticmethod
    def _result(item: _PreparedPendingTransition) -> PendingActionTransitionResult:
        return PendingActionTransitionResult(
            record=item.request.record,
            operation=item.request.operation,
            source_status=item.source_status,
            target_status=item.rule.target_status,
            changed=item.changed,
        )

    @staticmethod
    def _resolved_reason(
        request: PendingActionTransitionRequest,
        rule: PendingActionTransitionRule,
    ) -> str:
        raw_reason = str(request.reason)
        supplied = raw_reason.strip()
        if raw_reason != supplied:
            raise _transition_error("transition_reason_noncanonical", request.operation)
        if not rule.fixed_reason and supplied == "approval_expired":
            raise _transition_error("fixed_reason_reserved", request.operation, supplied)
        if rule.fixed_reason:
            if supplied and supplied != rule.fixed_reason:
                raise _transition_error("fixed_reason_mismatch", request.operation, supplied)
            return rule.fixed_reason
        if not supplied:
            raise _transition_error("transition_reason_required", request.operation)
        return supplied

    @staticmethod
    def _validate_guard_identity(
        record: PendingActionRecord,
        guard: PendingActionTransitionGuard,
        operation: PendingActionTransitionKind | str,
    ) -> None:
        actual = (
            record.record_schema_version,
            str(record.confirmation_id),
            str(record.session_id),
            str(record.user_id),
            str(record.workspace_id),
            str(record.action_id),
        )
        expected = (
            guard.expected_record_schema_version,
            guard.expected_confirmation_id,
            guard.expected_session_id,
            guard.expected_user_id,
            guard.expected_workspace_id,
            guard.expected_action_id,
        )
        if (
            type(record.record_schema_version) is not int
            or record.record_schema_version != PENDING_ACTION_RECORD_SCHEMA_VERSION
            or guard.expected_record_schema_version != PENDING_ACTION_RECORD_SCHEMA_VERSION
            or actual != expected
        ):
            raise _transition_error("guard_mismatch", operation, "record_identity")

    @staticmethod
    def _validate_guard_execution_identity(
        record: PendingActionRecord,
        guard: PendingActionTransitionGuard,
        operation: PendingActionTransitionKind | str,
        *,
        required: bool,
        recovery: bool = False,
    ) -> None:
        expected_attempt = guard.expected_execution_attempt_id
        expected_result = guard.expected_result_id
        for detail, expected, actual in (
            (
                "execution_attempt_id",
                expected_attempt,
                str(record.execution_attempt_id),
            ),
            ("result_id", expected_result, str(record.result_id)),
        ):
            if (required or actual) and not expected:
                raise _transition_error("guard_mismatch", operation, "execution_identity_required")
            if expected is not None and not safe_compare_text(expected, actual):
                raise _transition_error("guard_mismatch", operation, detail)
        if recovery and (
            not guard.expected_recovery_authority_mac
            or not safe_compare_text(
                guard.expected_recovery_authority_mac,
                record.recovery_authority_mac,
            )
        ):
            raise _transition_error("recovery_authority_mismatch", operation)

    @staticmethod
    def _validate_guard_authority(
        record: PendingActionRecord,
        guard: PendingActionTransitionGuard,
        operation: PendingActionTransitionKind,
        *,
        recovery: bool = False,
    ) -> None:
        expected_nonce = guard.expected_decision_nonce
        if expected_nonce is not None and (
            not expected_nonce or not safe_compare_text(expected_nonce, record.decision_nonce)
        ):
            raise _transition_error("guard_mismatch", operation, "decision_nonce")
        if (
            operation
            in {
                PendingActionTransitionKind.START,
                PendingActionTransitionKind.REJECT,
            }
            and expected_nonce is None
        ):
            raise _transition_error("guard_mismatch", operation, "decision_nonce_required")

        expected_evidence_hash = guard.expected_evidence_hash
        evidence = record.confirmation_evidence
        if not expected_evidence_hash and (
            operation is PendingActionTransitionKind.START
            or (
                record.status == "pending"
                and evidence is not None
                and operation.value in {"reject", "fail"}
            )
        ):
            raise _transition_error("proof_binding_mismatch", operation, "evidence_hash_required")
        if expected_evidence_hash is not None and (
            evidence is None
            or not expected_evidence_hash
            or not safe_compare_text(evidence.evidence_hash, expected_evidence_hash)
            or not safe_compare_text(
                record.approval_evidence_hash,
                expected_evidence_hash,
            )
            or expected_nonce is None
            or not safe_compare_text(evidence.decision_nonce, expected_nonce)
            or not safe_compare_text(evidence.decision_nonce, record.decision_nonce)
            or not safe_compare_text(evidence.action_digest, record.action_digest)
        ):
            raise _transition_error("proof_binding_mismatch", operation)

        expected_principal = guard.expected_approver_principal_id
        if expected_principal is not None:
            if evidence is not None and expected_evidence_hash is not None:
                principal_matches = bool(expected_principal) and safe_compare_text(
                    evidence.approver_principal_id,
                    expected_principal,
                )
            else:
                allowed_principals = {
                    str(record.user_id),
                    *(str(item) for item in record.allowed_channel_principals if str(item).strip()),
                }
                principal_matches = expected_principal in allowed_principals
            if not principal_matches:
                raise _transition_error("guard_mismatch", operation, "approver_principal")
        if operation in {
            PendingActionTransitionKind.START,
            PendingActionTransitionKind.APPROVE,
            PendingActionTransitionKind.RECOVER_APPROVE,
            PendingActionTransitionKind.RECOVER_FAIL,
        } or (
            operation
            in {
                PendingActionTransitionKind.FAIL,
                PendingActionTransitionKind.OUTCOME_UNKNOWN,
                PendingActionTransitionKind.INVALIDATE_RECOVERY,
            }
            and (record.execution_attempt_id or record.result_id)
        ):
            PendingActionLifecycleService._validate_guard_execution_identity(
                record,
                guard,
                operation,
                required=operation is not PendingActionTransitionKind.INVALIDATE_RECOVERY,
                recovery=recovery
                or operation
                in {
                    PendingActionTransitionKind.RECOVER_APPROVE,
                    PendingActionTransitionKind.RECOVER_FAIL,
                },
            )

    @staticmethod
    def _apply_transition(item: _PreparedPendingTransition) -> None:
        record = item.request.record
        record.status = item.rule.target_status
        record.status_reason = item.reason
        if item.rule.clear_decision_nonce:
            record.decision_nonce = ""
        accounting_mode = item.request.scheduler_accounting_mode
        if accounting_mode is not None:
            scheduled = bool(str(record.task_id).strip())
            record.scheduler_accounting_pending = scheduled
            if scheduled:
                record.scheduler_accounting_mode = accounting_mode
                record.recovery_scheduler_accounted = False
        PendingActionLifecycleService._apply_mutation(
            record,
            dict(item.mutation_values),
        )
        if item.request.canonicalize_recovery_event_identity:
            marker_at, marker_id = datetime.now(UTC), uuid.uuid4().hex
            record.recovery_event_identity_untrusted = True
            record.recovery_event_identity_untrusted_at = marker_at
            record.recovery_event_identity_trusted_at = marker_at
            record.recovery_anonymous_accounting_id = marker_id
            record.recovery_anonymous_accounting_id_trusted = marker_id

    @staticmethod
    def _prepare_mutation(
        record: PendingActionRecord,
        mutation: PendingActionMutation,
        *,
        operation: PendingActionTransitionKind | str,
    ) -> tuple[PendingActionMutationKind, dict[str, object]]:
        try:
            kind = PendingActionMutationKind(mutation.kind)
        except ValueError as exc:
            raise _transition_error("mutation_kind_invalid", operation, str(mutation.kind)) from exc
        allowed_fields = _PENDING_ACTION_MUTATION_FIELDS[kind]
        try:
            supplied = dict(mutation.values)
        except (TypeError, ValueError) as exc:
            raise _transition_error("mutation_values_invalid", operation) from exc
        authority_fields = supplied.keys() & _RECOVERY_AUTHORITY_MUTATION_FIELDS
        event_fields = supplied.keys() & _RECOVERY_EVENT_MUTATION_FIELDS
        if kind is PendingActionMutationKind.RECOVERY and (
            event_fields
            or (operation != PendingActionTransitionKind.INVALIDATE_RECOVERY and authority_fields)
            or any(supplied[field] not in ("", None, {}) for field in authority_fields)
        ):
            raise _transition_error("mutation_value_invalid", operation, "recovery_authority")
        prepared: dict[str, object] = {}
        for raw_field, value in supplied.items():
            if not isinstance(raw_field, str) or raw_field not in allowed_fields:
                raise _transition_error("mutation_field_forbidden", operation, str(raw_field))
            if raw_field == "status_reason" and (
                not isinstance(value, str)
                or value != value.strip()
                or (
                    value != record.status_reason
                    and value not in _PENDING_ACTION_STATUS_REASONS.get(kind, set())
                )
            ):
                raise _transition_error("mutation_value_invalid", operation, raw_field)
            if raw_field == "scheduler_accounting_mode" and value not in {
                "",
                "failure",
                "shadow_only",
                "ambiguous",
            }:
                raise _transition_error("mutation_value_invalid", operation, raw_field)
            if getattr(record, raw_field) != value:
                prepared[raw_field] = value
        return kind, prepared

    @staticmethod
    def _apply_mutation(
        record: PendingActionRecord,
        values: Mapping[str, object],
    ) -> None:
        for field_name, value in values.items():
            setattr(record, field_name, value)

    @staticmethod
    def _validate_update_guard(
        record: PendingActionRecord,
        guard: PendingActionTransitionGuard,
        kind: PendingActionMutationKind,
    ) -> None:
        if kind in {
            PendingActionMutationKind.EXECUTION,
            PendingActionMutationKind.RECOVERY,
        } and (
            record.execution_attempt_id
            or record.result_id
            or kind is PendingActionMutationKind.RECOVERY
        ):
            PendingActionLifecycleService._validate_guard_execution_identity(
                record,
                guard,
                "update",
                required=kind is PendingActionMutationKind.EXECUTION,
                recovery=kind is PendingActionMutationKind.RECOVERY,
            )

    def _remember_terminal_operations(
        self,
        items: Sequence[_PreparedPendingTransition],
    ) -> None:
        for item in items:
            self._queue_keys[item.request.record.confirmation_id] = item.terminal_key

    @staticmethod
    def _durable_terminal_repeat_matches(
        record: PendingActionRecord,
        operation: PendingActionTransitionKind,
        kind: PendingActionMutationKind | None,
    ) -> bool:
        recovered = record.retry_generation > 0 and record.recovery_started_at is not None
        authority = any(getattr(record, field) for field in _RECOVERY_AUTHORITY_MUTATION_FIELDS)
        if operation in {
            PendingActionTransitionKind.RECOVER_APPROVE,
            PendingActionTransitionKind.RECOVER_FAIL,
        }:
            return recovered and kind is PendingActionMutationKind.RECOVERY
        if operation is PendingActionTransitionKind.INVALIDATE_RECOVERY:
            return kind is not None and not authority
        if operation in {
            PendingActionTransitionKind.APPROVE,
            PendingActionTransitionKind.FAIL,
            PendingActionTransitionKind.OUTCOME_UNKNOWN,
        }:
            return (
                not recovered
                and kind is not PendingActionMutationKind.RECOVERY
                and (operation is not PendingActionTransitionKind.OUTCOME_UNKNOWN or authority)
            )
        return operation.value in {"reject", "expire", "cancel", "supersede"}

    @staticmethod
    def _validate_loaded_record(record: PendingActionRecord) -> None:
        PendingActionLifecycleService._validate_record_identity(
            record,
            operation="load",
            label="loaded",
        )

    @staticmethod
    def _validate_record_identity(
        record: PendingActionRecord,
        *,
        operation: PendingActionTransitionKind | str,
        label: str,
    ) -> None:
        if (
            type(record.record_schema_version) is not int
            or record.record_schema_version != PENDING_ACTION_RECORD_SCHEMA_VERSION
        ):
            raise _transition_error(f"{label}_record_version_invalid", operation)
        identity_values = (
            str(record.confirmation_id),
            str(record.session_id),
            str(record.user_id),
            str(record.workspace_id),
            str(record.action_id),
            str(record.followup_id),
        )
        if any(not value or value != value.strip() for value in identity_values):
            raise _transition_error(
                f"{label}_record_identity_invalid", operation, str(record.confirmation_id)
            )

    @staticmethod
    def _validate_queue_record(
        record: PendingActionRecord,
    ) -> PendingActionTransitionKind:
        stored_status = str(record.status)
        operation = (
            PendingActionTransitionKind.QUEUE_EXECUTING
            if stored_status == "executing"
            else PendingActionTransitionKind.QUEUE_PENDING
        )
        PendingActionLifecycleService._validate_record_identity(
            record,
            operation=operation,
            label="queue",
        )
        envelope = record.approval_envelope
        if (
            envelope is None
            or envelope.approval_id != record.confirmation_id
            or envelope.pending_action_id != record.action_id
            or envelope.session_id != str(record.session_id)
            or envelope.workspace_id != str(record.workspace_id)
        ):
            raise _transition_error("queue_approval_identity_mismatch", operation)
        if stored_status == "pending":
            if (
                not record.decision_nonce.strip()
                or record.status_reason
                or record.execution_attempt_id
                or record.result_id
            ):
                raise _transition_error("queue_pending_phase_invalid", operation)
        elif stored_status == "executing":
            operation_ids = {
                record.confirmation_id,
                record.action_id,
                record.execution_attempt_id,
                record.result_id,
                record.followup_id,
            }
            if (
                record.decision_nonce
                or not record.execution_attempt_id.strip()
                or not record.result_id.strip()
                or len(operation_ids) != 5
                or record.execution_authorization_kind != "policy_allow"
            ):
                raise _transition_error("queue_executing_phase_invalid", operation)
        else:
            raise _transition_error("queue_status_invalid", operation, stored_status)
        return operation

    @staticmethod
    def _queue_key(record: PendingActionRecord) -> tuple[object, ...]:
        return (
            record.record_schema_version,
            record.confirmation_id,
            str(record.session_id),
            str(record.user_id),
            str(record.workspace_id),
            record.action_id,
            record.status,
            record.reason,
            record.status_reason,
        )

    def _capture_store_mutations(self) -> dict[str, PendingActionMutationSnapshot]:
        return {
            confirmation_id: capture_pending_action_mutation(record)
            for confirmation_id, record in self.store.actions.items()
        }

    def _copy_session_index(self) -> dict[SessionId, list[str]]:
        return {sid: list(ids) for sid, ids in self.store.by_session.items()}

    def _persist(self, persist: Callable[[], None]) -> None:
        preparer = self._persistence_preparer
        try:
            if preparer is not None:
                prepared = tuple(preparer(tuple(self.store.actions.values())))
                if len({id(record) for record, _mutation in prepared}) != len(prepared):
                    raise _transition_error("duplicate_persistence_record", "persistence")
                for record, mutation in prepared:
                    if self.store.actions.get(record.confirmation_id) is not record:
                        raise _transition_error(
                            "unowned_record", "persistence", record.confirmation_id
                        )
                    kind, values = self._prepare_mutation(
                        record,
                        mutation,
                        operation="persistence",
                    )
                    if kind is not PendingActionMutationKind.PERSISTENCE:
                        raise _transition_error("mutation_kind_invalid", "persistence", kind.value)
                    self._apply_mutation(record, values)
            persist()
        except (AttributeError, TypeError, ValueError) as exc:
            raise PendingActionPayloadError(path=self.store.path, reason=str(exc)) from exc

    def _persist_with_rollback(
        self,
        source: Mapping[str, PendingActionMutationSnapshot],
        *,
        label: str,
        persist: Callable[[], None],
    ) -> None:
        try:
            self._persist(persist)
        except AtomicWriteError as write_error:
            target = self._capture_store_mutations()
            self._restore_store_mutations(source)
            if write_error.publication_may_have_committed:
                try:
                    self._persist(persist)
                except AtomicWriteError as rollback_error:
                    self._restore_store_mutations(target)
                    self._degrade(label, rollback_error)
                    raise rollback_error from write_error
                self._restore_store_mutations(source)
            raise

    def _restore_store_topology(
        self,
        actions: Mapping[str, PendingActionRecord],
        by_session: Mapping[SessionId, Sequence[str]],
        queue_keys: Mapping[str, tuple[object, ...]],
    ) -> None:
        self.store.actions.clear()
        self.store.actions.update(actions)
        self.store.by_session.clear()
        self.store.by_session.update({sid: list(ids) for sid, ids in by_session.items()})
        self._queue_keys.clear()
        self._queue_keys.update(queue_keys)

    def _restore_store_mutations(
        self,
        snapshots: Mapping[str, PendingActionMutationSnapshot],
    ) -> None:
        for confirmation_id, snapshot in snapshots.items():
            record = self.store.actions.get(confirmation_id)
            if record is None:
                raise RuntimeError("pending mutation rollback lost record identity")
            restore_pending_action_mutation(record, snapshot)

    def _assert_store_index_parity(
        self,
        operation: PendingActionTransitionKind | str,
    ) -> None:
        try:
            self.store.assert_index_parity()
        except ValueError as exc:
            raise _transition_error("store_index_mismatch", operation, str(exc)) from exc

    def _raise_if_degraded(self) -> None:
        if self.degradation is None:
            return
        raise StatePersistenceDegradedError(
            authority="pending_actions",
            transition=self.degradation["transition"],
            stage=self.degradation["stage"],
            reason=self.degradation["reason"],
        )

    def _degrade(self, transition: str, error: AtomicWriteError) -> None:
        self.degradation = {
            "transition": transition,
            "stage": error.stage.value,
            "reason": "pending_state_rollback_uncommitted",
        }

    @staticmethod
    def _degradation_label(operation: PendingActionTransitionKind) -> str:
        if operation is PendingActionTransitionKind.START:
            return "executing"
        if operation in {
            PendingActionTransitionKind.QUEUE_PENDING,
            PendingActionTransitionKind.QUEUE_EXECUTING,
        }:
            return "queue"
        return "terminal"
