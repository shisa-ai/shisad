"""Service-owned pending-action record store and durable schema boundary."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from shisad.core.action_state import (
    PendingActionTransitionKind,
    PendingActionTransitionRule,
    pending_action_transition_rule,
)
from shisad.core.approval import (
    ConfirmationEvidence,
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

    @classmethod
    def for_record(
        cls,
        record: PendingActionRecord,
        *,
        decision_nonce: str | None = None,
        evidence_hash: str | None = None,
        approver_principal_id: str | None = None,
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
        )


@dataclass(frozen=True, slots=True)
class PendingActionMutationSnapshot:
    """Fields mutated across decision, execution-start, and terminal commits."""

    status: str
    status_reason: str
    decision_nonce: str
    action_digest: str
    approval_evidence_hash: str
    execution_attempt_id: str
    result_id: str
    stage2_correlation_id: str
    stage2_previous_plan_hash: str
    stage2_plan_hash: str
    recovery_scheduler_posture_captured: bool
    recovery_scheduler_restore_enabled: bool
    recovery_scheduler_accounted: bool
    scheduler_accounting_pending: bool
    scheduler_accounting_mode: str
    confirmation_evidence: ConfirmationEvidence | None

    @classmethod
    def capture(cls, record: PendingActionRecord) -> PendingActionMutationSnapshot:
        return cls(
            status=str(record.status),
            status_reason=str(record.status_reason),
            decision_nonce=str(record.decision_nonce),
            action_digest=str(record.action_digest),
            approval_evidence_hash=str(record.approval_evidence_hash),
            execution_attempt_id=str(record.execution_attempt_id),
            result_id=str(record.result_id),
            stage2_correlation_id=str(record.stage2_correlation_id),
            stage2_previous_plan_hash=str(record.stage2_previous_plan_hash),
            stage2_plan_hash=str(record.stage2_plan_hash),
            recovery_scheduler_posture_captured=bool(record.recovery_scheduler_posture_captured),
            recovery_scheduler_restore_enabled=bool(record.recovery_scheduler_restore_enabled),
            recovery_scheduler_accounted=bool(record.recovery_scheduler_accounted),
            scheduler_accounting_pending=bool(record.scheduler_accounting_pending),
            scheduler_accounting_mode=str(record.scheduler_accounting_mode),
            confirmation_evidence=record.confirmation_evidence,
        )

    def restore(self, record: PendingActionRecord) -> None:
        record.status = self.status
        record.status_reason = self.status_reason
        record.decision_nonce = self.decision_nonce
        record.action_digest = self.action_digest
        record.approval_evidence_hash = self.approval_evidence_hash
        record.execution_attempt_id = self.execution_attempt_id
        record.result_id = self.result_id
        record.stage2_correlation_id = self.stage2_correlation_id
        record.stage2_previous_plan_hash = self.stage2_previous_plan_hash
        record.stage2_plan_hash = self.stage2_plan_hash
        record.recovery_scheduler_posture_captured = self.recovery_scheduler_posture_captured
        record.recovery_scheduler_restore_enabled = self.recovery_scheduler_restore_enabled
        record.recovery_scheduler_accounted = self.recovery_scheduler_accounted
        record.scheduler_accounting_pending = self.scheduler_accounting_pending
        record.scheduler_accounting_mode = self.scheduler_accounting_mode
        record.confirmation_evidence = self.confirmation_evidence


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


@dataclass(frozen=True, slots=True)
class PendingActionTransitionRequest:
    """One validated lifecycle mutation and its compatibility accounting mode."""

    record: PendingActionRecord
    operation: PendingActionTransitionKind
    reason: str
    guard: PendingActionTransitionGuard
    rollback_snapshot: PendingActionMutationSnapshot | None = None
    scheduler_accounting_mode: PendingSchedulerAccountingMode | None = None


@dataclass(frozen=True, slots=True)
class PendingActionTransitionResult:
    record: PendingActionRecord
    operation: PendingActionTransitionKind
    source_status: str
    target_status: str
    changed: bool


@dataclass(frozen=True, slots=True)
class _PreparedPendingTransition:
    request: PendingActionTransitionRequest
    rule: PendingActionTransitionRule
    source_status: str
    reason: str
    changed: bool


class PendingActionLifecycleService:
    """Own queue/index and finite durable mutations over one pending store."""

    def __init__(self, store: PendingActionStore) -> None:
        self.store = store
        self.degradation: dict[str, str] | None = None

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

    def reset_for_tests(self) -> None:
        self.store.actions.clear()
        self.store.by_session.clear()
        self.clear_degradation()

    def queue(
        self,
        record: PendingActionRecord,
        *,
        persist: Callable[[], None],
    ) -> PendingActionTransitionResult:
        self._raise_if_degraded()
        operation = self._validate_queue_record(record)
        self._assert_store_index_parity(operation)
        existing = self.store.actions.get(record.confirmation_id)
        if existing is record:
            return PendingActionTransitionResult(
                record=record,
                operation=operation,
                source_status="",
                target_status=record.status,
                changed=False,
            )
        if existing is not None:
            raise PendingActionTransitionError(
                "duplicate_queue_identity",
                operation=operation,
                detail=record.confirmation_id,
            )
        self.store.add(record)
        try:
            persist()
        except AtomicWriteError as write_error:
            removed = self.store.remove(record.confirmation_id)
            if removed is not record:
                raise RuntimeError("pending queue rollback lost record identity") from write_error
            if write_error.publication_may_have_committed:
                try:
                    persist()
                except AtomicWriteError as rollback_error:
                    self.store.add(record)
                    self._degrade("queue", rollback_error)
                    raise rollback_error from write_error
            raise
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
            raise PendingActionTransitionError(
                "duplicate_batch_record",
                operation="batch",
            )
        prepared = tuple(self._prepare_transition(request) for request in requests)
        changed = tuple(item for item in prepared if item.changed)
        if not changed:
            return tuple(self._result(item) for item in prepared)

        source_snapshots = tuple(
            item.request.rollback_snapshot or capture_pending_action_mutation(item.request.record)
            for item in changed
        )
        for item in changed:
            self._apply_transition(item)
        target_snapshots = tuple(
            capture_pending_action_mutation(item.request.record) for item in changed
        )
        try:
            persist()
        except AtomicWriteError as write_error:
            for item, snapshot in zip(changed, source_snapshots, strict=True):
                restore_pending_action_mutation(item.request.record, snapshot)
            if write_error.publication_may_have_committed:
                try:
                    persist()
                except AtomicWriteError as rollback_error:
                    for item, snapshot in zip(changed, target_snapshots, strict=True):
                        restore_pending_action_mutation(item.request.record, snapshot)
                    transition = (
                        self._degradation_label(changed[0].request.operation)
                        if len(changed) == 1
                        else "terminal"
                    )
                    self._degrade(transition, rollback_error)
                    raise rollback_error from write_error
            raise
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
            raise PendingActionTransitionError(
                "queue_operation_requires_queue",
                operation=operation,
            )
        record = request.record
        owned = self.store.actions.get(record.confirmation_id)
        if owned is not record:
            raise PendingActionTransitionError(
                "unowned_record",
                operation=operation,
                detail=record.confirmation_id,
            )
        self._validate_guard_identity(record, request.guard, operation)
        rule = pending_action_transition_rule(operation)
        reason = self._resolved_reason(request, rule)
        source_status = str(record.status)
        if source_status == rule.target_status and str(record.status_reason) == reason:
            return _PreparedPendingTransition(
                request=request,
                rule=rule,
                source_status=source_status,
                reason=reason,
                changed=False,
            )
        if source_status not in rule.allowed_sources:
            raise PendingActionTransitionError(
                "illegal_transition",
                operation=operation,
                detail=f"{source_status}->{rule.target_status}",
            )
        self._validate_guard_authority(record, request.guard, operation)
        if (
            request.scheduler_accounting_mode is not None
            and request.scheduler_accounting_mode not in {"failure", "shadow_only", "ambiguous"}
        ):
            raise PendingActionTransitionError(
                "invalid_scheduler_accounting_mode",
                operation=operation,
            )
        return _PreparedPendingTransition(
            request=request,
            rule=rule,
            source_status=source_status,
            reason=reason,
            changed=True,
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
            raise PendingActionTransitionError(
                "transition_reason_noncanonical",
                operation=request.operation,
            )
        if rule.fixed_reason:
            if supplied and supplied != rule.fixed_reason:
                raise PendingActionTransitionError(
                    "fixed_reason_mismatch",
                    operation=request.operation,
                    detail=supplied,
                )
            return rule.fixed_reason
        if not supplied:
            raise PendingActionTransitionError(
                "transition_reason_required",
                operation=request.operation,
            )
        return supplied

    @staticmethod
    def _validate_guard_identity(
        record: PendingActionRecord,
        guard: PendingActionTransitionGuard,
        operation: PendingActionTransitionKind,
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
            raise PendingActionTransitionError(
                "guard_mismatch",
                operation=operation,
                detail="record_identity",
            )

    @staticmethod
    def _validate_guard_authority(
        record: PendingActionRecord,
        guard: PendingActionTransitionGuard,
        operation: PendingActionTransitionKind,
    ) -> None:
        expected_nonce = guard.expected_decision_nonce
        if expected_nonce is not None and (
            not expected_nonce or not safe_compare_text(expected_nonce, record.decision_nonce)
        ):
            raise PendingActionTransitionError(
                "guard_mismatch",
                operation=operation,
                detail="decision_nonce",
            )
        if (
            operation
            in {
                PendingActionTransitionKind.START,
                PendingActionTransitionKind.REJECT,
            }
            and expected_nonce is None
        ):
            raise PendingActionTransitionError(
                "guard_mismatch",
                operation=operation,
                detail="decision_nonce_required",
            )

        expected_evidence_hash = guard.expected_evidence_hash
        evidence = record.confirmation_evidence
        if operation is PendingActionTransitionKind.START and not expected_evidence_hash:
            raise PendingActionTransitionError(
                "proof_binding_mismatch",
                operation=operation,
                detail="evidence_hash_required",
            )
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
            raise PendingActionTransitionError(
                "proof_binding_mismatch",
                operation=operation,
            )

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
                raise PendingActionTransitionError(
                    "guard_mismatch",
                    operation=operation,
                    detail="approver_principal",
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
            record.scheduler_accounting_mode = accounting_mode if scheduled else ""
            if scheduled:
                record.recovery_scheduler_accounted = False

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
        if (
            type(record.record_schema_version) is not int
            or record.record_schema_version != PENDING_ACTION_RECORD_SCHEMA_VERSION
        ):
            raise PendingActionTransitionError(
                "queue_record_version_invalid",
                operation=operation,
            )
        identity_values = (
            str(record.confirmation_id),
            str(record.session_id),
            str(record.user_id),
            str(record.workspace_id),
            str(record.action_id),
            str(record.followup_id),
        )
        if any(not value or value != value.strip() for value in identity_values):
            raise PendingActionTransitionError(
                "queue_record_identity_invalid",
                operation=operation,
            )
        envelope = record.approval_envelope
        if (
            envelope is None
            or envelope.approval_id != record.confirmation_id
            or envelope.pending_action_id != record.action_id
            or envelope.session_id != str(record.session_id)
            or envelope.workspace_id != str(record.workspace_id)
        ):
            raise PendingActionTransitionError(
                "queue_approval_identity_mismatch",
                operation=operation,
            )
        if stored_status == "pending":
            if (
                not record.decision_nonce.strip()
                or record.status_reason
                or record.execution_attempt_id
                or record.result_id
            ):
                raise PendingActionTransitionError(
                    "queue_pending_phase_invalid",
                    operation=operation,
                )
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
                raise PendingActionTransitionError(
                    "queue_executing_phase_invalid",
                    operation=operation,
                )
        else:
            raise PendingActionTransitionError(
                "queue_status_invalid",
                operation=operation,
                detail=stored_status,
            )
        return operation

    def _assert_store_index_parity(
        self,
        operation: PendingActionTransitionKind | str,
    ) -> None:
        try:
            self.store.assert_index_parity()
        except ValueError as exc:
            raise PendingActionTransitionError(
                "store_index_mismatch",
                operation=operation,
                detail=str(exc),
            ) from exc

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
