"""F10B/F10C contracts for the finite pending-action lifecycle authority."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from shisad.core.action_state import (
    PendingActionTransitionKind,
    pending_action_transition_rule,
)
from shisad.core.approval import (
    ApprovalEnvelope,
    ConfirmationEvidence,
    ConfirmationLevel,
)
from shisad.core.atomic_state import (
    AtomicWriteError,
    AtomicWriteStage,
    StatePersistenceDegradedError,
)
from shisad.core.pending_action import PENDING_ACTION_RECORD_SCHEMA_VERSION
from shisad.daemon.pending_actions import (
    PendingActionLifecycleService,
    PendingActionMutation,
    PendingActionMutationKind,
    PendingActionPayloadError,
    PendingActionStore,
    PendingActionTransitionError,
    PendingActionTransitionGuard,
    PendingActionTransitionRequest,
    PendingActionUpdateRequest,
)
from tests.helpers.approval import make_pending_action

_STORED_STATUSES = (
    "pending",
    "executing",
    "approved",
    "failed",
    "rejected",
    "cancelled",
    "superseded",
    "outcome_unknown",
)

_EXPECTED_RULES = {
    PendingActionTransitionKind.QUEUE_PENDING: (frozenset(), "pending", False, ""),
    PendingActionTransitionKind.QUEUE_EXECUTING: (frozenset(), "executing", False, ""),
    PendingActionTransitionKind.START: (frozenset({"pending"}), "executing", False, ""),
    PendingActionTransitionKind.APPROVE: (frozenset({"executing"}), "approved", False, ""),
    PendingActionTransitionKind.REJECT: (frozenset({"pending"}), "rejected", True, ""),
    PendingActionTransitionKind.EXPIRE: (
        frozenset({"pending"}),
        "failed",
        True,
        "approval_expired",
    ),
    PendingActionTransitionKind.FAIL: (
        frozenset({"pending", "executing"}),
        "failed",
        True,
        "",
    ),
    PendingActionTransitionKind.CANCEL: (
        frozenset({"pending", "executing"}),
        "cancelled",
        True,
        "",
    ),
    PendingActionTransitionKind.SUPERSEDE: (
        frozenset({"pending"}),
        "superseded",
        True,
        "",
    ),
    PendingActionTransitionKind.OUTCOME_UNKNOWN: (
        frozenset({"pending", "executing"}),
        "outcome_unknown",
        True,
        "",
    ),
    PendingActionTransitionKind.RECOVER_APPROVE: (
        frozenset({"executing", "outcome_unknown"}),
        "approved",
        True,
        "",
    ),
    PendingActionTransitionKind.RECOVER_FAIL: (
        frozenset({"executing", "outcome_unknown"}),
        "failed",
        True,
        "",
    ),
    PendingActionTransitionKind.INVALIDATE_RECOVERY: (
        frozenset({"pending", "executing", "approved", "failed", "outcome_unknown"}),
        "outcome_unknown",
        True,
        "",
    ),
}

_NON_QUEUE_OPERATIONS = tuple(
    operation
    for operation in PendingActionTransitionKind
    if operation
    not in {
        PendingActionTransitionKind.QUEUE_PENDING,
        PendingActionTransitionKind.QUEUE_EXECUTING,
    }
)

_LEGAL_EDGES = tuple(
    (operation, source)
    for operation in _NON_QUEUE_OPERATIONS
    for source in _EXPECTED_RULES[operation][0]
)

_ILLEGAL_EDGES = tuple(
    (operation, source)
    for operation in _NON_QUEUE_OPERATIONS
    for source in _STORED_STATUSES
    if source not in _EXPECTED_RULES[operation][0]
)


class _PersistRecorder:
    def __init__(
        self,
        failures: list[AtomicWriteError] | None = None,
        *,
        before_call: Callable[[int], None] | None = None,
    ) -> None:
        self.calls = 0
        self._failures = list(failures or [])
        self._before_call = before_call

    def __call__(self) -> None:
        self.calls += 1
        if self._before_call is not None:
            self._before_call(self.calls)
        if self._failures:
            raise self._failures.pop(0)


def _record(
    *,
    confirmation_id: str = "c-1",
    status: str = "pending",
    status_reason: str = "",
) -> Any:
    record = make_pending_action(
        confirmation_id=confirmation_id,
        decision_nonce="decision-nonce",
        selected_backend_id="software.default",
        selected_backend_method="software",
    )
    record.action_id = f"act-{confirmation_id}"
    record.followup_id = f"followup-{confirmation_id}"
    record.status = status
    record.status_reason = status_reason
    record.action_digest = f"sha256:{'1' * 64}"
    record.expires_at = datetime.now(UTC) + timedelta(hours=1)
    if status == "executing":
        record.decision_nonce = ""
        record.execution_attempt_id = f"attempt-{confirmation_id}"
        record.result_id = f"result-{confirmation_id}"
        record.execution_authorization_kind = "policy_allow"
    elif status != "pending":
        record.decision_nonce = ""
        record.execution_attempt_id = f"attempt-{confirmation_id}"
        record.result_id = f"result-{confirmation_id}"
    record.approval_envelope = ApprovalEnvelope(
        approval_id=record.confirmation_id,
        pending_action_id=record.action_id,
        workspace_id=str(record.workspace_id),
        daemon_id="daemon-1",
        session_id=str(record.session_id),
        required_level=ConfirmationLevel.SOFTWARE,
        policy_reason=record.reason,
        action_digest=record.action_digest,
        expires_at=record.expires_at,
        nonce="approval-nonce",
    )
    return record


def _bind_evidence(record: Any, *, principal_id: str = "alice-key") -> None:
    evidence = ConfirmationEvidence(
        level=ConfirmationLevel.SOFTWARE,
        method="software",
        backend_id="software.default",
        approver_principal_id=principal_id,
        approval_envelope_hash=f"sha256:{'2' * 64}",
        action_digest=str(record.action_digest),
        decision_nonce=str(record.decision_nonce),
        evidence_hash=f"sha256:{'3' * 64}",
    )
    record.confirmation_evidence = evidence
    record.approval_evidence_hash = evidence.evidence_hash


def _guard(
    record: Any,
    *,
    proof: bool = False,
    decision: bool = False,
    execution: bool = False,
) -> PendingActionTransitionGuard:
    evidence = getattr(record, "confirmation_evidence", None)
    return PendingActionTransitionGuard.for_record(
        record,
        decision_nonce=str(record.decision_nonce) if proof or decision else None,
        evidence_hash=str(getattr(evidence, "evidence_hash", "")) if proof else None,
        approver_principal_id=(
            str(getattr(evidence, "approver_principal_id", "")) if proof else None
        ),
        execution_attempt_id=(str(record.execution_attempt_id) if execution or proof else None),
        result_id=(str(record.result_id) if execution or proof else None),
    )


def _reason(operation: PendingActionTransitionKind) -> str:
    fixed = _EXPECTED_RULES[operation][3]
    return fixed or f"{operation.value}_reason"


def _service(tmp_path: Path) -> PendingActionLifecycleService:
    return PendingActionLifecycleService(PendingActionStore(tmp_path / "pending_actions.json"))


def _serializer_fields(record: Any) -> tuple[object, ...]:
    return (
        record.recovery_authority_mac,
        record.recovery_event_identity_untrusted,
        record.recovery_event_identity_untrusted_at,
        record.recovery_anonymous_accounting_id,
        record.recovery_event_identity_trusted_at,
        record.recovery_anonymous_accounting_id_trusted,
    )


def _set_serializer_fields(record: Any, tag: str) -> None:
    marker_at = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=sum(tag.encode()))
    record.recovery_authority_mac = f"mac-{tag}"
    record.recovery_event_identity_untrusted = tag != "source"
    record.recovery_event_identity_untrusted_at = marker_at
    record.recovery_anonymous_accounting_id = f"accounting-{tag}"
    record.recovery_event_identity_trusted_at = marker_at
    record.recovery_anonymous_accounting_id_trusted = f"trusted-{tag}"


def _atomic_error(
    path: Path,
    *,
    stage: AtomicWriteStage,
    committed: bool,
) -> AtomicWriteError:
    return AtomicWriteError(
        path=path,
        stage=stage,
        publication_may_have_committed=committed,
    )


def test_f10_transition_table_is_complete_and_exact() -> None:
    assert set(PendingActionTransitionKind) == set(_EXPECTED_RULES)
    for operation, expected in _EXPECTED_RULES.items():
        rule = pending_action_transition_rule(operation)
        assert (
            rule.allowed_sources,
            rule.target_status,
            rule.clear_decision_nonce,
            rule.fixed_reason,
        ) == expected


@pytest.mark.parametrize(("operation", "source"), _LEGAL_EDGES)
def test_f10_every_legal_transition_commits_once(
    tmp_path: Path,
    operation: PendingActionTransitionKind,
    source: str,
) -> None:
    service = _service(tmp_path)
    record = _record(status=source)
    if operation is PendingActionTransitionKind.START:
        record.decision_nonce = "decision-nonce"
        record.execution_attempt_id = "attempt-c-1"
        record.result_id = "result-c-1"
        _bind_evidence(record)
    service.store.add(record)
    persist = _PersistRecorder()

    result = service.transition(
        PendingActionTransitionRequest(
            record=record,
            operation=operation,
            reason=_reason(operation),
            guard=_guard(
                record,
                proof=operation is PendingActionTransitionKind.START,
                decision=operation is PendingActionTransitionKind.REJECT,
                execution=operation
                in {
                    PendingActionTransitionKind.APPROVE,
                    PendingActionTransitionKind.RECOVER_APPROVE,
                    PendingActionTransitionKind.RECOVER_FAIL,
                    PendingActionTransitionKind.INVALIDATE_RECOVERY,
                }
                and bool(record.execution_attempt_id),
            ),
        ),
        persist=persist,
    )

    rule = pending_action_transition_rule(operation)
    assert result.changed is True
    assert result.source_status == source
    assert result.target_status == rule.target_status
    assert record.status == rule.target_status
    assert record.status_reason == _reason(operation)
    assert persist.calls == 1
    if rule.clear_decision_nonce:
        assert record.decision_nonce == ""


@pytest.mark.parametrize(("operation", "source"), _ILLEGAL_EDGES)
def test_f10_every_illegal_transition_fails_before_mutation(
    tmp_path: Path,
    operation: PendingActionTransitionKind,
    source: str,
) -> None:
    service = _service(tmp_path)
    record = _record(status=source, status_reason="existing-state")
    service.store.add(record)
    persist = _PersistRecorder()
    before = (record.status, record.status_reason, record.decision_nonce)

    with pytest.raises(PendingActionTransitionError, match="illegal_transition"):
        service.transition(
            PendingActionTransitionRequest(
                record=record,
                operation=operation,
                reason=_reason(operation),
                guard=_guard(record),
            ),
            persist=persist,
        )

    assert (record.status, record.status_reason, record.decision_nonce) == before
    assert persist.calls == 0


def test_f10b_queue_pending_and_executing_own_store_index_and_idempotency(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    pending = _record(confirmation_id="c-pending")
    executing = _record(confirmation_id="c-executing", status="executing")
    persist = _PersistRecorder()

    queued_pending = service.queue(pending, persist=persist)
    queued_executing = service.queue(executing, persist=persist)
    repeated = service.queue(pending, persist=persist)
    reconstructed = _record(confirmation_id="c-pending")
    reconstructed_repeat = service.queue(reconstructed, persist=persist)

    assert queued_pending.changed is True
    assert queued_executing.changed is True
    assert repeated.changed is False
    assert reconstructed_repeat.changed is False
    assert reconstructed_repeat.record is pending
    assert persist.calls == 2
    assert service.store.actions == {
        "c-pending": pending,
        "c-executing": executing,
    }
    assert service.store.by_session == {
        pending.session_id: ["c-pending", "c-executing"],
    }
    service.store.assert_index_parity()

    conflicting = _record(confirmation_id="c-pending")
    conflicting.reason = "different-policy-reason"
    with pytest.raises(PendingActionTransitionError, match="duplicate_queue_identity"):
        service.queue(conflicting, persist=persist)
    pending.reason = "mutated-after-queue"
    with pytest.raises(PendingActionTransitionError, match="duplicate_queue_identity"):
        service.queue(pending, persist=persist)
    assert persist.calls == 2


@pytest.mark.parametrize(
    ("case", "mutate"),
    [
        (
            "future-version",
            lambda record: setattr(
                record,
                "record_schema_version",
                PENDING_ACTION_RECORD_SCHEMA_VERSION + 1,
            ),
        ),
        ("noncanonical-status", lambda record: setattr(record, "status", " Pending ")),
        ("empty-action", lambda record: setattr(record, "action_id", "")),
        ("missing-envelope", lambda record: setattr(record, "approval_envelope", None)),
        (
            "envelope-confirmation-mismatch",
            lambda record: setattr(
                record,
                "approval_envelope",
                record.approval_envelope.model_copy(update={"approval_id": "c-other"}),
            ),
        ),
        (
            "envelope-action-mismatch",
            lambda record: setattr(
                record,
                "approval_envelope",
                record.approval_envelope.model_copy(update={"pending_action_id": "act-other"}),
            ),
        ),
        (
            "envelope-session-mismatch",
            lambda record: setattr(
                record,
                "approval_envelope",
                record.approval_envelope.model_copy(update={"session_id": "session-other"}),
            ),
        ),
        (
            "envelope-workspace-mismatch",
            lambda record: setattr(
                record,
                "approval_envelope",
                record.approval_envelope.model_copy(update={"workspace_id": "workspace-other"}),
            ),
        ),
        ("pending-without-nonce", lambda record: setattr(record, "decision_nonce", "")),
        (
            "pending-with-attempt",
            lambda record: setattr(record, "execution_attempt_id", "attempt-early"),
        ),
        (
            "executing-with-nonce",
            lambda record: (
                setattr(record, "status", "executing"),
                setattr(record, "decision_nonce", "still-live"),
                setattr(record, "execution_attempt_id", "attempt-1"),
                setattr(record, "result_id", "result-1"),
            ),
        ),
        (
            "executing-without-attempt",
            lambda record: (
                setattr(record, "status", "executing"),
                setattr(record, "decision_nonce", ""),
                setattr(record, "result_id", "result-1"),
            ),
        ),
        (
            "executing-without-result",
            lambda record: (
                setattr(record, "status", "executing"),
                setattr(record, "decision_nonce", ""),
                setattr(record, "execution_attempt_id", "attempt-1"),
            ),
        ),
        (
            "executing-without-authorization",
            lambda record: (
                setattr(record, "status", "executing"),
                setattr(record, "decision_nonce", ""),
                setattr(record, "execution_attempt_id", "attempt-1"),
                setattr(record, "result_id", "result-1"),
                setattr(record, "execution_authorization_kind", ""),
            ),
        ),
        (
            "executing-with-duplicate-operation-identity",
            lambda record: (
                setattr(record, "status", "executing"),
                setattr(record, "decision_nonce", ""),
                setattr(record, "execution_attempt_id", record.action_id),
                setattr(record, "result_id", "result-1"),
                setattr(record, "execution_authorization_kind", "policy_allow"),
            ),
        ),
        ("terminal-status", lambda record: setattr(record, "status", "approved")),
    ],
)
def test_f10b_queue_rejects_invalid_version_identity_or_phase(
    tmp_path: Path,
    case: str,
    mutate: Callable[[Any], object],
) -> None:
    _ = case
    service = _service(tmp_path)
    record = _record()
    mutate(record)
    persist = _PersistRecorder()

    with pytest.raises(PendingActionTransitionError):
        service.queue(record, persist=persist)

    assert service.store.actions == {}
    assert service.store.by_session == {}
    assert persist.calls == 0


@pytest.mark.parametrize(
    ("field_name", "wrong_value", "expected_error"),
    [
        (
            "expected_record_schema_version",
            PENDING_ACTION_RECORD_SCHEMA_VERSION + 1,
            "guard_mismatch",
        ),
        ("expected_confirmation_id", "c-other", "guard_mismatch"),
        ("expected_session_id", "session-other", "guard_mismatch"),
        ("expected_user_id", "mallory", "guard_mismatch"),
        ("expected_workspace_id", "workspace-other", "guard_mismatch"),
        ("expected_action_id", "act-other", "guard_mismatch"),
        ("expected_decision_nonce", "nonce-other", "guard_mismatch"),
        (
            "expected_evidence_hash",
            f"sha256:{'9' * 64}",
            "proof_binding_mismatch",
        ),
        ("expected_approver_principal_id", "mallory-key", "guard_mismatch"),
    ],
)
def test_f10b_start_guard_rejects_every_wrong_binding_without_mutation(
    tmp_path: Path,
    field_name: str,
    wrong_value: object,
    expected_error: str,
) -> None:
    service = _service(tmp_path)
    record = _record()
    record.execution_attempt_id = "attempt-c-1"
    record.result_id = "result-c-1"
    _bind_evidence(record)
    service.store.add(record)
    guard = replace(_guard(record, proof=True), **{field_name: wrong_value})
    persist = _PersistRecorder()

    with pytest.raises(PendingActionTransitionError, match=expected_error):
        service.transition(
            PendingActionTransitionRequest(
                record=record,
                operation=PendingActionTransitionKind.START,
                reason="confirmation_execution_started",
                guard=guard,
            ),
            persist=persist,
        )

    assert record.status == "pending"
    assert record.status_reason == ""
    assert persist.calls == 0


@pytest.mark.parametrize(
    "mutate",
    [
        lambda record: setattr(
            record,
            "confirmation_evidence",
            record.confirmation_evidence.model_copy(
                update={"decision_nonce": "evidence-for-another-decision"}
            ),
        ),
        lambda record: setattr(
            record,
            "confirmation_evidence",
            record.confirmation_evidence.model_copy(update={"action_digest": f"sha256:{'8' * 64}"}),
        ),
        lambda record: setattr(
            record,
            "approval_evidence_hash",
            f"sha256:{'9' * 64}",
        ),
    ],
)
def test_f10b_start_guard_binds_every_proof_field(
    tmp_path: Path,
    mutate: Callable[[Any], object],
) -> None:
    service = _service(tmp_path)
    record = _record()
    record.execution_attempt_id = "attempt-c-1"
    record.result_id = "result-c-1"
    _bind_evidence(record)
    mutate(record)
    service.store.add(record)
    persist = _PersistRecorder()

    with pytest.raises(PendingActionTransitionError, match="proof_binding_mismatch"):
        service.transition(
            PendingActionTransitionRequest(
                record=record,
                operation=PendingActionTransitionKind.START,
                reason="confirmation_execution_started",
                guard=_guard(record, proof=True),
            ),
            persist=persist,
        )

    assert record.status == "pending"
    assert persist.calls == 0


@pytest.mark.parametrize(
    ("guard_update", "expected_error"),
    [
        (
            {
                "expected_decision_nonce": None,
            },
            "guard_mismatch",
        ),
        (
            {
                "expected_evidence_hash": None,
            },
            "proof_binding_mismatch",
        ),
    ],
)
def test_f10b_start_requires_explicit_nonce_and_proof_preconditions(
    tmp_path: Path,
    guard_update: dict[str, object],
    expected_error: str,
) -> None:
    service = _service(tmp_path)
    record = _record()
    record.execution_attempt_id = "attempt-c-1"
    record.result_id = "result-c-1"
    _bind_evidence(record)
    service.store.add(record)

    with pytest.raises(PendingActionTransitionError, match=expected_error):
        service.transition(
            PendingActionTransitionRequest(
                record=record,
                operation=PendingActionTransitionKind.START,
                reason="confirmation_execution_started",
                guard=replace(_guard(record, proof=True), **guard_update),
            ),
            persist=_PersistRecorder(),
        )

    assert record.status == "pending"


def test_f10b_exact_terminal_repeat_is_no_write_idempotent(tmp_path: Path) -> None:
    service = _service(tmp_path)
    record = _record(status="failed", status_reason="approval_expired")
    service.store.add(record)
    persist = _PersistRecorder()

    result = service.transition(
        PendingActionTransitionRequest(
            record=record,
            operation=PendingActionTransitionKind.EXPIRE,
            reason="approval_expired",
            guard=_guard(record),
        ),
        persist=persist,
    )

    assert result.changed is False
    assert result.source_status == "failed"
    assert result.target_status == "failed"
    assert persist.calls == 0


def test_f10b_transition_rejects_noncanonical_source_and_reason_without_write(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    malformed_source = _record(confirmation_id="c-source", status=" Pending ")
    canonical_source = _record(confirmation_id="c-reason")
    service.store.add(malformed_source)
    service.store.add(canonical_source)
    persist = _PersistRecorder()

    with pytest.raises(PendingActionTransitionError, match="illegal_transition"):
        service.transition(
            PendingActionTransitionRequest(
                record=malformed_source,
                operation=PendingActionTransitionKind.CANCEL,
                reason="cancelled",
                guard=_guard(malformed_source),
            ),
            persist=persist,
        )
    with pytest.raises(PendingActionTransitionError, match="transition_reason_noncanonical"):
        service.transition(
            PendingActionTransitionRequest(
                record=canonical_source,
                operation=PendingActionTransitionKind.CANCEL,
                reason=" cancelled ",
                guard=_guard(canonical_source),
            ),
            persist=persist,
        )

    assert malformed_source.status == " Pending "
    assert canonical_source.status == "pending"
    assert persist.calls == 0


def test_f10b_idempotent_repeat_rejects_corrupt_store_index(tmp_path: Path) -> None:
    service = _service(tmp_path)
    record = _record(status="failed", status_reason="approval_expired")
    service.store.add(record)
    service.store.by_session.clear()
    persist = _PersistRecorder()

    with pytest.raises(PendingActionTransitionError, match="store_index_mismatch"):
        service.transition(
            PendingActionTransitionRequest(
                record=record,
                operation=PendingActionTransitionKind.EXPIRE,
                reason="approval_expired",
                guard=_guard(record),
            ),
            persist=persist,
        )

    assert record.status == "failed"
    assert persist.calls == 0


def test_f10b_transition_rejects_queue_operation_unowned_and_duplicate_batch(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    owned = _record(confirmation_id="c-owned")
    unowned = _record(confirmation_id="c-unowned")
    service.store.add(owned)
    persist = _PersistRecorder()

    with pytest.raises(PendingActionTransitionError, match="queue_operation_requires_queue"):
        service.transition(
            PendingActionTransitionRequest(
                record=owned,
                operation=PendingActionTransitionKind.QUEUE_PENDING,
                reason="queue",
                guard=_guard(owned),
            ),
            persist=persist,
        )
    with pytest.raises(PendingActionTransitionError, match="unowned_record"):
        service.transition(
            PendingActionTransitionRequest(
                record=unowned,
                operation=PendingActionTransitionKind.CANCEL,
                reason="cancelled",
                guard=_guard(unowned),
            ),
            persist=persist,
        )
    request = PendingActionTransitionRequest(
        record=owned,
        operation=PendingActionTransitionKind.CANCEL,
        reason="cancelled",
        guard=_guard(owned),
    )
    with pytest.raises(PendingActionTransitionError, match="duplicate_batch_record"):
        service.transition_many((request, request), persist=persist)

    assert service.transition_many((), persist=persist) == ()
    assert owned.status == "pending"
    assert persist.calls == 0


@pytest.mark.parametrize(
    ("reason", "accounting_mode", "expected_error"),
    [
        ("wrong-expiry-reason", None, "fixed_reason_mismatch"),
        ("", None, "transition_reason_required"),
        ("cancelled", "not-a-mode", "invalid_scheduler_accounting_mode"),
    ],
)
def test_f10b_transition_rejects_invalid_reason_or_accounting_mode(
    tmp_path: Path,
    reason: str,
    accounting_mode: Any,
    expected_error: str,
) -> None:
    service = _service(tmp_path)
    record = _record()
    service.store.add(record)
    operation = (
        PendingActionTransitionKind.EXPIRE
        if expected_error == "fixed_reason_mismatch"
        else PendingActionTransitionKind.CANCEL
    )

    with pytest.raises(PendingActionTransitionError, match=expected_error):
        service.transition(
            PendingActionTransitionRequest(
                record=record,
                operation=operation,
                reason=reason,
                guard=_guard(record),
                scheduler_accounting_mode=accounting_mode,
            ),
            persist=_PersistRecorder(),
        )

    assert record.status == "pending"


def test_f10b_unscheduled_terminal_preserves_existing_accounting_mode(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    record = _record()
    record.scheduler_accounting_mode = "legacy-shadow"
    service.store.add(record)

    service.transition(
        PendingActionTransitionRequest(
            record=record,
            operation=PendingActionTransitionKind.CANCEL,
            reason="cancelled",
            guard=_guard(record),
            scheduler_accounting_mode="failure",
        ),
        persist=_PersistRecorder(),
    )

    assert record.scheduler_accounting_pending is False
    assert record.scheduler_accounting_mode == "legacy-shadow"


def test_f10b_transition_uncommitted_failure_restores_exact_source(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    record = _record()
    _set_serializer_fields(record, "source")
    source_serializer_fields = _serializer_fields(record)
    service.store.add(record)
    persist = _PersistRecorder(
        [
            _atomic_error(
                service.store.path,
                stage=AtomicWriteStage.WRITE,
                committed=False,
            )
        ],
        before_call=lambda _call: _set_serializer_fields(record, "target"),
    )

    with pytest.raises(AtomicWriteError):
        service.transition(
            PendingActionTransitionRequest(
                record=record,
                operation=PendingActionTransitionKind.REJECT,
                reason="operator_rejected",
                guard=_guard(record, decision=True),
            ),
            persist=persist,
        )

    assert (record.status, record.status_reason, record.decision_nonce) == (
        "pending",
        "",
        "decision-nonce",
    )
    assert _serializer_fields(record) == source_serializer_fields
    assert service.degradation is None
    assert persist.calls == 1


def test_f10b_uncertain_transition_failed_rollback_retains_target_and_degrades(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    record = _record()
    _set_serializer_fields(record, "source")
    service.store.add(record)
    persist = _PersistRecorder(
        [
            _atomic_error(
                service.store.path,
                stage=AtomicWriteStage.PARENT_FSYNC,
                committed=True,
            ),
            _atomic_error(
                service.store.path,
                stage=AtomicWriteStage.REPLACE,
                committed=True,
            ),
        ],
        before_call=lambda call: _set_serializer_fields(
            record,
            "target" if call == 1 else "source",
        ),
    )

    with pytest.raises(AtomicWriteError) as caught:
        service.transition(
            PendingActionTransitionRequest(
                record=record,
                operation=PendingActionTransitionKind.REJECT,
                reason="operator_rejected",
                guard=_guard(record, decision=True),
            ),
            persist=persist,
        )

    assert caught.value.stage is AtomicWriteStage.REPLACE
    assert (record.status, record.status_reason, record.decision_nonce) == (
        "rejected",
        "operator_rejected",
        "",
    )
    target = _record()
    _set_serializer_fields(target, "target")
    assert _serializer_fields(record) == _serializer_fields(target)
    assert service.degradation == {
        "transition": "terminal",
        "stage": "replace",
        "reason": "pending_state_rollback_uncommitted",
    }
    with pytest.raises(StatePersistenceDegradedError):
        service.queue(_record(confirmation_id="c-blocked"), persist=_PersistRecorder())


def test_f10b_uncertain_start_failed_rollback_retains_executing_and_degrades(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    record = _record()
    record.execution_attempt_id = "attempt-c-1"
    record.result_id = "result-c-1"
    _bind_evidence(record)
    _set_serializer_fields(record, "source")
    service.store.add(record)
    persist = _PersistRecorder(
        [
            _atomic_error(
                service.store.path,
                stage=AtomicWriteStage.PARENT_FSYNC,
                committed=True,
            ),
            _atomic_error(
                service.store.path,
                stage=AtomicWriteStage.REPLACE,
                committed=True,
            ),
        ],
        before_call=lambda call: _set_serializer_fields(
            record,
            "target" if call == 1 else "source",
        ),
    )

    with pytest.raises(AtomicWriteError):
        service.transition(
            PendingActionTransitionRequest(
                record=record,
                operation=PendingActionTransitionKind.START,
                reason="confirmation_execution_started",
                guard=_guard(record, proof=True),
            ),
            persist=persist,
        )

    assert record.status == "executing"
    target = _record()
    _set_serializer_fields(target, "target")
    assert _serializer_fields(record) == _serializer_fields(target)
    assert service.degradation == {
        "transition": "executing",
        "stage": "replace",
        "reason": "pending_state_rollback_uncommitted",
    }


def test_f10b_queue_uncertain_failure_restores_index_or_degrades(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    record = _record()
    _set_serializer_fields(record, "source")
    persist = _PersistRecorder(
        [
            _atomic_error(
                service.store.path,
                stage=AtomicWriteStage.PARENT_FSYNC,
                committed=True,
            ),
            _atomic_error(
                service.store.path,
                stage=AtomicWriteStage.REPLACE,
                committed=True,
            ),
        ],
        before_call=lambda call: _set_serializer_fields(
            record,
            "target" if call == 1 else "source",
        ),
    )

    with pytest.raises(AtomicWriteError):
        service.queue(record, persist=persist)

    assert service.store.actions == {"c-1": record}
    assert service.store.by_session == {record.session_id: ["c-1"]}
    target = _record()
    _set_serializer_fields(target, "target")
    assert _serializer_fields(record) == _serializer_fields(target)
    assert service.degradation == {
        "transition": "queue",
        "stage": "replace",
        "reason": "pending_state_rollback_uncommitted",
    }


def test_f10b_queue_uncommitted_failure_restores_record_and_untouched_sibling(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    sibling = _record(confirmation_id="c-sibling")
    queued = _record()
    for record in (sibling, queued):
        _set_serializer_fields(record, "source")
    source_fields = {
        record.confirmation_id: _serializer_fields(record) for record in (sibling, queued)
    }
    service.store.add(sibling)

    def _mutate_all(_call: int) -> None:
        for record in (sibling, queued):
            _set_serializer_fields(record, "target")

    persist = _PersistRecorder(
        [
            _atomic_error(
                service.store.path,
                stage=AtomicWriteStage.WRITE,
                committed=False,
            )
        ],
        before_call=_mutate_all,
    )

    with pytest.raises(AtomicWriteError):
        service.queue(queued, persist=persist)

    assert service.store.actions == {"c-sibling": sibling}
    assert service.store.by_session == {sibling.session_id: ["c-sibling"]}
    assert _serializer_fields(sibling) == source_fields["c-sibling"]
    assert _serializer_fields(queued) == source_fields["c-1"]


def test_f10b_batch_validates_all_edges_before_mutating_any_record(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    first = _record(confirmation_id="c-first")
    second = _record(
        confirmation_id="c-second",
        status="approved",
        status_reason="already-complete",
    )
    service.store.add(first)
    service.store.add(second)
    persist = _PersistRecorder()

    with pytest.raises(PendingActionTransitionError, match="illegal_transition"):
        service.transition_many(
            (
                PendingActionTransitionRequest(
                    record=first,
                    operation=PendingActionTransitionKind.CANCEL,
                    reason="task_disabled",
                    guard=_guard(first),
                    scheduler_accounting_mode="shadow_only",
                ),
                PendingActionTransitionRequest(
                    record=second,
                    operation=PendingActionTransitionKind.CANCEL,
                    reason="task_disabled",
                    guard=_guard(second),
                    scheduler_accounting_mode="shadow_only",
                ),
            ),
            persist=persist,
        )

    assert first.status == "pending"
    assert second.status == "approved"
    assert persist.calls == 0


def test_f10b_batch_commits_once_and_all_store_observers_see_same_records(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    first = _record(confirmation_id="c-first")
    second = _record(confirmation_id="c-second")
    first.task_id = "task-1"
    second.task_id = "task-1"
    service.store.add(first)
    service.store.add(second)
    observer = service.store.actions
    persist = _PersistRecorder()

    results = service.transition_many(
        tuple(
            PendingActionTransitionRequest(
                record=record,
                operation=PendingActionTransitionKind.CANCEL,
                reason="task_disabled",
                guard=_guard(record),
                scheduler_accounting_mode="shadow_only",
            )
            for record in (first, second)
        ),
        persist=persist,
    )

    assert [result.changed for result in results] == [True, True]
    assert persist.calls == 1
    assert observer is service.store.actions
    assert observer["c-first"] is first
    assert observer["c-second"] is second
    assert {record.status for record in observer.values()} == {"cancelled"}
    assert {record.scheduler_accounting_mode for record in observer.values()} == {"shadow_only"}


@pytest.mark.parametrize("rollback_commits", [False, True])
def test_f10b_batch_write_failure_restores_all_or_retains_all_as_degraded(
    tmp_path: Path,
    rollback_commits: bool,
) -> None:
    service = _service(tmp_path)
    first = _record(confirmation_id="c-first")
    second = _record(confirmation_id="c-second")
    sibling = _record(confirmation_id="c-sibling")
    for record in (first, second, sibling):
        _set_serializer_fields(record, "source")
        service.store.add(record)
    failures = [
        _atomic_error(
            service.store.path,
            stage=AtomicWriteStage.PARENT_FSYNC,
            committed=True,
        )
    ]
    if rollback_commits:
        failures.append(
            _atomic_error(
                service.store.path,
                stage=AtomicWriteStage.REPLACE,
                committed=True,
            )
        )

    def _mutate_all(call: int) -> None:
        for record in (first, second, sibling):
            _set_serializer_fields(record, "target" if call == 1 else "source")

    persist = _PersistRecorder(
        failures,
        before_call=_mutate_all,
    )
    requests = tuple(
        PendingActionTransitionRequest(
            record=record,
            operation=PendingActionTransitionKind.CANCEL,
            reason="task_disabled",
            guard=_guard(record),
        )
        for record in (first, second)
    )

    with pytest.raises(AtomicWriteError):
        service.transition_many(requests, persist=persist)

    if rollback_commits:
        assert [first.status, second.status] == ["cancelled", "cancelled"]
        target = _record()
        _set_serializer_fields(target, "target")
        expected_serializer_fields = _serializer_fields(target)
        assert service.degradation == {
            "transition": "terminal",
            "stage": "replace",
            "reason": "pending_state_rollback_uncommitted",
        }
    else:
        assert [first.status, second.status] == ["pending", "pending"]
        source = _record()
        _set_serializer_fields(source, "source")
        expected_serializer_fields = _serializer_fields(source)
        assert service.degradation is None
    assert sibling.status == "pending"
    assert {_serializer_fields(record) for record in (first, second, sibling)} == {
        expected_serializer_fields
    }


def test_f10c_update_rejects_unowned_stale_or_forbidden_fields_before_write(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    record = _record(status="executing")
    unowned = _record(confirmation_id="c-unowned", status="executing")
    service.store.add(record)
    persist = _PersistRecorder()

    with pytest.raises(PendingActionTransitionError, match="unowned_record"):
        service.update(
            PendingActionUpdateRequest(
                record=unowned,
                mutation=PendingActionMutation(
                    kind=PendingActionMutationKind.EXECUTION,
                    values={"provider_operation_id": "provider-1"},
                ),
                guard=_guard(unowned, execution=True),
            ),
            persist=persist,
        )

    stale_guard = replace(
        _guard(record, execution=True),
        expected_execution_attempt_id="attempt-stale",
    )
    with pytest.raises(PendingActionTransitionError, match="guard_mismatch"):
        service.update(
            PendingActionUpdateRequest(
                record=record,
                mutation=PendingActionMutation(
                    kind=PendingActionMutationKind.EXECUTION,
                    values={"provider_operation_id": "provider-1"},
                ),
                guard=stale_guard,
            ),
            persist=persist,
        )

    for forbidden in ("status", "user_id", "record_schema_version"):
        with pytest.raises(PendingActionTransitionError, match="mutation_field_forbidden"):
            service.update(
                PendingActionUpdateRequest(
                    record=record,
                    mutation=PendingActionMutation(
                        kind=PendingActionMutationKind.EXECUTION,
                        values={forbidden: "forbidden"},
                    ),
                    guard=_guard(record, execution=True),
                ),
                persist=persist,
            )

    for transition_only in (
        PendingActionMutationKind.START,
        PendingActionMutationKind.DECISION,
        PendingActionMutationKind.PERSISTENCE,
    ):
        with pytest.raises(PendingActionTransitionError, match="mutation_kind_invalid"):
            service.update(
                PendingActionUpdateRequest(
                    record=record,
                    mutation=PendingActionMutation(kind=transition_only, values={}),
                    guard=_guard(record, execution=True),
                ),
                persist=persist,
            )

    assert persist.calls == 0
    assert record.provider_operation_id == ""
    assert record.status == "executing"


def test_f10c_completion_applies_metadata_and_transition_in_one_write(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    record = _record(status="executing")
    record.task_id = "task-1"
    service.store.add(record)
    persist = _PersistRecorder()

    result = service.transition(
        PendingActionTransitionRequest(
            record=record,
            operation=PendingActionTransitionKind.APPROVE,
            reason="allowed_execution_succeeded",
            guard=_guard(record, execution=True),
            mutation=PendingActionMutation(
                kind=PendingActionMutationKind.EXECUTION,
                values={
                    "provider_operation_id": "provider-1",
                    "recovery_effect_invoked": True,
                    "scheduler_accounting_pending": True,
                },
            ),
        ),
        persist=persist,
    )

    assert result.changed is True
    assert persist.calls == 1
    assert (
        record.status,
        record.status_reason,
        record.provider_operation_id,
        record.recovery_effect_invoked,
        record.scheduler_accounting_pending,
    ) == (
        "approved",
        "allowed_execution_succeeded",
        "provider-1",
        True,
        True,
    )


def test_f10c_terminal_decision_patch_requires_exact_proof_guard(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    record = _record()
    _bind_evidence(record)
    evidence = record.confirmation_evidence
    record.confirmation_evidence = None
    record.approval_evidence_hash = ""
    service.store.add(record)
    mutation = PendingActionMutation(
        kind=PendingActionMutationKind.DECISION,
        values={
            "confirmation_evidence": evidence,
            "approval_evidence_hash": evidence.evidence_hash,
        },
    )

    with pytest.raises(PendingActionTransitionError, match="proof_binding_mismatch"):
        service.transition(
            PendingActionTransitionRequest(
                record=record,
                operation=PendingActionTransitionKind.REJECT,
                reason="proof_rejected",
                guard=_guard(record, decision=True),
                mutation=mutation,
            ),
            persist=_PersistRecorder(),
        )

    executing = _record(confirmation_id="c-executing", status="executing")
    service.store.add(executing)
    with pytest.raises(PendingActionTransitionError, match="mutation_kind_invalid"):
        service.transition(
            PendingActionTransitionRequest(
                record=executing,
                operation=PendingActionTransitionKind.FAIL,
                reason="late_decision_forbidden",
                guard=_guard(executing, execution=True),
                mutation=mutation,
            ),
            persist=_PersistRecorder(),
        )

    persist = _PersistRecorder()
    result = service.transition(
        PendingActionTransitionRequest(
            record=record,
            operation=PendingActionTransitionKind.REJECT,
            reason="proof_rejected",
            guard=replace(
                _guard(record, decision=True),
                expected_evidence_hash=evidence.evidence_hash,
                expected_approver_principal_id=evidence.approver_principal_id,
            ),
            mutation=mutation,
        ),
        persist=persist,
    )

    assert result.changed is True
    assert record.confirmation_evidence is evidence
    assert record.approval_evidence_hash == evidence.evidence_hash
    assert persist.calls == 1


def test_f10c_transition_rejects_status_reason_override_before_write(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    record = _record(status="executing")
    service.store.add(record)
    persist = _PersistRecorder()

    with pytest.raises(PendingActionTransitionError, match="transition_reason_mutation_forbidden"):
        service.transition(
            PendingActionTransitionRequest(
                record=record,
                operation=PendingActionTransitionKind.OUTCOME_UNKNOWN,
                reason="canonical_transition_reason",
                guard=_guard(record, execution=True),
                mutation=PendingActionMutation(
                    kind=PendingActionMutationKind.RECOVERY,
                    values={"status_reason": "overriding_mutation_reason"},
                ),
            ),
            persist=persist,
        )

    assert (record.status, record.status_reason) == ("executing", "")
    assert persist.calls == 0


def test_f10c_preparer_rejection_rolls_back_transition_and_sibling_patch(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    record = _record()
    sibling = _record(confirmation_id="c-sibling")
    service.store.add(record)
    service.store.add(sibling)
    service.bind_persistence_preparer(
        lambda _records: (
            (
                sibling,
                PendingActionMutation(
                    kind=PendingActionMutationKind.PERSISTENCE,
                    values={"result_id": "serializer-derived"},
                ),
            ),
            (
                record,
                PendingActionMutation(
                    kind=PendingActionMutationKind.PERSISTENCE,
                    values={"status": "forbidden"},
                ),
            ),
        )
    )
    persist = _PersistRecorder()

    with pytest.raises(PendingActionPayloadError):
        service.transition(
            PendingActionTransitionRequest(
                record=record,
                operation=PendingActionTransitionKind.REJECT,
                reason="operator_rejected",
                guard=_guard(record, decision=True),
            ),
            persist=persist,
        )

    assert (record.status, record.status_reason, record.decision_nonce) == (
        "pending",
        "",
        "decision-nonce",
    )
    assert sibling.result_id == ""
    assert persist.calls == 0


def test_f10c_update_uncommitted_failure_restores_exact_record_and_sibling(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    record = _record(status="executing")
    sibling = _record(confirmation_id="c-sibling", status="executing")
    for item in (record, sibling):
        _set_serializer_fields(item, "source")
        service.store.add(item)
    source = {
        item.confirmation_id: (
            item.provider_operation_id,
            item.recovery_effect_invoked,
            _serializer_fields(item),
        )
        for item in (record, sibling)
    }

    def _mutate_serializer(_call: int) -> None:
        for item in (record, sibling):
            _set_serializer_fields(item, "target")

    persist = _PersistRecorder(
        [
            _atomic_error(
                service.store.path,
                stage=AtomicWriteStage.WRITE,
                committed=False,
            )
        ],
        before_call=_mutate_serializer,
    )

    with pytest.raises(AtomicWriteError):
        service.update(
            PendingActionUpdateRequest(
                record=record,
                mutation=PendingActionMutation(
                    kind=PendingActionMutationKind.RECOVERY,
                    values={
                        "provider_operation_id": "provider-recovered",
                        "recovery_effect_invoked": True,
                    },
                ),
                guard=_guard(record, execution=True),
            ),
            persist=persist,
        )

    assert {
        item.confirmation_id: (
            item.provider_operation_id,
            item.recovery_effect_invoked,
            _serializer_fields(item),
        )
        for item in (record, sibling)
    } == source
    assert service.degradation is None


def test_f10c_transition_patch_failed_uncertain_rollback_retains_target(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    record = _record(status="executing")
    _set_serializer_fields(record, "source")
    service.store.add(record)
    persist = _PersistRecorder(
        [
            _atomic_error(
                service.store.path,
                stage=AtomicWriteStage.PARENT_FSYNC,
                committed=True,
            ),
            _atomic_error(
                service.store.path,
                stage=AtomicWriteStage.REPLACE,
                committed=True,
            ),
        ],
        before_call=lambda call: _set_serializer_fields(
            record,
            "target" if call == 1 else "source",
        ),
    )

    with pytest.raises(AtomicWriteError):
        service.transition(
            PendingActionTransitionRequest(
                record=record,
                operation=PendingActionTransitionKind.OUTCOME_UNKNOWN,
                reason="uncertain_effect_requires_fresh_approval",
                guard=_guard(record, execution=True),
                mutation=PendingActionMutation(
                    kind=PendingActionMutationKind.EXECUTION,
                    values={
                        "provider_operation_id": "provider-uncertain",
                        "recovery_effect_invoked": True,
                        "recovery_accounting_pending": True,
                    },
                ),
            ),
            persist=persist,
        )

    assert record.status == "outcome_unknown"
    assert record.provider_operation_id == "provider-uncertain"
    assert record.recovery_effect_invoked is True
    assert record.recovery_accounting_pending is True
    target = _record(status="executing")
    _set_serializer_fields(target, "target")
    assert _serializer_fields(record) == _serializer_fields(target)
    assert service.degradation == {
        "transition": "terminal",
        "stage": "replace",
        "reason": "pending_state_rollback_uncommitted",
    }


def test_f10c_recovery_invalidation_binds_only_existing_partial_identity(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    record = _record(status="approved")
    record.execution_attempt_id = ""
    service.store.add(record)
    mutation = PendingActionMutation(kind=PendingActionMutationKind.RECOVERY, values={})

    stale_guard = PendingActionTransitionGuard.for_record(
        record,
        result_id="result-stale",
    )
    with pytest.raises(PendingActionTransitionError, match="guard_mismatch"):
        service.transition(
            PendingActionTransitionRequest(
                record=record,
                operation=PendingActionTransitionKind.INVALIDATE_RECOVERY,
                reason="corrupt_partial_identity",
                guard=stale_guard,
                mutation=mutation,
            ),
            persist=_PersistRecorder(),
        )

    persist = _PersistRecorder()
    result = service.transition(
        PendingActionTransitionRequest(
            record=record,
            operation=PendingActionTransitionKind.INVALIDATE_RECOVERY,
            reason="corrupt_partial_identity",
            guard=PendingActionTransitionGuard.for_record(
                record,
                result_id=record.result_id,
            ),
            mutation=mutation,
        ),
        persist=persist,
    )

    assert result.target_status == "outcome_unknown"
    assert record.status == "outcome_unknown"
    assert persist.calls == 1
    service.update(
        PendingActionUpdateRequest(
            record=record,
            mutation=PendingActionMutation(
                kind=PendingActionMutationKind.RECOVERY,
                values={"recovery_accounting_pending": True},
            ),
            guard=PendingActionTransitionGuard.for_record(
                record,
                result_id=record.result_id,
            ),
        ),
        persist=persist,
    )
    assert record.recovery_accounting_pending is True
    assert persist.calls == 2


def test_f10c_loaded_adoption_is_all_or_nothing_and_builds_one_index(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    first = _record(confirmation_id="c-first")
    second = _record(confirmation_id="c-second", status="approved")

    adopted = service.adopt_loaded((first, second))

    assert adopted == (first, second)
    assert service.store.actions == {"c-first": first, "c-second": second}
    assert service.store.by_session == {
        first.session_id: ["c-first", "c-second"],
    }
    service.store.assert_index_parity()

    duplicate = _record(confirmation_id="c-first")
    before_actions = dict(service.store.actions)
    before_index = {
        session_id: list(confirmation_ids)
        for session_id, confirmation_ids in service.store.by_session.items()
    }
    with pytest.raises(PendingActionTransitionError, match="duplicate_loaded_identity"):
        service.adopt_loaded((duplicate,))
    assert service.store.actions == before_actions
    assert service.store.by_session == before_index


def test_f10c_purge_owns_index_and_restores_exactly_on_uncommitted_failure(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    first = _record(confirmation_id="c-first", status="approved")
    second = _record(confirmation_id="c-second", status="failed")
    for item in (first, second):
        _set_serializer_fields(item, "source")
        service.store.add(item)
    persist = _PersistRecorder(
        [
            _atomic_error(
                service.store.path,
                stage=AtomicWriteStage.WRITE,
                committed=False,
            )
        ],
        before_call=lambda _call: _set_serializer_fields(second, "target"),
    )

    with pytest.raises(AtomicWriteError):
        service.purge((first,), persist=persist)

    assert service.store.actions == {"c-first": first, "c-second": second}
    assert service.store.by_session == {
        first.session_id: ["c-first", "c-second"],
    }
    source = _record(status="failed")
    _set_serializer_fields(source, "source")
    assert _serializer_fields(second) == _serializer_fields(source)
    assert service.degradation is None

    removed = service.purge((first,), persist=_PersistRecorder())
    assert removed == (first,)
    assert service.store.actions == {"c-second": second}
    assert service.store.by_session == {second.session_id: ["c-second"]}


def test_f10c_purge_failed_uncertain_rollback_retains_deletion_and_degrades(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    first = _record(confirmation_id="c-first", status="approved")
    second = _record(confirmation_id="c-second", status="failed")
    service.store.add(first)
    service.store.add(second)
    persist = _PersistRecorder(
        [
            _atomic_error(
                service.store.path,
                stage=AtomicWriteStage.PARENT_FSYNC,
                committed=True,
            ),
            _atomic_error(
                service.store.path,
                stage=AtomicWriteStage.REPLACE,
                committed=True,
            ),
        ]
    )

    with pytest.raises(AtomicWriteError):
        service.purge((first,), persist=persist)

    assert service.store.actions == {"c-second": second}
    assert service.store.by_session == {second.session_id: ["c-second"]}
    assert service.degradation == {
        "transition": "purge",
        "stage": "replace",
        "reason": "pending_state_rollback_uncommitted",
    }
