"""Action confirmation handler implementations."""

from __future__ import annotations

import asyncio
import getpass
import json
import logging
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from shisad.core.approval import (
    ConfirmationEvidence,
    ConfirmationLevel,
    ConfirmationRequirement,
    ConfirmationVerificationError,
    LocalFido2Backend,
    SignerConfirmationAdapter,
    TOTPBackend,
    WebAuthnBackend,
    approval_audit_fields,
    approval_envelope_hash,
    compute_action_digest,
    confirmation_backend_satisfies_constraints,
    confirmation_evidence_has_backend_proof,
    confirmation_evidence_is_canonical,
    confirmation_evidence_satisfies_requirement,
    generate_recovery_codes,
    generate_totp_secret,
    hash_recovery_code,
    intent_envelope_hash,
    match_totp_window,
    resolve_confirmation_destinations,
    safe_compare_sha256,
    safe_compare_text,
)
from shisad.core.atomic_state import AtomicWriteError, StatePersistenceDegradedError
from shisad.core.events import (
    PlanAmended,
    SignerKeyRegistered,
    SignerKeyRevoked,
    ToolRejected,
    TwoFactorEnrolled,
    TwoFactorRevoked,
)
from shisad.core.evidence import ArtifactEndorsementState
from shisad.core.tools.names import canonical_tool_name
from shisad.core.types import TaintLabel
from shisad.daemon.handlers._mixin_typing import (
    HandlerMixinBase,
)
from shisad.daemon.handlers._mixin_typing import (
    call_control_plane as _call_control_plane,
)
from shisad.daemon.handlers._pending_approval import (
    build_policy_context_for_pending_action,
    pending_action_event_identity_fields,
    pending_action_is_live_pending,
    pending_action_state_view,
    pending_approval_contract_hash,
    pep_arguments_for_policy_evaluation,
)
from shisad.security.control_plane.schema import RiskTier, build_action
from shisad.security.control_plane.sidecar import ControlPlaneRpcError
from shisad.security.credentials import ApprovalFactorRecord, RecoveryCodeRecord, SignerKeyRecord

logger = logging.getLogger(__name__)
_CONFIRMATION_SHORT_COOLDOWN_WAIT_MAX_SECONDS = 3.5
_CONFIRMATION_COOLDOWN_WAKE_MARGIN_SECONDS = 0.05
_CONFIRMATION_INTERNAL_SHORT_WAIT_KEY = "_shisad_internal_short_cooldown_wait_seconds"
_CONFIRMATION_INTERNAL_TASK_CANCEL_REASON_KEY = "_shisad_internal_task_cancel_reason"
_STALE_PENDING_APPROVAL_REASONS = frozenset(
    {
        "approval_envelope_missing",
        "approval_contract_missing",
        "approval_contract_mismatch",
        "action_digest_missing",
        "action_identity_mismatch",
    }
)
_PURGED_STALE_PENDING_ACTION_REASON = "purged_stale_pending_action"
_CONFIRMED_TRANSCRIPT_PAGE_TITLE_TOOL_NAMES = frozenset(
    {
        "browser.click",
        "browser.navigate",
        "browser.read_page",
        "browser.screenshot",
        "browser.type_text",
        "web.fetch",
    }
)


@dataclass(frozen=True, slots=True)
class _PendingAttemptSnapshot:
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
    confirmation_evidence: ConfirmationEvidence | None


def _capture_pending_attempt_snapshot(pending: Any) -> _PendingAttemptSnapshot:
    return _PendingAttemptSnapshot(
        status=str(getattr(pending, "status", "pending")),
        status_reason=str(getattr(pending, "status_reason", "")),
        decision_nonce=str(getattr(pending, "decision_nonce", "")),
        action_digest=str(getattr(pending, "action_digest", "")),
        approval_evidence_hash=str(getattr(pending, "approval_evidence_hash", "")),
        execution_attempt_id=str(getattr(pending, "execution_attempt_id", "")),
        result_id=str(getattr(pending, "result_id", "")),
        stage2_correlation_id=str(getattr(pending, "stage2_correlation_id", "")),
        stage2_previous_plan_hash=str(
            getattr(pending, "stage2_previous_plan_hash", "")
        ),
        stage2_plan_hash=str(getattr(pending, "stage2_plan_hash", "")),
        confirmation_evidence=getattr(pending, "confirmation_evidence", None),
    )


def _restore_pending_attempt_snapshot(
    pending: Any,
    snapshot: _PendingAttemptSnapshot,
) -> None:
    pending.status = snapshot.status
    pending.status_reason = snapshot.status_reason
    pending.decision_nonce = snapshot.decision_nonce
    pending.action_digest = snapshot.action_digest
    pending.approval_evidence_hash = snapshot.approval_evidence_hash
    pending.execution_attempt_id = snapshot.execution_attempt_id
    pending.result_id = snapshot.result_id
    pending.stage2_correlation_id = snapshot.stage2_correlation_id
    pending.stage2_previous_plan_hash = snapshot.stage2_previous_plan_hash
    pending.stage2_plan_hash = snapshot.stage2_plan_hash
    pending.confirmation_evidence = snapshot.confirmation_evidence


def _channel_principal_rejection_reason(
    pending: Any,
    params: Mapping[str, Any],
) -> str:
    allowed_channel_principals = [
        str(item).strip()
        for item in getattr(pending, "allowed_channel_principals", ())
        if str(item).strip()
    ]
    if not allowed_channel_principals:
        return ""
    principal_id = str(params.get("principal_id", "")).strip()
    if not principal_id:
        return "missing_channel_principal"
    if principal_id not in set(allowed_channel_principals):
        return "channel_principal_not_allowed"
    return ""


def _validate_signer_public_key(public_key_pem: str, *, algorithm: str) -> str:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    except (TypeError, ValueError):
        return "invalid_signer_public_key"

    if algorithm == "ed25519":
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            return ""
        return "signer_public_key_algorithm_mismatch"
    if algorithm == "ecdsa-secp256k1":
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            return "signer_public_key_algorithm_mismatch"
        if public_key.curve.name.lower() != "secp256k1":
            return "signer_public_key_algorithm_mismatch"
        return ""
    return "unsupported_signer_algorithm"


def _confirmation_control_plane_reason(exc: ControlPlaneRpcError) -> str:
    message = str(exc.message).strip().lower()
    if exc.reason_code == "rpc.invalid_params" and "inactive plan" in message:
        return "plan_missing_or_inactive"
    if exc.reason_code == "rpc.permission_denied":
        return "control_plane_permission_denied"
    if exc.reason_code in {"rpc.unavailable", "rpc.timeout"}:
        return "control_plane_unavailable"
    return "control_plane_rejected"


def _parse_confirmed_tool_output_payload(raw_content: str) -> dict[str, Any]:
    text = raw_content.strip()
    if not text:
        return {"structured": False, "text": ""}
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {"structured": False, "text": text}
    if isinstance(parsed, dict):
        return parsed
    return {"structured": True, "value": parsed}


def _serialize_confirmed_tool_output(record: Any) -> dict[str, Any]:
    tool_name = str(getattr(record, "tool_name", "")).strip() or "tool"
    canonical_name = canonical_tool_name(tool_name, warn_on_alias=False)
    taint_values_raw: Any = getattr(record, "taint_labels", set())
    taint_values: list[str] = []
    if isinstance(taint_values_raw, (set, frozenset, list, tuple)):
        taint_values = sorted(
            {
                str(getattr(label, "value", label)).strip().lower()
                for label in taint_values_raw
                if str(getattr(label, "value", label)).strip()
            }
        )
    ingress_context = str(getattr(record, "ingress_context", "") or "").strip()
    content_digest = str(getattr(record, "content_digest", "") or "").strip()
    raw_arguments = getattr(record, "arguments", None)
    arguments: dict[str, Any] = {}
    if canonical_name == "browser.navigate" and isinstance(raw_arguments, Mapping):
        url = str(raw_arguments.get("url", "")).strip()
        if url:
            arguments["url"] = url
    elif canonical_name == "fs.list" and isinstance(raw_arguments, Mapping):
        for key in ("path", "recursive", "limit", "filesystem_intent"):
            if key in raw_arguments:
                arguments[key] = raw_arguments[key]
    elif canonical_name == "fs.read" and isinstance(raw_arguments, Mapping):
        for key in ("path", "max_bytes", "filesystem_intent"):
            if key in raw_arguments:
                arguments[key] = raw_arguments[key]
    return {
        "tool_name": tool_name,
        "success": bool(getattr(record, "success", False)),
        "payload": _parse_confirmed_tool_output_payload(str(getattr(record, "content", ""))),
        "taint_labels": taint_values,
        **({"ingress_context": ingress_context} if ingress_context else {}),
        **({"content_digest": content_digest} if content_digest else {}),
        **({"arguments": arguments} if arguments else {}),
    }


def _safe_confirmed_tool_output_arguments(
    *,
    tool_name: str,
    arguments: Mapping[str, Any],
) -> dict[str, Any]:
    canonical_name = canonical_tool_name(tool_name, warn_on_alias=False)
    safe_arguments: dict[str, Any] = {}
    if canonical_name == "fs.list":
        for key in ("path", "recursive", "limit", "filesystem_intent"):
            if key in arguments:
                safe_arguments[key] = arguments[key]
    elif canonical_name == "fs.read":
        for key in ("path", "max_bytes", "filesystem_intent"):
            if key in arguments:
                safe_arguments[key] = arguments[key]
    return safe_arguments


def _confirmed_execution_failure_reason(record: Any) -> str:
    if record is None or bool(getattr(record, "success", False)):
        return ""
    try:
        payload = json.loads(str(getattr(record, "content", "")))
    except json.JSONDecodeError:
        return ""
    if not isinstance(payload, dict):
        return ""
    for key in ("error", "reason", "status_reason"):
        reason = str(payload.get(key, "")).strip()
        if reason:
            return reason
    return ""


def _confirmed_tool_output_transcript_content(*, tool_name: str, content: str) -> str:
    canonical_name = canonical_tool_name(tool_name, warn_on_alias=False)
    if canonical_name not in _CONFIRMED_TRANSCRIPT_PAGE_TITLE_TOOL_NAMES:
        return content
    parsed = _parse_confirmed_tool_output_payload(content)
    if "title" not in parsed:
        return content
    sanitized = dict(parsed)
    sanitized.pop("title", None)
    return json.dumps(sanitized, ensure_ascii=True, sort_keys=True)


def _confirmed_tool_output_page_title_metadata(*, tool_name: str, content: str) -> dict[str, Any]:
    canonical_name = canonical_tool_name(tool_name, warn_on_alias=False)
    if canonical_name not in _CONFIRMED_TRANSCRIPT_PAGE_TITLE_TOOL_NAMES:
        return {}
    parsed = _parse_confirmed_tool_output_payload(content)
    title = str(parsed.get("title", "")).strip()
    if not title:
        return {}
    metadata = {"title": title}
    for key in ("url", "screenshot_id"):
        value = str(parsed.get(key, "")).strip()
        if value:
            metadata[key] = value
    return metadata


def _apply_delivery_target_metadata(metadata: dict[str, Any], delivery_target: Any) -> None:
    delivery_target_payload: dict[str, Any] | None = None
    if hasattr(delivery_target, "model_dump"):
        delivery_target_payload = delivery_target.model_dump(mode="json")
    elif isinstance(delivery_target, Mapping):
        delivery_target_payload = dict(delivery_target)
    if delivery_target_payload is None:
        return
    metadata["delivery_target"] = delivery_target_payload
    delivery_channel = str(delivery_target_payload.get("channel", "")).strip()
    if delivery_channel:
        metadata["channel"] = delivery_channel


@dataclass(slots=True)
class PendingTwoFactorEnrollment:
    enrollment_id: str
    user_id: str
    method: str
    principal_id: str
    credential_id: str
    created_at: datetime
    expires_at: datetime
    secret_b32: str = ""
    webauthn_creation_options: dict[str, Any] = field(default_factory=dict)
    webauthn_registration_state: dict[str, Any] = field(default_factory=dict)
    webauthn_rp_id: str = ""
    webauthn_origin: str = ""


class ConfirmationImplMixin(HandlerMixinBase):
    def _append_confirmed_tool_output_transcript(
        self,
        *,
        pending: Any,
        tool_output: Any,
        decision_timestamp: str,
    ) -> None:
        pending_tool_name = canonical_tool_name(
            str(getattr(pending, "tool_name", "")).strip(),
            warn_on_alias=False,
        )
        if pending_tool_name == "evidence.promote":
            return
        tool_name = str(getattr(pending, "tool_name", "")).strip()
        raw_content = str(getattr(tool_output, "content", "") or "")
        page_title_metadata = _confirmed_tool_output_page_title_metadata(
            tool_name=tool_name,
            content=raw_content,
        )
        content = _confirmed_tool_output_transcript_content(
            tool_name=tool_name,
            content=raw_content,
        )
        if not content.strip():
            return
        raw_taints: Any = getattr(tool_output, "taint_labels", set())
        taint_labels: set[TaintLabel] = set(raw_taints) if isinstance(raw_taints, set) else set()
        metadata: dict[str, Any] = {
            "channel": "confirmation",
            "actor": "human_confirmation",
            "confirmed_tool_output": True,
            "tool_name": tool_name,
            "confirmation_id": str(getattr(pending, "confirmation_id", "")).strip(),
            "tool_success": bool(getattr(tool_output, "success", False)),
            "timestamp_utc": decision_timestamp,
            "action_identity": pending_action_state_view(pending).identity.to_payload(),
        }
        if page_title_metadata:
            metadata["page_title_metadata"] = page_title_metadata
        pending_user_id = str(getattr(pending, "user_id", "")).strip()
        pending_workspace_id = str(getattr(pending, "workspace_id", "")).strip()
        if pending_user_id:
            metadata["user_id"] = pending_user_id
        if pending_workspace_id:
            metadata["workspace_id"] = pending_workspace_id
        _apply_delivery_target_metadata(metadata, getattr(pending, "delivery_target", None))
        try:
            self._transcript_store.append(
                pending.session_id,
                role="tool",
                content=content,
                taint_labels=taint_labels,
                metadata=metadata,
            )
        except (OSError, RuntimeError, TypeError, ValueError):
            logger.warning(
                "Failed to append confirmed tool output to transcript for confirmation %s",
                getattr(pending, "confirmation_id", ""),
                exc_info=True,
            )

    @staticmethod
    def _pending_confirmation_method_for_lockout(pending: Any) -> str:
        method = str(getattr(pending, "selected_backend_method", "") or "software").strip()
        return method or "software"

    def _pending_approval_contract_invalid_reason(
        self,
        pending: Any,
        *,
        require_evidence: bool = False,
    ) -> str:
        approval_envelope = getattr(pending, "approval_envelope", None)
        if approval_envelope is None:
            return "approval_envelope_missing"
        if str(getattr(approval_envelope, "schema_version", "")) != (
            "shisad.approval.v2"
        ):
            return "approval_contract_missing"
        stored_contract_hash = str(
            getattr(approval_envelope, "approval_contract_hash", "")
        ).strip()
        if not stored_contract_hash:
            return "approval_contract_missing"
        stored_envelope_hash = str(
            getattr(pending, "approval_envelope_hash", "")
        ).strip()
        try:
            expected_envelope_hash = approval_envelope_hash(approval_envelope)
        except (TypeError, ValueError):
            return "approval_contract_mismatch"
        if not stored_envelope_hash or expected_envelope_hash != stored_envelope_hash:
            return "approval_contract_mismatch"

        identity = pending_action_state_view(pending).identity
        created_at = getattr(pending, "created_at", None)
        execute_after = getattr(pending, "execute_after", None)
        expires_at = getattr(pending, "expires_at", None)
        envelope_expires_at = getattr(approval_envelope, "expires_at", None)
        if not (
            isinstance(created_at, datetime)
            and isinstance(expires_at, datetime)
            and isinstance(envelope_expires_at, datetime)
        ):
            return "approval_contract_mismatch"
        if any(
            value.tzinfo is None or value.utcoffset() is None
            for value in (created_at, expires_at, envelope_expires_at)
        ):
            return "approval_contract_mismatch"
        if expires_at != envelope_expires_at or expires_at <= created_at:
            return "approval_contract_mismatch"
        if execute_after is not None and (
            not isinstance(execute_after, datetime)
            or execute_after.tzinfo is None
            or execute_after.utcoffset() is None
            or execute_after < created_at
            or execute_after > expires_at
        ):
            return "approval_contract_mismatch"
        if (
            str(getattr(approval_envelope, "approval_id", "")).strip()
            != identity.confirmation_id
            or str(getattr(approval_envelope, "pending_action_id", "")).strip()
            != identity.action_id
        ):
            return "action_identity_mismatch"
        if (
            str(getattr(approval_envelope, "session_id", "")).strip()
            != identity.session_id
            or str(getattr(approval_envelope, "workspace_id", "")).strip()
            != identity.workspace_id
            or str(getattr(approval_envelope, "daemon_id", "")).strip()
            != str(getattr(self, "_daemon_id", "")).strip()
            or getattr(approval_envelope, "required_level", None)
            != getattr(pending, "required_level", None)
            or list(getattr(approval_envelope, "allowed_principals", ()))
            != list(getattr(pending, "allowed_principals", ()))
            or list(getattr(approval_envelope, "allowed_credentials", ()))
            != list(getattr(pending, "allowed_credentials", ()))
            or str(getattr(approval_envelope, "policy_reason", ""))
            != str(getattr(pending, "reason", ""))
        ):
            return "approval_contract_mismatch"

        backend_registry = getattr(self, "_confirmation_backend_registry", None)
        get_backend = getattr(backend_registry, "get_backend", None)
        backend = (
            get_backend(
                str(getattr(pending, "selected_backend_id", "")).strip()
                or "software.default"
            )
            if callable(get_backend)
            else None
        )
        selected_backend_method = str(
            getattr(pending, "selected_backend_method", "")
        ).strip()
        if (
            backend is None
            or str(getattr(backend, "method", "")).strip()
            != selected_backend_method
            or not confirmation_backend_satisfies_constraints(
                backend,
                user_id=identity.user_id,
                required_capabilities=getattr(
                    pending,
                    "required_capabilities",
                    ConfirmationRequirement().require_capabilities,
                ),
                allowed_principals=getattr(pending, "allowed_principals", ()),
                allowed_credentials=getattr(pending, "allowed_credentials", ()),
            )
        ):
            return "approval_contract_mismatch"

        registry = getattr(self, "_registry", None)
        get_tool = getattr(registry, "get_tool", None)
        tool_definition = get_tool(pending.tool_name) if callable(get_tool) else None
        if tool_definition is None:
            return "approval_contract_mismatch"
        try:
            normalized_arguments = pep_arguments_for_policy_evaluation(
                pending.tool_name,
                pending.arguments,
            )
            expected_action_digest = compute_action_digest(
                tool_definition=tool_definition,
                arguments=normalized_arguments,
                destinations=resolve_confirmation_destinations(
                    tool_definition=tool_definition,
                    arguments=normalized_arguments,
                ),
                stable_idempotency_key=str(
                    getattr(pending, "stable_idempotency_key", "")
                ).strip(),
            )
        except (TypeError, ValueError):
            return "approval_contract_mismatch"
        if not str(getattr(pending, "action_digest", "")).strip() or not str(
            getattr(approval_envelope, "action_digest", "")
        ).strip():
            return "action_digest_missing"
        if (
            str(getattr(pending, "action_digest", "")).strip()
            != expected_action_digest
            or str(getattr(approval_envelope, "action_digest", "")).strip()
            != expected_action_digest
        ):
            return "approval_contract_mismatch"
        try:
            expected_contract_hash = pending_approval_contract_hash(pending)
        except (TypeError, ValueError):
            return "approval_contract_mismatch"
        if not safe_compare_sha256(stored_contract_hash, expected_contract_hash):
            return "approval_contract_mismatch"

        intent_envelope = getattr(pending, "intent_envelope", None)
        stored_intent_hash = str(
            getattr(approval_envelope, "intent_envelope_hash", "") or ""
        ).strip()
        if intent_envelope is None:
            if stored_intent_hash:
                return "approval_contract_mismatch"
        else:
            try:
                actual_intent_hash = intent_envelope_hash(intent_envelope)
            except (TypeError, ValueError):
                return "approval_contract_mismatch"
            if actual_intent_hash != stored_intent_hash:
                return "approval_contract_mismatch"

        if require_evidence:
            evidence = getattr(pending, "confirmation_evidence", None)
            evidence_authenticator = getattr(
                self,
                "_confirmation_evidence_authenticator",
                None,
            )
            if (
                evidence is None
                or backend is None
                or str(getattr(evidence, "approval_envelope_hash", "")).strip()
                != stored_envelope_hash
                or str(getattr(evidence, "action_digest", "")).strip()
                != expected_action_digest
                or str(getattr(evidence, "decision_nonce", "")).strip()
                != str(getattr(pending, "decision_nonce", "")).strip()
                or bool(getattr(evidence, "fallback_used", False))
                != bool(getattr(pending, "fallback_used", False))
                or not isinstance(getattr(evidence, "verified_at", None), datetime)
                or evidence.verified_at.tzinfo is None
                or evidence.verified_at.utcoffset() is None
                or evidence.verified_at < created_at
                or evidence.verified_at > expires_at
                or not confirmation_evidence_is_canonical(
                    evidence=evidence,
                    backend=backend,
                    confirmation_id=identity.confirmation_id,
                )
                or not confirmation_evidence_has_backend_proof(
                    pending_action=pending,
                    evidence=evidence,
                    backend=backend,
                )
                or evidence_authenticator is None
                or not evidence_authenticator.verify(evidence)
                or not confirmation_evidence_satisfies_requirement(
                    requirement=self._pending_confirmation_requirement(pending),
                    evidence=evidence,
                    backend=backend,
                )
            ):
                return "approval_contract_mismatch"
            allowed_channel_principals = {
                str(item).strip()
                for item in getattr(pending, "allowed_channel_principals", ())
                if str(item).strip()
            }
            if allowed_channel_principals:
                evidence_channel_principal = str(
                    evidence.evidence_payload.get("channel_principal_id", "")
                    or evidence.approver_principal_id
                ).strip()
                if evidence_channel_principal not in allowed_channel_principals:
                    return "approval_contract_mismatch"
        return ""

    def _pending_approval_stale_reason(self, pending: Any) -> str:
        if str(getattr(pending, "status", "")).strip().lower() != "pending":
            return ""
        return self._pending_approval_contract_invalid_reason(pending)

    def _stale_pending_action_reason(self, pending: Any) -> str:
        if str(getattr(pending, "status", "")).strip().lower() != "pending":
            return ""
        reason = self._pending_approval_stale_reason(pending)
        if reason:
            return reason
        tracker = getattr(self, "_confirmation_failure_tracker", None)
        status = getattr(tracker, "status", None)
        if not callable(status):
            return ""
        retry_after = status(
            user_id=str(getattr(pending, "user_id", "")),
            method=self._pending_confirmation_method_for_lockout(pending),
        )
        return "confirmation_method_locked_out" if retry_after is not None else ""

    def _mark_stale_pending_action(
        self,
        pending: Any,
        *,
        reason: str,
        persist: bool = True,
    ) -> None:
        if persist:
            self._commit_pending_terminal_state(
                pending,
                status="failed",
                reason=reason,
            )
            self._sync_task_confirmation_status(pending)
            self._record_task_confirmation_failure(pending)
            return
        pending.status = "failed"
        pending.status_reason = reason
        pending.decision_nonce = ""

    def _commit_pending_terminal_states(
        self,
        transitions: list[tuple[Any, str, str]],
        *,
        rollback_snapshots: list[_PendingAttemptSnapshot] | None = None,
    ) -> None:
        if not transitions:
            return
        previous = rollback_snapshots or [
            _capture_pending_attempt_snapshot(pending)
            for pending, _status, _reason in transitions
        ]
        if len(previous) != len(transitions):
            raise ValueError("terminal rollback snapshot count mismatch")
        for pending, status, reason in transitions:
            pending.status = status
            pending.status_reason = reason
            pending.decision_nonce = ""
        terminal = [
            _capture_pending_attempt_snapshot(pending)
            for pending, _status, _reason in transitions
        ]
        try:
            self._persist_pending_actions()
        except AtomicWriteError as write_error:
            for (pending, _status, _reason), snapshot in zip(
                transitions,
                previous,
                strict=True,
            ):
                _restore_pending_attempt_snapshot(pending, snapshot)
            if write_error.publication_may_have_committed:
                try:
                    self._persist_pending_actions()
                except AtomicWriteError as rollback_error:
                    for (pending, _status, _reason), snapshot in zip(
                        transitions,
                        terminal,
                        strict=True,
                    ):
                        _restore_pending_attempt_snapshot(pending, snapshot)
                    self._pending_state_degradation = {
                        "transition": "terminal",
                        "stage": rollback_error.stage.value,
                        "reason": "pending_state_rollback_uncommitted",
                    }
                    raise rollback_error from write_error
            raise

    def _commit_pending_terminal_state(
        self,
        pending: Any,
        *,
        status: str,
        reason: str,
        rollback_snapshot: _PendingAttemptSnapshot | None = None,
    ) -> None:
        self._commit_pending_terminal_states(
            [(pending, status, reason)],
            rollback_snapshots=[rollback_snapshot] if rollback_snapshot is not None else None,
        )

    async def _commit_and_publish_pending_terminal(
        self,
        pending: Any,
        *,
        status: str,
        status_reason: str,
        event_reason: str | None = None,
        actor: str = "human_confirmation",
        record_analytics: bool = True,
        emit_hygiene_alert: bool = True,
        rollback_snapshot: _PendingAttemptSnapshot | None = None,
    ) -> None:
        decision_timestamp = datetime.now(UTC).isoformat()
        decision_nonce = str(getattr(pending, "decision_nonce", ""))
        evidence_fields = approval_audit_fields(
            getattr(pending, "confirmation_evidence", None)
        )
        self._commit_pending_terminal_state(
            pending,
            status=status,
            reason=status_reason,
            rollback_snapshot=rollback_snapshot,
        )
        event_fields = self._pending_approval_event_fields(
            pending,
            decision_timestamp=decision_timestamp,
        )
        event_fields["approval_decision_nonce"] = decision_nonce
        event_fields.update(evidence_fields)
        self._sync_task_confirmation_status(pending)
        self._record_task_confirmation_failure(pending)
        await self._event_bus.publish(
            ToolRejected(
                session_id=pending.session_id,
                actor=actor,
                tool_name=pending.tool_name,
                reason=event_reason or status_reason,
                **event_fields,
            )
        )
        if record_analytics:
            self._confirmation_analytics.record(
                user_id=str(pending.user_id),
                decision="reject",
                created_at=pending.created_at,
            )
        if emit_hygiene_alert:
            await self._maybe_emit_confirmation_hygiene_alert(
                user_id=str(pending.user_id),
                session_id=pending.session_id,
            )

    async def _cancel_stage2_authority(
        self,
        pending: Any,
        *,
        reason: str,
    ) -> bool:
        correlation_id = str(
            getattr(pending, "stage2_correlation_id", "")
        ).strip()
        if not correlation_id:
            return False
        try:
            return bool(
                await _call_control_plane(
                    self,
                    "cancel_stage2",
                    session_id=str(pending.session_id),
                    correlation_id=correlation_id,
                    expected_plan_hash=str(
                        getattr(pending, "stage2_plan_hash", "")
                    ).strip(),
                    reason=reason,
                    actor="human_confirmation",
                )
            )
        except Exception:
            self._terminate_session(
                pending.session_id,
                reason="stage2_authority_reconciliation_failed",
            )
            logger.exception(
                "Failed to reconcile stage-two authority for %s",
                pending.confirmation_id,
            )
            return False

    async def _cancel_pending_actions_for_task(
        self,
        task_id: str,
        *,
        reason: str,
    ) -> list[str]:
        normalized_task_id = task_id.strip()
        if not normalized_task_id:
            return []
        candidate_ids = sorted(
            str(getattr(pending, "confirmation_id", "")).strip()
            for pending in self._pending_actions.values()
            if str(getattr(pending, "task_id", "")).strip() == normalized_task_id
            and pending_action_state_view(pending).is_live_pending
            and str(getattr(pending, "confirmation_id", "")).strip()
        )
        locks: list[tuple[str, asyncio.Lock]] = []
        cancelled: list[Any] = []
        try:
            for confirmation_id in candidate_ids:
                lock = self._action_confirmation_lock(confirmation_id)
                await lock.acquire()
                locks.append((confirmation_id, lock))
            for confirmation_id in candidate_ids:
                pending = self._pending_actions.get(confirmation_id)
                if pending is None:
                    continue
                if str(getattr(pending, "task_id", "")).strip() != normalized_task_id:
                    continue
                if not pending_action_state_view(pending).is_live_pending:
                    continue
                cancelled.append(pending)
            if cancelled:
                self._commit_pending_terminal_states(
                    [
                        (pending, "cancelled", reason)
                        for pending in cancelled
                    ]
                )
            for pending in cancelled:
                self._sync_task_confirmation_status(pending)
                await self._event_bus.publish(
                    ToolRejected(
                        session_id=pending.session_id,
                        actor="scheduler",
                        tool_name=pending.tool_name,
                        reason=reason,
                        **self._pending_approval_event_fields(
                            pending,
                            decision_timestamp=datetime.now(UTC).isoformat(),
                        ),
                    )
                )
        finally:
            for confirmation_id, lock in reversed(locks):
                if lock.locked():
                    lock.release()
                self._discard_action_confirmation_lock_if_idle(confirmation_id, lock)
        return [str(pending.confirmation_id) for pending in cancelled]

    @staticmethod
    def _requested_confirmation_method(*, params: Mapping[str, Any], pending: Any) -> str:
        requested = str(
            params.get("approval_method")
            or params.get("method")
            or getattr(pending, "selected_backend_method", "")
            or "software"
        ).strip()
        return requested or "software"

    @staticmethod
    def _pending_confirmation_requirement(pending: Any) -> ConfirmationRequirement:
        return ConfirmationRequirement(
            level=getattr(pending, "required_level", ConfirmationRequirement().level),
            methods=list(getattr(pending, "required_methods", ())),
            allowed_principals=list(getattr(pending, "allowed_principals", ())),
            allowed_credentials=list(getattr(pending, "allowed_credentials", ())),
            require_capabilities=getattr(pending, "required_capabilities", None)
            or ConfirmationRequirement().require_capabilities,
            fallback=getattr(pending, "fallback", None) or ConfirmationRequirement().fallback,
        )

    @staticmethod
    def _pending_approval_event_fields(
        pending: Any,
        *,
        decision_timestamp: str,
    ) -> dict[str, Any]:
        fields: dict[str, Any] = pending_action_event_identity_fields(pending)
        fields["approval_decision_nonce"] = str(getattr(pending, "decision_nonce", ""))
        fields["approval_timestamp"] = decision_timestamp
        fields.update(approval_audit_fields(getattr(pending, "confirmation_evidence", None)))
        return fields

    @staticmethod
    def _pending_action_response_identity_fields(pending: Any) -> dict[str, Any]:
        state_view = pending_action_state_view(pending)
        return {
            "action_id": state_view.identity.action_id,
            "identity": state_view.identity.to_payload(),
            "lifecycle_state": state_view.lifecycle_state,
        }

    def _pending_state_degradation_fields(self) -> dict[str, str]:
        degradation = getattr(self, "_pending_state_degradation", None)
        if not isinstance(degradation, Mapping):
            return {}
        return {
            "persistence_status": "degraded",
            "persistence_reason": str(degradation.get("reason", "")),
            "persistence_stage": str(degradation.get("stage", "")),
            "persistence_transition": str(degradation.get("transition", "")),
        }

    def _pending_state_degraded_decision_response(
        self,
        *,
        confirmation_id: str,
        decision_field: Literal["confirmed", "rejected"],
    ) -> dict[str, Any] | None:
        fields = self._pending_state_degradation_fields()
        if not fields:
            return None
        return {
            decision_field: False,
            "confirmation_id": confirmation_id,
            "reason": "pending_state_persistence_degraded",
            **fields,
        }

    def _sync_task_confirmation_status(self, pending: Any) -> None:
        task_id = str(getattr(pending, "task_id", "")).strip()
        if not task_id:
            return
        resolver = getattr(self, "_scheduler", None)
        if resolver is None:
            return
        resolve_confirmation = getattr(resolver, "resolve_confirmation", None)
        if not callable(resolve_confirmation):
            return
        state_view = pending_action_state_view(pending)
        resolve_confirmation(
            task_id,
            confirmation_id=str(getattr(pending, "confirmation_id", "")),
            status=str(getattr(pending, "status", "")),
            status_reason=str(getattr(pending, "status_reason", "")),
            lifecycle_state=state_view.lifecycle_state,
            action_id=state_view.identity.action_id,
            execution_attempt_id=state_view.identity.execution_attempt_id,
            result_id=state_view.identity.result_id,
        )

    def _record_task_confirmation_failure(self, pending: Any) -> None:
        task_id = str(getattr(pending, "task_id", "")).strip()
        if not task_id:
            return
        scheduler = getattr(self, "_scheduler", None)
        if scheduler is None:
            return
        confirmation_id = str(getattr(pending, "confirmation_id", "")).strip()
        confirmation_recorder = getattr(scheduler, "record_confirmation_outcome", None)
        if (
            confirmation_id
            and callable(confirmation_recorder)
            and confirmation_recorder(
                task_id,
                confirmation_id=confirmation_id,
                success=False,
            )
        ):
            return
        recorder = getattr(scheduler, "record_run_outcome", None)
        if callable(recorder):
            recorder(task_id, success=False)

    async def _complete_confirmation_scheduler_accounting(
        self,
        pending: Any,
        *,
        success: bool,
        outcome_unknown: bool,
    ) -> str:
        complete_accounting = getattr(
            self,
            "_complete_pending_scheduler_accounting",
            None,
        )
        if callable(complete_accounting):
            return str(complete_accounting(pending))

        task_id = str(getattr(pending, "task_id", "")).strip()
        task_auto_disabled = await self._record_task_run_outcome(
            task_id,
            success=success,
            cancel_pending=False,
            confirmation_id=str(getattr(pending, "confirmation_id", "")),
        )
        task_uncertainty_disabled = False
        if outcome_unknown and task_id:
            disable_task = getattr(self._scheduler, "disable_task", None)
            if callable(disable_task):
                task_uncertainty_disabled = bool(disable_task(task_id))
        pending.scheduler_accounting_pending = False
        try:
            self._persist_pending_actions()
        except AtomicWriteError:
            pending.scheduler_accounting_pending = True
            raise
        if task_auto_disabled:
            return "max_runs_reached"
        if task_uncertainty_disabled:
            return "outcome_unknown"
        return ""

    def _contain_confirmation_scheduler_attempt(self, task_id: str) -> None:
        contain_attempt = getattr(self, "_contain_unresolved_task_attempt", None)
        if callable(contain_attempt):
            contain_attempt(task_id)
            return
        disable_task = getattr(getattr(self, "_scheduler", None), "disable_task", None)
        if not callable(disable_task) or not bool(disable_task(task_id)):
            raise RuntimeError("scheduler_attempt_containment_failed")

    async def do_confirmation_metrics(self, params: Mapping[str, Any]) -> dict[str, Any]:
        window_seconds = max(60, int(params.get("window_seconds", 900)))
        requested_user = str(params.get("user_id") or "").strip()
        if requested_user:
            metrics = self._confirmation_analytics.metrics(
                user_id=requested_user,
                window_seconds=window_seconds,
            )
            return {"metrics": [metrics], "count": 1}
        rows = [
            self._confirmation_analytics.metrics(user_id=user, window_seconds=window_seconds)
            for user in self._confirmation_analytics.users()
        ]
        return {"metrics": rows, "count": len(rows)}

    def _totp_backend(self) -> TOTPBackend:
        backend = self._confirmation_backend_registry.get_backend("totp.default")
        if not isinstance(backend, TOTPBackend):
            raise RuntimeError("totp backend is unavailable")
        return backend

    def _webauthn_backend(self) -> WebAuthnBackend:
        backend = self._confirmation_backend_registry.get_backend("webauthn.default")
        if not isinstance(backend, WebAuthnBackend):
            raise RuntimeError("webauthn backend is unavailable")
        return backend

    def _selected_backend_available_for_pending(self, pending: Any) -> bool:
        selected_backend_available = getattr(self, "_pending_selected_backend_available", None)
        if not callable(selected_backend_available):
            return True
        try:
            return bool(selected_backend_available(pending))
        except Exception:
            return False

    def _local_fido2_backend(self) -> LocalFido2Backend:
        backend = self._confirmation_backend_registry.get_backend("approver.local_fido2")
        if not isinstance(backend, LocalFido2Backend):
            raise RuntimeError("local_fido2 backend is unavailable")
        return backend

    def _prune_two_factor_enrollments(self, *, now: datetime | None = None) -> None:
        current = now or datetime.now(UTC)
        pending = getattr(self, "_pending_two_factor_enrollments", {})
        expired = [
            enrollment_id
            for enrollment_id, enrollment in pending.items()
            if isinstance(enrollment, PendingTwoFactorEnrollment)
            and enrollment.expires_at <= current
        ]
        for enrollment_id in expired:
            pending.pop(enrollment_id, None)

    async def _webauthn_registration_ceremony_context(
        self,
        enrollment_id: str,
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        self._prune_two_factor_enrollments(now=now)
        enrollment = self._pending_two_factor_enrollments.get(enrollment_id)
        if not isinstance(enrollment, PendingTwoFactorEnrollment):
            return {
                "ok": False,
                "status": "not_found",
                "reason": "enrollment_not_found",
                "message": "This passkey registration link is no longer available.",
            }
        if enrollment.method != "webauthn":
            return {
                "ok": False,
                "status": "invalid_method",
                "reason": "unsupported_2fa_method",
                "message": "This enrollment is not a WebAuthn registration.",
            }
        if enrollment.expires_at <= now:
            return {
                "ok": False,
                "status": "expired",
                "reason": "enrollment_expired",
                "message": "This passkey registration link has expired.",
            }
        return {
            "ok": True,
            "status": "pending",
            "summary": (
                f"Register a passkey for user={enrollment.user_id} "
                f"principal={enrollment.principal_id} credential={enrollment.credential_id}"
            ),
            "public_key": dict(enrollment.webauthn_creation_options),
            "expires_at": enrollment.expires_at.isoformat().replace("+00:00", "Z"),
            "credential_id": enrollment.credential_id,
            "principal_id": enrollment.principal_id,
            "user_id": enrollment.user_id,
            "rp_id": enrollment.webauthn_rp_id,
            "origin": enrollment.webauthn_origin,
        }

    async def _complete_webauthn_registration_ceremony(
        self,
        enrollment_id: str,
        response_payload: dict[str, Any],
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        self._prune_two_factor_enrollments(now=now)
        enrollment = self._pending_two_factor_enrollments.get(enrollment_id)
        if not isinstance(enrollment, PendingTwoFactorEnrollment):
            return {"registered": False, "reason": "enrollment_not_found"}
        if enrollment.method != "webauthn":
            return {"registered": False, "reason": "unsupported_2fa_method"}
        if enrollment.expires_at <= now:
            self._pending_two_factor_enrollments.pop(enrollment_id, None)
            return {"registered": False, "reason": "enrollment_expired"}

        try:
            factor = self._webauthn_backend().registration_complete(
                credential_id=enrollment.credential_id,
                user_id=enrollment.user_id,
                principal_id=enrollment.principal_id,
                created_at=enrollment.created_at,
                state=dict(enrollment.webauthn_registration_state),
                response_payload=dict(response_payload),
            )
        except ConfirmationVerificationError as exc:
            return {"registered": False, "reason": exc.reason}

        self._credential_store.register_approval_factor(factor)
        self._pending_two_factor_enrollments.pop(enrollment_id, None)
        await self._event_bus.publish(
            TwoFactorEnrolled(
                actor="control_plane",
                user_id=factor.user_id,
                method=factor.method,
                credential_id=factor.credential_id,
                principal_id=factor.principal_id,
            )
        )
        return {
            "registered": True,
            "user_id": factor.user_id,
            "method": factor.method,
            "principal_id": factor.principal_id,
            "credential_id": factor.credential_id,
        }

    def _local_fido2_approval_context(self, pending: Any) -> dict[str, Any]:
        if str(getattr(pending, "selected_backend_method", "")).strip() != "local_fido2":
            return {"ok": False, "reason": "unsupported_confirmation_method"}
        try:
            backend = self._local_fido2_backend()
            public_key = backend.approval_request_options(pending_action=pending)
        except (ConfirmationVerificationError, RuntimeError) as exc:
            reason = exc.reason if isinstance(exc, ConfirmationVerificationError) else str(exc)
            return {"ok": False, "reason": reason}
        return {
            "ok": True,
            "public_key": public_key,
            "origin": backend.approval_origin,
            "rp_id": backend.rp_id,
        }

    async def _webauthn_approval_ceremony_context(
        self,
        confirmation_id: str,
    ) -> dict[str, Any]:
        pending = self._pending_actions.get(confirmation_id)
        if pending is None:
            return {
                "ok": False,
                "status": "not_found",
                "reason": "not_found",
                "message": "This approval request is no longer available.",
            }
        if pending.status != "pending":
            return {
                "ok": False,
                "status": pending.status,
                "reason": f"already_{pending.status}",
                "message": f"This approval request is already {pending.status}.",
            }
        if pending.expires_at is not None and pending.expires_at <= datetime.now(UTC):
            return {
                "ok": False,
                "status": "expired",
                "reason": "approval_expired",
                "message": "This approval request has expired.",
            }
        if str(getattr(pending, "selected_backend_method", "")).strip() != "webauthn":
            return {
                "ok": False,
                "status": "invalid_method",
                "reason": "confirmation_method_not_allowed",
                "message": "This approval request is not waiting for WebAuthn confirmation.",
            }
        if not self._selected_backend_available_for_pending(pending):
            return {
                "ok": False,
                "status": "unavailable",
                "reason": "confirmation_backend_unavailable",
                "message": "This approval request cannot be completed with WebAuthn.",
            }
        try:
            public_key = self._webauthn_backend().approval_request_options(
                pending_action=pending,
            )
        except (ConfirmationVerificationError, RuntimeError) as exc:
            reason = (
                "confirmation_backend_unavailable" if isinstance(exc, RuntimeError) else exc.reason
            )
            return {
                "ok": False,
                "status": (
                    "unavailable"
                    if reason == "confirmation_backend_unavailable"
                    else "invalid_request"
                ),
                "reason": reason,
                "message": "This approval request cannot be completed with WebAuthn.",
            }
        public_pending = self._pending_to_dict(pending, public=True)
        return {
            "ok": True,
            "status": "pending",
            "summary": str(public_pending.get("safe_preview") or pending.reason),
            "public_key": public_key,
            "expires_at": (
                pending.expires_at.isoformat().replace("+00:00", "Z")
                if pending.expires_at is not None
                else None
            ),
            "confirmation_id": confirmation_id,
            "required_level": pending.required_level.value,
        }

    async def _complete_webauthn_approval_ceremony(
        self,
        confirmation_id: str,
        response_payload: dict[str, Any],
    ) -> dict[str, Any]:
        pending = self._pending_actions.get(confirmation_id)
        if pending is None:
            return {"confirmed": False, "reason": "not_found", "confirmation_id": confirmation_id}
        return await self.do_action_confirm(
            {
                "confirmation_id": confirmation_id,
                "decision_nonce": str(pending.decision_nonce),
                "approval_method": "webauthn",
                "proof": dict(response_payload),
            }
        )

    async def _send_chat_approval_link_notifications(
        self,
        *,
        confirmation_ids: list[str],
        delivery_target: Any,
    ) -> None:
        approval_web = getattr(self, "_approval_web", None)
        if approval_web is None or not approval_web.enabled:
            return
        for confirmation_id in confirmation_ids:
            pending = self._pending_actions.get(str(confirmation_id))
            if pending is None:
                continue
            if pending.required_level.priority < ConfirmationLevel.REAUTHENTICATED.priority:
                continue
            if str(getattr(pending, "selected_backend_method", "")).strip() != "webauthn":
                continue
            if not pending_action_is_live_pending(pending):
                continue
            if not self._selected_backend_available_for_pending(pending):
                continue
            approval_url = approval_web.issue_approval_link(str(pending.confirmation_id))
            if not approval_url:
                continue
            qr_ascii = approval_web.qr_ascii(approval_url)
            public_pending = self._pending_to_dict(pending, public=True)
            lines = [
                "Approval required",
                str(public_pending.get("safe_preview") or pending.reason),
                f"Level: {pending.required_level.value}",
                "Open this link in a system browser:",
                approval_url,
            ]
            if qr_ascii:
                lines.extend(["QR:", qr_ascii])
            await self._delivery.send(
                target=delivery_target,
                message="\n".join(lines).strip(),
            )

    async def do_two_factor_register_begin(self, params: Mapping[str, Any]) -> dict[str, Any]:
        self._prune_two_factor_enrollments()
        method = str(params.get("method") or "totp").strip().lower()
        if method not in {"totp", "webauthn", "local_fido2"}:
            return {"started": False, "reason": "unsupported_2fa_method"}
        user_id = str(params.get("user_id") or "").strip()
        if not user_id:
            raise ValueError("user_id is required")
        requested_name = str(params.get("name") or "").strip()
        principal_id = requested_name or getpass.getuser().strip() or user_id
        now = datetime.now(UTC)
        enrollment_id = uuid.uuid4().hex
        expires_at = now + timedelta(minutes=10)
        credential_id = f"{method}.{uuid.uuid4().hex[:12]}"

        if method == "totp":
            secret_b32 = generate_totp_secret()
            enrollment = PendingTwoFactorEnrollment(
                enrollment_id=enrollment_id,
                user_id=user_id,
                method=method,
                principal_id=principal_id,
                credential_id=credential_id,
                created_at=now,
                expires_at=expires_at,
                secret_b32=secret_b32,
            )
            self._pending_two_factor_enrollments[enrollment_id] = enrollment
            totp_backend = self._totp_backend()
            return {
                "started": True,
                "enrollment_id": enrollment_id,
                "user_id": user_id,
                "method": method,
                "principal_id": principal_id,
                "credential_id": credential_id,
                "secret": secret_b32,
                "otpauth_uri": totp_backend.enrollment_uri(
                    user_id=user_id,
                    principal_id=principal_id,
                    secret_b32=secret_b32,
                ),
                "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
            }

        if method == "webauthn":
            if not getattr(self, "_approval_web", None) or not self._approval_web.enabled:
                return {"started": False, "reason": "approval_origin_not_configured"}
            try:
                backend: WebAuthnBackend | LocalFido2Backend = self._webauthn_backend()
            except RuntimeError:
                return {"started": False, "reason": "approval_origin_not_configured"}
        else:
            try:
                backend = self._local_fido2_backend()
            except RuntimeError:
                return {"started": False, "reason": "local_helper_unavailable"}

        creation_options, registration_state = backend.registration_begin(
            user_id=user_id,
            principal_id=principal_id,
            credential_id=credential_id,
        )
        enrollment = PendingTwoFactorEnrollment(
            enrollment_id=enrollment_id,
            user_id=user_id,
            method=method,
            principal_id=principal_id,
            credential_id=credential_id,
            created_at=now,
            expires_at=expires_at,
            webauthn_creation_options=creation_options,
            webauthn_registration_state=registration_state,
            webauthn_rp_id=backend.rp_id,
            webauthn_origin=backend.approval_origin,
        )
        self._pending_two_factor_enrollments[enrollment_id] = enrollment
        payload = {
            "started": True,
            "enrollment_id": enrollment_id,
            "user_id": user_id,
            "method": method,
            "principal_id": principal_id,
            "credential_id": credential_id,
            "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        }
        if method == "webauthn":
            payload["registration_url"] = self._approval_web.issue_registration_link(enrollment_id)
            payload["approval_origin"] = backend.approval_origin
            payload["rp_id"] = backend.rp_id
        else:
            payload["helper_origin"] = backend.approval_origin
            payload["helper_rp_id"] = backend.rp_id
            payload["helper_public_key"] = creation_options
        return payload

    async def do_two_factor_register_confirm(self, params: Mapping[str, Any]) -> dict[str, Any]:
        now = datetime.now(UTC)
        self._prune_two_factor_enrollments(now=now)
        enrollment_id = str(params.get("enrollment_id") or "").strip()
        if not enrollment_id:
            raise ValueError("enrollment_id is required")
        enrollment = self._pending_two_factor_enrollments.get(enrollment_id)
        if not isinstance(enrollment, PendingTwoFactorEnrollment):
            return {"registered": False, "reason": "enrollment_not_found"}
        recovery_codes: list[str] = []
        if enrollment.method == "totp":
            verify_code = str(params.get("verify_code") or "").strip()
            if not verify_code:
                raise ValueError("verify_code is required")
            matched = match_totp_window(
                secret_b32=enrollment.secret_b32,
                code=verify_code,
                now=now,
            )
            if matched is None:
                return {"registered": False, "reason": "invalid_totp_code"}

            recovery_codes = generate_recovery_codes()
            factor = ApprovalFactorRecord(
                credential_id=enrollment.credential_id,
                user_id=enrollment.user_id,
                method=enrollment.method,
                principal_id=enrollment.principal_id,
                secret_b32=enrollment.secret_b32,
                created_at=enrollment.created_at,
                recovery_codes=[
                    RecoveryCodeRecord(code_hash=hash_recovery_code(code))
                    for code in recovery_codes
                ],
            )
        elif enrollment.method == "local_fido2":
            proof = params.get("proof")
            proof_payload = proof if isinstance(proof, dict) else None
            if not proof_payload:
                raise ValueError("proof is required")
            try:
                factor = self._local_fido2_backend().registration_complete(
                    credential_id=enrollment.credential_id,
                    user_id=enrollment.user_id,
                    principal_id=enrollment.principal_id,
                    created_at=enrollment.created_at,
                    state=dict(enrollment.webauthn_registration_state),
                    response_payload=proof_payload,
                )
            except (ConfirmationVerificationError, RuntimeError) as exc:
                reason = exc.reason if isinstance(exc, ConfirmationVerificationError) else str(exc)
                return {"registered": False, "reason": reason}
        else:
            return {"registered": False, "reason": "unsupported_2fa_method"}
        self._credential_store.register_approval_factor(factor)
        self._pending_two_factor_enrollments.pop(enrollment_id, None)
        await self._event_bus.publish(
            TwoFactorEnrolled(
                actor="control_plane",
                user_id=enrollment.user_id,
                method=enrollment.method,
                credential_id=enrollment.credential_id,
                principal_id=enrollment.principal_id,
            )
        )
        return {
            "registered": True,
            "user_id": enrollment.user_id,
            "method": enrollment.method,
            "principal_id": enrollment.principal_id,
            "credential_id": enrollment.credential_id,
            "recovery_codes": recovery_codes,
        }

    async def do_two_factor_list(self, params: Mapping[str, Any]) -> dict[str, Any]:
        user_id = str(params.get("user_id") or "").strip() or None
        method = str(params.get("method") or "").strip().lower() or None
        entries = self._credential_store.list_approval_factors(user_id=user_id, method=method)
        rows = [
            {
                "user_id": item.user_id,
                "method": item.method,
                "principal_id": item.principal_id,
                "credential_id": item.credential_id,
                "created_at": item.created_at.isoformat().replace("+00:00", "Z"),
                "last_verified_at": (
                    item.last_verified_at.isoformat().replace("+00:00", "Z")
                    if item.last_verified_at is not None
                    else None
                ),
                "last_used_at": (
                    item.last_used_at.isoformat().replace("+00:00", "Z")
                    if item.last_used_at is not None
                    else None
                ),
                "recovery_codes_remaining": sum(
                    1 for code in item.recovery_codes if code.consumed_at is None
                ),
            }
            for item in entries
        ]
        return {"entries": rows, "count": len(rows)}

    async def do_two_factor_revoke(self, params: Mapping[str, Any]) -> dict[str, Any]:
        user_id = str(params.get("user_id") or "").strip()
        if not user_id:
            raise ValueError("user_id is required")
        method = str(params.get("method") or "totp").strip().lower() or "totp"
        credential_id = str(params.get("credential_id") or "").strip() or None
        matched = [
            factor
            for factor in self._credential_store.list_approval_factors(
                user_id=user_id,
                method=method,
            )
            if credential_id is None or factor.credential_id == credential_id
        ]
        removed = self._credential_store.revoke_approval_factor(
            user_id=user_id,
            method=method,
            credential_id=credential_id,
        )
        if removed > 0:
            for factor in matched:
                await self._event_bus.publish(
                    TwoFactorRevoked(
                        actor="control_plane",
                        user_id=factor.user_id,
                        method=factor.method,
                        credential_id=factor.credential_id,
                        principal_id=factor.principal_id,
                    )
                )
        return {
            "revoked": removed > 0,
            "removed": removed,
            "reason": "" if removed > 0 else "not_found",
        }

    async def do_signer_register(self, params: Mapping[str, Any]) -> dict[str, Any]:
        backend = str(params.get("backend") or "kms").strip().lower()
        if backend not in {"kms", "ledger"}:
            return {"registered": False, "reason": "unsupported_signer_backend"}
        user_id = str(params.get("user_id") or "").strip()
        if not user_id:
            raise ValueError("user_id is required")
        key_id = str(params.get("key_id") or "").strip()
        if not key_id:
            raise ValueError("key_id is required")
        public_key_pem = str(params.get("public_key_pem") or "").strip()
        if not public_key_pem:
            raise ValueError("public_key_pem is required")
        principal_id = str(params.get("name") or "").strip() or getpass.getuser().strip() or user_id
        default_algorithm = "ecdsa-secp256k1" if backend == "ledger" else "ed25519"
        algorithm = (
            str(params.get("algorithm") or default_algorithm).strip().lower() or default_algorithm
        )
        if algorithm not in {"ed25519", "ecdsa-secp256k1"}:
            return {"registered": False, "reason": "unsupported_signer_algorithm"}
        if backend == "ledger" and algorithm != "ecdsa-secp256k1":
            return {"registered": False, "reason": "unsupported_ledger_signer_algorithm"}
        default_device_type = "ledger-consumer" if backend == "ledger" else "ledger-enterprise"
        device_type = (
            str(params.get("device_type") or default_device_type).strip() or default_device_type
        )
        default_signing_scheme = "eip712" if backend == "ledger" else "raw"
        signing_scheme = (
            str(params.get("signing_scheme") or default_signing_scheme).strip().lower()
            or default_signing_scheme
        )
        if signing_scheme not in {"raw", "eip712", "eth_personal_sign"}:
            return {"registered": False, "reason": "unsupported_signing_scheme"}
        if backend == "ledger" and signing_scheme != "eip712":
            return {"registered": False, "reason": "unsupported_ledger_signing_scheme"}
        public_key_error = _validate_signer_public_key(public_key_pem, algorithm=algorithm)
        if public_key_error:
            return {"registered": False, "reason": public_key_error}
        existing = self._credential_store.get_signer_key(key_id)
        if existing is not None:
            return {
                "registered": False,
                "reason": (
                    "signer_key_id_reused"
                    if existing.revoked_at is not None
                    else "signer_key_id_exists"
                ),
            }
        record = SignerKeyRecord(
            credential_id=key_id,
            user_id=user_id,
            backend=backend,
            principal_id=principal_id,
            algorithm=algorithm,
            device_type=device_type,
            public_key_pem=public_key_pem,
            signing_scheme=signing_scheme,
        )
        self._credential_store.register_signer_key(record)
        await self._event_bus.publish(
            SignerKeyRegistered(
                actor="control_plane",
                user_id=user_id,
                backend=backend,
                credential_id=key_id,
                principal_id=principal_id,
                algorithm=algorithm,
                device_type=device_type,
            )
        )
        return {
            "registered": True,
            "backend": backend,
            "user_id": user_id,
            "principal_id": principal_id,
            "credential_id": key_id,
            "algorithm": algorithm,
            "device_type": device_type,
            "reason": "",
        }

    async def do_signer_list(self, params: Mapping[str, Any]) -> dict[str, Any]:
        user_id = str(params.get("user_id") or "").strip() or None
        backend = str(params.get("backend") or "").strip().lower() or None
        include_revoked = bool(params.get("include_revoked", False))
        entries = self._credential_store.list_signer_keys(
            user_id=user_id,
            backend=backend,
            include_revoked=include_revoked,
        )
        rows = [
            {
                "user_id": item.user_id,
                "backend": item.backend,
                "principal_id": item.principal_id,
                "credential_id": item.credential_id,
                "algorithm": item.algorithm,
                "device_type": item.device_type,
                "created_at": item.created_at.isoformat().replace("+00:00", "Z"),
                "last_verified_at": (
                    item.last_verified_at.isoformat().replace("+00:00", "Z")
                    if item.last_verified_at is not None
                    else None
                ),
                "last_used_at": (
                    item.last_used_at.isoformat().replace("+00:00", "Z")
                    if item.last_used_at is not None
                    else None
                ),
                "revoked": item.revoked_at is not None,
            }
            for item in entries
        ]
        return {"entries": rows, "count": len(rows)}

    async def do_signer_revoke(self, params: Mapping[str, Any]) -> dict[str, Any]:
        key_id = str(params.get("key_id") or "").strip()
        if not key_id:
            raise ValueError("key_id is required")
        record = self._credential_store.get_signer_key(key_id)
        removed = self._credential_store.revoke_signer_key(credential_id=key_id)
        if removed > 0 and record is not None:
            await self._event_bus.publish(
                SignerKeyRevoked(
                    actor="control_plane",
                    user_id=record.user_id,
                    backend=record.backend,
                    credential_id=record.credential_id,
                    principal_id=record.principal_id,
                    algorithm=record.algorithm,
                    device_type=record.device_type,
                )
            )
        return {
            "revoked": removed > 0,
            "removed": removed,
            "reason": "" if removed > 0 else "not_found",
        }

    async def do_action_pending(self, params: Mapping[str, Any]) -> dict[str, Any]:
        confirmation_filter = str(params.get("confirmation_id") or "").strip()
        session_filter = str(params.get("session_id") or "").strip()
        status_filter = str(params.get("status") or "").strip().lower()
        limit = int(params.get("limit", 100))
        include_ui = bool(params.get("include_ui", True))

        if confirmation_filter:
            candidate = self._pending_actions.get(confirmation_filter)
            pending_items = [candidate] if candidate is not None else []
        else:
            pending_items = list(self._pending_actions.values())
            pending_items.sort(key=lambda item: item.created_at, reverse=True)
        rows: list[dict[str, Any]] = []
        for item in pending_items:
            if item is None:
                continue
            if session_filter and str(item.session_id) != session_filter:
                continue
            if (
                str(getattr(item, "status", "")).strip().lower() == "pending"
                and pending_action_state_view(item).lifecycle_state == "expired"
            ):
                self._mark_stale_pending_action(item, reason="approval_expired")
            state_view = pending_action_state_view(item)
            expected_lifecycle = "executed" if status_filter == "approved" else status_filter
            if (
                status_filter
                and status_filter != "all"
                and state_view.lifecycle_state != expected_lifecycle
            ):
                continue
            selected_backend_available = self._selected_backend_available_for_pending(item)
            payload = self._pending_to_dict(
                item,
                public=True,
                selected_backend_available=selected_backend_available,
            )
            if (
                getattr(self, "_approval_web", None) is not None
                and self._approval_web.enabled
                and str(getattr(item, "selected_backend_method", "")).strip() == "webauthn"
                and pending_action_is_live_pending(item)
                and selected_backend_available
            ):
                approval_url = self._approval_web.issue_approval_link(
                    str(getattr(item, "confirmation_id", ""))
                )
                if approval_url:
                    payload["approval_url"] = approval_url
                    payload["approval_qr_ascii"] = self._approval_web.qr_ascii(approval_url)
            elif (
                str(getattr(item, "selected_backend_method", "")).strip() == "local_fido2"
                and pending_action_is_live_pending(item)
                and selected_backend_available
            ):
                helper_context = self._local_fido2_approval_context(item)
                if helper_context.get("ok") is True:
                    payload["helper_origin"] = helper_context.get("origin")
                    payload["helper_rp_id"] = helper_context.get("rp_id")
                    payload["helper_public_key"] = helper_context.get("public_key")
            payload.pop("pep_context", None)
            if not include_ui:
                payload.pop("safe_preview", None)
                payload.pop("warnings", None)
                payload.pop("leak_check", None)
            rows.append(payload)
            if len(rows) >= limit:
                break
        result: dict[str, Any] = {"actions": rows, "count": len(rows)}
        result.update(self._pending_state_degradation_fields())
        return result

    async def do_action_purge(self, params: Mapping[str, Any]) -> dict[str, Any]:
        degradation = self._pending_state_degradation_fields()
        if degradation:
            raise StatePersistenceDegradedError(
                authority="pending_actions",
                transition=degradation["persistence_transition"],
                stage=degradation["persistence_stage"],
                reason=degradation["persistence_reason"],
            )
        session_filter = str(params.get("session_id") or "").strip()
        status_filter = str(params.get("status") or "terminal").strip().lower() or "terminal"
        older_than_days_raw = params.get("older_than_days")
        dry_run = bool(params.get("dry_run", False))
        limit = int(params.get("limit", 1000))
        if limit < 0:
            raise ValueError("limit must be non-negative")
        older_than_days: int | None = None
        if older_than_days_raw is not None:
            older_than_days = int(older_than_days_raw)
            if older_than_days < 0:
                raise ValueError("older_than_days must be non-negative")
        if status_filter not in {
            "terminal",
            "all",
            "pending",
            "approved",
            "executed",
            "failed",
            "rejected",
            "expired",
            "cancelled",
            "superseded",
            "outcome_unknown",
        }:
            raise ValueError(
                "status must be one of terminal, pending, approved, executed, failed, "
                "rejected, expired, cancelled, superseded, outcome_unknown, all"
            )
        if status_filter in {"pending", "all"} and (
            older_than_days is None or older_than_days <= 0
        ):
            raise ValueError("older_than_days must be positive when purging pending or all actions")

        cutoff = (
            datetime.now(UTC) - timedelta(days=older_than_days)
            if older_than_days is not None
            else None
        )
        candidates = sorted(
            self._pending_actions.values(),
            key=lambda item: item.created_at,
        )
        purge_ids: list[str] = []
        for item in candidates:
            if len(purge_ids) >= limit:
                break
            if not self._action_purge_item_matches(
                item,
                session_filter=session_filter,
                status_filter=status_filter,
                cutoff=cutoff,
            ):
                continue
            purge_ids.append(item.confirmation_id)

        if not dry_run and purge_ids:
            locks: list[tuple[str, asyncio.Lock]] = []
            try:
                for confirmation_id in sorted(set(purge_ids)):
                    lock = self._action_confirmation_lock(confirmation_id)
                    await lock.acquire()
                    locks.append((confirmation_id, lock))
                purge_items: list[Any] = []
                for confirmation_id in purge_ids:
                    item = self._pending_actions.get(confirmation_id)
                    if item is None:
                        continue
                    if not self._action_purge_item_matches(
                        item,
                        session_filter=session_filter,
                        status_filter=status_filter,
                        cutoff=cutoff,
                    ):
                        continue
                    purge_items.append(item)
                purge_ids = [item.confirmation_id for item in purge_items]
                if purge_items:
                    previous_actions = dict(self._pending_actions)
                    pending_by_session = getattr(self, "_pending_by_session", {})
                    previous_by_session = (
                        {
                            session_id: list(confirmation_ids)
                            for session_id, confirmation_ids in pending_by_session.items()
                        }
                        if isinstance(pending_by_session, dict)
                        else {}
                    )
                    previous_item_states = [
                        _capture_pending_attempt_snapshot(item) for item in purge_items
                    ]
                    purge_id_set = set(purge_ids)
                    pending_terminal_items: list[Any] = []
                    for item in purge_items:
                        item_status = str(getattr(item, "status", "")).strip().lower()
                        if item_status == "pending":
                            lifecycle_state = pending_action_state_view(item).lifecycle_state
                            self._mark_stale_pending_action(
                                item,
                                reason=(
                                    "approval_expired"
                                    if lifecycle_state == "expired"
                                    else _PURGED_STALE_PENDING_ACTION_REASON
                                ),
                                persist=False,
                            )
                            pending_terminal_items.append(item)
                    for confirmation_id in purge_ids:
                        self._pending_actions.pop(confirmation_id, None)
                    if isinstance(pending_by_session, dict):
                        for session_id, confirmation_ids in list(pending_by_session.items()):
                            remaining = [
                                confirmation_id
                                for confirmation_id in confirmation_ids
                                if confirmation_id not in purge_id_set
                            ]
                            if remaining:
                                pending_by_session[session_id] = remaining
                            else:
                                pending_by_session.pop(session_id, None)
                    purged_actions = dict(self._pending_actions)
                    purged_by_session = (
                        {
                            session_id: list(confirmation_ids)
                            for session_id, confirmation_ids in pending_by_session.items()
                        }
                        if isinstance(pending_by_session, dict)
                        else {}
                    )
                    purged_item_states = [
                        _capture_pending_attempt_snapshot(item) for item in purge_items
                    ]
                    try:
                        self._persist_pending_actions()
                    except AtomicWriteError as write_error:
                        self._pending_actions.clear()
                        self._pending_actions.update(previous_actions)
                        if isinstance(pending_by_session, dict):
                            pending_by_session.clear()
                            pending_by_session.update(previous_by_session)
                        for item, snapshot in zip(
                            purge_items,
                            previous_item_states,
                            strict=True,
                        ):
                            _restore_pending_attempt_snapshot(item, snapshot)
                        if write_error.publication_may_have_committed:
                            try:
                                self._persist_pending_actions()
                            except AtomicWriteError as rollback_error:
                                for item, snapshot in zip(
                                    purge_items,
                                    purged_item_states,
                                    strict=True,
                                ):
                                    _restore_pending_attempt_snapshot(item, snapshot)
                                self._pending_actions.clear()
                                self._pending_actions.update(purged_actions)
                                if isinstance(pending_by_session, dict):
                                    pending_by_session.clear()
                                    pending_by_session.update(purged_by_session)
                                self._pending_state_degradation = {
                                    "transition": "purge",
                                    "stage": rollback_error.stage.value,
                                    "reason": "pending_state_rollback_uncommitted",
                                }
                                raise rollback_error from write_error
                        raise
                    for item in purge_items:
                        self._sync_task_confirmation_status(item)
                    for item in pending_terminal_items:
                        self._record_task_confirmation_failure(item)
            finally:
                for confirmation_id, lock in reversed(locks):
                    if lock.locked():
                        lock.release()
                    self._discard_action_confirmation_lock_if_idle(confirmation_id, lock)

        return {
            "purged": len(purge_ids),
            "confirmation_ids": purge_ids,
            "remaining": len(self._pending_actions),
            "dry_run": dry_run,
        }

    def _action_purge_item_matches(
        self,
        item: Any,
        *,
        session_filter: str,
        status_filter: str,
        cutoff: datetime | None,
    ) -> bool:
        if session_filter and str(item.session_id) != session_filter:
            return False
        lifecycle_state = pending_action_state_view(item).lifecycle_state
        if status_filter == "terminal":
            if lifecycle_state in {"pending", "executing"}:
                return False
        elif status_filter != "all":
            canonical_filter = "executed" if status_filter == "approved" else status_filter
            if lifecycle_state != canonical_filter:
                return False
        return not (cutoff is not None and item.created_at > cutoff)

    async def do_action_confirm(self, params: Mapping[str, Any]) -> dict[str, Any]:
        batch_ids = params.get("confirmation_ids")
        if isinstance(batch_ids, list) and len(batch_ids) > 1:
            return {"confirmed": False, "reason": "batch_confirmation_not_allowed"}
        confirmation_id = str(params.get("confirmation_id", "")).strip()
        if not confirmation_id:
            raise ValueError("confirmation_id is required")
        degraded_response = self._pending_state_degraded_decision_response(
            confirmation_id=confirmation_id,
            decision_field="confirmed",
        )
        if degraded_response is not None:
            return degraded_response
        if self._pending_actions.get(confirmation_id) is None:
            return {"confirmed": False, "confirmation_id": confirmation_id, "reason": "not_found"}
        waited_for_short_cooldown = False
        while True:
            pending = self._pending_actions.get(confirmation_id)
            task_id = str(getattr(pending, "task_id", "")).strip()
            task_lock = self._task_lifecycle_lock(task_id) if task_id else None
            confirmation_lock = self._action_confirmation_lock(confirmation_id)
            task_lock_acquired = False
            confirmation_lock_acquired = False
            try:
                if task_lock is not None:
                    await task_lock.acquire()
                    task_lock_acquired = True
                await confirmation_lock.acquire()
                confirmation_lock_acquired = True
                result = await self._do_action_confirm_locked(
                    params,
                    confirmation_id=confirmation_id,
                    allow_short_cooldown_wait=not waited_for_short_cooldown,
                )
                deferred_cancel_reason = str(
                    result.pop(_CONFIRMATION_INTERNAL_TASK_CANCEL_REASON_KEY, "")
                ).strip()
                if deferred_cancel_reason and task_id:
                    confirmation_lock.release()
                    confirmation_lock_acquired = False
                    await self._cancel_pending_actions_for_task(
                        task_id,
                        reason=deferred_cancel_reason,
                    )
            finally:
                if confirmation_lock_acquired:
                    confirmation_lock.release()
                self._discard_action_confirmation_lock_if_idle(
                    confirmation_id,
                    confirmation_lock,
                )
                if task_lock is not None:
                    if task_lock_acquired:
                        task_lock.release()
                    self._discard_task_lifecycle_lock_if_idle(task_id, task_lock)
            wait_seconds_raw = result.pop(_CONFIRMATION_INTERNAL_SHORT_WAIT_KEY, None)
            if wait_seconds_raw is None:
                pending = self._pending_actions.get(confirmation_id)
                if pending is not None:
                    result.update(self._pending_action_response_identity_fields(pending))
                return result
            waited_for_short_cooldown = True
            wait_seconds = max(0.0, float(wait_seconds_raw))
            await asyncio.sleep(wait_seconds + _CONFIRMATION_COOLDOWN_WAKE_MARGIN_SECONDS)

    def _action_confirmation_lock(self, confirmation_id: str) -> asyncio.Lock:
        locks: dict[str, asyncio.Lock] | None = getattr(
            self,
            "_action_confirmation_locks",
            None,
        )
        if locks is None:
            locks = {}
            self._action_confirmation_locks = locks
        lock = locks.get(confirmation_id)
        if lock is None:
            lock = asyncio.Lock()
            locks[confirmation_id] = lock
        return lock

    def _discard_action_confirmation_lock_if_idle(
        self,
        confirmation_id: str,
        lock: asyncio.Lock,
    ) -> None:
        waiters = getattr(lock, "_waiters", None)
        has_waiters = bool(waiters)
        if lock.locked() or has_waiters:
            return
        locks: dict[str, asyncio.Lock] | None = getattr(
            self,
            "_action_confirmation_locks",
            None,
        )
        if locks is not None and locks.get(confirmation_id) is lock:
            locks.pop(confirmation_id, None)

    def _expired_action_decision_response(
        self,
        pending: Any,
        *,
        confirmation_id: str,
        decision_field: Literal["confirmed", "rejected"],
    ) -> dict[str, Any] | None:
        expires_at = getattr(pending, "expires_at", None)
        if expires_at is None or expires_at > datetime.now(UTC):
            return None
        self._mark_stale_pending_action(pending, reason="approval_expired")
        return {
            decision_field: False,
            "confirmation_id": confirmation_id,
            "reason": "approval_expired",
            "status": pending.status,
            "status_reason": pending.status_reason,
        }

    def _pending_action_decision_lifecycle_response(
        self,
        pending: Any | None,
        *,
        confirmation_id: str,
        decision_field: Literal["confirmed", "rejected"],
    ) -> dict[str, Any] | None:
        if pending is None:
            return {
                decision_field: False,
                "confirmation_id": confirmation_id,
                "reason": "not_found",
            }
        if pending.status != "pending":
            state_view = pending_action_state_view(pending)
            reason = (
                "approval_expired"
                if state_view.lifecycle_state == "expired"
                else f"already_{pending.status}"
            )
            return {
                decision_field: False,
                "confirmation_id": confirmation_id,
                "reason": reason,
                "status": pending.status,
                "status_reason": str(getattr(pending, "status_reason", "")),
                "lifecycle_state": state_view.lifecycle_state,
            }
        return self._expired_action_decision_response(
            pending,
            confirmation_id=confirmation_id,
            decision_field=decision_field,
        )

    async def _disabled_task_action_response(
        self,
        pending: Any,
        *,
        confirmation_id: str,
        decision_field: Literal["confirmed", "rejected"],
    ) -> dict[str, Any] | None:
        task_id = str(getattr(pending, "task_id", "")).strip()
        if not task_id:
            return None
        scheduler = getattr(self, "_scheduler", None)
        get_task = getattr(scheduler, "get_task", None)
        if not callable(get_task):
            return None
        task = get_task(task_id)
        if task is None or bool(getattr(task, "enabled", False)):
            return None
        await self._commit_and_publish_pending_terminal(
            pending,
            status="cancelled",
            status_reason="task_disabled",
            actor="scheduler",
            record_analytics=False,
            emit_hygiene_alert=False,
        )
        return {
            decision_field: False,
            "confirmation_id": confirmation_id,
            "reason": "task_disabled",
            "status": pending.status,
            "status_reason": pending.status_reason,
            "lifecycle_state": "cancelled",
        }

    def _confirmation_method_lockout_response(
        self,
        pending: Any,
        *,
        confirmation_id: str,
        confirmation_method: str,
    ) -> dict[str, Any] | None:
        retry_after = self._confirmation_failure_tracker.status(
            user_id=str(pending.user_id),
            method=confirmation_method,
        )
        if retry_after is None:
            return None
        self._mark_stale_pending_action(
            pending,
            reason="confirmation_method_locked_out",
        )
        return {
            "confirmed": False,
            "confirmation_id": confirmation_id,
            "reason": "confirmation_method_locked_out",
            "retry_after_seconds": round(retry_after, 3),
            "status": pending.status,
            "status_reason": pending.status_reason,
        }

    def _scheduler_control_confirmation_principal(
        self,
        pending: Any,
        params: Mapping[str, Any],
        session: Any,
    ) -> str:
        if str(params.get("principal_id", "")).strip():
            return ""
        if str(getattr(session, "channel", "")).strip().lower() != "scheduler":
            return ""
        allowed_channel_principals = [
            str(item).strip()
            for item in getattr(pending, "allowed_channel_principals", ())
            if str(item).strip()
        ]
        if len(allowed_channel_principals) != 1:
            return ""
        pending_user_id = str(getattr(pending, "user_id", "")).strip()
        if pending_user_id != allowed_channel_principals[0]:
            return ""
        return pending_user_id

    async def _do_action_confirm_locked(
        self,
        params: Mapping[str, Any],
        *,
        confirmation_id: str,
        allow_short_cooldown_wait: bool,
    ) -> dict[str, Any]:
        pending = self._pending_actions.get(confirmation_id)
        lifecycle_response = self._pending_action_decision_lifecycle_response(
            pending,
            confirmation_id=confirmation_id,
            decision_field="confirmed",
        )
        if lifecycle_response is not None:
            return lifecycle_response
        assert pending is not None
        pre_decision_attempt = _capture_pending_attempt_snapshot(pending)
        disabled_task_response = await self._disabled_task_action_response(
            pending,
            confirmation_id=confirmation_id,
            decision_field="confirmed",
        )
        if disabled_task_response is not None:
            return disabled_task_response
        confirmation_method = (
            str(getattr(pending, "selected_backend_method", "") or "software").strip() or "software"
        )
        lockout = self._confirmation_method_lockout_response(
            pending,
            confirmation_id=confirmation_id,
            confirmation_method=confirmation_method,
        )
        if lockout is not None:
            return lockout
        raw_nonce = params.get("decision_nonce", "")
        provided_nonce = raw_nonce.strip() if isinstance(raw_nonce, str) else ""
        if not provided_nonce:
            return {
                "confirmed": False,
                "confirmation_id": confirmation_id,
                "reason": "missing_decision_nonce",
            }
        if not safe_compare_text(provided_nonce, pending.decision_nonce):
            self._confirmation_failure_tracker.record_failure(
                user_id=str(pending.user_id),
                method=confirmation_method,
            )
            return {
                "confirmed": False,
                "confirmation_id": confirmation_id,
                "reason": "invalid_decision_nonce",
            }
        stale_reason = self._pending_approval_stale_reason(pending)
        if stale_reason:
            self._mark_stale_pending_action(pending, reason=stale_reason)
            return {
                "confirmed": False,
                "confirmation_id": confirmation_id,
                "reason": stale_reason,
                "status": pending.status,
                "status_reason": pending.status_reason,
            }
        if pending.execute_after is not None:
            remaining = (pending.execute_after - datetime.now(UTC)).total_seconds()
            if remaining > 0:
                if (
                    allow_short_cooldown_wait
                    and remaining <= _CONFIRMATION_SHORT_COOLDOWN_WAIT_MAX_SECONDS
                ):
                    return {_CONFIRMATION_INTERNAL_SHORT_WAIT_KEY: remaining}
                if remaining > 0:
                    return {
                        "confirmed": False,
                        "confirmation_id": confirmation_id,
                        "reason": "cooldown_active",
                        "retry_after_seconds": round(remaining, 3),
                    }
        if self._lockdown_manager.should_block_all_actions(pending.session_id):
            await self._commit_and_publish_pending_terminal(
                pending,
                status="rejected",
                status_reason="session_in_lockdown",
                rollback_snapshot=pre_decision_attempt,
            )
            return {
                "confirmed": False,
                "confirmation_id": confirmation_id,
                "reason": "session_in_lockdown",
            }

        session = self._session_manager.get(pending.session_id)
        if session is None:
            await self._commit_and_publish_pending_terminal(
                pending,
                status="failed",
                status_reason="session_missing",
                rollback_snapshot=pre_decision_attempt,
            )
            return {
                "confirmed": False,
                "confirmation_id": confirmation_id,
                "reason": "session_missing",
            }

        params = dict(params)
        scheduler_principal = self._scheduler_control_confirmation_principal(
            pending,
            params,
            session,
        )
        if scheduler_principal:
            params["principal_id"] = scheduler_principal

        backend = self._confirmation_backend_registry.get_backend(
            str(getattr(pending, "selected_backend_id", "")).strip() or "software.default"
        )
        if backend is None:
            await self._commit_and_publish_pending_terminal(
                pending,
                status="failed",
                status_reason="confirmation_backend_unavailable",
                record_analytics=False,
                emit_hygiene_alert=False,
                rollback_snapshot=pre_decision_attempt,
            )
            return {
                "confirmed": False,
                "confirmation_id": confirmation_id,
                "reason": "confirmation_backend_unavailable",
                "status": pending.status,
                "status_reason": pending.status_reason,
            }

        requirement = self._pending_confirmation_requirement(pending)
        requested_method = self._requested_confirmation_method(params=params, pending=pending)
        if requirement.methods and requested_method not in requirement.methods:
            self._confirmation_failure_tracker.record_failure(
                user_id=str(pending.user_id),
                method=confirmation_method,
            )
            return {
                "confirmed": False,
                "confirmation_id": confirmation_id,
                "reason": "confirmation_method_not_allowed",
            }

        try:
            if isinstance(backend, SignerConfirmationAdapter):
                evidence = await asyncio.to_thread(
                    backend.verify,
                    pending_action=pending,
                    params=dict(params),
                )
            else:
                evidence = backend.verify(
                    pending_action=pending,
                    params=dict(params),
                )
        except ConfirmationVerificationError as exc:
            reason = str(exc.reason)
            if reason in _STALE_PENDING_APPROVAL_REASONS:
                self._mark_stale_pending_action(pending, reason=reason)
                return {
                    "confirmed": False,
                    "confirmation_id": confirmation_id,
                    "reason": reason,
                    "status": pending.status,
                    "status_reason": pending.status_reason,
                }
            self._confirmation_failure_tracker.record_failure(
                user_id=str(pending.user_id),
                method=confirmation_method,
            )
            retry_after = self._confirmation_failure_tracker.status(
                user_id=str(pending.user_id),
                method=confirmation_method,
            )
            response: dict[str, Any] = {
                "confirmed": False,
                "confirmation_id": confirmation_id,
                "reason": reason,
            }
            if retry_after is not None:
                response["retry_after_seconds"] = round(retry_after, 3)
            return response
        validated_evidence = ConfirmationEvidence.model_validate(
            evidence.model_dump(mode="json")
            if isinstance(evidence, ConfirmationEvidence)
            else evidence
        )
        if not confirmation_evidence_satisfies_requirement(
            requirement=requirement,
            evidence=validated_evidence,
            backend=backend,
        ):
            pending.confirmation_evidence = None
            self._confirmation_failure_tracker.record_failure(
                user_id=str(pending.user_id),
                method=confirmation_method,
            )
            return {
                "confirmed": False,
                "confirmation_id": confirmation_id,
                "reason": "confirmation_requirement_unsatisfied",
            }
        if not confirmation_evidence_is_canonical(
            evidence=validated_evidence,
            backend=backend,
            confirmation_id=str(pending.confirmation_id),
        ) or not confirmation_evidence_has_backend_proof(
            pending_action=pending,
            evidence=validated_evidence,
            backend=backend,
        ):
            pending.confirmation_evidence = None
            self._confirmation_failure_tracker.record_failure(
                user_id=str(pending.user_id),
                method=confirmation_method,
            )
            return {
                "confirmed": False,
                "confirmation_id": confirmation_id,
                "reason": "approval_contract_mismatch",
            }
        validated_evidence = self._confirmation_evidence_authenticator.stamp(
            validated_evidence
        )
        pending.confirmation_evidence = validated_evidence
        evidence_binding_reason = self._pending_approval_contract_invalid_reason(
            pending,
            require_evidence=True,
        )
        if evidence_binding_reason:
            pending.confirmation_evidence = None
            self._confirmation_failure_tracker.record_failure(
                user_id=str(pending.user_id),
                method=confirmation_method,
            )
            return {
                "confirmed": False,
                "confirmation_id": confirmation_id,
                "reason": evidence_binding_reason,
            }
        self._confirmation_failure_tracker.record_success(
            user_id=str(pending.user_id),
            method=confirmation_method,
        )

        pending_preflight_action = pending.preflight_action
        stage2_reason = "stage2_upgrade_required" in pending.reason
        stage2_action: Any | None = None
        stage2_previous_hash = ""
        if stage2_reason:
            if not bool(self._policy_loader.policy.control_plane.trace.allow_amendment):
                await self._commit_and_publish_pending_terminal(
                    pending,
                    status="rejected",
                    status_reason="plan_amendment_disabled",
                    rollback_snapshot=pre_decision_attempt,
                )
                return {
                    "confirmed": False,
                    "confirmation_id": confirmation_id,
                    "reason": "plan_amendment_disabled",
                }
            fallback_risk_tier = (
                pending_preflight_action.risk_tier
                if pending_preflight_action is not None
                else RiskTier.LOW
            )
            stage2_action = pending_preflight_action or build_action(
                tool_name=str(pending.tool_name),
                arguments=dict(pending.arguments),
                origin=self._origin_for(session=session, actor="human_confirmation"),
                risk_tier=fallback_risk_tier,
                workspace_roots=list(
                    getattr(getattr(self, "_config", None), "assistant_fs_roots", [Path.cwd()])
                ),
            )
            stage2_previous_hash = await _call_control_plane(
                self,
                "active_plan_hash",
                str(pending.session_id),
            )

        execution_capabilities = set(pending.capabilities)
        pep_elevation = getattr(pending, "pep_elevation", None)
        if pep_elevation is not None:
            # Human approval authorizes a scoped retry; it does not directly
            # execute an action that the original PEP evaluation rejected.
            pep_context = getattr(pending, "pep_context", None)
            if pep_context is None:
                await self._commit_and_publish_pending_terminal(
                    pending,
                    status="failed",
                    status_reason="pep_elevation_context_missing",
                    rollback_snapshot=pre_decision_attempt,
                )
                return {
                    "confirmed": False,
                    "confirmation_id": confirmation_id,
                    "reason": "pep_elevation_context_missing",
                    "status": pending.status,
                    "status_reason": pending.status_reason,
                }
            policy_context = build_policy_context_for_pending_action(
                session=session,
                pending_session_id=pending.session_id,
                pending_workspace_id=pending.workspace_id,
                pending_user_id=pending.user_id,
                snapshot=pep_context,
                elevation=pep_elevation,
            )
            pep_decision = self._pep.evaluate(
                pending.tool_name,
                pep_arguments_for_policy_evaluation(pending.tool_name, pending.arguments),
                policy_context,
            )
            execution_capabilities = set(policy_context.capabilities)
            if pep_decision.kind.value == "reject":
                status_reason = (
                    pep_decision.reason_code.strip() or "pep_reject_after_confirmation"
                )
                await self._commit_and_publish_pending_terminal(
                    pending,
                    status="rejected",
                    status_reason=status_reason,
                    event_reason=pep_decision.reason or status_reason,
                    rollback_snapshot=pre_decision_attempt,
                )
                return {
                    "confirmed": False,
                    "confirmation_id": confirmation_id,
                    "decision_nonce": pending.decision_nonce,
                    "status": pending.status,
                    "status_reason": pending.status_reason,
                    "reason": pending.status_reason,
                }
            if pep_decision.kind.value == "require_confirmation":
                payload = pep_decision.confirmation_requirement
                terminal_status = ""
                terminal_reason = ""
                if not isinstance(payload, Mapping):
                    terminal_status = "failed"
                    terminal_reason = "confirmation_requirement_missing_after_confirmation"
                else:
                    requirement = ConfirmationRequirement.model_validate(payload)
                    backend = self._confirmation_backend_registry.get_backend(
                        str(getattr(pending, "selected_backend_id", "")).strip()
                        or "software.default"
                    )
                    if (
                        pending.confirmation_evidence is None
                        or backend is None
                        or not confirmation_evidence_satisfies_requirement(
                            requirement=requirement,
                            evidence=pending.confirmation_evidence,
                            backend=backend,
                        )
                    ):
                        terminal_status = "rejected"
                        terminal_reason = (
                            "confirmation_requirement_unsatisfied_after_confirmation"
                        )
                if terminal_status:
                    await self._commit_and_publish_pending_terminal(
                        pending,
                        status=terminal_status,
                        status_reason=terminal_reason,
                        event_reason=pep_decision.reason or terminal_reason,
                        rollback_snapshot=pre_decision_attempt,
                    )
                    return {
                        "confirmed": False,
                        "confirmation_id": confirmation_id,
                        "decision_nonce": pending.decision_nonce,
                        "status": pending.status,
                        "status_reason": pending.status_reason,
                        "reason": pending.status_reason,
                    }

        lifecycle_response = self._pending_action_decision_lifecycle_response(
            pending,
            confirmation_id=confirmation_id,
            decision_field="confirmed",
        )
        if lifecycle_response is not None:
            return lifecycle_response

        decision_timestamp = datetime.now(UTC).isoformat()
        decision_at = datetime.fromisoformat(decision_timestamp)
        if not str(getattr(pending, "action_digest", "")).strip():
            approval_envelope = getattr(pending, "approval_envelope", None)
            pending.action_digest = str(
                getattr(approval_envelope, "action_digest", "")
            ).strip()
        pending.approval_evidence_hash = str(
            getattr(pending.confirmation_evidence, "evidence_hash", "")
        ).strip()
        if not str(getattr(pending, "execution_attempt_id", "")).strip():
            pending.execution_attempt_id = f"attempt-{uuid.uuid4().hex}"
        if not str(getattr(pending, "result_id", "")).strip():
            pending.result_id = f"result-{uuid.uuid4().hex}"
        if stage2_action is not None:
            pending.stage2_correlation_id = (
                f"{pending.confirmation_id}:{pending.execution_attempt_id}"
            )
            pending.stage2_previous_plan_hash = stage2_previous_hash
            pending.stage2_plan_hash = ""
        action_identity = pending_action_state_view(pending).identity
        promote_ref_id = str(pending.arguments.get("ref_id", "")).strip()
        pending.status = "executing"
        pending.status_reason = (
            "stage2_amendment_pending"
            if stage2_action is not None
            else "confirmation_execution_started"
        )
        executing_attempt = _capture_pending_attempt_snapshot(pending)
        try:
            self._persist_pending_actions()
        except AtomicWriteError as write_error:
            _restore_pending_attempt_snapshot(pending, pre_decision_attempt)
            if write_error.publication_may_have_committed:
                try:
                    self._persist_pending_actions()
                except AtomicWriteError as rollback_error:
                    _restore_pending_attempt_snapshot(pending, executing_attempt)
                    self._pending_state_degradation = {
                        "transition": "executing",
                        "stage": rollback_error.stage.value,
                        "reason": "pending_state_rollback_uncommitted",
                    }
                    raise rollback_error from write_error
            raise
        self._sync_task_confirmation_status(pending)
        if stage2_action is not None:
            try:
                plan_hash = await _call_control_plane(
                    self,
                    "approve_stage2",
                    action=stage2_action,
                    approved_by="human_confirmation",
                    correlation_id=pending.stage2_correlation_id,
                    expected_previous_hash=pending.stage2_previous_plan_hash,
                )
            except ControlPlaneRpcError as exc:
                reason = _confirmation_control_plane_reason(exc)
                if reason == "control_plane_unavailable":
                    await self._cancel_stage2_authority(
                        pending,
                        reason="stage2_approval_response_uncertain",
                    )
                await self._commit_and_publish_pending_terminal(
                    pending,
                    status="failed",
                    status_reason=reason,
                )
                return {
                    "confirmed": False,
                    "confirmation_id": confirmation_id,
                    "reason": reason,
                    "status": pending.status,
                    "status_reason": pending.status_reason,
                }
            pending.stage2_plan_hash = plan_hash
            try:
                await self._event_bus.publish(
                    PlanAmended(
                        session_id=pending.session_id,
                        actor="human_confirmation",
                        plan_hash=plan_hash,
                        amendment_of=stage2_previous_hash,
                        stage="stage2_postevidence",
                    )
                )
                stage2_pending_attempt = _capture_pending_attempt_snapshot(pending)
                pending.status_reason = "confirmation_execution_started"
                stage2_ready_attempt = _capture_pending_attempt_snapshot(pending)
                try:
                    self._persist_pending_actions()
                except AtomicWriteError as write_error:
                    _restore_pending_attempt_snapshot(pending, stage2_pending_attempt)
                    if write_error.publication_may_have_committed:
                        try:
                            self._persist_pending_actions()
                        except AtomicWriteError as rollback_error:
                            _restore_pending_attempt_snapshot(pending, stage2_ready_attempt)
                            self._pending_state_degradation = {
                                "transition": "stage2_ready",
                                "stage": rollback_error.stage.value,
                                "reason": "pending_state_rollback_uncommitted",
                            }
                            raise rollback_error from write_error
                    raise
            except Exception:
                await self._cancel_stage2_authority(
                    pending,
                    reason="stage2_ready_transition_failed",
                )
                raise
            self._sync_task_confirmation_status(pending)
        execution_result = await self._execute_approved_action(
            sid=pending.session_id,
            user_id=pending.user_id,
            tool_name=pending.tool_name,
            arguments=pending.arguments,
            capabilities=execution_capabilities,
            approval_actor="human_confirmation",
            execution_action=pending_preflight_action,
            merged_policy=pending.merged_policy,
            user_confirmed=True,
            action_id=action_identity.action_id,
            origin_turn_id=action_identity.origin_turn_id,
            execution_attempt_id=action_identity.execution_attempt_id,
            result_id=action_identity.result_id,
            followup_id=action_identity.followup_id,
            workspace_id=pending.workspace_id,
            task_id=action_identity.task_id,
            delivery_target=pending.delivery_target,
            approval_confirmation_id=str(pending.confirmation_id),
            approval_decision_nonce=str(pending.decision_nonce),
            approval_task_envelope_id=str(
                getattr(pending, "approval_task_envelope_id", "")
            ).strip(),
            approval_timestamp=decision_timestamp,
            approval_evidence=pending.confirmation_evidence,
            strip_direct_tool_execute_envelope_keys=bool(
                pending.should_strip_direct_tool_execute_envelope_keys()
            ),
        )
        pending.provider_operation_id = str(
            getattr(execution_result, "provider_operation_id", "")
        ).strip()
        success = execution_result.success
        outcome_unknown = bool(getattr(execution_result, "outcome_unknown", False))
        checkpoint_id = execution_result.checkpoint_id
        tool_output = getattr(execution_result, "tool_output", None)
        pending_tool_name = canonical_tool_name(str(pending.tool_name), warn_on_alias=False)
        serialized_tool_outputs = (
            [_serialize_confirmed_tool_output(tool_output)] if tool_output is not None else []
        )
        if serialized_tool_outputs:
            serialized_tool_outputs[0]["action_identity"] = action_identity.to_payload()
        if serialized_tool_outputs and not serialized_tool_outputs[0].get("arguments"):
            safe_arguments = _safe_confirmed_tool_output_arguments(
                tool_name=pending_tool_name,
                arguments=pending.arguments,
            )
            if safe_arguments:
                serialized_tool_outputs[0]["arguments"] = safe_arguments
        if tool_output is not None:
            self._append_confirmed_tool_output_transcript(
                pending=pending,
                tool_output=tool_output,
                decision_timestamp=decision_timestamp,
            )
        promote_followup_reason = ""
        if success and tool_output is not None and pending_tool_name == "evidence.promote":
            try:
                payload = json.loads(str(getattr(tool_output, "content", "")))
            except json.JSONDecodeError:
                payload = {}
            content = str(payload.get("content", ""))
            ref_id = str(payload.get("ref_id", "")).strip()
            target_ref_id = promote_ref_id or ref_id
            store = getattr(self, "_evidence_store", None)
            transcript_entries_before = 0
            transcript_appended = False
            try:
                transcript_entries_before = len(
                    self._transcript_store.list_entries(pending.session_id)
                )
                if not content.strip():
                    raise ValueError("promoted evidence content is empty")
                metadata = {
                    "channel": str(session.channel),
                    "timestamp_utc": datetime.now(UTC).isoformat(),
                    "session_mode": session.mode.value,
                    "user_id": str(pending.user_id),
                    "workspace_id": str(pending.workspace_id),
                    "promoted_evidence": True,
                    "promoted_ref_id": target_ref_id,
                    "action_identity": action_identity.to_payload(),
                }
                _apply_delivery_target_metadata(metadata, getattr(pending, "delivery_target", None))
                self._transcript_store.append(
                    pending.session_id,
                    role="assistant",
                    content=content,
                    taint_labels=set(getattr(tool_output, "taint_labels", set()))
                    or {TaintLabel.USER_REVIEWED},
                    metadata=metadata,
                    evidence_ref_id=target_ref_id or None,
                )
                transcript_appended = True
                if not target_ref_id or store is None:
                    raise ValueError("missing evidence ref for endorsement")
                endorsed = store.endorse(
                    pending.session_id,
                    target_ref_id,
                    endorsement_state=ArtifactEndorsementState.USER_ENDORSED,
                    actor="human_confirmation",
                    endorsed_at=decision_at,
                )
                if endorsed is None:
                    raise ValueError("missing evidence ref for endorsement")
            except (OSError, RuntimeError, TypeError, ValueError):
                if transcript_appended:
                    try:
                        self._transcript_store.truncate(
                            pending.session_id,
                            keep_entries=transcript_entries_before,
                        )
                    except OSError:
                        logger.warning(
                            (
                                "Failed to roll back promoted transcript entry after "
                                "endorsement failure for session %s"
                            ),
                            pending.session_id,
                            exc_info=True,
                        )
                success = False
                promote_followup_reason = "artifact_endorse_failed"
                await self._event_bus.publish(
                    ToolRejected(
                        session_id=pending.session_id,
                        actor="human_confirmation",
                        tool_name=pending.tool_name,
                        reason=promote_followup_reason,
                        **self._pending_approval_event_fields(
                            pending,
                            decision_timestamp=decision_timestamp,
                        ),
                    )
                )
        if success:
            pending.status = "approved"
        elif outcome_unknown:
            pending.status = "outcome_unknown"
        else:
            pending.status = "failed"
        execution_failure_reason = (
            ""
            if success
            else (
                _confirmed_execution_failure_reason(tool_output)
                or str(getattr(execution_result, "error", "")).strip()
            )
        )
        pending.status_reason = (
            "idempotent_adapter_outcome_unknown"
            if outcome_unknown
            else promote_followup_reason
            or execution_failure_reason
            or str(params.get("reason", "")).strip()
            or pending.status
        )
        if outcome_unknown:
            pending.decision_nonce = ""
        pending_task_id = str(getattr(pending, "task_id", "")).strip()
        pending.scheduler_accounting_pending = bool(pending_task_id)
        try:
            self._persist_pending_actions()
            self._sync_task_confirmation_status(pending)
            task_cancel_reason = (
                await self._complete_confirmation_scheduler_accounting(
                    pending,
                    success=success,
                    outcome_unknown=outcome_unknown,
                )
                if pending_task_id
                else ""
            )
        except Exception:
            if pending_task_id:
                self._contain_confirmation_scheduler_attempt(pending_task_id)
            raise
        self._confirmation_analytics.record(
            user_id=str(pending.user_id),
            decision="approve" if success or outcome_unknown else "reject",
            created_at=pending.created_at,
        )
        await self._maybe_emit_confirmation_hygiene_alert(
            user_id=str(pending.user_id),
            session_id=pending.session_id,
        )
        response = {
            "confirmed": success,
            "confirmation_id": confirmation_id,
            "decision_nonce": pending.decision_nonce,
            "status": pending.status,
            "status_reason": pending.status_reason,
            "checkpoint_id": checkpoint_id,
            "approval_level": (
                pending.confirmation_evidence.level.value
                if pending.confirmation_evidence is not None
                else None
            ),
            "approval_method": (
                pending.confirmation_evidence.method
                if pending.confirmation_evidence is not None
                else None
            ),
            "tool_outputs": serialized_tool_outputs,
            "continuation_user_goal": str(getattr(pending, "continuation_user_goal", "")).strip(),
            "continuation_mode": str(getattr(pending, "continuation_mode", "")).strip(),
        }
        if task_cancel_reason == "max_runs_reached":
            response[_CONFIRMATION_INTERNAL_TASK_CANCEL_REASON_KEY] = "max_runs_reached"
        elif task_cancel_reason == "outcome_unknown":
            response[_CONFIRMATION_INTERNAL_TASK_CANCEL_REASON_KEY] = "outcome_unknown"
        return response

    async def do_action_reject(self, params: Mapping[str, Any]) -> dict[str, Any]:
        confirmation_id = str(params.get("confirmation_id", "")).strip()
        if not confirmation_id:
            raise ValueError("confirmation_id is required")
        degraded_response = self._pending_state_degraded_decision_response(
            confirmation_id=confirmation_id,
            decision_field="rejected",
        )
        if degraded_response is not None:
            return degraded_response
        pending = self._pending_actions.get(confirmation_id)
        if pending is None:
            return {"rejected": False, "confirmation_id": confirmation_id, "reason": "not_found"}
        task_id = str(getattr(pending, "task_id", "")).strip()
        task_lock = self._task_lifecycle_lock(task_id) if task_id else None
        confirmation_lock = self._action_confirmation_lock(confirmation_id)
        task_lock_acquired = False
        confirmation_lock_acquired = False
        try:
            if task_lock is not None:
                await task_lock.acquire()
                task_lock_acquired = True
            await confirmation_lock.acquire()
            confirmation_lock_acquired = True
            result = await self._do_action_reject_locked(
                params,
                confirmation_id=confirmation_id,
            )
            pending = self._pending_actions.get(confirmation_id)
            if pending is not None:
                result.update(self._pending_action_response_identity_fields(pending))
            return result
        finally:
            if confirmation_lock_acquired:
                confirmation_lock.release()
            self._discard_action_confirmation_lock_if_idle(
                confirmation_id,
                confirmation_lock,
            )
            if task_lock is not None:
                if task_lock_acquired:
                    task_lock.release()
                self._discard_task_lifecycle_lock_if_idle(task_id, task_lock)

    async def _do_action_reject_locked(
        self,
        params: Mapping[str, Any],
        *,
        confirmation_id: str,
    ) -> dict[str, Any]:
        reason = str(params.get("reason", "manual_reject")).strip() or "manual_reject"
        pending = self._pending_actions.get(confirmation_id)
        lifecycle_response = self._pending_action_decision_lifecycle_response(
            pending,
            confirmation_id=confirmation_id,
            decision_field="rejected",
        )
        if lifecycle_response is not None:
            return lifecycle_response
        assert pending is not None
        disabled_task_response = await self._disabled_task_action_response(
            pending,
            confirmation_id=confirmation_id,
            decision_field="rejected",
        )
        if disabled_task_response is not None:
            return disabled_task_response
        raw_nonce = params.get("decision_nonce", "")
        provided_nonce = raw_nonce.strip() if isinstance(raw_nonce, str) else ""
        if not provided_nonce:
            return {
                "rejected": False,
                "confirmation_id": confirmation_id,
                "reason": "missing_decision_nonce",
            }
        if not safe_compare_text(provided_nonce, pending.decision_nonce):
            return {
                "rejected": False,
                "confirmation_id": confirmation_id,
                "reason": "invalid_decision_nonce",
            }
        channel_principal_reason = _channel_principal_rejection_reason(pending, params)
        if channel_principal_reason:
            return {
                "rejected": False,
                "confirmation_id": confirmation_id,
                "reason": channel_principal_reason,
            }
        await self._commit_and_publish_pending_terminal(
            pending,
            status="rejected",
            status_reason=reason,
        )
        return {
            "rejected": True,
            "confirmation_id": confirmation_id,
            "status": pending.status,
            "status_reason": reason,
        }
