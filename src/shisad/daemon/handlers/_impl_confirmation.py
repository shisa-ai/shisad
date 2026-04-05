"""Action confirmation handler implementations."""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from shisad.core.approval import (
    ConfirmationEvidence,
    ConfirmationVerificationError,
    approval_audit_fields,
)
from shisad.core.events import PlanAmended, ToolRejected
from shisad.core.evidence import ArtifactEndorsementState
from shisad.core.types import TaintLabel
from shisad.daemon.handlers._mixin_typing import (
    HandlerMixinBase,
)
from shisad.daemon.handlers._mixin_typing import (
    call_control_plane as _call_control_plane,
)
from shisad.daemon.handlers._pending_approval import (
    build_policy_context_for_pending_action,
    pep_arguments_for_policy_evaluation,
)
from shisad.security.control_plane.schema import RiskTier, build_action
from shisad.security.control_plane.sidecar import ControlPlaneRpcError

logger = logging.getLogger(__name__)


def _confirmation_control_plane_reason(exc: ControlPlaneRpcError) -> str:
    message = str(exc.message).strip().lower()
    if exc.reason_code == "rpc.invalid_params" and "inactive plan" in message:
        return "plan_missing_or_inactive"
    if exc.reason_code == "rpc.permission_denied":
        return "control_plane_permission_denied"
    return "control_plane_rejected"


class ConfirmationImplMixin(HandlerMixinBase):
    @staticmethod
    def _pending_approval_event_fields(
        pending: Any,
        *,
        decision_timestamp: str,
    ) -> dict[str, Any]:
        fields = {
            "approval_session_id": str(getattr(pending, "session_id", "")),
            "approval_task_envelope_id": str(
                getattr(pending, "approval_task_envelope_id", "")
            ).strip(),
            "approval_confirmation_id": str(getattr(pending, "confirmation_id", "")),
            "approval_decision_nonce": str(getattr(pending, "decision_nonce", "")),
            "approval_timestamp": decision_timestamp,
        }
        fields.update(
            approval_audit_fields(getattr(pending, "confirmation_evidence", None))
        )
        return fields

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
        resolve_confirmation(
            task_id,
            confirmation_id=str(getattr(pending, "confirmation_id", "")),
            status=str(getattr(pending, "status", "")),
            status_reason=str(getattr(pending, "status_reason", "")),
        )

    def _record_task_confirmation_outcome(self, pending: Any, *, success: bool) -> None:
        task_id = str(getattr(pending, "task_id", "")).strip()
        if not task_id:
            return
        scheduler = getattr(self, "_scheduler", None)
        if scheduler is None:
            return
        recorder = getattr(scheduler, "record_run_outcome", None)
        if callable(recorder):
            recorder(task_id, success=success)

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
            if status_filter and item.status.lower() != status_filter:
                continue
            payload = self._pending_to_dict(item)
            payload.pop("pep_context", None)
            if not include_ui:
                payload.pop("safe_preview", None)
                payload.pop("warnings", None)
                payload.pop("leak_check", None)
            rows.append(payload)
            if len(rows) >= limit:
                break
        return {"actions": rows, "count": len(rows)}

    async def do_action_confirm(self, params: Mapping[str, Any]) -> dict[str, Any]:
        batch_ids = params.get("confirmation_ids")
        if isinstance(batch_ids, list) and len(batch_ids) > 1:
            return {"confirmed": False, "reason": "batch_confirmation_not_allowed"}
        confirmation_id = str(params.get("confirmation_id", "")).strip()
        if not confirmation_id:
            raise ValueError("confirmation_id is required")
        pending = self._pending_actions.get(confirmation_id)
        if pending is None:
            return {"confirmed": False, "confirmation_id": confirmation_id, "reason": "not_found"}
        confirmation_method = str(
            getattr(pending, "selected_backend_method", "") or "software"
        ).strip() or "software"
        retry_after = self._confirmation_failure_tracker.status(
            user_id=str(pending.user_id),
            method=confirmation_method,
        )
        if retry_after is not None:
            return {
                "confirmed": False,
                "confirmation_id": confirmation_id,
                "reason": "confirmation_method_locked_out",
                "retry_after_seconds": round(retry_after, 3),
            }
        raw_nonce = params.get("decision_nonce", "")
        provided_nonce = raw_nonce.strip() if isinstance(raw_nonce, str) else ""
        if not provided_nonce:
            return {
                "confirmed": False,
                "confirmation_id": confirmation_id,
                "reason": "missing_decision_nonce",
            }
        if provided_nonce != pending.decision_nonce:
            self._confirmation_failure_tracker.record_failure(
                user_id=str(pending.user_id),
                method=confirmation_method,
            )
            return {
                "confirmed": False,
                "confirmation_id": confirmation_id,
                "reason": "invalid_decision_nonce",
            }
        if pending.status != "pending":
            return {
                "confirmed": False,
                "confirmation_id": confirmation_id,
                "reason": f"already_{pending.status}",
            }
        if pending.execute_after is not None:
            remaining = (pending.execute_after - datetime.now(UTC)).total_seconds()
            if remaining > 0:
                return {
                    "confirmed": False,
                    "confirmation_id": confirmation_id,
                    "reason": "cooldown_active",
                    "retry_after_seconds": round(remaining, 3),
                }
        if pending.expires_at is not None:
            expires_at = pending.expires_at
            if expires_at is not None and expires_at <= datetime.now(UTC):
                pending.status = "failed"
                pending.status_reason = "approval_expired"
                self._sync_task_confirmation_status(pending)
                self._record_task_confirmation_outcome(pending, success=False)
                self._persist_pending_actions()
                return {
                    "confirmed": False,
                    "confirmation_id": confirmation_id,
                    "reason": "approval_expired",
                    "status": pending.status,
                    "status_reason": pending.status_reason,
                }
        if self._lockdown_manager.should_block_all_actions(pending.session_id):
            pending.status = "rejected"
            pending.status_reason = "session_in_lockdown"
            decision_timestamp = datetime.now(UTC).isoformat()
            await self._event_bus.publish(
                ToolRejected(
                    session_id=pending.session_id,
                    actor="human_confirmation",
                    tool_name=pending.tool_name,
                    reason="session_in_lockdown",
                    **self._pending_approval_event_fields(
                        pending,
                        decision_timestamp=decision_timestamp,
                    ),
                )
            )
            self._sync_task_confirmation_status(pending)
            self._record_task_confirmation_outcome(pending, success=False)
            self._persist_pending_actions()
            self._confirmation_analytics.record(
                user_id=str(pending.user_id),
                decision="reject",
                created_at=pending.created_at,
            )
            await self._maybe_emit_confirmation_hygiene_alert(
                user_id=str(pending.user_id),
                session_id=pending.session_id,
            )
            return {
                "confirmed": False,
                "confirmation_id": confirmation_id,
                "reason": "session_in_lockdown",
            }

        session = self._session_manager.get(pending.session_id)
        if session is None:
            pending.status = "failed"
            pending.status_reason = "session_missing"
            decision_timestamp = datetime.now(UTC).isoformat()
            await self._event_bus.publish(
                ToolRejected(
                    session_id=pending.session_id,
                    actor="human_confirmation",
                    tool_name=pending.tool_name,
                    reason="session_missing",
                    **self._pending_approval_event_fields(
                        pending,
                        decision_timestamp=decision_timestamp,
                    ),
                )
            )
            self._sync_task_confirmation_status(pending)
            self._record_task_confirmation_outcome(pending, success=False)
            self._persist_pending_actions()
            self._confirmation_analytics.record(
                user_id=str(pending.user_id),
                decision="reject",
                created_at=pending.created_at,
            )
            await self._maybe_emit_confirmation_hygiene_alert(
                user_id=str(pending.user_id),
                session_id=pending.session_id,
            )
            return {
                "confirmed": False,
                "confirmation_id": confirmation_id,
                "reason": "session_missing",
            }

        backend = self._confirmation_backend_registry.get_backend(
            str(getattr(pending, "selected_backend_id", "")).strip() or "software.default"
        )
        if backend is None:
            pending.status = "failed"
            pending.status_reason = "confirmation_backend_unavailable"
            decision_timestamp = datetime.now(UTC).isoformat()
            await self._event_bus.publish(
                ToolRejected(
                    session_id=pending.session_id,
                    actor="human_confirmation",
                    tool_name=pending.tool_name,
                    reason="confirmation_backend_unavailable",
                    **self._pending_approval_event_fields(
                        pending,
                        decision_timestamp=decision_timestamp,
                    ),
                )
            )
            self._sync_task_confirmation_status(pending)
            self._record_task_confirmation_outcome(pending, success=False)
            self._persist_pending_actions()
            return {
                "confirmed": False,
                "confirmation_id": confirmation_id,
                "reason": "confirmation_backend_unavailable",
                "status": pending.status,
                "status_reason": pending.status_reason,
            }

        try:
            evidence = backend.verify(
                pending_action=pending,
                params=dict(params),
            )
        except ConfirmationVerificationError as exc:
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
                "reason": str(exc.reason),
            }
            if retry_after is not None:
                response["retry_after_seconds"] = round(retry_after, 3)
            return response
        pending.confirmation_evidence = ConfirmationEvidence.model_validate(
            evidence.model_dump(mode="json")
            if isinstance(evidence, ConfirmationEvidence)
            else evidence
        )
        self._confirmation_failure_tracker.record_success(
            user_id=str(pending.user_id),
            method=confirmation_method,
        )

        pending_preflight_action = pending.preflight_action
        stage2_reason = "stage2_upgrade_required" in pending.reason
        if stage2_reason:
            if not bool(self._policy_loader.policy.control_plane.trace.allow_amendment):
                pending.status = "rejected"
                pending.status_reason = "plan_amendment_disabled"
                decision_timestamp = datetime.now(UTC).isoformat()
                await self._event_bus.publish(
                    ToolRejected(
                        session_id=pending.session_id,
                        actor="human_confirmation",
                        tool_name=pending.tool_name,
                        reason="plan_amendment_disabled",
                        **self._pending_approval_event_fields(
                            pending,
                            decision_timestamp=decision_timestamp,
                        ),
                    )
                )
                self._sync_task_confirmation_status(pending)
                self._record_task_confirmation_outcome(pending, success=False)
                self._persist_pending_actions()
                self._confirmation_analytics.record(
                    user_id=str(pending.user_id),
                    decision="reject",
                    created_at=pending.created_at,
                )
                await self._maybe_emit_confirmation_hygiene_alert(
                    user_id=str(pending.user_id),
                    session_id=pending.session_id,
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
            approved_action = pending_preflight_action or build_action(
                tool_name=str(pending.tool_name),
                arguments=dict(pending.arguments),
                origin=self._origin_for(session=session, actor="human_confirmation"),
                risk_tier=fallback_risk_tier,
                workspace_roots=list(
                    getattr(getattr(self, "_config", None), "assistant_fs_roots", [Path.cwd()])
                ),
            )
            previous_hash = await _call_control_plane(
                self,
                "active_plan_hash",
                str(pending.session_id),
            )
            try:
                plan_hash = await _call_control_plane(
                    self,
                    "approve_stage2",
                    action=approved_action,
                    approved_by="human_confirmation",
                )
            except ControlPlaneRpcError as exc:
                reason = _confirmation_control_plane_reason(exc)
                pending.status = "failed"
                pending.status_reason = reason
                decision_timestamp = datetime.now(UTC).isoformat()
                await self._event_bus.publish(
                    ToolRejected(
                        session_id=pending.session_id,
                        actor="human_confirmation",
                        tool_name=pending.tool_name,
                        reason=reason,
                        **self._pending_approval_event_fields(
                            pending,
                            decision_timestamp=decision_timestamp,
                        ),
                    )
                )
                self._sync_task_confirmation_status(pending)
                self._record_task_confirmation_outcome(pending, success=False)
                self._persist_pending_actions()
                self._confirmation_analytics.record(
                    user_id=str(pending.user_id),
                    decision="reject",
                    created_at=pending.created_at,
                )
                await self._maybe_emit_confirmation_hygiene_alert(
                    user_id=str(pending.user_id),
                    session_id=pending.session_id,
                )
                return {
                    "confirmed": False,
                    "confirmation_id": confirmation_id,
                    "reason": reason,
                    "status": pending.status,
                    "status_reason": pending.status_reason,
                }
            await self._event_bus.publish(
                PlanAmended(
                    session_id=pending.session_id,
                    actor="human_confirmation",
                    plan_hash=plan_hash,
                    amendment_of=previous_hash,
                    stage="stage2_postevidence",
                )
            )

        execution_capabilities = set(pending.capabilities)
        pep_elevation = getattr(pending, "pep_elevation", None)
        if pep_elevation is not None:
            # Human approval authorizes a scoped retry; it does not directly
            # execute an action that the original PEP evaluation rejected.
            pep_context = getattr(pending, "pep_context", None)
            if pep_context is None:
                pending.status = "failed"
                pending.status_reason = "pep_elevation_context_missing"
                decision_timestamp = datetime.now(UTC).isoformat()
                await self._event_bus.publish(
                    ToolRejected(
                        session_id=pending.session_id,
                        actor="human_confirmation",
                        tool_name=pending.tool_name,
                        reason="pep_elevation_context_missing",
                        **self._pending_approval_event_fields(
                            pending,
                            decision_timestamp=decision_timestamp,
                        ),
                    )
                )
                self._sync_task_confirmation_status(pending)
                self._record_task_confirmation_outcome(pending, success=False)
                self._persist_pending_actions()
                self._confirmation_analytics.record(
                    user_id=str(pending.user_id),
                    decision="reject",
                    created_at=pending.created_at,
                )
                await self._maybe_emit_confirmation_hygiene_alert(
                    user_id=str(pending.user_id),
                    session_id=pending.session_id,
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
                pending.status = "rejected"
                pending.status_reason = (
                    pep_decision.reason_code.strip() or "pep_reject_after_confirmation"
                )
                decision_timestamp = datetime.now(UTC).isoformat()
                await self._event_bus.publish(
                    ToolRejected(
                        session_id=pending.session_id,
                        actor="human_confirmation",
                        tool_name=pending.tool_name,
                        reason=pep_decision.reason or pending.status_reason,
                        **self._pending_approval_event_fields(
                            pending,
                            decision_timestamp=decision_timestamp,
                        ),
                    )
                )
                self._sync_task_confirmation_status(pending)
                self._record_task_confirmation_outcome(pending, success=False)
                self._persist_pending_actions()
                self._confirmation_analytics.record(
                    user_id=str(pending.user_id),
                    decision="reject",
                    created_at=pending.created_at,
                )
                await self._maybe_emit_confirmation_hygiene_alert(
                    user_id=str(pending.user_id),
                    session_id=pending.session_id,
                )
                return {
                    "confirmed": False,
                    "confirmation_id": confirmation_id,
                    "decision_nonce": pending.decision_nonce,
                    "status": pending.status,
                    "status_reason": pending.status_reason,
                    "reason": pending.status_reason,
                }

        decision_timestamp = datetime.now(UTC).isoformat()
        decision_at = datetime.fromisoformat(decision_timestamp)
        promote_ref_id = str(pending.arguments.get("ref_id", "")).strip()
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
            approval_confirmation_id=str(pending.confirmation_id),
            approval_decision_nonce=str(pending.decision_nonce),
            approval_task_envelope_id=str(
                getattr(pending, "approval_task_envelope_id", "")
            ).strip(),
            approval_timestamp=decision_timestamp,
            approval_evidence=pending.confirmation_evidence,
        )
        success = execution_result.success
        checkpoint_id = execution_result.checkpoint_id
        tool_output = getattr(execution_result, "tool_output", None)
        promote_followup_reason = ""
        if success and tool_output is not None and str(pending.tool_name) == "evidence.promote":
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
                self._transcript_store.append(
                    pending.session_id,
                    role="assistant",
                    content=content,
                    taint_labels=set(getattr(tool_output, "taint_labels", set()))
                    or {TaintLabel.USER_REVIEWED},
                    metadata={
                        "channel": str(session.channel),
                        "timestamp_utc": datetime.now(UTC).isoformat(),
                        "session_mode": session.mode.value,
                        "promoted_evidence": True,
                        "promoted_ref_id": target_ref_id,
                    },
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
        pending.status = "approved" if success else "failed"
        pending.status_reason = (
            promote_followup_reason or str(params.get("reason", "")).strip() or pending.status
        )
        self._sync_task_confirmation_status(pending)
        self._record_task_confirmation_outcome(pending, success=success)
        self._persist_pending_actions()
        self._confirmation_analytics.record(
            user_id=str(pending.user_id),
            decision="approve" if success else "reject",
            created_at=pending.created_at,
        )
        await self._maybe_emit_confirmation_hygiene_alert(
            user_id=str(pending.user_id),
            session_id=pending.session_id,
        )
        return {
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
        }

    async def do_action_reject(self, params: Mapping[str, Any]) -> dict[str, Any]:
        confirmation_id = str(params.get("confirmation_id", "")).strip()
        if not confirmation_id:
            raise ValueError("confirmation_id is required")
        reason = str(params.get("reason", "manual_reject")).strip() or "manual_reject"
        pending = self._pending_actions.get(confirmation_id)
        if pending is None:
            return {"rejected": False, "confirmation_id": confirmation_id, "reason": "not_found"}
        raw_nonce = params.get("decision_nonce", "")
        provided_nonce = raw_nonce.strip() if isinstance(raw_nonce, str) else ""
        if not provided_nonce:
            return {
                "rejected": False,
                "confirmation_id": confirmation_id,
                "reason": "missing_decision_nonce",
            }
        if provided_nonce != pending.decision_nonce:
            return {
                "rejected": False,
                "confirmation_id": confirmation_id,
                "reason": "invalid_decision_nonce",
            }
        if pending.status != "pending":
            return {
                "rejected": False,
                "confirmation_id": confirmation_id,
                "reason": f"already_{pending.status}",
            }
        pending.status = "rejected"
        pending.status_reason = reason
        decision_timestamp = datetime.now(UTC).isoformat()
        await self._event_bus.publish(
            ToolRejected(
                session_id=pending.session_id,
                actor="human_confirmation",
                tool_name=pending.tool_name,
                reason=reason,
                **self._pending_approval_event_fields(
                    pending,
                    decision_timestamp=decision_timestamp,
                ),
            )
        )
        self._sync_task_confirmation_status(pending)
        self._record_task_confirmation_outcome(pending, success=False)
        self._persist_pending_actions()
        self._confirmation_analytics.record(
            user_id=str(pending.user_id),
            decision="reject",
            created_at=pending.created_at,
        )
        await self._maybe_emit_confirmation_hygiene_alert(
            user_id=str(pending.user_id),
            session_id=pending.session_id,
        )
        return {
            "rejected": True,
            "confirmation_id": confirmation_id,
            "status": pending.status,
            "status_reason": reason,
        }
