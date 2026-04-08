"""Action confirmation handler implementations."""

from __future__ import annotations

import asyncio
import getpass
import hmac
import json
import logging
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

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
    confirmation_evidence_satisfies_requirement,
    generate_recovery_codes,
    generate_totp_secret,
    hash_recovery_code,
    match_totp_window,
)
from shisad.core.events import (
    PlanAmended,
    SignerKeyRegistered,
    SignerKeyRevoked,
    ToolRejected,
    TwoFactorEnrolled,
    TwoFactorRevoked,
)
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
from shisad.security.credentials import ApprovalFactorRecord, RecoveryCodeRecord, SignerKeyRecord

logger = logging.getLogger(__name__)


def _confirmation_control_plane_reason(exc: ControlPlaneRpcError) -> str:
    message = str(exc.message).strip().lower()
    if exc.reason_code == "rpc.invalid_params" and "inactive plan" in message:
        return "plan_missing_or_inactive"
    if exc.reason_code == "rpc.permission_denied":
        return "control_plane_permission_denied"
    return "control_plane_rejected"


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
        try:
            public_key = self._webauthn_backend().approval_request_options(
                pending_action=pending,
            )
        except ConfirmationVerificationError as exc:
            return {
                "ok": False,
                "status": "invalid_request",
                "reason": exc.reason,
                "message": "This approval request cannot be completed with WebAuthn.",
            }
        return {
            "ok": True,
            "status": "pending",
            "summary": pending.safe_preview or pending.reason,
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
            approval_url = approval_web.issue_approval_link(str(pending.confirmation_id))
            if not approval_url:
                continue
            qr_ascii = approval_web.qr_ascii(approval_url)
            lines = [
                "Approval required",
                pending.safe_preview or pending.reason,
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
        if backend != "kms":
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
        algorithm = str(params.get("algorithm") or "ed25519").strip().lower() or "ed25519"
        if algorithm not in {"ed25519", "ecdsa-secp256k1"}:
            return {"registered": False, "reason": "unsupported_signer_algorithm"}
        device_type = (
            str(params.get("device_type") or "ledger-enterprise").strip()
            or "ledger-enterprise"
        )
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
            if status_filter and item.status.lower() != status_filter:
                continue
            payload = self._pending_to_dict(item)
            if (
                getattr(self, "_approval_web", None) is not None
                and self._approval_web.enabled
                and str(getattr(item, "selected_backend_method", "")).strip() == "webauthn"
                and str(getattr(item, "status", "")).strip() == "pending"
            ):
                approval_url = self._approval_web.issue_approval_link(
                    str(getattr(item, "confirmation_id", ""))
                )
                if approval_url:
                    payload["approval_url"] = approval_url
                    payload["approval_qr_ascii"] = self._approval_web.qr_ascii(approval_url)
            elif (
                str(getattr(item, "selected_backend_method", "")).strip() == "local_fido2"
                and str(getattr(item, "status", "")).strip() == "pending"
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
        if pending.status != "pending":
            return {
                "confirmed": False,
                "confirmation_id": confirmation_id,
                "reason": f"already_{pending.status}",
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
        if not hmac.compare_digest(provided_nonce, pending.decision_nonce):
            self._confirmation_failure_tracker.record_failure(
                user_id=str(pending.user_id),
                method=confirmation_method,
            )
            return {
                "confirmed": False,
                "confirmation_id": confirmation_id,
                "reason": "invalid_decision_nonce",
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
        pending.confirmation_evidence = validated_evidence
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
            if pep_decision.kind.value == "require_confirmation":
                payload = pep_decision.confirmation_requirement
                if not isinstance(payload, Mapping):
                    pending.status = "failed"
                    pending.status_reason = "confirmation_requirement_missing_after_confirmation"
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
                        pending.status = "rejected"
                        pending.status_reason = (
                            "confirmation_requirement_unsatisfied_after_confirmation"
                        )
                    else:
                        pending.status = "pending"
                        pending.status_reason = ""
                if pending.status != "pending":
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
        if not hmac.compare_digest(provided_nonce, pending.decision_nonce):
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
