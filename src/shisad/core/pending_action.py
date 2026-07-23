"""Versioned pending-action record shared by daemon lifecycle collaborators."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from shisad.core.action_state import derive_action_followup_id, derive_legacy_action_id
from shisad.core.approval import (
    ApprovalEnvelope,
    ConfirmationCapabilities,
    ConfirmationEvidence,
    ConfirmationFallbackPolicy,
    ConfirmationLevel,
    IntentEnvelope,
)
from shisad.core.types import Capability, SessionId, ToolName, UserId, WorkspaceId

if TYPE_CHECKING:
    from shisad.channels.base import DeliveryTarget
    from shisad.core.tools.schema import ToolRetryDescriptor
    from shisad.daemon.handlers._pending_approval import (
        PendingPepContextSnapshot,
        PendingPepElevationRequest,
    )
    from shisad.governance.merge import ToolExecutionPolicy
    from shisad.security.control_plane.schema import ControlPlaneAction

PENDING_ACTION_RECORD_SCHEMA_VERSION = 1


@dataclass(slots=True)
class PendingActionRecord:
    """Canonical mutable record for one local pending-action lifecycle."""

    confirmation_id: str
    decision_nonce: str
    session_id: SessionId
    user_id: UserId
    workspace_id: WorkspaceId
    tool_name: ToolName
    arguments: dict[str, Any]
    reason: str
    capabilities: set[Capability]
    created_at: datetime
    record_schema_version: int = field(
        default=PENDING_ACTION_RECORD_SCHEMA_VERSION,
        kw_only=True,
    )
    public_arguments: dict[str, Any] | None = None
    sensitive_public_payload: bool = False
    delivery_target: DeliveryTarget | None = None
    task_id: str = ""
    preflight_action: ControlPlaneAction | None = None
    execute_after: datetime | None = None
    safe_preview: str = ""
    warnings: list[str] = field(default_factory=list)
    leak_check: dict[str, Any] = field(default_factory=dict)
    merged_policy: ToolExecutionPolicy | None = None
    approval_task_envelope_id: str = ""
    pep_context: PendingPepContextSnapshot | None = None
    pep_elevation: PendingPepElevationRequest | None = None
    required_level: ConfirmationLevel = ConfirmationLevel.SOFTWARE
    required_methods: list[str] = field(default_factory=list)
    allowed_principals: list[str] = field(default_factory=list)
    allowed_channel_principals: list[str] = field(default_factory=list)
    allowed_credentials: list[str] = field(default_factory=list)
    required_capabilities: ConfirmationCapabilities = field(
        default_factory=ConfirmationCapabilities
    )
    approval_envelope: ApprovalEnvelope | None = None
    approval_envelope_hash: str = ""
    intent_envelope: IntentEnvelope | None = None
    confirmation_evidence: ConfirmationEvidence | None = None
    fallback: ConfirmationFallbackPolicy = field(default_factory=ConfirmationFallbackPolicy)
    expires_at: datetime | None = None
    selected_backend_id: str = ""
    selected_backend_method: str = ""
    fallback_used: bool = False
    strip_direct_tool_execute_envelope_keys: bool = False
    continuation_user_goal: str = ""
    continuation_mode: str = ""
    status: str = "pending"
    status_reason: str = ""
    action_id: str = ""
    origin_turn_id: str = ""
    action_digest: str = ""
    approval_evidence_hash: str = ""
    execution_authorization_kind: str = ""
    retry_descriptor: ToolRetryDescriptor | None = None
    retry_generation: int = 0
    recovery_started_at: datetime | None = None
    recovery_result: dict[str, Any] = field(default_factory=dict)
    recovery_accounting_pending: bool = False
    recovery_effect_invoked: bool = False
    recovery_scheduler_accounted: bool = False
    recovery_scheduler_posture_captured: bool = False
    recovery_scheduler_restore_enabled: bool = False
    scheduler_accounting_pending: bool = False
    scheduler_accounting_mode: str = ""
    stage2_correlation_id: str = ""
    stage2_previous_plan_hash: str = ""
    stage2_plan_hash: str = ""
    stable_idempotency_key: str = ""
    provider_operation_id: str = ""
    execution_attempt_id: str = ""
    result_id: str = ""
    followup_id: str = ""
    recovery_authority_mac: str = ""
    recovery_event_identity_untrusted: bool = False
    recovery_event_identity_untrusted_at: datetime | None = None
    recovery_anonymous_accounting_id: str = ""
    recovery_event_identity_trusted_at: datetime | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    recovery_anonymous_accounting_id_trusted: str = field(
        default="",
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if (
            type(self.record_schema_version) is not int
            or self.record_schema_version != PENDING_ACTION_RECORD_SCHEMA_VERSION
        ):
            raise ValueError("unsupported pending-action record schema")
        if not self.action_id.strip():
            self.action_id = derive_legacy_action_id(
                confirmation_id=self.confirmation_id,
                session_id=str(self.session_id),
                created_at=self.created_at,
            )
        if not self.followup_id.strip():
            self.followup_id = derive_action_followup_id(self.action_id)

    @staticmethod
    def _is_legacy_direct_mcp_tool_execute_shape(
        *,
        tool_name: ToolName | str,
        arguments: Mapping[str, Any],
        preflight_action: ControlPlaneAction | Mapping[str, Any] | None,
    ) -> bool:
        if not str(tool_name).strip().startswith("mcp."):
            return False
        if not all(key in arguments for key in ("session_id", "tool_name", "command")):
            return False
        if isinstance(preflight_action, Mapping):
            origin = preflight_action.get("origin")
            if isinstance(origin, Mapping):
                return str(origin.get("actor", "")).strip() == "control_api"
            return False
        return str(getattr(getattr(preflight_action, "origin", None), "actor", "")).strip() == (
            "control_api"
        )

    def should_strip_direct_tool_execute_envelope_keys(self) -> bool:
        return bool(self.strip_direct_tool_execute_envelope_keys) or (
            PendingActionRecord._is_legacy_direct_mcp_tool_execute_shape(
                tool_name=self.tool_name,
                arguments=self.arguments,
                preflight_action=self.preflight_action,
            )
        )


# Compatibility import retained while F10B/F10C migrate handler consumers.
PendingAction = PendingActionRecord
