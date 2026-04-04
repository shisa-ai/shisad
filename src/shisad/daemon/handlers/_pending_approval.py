"""Shared helpers for pending confirmation approvals."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from shisad.core.session import Session
from shisad.core.types import (
    Capability,
    CredentialRef,
    SessionId,
    TaintLabel,
    ToolName,
    UserId,
    WorkspaceId,
)
from shisad.daemon.handlers._task_scope import task_resource_authorizer
from shisad.scheduler.schema import TaskEnvelope
from shisad.security.pep import PolicyContext


@dataclass(slots=True)
class PendingPepContextSnapshot:
    """Queue-time policy context snapshot for confirmation-time PEP re-checks."""

    capabilities: set[Capability] = field(default_factory=set)
    taint_labels: set[TaintLabel] = field(default_factory=set)
    user_goal_host_patterns: set[str] = field(default_factory=set)
    untrusted_host_patterns: set[str] = field(default_factory=set)
    tool_allowlist: set[ToolName] | None = None
    trust_level: str = "untrusted"
    credential_refs: set[CredentialRef] = field(default_factory=set)
    enforce_explicit_credential_refs: bool = False


@dataclass(slots=True)
class PendingPepElevationRequest:
    """Explicit, per-action PEP elevation approved by the user."""

    kind: str = "capability_grant"
    reason_code: str = ""
    capability_grants: set[Capability] = field(default_factory=set)


def pep_arguments_for_policy_evaluation(
    tool_name: ToolName | str,
    arguments: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize runtime-only fields away before PEP schema evaluation."""
    payload = dict(arguments)
    normalized_tool_name = str(tool_name).strip()
    if normalized_tool_name in {"browser.click", "browser.type_text"}:
        payload.pop("resolved_target", None)
        payload.pop("source_url", None)
        payload.pop("source_binding", None)
    if normalized_tool_name == "browser.type_text":
        payload.pop("description", None)
    return payload


def capability_elevation_for_missing_capabilities(
    *,
    reason_code: str,
    session_capabilities: set[Capability],
    required_capabilities: set[Capability],
) -> PendingPepElevationRequest | None:
    normalized_reason_code = reason_code.strip()
    if normalized_reason_code != "pep:missing_capabilities":
        return None
    missing = {
        capability
        for capability in required_capabilities
        if capability not in session_capabilities
    }
    if not missing:
        return None
    return PendingPepElevationRequest(
        kind="capability_grant",
        reason_code=normalized_reason_code,
        capability_grants=missing,
    )


def pending_pep_elevation_warning(elevation: PendingPepElevationRequest | None) -> str:
    if elevation is None or not elevation.capability_grants:
        return ""
    if elevation.kind != "capability_grant":
        return ""
    granted = ", ".join(sorted(capability.value for capability in elevation.capability_grants))
    return (
        "Approval will re-run policy with a per-action capability grant: "
        f"{granted}."
    )


def pending_pep_context_to_payload(
    snapshot: PendingPepContextSnapshot,
) -> dict[str, Any]:
    return {
        "capabilities": sorted(capability.value for capability in snapshot.capabilities),
        "taint_labels": sorted(label.value for label in snapshot.taint_labels),
        "user_goal_host_patterns": sorted(snapshot.user_goal_host_patterns),
        "untrusted_host_patterns": sorted(snapshot.untrusted_host_patterns),
        "tool_allowlist": (
            sorted(str(tool_name) for tool_name in snapshot.tool_allowlist)
            if snapshot.tool_allowlist is not None
            else None
        ),
        "trust_level": snapshot.trust_level,
        "credential_refs": sorted(str(ref_id) for ref_id in snapshot.credential_refs),
        "enforce_explicit_credential_refs": bool(snapshot.enforce_explicit_credential_refs),
    }


def pending_pep_context_from_payload(raw: Mapping[str, Any]) -> PendingPepContextSnapshot:
    tool_allowlist_raw = raw.get("tool_allowlist")
    tool_allowlist: set[ToolName] | None = None
    if tool_allowlist_raw is not None:
        if not isinstance(tool_allowlist_raw, list):
            raise TypeError("tool_allowlist must be a list or null")
        tool_allowlist = {
            ToolName(str(tool_name))
            for tool_name in tool_allowlist_raw
            if str(tool_name).strip()
        }
    return PendingPepContextSnapshot(
        capabilities={
            Capability(str(capability))
            for capability in raw.get("capabilities", [])
            if str(capability).strip()
        },
        taint_labels={
            TaintLabel(str(label))
            for label in raw.get("taint_labels", [])
            if str(label).strip()
        },
        user_goal_host_patterns={
            str(pattern).strip()
            for pattern in raw.get("user_goal_host_patterns", [])
            if str(pattern).strip()
        },
        untrusted_host_patterns={
            str(pattern).strip()
            for pattern in raw.get("untrusted_host_patterns", [])
            if str(pattern).strip()
        },
        tool_allowlist=tool_allowlist,
        trust_level=str(raw.get("trust_level", "untrusted")).strip() or "untrusted",
        credential_refs={
            CredentialRef(str(ref_id))
            for ref_id in raw.get("credential_refs", [])
            if str(ref_id).strip()
        },
        enforce_explicit_credential_refs=bool(raw.get("enforce_explicit_credential_refs", False)),
    )


def pending_pep_elevation_to_payload(
    elevation: PendingPepElevationRequest,
) -> dict[str, Any]:
    return {
        "kind": elevation.kind,
        "reason_code": elevation.reason_code,
        "capability_grants": sorted(
            capability.value for capability in elevation.capability_grants
        ),
    }


def pending_pep_elevation_from_payload(
    raw: Mapping[str, Any],
) -> PendingPepElevationRequest:
    return PendingPepElevationRequest(
        kind=str(raw.get("kind", "capability_grant")).strip() or "capability_grant",
        reason_code=str(raw.get("reason_code", "")).strip(),
        capability_grants={
            Capability(str(capability))
            for capability in raw.get("capability_grants", [])
            if str(capability).strip()
        },
    )


def task_envelope_for_session(session: Session | None) -> TaskEnvelope | None:
    if session is None:
        return None
    metadata = getattr(session, "metadata", None)
    if not isinstance(metadata, Mapping):
        return None
    raw = metadata.get("task_envelope")
    if raw in ({}, None, ""):
        return None
    if not isinstance(raw, dict):
        return None
    try:
        return TaskEnvelope.model_validate(raw)
    except ValidationError:
        return None


def build_policy_context_for_pending_action(
    *,
    session: Session,
    pending_session_id: SessionId,
    pending_workspace_id: WorkspaceId,
    pending_user_id: UserId,
    snapshot: PendingPepContextSnapshot,
    elevation: PendingPepElevationRequest | None = None,
) -> PolicyContext:
    capabilities = set(snapshot.capabilities)
    if elevation is not None and elevation.kind == "capability_grant":
        capabilities.update(elevation.capability_grants)
    return PolicyContext(
        capabilities=capabilities,
        taint_labels=set(snapshot.taint_labels),
        user_goal_host_patterns=set(snapshot.user_goal_host_patterns),
        untrusted_host_patterns=set(snapshot.untrusted_host_patterns),
        session_id=pending_session_id,
        workspace_id=pending_workspace_id,
        user_id=pending_user_id,
        resource_authorizer=task_resource_authorizer(task_envelope_for_session(session)),
        tool_allowlist=(
            set(snapshot.tool_allowlist) if snapshot.tool_allowlist is not None else None
        ),
        trust_level=snapshot.trust_level,
        credential_refs=set(snapshot.credential_refs),
        enforce_explicit_credential_refs=bool(snapshot.enforce_explicit_credential_refs),
    )
