"""Shared typed readiness vocabulary and redacted projections."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any

from pydantic import BaseModel

from shisad.core.providers.capabilities import AuthMode


class ReadinessState(StrEnum):
    """Finite readiness states shared by runtime and user-facing diagnostics."""

    ABSENT = "absent"
    INSTALLED = "installed"
    CONFIGURED = "configured"
    REACHABLE = "reachable"
    AUTHENTICATED = "authenticated"
    VERIFIED = "verified"
    DEGRADED = "degraded"
    BLOCKED = "blocked"


class ReadinessStatus(BaseModel):
    """Stable redacted readiness evidence for one component or route."""

    state: ReadinessState
    installed: bool = True
    configured: bool = False
    reachable: bool = False
    authenticated: bool = False
    verified: bool = False
    evidence: str = "config_only"
    reason: str
    next_action: str
    source: str = "runtime_config"

    def redacted_projection(self) -> dict[str, object]:
        return self.model_dump(mode="json")


def configured_route_readiness(route: Any) -> ReadinessStatus:
    """Project config-only model-route readiness without implying a live probe."""

    remote_enabled = bool(route.remote_enabled)
    requires_key = route.auth_mode != AuthMode.NONE
    has_key = bool(route.api_key)
    if not remote_enabled:
        return ReadinessStatus(
            state=ReadinessState.BLOCKED,
            configured=False,
            reason="route_disabled",
            next_action=(
                "configure or explicitly enable this route; live probe has not run"
            ),
        )
    if requires_key and not has_key:
        return ReadinessStatus(
            state=ReadinessState.BLOCKED,
            configured=False,
            reason="missing_api_key",
            next_action="configure the route credential; live probe has not run",
        )
    return ReadinessStatus(
        state=ReadinessState.CONFIGURED,
        configured=True,
        reason="live_probe_not_run",
        next_action="run provider doctor with the opt-in live probe",
    )


def aggregate_config_readiness(statuses: list[ReadinessStatus]) -> ReadinessState:
    """Return a truthful non-green aggregate for config-only route evidence."""

    if not statuses:
        return ReadinessState.ABSENT
    if any(item.state == ReadinessState.BLOCKED for item in statuses):
        return ReadinessState.DEGRADED
    if all(item.state == ReadinessState.VERIFIED for item in statuses):
        return ReadinessState.VERIFIED
    return ReadinessState.CONFIGURED


def verified_probe_readiness() -> ReadinessStatus:
    return ReadinessStatus(
        state=ReadinessState.VERIFIED,
        configured=True,
        reachable=True,
        authenticated=True,
        verified=True,
        evidence="live_probe",
        reason="probe_succeeded",
        next_action="none",
        source="live_provider_probe",
    )


def failed_probe_readiness(error_text: str) -> ReadinessStatus:
    """Classify finite machine HTTP/transport evidence without exposing details."""

    match = re.search(r"\bHTTP (?:error )?(?P<status>[1-5][0-9]{2})\b", error_text)
    status_code = int(match.group("status")) if match is not None else None
    if status_code in {401, 403}:
        return ReadinessStatus(
            state=ReadinessState.BLOCKED,
            configured=True,
            reachable=True,
            evidence="live_probe",
            reason="authentication_failed",
            next_action="replace or re-enroll the configured provider credential",
            source="live_provider_probe",
        )
    if status_code is not None:
        return ReadinessStatus(
            state=ReadinessState.DEGRADED,
            configured=True,
            reachable=True,
            evidence="live_probe",
            reason=f"provider_http_{status_code}",
            next_action="check provider route compatibility and service status",
            source="live_provider_probe",
        )
    return ReadinessStatus(
        state=ReadinessState.DEGRADED,
        configured=True,
        evidence="live_probe",
        reason="provider_unreachable",
        next_action="check provider network reachability and endpoint configuration",
        source="live_provider_probe",
    )


def normalize_readiness_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Project existing component diagnostics through the shared vocabulary."""

    result = {
        key: _normalize_nested_readiness(value)
        for key, value in payload.items()
    }
    raw_status = str(result.get("status", "")).strip().lower()
    if raw_status in {state.value for state in ReadinessState}:
        state = ReadinessState(raw_status)
    else:
        mapping = {
            "ok": ReadinessState.VERIFIED,
            "healthy": ReadinessState.VERIFIED,
            "disabled": ReadinessState.ABSENT,
            "missing": ReadinessState.ABSENT,
            "unconfigured": ReadinessState.ABSENT,
            "misconfigured": ReadinessState.BLOCKED,
            "error": ReadinessState.BLOCKED,
            "unavailable": ReadinessState.BLOCKED,
            "unhealthy": ReadinessState.DEGRADED,
        }
        state = mapping.get(raw_status, ReadinessState.DEGRADED)
        result["status"] = state.value
        result["legacy_status"] = raw_status or "missing"
    default_reason = {
        ReadinessState.ABSENT: "component_disabled_or_absent",
        ReadinessState.INSTALLED: "component_installed_not_configured",
        ReadinessState.CONFIGURED: "configuration_present_not_verified",
        ReadinessState.REACHABLE: "component_reachable_not_authenticated",
        ReadinessState.AUTHENTICATED: "component_authenticated_not_verified",
        ReadinessState.VERIFIED: "legacy_ok",
        ReadinessState.DEGRADED: "component_degraded",
        ReadinessState.BLOCKED: "component_blocked",
    }[state]
    default_action = {
        ReadinessState.ABSENT: "enable and configure the component if it is needed",
        ReadinessState.INSTALLED: "configure the installed component",
        ReadinessState.CONFIGURED: "run the component's bounded verification path",
        ReadinessState.REACHABLE: "configure and verify component authentication",
        ReadinessState.AUTHENTICATED: "run the component verification path",
        ReadinessState.VERIFIED: "none",
        ReadinessState.DEGRADED: "inspect component problems and restore its dependency",
        ReadinessState.BLOCKED: "correct the component configuration before use",
    }[state]
    result.setdefault("reason", default_reason)
    result.setdefault("next_action", default_action)
    return result


def _normalize_nested_readiness(value: Any) -> Any:
    if isinstance(value, dict):
        if "status" in value:
            return normalize_readiness_payload(value)
        return {key: _normalize_nested_readiness(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize_nested_readiness(item) for item in value]
    return value
