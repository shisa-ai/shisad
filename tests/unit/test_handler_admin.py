"""Unit checks for admin handler wrappers."""

from __future__ import annotations

import pytest

from shisad.core.api.schema import (
    ChannelIngestParams,
    ChannelPairingProposalParams,
    DoctorCheckParams,
    LockdownSetParams,
    NoParams,
)
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers.admin import AdminHandlers


class _StubImpl:
    async def do_daemon_status(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"status": "running", "sessions_active": 0}

    async def do_policy_explain(self, payload: dict[str, object]) -> dict[str, object]:
        return {
            "session_id": str(payload.get("session_id", "")),
            "tool_name": "shell_exec",
            "action": str(payload.get("action", "")),
            "effective_policy": {},
            "control_plane": {},
            "contributors": {},
        }

    async def do_daemon_shutdown(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"status": "shutting_down"}

    async def do_doctor_check(self, payload: dict[str, object]) -> dict[str, object]:
        return {
            "status": "ok",
            "component": str(payload.get("component", "all")),
            "checks": {"realitycheck": {"status": "disabled"}},
            "error": "",
        }

    async def do_lockdown_set(self, payload: dict[str, object]) -> dict[str, object]:
        return {"session_id": str(payload["session_id"]), "level": "caution", "reason": "manual"}

    async def do_risk_calibrate(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"version": "v1", "thresholds": {}}

    async def do_channel_ingest(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"session_id": "s1", "response": "ok", "ingress_risk": 0.1}

    async def do_channel_pairing_propose(self, _payload: dict[str, object]) -> dict[str, object]:
        return {
            "proposal_id": "p1",
            "proposal_path": "/tmp/p1.json",
            "generated_at": "2026-02-15T00:00:00+00:00",
            "entries": [],
            "invalid_entries": [],
            "count": 0,
            "config_patch": {},
            "applied": False,
        }


@pytest.mark.asyncio
async def test_admin_status_and_lockdown_wrappers() -> None:
    handlers = AdminHandlers(_StubImpl(), internal_ingress_marker=object())  # type: ignore[arg-type]
    status = await handlers.handle_daemon_status(NoParams(), RequestContext())
    doctor = await handlers.handle_doctor_check(
        DoctorCheckParams(component="realitycheck"),
        RequestContext(),
    )
    lockdown = await handlers.handle_lockdown_set(
        LockdownSetParams(session_id="s1"),
        RequestContext(),
    )
    assert status.status == "running"
    assert doctor.component == "realitycheck"
    assert lockdown.session_id == "s1"


@pytest.mark.asyncio
async def test_channel_ingest_wrapper() -> None:
    handlers = AdminHandlers(_StubImpl(), internal_ingress_marker=object())  # type: ignore[arg-type]
    result = await handlers.handle_channel_ingest(
        ChannelIngestParams(
            message={
                "channel": "cli",
                "external_user_id": "alice",
                "workspace_hint": "w1",
                "content": "hi",
            }
        ),
        RequestContext(),
    )
    assert result.ingress_risk == 0.1


@pytest.mark.asyncio
async def test_channel_pairing_proposal_wrapper() -> None:
    handlers = AdminHandlers(_StubImpl(), internal_ingress_marker=object())  # type: ignore[arg-type]
    result = await handlers.handle_channel_pairing_propose(
        ChannelPairingProposalParams(limit=5),
        RequestContext(),
    )
    assert result.proposal_id == "p1"
