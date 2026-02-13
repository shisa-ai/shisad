"""Unit checks for admin handler wrappers."""

from __future__ import annotations

import pytest

from shisad.core.api.schema import ChannelIngestParams, LockdownSetParams, NoParams
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

    async def do_lockdown_set(self, payload: dict[str, object]) -> dict[str, object]:
        return {"session_id": str(payload["session_id"]), "level": "caution", "reason": "manual"}

    async def do_risk_calibrate(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"version": "v1", "thresholds": {}}

    async def do_channel_ingest(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"session_id": "s1", "response": "ok", "ingress_risk": 0.1}


@pytest.mark.asyncio
async def test_admin_status_and_lockdown_wrappers() -> None:
    handlers = AdminHandlers(_StubImpl(), internal_ingress_marker=object())  # type: ignore[arg-type]
    status = await handlers.handle_daemon_status(NoParams(), RequestContext())
    lockdown = await handlers.handle_lockdown_set(
        LockdownSetParams(session_id="s1"),
        RequestContext(),
    )
    assert status.status == "running"
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
