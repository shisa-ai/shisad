"""Error-path observability checks (audit + transport logging)."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import pytest

from shisad.core.api.schema import JsonRpcResponse, SessionCreateParams
from shisad.core.api.transport import ControlServer
from shisad.core.audit import AuditLog
from shisad.core.events import EventBus, SessionCreated
from shisad.core.request_context import RequestContext
from shisad.core.types import SessionId, UserId, WorkspaceId


@pytest.mark.asyncio
async def test_event_bus_persists_audit_when_handler_fails(tmp_path: Path) -> None:
    audit_log = AuditLog(tmp_path / "audit.jsonl")
    bus = EventBus(persister=audit_log)
    handled: list[str] = []

    async def _failing_handler(_event: SessionCreated) -> None:
        raise RuntimeError("handler failed")

    async def _healthy_handler(event: SessionCreated) -> None:
        handled.append(str(event.session_id))

    bus.subscribe(SessionCreated, _failing_handler)
    bus.subscribe(SessionCreated, _healthy_handler)

    event = SessionCreated(
        session_id=SessionId("session-1"),
        actor="test",
        user_id=UserId("user-1"),
        workspace_id=WorkspaceId("ws-1"),
    )
    await bus.publish(event)

    assert handled == ["session-1"]
    valid, count, error = audit_log.verify_chain()
    assert valid is True
    assert error == ""
    assert count == 1


@pytest.mark.asyncio
async def test_transport_logs_reason_code_for_internal_error(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    server = ControlServer(tmp_path / "control.sock")

    async def _handler(params: SessionCreateParams, ctx: RequestContext) -> dict[str, object]:
        _ = params, ctx
        raise RuntimeError("boom")

    server.register_method("session.create", _handler, params_model=SessionCreateParams)
    await server.start()
    caplog.set_level(logging.ERROR, logger="shisad.core.api.transport")
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.open_unix_connection(str(tmp_path / "control.sock"))
        request = {
            "jsonrpc": "2.0",
            "method": "session.create",
            "params": {"channel": "cli"},
            "id": 1,
        }
        writer.write(json.dumps(request).encode("utf-8") + b"\n")
        await writer.drain()
        response = JsonRpcResponse.model_validate_json(await reader.readline())
        assert response.error is not None
        assert response.error.code == -32603
        assert response.error.data == {"reason_code": "rpc.internal_error"}
        assert "reason_code=rpc.internal_error" in caplog.text
    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()
        await server.stop()
