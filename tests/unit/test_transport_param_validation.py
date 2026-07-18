"""Transport-level per-method parameter schema validation."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest
from pydantic import BaseModel

from shisad.core.api.schema import JsonRpcResponse, SessionCreateParams
from shisad.core.api.transport import ControlServer
from shisad.core.errors import PolicyError
from shisad.daemon.context import RequestContext


@pytest.mark.asyncio
async def test_transport_rejects_extra_params_when_model_is_registered(tmp_path: Path) -> None:
    server = ControlServer(tmp_path / "control.sock")

    async def _handler(params: SessionCreateParams, ctx: RequestContext) -> dict[str, object]:
        return {"ok": True, "params": params.model_dump(mode="json"), "uid": ctx.rpc_peer}

    server.register_method("session.create", _handler, params_model=SessionCreateParams)
    await server.start()
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.open_unix_connection(str(tmp_path / "control.sock"))
        request = {
            "jsonrpc": "2.0",
            "method": "session.create",
            "params": {
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "trust_level": "trusted",
            },
            "id": 1,
        }
        writer.write(json.dumps(request).encode("utf-8") + b"\n")
        await writer.drain()
        response = JsonRpcResponse.model_validate_json(await reader.readline())
        assert response.error is not None
        assert response.error.code == -32602
        assert response.error.data == {"reason_code": "rpc.invalid_params"}
    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()
        await server.stop()


@pytest.mark.asyncio
async def test_transport_preserves_model_field_tristate_and_hides_rpc_peer(
    tmp_path: Path,
) -> None:
    server = ControlServer(tmp_path / "control.sock")
    captured: dict[str, object] = {}

    async def _handler(params: SessionCreateParams, ctx: RequestContext) -> dict[str, object]:
        captured["fields_set"] = sorted(params.model_fields_set)
        captured["dump"] = params.model_dump(mode="json", exclude_unset=True)
        captured["ctx_peer"] = ctx.rpc_peer
        return {"ok": True}

    server.register_method("session.create", _handler, params_model=SessionCreateParams)
    await server.start()
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.open_unix_connection(str(tmp_path / "control.sock"))
        request = {
            "jsonrpc": "2.0",
            "method": "session.create",
            "params": {"channel": "cli"},
            "id": 2,
        }
        writer.write(json.dumps(request).encode("utf-8") + b"\n")
        await writer.drain()
        response = JsonRpcResponse.model_validate_json(await reader.readline())
        assert response.error is None

        assert captured["fields_set"] == ["channel"]
        assert captured["dump"] == {"channel": "cli"}
        peer = captured["ctx_peer"]
        assert isinstance(peer, dict)
        assert peer["uid"] == os.getuid()
    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()
        await server.stop()


@pytest.mark.asyncio
async def test_transport_handles_non_object_invalid_request_without_crashing(
    tmp_path: Path,
) -> None:
    server = ControlServer(tmp_path / "control.sock")
    await server.start()
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.open_unix_connection(str(tmp_path / "control.sock"))
        writer.write(b"[]\n")
        await writer.drain()
        response = JsonRpcResponse.model_validate_json(await reader.readline())
        assert response.error is not None
        assert response.error.code == -32600
        assert response.id is None
    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()
        await server.stop()


@pytest.mark.asyncio
async def test_transport_returns_parse_error_for_non_utf8_frame(tmp_path: Path) -> None:
    server = ControlServer(tmp_path / "control.sock")
    await server.start()
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.open_unix_connection(str(tmp_path / "control.sock"))
        writer.write(b"\xff\n")
        await writer.drain()
        response = JsonRpcResponse.model_validate_json(await reader.readline())
        assert response.error is not None
        assert response.error.code == -32700
        assert response.error.data == {"reason_code": "rpc.parse_error"}
        assert response.id is None
    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()
        await server.stop()


@pytest.mark.asyncio
async def test_transport_maps_handler_validation_error_to_internal_error(
    tmp_path: Path,
) -> None:
    server = ControlServer(tmp_path / "control.sock")

    class _ResponseEnvelope(BaseModel):
        ok: bool

    async def _handler(params: SessionCreateParams, ctx: RequestContext) -> dict[str, object]:
        _ = params, ctx
        _ResponseEnvelope.model_validate({"unexpected": "shape"})
        return {"ok": True}

    server.register_method("session.create", _handler, params_model=SessionCreateParams)
    await server.start()
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.open_unix_connection(str(tmp_path / "control.sock"))
        request = {
            "jsonrpc": "2.0",
            "method": "session.create",
            "params": {"channel": "cli"},
            "id": 3,
        }
        writer.write(json.dumps(request).encode("utf-8") + b"\n")
        await writer.drain()
        response = JsonRpcResponse.model_validate_json(await reader.readline())
        assert response.error is not None
        assert response.error.code == -32603
        assert response.error.message == "Internal error"
    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()
        await server.stop()


@pytest.mark.asyncio
async def test_transport_invalid_request_sanitizes_non_scalar_id(
    tmp_path: Path,
) -> None:
    server = ControlServer(tmp_path / "control.sock")
    await server.start()
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.open_unix_connection(str(tmp_path / "control.sock"))
        request = {
            "jsonrpc": "2.0",
            "method": "session.create",
            "params": {"channel": "cli", "user_id": "alice"},
            "id": [],
        }
        writer.write(json.dumps(request).encode("utf-8") + b"\n")
        await writer.drain()
        response = JsonRpcResponse.model_validate_json(await reader.readline())
        assert response.error is not None
        assert response.error.code == -32600
        assert response.id is None
    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()
        await server.stop()


@pytest.mark.asyncio
async def test_transport_invalid_request_rejects_boolean_id(
    tmp_path: Path,
) -> None:
    server = ControlServer(tmp_path / "control.sock")
    await server.start()
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.open_unix_connection(str(tmp_path / "control.sock"))
        request = {
            "jsonrpc": "2.0",
            "method": "session.create",
            "params": {"channel": "cli", "user_id": "alice"},
            "id": True,
        }
        writer.write(json.dumps(request).encode("utf-8") + b"\n")
        await writer.drain()
        response = JsonRpcResponse.model_validate_json(await reader.readline())
        assert response.error is not None
        assert response.error.code == -32600
        assert response.id is None
        assert response.error.data == {"reason_code": "rpc.invalid_request"}
    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()
        await server.stop()


@pytest.mark.asyncio
async def test_transport_maps_shisad_errors_to_structured_reason_codes(
    tmp_path: Path,
) -> None:
    server = ControlServer(tmp_path / "control.sock")

    async def _handler(params: SessionCreateParams, ctx: RequestContext) -> dict[str, object]:
        _ = params, ctx
        raise PolicyError(
            "capability denied",
            reason_code="policy.capability_denied",
            details={"capability": "network"},
        )

    server.register_method("session.create", _handler, params_model=SessionCreateParams)
    await server.start()
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.open_unix_connection(str(tmp_path / "control.sock"))
        request = {
            "jsonrpc": "2.0",
            "method": "session.create",
            "params": {"channel": "cli"},
            "id": 4,
        }
        writer.write(json.dumps(request).encode("utf-8") + b"\n")
        await writer.drain()
        response = JsonRpcResponse.model_validate_json(await reader.readline())
        assert response.error is not None
        assert response.error.code == -32602
        assert response.error.message == "capability denied"
        assert response.error.data == {"reason_code": "policy.capability_denied"}
    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()
        await server.stop()
