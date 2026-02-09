"""Transport-level per-method parameter schema validation."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from shisad.core.api.schema import JsonRpcResponse, SessionCreateParams
from shisad.core.api.transport import ControlServer


@pytest.mark.asyncio
async def test_transport_rejects_extra_params_when_model_is_registered(tmp_path: Path) -> None:
    server = ControlServer(tmp_path / "control.sock")

    async def _handler(params: dict[str, object]) -> dict[str, object]:
        return {"ok": True, "params": params}

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
    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()
        await server.stop()
