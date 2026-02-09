"""Control API event subscription behavior."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from shisad.core.api.schema import JsonRpcResponse
from shisad.core.api.transport import ControlServer


async def _subscribe(
    socket_path: Path,
    params: dict[str, object],
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.open_unix_connection(str(socket_path))
    request = {
        "jsonrpc": "2.0",
        "method": "events.subscribe",
        "params": params,
        "id": 1,
    }
    writer.write(json.dumps(request).encode("utf-8") + b"\n")
    await writer.drain()

    ack = await asyncio.wait_for(reader.readline(), timeout=1.0)
    response = JsonRpcResponse.model_validate_json(ack)
    assert response.error is None
    assert response.result["subscribed"] is True
    return reader, writer


@pytest.mark.asyncio
async def test_event_subscription_filters_by_event_type_and_session_id(tmp_path: Path) -> None:
    server = ControlServer(tmp_path / "control.sock")
    await server.start()
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None

    try:
        reader, writer = await _subscribe(
            tmp_path / "control.sock",
            {"event_types": ["ToolRejected"], "session_id": "s1"},
        )

        await server.broadcast_event({"event_type": "ToolApproved", "session_id": "s1"})
        await server.broadcast_event({"event_type": "ToolRejected", "session_id": "s2"})
        await server.broadcast_event(
            {"event_type": "ToolRejected", "session_id": "s1", "payload": "hit"}
        )

        line = await asyncio.wait_for(reader.readline(), timeout=1.0)
        event = json.loads(line.decode("utf-8"))
        assert event["event_type"] == "ToolRejected"
        assert event["session_id"] == "s1"
        assert event["payload"] == "hit"

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(reader.readline(), timeout=0.1)
    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()
        await server.stop()


@pytest.mark.asyncio
async def test_event_subscription_drops_slow_subscriber_on_backpressure(tmp_path: Path) -> None:
    server = ControlServer(tmp_path / "control.sock", event_queue_size=1)
    await server.start()
    writer: asyncio.StreamWriter | None = None

    try:
        _, writer = await _subscribe(tmp_path / "control.sock", {})
        assert server.subscriber_count == 1

        for i in range(10):
            await server.broadcast_event(
                {"event_type": "SessionCreated", "session_id": f"s{i}", "index": i}
            )

        assert server.subscriber_count == 0
    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()
        await server.stop()
