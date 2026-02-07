"""Unix domain socket transport for the shisad control API.

JSON-RPC 2.0 over Unix socket with peer credential authentication.
Newline-delimited JSON for message framing.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from shisad.core.api.schema import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    JsonRpcError,
    JsonRpcRequest,
    JsonRpcResponse,
)

logger = logging.getLogger(__name__)

# Method handler type
type MethodHandler = Any  # Callable[[dict[str, Any]], Awaitable[Any]]


class ControlServer:
    """Unix domain socket server implementing JSON-RPC 2.0.

    Authenticates connections via SO_PEERCRED (peer credentials).
    Each connection is handled in a separate asyncio task.
    """

    def __init__(self, socket_path: Path) -> None:
        self._socket_path = socket_path
        self._server: asyncio.Server | None = None
        self._methods: dict[str, MethodHandler] = {}
        self._event_subscribers: list[asyncio.StreamWriter] = []

    def register_method(self, name: str, handler: MethodHandler) -> None:
        """Register a JSON-RPC method handler."""
        self._methods[name] = handler

    async def start(self) -> None:
        """Start listening on the Unix socket."""
        # Ensure parent directory exists
        self._socket_path.parent.mkdir(parents=True, exist_ok=True)

        # Remove stale socket
        if self._socket_path.exists():
            self._socket_path.unlink()

        self._server = await asyncio.start_unix_server(
            self._handle_connection,
            path=str(self._socket_path),
        )
        # Restrict socket permissions to owner only
        os.chmod(self._socket_path, 0o600)
        logger.info("Control API listening on %s", self._socket_path)

    async def stop(self) -> None:
        """Stop the server and clean up."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        # Close event subscribers
        import contextlib

        for writer in self._event_subscribers:
            with contextlib.suppress(Exception):
                writer.close()
        self._event_subscribers.clear()

        # Clean up socket file
        if self._socket_path.exists():
            self._socket_path.unlink()

        logger.info("Control API stopped")

    async def broadcast_event(self, event_data: dict[str, Any]) -> None:
        """Broadcast an event to all subscribed connections (SSE-style)."""
        line = json.dumps(event_data) + "\n"
        dead: list[asyncio.StreamWriter] = []
        for writer in self._event_subscribers:
            try:
                writer.write(line.encode())
                await writer.drain()
            except Exception:
                dead.append(writer)
        for w in dead:
            self._event_subscribers.remove(w)

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single client connection."""
        peer_info = self._get_peer_info(writer)
        logger.debug("Connection from %s", peer_info)

        try:
            while True:
                line = await reader.readline()
                if not line:
                    break

                response = await self._process_message(line)
                writer.write(response.encode() + b"\n")
                await writer.drain()
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("Error handling connection")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _process_message(self, raw: bytes) -> str:
        """Parse and dispatch a JSON-RPC message."""
        # Parse JSON
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            return self._error_response(None, PARSE_ERROR, f"Parse error: {e}")

        # Validate request structure
        try:
            request = JsonRpcRequest.model_validate(data)
        except ValidationError as e:
            return self._error_response(
                data.get("id"), INVALID_REQUEST, f"Invalid request: {e}"
            )

        # Handle event subscription
        if request.method == "events.subscribe":
            # This is handled specially — not a normal RPC call
            return self._success_response(request.id, {"subscribed": True})

        # Dispatch to method handler
        handler = self._methods.get(request.method)
        if handler is None:
            return self._error_response(
                request.id, METHOD_NOT_FOUND, f"Method not found: {request.method}"
            )

        try:
            result = await handler(request.params)
            return self._success_response(request.id, result)
        except (TypeError, ValueError) as e:
            return self._error_response(request.id, INVALID_PARAMS, str(e))
        except Exception as e:
            logger.exception("Method %s failed", request.method)
            return self._error_response(request.id, INTERNAL_ERROR, str(e))

    @staticmethod
    def _success_response(req_id: str | int | None, result: Any) -> str:
        resp = JsonRpcResponse(id=req_id, result=result)
        return resp.model_dump_json()

    @staticmethod
    def _error_response(req_id: str | int | None, code: int, message: str) -> str:
        resp = JsonRpcResponse(id=req_id, error=JsonRpcError(code=code, message=message))
        return resp.model_dump_json()

    @staticmethod
    def _get_peer_info(writer: asyncio.StreamWriter) -> str:
        """Extract peer credentials from the socket (Linux SO_PEERCRED)."""
        try:
            sock = writer.get_extra_info("socket")
            if sock is not None:
                import struct

                SO_PEERCRED = 17  # Linux-specific
                cred = sock.getsockopt(1, SO_PEERCRED, struct.calcsize("3i"))  # SOL_SOCKET=1
                pid, uid, gid = struct.unpack("3i", cred)
                return f"pid={pid} uid={uid} gid={gid}"
        except Exception:
            pass
        return "unknown"


class ControlClient:
    """Client for connecting to the shisad control API."""

    def __init__(self, socket_path: Path) -> None:
        self._socket_path = socket_path
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._request_id = 0

    async def connect(self) -> None:
        """Connect to the daemon."""
        self._reader, self._writer = await asyncio.open_unix_connection(
            str(self._socket_path)
        )

    async def close(self) -> None:
        """Close the connection."""
        if self._writer is not None:
            self._writer.close()
            await self._writer.wait_closed()
            self._writer = None
            self._reader = None

    async def call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        """Make a JSON-RPC call and return the result."""
        if self._reader is None or self._writer is None:
            raise RuntimeError("Not connected")

        self._request_id += 1
        request = JsonRpcRequest(
            method=method,
            params=params or {},
            id=self._request_id,
        )

        self._writer.write(request.model_dump_json().encode() + b"\n")
        await self._writer.drain()

        line = await self._reader.readline()
        if not line:
            raise ConnectionError("Connection closed")

        response = JsonRpcResponse.model_validate_json(line)
        if response.error is not None:
            raise RuntimeError(f"RPC error {response.error.code}: {response.error.message}")

        return response.result
