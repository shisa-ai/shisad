"""Unix domain socket transport for the shisad control API.

JSON-RPC 2.0 over Unix socket with peer credential authentication.
Newline-delimited JSON for message framing.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from pydantic import BaseModel, Field, ValidationError

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
from shisad.core.errors import ShisadError
from shisad.core.interfaces import TypedHandler, TypedMethodRegistration
from shisad.core.request_context import RequestContext

logger = logging.getLogger(__name__)

PERMISSION_DENIED = -32001


class _UntypedParams(BaseModel):
    """Fallback params wrapper for methods without explicit param schema."""

    payload: dict[str, Any] = Field(default_factory=dict)


class PeerCredentials:
    """Peer credentials extracted from Unix socket connection."""

    def __init__(
        self,
        *,
        pid: int | None = None,
        uid: int | None = None,
        gid: int | None = None,
    ) -> None:
        self.pid = pid
        self.uid = uid
        self.gid = gid

    def as_dict(self) -> dict[str, int | None]:
        return {"pid": self.pid, "uid": self.uid, "gid": self.gid}

    @property
    def summary(self) -> str:
        if self.uid is None:
            return "unknown"
        return f"pid={self.pid} uid={self.uid} gid={self.gid}"


@dataclass(slots=True)
class _EventSubscription:
    writer: asyncio.StreamWriter
    event_types: set[str] = field(default_factory=set)
    session_id: str | None = None
    queue: asyncio.Queue[str] = field(default_factory=asyncio.Queue)
    task: asyncio.Task[None] | None = None

    def matches(self, event_data: dict[str, Any]) -> bool:
        if self.event_types:
            event_type = str(event_data.get("event_type", ""))
            if event_type not in self.event_types:
                return False
        return self.session_id is None or str(event_data.get("session_id")) == self.session_id


class ControlServer:
    """Unix domain socket server implementing JSON-RPC 2.0.

    Authenticates connections via SO_PEERCRED (peer credentials).
    Each connection is handled in a separate asyncio task.
    """

    def __init__(self, socket_path: Path, *, event_queue_size: int = 256) -> None:
        self._socket_path = socket_path
        self._server: asyncio.Server | None = None
        self._methods: dict[str, TypedMethodRegistration] = {}
        self._event_subscribers: dict[asyncio.StreamWriter, _EventSubscription] = {}
        self._event_queue_size = event_queue_size

    @property
    def subscriber_count(self) -> int:
        return len(self._event_subscribers)

    def register_method(
        self,
        name: str,
        handler: TypedHandler,
        *,
        admin_only: bool = False,
        params_model: type[BaseModel] | None = None,
    ) -> None:
        """Register a JSON-RPC method handler."""
        self._methods[name] = (handler, admin_only, params_model)

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
        for writer in list(self._event_subscribers):
            await self._remove_subscription(writer, close_writer=True)

        # Clean up socket file
        if self._socket_path.exists():
            self._socket_path.unlink()

        logger.info("Control API stopped")

    async def broadcast_event(self, event_data: dict[str, Any]) -> None:
        """Broadcast an event to all subscribed connections (SSE-style)."""
        line = json.dumps(event_data) + "\n"
        for writer, subscription in list(self._event_subscribers.items()):
            if not subscription.matches(event_data):
                continue
            try:
                subscription.queue.put_nowait(line)
            except asyncio.QueueFull:
                logger.warning(
                    "Dropping event subscriber due to backpressure (queue full): %s",
                    writer,
                )
                await self._remove_subscription(writer, close_writer=True)

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single client connection."""
        peer = self._get_peer_credentials(writer)
        logger.debug("Connection from %s", peer.summary)

        try:
            while True:
                line = await reader.readline()
                if not line:
                    break

                response = await self._process_message(line, peer, writer=writer)
                writer.write(response.encode() + b"\n")
                await writer.drain()
        except asyncio.CancelledError:
            pass
        except (
            ConnectionError,
            OSError,
            RuntimeError,
            UnicodeDecodeError,
            ValueError,
            ValidationError,
        ):
            logger.exception("Error handling connection")
        finally:
            await self._remove_subscription(writer, close_writer=False)
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass

    async def _process_message(
        self,
        raw: bytes,
        peer: PeerCredentials,
        *,
        writer: asyncio.StreamWriter | None = None,
    ) -> str:
        """Parse and dispatch a JSON-RPC message."""
        # Parse JSON
        try:
            data = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as e:
            return self._error_response(
                None,
                PARSE_ERROR,
                f"Parse error: {e}",
                reason_code="rpc.parse_error",
            )

        # Validate request structure
        try:
            request = JsonRpcRequest.model_validate(data)
        except ValidationError as e:
            request_id = (
                self._sanitize_request_id(data.get("id")) if isinstance(data, dict) else None
            )
            return self._error_response(
                request_id,
                INVALID_REQUEST,
                f"Invalid request: {e}",
                reason_code="rpc.invalid_request",
            )

        # Handle event subscription
        if request.method == "events.subscribe":
            if writer is None:
                return self._error_response(
                    request.id,
                    INVALID_PARAMS,
                    "events.subscribe requires an active connection",
                    reason_code="rpc.subscription_requires_connection",
                )
            try:
                event_types, session_id = self._parse_subscription_filters(request.params)
            except ValueError as exc:
                return self._error_response(
                    request.id,
                    INVALID_PARAMS,
                    str(exc),
                    reason_code="rpc.subscription_filter_invalid",
                )
            await self._register_event_subscription(writer, event_types, session_id)
            return self._success_response(
                request.id,
                {
                    "subscribed": True,
                    "event_types": sorted(event_types),
                    "session_id": session_id,
                    "backpressure": "disconnect_on_queue_full",
                },
            )

        # Dispatch to method handler
        method_entry = self._methods.get(request.method)
        if method_entry is None:
            return self._error_response(
                request.id,
                METHOD_NOT_FOUND,
                f"Method not found: {request.method}",
                reason_code="rpc.method_not_found",
            )
        handler, admin_only, params_model = method_entry
        if admin_only and not self._is_admin_peer(peer):
            return self._error_response(
                request.id,
                PERMISSION_DENIED,
                "Permission denied: admin peer credentials required",
                reason_code="rpc.permission_denied",
            )

        try:
            if params_model is not None:
                # Preserve caller tri-state semantics for optional fields.
                params = params_model.model_validate(request.params)
            else:
                params = _UntypedParams(payload=dict(request.params))
        except (TypeError, ValueError, ValidationError) as e:
            return self._error_response(
                request.id,
                INVALID_PARAMS,
                str(e),
                reason_code="rpc.invalid_params",
            )

        try:
            ctx = RequestContext(rpc_peer=peer.as_dict())
            result = await handler(params, ctx)
            if isinstance(result, BaseModel):
                payload = result.model_dump(mode="json", exclude_unset=True)
            else:
                payload = result
            return self._success_response(request.id, payload)
        except ShisadError as exc:
            logger.warning(
                "Method %s failed (%s); reason_code=%s",
                request.method,
                exc.__class__.__name__,
                exc.reason_code,
            )
            logger.debug("Method %s error detail: %s", request.method, exc)
            return self._error_response(
                request.id,
                exc.rpc_code,
                exc.public_message,
                reason_code=exc.reason_code,
            )
        except ValidationError:
            logger.exception("Method %s returned invalid response shape", request.method)
            return self._error_response(
                request.id,
                INTERNAL_ERROR,
                "Internal error",
                reason_code="rpc.response_validation_failed",
            )
        except (TypeError, ValueError) as e:
            return self._error_response(
                request.id,
                INVALID_PARAMS,
                str(e),
                reason_code="rpc.invalid_params",
            )
        except Exception:
            logger.exception("Method %s failed; reason_code=rpc.internal_error", request.method)
            return self._error_response(
                request.id,
                INTERNAL_ERROR,
                "Internal error",
                reason_code="rpc.internal_error",
            )

    @staticmethod
    def _parse_subscription_filters(
        params: dict[str, Any],
    ) -> tuple[set[str], str | None]:
        event_types: set[str] = set()
        raw_event_types = params.get("event_types")
        if isinstance(raw_event_types, list):
            for item in raw_event_types:
                if not isinstance(item, str) or not item:
                    raise ValueError("event_types must be a list of non-empty strings")
                event_types.add(item)
        elif raw_event_types is not None:
            raise ValueError("event_types must be a list of strings")

        raw_event_type = params.get("event_type")
        if isinstance(raw_event_type, str) and raw_event_type:
            event_types.add(raw_event_type)
        elif raw_event_type is not None and not isinstance(raw_event_type, str):
            raise ValueError("event_type must be a string")

        raw_session_id = params.get("session_id")
        if raw_session_id is None:
            session_id: str | None = None
        elif isinstance(raw_session_id, str) and raw_session_id:
            session_id = raw_session_id
        else:
            raise ValueError("session_id must be a non-empty string")

        return event_types, session_id

    async def _register_event_subscription(
        self,
        writer: asyncio.StreamWriter,
        event_types: set[str],
        session_id: str | None,
    ) -> None:
        await self._remove_subscription(writer, close_writer=False)
        subscription = _EventSubscription(
            writer=writer,
            event_types=set(event_types),
            session_id=session_id,
            queue=asyncio.Queue(maxsize=self._event_queue_size),
        )
        subscription.task = asyncio.create_task(self._stream_events(subscription))
        self._event_subscribers[writer] = subscription

    async def _remove_subscription(
        self,
        writer: asyncio.StreamWriter,
        *,
        close_writer: bool,
    ) -> None:
        subscription = self._event_subscribers.pop(writer, None)
        if subscription is None:
            return
        current_task = asyncio.current_task()
        if subscription.task is not None and subscription.task is not current_task:
            subscription.task.cancel()
            with contextlib.suppress(asyncio.CancelledError, RuntimeError, OSError):
                await subscription.task
        elif subscription.task is not None:
            subscription.task.cancel()
        if close_writer:
            with contextlib.suppress(OSError, RuntimeError):
                writer.close()

    async def _stream_events(self, subscription: _EventSubscription) -> None:
        writer = subscription.writer
        try:
            while True:
                line = await subscription.queue.get()
                writer.write(line.encode("utf-8"))
                await writer.drain()
        except asyncio.CancelledError:
            raise
        except (ConnectionError, OSError, RuntimeError):
            logger.debug("Event subscriber disconnected: %s", writer)
            await self._remove_subscription(writer, close_writer=False)

    @staticmethod
    def _success_response(req_id: str | int | None, result: Any) -> str:
        resp = JsonRpcResponse(id=req_id, result=result)
        return resp.model_dump_json()

    @staticmethod
    def _sanitize_request_id(value: Any) -> str | int | None:
        if isinstance(value, str):
            return value
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        return None

    @staticmethod
    def _default_reason_code(code: int) -> str:
        if code == PARSE_ERROR:
            return "rpc.parse_error"
        if code == INVALID_REQUEST:
            return "rpc.invalid_request"
        if code == METHOD_NOT_FOUND:
            return "rpc.method_not_found"
        if code == INVALID_PARAMS:
            return "rpc.invalid_params"
        if code == INTERNAL_ERROR:
            return "rpc.internal_error"
        if code == PERMISSION_DENIED:
            return "rpc.permission_denied"
        return "rpc.error"

    @classmethod
    def _error_response(
        cls,
        req_id: str | int | None,
        code: int,
        message: str,
        *,
        reason_code: str | None = None,
    ) -> str:
        safe_id = cls._sanitize_request_id(req_id)
        resp = JsonRpcResponse(
            id=safe_id,
            error=JsonRpcError(
                code=code,
                message=message,
                data={"reason_code": reason_code or cls._default_reason_code(code)},
            ),
        )
        return resp.model_dump_json()

    @staticmethod
    def _get_peer_credentials(writer: asyncio.StreamWriter) -> PeerCredentials:
        """Extract peer credentials from the socket (Linux SO_PEERCRED)."""
        try:
            sock = writer.get_extra_info("socket")
            if sock is not None:
                SO_PEERCRED = 17  # Linux-specific
                cred = sock.getsockopt(1, SO_PEERCRED, struct.calcsize("3i"))  # SOL_SOCKET=1
                pid, uid, gid = struct.unpack("3i", cred)
                return PeerCredentials(pid=pid, uid=uid, gid=gid)
        except OSError:
            pass
        return PeerCredentials()

    @staticmethod
    def _is_admin_peer(peer: PeerCredentials) -> bool:
        """Authorize admin-only methods based on peer uid."""
        if peer.uid is None:
            return False
        return peer.uid in {0, os.getuid()}


class ControlClient:
    """Client for connecting to the shisad control API."""

    def __init__(self, socket_path: Path) -> None:
        self._socket_path = socket_path
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._request_id = 0

    async def connect(self) -> None:
        """Connect to the daemon."""
        self._reader, self._writer = await asyncio.open_unix_connection(str(self._socket_path))

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

    async def subscribe_events(
        self,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Subscribe to event stream on the current connection."""
        result = await self.call("events.subscribe", params=params or {})
        if not isinstance(result, dict):
            raise RuntimeError("Invalid subscribe response")
        return result

    async def read_event(self) -> dict[str, Any]:
        """Read one event line from a subscribed stream."""
        if self._reader is None:
            raise RuntimeError("Not connected")
        line = await self._reader.readline()
        if not line:
            raise ConnectionError("Connection closed")
        return cast(dict[str, Any], json.loads(line))
