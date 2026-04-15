"""A2A socket and HTTP transport adapters."""

from __future__ import annotations

import asyncio
import json
import ssl
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import ParseResult, urlparse

from pydantic import ValidationError

from shisad.interop.a2a_envelope import A2aEnvelope
from shisad.interop.a2a_registry import A2aAgentEntry

type A2aTransportHandler = Callable[[A2aEnvelope], Awaitable[A2aEnvelope | Mapping[str, Any]]]
DEFAULT_A2A_HTTP_MAX_BODY_BYTES = 1 << 20


def _payload_bytes(response: A2aEnvelope | Mapping[str, Any]) -> bytes:
    if isinstance(response, A2aEnvelope):
        payload = response.model_dump(mode="json", by_alias=True)
    else:
        payload = dict(response)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _parse_socket_address(address: str) -> tuple[str, int]:
    host, separator, port_text = str(address).strip().rpartition(":")
    if not host or separator != ":":
        raise ValueError("A2A socket addresses must use host:port")
    port = int(port_text)
    if port <= 0 or port > 65535:
        raise ValueError("A2A socket port must be between 1 and 65535")
    return host, port


def _parse_http_response(payload: bytes) -> tuple[int, bytes]:
    head, separator, body = payload.partition(b"\r\n\r\n")
    if not separator:
        raise ValueError("Malformed HTTP response")
    lines = head.decode("utf-8").split("\r\n")
    if not lines:
        raise ValueError("Malformed HTTP response status line")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2:
        raise ValueError("Malformed HTTP response status line")
    return int(parts[1]), body


def _error_payload(reason: str) -> dict[str, Any]:
    return {"ok": False, "error": reason}


def _format_http_host(host: str) -> str:
    candidate = str(host).strip()
    if ":" in candidate and not candidate.startswith("["):
        return f"[{candidate}]"
    return candidate


def _http_host_header(parsed: ParseResult) -> str:
    host = _format_http_host(str(parsed.hostname))
    port = parsed.port
    if port is None:
        return host
    default_port = 443 if parsed.scheme == "https" else 80
    if port == default_port:
        return host
    return f"{host}:{port}"


def _build_http_response(status: int, payload: A2aEnvelope | Mapping[str, Any]) -> bytes:
    body = _payload_bytes(payload)
    reason = {
        200: "OK",
        400: "Bad Request",
        413: "Payload Too Large",
        404: "Not Found",
        405: "Method Not Allowed",
        500: "Internal Server Error",
    }.get(status, "OK")
    headers = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()
    return headers + body


@dataclass(slots=True)
class A2aTransportListener:
    """Opaque handle for an active A2A listener."""

    transport: str
    address: str
    _server: asyncio.AbstractServer

    async def close(self) -> None:
        self._server.close()
        await self._server.wait_closed()


class SocketTransport:
    """JSON-line framed TCP transport for A2A messages."""

    def __init__(self, *, host: str = "127.0.0.1", port: int = 9820) -> None:
        self._host = host
        self._port = port

    async def send(self, envelope: A2aEnvelope, target: A2aAgentEntry) -> dict[str, Any]:
        if target.transport != "socket":
            raise ValueError("SocketTransport requires a socket target")
        host, port = _parse_socket_address(target.address)
        reader, writer = await asyncio.open_connection(host, port)
        try:
            writer.write(_payload_bytes(envelope) + b"\n")
            await writer.drain()
            raw = await reader.readline()
            if not raw:
                raise RuntimeError("A2A socket transport closed without a response")
            parsed = json.loads(raw.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise ValueError("A2A socket responses must be JSON objects")
            return dict(parsed)
        finally:
            writer.close()
            await writer.wait_closed()

    async def listen(self, handler: A2aTransportHandler) -> A2aTransportListener:
        async def _serve(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            response: A2aEnvelope | Mapping[str, Any] | None = None
            try:
                try:
                    raw = await reader.readline()
                except (ValueError, asyncio.LimitOverrunError):
                    response = _error_payload("invalid_request")
                    raw = b""
                if not raw:
                    if response is None:
                        return
                else:
                    try:
                        envelope = A2aEnvelope.model_validate_json(raw)
                    except (ValidationError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
                        response = _error_payload("invalid_request")
                    else:
                        try:
                            response = await handler(envelope)
                        except Exception:
                            response = _error_payload("internal_error")
                if response is not None:
                    writer.write(_payload_bytes(response) + b"\n")
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(_serve, self._host, self._port)
        bound_port = int(server.sockets[0].getsockname()[1]) if server.sockets else self._port
        return A2aTransportListener(
            transport="socket",
            address=f"{self._host}:{bound_port}",
            _server=server,
        )


class HttpTransport:
    """Minimal HTTP POST transport for A2A messages."""

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 9820,
        path: str = "/a2a",
        max_body_bytes: int = DEFAULT_A2A_HTTP_MAX_BODY_BYTES,
    ) -> None:
        self._host = host
        self._port = port
        self._path = path if path.startswith("/") else "/" + path
        self._max_body_bytes = max(1, int(max_body_bytes))

    async def send(self, envelope: A2aEnvelope, target: A2aAgentEntry) -> dict[str, Any]:
        if target.transport != "http":
            raise ValueError("HttpTransport requires an HTTP target")
        parsed = urlparse(target.address)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("A2A HTTP targets must use full http(s) URLs")
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError as exc:
            raise ValueError(
                "A2A HTTP targets must use bracketed IPv6 literals when needed"
            ) from exc
        path = parsed.path or self._path
        if parsed.query:
            path = f"{path}?{parsed.query}"
        ssl_context = ssl.create_default_context() if parsed.scheme == "https" else None
        reader, writer = await asyncio.open_connection(parsed.hostname, port, ssl=ssl_context)
        body = _payload_bytes(envelope)
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {_http_host_header(parsed)}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode() + body
        try:
            writer.write(request)
            await writer.drain()
            raw_response = await reader.read()
            status, response_body = _parse_http_response(raw_response)
            parsed_payload = json.loads(response_body.decode("utf-8"))
            if not isinstance(parsed_payload, dict):
                raise ValueError("A2A HTTP responses must be JSON objects")
            if status >= 400:
                error = str(parsed_payload.get("error", "")).strip() or f"http_status_{status}"
                raise RuntimeError(error)
            return dict(parsed_payload)
        finally:
            writer.close()
            await writer.wait_closed()

    async def listen(self, handler: A2aTransportHandler) -> A2aTransportListener:
        async def _serve(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            status = 200
            payload: A2aEnvelope | Mapping[str, Any] = _error_payload("invalid_request")
            try:
                head = await reader.readuntil(b"\r\n\r\n")
                header_text = head.decode("utf-8")
                lines = header_text.split("\r\n")
                request_line = lines[0]
                method, path, _version = request_line.split(" ", 2)
                request_target = urlparse(path)
                headers: dict[str, str] = {}
                for line in lines[1:]:
                    if not line:
                        continue
                    key, _separator, value = line.partition(":")
                    headers[key.strip().lower()] = value.strip()
                if method != "POST":
                    status = 405
                    payload = _error_payload("method_not_allowed")
                elif (request_target.path or "/") != self._path:
                    status = 404
                    payload = _error_payload("not_found")
                else:
                    try:
                        content_length = int(headers.get("content-length", "0"))
                    except ValueError:
                        status = 400
                        payload = _error_payload("invalid_content_length")
                    else:
                        if content_length < 0:
                            status = 400
                            payload = _error_payload("invalid_content_length")
                        elif content_length > self._max_body_bytes:
                            status = 413
                            payload = _error_payload("payload_too_large")
                        else:
                            body = await reader.readexactly(content_length)
                            try:
                                envelope = A2aEnvelope.model_validate_json(body)
                            except (
                                ValidationError,
                                ValueError,
                                UnicodeDecodeError,
                                json.JSONDecodeError,
                            ):
                                status = 400
                                payload = _error_payload("invalid_request")
                            else:
                                try:
                                    payload = await handler(envelope)
                                except Exception:
                                    status = 500
                                    payload = _error_payload("internal_error")
            except (
                asyncio.IncompleteReadError,
                asyncio.LimitOverrunError,
                UnicodeDecodeError,
                ValueError,
            ):
                if status == 200:
                    status = 400
                payload = _error_payload("invalid_request")
            except Exception:
                if status == 200:
                    status = 500
                payload = _error_payload("internal_error")
            finally:
                writer.write(_build_http_response(status, payload))
                await writer.drain()
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(_serve, self._host, self._port)
        bound_port = int(server.sockets[0].getsockname()[1]) if server.sockets else self._port
        return A2aTransportListener(
            transport="http",
            address=f"http://{_format_http_host(self._host)}:{bound_port}{self._path}",
            _server=server,
        )
