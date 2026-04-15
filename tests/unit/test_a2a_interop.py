"""I3 A2A unit coverage for envelope, registry, keygen, transport, and ingress."""

from __future__ import annotations

import asyncio
import json
import socket
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner

from shisad.cli import main as cli_main
from shisad.core.api.schema import (
    SessionCreateParams,
    SessionCreateResult,
    SessionMessageParams,
    SessionMessageResult,
)
from shisad.core.config import DaemonConfig
from shisad.core.request_context import RequestContext
from shisad.core.types import TaintLabel
from shisad.interop.a2a_envelope import (
    A2aEnvelope,
    ReplayCache,
    attach_signature,
    create_envelope,
    fingerprint_for_public_key,
    generate_ed25519_keypair,
    parse_a2a_timestamp,
    serialize_public_key_pem,
    sign_envelope,
    verify_envelope,
    write_ed25519_keypair,
)
from shisad.interop.a2a_ingress import A2aIngress, A2aIngressError
from shisad.interop.a2a_registry import (
    A2aAgentConfig,
    A2aConfig,
    A2aIdentityConfig,
    A2aRegistry,
    load_local_identity,
)
from shisad.interop.a2a_transport import HttpTransport, SocketTransport
from shisad.security.firewall import ContentFirewall


def _reserve_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _signed_request(
    *,
    private_key,
    sender_agent_id: str,
    sender_fingerprint: str,
    recipient_agent_id: str,
    intent: str = "query",
    payload: dict[str, object] | None = None,
    timestamp: datetime | None = None,
) -> A2aEnvelope:
    envelope = create_envelope(
        from_agent_id=sender_agent_id,
        from_fingerprint=sender_fingerprint,
        to_agent_id=recipient_agent_id,
        message_type="request",
        intent=intent,
        payload=dict(payload or {"content": "hello from remote agent"}),
        timestamp=timestamp,
    )
    return attach_signature(envelope, sign_envelope(envelope, private_key))


def test_a2a_envelope_sign_verify_round_trip() -> None:
    private_key, public_key = generate_ed25519_keypair()
    envelope = _signed_request(
        private_key=private_key,
        sender_agent_id="alice-agent",
        sender_fingerprint=fingerprint_for_public_key(public_key),
        recipient_agent_id="bob-agent",
    )

    assert verify_envelope(envelope, public_key) is True


def test_a2a_envelope_rejects_tampered_payload() -> None:
    private_key, public_key = generate_ed25519_keypair()
    envelope = _signed_request(
        private_key=private_key,
        sender_agent_id="alice-agent",
        sender_fingerprint=fingerprint_for_public_key(public_key),
        recipient_agent_id="bob-agent",
        payload={"content": "original"},
    )
    tampered = envelope.model_copy(update={"payload": {"content": "tampered"}})

    assert verify_envelope(tampered, public_key) is False


def test_a2a_envelope_rejects_missing_signature() -> None:
    _private_key, public_key = generate_ed25519_keypair()
    envelope = create_envelope(
        from_agent_id="alice-agent",
        from_fingerprint=fingerprint_for_public_key(public_key),
        to_agent_id="bob-agent",
        message_type="request",
        intent="query",
        payload={"content": "unsigned"},
    )

    assert verify_envelope(envelope, public_key) is False


def test_a2a_envelope_rejects_wrong_signing_key() -> None:
    alice_private, alice_public = generate_ed25519_keypair()
    _bob_private, bob_public = generate_ed25519_keypair()
    envelope = _signed_request(
        private_key=alice_private,
        sender_agent_id="alice-agent",
        sender_fingerprint=fingerprint_for_public_key(alice_public),
        recipient_agent_id="bob-agent",
    )

    assert verify_envelope(envelope, bob_public) is False


def test_a2a_envelope_rejects_invalid_agent_id() -> None:
    _private_key, public_key = generate_ed25519_keypair()

    with pytest.raises(ValueError, match="agent_id must match"):
        create_envelope(
            from_agent_id="alice agent",
            from_fingerprint=fingerprint_for_public_key(public_key),
            to_agent_id="bob-agent",
            message_type="request",
            intent="query",
            payload={"content": "invalid"},
        )


def test_replay_cache_rejects_duplicate_message_ids_within_window() -> None:
    private_key, public_key = generate_ed25519_keypair()
    now = datetime(2026, 4, 15, 12, 0, tzinfo=UTC)
    envelope = _signed_request(
        private_key=private_key,
        sender_agent_id="alice-agent",
        sender_fingerprint=fingerprint_for_public_key(public_key),
        recipient_agent_id="bob-agent",
        timestamp=now,
    )
    cache = ReplayCache(window_seconds=300)

    first = cache.check(envelope, now=now)
    duplicate = cache.check(envelope, now=now + timedelta(seconds=30))

    assert first.allowed is True
    assert duplicate.allowed is False
    assert duplicate.reason == "replay_detected"


def test_replay_cache_rejects_timestamps_outside_window() -> None:
    private_key, public_key = generate_ed25519_keypair()
    now = datetime(2026, 4, 15, 12, 0, tzinfo=UTC)
    stale_time = now - timedelta(minutes=6)
    envelope = _signed_request(
        private_key=private_key,
        sender_agent_id="alice-agent",
        sender_fingerprint=fingerprint_for_public_key(public_key),
        recipient_agent_id="bob-agent",
        timestamp=stale_time,
    )
    cache = ReplayCache(window_seconds=300)

    result = cache.check(envelope, now=now)

    assert parse_a2a_timestamp(envelope.timestamp) == stale_time
    assert result.allowed is False
    assert result.reason == "timestamp_out_of_window"


def test_replay_cache_rejects_replay_until_future_skew_window_expires() -> None:
    private_key, public_key = generate_ed25519_keypair()
    now = datetime(2026, 4, 15, 12, 0, tzinfo=UTC)
    future_time = now + timedelta(minutes=5)
    envelope = _signed_request(
        private_key=private_key,
        sender_agent_id="alice-agent",
        sender_fingerprint=fingerprint_for_public_key(public_key),
        recipient_agent_id="bob-agent",
        timestamp=future_time,
    )
    cache = ReplayCache(window_seconds=300)

    first = cache.check(envelope, now=now)
    duplicate = cache.check(envelope, now=now + timedelta(seconds=301))

    assert first.allowed is True
    assert duplicate.allowed is False
    assert duplicate.reason == "replay_detected"


def test_a2a_registry_loads_agent_entries_and_validates_fingerprint(tmp_path: Path) -> None:
    private_key, public_key = generate_ed25519_keypair()
    _unused_private = private_key
    public_key_path = tmp_path / "remote.pub"
    public_key_path.write_bytes(serialize_public_key_pem(public_key))
    fingerprint = fingerprint_for_public_key(public_key)
    config = A2aConfig(
        agents=[
            A2aAgentConfig(
                agent_id="alice-agent",
                fingerprint=fingerprint,
                public_key_path=public_key_path,
                address="127.0.0.1:9820",
                transport="socket",
            )
        ]
    )

    registry = A2aRegistry.from_config(config)
    entry = registry.require("alice-agent")

    assert entry.agent_id == "alice-agent"
    assert entry.address == "127.0.0.1:9820"
    assert entry.transport == "socket"
    assert fingerprint_for_public_key(entry.public_key) == fingerprint


def test_cli_a2a_keygen_writes_valid_owner_only_private_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key_path = tmp_path / "keys" / "a2a-private.pem"
    public_key_path = tmp_path / "keys" / "a2a-public.pem"
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        a2a=A2aConfig(
            identity=A2aIdentityConfig(
                agent_id="local-agent",
                private_key_path=private_key_path,
                public_key_path=public_key_path,
            )
        ),
    )
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)
    runner = CliRunner()

    result = runner.invoke(cli_main.cli, ["a2a", "keygen"])

    assert result.exit_code == 0, result.output
    assert private_key_path.exists()
    assert public_key_path.exists()
    assert stat.S_IMODE(private_key_path.stat().st_mode) == 0o600
    assert "Fingerprint: sha256:" in result.output
    local_identity = load_local_identity(config.a2a.identity)
    assert local_identity.fingerprint in result.output
    assert f"Verified public fingerprint: {local_identity.fingerprint}" in result.output


def test_cli_a2a_keygen_rejects_existing_key_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key_path = tmp_path / "keys" / "a2a-private.pem"
    public_key_path = tmp_path / "keys" / "a2a-public.pem"
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        a2a=A2aConfig(
            identity=A2aIdentityConfig(
                agent_id="local-agent",
                private_key_path=private_key_path,
                public_key_path=public_key_path,
            )
        ),
    )
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)
    runner = CliRunner()

    first = runner.invoke(cli_main.cli, ["a2a", "keygen"])
    second = runner.invoke(cli_main.cli, ["a2a", "keygen"])

    assert first.exit_code == 0, first.output
    assert second.exit_code != 0
    assert "A2A key output already exists" in second.output


@pytest.mark.asyncio
async def test_socket_transport_round_trip() -> None:
    server_private, server_public = generate_ed25519_keypair()
    client_private, client_public = generate_ed25519_keypair()
    server_fingerprint = fingerprint_for_public_key(server_public)
    client_fingerprint = fingerprint_for_public_key(client_public)
    listen_port = _reserve_local_port()
    registry = A2aRegistry.from_config(
        A2aConfig(
            agents=[
                A2aAgentConfig(
                    agent_id="server-agent",
                    fingerprint=server_fingerprint,
                    public_key=serialize_public_key_pem(server_public).decode("utf-8"),
                    address=f"127.0.0.1:{listen_port}",
                    transport="socket",
                )
            ]
        )
    )
    transport = SocketTransport(host="127.0.0.1", port=listen_port)
    listener = await transport.listen(
        lambda envelope: _echo_response(envelope, server_private, server_fingerprint)
    )
    try:
        target = registry.require("server-agent")
        envelope = _signed_request(
            private_key=client_private,
            sender_agent_id="client-agent",
            sender_fingerprint=client_fingerprint,
            recipient_agent_id="server-agent",
            payload={"content": "socket hello"},
        )
        raw_response = await SocketTransport().send(envelope, target)
        response = A2aEnvelope.model_validate(raw_response)
    finally:
        await listener.close()

    assert response.payload["ok"] is True
    assert response.payload["echo"] == "socket hello"
    assert verify_envelope(response, server_public) is True


@pytest.mark.asyncio
async def test_socket_transport_returns_reason_coded_error_on_handler_failure() -> None:
    _server_private, server_public = generate_ed25519_keypair()
    client_private, client_public = generate_ed25519_keypair()
    server_fingerprint = fingerprint_for_public_key(server_public)
    client_fingerprint = fingerprint_for_public_key(client_public)
    listen_port = _reserve_local_port()
    registry = A2aRegistry.from_config(
        A2aConfig(
            agents=[
                A2aAgentConfig(
                    agent_id="server-agent",
                    fingerprint=server_fingerprint,
                    public_key=serialize_public_key_pem(server_public).decode("utf-8"),
                    address=f"127.0.0.1:{listen_port}",
                    transport="socket",
                )
            ]
        )
    )
    transport = SocketTransport(host="127.0.0.1", port=listen_port)
    listener = await transport.listen(_raising_handler)
    try:
        target = registry.require("server-agent")
        envelope = _signed_request(
            private_key=client_private,
            sender_agent_id="client-agent",
            sender_fingerprint=client_fingerprint,
            recipient_agent_id="server-agent",
            payload={"content": "socket boom"},
        )
        response = await SocketTransport().send(envelope, target)
    finally:
        await listener.close()

    assert response == {"error": "internal_error", "ok": False}


@pytest.mark.asyncio
async def test_http_transport_round_trip() -> None:
    server_private, server_public = generate_ed25519_keypair()
    client_private, client_public = generate_ed25519_keypair()
    server_fingerprint = fingerprint_for_public_key(server_public)
    client_fingerprint = fingerprint_for_public_key(client_public)
    listen_port = _reserve_local_port()
    registry = A2aRegistry.from_config(
        A2aConfig(
            agents=[
                A2aAgentConfig(
                    agent_id="server-agent",
                    fingerprint=server_fingerprint,
                    public_key=serialize_public_key_pem(server_public).decode("utf-8"),
                    address=f"http://127.0.0.1:{listen_port}/a2a",
                    transport="http",
                )
            ]
        )
    )
    transport = HttpTransport(host="127.0.0.1", port=listen_port, path="/a2a")
    listener = await transport.listen(
        lambda envelope: _echo_response(envelope, server_private, server_fingerprint)
    )
    try:
        target = registry.require("server-agent")
        envelope = _signed_request(
            private_key=client_private,
            sender_agent_id="client-agent",
            sender_fingerprint=client_fingerprint,
            recipient_agent_id="server-agent",
            payload={"content": "http hello"},
        )
        raw_response = await HttpTransport().send(envelope, target)
        response = A2aEnvelope.model_validate(raw_response)
    finally:
        await listener.close()

    assert response.payload["ok"] is True
    assert response.payload["echo"] == "http hello"
    assert verify_envelope(response, server_public) is True


@pytest.mark.asyncio
async def test_http_transport_preserves_query_and_host_header() -> None:
    _server_private, server_public = generate_ed25519_keypair()
    client_private, client_public = generate_ed25519_keypair()
    server_fingerprint = fingerprint_for_public_key(server_public)
    client_fingerprint = fingerprint_for_public_key(client_public)
    listen_port = _reserve_local_port()
    observed: dict[str, str] = {}

    async def _server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = await reader.readuntil(b"\r\n\r\n")
        lines = head.decode("utf-8").split("\r\n")
        observed["request_line"] = lines[0]
        headers = {
            key.strip().lower(): value.strip()
            for key, _separator, value in (line.partition(":") for line in lines[1:] if line)
        }
        observed["host"] = headers["host"]
        content_length = int(headers.get("content-length", "0"))
        if content_length:
            await reader.readexactly(content_length)
        payload = json.dumps({"ok": True}).encode("utf-8")
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: "
            + str(len(payload)).encode("ascii")
            + b"\r\nConnection: close\r\n\r\n"
            + payload
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(_server, "127.0.0.1", listen_port)
    try:
        target = A2aRegistry.from_config(
            A2aConfig(
                agents=[
                    A2aAgentConfig(
                        agent_id="server-agent",
                        fingerprint=server_fingerprint,
                        public_key=serialize_public_key_pem(server_public).decode("utf-8"),
                        address=f"http://127.0.0.1:{listen_port}/a2a?token=abc123",
                        transport="http",
                    )
                ]
            )
        ).require("server-agent")
        envelope = _signed_request(
            private_key=client_private,
            sender_agent_id="client-agent",
            sender_fingerprint=client_fingerprint,
            recipient_agent_id="server-agent",
            payload={"content": "http query"},
        )
        response = await HttpTransport().send(envelope, target)
    finally:
        server.close()
        await server.wait_closed()

    assert response == {"ok": True}
    assert observed["request_line"] == "POST /a2a?token=abc123 HTTP/1.1"
    assert observed["host"] == f"127.0.0.1:{listen_port}"


@pytest.mark.asyncio
async def test_http_transport_returns_reason_coded_error_on_handler_failure() -> None:
    _server_private, server_public = generate_ed25519_keypair()
    client_private, client_public = generate_ed25519_keypair()
    server_fingerprint = fingerprint_for_public_key(server_public)
    client_fingerprint = fingerprint_for_public_key(client_public)
    listen_port = _reserve_local_port()
    registry = A2aRegistry.from_config(
        A2aConfig(
            agents=[
                A2aAgentConfig(
                    agent_id="server-agent",
                    fingerprint=server_fingerprint,
                    public_key=serialize_public_key_pem(server_public).decode("utf-8"),
                    address=f"http://127.0.0.1:{listen_port}/a2a",
                    transport="http",
                )
            ]
        )
    )
    transport = HttpTransport(host="127.0.0.1", port=listen_port, path="/a2a")
    listener = await transport.listen(_raising_handler)
    try:
        target = registry.require("server-agent")
        envelope = _signed_request(
            private_key=client_private,
            sender_agent_id="client-agent",
            sender_fingerprint=client_fingerprint,
            recipient_agent_id="server-agent",
            payload={"content": "http boom"},
        )
        with pytest.raises(RuntimeError, match="internal_error"):
            await HttpTransport().send(envelope, target)
    finally:
        await listener.close()


@pytest.mark.asyncio
async def test_http_transport_rejects_oversized_request_body_without_leaking_details() -> None:
    listen_port = _reserve_local_port()
    transport = HttpTransport(
        host="127.0.0.1",
        port=listen_port,
        path="/a2a",
        max_body_bytes=8,
    )
    listener = await transport.listen(_raising_handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", listen_port)
        request = (
            b"POST /a2a HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 9\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"xxxxxxxxx"
        )
        writer.write(request)
        await writer.drain()
        raw_response = await reader.read()
        writer.close()
        await writer.wait_closed()
    finally:
        await listener.close()

    head, _separator, body = raw_response.partition(b"\r\n\r\n")
    status_line = head.decode("utf-8").split("\r\n", 1)[0]
    payload = json.loads(body.decode("utf-8"))
    assert status_line == "HTTP/1.1 413 Payload Too Large"
    assert payload == {"error": "payload_too_large", "ok": False}


@pytest.mark.asyncio
async def test_a2a_ingress_routes_message_with_a2a_external_taint(tmp_path: Path) -> None:
    local_fingerprint = write_ed25519_keypair(tmp_path / "local.pem", tmp_path / "local.pub")
    remote_private, remote_public = generate_ed25519_keypair()
    remote_fingerprint = fingerprint_for_public_key(remote_public)
    identity = load_local_identity(
        A2aIdentityConfig(
            agent_id="local-agent",
            private_key_path=tmp_path / "local.pem",
            public_key_path=tmp_path / "local.pub",
        )
    )
    registry = A2aRegistry.from_config(
        A2aConfig(
            agents=[
                A2aAgentConfig(
                    agent_id="remote-agent",
                    fingerprint=remote_fingerprint,
                    public_key=serialize_public_key_pem(remote_public).decode("utf-8"),
                    address="127.0.0.1:9820",
                    transport="socket",
                    trust_level="untrusted",
                )
            ]
        )
    )
    captured_create: list[tuple[SessionCreateParams, RequestContext]] = []
    captured_message: list[tuple[SessionMessageParams, RequestContext]] = []

    async def _create(params: SessionCreateParams, ctx: RequestContext) -> SessionCreateResult:
        captured_create.append((params, ctx))
        return SessionCreateResult(session_id="sess-a2a")

    async def _message(params: SessionMessageParams, ctx: RequestContext) -> SessionMessageResult:
        captured_message.append((params, ctx))
        return SessionMessageResult(session_id="sess-a2a", response="ack")

    ingress = A2aIngress(
        local_identity=identity,
        registry=registry,
        firewall=ContentFirewall(),
        session_create=_create,
        session_message=_message,
    )
    envelope = _signed_request(
        private_key=remote_private,
        sender_agent_id="remote-agent",
        sender_fingerprint=remote_fingerprint,
        recipient_agent_id="local-agent",
        payload={"content": "please answer this"},
    )

    result = await ingress.handle_envelope(envelope)

    assert local_fingerprint == identity.fingerprint
    assert result.session_id == "sess-a2a"
    assert captured_create
    assert captured_message
    create_params, create_ctx = captured_create[0]
    message_params, message_ctx = captured_message[0]
    assert create_params.channel == "a2a"
    assert create_params.user_id == "remote-agent"
    assert message_params.content == "please answer this"
    assert create_ctx.is_internal_ingress is True
    assert message_ctx.firewall_result is not None
    assert TaintLabel.A2A_EXTERNAL in message_ctx.firewall_result.taint_labels
    assert TaintLabel.UNTRUSTED in message_ctx.firewall_result.taint_labels


@pytest.mark.asyncio
async def test_a2a_ingress_rejects_non_request_envelope_types(tmp_path: Path) -> None:
    write_ed25519_keypair(tmp_path / "local.pem", tmp_path / "local.pub")
    remote_private, remote_public = generate_ed25519_keypair()
    remote_fingerprint = fingerprint_for_public_key(remote_public)
    identity = load_local_identity(
        A2aIdentityConfig(
            agent_id="local-agent",
            private_key_path=tmp_path / "local.pem",
            public_key_path=tmp_path / "local.pub",
        )
    )
    registry = A2aRegistry.from_config(
        A2aConfig(
            agents=[
                A2aAgentConfig(
                    agent_id="remote-agent",
                    fingerprint=remote_fingerprint,
                    public_key=serialize_public_key_pem(remote_public).decode("utf-8"),
                    address="127.0.0.1:9820",
                    transport="socket",
                )
            ]
        )
    )
    ingress = A2aIngress(
        local_identity=identity,
        registry=registry,
        firewall=ContentFirewall(),
        session_create=_unused_create,
        session_message=_unused_message,
    )
    envelope = create_envelope(
        from_agent_id="remote-agent",
        from_fingerprint=remote_fingerprint,
        to_agent_id="local-agent",
        message_type="response",
        intent="query",
        payload={"content": "should not run"},
    )
    signed = attach_signature(envelope, sign_envelope(envelope, remote_private))

    with pytest.raises(A2aIngressError, match="unsupported_message_type"):
        await ingress.handle_envelope(signed)


async def _echo_response(
    envelope: A2aEnvelope,
    private_key,
    fingerprint: str,
) -> A2aEnvelope:
    content = str(envelope.payload.get("content", ""))
    response = create_envelope(
        from_agent_id="server-agent",
        from_fingerprint=fingerprint,
        to_agent_id=envelope.sender.agent_id,
        message_type="response",
        intent=envelope.intent,
        payload={"ok": True, "echo": content},
    )
    return attach_signature(response, sign_envelope(response, private_key))


async def _raising_handler(_envelope: A2aEnvelope) -> A2aEnvelope:
    raise RuntimeError("boom secret")


async def _unused_create(
    _params: SessionCreateParams,
    _ctx: RequestContext,
) -> SessionCreateResult:
    raise AssertionError("session_create should not run")


async def _unused_message(
    _params: SessionMessageParams,
    _ctx: RequestContext,
) -> SessionMessageResult:
    raise AssertionError("session_message should not run")
