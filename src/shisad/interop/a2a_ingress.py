"""A2A envelope verification and session-ingress wiring."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from shisad.core.api.schema import (
    SessionCreateParams,
    SessionCreateResult,
    SessionMessageParams,
    SessionMessageResult,
)
from shisad.core.request_context import RequestContext
from shisad.core.types import TaintLabel
from shisad.daemon.context import RequestContext as DaemonRequestContext
from shisad.interop.a2a_envelope import (
    A2aEnvelope,
    ReplayCache,
    attach_signature,
    create_envelope,
    sign_envelope,
    verify_envelope,
)
from shisad.interop.a2a_registry import A2aListenConfig, A2aLocalIdentity, A2aRegistry
from shisad.interop.a2a_transport import A2aTransportListener, HttpTransport, SocketTransport
from shisad.security.firewall import ContentFirewall, FirewallResult

type SessionCreateHandler = Callable[
    [SessionCreateParams, RequestContext],
    Awaitable[SessionCreateResult],
]
type SessionMessageHandler = Callable[
    [SessionMessageParams, RequestContext],
    Awaitable[SessionMessageResult],
]


def _payload_text(payload: dict[str, Any]) -> str:
    for key in ("content", "message", "query", "text"):
        candidate = payload.get(key)
        if isinstance(candidate, str) and candidate.strip():
            return candidate
    return json.dumps(payload, sort_keys=True)


@dataclass(frozen=True, slots=True)
class A2aIngressResult:
    """Successful A2A ingress dispatch result."""

    session_id: str
    response: str
    sender_agent_id: str
    sender_fingerprint: str
    receiver_agent_id: str
    intent: str
    trust_level: str


class A2aIngressError(RuntimeError):
    """Structured A2A ingress rejection."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class A2aIngress:
    """Verify signed A2A requests and route them into the session pipeline."""

    def __init__(
        self,
        *,
        local_identity: A2aLocalIdentity,
        registry: A2aRegistry,
        firewall: ContentFirewall,
        session_create: SessionCreateHandler,
        session_message: SessionMessageHandler,
        replay_cache: ReplayCache | None = None,
    ) -> None:
        self._local_identity = local_identity
        self._registry = registry
        self._firewall = firewall
        self._session_create = session_create
        self._session_message = session_message
        self._replay_cache = replay_cache or ReplayCache()

    async def handle_envelope(self, envelope: A2aEnvelope) -> A2aIngressResult:
        """Validate and dispatch an inbound A2A envelope."""

        if envelope.version != self._local_identity_public_version:
            raise A2aIngressError("unsupported_version")
        if envelope.recipient.agent_id != self._local_identity.agent_id:
            raise A2aIngressError("unknown_recipient")
        entry = self._registry.resolve(envelope.sender.agent_id)
        if entry is None:
            raise A2aIngressError("unknown_sender")
        if envelope.sender.public_key_fingerprint != entry.fingerprint:
            raise A2aIngressError("fingerprint_mismatch")
        if not verify_envelope(envelope, entry.public_key):
            raise A2aIngressError("signature_invalid")
        replay_result = self._replay_cache.check(envelope)
        if not replay_result.allowed:
            raise A2aIngressError(replay_result.reason)

        payload_text = _payload_text(envelope.payload)
        firewall_result = self._firewall.inspect(payload_text, trusted_input=False)
        taint_labels = sorted({*firewall_result.taint_labels, TaintLabel.A2A_EXTERNAL})
        a2a_firewall_result = FirewallResult.model_validate(
            {
                **firewall_result.model_dump(mode="json"),
                "taint_labels": taint_labels,
            }
        )
        request_ctx = DaemonRequestContext(
            is_internal_ingress=True,
            trust_level_override=entry.trust_level,
            firewall_result=a2a_firewall_result,
        )
        created = await self._session_create(
            SessionCreateParams(
                channel="a2a",
                user_id=envelope.sender.agent_id,
                workspace_id=envelope.recipient.agent_id,
            ),
            request_ctx,
        )
        result = await self._session_message(
            SessionMessageParams(
                session_id=created.session_id,
                channel="a2a",
                user_id=envelope.sender.agent_id,
                workspace_id=envelope.recipient.agent_id,
                content=payload_text,
            ),
            request_ctx,
        )
        return A2aIngressResult(
            session_id=result.session_id,
            response=result.response,
            sender_agent_id=entry.agent_id,
            sender_fingerprint=entry.fingerprint,
            receiver_agent_id=self._local_identity.agent_id,
            intent=envelope.intent,
            trust_level=entry.trust_level,
        )

    @property
    def _local_identity_public_version(self) -> str:
        return "shisad-a2a/0.1"


class A2aRuntime:
    """Listener runtime that wires verified A2A messages into the daemon."""

    def __init__(
        self,
        *,
        local_identity: A2aLocalIdentity,
        registry: A2aRegistry,
        firewall: ContentFirewall,
        session_create: SessionCreateHandler,
        session_message: SessionMessageHandler,
        listen_config: A2aListenConfig,
    ) -> None:
        self._local_identity = local_identity
        self._listen_config = listen_config
        self._ingress = A2aIngress(
            local_identity=local_identity,
            registry=registry,
            firewall=firewall,
            session_create=session_create,
            session_message=session_message,
        )
        self._listener: A2aTransportListener | None = None

    async def start(self) -> None:
        transport: SocketTransport | HttpTransport
        if self._listen_config.transport == "socket":
            transport = SocketTransport(
                host=self._listen_config.host,
                port=self._listen_config.port,
            )
        else:
            transport = HttpTransport(
                host=self._listen_config.host,
                port=self._listen_config.port,
                path=self._listen_config.path,
            )
        self._listener = await transport.listen(self._handle_request)

    async def close(self) -> None:
        if self._listener is not None:
            await self._listener.close()
            self._listener = None

    def status(self) -> dict[str, Any]:
        listener = self._listener
        return {
            "enabled": listener is not None,
            "transport": self._listen_config.transport,
            "address": listener.address if listener is not None else "",
            "agent_id": self._local_identity.agent_id,
            "fingerprint": self._local_identity.fingerprint,
        }

    async def _handle_request(self, envelope: A2aEnvelope) -> A2aEnvelope:
        try:
            result = await self._ingress.handle_envelope(envelope)
            payload = {
                "ok": True,
                "response": result.response,
                "session_id": result.session_id,
                "intent": result.intent,
            }
        except A2aIngressError as exc:
            payload = {"ok": False, "error": exc.reason}
        response = create_envelope(
            from_agent_id=self._local_identity.agent_id,
            from_fingerprint=self._local_identity.fingerprint,
            to_agent_id=envelope.sender.agent_id,
            message_type="response",
            intent=envelope.intent,
            payload=payload,
        )
        return attach_signature(response, sign_envelope(response, self._local_identity.private_key))
