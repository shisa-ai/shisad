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
from shisad.core.events import A2aIngressEvaluated, EventBus
from shisad.core.request_context import RequestContext
from shisad.core.types import SessionId, TaintLabel
from shisad.daemon.context import RequestContext as DaemonRequestContext
from shisad.interop.a2a_envelope import (
    A2A_PROTOCOL_VERSION,
    A2aEnvelope,
    ReplayCache,
    attach_signature,
    create_envelope,
    sign_envelope,
    verify_envelope,
)
from shisad.interop.a2a_ratelimit import A2aRateLimiter
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

    def __init__(
        self,
        reason: str,
        *,
        status: int = 400,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = int(status)
        self.details = dict(details or {})

    def response_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": False,
            "error": self.reason,
            "status": self.status,
        }
        payload.update(self.details)
        return payload


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
        rate_limiter: A2aRateLimiter | None = None,
        event_bus: EventBus | None = None,
    ) -> None:
        self._local_identity = local_identity
        self._registry = registry
        self._firewall = firewall
        self._session_create = session_create
        self._session_message = session_message
        self._replay_cache = replay_cache or ReplayCache()
        self._rate_limiter = rate_limiter
        self._event_bus = event_bus

    async def handle_envelope(self, envelope: A2aEnvelope) -> A2aIngressResult:
        """Validate and dispatch an inbound A2A envelope."""

        entry = None
        capability_granted: bool | None = None
        session_id = ""
        try:
            if envelope.version != A2A_PROTOCOL_VERSION:
                raise A2aIngressError("unsupported_version", status=400)
            if envelope.type != "request":
                raise A2aIngressError("unsupported_message_type", status=400)
            if envelope.recipient.agent_id != self._local_identity.agent_id:
                raise A2aIngressError("unknown_recipient", status=404)
            entry = self._registry.resolve(envelope.sender.agent_id)
            if entry is None:
                raise A2aIngressError("unknown_sender", status=403)
            if envelope.sender.public_key_fingerprint != entry.fingerprint:
                raise A2aIngressError("fingerprint_mismatch", status=403)
            if not verify_envelope(envelope, entry.public_key):
                raise A2aIngressError("signature_invalid", status=403)
            if self._rate_limiter is not None:
                rate_limit = self._rate_limiter.check_rate_limit(entry.fingerprint)
                if not rate_limit.allowed:
                    raise A2aIngressError(
                        "rate_limited",
                        status=429,
                        details={"retry_after_seconds": rate_limit.retry_after_seconds},
                    )
            replay_result = self._replay_cache.check(envelope)
            if not replay_result.allowed:
                raise A2aIngressError(
                    replay_result.reason,
                    status=409 if replay_result.reason == "replay_detected" else 400,
                )
            capability_granted = envelope.intent in (entry.allowed_intents or ())
            if not capability_granted:
                raise A2aIngressError("intent_not_allowed", status=403)

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
            session_id = created.session_id
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
            await self._publish_audit(
                envelope,
                entry=entry,
                session_id=result.session_id,
                outcome="accepted",
                reason="ok",
                status_code=200,
                capability_granted=True,
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
        except A2aIngressError as exc:
            await self._publish_audit(
                envelope,
                entry=entry,
                session_id=session_id,
                outcome="rejected",
                reason=exc.reason,
                status_code=exc.status,
                capability_granted=capability_granted,
                retry_after_seconds=float(exc.details.get("retry_after_seconds", 0.0) or 0.0),
            )
            raise
        except Exception:
            await self._publish_audit(
                envelope,
                entry=entry,
                session_id=session_id,
                outcome="rejected",
                reason="internal_error",
                status_code=500,
                capability_granted=capability_granted,
            )
            raise

    async def _publish_audit(
        self,
        envelope: A2aEnvelope,
        *,
        entry: Any,
        session_id: str,
        outcome: str,
        reason: str,
        status_code: int,
        capability_granted: bool | None,
        retry_after_seconds: float = 0.0,
    ) -> None:
        if self._event_bus is None:
            return
        await self._event_bus.publish(
            A2aIngressEvaluated(
                session_id=SessionId(session_id) if session_id else None,
                actor="a2a_ingress",
                sender_agent_id=envelope.sender.agent_id,
                sender_fingerprint=envelope.sender.public_key_fingerprint,
                verified_fingerprint=entry.fingerprint if entry is not None else "",
                receiver_agent_id=self._local_identity.agent_id,
                message_id=envelope.message_id,
                intent=envelope.intent,
                trust_level=entry.trust_level if entry is not None else "",
                outcome=outcome,
                reason=reason,
                status_code=status_code,
                capability_granted=capability_granted,
                retry_after_seconds=retry_after_seconds,
            )
        )


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
        rate_limiter: A2aRateLimiter | None = None,
        event_bus: EventBus | None = None,
    ) -> None:
        self._local_identity = local_identity
        self._listen_config = listen_config
        self._ingress = A2aIngress(
            local_identity=local_identity,
            registry=registry,
            firewall=firewall,
            session_create=session_create,
            session_message=session_message,
            rate_limiter=rate_limiter,
            event_bus=event_bus,
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
            payload = exc.response_payload()
        except Exception:
            payload = {"ok": False, "error": "internal_error", "status": 500}
        response = create_envelope(
            from_agent_id=self._local_identity.agent_id,
            from_fingerprint=self._local_identity.fingerprint,
            to_agent_id=envelope.sender.agent_id,
            message_type="response",
            intent=envelope.intent,
            payload=payload,
        )
        return attach_signature(response, sign_envelope(response, self._local_identity.private_key))
