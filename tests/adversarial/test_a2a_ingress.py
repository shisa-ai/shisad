"""Adversarial coverage for A2A ingress security controls."""

from __future__ import annotations

from pathlib import Path

import pytest

from shisad.core.api.schema import (
    SessionCreateParams,
    SessionCreateResult,
    SessionMessageParams,
    SessionMessageResult,
)
from shisad.core.audit import AuditLog
from shisad.core.events import EventBus
from shisad.core.request_context import RequestContext
from shisad.interop.a2a_envelope import (
    A2aEnvelope,
    attach_signature,
    create_envelope,
    fingerprint_for_public_key,
    generate_ed25519_keypair,
    serialize_public_key_pem,
    sign_envelope,
    write_ed25519_keypair,
)
from shisad.interop.a2a_ingress import A2aIngress, A2aIngressError
from shisad.interop.a2a_ratelimit import A2aRateLimiter
from shisad.interop.a2a_registry import (
    A2aAgentConfig,
    A2aConfig,
    A2aIdentityConfig,
    A2aRateLimitsConfig,
    A2aRegistry,
    load_local_identity,
)
from shisad.security.firewall import ContentFirewall


def _signed_request(
    *,
    private_key,
    sender_agent_id: str,
    sender_fingerprint: str,
    recipient_agent_id: str,
    intent: str = "query",
    payload: dict[str, object] | None = None,
) -> A2aEnvelope:
    envelope = create_envelope(
        from_agent_id=sender_agent_id,
        from_fingerprint=sender_fingerprint,
        to_agent_id=recipient_agent_id,
        message_type="request",
        intent=intent,
        payload=dict(payload or {"content": "hello from remote agent"}),
    )
    return attach_signature(envelope, sign_envelope(envelope, private_key))


async def _create(_params: SessionCreateParams, _ctx: RequestContext) -> SessionCreateResult:
    return SessionCreateResult(session_id="sess-a2a")


async def _message(_params: SessionMessageParams, _ctx: RequestContext) -> SessionMessageResult:
    return SessionMessageResult(session_id="sess-a2a", response="ack")


def _audit_events(audit_log: AuditLog, *, limit: int = 200) -> list[dict[str, object]]:
    return audit_log.query(event_type="A2aIngressEvaluated", limit=limit)


def _build_ingress(
    tmp_path: Path,
    *,
    agents: list[A2aAgentConfig],
    rate_limits: A2aRateLimitsConfig | None = None,
) -> tuple[A2aIngress, AuditLog]:
    write_ed25519_keypair(tmp_path / "local.pem", tmp_path / "local.pub")
    identity = load_local_identity(
        A2aIdentityConfig(
            agent_id="local-agent",
            private_key_path=tmp_path / "local.pem",
            public_key_path=tmp_path / "local.pub",
        )
    )
    audit_log = AuditLog(tmp_path / "audit.jsonl")
    ingress = A2aIngress(
        local_identity=identity,
        registry=A2aRegistry.from_config(
            A2aConfig(
                agents=agents,
                rate_limits=rate_limits or A2aRateLimitsConfig(),
            )
        ),
        firewall=ContentFirewall(),
        session_create=_create,
        session_message=_message,
        rate_limiter=A2aRateLimiter(rate_limits or A2aRateLimitsConfig()),
        event_bus=EventBus(persister=audit_log),
    )
    return ingress, audit_log


@pytest.mark.asyncio
async def test_adversarial_a2a_spoofed_agent_id_signed_with_wrong_key_is_rejected_and_audited(
    tmp_path: Path,
) -> None:
    alice_private, alice_public = generate_ed25519_keypair()
    bob_private, _bob_public = generate_ed25519_keypair()
    alice_fingerprint = fingerprint_for_public_key(alice_public)
    ingress, audit_log = _build_ingress(
        tmp_path,
        agents=[
            A2aAgentConfig(
                agent_id="alice-agent",
                fingerprint=alice_fingerprint,
                public_key=serialize_public_key_pem(alice_public).decode("utf-8"),
                address="127.0.0.1:9820",
                transport="socket",
                allowed_intents=["query"],
            )
        ],
    )
    unsigned = _signed_request(
        private_key=alice_private,
        sender_agent_id="alice-agent",
        sender_fingerprint=alice_fingerprint,
        recipient_agent_id="local-agent",
    ).model_copy(update={"signature": ""})
    forged = attach_signature(unsigned, sign_envelope(unsigned, bob_private))

    with pytest.raises(A2aIngressError, match="signature_invalid"):
        await ingress.handle_envelope(forged)

    audit_data = dict(_audit_events(audit_log)[0]["data"])
    assert audit_data["sender_agent_id"] == "alice-agent"
    assert audit_data["sender_fingerprint"] == alice_fingerprint
    assert audit_data["verified_fingerprint"] == alice_fingerprint
    assert audit_data["outcome"] == "rejected"
    assert audit_data["reason"] == "signature_invalid"


@pytest.mark.asyncio
async def test_adversarial_a2a_replay_is_rejected_and_audited(tmp_path: Path) -> None:
    remote_private, remote_public = generate_ed25519_keypair()
    remote_fingerprint = fingerprint_for_public_key(remote_public)
    ingress, audit_log = _build_ingress(
        tmp_path,
        agents=[
            A2aAgentConfig(
                agent_id="remote-agent",
                fingerprint=remote_fingerprint,
                public_key=serialize_public_key_pem(remote_public).decode("utf-8"),
                address="127.0.0.1:9820",
                transport="socket",
                allowed_intents=["query"],
            )
        ],
    )
    envelope = _signed_request(
        private_key=remote_private,
        sender_agent_id="remote-agent",
        sender_fingerprint=remote_fingerprint,
        recipient_agent_id="local-agent",
    )

    accepted = await ingress.handle_envelope(envelope)
    with pytest.raises(A2aIngressError, match="replay_detected"):
        await ingress.handle_envelope(envelope)

    events = _audit_events(audit_log)
    assert accepted.session_id == "sess-a2a"
    assert len(events) == 2
    assert dict(events[0]["data"])["outcome"] == "accepted"
    replay_data = dict(events[1]["data"])
    assert replay_data["message_id"] == envelope.message_id
    assert replay_data["outcome"] == "rejected"
    assert replay_data["reason"] == "replay_detected"


@pytest.mark.asyncio
async def test_adversarial_a2a_capability_escalation_is_rejected_and_audited(
    tmp_path: Path,
) -> None:
    remote_private, remote_public = generate_ed25519_keypair()
    remote_fingerprint = fingerprint_for_public_key(remote_public)
    ingress, audit_log = _build_ingress(
        tmp_path,
        agents=[
            A2aAgentConfig(
                agent_id="remote-agent",
                fingerprint=remote_fingerprint,
                public_key=serialize_public_key_pem(remote_public).decode("utf-8"),
                address="127.0.0.1:9820",
                transport="socket",
                allowed_intents=["query"],
            )
        ],
    )
    envelope = _signed_request(
        private_key=remote_private,
        sender_agent_id="remote-agent",
        sender_fingerprint=remote_fingerprint,
        recipient_agent_id="local-agent",
        intent="delegate_task",
        payload={"content": "delegate now"},
    )

    with pytest.raises(A2aIngressError, match="intent_not_allowed"):
        await ingress.handle_envelope(envelope)

    audit_data = dict(_audit_events(audit_log)[0]["data"])
    assert audit_data["message_id"] == envelope.message_id
    assert audit_data["intent"] == "delegate_task"
    assert audit_data["capability_granted"] is False
    assert audit_data["outcome"] == "rejected"
    assert audit_data["reason"] == "intent_not_allowed"


@pytest.mark.asyncio
async def test_adversarial_a2a_burst_hits_rate_limit_after_sixty_requests(tmp_path: Path) -> None:
    remote_private, remote_public = generate_ed25519_keypair()
    remote_fingerprint = fingerprint_for_public_key(remote_public)
    ingress, audit_log = _build_ingress(
        tmp_path,
        agents=[
            A2aAgentConfig(
                agent_id="remote-agent",
                fingerprint=remote_fingerprint,
                public_key=serialize_public_key_pem(remote_public).decode("utf-8"),
                address="127.0.0.1:9820",
                transport="socket",
                allowed_intents=["query"],
            )
        ],
        rate_limits=A2aRateLimitsConfig(max_per_minute=60, max_per_hour=600),
    )

    accepted = 0
    rejected = 0
    for attempt in range(100):
        envelope = _signed_request(
            private_key=remote_private,
            sender_agent_id="remote-agent",
            sender_fingerprint=remote_fingerprint,
            recipient_agent_id="local-agent",
            payload={"content": f"burst-{attempt}"},
        )
        try:
            await ingress.handle_envelope(envelope)
        except A2aIngressError as exc:
            assert exc.reason == "rate_limited"
            assert exc.status == 429
            assert float(exc.details["retry_after_seconds"]) > 0.0
            rejected += 1
        else:
            accepted += 1

    events = _audit_events(audit_log)
    accepted_events = [
        event for event in events if dict(event["data"]).get("outcome") == "accepted"
    ]
    rejected_events = [
        event for event in events if dict(event["data"]).get("reason") == "rate_limited"
    ]

    assert accepted == 60
    assert rejected == 40
    assert len(accepted_events) == 60
    assert len(rejected_events) == 40
