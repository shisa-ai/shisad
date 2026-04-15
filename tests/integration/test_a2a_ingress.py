"""I3 A2A integration coverage against a live daemon instance."""

from __future__ import annotations

from pathlib import Path

import pytest

from shisad.core.audit import AuditLog
from shisad.core.config import DaemonConfig
from shisad.core.planner import Planner, PlannerOutput, PlannerResult
from shisad.core.types import SessionId, TaintLabel
from shisad.daemon.services import DaemonServices
from shisad.interop.a2a_envelope import (
    A2aEnvelope,
    attach_signature,
    create_envelope,
    fingerprint_for_public_key,
    generate_ed25519_keypair,
    load_public_key_from_path,
    serialize_public_key_pem,
    sign_envelope,
    verify_envelope,
    write_ed25519_keypair,
)
from shisad.interop.a2a_registry import (
    A2aAgentConfig,
    A2aConfig,
    A2aIdentityConfig,
    A2aListenConfig,
    A2aRegistry,
)
from shisad.interop.a2a_transport import SocketTransport


@pytest.mark.asyncio
async def test_i3_a2a_socket_ingress_creates_tainted_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")

    async def _capture_propose(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (self, user_content, context, tools, persona_tone_override)
        return PlannerResult(
            output=PlannerOutput(actions=[], assistant_response="A2A received"),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _capture_propose)
    local_private_path = tmp_path / "local-a2a.pem"
    local_public_path = tmp_path / "local-a2a.pub"
    local_fingerprint = write_ed25519_keypair(local_private_path, local_public_path)
    remote_private, remote_public = generate_ed25519_keypair()
    remote_fingerprint = fingerprint_for_public_key(remote_public)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text('version: "1"\ndefault_require_confirmation: false\n', encoding="utf-8")
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        a2a=A2aConfig(
            enabled=True,
            identity=A2aIdentityConfig(
                agent_id="local-agent",
                private_key_path=local_private_path,
                public_key_path=local_public_path,
            ),
            listen=A2aListenConfig(transport="socket", host="127.0.0.1", port=0),
            agents=[
                A2aAgentConfig(
                    agent_id="remote-agent",
                    fingerprint=remote_fingerprint,
                    public_key=serialize_public_key_pem(remote_public).decode("utf-8"),
                    address="127.0.0.1:9820",
                    transport="socket",
                    trust_level="untrusted",
                    allowed_intents=["query"],
                )
            ],
        ),
    )

    services = await DaemonServices.build(config)
    try:
        envelope = create_envelope(
            from_agent_id="remote-agent",
            from_fingerprint=remote_fingerprint,
            to_agent_id="local-agent",
            message_type="request",
            intent="query",
            payload={"content": "hello from a2a"},
        )
        signed = attach_signature(envelope, sign_envelope(envelope, remote_private))
        runtime_status = (
            services.a2a_runtime.status() if services.a2a_runtime is not None else {"address": ""}
        )
        target = A2aRegistry.from_config(
            A2aConfig(
                agents=[
                    A2aAgentConfig(
                        agent_id="local-agent",
                        fingerprint=local_fingerprint,
                        public_key_path=local_public_path,
                        address=str(runtime_status["address"]),
                        transport="socket",
                    )
                ]
            )
        ).require("local-agent")
        assert target is not None
        raw_response = await SocketTransport().send(signed, target)
        response = A2aEnvelope.model_validate(raw_response)
        session_id = SessionId(str(response.payload.get("session_id", "")))
        entries = services.transcript_store.list_entries(session_id)
        local_public = load_public_key_from_path(local_public_path)
        audit_events = AuditLog(config.data_dir / "audit.jsonl").query(
            event_type="A2aIngressEvaluated",
            session_id=str(session_id),
            limit=10,
        )
        assert verify_envelope(response, local_public) is True
    finally:
        await services.shutdown()

    assert local_fingerprint
    assert runtime_status["enabled"] is True
    assert runtime_status["address"] != "127.0.0.1:0"
    assert response.payload["ok"] is True
    assert response.payload["response"] == "A2A received"
    user_entries = [entry for entry in entries if entry.role == "user"]
    assert user_entries
    assert TaintLabel.A2A_EXTERNAL in user_entries[0].taint_labels
    assert TaintLabel.UNTRUSTED in user_entries[0].taint_labels
    assert len(audit_events) == 1
    audit_data = dict(audit_events[0]["data"])
    assert audit_data["sender_agent_id"] == "remote-agent"
    assert audit_data["sender_fingerprint"] == remote_fingerprint
    assert audit_data["receiver_agent_id"] == "local-agent"
    assert audit_data["message_id"] == envelope.message_id
    assert audit_data["intent"] == "query"
    assert audit_data["capability_granted"] is True
    assert audit_data["outcome"] == "accepted"
    assert audit_data["reason"] == "ok"
