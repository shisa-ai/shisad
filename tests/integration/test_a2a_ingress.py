"""I3 A2A integration coverage against a live daemon instance."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from pathlib import Path

import pytest

from shisad.core.api.transport import ControlClient
from shisad.core.audit import AuditLog
from shisad.core.config import DaemonConfig
from shisad.core.planner import (
    ActionProposal,
    EvaluatedProposal,
    Planner,
    PlannerOutput,
    PlannerResult,
)
from shisad.core.types import SessionId, TaintLabel, ToolName
from shisad.daemon.runner import _serve_daemon
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
from tests.helpers.daemon import wait_for_socket


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


@pytest.mark.asyncio
async def test_f9_a2a_pending_action_is_shared_with_control_confirmation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")

    async def _queue_time_confirmation(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (user_content, tools, persona_tone_override)
        proposal = ActionProposal(
            action_id="f9-a2a-time",
            tool_name=ToolName("time.now"),
            arguments={"timezone": "UTC"},
            reasoning="exercise one cross-surface pending-action owner",
            data_sources=[],
        )
        decision = self._pep.evaluate(proposal.tool_name, proposal.arguments, context)
        return PlannerResult(
            output=PlannerOutput(
                actions=[proposal], assistant_response="Time check needs approval."
            ),
            evaluated=[EvaluatedProposal(proposal=proposal, decision=decision)],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _queue_time_confirmation)
    local_private_path = tmp_path / "local-a2a.pem"
    local_public_path = tmp_path / "local-a2a.pub"
    local_fingerprint = write_ed25519_keypair(local_private_path, local_public_path)
    remote_private, remote_public = generate_ed25519_keypair()
    remote_fingerprint = fingerprint_for_public_key(remote_public)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        'version: "1"\ndefault_require_confirmation: true\n',
        encoding="utf-8",
    )
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
    serve_task = asyncio.create_task(_serve_daemon(config, services, None))
    client = ControlClient(config.socket_path)
    try:
        await wait_for_socket(config.socket_path)
        await client.connect()
        assert services.a2a_runtime is not None
        runtime_status = services.a2a_runtime.status()
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
        envelope = create_envelope(
            from_agent_id="remote-agent",
            from_fingerprint=remote_fingerprint,
            to_agent_id="local-agent",
            message_type="request",
            intent="query",
            payload={"content": "what time is it in UTC?"},
        )
        signed = attach_signature(envelope, sign_envelope(envelope, remote_private))
        response = A2aEnvelope.model_validate(await SocketTransport().send(signed, target))
        session_id = str(response.payload["session_id"])

        pending = await client.call(
            "action.pending",
            {"session_id": session_id, "status": "pending", "limit": 10},
        )
        assert pending["count"] == 1
        action = pending["actions"][0]
        confirmation_id = str(action["confirmation_id"])
        decision_nonce = str(action["decision_nonce"])
        proof_requirement = {
            key: action[key]
            for key in (
                "required_proof_tier",
                "required_level",
                "required_methods",
                "required_capabilities",
                "fallback",
            )
        }
        assert action["session_id"] == session_id
        assert action["user_id"] == "remote-agent"
        assert action["workspace_id"] == "local-agent"
        assert action["lifecycle_state"] == "pending"

        confirm_params = {
            "confirmation_id": confirmation_id,
            "decision_nonce": decision_nonce,
            "reason": "f9_cross_surface_approval",
        }
        confirmed = await client.call("action.confirm", confirm_params)
        if str(confirmed.get("reason", "")) == "cooldown_active":
            await asyncio.sleep(float(confirmed["retry_after_seconds"]) + 0.05)
            confirmed = await client.call("action.confirm", confirm_params)
        assert confirmed["confirmed"] is True
        assert confirmed["status"] == "approved"
        assert confirmed["lifecycle_state"] == "executed"
        confirmed_identity = confirmed["identity"]
        result_id = str(confirmed_identity["result_id"])
        assert result_id.startswith("result-")
        assert confirmed_identity["confirmation_id"] == confirmation_id
        assert confirmed_identity["session_id"] == session_id
        assert confirmed_identity["user_id"] == "remote-agent"
        assert confirmed_identity["workspace_id"] == "local-agent"
        assert confirmed["approval_level"] == proof_requirement["required_level"]
        assert len(confirmed["tool_outputs"]) == 1
        tool_output = confirmed["tool_outputs"][0]
        assert tool_output["tool_name"] == "time.now"
        assert tool_output["success"] is True
        assert tool_output["payload"]["ok"] is True
        assert tool_output["payload"]["timezone"] == "UTC"
        assert tool_output["payload"]["source"] == "daemon_clock"
        assert tool_output["action_identity"] == confirmed_identity

        terminal = await client.call(
            "action.pending",
            {"confirmation_id": confirmation_id, "status": "all", "limit": 10},
        )
        assert terminal["count"] == 1
        terminal_action = terminal["actions"][0]
        assert terminal_action["confirmation_id"] == confirmation_id
        assert terminal_action["decision_nonce"] == decision_nonce
        assert terminal_action["session_id"] == session_id
        assert terminal_action["user_id"] == "remote-agent"
        assert terminal_action["workspace_id"] == "local-agent"
        assert terminal_action["status"] == "approved"
        assert terminal_action["lifecycle_state"] == "executed"
        assert terminal_action["result_id"] == result_id
        assert terminal_action["identity"] == confirmed_identity
        assert {key: terminal_action[key] for key in proof_requirement} == proof_requirement

        ingress = services.a2a_runtime._ingress
        assert ingress._session_create.__self__ is services.control_handlers.session
        assert ingress._session_message.__self__ is services.control_handlers.session
        assert services.approval_web._approval_complete_cb.__self__ is (
            services.control_handlers._impl
        )
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        services.shutdown_event.set()
        await client.close()
        await asyncio.wait_for(serve_task, timeout=3)
        await services.shutdown()
