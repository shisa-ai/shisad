"""Unit coverage for channel-ingest ingress-handle minting."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from shisad.channels.identity import ChannelIdentityMap
from shisad.core.types import SessionId, TaintLabel
from shisad.daemon.handlers._impl_admin import AdminImplMixin
from shisad.memory.ingress import IngressContextRegistry
from shisad.security.firewall import FirewallResult


class _DeliveryResult:
    def __init__(self, *, sent: bool = True, reason: str = "ok") -> None:
        self.sent = sent
        self.reason = reason

    def as_dict(self) -> dict[str, Any]:
        return {"attempted": True, "sent": self.sent, "reason": self.reason, "target": {}}


class _DeliveryStub:
    async def send(self, *, target: object, message: str) -> _DeliveryResult:
        _ = (target, message)
        return _DeliveryResult()


class _SessionManagerStub:
    def __init__(self) -> None:
        self._sessions: dict[str, object] = {}
        self.terminated: list[tuple[str, str]] = []

    def get(self, sid: object) -> object | None:
        return self._sessions.get(str(sid))

    def find_by_binding(
        self,
        *,
        channel: str,
        user_id: object,
        workspace_id: object,
    ) -> object | None:
        _ = (channel, user_id, workspace_id)
        return None

    def terminate(self, sid: object, *, reason: str) -> None:
        self.terminated.append((str(sid), reason))

    def put(self, sid: str) -> None:
        self._sessions[sid] = SimpleNamespace(id=SessionId(sid))


class _AdminChannelIngressHarness(AdminImplMixin):
    def __init__(self) -> None:
        self._config = SimpleNamespace(discord_channel_rules=(), matrix_room_id="")
        self._matrix_channel = None
        self._discord_channel = None
        self._telegram_channel = None
        self._slack_channel = None
        self._identity_map = ChannelIdentityMap(
            default_trust={"discord": "owner"},
            allowlists={"discord": {"alice"}},
        )
        self._channel_ingress = SimpleNamespace(process=self._process_channel_ingress)
        self._transcript_root = Path("/tmp/shisad-tests")
        self._session_manager = _SessionManagerStub()
        self._delivery = _DeliveryStub()
        self._channel_proactive_last_sent_at: dict[str, object] = {}
        self._internal_ingress_marker = object()
        self._event_bus = SimpleNamespace(publish=self._publish)
        self._memory_ingress_registry = IngressContextRegistry()
        self.created_payloads: list[dict[str, Any]] = []
        self.message_payloads: list[dict[str, Any]] = []

    def _is_verified_channel_identity(self, *, channel: str, external_user_id: str) -> bool:
        _ = (channel, external_user_id)
        return False

    def _process_channel_ingress(
        self,
        message: object,
        *,
        trusted_input: bool,
    ) -> tuple[object, FirewallResult]:
        _ = message
        return (
            message,
            FirewallResult(
                sanitized_text="remember that I like tea",
                original_hash="0" * 64,
                risk_score=0.1,
                taint_labels=[] if trusted_input else [TaintLabel.UNTRUSTED],
            ),
        )

    async def _publish(self, _event: object) -> None:
        return None

    async def do_session_create(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.created_payloads.append(dict(payload))
        session_id = "sess-channel"
        self._session_manager.put(session_id)
        return {"session_id": session_id}

    async def do_session_message(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.message_payloads.append(dict(payload))
        return {"session_id": str(payload["session_id"]), "response": "ok"}


@pytest.mark.asyncio
async def test_m1_channel_ingest_mints_explicit_memory_handle_at_boundary() -> None:
    harness = _AdminChannelIngressHarness()

    result = await harness.do_channel_ingest(
        {
            "message": {
                "channel": "discord",
                "external_user_id": "alice",
                "workspace_hint": "guild-1",
                "reply_target": "chan-1",
                "message_id": "msg-9",
                "content": "remember that I like tea",
            }
        }
    )

    assert result["response"] == "ok"
    assert len(harness.message_payloads) == 1
    payload = harness.message_payloads[0]
    handle_id = str(payload.get("_explicit_memory_ingress_context", ""))
    assert handle_id
    context = harness._memory_ingress_registry.resolve(handle_id)
    assert context.source_origin == "user_direct"
    assert context.channel_trust == "owner_observed"
    assert context.confirmation_status == "auto_accepted"
    assert context.scope == "user"
    assert context.source_id == "discord:msg-9"
