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
from shisad.memory.manager import MemoryManager
from shisad.memory.participation import (
    channel_participation_key,
    channel_summary_key,
    compose_channel_binding,
    inbox_item_key,
    person_note_key,
    response_feedback_key,
)
from shisad.memory.schema import MemorySource
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


class _TranscriptStoreStub:
    def __init__(self) -> None:
        self.entries: list[dict[str, object]] = []

    def append(
        self,
        sid: object,
        *,
        role: str,
        content: str,
        taint_labels: object,
        metadata: dict[str, object],
    ) -> None:
        self.entries.append(
            {
                "session_id": str(sid),
                "role": role,
                "content": content,
                "taint_labels": taint_labels,
                "metadata": metadata,
            }
        )


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
    def __init__(
        self,
        *,
        tmp_path: Path,
        default_trust: str = "owner",
        allowlisted_users: set[str] | None = None,
    ) -> None:
        self._config = SimpleNamespace(
            discord_channel_rules=(),
            matrix_room_id="",
            discord_trusted_users=["owner-user"],
            slack_trusted_users=[],
            matrix_trusted_users=[],
            telegram_trusted_users=[],
        )
        self._matrix_channel = None
        self._discord_channel = None
        self._telegram_channel = None
        self._slack_channel = None
        self._identity_map = ChannelIdentityMap(
            default_trust={"discord": default_trust},
            allowlists={"discord": set(allowlisted_users or {"alice"})},
        )
        self._channel_ingress = SimpleNamespace(process=self._process_channel_ingress)
        self._transcript_root = Path("/tmp/shisad-tests")
        self._transcript_store = _TranscriptStoreStub()
        self._session_manager = _SessionManagerStub()
        self._delivery = _DeliveryStub()
        self._channel_proactive_last_sent_at: dict[str, object] = {}
        self._internal_ingress_marker = object()
        self._event_bus = SimpleNamespace(publish=self._publish)
        self._memory_ingress_registry = IngressContextRegistry()
        self._memory_manager = MemoryManager(tmp_path / "memory_entries")
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
async def test_m1_channel_ingest_mints_explicit_memory_handle_at_boundary(
    tmp_path: Path,
) -> None:
    harness = _AdminChannelIngressHarness(tmp_path=tmp_path)

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


@pytest.mark.asyncio
async def test_m3_channel_ingest_persists_structured_participation_memory(
    tmp_path: Path,
) -> None:
    harness = _AdminChannelIngressHarness(
        tmp_path=tmp_path,
        default_trust="public",
        allowlisted_users={"guest-1"},
    )

    result = await harness.do_channel_ingest(
        {
            "message": {
                "channel": "discord",
                "external_user_id": "guest-1",
                "workspace_hint": "guild-1",
                "reply_target": "chan-1",
                "message_id": "msg-21",
                "content": "Can you share the release notes?",
                "metadata": {
                    "display_name": "Guest One",
                    "interaction_type": "direct",
                },
            }
        }
    )

    assert result["response"] == "ok"
    entries = harness._memory_manager.list_entries(limit=20)
    by_key = {entry.key: entry for entry in entries}
    channel_binding = compose_channel_binding(
        channel="discord",
        workspace_hint="guild-1",
        channel_id="chan-1",
    )

    inbox = by_key[inbox_item_key(owner_id="owner-user", item_id="msg-21")]
    assert inbox.entry_type == "inbox_item"
    assert inbox.scope == "user"
    assert inbox.source_origin == "external_message"
    assert inbox.channel_trust == "shared_participant"

    note = by_key[person_note_key(channel_id=channel_binding, external_user_id="guest-1")]
    assert note.entry_type == "person_note"
    assert note.scope == "channel"
    assert note.channel_trust == "shared_participant"

    participation = by_key[channel_participation_key(channel_id=channel_binding)]
    assert participation.entry_type == "channel_participation"
    assert participation.scope == "channel"
    assert participation.channel_trust == "shared_participant"


@pytest.mark.asyncio
async def test_m3_channel_ingest_persists_summary_and_feedback_records_from_metadata(
    tmp_path: Path,
) -> None:
    harness = _AdminChannelIngressHarness(
        tmp_path=tmp_path,
        default_trust="public",
        allowlisted_users={"guest-2"},
    )

    await harness.do_channel_ingest(
        {
            "message": {
                "channel": "discord",
                "external_user_id": "guest-2",
                "workspace_hint": "guild-1",
                "reply_target": "chan-2",
                "message_id": "msg-30",
                "content": "thumbs up",
                "metadata": {
                    "interaction_type": "direct",
                    "summary_kind": "digest",
                    "summary_text": "Guest follow-up summary.",
                    "feedback_signal": "reaction_add",
                    "feedback_target_message_id": "agent-msg-9",
                    "feedback_emoji": ":+1:",
                    "feedback_valence": "positive",
                },
            }
        }
    )

    entries = harness._memory_manager.list_entries(limit=20)
    by_key = {entry.key: entry for entry in entries}
    channel_binding = compose_channel_binding(
        channel="discord",
        workspace_hint="guild-1",
        channel_id="chan-2",
    )

    summary = by_key[channel_summary_key(channel_id=channel_binding, summary_kind="digest")]
    assert summary.entry_type == "channel_summary"
    assert summary.scope == "channel"

    feedback = by_key[
        response_feedback_key(
            channel_id=channel_binding,
            message_id="agent-msg-9",
            actor_external_user_id="guest-2",
            signal="reaction_add",
        )
    ]
    assert feedback.entry_type == "response_feedback"
    assert feedback.scope == "channel"


@pytest.mark.asyncio
async def test_m3_channel_ingest_observation_updates_participation_without_inbox_item(
    tmp_path: Path,
) -> None:
    harness = _AdminChannelIngressHarness(
        tmp_path=tmp_path,
        default_trust="public",
        allowlisted_users={"guest-3"},
    )

    result = await harness.do_channel_ingest(
        {
            "message": {
                "channel": "discord",
                "external_user_id": "guest-3",
                "workspace_hint": "guild-1",
                "reply_target": "chan-3",
                "message_id": "msg-44",
                "content": "reading along here",
                "metadata": {
                    "interaction_type": "observed",
                    "passive_reason": "passive_observe",
                },
            }
        }
    )

    assert result["response"] == ""
    entries = harness._memory_manager.list_entries(limit=20)
    keys = {entry.key for entry in entries}
    channel_binding = compose_channel_binding(
        channel="discord",
        workspace_hint="guild-1",
        channel_id="chan-3",
    )
    assert channel_participation_key(channel_id=channel_binding) in keys
    assert person_note_key(channel_id=channel_binding, external_user_id="guest-3") in keys
    assert inbox_item_key(owner_id="owner-user", item_id="msg-44") not in keys


@pytest.mark.asyncio
async def test_m3_channel_ingest_migrates_legacy_bare_inbox_bindings(
    tmp_path: Path,
) -> None:
    harness = _AdminChannelIngressHarness(
        tmp_path=tmp_path,
        default_trust="public",
        allowlisted_users={"guest-4"},
    )
    harness._transcript_store.append(
        SessionId("sess-legacy-1"),
        role="user",
        content="legacy workspace one",
        taint_labels=set(),
        metadata={
            "channel_message_id": "legacy-msg-1",
            "delivery_target": {
                "channel": "discord",
                "recipient": "chan-legacy",
                "workspace_hint": "guild-1",
                "thread_id": "",
            },
        },
    )
    harness._transcript_store.append(
        SessionId("sess-legacy-2"),
        role="user",
        content="legacy workspace two",
        taint_labels=set(),
        metadata={
            "channel_message_id": "legacy-msg-2",
            "delivery_target": {
                "channel": "discord",
                "recipient": "chan-legacy",
                "workspace_hint": "guild-2",
                "thread_id": "",
            },
        },
    )
    legacy = harness._memory_manager.write_with_provenance(
        entry_type="inbox_item",
        key=inbox_item_key(owner_id="owner-user", item_id="legacy-1"),
        value={
            "owner_id": "owner-user",
            "sender_id": "guest-4",
            "channel_id": "chan-legacy",
            "body": "Legacy bare channel binding.",
        },
        source=MemorySource(
            origin="external",
            source_id="discord:legacy-msg-1",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:legacy-msg-1",
        scope="user",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    assert legacy.kind == "allow"
    assert legacy.entry is not None
    other_workspace = harness._memory_manager.write_with_provenance(
        entry_type="inbox_item",
        key=inbox_item_key(owner_id="owner-user", item_id="legacy-2"),
        value={
            "owner_id": "owner-user",
            "sender_id": "guest-4",
            "channel_id": "chan-legacy",
            "body": "Legacy bare channel binding from another workspace.",
        },
        source=MemorySource(
            origin="external",
            source_id="legacy-msg-2",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:legacy-msg-2",
        scope="user",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    assert other_workspace.kind == "allow"
    assert other_workspace.entry is not None

    await harness.do_channel_ingest(
        {
            "message": {
                "channel": "discord",
                "external_user_id": "guest-4",
                "workspace_hint": "guild-1",
                "reply_target": "chan-legacy",
                "message_id": "msg-55",
                "content": "fresh message on the same channel",
                "metadata": {"interaction_type": "direct"},
            }
        }
    )

    legacy_entry = harness._memory_manager.get_entry(legacy.entry.id)
    assert legacy_entry is not None
    assert isinstance(legacy_entry.value, dict)
    other_workspace_entry = harness._memory_manager.get_entry(other_workspace.entry.id)
    assert other_workspace_entry is not None
    assert isinstance(other_workspace_entry.value, dict)
    channel_binding = compose_channel_binding(
        channel="discord",
        workspace_hint="guild-1",
        channel_id="chan-legacy",
    )
    assert legacy_entry.value["channel_id"] == channel_binding
    assert other_workspace_entry.value["channel_id"] == "chan-legacy"

    pack = harness._memory_manager.compile_active_attention(
        max_tokens=256,
        scope_filter={"user"},
        channel_binding=channel_binding,
    )

    surfaced_ids = {entry.id for entry in pack.entries}
    assert legacy.entry.id in surfaced_ids
    assert other_workspace.entry.id not in surfaced_ids
