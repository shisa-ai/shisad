"""Unit coverage for channel-ingest ingress-handle minting."""

from __future__ import annotations

import json
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
            emoji=":+1:",
        )
    ]
    assert feedback.entry_type == "response_feedback"
    assert feedback.scope == "channel"


@pytest.mark.asyncio
async def test_m8_channel_feedback_downgrades_spoofed_influence_and_supersedes_replay(
    tmp_path: Path,
) -> None:
    harness = _AdminChannelIngressHarness(
        tmp_path=tmp_path,
        default_trust="public",
        allowlisted_users={"guest-2"},
    )

    base_message = {
        "channel": "discord",
        "external_user_id": "guest-2",
        "workspace_hint": "guild-1",
        "reply_target": "chan-2",
        "content": "thumbs up",
        "metadata": {
            "interaction_type": "direct",
            "feedback_signal": "reaction_add",
            "feedback_target_message_id": "agent-msg-9",
            "feedback_emoji": ":+1:",
            "feedback_valence": "positive",
            "feedback_can_influence_retrieval": True,
            "feedback_signal_confidence": 0.95,
            "feedback_policy_allowed": True,
            "feedback_telemetry_weight": 0.15,
        },
    }
    await harness.do_channel_ingest({"message": {**base_message, "message_id": "msg-31"}})

    channel_binding = compose_channel_binding(
        channel="discord",
        workspace_hint="guild-1",
        channel_id="chan-2",
    )
    feedback_key = response_feedback_key(
        channel_id=channel_binding,
        message_id="agent-msg-9",
        actor_external_user_id="guest-2",
        signal="reaction_add",
        emoji=":+1:",
    )
    first = next(
        entry
        for entry in harness._memory_manager.list_entries(limit=20)
        if entry.key == feedback_key
    )
    assert first.value["can_influence_retrieval"] is False
    assert first.value["utility_score"] == 1.0
    assert first.value["harm_score"] == 0.0
    assert first.value["telemetry_weight"] == 0.0
    assert first.value["telemetry_policy"] == "observation_only"

    trusted_metadata = {
        **base_message["metadata"],
        "feedback_event_id": "discord:guild-1:chan-2:agent-msg-9:guest-2:+1",
        "feedback_authenticated_actor": True,
    }
    await harness.do_channel_ingest(
        {
            "message": {
                **base_message,
                "message_id": "msg-32",
                "metadata": trusted_metadata,
            }
        }
    )

    feedback_entries = [
        entry
        for entry in harness._memory_manager.list_entries(limit=20)
        if entry.key == feedback_key
    ]
    current = [entry for entry in feedback_entries if entry.superseded_by is None]
    assert len(current) == 1
    assert current[0].supersedes == first.id
    assert current[0].value["can_influence_retrieval"] is True
    assert current[0].value["utility_score"] == 1.0
    assert current[0].value["harm_score"] == 0.0
    assert current[0].value["telemetry_weight"] == 0.15
    assert current[0].value["telemetry_policy"] == "bounded_retrieval"


@pytest.mark.asyncio
async def test_m8_channel_feedback_spoofed_replay_preserves_trusted_current(
    tmp_path: Path,
) -> None:
    harness = _AdminChannelIngressHarness(
        tmp_path=tmp_path,
        default_trust="public",
        allowlisted_users={"guest-2"},
    )
    trusted_metadata = {
        "interaction_type": "direct",
        "feedback_signal": "reaction_add",
        "feedback_target_message_id": "agent-msg-9",
        "feedback_emoji": ":+1:",
        "feedback_valence": "positive",
        "feedback_can_influence_retrieval": True,
        "feedback_signal_confidence": 0.95,
        "feedback_policy_allowed": True,
        "feedback_telemetry_weight": 0.15,
        "feedback_event_id": "discord:guild-1:chan-2:agent-msg-9:guest-2:+1",
        "feedback_authenticated_actor": True,
    }
    base_message = {
        "channel": "discord",
        "external_user_id": "guest-2",
        "workspace_hint": "guild-1",
        "reply_target": "chan-2",
        "content": "thumbs up",
    }
    await harness.do_channel_ingest(
        {"message": {**base_message, "message_id": "msg-40", "metadata": trusted_metadata}}
    )
    await harness.do_channel_ingest(
        {
            "message": {
                **base_message,
                "message_id": "msg-41",
                "metadata": {
                    **trusted_metadata,
                    "feedback_event_id": "",
                    "feedback_authenticated_actor": False,
                },
            }
        }
    )

    channel_binding = compose_channel_binding(
        channel="discord",
        workspace_hint="guild-1",
        channel_id="chan-2",
    )
    feedback_key = response_feedback_key(
        channel_id=channel_binding,
        message_id="agent-msg-9",
        actor_external_user_id="guest-2",
        signal="reaction_add",
        emoji=":+1:",
    )
    feedback_entries = [
        entry
        for entry in harness._memory_manager.list_entries(limit=20)
        if entry.key == feedback_key or entry.key.startswith(f"{feedback_key}:observation:")
    ]
    canonical = [entry for entry in feedback_entries if entry.key == feedback_key]
    downgraded = [entry for entry in feedback_entries if entry.key != feedback_key]

    assert len(canonical) == 1
    assert canonical[0].superseded_by is None
    assert canonical[0].value["can_influence_retrieval"] is True
    assert canonical[0].value["telemetry_weight"] == 0.15
    assert len(downgraded) == 1
    assert downgraded[0].supersedes is None
    assert downgraded[0].value["can_influence_retrieval"] is False
    assert downgraded[0].value["telemetry_weight"] == 0.0


@pytest.mark.asyncio
async def test_m8_channel_feedback_duplicate_event_id_is_not_replayed(
    tmp_path: Path,
) -> None:
    harness = _AdminChannelIngressHarness(
        tmp_path=tmp_path,
        default_trust="public",
        allowlisted_users={"guest-replay"},
    )
    metadata = {
        "interaction_type": "direct",
        "feedback_signal": "reaction_add",
        "feedback_target_message_id": "agent-msg-replay",
        "feedback_emoji": ":+1:",
        "feedback_valence": "positive",
        "feedback_can_influence_retrieval": True,
        "feedback_signal_confidence": 0.95,
        "feedback_policy_allowed": True,
        "feedback_telemetry_weight": 0.15,
        "feedback_event_id": "discord:guild-1:chan-replay:agent-msg-replay:guest-replay:+1",
        "feedback_authenticated_actor": True,
    }
    base_message = {
        "channel": "discord",
        "external_user_id": "guest-replay",
        "workspace_hint": "guild-1",
        "reply_target": "chan-replay",
        "content": "thumbs up",
    }
    await harness.do_channel_ingest(
        {"message": {**base_message, "message_id": "msg-replay-1", "metadata": metadata}}
    )
    await harness.do_channel_ingest(
        {"message": {**base_message, "message_id": "msg-replay-2", "metadata": metadata}}
    )

    channel_binding = compose_channel_binding(
        channel="discord",
        workspace_hint="guild-1",
        channel_id="chan-replay",
    )
    feedback_key = response_feedback_key(
        channel_id=channel_binding,
        message_id="agent-msg-replay",
        actor_external_user_id="guest-replay",
        signal="reaction_add",
        emoji=":+1:",
    )
    feedback_entries = [
        entry
        for entry in harness._memory_manager.list_entries(limit=20)
        if entry.key == feedback_key
    ]

    assert len(feedback_entries) == 1
    assert feedback_entries[0].superseded_by is None
    assert feedback_entries[0].supersedes is None
    assert feedback_entries[0].value["event_id"] == metadata["feedback_event_id"]
    assert feedback_entries[0].value["telemetry_policy"] == "bounded_retrieval"


@pytest.mark.asyncio
async def test_m8_channel_feedback_reaction_remove_supersedes_trusted_add(
    tmp_path: Path,
) -> None:
    harness = _AdminChannelIngressHarness(
        tmp_path=tmp_path,
        default_trust="public",
        allowlisted_users={"guest-remove"},
    )
    base_message = {
        "channel": "discord",
        "external_user_id": "guest-remove",
        "workspace_hint": "guild-1",
        "reply_target": "chan-remove",
        "content": "reaction event",
    }
    add_metadata = {
        "interaction_type": "direct",
        "feedback_signal": "reaction_add",
        "feedback_target_message_id": "agent-msg-remove",
        "feedback_emoji": ":+1:",
        "feedback_valence": "positive",
        "feedback_can_influence_retrieval": True,
        "feedback_signal_confidence": 0.95,
        "feedback_policy_allowed": True,
        "feedback_telemetry_weight": 0.15,
        "feedback_event_id": "discord:guild-1:chan-remove:agent-msg-remove:guest-remove:+1:add",
        "feedback_authenticated_actor": True,
    }
    await harness.do_channel_ingest(
        {"message": {**base_message, "message_id": "msg-add", "metadata": add_metadata}}
    )
    await harness.do_channel_ingest(
        {
            "message": {
                **base_message,
                "message_id": "msg-remove",
                "metadata": {
                    **add_metadata,
                    "feedback_signal": "reaction_remove",
                    "feedback_valence": "none",
                    "feedback_can_influence_retrieval": False,
                    "feedback_telemetry_weight": 0.0,
                    "feedback_event_id": (
                        "discord:guild-1:chan-remove:agent-msg-remove:"
                        "guest-remove:+1:remove"
                    ),
                },
            }
        }
    )

    channel_binding = compose_channel_binding(
        channel="discord",
        workspace_hint="guild-1",
        channel_id="chan-remove",
    )
    add_key = response_feedback_key(
        channel_id=channel_binding,
        message_id="agent-msg-remove",
        actor_external_user_id="guest-remove",
        signal="reaction_add",
        emoji=":+1:",
    )
    remove_key = response_feedback_key(
        channel_id=channel_binding,
        message_id="agent-msg-remove",
        actor_external_user_id="guest-remove",
        signal="reaction_remove",
        emoji=":+1:",
    )
    current_entries = [
        entry
        for entry in harness._memory_manager.list_entries(limit=20)
        if entry.superseded_by is None
    ]
    current_add = [entry for entry in current_entries if entry.key == add_key]
    current_remove = [entry for entry in current_entries if entry.key == remove_key]

    assert len(current_add) == 1
    assert current_add[0].value["signal"] == "reaction_remove"
    assert current_add[0].value["can_influence_retrieval"] is False
    assert current_add[0].value["telemetry_weight"] == 0.0
    assert current_add[0].supersedes is not None
    assert current_remove == []


@pytest.mark.asyncio
async def test_m8_channel_feedback_reaction_remove_preserves_other_emoji_add(
    tmp_path: Path,
) -> None:
    harness = _AdminChannelIngressHarness(
        tmp_path=tmp_path,
        default_trust="public",
        allowlisted_users={"guest-emoji"},
    )
    base_message = {
        "channel": "discord",
        "external_user_id": "guest-emoji",
        "workspace_hint": "guild-1",
        "reply_target": "chan-emoji",
        "content": "reaction event",
    }
    heart_add = {
        "interaction_type": "direct",
        "feedback_signal": "reaction_add",
        "feedback_target_message_id": "agent-msg-emoji",
        "feedback_emoji": ":heart:",
        "feedback_valence": "positive",
        "feedback_can_influence_retrieval": True,
        "feedback_signal_confidence": 0.95,
        "feedback_policy_allowed": True,
        "feedback_telemetry_weight": 0.15,
        "feedback_event_id": "discord:guild-1:chan-emoji:agent-msg-emoji:guest-emoji:heart:add",
        "feedback_authenticated_actor": True,
    }
    await harness.do_channel_ingest(
        {"message": {**base_message, "message_id": "msg-heart", "metadata": heart_add}}
    )
    await harness.do_channel_ingest(
        {
            "message": {
                **base_message,
                "message_id": "msg-thumb-remove",
                "metadata": {
                    **heart_add,
                    "feedback_signal": "reaction_remove",
                    "feedback_emoji": ":+1:",
                    "feedback_valence": "none",
                    "feedback_can_influence_retrieval": False,
                    "feedback_telemetry_weight": 0.0,
                    "feedback_event_id": (
                        "discord:guild-1:chan-emoji:agent-msg-emoji:"
                        "guest-emoji:+1:remove"
                    ),
                },
            }
        }
    )

    channel_binding = compose_channel_binding(
        channel="discord",
        workspace_hint="guild-1",
        channel_id="chan-emoji",
    )
    heart_add_key = response_feedback_key(
        channel_id=channel_binding,
        message_id="agent-msg-emoji",
        actor_external_user_id="guest-emoji",
        signal="reaction_add",
        emoji=":heart:",
    )
    thumb_remove_key = response_feedback_key(
        channel_id=channel_binding,
        message_id="agent-msg-emoji",
        actor_external_user_id="guest-emoji",
        signal="reaction_remove",
        emoji=":+1:",
    )
    current_entries = [
        entry
        for entry in harness._memory_manager.list_entries(limit=20)
        if entry.superseded_by is None
    ]
    current_heart_add = [entry for entry in current_entries if entry.key == heart_add_key]
    current_thumb_remove = [entry for entry in current_entries if entry.key == thumb_remove_key]

    assert len(current_heart_add) == 1
    assert current_heart_add[0].value["emoji"] == ":heart:"
    assert current_heart_add[0].value["signal"] == "reaction_add"
    assert current_heart_add[0].value["can_influence_retrieval"] is True
    assert current_heart_add[0].superseded_by is None
    assert len(current_thumb_remove) == 1
    assert current_thumb_remove[0].value["signal"] == "reaction_remove"
    assert current_thumb_remove[0].supersedes is None


@pytest.mark.asyncio
async def test_m8_channel_feedback_remove_migrates_matching_legacy_bare_add(
    tmp_path: Path,
) -> None:
    harness = _AdminChannelIngressHarness(
        tmp_path=tmp_path,
        default_trust="public",
        allowlisted_users={"guest-legacy-feedback"},
    )
    channel_binding = compose_channel_binding(
        channel="discord",
        workspace_hint="guild-1",
        channel_id="chan-legacy-feedback",
    )
    legacy_add_key = response_feedback_key(
        channel_id=channel_binding,
        message_id="agent-msg-legacy-feedback",
        actor_external_user_id="guest-legacy-feedback",
        signal="reaction_add",
    )
    emoji_add_key = response_feedback_key(
        channel_id=channel_binding,
        message_id="agent-msg-legacy-feedback",
        actor_external_user_id="guest-legacy-feedback",
        signal="reaction_add",
        emoji=":+1:",
    )
    legacy_add = harness._memory_manager.write_with_provenance(
        entry_type="response_feedback",
        key=legacy_add_key,
        value={
            "channel_id": channel_binding,
            "event_id": "discord:guild-1:chan-legacy-feedback:agent-msg:+1:add",
            "target_message_id": "agent-msg-legacy-feedback",
            "actor_external_user_id": "guest-legacy-feedback",
            "signal": "reaction_add",
            "emoji": ":+1:",
            "valence": "positive",
            "observed_at": "2026-05-01T00:00:00Z",
            "signal_confidence": 0.95,
            "authenticated_actor": True,
            "policy_allowed": True,
            "can_influence_retrieval": True,
            "utility_score": 1.0,
            "harm_score": 0.0,
            "telemetry_weight": 0.15,
            "telemetry_policy": "bounded_retrieval",
        },
        source=MemorySource(
            origin="external",
            source_id="discord:legacy-feedback-add",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:legacy-feedback-add",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    assert legacy_add.entry is not None

    await harness.do_channel_ingest(
        {
            "message": {
                "channel": "discord",
                "external_user_id": "guest-legacy-feedback",
                "workspace_hint": "guild-1",
                "reply_target": "chan-legacy-feedback",
                "message_id": "msg-legacy-feedback-remove",
                "content": "remove reaction event",
                "metadata": {
                    "interaction_type": "direct",
                    "feedback_signal": "reaction_remove",
                    "feedback_target_message_id": "agent-msg-legacy-feedback",
                    "feedback_emoji": ":+1:",
                    "feedback_valence": "none",
                    "feedback_signal_confidence": 0.95,
                    "feedback_policy_allowed": True,
                    "feedback_event_id": (
                        "discord:guild-1:chan-legacy-feedback:"
                        "agent-msg-legacy-feedback:guest-legacy-feedback:+1:remove"
                    ),
                    "feedback_authenticated_actor": True,
                },
            }
        }
    )

    migrated_legacy = harness._memory_manager.get_entry(legacy_add.entry.id)
    assert migrated_legacy is not None
    assert migrated_legacy.key == emoji_add_key
    assert migrated_legacy.superseded_by is not None

    current_entries = [
        entry
        for entry in harness._memory_manager.list_entries(limit=20)
        if entry.superseded_by is None
    ]
    assert [entry for entry in current_entries if entry.key == legacy_add_key] == []
    current_add = [entry for entry in current_entries if entry.key == emoji_add_key]
    assert len(current_add) == 1
    assert current_add[0].value["signal"] == "reaction_remove"
    assert current_add[0].value["emoji"] == ":+1:"
    assert current_add[0].supersedes == legacy_add.entry.id


@pytest.mark.asyncio
async def test_m8_channel_feedback_remove_retires_legacy_bare_add_with_emoji_current(
    tmp_path: Path,
) -> None:
    harness = _AdminChannelIngressHarness(
        tmp_path=tmp_path,
        default_trust="public",
        allowlisted_users={"guest-orphan-feedback"},
    )
    channel_binding = compose_channel_binding(
        channel="discord",
        workspace_hint="guild-1",
        channel_id="chan-orphan-feedback",
    )
    legacy_add_key = response_feedback_key(
        channel_id=channel_binding,
        message_id="agent-msg-orphan-feedback",
        actor_external_user_id="guest-orphan-feedback",
        signal="reaction_add",
    )
    emoji_add_key = response_feedback_key(
        channel_id=channel_binding,
        message_id="agent-msg-orphan-feedback",
        actor_external_user_id="guest-orphan-feedback",
        signal="reaction_add",
        emoji=":+1:",
    )
    feedback_value = {
        "channel_id": channel_binding,
        "event_id": "discord:guild-1:chan-orphan-feedback:agent-msg:+1:add",
        "target_message_id": "agent-msg-orphan-feedback",
        "actor_external_user_id": "guest-orphan-feedback",
        "signal": "reaction_add",
        "emoji": ":+1:",
        "valence": "positive",
        "observed_at": "2026-05-01T00:00:00Z",
        "signal_confidence": 0.95,
        "authenticated_actor": True,
        "policy_allowed": True,
        "can_influence_retrieval": True,
        "utility_score": 1.0,
        "harm_score": 0.0,
        "telemetry_weight": 0.15,
        "telemetry_policy": "bounded_retrieval",
    }
    legacy_add = harness._memory_manager.write_with_provenance(
        entry_type="response_feedback",
        key=legacy_add_key,
        value=feedback_value,
        source=MemorySource(
            origin="external",
            source_id="discord:orphan-feedback-bare-add",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:orphan-feedback-bare-add",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    emoji_add = harness._memory_manager.write_with_provenance(
        entry_type="response_feedback",
        key=emoji_add_key,
        value={
            **feedback_value,
            "event_id": "discord:guild-1:chan-orphan-feedback:agent-msg:+1:add:emoji",
        },
        source=MemorySource(
            origin="external",
            source_id="discord:orphan-feedback-emoji-add",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:orphan-feedback-emoji-add",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    assert legacy_add.entry is not None
    assert emoji_add.entry is not None

    await harness.do_channel_ingest(
        {
            "message": {
                "channel": "discord",
                "external_user_id": "guest-orphan-feedback",
                "workspace_hint": "guild-1",
                "reply_target": "chan-orphan-feedback",
                "message_id": "msg-orphan-feedback-remove",
                "content": "remove reaction event",
                "metadata": {
                    "interaction_type": "direct",
                    "feedback_signal": "reaction_remove",
                    "feedback_target_message_id": "agent-msg-orphan-feedback",
                    "feedback_emoji": ":+1:",
                    "feedback_valence": "none",
                    "feedback_signal_confidence": 0.95,
                    "feedback_policy_allowed": True,
                    "feedback_event_id": (
                        "discord:guild-1:chan-orphan-feedback:"
                        "agent-msg-orphan-feedback:guest-orphan-feedback:+1:remove"
                    ),
                    "feedback_authenticated_actor": True,
                },
            }
        }
    )

    retired_legacy = harness._memory_manager.get_entry(legacy_add.entry.id)
    retired_emoji = harness._memory_manager.get_entry(emoji_add.entry.id)
    assert retired_legacy is not None
    assert retired_legacy.superseded_by is not None
    assert retired_emoji is not None
    assert retired_emoji.superseded_by is not None

    current_entries = [
        entry
        for entry in harness._memory_manager.list_entries(limit=20)
        if entry.superseded_by is None
    ]
    assert [entry for entry in current_entries if entry.key == legacy_add_key] == []
    current_add = [entry for entry in current_entries if entry.key == emoji_add_key]
    assert len(current_add) == 1
    assert current_add[0].value["signal"] == "reaction_remove"
    assert current_add[0].value["emoji"] == ":+1:"


@pytest.mark.asyncio
async def test_m8_channel_ingest_preserves_owner_curated_channel_records(
    tmp_path: Path,
) -> None:
    harness = _AdminChannelIngressHarness(
        tmp_path=tmp_path,
        default_trust="public",
        allowlisted_users={"guest-curated"},
    )
    channel_binding = compose_channel_binding(
        channel="discord",
        workspace_hint="guild-1",
        channel_id="chan-curated",
    )
    note_key = person_note_key(channel_id=channel_binding, external_user_id="guest-curated")
    summary_key = channel_summary_key(channel_id=channel_binding, summary_kind="digest")
    curated_note = harness._memory_manager.write_with_provenance(
        entry_type="person_note",
        key=note_key,
        value={
            "external_user_id": "guest-curated",
            "display_name": "Curated Guest",
            "channel_id": channel_binding,
            "interaction_summary": "Owner curated summary.",
            "confidence_source": "owner_curated",
            "owner_curated": True,
        },
        source=MemorySource(origin="user", source_id="curated-note", extraction_method="manual"),
        source_origin="user_corrected",
        channel_trust="command",
        confirmation_status="user_corrected",
        source_id="curated-note",
        scope="channel",
        confidence=0.95,
        confirmation_satisfied=True,
    )
    curated_summary = harness._memory_manager.write_with_provenance(
        entry_type="channel_summary",
        key=summary_key,
        value={
            "channel_id": channel_binding,
            "summary_kind": "digest",
            "summary_text": "Owner curated digest.",
            "confidence_source": "observed",
            "owner_curated": False,
        },
        source=MemorySource(origin="user", source_id="curated-summary", extraction_method="manual"),
        source_origin="user_corrected",
        channel_trust="command",
        confirmation_status="user_corrected",
        source_id="curated-summary",
        scope="channel",
        confidence=0.95,
        confirmation_satisfied=True,
    )
    assert curated_note.entry is not None
    assert curated_summary.entry is not None

    await harness.do_channel_ingest(
        {
            "message": {
                "channel": "discord",
                "external_user_id": "guest-curated",
                "workspace_hint": "guild-1",
                "reply_target": "chan-curated",
                "message_id": "msg-curated-1",
                "content": "fresh observed note",
                "metadata": {
                    "interaction_type": "direct",
                    "display_name": "Curated Guest",
                    "summary_kind": "digest",
                    "summary_text": "Observed digest.",
                },
            }
        }
    )

    preserved_note = harness._memory_manager.get_entry(curated_note.entry.id)
    preserved_summary = harness._memory_manager.get_entry(curated_summary.entry.id)
    assert preserved_note is not None
    assert preserved_note.superseded_by is None
    assert preserved_note.value["owner_curated"] is True
    assert preserved_summary is not None
    assert preserved_summary.superseded_by is None
    assert preserved_summary.source_origin == "user_corrected"

    observed_entries = [
        entry
        for entry in harness._memory_manager.list_entries(limit=20)
        if entry.key.startswith(f"{note_key}:observed")
        or entry.key.startswith(f"{summary_key}:observed")
    ]
    assert {entry.entry_type for entry in observed_entries} == {"person_note", "channel_summary"}
    assert all(entry.supersedes is None for entry in observed_entries)
    assert all(entry.value["owner_curated"] is False for entry in observed_entries)


@pytest.mark.asyncio
async def test_m8_channel_ingest_side_key_skips_legacy_canonical_migration(
    tmp_path: Path,
) -> None:
    harness = _AdminChannelIngressHarness(
        tmp_path=tmp_path,
        default_trust="public",
        allowlisted_users={"guest-legacy"},
    )
    for session_id, message_id in (
        ("sess-m8-legacy-note", "legacy-m8-note-msg"),
        ("sess-m8-legacy-summary", "legacy-m8-summary-msg"),
    ):
        harness._transcript_store.append(
            SessionId(session_id),
            role="user",
            content=f"legacy {message_id}",
            taint_labels=set(),
            metadata={
                "channel_message_id": message_id,
                "delivery_target": {
                    "channel": "discord",
                    "recipient": "chan-m8-legacy",
                    "workspace_hint": "guild-1",
                    "thread_id": "",
                },
            },
        )

    channel_binding = compose_channel_binding(
        channel="discord",
        workspace_hint="guild-1",
        channel_id="chan-m8-legacy",
    )
    canonical_note_key = person_note_key(
        channel_id=channel_binding,
        external_user_id="guest-legacy",
    )
    canonical_summary_key = channel_summary_key(
        channel_id=channel_binding,
        summary_kind="digest",
    )
    legacy_note_key = person_note_key(
        channel_id="chan-m8-legacy",
        external_user_id="guest-legacy",
    )
    legacy_summary_key = channel_summary_key(
        channel_id="chan-m8-legacy",
        summary_kind="digest",
    )
    curated_note = harness._memory_manager.write_with_provenance(
        entry_type="person_note",
        key=canonical_note_key,
        value={
            "external_user_id": "guest-legacy",
            "display_name": "Legacy Guest",
            "channel_id": channel_binding,
            "interaction_summary": "Owner curated canonical note.",
            "confidence_source": "owner_curated",
            "owner_curated": True,
        },
        source=MemorySource(origin="user", source_id="curated-note", extraction_method="manual"),
        source_origin="user_corrected",
        channel_trust="command",
        confirmation_status="user_corrected",
        source_id="curated-note",
        scope="channel",
        confidence=0.95,
        confirmation_satisfied=True,
    )
    curated_summary = harness._memory_manager.write_with_provenance(
        entry_type="channel_summary",
        key=canonical_summary_key,
        value={
            "channel_id": channel_binding,
            "summary_kind": "digest",
            "summary_text": "Owner curated digest.",
            "confidence_source": "owner_curated",
            "owner_curated": True,
        },
        source=MemorySource(
            origin="user",
            source_id="curated-summary",
            extraction_method="manual",
        ),
        source_origin="user_corrected",
        channel_trust="command",
        confirmation_status="user_corrected",
        source_id="curated-summary",
        scope="channel",
        confidence=0.95,
        confirmation_satisfied=True,
    )
    legacy_note = harness._memory_manager.write_with_provenance(
        entry_type="person_note",
        key=legacy_note_key,
        value={
            "external_user_id": "guest-legacy",
            "display_name": "Legacy Guest",
            "channel_id": "chan-m8-legacy",
            "interaction_summary": "Legacy observed note.",
        },
        source=MemorySource(
            origin="external",
            source_id="discord:legacy-m8-note-msg",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:legacy-m8-note-msg",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    legacy_summary = harness._memory_manager.write_with_provenance(
        entry_type="channel_summary",
        key=legacy_summary_key,
        value={
            "channel_id": "chan-m8-legacy",
            "summary_kind": "digest",
            "summary_text": "Legacy observed digest.",
        },
        source=MemorySource(
            origin="external",
            source_id="discord:legacy-m8-summary-msg",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:legacy-m8-summary-msg",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    assert curated_note.entry is not None
    assert curated_summary.entry is not None
    assert legacy_note.entry is not None
    assert legacy_summary.entry is not None

    await harness.do_channel_ingest(
        {
            "message": {
                "channel": "discord",
                "external_user_id": "guest-legacy",
                "workspace_hint": "guild-1",
                "reply_target": "chan-m8-legacy",
                "message_id": "msg-m8-legacy",
                "content": "fresh observed note beside curated state",
                "metadata": {
                    "interaction_type": "direct",
                    "display_name": "Legacy Guest",
                    "summary_kind": "digest",
                    "summary_text": "Fresh observed digest.",
                },
            }
        }
    )

    preserved_note = harness._memory_manager.get_entry(curated_note.entry.id)
    preserved_summary = harness._memory_manager.get_entry(curated_summary.entry.id)
    preserved_legacy_note = harness._memory_manager.get_entry(legacy_note.entry.id)
    preserved_legacy_summary = harness._memory_manager.get_entry(legacy_summary.entry.id)
    observed_note_key = f"{canonical_note_key}:observed"
    observed_summary_key = f"{canonical_summary_key}:observed"
    assert preserved_note is not None
    assert preserved_note.superseded_by is None
    assert preserved_note.value["owner_curated"] is True
    assert preserved_summary is not None
    assert preserved_summary.superseded_by is None
    assert preserved_summary.value["owner_curated"] is True
    assert preserved_legacy_note is not None
    assert preserved_legacy_note.key == canonical_note_key
    assert preserved_legacy_note.superseded_by is not None
    assert preserved_legacy_summary is not None
    assert preserved_legacy_summary.key == canonical_summary_key
    assert preserved_legacy_summary.superseded_by is not None

    current_entries = harness._memory_manager.list_entries(limit=50)
    canonical_observed = [
        entry
        for entry in current_entries
        if entry.key in {canonical_note_key, canonical_summary_key}
        and entry.source_origin == "external_message"
        and entry.superseded_by is None
    ]
    observed_side_entries = [
        entry
        for entry in current_entries
        if entry.key in {observed_note_key, observed_summary_key}
        and entry.superseded_by is None
    ]
    assert canonical_observed == []
    assert {entry.entry_type for entry in observed_side_entries} == {
        "person_note",
        "channel_summary",
    }
    assert all(entry.supersedes is None for entry in observed_side_entries)
    assert [
        entry
        for entry in current_entries
        if entry.key in {legacy_note_key, legacy_summary_key}
        and entry.superseded_by is None
    ] == []


@pytest.mark.asyncio
async def test_m8_channel_ingest_preserves_legacy_owner_curated_records(
    tmp_path: Path,
) -> None:
    harness = _AdminChannelIngressHarness(
        tmp_path=tmp_path,
        default_trust="public",
        allowlisted_users={"guest-legacy-curated"},
    )
    for session_id, message_id in (
        ("sess-m8-legacy-curated-note", "legacy-m8-curated-note-msg"),
        ("sess-m8-legacy-curated-summary", "legacy-m8-curated-summary-msg"),
    ):
        harness._transcript_store.append(
            SessionId(session_id),
            role="user",
            content=f"legacy curated {message_id}",
            taint_labels=set(),
            metadata={
                "channel_message_id": message_id,
                "delivery_target": {
                    "channel": "discord",
                    "recipient": "chan-m8-legacy-curated",
                    "workspace_hint": "guild-1",
                    "thread_id": "",
                },
            },
        )

    channel_binding = compose_channel_binding(
        channel="discord",
        workspace_hint="guild-1",
        channel_id="chan-m8-legacy-curated",
    )
    canonical_note_key = person_note_key(
        channel_id=channel_binding,
        external_user_id="guest-legacy-curated",
    )
    canonical_summary_key = channel_summary_key(
        channel_id=channel_binding,
        summary_kind="digest",
    )
    legacy_note = harness._memory_manager.write_with_provenance(
        entry_type="person_note",
        key=person_note_key(
            channel_id="chan-m8-legacy-curated",
            external_user_id="guest-legacy-curated",
        ),
        value={
            "external_user_id": "guest-legacy-curated",
            "display_name": "Legacy Curated Guest",
            "channel_id": "chan-m8-legacy-curated",
            "interaction_summary": "Legacy owner-curated note.",
            "confidence_source": "owner_curated",
            "owner_curated": True,
        },
        source=MemorySource(
            origin="user",
            source_id="discord:legacy-m8-curated-note-msg",
            extraction_method="manual",
        ),
        source_origin="user_corrected",
        channel_trust="command",
        confirmation_status="user_corrected",
        source_id="discord:legacy-m8-curated-note-msg",
        scope="channel",
        confidence=0.95,
        confirmation_satisfied=True,
    )
    legacy_summary = harness._memory_manager.write_with_provenance(
        entry_type="channel_summary",
        key=channel_summary_key(
            channel_id="chan-m8-legacy-curated",
            summary_kind="digest",
        ),
        value={
            "channel_id": "chan-m8-legacy-curated",
            "summary_kind": "digest",
            "summary_text": "Legacy owner-curated digest.",
            "confidence_source": "owner_curated",
            "owner_curated": True,
        },
        source=MemorySource(
            origin="user",
            source_id="discord:legacy-m8-curated-summary-msg",
            extraction_method="manual",
        ),
        source_origin="user_corrected",
        channel_trust="command",
        confirmation_status="user_corrected",
        source_id="discord:legacy-m8-curated-summary-msg",
        scope="channel",
        confidence=0.95,
        confirmation_satisfied=True,
    )
    assert legacy_note.entry is not None
    assert legacy_summary.entry is not None

    await harness.do_channel_ingest(
        {
            "message": {
                "channel": "discord",
                "external_user_id": "guest-legacy-curated",
                "workspace_hint": "guild-1",
                "reply_target": "chan-m8-legacy-curated",
                "message_id": "msg-m8-legacy-curated",
                "content": "fresh observed beside legacy curated state",
                "metadata": {
                    "interaction_type": "direct",
                    "display_name": "Legacy Curated Guest",
                    "summary_kind": "digest",
                    "summary_text": "Fresh observed digest.",
                },
            }
        }
    )

    preserved_note = harness._memory_manager.get_entry(legacy_note.entry.id)
    preserved_summary = harness._memory_manager.get_entry(legacy_summary.entry.id)
    assert preserved_note is not None
    assert preserved_note.key == canonical_note_key
    assert preserved_note.superseded_by is None
    assert preserved_note.value["owner_curated"] is True
    assert preserved_summary is not None
    assert preserved_summary.key == canonical_summary_key
    assert preserved_summary.superseded_by is None
    assert preserved_summary.value["owner_curated"] is True

    observed_side_entries = [
        entry
        for entry in harness._memory_manager.list_entries(limit=50)
        if entry.superseded_by is None
        and (
            entry.key == f"{canonical_note_key}:observed"
            or entry.key == f"{canonical_summary_key}:observed"
        )
    ]
    assert {entry.entry_type for entry in observed_side_entries} == {
        "person_note",
        "channel_summary",
    }
    assert all(entry.supersedes is None for entry in observed_side_entries)


@pytest.mark.asyncio
async def test_m8_channel_ingest_retires_legacy_duplicates_with_canonical_current(
    tmp_path: Path,
) -> None:
    harness = _AdminChannelIngressHarness(
        tmp_path=tmp_path,
        default_trust="public",
        allowlisted_users={"guest-duplicate"},
    )
    for session_id, message_id in (
        ("sess-m8-duplicate-note", "legacy-m8-duplicate-note-msg"),
        ("sess-m8-duplicate-summary", "legacy-m8-duplicate-summary-msg"),
    ):
        harness._transcript_store.append(
            SessionId(session_id),
            role="user",
            content=f"legacy duplicate {message_id}",
            taint_labels=set(),
            metadata={
                "channel_message_id": message_id,
                "delivery_target": {
                    "channel": "discord",
                    "recipient": "chan-m8-duplicate",
                    "workspace_hint": "guild-1",
                    "thread_id": "",
                },
            },
        )

    channel_binding = compose_channel_binding(
        channel="discord",
        workspace_hint="guild-1",
        channel_id="chan-m8-duplicate",
    )
    canonical_note = harness._memory_manager.write_with_provenance(
        entry_type="person_note",
        key=person_note_key(channel_id=channel_binding, external_user_id="guest-duplicate"),
        value={
            "external_user_id": "guest-duplicate",
            "display_name": "Duplicate Guest",
            "channel_id": channel_binding,
            "total_interactions": 3,
            "interaction_summary": "Canonical observed note.",
        },
        source=MemorySource(
            origin="external",
            source_id="discord:canonical-duplicate-note",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:canonical-duplicate-note",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    canonical_summary = harness._memory_manager.write_with_provenance(
        entry_type="channel_summary",
        key=channel_summary_key(channel_id=channel_binding, summary_kind="digest"),
        value={
            "channel_id": channel_binding,
            "summary_kind": "digest",
            "summary_text": "Canonical observed digest.",
        },
        source=MemorySource(
            origin="external",
            source_id="discord:canonical-duplicate-summary",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:canonical-duplicate-summary",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    legacy_note = harness._memory_manager.write_with_provenance(
        entry_type="person_note",
        key=person_note_key(channel_id="chan-m8-duplicate", external_user_id="guest-duplicate"),
        value={
            "external_user_id": "guest-duplicate",
            "display_name": "Duplicate Guest",
            "channel_id": "chan-m8-duplicate",
            "total_interactions": 1,
            "interaction_summary": "Legacy duplicate note.",
        },
        source=MemorySource(
            origin="external",
            source_id="discord:legacy-m8-duplicate-note-msg",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:legacy-m8-duplicate-note-msg",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    legacy_summary = harness._memory_manager.write_with_provenance(
        entry_type="channel_summary",
        key=channel_summary_key(channel_id="chan-m8-duplicate", summary_kind="digest"),
        value={
            "channel_id": "chan-m8-duplicate",
            "summary_kind": "digest",
            "summary_text": "Legacy duplicate digest.",
        },
        source=MemorySource(
            origin="external",
            source_id="discord:legacy-m8-duplicate-summary-msg",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:legacy-m8-duplicate-summary-msg",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    assert canonical_note.entry is not None
    assert canonical_summary.entry is not None
    assert legacy_note.entry is not None
    assert legacy_summary.entry is not None

    await harness.do_channel_ingest(
        {
            "message": {
                "channel": "discord",
                "external_user_id": "guest-duplicate",
                "workspace_hint": "guild-1",
                "reply_target": "chan-m8-duplicate",
                "message_id": "msg-m8-duplicate",
                "content": "fresh canonical duplicate update",
                "metadata": {
                    "interaction_type": "direct",
                    "display_name": "Duplicate Guest",
                    "summary_kind": "digest",
                    "summary_text": "Fresh canonical digest.",
                },
            }
        }
    )

    retired_legacy_note = harness._memory_manager.get_entry(legacy_note.entry.id)
    retired_legacy_summary = harness._memory_manager.get_entry(legacy_summary.entry.id)
    assert retired_legacy_note is not None
    assert retired_legacy_note.superseded_by is not None
    assert retired_legacy_summary is not None
    assert retired_legacy_summary.superseded_by is not None

    current_entries = [
        entry
        for entry in harness._memory_manager.list_entries(limit=50)
        if entry.superseded_by is None
    ]
    assert [
        entry
        for entry in current_entries
        if entry.key
        in {
            person_note_key(channel_id="chan-m8-duplicate", external_user_id="guest-duplicate"),
            channel_summary_key(channel_id="chan-m8-duplicate", summary_kind="digest"),
        }
    ] == []


@pytest.mark.asyncio
async def test_m8_channel_ingest_promotes_trusted_legacy_over_observed_canonical(
    tmp_path: Path,
) -> None:
    harness = _AdminChannelIngressHarness(
        tmp_path=tmp_path,
        default_trust="public",
        allowlisted_users={"guest-promote"},
    )
    for session_id, message_id in (
        ("sess-m8-promote-note", "legacy-m8-promote-note-msg"),
        ("sess-m8-promote-summary", "legacy-m8-promote-summary-msg"),
    ):
        harness._transcript_store.append(
            SessionId(session_id),
            role="user",
            content=f"legacy trusted {message_id}",
            taint_labels=set(),
            metadata={
                "channel_message_id": message_id,
                "delivery_target": {
                    "channel": "discord",
                    "recipient": "chan-m8-promote",
                    "workspace_hint": "guild-1",
                    "thread_id": "",
                },
            },
        )

    channel_binding = compose_channel_binding(
        channel="discord",
        workspace_hint="guild-1",
        channel_id="chan-m8-promote",
    )
    canonical_note_key = person_note_key(
        channel_id=channel_binding,
        external_user_id="guest-promote",
    )
    canonical_summary_key = channel_summary_key(
        channel_id=channel_binding,
        summary_kind="digest",
    )
    observed_note = harness._memory_manager.write_with_provenance(
        entry_type="person_note",
        key=canonical_note_key,
        value={
            "external_user_id": "guest-promote",
            "display_name": "Promote Guest",
            "channel_id": channel_binding,
            "interaction_summary": "Observed canonical note.",
        },
        source=MemorySource(
            origin="external",
            source_id="discord:observed-promote-note",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:observed-promote-note",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    observed_summary = harness._memory_manager.write_with_provenance(
        entry_type="channel_summary",
        key=canonical_summary_key,
        value={
            "channel_id": channel_binding,
            "summary_kind": "digest",
            "summary_text": "Observed canonical digest.",
        },
        source=MemorySource(
            origin="external",
            source_id="discord:observed-promote-summary",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:observed-promote-summary",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    trusted_note = harness._memory_manager.write_with_provenance(
        entry_type="person_note",
        key=person_note_key(channel_id="chan-m8-promote", external_user_id="guest-promote"),
        value={
            "external_user_id": "guest-promote",
            "display_name": "Promote Guest",
            "channel_id": "chan-m8-promote",
            "interaction_summary": "Trusted legacy note.",
            "confidence_source": "owner_curated",
            "owner_curated": True,
        },
        source=MemorySource(
            origin="user",
            source_id="discord:legacy-m8-promote-note-msg",
            extraction_method="manual",
        ),
        source_origin="user_corrected",
        channel_trust="command",
        confirmation_status="user_corrected",
        source_id="discord:legacy-m8-promote-note-msg",
        scope="channel",
        confidence=0.95,
        confirmation_satisfied=True,
    )
    trusted_summary = harness._memory_manager.write_with_provenance(
        entry_type="channel_summary",
        key=channel_summary_key(channel_id="chan-m8-promote", summary_kind="digest"),
        value={
            "channel_id": "chan-m8-promote",
            "summary_kind": "digest",
            "summary_text": "Trusted legacy digest.",
            "confidence_source": "owner_curated",
            "owner_curated": True,
        },
        source=MemorySource(
            origin="user",
            source_id="discord:legacy-m8-promote-summary-msg",
            extraction_method="manual",
        ),
        source_origin="user_corrected",
        channel_trust="command",
        confirmation_status="user_corrected",
        source_id="discord:legacy-m8-promote-summary-msg",
        scope="channel",
        confidence=0.95,
        confirmation_satisfied=True,
    )
    assert observed_note.entry is not None
    assert observed_summary.entry is not None
    assert trusted_note.entry is not None
    assert trusted_summary.entry is not None

    await harness.do_channel_ingest(
        {
            "message": {
                "channel": "discord",
                "external_user_id": "guest-promote",
                "workspace_hint": "guild-1",
                "reply_target": "chan-m8-promote",
                "message_id": "msg-m8-promote",
                "content": "fresh observed after trusted legacy",
                "metadata": {
                    "interaction_type": "direct",
                    "display_name": "Promote Guest",
                    "summary_kind": "digest",
                    "summary_text": "Fresh observed digest.",
                },
            }
        }
    )

    promoted_note = harness._memory_manager.get_entry(trusted_note.entry.id)
    promoted_summary = harness._memory_manager.get_entry(trusted_summary.entry.id)
    superseded_observed_note = harness._memory_manager.get_entry(observed_note.entry.id)
    superseded_observed_summary = harness._memory_manager.get_entry(observed_summary.entry.id)
    assert promoted_note is not None
    assert promoted_note.key == canonical_note_key
    assert promoted_note.superseded_by is None
    assert promoted_note.supersedes == observed_note.entry.id
    assert promoted_note.value["owner_curated"] is True
    assert promoted_note.value["supersedes_entry_id"] == observed_note.entry.id
    assert promoted_summary is not None
    assert promoted_summary.key == canonical_summary_key
    assert promoted_summary.superseded_by is None
    assert promoted_summary.supersedes == observed_summary.entry.id
    assert promoted_summary.value["owner_curated"] is True
    assert promoted_summary.value["supersedes_entry_id"] == observed_summary.entry.id
    assert superseded_observed_note is not None
    assert superseded_observed_note.superseded_by == trusted_note.entry.id
    assert superseded_observed_summary is not None
    assert superseded_observed_summary.superseded_by == trusted_summary.entry.id

    current_side_entries = [
        entry
        for entry in harness._memory_manager.list_entries(limit=50)
        if entry.superseded_by is None
        and (
            entry.key == f"{canonical_note_key}:observed"
            or entry.key == f"{canonical_summary_key}:observed"
        )
    ]
    assert {entry.entry_type for entry in current_side_entries} == {
        "person_note",
        "channel_summary",
    }
    assert all(entry.supersedes is None for entry in current_side_entries)


@pytest.mark.asyncio
async def test_m8_channel_ingest_skips_pending_review_observed_side_rows(
    tmp_path: Path,
) -> None:
    harness = _AdminChannelIngressHarness(
        tmp_path=tmp_path,
        default_trust="public",
        allowlisted_users={"guest-pending"},
    )
    channel_binding = compose_channel_binding(
        channel="discord",
        workspace_hint="guild-1",
        channel_id="chan-m8-pending",
    )
    note_key = person_note_key(channel_id=channel_binding, external_user_id="guest-pending")
    summary_key = channel_summary_key(channel_id=channel_binding, summary_kind="digest")
    observed_note_key = f"{note_key}:observed"
    observed_summary_key = f"{summary_key}:observed"
    curated_note = harness._memory_manager.write_with_provenance(
        entry_type="person_note",
        key=note_key,
        value={
            "external_user_id": "guest-pending",
            "display_name": "Pending Guest",
            "channel_id": channel_binding,
            "interaction_summary": "Owner curated canonical note.",
            "confidence_source": "owner_curated",
            "owner_curated": True,
        },
        source=MemorySource(origin="user", source_id="curated-note", extraction_method="manual"),
        source_origin="user_corrected",
        channel_trust="command",
        confirmation_status="user_corrected",
        source_id="curated-note",
        scope="channel",
        confidence=0.95,
        confirmation_satisfied=True,
    )
    curated_summary = harness._memory_manager.write_with_provenance(
        entry_type="channel_summary",
        key=summary_key,
        value={
            "channel_id": channel_binding,
            "summary_kind": "digest",
            "summary_text": "Owner curated digest.",
            "confidence_source": "owner_curated",
            "owner_curated": True,
        },
        source=MemorySource(
            origin="user",
            source_id="curated-summary",
            extraction_method="manual",
        ),
        source_origin="user_corrected",
        channel_trust="command",
        confirmation_status="user_corrected",
        source_id="curated-summary",
        scope="channel",
        confidence=0.95,
        confirmation_satisfied=True,
    )
    pending_note = harness._memory_manager.write_with_provenance(
        entry_type="person_note",
        key=observed_note_key,
        value={
            "external_user_id": "guest-pending",
            "display_name": "Pending Guest",
            "channel_id": channel_binding,
            "interaction_summary": "Pending observed note.",
            "confidence_source": "observed",
            "owner_curated": False,
        },
        source=MemorySource(
            origin="external",
            source_id="discord:pending-observed-note",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="pending_review",
        source_id="discord:pending-observed-note",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=False,
    )
    pending_summary = harness._memory_manager.write_with_provenance(
        entry_type="channel_summary",
        key=observed_summary_key,
        value={
            "channel_id": channel_binding,
            "summary_kind": "digest",
            "summary_text": "Pending observed digest.",
            "confidence_source": "observed",
            "owner_curated": False,
        },
        source=MemorySource(
            origin="external",
            source_id="discord:pending-observed-summary",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="pending_review",
        source_id="discord:pending-observed-summary",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=False,
    )
    assert curated_note.entry is not None
    assert curated_summary.entry is not None
    assert pending_note.entry is not None
    assert pending_summary.entry is not None

    await harness.do_channel_ingest(
        {
            "message": {
                "channel": "discord",
                "external_user_id": "guest-pending",
                "workspace_hint": "guild-1",
                "reply_target": "chan-m8-pending",
                "message_id": "msg-m8-pending",
                "content": "fresh observed while side row pending review",
                "metadata": {
                    "interaction_type": "direct",
                    "display_name": "Pending Guest",
                    "summary_kind": "digest",
                    "summary_text": "Fresh observed digest.",
                },
            }
        }
    )

    pending_note_entry = harness._memory_manager.get_entry(
        pending_note.entry.id,
        include_pending_review=True,
    )
    pending_summary_entry = harness._memory_manager.get_entry(
        pending_summary.entry.id,
        include_pending_review=True,
    )
    assert pending_note_entry is not None
    assert pending_note_entry.confirmation_status == "pending_review"
    assert pending_note_entry.superseded_by is None
    assert pending_summary_entry is not None
    assert pending_summary_entry.confirmation_status == "pending_review"
    assert pending_summary_entry.superseded_by is None
    assert [
        entry
        for entry in harness._memory_manager.list_entries(limit=50)
        if entry.key in {observed_note_key, observed_summary_key}
    ] == []


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


@pytest.mark.asyncio
async def test_m3_channel_ingest_carries_forward_legacy_keyed_channel_state(
    tmp_path: Path,
) -> None:
    harness = _AdminChannelIngressHarness(
        tmp_path=tmp_path,
        default_trust="public",
        allowlisted_users={"guest-5"},
    )
    for session_id, message_id in (
        ("sess-note", "legacy-note-msg"),
        ("sess-participation", "legacy-participation-msg"),
        ("sess-summary", "legacy-summary-msg"),
        ("sess-note-other", "legacy-note-msg-other"),
        ("sess-participation-other", "legacy-participation-msg-other"),
        ("sess-summary-other", "legacy-summary-msg-other"),
    ):
        harness._transcript_store.append(
            SessionId(session_id),
            role="user",
            content=f"legacy {message_id}",
            taint_labels=set(),
            metadata={
                "channel_message_id": message_id,
                "delivery_target": {
                    "channel": "discord",
                    "recipient": "chan-state",
                    "workspace_hint": "guild-2" if message_id.endswith("-other") else "guild-1",
                    "thread_id": "",
                },
            },
        )

    legacy_note = harness._memory_manager.write_with_provenance(
        entry_type="person_note",
        key=person_note_key(channel_id="chan-state", external_user_id="guest-5"),
        value={
            "external_user_id": "guest-5",
            "display_name": "Guest Five",
            "channel_id": "chan-state",
            "total_interactions": 2,
            "interaction_summary": "Legacy note",
        },
        source=MemorySource(
            origin="external",
            source_id="discord:legacy-note-msg",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:legacy-note-msg",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    assert legacy_note.kind == "allow"
    assert legacy_note.entry is not None

    other_workspace_note = harness._memory_manager.write_with_provenance(
        entry_type="person_note",
        key=person_note_key(channel_id="chan-state", external_user_id="guest-5"),
        value={
            "external_user_id": "guest-5",
            "display_name": "Guest Five Elsewhere",
            "channel_id": "chan-state",
            "total_interactions": 7,
            "interaction_summary": "Other workspace note",
        },
        source=MemorySource(
            origin="external",
            source_id="discord:legacy-note-msg-other",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:legacy-note-msg-other",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    assert other_workspace_note.kind == "allow"
    assert other_workspace_note.entry is not None

    legacy_participation = harness._memory_manager.write_with_provenance(
        entry_type="channel_participation",
        key=channel_participation_key(channel_id="chan-state"),
        value={
            "channel_id": "chan-state",
            "tracked_threads": [
                {
                    "thread_id": "chan-state",
                    "participants": ["guest-5"],
                }
            ],
        },
        source=MemorySource(
            origin="external",
            source_id="discord:legacy-participation-msg",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:legacy-participation-msg",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    assert legacy_participation.kind == "allow"
    assert legacy_participation.entry is not None

    other_workspace_participation = harness._memory_manager.write_with_provenance(
        entry_type="channel_participation",
        key=channel_participation_key(channel_id="chan-state"),
        value={
            "channel_id": "chan-state",
            "tracked_threads": [
                {
                    "thread_id": "chan-state",
                    "participants": ["guest-5", "guest-elsewhere"],
                }
            ],
        },
        source=MemorySource(
            origin="external",
            source_id="discord:legacy-participation-msg-other",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:legacy-participation-msg-other",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    assert other_workspace_participation.kind == "allow"
    assert other_workspace_participation.entry is not None

    legacy_summary = harness._memory_manager.write_with_provenance(
        entry_type="channel_summary",
        key=channel_summary_key(channel_id="chan-state", summary_kind="digest"),
        value={
            "channel_id": "chan-state",
            "summary_kind": "digest",
            "summary_text": "Legacy digest",
        },
        source=MemorySource(
            origin="external",
            source_id="discord:legacy-summary-msg",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:legacy-summary-msg",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    assert legacy_summary.kind == "allow"
    assert legacy_summary.entry is not None

    other_workspace_summary = harness._memory_manager.write_with_provenance(
        entry_type="channel_summary",
        key=channel_summary_key(channel_id="chan-state", summary_kind="digest"),
        value={
            "channel_id": "chan-state",
            "summary_kind": "digest",
            "summary_text": "Other workspace digest",
        },
        source=MemorySource(
            origin="external",
            source_id="discord:legacy-summary-msg-other",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:legacy-summary-msg-other",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    assert other_workspace_summary.kind == "allow"
    assert other_workspace_summary.entry is not None

    await harness.do_channel_ingest(
        {
            "message": {
                "channel": "discord",
                "external_user_id": "guest-5",
                "workspace_hint": "guild-1",
                "reply_target": "chan-state",
                "message_id": "msg-77",
                "content": "carry forward legacy state",
                "metadata": {
                    "interaction_type": "direct",
                    "display_name": "Guest Five",
                    "summary_kind": "digest",
                    "summary_text": "Updated digest",
                },
            }
        }
    )

    channel_binding = compose_channel_binding(
        channel="discord",
        workspace_hint="guild-1",
        channel_id="chan-state",
    )
    current_entries = {
        entry.key: entry
        for entry in harness._memory_manager.list_entries(limit=20)
        if entry.superseded_by is None
    }

    current_note = current_entries[
        person_note_key(channel_id=channel_binding, external_user_id="guest-5")
    ]
    assert current_note.supersedes == legacy_note.entry.id
    assert current_note.value["total_interactions"] == 3

    current_participation = current_entries[channel_participation_key(channel_id=channel_binding)]
    assert current_participation.supersedes == legacy_participation.entry.id
    assert current_participation.value["tracked_threads"][0]["participants"] == ["guest-5"]

    current_summary = current_entries[
        channel_summary_key(channel_id=channel_binding, summary_kind="digest")
    ]
    assert current_summary.supersedes == legacy_summary.entry.id

    preserved_note = harness._memory_manager.get_entry(other_workspace_note.entry.id)
    assert preserved_note is not None
    assert preserved_note.key == person_note_key(
        channel_id="chan-state",
        external_user_id="guest-5",
    )
    assert preserved_note.superseded_by is None

    preserved_participation = harness._memory_manager.get_entry(
        other_workspace_participation.entry.id
    )
    assert preserved_participation is not None
    assert preserved_participation.key == channel_participation_key(channel_id="chan-state")
    assert preserved_participation.superseded_by is None

    preserved_summary = harness._memory_manager.get_entry(other_workspace_summary.entry.id)
    assert preserved_summary is not None
    assert preserved_summary.key == channel_summary_key(
        channel_id="chan-state",
        summary_kind="digest",
    )
    assert preserved_summary.superseded_by is None


@pytest.mark.asyncio
async def test_m3_channel_ingest_carries_forward_legacy_keyed_state_without_workspace_hint(
    tmp_path: Path,
) -> None:
    harness = _AdminChannelIngressHarness(
        tmp_path=tmp_path,
        default_trust="public",
        allowlisted_users={"guest-6"},
    )
    for session_id, message_id in (
        ("sess-note-blank", "legacy-note-msg-blank"),
        ("sess-participation-blank", "legacy-participation-msg-blank"),
        ("sess-summary-blank", "legacy-summary-msg-blank"),
    ):
        harness._transcript_store.append(
            SessionId(session_id),
            role="user",
            content=f"legacy {message_id}",
            taint_labels=set(),
            metadata={
                "channel_message_id": message_id,
                "delivery_target": {
                    "channel": "discord",
                    "recipient": "chan-blank",
                    "workspace_hint": "",
                    "thread_id": "",
                },
            },
        )

    legacy_note = harness._memory_manager.write_with_provenance(
        entry_type="person_note",
        key=person_note_key(channel_id="chan-blank", external_user_id="guest-6"),
        value={
            "external_user_id": "guest-6",
            "display_name": "Guest Six",
            "channel_id": "chan-blank",
            "total_interactions": 4,
            "interaction_summary": "Blank workspace note",
        },
        source=MemorySource(
            origin="external",
            source_id="discord:legacy-note-msg-blank",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:legacy-note-msg-blank",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    assert legacy_note.kind == "allow"
    assert legacy_note.entry is not None

    legacy_participation = harness._memory_manager.write_with_provenance(
        entry_type="channel_participation",
        key=channel_participation_key(channel_id="chan-blank"),
        value={
            "channel_id": "chan-blank",
            "tracked_threads": [
                {
                    "thread_id": "chan-blank",
                    "participants": ["guest-6"],
                }
            ],
        },
        source=MemorySource(
            origin="external",
            source_id="discord:legacy-participation-msg-blank",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:legacy-participation-msg-blank",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    assert legacy_participation.kind == "allow"
    assert legacy_participation.entry is not None

    legacy_summary = harness._memory_manager.write_with_provenance(
        entry_type="channel_summary",
        key=channel_summary_key(channel_id="chan-blank", summary_kind="digest"),
        value={
            "channel_id": "chan-blank",
            "summary_kind": "digest",
            "summary_text": "Blank workspace digest",
        },
        source=MemorySource(
            origin="external",
            source_id="discord:legacy-summary-msg-blank",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:legacy-summary-msg-blank",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    assert legacy_summary.kind == "allow"
    assert legacy_summary.entry is not None

    await harness.do_channel_ingest(
        {
            "message": {
                "channel": "discord",
                "external_user_id": "guest-6",
                "workspace_hint": "",
                "reply_target": "chan-blank",
                "message_id": "msg-88",
                "content": "carry forward blank-workspace state",
                "metadata": {
                    "interaction_type": "direct",
                    "display_name": "Guest Six",
                    "summary_kind": "digest",
                    "summary_text": "Updated blank workspace digest",
                },
            }
        }
    )

    channel_binding = compose_channel_binding(
        channel="discord",
        workspace_hint="",
        channel_id="chan-blank",
    )
    current_entries = {
        entry.key: entry
        for entry in harness._memory_manager.list_entries(limit=20)
        if entry.superseded_by is None
    }

    current_note = current_entries[
        person_note_key(channel_id=channel_binding, external_user_id="guest-6")
    ]
    assert current_note.supersedes == legacy_note.entry.id
    assert current_note.value["total_interactions"] == 5

    current_participation = current_entries[channel_participation_key(channel_id=channel_binding)]
    assert current_participation.supersedes == legacy_participation.entry.id

    current_summary = current_entries[
        channel_summary_key(channel_id=channel_binding, summary_kind="digest")
    ]
    assert current_summary.supersedes == legacy_summary.entry.id


@pytest.mark.asyncio
async def test_m3_channel_ingest_requires_explicit_blank_workspace_hint_for_legacy_carry_forward(
    tmp_path: Path,
) -> None:
    harness = _AdminChannelIngressHarness(
        tmp_path=tmp_path,
        default_trust="public",
        allowlisted_users={"guest-7"},
    )
    transcript_dir = tmp_path / "transcripts"
    transcript_dir.mkdir()
    (transcript_dir / "channel.jsonl").write_text(
        json.dumps(
            {
                "session_id": "sess-note-missing-workspace",
                "role": "user",
                "content": "legacy note without workspace hint",
                "metadata": {
                    "channel_message_id": "legacy-note-msg-missing-workspace",
                    "delivery_target": {
                        "channel": "discord",
                        "recipient": "chan-missing-workspace",
                        "thread_id": "",
                    },
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    harness._transcript_store.entries = None
    harness._transcript_store._transcript_dir = transcript_dir

    legacy_note = harness._memory_manager.write_with_provenance(
        entry_type="person_note",
        key=person_note_key(
            channel_id="chan-missing-workspace",
            external_user_id="guest-7",
        ),
        value={
            "external_user_id": "guest-7",
            "display_name": "Guest Seven",
            "channel_id": "chan-missing-workspace",
            "total_interactions": 6,
            "interaction_summary": "Missing workspace note",
        },
        source=MemorySource(
            origin="external",
            source_id="discord:legacy-note-msg-missing-workspace",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:legacy-note-msg-missing-workspace",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    assert legacy_note.kind == "allow"
    assert legacy_note.entry is not None

    await harness.do_channel_ingest(
        {
            "message": {
                "channel": "discord",
                "external_user_id": "guest-7",
                "workspace_hint": "",
                "reply_target": "chan-missing-workspace",
                "message_id": "msg-99",
                "content": "fresh blank-workspace message",
                "metadata": {
                    "interaction_type": "direct",
                    "display_name": "Guest Seven",
                },
            }
        }
    )

    channel_binding = compose_channel_binding(
        channel="discord",
        workspace_hint="",
        channel_id="chan-missing-workspace",
    )
    current_entries = {
        entry.key: entry
        for entry in harness._memory_manager.list_entries(limit=20)
        if entry.superseded_by is None
    }

    current_note = current_entries[
        person_note_key(channel_id=channel_binding, external_user_id="guest-7")
    ]
    assert current_note.supersedes is None
    assert current_note.value["total_interactions"] == 1

    preserved_legacy = harness._memory_manager.get_entry(legacy_note.entry.id)
    assert preserved_legacy is not None
    assert preserved_legacy.key == person_note_key(
        channel_id="chan-missing-workspace",
        external_user_id="guest-7",
    )
    assert preserved_legacy.superseded_by is None


@pytest.mark.asyncio
async def test_m3_channel_ingest_ignores_non_active_predecessors_for_keyed_state(
    tmp_path: Path,
) -> None:
    harness = _AdminChannelIngressHarness(
        tmp_path=tmp_path,
        default_trust="public",
        allowlisted_users={"guest-8"},
    )
    harness._transcript_store.append(
        SessionId("sess-note-pending-review"),
        role="user",
        content="legacy note pending review",
        taint_labels=set(),
        metadata={
            "channel_message_id": "legacy-note-msg-pending-review",
            "delivery_target": {
                "channel": "discord",
                "recipient": "chan-review-state",
                "workspace_hint": "guild-1",
                "thread_id": "",
            },
        },
    )

    channel_binding = compose_channel_binding(
        channel="discord",
        workspace_hint="guild-1",
        channel_id="chan-review-state",
    )
    current_quarantined = harness._memory_manager.write_with_provenance(
        entry_type="person_note",
        key=person_note_key(channel_id=channel_binding, external_user_id="guest-8"),
        value={
            "external_user_id": "guest-8",
            "display_name": "Guest Eight",
            "channel_id": channel_binding,
            "total_interactions": 9,
            "interaction_summary": "Quarantined canonical note",
        },
        source=MemorySource(
            origin="external",
            source_id="discord:canonical-note-msg",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:canonical-note-msg",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    assert current_quarantined.kind == "allow"
    assert current_quarantined.entry is not None
    assert harness._memory_manager.quarantine(
        current_quarantined.entry.id,
        reason="manual-review",
    )

    pending_review_legacy = harness._memory_manager.write_with_provenance(
        entry_type="person_note",
        key=person_note_key(channel_id="chan-review-state", external_user_id="guest-8"),
        value={
            "external_user_id": "guest-8",
            "display_name": "Guest Eight",
            "channel_id": "chan-review-state",
            "total_interactions": 4,
            "interaction_summary": "Pending review legacy note",
        },
        source=MemorySource(
            origin="external",
            source_id="discord:legacy-note-msg-pending-review",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="pending_review",
        source_id="discord:legacy-note-msg-pending-review",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=False,
    )
    assert pending_review_legacy.kind == "allow"
    assert pending_review_legacy.entry is not None

    await harness.do_channel_ingest(
        {
            "message": {
                "channel": "discord",
                "external_user_id": "guest-8",
                "workspace_hint": "guild-1",
                "reply_target": "chan-review-state",
                "message_id": "msg-109",
                "content": "fresh active message",
                "metadata": {
                    "interaction_type": "direct",
                    "display_name": "Guest Eight",
                },
            }
        }
    )

    current_entries = {
        entry.key: entry
        for entry in harness._memory_manager.list_entries(limit=20)
        if entry.superseded_by is None
    }

    current_note = current_entries[
        person_note_key(channel_id=channel_binding, external_user_id="guest-8")
    ]
    assert current_note.supersedes is None
    assert current_note.value["total_interactions"] == 1

    quarantined_entry = harness._memory_manager.get_entry(
        current_quarantined.entry.id,
        include_quarantined=True,
    )
    assert quarantined_entry is not None
    assert quarantined_entry.status == "quarantined"
    assert quarantined_entry.superseded_by is None

    pending_review_entry = harness._memory_manager.get_entry(
        pending_review_legacy.entry.id,
        include_pending_review=True,
    )
    assert pending_review_entry is not None
    assert pending_review_entry.confirmation_status == "pending_review"
    assert pending_review_entry.superseded_by is None


@pytest.mark.asyncio
async def test_m3_channel_ingest_skips_keyed_state_when_canonical_pending_review_exists(
    tmp_path: Path,
) -> None:
    harness = _AdminChannelIngressHarness(
        tmp_path=tmp_path,
        default_trust="public",
        allowlisted_users={"guest-9"},
    )
    for session_id, message_id in (
        ("sess-note-pending-current", "legacy-note-msg-current"),
        ("sess-participation-pending-current", "legacy-participation-msg-current"),
        ("sess-summary-pending-current", "legacy-summary-msg-current"),
    ):
        harness._transcript_store.append(
            SessionId(session_id),
            role="user",
            content=f"legacy {message_id}",
            taint_labels=set(),
            metadata={
                "channel_message_id": message_id,
                "delivery_target": {
                    "channel": "discord",
                    "recipient": "chan-pending-current",
                    "workspace_hint": "guild-1",
                    "thread_id": "",
                },
            },
        )

    channel_binding = compose_channel_binding(
        channel="discord",
        workspace_hint="guild-1",
        channel_id="chan-pending-current",
    )

    legacy_note = harness._memory_manager.write_with_provenance(
        entry_type="person_note",
        key=person_note_key(channel_id="chan-pending-current", external_user_id="guest-9"),
        value={
            "external_user_id": "guest-9",
            "display_name": "Guest Nine",
            "channel_id": "chan-pending-current",
            "total_interactions": 4,
            "interaction_summary": "Legacy note",
        },
        source=MemorySource(
            origin="external",
            source_id="discord:legacy-note-msg-current",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:legacy-note-msg-current",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    assert legacy_note.kind == "allow"
    assert legacy_note.entry is not None

    pending_review_note = harness._memory_manager.write_with_provenance(
        entry_type="person_note",
        key=person_note_key(channel_id=channel_binding, external_user_id="guest-9"),
        value={
            "external_user_id": "guest-9",
            "display_name": "Guest Nine",
            "channel_id": channel_binding,
            "total_interactions": 8,
            "interaction_summary": "Pending review note",
        },
        source=MemorySource(
            origin="external",
            source_id="discord:pending-note-msg-current",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="pending_review",
        source_id="discord:pending-note-msg-current",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=False,
    )
    assert pending_review_note.kind == "allow"
    assert pending_review_note.entry is not None

    legacy_participation = harness._memory_manager.write_with_provenance(
        entry_type="channel_participation",
        key=channel_participation_key(channel_id="chan-pending-current"),
        value={
            "channel_id": "chan-pending-current",
            "tracked_threads": [
                {
                    "thread_id": "chan-pending-current",
                    "participants": ["guest-9"],
                }
            ],
        },
        source=MemorySource(
            origin="external",
            source_id="discord:legacy-participation-msg-current",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:legacy-participation-msg-current",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    assert legacy_participation.kind == "allow"
    assert legacy_participation.entry is not None

    pending_review_participation = harness._memory_manager.write_with_provenance(
        entry_type="channel_participation",
        key=channel_participation_key(channel_id=channel_binding),
        value={
            "channel_id": channel_binding,
            "tracked_threads": [
                {
                    "thread_id": "chan-pending-current",
                    "participants": ["guest-9", "guest-review"],
                }
            ],
        },
        source=MemorySource(
            origin="external",
            source_id="discord:pending-participation-msg-current",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="pending_review",
        source_id="discord:pending-participation-msg-current",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=False,
    )
    assert pending_review_participation.kind == "allow"
    assert pending_review_participation.entry is not None

    legacy_summary = harness._memory_manager.write_with_provenance(
        entry_type="channel_summary",
        key=channel_summary_key(channel_id="chan-pending-current", summary_kind="digest"),
        value={
            "channel_id": "chan-pending-current",
            "summary_kind": "digest",
            "summary_text": "Legacy digest",
        },
        source=MemorySource(
            origin="external",
            source_id="discord:legacy-summary-msg-current",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="auto_accepted",
        source_id="discord:legacy-summary-msg-current",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=True,
    )
    assert legacy_summary.kind == "allow"
    assert legacy_summary.entry is not None

    pending_review_summary = harness._memory_manager.write_with_provenance(
        entry_type="channel_summary",
        key=channel_summary_key(channel_id=channel_binding, summary_kind="digest"),
        value={
            "channel_id": channel_binding,
            "summary_kind": "digest",
            "summary_text": "Pending review digest",
        },
        source=MemorySource(
            origin="external",
            source_id="discord:pending-summary-msg-current",
            extraction_method="channel.ingest.structured",
        ),
        source_origin="external_message",
        channel_trust="shared_participant",
        confirmation_status="pending_review",
        source_id="discord:pending-summary-msg-current",
        scope="channel",
        confidence=0.5,
        confirmation_satisfied=False,
    )
    assert pending_review_summary.kind == "allow"
    assert pending_review_summary.entry is not None

    await harness.do_channel_ingest(
        {
            "message": {
                "channel": "discord",
                "external_user_id": "guest-9",
                "workspace_hint": "guild-1",
                "reply_target": "chan-pending-current",
                "message_id": "msg-119",
                "content": "fresh active message with pending review collision",
                "metadata": {
                    "interaction_type": "direct",
                    "display_name": "Guest Nine",
                    "summary_kind": "digest",
                    "summary_text": "Fresh digest",
                },
            }
        }
    )

    current_entries = {
        entry.key: entry
        for entry in harness._memory_manager.list_entries(limit=30)
        if entry.superseded_by is None
    }

    assert (
        person_note_key(channel_id=channel_binding, external_user_id="guest-9")
        not in current_entries
    )
    assert channel_participation_key(channel_id=channel_binding) not in current_entries
    assert (
        channel_summary_key(channel_id=channel_binding, summary_kind="digest")
        not in current_entries
    )

    preserved_legacy_note = harness._memory_manager.get_entry(legacy_note.entry.id)
    assert preserved_legacy_note is not None
    assert preserved_legacy_note.key == person_note_key(
        channel_id="chan-pending-current",
        external_user_id="guest-9",
    )
    assert preserved_legacy_note.superseded_by is None

    preserved_legacy_participation = harness._memory_manager.get_entry(
        legacy_participation.entry.id
    )
    assert preserved_legacy_participation is not None
    assert preserved_legacy_participation.key == channel_participation_key(
        channel_id="chan-pending-current"
    )
    assert preserved_legacy_participation.superseded_by is None

    preserved_legacy_summary = harness._memory_manager.get_entry(legacy_summary.entry.id)
    assert preserved_legacy_summary is not None
    assert preserved_legacy_summary.key == channel_summary_key(
        channel_id="chan-pending-current",
        summary_kind="digest",
    )
    assert preserved_legacy_summary.superseded_by is None

    pending_note_entry = harness._memory_manager.get_entry(
        pending_review_note.entry.id,
        include_pending_review=True,
    )
    assert pending_note_entry is not None
    assert pending_note_entry.confirmation_status == "pending_review"
    assert pending_note_entry.superseded_by is None

    pending_participation_entry = harness._memory_manager.get_entry(
        pending_review_participation.entry.id,
        include_pending_review=True,
    )
    assert pending_participation_entry is not None
    assert pending_participation_entry.confirmation_status == "pending_review"
    assert pending_participation_entry.superseded_by is None

    pending_summary_entry = harness._memory_manager.get_entry(
        pending_review_summary.entry.id,
        include_pending_review=True,
    )
    assert pending_summary_entry is not None
    assert pending_summary_entry.confirmation_status == "pending_review"
    assert pending_summary_entry.superseded_by is None
