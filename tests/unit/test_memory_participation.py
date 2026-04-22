"""Unit coverage for typed Discord multiuser memory contracts."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from shisad.memory.participation import (
    AgentResponseSummary,
    ChannelSummaryValue,
    InboxItemValue,
    PersonNoteValue,
    ResponseFeedbackEventValue,
    ScratchpadEntry,
    TrackedThreadState,
    channel_participation_key,
    channel_summary_key,
    inbox_item_key,
    person_note_key,
    response_feedback_key,
)
from shisad.memory.schema import MemoryEntry


def test_m1_participation_namespace_helpers_generate_stable_keys() -> None:
    assert inbox_item_key(owner_id="owner-1", item_id="msg 42") == "inbox:owner-1:msg%2042"
    assert (
        channel_summary_key(channel_id="discord:guild/general", summary_kind="topic")
        == "channel-summary:discord%3Aguild%2Fgeneral:topic"
    )
    assert (
        person_note_key(channel_id="discord:guild/general", external_user_id="alice@example.com")
        == "person-note:discord%3Aguild%2Fgeneral:alice%40example.com"
    )
    assert (
        channel_participation_key(channel_id="discord:guild/general", thread_id="thread/1")
        == "channel-participation:discord%3Aguild%2Fgeneral:thread%2F1"
    )
    assert (
        response_feedback_key(
            channel_id="discord:guild/general",
            message_id="msg:1",
            actor_external_user_id="alice@example.com",
            signal="reaction_add",
        )
        == "response-feedback:discord%3Aguild%2Fgeneral:msg%3A1:alice%40example.com:reaction_add"
    )


def test_m1_memory_entry_validates_structured_multiuser_payloads() -> None:
    now = datetime(2026, 4, 22, 12, 30, tzinfo=UTC)
    entry = MemoryEntry.model_validate(
        {
            "id": "channel-participation-1",
            "entry_type": "channel_participation",
            "key": channel_participation_key(
                channel_id="discord:guild/general",
                thread_id="launch-thread",
            ),
            "value": {
                "channel_id": "discord:guild/general",
                "guild_id": "guild-1",
                "my_responses": [
                    AgentResponseSummary(
                        timestamp=now,
                        message_id="resp-1",
                        content_summary="Asked clarifying question about release blockers.",
                        thread_id="launch-thread",
                        reaction_summary={"positive": 1},
                        was_proactive=True,
                    ).model_dump(mode="python")
                ],
                "tracked_threads": [
                    TrackedThreadState(
                        thread_id="launch-thread",
                        topic_summary="Launch blockers and readiness.",
                        last_activity=now,
                        my_participation_count=2,
                        participants=["alice", "bob"],
                    ).model_dump(mode="python")
                ],
                "topic_summary": "Launch coordination and blocker triage.",
                "topic_summary_updated_at": now,
                "scratchpad": [
                    ScratchpadEntry(
                        timestamp=now,
                        content="Docs still missing rollback section.",
                        relevance_score=0.8,
                        expiry=now,
                    ).model_dump(mode="python")
                ],
            },
            "source": {
                "origin": "user",
                "source_id": "msg-1",
                "extraction_method": "manual",
            },
        }
    )

    assert entry.entry_type == "channel_participation"
    assert entry.value["topic_summary"] == "Launch coordination and blocker triage."
    assert entry.value["tracked_threads"][0]["thread_id"] == "launch-thread"
    assert entry.content_digest


@pytest.mark.parametrize(
    ("entry_type", "key", "value"),
    [
        (
            "inbox_item",
            inbox_item_key(owner_id="owner-1", item_id="inbox-1"),
            InboxItemValue(
                owner_id="owner-1",
                sender_id="guest-1",
                sender_display_name="Alice",
                channel_id="discord:guild/general",
                message_type="message_for_owner",
                body="Deploy is ready for review.",
            ).model_dump(mode="python"),
        ),
        (
            "channel_summary",
            channel_summary_key(channel_id="discord:guild/general", summary_kind="topic"),
            ChannelSummaryValue(
                channel_id="discord:guild/general",
                guild_id="guild-1",
                summary_kind="topic",
                summary_text="The team is discussing launch readiness.",
                window_start=datetime(2026, 4, 22, 10, 0, tzinfo=UTC),
                window_end=datetime(2026, 4, 22, 11, 0, tzinfo=UTC),
                source_message_ids=["m1", "m2"],
            ).model_dump(mode="python"),
        ),
        (
            "person_note",
            person_note_key(
                channel_id="discord:guild/general",
                external_user_id="guest-1",
            ),
            PersonNoteValue(
                external_user_id="guest-1",
                display_name="Alice",
                channel_id="discord:guild/general",
                role_notes="Release manager",
                language_preferences=["en"],
                topic_interests=["deploys", "rollbacks"],
                interaction_style="concise",
                total_interactions=4,
                interaction_summary="Usually asks for status and next steps.",
                positive_reactions=2,
                negative_reactions=0,
                ignored_responses=1,
                thread_starts=1,
            ).model_dump(mode="python"),
        ),
        (
            "response_feedback",
            response_feedback_key(
                channel_id="discord:guild/general",
                message_id="resp-1",
                actor_external_user_id="guest-1",
                signal="reaction_add",
            ),
            ResponseFeedbackEventValue(
                channel_id="discord:guild/general",
                target_message_id="resp-1",
                actor_external_user_id="guest-1",
                signal="reaction_add",
                emoji=":+1:",
                valence="positive",
                observed_at=datetime(2026, 4, 22, 12, 45, tzinfo=UTC),
                was_proactive=True,
            ).model_dump(mode="python"),
        ),
    ],
)
def test_m1_memory_entry_accepts_each_multiuser_record_family(
    entry_type: str,
    key: str,
    value: dict[str, object],
) -> None:
    entry = MemoryEntry.model_validate(
        {
            "id": f"{entry_type}-1",
            "entry_type": entry_type,
            "key": key,
            "value": value,
            "source": {
                "origin": "user",
                "source_id": "msg-typed",
                "extraction_method": "manual",
            },
        }
    )

    assert entry.entry_type == entry_type
    assert entry.key == key
    assert entry.value == value


def test_m1_person_note_rejects_negative_feedback_counters() -> None:
    with pytest.raises(ValidationError):
        MemoryEntry.model_validate(
            {
                "id": "person-note-bad",
                "entry_type": "person_note",
                "key": person_note_key(
                    channel_id="discord:guild/general",
                    external_user_id="guest-2",
                ),
                "value": {
                    "external_user_id": "guest-2",
                    "display_name": "Bob",
                    "channel_id": "discord:guild/general",
                    "positive_reactions": -1,
                },
                "source": {
                    "origin": "user",
                    "source_id": "msg-bad",
                    "extraction_method": "manual",
                },
            }
        )
