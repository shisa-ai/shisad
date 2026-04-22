"""Unit coverage for v0.7 canonical memory-entry schema backfill."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from shisad.memory.schema import MemoryEntry


def test_m1_memory_entry_backfills_legacy_user_shape_to_v070_fields() -> None:
    created_at = datetime(2026, 4, 22, 12, 0, tzinfo=UTC)
    entry = MemoryEntry.model_validate(
        {
            "id": "legacy-user",
            "entry_type": "fact",
            "key": "profile.name",
            "value": "alice",
            "source": {
                "origin": "user",
                "source_id": "msg-1",
                "extraction_method": "manual",
            },
            "created_at": created_at,
            "confidence": 0.72,
            "user_verified": True,
        }
    )

    assert entry.entry_id == "legacy-user"
    assert entry.source_origin == "user_direct"
    assert entry.channel_trust == "command"
    assert entry.confirmation_status == "auto_accepted"
    assert entry.trust_band == "untrusted"
    assert entry.scope == "user"
    assert entry.workflow_state is None
    assert entry.status == "active"
    assert entry.last_verified_at == created_at
    assert entry.source_id == "msg-1"
    assert entry.content_digest


@pytest.mark.parametrize(
    ("value", "expected_entry_type"),
    [
        ("2026-04-22 design review meeting with Alice", "episode"),
        ("Blue notebook lives on the top shelf", "note"),
    ],
)
def test_m1_memory_entry_backfills_legacy_context_shape_by_content(
    value: str,
    expected_entry_type: str,
) -> None:
    entry = MemoryEntry.model_validate(
        {
            "id": "legacy-context",
            "entry_type": "context",
            "key": "legacy.context",
            "value": value,
            "source": {
                "origin": "external",
                "source_id": "doc-1",
                "extraction_method": "extract",
            },
        }
    )

    assert entry.entry_type == expected_entry_type
    assert entry.source_origin == "external_web"
    assert entry.channel_trust == "web_passed"
    assert entry.confirmation_status == "auto_accepted"
    assert entry.trust_band == "untrusted"


def test_m1_memory_entry_backfills_confirmed_legacy_capture_conservatively() -> None:
    entry = MemoryEntry.model_validate(
        {
            "id": "legacy-confirmed",
            "entry_type": "fact",
            "key": "profile.location",
            "value": "Berlin",
            "source": {
                "origin": "user",
                "source_id": "approval-1",
                "extraction_method": "agent_confirmed",
            },
        }
    )

    assert entry.source_origin == "user_confirmed"
    assert entry.channel_trust == "command"
    assert entry.confirmation_status == "auto_accepted"
    assert entry.trust_band == "untrusted"

