"""Smoke coverage for reusable behavioral prefill helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tests.behavioral._prefill import (
    load_prefill_profile,
    prefill_memory,
    prefill_pending_actions,
    prefill_transcript,
)
from tests.behavioral.test_behavioral_contract import ContractHarness, _create_session

pytestmark = pytest.mark.asyncio


def _profile(name: str) -> dict[str, Any]:
    path = Path(__file__).with_name("_prefill_data") / f"{name}.yaml"
    return load_prefill_profile(path)


async def test_prefill_memory_smoke(clean_harness: ContractHarness) -> None:
    profile = _profile("light_user")
    entry_ids = await prefill_memory(
        clean_harness.client,
        user_id=str(profile["user_id"]),
        entries=profile["memory"],
    )
    assert entry_ids

    listed = await clean_harness.client.call("memory.list", {"limit": 20})
    rendered = str(listed).lower()
    assert "favorite_editor" in rendered
    assert "helix" in rendered
    assert "structured_prefill" in rendered
    assert "python" in rendered


async def test_prefill_transcript_smoke(clean_harness: ContractHarness) -> None:
    profile = _profile("light_user")
    sid = await prefill_transcript(
        clean_harness.client,
        user_id=str(profile["user_id"]),
        turns=profile["transcript"],
    )
    assert sid

    listed = await clean_harness.client.call("session.list", {})
    rendered = str(listed)
    assert sid in rendered


async def test_prefill_pending_actions_smoke(
    confirmation_followup_harness: ContractHarness,
) -> None:
    profile = _profile("light_user")
    sid = await _create_session(confirmation_followup_harness.client)
    first = await confirmation_followup_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "review TODO.LOG and list only open items"},
    )
    assert first.get("lockdown_level") == "normal"

    pending_ids = await prefill_pending_actions(
        confirmation_followup_harness.client,
        session_id=sid,
        queued=profile["pending_actions"],
    )
    assert pending_ids
