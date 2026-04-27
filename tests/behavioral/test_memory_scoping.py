"""C2 memory (user, workspace) scoping: end-to-end cross-session checks.

Closes LUS-9 Phase C cross-scope recall leakage. See
planning/PLAN-lockdown-no-deadend.md §4.4 and
planning/v0.7/IMPLEMENTATION-v0.7.1.md memory-scoping punchlist.
"""

from __future__ import annotations

from typing import Any

import pytest

from tests.behavioral.test_behavioral_contract import ContractHarness

pytestmark = [pytest.mark.asyncio]


async def _create_session_for(
    harness: ContractHarness,
    *,
    user_id: str,
    workspace_id: str,
    channel: str = "cli",
) -> str:
    created = await harness.client.call(
        "session.create",
        {"channel": channel, "user_id": user_id, "workspace_id": workspace_id},
    )
    return str(created["session_id"])


async def _send(
    harness: ContractHarness, sid: str, content: str
) -> dict[str, Any]:
    return dict(
        await harness.client.call(
            "session.message",
            {"session_id": sid, "content": content},
        )
    )


async def test_c2_cross_scope_memory_recall_does_not_leak(
    cross_session_harness: ContractHarness,
) -> None:
    """A session under (alice, ws1) must not recall memory written by a
    session under (bob, ws2). This is the LUS-9 Phase C regression.
    """
    alice_sid = await _create_session_for(
        cross_session_harness, user_id="alice", workspace_id="ws1"
    )
    await _send(
        cross_session_harness,
        alice_sid,
        "remember that my favorite color is blue",
    )

    bob_sid = await _create_session_for(
        cross_session_harness, user_id="bob", workspace_id="ws2"
    )
    reply = await _send(
        cross_session_harness,
        bob_sid,
        "what is my favorite color?",
    )
    response_text = str(reply.get("response", "")).lower()
    # Cross-scope recall must not leak alice's preference.
    assert "blue" not in response_text


async def test_c2_same_scope_memory_recall_still_surfaces(
    cross_session_harness: ContractHarness,
) -> None:
    """A new session under the same (user, workspace) still recalls
    prior memory. The scoping fix must close leaks without breaking
    the legitimate case.
    """
    first = await _create_session_for(
        cross_session_harness, user_id="alice", workspace_id="ws1"
    )
    await _send(
        cross_session_harness,
        first,
        "remember that my favorite color is blue",
    )

    second = await _create_session_for(
        cross_session_harness, user_id="alice", workspace_id="ws1"
    )
    reply = await _send(
        cross_session_harness,
        second,
        "what is my favorite color?",
    )
    assert "blue" in str(reply.get("response", "")).lower()
