"""Named first-principles behavioral gates for milestone/release close."""

from __future__ import annotations

import json
from typing import Any

import pytest

from tests.behavioral.test_behavioral_contract import (
    ContractHarness,
    _confirm_pending_action,
    _create_session,
    _wait_for_audit_event,
)
from tests.helpers.behavioral import extract_tool_outputs

pytestmark = [pytest.mark.asyncio, pytest.mark.first_principles]


def _assert_normal_reply(
    reply: dict[str, Any],
    *,
    executed_actions: int | None = None,
    confirmation_required_actions: int | None = 0,
) -> None:
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    if confirmation_required_actions is not None:
        assert int(reply.get("confirmation_required_actions", 0)) == confirmation_required_actions
    if executed_actions is not None:
        assert int(reply.get("executed_actions", 0)) == executed_actions


def _first_tool_payload(reply: dict[str, Any], tool_name: str) -> dict[str, Any]:
    outputs = extract_tool_outputs(reply)
    assert tool_name in outputs
    return outputs[tool_name][0]


async def _assert_core_product_gates(harness: ContractHarness) -> None:
    sid = await _create_session(harness.client)

    hello = await harness.client.call(
        "session.message",
        {"session_id": sid, "content": "hello"},
    )
    _assert_normal_reply(hello, executed_actions=0)
    assert str(hello.get("response", "")).strip()

    search = await harness.client.call(
        "session.message",
        {"session_id": sid, "content": "search for the latest news"},
    )
    _assert_normal_reply(search, executed_actions=1)
    assert _first_tool_payload(search, "web.search").get("ok") is True

    read = await harness.client.call(
        "session.message",
        {"session_id": sid, "content": "read README.md"},
    )
    _assert_normal_reply(read, executed_actions=1)
    assert _first_tool_payload(read, "fs.read").get("ok") is True

    remember = await harness.client.call(
        "session.message",
        {"session_id": sid, "content": "remember that my favorite color is blue"},
    )
    _assert_normal_reply(remember, executed_actions=1)
    assert _first_tool_payload(remember, "note.create").get("ok") is True

    sid_later = await _create_session(harness.client)
    recalled = await harness.client.call(
        "session.message",
        {"session_id": sid_later, "content": "what is my favorite color?"},
    )
    _assert_normal_reply(recalled)
    assert "blue" in str(recalled.get("response", "")).lower()

    multi = await harness.client.call(
        "session.message",
        {"session_id": sid_later, "content": "read the README and search for related projects"},
    )
    _assert_normal_reply(multi)
    outputs = extract_tool_outputs(multi)
    assert "fs.read" in outputs
    assert "web.search" in outputs


async def _assert_confirmation_recovery_gate(harness: ContractHarness) -> None:
    (harness.workspace_root / "todo.log").write_text(
        "OPEN: verify confirmed result threading\n",
        encoding="utf-8",
    )
    sid = await _create_session(harness.client)

    first = await harness.client.call(
        "session.message",
        {"session_id": sid, "content": "review TODO.LOG and list only open items"},
    )
    _assert_normal_reply(first)
    first_payload = _first_tool_payload(first, "fs.read")
    assert first_payload.get("ok") is False
    assert first_payload.get("error") == "path_not_found"

    proposed = await harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": "can you look for the file? filename should be similar if it's not exact",
        },
    )
    _assert_normal_reply(
        proposed,
        executed_actions=0,
        confirmation_required_actions=None,
    )
    assert int(proposed.get("confirmation_required_actions", 0)) >= 1
    pending_ids = proposed.get("pending_confirmation_ids")
    assert isinstance(pending_ids, list)
    assert pending_ids

    confirmed = await harness.client.call(
        "session.message",
        {"session_id": sid, "content": "confirm"},
    )
    _assert_normal_reply(confirmed, executed_actions=1)
    confirmed_payload = _first_tool_payload(confirmed, "fs.list")
    assert "todo.log" in json.dumps(confirmed_payload, ensure_ascii=True)
    assert "todo.log" in str(confirmed.get("response", ""))

    followup = await harness.client.call(
        "session.message",
        {"session_id": sid, "content": "what was in that listing?"},
    )
    _assert_normal_reply(followup)
    assert "todo.log" in str(followup.get("response", ""))


async def test_first_principles_clean_harness(clean_harness: ContractHarness) -> None:
    await _assert_core_product_gates(clean_harness)


async def test_first_principles_accumulated_state_harness(
    accumulated_state_harness: ContractHarness,
) -> None:
    await _assert_core_product_gates(accumulated_state_harness)


async def test_first_principles_degraded_web_search_harness(
    degraded_runtime_harness: ContractHarness,
) -> None:
    sid = await _create_session(degraded_runtime_harness.client)
    reply = await degraded_runtime_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "search for the latest news"},
    )

    _assert_normal_reply(reply, executed_actions=0)
    payload = _first_tool_payload(reply, "web.search")
    assert payload.get("ok") is False
    assert payload.get("error") == "web_search_backend_unconfigured"


async def test_first_principles_confirmation_recovery_gate(
    confirmation_followup_harness: ContractHarness,
) -> None:
    await _assert_confirmation_recovery_gate(confirmation_followup_harness)


async def test_first_principles_require_confirmation_harness(
    require_confirmation_harness: ContractHarness,
) -> None:
    sid = await _create_session(require_confirmation_harness.client)
    fetch_url = f"{require_confirmation_harness.web_search_backend_url}/page"
    proposed = await require_confirmation_harness.client.call(
        "session.message",
        {"session_id": sid, "content": f"fetch the URL {fetch_url}"},
    )
    _assert_normal_reply(proposed, executed_actions=0, confirmation_required_actions=None)
    assert int(proposed.get("confirmation_required_actions", 0)) >= 1
    pending_ids = proposed.get("pending_confirmation_ids")
    assert isinstance(pending_ids, list)
    assert pending_ids

    confirmed = await _confirm_pending_action(
        require_confirmation_harness.client,
        str(pending_ids[0]),
    )
    assert confirmed.get("confirmed") is True
    await _wait_for_audit_event(
        require_confirmation_harness.client,
        event_type="ToolExecuted",
        session_id=sid,
        predicate=lambda event: (
            str(event.get("data", {}).get("tool_name", "")) == "web.fetch"
            and bool(event.get("data", {}).get("success")) is True
        ),
    )


async def test_first_principles_cross_session_harness(
    cross_session_harness: ContractHarness,
) -> None:
    sid = await _create_session(cross_session_harness.client)
    remember = await cross_session_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "remember that my favorite color is blue"},
    )
    _assert_normal_reply(remember, executed_actions=1)
    assert _first_tool_payload(remember, "note.create").get("ok") is True

    sid_later = await _create_session(cross_session_harness.client)
    recalled = await cross_session_harness.client.call(
        "session.message",
        {"session_id": sid_later, "content": "what is my favorite color?"},
    )
    _assert_normal_reply(recalled)
    assert "blue" in str(recalled.get("response", "")).lower()
