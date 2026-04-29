"""Behavioral coverage for trusted command chat with pending actions."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from shisad.core.config import DaemonConfig
from shisad.core.providers.base import Message, ProviderResponse
from shisad.core.providers.local_planner import LocalPlannerProvider
from shisad.memory.ingestion import IngestionPipeline
from tests.behavioral.test_behavioral_contract import (
    _contract_harness_context,
    _create_session,
    _stub_complete,
    _tool_call,
)


def _seed_accumulated_tool_recall(config: DaemonConfig, *, content: str) -> None:
    retrieval = IngestionPipeline(config.data_dir / "memory_entries").ingest(
        source_id="prior-tool-output",
        source_type="tool",
        collection="tool_outputs",
        content=content,
        source_origin="tool_output",
        channel_trust="tool_passed",
        confirmation_status="auto_accepted",
        scope="user",
    )
    assert retrieval.chunk_id


def _current_user_request(planner_input: str) -> str:
    normalized = planner_input.replace("^", "")
    _head, separator, tail = normalized.partition("=== USER REQUEST ===")
    if not separator:
        return normalized.strip()
    lines = tail.lstrip("\n").splitlines()
    if lines:
        lines = lines[1:]
    request_lines: list[str] = []
    for line in lines:
        if line.startswith("==="):
            break
        if not line.strip() and request_lines:
            break
        if line.strip():
            request_lines.append(line)
    return "\n".join(request_lines).strip()


def _tool_function_names(tools: list[dict[str, Any]] | None) -> set[str]:
    return {
        str(item.get("function", {}).get("name", "")).strip()
        for item in tools or []
        if str(item.get("function", {}).get("name", "")).strip()
    }


async def _open_browser_fixture_page(harness: Any, sid: str) -> None:
    opened = await harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": f"browser navigate {harness.browser_base_url}/browser",
        },
    )
    assert opened.get("lockdown_level") == "normal"


async def _queue_browser_click_confirmation(harness: Any, sid: str, *, label: str) -> str:
    proposed = await harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": f"browser click the continue button in the browser for {label}",
        },
    )
    pending_ids = proposed.get("pending_confirmation_ids")
    assert isinstance(pending_ids, list)
    assert pending_ids
    return str(pending_ids[-1])


async def _pending_confirmation_ids(harness: Any, sid: str) -> list[str]:
    pending = await harness.client.call(
        "action.pending",
        {"session_id": sid, "status": "pending", "limit": 10},
    )
    actions = pending.get("actions", [])
    assert isinstance(actions, list)
    return [
        str(action.get("confirmation_id", "")).strip()
        for action in actions
        if str(action.get("confirmation_id", "")).strip()
    ]


async def _reject_pending_action(harness: Any, confirmation_id: str) -> None:
    pending = await harness.client.call(
        "action.pending",
        {"confirmation_id": confirmation_id},
    )
    actions = pending.get("actions", [])
    assert isinstance(actions, list)
    assert actions
    nonce = str(actions[0].get("decision_nonce", "")).strip()
    assert nonce
    rejected = await harness.client.call(
        "action.reject",
        {"confirmation_id": confirmation_id, "decision_nonce": nonce},
    )
    assert rejected.get("rejected") is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "content",
    [
        "hey what can you do?",
        "no i mean capabilities",
        "no thanks, just exploring",
        "yes please continue what you were saying",
        "confirm that the file exists",
        "deny it ever happened",
    ],
)
async def test_command_chat_pending_free_form_turn_reaches_planner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    content: str,
) -> None:
    planner_inputs: list[str] = []
    seen_requests: list[str] = []

    async def _pending_chat_complete(
        self: LocalPlannerProvider,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        planner_input = messages[-1].content if messages else ""
        current_request = _current_user_request(planner_input).lower()
        seen_requests.append(current_request)
        if "browser navigate" in current_request or "browser click" in current_request:
            return await _stub_complete(self, messages, tools)
        planner_inputs.append(planner_input)
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="I can help with files, notes, todos, reminders, and web tasks.",
            ),
            model="behavioral-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    async with _contract_harness_context(tmp_path, monkeypatch) as harness:
        monkeypatch.setattr(LocalPlannerProvider, "complete", _pending_chat_complete, raising=True)
        sid = await _create_session(harness.client)
        await _open_browser_fixture_page(harness, sid)
        pending_id = await _queue_browser_click_confirmation(harness, sid, label="free-form")

        reply = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": content},
        )
        remaining_ids = await _pending_confirmation_ids(harness, sid)

    assert planner_inputs, (
        "free-form command-chat turn should reach the planner; "
        f"reply={reply!r} remaining_ids={remaining_ids!r} seen_requests={seen_requests!r}"
    )
    assert "PENDING ACTIONS (TRUSTED CONTROL STATE)" in planner_inputs[-1]
    assert pending_id in planner_inputs[-1]
    assert "approval_level:" in planner_inputs[-1]
    assert "summary:" in planner_inputs[-1]
    assert "preview:" not in planner_inputs[-1]
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("executed_actions", 0)) == 0
    assert str(reply.get("response", "")).startswith("I can help with")
    assert pending_id in remaining_ids
    assert set(reply.get("pending_confirmation_ids", [])) == set(remaining_ids)
    response_lower = str(reply.get("response", "")).lower()
    assert "confirmation command not recognized" not in response_lower
    assert "did you mean" not in response_lower


@pytest.mark.asyncio
async def test_command_chat_action_resolve_hidden_without_surfaced_pending_actions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    visible_toolsets: list[set[str]] = []

    async def _plain_chat_complete(
        self: LocalPlannerProvider,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        planner_input = messages[-1].content if messages else ""
        current_request = _current_user_request(planner_input).lower()
        if "browser navigate" in current_request:
            return await _stub_complete(self, messages, tools)
        visible_toolsets.append(_tool_function_names(tools))
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="I can help with files, notes, todos, reminders, and web tasks.",
            ),
            model="behavioral-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    async with _contract_harness_context(tmp_path, monkeypatch) as harness:
        monkeypatch.setattr(LocalPlannerProvider, "complete", _plain_chat_complete, raising=True)
        sid = await _create_session(harness.client)

        reply = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "what can you do?"},
        )

    assert visible_toolsets
    assert "action_resolve" not in visible_toolsets[-1]
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("executed_actions", 0)) == 0
    assert reply.get("pending_confirmation_ids") == []


@pytest.mark.asyncio
async def test_command_chat_action_resolve_rejects_clean_free_form_planner_misfire(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _misfire_resolution_complete(
        self: LocalPlannerProvider,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        planner_input = messages[-1].content if messages else ""
        current_request = _current_user_request(planner_input).lower()
        if "browser navigate" in current_request or "browser click" in current_request:
            return await _stub_complete(self, messages, tools)
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="I should answer capabilities, not resolve approval.",
                tool_calls=[
                    _tool_call(
                        "action.resolve",
                        {"decision": "confirm", "target": "1", "scope": "one"},
                        call_id="t-action-resolve-clean-misfire",
                    )
                ],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    async with _contract_harness_context(tmp_path, monkeypatch) as harness:
        monkeypatch.setattr(
            LocalPlannerProvider,
            "complete",
            _misfire_resolution_complete,
            raising=True,
        )
        sid = await _create_session(harness.client)
        await _open_browser_fixture_page(harness, sid)
        pending_id = await _queue_browser_click_confirmation(harness, sid, label="misfire")

        reply = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "what can you do?"},
        )
        remaining_ids = await _pending_confirmation_ids(harness, sid)

    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("executed_actions", 0)) == 0
    assert int(reply.get("blocked_actions", 0)) == 1
    assert "explicit current-turn confirmation intent required" in str(reply.get("response", ""))
    assert pending_id in remaining_ids
    assert reply.get("pending_confirmation_ids") == remaining_ids


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("content", "decision", "target", "scope", "expected_remaining", "expected_executed"),
    [
        ("confirm 1", "confirm", "1", "one", 1, 1),
        ("confirm 1 please", "confirm", "1", "one", 1, 1),
        ("reject 1", "reject", "1", "one", 1, 1),
        # The two queued browser clicks share one page control; after the first
        # confirm advances the page, the second pending action is resolved but
        # cannot also execute successfully.
        ("yes to all", "confirm", "all", "all", 0, 1),
        ("no to all", "reject", "all", "all", 0, 2),
    ],
)
async def test_command_chat_explicit_resolution_uses_planner_action_resolve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    content: str,
    decision: str,
    target: str,
    scope: str,
    expected_remaining: int,
    expected_executed: int,
) -> None:
    planner_inputs: list[str] = []
    seen_requests: list[str] = []

    async def _pending_resolution_complete(
        self: LocalPlannerProvider,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        planner_input = messages[-1].content if messages else ""
        current_request = _current_user_request(planner_input).lower()
        seen_requests.append(current_request)
        if "browser navigate" in current_request or "browser click" in current_request:
            return await _stub_complete(self, messages, tools)
        planner_inputs.append(planner_input)
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Resolving the pending action.",
                tool_calls=[
                    _tool_call(
                        "action.resolve",
                        {"decision": decision, "target": target, "scope": scope},
                        call_id="t-action-resolve",
                    )
                ],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    async with _contract_harness_context(tmp_path, monkeypatch) as harness:
        monkeypatch.setattr(
            LocalPlannerProvider,
            "complete",
            _pending_resolution_complete,
            raising=True,
        )
        sid = await _create_session(harness.client)
        await _open_browser_fixture_page(harness, sid)
        first_id = await _queue_browser_click_confirmation(harness, sid, label="one")
        second_id = await _queue_browser_click_confirmation(harness, sid, label="two")
        if decision == "confirm":
            await asyncio.sleep(3.2)
        reply = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": content},
        )
        remaining_ids = await _pending_confirmation_ids(harness, sid)

    assert planner_inputs, (
        "explicit command-chat resolution should reach the planner; "
        f"reply={reply!r} remaining_ids={remaining_ids!r} seen_requests={seen_requests!r}"
    )
    assert "PENDING ACTIONS (TRUSTED CONTROL STATE)" in planner_inputs[-1]
    assert first_id in planner_inputs[-1]
    assert second_id in planner_inputs[-1]
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("executed_actions", 0)) == expected_executed
    assert len(remaining_ids) == expected_remaining
    if scope == "one":
        assert second_id in remaining_ids
    else:
        assert remaining_ids == []


@pytest.mark.asyncio
async def test_command_chat_action_resolve_accepts_polite_id_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pending_id = ""
    planner_inputs: list[str] = []

    async def _polite_id_resolution_complete(
        self: LocalPlannerProvider,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        planner_input = messages[-1].content if messages else ""
        current_request = _current_user_request(planner_input).lower()
        if "browser navigate" in current_request or "browser click" in current_request:
            return await _stub_complete(self, messages, tools)
        planner_inputs.append(planner_input)
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Resolving the pending action.",
                tool_calls=[
                    _tool_call(
                        "action.resolve",
                        {"decision": "confirm", "target": pending_id, "scope": "one"},
                        call_id="t-action-resolve-polite-id",
                    )
                ],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    async with _contract_harness_context(tmp_path, monkeypatch) as harness:
        monkeypatch.setattr(
            LocalPlannerProvider,
            "complete",
            _polite_id_resolution_complete,
            raising=True,
        )
        sid = await _create_session(harness.client)
        await _open_browser_fixture_page(harness, sid)
        pending_id = await _queue_browser_click_confirmation(harness, sid, label="polite-id")
        await asyncio.sleep(3.2)

        reply = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": f"confirm {pending_id} please"},
        )
        remaining_ids = await _pending_confirmation_ids(harness, sid)

    assert planner_inputs
    assert "Use target=<exact id> when the user names a pending id." in planner_inputs[-1]
    assert pending_id in planner_inputs[-1]
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("executed_actions", 0)) == 1
    assert int(reply.get("blocked_actions", 0)) == 0
    assert pending_id not in remaining_ids
    assert reply.get("pending_confirmation_ids") == []


@pytest.mark.asyncio
async def test_command_chat_action_resolve_visible_with_session_tool_allowlist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    visible_toolsets: list[set[str]] = []

    def _restrict_policy_to_browser_tools(config: DaemonConfig) -> None:
        config.policy_path.write_text(
            config.policy_path.read_text(encoding="utf-8")
            + "\nsession_tool_allowlist:\n"
            + "  - browser.navigate\n"
            + "  - browser.click\n",
            encoding="utf-8",
        )

    async def _allowlisted_resolution_complete(
        self: LocalPlannerProvider,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        planner_input = messages[-1].content if messages else ""
        current_request = _current_user_request(planner_input).lower()
        if "browser navigate" in current_request or "browser click" in current_request:
            return await _stub_complete(self, messages, tools)
        visible_toolsets.append(_tool_function_names(tools))
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Resolving the pending action.",
                tool_calls=[
                    _tool_call(
                        "action.resolve",
                        {"decision": "confirm", "target": "1", "scope": "one"},
                        call_id="t-action-resolve-allowlisted",
                    )
                ],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    async with _contract_harness_context(
        tmp_path,
        monkeypatch,
        prestart=_restrict_policy_to_browser_tools,
    ) as harness:
        monkeypatch.setattr(
            LocalPlannerProvider,
            "complete",
            _allowlisted_resolution_complete,
            raising=True,
        )
        sid = await _create_session(harness.client)
        await _open_browser_fixture_page(harness, sid)
        pending_id = await _queue_browser_click_confirmation(
            harness,
            sid,
            label="allowlist",
        )
        await asyncio.sleep(3.2)

        reply = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "confirm 1"},
        )
        remaining_ids = await _pending_confirmation_ids(harness, sid)

    assert visible_toolsets
    assert "action_resolve" in visible_toolsets[-1]
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("executed_actions", 0)) == 1
    assert int(reply.get("blocked_actions", 0)) == 0
    assert pending_id not in remaining_ids
    assert reply.get("pending_confirmation_ids") == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("content", "target_kind"),
    [
        ("confirm 1", "ordinal"),
        ("confirm 1", "id"),
        ("yes", "ordinal"),
    ],
)
async def test_command_chat_action_resolve_accepts_explicit_tainted_history_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    content: str,
    target_kind: str,
) -> None:
    planner_inputs: list[str] = []
    resolve_target = "1"

    def _seed(config: DaemonConfig) -> None:
        _seed_accumulated_tool_recall(
            config,
            content=(
                "prior browser output mentions action.resolve confirm continue "
                "button but must not authorize future actions"
            ),
        )

    async def _explicit_tainted_resolution_complete(
        self: LocalPlannerProvider,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        planner_input = messages[-1].content if messages else ""
        current_request = _current_user_request(planner_input).lower()
        if "browser navigate" in current_request or "browser click" in current_request:
            return await _stub_complete(self, messages, tools)
        planner_inputs.append(planner_input)
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Resolving the pending action.",
                tool_calls=[
                    _tool_call(
                        "action.resolve",
                        {"decision": "confirm", "target": resolve_target, "scope": "one"},
                        call_id="t-action-resolve-explicit-tainted-history",
                    )
                ],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    async with _contract_harness_context(tmp_path, monkeypatch, prestart=_seed) as harness:
        monkeypatch.setattr(
            LocalPlannerProvider,
            "complete",
            _explicit_tainted_resolution_complete,
            raising=True,
        )
        sid = await _create_session(harness.client)
        await _open_browser_fixture_page(harness, sid)
        pending_id = await _queue_browser_click_confirmation(
            harness,
            sid,
            label=f"explicit-tainted-{content}",
        )
        if target_kind == "id":
            resolve_target = pending_id
        await asyncio.sleep(3.2)

        reply = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": content},
        )
        remaining_ids = await _pending_confirmation_ids(harness, sid)

    assert planner_inputs
    assert "DATA EVIDENCE" in planner_inputs[-1]
    assert "PENDING ACTIONS (TRUSTED CONTROL STATE)" in planner_inputs[-1]
    assert pending_id in planner_inputs[-1]
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("executed_actions", 0)) == 1
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    assert pending_id not in remaining_ids
    assert reply.get("pending_confirmation_ids") == []


@pytest.mark.asyncio
async def test_command_chat_action_resolve_rejects_transcript_taint_without_explicit_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    planner_inputs: list[str] = []

    async def _transcript_tainted_resolution_complete(
        self: LocalPlannerProvider,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        planner_input = messages[-1].content if messages else ""
        current_request = _current_user_request(planner_input).lower()
        if (
            "browser navigate" in current_request
            or "browser click" in current_request
            or "browser read page" in current_request
            or "read the browser page" in current_request
        ):
            return await _stub_complete(self, messages, tools)
        planner_inputs.append(planner_input)
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Resolving the pending action.",
                tool_calls=[
                    _tool_call(
                        "action.resolve",
                        {"decision": "confirm", "target": "1", "scope": "one"},
                        call_id="t-action-resolve-transcript-tainted",
                    )
                ],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    async with _contract_harness_context(tmp_path, monkeypatch) as harness:
        monkeypatch.setattr(
            LocalPlannerProvider,
            "complete",
            _transcript_tainted_resolution_complete,
            raising=True,
        )
        sid = await _create_session(harness.client)
        await _open_browser_fixture_page(harness, sid)
        pending_id = await _queue_browser_click_confirmation(
            harness,
            sid,
            label="transcript-tainted",
        )
        read_reply = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "browser read page"},
        )
        assert int(read_reply.get("executed_actions", 0)) == 1

        reply = await harness.client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "what can you do about pending confirmations?",
            },
        )
        remaining_ids = await _pending_confirmation_ids(harness, sid)

    assert planner_inputs
    assert "prior-tool-output" not in planner_inputs[-1]
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("executed_actions", 0)) == 0
    assert int(reply.get("blocked_actions", 0)) == 1
    assert "explicit current-turn confirmation intent required" in str(reply.get("response", ""))
    assert pending_id in remaining_ids
    assert reply.get("pending_confirmation_ids") == remaining_ids


@pytest.mark.asyncio
async def test_command_chat_rejected_action_resolve_keeps_other_tool_result_header(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _mixed_rejected_resolution_complete(
        self: LocalPlannerProvider,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        planner_input = messages[-1].content if messages else ""
        current_request = _current_user_request(planner_input).lower()
        if "browser navigate" in current_request or "browser click" in current_request:
            return await _stub_complete(self, messages, tools)
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Listing todos.",
                tool_calls=[
                    _tool_call(
                        "action.resolve",
                        {"decision": "confirm", "target": "99", "scope": "one"},
                        call_id="t-action-resolve-invalid-target",
                    ),
                    _tool_call(
                        "todo.list",
                        {"limit": 10},
                        call_id="t-todo-list-after-rejected-resolve",
                    ),
                ],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    async with _contract_harness_context(tmp_path, monkeypatch) as harness:
        monkeypatch.setattr(
            LocalPlannerProvider,
            "complete",
            _mixed_rejected_resolution_complete,
            raising=True,
        )
        sid = await _create_session(harness.client)
        await _open_browser_fixture_page(harness, sid)
        pending_id = await _queue_browser_click_confirmation(harness, sid, label="header")

        reply = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "confirm 99 and list my todos"},
        )
        remaining_ids = await _pending_confirmation_ids(harness, sid)

    response_text = str(reply.get("response", ""))
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("executed_actions", 0)) == 1
    assert int(reply.get("blocked_actions", 0)) == 1
    assert "Tool results summary:" in response_text
    assert "Confirmed action result:" not in response_text
    assert "action.resolve rejected:" in response_text
    assert pending_id in remaining_ids


@pytest.mark.asyncio
async def test_command_chat_action_resolve_summary_survives_new_confirmation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    planner_inputs: list[str] = []

    async def _mixed_resolution_complete(
        self: LocalPlannerProvider,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        planner_input = messages[-1].content if messages else ""
        current_request = _current_user_request(planner_input).lower()
        if "browser navigate" in current_request:
            return await _stub_complete(self, messages, tools)
        if "reject 1" not in current_request and "browser click" in current_request:
            return await _stub_complete(self, messages, tools)
        planner_inputs.append(planner_input)
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Resolving the pending action and proposing the next click.",
                tool_calls=[
                    _tool_call(
                        "action.resolve",
                        {"decision": "reject", "target": "1", "scope": "one"},
                        call_id="t-action-resolve-mixed",
                    ),
                    _tool_call(
                        "browser.click",
                        {"target": "#continue", "description": "continue link"},
                        call_id="t-browser-click-mixed",
                    ),
                ],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    async with _contract_harness_context(tmp_path, monkeypatch) as harness:
        monkeypatch.setattr(
            LocalPlannerProvider,
            "complete",
            _mixed_resolution_complete,
            raising=True,
        )
        sid = await _create_session(harness.client)
        await _open_browser_fixture_page(harness, sid)
        rejected_id = await _queue_browser_click_confirmation(harness, sid, label="mixed")
        leftover_id = await _queue_browser_click_confirmation(harness, sid, label="leftover")

        reply = await harness.client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "reject 1 and then browser click the continue button",
            },
        )
        remaining_ids = await _pending_confirmation_ids(harness, sid)

    assert planner_inputs
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("executed_actions", 0)) == 1
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 1
    assert rejected_id not in remaining_ids
    assert leftover_id in remaining_ids
    assert set(reply.get("pending_confirmation_ids", [])) == set(remaining_ids)
    assert len(remaining_ids) == 2
    response_text = str(reply.get("response", ""))
    assert "Pending action resolution:" in response_text
    pending_prompt = response_text.split("Pending action resolution:", 1)[0]
    assert "[PENDING CONFIRMATIONS]" in pending_prompt
    for confirmation_id in remaining_ids:
        assert confirmation_id in pending_prompt
    assert f"{rejected_id} (browser.click): rejected" in response_text


@pytest.mark.asyncio
async def test_command_chat_action_resolve_all_uses_surfaced_pending_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    planner_inputs: list[str] = []

    async def _reverse_mixed_resolution_complete(
        self: LocalPlannerProvider,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        planner_input = messages[-1].content if messages else ""
        current_request = _current_user_request(planner_input).lower()
        if "browser navigate" in current_request:
            return await _stub_complete(self, messages, tools)
        if "reject all" not in current_request and "browser click" in current_request:
            return await _stub_complete(self, messages, tools)
        planner_inputs.append(planner_input)
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Proposing the text entry, then clearing surfaced pending actions.",
                tool_calls=[
                    _tool_call(
                        "browser.type_text",
                        {"target": "#message", "text": "hello", "submit": False},
                        call_id="t-browser-type-before-resolve",
                    ),
                    _tool_call(
                        "action.resolve",
                        {"decision": "reject", "target": "all", "scope": "all"},
                        call_id="t-action-resolve-all-after-new-pending",
                    ),
                ],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    async with _contract_harness_context(tmp_path, monkeypatch) as harness:
        monkeypatch.setattr(
            LocalPlannerProvider,
            "complete",
            _reverse_mixed_resolution_complete,
            raising=True,
        )
        sid = await _create_session(harness.client)
        await _open_browser_fixture_page(harness, sid)
        surfaced_id = await _queue_browser_click_confirmation(harness, sid, label="snapshot")

        reply = await harness.client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "reject all pending and browser type text into the page",
            },
        )
        remaining_ids = await _pending_confirmation_ids(harness, sid)

    assert planner_inputs
    assert surfaced_id in planner_inputs[-1]
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("executed_actions", 0)) == 1
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 1
    assert surfaced_id not in remaining_ids
    assert reply.get("pending_confirmation_ids") == remaining_ids
    assert len(remaining_ids) == 1
    response_text = str(reply.get("response", ""))
    assert "Pending action resolution:" in response_text
    assert f"{surfaced_id} (browser.click): rejected" in response_text


@pytest.mark.asyncio
async def test_command_chat_action_resolve_invalid_target_keeps_pending(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _invalid_resolution_complete(
        self: LocalPlannerProvider,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        planner_input = messages[-1].content if messages else ""
        current_request = _current_user_request(planner_input).lower()
        if "browser navigate" in current_request or "browser click" in current_request:
            return await _stub_complete(self, messages, tools)
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Resolving the pending action.",
                tool_calls=[
                    _tool_call(
                        "action.resolve",
                        {"decision": "confirm", "target": "99", "scope": "one"},
                        call_id="t-action-resolve-invalid",
                    )
                ],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    async with _contract_harness_context(tmp_path, monkeypatch) as harness:
        monkeypatch.setattr(
            LocalPlannerProvider,
            "complete",
            _invalid_resolution_complete,
            raising=True,
        )
        sid = await _create_session(harness.client)
        await _open_browser_fixture_page(harness, sid)
        pending_id = await _queue_browser_click_confirmation(harness, sid, label="invalid")

        reply = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "confirm 99"},
        )
        remaining_ids = await _pending_confirmation_ids(harness, sid)

    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("executed_actions", 0)) == 0
    assert int(reply.get("blocked_actions", 0)) == 1
    assert "target_not_pending" in str(reply.get("response", ""))
    assert pending_id in remaining_ids
    assert reply.get("pending_confirmation_ids") == remaining_ids


@pytest.mark.asyncio
async def test_command_chat_action_resolve_rejects_cross_session_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    other_pending_id = ""

    async def _cross_session_resolution_complete(
        self: LocalPlannerProvider,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        planner_input = messages[-1].content if messages else ""
        current_request = _current_user_request(planner_input).lower()
        if "browser navigate" in current_request or "browser click" in current_request:
            return await _stub_complete(self, messages, tools)
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Resolving the pending action.",
                tool_calls=[
                    _tool_call(
                        "action.resolve",
                        {"decision": "confirm", "target": other_pending_id, "scope": "one"},
                        call_id="t-action-resolve-cross-session",
                    )
                ],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    async with _contract_harness_context(tmp_path, monkeypatch) as harness:
        monkeypatch.setattr(
            LocalPlannerProvider,
            "complete",
            _cross_session_resolution_complete,
            raising=True,
        )
        sid = await _create_session(harness.client)
        other_sid = await _create_session(harness.client)
        await _open_browser_fixture_page(harness, sid)
        await _open_browser_fixture_page(harness, other_sid)
        current_pending_id = await _queue_browser_click_confirmation(
            harness,
            sid,
            label="current",
        )
        other_pending_id = await _queue_browser_click_confirmation(
            harness,
            other_sid,
            label="other",
        )

        reply = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": f"confirm {other_pending_id}"},
        )
        current_remaining_ids = await _pending_confirmation_ids(harness, sid)
        other_remaining_ids = await _pending_confirmation_ids(harness, other_sid)

    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("executed_actions", 0)) == 0
    assert int(reply.get("blocked_actions", 0)) == 1
    assert "target_not_pending" in str(reply.get("response", ""))
    assert current_pending_id in current_remaining_ids
    assert other_pending_id in other_remaining_ids


@pytest.mark.asyncio
async def test_command_chat_action_resolve_rejects_already_resolved_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolved_pending_id = ""

    async def _resolved_target_complete(
        self: LocalPlannerProvider,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        planner_input = messages[-1].content if messages else ""
        current_request = _current_user_request(planner_input).lower()
        if "browser navigate" in current_request or "browser click" in current_request:
            return await _stub_complete(self, messages, tools)
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Resolving the pending action.",
                tool_calls=[
                    _tool_call(
                        "action.resolve",
                        {"decision": "confirm", "target": resolved_pending_id, "scope": "one"},
                        call_id="t-action-resolve-already-resolved",
                    )
                ],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    async with _contract_harness_context(tmp_path, monkeypatch) as harness:
        monkeypatch.setattr(
            LocalPlannerProvider,
            "complete",
            _resolved_target_complete,
            raising=True,
        )
        sid = await _create_session(harness.client)
        await _open_browser_fixture_page(harness, sid)
        resolved_pending_id = await _queue_browser_click_confirmation(
            harness,
            sid,
            label="resolved",
        )
        await _reject_pending_action(harness, resolved_pending_id)

        reply = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": f"confirm {resolved_pending_id}"},
        )
        remaining_ids = await _pending_confirmation_ids(harness, sid)

    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("executed_actions", 0)) == 0
    assert int(reply.get("blocked_actions", 0)) == 1
    assert "not permitted by session/policy allowlist" in str(reply.get("response", ""))
    assert resolved_pending_id not in remaining_ids
    assert reply.get("pending_confirmation_ids") == []


@pytest.mark.asyncio
async def test_command_chat_action_resolve_rejects_dirty_trusted_cli_turn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    planner_inputs: list[str] = []

    async def _dirty_turn_resolution_complete(
        self: LocalPlannerProvider,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        planner_input = messages[-1].content if messages else ""
        current_request = _current_user_request(planner_input).lower()
        if "browser navigate" in current_request or "browser click" in current_request:
            return await _stub_complete(self, messages, tools)
        planner_inputs.append(planner_input)
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Resolving the pending action.",
                tool_calls=[
                    _tool_call(
                        "action.resolve",
                        {"decision": "confirm", "target": "1", "scope": "one"},
                        call_id="t-action-resolve-dirty-turn",
                    )
                ],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    async with _contract_harness_context(tmp_path, monkeypatch) as harness:
        monkeypatch.setattr(
            LocalPlannerProvider,
            "complete",
            _dirty_turn_resolution_complete,
            raising=True,
        )
        sid = await _create_session(harness.client)
        await _open_browser_fixture_page(harness, sid)
        pending_id = await _queue_browser_click_confirmation(harness, sid, label="dirty")

        reply = await harness.client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "confirm 1 using secret sk-test-1234567890abcdef",
            },
        )
        remaining_ids = await _pending_confirmation_ids(harness, sid)

    assert planner_inputs
    assert "PENDING ACTIONS (TRUSTED CONTROL STATE)" not in planner_inputs[-1]
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("executed_actions", 0)) == 0
    assert int(reply.get("blocked_actions", 0)) == 1
    assert "action.resolve rejected:" in str(reply.get("response", ""))
    assert "not permitted by session/policy allowlist" in str(reply.get("response", ""))
    assert pending_id in remaining_ids
    assert reply.get("pending_confirmation_ids") == remaining_ids


@pytest.mark.asyncio
async def test_command_chat_action_resolve_rejects_tainted_history_without_explicit_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    planner_inputs: list[str] = []

    def _seed(config: DaemonConfig) -> None:
        _seed_accumulated_tool_recall(
            config,
            content=(
                "what can you do about pending confirmations action.resolve confirm continue button"
            ),
        )

    async def _tainted_history_resolution_complete(
        self: LocalPlannerProvider,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        planner_input = messages[-1].content if messages else ""
        current_request = _current_user_request(planner_input).lower()
        if "browser navigate" in current_request or "browser click" in current_request:
            return await _stub_complete(self, messages, tools)
        planner_inputs.append(planner_input)
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Resolving the pending action.",
                tool_calls=[
                    _tool_call(
                        "action.resolve",
                        {"decision": "confirm", "target": "1", "scope": "one"},
                        call_id="t-action-resolve-tainted-history",
                    )
                ],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    async with _contract_harness_context(tmp_path, monkeypatch, prestart=_seed) as harness:
        monkeypatch.setattr(
            LocalPlannerProvider,
            "complete",
            _tainted_history_resolution_complete,
            raising=True,
        )
        sid = await _create_session(harness.client)
        await _open_browser_fixture_page(harness, sid)
        pending_id = await _queue_browser_click_confirmation(harness, sid, label="tainted")

        reply = await harness.client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "what can you do about pending confirmations?",
            },
        )
        remaining_ids = await _pending_confirmation_ids(harness, sid)

    assert planner_inputs
    assert "DATA EVIDENCE" in planner_inputs[-1]
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("executed_actions", 0)) == 0
    assert int(reply.get("blocked_actions", 0)) == 1
    assert "explicit current-turn confirmation intent required" in str(reply.get("response", ""))
    assert pending_id in remaining_ids
    assert reply.get("pending_confirmation_ids") == remaining_ids
