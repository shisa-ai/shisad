"""Unit checks for shared tool execution helper flows."""

from __future__ import annotations

import pytest

from shisad.core.events import ToolExecuted, ToolRejected
from shisad.core.types import SessionId, TaintLabel, ToolName
from shisad.daemon.handlers._tool_exec_helpers import execute_structured_tool


@pytest.mark.asyncio
async def test_execute_structured_tool_success_emits_executed_only() -> None:
    emitted: list[object] = []
    recorded: list[bool] = []
    seen_raw: list[str] = []

    async def _emit(event: object) -> None:
        emitted.append(event)

    def _record(success: bool) -> None:
        recorded.append(success)

    def _sanitize(raw: str) -> str:
        seen_raw.append(raw)
        return f"sanitized::{raw}"

    result = await execute_structured_tool(
        session_id=SessionId("s1"),
        tool_name=ToolName("web_search"),
        payload={"ok": True, "text": "caf\u00e9"},
        default_error="web_search_failed",
        actor="tool_runtime",
        emit_event=_emit,
        record_execution=_record,
        sanitize_output=_sanitize,
        taint_labels={TaintLabel.UNTRUSTED},
    )

    assert result.success is True
    assert recorded == [True]
    assert len(emitted) == 1
    assert isinstance(emitted[0], ToolExecuted)
    assert emitted[0].success is True
    assert "\\u00e9" in seen_raw[0]
    assert result.content.startswith("sanitized::")
    assert result.taint_labels == {TaintLabel.UNTRUSTED}


@pytest.mark.asyncio
async def test_execute_structured_tool_rejection_emits_rejected_then_executed() -> None:
    emitted: list[object] = []
    recorded: list[bool] = []

    async def _emit(event: object) -> None:
        emitted.append(event)

    result = await execute_structured_tool(
        session_id=SessionId("s1"),
        tool_name=ToolName("web_fetch"),
        payload={"ok": False, "error": "destination_not_allowlisted"},
        default_error="web_fetch_failed",
        actor="tool_runtime",
        emit_event=_emit,
        record_execution=recorded.append,
        sanitize_output=lambda raw: raw,
        taint_labels={TaintLabel.UNTRUSTED},
    )

    assert result.success is False
    assert recorded == [False]
    assert len(emitted) == 2
    assert isinstance(emitted[0], ToolRejected)
    assert emitted[0].reason == "destination_not_allowlisted"
    assert isinstance(emitted[1], ToolExecuted)
    assert emitted[1].success is False


@pytest.mark.asyncio
async def test_execute_structured_tool_uses_default_error_when_missing() -> None:
    emitted: list[object] = []

    async def _emit(event: object) -> None:
        emitted.append(event)

    await execute_structured_tool(
        session_id=SessionId("s1"),
        tool_name=ToolName("git.diff"),
        payload={"ok": False},
        default_error="git_diff_failed",
        actor="tool_runtime",
        emit_event=_emit,
        record_execution=lambda _success: None,
        sanitize_output=lambda raw: raw,
        taint_labels={TaintLabel.UNTRUSTED},
    )

    assert isinstance(emitted[0], ToolRejected)
    assert emitted[0].reason == "git_diff_failed"
