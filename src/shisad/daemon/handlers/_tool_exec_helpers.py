"""Shared helpers for structured tool-execution result handling."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any

from shisad.core.events import BaseEvent, ToolExecuted, ToolRejected
from shisad.core.types import SessionId, TaintLabel, ToolName


@dataclass(slots=True, frozen=True)
class StructuredToolExecutionResult:
    success: bool
    content: str
    taint_labels: set[TaintLabel]


async def execute_structured_tool(
    *,
    session_id: SessionId,
    tool_name: ToolName,
    payload: Mapping[str, Any],
    default_error: str,
    actor: str,
    emit_event: Callable[[BaseEvent], Awaitable[None]],
    record_execution: Callable[[bool], None],
    sanitize_output: Callable[[str], str],
    taint_labels: set[TaintLabel],
) -> StructuredToolExecutionResult:
    success = bool(payload.get("ok", False))
    if not success:
        await emit_event(
            ToolRejected(
                session_id=session_id,
                actor=actor,
                tool_name=tool_name,
                reason=str(payload.get("error", default_error)),
            )
        )
    await emit_event(
        ToolExecuted(
            session_id=session_id,
            actor=actor,
            tool_name=tool_name,
            success=success,
        )
    )
    record_execution(success)
    return StructuredToolExecutionResult(
        success=success,
        content=sanitize_output(json.dumps(payload, ensure_ascii=True)),
        taint_labels=set(taint_labels),
    )
