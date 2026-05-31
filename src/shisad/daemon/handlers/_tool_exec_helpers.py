"""Shared helpers for structured tool-execution result handling."""

import inspect
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


def _payload_taint_labels(payload: Mapping[str, Any]) -> set[TaintLabel]:
    raw = payload.get("taint_labels")
    if not isinstance(raw, list):
        return set()
    labels: set[TaintLabel] = set()
    for item in raw:
        try:
            labels.add(TaintLabel(str(item)))
        except ValueError:
            continue
    return labels


def _browser_audit_details(tool_name: ToolName, payload: Mapping[str, Any]) -> dict[str, Any]:
    if not str(tool_name).startswith("browser."):
        return {}
    details = payload.get("details")
    if not isinstance(details, Mapping):
        return {}
    safe_details: dict[str, Any] = {}
    for key, value in details.items():
        if not isinstance(key, str):
            continue
        if isinstance(value, str | int | float | bool) or value is None:
            safe_details[key] = value
    return safe_details


async def execute_structured_tool(
    *,
    session_id: SessionId,
    tool_name: ToolName,
    payload: Mapping[str, Any],
    default_error: str,
    actor: str,
    emit_event: Callable[[BaseEvent], Awaitable[None]],
    record_execution: Callable[[bool], None | Awaitable[None]],
    sanitize_output: Callable[[str], str],
    taint_labels: set[TaintLabel],
    approval_event_fields: Mapping[str, str] | None = None,
) -> StructuredToolExecutionResult:
    success = bool(payload.get("ok", False))
    event_fields = dict(approval_event_fields or {})
    error = "" if success else str(payload.get("error", default_error))
    details = {} if success else _browser_audit_details(tool_name, payload)
    if not success:
        await emit_event(
            ToolRejected(
                session_id=session_id,
                actor=actor,
                tool_name=tool_name,
                reason=error,
                **event_fields,
            )
        )
    await emit_event(
        ToolExecuted(
            session_id=session_id,
            actor=actor,
            tool_name=tool_name,
            success=success,
            error=error,
            details=details,
            **event_fields,
        )
    )
    record_result = record_execution(success)
    if inspect.isawaitable(record_result):
        await record_result
    return StructuredToolExecutionResult(
        success=success,
        content=sanitize_output(json.dumps(payload, ensure_ascii=True)),
        taint_labels=_payload_taint_labels(payload) or set(taint_labels),
    )
