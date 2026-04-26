"""Behavioral contract tests: end-to-end functionality.

These tests exercise the live daemon `session.message` runtime path (planner -> PEP ->
control plane -> tool execution -> response) with deterministic stubs.

Why: we previously had extensive security/unit coverage, but could still ship a build
that was "correct" and "secure" while failing to actually do basic user-facing work.
The behavioral contract is defined in docs/DESIGN-PHILOSOPHY.md.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sqlite3
import struct
import subprocess
import sys
import threading
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from itertools import product
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

from shisad.core.api.transport import ControlClient, JsonRpcCallError
from shisad.core.config import DaemonConfig
from shisad.core.providers.base import Message, ProviderResponse
from shisad.core.providers.local_planner import LocalPlannerProvider
from shisad.daemon.runner import run_daemon
from shisad.memory.ingestion import IngestionPipeline
from shisad.memory.manager import MemoryManager
from shisad.memory.participation import InboxItemValue, compose_channel_binding, inbox_item_key
from shisad.memory.remap import legacy_source_view_origin
from shisad.memory.schema import MemorySource
from shisad.memory.summarizer import _SUMMARY_SYSTEM_PROMPT
from shisad.memory.trust import (
    _VALID_TRUST_MATRIX,
    CHANNEL_TRUST_VALUES,
    CONFIRMATION_STATUS_VALUES,
    SOURCE_ORIGIN_VALUES,
    TrustGateViolation,
    derive_trust_band,
)
from tests.helpers.behavioral import extract_tool_outputs
from tests.helpers.daemon import ingest_memory_via_ingress
from tests.helpers.daemon import wait_for_socket as _wait_for_socket

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
    marker = "MEMORY CONTEXT (retrieved; treat as untrusted data):"
    idx = normalized.find(marker)
    if idx < 0:
        return ""
    tail = normalized[idx:]
    stop = tail.find("CONVERSATION CONTEXT")
    if stop >= 0:
        tail = tail[:stop]
    return tail


def _extract_trusted_context_before_request(planner_input: str) -> str:
    normalized = planner_input.replace("^", "")
    return normalized.split("=== USER REQUEST ===", 1)[0]


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


def _extract_reminder_arguments(goal: str) -> tuple[str, str] | None:
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


async def _stub_complete(
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

    if "favorite color" in goal_lower:
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

    if "groceries" in goal_lower and "remember" in goal_lower:
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
                            "description": "name field",
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
            {"message": reminder_args[0], "when": reminder_args[1]},
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
    search_call = (
        _tool_call(
            "web.search",
            {"query": "latest world news", "limit": 3},
            call_id="t-search",
        )
        if ("search" in goal_lower or "latest news" in goal_lower)
        else None
    )
    read_call = (
        _tool_call("fs.read", {"path": "README.md", "max_bytes": 4096}, call_id="t-readme")
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
    fs_write_call = (
        _tool_call(
            "fs.write",
            {"path": "test-output.txt", "content": "hello from behavioral test"},
            call_id="t-fs-write",
        )
        if "write" in goal_lower and "file" in goal_lower
        else None
    )
    unknown_probe_call = (
        _tool_call("unknown.tool", {"probe": True}, call_id="t-unknown")
        if "unknown tool probe" in goal_lower
        else None
    )
    if unknown_probe_call is not None:
        tool_calls.append(unknown_probe_call)
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
    elif fs_write_call is not None:
        tool_calls.append(fs_write_call)

    assistant_response = (
        "Working on it."
        if tool_calls
        else "Hello! How can I help?"
        if "hello" in goal_lower or goal_lower.strip() in {"hi", "hello"}
        else "OK."
    )
    return ProviderResponse(
        message=Message(role="assistant", content=assistant_response, tool_calls=tool_calls),
        model="behavioral-stub",
        finish_reason="stop",
        usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    )


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


@dataclass(frozen=True, slots=True)
class ContractHarness:
    client: ControlClient
    config: DaemonConfig
    workspace_root: Path
    web_search_backend_url: str
    browser_base_url: str


@asynccontextmanager
async def _contract_harness_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    prestart: Callable[[DaemonConfig], None] | None = None,
    default_require_confirmation: bool = False,
    web_search_backend_configured: bool = True,
    policy_egress_allowed: bool = True,
    browser_enabled: bool | None = None,
) -> AsyncIterator[ContractHarness]:
    server: ThreadingHTTPServer | None = None
    thread: threading.Thread | None = None
    backend_url = ""
    backend_port = 0
    if web_search_backend_configured:
        server, thread, backend_url, backend_port = _start_stub_search_backend()
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
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "\n".join(
            [
                'version: "1"',
                f"default_require_confirmation: {str(default_require_confirmation).lower()}",
                "safe_output_domains:",
                '  - "localhost"',
                '  - "example.com"',
                *egress_lines,
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    _force_deterministic_local_planner(monkeypatch=monkeypatch)

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        log_level="WARNING",
        context_window=1,
        web_search_enabled=True,
        web_search_backend_url=backend_url,
        web_allowed_domains=["127.0.0.1", "localhost"],
        browser_enabled=web_search_backend_configured
        if browser_enabled is None
        else browser_enabled,
        browser_command=(
            f"{sys.executable} "
            f"{Path(__file__).resolve().parents[1] / 'fixtures' / 'fake_playwright_cli.py'}"
        ),
        browser_allowed_domains=["127.0.0.1", "localhost"],
        browser_require_hardened_isolation=False,
        assistant_fs_roots=[workspace_root],
    )
    if prestart is not None:
        prestart(config)

    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        yield ContractHarness(
            client=client,
            config=config,
            workspace_root=workspace_root,
            web_search_backend_url=backend_url,
            browser_base_url=backend_url,
        )
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        with suppress(Exception):
            await asyncio.wait_for(daemon_task, timeout=5)
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            with suppress(Exception):
                thread.join(timeout=1.0)


@pytest.fixture
async def contract_harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ContractHarness:
    async with _contract_harness_context(tmp_path, monkeypatch) as harness:
        yield harness


async def _create_session(client: ControlClient, *, channel: str = "cli") -> str:
    created = await client.call(
        "session.create",
        {"channel": channel, "user_id": "alice", "workspace_id": "ws1"},
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


@pytest.mark.asyncio
async def test_contract_hello_responds_without_lockdown(contract_harness: ContractHarness) -> None:
    sid = await _create_session(contract_harness.client)
    reply = await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "channel": "cli",
            "user_id": "alice",
            "workspace_id": "ws1",
            "content": "hello",
        },
    )
    assert str(reply.get("response", "")).strip()
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 0


@pytest.mark.asyncio
async def test_contract_web_search_executes_and_returns_results(
    contract_harness: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness.client)
    reply = await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": "search for the latest news",
        },
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    outputs = _extract_tool_outputs(reply)
    assert "web.search" in outputs
    payload = outputs["web.search"][0]
    assert payload.get("ok") is True
    assert payload.get("results")
    assert str(payload.get("backend", "")).startswith(contract_harness.web_search_backend_url)


@pytest.mark.asyncio
async def test_m1_rlc7_clean_session_latest_news_executes_without_confirmation(
    contract_harness: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness.client)
    reply = await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": "can you get me the latest news?",
        },
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    outputs = _extract_tool_outputs(reply)
    assert "web.search" in outputs
    payload = outputs["web.search"][0]
    assert payload.get("ok") is True


@pytest.mark.asyncio
async def test_m1_rlc7_repeat_latest_news_same_session_executes_without_confirmation(
    contract_harness: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness.client)
    first = await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": "search for the latest news",
        },
    )
    assert first.get("lockdown_level") == "normal"
    assert int(first.get("blocked_actions", 0)) == 0
    assert int(first.get("confirmation_required_actions", 0)) == 0
    assert int(first.get("executed_actions", 0)) == 1

    second = await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": "search for the latest news",
        },
    )
    assert second.get("lockdown_level") == "normal"
    assert int(second.get("blocked_actions", 0)) == 0
    assert int(second.get("confirmation_required_actions", 0)) == 0
    assert int(second.get("executed_actions", 0)) == 1
    outputs = _extract_tool_outputs(second)
    assert "web.search" in outputs


@pytest.mark.asyncio
async def test_contract_file_read_executes_and_returns_content(
    contract_harness: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness.client)
    reply = await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": "read README.md",
        },
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    outputs = _extract_tool_outputs(reply)
    assert "fs.read" in outputs
    payload = outputs["fs.read"][0]
    assert payload.get("ok") is True
    assert "behavioral-readme" in str(payload.get("content", ""))
    assert "behavioral-readme" in str(reply.get("response", ""))


@pytest.mark.asyncio
async def test_contract_attachment_ingest_executes_and_returns_manifest_ref(
    contract_harness: ContractHarness,
) -> None:
    image = contract_harness.workspace_root / "receipt.png"
    ihdr = b"IHDR" + struct.pack(">IIBBBBB", 3, 4, 8, 2, 0, 0, 0)
    image.write_bytes(b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + ihdr + b"\x00\x00\x00\x00")

    sid = await _create_session(contract_harness.client)
    reply = await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": f"ingest attachment {image}",
        },
    )

    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    outputs = _extract_tool_outputs(reply)
    assert "attachment.ingest" in outputs
    payload = outputs["attachment.ingest"][0]
    assert payload.get("ok") is True
    assert payload.get("status") == "active"
    assert payload.get("kind") == "image"
    assert str(payload.get("evidence_ref_id", "")).startswith("ev-")


@pytest.mark.asyncio
async def test_contract_fs_list_executes_and_returns_entries(
    contract_harness: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness.client)
    reply = await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": "can you list the files in the folder you're in?",
        },
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    outputs = _extract_tool_outputs(reply)
    assert "fs.list" in outputs
    payload = outputs["fs.list"][0]
    assert payload.get("ok") is True
    entries = payload.get("entries")
    assert isinstance(entries, list)
    assert int(payload.get("count", 0)) >= 1
    assert any(str(item.get("path", "")).strip() for item in entries)


@pytest.mark.asyncio
async def test_contract_confirmed_fs_list_result_is_usable_on_followup(
    contract_harness: ContractHarness,
) -> None:
    (contract_harness.workspace_root / "todo.log").write_text(
        "OPEN: verify confirmed result threading\n",
        encoding="utf-8",
    )
    sid = await _create_session(contract_harness.client)
    first = await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": "review TODO.LOG and list only open items",
        },
    )
    assert first.get("lockdown_level") == "normal"
    assert int(first.get("blocked_actions", 0)) == 0
    assert int(first.get("confirmation_required_actions", 0)) == 0
    first_outputs = _extract_tool_outputs(first)
    assert "fs.read" in first_outputs
    assert first_outputs["fs.read"][0].get("ok") is False
    assert first_outputs["fs.read"][0].get("error") == "path_not_found"

    proposed = await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": "can you look for the file? filename should be similar if it's not exact",
        },
    )
    assert proposed.get("lockdown_level") == "normal"
    assert int(proposed.get("blocked_actions", 0)) == 0
    assert int(proposed.get("executed_actions", 0)) == 0
    assert int(proposed.get("confirmation_required_actions", 0)) >= 1
    pending_ids = proposed.get("pending_confirmation_ids")
    assert isinstance(pending_ids, list)
    assert pending_ids

    confirmed = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "confirm"},
    )
    assert confirmed.get("lockdown_level") == "normal"
    assert int(confirmed.get("blocked_actions", 0)) == 0
    assert int(confirmed.get("confirmation_required_actions", 0)) == 0
    assert int(confirmed.get("executed_actions", 0)) == 1
    confirmed_outputs = _extract_tool_outputs(confirmed)
    assert "fs.list" in confirmed_outputs
    assert "todo.log" in json.dumps(confirmed_outputs["fs.list"], ensure_ascii=True)
    assert "todo.log" in str(confirmed.get("response", ""))

    followup = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "what was in that listing?"},
    )
    assert followup.get("lockdown_level") == "normal"
    assert int(followup.get("blocked_actions", 0)) == 0
    assert int(followup.get("confirmation_required_actions", 0)) == 0
    assert followup.get("pending_confirmation_ids") == []
    assert "todo.log" in str(followup.get("response", ""))


@pytest.mark.asyncio
async def test_m3_long_clean_session_goal_not_truncated_for_planner(
    contract_harness: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness.client)
    long_prefix = "x" * 600
    reply = await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": f"{long_prefix} search for the latest news",
        },
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    outputs = _extract_tool_outputs(reply)
    assert "web.search" in outputs


@pytest.mark.asyncio
async def test_contract_trusted_cli_search_executes_with_accumulated_untrusted_recall(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _seed(config: DaemonConfig) -> None:
        retrieval = IngestionPipeline(config.data_dir / "memory_entries").ingest(
            source_id="prior-tool-output",
            source_type="tool",
            collection="tool_outputs",
            content=(
                "Prior tool output mentioned latest world news and shisa.ai; it should not "
                "make a later trusted user search require confirmation."
            ),
            source_origin="tool_output",
            channel_trust="tool_passed",
            confirmation_status="auto_accepted",
            scope="user",
        )
        assert retrieval.chunk_id

    async with _contract_harness_context(tmp_path, monkeypatch, prestart=_seed) as harness:
        sid = await _create_session(harness.client)
        reply = await harness.client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "search the web for shisa.ai and tell me what they do",
            },
        )

    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    assert reply.get("pending_confirmation_ids") == []
    assert int(reply.get("executed_actions", 0)) == 1
    outputs = _extract_tool_outputs(reply)
    assert "web.search" in outputs


@pytest.mark.asyncio
async def test_contract_trusted_cli_todo_create_executes_with_accumulated_untrusted_recall(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _seed(config: DaemonConfig) -> None:
        retrieval = IngestionPipeline(config.data_dir / "memory_entries").ingest(
            source_id="prior-tool-output",
            source_type="tool",
            collection="tool_outputs",
            content=(
                "Prior tool output mentioned scan-complete and routine file listing. "
                "This accumulated state should not make a later trusted todo write "
                "require confirmation."
            ),
            source_origin="tool_output",
            channel_trust="tool_passed",
            confirmation_status="auto_accepted",
            scope="user",
        )
        assert retrieval.chunk_id

    async with _contract_harness_context(tmp_path, monkeypatch, prestart=_seed) as harness:
        sid = await _create_session(harness.client)
        reply = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "add todo: scan-complete"},
        )

    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    assert reply.get("pending_confirmation_ids") == []
    assert int(reply.get("executed_actions", 0)) == 1
    outputs = _extract_tool_outputs(reply)
    assert "todo.create" in outputs


@pytest.mark.asyncio
async def test_contract_first_principles_gates_survive_accumulated_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _seed(config: DaemonConfig) -> None:
        tool_recall = IngestionPipeline(config.data_dir / "memory_entries").ingest(
            source_id="prior-tool-output",
            source_type="tool",
            collection="tool_outputs",
            content=(
                "Prior tool output mentioned latest world news, README.md, favorite color, "
                "and related projects. This accumulated state should not make the first "
                "principles gates require confirmation."
            ),
            source_origin="tool_output",
            channel_trust="tool_passed",
            confirmation_status="auto_accepted",
            scope="user",
        )
        assert tool_recall.chunk_id

    async with _contract_harness_context(tmp_path, monkeypatch, prestart=_seed) as harness:
        sid = await _create_session(harness.client)

        hello = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "hello"},
        )
        assert hello.get("lockdown_level") == "normal"
        assert int(hello.get("blocked_actions", 0)) == 0
        assert int(hello.get("confirmation_required_actions", 0)) == 0
        assert str(hello.get("response", "")).strip()

        search = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "search for the latest news"},
        )
        assert search.get("lockdown_level") == "normal"
        assert int(search.get("blocked_actions", 0)) == 0
        assert int(search.get("confirmation_required_actions", 0)) == 0
        assert "web.search" in _extract_tool_outputs(search)

        read = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "read README.md"},
        )
        assert read.get("lockdown_level") == "normal"
        assert int(read.get("blocked_actions", 0)) == 0
        assert int(read.get("confirmation_required_actions", 0)) == 0
        assert "fs.read" in _extract_tool_outputs(read)

        remember = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "remember that my favorite color is blue"},
        )
        assert remember.get("lockdown_level") == "normal"
        assert int(remember.get("blocked_actions", 0)) == 0
        assert int(remember.get("confirmation_required_actions", 0)) == 0
        assert remember.get("pending_confirmation_ids") == []
        assert "note.create" in _extract_tool_outputs(remember)

        sid_later = await _create_session(harness.client)
        recalled = await harness.client.call(
            "session.message",
            {"session_id": sid_later, "content": "what is my favorite color?"},
        )
        assert recalled.get("lockdown_level") == "normal"
        assert int(recalled.get("blocked_actions", 0)) == 0
        assert int(recalled.get("confirmation_required_actions", 0)) == 0
        assert "blue" in str(recalled.get("response", "")).lower()

        multi = await harness.client.call(
            "session.message",
            {"session_id": sid_later, "content": "read the README and search for related projects"},
        )
        assert multi.get("lockdown_level") == "normal"
        assert int(multi.get("blocked_actions", 0)) == 0
        assert int(multi.get("confirmation_required_actions", 0)) == 0
        outputs = _extract_tool_outputs(multi)
        assert "fs.read" in outputs
        assert "web.search" in outputs


@pytest.mark.asyncio
async def test_contract_single_unknown_action_kind_does_not_immediately_lockdown(
    contract_harness: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness.client)
    reply = await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": "please run unknown tool probe now",
        },
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) >= 1

    violations = await contract_harness.client.call(
        "audit.query",
        {"event_type": "PlanViolationDetected", "session_id": sid, "limit": 20},
    )
    assert violations["total"] >= 1
    assert any(
        "trace:action_not_committed" in json.dumps(event, ensure_ascii=True)
        for event in violations.get("events", [])
    )


@pytest.mark.asyncio
async def test_contract_memory_remember_persists_and_is_used_later(
    contract_harness: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness.client)

    # Turn 1: user asks to remember.
    remember = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "remember that my favorite color is blue"},
    )
    assert remember.get("lockdown_level") == "normal"
    assert int(remember.get("blocked_actions", 0)) == 0
    assert int(remember.get("confirmation_required_actions", 0)) == 0
    assert remember.get("pending_confirmation_ids") == []
    assert "note.create" in _extract_tool_outputs(remember)

    # Trigger summarization (default summarize_interval=10 entries; ~5 turns).
    for _ in range(4):
        await contract_harness.client.call(
            "session.message",
            {"session_id": sid, "content": "ok"},
        )

    retrieved = await contract_harness.client.call(
        "memory.retrieve",
        {"query": "favorite color", "limit": 5},
    )
    rendered = json.dumps(retrieved, ensure_ascii=True).lower()
    assert "favorite color" in rendered
    assert "blue" in rendered

    # Turn 6: ensure the planner sees MEMORY CONTEXT and can answer from it.
    reply = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "what is my favorite color"},
    )
    assert reply.get("lockdown_level") == "normal"
    assert "blue" in str(reply.get("response", "")).lower()


@pytest.mark.asyncio
async def test_contract_same_session_trusted_user_fact_is_usable_immediately(
    contract_harness: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness.client)

    remember = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "remember that my favorite color is blue"},
    )
    assert remember.get("lockdown_level") == "normal"
    assert int(remember.get("blocked_actions", 0)) == 0
    assert int(remember.get("confirmation_required_actions", 0)) == 0
    assert remember.get("pending_confirmation_ids") == []
    assert "note.create" in _extract_tool_outputs(remember)

    reply = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "what is my favorite color?"},
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    assert "blue" in str(reply.get("response", "")).lower()


@pytest.mark.asyncio
async def test_contract_same_session_trusted_user_fact_not_only_untrusted_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_inputs: list[str] = []

    async with _contract_harness_context(tmp_path, monkeypatch) as harness:

        async def _capture_complete(
            self: LocalPlannerProvider,
            messages: list[Message],
            tools: list[dict[str, Any]] | None = None,
        ) -> ProviderResponse:
            if messages:
                captured_inputs.append(str(messages[-1].content))
            return await _stub_complete(self, messages, tools)

        monkeypatch.setattr(LocalPlannerProvider, "complete", _capture_complete, raising=True)
        sid = await _create_session(harness.client)
        await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "remember that my favorite color is blue"},
        )
        reply = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "what is my favorite color?"},
        )
        assert "blue" in str(reply.get("response", "")).lower()

    planner_input = _latest_user_request_planner_input(captured_inputs)
    trusted_section = _extract_trusted_context_before_request(planner_input).lower()
    assert "trusted same-session user context" in trusted_section
    assert "favorite color is blue" in trusted_section


@pytest.mark.asyncio
async def test_contract_cli_memory_write_surfaces_identity_in_new_session(
    contract_harness: ContractHarness,
) -> None:
    written = await _run_contract_cli(
        contract_harness.config,
        "memory",
        "write",
        "--type",
        "persona_fact",
        "--key",
        "user:editor",
        "--value",
        "helix",
    )
    assert written.returncode == 0, written.stderr or written.stdout

    sid = await _create_session(contract_harness.client)
    reply = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "what is my favorite editor?"},
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    assert "helix" in str(reply.get("response", "")).lower()


@pytest.mark.asyncio
async def test_contract_cli_memory_write_identity_context_is_explicitly_trusted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_inputs: list[str] = []

    async with _contract_harness_context(tmp_path, monkeypatch) as harness:
        written = await _run_contract_cli(
            harness.config,
            "memory",
            "write",
            "--type",
            "persona_fact",
            "--key",
            "user:editor",
            "--value",
            "helix",
        )
        assert written.returncode == 0, written.stderr or written.stdout

        async def _capture_complete(
            self: LocalPlannerProvider,
            messages: list[Message],
            tools: list[dict[str, Any]] | None = None,
        ) -> ProviderResponse:
            if messages:
                captured_inputs.append(str(messages[-1].content))
            return await _stub_complete(self, messages, tools)

        monkeypatch.setattr(LocalPlannerProvider, "complete", _capture_complete, raising=True)
        sid = await _create_session(harness.client)
        reply = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "what is my favorite editor?"},
        )
        assert "helix" in str(reply.get("response", "")).lower()

    planner_input = _latest_user_request_planner_input(captured_inputs)
    trusted_section = _extract_trusted_context_before_request(planner_input).lower()
    assert "trusted identity memory" in trusted_section
    assert "user:editor" in trusted_section
    assert "helix" in trusted_section


@pytest.mark.asyncio
async def test_contract_memory_retrieve_prioritizes_user_curated_and_marks_untrusted(
    contract_harness: ContractHarness,
) -> None:
    await ingest_memory_via_ingress(
        contract_harness.client,
        source_type="user",
        source_id="user-ranked",
        content="The release codename is nebula and the user confirmed it directly.",
    )
    await ingest_memory_via_ingress(
        contract_harness.client,
        source_type="external",
        source_id="web-ranked",
        collection="external_web",
        content="The release codename is nebula according to an untrusted web mirror.",
    )

    retrieved = await contract_harness.client.call(
        "memory.retrieve",
        {"query": "release codename nebula", "limit": 2},
    )

    results = list(retrieved.get("results") or [])
    assert len(results) == 2
    assert str(results[0].get("collection", "")) == "user_curated"
    assert float(results[0].get("effective_score", 0.0)) >= float(
        results[1].get("effective_score", 0.0)
    )
    assert str(results[1].get("collection", "")) == "external_web"
    assert results[1].get("verification_gap") is True


@pytest.mark.asyncio
async def test_contract_memory_retrieve_uses_canonical_trust_band_for_user_curated_hits(
    contract_harness: ContractHarness,
) -> None:
    elevated = await ingest_memory_via_ingress(
        contract_harness.client,
        source_type="user",
        source_id="user-elevated",
        content="The release owner handle is shisa-ai according to the user directly.",
    )
    observed = await ingest_memory_via_ingress(
        contract_harness.client,
        source_type="user",
        source_id="user-observed",
        content="The release owner handle is shisa-ai from an owner-observed channel sync.",
    )
    db_path = contract_harness.config.data_dir / "memory_entries" / "memory.sqlite3"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            UPDATE retrieval_records
            SET source_origin = ?, channel_trust = ?, confirmation_status = ?, scope = ?
            WHERE chunk_id = ?
            """,
            ("user_direct", "owner_observed", "auto_accepted", "channel", observed["chunk_id"]),
        )

    retrieved = await contract_harness.client.call(
        "memory.retrieve",
        {"query": "release owner handle shisa-ai", "limit": 2},
    )

    results = list(retrieved.get("results") or [])
    assert [item.get("chunk_id") for item in results] == [
        elevated["chunk_id"],
        observed["chunk_id"],
    ]
    assert results[0].get("collection") == "user_curated"
    assert results[0].get("trust_band") == "elevated"
    assert results[0].get("trust_caveat") is None
    assert results[1].get("collection") == "user_curated"
    assert results[1].get("trust_band") == "untrusted"
    assert str(results[1].get("trust_caveat", "")).strip()
    assert results[1].get("verification_gap") is True


@pytest.mark.asyncio
async def test_contract_memory_retrieve_scope_filter_limits_results(
    contract_harness: ContractHarness,
) -> None:
    session_entry = await ingest_memory_via_ingress(
        contract_harness.client,
        source_type="user",
        source_id="session-scope",
        content="Deployment checklist item for the active session only.",
    )
    await ingest_memory_via_ingress(
        contract_harness.client,
        source_type="user",
        source_id="user-scope",
        content="Deployment checklist item for the long-term user profile.",
    )
    db_path = contract_harness.config.data_dir / "memory_entries" / "memory.sqlite3"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE retrieval_records SET scope = ? WHERE chunk_id = ?",
            ("session", session_entry["chunk_id"]),
        )

    retrieved = await contract_harness.client.call(
        "memory.retrieve",
        {"query": "deployment checklist item", "limit": 5, "scope_filter": ["session"]},
    )

    results = list(retrieved.get("results") or [])
    assert len(results) == 1
    assert results[0].get("chunk_id") == session_entry["chunk_id"]
    assert results[0].get("scope") == "session"


@pytest.mark.asyncio
async def test_contract_memory_retrieve_auto_widens_into_archive(
    contract_harness: ContractHarness,
) -> None:
    stored = await ingest_memory_via_ingress(
        contract_harness.client,
        source_type="external",
        source_id="archive-ranked",
        collection="external_web",
        content="Archived nebula status note from a stale web snapshot.",
    )
    db_path = contract_harness.config.data_dir / "memory_entries" / "memory.sqlite3"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE retrieval_records SET created_at = ? WHERE chunk_id = ?",
            ("2025-01-01T00:00:00+00:00", str(stored.get("chunk_id", ""))),
        )

    retrieved = await contract_harness.client.call(
        "memory.retrieve",
        {"query": "nebula status note", "limit": 5},
    )

    assert retrieved.get("include_archived") is True
    results = list(retrieved.get("results") or [])
    assert len(results) == 1
    assert results[0].get("archived") is True
    assert results[0].get("stale") is True
    assert results[0].get("verification_gap") is True


@pytest.mark.asyncio
async def test_contract_memory_retrieve_marks_conflicting_results(
    contract_harness: ContractHarness,
) -> None:
    positive = await ingest_memory_via_ingress(
        contract_harness.client,
        source_type="external",
        source_id="conflict-positive",
        collection="external_web",
        content="Favorite color is blue for this profile note.",
    )
    negative = await ingest_memory_via_ingress(
        contract_harness.client,
        source_type="external",
        source_id="conflict-negative",
        collection="external_web",
        content="Favorite color is not blue for this profile note.",
    )

    retrieved = await contract_harness.client.call(
        "memory.retrieve",
        {"query": "favorite color blue", "limit": 5},
    )

    results = list(retrieved.get("results") or [])
    assert {item.get("chunk_id") for item in results} == {
        positive["chunk_id"],
        negative["chunk_id"],
    }
    assert all(item.get("conflict") is True for item in results)


@pytest.mark.asyncio
async def test_contract_memory_write_round_trips_through_ingress_context_handle(
    contract_harness: ContractHarness,
) -> None:
    minted = await _mint_memory_ingress_context(
        contract_harness.client,
        content="prefers structured write paths",
    )

    created = await contract_harness.client.call(
        "memory.write",
        {
            "ingress_context": minted["ingress_context"],
            "entry_type": "fact",
            "key": "profile.write_path",
            "value": "prefers structured write paths",
        },
    )

    assert created.get("kind") == "allow"
    entry = created.get("entry") or {}
    entry_id = str(entry.get("id", "")).strip()
    assert entry_id
    assert entry.get("ingress_handle_id") == minted["ingress_context"]
    assert entry.get("source_origin") == "user_direct"
    assert entry.get("channel_trust") == "command"
    assert entry.get("confirmation_status") == "user_asserted"

    fetched = await contract_harness.client.call("memory.get", {"entry_id": entry_id})
    stored = fetched.get("entry") or {}
    assert stored.get("key") == "profile.write_path"
    assert stored.get("value") == "prefers structured write paths"
    assert stored.get("content_digest") == minted["content_digest"]


@pytest.mark.asyncio
async def test_contract_memory_write_rejects_mismatched_handle_digest_and_trust_fields(
    contract_harness: ContractHarness,
) -> None:
    minted = await _mint_memory_ingress_context(
        contract_harness.client,
        content="handle-bound memory payload",
    )

    with pytest.raises(JsonRpcCallError, match="content digest does not match ingress context"):
        await contract_harness.client.call(
            "memory.write",
            {
                "ingress_context": minted["ingress_context"],
                "entry_type": "fact",
                "key": "profile.invalid",
                "value": "handle-bound memory payload",
                "content_digest": "0" * 64,
            },
        )

    with pytest.raises(JsonRpcCallError) as excinfo:
        await contract_harness.client.call(
            "memory.write",
            {
                "ingress_context": minted["ingress_context"],
                "entry_type": "fact",
                "key": "profile.invalid",
                "value": "handle-bound memory payload",
                "source_origin": "user_direct",
            },
        )

    assert excinfo.value.code == -32602


@pytest.mark.asyncio
async def test_contract_note_create_and_search_executes_without_lockdown(
    contract_harness: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness.client)

    created = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "add a note: remember to buy groceries"},
    )
    assert created.get("lockdown_level") == "normal"
    assert int(created.get("blocked_actions", 0)) == 0
    assert int(created.get("confirmation_required_actions", 0)) == 0
    assert int(created.get("executed_actions", 0)) == 1
    created_outputs = _extract_tool_outputs(created)
    assert "note.create" in created_outputs
    created_payload = created_outputs["note.create"][0]
    assert created_payload.get("ok") is True
    assert created_payload.get("kind") == "allow"

    searched = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "search my notes for groceries"},
    )
    assert searched.get("lockdown_level") == "normal"
    assert int(searched.get("blocked_actions", 0)) == 0
    assert int(searched.get("confirmation_required_actions", 0)) == 0
    assert int(searched.get("executed_actions", 0)) == 1
    search_outputs = _extract_tool_outputs(searched)
    assert "note.search" in search_outputs
    search_payload = search_outputs["note.search"][0]
    assert search_payload.get("ok") is True
    assert int(search_payload.get("count", 0)) >= 1
    assert any(
        "groceries" in json.dumps(item, ensure_ascii=True).lower()
        for item in search_payload["entries"]
    )

    sid_later = await _create_session(contract_harness.client)
    recalled = await contract_harness.client.call(
        "session.message",
        {"session_id": sid_later, "content": "what did I ask you to remember about groceries?"},
    )
    assert recalled.get("lockdown_level") == "normal"
    assert int(recalled.get("blocked_actions", 0)) == 0
    assert int(recalled.get("confirmation_required_actions", 0)) == 0
    assert "groceries" in str(recalled.get("response", "")).lower()


@pytest.mark.asyncio
async def test_contract_note_create_persists_ingress_metadata_on_readback(
    contract_harness: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness.client)

    created = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "add a note: remember to buy groceries"},
    )
    created_outputs = _extract_tool_outputs(created)
    created_payload = created_outputs["note.create"][0]
    entry = created_payload.get("entry") or {}
    entry_id = str(entry.get("id", "")).strip()

    assert entry_id

    fetched = await contract_harness.client.call("note.get", {"entry_id": entry_id})
    stored = fetched.get("entry") or {}

    assert str(stored.get("ingress_handle_id", "")).strip()
    assert stored.get("source_origin") == "user_direct"
    assert stored.get("channel_trust") == "command"
    assert stored.get("confirmation_status") == "user_asserted"


@pytest.mark.asyncio
async def test_contract_todo_create_list_and_complete_executes_without_lockdown(
    contract_harness: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness.client)

    created = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "add todo: buy milk"},
    )
    assert created.get("lockdown_level") == "normal"
    assert int(created.get("blocked_actions", 0)) == 0
    assert int(created.get("confirmation_required_actions", 0)) == 0
    assert int(created.get("executed_actions", 0)) == 1
    created_outputs = _extract_tool_outputs(created)
    assert "todo.create" in created_outputs
    created_payload = created_outputs["todo.create"][0]
    assert created_payload.get("ok") is True
    assert created_payload.get("kind") == "allow"

    listed = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "list my todos"},
    )
    assert listed.get("lockdown_level") == "normal"
    assert int(listed.get("executed_actions", 0)) == 1
    list_outputs = _extract_tool_outputs(listed)
    assert "todo.list" in list_outputs
    list_payload = list_outputs["todo.list"][0]
    assert list_payload.get("ok") is True
    assert any(
        "buy milk" in json.dumps(item, ensure_ascii=True).lower()
        for item in list_payload["entries"]
    )

    completed = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "mark the buy milk todo complete"},
    )
    assert completed.get("lockdown_level") == "normal"
    assert int(completed.get("blocked_actions", 0)) == 0
    assert int(completed.get("confirmation_required_actions", 0)) == 0
    assert int(completed.get("executed_actions", 0)) == 1
    complete_outputs = _extract_tool_outputs(completed)
    assert "todo.complete" in complete_outputs
    complete_payload = complete_outputs["todo.complete"][0]
    assert complete_payload.get("ok") is True
    assert complete_payload.get("completed") is True
    entry = complete_payload.get("entry") or {}
    value = entry.get("value") if isinstance(entry, dict) else {}
    assert isinstance(value, dict)
    assert value.get("status") == "done"


@pytest.mark.asyncio
async def test_contract_memory_write_rejects_caller_supplied_trust_fields(
    contract_harness: ContractHarness,
) -> None:
    minted = await _mint_memory_ingress_context(
        contract_harness.client,
        content="blue",
    )

    with pytest.raises(RuntimeError, match=r"RPC error -32602"):
        await contract_harness.client.call(
            "memory.write",
            {
                "ingress_context": minted["ingress_context"],
                "entry_type": "fact",
                "key": "profile.color",
                "value": "blue",
                "source_origin": "user_direct",
                "channel_trust": "command",
                "confirmation_status": "user_asserted",
                "scope": "user",
            },
        )


@pytest.mark.asyncio
async def test_contract_persona_fact_write_rejects_workflow_state(
    contract_harness: ContractHarness,
) -> None:
    result = await _write_memory_via_ingress(
        contract_harness.client,
        entry_type="persona_fact",
        key="persona:timezone",
        value="UTC",
        workflow_state="active",
    )

    assert result.get("kind") == "reject"
    assert result.get("reason") == "workflow_state_requires_active_agenda_entry_type"


@pytest.mark.asyncio
async def test_contract_open_thread_defaults_workflow_state_and_emits_init_audit(
    contract_harness: ContractHarness,
) -> None:
    created = await _write_memory_via_ingress(
        contract_harness.client,
        entry_type="open_thread",
        key="thread:vendor-followup",
        value="follow up with vendor tomorrow",
    )

    assert created.get("kind") == "allow"
    entry = created.get("entry") or {}
    entry_id = str(entry.get("id", "")).strip()

    assert entry_id
    assert entry.get("workflow_state") == "active"
    assert entry.get("status") == "active"

    db_path = contract_harness.config.data_dir / "memory_entries" / "memory.sqlite3"
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT event_type, metadata_json
            FROM memory_events
            WHERE entry_id = ?
            ORDER BY timestamp ASC, rowid ASC
            """,
            (entry_id,),
        ).fetchall()

    assert [str(row[0]) for row in rows] == ["created", "workflow_state_changed"]
    transition = json.loads(str(rows[-1][1]))
    assert transition.get("from") is None
    assert transition.get("to") == "active"
    assert transition.get("status") == "active"


@pytest.mark.asyncio
async def test_contract_quarantine_cycle_preserves_open_thread_workflow_state(
    contract_harness: ContractHarness,
) -> None:
    created = await _write_memory_via_ingress(
        contract_harness.client,
        entry_type="open_thread",
        key="thread:customer-response",
        value="waiting on customer response",
        workflow_state="waiting",
    )

    assert created.get("kind") == "allow"
    entry = created.get("entry") or {}
    entry_id = str(entry.get("id", "")).strip()

    assert entry_id
    assert entry.get("workflow_state") == "waiting"
    assert entry.get("status") == "active"

    quarantined = await contract_harness.client.call(
        "memory.quarantine",
        {"entry_id": entry_id, "reason": "manual-review"},
    )
    assert quarantined.get("changed") is True

    hidden = await contract_harness.client.call("memory.get", {"entry_id": entry_id})
    assert hidden.get("entry") is None

    quarantined_view = await contract_harness.client.call(
        "memory.get",
        {"entry_id": entry_id, "include_quarantined": True, "confirmed": True},
    )
    quarantined_entry = quarantined_view.get("entry") or {}
    assert quarantined_entry.get("workflow_state") == "waiting"
    assert quarantined_entry.get("status") == "quarantined"

    restored = await contract_harness.client.call(
        "memory.unquarantine",
        {"entry_id": entry_id, "reason": "review-cleared"},
    )
    assert restored.get("changed") is True

    restored_view = await contract_harness.client.call("memory.get", {"entry_id": entry_id})
    restored_entry = restored_view.get("entry") or {}
    assert restored_entry.get("workflow_state") == "waiting"
    assert restored_entry.get("status") == "active"


@pytest.mark.asyncio
async def test_contract_set_workflow_state_keeps_status_active(
    contract_harness: ContractHarness,
) -> None:
    created = await _write_memory_via_ingress(
        contract_harness.client,
        entry_type="open_thread",
        key="thread:closeable",
        value="close this thread later",
    )

    assert created.get("kind") == "allow"
    entry = created.get("entry") or {}
    entry_id = str(entry.get("id", "")).strip()

    assert entry_id

    updated = await contract_harness.client.call(
        "memory.set_workflow_state",
        {"entry_id": entry_id, "workflow_state": "closed"},
    )
    assert updated.get("changed") is True
    assert updated.get("workflow_state") == "closed"

    fetched = await contract_harness.client.call("memory.get", {"entry_id": entry_id})
    stored = fetched.get("entry") or {}

    assert stored.get("workflow_state") == "closed"
    assert stored.get("status") == "active"

    db_path = contract_harness.config.data_dir / "memory_entries" / "memory.sqlite3"
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT metadata_json
            FROM memory_events
            WHERE entry_id = ? AND event_type = 'workflow_state_changed'
            ORDER BY timestamp DESC, rowid DESC
            LIMIT 1
            """,
            (entry_id,),
        ).fetchone()

    assert row is not None
    transition = json.loads(str(row[0]))
    assert transition.get("from") == "active"
    assert transition.get("to") == "closed"
    assert transition.get("status") == "active"


@pytest.mark.asyncio
async def test_contract_pending_review_entries_are_isolated_to_review_queue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded: dict[str, str] = {}

    def _seed(config: DaemonConfig) -> None:
        manager = MemoryManager(config.data_dir / "memory_entries")
        decision = manager.write_with_provenance(
            entry_type="note",
            key="note:queue",
            value="Needs operator review",
            source=MemorySource(origin="external", source_id="msg-5", extraction_method="extract"),
            source_origin="external_message",
            channel_trust="shared_participant",
            confirmation_status="pending_review",
            source_id="msg-5",
            scope="user",
            confidence=0.41,
            confirmation_satisfied=True,
        )
        assert decision.entry is not None
        seeded["entry_id"] = decision.entry.id
        retrieval = IngestionPipeline(config.data_dir / "memory_entries").ingest(
            source_id="msg-5-recall",
            source_type="external",
            content="Needs operator review",
            source_origin="external_message",
            channel_trust="shared_participant",
            confirmation_status="pending_review",
            scope="user",
        )
        seeded["chunk_id"] = retrieval.chunk_id

    async with _contract_harness_context(tmp_path, monkeypatch, prestart=_seed) as harness:
        entry_id = seeded["entry_id"]
        chunk_id = seeded["chunk_id"]

        listing = await harness.client.call("memory.list", {"limit": 10})
        listed_ids = {
            str(item.get("id") or item.get("entry_id") or "").strip()
            for item in listing.get("entries", [])
            if isinstance(item, dict)
        }
        assert entry_id not in listed_ids

        fetched = await harness.client.call("memory.get", {"entry_id": entry_id})
        assert fetched.get("entry") is None

        retrieved = await harness.client.call(
            "memory.retrieve",
            {"query": "operator review", "limit": 10},
        )
        retrieved_ids = {
            str(item.get("chunk_id") or "").strip()
            for item in retrieved.get("results", [])
            if isinstance(item, dict)
        }
        assert chunk_id not in retrieved_ids

        review_queue = await harness.client.call("memory.list_review_queue", {"limit": 10})
        queued_ids = {
            str(item.get("id") or item.get("entry_id") or "").strip()
            for item in review_queue.get("entries", [])
            if isinstance(item, dict)
        }
        assert entry_id in queued_ids


@pytest.mark.asyncio
async def test_contract_cli_planner_context_filters_identity_and_active_attention(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_inputs: list[str] = []

    def _seed(config: DaemonConfig) -> None:
        manager = MemoryManager(config.data_dir / "memory_entries")
        trusted_identity = manager.write_with_provenance(
            entry_type="persona_fact",
            key="persona:timezone",
            value="Timezone is UTC.",
            source=MemorySource(
                origin="user",
                source_id="identity-trusted",
                extraction_method="manual",
            ),
            source_origin="user_direct",
            channel_trust="command",
            confirmation_status="user_asserted",
            source_id="identity-trusted",
            scope="user",
            confidence=0.9,
            confirmation_satisfied=True,
        )
        leaked_external = manager.write_with_provenance(
            entry_type="persona_fact",
            key="persona:leak-external",
            value="This external persona fact should not enter Identity.",
            source=MemorySource(
                origin="external",
                source_id="identity-external",
                extraction_method="manual",
            ),
            source_origin="external_message",
            channel_trust="shared_participant",
            confirmation_status="auto_accepted",
            source_id="identity-external",
            scope="user",
            confidence=0.4,
            confirmation_satisfied=True,
        )
        leaked_tool = manager.write_with_provenance(
            entry_type="persona_fact",
            key="persona:leak-tool",
            value="This tool-derived persona fact should not enter Identity.",
            source=MemorySource(
                origin="project_doc",
                source_id="identity-tool",
                extraction_method="tool.output",
            ),
            source_origin="tool_output",
            channel_trust="tool_passed",
            confirmation_status="pep_approved",
            source_id="identity-tool",
            scope="user",
            confidence=0.4,
            confirmation_satisfied=True,
        )
        leaked_consolidation = manager.write_with_provenance(
            entry_type="persona_fact",
            key="persona:leak-consolidation",
            value="This consolidation-derived persona fact should not enter Identity.",
            source=MemorySource(
                origin="inferred",
                source_id="identity-consolidation",
                extraction_method="consolidation",
            ),
            source_origin="consolidation_derived",
            channel_trust="consolidation",
            confirmation_status="auto_accepted",
            source_id="identity-consolidation",
            scope="user",
            confidence=0.4,
            confirmation_satisfied=True,
        )
        pending_review_identity = manager.write_with_provenance(
            entry_type="persona_fact",
            key="persona:pending-review",
            value="Pending-review persona fact should not enter Identity.",
            source=MemorySource(
                origin="external",
                source_id="identity-pending-review",
                extraction_method="manual",
            ),
            source_origin="external_message",
            channel_trust="shared_participant",
            confirmation_status="pending_review",
            source_id="identity-pending-review",
            scope="user",
            confidence=0.4,
            confirmation_satisfied=True,
        )
        owner_observed_attention = manager.write_with_provenance(
            entry_type="waiting_on",
            key="thread:owner-observed",
            value="Owner-observed channel follow-up should surface in CLI attention.",
            source=MemorySource(
                origin="user",
                source_id="attention-owner-observed",
                extraction_method="manual",
            ),
            source_origin="user_direct",
            channel_trust="owner_observed",
            confirmation_status="auto_accepted",
            source_id="attention-owner-observed",
            scope="channel",
            workflow_state="waiting",
            confidence=0.5,
            confirmation_satisfied=True,
        )
        cli_inbox = manager.write_with_provenance(
            entry_type="inbox_item",
            key=inbox_item_key(owner_id="owner-1", item_id="msg-general"),
            value=InboxItemValue(
                owner_id="owner-1",
                sender_id="guest-1",
                channel_id="discord:guild/general",
                body="Shared inbox item should surface in CLI attention.",
            ).model_dump(mode="python"),
            source=MemorySource(
                origin="external",
                source_id="attention-inbox",
                extraction_method="channel.ingest.structured",
            ),
            source_origin="external_message",
            channel_trust="shared_participant",
            confirmation_status="auto_accepted",
            source_id="attention-inbox",
            scope="user",
            confidence=0.5,
            confirmation_satisfied=True,
        )
        shared_noise = manager.write_with_provenance(
            entry_type="open_thread",
            key="thread:shared-noise",
            value="Shared-participant channel noise should stay out of CLI attention.",
            source=MemorySource(
                origin="external",
                source_id="attention-shared",
                extraction_method="manual",
            ),
            source_origin="external_message",
            channel_trust="shared_participant",
            confirmation_status="auto_accepted",
            source_id="attention-shared",
            scope="channel",
            workflow_state="active",
            confidence=0.5,
            confirmation_satisfied=True,
        )
        incoming_noise = manager.write_with_provenance(
            entry_type="open_thread",
            key="thread:incoming-noise",
            value="External incoming channel noise should stay out of CLI attention.",
            source=MemorySource(
                origin="external",
                source_id="attention-incoming",
                extraction_method="manual",
            ),
            source_origin="external_message",
            channel_trust="external_incoming",
            confirmation_status="auto_accepted",
            source_id="attention-incoming",
            scope="channel",
            workflow_state="active",
            confidence=0.5,
            confirmation_satisfied=True,
        )
        pending_review_attention = manager.write_with_provenance(
            entry_type="open_thread",
            key="thread:pending-review",
            value="Pending-review agenda item should stay out of active attention.",
            source=MemorySource(
                origin="external",
                source_id="attention-pending-review",
                extraction_method="manual",
            ),
            source_origin="external_message",
            channel_trust="shared_participant",
            confirmation_status="pending_review",
            source_id="attention-pending-review",
            scope="session",
            workflow_state="active",
            confidence=0.5,
            confirmation_satisfied=True,
        )
        closed_thread = manager.write_with_provenance(
            entry_type="open_thread",
            key="thread:closed",
            value="Closed agenda item should be excluded from active attention.",
            source=MemorySource(
                origin="user",
                source_id="attention-closed",
                extraction_method="manual",
            ),
            source_origin="user_direct",
            channel_trust="command",
            confirmation_status="user_asserted",
            source_id="attention-closed",
            scope="session",
            workflow_state="closed",
            confidence=0.5,
            confirmation_satisfied=True,
        )
        assert all(
            decision.kind == "allow"
            for decision in (
                trusted_identity,
                leaked_external,
                leaked_tool,
                leaked_consolidation,
                pending_review_identity,
                owner_observed_attention,
                cli_inbox,
                shared_noise,
                incoming_noise,
                pending_review_attention,
                closed_thread,
            )
        )

    async with _contract_harness_context(tmp_path, monkeypatch, prestart=_seed) as harness:

        async def _capture_complete(
            self: LocalPlannerProvider,
            messages: list[Message],
            tools: list[dict[str, Any]] | None = None,
        ) -> ProviderResponse:
            if messages:
                captured_inputs.append(str(messages[-1].content))
            return await _stub_complete(self, messages, tools)

        monkeypatch.setattr(LocalPlannerProvider, "complete", _capture_complete, raising=True)
        sid = await _create_session(harness.client)
        reply = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "hello"},
        )
        assert str(reply.get("response", "")).strip()

    planner_input = _latest_user_request_planner_input(captured_inputs)
    normalized_planner_input = planner_input.replace("^", "")
    trusted_section = normalized_planner_input.split("=== USER REQUEST ===", 1)[0]

    assert "identity_total=1" in trusted_section
    assert "persona:timezone" in trusted_section
    assert "persona:leak-external" not in trusted_section
    assert "persona:leak-tool" not in trusted_section
    assert "persona:leak-consolidation" not in trusted_section
    assert "persona:pending-review" not in trusted_section

    assert "thread:owner-observed" in trusted_section
    assert "inbox:owner-1:msg-general" in trusted_section
    assert "thread:shared-noise" not in trusted_section
    assert "thread:incoming-noise" not in trusted_section
    assert "thread:pending-review" not in trusted_section
    assert "thread:closed" not in trusted_section

    owner_attention_text = "Owner-observed channel follow-up should surface in CLI attention."
    inbox_attention_text = "Shared inbox item should surface in CLI attention."
    assert owner_attention_text in normalized_planner_input
    assert inbox_attention_text in normalized_planner_input
    assert owner_attention_text not in trusted_section
    assert inbox_attention_text not in trusted_section
    assert (
        "Shared-participant channel noise should stay out of CLI attention."
        not in normalized_planner_input
    )
    assert "External incoming channel noise should stay out of CLI attention." not in (
        normalized_planner_input
    )
    assert "Closed agenda item should be excluded from active attention." not in (
        normalized_planner_input
    )


@pytest.mark.asyncio
async def test_contract_discord_channel_context_binds_active_attention_to_current_channel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_inputs: list[str] = []

    def _seed(config: DaemonConfig) -> None:
        config.channel_identity_allowlist = {"discord": ["guest-1"]}
        manager = MemoryManager(config.data_dir / "memory_entries")
        current_channel_inbox = manager.write_with_provenance(
            entry_type="inbox_item",
            key=inbox_item_key(owner_id="owner-1", item_id="current"),
            value=InboxItemValue(
                owner_id="owner-1",
                sender_id="guest-1",
                channel_id=compose_channel_binding(
                    channel="discord",
                    workspace_hint="guild-1",
                    channel_id="chan-1",
                ),
                body="Current channel inbox item should surface.",
            ).model_dump(mode="python"),
            source=MemorySource(
                origin="external",
                source_id="discord-current",
                extraction_method="channel.ingest.structured",
            ),
            source_origin="external_message",
            channel_trust="shared_participant",
            confirmation_status="auto_accepted",
            source_id="discord-current",
            scope="user",
            confidence=0.5,
            confirmation_satisfied=True,
        )
        other_channel_inbox = manager.write_with_provenance(
            entry_type="inbox_item",
            key=inbox_item_key(owner_id="owner-1", item_id="other"),
            value=InboxItemValue(
                owner_id="owner-1",
                sender_id="guest-2",
                channel_id=compose_channel_binding(
                    channel="discord",
                    workspace_hint="guild-1",
                    channel_id="chan-2",
                ),
                body="Other channel inbox item should not surface.",
            ).model_dump(mode="python"),
            source=MemorySource(
                origin="external",
                source_id="discord-other",
                extraction_method="channel.ingest.structured",
            ),
            source_origin="external_message",
            channel_trust="shared_participant",
            confirmation_status="auto_accepted",
            source_id="discord-other",
            scope="user",
            confidence=0.5,
            confirmation_satisfied=True,
        )
        assert current_channel_inbox.kind == "allow"
        assert other_channel_inbox.kind == "allow"

    async with _contract_harness_context(tmp_path, monkeypatch, prestart=_seed) as harness:

        async def _capture_complete(
            self: LocalPlannerProvider,
            messages: list[Message],
            tools: list[dict[str, Any]] | None = None,
        ) -> ProviderResponse:
            if messages:
                captured_inputs.append(str(messages[-1].content))
            return await _stub_complete(self, messages, tools)

        monkeypatch.setattr(LocalPlannerProvider, "complete", _capture_complete, raising=True)
        reply = await harness.client.call(
            "channel.ingest",
            {
                "message": {
                    "channel": "discord",
                    "external_user_id": "guest-1",
                    "workspace_hint": "guild-1",
                    "reply_target": "chan-1",
                    "message_id": "msg-live-discord",
                    "content": "hello",
                }
            },
        )
        assert str(reply.get("response", "")).strip()

    planner_input = _latest_user_request_planner_input(captured_inputs).replace("^", "")
    trusted_section = planner_input.split("=== USER REQUEST ===", 1)[0]

    assert "inbox:owner-1:current" in trusted_section
    assert "inbox:owner-1:other" not in trusted_section
    assert "Current channel inbox item should surface." in planner_input
    assert "Other channel inbox item should not surface." not in planner_input


@pytest.mark.asyncio
async def test_contract_identity_candidate_cli_surface_and_accept_flow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded: dict[str, str] = {}

    def _seed(config: DaemonConfig) -> None:
        manager = MemoryManager(config.data_dir / "memory_entries")
        decision = manager.write_with_provenance(
            entry_type="preference",
            key="preference:tea",
            value="I prefer tea over coffee.",
            predicate="likes(tea)",
            source=MemorySource(
                origin="external",
                source_id="candidate-identity-1",
                extraction_method="identity.candidate",
            ),
            source_origin="external_message",
            channel_trust="shared_participant",
            confirmation_status="pending_review",
            source_id="candidate-identity-1",
            scope="user",
            confidence=0.62,
            confirmation_satisfied=True,
        )
        assert decision.entry is not None
        seeded["candidate_id"] = decision.entry.id

    async with _contract_harness_context(tmp_path, monkeypatch, prestart=_seed) as harness:
        candidate_id = seeded["candidate_id"]
        sid = await _create_session(harness.client)

        surfaced = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "hello"},
        )
        assert candidate_id in str(surfaced.get("response", ""))
        assert "/identity accept" in str(surfaced.get("response", ""))

        accepted = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": f"/identity accept {candidate_id}"},
        )
        assert "Remembered identity candidate" in str(accepted.get("response", ""))

        review_queue = await harness.client.call("memory.list_review_queue", {"limit": 10})
        queued_ids = {
            str(item.get("id") or item.get("entry_id") or "").strip()
            for item in review_queue.get("entries", [])
            if isinstance(item, dict)
        }
        assert candidate_id not in queued_ids

        listing = await harness.client.call("memory.list", {"limit": 20})
        promoted = next(
            (
                item
                for item in listing.get("entries", [])
                if isinstance(item, dict)
                and str(item.get("entry_type", "")) == "preference"
                and str(item.get("key", "")) == "preference:tea"
                and str(item.get("confirmation_status", "")) == "user_confirmed"
            ),
            None,
        )
        assert isinstance(promoted, dict)


@pytest.mark.asyncio
async def test_contract_identity_candidate_reject_emits_backoff_and_closes_queue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded: dict[str, str] = {}

    def _seed(config: DaemonConfig) -> None:
        manager = MemoryManager(config.data_dir / "memory_entries")
        decision = manager.write_with_provenance(
            entry_type="preference",
            key="preference:tea",
            value="I prefer tea over coffee.",
            predicate="likes(tea)",
            source=MemorySource(
                origin="external",
                source_id="candidate-identity-reject",
                extraction_method="identity.candidate",
            ),
            source_origin="external_message",
            channel_trust="shared_participant",
            confirmation_status="pending_review",
            source_id="candidate-identity-reject",
            scope="user",
            confidence=0.62,
            confirmation_satisfied=True,
        )
        assert decision.entry is not None
        seeded["candidate_id"] = decision.entry.id

    async with _contract_harness_context(tmp_path, monkeypatch, prestart=_seed) as harness:
        candidate_id = seeded["candidate_id"]
        sid = await _create_session(harness.client)

        surfaced = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "hello"},
        )
        assert candidate_id in str(surfaced.get("response", ""))

        rejected = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": f"/identity reject {candidate_id}"},
        )
        assert "Rejected identity candidate" in str(rejected.get("response", ""))

        review_queue = await harness.client.call("memory.list_review_queue", {"limit": 10})
        queued_ids = {
            str(item.get("id") or item.get("entry_id") or "").strip()
            for item in review_queue.get("entries", [])
            if isinstance(item, dict)
        }
        assert candidate_id not in queued_ids

        db_path = harness.config.data_dir / "memory_entries" / "memory.sqlite3"
        with sqlite3.connect(db_path) as conn:
            rejected_row = conn.execute(
                """
                SELECT metadata_json
                FROM memory_events
                WHERE entry_id = ? AND event_type = 'candidate_rejected'
                ORDER BY timestamp DESC, rowid DESC
                LIMIT 1
                """,
                (candidate_id,),
            ).fetchone()

        assert rejected_row is not None
        rejected_meta = json.loads(str(rejected_row[0]))
        assert rejected_meta.get("backoff_key") == "likes(tea)"


@pytest.mark.asyncio
async def test_contract_identity_candidate_silence_expires_without_rejection_signal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded: dict[str, str] = {}

    def _seed(config: DaemonConfig) -> None:
        manager = MemoryManager(config.data_dir / "memory_entries")
        decision = manager.write_with_provenance(
            entry_type="preference",
            key="preference:tea",
            value="I prefer tea over coffee.",
            predicate="likes(tea)",
            source=MemorySource(
                origin="external",
                source_id="candidate-identity-2",
                extraction_method="identity.candidate",
            ),
            source_origin="external_message",
            channel_trust="shared_participant",
            confirmation_status="pending_review",
            source_id="candidate-identity-2",
            scope="user",
            confidence=0.62,
            confirmation_satisfied=True,
        )
        assert decision.entry is not None
        seeded["candidate_id"] = decision.entry.id

    async with _contract_harness_context(tmp_path, monkeypatch, prestart=_seed) as harness:
        candidate_id = seeded["candidate_id"]
        sid = await _create_session(harness.client)

        first = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "hello"},
        )
        second = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "hello again"},
        )
        third = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "still there?"},
        )

        assert candidate_id in str(first.get("response", ""))
        assert candidate_id in str(second.get("response", ""))
        assert candidate_id not in str(third.get("response", ""))

        review_queue = await harness.client.call("memory.list_review_queue", {"limit": 10})
        queued_ids = {
            str(item.get("id") or item.get("entry_id") or "").strip()
            for item in review_queue.get("entries", [])
            if isinstance(item, dict)
        }
        assert candidate_id not in queued_ids

        db_path = harness.config.data_dir / "memory_entries" / "memory.sqlite3"
        with sqlite3.connect(db_path) as conn:
            expired = conn.execute(
                """
                SELECT COUNT(*)
                FROM memory_events
                WHERE entry_id = ? AND event_type = 'candidate_expired'
                """,
                (candidate_id,),
            ).fetchone()
            rejected = conn.execute(
                """
                SELECT COUNT(*)
                FROM memory_events
                WHERE entry_id = ? AND event_type = 'candidate_rejected'
                """,
                (candidate_id,),
            ).fetchone()

        assert expired is not None and int(expired[0]) == 1
        assert rejected is not None and int(rejected[0]) == 0


@pytest.mark.asyncio
async def test_contract_trust_matrix_rows_round_trip_with_expected_bands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded: dict[str, tuple[str, str, str, float, str]] = {}
    invalid_rejection_count = 0

    def _seed(config: DaemonConfig) -> None:
        nonlocal invalid_rejection_count
        manager = MemoryManager(config.data_dir / "memory_entries")

        for idx, ((source_origin, channel_trust, confirmation_status), rule) in enumerate(
            _VALID_TRUST_MATRIX.items()
        ):
            requested_confidence = (
                float(rule.default_confidence) if rule.default_confidence is not None else 0.42
            )
            decision = manager.write_with_provenance(
                entry_type="fact",
                key=f"trust.matrix.{idx}",
                value=f"matrix row {idx}",
                source=MemorySource(
                    origin=legacy_source_view_origin(source_origin),
                    source_id=f"matrix-row-{idx}",
                    extraction_method="behavioral.matrix",
                ),
                source_origin=source_origin,
                channel_trust=channel_trust,
                confirmation_status=confirmation_status,
                source_id=f"matrix-row-{idx}",
                scope="user",
                confidence=requested_confidence,
                confirmation_satisfied=True,
            )
            assert decision.kind == "allow"
            assert decision.entry is not None
            seeded[decision.entry.id] = (
                source_origin,
                channel_trust,
                confirmation_status,
                requested_confidence,
                "untrusted" if rule.trust_band == "observed" else rule.trust_band,
            )

        for source_origin, channel_trust, confirmation_status in product(
            SOURCE_ORIGIN_VALUES,
            CHANNEL_TRUST_VALUES,
            CONFIRMATION_STATUS_VALUES,
        ):
            triple = (source_origin, channel_trust, confirmation_status)
            if confirmation_status == "pending_review":
                continue
            if triple in _VALID_TRUST_MATRIX:
                continue
            invalid_rejection_count += 1
            with pytest.raises(TrustGateViolation):
                manager.write_with_provenance(
                    entry_type="fact",
                    key=f"invalid.matrix.{invalid_rejection_count}",
                    value="invalid triple",
                    source=MemorySource(
                        origin=legacy_source_view_origin(source_origin),
                        source_id=f"invalid-row-{invalid_rejection_count}",
                        extraction_method="behavioral.matrix.invalid",
                    ),
                    source_origin=source_origin,
                    channel_trust=channel_trust,
                    confirmation_status=confirmation_status,
                    source_id=f"invalid-row-{invalid_rejection_count}",
                    scope="user",
                    confidence=0.42,
                    confirmation_satisfied=True,
                )

    async with _contract_harness_context(tmp_path, monkeypatch, prestart=_seed) as harness:
        assert len(seeded) == len(_VALID_TRUST_MATRIX)
        assert invalid_rejection_count > 0

        listing = await harness.client.call("memory.list", {"limit": len(seeded) + 10})
        listed_ids = {
            str(item.get("id") or item.get("entry_id") or "").strip()
            for item in listing.get("entries", [])
            if isinstance(item, dict)
        }
        assert set(seeded).issubset(listed_ids)

        for entry_id, (
            source_origin,
            channel_trust,
            confirmation_status,
            expected_confidence,
            expected_band,
        ) in seeded.items():
            fetched = await harness.client.call("memory.get", {"entry_id": entry_id})
            entry = fetched.get("entry") or {}

            assert entry.get("source_origin") == source_origin
            assert entry.get("channel_trust") == channel_trust
            assert entry.get("confirmation_status") == confirmation_status
            assert (
                derive_trust_band(
                    str(entry.get("source_origin", "")),
                    str(entry.get("channel_trust", "")),
                    str(entry.get("confirmation_status", "")),
                )
                == expected_band
            )
            assert float(entry.get("confidence", 0.0)) == pytest.approx(expected_confidence)


@pytest.mark.asyncio
async def test_contract_legacy_v06_entries_backfill_on_daemon_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created_at = "2026-04-22T09:00:00+00:00"

    def _seed(config: DaemonConfig) -> None:
        storage = config.data_dir / "memory_entries"
        storage.mkdir(parents=True, exist_ok=True)
        payloads = [
            {
                "id": "legacy-user-verified",
                "entry_type": "fact",
                "key": "profile.name",
                "value": "alice",
                "source": {
                    "origin": "user",
                    "source_id": "msg-legacy-user",
                    "extraction_method": "manual",
                },
                "created_at": created_at,
                "user_verified": True,
            },
            {
                "id": "legacy-context-episode",
                "entry_type": "context",
                "key": "legacy.context.episode",
                "value": "2026-04-22 design review meeting with Alice",
                "source": {
                    "origin": "external",
                    "source_id": "doc-legacy-episode",
                    "extraction_method": "extract",
                },
                "created_at": created_at,
            },
            {
                "id": "legacy-context-note",
                "entry_type": "context",
                "key": "legacy.context.note",
                "value": "Blue notebook lives on the top shelf",
                "source": {
                    "origin": "external",
                    "source_id": "doc-legacy-note",
                    "extraction_method": "extract",
                },
                "created_at": created_at,
            },
            {
                "id": "legacy-user-confirmed",
                "entry_type": "fact",
                "key": "profile.city",
                "value": "Berlin",
                "source": {
                    "origin": "user",
                    "source_id": "approval-1",
                    "extraction_method": "agent_confirmed",
                },
                "created_at": created_at,
            },
            {
                "id": "legacy-inferred",
                "entry_type": "fact",
                "key": "profile.preference",
                "value": "likes coffee",
                "source": {
                    "origin": "inferred",
                    "source_id": "infer-1",
                    "extraction_method": "summarize",
                },
                "created_at": created_at,
            },
            {
                "id": "legacy-deleted",
                "entry_type": "fact",
                "key": "profile.deleted",
                "value": "gone",
                "source": {
                    "origin": "external",
                    "source_id": "doc-legacy-deleted",
                    "extraction_method": "extract",
                },
                "created_at": created_at,
                "deleted_at": created_at,
            },
        ]
        for payload in payloads:
            (storage / f"{payload['id']}.json").write_text(json.dumps(payload), encoding="utf-8")

    async with _contract_harness_context(tmp_path, monkeypatch, prestart=_seed) as harness:
        legacy_user = await harness.client.call("memory.get", {"entry_id": "legacy-user-verified"})
        user_entry = legacy_user.get("entry") or {}
        assert user_entry.get("scope") == "user"
        assert user_entry.get("source_origin") == "user_direct"
        assert user_entry.get("channel_trust") == "command"
        assert user_entry.get("confirmation_status") == "auto_accepted"
        assert (
            derive_trust_band(
                str(user_entry.get("source_origin", "")),
                str(user_entry.get("channel_trust", "")),
                str(user_entry.get("confirmation_status", "")),
            )
            == "untrusted"
        )
        assert str(user_entry.get("last_verified_at", "")).startswith("2026-04-22T09:00:00")

        legacy_episode = await harness.client.call(
            "memory.get",
            {"entry_id": "legacy-context-episode"},
        )
        assert (legacy_episode.get("entry") or {}).get("entry_type") == "episode"

        legacy_note = await harness.client.call("memory.get", {"entry_id": "legacy-context-note"})
        assert (legacy_note.get("entry") or {}).get("entry_type") == "note"

        legacy_user_confirmed = await harness.client.call(
            "memory.get",
            {"entry_id": "legacy-user-confirmed"},
        )
        user_confirmed_entry = legacy_user_confirmed.get("entry") or {}
        assert user_confirmed_entry.get("source_origin") == "user_confirmed"
        assert user_confirmed_entry.get("channel_trust") == "command"
        assert user_confirmed_entry.get("confirmation_status") == "auto_accepted"

        legacy_inferred = await harness.client.call("memory.get", {"entry_id": "legacy-inferred"})
        inferred_entry = legacy_inferred.get("entry") or {}
        assert inferred_entry.get("source_origin") == "consolidation_derived"
        assert inferred_entry.get("channel_trust") == "consolidation"
        assert inferred_entry.get("confirmation_status") == "auto_accepted"

        default_list = await harness.client.call("memory.list", {"limit": 20})
        default_ids = {
            str(item.get("id") or item.get("entry_id") or "").strip()
            for item in default_list.get("entries", [])
            if isinstance(item, dict)
        }
        assert "legacy-deleted" not in default_ids

        hidden_deleted = await harness.client.call("memory.get", {"entry_id": "legacy-deleted"})
        assert hidden_deleted.get("entry") is None

        visible_deleted = await harness.client.call(
            "memory.get",
            {"entry_id": "legacy-deleted", "include_deleted": True},
        )
        deleted_entry = visible_deleted.get("entry") or {}
        assert deleted_entry.get("status") == "tombstoned"
        assert deleted_entry.get("source_origin") == "external_web"
        assert deleted_entry.get("channel_trust") == "web_passed"
        assert deleted_entry.get("confirmation_status") == "auto_accepted"

        for entry in (user_entry, user_confirmed_entry, inferred_entry, deleted_entry):
            assert (
                derive_trust_band(
                    str(entry.get("source_origin", "")),
                    str(entry.get("channel_trust", "")),
                    str(entry.get("confirmation_status", "")),
                )
                == "untrusted"
            )


@pytest.mark.asyncio
async def test_contract_memory_write_clamps_confidence_to_trust_cap(
    contract_harness: ContractHarness,
) -> None:
    result = await _write_memory_via_ingress(
        contract_harness.client,
        entry_type="fact",
        key="profile.color",
        value="blue",
        confidence=0.99,
    )

    assert result.get("kind") == "allow"
    entry = result.get("entry") or {}
    assert float(entry.get("confidence", 0.0)) == pytest.approx(0.95)


@pytest.mark.asyncio
async def test_contract_user_authored_skill_write_sets_invocation_eligible(
    contract_harness: ContractHarness,
) -> None:
    result = await _write_memory_via_ingress(
        contract_harness.client,
        entry_type="skill",
        key="skill:demo",
        value="demo skill contents",
        invocation_eligible=True,
    )

    assert result.get("kind") == "allow"
    entry = result.get("entry") or {}
    assert entry.get("invocation_eligible") is True
    assert entry.get("source_origin") == "user_direct"
    assert entry.get("channel_trust") == "command"
    assert entry.get("confirmation_status") == "user_asserted"


@pytest.mark.asyncio
async def test_contract_memory_read_original_is_explicit_and_audited(
    contract_harness: ContractHarness,
) -> None:
    original = "Original evidence payload marker m4-read-original."
    minted = await _mint_memory_ingress_context(
        contract_harness.client,
        content=original,
        source_type="external",
        source_id="evidence-doc-1",
    )
    stored = await contract_harness.client.call(
        "memory.ingest",
        {
            "ingress_context": minted["ingress_context"],
            "content": original,
            "collection": "external_web",
        },
    )
    chunk_id = str(stored.get("chunk_id", "")).strip()
    assert chunk_id

    retrieved = await contract_harness.client.call(
        "memory.retrieve",
        {"query": "m4-read-original", "limit": 5},
    )
    results = list(retrieved.get("results") or [])
    matching = next(item for item in results if str(item.get("chunk_id", "")).strip() == chunk_id)
    assert "content" not in matching
    assert "original_content" not in matching

    reread = await contract_harness.client.call(
        "memory.read_original",
        {"chunk_id": chunk_id},
    )
    assert reread.get("found") is True
    assert reread.get("content") == original

    event = await _wait_for_audit_event(
        contract_harness.client,
        event_type="MemoryEvidenceRead",
        predicate=lambda item: str(item.get("data", {}).get("chunk_id", "")).strip() == chunk_id,
    )
    assert event.get("data", {}).get("caller_context", {}).get("method") == "memory.read_original"


@pytest.mark.asyncio
async def test_contract_skill_command_invokes_without_confirmation_and_emits_audit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded: dict[str, str] = {}

    def _seed(config: DaemonConfig) -> None:
        manager = MemoryManager(config.data_dir / "memory_entries")
        decision = manager.write_with_provenance(
            entry_type="skill",
            key="skill:release-close",
            value="Release close checklist\nRun the behavioral bundle before release.",
            source=MemorySource(
                origin="user",
                source_id="skill-command-1",
                extraction_method="manual",
            ),
            source_origin="user_direct",
            channel_trust="command",
            confirmation_status="user_asserted",
            source_id="skill-command-1",
            scope="user",
            confidence=0.95,
            confirmation_satisfied=True,
            invocation_eligible=True,
        )
        assert decision.entry is not None
        seeded["skill_id"] = decision.entry.id

    async with _contract_harness_context(tmp_path, monkeypatch, prestart=_seed) as harness:
        sid = await _create_session(harness.client)
        skill_id = seeded["skill_id"]

        invoked = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": f"/skill {skill_id}"},
        )
        assert "Loaded skill" in str(invoked.get("response", ""))
        assert "Release close checklist" in str(invoked.get("response", ""))

        pending = await harness.client.call(
            "action.pending",
            {"status": "pending", "limit": 10},
        )
        assert int(pending.get("count", 0)) == 0

        event = await _wait_for_audit_event(
            harness.client,
            event_type="MemorySkillInvoked",
            predicate=lambda item: (
                str(item.get("data", {}).get("skill_id", "")).strip() == skill_id
                and bool(item.get("data", {}).get("invoked", False))
            ),
        )
        assert event.get("data", {}).get("caller_context", {}).get("command") == "/skill"


@pytest.mark.asyncio
async def test_contract_skills_browse_search_and_info_surface_invocable_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded: dict[str, str] = {}

    def _seed(config: DaemonConfig) -> None:
        manager = MemoryManager(config.data_dir / "memory_entries")
        release = manager.write_with_provenance(
            entry_type="skill",
            key="skill:release-close",
            value="Release close checklist\nRun the behavioral bundle before release.",
            source=MemorySource(
                origin="user",
                source_id="skill-browse-1",
                extraction_method="manual",
            ),
            source_origin="user_direct",
            channel_trust="command",
            confirmation_status="user_asserted",
            source_id="skill-browse-1",
            scope="user",
            confidence=0.95,
            confirmation_satisfied=True,
            invocation_eligible=True,
        )
        hidden = manager.write_with_provenance(
            entry_type="skill",
            key="skill:draft-only",
            value="Draft-only skill\nThis should not be invocable yet.",
            source=MemorySource(
                origin="user",
                source_id="skill-browse-2",
                extraction_method="manual",
            ),
            source_origin="user_direct",
            channel_trust="command",
            confirmation_status="user_asserted",
            source_id="skill-browse-2",
            scope="user",
            confidence=0.95,
            confirmation_satisfied=True,
            invocation_eligible=False,
        )
        assert release.entry is not None
        assert hidden.entry is not None
        seeded["release_id"] = release.entry.id
        seeded["hidden_id"] = hidden.entry.id

    async with _contract_harness_context(tmp_path, monkeypatch, prestart=_seed) as harness:
        sid = await _create_session(harness.client)
        release_id = seeded["release_id"]
        hidden_id = seeded["hidden_id"]

        listed = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "/skills"},
        )
        assert release_id in str(listed.get("response", ""))
        assert "release-close" in str(listed.get("response", ""))
        assert hidden_id not in str(listed.get("response", ""))

        searched = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "/skills search behavioral"},
        )
        assert release_id in str(searched.get("response", ""))
        assert "behavioral bundle" in str(searched.get("response", ""))

        preview = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": f"/skill info {release_id}"},
        )
        assert "Trust band: elevated" in str(preview.get("response", ""))
        assert "Source origin: user_direct" in str(preview.get("response", ""))
        assert "Release close checklist" in str(preview.get("response", ""))


@pytest.mark.asyncio
async def test_contract_untrusted_but_invocable_tool_skill_stays_out_of_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded: dict[str, str] = {}

    def _seed(config: DaemonConfig) -> None:
        manager = MemoryManager(config.data_dir / "memory_entries")
        decision = manager.write_with_provenance(
            entry_type="skill",
            key="skill:tool-release-close",
            value="Tool-installed release-close skill",
            source=MemorySource(
                origin="external",
                source_id="tool-skill-1",
                extraction_method="tool",
            ),
            source_origin="tool_output",
            channel_trust="tool_passed",
            confirmation_status="pep_approved",
            source_id="tool-skill-1",
            scope="user",
            confidence=0.70,
            confirmation_satisfied=True,
            invocation_eligible=True,
        )
        assert decision.entry is not None
        seeded["skill_id"] = decision.entry.id

    async with _contract_harness_context(tmp_path, monkeypatch, prestart=_seed) as harness:
        skill_id = seeded["skill_id"]

        invoked = await harness.client.call(
            "memory.invoke_skill",
            {"skill_id": skill_id},
        )
        assert invoked.get("found") is True
        assert invoked.get("invoked") is True
        artifact = invoked.get("artifact") or {}
        assert artifact.get("trust_band") == "untrusted"

        manager = MemoryManager(harness.config.data_dir / "memory_entries")
        identity_ids = {entry.id for entry in manager.compile_identity(max_tokens=128).entries}
        assert skill_id not in identity_ids


@pytest.mark.asyncio
async def test_contract_skill_suggestion_waits_for_explicit_user_yes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded: dict[str, str] = {}

    def _seed(config: DaemonConfig) -> None:
        manager = MemoryManager(config.data_dir / "memory_entries")
        decision = manager.write_with_provenance(
            entry_type="skill",
            key="skill:release-close",
            value="Release close checklist\nRun the behavioral bundle before release.",
            source=MemorySource(
                origin="user",
                source_id="skill-suggest-1",
                extraction_method="manual",
            ),
            source_origin="user_direct",
            channel_trust="command",
            confirmation_status="user_asserted",
            source_id="skill-suggest-1",
            scope="user",
            confidence=0.95,
            confirmation_satisfied=True,
            invocation_eligible=True,
        )
        assert decision.entry is not None
        seeded["skill_id"] = decision.entry.id

    async with _contract_harness_context(tmp_path, monkeypatch, prestart=_seed) as harness:
        sid = await _create_session(harness.client)
        skill_id = seeded["skill_id"]

        proposed = await harness.client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "Can you use the release-close skill for this task?",
            },
        )
        assert "Reply yes to load it" in str(proposed.get("response", ""))
        assert f"/skill {skill_id}" in str(proposed.get("response", ""))

        manager = MemoryManager(harness.config.data_dir / "memory_entries")
        before = manager.get_entry(skill_id)
        assert before is not None
        assert before.citation_count == 0

        approved = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "yes"},
        )
        assert "Loaded skill" in str(approved.get("response", ""))
        assert "Release close checklist" in str(approved.get("response", ""))

        manager = MemoryManager(harness.config.data_dir / "memory_entries")
        after = manager.get_entry(skill_id)
        assert after is not None
        assert after.citation_count == 1


@pytest.mark.asyncio
async def test_contract_pending_review_skill_requires_promotion_before_invocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded: dict[str, str] = {}

    def _seed(config: DaemonConfig) -> None:
        manager = MemoryManager(config.data_dir / "memory_entries")
        current = manager.write_with_provenance(
            entry_type="skill",
            key="skill:release-close",
            value="Release close checklist\nCurrent version",
            source=MemorySource(
                origin="user",
                source_id="skill-promote-1",
                extraction_method="manual",
            ),
            source_origin="user_direct",
            channel_trust="command",
            confirmation_status="user_asserted",
            source_id="skill-promote-1",
            scope="user",
            confidence=0.95,
            confirmation_satisfied=True,
            invocation_eligible=True,
        )
        candidate = manager.write_with_provenance(
            entry_type="skill",
            key="skill:release-close",
            value="Release close checklist\nCandidate version",
            source=MemorySource(
                origin="external",
                source_id="skill-promote-2",
                extraction_method="review.queue",
            ),
            source_origin="external_message",
            channel_trust="shared_participant",
            confirmation_status="pending_review",
            source_id="skill-promote-2",
            scope="user",
            confidence=0.62,
            confirmation_satisfied=True,
        )
        assert current.entry is not None
        assert candidate.entry is not None
        seeded["current_id"] = current.entry.id
        seeded["candidate_id"] = candidate.entry.id
        seeded["candidate_value"] = str(candidate.entry.value)

    async with _contract_harness_context(tmp_path, monkeypatch, prestart=_seed) as harness:
        sid = await _create_session(harness.client)
        candidate_id = seeded["candidate_id"]

        preview = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": f"/skill info {candidate_id}"},
        )
        assert "pending_review" in str(preview.get("response", ""))
        assert "Current version" in str(preview.get("response", ""))
        assert "Candidate version" in str(preview.get("response", ""))

        blocked = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": f"/skill {candidate_id}"},
        )
        assert "is not invocable" in str(blocked.get("response", ""))

        minted = await _mint_memory_ingress_context(
            harness.client,
            content=seeded["candidate_value"],
            source_type="user",
        )
        promoted = await harness.client.call(
            "memory.promote_to_skill",
            {
                "ingress_context": minted["ingress_context"],
                "entry_id": candidate_id,
            },
        )
        assert promoted.get("kind") == "allow"
        entry = promoted.get("entry") or {}
        promoted_id = str(entry.get("id", "")).strip()
        assert promoted_id
        assert entry.get("invocation_eligible") is True

        review_queue = await harness.client.call("memory.list_review_queue", {"limit": 10})
        queued_ids = {
            str(item.get("id") or item.get("entry_id") or "").strip()
            for item in review_queue.get("entries", [])
            if isinstance(item, dict)
        }
        assert candidate_id not in queued_ids

        invoked = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": f"/skill {promoted_id}"},
        )
        assert "Loaded skill" in str(invoked.get("response", ""))
        assert "Candidate version" in str(invoked.get("response", ""))


@pytest.mark.asyncio
async def test_contract_quarantined_promotion_rpcs_fail_closed_without_binding_oracle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded: dict[str, str] = {}

    def _seed(config: DaemonConfig) -> None:
        manager = MemoryManager(config.data_dir / "memory_entries")
        identity = manager.write_with_provenance(
            entry_type="preference",
            key="preference:tea",
            value="I prefer tea over coffee.",
            predicate="likes(tea)",
            source=MemorySource(
                origin="external",
                source_id="candidate-oracle-1",
                extraction_method="identity.candidate",
            ),
            source_origin="external_message",
            channel_trust="shared_participant",
            confirmation_status="pending_review",
            source_id="candidate-oracle-1",
            scope="user",
            confidence=0.62,
            confirmation_satisfied=True,
        )
        skill = manager.write_with_provenance(
            entry_type="skill",
            key="skill:release-close",
            value="Release close checklist\nQuarantined candidate",
            source=MemorySource(
                origin="external",
                source_id="skill-oracle-1",
                extraction_method="review.queue",
            ),
            source_origin="external_message",
            channel_trust="shared_participant",
            confirmation_status="pending_review",
            source_id="skill-oracle-1",
            scope="user",
            confidence=0.62,
            confirmation_satisfied=True,
        )
        assert identity.entry is not None
        assert skill.entry is not None
        assert manager.quarantine(identity.entry.id, reason="test_quarantine")
        assert manager.quarantine(skill.entry.id, reason="test_quarantine")
        seeded["identity_id"] = identity.entry.id
        seeded["skill_id"] = skill.entry.id

    async with _contract_harness_context(tmp_path, monkeypatch, prestart=_seed) as harness:
        minted = await _mint_memory_ingress_context(
            harness.client,
            content="mismatched quarantined promotion payload",
            source_type="user",
        )

        rejected_identity = await harness.client.call(
            "memory.promote_identity_candidate",
            {
                "ingress_context": minted["ingress_context"],
                "candidate_id": seeded["identity_id"],
            },
        )
        assert rejected_identity.get("kind") == "reject"
        assert rejected_identity.get("reason") == "candidate_not_found"
        assert rejected_identity.get("entry") is None

        rejected_skill = await harness.client.call(
            "memory.promote_to_skill",
            {
                "ingress_context": minted["ingress_context"],
                "entry_id": seeded["skill_id"],
            },
        )
        assert rejected_skill.get("kind") == "reject"
        assert rejected_skill.get("reason") == "skill_not_found"
        assert rejected_skill.get("entry") is None


@pytest.mark.asyncio
async def test_contract_graph_query_export_and_consolidation_run_via_control_api(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded: dict[str, str] = {}

    def _seed(config: DaemonConfig) -> None:
        manager = MemoryManager(config.data_dir / "memory_entries")

        def _write(
            *,
            entry_type: str,
            key: str,
            value: str,
            source_id: str,
            source_origin: str = "user_direct",
            channel_trust: str = "command",
            confirmation_status: str = "user_asserted",
            confidence: float = 0.95,
            scope: str = "user",
        ) -> str:
            source_origin_kind = "user"
            if source_origin.startswith("external_"):
                source_origin_kind = "external"
            elif source_origin == "consolidation_derived":
                source_origin_kind = "inferred"
            decision = manager.write_with_provenance(
                entry_type=entry_type,
                key=key,
                value=value,
                source=MemorySource(
                    origin=source_origin_kind,
                    source_id=source_id,
                    extraction_method="manual",
                ),
                source_origin=source_origin,  # type: ignore[arg-type]
                channel_trust=channel_trust,  # type: ignore[arg-type]
                confirmation_status=confirmation_status,  # type: ignore[arg-type]
                source_id=source_id,
                scope=scope,
                confidence=confidence,
                confirmation_satisfied=True,
            )
            assert decision.entry is not None
            return decision.entry.id

        _write(
            entry_type="fact",
            key="project:shisad",
            value="Shisad uses MemoryPack recall for release planning.",
            source_id="graph-live-1",
        )
        _write(
            entry_type="fact",
            key="component:memorypack",
            value="MemoryPack recall supports Shisad release workflows.",
            source_id="graph-live-2",
        )
        _write(
            entry_type="fact",
            key="project:shisad-derived",
            value="Shisad and MemoryPack appeared together in a derived summary.",
            source_id="graph-live-derived",
            source_origin="consolidation_derived",
            channel_trust="consolidation",
            confirmation_status="auto_accepted",
            confidence=0.40,
        )
        seeded["channel_distractor_id"] = _write(
            entry_type="fact",
            key="project:shisad-channel-distractor",
            value="Shisad channel-only distractor should not enter the default graph.",
            source_id="graph-live-channel-distractor",
            scope="channel",
        )
        seeded["target_id"] = _write(
            entry_type="persona_fact",
            key="work:acme",
            value="I work at ACME as VP Eng.",
            source_id="strong-live-target",
        )
        seeded["signal_id"] = _write(
            entry_type="episode",
            key="episode:left-acme",
            value="I no longer work at ACME.",
            source_id="strong-live-signal",
            source_origin="user_direct",
            channel_trust="owner_observed",
            confirmation_status="auto_accepted",
            confidence=0.30,
        )
        for index, value in enumerate(
            [
                "I like ramen for lunch.",
                "I prefer ramen when traveling.",
                "Ramen is my favorite comfort food.",
            ],
            start=1,
        ):
            _write(
                entry_type="episode",
                key=f"episode:ramen-{index}",
                value=value,
                source_id=f"ramen-live-{index}",
                source_origin="user_direct",
                channel_trust="owner_observed",
                confirmation_status="auto_accepted",
                confidence=0.30,
            )

    async with _contract_harness_context(tmp_path, monkeypatch, prestart=_seed) as harness:
        graph = await harness.client.call(
            "graph.query",
            {"entity": "Shisad", "depth": 1, "limit": 10},
        )
        assert graph.get("root_entity_id")
        assert graph.get("nodes")
        assert any(node.get("evidence_entry_ids") for node in graph.get("nodes", []))
        assert graph.get("edges")
        root_node = next(
            node
            for node in graph.get("nodes", [])
            if isinstance(node, dict) and node.get("entity_id") == graph.get("root_entity_id")
        )
        assert root_node.get("source_origin") == "mixed"
        assert root_node.get("trust_band") == "untrusted"
        graph_evidence_ids = {
            str(evidence_id)
            for collection_name in ("nodes", "edges")
            for item in graph.get(collection_name, [])
            if isinstance(item, dict)
            for evidence_id in item.get("evidence_entry_ids", [])
        }
        assert seeded["channel_distractor_id"] not in graph_evidence_ids
        assert any(
            isinstance(edge, dict)
            and edge.get("source_origin") == "mixed"
            and edge.get("trust_band") == "untrusted"
            for edge in graph.get("edges", [])
        )

        exported = await harness.client.call("graph.export", {"format": "md"})
        assert exported.get("format") == "md"
        assert "Derived Knowledge Graph" in str(exported.get("data", ""))
        assert "Evidence" in str(exported.get("data", ""))

        consolidated = await harness.client.call("memory.consolidate", {})
        assert consolidated.get("identity_candidate_count") == 1
        assert consolidated.get("strong_invalidation_count") == 1
        assert consolidated.get("capability_scope", {}).get("network") is False
        assert consolidated.get("capability_scope", {}).get("tool_recursion") is False

        review_queue = await harness.client.call("memory.list_review_queue", {"limit": 10})
        predicates = {
            str(item.get("predicate", "")).strip()
            for item in review_queue.get("entries", [])
            if isinstance(item, dict)
        }
        assert "prefers(ramen)" in predicates

        sid = await _create_session(harness.client)
        surfaced = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "hello"},
        )
        assert "Memory update candidate" in str(surfaced.get("response", ""))
        assert "Reply yes to update this memory" in str(surfaced.get("response", ""))

        accepted = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "yes"},
        )
        assert "Updated memory" in str(accepted.get("response", ""))

        reconsolidated = await harness.client.call("memory.consolidate", {})
        assert reconsolidated.get("strong_invalidation_count") == 0

        listing = await harness.client.call("memory.list", {"limit": 20})
        promoted = next(
            (
                item
                for item in listing.get("entries", [])
                if isinstance(item, dict)
                and str(item.get("entry_type", "")) == "persona_fact"
                and str(item.get("key", "")) == "work:acme"
                and str(item.get("confirmation_status", "")) == "user_confirmed"
            ),
            None,
        )
        assert isinstance(promoted, dict)
        assert promoted.get("value") == "I no longer work at ACME."
        assert promoted.get("supersedes") == seeded["target_id"]
        assert promoted.get("source_id") == f"strong-invalidation:{seeded['signal_id']}"
        assert str(promoted.get("ingress_handle_id", "")).strip()


@pytest.mark.asyncio
async def test_contract_reminder_create_executes_and_due_run_delivers_without_lockdown(
    contract_harness: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness.client)

    created = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "remind me to check email in 1 second"},
    )
    assert created.get("lockdown_level") == "normal"
    assert int(created.get("blocked_actions", 0)) == 0
    assert int(created.get("confirmation_required_actions", 0)) == 0
    assert int(created.get("executed_actions", 0)) == 1
    outputs = _extract_tool_outputs(created)
    assert "reminder.create" in outputs
    payload = outputs["reminder.create"][0]
    assert payload.get("ok") is True
    reminder = payload.get("task") or {}
    task_id = str(reminder.get("id", "")).strip()
    assert task_id

    task_triggered = await _wait_for_audit_event(
        contract_harness.client,
        event_type="TaskTriggered",
        predicate=lambda event: str(event.get("data", {}).get("task_id", "")) == task_id,
        timeout=5.0,
    )
    background_sid = str(task_triggered.get("session_id", "")).strip()
    assert background_sid

    await _wait_for_audit_event(
        contract_harness.client,
        event_type="ToolExecuted",
        session_id=background_sid,
        predicate=lambda event: (
            str(event.get("data", {}).get("tool_name", "")) == "message.send"
            and bool(event.get("data", {}).get("success")) is True
        ),
        timeout=5.0,
    )

    reminders = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "list my reminders"},
    )
    reminder_outputs = _extract_tool_outputs(reminders)
    assert "reminder.list" in reminder_outputs
    reminder_list_payload = reminder_outputs["reminder.list"][0]
    assert reminder_list_payload.get("ok") is True
    assert any(
        str(item.get("id", "")) == task_id for item in reminder_list_payload.get("tasks", [])
    )


@pytest.mark.asyncio
async def test_contract_multi_tool_executes_both_tools_in_one_turn(
    contract_harness: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness.client)
    reply = await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": "read the README and search for related projects",
        },
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 2
    response_text = str(reply.get("response", ""))
    assert "[[TOOL_OUTPUT_BEGIN" not in response_text
    assert "[[TOOL_OUTPUT_END]]" not in response_text
    assert "=== TOOL OUTPUTS (UNTRUSTED DATA) ===" not in response_text
    outputs = _extract_tool_outputs(reply)
    assert "fs.read" in outputs
    assert "web.search" in outputs


@pytest.mark.asyncio
async def test_contract_web_fetch_routes_to_confirmation_not_lockdown(
    contract_harness: ContractHarness,
) -> None:
    """web.fetch is a side-effect action that requires confirmation, not lockdown."""
    sid = await _create_session(contract_harness.client)
    fetch_url = f"{contract_harness.web_search_backend_url}/page"
    reply = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": f"fetch the URL {fetch_url}"},
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    # web.fetch is confirmation-gated (side_effect_action), not blocked
    assert int(reply.get("confirmation_required_actions", 0)) >= 1


@pytest.mark.asyncio
async def test_contract_browser_navigate_executes_and_returns_page(
    contract_harness: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness.client)
    reply = await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": f"browser navigate {contract_harness.browser_base_url}/browser",
        },
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    outputs = _extract_tool_outputs(reply)
    assert "browser.navigate" in outputs
    payload = outputs["browser.navigate"][0]
    assert payload.get("ok") is True
    assert payload.get("title") == "Browser Home"


@pytest.mark.asyncio
async def test_contract_browser_click_routes_to_confirmation_not_lockdown(
    contract_harness: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness.client)
    await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": f"browser navigate {contract_harness.browser_base_url}/browser",
        },
    )
    reply = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "browser click the continue button in the browser"},
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) >= 1
    pending_ids = reply.get("pending_confirmation_ids")
    assert isinstance(pending_ids, list)
    assert pending_ids
    pending = await contract_harness.client.call(
        "action.pending",
        {"confirmation_id": str(pending_ids[0])},
    )
    actions = pending.get("actions", [])
    assert actions
    arguments = dict(actions[0].get("arguments", {}))
    assert arguments.get("resolved_target") == "#continue"
    assert str(arguments.get("destination", "")).endswith("/browser-next")
    assert str(arguments.get("source_url", "")).endswith("/browser")
    assert str(arguments.get("source_binding", "")).strip()


@pytest.mark.asyncio
async def test_contract_browser_click_confirmation_approve_executes_after_confirmation(
    contract_harness: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness.client)
    await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": f"browser navigate {contract_harness.browser_base_url}/browser",
        },
    )
    proposed = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "browser click the continue button in the browser"},
    )
    assert proposed.get("lockdown_level") == "normal"
    pending_ids = proposed.get("pending_confirmation_ids")
    assert isinstance(pending_ids, list)
    assert pending_ids

    confirmed = await _confirm_pending_action(contract_harness.client, str(pending_ids[0]))
    assert confirmed.get("confirmed") is True
    await _wait_for_audit_event(
        contract_harness.client,
        event_type="ToolExecuted",
        session_id=sid,
        predicate=lambda event: (
            str(event.get("data", {}).get("tool_name", "")) == "browser.click"
            and bool(event.get("data", {}).get("success")) is True
        ),
    )


@pytest.mark.asyncio
async def test_contract_action_pending_cli_defaults_and_purge_terminal_rows(
    contract_harness: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness.client)
    await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": f"browser navigate {contract_harness.browser_base_url}/browser",
        },
    )
    first = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "browser click the continue button in the browser"},
    )
    first_ids = first.get("pending_confirmation_ids")
    assert isinstance(first_ids, list)
    assert first_ids
    rejected_id = str(first_ids[0])
    rejected = await _reject_pending_action(contract_harness.client, rejected_id)
    assert rejected.get("rejected") is True

    second = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "browser click the continue button in the browser"},
    )
    second_ids = second.get("pending_confirmation_ids")
    assert isinstance(second_ids, list)
    assert second_ids
    pending_id = str(second_ids[0])
    assert pending_id != rejected_id

    default_pending = await _run_contract_cli(contract_harness.config, "action", "pending")
    assert default_pending.returncode == 0, default_pending.stderr or default_pending.stdout
    assert pending_id in default_pending.stdout
    assert rejected_id not in default_pending.stdout

    all_pending = await _run_contract_cli(
        contract_harness.config,
        "action",
        "pending",
        "--status",
        "all",
    )
    assert all_pending.returncode == 0, all_pending.stderr or all_pending.stdout
    assert pending_id in all_pending.stdout
    assert rejected_id in all_pending.stdout

    dry_run = await _run_contract_cli(contract_harness.config, "action", "purge", "--dry-run")
    assert dry_run.returncode == 0, dry_run.stderr or dry_run.stdout
    assert "Would purge 1 pending action row(s)" in dry_run.stdout
    assert rejected_id in dry_run.stdout

    after_dry_run = await contract_harness.client.call(
        "action.pending",
        {"confirmation_id": rejected_id},
    )
    assert after_dry_run["count"] == 1

    purged = await _run_contract_cli(contract_harness.config, "action", "purge")
    assert purged.returncode == 0, purged.stderr or purged.stdout
    assert "Purged 1 pending action row(s)" in purged.stdout
    assert rejected_id in purged.stdout

    after_purge = await _run_contract_cli(
        contract_harness.config,
        "action",
        "pending",
        "--status",
        "all",
    )
    assert after_purge.returncode == 0, after_purge.stderr or after_purge.stdout
    assert pending_id in after_purge.stdout
    assert rejected_id not in after_purge.stdout


@pytest.mark.asyncio
async def test_contract_browser_read_page_executes_and_returns_page(
    contract_harness: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness.client)
    await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": f"browser navigate {contract_harness.browser_base_url}/browser",
        },
    )
    reply = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "browser read page"},
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    outputs = _extract_tool_outputs(reply)
    assert "browser.read_page" in outputs
    payload = outputs["browser.read_page"][0]
    assert payload.get("ok") is True
    assert payload.get("title") == "Browser Home"
    assert "Hello browser" in str(payload.get("content", ""))


@pytest.mark.asyncio
async def test_contract_browser_screenshot_executes_and_returns_artifact(
    contract_harness: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness.client)
    await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": f"browser navigate {contract_harness.browser_base_url}/browser",
        },
    )
    reply = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "browser screenshot"},
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    outputs = _extract_tool_outputs(reply)
    assert "browser.screenshot" in outputs
    payload = outputs["browser.screenshot"][0]
    assert payload.get("ok") is True
    assert str(payload.get("screenshot_id", "")).strip()
    assert str(payload.get("path", "")).strip()
    assert payload.get("taint_labels") == ["untrusted"]


@pytest.mark.asyncio
async def test_contract_browser_type_text_routes_to_confirmation_not_lockdown(
    contract_harness: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness.client)
    await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": f"browser navigate {contract_harness.browser_base_url}/browser-form",
        },
    )
    reply = await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": "browser type hello into the name field and submit",
        },
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) >= 1
    pending_ids = reply.get("pending_confirmation_ids")
    assert isinstance(pending_ids, list)
    assert pending_ids
    pending = await contract_harness.client.call(
        "action.pending",
        {"confirmation_id": str(pending_ids[0])},
    )
    actions = pending.get("actions", [])
    assert actions
    arguments = dict(actions[0].get("arguments", {}))
    assert arguments.get("resolved_target", arguments.get("target")) == "#name"
    assert str(arguments.get("destination", "")).endswith("/browser-submitted")
    assert str(arguments.get("source_url", "")).endswith("/browser-form")
    assert str(arguments.get("source_binding", "")).strip()


@pytest.mark.asyncio
async def test_contract_browser_type_text_confirmation_approve_executes_after_confirmation(
    contract_harness: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness.client)
    await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": f"browser navigate {contract_harness.browser_base_url}/browser-form",
        },
    )
    proposed = await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": "browser type hello into the name field and submit",
        },
    )
    assert proposed.get("lockdown_level") == "normal"
    pending_ids = proposed.get("pending_confirmation_ids")
    assert isinstance(pending_ids, list)
    assert pending_ids

    confirmed = await _confirm_pending_action(contract_harness.client, str(pending_ids[0]))
    assert confirmed.get("confirmed") is True
    await _wait_for_audit_event(
        contract_harness.client,
        event_type="ToolExecuted",
        session_id=sid,
        predicate=lambda event: (
            str(event.get("data", {}).get("tool_name", "")) == "browser.type_text"
            and bool(event.get("data", {}).get("success")) is True
        ),
    )
    reread = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "browser read page"},
    )
    outputs = _extract_tool_outputs(reread)
    assert "browser.read_page" in outputs
    payload = outputs["browser.read_page"][0]
    assert "Submitted: hello" in str(payload.get("content", ""))


@pytest.mark.asyncio
async def test_contract_browser_end_session_executes_without_lockdown(
    contract_harness: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness.client)
    await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": f"browser navigate {contract_harness.browser_base_url}/browser",
        },
    )
    reply = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "end the browser session"},
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    outputs = _extract_tool_outputs(reply)
    assert "browser.end_session" in outputs
    payload = outputs["browser.end_session"][0]
    assert payload.get("ok") is True
    assert payload.get("closed") is True


@pytest.mark.asyncio
async def test_contract_git_status_executes_and_returns_output(
    contract_harness: ContractHarness,
) -> None:
    ws = contract_harness.workspace_root
    subprocess.run(["git", "init", str(ws)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(ws), "commit", "--allow-empty", "-m", "init"],
        check=True,
        capture_output=True,
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "test",
            "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_NAME": "test",
            "GIT_COMMITTER_EMAIL": "t@t",
        },
    )
    sid = await _create_session(contract_harness.client)
    reply = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "show me the git status"},
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    outputs = _extract_tool_outputs(reply)
    assert "git.status" in outputs
    payload = outputs["git.status"][0]
    assert payload.get("ok") is True


@pytest.mark.asyncio
async def test_contract_git_log_executes_and_returns_entries(
    contract_harness: ContractHarness,
) -> None:
    ws = contract_harness.workspace_root
    subprocess.run(["git", "init", str(ws)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(ws), "commit", "--allow-empty", "-m", "init"],
        check=True,
        capture_output=True,
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "test",
            "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_NAME": "test",
            "GIT_COMMITTER_EMAIL": "t@t",
        },
    )
    sid = await _create_session(contract_harness.client)
    reply = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "show me the git log"},
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    outputs = _extract_tool_outputs(reply)
    assert "git.log" in outputs
    payload = outputs["git.log"][0]
    assert payload.get("ok") is True


@pytest.mark.asyncio
async def test_contract_git_diff_executes_and_returns_output(
    contract_harness: ContractHarness,
) -> None:
    ws = contract_harness.workspace_root
    subprocess.run(["git", "init", str(ws)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(ws), "commit", "--allow-empty", "-m", "init"],
        check=True,
        capture_output=True,
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "test",
            "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_NAME": "test",
            "GIT_COMMITTER_EMAIL": "t@t",
        },
    )
    (ws / "README.md").write_text("behavioral-readme-updated\n", encoding="utf-8")
    sid = await _create_session(contract_harness.client)
    reply = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "show me the git diff"},
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    outputs = _extract_tool_outputs(reply)
    assert "git.diff" in outputs
    payload = outputs["git.diff"][0]
    assert payload.get("ok") is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("content", "expected_tool", "mutate_workspace"),
    [
        ("git status", "git.status", False),
        ("git log", "git.log", False),
        ("git diff", "git.diff", True),
    ],
)
async def test_contract_bare_git_commands_execute_without_confirmation(
    contract_harness: ContractHarness,
    content: str,
    expected_tool: str,
    mutate_workspace: bool,
) -> None:
    ws = contract_harness.workspace_root
    subprocess.run(["git", "init", str(ws)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(ws), "commit", "--allow-empty", "-m", "init"],
        check=True,
        capture_output=True,
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "test",
            "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_NAME": "test",
            "GIT_COMMITTER_EMAIL": "t@t",
        },
    )
    if mutate_workspace:
        (ws / "README.md").write_text("behavioral-readme-updated\n", encoding="utf-8")

    sid = await _create_session(contract_harness.client)
    reply = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": content},
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    outputs = _extract_tool_outputs(reply)
    assert expected_tool in outputs
    payload = outputs[expected_tool][0]
    assert payload.get("ok") is True


@pytest.mark.asyncio
async def test_contract_cli_fs_write_executes_without_confirmation_or_lockdown(
    contract_harness: ContractHarness,
) -> None:
    """Trusted CLI keeps clean local writes frictionless."""
    sid = await _create_session(contract_harness.client)
    reply = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "write a file called test-output.txt"},
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    outputs = _extract_tool_outputs(reply)
    assert "fs.write" in outputs
    payload = outputs["fs.write"][0]
    assert payload.get("ok") is True
    target = contract_harness.workspace_root / "test-output.txt"
    assert target.read_text(encoding="utf-8") == "hello from behavioral test"


@pytest.mark.asyncio
async def test_contract_non_cli_fs_write_routes_to_confirmation_not_lockdown(
    contract_harness: ContractHarness,
) -> None:
    """Non-CLI writes still route to confirmation instead of lockdown."""
    sid = await _create_session(contract_harness.client, channel="matrix")
    reply = await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "channel": "matrix",
            "user_id": "alice",
            "workspace_id": "ws1",
            "content": "write a file called test-output.txt",
        },
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) >= 1
    pending_ids = reply.get("pending_confirmation_ids")
    assert isinstance(pending_ids, list)
    assert pending_ids
    response = str(reply.get("response", ""))
    assert "[PENDING CONFIRMATIONS]" in response
    assert f"shisad action confirm {pending_ids[0]}" in response
    assert "shisad action pending" in response
    assert "ACTION CONFIRMATION" in response
    assert "I can proceed after confirmation" not in response


@pytest.mark.asyncio
async def test_contract_web_fetch_confirmation_approve_executes_after_confirmation(
    contract_harness: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness.client)
    fetch_url = f"{contract_harness.web_search_backend_url}/page"
    proposed = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": f"fetch the URL {fetch_url}"},
    )
    assert proposed.get("lockdown_level") == "normal"
    assert int(proposed.get("blocked_actions", 0)) == 0
    assert int(proposed.get("executed_actions", 0)) == 0
    pending_ids = proposed.get("pending_confirmation_ids")
    assert isinstance(pending_ids, list)
    assert pending_ids
    response = str(proposed.get("response", ""))
    assert "[PENDING CONFIRMATIONS]" in response
    assert f"shisad action confirm {pending_ids[0]}" in response
    assert "shisad action pending" in response

    confirmed = await _confirm_pending_action(contract_harness.client, str(pending_ids[0]))
    assert confirmed.get("confirmed") is True
    await _wait_for_audit_event(
        contract_harness.client,
        event_type="ToolExecuted",
        session_id=sid,
        predicate=lambda event: (
            str(event.get("data", {}).get("tool_name", "")) == "web.fetch"
            and bool(event.get("data", {}).get("success")) is True
        ),
    )


@pytest.mark.asyncio
async def test_contract_fs_write_confirmation_reject_does_not_write_file(
    contract_harness: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness.client, channel="matrix")
    proposed = await contract_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "channel": "matrix",
            "user_id": "alice",
            "workspace_id": "ws1",
            "content": "write a file called test-output.txt",
        },
    )
    assert proposed.get("lockdown_level") == "normal"
    assert int(proposed.get("blocked_actions", 0)) == 0
    assert int(proposed.get("executed_actions", 0)) == 0
    pending_ids = proposed.get("pending_confirmation_ids")
    assert isinstance(pending_ids, list)
    assert pending_ids

    rejected = await _reject_pending_action(contract_harness.client, str(pending_ids[0]))
    assert rejected.get("rejected") is True

    target = contract_harness.workspace_root / "test-output.txt"
    assert not target.exists()


@pytest.mark.asyncio
async def test_contract_multi_turn_context_persists_without_memory(
    contract_harness: ContractHarness,
) -> None:
    """Conversation context (not memory/RAG) is visible to the planner on subsequent turns."""
    sid = await _create_session(contract_harness.client)
    intro = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "my name is Alice"},
    )
    assert intro.get("lockdown_level") == "normal"
    assert int(intro.get("blocked_actions", 0)) == 0

    recall = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "what is my name"},
    )
    assert recall.get("lockdown_level") == "normal"
    assert "alice" in str(recall.get("response", "")).lower()


@pytest.fixture
async def contract_harness_no_policy_egress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> ContractHarness:
    async with _contract_harness_context(
        tmp_path,
        monkeypatch,
        policy_egress_allowed=False,
        browser_enabled=False,
    ) as harness:
        yield harness


@pytest.fixture
async def contract_harness_backend_unconfigured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> ContractHarness:
    async with _contract_harness_context(
        tmp_path,
        monkeypatch,
        web_search_backend_configured=False,
        policy_egress_allowed=False,
    ) as harness:
        yield harness


@pytest.mark.asyncio
async def test_contract_web_search_executes_without_policy_egress_allowlist(
    contract_harness_no_policy_egress: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness_no_policy_egress.client)
    reply = await contract_harness_no_policy_egress.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": "search for the latest news",
        },
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    outputs = _extract_tool_outputs(reply)
    assert "web.search" in outputs
    payload = outputs["web.search"][0]
    assert payload.get("ok") is True
    assert payload.get("results")


@pytest.mark.asyncio
async def test_contract_web_search_backend_unconfigured_is_actionable(
    contract_harness_backend_unconfigured: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness_backend_unconfigured.client)
    reply = await contract_harness_backend_unconfigured.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": "search for the latest news",
        },
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 0
    tool_output_records = reply.get("tool_outputs")
    assert isinstance(tool_output_records, list)
    web_search_records = [
        record
        for record in tool_output_records
        if isinstance(record, dict) and str(record.get("tool_name", "")) == "web.search"
    ]
    assert web_search_records
    assert web_search_records[0].get("success") is False
    outputs = _extract_tool_outputs(reply)
    assert "web.search" in outputs
    payload = outputs["web.search"][0]
    assert payload.get("ok") is False
    assert payload.get("error") == "web_search_backend_unconfigured"


@pytest.mark.asyncio
async def test_contract_session_scoped_tool_handles_remain_session_scoped_on_write(
    contract_harness_backend_unconfigured: ContractHarness,
) -> None:
    sid = await _create_session(contract_harness_backend_unconfigured.client)
    reply = await contract_harness_backend_unconfigured.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": "search for the latest news",
        },
    )
    tool_output_records = reply.get("tool_outputs")
    assert isinstance(tool_output_records, list)
    web_search_record = next(
        (
            record
            for record in tool_output_records
            if isinstance(record, dict) and str(record.get("tool_name", "")) == "web.search"
        ),
        None,
    )
    assert isinstance(web_search_record, dict)
    ingress_context = str(web_search_record.get("ingress_context", "")).strip()
    content_digest = str(web_search_record.get("content_digest", "")).strip()
    assert ingress_context
    assert content_digest

    created = await contract_harness_backend_unconfigured.client.call(
        "memory.write",
        {
            "ingress_context": ingress_context,
            "entry_type": "fact",
            "key": "tool.web_search.status",
            "value": "web search attempt noted",
            "derivation_path": "summary",
            "parent_digest": content_digest,
        },
    )
    assert created.get("kind") == "require_confirmation"
    assert created.get("reason") == "external_origin_requires_confirmation"

    for extra_field in (
        {"scope": "user"},
        {"source_id": "forged-source"},
        {"source_origin": "user_direct"},
    ):
        with pytest.raises(JsonRpcCallError) as excinfo:
            await contract_harness_backend_unconfigured.client.call(
                "memory.write",
                {
                    "ingress_context": ingress_context,
                    "entry_type": "fact",
                    "key": "tool.web_search.invalid",
                    "value": "web search attempt noted",
                    "derivation_path": "summary",
                    "parent_digest": content_digest,
                    **extra_field,
                },
            )
        assert excinfo.value.code == -32602
