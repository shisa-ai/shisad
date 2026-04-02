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
import subprocess
import threading
from collections.abc import Callable, Mapping
from contextlib import suppress
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
from shisad.daemon.runner import run_daemon

_USER_GOAL_RE = re.compile(
    (
        r"=== (?:USER GOAL|USER REQUEST) ===\n"
        r".*?\n"
        r"(.*?)\n\n"
        r"=== (?:EXTERNAL CONTENT[^\n]*|DATA EVIDENCE[^\n]*|END CONTEXT|END PAYLOAD)"
    ),
    flags=re.DOTALL,
)
_SUMMARIZER_SYSTEM_MARKER = "You extract durable memory candidates from conversation history."


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

    if goal_lower.startswith("remember that"):
        return ProviderResponse(
            message=Message(role="assistant", content="Got it — I'll remember that."),
            model="behavioral-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "favorite color" in goal_lower:
        memory_context = _extract_memory_context(planner_input).lower()
        response = (
            "Your favorite color is blue."
            if "favorite color is blue" in memory_context
            else "I don't know your favorite color yet."
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

    tool_calls: list[dict[str, Any]] = []
    note_create_call = None
    if "add a note" in goal_lower or goal_lower.startswith("note:"):
        content = _extract_after_colon(goal)
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
        _tool_call("git.status", {}, call_id="t-git-status")
        if "git status" in goal_lower
        else None
    )
    git_log_call = (
        _tool_call("git.log", {"limit": 5}, call_id="t-git-log")
        if "git log" in goal_lower
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
    elif read_call is not None:
        tool_calls.append(read_call)
    elif search_call is not None:
        tool_calls.append(search_call)
    elif list_call is not None:
        tool_calls.append(list_call)
    elif fetch_call is not None:
        tool_calls.append(fetch_call)
    elif git_status_call is not None:
        tool_calls.append(git_status_call)
    elif git_log_call is not None:
        tool_calls.append(git_log_call)
    elif fs_write_call is not None:
        tool_calls.append(fs_write_call)

    assistant_response = (
        "Working on it." if tool_calls else "Hello! How can I help?"
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


async def _wait_for_socket(path: Path, timeout: float = 2.0) -> None:
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if path.exists():
            return
        await asyncio.sleep(0.01)
    raise TimeoutError(f"Timed out waiting for socket {path}")


def _extract_tool_outputs(payload: Mapping[str, Any] | str) -> dict[str, list[dict[str, Any]]]:
    if isinstance(payload, Mapping):
        raw_records = payload.get("tool_outputs")
        if isinstance(raw_records, list):
            outputs: dict[str, list[dict[str, Any]]] = {}
            for record in raw_records:
                if not isinstance(record, dict):
                    continue
                tool_name = str(record.get("tool_name", "")).strip()
                data = record.get("payload")
                if tool_name and isinstance(data, dict):
                    outputs.setdefault(tool_name, []).append(data)
            if outputs:
                return outputs
        response_text = str(payload.get("response", ""))
    else:
        response_text = str(payload)

    outputs: dict[str, list[dict[str, Any]]] = {}
    begin = "[[TOOL_OUTPUT_BEGIN"
    end = "[[TOOL_OUTPUT_END]]"
    cursor = 0
    while True:
        start = response_text.find(begin, cursor)
        if start < 0:
            break
        header_end = response_text.find("]]", start)
        if header_end < 0:
            raise AssertionError("Malformed tool boundary: missing closing brackets")
        header = response_text[start : header_end + 2]
        match = re.search(r"tool=([^\s]+)", header)
        if match is None:
            raise AssertionError(f"Malformed tool boundary: {header}")
        tool_name = match.group(1).strip()
        payload_start = header_end + 2
        payload_end = response_text.find(end, payload_start)
        if payload_end < 0:
            raise AssertionError(f"Malformed tool boundary: missing end marker for {tool_name}")
        raw_payload = response_text[payload_start:payload_end].strip()
        try:
            payload = json.loads(raw_payload)
        except json.JSONDecodeError as exc:
            raise AssertionError(
                f"Tool payload is not JSON for {tool_name}: {raw_payload}"
            ) from exc
        outputs.setdefault(tool_name, []).append(payload)
        cursor = payload_end + len(end)
    return outputs


@dataclass(frozen=True, slots=True)
class ContractHarness:
    client: ControlClient
    config: DaemonConfig
    workspace_root: Path
    web_search_backend_url: str


@pytest.fixture
async def contract_harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ContractHarness:
    server, thread, backend_url, backend_port = _start_stub_search_backend()
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir(parents=True, exist_ok=True)
    (workspace_root / "README.md").write_text("behavioral-readme\n", encoding="utf-8")

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "\n".join(
            [
                'version: "1"',
                "default_require_confirmation: false",
                "safe_output_domains:",
                '  - "localhost"',
                '  - "example.com"',
                "egress:",
                '  - host: "localhost"',
                f"    ports: [{backend_port}]",
                '    protocols: ["http"]',
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
        assistant_fs_roots=[workspace_root],
    )

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
        )
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        with suppress(Exception):
            await asyncio.wait_for(daemon_task, timeout=3)
        server.shutdown()
        server.server_close()
        with suppress(Exception):
            thread.join(timeout=1.0)


async def _create_session(client: ControlClient) -> str:
    created = await client.call(
        "session.create",
        {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
    )
    return str(created["session_id"])


async def _confirm_pending_action(
    client: ControlClient,
    confirmation_id: str,
) -> dict[str, Any]:
    """Fetch decision nonce for a pending action and confirm it."""
    pending = await client.call(
        "action.pending",
        {"confirmation_id": confirmation_id},
    )
    actions = pending.get("actions", [])
    assert actions, f"No pending action found for {confirmation_id}"
    nonce = str(actions[0].get("decision_nonce", "")).strip()
    assert nonce, f"Missing decision_nonce for {confirmation_id}"
    result = await client.call(
        "action.confirm",
        {"confirmation_id": confirmation_id, "decision_nonce": nonce},
    )
    return dict(result)


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
        predicate=lambda event: str(event.get("data", {}).get("tool_name", "")) == "message.send"
        and bool(event.get("data", {}).get("success")) is True,
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
        str(item.get("id", "")) == task_id
        for item in reminder_list_payload.get("tasks", [])
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
async def test_contract_git_status_executes_and_returns_output(
    contract_harness: ContractHarness,
) -> None:
    ws = contract_harness.workspace_root
    subprocess.run(["git", "init", str(ws)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(ws), "commit", "--allow-empty", "-m", "init"],
        check=True,
        capture_output=True,
        env={**os.environ, "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "t@t",
             "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "t@t"},
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
        env={**os.environ, "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "t@t",
             "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "t@t"},
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
async def test_contract_fs_write_routes_to_confirmation_not_lockdown(
    contract_harness: ContractHarness,
) -> None:
    """fs.write is a side-effect action that requires confirmation, not lockdown."""
    sid = await _create_session(contract_harness.client)
    reply = await contract_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "write a file called test-output.txt"},
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    # fs.write is confirmation-gated (side_effect_action), not blocked
    assert int(reply.get("confirmation_required_actions", 0)) >= 1


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
    server, thread, backend_url, _backend_port = _start_stub_search_backend()
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir(parents=True, exist_ok=True)
    (workspace_root / "README.md").write_text("behavioral-readme\n", encoding="utf-8")

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "\n".join(
            [
                'version: "1"',
                "default_require_confirmation: false",
                "safe_output_domains:",
                '  - "localhost"',
                '  - "example.com"',
                "egress: []",
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
        web_allowed_domains=["localhost"],
        assistant_fs_roots=[workspace_root],
    )

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
        )
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        with suppress(Exception):
            await asyncio.wait_for(daemon_task, timeout=3)
        server.shutdown()
        server.server_close()
        with suppress(Exception):
            thread.join(timeout=1.0)


@pytest.fixture
async def contract_harness_backend_unconfigured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> ContractHarness:
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir(parents=True, exist_ok=True)
    (workspace_root / "README.md").write_text("behavioral-readme\n", encoding="utf-8")

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "\n".join(
            [
                'version: "1"',
                "default_require_confirmation: false",
                "safe_output_domains:",
                '  - "localhost"',
                '  - "example.com"',
                "egress: []",
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
        web_search_backend_url="",
        assistant_fs_roots=[workspace_root],
    )

    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        yield ContractHarness(
            client=client,
            config=config,
            workspace_root=workspace_root,
            web_search_backend_url="",
        )
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        with suppress(Exception):
            await asyncio.wait_for(daemon_task, timeout=3)


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
