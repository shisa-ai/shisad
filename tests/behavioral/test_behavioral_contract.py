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
import re
import threading
from collections.abc import Mapping
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

    if "remember" in goal_lower:
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

    tool_calls: list[dict[str, Any]] = []
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
    unknown_probe_call = (
        _tool_call("unknown.tool", {"probe": True}, call_id="t-unknown")
        if "unknown tool probe" in goal_lower
        else None
    )
    if unknown_probe_call is not None:
        tool_calls.append(unknown_probe_call)
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
            self.send_response(404)
            self.end_headers()
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
    outputs = _extract_tool_outputs(reply)
    assert "web.search" in outputs
    payload = outputs["web.search"][0]
    assert payload.get("ok") is False
    assert payload.get("error") == "web_search_backend_unconfigured"
