"""Opt-in live-model behavioral contract tests.

These tests are intended for v0.3.4 model suitability evaluation. They exercise the
live daemon `session.message` path with a *real* planner model provider (remote or
local vLLM), while keeping tool backends deterministic (stub `web.search`).

By default this file is skipped to avoid flakiness and external dependencies.
Run via: `bash live-behavior.sh --live-model`.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
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
from shisad.daemon.runner import run_daemon

_RUN_LIVE = os.environ.get("SHISAD_LIVE_MODEL_TESTS", "").strip() == "1"
pytestmark = pytest.mark.skipif(
    not _RUN_LIVE,
    reason="Set SHISAD_LIVE_MODEL_TESTS=1 to run opt-in live-model behavioral tests.",
)


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


async def _wait_for_socket(path: Path, timeout: float = 5.0) -> None:
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if path.exists():
            return
        await asyncio.sleep(0.01)
    raise TimeoutError(f"Timed out waiting for socket {path}")


def _extract_tool_outputs(payload: Mapping[str, Any] | str) -> dict[str, list[dict[str, Any]]]:
    """Parse structured `tool_outputs`, falling back to legacy response markers."""
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
class LiveHarness:
    client: ControlClient
    config: DaemonConfig
    workspace_root: Path
    web_search_backend_url: str


@pytest.fixture
async def live_harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> LiveHarness:
    server, thread, backend_url, backend_port = _start_stub_search_backend()
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir(parents=True, exist_ok=True)
    (workspace_root / "README.md").write_text("live-model-readme\n", encoding="utf-8")

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

    # Keep the evaluation focused on planner model quality by default.
    # Live planner may be remote; embeddings/monitor routes are disabled to avoid extra keys.
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_REMOTE_ENABLED", "false")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_REMOTE_ENABLED", "false")

    base = DaemonConfig()
    config = base.model_copy(
        update={
            "data_dir": tmp_path / "data",
            "socket_path": tmp_path / "control.sock",
            "policy_path": policy_path,
            "log_level": "INFO",
            "context_window": 2,
            "web_search_enabled": True,
            "web_search_backend_url": backend_url,
            "web_allowed_domains": ["127.0.0.1", "localhost"],
            "assistant_fs_roots": [workspace_root],
        }
    )

    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        yield LiveHarness(
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
            await asyncio.wait_for(daemon_task, timeout=5)
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


def _assert_not_local_fallback(text: str) -> None:
    normalized = text.strip()
    if normalized.startswith("Safe summary:") or normalized.startswith("[PLANNER FALLBACK:"):
        raise AssertionError(
            "Planner appears to be using LocalPlannerProvider (fallback). "
            "Configure a live planner route and re-run."
        )


@pytest.mark.asyncio
@pytest.mark.live_smoke
async def test_live_model_hello_responds_without_lockdown(live_harness: LiveHarness) -> None:
    sid = await _create_session(live_harness.client)
    reply = await live_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": "hello",
        },
    )
    text = str(reply.get("response", "")).strip()
    assert text
    _assert_not_local_fallback(text)
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0


@pytest.mark.asyncio
@pytest.mark.live_smoke
async def test_live_model_web_search_executes(live_harness: LiveHarness) -> None:
    sid = await _create_session(live_harness.client)
    reply = await live_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "what's the weather in Tokyo right now"},
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    outputs = _extract_tool_outputs(reply)
    assert "web.search" in outputs
    payload = outputs["web.search"][0]
    assert payload.get("ok") is True
    assert payload.get("results")
    assert str(payload.get("backend", "")).startswith(live_harness.web_search_backend_url)


@pytest.mark.asyncio
@pytest.mark.live_smoke
async def test_live_model_file_read_executes(live_harness: LiveHarness) -> None:
    sid = await _create_session(live_harness.client)
    reply = await live_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "read README.md"},
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    outputs = _extract_tool_outputs(reply)
    assert "fs.read" in outputs
    payload = outputs["fs.read"][0]
    assert payload.get("ok") is True
    assert "live-model-readme" in str(payload.get("content", ""))


@pytest.mark.asyncio
async def test_live_model_fs_list_executes(live_harness: LiveHarness) -> None:
    sid = await _create_session(live_harness.client)
    reply = await live_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": "Use fs.list to list files in the current folder.",
        },
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    outputs = _extract_tool_outputs(reply)
    assert "fs.list" in outputs
    payload = outputs["fs.list"][0]
    assert payload.get("ok") is True
    entries = payload.get("entries")
    assert isinstance(entries, list)
    assert len(entries) > 0


@pytest.mark.asyncio
@pytest.mark.live_smoke
async def test_live_model_memory_remember_persists_and_is_used_later(
    live_harness: LiveHarness,
) -> None:
    sid = await _create_session(live_harness.client)

    remember = await live_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "remember that my dog is named Woofie"},
    )
    assert remember.get("lockdown_level") == "normal"
    assert int(remember.get("blocked_actions", 0)) == 0

    for _ in range(4):
        await live_harness.client.call(
            "session.message",
            {"session_id": sid, "content": "ok"},
        )

    retrieved = await live_harness.client.call(
        "memory.retrieve",
        {"query": "dog name", "limit": 5},
    )
    rendered = json.dumps(retrieved, ensure_ascii=True).lower()
    assert "woofie" in rendered

    reply = await live_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "what is my dog's name"},
    )
    assert reply.get("lockdown_level") == "normal"
    assert str(reply.get("response", "")).strip()


@pytest.mark.asyncio
@pytest.mark.live_smoke
async def test_live_model_multi_tool_executes_both_tools_in_one_turn(
    live_harness: LiveHarness,
) -> None:
    sid = await _create_session(live_harness.client)
    reply = await live_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": "Read README.md and search the web for related projects.",
        },
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    response_text = str(reply.get("response", ""))
    assert "[[TOOL_OUTPUT_BEGIN" not in response_text
    assert "[[TOOL_OUTPUT_END]]" not in response_text
    outputs = _extract_tool_outputs(reply)
    assert "fs.read" in outputs
    assert "web.search" in outputs


@pytest.mark.asyncio
@pytest.mark.live_smoke
async def test_live_model_web_fetch_routes_to_confirmation(
    live_harness: LiveHarness,
) -> None:
    """web.fetch is confirmation-gated (side-effect action), not blocked or locked down."""
    sid = await _create_session(live_harness.client)
    fetch_url = f"{live_harness.web_search_backend_url}/page"
    reply = await live_harness.client.call(
        "session.message",
        {"session_id": sid, "content": f"Use web.fetch to get {fetch_url}"},
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    # web.fetch routes to confirmation, not lockdown
    assert int(reply.get("confirmation_required_actions", 0)) >= 1


@pytest.mark.asyncio
async def test_live_model_git_status_executes(live_harness: LiveHarness) -> None:
    ws = live_harness.workspace_root
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
    sid = await _create_session(live_harness.client)
    reply = await live_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "Use git.status to show the repo status."},
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    outputs = _extract_tool_outputs(reply)
    assert "git.status" in outputs
    payload = outputs["git.status"][0]
    assert payload.get("ok") is True


@pytest.mark.asyncio
async def test_live_model_note_create_executes(live_harness: LiveHarness) -> None:
    sid = await _create_session(live_harness.client)
    reply = await live_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "Use note.create to save a note: meeting at 3pm"},
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) >= 1
    outputs = _extract_tool_outputs(reply)
    assert "note.create" in outputs
    payload = outputs["note.create"][0]
    assert payload.get("ok") is True


@pytest.mark.asyncio
async def test_live_model_todo_create_executes(live_harness: LiveHarness) -> None:
    sid = await _create_session(live_harness.client)
    reply = await live_harness.client.call(
        "session.message",
        {"session_id": sid, "content": "Use todo.create to add a todo: water the plants"},
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) >= 1
    outputs = _extract_tool_outputs(reply)
    assert "todo.create" in outputs
    payload = outputs["todo.create"][0]
    assert payload.get("ok") is True


@pytest.mark.asyncio
async def test_live_model_reminder_create_executes(live_harness: LiveHarness) -> None:
    sid = await _create_session(live_harness.client)
    reply = await live_harness.client.call(
        "session.message",
        {
            "session_id": sid,
            "content": "Use reminder.create to remind me to stretch in 30 seconds",
        },
    )
    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) >= 1
    outputs = _extract_tool_outputs(reply)
    assert "reminder.create" in outputs
    payload = outputs["reminder.create"][0]
    assert payload.get("ok") is True
