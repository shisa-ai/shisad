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
import subprocess
import threading
from contextlib import suppress
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.daemon.runner import run_daemon
from tests.helpers.behavioral import extract_tool_outputs
from tests.helpers.daemon import wait_for_socket as _wait_for_socket

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


_extract_tool_outputs = extract_tool_outputs


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


async def _call_live_turn_until_tools(
    live_harness: LiveHarness,
    *,
    content: str,
    required_tools: set[str],
    attempts: int = 3,
) -> dict[str, object]:
    observed_tool_sets: list[list[str]] = []
    last_reply: dict[str, object] | None = None

    for _ in range(attempts):
        sid = await _create_session(live_harness.client)
        reply = await live_harness.client.call(
            "session.message",
            {
                "session_id": sid,
                "content": content,
            },
        )
        last_reply = reply
        outputs = _extract_tool_outputs(reply)
        observed = sorted(str(name) for name in outputs)
        observed_tool_sets.append(observed)
        if required_tools.issubset(outputs):
            return reply

    pytest.fail(
        "Live planner did not emit the required tool set after "
        f"{attempts} attempts. Required={sorted(required_tools)} "
        f"observed={observed_tool_sets!r} last_reply={last_reply!r}"
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


def _reply_exposes_recovered_todo_log(reply: dict[str, object]) -> bool:
    outputs = _extract_tool_outputs(reply)
    for payload in outputs.get("fs.read", []):
        if payload.get("ok") is not True:
            continue
        path = str(payload.get("path", "")).lower()
        content = str(payload.get("content", "")).lower()
        if path.endswith("/todo.log") or "open: verify live similar-file recovery" in content:
            return True
    for payload in outputs.get("fs.list", []):
        if payload.get("ok") is not True:
            continue
        entries = payload.get("entries", [])
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name", "")).lower()
            path = str(entry.get("path", "")).lower()
            if name == "todo.log" or path.endswith("/todo.log"):
                return True
    for payload in outputs.get("shell.exec", []):
        if payload.get("allowed") is not True:
            continue
        if "todo.log" in str(payload.get("stdout", "")).lower():
            return True
    return False


def test_gh12_recovery_matcher_ignores_failed_read_path() -> None:
    reply = {
        "tool_outputs": [
            {
                "tool_name": "fs.read",
                "payload": {
                    "ok": False,
                    "path": "/workspace/TODO.LOG",
                    "error": "path_not_found",
                },
            }
        ],
    }

    assert not _reply_exposes_recovered_todo_log(reply)


def test_gh12_recovery_matcher_accepts_real_listing_or_shell_output() -> None:
    listed = {
        "tool_outputs": [
            {
                "tool_name": "fs.list",
                "payload": {
                    "ok": True,
                    "entries": [{"name": "todo.log", "path": "/workspace/todo.log"}],
                },
            }
        ],
    }
    shell = {
        "tool_outputs": [
            {
                "tool_name": "shell.exec",
                "payload": {"allowed": True, "stdout": "./todo.log\n"},
            }
        ],
    }

    assert _reply_exposes_recovered_todo_log(listed)
    assert _reply_exposes_recovered_todo_log(shell)


def _assert_no_legacy_or_shell_file_lookup(reply: dict[str, object]) -> None:
    outputs = _extract_tool_outputs(reply)
    assert "file.read" not in outputs
    assert "shell.exec" not in outputs


@pytest.mark.asyncio
@pytest.mark.live_smoke
async def test_live_model_similar_file_recovery_reaches_confirmation_or_listing(
    live_harness: LiveHarness,
) -> None:
    """LUS-8: typo'd file read followed by similar-file recovery must not lockdown."""
    (live_harness.workspace_root / "todo.log").write_text(
        "OPEN: verify live similar-file recovery\n",
        encoding="utf-8",
    )
    observed: list[dict[str, object]] = []

    for _ in range(3):
        sid = await _create_session(live_harness.client)
        first = await live_harness.client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "read TODO.LOG and tell me what's at the end",
            },
        )
        assert first.get("lockdown_level") == "normal"
        assert int(first.get("blocked_actions", 0)) == 0
        _assert_no_legacy_or_shell_file_lookup(first)
        if _reply_exposes_recovered_todo_log(first):
            return
        if int(first.get("confirmation_required_actions", 0)) >= 1:
            confirmed_first = await live_harness.client.call(
                "session.message",
                {"session_id": sid, "content": "confirm"},
            )
            assert confirmed_first.get("lockdown_level") == "normal"
            assert int(confirmed_first.get("blocked_actions", 0)) == 0
            _assert_no_legacy_or_shell_file_lookup(confirmed_first)
            if _reply_exposes_recovered_todo_log(confirmed_first):
                return
            observed.append(confirmed_first)
            continue
        first_outputs = _extract_tool_outputs(first)
        if first_outputs.get("fs.read", [{}])[0].get("error") != "path_not_found":
            observed.append(first)
            continue

        proposed = await live_harness.client.call(
            "session.message",
            {
                "session_id": sid,
                "content": (
                    "can you look for the file? filename should be similar if it's not exact"
                ),
            },
        )
        observed.append(proposed)
        assert proposed.get("lockdown_level") == "normal"
        assert int(proposed.get("blocked_actions", 0)) == 0
        _assert_no_legacy_or_shell_file_lookup(proposed)

        if int(proposed.get("confirmation_required_actions", 0)) >= 1:
            confirmed = await live_harness.client.call(
                "session.message",
                {"session_id": sid, "content": "confirm"},
            )
            assert confirmed.get("lockdown_level") == "normal"
            assert int(confirmed.get("blocked_actions", 0)) == 0
            _assert_no_legacy_or_shell_file_lookup(confirmed)
            if _reply_exposes_recovered_todo_log(confirmed):
                return
            observed.append(confirmed)
            continue

        if _reply_exposes_recovered_todo_log(proposed):
            return

    pytest.fail(
        "Live planner similar-file recovery did not expose todo.log after bounded retries. "
        f"observed={observed!r}"
    )


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
        {
            "query": "dog name",
            "limit": 5,
            "user_id": "alice",
            "workspace_id": "ws1",
        },
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
    # Live planner routes are stochastic; bounded retry keeps this smoke test
    # focused on capability instead of a single provider sample.
    reply = await _call_live_turn_until_tools(
        live_harness,
        content="Read README.md and search the web for related projects.",
        required_tools={"fs.read", "web.search"},
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
