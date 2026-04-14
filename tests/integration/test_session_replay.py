"""M1 runtime-loop session replay integration checks."""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
import threading
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.core.providers.base import Message, ProviderResponse
from shisad.core.providers.local_planner import LocalPlannerProvider
from shisad.daemon.runner import run_daemon
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


def _extract_user_goal(planner_input: str) -> str:
    normalized = planner_input.replace("^", "")
    match = _USER_GOAL_RE.search(normalized)
    if match:
        return match.group(1).strip()
    return normalized.strip()


def _tool_call(tool_name: str, arguments: dict[str, object], *, call_id: str) -> dict[str, object]:
    return {
        "id": call_id,
        "type": "function",
        "function": {
            "name": tool_name,
            "arguments": json.dumps(arguments, sort_keys=True),
        },
    }


async def _replay_complete(
    self: LocalPlannerProvider,
    messages: list[Message],
    tools: list[dict[str, object]] | None = None,
) -> ProviderResponse:
    _ = self, tools
    planner_input = messages[-1].content if messages else ""
    goal = _extract_user_goal(planner_input)
    goal_lower = goal.lower()

    if "what tools are available" in goal_lower:
        return ProviderResponse(
            message=Message(
                role="assistant",
                content=(
                    "Available tools: fs.list, fs.read, fs.write, git.status, git.diff, "
                    "git.log, web.search, web.fetch."
                ),
            ),
            model="session-replay-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "latest news" in goal_lower:
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Searching latest news now.",
                tool_calls=[
                    _tool_call(
                        "web.search",
                        {"query": "latest news", "limit": 3},
                        call_id="replay-search-1",
                    )
                ],
            ),
            model="session-replay-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "git info please" in goal_lower or "git status" in goal_lower:
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Checking git status.",
                tool_calls=[
                    _tool_call(
                        "functions.git_status",
                        {"repo_path": "."},
                        call_id="replay-git-1",
                    )
                ],
            ),
            model="session-replay-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    return ProviderResponse(
        message=Message(role="assistant", content="OK."),
        model="session-replay-stub",
        finish_reason="stop",
        usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    )


class _StubSearchHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/search":
            self.send_response(404)
            self.end_headers()
            return
        query = (parse_qs(parsed.query).get("q") or [""])[0]
        payload = {
            "results": [
                {
                    "title": f"stub result for {query}",
                    "url": "https://example.com/result",
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


@pytest.mark.asyncio
async def test_m1_rlc5_session_replay_latest_news_then_git_info_no_lockdown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, thread, backend_url, backend_port = _start_stub_search_backend()
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init"], cwd=workspace_root, check=True, capture_output=True)

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
    monkeypatch.setattr(LocalPlannerProvider, "complete", _replay_complete, raising=True)

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

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        log_level="WARNING",
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

        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = str(created["session_id"])

        tools_reply = await client.call(
            "session.message",
            {"session_id": sid, "content": "what tools are available?"},
        )
        assert tools_reply.get("lockdown_level") == "normal"
        assert "available tools" in str(tools_reply.get("response", "")).lower()

        news_reply = await client.call(
            "session.message",
            {"session_id": sid, "content": "can you get the latest news for me?"},
        )
        assert news_reply.get("lockdown_level") == "normal"
        assert (
            int(news_reply.get("executed_actions", 0))
            + int(news_reply.get("confirmation_required_actions", 0))
            >= 1
        )

        git_reply = await client.call(
            "session.message",
            {"session_id": sid, "content": "git status"},
        )
        assert git_reply.get("lockdown_level") == "normal"
        assert int(git_reply.get("executed_actions", 0)) >= 1

        violations = await client.call(
            "audit.query",
            {"event_type": "PlanViolationDetected", "session_id": sid, "limit": 50},
        )
        assert not any(
            "trace:action_not_committed" in json.dumps(event, ensure_ascii=True)
            for event in violations.get("events", [])
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
