"""Behavioral coverage for evidence refs."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

from shisad.assistant.web import WebToolkit
from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.core.providers.base import Message, ProviderResponse
from shisad.core.providers.local_planner import LocalPlannerProvider
from shisad.core.transcript import TranscriptStore
from shisad.core.types import SessionId
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
_UNIQUE_MARKER = "EVIDENCE_BEHAVIORAL_MARKER"
_REF_RE = re.compile(r"\bev-[0-9a-f]{16}\b")


def _extract_user_goal(planner_input: str) -> str:
    normalized = planner_input.replace("^", "")
    match = _USER_GOAL_RE.search(normalized)
    if match:
        return match.group(1).strip()
    return normalized.strip()


def _extract_ref_id(text: str) -> str:
    match = _REF_RE.search(text)
    return match.group(0) if match else ""


def _tool_call(tool_name: str, arguments: dict[str, Any], *, call_id: str) -> dict[str, Any]:
    import json

    return {
        "id": call_id,
        "type": "function",
        "function": {
            "name": tool_name,
            "arguments": json.dumps(arguments, sort_keys=True),
        },
    }


async def _evidence_stub_complete(
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
            model="behavioral-evidence-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    planner_input = messages[-1].content if messages else ""
    normalized_planner_input = planner_input.replace("^", "")
    goal = _extract_user_goal(planner_input)
    goal_lower = goal.lower()

    if goal_lower.startswith("fetch https://example.com"):
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Fetching the page.",
                tool_calls=[
                    _tool_call(
                        "web.fetch",
                        {"url": "https://example.com/evidence", "snapshot": False},
                        call_id="t-fetch",
                    )
                ],
            ),
            model="behavioral-evidence-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if goal_lower.startswith("read evidence "):
        ref_id = _extract_ref_id(goal)
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Reading the evidence.",
                tool_calls=[_tool_call("evidence.read", {"ref_id": ref_id}, call_id="t-read")],
            ),
            model="behavioral-evidence-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if goal_lower.startswith("promote evidence "):
        ref_id = _extract_ref_id(goal)
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Promoting the evidence.",
                tool_calls=[
                    _tool_call("evidence.promote", {"ref_id": ref_id}, call_id="t-promote")
                ],
            ),
            model="behavioral-evidence-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "what did the page say" in goal_lower or "what was in that evidence again" in goal_lower:
        if _UNIQUE_MARKER in normalized_planner_input:
            response = "promoted-context-visible"
        elif "[EVIDENCE ref=" in normalized_planner_input:
            response = "stub-only"
        else:
            response = "missing-evidence"
        return ProviderResponse(
            message=Message(role="assistant", content=response),
            model="behavioral-evidence-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    return ProviderResponse(
        message=Message(role="assistant", content="OK."),
        model="behavioral-evidence-stub",
        finish_reason="stop",
        usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    )


def _stub_fetch(
    self: WebToolkit,
    *,
    url: str,
    snapshot: bool = False,
    max_bytes: int | None = None,
) -> dict[str, Any]:
    _ = (self, snapshot, max_bytes)
    content = (
        "This is a benign lead sentence for the fetched page. "
        + ("x" * 120)
        + f" {_UNIQUE_MARKER} "
        + "Prompt injection bait should not persist across turns. "
        + ("x" * 200)
    )
    return {
        "ok": True,
        "url": url,
        "status_code": 200,
        "title": "evidence page",
        "content": content,
        "blocked_reason": "",
        "truncated": False,
        "taint_labels": ["untrusted"],
        "evidence": {
            "operation": "web_fetch",
            "url": url,
        },
        "error": "",
        "snapshot_path": "",
    }


async def _wait_for_socket(path: Path, timeout: float = 2.0) -> None:
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if path.exists():
            return
        await asyncio.sleep(0.01)
    raise TimeoutError(f"Timed out waiting for socket {path}")


async def _create_session(client: ControlClient) -> str:
    created = await client.call(
        "session.create",
        {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
    )
    return str(created["session_id"])


def _tool_outputs(payload: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    rows = payload.get("tool_outputs")
    outputs: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(rows, list):
        return outputs
    for record in rows:
        if not isinstance(record, dict):
            continue
        tool_name = str(record.get("tool_name", "")).strip()
        data = record.get("payload")
        if tool_name and isinstance(data, dict):
            outputs.setdefault(tool_name, []).append(data)
    return outputs


@pytest.fixture
async def evidence_harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(LocalPlannerProvider, "complete", _evidence_stub_complete, raising=True)
    monkeypatch.setattr(WebToolkit, "fetch", _stub_fetch, raising=True)
    for var in (
        "SHISAD_MODEL_REMOTE_ENABLED",
        "SHISAD_MODEL_PLANNER_REMOTE_ENABLED",
        "SHISAD_MODEL_EMBEDDINGS_REMOTE_ENABLED",
        "SHISAD_MODEL_MONITOR_REMOTE_ENABLED",
    ):
        monkeypatch.setenv(var, "false")

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "\n".join(
            [
                'version: "1"',
                "default_require_confirmation: false",
                "safe_output_domains:",
                '  - "example.com"',
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
        context_window=6,
        web_fetch_enabled=True,
        web_allowed_domains=["example.com"],
    )
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        yield {"client": client, "config": config}
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        with suppress(Exception):
            await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_behavioral_fetch_stub_read_strip_promote_flow(evidence_harness) -> None:
    client: ControlClient = evidence_harness["client"]
    config: DaemonConfig = evidence_harness["config"]
    sid = await _create_session(client)

    fetched = await client.call(
        "session.message",
        {"session_id": sid, "content": "fetch https://example.com/evidence"},
    )
    assert int(fetched.get("executed_actions", 0)) == 1
    outputs = _tool_outputs(fetched)
    assert _UNIQUE_MARKER in outputs["web.fetch"][0]["content"]
    assert "[EVIDENCE ref=" in str(fetched.get("response", ""))
    assert _UNIQUE_MARKER not in str(fetched.get("response", ""))
    ref_id = _extract_ref_id(str(fetched.get("response", "")))
    assert ref_id

    transcript_store = TranscriptStore(config.data_dir / "sessions")
    entries = transcript_store.list_entries(SessionId(sid))
    assert entries[-1].metadata.get("evidence_ref_ids") == [ref_id]

    stub_only = await client.call(
        "session.message",
        {"session_id": sid, "content": "what did the page say?"},
    )
    assert stub_only["response"] == "stub-only"

    reread = await client.call(
        "session.message",
        {"session_id": sid, "content": f"read evidence {ref_id}"},
    )
    assert int(reread.get("executed_actions", 0)) == 1
    reread_outputs = _tool_outputs(reread)
    assert _UNIQUE_MARKER in reread_outputs["evidence.read"][0]["content"]

    stripped = await client.call(
        "session.message",
        {"session_id": sid, "content": "what was in that evidence again?"},
    )
    assert stripped["response"] == "stub-only"

    promote = await client.call(
        "session.message",
        {"session_id": sid, "content": f"promote evidence {ref_id}"},
    )
    assert int(promote.get("confirmation_required_actions", 0)) == 1
    pending = await client.call(
        "action.pending",
        {"session_id": sid, "status": "pending", "limit": 10},
    )
    promote_pending = next(
        item for item in pending["actions"] if str(item.get("tool_name", "")) == "evidence.promote"
    )
    confirmed = await client.call(
        "action.confirm",
        {
            "confirmation_id": promote_pending["confirmation_id"],
            "decision_nonce": promote_pending["decision_nonce"],
        },
    )
    assert confirmed["confirmed"] is True

    promoted = await client.call(
        "session.message",
        {"session_id": sid, "content": "what was in that evidence again?"},
    )
    assert promoted["response"] == "promoted-context-visible"
