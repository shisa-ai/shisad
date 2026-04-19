"""Behavioral coverage for evidence refs."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Mapping
from contextlib import asynccontextmanager, suppress
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
from shisad.memory.summarizer import _SUMMARY_SYSTEM_PROMPT
from tests.helpers.artifact_kms import StubArtifactKmsService
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
# ADV-M3: take the first sentence of the live summarizer system prompt as the
# stub's routing marker. Before this, the test embedded a hardcoded string
# that could silently drift from production and leave the stub's summarizer
# branch forever unreachable.
_SUMMARIZER_SYSTEM_MARKER = _SUMMARY_SYSTEM_PROMPT.split(". ")[0] + "."
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

    # ADV-M3: the `startswith("fetch https://...")` literal is still the
    # simplest test-input match, but we also tolerate additional leading
    # verbs like "please fetch https://..." so minor phrasing tweaks in
    # the harness test text don't silently skip this stub branch.
    if "fetch https://example.com" in goal_lower and "fetch" in goal_lower.split():
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

    if goal_lower.startswith("search hokkaido venues"):
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Searching Hokkaido venues.",
                tool_calls=[
                    _tool_call(
                        "web.search",
                        {"query": "Hokkaido venues", "limit": 1},
                        call_id="t-search",
                    )
                ],
            ),
            model="behavioral-evidence-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "itinerary using what you found" in goal_lower:
        has_working_packet = "WORKING EVIDENCE PACKET" in normalized_planner_input
        has_evidence_ref = "[EVIDENCE ref=" in normalized_planner_input
        if has_working_packet and has_evidence_ref:
            response = "grounded-itinerary"
        else:
            response = "generic-itinerary"
        return ProviderResponse(
            message=Message(role="assistant", content=response),
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


def _stub_search(self: WebToolkit, *, query: str, limit: int = 5) -> dict[str, Any]:
    _ = (self, limit)
    return {
        "ok": True,
        "query": query,
        "backend": "https://search.example.test/search",
        "results": [
            {
                "title": "Yoichi distillery",
                "url": "https://example.test/yoichi",
                "snippet": "Yoichi distillery tours require advance booking.",
                "host": "example.test",
                "allowlisted_host": False,
                "engine": "stub",
            }
        ],
        "taint_labels": ["untrusted"],
        "evidence": {
            "operation": "web_search",
            "backend_url": "https://search.example.test/search",
            "query_hash": "stub",
            "response_hash": "stub",
            "fetched_at": "2026-04-18T00:00:00+00:00",
            "status_code": 200,
            "truncated": False,
            "result_count": 1,
            "final_url": "https://search.example.test/search",
        },
    }


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


@asynccontextmanager
async def _run_evidence_harness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    evidence_kms_url: str = "",
    evidence_kms_bearer_token: str = "",
):
    monkeypatch.setattr(LocalPlannerProvider, "complete", _evidence_stub_complete, raising=True)
    monkeypatch.setattr(WebToolkit, "fetch", _stub_fetch, raising=True)
    monkeypatch.setattr(WebToolkit, "search", _stub_search, raising=True)
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
        web_search_enabled=True,
        web_allowed_domains=["example.com"],
        evidence_kms_url=evidence_kms_url,
        evidence_kms_bearer_token=evidence_kms_bearer_token,
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
            await asyncio.wait_for(daemon_task, timeout=5)


@pytest.fixture
async def evidence_harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    async with _run_evidence_harness(tmp_path, monkeypatch) as harness:
        yield harness


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

    promote_again = await client.call(
        "session.message",
        {"session_id": sid, "content": f"promote evidence {ref_id}"},
    )
    assert int(promote_again.get("confirmation_required_actions", 0)) == 0
    assert int(promote_again.get("executed_actions", 0)) == 1

    promoted = await client.call(
        "session.message",
        {"session_id": sid, "content": "what was in that evidence again?"},
    )
    assert promoted["response"] == "promoted-context-visible"


@pytest.mark.asyncio
async def test_behavioral_search_followup_receives_working_evidence_packet(
    evidence_harness,
) -> None:
    client: ControlClient = evidence_harness["client"]
    sid = await _create_session(client)

    searched = await client.call(
        "session.message",
        {"session_id": sid, "content": "search Hokkaido venues"},
    )
    assert int(searched.get("executed_actions", 0)) == 1
    assert "[EVIDENCE ref=" in str(searched.get("response", ""))

    followup = await client.call(
        "session.message",
        {"session_id": sid, "content": "now write the itinerary using what you found"},
    )

    assert followup["response"] == "grounded-itinerary"


@pytest.mark.asyncio
async def test_behavioral_fetch_stub_read_strip_promote_flow_with_encrypted_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with StubArtifactKmsService(key_material=b"a" * 32).run() as evidence_kms_url:
        async with _run_evidence_harness(
            tmp_path,
            monkeypatch,
            evidence_kms_url=evidence_kms_url,
        ) as harness:
            client: ControlClient = harness["client"]
            config: DaemonConfig = harness["config"]
            sid = await _create_session(client)

            fetched = await client.call(
                "session.message",
                {"session_id": sid, "content": "fetch https://example.com/evidence"},
            )
            assert int(fetched.get("executed_actions", 0)) == 1
            ref_id = _extract_ref_id(str(fetched.get("response", "")))
            assert ref_id

            index_path = config.data_dir / "sessions" / "evidence" / "refs_index.json"
            index = json.loads(index_path.read_text(encoding="utf-8"))
            content_hash = str(index[sid][ref_id]["content_hash"])
            blob_path = config.data_dir / "sessions" / "evidence" / "blobs" / f"{content_hash}.txt"
            assert _UNIQUE_MARKER.encode("utf-8") not in blob_path.read_bytes()

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
                item
                for item in pending["actions"]
                if str(item.get("tool_name", "")) == "evidence.promote"
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
