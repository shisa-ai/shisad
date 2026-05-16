"""Behavioral coverage for weak web-search evidence recovery."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Mapping
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

from shisad.assistant.web import WebToolkit
from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.core.providers.base import Message, ProviderResponse
from shisad.core.providers.local_planner import LocalPlannerProvider
from shisad.daemon.runner import run_daemon
from shisad.memory.summarizer import _SUMMARY_SYSTEM_PROMPT
from tests.helpers.daemon import wait_for_socket as _wait_for_socket

_SUMMARY_SYSTEM_MARKER = _SUMMARY_SYSTEM_PROMPT.split(". ")[0] + "."
_RECOVERY_POLICY_MARKER = "SEARCH EVIDENCE RECOVERY POLICY"
_UNSUPPORTED_PRELIMINARY_POSITIVE_MARKER = "UNSUPPORTED_PRELIMINARY_POSITIVE_TEST"
_TRUSTED_CONTEXT_RECOVERY_MARKER = (
    "Trusted runtime and session context may resolve current-turn referents"
)
_AMOUR_URL = "https://tabelog.com/hokkaido/A0101/A010101/123456/"
_AMOUR_HOST = urlsplit(_AMOUR_URL).hostname or ""
_AMOUR_SITE_QUERY = f"site:{_AMOUR_HOST}"
_USER_GOAL_RE = re.compile(
    (
        r"=== (?:USER GOAL|USER REQUEST) ===\n"
        r".*?\n"
        r"(.*?)\n\n"
        r"=== (?:EXTERNAL CONTENT[^\n]*|DATA EVIDENCE[^\n]*|END CONTEXT|END PAYLOAD)"
    ),
    flags=re.DOTALL,
)


def _tool_call(tool_name: str, arguments: dict[str, Any], *, call_id: str) -> dict[str, Any]:
    return {
        "id": call_id,
        "type": "function",
        "function": {
            "name": tool_name,
            "arguments": json.dumps(arguments, sort_keys=True),
        },
    }


def _extract_user_request(planner_input: str) -> str:
    normalized = planner_input.replace("^", "")
    match = _USER_GOAL_RE.search(normalized)
    if match:
        return match.group(1).strip()
    return normalized.strip()


def _trusted_preamble(planner_input: str) -> str:
    normalized = planner_input.replace("^", "")
    return normalized.split("=== USER REQUEST ===", 1)[0]


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


async def _planner_stub_complete(
    self: LocalPlannerProvider,
    messages: list[Message],
    tools: list[dict[str, Any]] | None = None,
) -> ProviderResponse:
    _ = (self, tools)
    if messages and messages[0].role == "system" and _SUMMARY_SYSTEM_MARKER in messages[0].content:
        return ProviderResponse(
            message=Message(role="assistant", content='{"entries": []}'),
            model="gh27-web-recovery-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    system_prompt = messages[0].content if messages else ""
    planner_input = messages[-1].content if messages else ""
    normalized_input = planner_input.replace("^", "")

    if "POST-TOOL SYNTHESIS PASS" in normalized_input:
        if "Synthesis failure test" in normalized_input:
            raise RuntimeError("synthetic GH27 synthesis failure")
        if _UNSUPPORTED_PRELIMINARY_POSITIVE_MARKER in normalized_input:
            if "Do not preserve preliminary claims that a web target" in normalized_input:
                response = (
                    "The current evidence is insufficient to verify the Amour "
                    "reservation page. The search result did not establish the target."
                )
            else:
                response = "Found Amour on Tabelog; the reservation page is available."
        elif (
            "Amour reservation page" in normalized_input
            and "cancellation policy" in normalized_input
        ):
            response = (
                "Found Amour on Tabelog; the reservation page is available. "
                "The current web evidence does not establish a separate "
                "cancellation policy page."
            )
        elif "Amour reservation page" in normalized_input:
            response = "Found Amour on Tabelog; the reservation page is available."
        elif _RECOVERY_POLICY_MARKER in normalized_input:
            response = (
                "The current evidence is insufficient to verify a reservation path. "
                "I tried bounded search recovery but did not find a reliable page."
            )
        else:
            response = "The reservation path does not exist or is unavailable."
        return ProviderResponse(
            message=Message(role="assistant", content=response),
            model="gh27-web-recovery-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    goal = _extract_user_request(planner_input)
    goal_lower = goal.lower()
    trusted_preamble = _trusted_preamble(planner_input)
    has_recovery_policy = _RECOVERY_POLICY_MARKER in system_prompt
    has_trusted_context_recovery = _TRUSTED_CONTEXT_RECOVERY_MARKER in system_prompt

    if goal_lower.startswith("context note:"):
        return ProviderResponse(
            message=Message(role="assistant", content="Noted."),
            model="gh27-web-recovery-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "premature absence" in goal_lower and "amour" in goal_lower and "tabelog" in goal_lower:
        calls = [
            _tool_call(
                "web.search",
                {"query": "Amour Sapporo Tabelog reservation", "limit": 3},
                call_id="gh27-premature-search-noisy",
            )
        ]
        if has_recovery_policy:
            calls.extend(
                [
                    _tool_call(
                        "web.search",
                        {"query": '"Amour" "Tabelog" site:tabelog.com', "limit": 3},
                        call_id="gh27-premature-search-exact",
                    ),
                    _tool_call(
                        "web.fetch",
                        {"url": _AMOUR_URL, "max_bytes": 65536},
                        call_id="gh27-premature-fetch-tabelog",
                    ),
                ]
            )
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="The Tabelog reservation path does not exist.",
                tool_calls=calls,
            ),
            model="gh27-web-recovery-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "synthesis failure test" in goal_lower and "amour" in goal_lower:
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="The Tabelog reservation path does not exist.",
                tool_calls=[
                    _tool_call(
                        "web.search",
                        {"query": '"Amour" "Tabelog" site:tabelog.com', "limit": 3},
                        call_id="gh27-synthesis-failure-search",
                    )
                ],
            ),
            model="gh27-web-recovery-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "shorthand absence test" in goal_lower and "amour" in goal_lower:
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="The page is unavailable and the path does not exist.",
                tool_calls=[
                    _tool_call(
                        "web.search",
                        {"query": '"Amour" "Tabelog" site:tabelog.com', "limit": 3},
                        call_id="gh27-shorthand-absence-search",
                    )
                ],
            ),
            model="gh27-web-recovery-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "negative found test" in goal_lower and "amour" in goal_lower:
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="No reservation page was found.",
                tool_calls=[
                    _tool_call(
                        "web.search",
                        {"query": '"Amour" "Tabelog" site:tabelog.com', "limit": 3},
                        call_id="gh27-negative-found-search",
                    )
                ],
            ),
            model="gh27-web-recovery-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "insufficient pretool test" in goal_lower and "amour" in goal_lower:
        return ProviderResponse(
            message=Message(
                role="assistant",
                content=(
                    "The current evidence is insufficient to verify the Tabelog reservation path."
                ),
                tool_calls=[
                    _tool_call(
                        "web.search",
                        {"query": '"Amour" "Tabelog" site:tabelog.com', "limit": 3},
                        call_id="gh27-insufficient-pretool-search",
                    )
                ],
            ),
            model="gh27-web-recovery-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "unsupported preliminary positive test" in goal_lower and "amour" in goal_lower:
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="Found Amour on Tabelog; the reservation page is available.",
                tool_calls=[
                    _tool_call(
                        "web.search",
                        {"query": "Amour reservation page", "limit": 3},
                        call_id="gh27-unsupported-positive-search",
                    )
                ],
            ),
            model="gh27-web-recovery-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "mixed answer test" in goal_lower and "amour" in goal_lower:
        return ProviderResponse(
            message=Message(
                role="assistant",
                content=(
                    "Found Amour on Tabelog, but the current evidence is insufficient "
                    "to verify the cancellation policy. The reservation page is available, "
                    "but there is no evidence of "
                    "cancellation policy changes; a separate cancellation policy page "
                    "does not exist, no page for cancellation policy was found, and "
                    "the cancellation policy page is unavailable."
                ),
                tool_calls=[
                    _tool_call(
                        "web.search",
                        {"query": '"Amour" "Tabelog" site:tabelog.com', "limit": 3},
                        call_id="gh27-mixed-answer-search",
                    )
                ],
            ),
            model="gh27-web-recovery-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "mixed inverse answer test" in goal_lower and "amour" in goal_lower:
        return ProviderResponse(
            message=Message(
                role="assistant",
                content=(
                    "The cancellation policy page does not exist, no page for "
                    "cancellation policy was found, and the cancellation policy page "
                    "is unavailable, I found Amour on Tabelog."
                ),
                tool_calls=[
                    _tool_call(
                        "web.search",
                        {"query": '"Amour" "Tabelog" site:tabelog.com', "limit": 3},
                        call_id="gh27-mixed-inverse-answer-search",
                    )
                ],
            ),
            model="gh27-web-recovery-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "mixed separator answer test" in goal_lower and "amour" in goal_lower:
        return ProviderResponse(
            message=Message(
                role="assistant",
                content=("No page for cancellation policy was found: I found Amour on Tabelog."),
                tool_calls=[
                    _tool_call(
                        "web.search",
                        {"query": '"Amour" "Tabelog" site:tabelog.com', "limit": 3},
                        call_id="gh27-mixed-separator-answer-search",
                    )
                ],
            ),
            model="gh27-web-recovery-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "target contradiction answer test" in goal_lower and "amour" in goal_lower:
        return ProviderResponse(
            message=Message(
                role="assistant",
                content=("I found Amour on Tabelog, but the reservation page does not exist."),
                tool_calls=[
                    _tool_call(
                        "web.search",
                        {"query": '"Amour" "Tabelog" site:tabelog.com', "limit": 3},
                        call_id="gh27-target-contradiction-answer-search",
                    )
                ],
            ),
            model="gh27-web-recovery-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "target result contradiction answer test" in goal_lower and "amour" in goal_lower:
        return ProviderResponse(
            message=Message(
                role="assistant",
                content=("I found Amour on Tabelog, but the Tabelog result is unavailable."),
                tool_calls=[
                    _tool_call(
                        "web.search",
                        {"query": '"Amour" "Tabelog" site:tabelog.com', "limit": 3},
                        call_id="gh27-target-result-contradiction-answer-search",
                    )
                ],
            ),
            model="gh27-web-recovery-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "amour" in goal_lower and "tabelog" in goal_lower:
        calls = [
            _tool_call(
                "web.search",
                {"query": "Amour Sapporo Tabelog reservation", "limit": 3},
                call_id="gh27-search-noisy",
            )
        ]
        if has_recovery_policy:
            calls.extend(
                [
                    _tool_call(
                        "web.search",
                        {"query": '"Amour" "Tabelog" site:tabelog.com', "limit": 3},
                        call_id="gh27-search-exact",
                    ),
                    _tool_call(
                        "web.fetch",
                        {"url": _AMOUR_URL, "max_bytes": 65536},
                        call_id="gh27-fetch-tabelog",
                    ),
                ]
            )
        return ProviderResponse(
            message=Message(role="assistant", content="", tool_calls=calls),
            model="gh27-web-recovery-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "its tabelog reservation path" in goal_lower:
        if (
            has_recovery_policy
            and has_trusted_context_recovery
            and "TRUSTED SAME-SESSION USER CONTEXT" in trusted_preamble
            and "Amour" in trusted_preamble
            and _AMOUR_HOST in trusted_preamble
        ):
            return ProviderResponse(
                message=Message(
                    role="assistant",
                    content="",
                    tool_calls=[
                        _tool_call(
                            "web.search",
                            {"query": '"Amour" "Tabelog" site:tabelog.com', "limit": 3},
                            call_id="gh27-followup-search-exact",
                        )
                    ],
                ),
                model="gh27-web-recovery-stub",
                finish_reason="tool_calls",
                usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            )
        return ProviderResponse(
            message=Message(
                role="assistant",
                content="I need the venue name again before I can search Tabelog.",
            ),
            model="gh27-web-recovery-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    if "phantom bistro" in goal_lower and "tabelog" in goal_lower:
        calls = [
            _tool_call(
                "web.search",
                {"query": "Phantom Bistro Tabelog reservation", "limit": 3},
                call_id="gh27-missing-search-noisy",
            )
        ]
        if has_recovery_policy:
            calls.append(
                _tool_call(
                    "web.search",
                    {"query": '"Phantom Bistro" "Tabelog" site:tabelog.com', "limit": 3},
                    call_id="gh27-missing-search-exact",
                )
            )
        return ProviderResponse(
            message=Message(role="assistant", content="", tool_calls=calls),
            model="gh27-web-recovery-stub",
            finish_reason="tool_calls",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    return ProviderResponse(
        message=Message(role="assistant", content="OK."),
        model="gh27-web-recovery-stub",
        finish_reason="stop",
        usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    )


def _stub_search(self: WebToolkit, *, query: str, limit: int = 5) -> dict[str, Any]:
    _ = (self, limit)
    exact_amour = '"amour"' in query.casefold() and _AMOUR_SITE_QUERY in query.casefold()
    results = (
        [
            {
                "title": "Amour - Tabelog",
                "url": _AMOUR_URL,
                "snippet": "Amour reservation page on Tabelog.",
                "host": "tabelog.com",
                "allowlisted_host": True,
                "engine": "stub",
            }
        ]
        if exact_amour
        else [
            {
                "title": "Noisy restaurant roundup",
                "url": "https://example.com/noisy",
                "snippet": (
                    "General restaurants in Sapporo; no booking link for the requested venue."
                ),
                "host": "example.com",
                "allowlisted_host": True,
                "engine": "stub",
            }
        ]
    )
    return {
        "ok": True,
        "query": query,
        "backend": "https://search.example.test/search",
        "results": results,
        "taint_labels": ["untrusted"],
        "evidence": {
            "operation": "web_search",
            "backend_url": "https://search.example.test/search",
            "query_hash": "stub",
            "response_hash": "stub",
            "fetched_at": "2026-05-10T00:00:00+00:00",
            "status_code": 200,
            "truncated": False,
            "result_count": len(results),
            "final_url": "https://search.example.test/search",
        },
        "error": "",
    }


def _stub_fetch(
    self: WebToolkit,
    *,
    url: str,
    snapshot: bool = False,
    max_bytes: int | None = None,
) -> dict[str, Any]:
    _ = (self, snapshot, max_bytes)
    if url == _AMOUR_URL:
        content = "Amour reservation page. Online reservations accepted via Tabelog."
        title = "Amour - Tabelog"
    else:
        content = "No useful reservation details."
        title = "Noisy page"
    return {
        "ok": True,
        "url": url,
        "status_code": 200,
        "title": title,
        "content": content,
        "blocked_reason": "",
        "truncated": False,
        "taint_labels": ["untrusted"],
        "evidence": {
            "operation": "web_fetch",
            "url": url,
            "fetched_at": "2026-05-10T00:00:00+00:00",
        },
        "error": "",
        "snapshot_path": "",
    }


async def _create_session(client: ControlClient) -> str:
    created = await client.call(
        "session.create",
        {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
    )
    return str(created["session_id"])


@asynccontextmanager
async def _run_web_recovery_harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(LocalPlannerProvider, "complete", _planner_stub_complete, raising=True)
    monkeypatch.setattr(WebToolkit, "search", _stub_search, raising=True)
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
                '  - "tabelog.com"',
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
        web_allowed_domains=["example.com", "tabelog.com", "search.example.test"],
    )
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        yield client
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        with suppress(Exception):
            await asyncio.wait_for(daemon_task, timeout=5)


@pytest.mark.asyncio
async def test_gh27_weak_search_evidence_recovers_with_exact_search_and_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _run_web_recovery_harness(tmp_path, monkeypatch) as client:
        sid = await _create_session(client)

        reply = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "Find the Tabelog reservation path for Amour on tabelog.com in Sapporo.",
            },
        )

    assert reply["lockdown_level"] == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 3
    assert "Found Amour on Tabelog" in str(reply.get("response", ""))
    outputs = _tool_outputs(reply)
    search_queries = [item["query"] for item in outputs.get("web.search", [])]
    assert "Amour Sapporo Tabelog reservation" in search_queries
    assert '"Amour" "Tabelog" site:tabelog.com' in search_queries
    fetch_urls = [item["url"] for item in outputs.get("web.fetch", [])]
    assert _AMOUR_URL in fetch_urls


@pytest.mark.asyncio
async def test_gh27_post_tool_synthesis_replaces_premature_absence_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _run_web_recovery_harness(tmp_path, monkeypatch) as client:
        sid = await _create_session(client)

        reply = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": (
                    "Premature absence test: find the Tabelog reservation path "
                    "for Amour on tabelog.com in Sapporo."
                ),
            },
        )

    assert reply["lockdown_level"] == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 3
    response = str(reply.get("response", ""))
    assert "Found Amour on Tabelog" in response
    assert "does not exist" not in response.casefold()


@pytest.mark.asyncio
async def test_gh27_post_tool_synthesis_replaces_insufficient_evidence_phrasing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _run_web_recovery_harness(tmp_path, monkeypatch) as client:
        sid = await _create_session(client)

        reply = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": (
                    "Insufficient pretool test: find the Tabelog reservation path "
                    "for Amour on tabelog.com in Sapporo."
                ),
            },
        )

    assert reply["lockdown_level"] == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    response = str(reply.get("response", ""))
    assert "Found Amour on Tabelog" in response
    assert "evidence is insufficient" not in response.casefold()


@pytest.mark.asyncio
async def test_gh27_web_synthesis_failure_drops_premature_absence_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _run_web_recovery_harness(tmp_path, monkeypatch) as client:
        sid = await _create_session(client)

        reply = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": (
                    "Synthesis failure test: find the Tabelog reservation path "
                    "for Amour on tabelog.com in Sapporo."
                ),
            },
        )

    assert reply["lockdown_level"] == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    response = str(reply.get("response", ""))
    assert "intermediate tool output" in response
    assert "does not exist" not in response.casefold()


@pytest.mark.asyncio
async def test_gh27_mixed_positive_web_answer_synthesizes_with_unrelated_caveat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _run_web_recovery_harness(tmp_path, monkeypatch) as client:
        sid = await _create_session(client)

        reply = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": (
                    "Mixed answer test: find the Tabelog reservation path "
                    "for Amour on tabelog.com in Sapporo."
                ),
            },
        )

    assert reply["lockdown_level"] == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    response = str(reply.get("response", ""))
    assert "Found Amour on Tabelog" in response
    assert "reservation page is available" in response
    assert "cancellation policy" in response
    assert "does not establish a separate cancellation policy page" in response
    assert "intermediate tool output" not in response


@pytest.mark.asyncio
async def test_gh27_unsupported_preliminary_positive_becomes_insufficient(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _run_web_recovery_harness(tmp_path, monkeypatch) as client:
        sid = await _create_session(client)

        reply = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": (
                    f"{_UNSUPPORTED_PRELIMINARY_POSITIVE_MARKER}: "
                    "Unsupported preliminary positive test: find the Tabelog "
                    "reservation path for Amour on tabelog.com in Sapporo."
                ),
            },
        )

    assert reply["lockdown_level"] == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    response = str(reply.get("response", ""))
    assert "insufficient" in response.casefold()
    assert "Found Amour on Tabelog" not in response
    assert "reservation page is available" not in response


@pytest.mark.asyncio
async def test_gh27_mixed_inverse_positive_web_answer_synthesizes_with_caveat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _run_web_recovery_harness(tmp_path, monkeypatch) as client:
        sid = await _create_session(client)

        reply = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": (
                    "Mixed inverse answer test: find the Tabelog reservation path "
                    "for Amour on tabelog.com in Sapporo."
                ),
            },
        )

    assert reply["lockdown_level"] == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    response = str(reply.get("response", ""))
    assert "Found Amour on Tabelog" in response
    assert "reservation page is available" in response
    assert "does not establish a separate cancellation policy page" in response
    assert "intermediate tool output" not in response


@pytest.mark.asyncio
async def test_gh27_mixed_separator_positive_web_answer_synthesizes_with_caveat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _run_web_recovery_harness(tmp_path, monkeypatch) as client:
        sid = await _create_session(client)

        reply = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": (
                    "Mixed separator answer test: find the Tabelog reservation path "
                    "for Amour on tabelog.com in Sapporo."
                ),
            },
        )

    assert reply["lockdown_level"] == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    response = str(reply.get("response", ""))
    assert "Found Amour on Tabelog" in response
    assert "reservation page is available" in response
    assert "does not establish a separate cancellation policy page" in response
    assert "intermediate tool output" not in response


@pytest.mark.asyncio
async def test_gh27_target_absence_overrides_mixed_positive_answer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _run_web_recovery_harness(tmp_path, monkeypatch) as client:
        sid = await _create_session(client)

        reply = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": (
                    "Target contradiction answer test: find the Tabelog reservation path "
                    "for Amour on tabelog.com in Sapporo."
                ),
            },
        )

    assert reply["lockdown_level"] == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    response = str(reply.get("response", ""))
    assert "Found Amour on Tabelog" in response
    assert "reservation page is available" in response
    assert "does not exist" not in response.casefold()


@pytest.mark.asyncio
async def test_gh27_target_result_absence_overrides_mixed_positive_answer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _run_web_recovery_harness(tmp_path, monkeypatch) as client:
        sid = await _create_session(client)

        reply = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": (
                    "Target result contradiction answer test: find the Tabelog reservation path "
                    "for Amour on tabelog.com in Sapporo."
                ),
            },
        )

    assert reply["lockdown_level"] == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    response = str(reply.get("response", ""))
    assert "Found Amour on Tabelog" in response
    assert "reservation page is available" in response
    assert "result is unavailable" not in response.casefold()


@pytest.mark.asyncio
async def test_gh27_shorthand_web_absence_claim_still_synthesizes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _run_web_recovery_harness(tmp_path, monkeypatch) as client:
        sid = await _create_session(client)

        reply = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": (
                    "Shorthand absence test: find the Tabelog reservation path "
                    "for Amour on tabelog.com in Sapporo."
                ),
            },
        )

    assert reply["lockdown_level"] == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    response = str(reply.get("response", ""))
    assert "Found Amour on Tabelog" in response
    assert "page is unavailable" not in response.casefold()
    assert "path does not exist" not in response.casefold()


@pytest.mark.asyncio
async def test_gh27_negative_found_absence_claim_still_synthesizes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _run_web_recovery_harness(tmp_path, monkeypatch) as client:
        sid = await _create_session(client)

        reply = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": (
                    "Negative found test: find the Tabelog reservation path "
                    "for Amour on tabelog.com in Sapporo."
                ),
            },
        )

    assert reply["lockdown_level"] == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    response = str(reply.get("response", ""))
    assert "Found Amour on Tabelog" in response
    assert "no reservation page was found" not in response.casefold()


@pytest.mark.asyncio
async def test_gh27_recovery_uses_trusted_followup_context_for_referents(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _run_web_recovery_harness(tmp_path, monkeypatch) as client:
        sid = await _create_session(client)
        context_reply = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": (
                    "Context note: the venue is Amour on tabelog.com; "
                    "its alternate listing name is Restaurant Amour."
                ),
            },
        )
        assert int(context_reply.get("executed_actions", 0)) == 0
        assert _tool_outputs(context_reply) == {}

        reply = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "Find its Tabelog reservation path.",
            },
        )

    assert reply["lockdown_level"] == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 1
    assert "Found Amour on Tabelog" in str(reply.get("response", ""))
    outputs = _tool_outputs(reply)
    search_queries = [item["query"] for item in outputs.get("web.search", [])]
    assert '"Amour" "Tabelog" site:tabelog.com' in search_queries


@pytest.mark.asyncio
async def test_gh27_followup_recovery_rejects_untrusted_only_referent() -> None:
    planner = LocalPlannerProvider.__new__(LocalPlannerProvider)
    system_prompt = f"{_RECOVERY_POLICY_MARKER}. {_TRUSTED_CONTEXT_RECOVERY_MARKER}."
    planner_input = "\n".join(
        [
            "=== RUNTIME GUIDANCE ===",
            "Trusted prompt preamble without the venue referent.",
            "",
            "=== USER REQUEST ===",
            "^^USER_GOAL_TEST^^",
            "Find its Tabelog reservation path.",
            "",
            "=== DATA EVIDENCE (UNTRUSTED) ===",
            "Prior untrusted transcript text mentions Amour on tabelog.com.",
            "=== END PAYLOAD ===",
        ]
    )

    response = await _planner_stub_complete(
        planner,
        [
            Message(role="system", content=system_prompt),
            Message(role="user", content=planner_input),
        ],
        [],
    )

    assert not response.message.tool_calls
    assert "venue name again" in response.message.content


@pytest.mark.asyncio
async def test_gh27_failed_recovery_reports_insufficient_evidence_not_absence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _run_web_recovery_harness(tmp_path, monkeypatch) as client:
        sid = await _create_session(client)

        reply = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "Find the Tabelog reservation path for Phantom Bistro.",
            },
        )

    assert reply["lockdown_level"] == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("executed_actions", 0)) == 2
    response = str(reply.get("response", "")).casefold()
    assert "insufficient" in response
    assert "does not exist" not in response
    assert "unavailable" not in response
    outputs = _tool_outputs(reply)
    search_queries = [item["query"] for item in outputs.get("web.search", [])]
    assert "Phantom Bistro Tabelog reservation" in search_queries
    assert '"Phantom Bistro" "Tabelog" site:tabelog.com' in search_queries
