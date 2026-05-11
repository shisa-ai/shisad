"""Behavioral coverage for large fetched-page evidence extraction."""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Any

import pytest

import shisad.assistant.web as web_module
from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.core.providers.base import Message, ProviderResponse
from shisad.core.providers.local_planner import LocalPlannerProvider
from shisad.daemon.runner import run_daemon
from shisad.memory.summarizer import _SUMMARY_SYSTEM_PROMPT
from tests.helpers.behavioral import extract_tool_outputs
from tests.helpers.daemon import wait_for_socket as _wait_for_socket

_SUMMARY_SYSTEM_MARKER = _SUMMARY_SYSTEM_PROMPT.split(". ")[0] + "."
_FETCH_URL = "https://tabelog.com/hokkaido/A0101/A010101/123456/"
_ENGLISH_MARKER_URL = "https://tabelog.com/hokkaido/A0101/A010101/english-marker/"
_TITLE_ONLY_MARKER_URL = "https://tabelog.com/hokkaido/A0101/A010101/title-only-marker/"
_NO_MARKER_URL = "https://tabelog.com/hokkaido/A0101/A010101/no-marker/"
_RESERVATION_MARKERS = ("本日夜空席あり", "ネット予約")
_ENGLISH_RESERVATION_MARKER = "Reserve Online"
_TITLE_ONLY_RESERVATION_MARKER = "Reserve Online | Venue"


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
    marker = "=== USER REQUEST ==="
    if marker not in normalized:
        return normalized
    remainder = normalized.split(marker, 1)[1]
    return remainder.split("===", 1)[0].strip()


async def _planner_stub_complete(
    self: LocalPlannerProvider,
    messages: list[Message],
    tools: list[dict[str, Any]] | None = None,
) -> ProviderResponse:
    _ = (self, tools)
    if (
        messages
        and messages[0].role == "system"
        and _SUMMARY_SYSTEM_MARKER in messages[0].content
    ):
        return ProviderResponse(
            message=Message(role="assistant", content='{"entries": []}'),
            model="gh28-fetch-extraction-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    planner_input = messages[-1].content if messages else ""
    normalized_input = planner_input.replace("^", "")
    if "POST-TOOL SYNTHESIS PASS" in normalized_input:
        if (
            "actionable_evidence_snippets" in normalized_input
            and all(marker in normalized_input for marker in _RESERVATION_MARKERS)
        ):
            response = "Fetched evidence says 本日夜空席あり and ネット予約 are shown."
        elif (
            "actionable_evidence_snippets" in normalized_input
            and (
                _ENGLISH_RESERVATION_MARKER in normalized_input
                or _ENGLISH_RESERVATION_MARKER.casefold() in normalized_input.casefold()
            )
        ):
            response = "Fetched evidence says Reserve Online is shown."
        elif (
            _TITLE_ONLY_RESERVATION_MARKER in normalized_input
            and "page title" in normalized_input.casefold()
        ):
            response = f"The page title is {_TITLE_ONLY_RESERVATION_MARKER}."
        elif _TITLE_ONLY_RESERVATION_MARKER in normalized_input:
            response = "Fetched evidence used the title-only reservation marker."
        else:
            response = "The current evidence is insufficient; the fetched page was too large."
        return ProviderResponse(
            message=Message(role="assistant", content=response),
            model="gh28-fetch-extraction-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    goal = _extract_user_request(planner_input).lower()
    if "without reservation markers" in goal:
        url = _NO_MARKER_URL
    elif "page title" in goal or "title-only reservation marker" in goal:
        url = _TITLE_ONLY_MARKER_URL
    elif "english reservation marker" in goal:
        url = _ENGLISH_MARKER_URL
    elif "reservation availability" in goal:
        url = _FETCH_URL
    else:
        return ProviderResponse(
            message=Message(role="assistant", content="OK."),
            model="gh28-fetch-extraction-stub",
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )
    return ProviderResponse(
        message=Message(
            role="assistant",
            content="",
            tool_calls=[
                _tool_call(
                    "web.fetch",
                    {"url": url, "max_bytes": 60000},
                    call_id="gh28-fetch-large-page",
                )
            ],
        ),
        model="gh28-fetch-extraction-stub",
        finish_reason="tool_calls",
        usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    )


def _large_tabelog_html(*, include_markers: bool) -> bytes:
    filler_before = "レストラン紹介 " * 1600
    if include_markers:
        target = (
            '<section class="reservation">'
            "予約カレンダー 本日夜空席あり。ネット予約で席を確保できます。"
            "</section>"
        )
    else:
        target = '<section class="profile">店舗紹介のみ。予約状況の表示はありません。</section>'
    filler_after = " メニュー説明" * 2000
    html = (
        "<html><title>Amour - Tabelog</title><body>"
        f"{filler_before}{target}{filler_after}"
        "</body></html>"
    )
    return html.encode("utf-8")


def _large_english_marker_html() -> bytes:
    filler_before = "restaurant profile " * 900
    target = (
        '<section class="reservation">'
        "Booking calendar: Reserve On<span>line</span> from this page."
        "</section>"
    )
    filler_after = " menu details" * 7000
    html = (
        "<html><title>Amour - Tabelog</title><body>"
        f"{filler_before}{target}{filler_after}"
        "</body></html>"
    )
    return html.encode("utf-8")


def _title_only_marker_html() -> bytes:
    html = (
        "<html><head><title>Reserve Online | Venue</title></head>"
        "<body>Profile only. No booking calendar is shown here.</body></html>"
    )
    return html.encode("utf-8")


class _FakeHttpResponse:
    def __init__(self, body: bytes, url: str) -> None:
        self._body = body
        self._offset = 0
        self.status = 200
        self.headers = {"Content-Type": "text/html; charset=utf-8"}
        self._url = url

    def __enter__(self) -> _FakeHttpResponse:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        return None

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = len(self._body) - self._offset
        chunk = self._body[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk

    def geturl(self) -> str:
        return self._url


def _fake_open_no_redirect(request, *, timeout: float):  # type: ignore[no-untyped-def]
    _ = timeout
    url = str(getattr(request, "full_url", ""))
    if "english-marker" in url:
        body = _large_english_marker_html()
    elif "title-only-marker" in url:
        body = _title_only_marker_html()
    else:
        body = _large_tabelog_html(include_markers="no-marker" not in url)
    return _FakeHttpResponse(body, url)


@asynccontextmanager
async def _run_fetch_extraction_harness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(LocalPlannerProvider, "complete", _planner_stub_complete, raising=True)
    monkeypatch.setattr(web_module, "_open_no_redirect", _fake_open_no_redirect, raising=True)
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
        web_search_enabled=False,
        web_allowed_domains=["tabelog.com"],
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


async def _create_session(client: ControlClient) -> str:
    created = await client.call(
        "session.create",
        {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
    )
    return str(created["session_id"])


@pytest.mark.asyncio
async def test_gh28_large_fetch_surfaces_japanese_reservation_markers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _run_fetch_extraction_harness(tmp_path, monkeypatch) as client:
        sid = await _create_session(client)

        reply = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": f"Check reservation availability on the Tabelog page {_FETCH_URL}.",
            },
        )

    assert int(reply.get("executed_actions", 0)) == 1
    response = str(reply.get("response", ""))
    assert "本日夜空席あり" in response
    assert "ネット予約" in response
    assert "too large" not in response
    outputs = extract_tool_outputs(reply)
    fetch_payload = outputs["web.fetch"][0]
    assert fetch_payload["truncated"] is True
    assert fetch_payload["taint_labels"] == ["untrusted"]
    assert "本日夜空席あり" not in fetch_payload["content"]
    assert "actionable_evidence_snippets" in fetch_payload


@pytest.mark.asyncio
async def test_gh28_large_fetch_surfaces_english_reservation_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _run_fetch_extraction_harness(tmp_path, monkeypatch) as client:
        sid = await _create_session(client)

        reply = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": (
                    "Check the english reservation marker on the Tabelog page "
                    f"{_ENGLISH_MARKER_URL}."
                ),
            },
        )

    assert int(reply.get("executed_actions", 0)) == 1
    response = str(reply.get("response", ""))
    assert "Reserve Online" in response
    assert "too large" not in response
    outputs = extract_tool_outputs(reply)
    fetch_payload = outputs["web.fetch"][0]
    assert fetch_payload["truncated"] is True
    assert fetch_payload["taint_labels"] == ["untrusted"]
    assert "Reserve Online" not in fetch_payload["content"]
    assert "actionable_evidence_snippets" in fetch_payload


@pytest.mark.asyncio
async def test_gh28_title_only_marker_does_not_drive_final_answer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _run_fetch_extraction_harness(tmp_path, monkeypatch) as client:
        sid = await _create_session(client)

        reply = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": (
                    "Check the title-only reservation marker on the Tabelog page "
                    f"{_TITLE_ONLY_MARKER_URL}."
                ),
            },
        )

    assert int(reply.get("executed_actions", 0)) == 1
    response = str(reply.get("response", ""))
    assert "insufficient" in response.casefold()
    assert "title-only reservation marker" not in response
    outputs = extract_tool_outputs(reply)
    fetch_payload = outputs["web.fetch"][0]
    assert fetch_payload["title"] == _TITLE_ONLY_RESERVATION_MARKER
    assert "actionable_evidence_snippets" not in fetch_payload


@pytest.mark.asyncio
async def test_gh28_user_requested_page_title_still_uses_fetch_title_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _run_fetch_extraction_harness(tmp_path, monkeypatch) as client:
        sid = await _create_session(client)

        reply = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": (
                    "Fetch the Tabelog page "
                    f"{_TITLE_ONLY_MARKER_URL} and tell me the page title."
                ),
            },
        )

    assert int(reply.get("executed_actions", 0)) == 1
    response = str(reply.get("response", ""))
    assert _TITLE_ONLY_RESERVATION_MARKER in response
    outputs = extract_tool_outputs(reply)
    fetch_payload = outputs["web.fetch"][0]
    assert fetch_payload["title"] == _TITLE_ONLY_RESERVATION_MARKER


@pytest.mark.asyncio
async def test_gh28_large_fetch_without_markers_reports_insufficient(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _run_fetch_extraction_harness(tmp_path, monkeypatch) as client:
        sid = await _create_session(client)

        reply = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": (
                    "Check reservation availability without reservation markers "
                    f"on {_NO_MARKER_URL}."
                ),
            },
        )

    assert int(reply.get("executed_actions", 0)) == 1
    response = str(reply.get("response", "")).casefold()
    assert "insufficient" in response
    assert "本日夜空席あり" not in str(reply.get("response", ""))
    assert "ネット予約" not in str(reply.get("response", ""))
    outputs = extract_tool_outputs(reply)
    assert "actionable_evidence_snippets" not in outputs["web.fetch"][0]
