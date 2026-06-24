"""Tests for shisad.ui.chat — interactive chat TUI."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from textual.widgets import Markdown, TextArea

from shisad.core.api.transport import JsonRpcCallError
from shisad.ui.chat import ChatApp, format_assistant_message, format_user_message


def _rendered_static_texts(app: ChatApp, selector: str) -> list[str]:
    return [
        str(widget.renderable)
        for widget in app.query(selector)
        if hasattr(widget, "renderable")
    ]

# ---------------------------------------------------------------------------
# Message formatting tests
# ---------------------------------------------------------------------------


def test_format_user_message_contains_content() -> None:
    result = format_user_message("hello world")
    assert "hello world" in result


def test_format_assistant_message_contains_content() -> None:
    result = format_assistant_message("I can help with that.")
    assert "I can help with that." in result


def test_format_user_message_differs_from_assistant() -> None:
    user = format_user_message("test")
    assistant = format_assistant_message("test")
    assert user != assistant


def test_format_user_message_strips_whitespace() -> None:
    result = format_user_message("  hello  ")
    assert "hello" in result


def test_format_assistant_message_handles_empty() -> None:
    result = format_assistant_message("")
    assert isinstance(result, str)


def test_format_assistant_message_renders_literal_newline_escapes() -> None:
    result = format_assistant_message("1. first\\n2. second")

    assert result == "shisad: 1. first\n2. second"
    assert "\\n" not in result


def test_format_assistant_message_promotes_inline_bullets_to_markdown_list() -> None:
    result = format_assistant_message("I can help with: - Read files - Search the web")

    assert result == "shisad: I can help with:\n\n- Read files\n- Search the web"


def test_format_assistant_message_keeps_non_list_hyphens_inline() -> None:
    result = format_assistant_message("Range: 1 - 2 and alpha - beta")

    assert result == "shisad: Range: 1 - 2 and alpha - beta"


def test_format_assistant_message_does_not_split_year_in_list_item() -> None:
    result = format_assistant_message(
        "Highlights: - Released in 2024. It supports X - Next item"
    )

    assert "2024. It supports X" in result
    assert result == "shisad: Highlights:\n\n- Released in 2024. It supports X\n- Next item"


def test_format_assistant_message_does_not_split_digit_hyphen_range_in_item() -> None:
    result = format_assistant_message(
        "Options: - Range is 1 - 10 for this setting - Another option"
    )

    assert "1 - 10" in result
    assert result == (
        "shisad: Options:\n\n- Range is 1 - 10 for this setting\n- Another option"
    )


def test_format_assistant_message_does_not_rewrite_fenced_code() -> None:
    result = format_assistant_message("```\nItems: - one - two\n```")

    assert result == "shisad: ```\nItems: - one - two\n```"


def test_format_assistant_message_inserts_blank_line_before_markdown_headings() -> None:
    result = format_assistant_message(
        "Quantization means using lower-precision numbers.\n"
        "## Quantization in machine learning\n"
        "Weights and activations can both be quantized.\n"
        "### Practical tradeoffs\n"
        "Lower precision can reduce memory use."
    )

    assert result == (
        "shisad: Quantization means using lower-precision numbers.\n\n"
        "## Quantization in machine learning\n"
        "Weights and activations can both be quantized.\n\n"
        "### Practical tradeoffs\n"
        "Lower precision can reduce memory use."
    )


def test_format_assistant_message_keeps_existing_heading_block_spacing() -> None:
    result = format_assistant_message(
        "Intro paragraph.\n\n## Already separate\nBody text."
    )

    assert result == "shisad: Intro paragraph.\n\n## Already separate\nBody text."


def test_format_assistant_message_does_not_rewrite_fenced_code_headings() -> None:
    result = format_assistant_message(
        "Example:\n"
        "```\n"
        "value\n"
        "## Not a markdown heading here\n"
        "```\n"
        "Done.\n"
        "## Real heading"
    )

    assert result == (
        "shisad: Example:\n"
        "```\n"
        "value\n"
        "## Not a markdown heading here\n"
        "```\n"
        "Done.\n\n"
        "## Real heading"
    )


def test_format_assistant_message_skips_normalizer_for_pending_previews() -> None:
    result = format_assistant_message(
        "[PENDING CONFIRMATIONS]\n"
        "Queued for your approval:\n"
        "1. c-1\n"
        "   Preview:\n"
        "     body: - one - two\n\n"
        "Review all pending: shisad action list",
        preserve_pending_preview_escapes=True,
    )

    assert "body: - one - two" in result


def test_format_assistant_message_preserves_pending_preview_linebreak_markers() -> None:
    result = format_assistant_message(
        "[PENDING CONFIRMATIONS]\n"
        "Queued for your approval:\n"
        "1. c-1\n"
        "   Preview:\n"
        "     body: line1\\nline2\n\n"
        "Review all pending: shisad action list",
        preserve_pending_preview_escapes=True,
    )

    assert "body: line1\\nline2" in result
    assert "body: line1\nline2" not in result


def test_format_assistant_message_renders_evidence_ref_block() -> None:
    result = format_assistant_message(
        "[EVIDENCE ref=ev-61f3d4c48f54ff92 source=web.fetch:example.com "
        'taint=UNTRUSTED size=88 summary="Example Domain" '
        'Use evidence.read("ev-61f3d4c48f54ff92") for full content, or '
        'evidence.promote("ev-61f3d4c48f54ff92") to add it to the conversation.]'
    )

    assert result.startswith("shisad:")
    assert "[EVIDENCE ref=" not in result
    assert "[Evidence ev-61f3d4c48f54ff92]" in result


# ---------------------------------------------------------------------------
# ChatApp construction tests
# ---------------------------------------------------------------------------


def test_chat_app_can_be_constructed() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="default",
    )
    assert app._socket_path == Path("/tmp/test.sock")
    assert app._user_id == "ops"
    assert app._workspace_id == "default"
    assert app._session_id is None
    assert app._reuse_bound_session is True


def test_chat_app_with_existing_session() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="default",
        session_id="abc123",
    )
    assert app._session_id == "abc123"


def test_chat_app_bindings_include_new_session_hotkey() -> None:
    keys = {(binding.key, binding.action) for binding in ChatApp.BINDINGS}
    assert ("ctrl+n", "new_session") in keys


def test_chat_app_prompt_history_cycles_through_previous_prompts() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="default",
    )
    app._record_prompt_history("first prompt")
    app._record_prompt_history("second prompt")

    assert app._recall_prompt_history(direction=-1, current_value="") == "second prompt"
    assert app._recall_prompt_history(direction=-1, current_value="") == "first prompt"
    assert app._recall_prompt_history(direction=1, current_value="") == "second prompt"


def test_chat_app_prompt_history_restores_draft_after_navigation() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="default",
    )
    app._record_prompt_history("first prompt")
    app._record_prompt_history("second prompt")

    assert (
        app._recall_prompt_history(direction=-1, current_value="draft message") == "second prompt"
    )
    assert app._recall_prompt_history(direction=1, current_value="ignored") == "draft message"


def test_chat_app_prompt_history_down_without_active_cursor_keeps_current_value() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="default",
    )
    app._record_prompt_history("only prompt")

    assert app._recall_prompt_history(direction=1, current_value="draft") == "draft"


# ---------------------------------------------------------------------------
# RPC integration tests (mocked)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_chat_app_creates_session_on_connect() -> None:
    """When no session_id is provided, _ensure_session should create one."""
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="prod",
    )

    mock_client = AsyncMock()
    mock_client.call = AsyncMock(
        side_effect=[
            {"sessions": []},
            {"session_id": "new-session-id"},
        ]
    )

    await app._ensure_session(mock_client)

    assert mock_client.call.await_count == 2
    first = mock_client.call.await_args_list[0]
    second = mock_client.call.await_args_list[1]
    assert first.args == ("session.list",)
    assert first.kwargs == {"params": {}}
    assert second.args == ("session.create",)
    assert second.kwargs == {"params": {"user_id": "ops", "workspace_id": "prod"}}
    assert app._session_id == "new-session-id"


@pytest.mark.asyncio
async def test_chat_app_skips_create_when_session_exists() -> None:
    """When session_id is provided, _ensure_session should not create."""
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="prod",
        session_id="existing-id",
    )

    mock_client = AsyncMock()
    await app._ensure_session(mock_client)

    mock_client.call.assert_not_called()
    assert app._session_id == "existing-id"


@pytest.mark.asyncio
async def test_chat_app_reuses_existing_session_by_user_workspace_binding() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="prod",
    )
    mock_client = AsyncMock()
    mock_client.call = AsyncMock(
        return_value={
            "sessions": [
                {
                    "id": "active-sid",
                    "state": "active",
                    "channel": "cli",
                    "user_id": "ops",
                    "workspace_id": "prod",
                }
            ]
        }
    )

    await app._ensure_session(mock_client)

    mock_client.call.assert_awaited_once_with("session.list", params={})
    assert app._session_id == "active-sid"


@pytest.mark.asyncio
async def test_chat_app_reuse_emits_lockdown_notice_for_non_normal_session() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="prod",
    )
    appended: list[str] = []
    app._append_history = appended.append  # type: ignore[method-assign]

    mock_client = AsyncMock()
    mock_client.call = AsyncMock(
        return_value={
            "sessions": [
                {
                    "id": "active-sid",
                    "state": "active",
                    "channel": "cli",
                    "user_id": "ops",
                    "workspace_id": "prod",
                    "lockdown_level": "caution",
                }
            ]
        }
    )

    await app._ensure_session(mock_client)

    assert app._session_id == "active-sid"
    assert any("lockdown" in line.lower() and "caution" in line.lower() for line in appended)


@pytest.mark.asyncio
async def test_chat_app_force_new_session_skips_binding_lookup() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="prod",
        reuse_bound_session=False,
    )
    mock_client = AsyncMock()
    mock_client.call = AsyncMock(return_value={"session_id": "fresh-sid"})

    await app._ensure_session(mock_client)

    mock_client.call.assert_awaited_once_with(
        "session.create",
        params={"user_id": "ops", "workspace_id": "prod"},
    )
    assert app._session_id == "fresh-sid"


@pytest.mark.asyncio
async def test_chat_app_send_message_returns_response() -> None:
    """_send_message should call session.message and return the raw response payload."""
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="prod",
        session_id="sess-1",
    )

    mock_client = AsyncMock()
    mock_client.call = AsyncMock(return_value={"response": "Hello from shisad!"})

    result = await app._send_message(mock_client, "hello")

    mock_client.call.assert_called_once_with(
        "session.message",
        params={"session_id": "sess-1", "content": "hello"},
    )
    assert result == {"response": "Hello from shisad!"}


@pytest.mark.asyncio
async def test_chat_app_send_message_creates_session_when_unbound() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="prod",
        reuse_bound_session=False,
    )

    mock_client = AsyncMock()
    mock_client.call = AsyncMock(
        side_effect=[
            {"session_id": "fresh-sid"},
            {"response": "Hello from shisad!"},
        ]
    )

    result = await app._send_message(mock_client, "hello")

    assert result == {"response": "Hello from shisad!"}
    assert app._session_id == "fresh-sid"
    assert mock_client.call.call_args_list[0].args == ("session.create",)
    assert mock_client.call.call_args_list[1].args == ("session.message",)
    assert mock_client.call.call_args_list[1].kwargs == {
        "params": {"session_id": "fresh-sid", "content": "hello"}
    }


@pytest.mark.asyncio
async def test_chat_app_send_message_creates_session_when_local_session_id_blank() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="prod",
        session_id="   ",
        reuse_bound_session=False,
    )

    mock_client = AsyncMock()
    mock_client.call = AsyncMock(
        side_effect=[
            {"session_id": "fresh-sid"},
            {"response": "Hello from shisad!"},
        ]
    )

    result = await app._send_message(mock_client, "hello")

    assert result == {"response": "Hello from shisad!"}
    assert app._session_id == "fresh-sid"
    assert mock_client.call.call_args_list[0].args == ("session.create",)
    assert mock_client.call.call_args_list[1].kwargs == {
        "params": {"session_id": "fresh-sid", "content": "hello"}
    }


def test_chat_app_detects_pending_preview_preservation_from_raw_result() -> None:
    assert ChatApp._preserve_pending_preview_escapes({"pending_confirmation_ids": ["c-1"]}) is True
    assert ChatApp._preserve_pending_preview_escapes({"pending_confirmation_ids": []}) is False


@pytest.mark.asyncio
async def test_chat_app_send_message_handles_missing_response_key() -> None:
    """If the RPC response lacks 'response', raise a protocol error."""
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="prod",
        session_id="sess-1",
    )

    mock_client = AsyncMock()
    mock_client.call = AsyncMock(return_value={"unexpected": "data"})

    with pytest.raises(RuntimeError, match="no response text"):
        await app._send_message(mock_client, "hello")


@pytest.mark.asyncio
async def test_chat_app_send_message_handles_rpc_error() -> None:
    """RPC errors should bubble for red inline error rendering."""
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="prod",
        session_id="sess-1",
    )

    mock_client = AsyncMock()
    mock_client.call = AsyncMock(side_effect=OSError("connection refused"))

    with pytest.raises(OSError, match="connection refused"):
        await app._send_message(mock_client, "hello")


@pytest.mark.asyncio
async def test_chat_app_ensure_session_requires_nonempty_session_id() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="prod",
    )

    mock_client = AsyncMock()
    mock_client.call = AsyncMock(return_value={"session_id": ""})

    with pytest.raises(RuntimeError, match="invalid session_id"):
        await app._ensure_session(mock_client)


@pytest.mark.asyncio
async def test_chat_app_send_message_rejects_non_mapping_payload() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="prod",
        session_id="sess-1",
    )

    mock_client = AsyncMock()
    mock_client.call = AsyncMock(return_value="not-json-object")

    with pytest.raises(RuntimeError, match=r"Invalid session\.message response type"):
        await app._send_message(mock_client, "hello")


@pytest.mark.asyncio
async def test_chat_app_create_new_session_calls_session_create() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="prod",
        session_id="existing-id",
    )

    mock_client = AsyncMock()
    mock_client.call = AsyncMock(return_value={"session_id": "fresh-id"})

    await app._create_new_session(mock_client)

    mock_client.call.assert_awaited_once_with(
        "session.create",
        params={"user_id": "ops", "workspace_id": "prod"},
    )
    assert app._session_id == "fresh-id"


# ---------------------------------------------------------------------------
# Session recovery tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_chat_app_recovers_from_unknown_session() -> None:
    """When daemon restarts, _send_message should create a new session and retry."""
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="prod",
        session_id="stale-id",
    )

    mock_client = AsyncMock()
    # First call: session.message fails with unknown session
    # Second call: session.list reports no reusable binding
    # Third call: session.create returns new session
    # Fourth call: session.message succeeds with new session
    mock_client.call = AsyncMock(
        side_effect=[
            Exception("RPC error -32602: Unknown session: stale-id"),
            {"sessions": []},
            {"session_id": "new-session-id"},
            {"response": "Hello!"},
        ]
    )

    def fail_prime() -> None:
        raise OSError("transcript temporarily unavailable")

    app._prime_transcript_display_state = fail_prime  # type: ignore[method-assign]

    result = await app._send_message(mock_client, "hello")

    assert result == {"response": "Hello!"}
    assert app._session_id == "new-session-id"
    assert mock_client.call.call_count == 4


@pytest.mark.asyncio
async def test_chat_app_recovery_only_retries_once() -> None:
    """If the retry also fails, raise and stop retrying."""
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="prod",
        session_id="stale-id",
    )

    mock_client = AsyncMock()
    mock_client.call = AsyncMock(
        side_effect=[
            Exception("RPC error -32602: Unknown session: stale-id"),
            {"sessions": []},
            {"session_id": "new-id"},
            Exception("RPC error -32602: Unknown session: new-id"),
        ]
    )

    with pytest.raises(RuntimeError, match="Unknown session: new-id"):
        await app._send_message(mock_client, "hello")


@pytest.mark.asyncio
async def test_chat_app_recovery_sets_reconnected_flag() -> None:
    """After recovery, _reconnected should be True for notice display."""
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="prod",
        session_id="stale-id",
    )

    mock_client = AsyncMock()
    mock_client.call = AsyncMock(
        side_effect=[
            Exception("RPC error -32602: Unknown session: stale-id"),
            {"sessions": []},
            {"session_id": "new-id"},
            {"response": "Hi!"},
        ]
    )

    assert not app._reconnected
    await app._send_message(mock_client, "hello")
    assert app._reconnected


@pytest.mark.asyncio
async def test_chat_app_recovers_from_session_expired_variant() -> None:
    """Recovery should match RPC shape/code, not a single literal phrase."""
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="prod",
        session_id="stale-id",
    )

    mock_client = AsyncMock()
    mock_client.call = AsyncMock(
        side_effect=[
            RuntimeError("RPC error -32602: Session no longer exists: stale-id"),
            {"sessions": []},
            {"session_id": "new-id"},
            {"response": "Recovered"},
        ]
    )

    result = await app._send_message(mock_client, "hello")
    assert result == {"response": "Recovered"}
    assert app._session_id == "new-id"
    assert app._reconnected is True


@pytest.mark.asyncio
async def test_chat_app_recovers_from_session_id_validation_error_shape() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="prod",
        session_id="stale-id",
    )

    mock_client = AsyncMock()
    mock_client.call = AsyncMock(
        side_effect=[
            JsonRpcCallError(
                code=-32602,
                message=(
                    "1 validation error for SessionMessageParams\n"
                    "session_id\n"
                    "  Input should be a valid string"
                ),
            ),
            {"sessions": []},
            {"session_id": "new-id"},
            {"response": "Recovered"},
        ]
    )

    result = await app._send_message(mock_client, "hello")

    assert result == {"response": "Recovered"}
    assert app._session_id == "new-id"
    assert app._reconnected is True
    assert mock_client.call.call_args_list[3].kwargs == {
        "params": {"session_id": "new-id", "content": "hello"}
    }


@pytest.mark.asyncio
async def test_chat_app_subtitle_shows_connected_after_mount() -> None:
    """Mounted app should set a stable non-session-id subtitle."""
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="default",
    )
    fake_client = AsyncMock()
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]

    async with app.run_test() as pilot:
        await pilot.pause()
        await asyncio.sleep(0)

    assert app.sub_title == "connected"
    assert "ff0225da" not in app.sub_title


@pytest.mark.asyncio
async def test_chat_app_mount_treats_transcript_poll_errors_as_nonfatal() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="default",
    )
    fake_client = AsyncMock()
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]

    def fail_prime() -> None:
        raise OSError("transcript temporarily unavailable")

    def fail_poll() -> None:
        raise OSError("transcript temporarily unavailable")

    app._prime_transcript_display_state = fail_prime  # type: ignore[method-assign]
    app._poll_transcript_for_async_messages = fail_poll  # type: ignore[method-assign]

    async with app.run_test() as pilot:
        await pilot.pause()
        await asyncio.sleep(0)

    assert app.sub_title == "connected"


@pytest.mark.asyncio
async def test_chat_app_new_session_keeps_created_session_when_poll_fails() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="default",
        session_id="old-session",
    )
    fake_client = AsyncMock()
    fake_client.call = AsyncMock(return_value={"session_id": "new-session"})
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]

    def fail_prime() -> None:
        raise OSError("transcript temporarily unavailable")

    def fail_poll() -> None:
        raise OSError("transcript temporarily unavailable")

    app._prime_transcript_display_state = fail_prime  # type: ignore[method-assign]
    app._poll_transcript_for_async_messages = fail_poll  # type: ignore[method-assign]

    async with app.run_test() as pilot:
        await pilot.pause()
        await app.action_new_session()
        await pilot.pause()

    assert app._session_id == "new-session"


@pytest.mark.asyncio
async def test_chat_app_renders_assistant_turn_as_markdown_widget() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="default",
    )
    fake_client = AsyncMock()
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]
    markdown = "**Summary**\n\n1. First item\n2. Second item"

    async with app.run_test() as pilot:
        await pilot.pause()
        app._append_assistant_message(markdown)
        await pilot.pause()

        assistant_turns = list(app.query(".assistant-turn"))
        rendered_markdown = list(app.query(Markdown))
        assert assistant_turns
        assert len(rendered_markdown) == 1
        assert rendered_markdown[0]._markdown == markdown


@pytest.mark.asyncio
async def test_chat_app_mount_replays_existing_session_history(tmp_path) -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        data_dir=tmp_path,
        user_id="ops",
        workspace_id="default",
        session_id="sess-1",
    )
    fake_client = AsyncMock()
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]
    transcript_dir = tmp_path / "sessions" / "transcripts"
    transcript_dir.mkdir(parents=True)
    transcript_path = transcript_dir / "sess-1.jsonl"
    transcript_path.write_text(
        "\n".join(
            json.dumps(row)
            for row in [
                {
                    "entry_id": "u-1",
                    "role": "user",
                    "content_preview": "What did we decide?",
                    "metadata": {"channel": "cli"},
                },
                {
                    "entry_id": "tool-1",
                    "role": "tool",
                    "content_preview": "internal tool output",
                    "metadata": {"channel": "cli"},
                },
                {
                    "entry_id": "ev-1",
                    "role": "assistant",
                    "content_preview": "raw evidence read content",
                    "metadata": {
                        "channel": "cli",
                        "ephemeral_evidence_read": True,
                    },
                },
                {
                    "entry_id": "a-1",
                    "role": "assistant",
                    "content_preview": "We decided to ship the small fix.",
                    "metadata": {"channel": "cli"},
                },
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    async with app.run_test() as pilot:
        await pilot.pause()
        user_messages = _rendered_static_texts(app, ".user-message")
        status_messages = _rendered_static_texts(app, ".status-message")
        assistant_messages = [widget._markdown for widget in app.query(Markdown)]

    assert "info: current session sess-1 user=ops workspace=default" in status_messages
    assert user_messages == ["you: What did we decide?"]
    assert assistant_messages == ["We decided to ship the small fix."]
    assert "tool-1" in app._displayed_transcript_entry_ids
    assert "ev-1" in app._displayed_transcript_entry_ids
    assert all("internal tool output" not in message for message in status_messages)
    assert all("internal tool output" not in message for message in user_messages)
    assert all("internal tool output" not in message for message in assistant_messages)
    assert all("raw evidence read content" not in message for message in assistant_messages)


@pytest.mark.asyncio
async def test_chat_app_mount_replays_blob_backed_assistant_history(tmp_path) -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        data_dir=tmp_path,
        user_id="ops",
        workspace_id="default",
        session_id="sess-1",
    )
    fake_client = AsyncMock()
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]
    transcript_dir = tmp_path / "sessions" / "transcripts"
    blob_dir = tmp_path / "sessions" / "blobs"
    transcript_dir.mkdir(parents=True)
    blob_dir.mkdir(parents=True)
    (blob_dir / "blob-1.txt").write_text(
        "Full previous answer from blob storage.",
        encoding="utf-8",
    )
    transcript_path = transcript_dir / "sess-1.jsonl"
    transcript_path.write_text(
        json.dumps(
            {
                "entry_id": "a-blob",
                "role": "assistant",
                "blob_ref": "blob-1",
                "content_preview": "truncated previous answer",
                "metadata": {"channel": "cli"},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    async with app.run_test() as pilot:
        await pilot.pause()
        rendered = [widget._markdown for widget in app.query(Markdown)]

    assert rendered == ["Full previous answer from blob storage."]
    assert "a-blob" in app._displayed_transcript_entry_ids


@pytest.mark.asyncio
async def test_chat_app_mount_bounds_transcript_content_reads_before_replay(
    tmp_path,
) -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        data_dir=tmp_path,
        user_id="ops",
        workspace_id="default",
        session_id="sess-1",
    )
    fake_client = AsyncMock()
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]
    transcript_dir = tmp_path / "sessions" / "transcripts"
    transcript_dir.mkdir(parents=True)
    transcript_path = transcript_dir / "sess-1.jsonl"
    transcript_path.write_text(
        "\n".join(
            json.dumps(
                {
                    "entry_id": f"a-{index}",
                    "role": "assistant",
                    "content_preview": f"preview {index}",
                    "metadata": {"channel": "cli"},
                }
            )
            for index in range(ChatApp.TRANSCRIPT_REPLAY_LIMIT + 5)
        )
        + "\n",
        encoding="utf-8",
    )
    read_entry_ids: list[str] = []

    def content_for(entry: object) -> str:
        assert isinstance(entry, dict)
        entry_id = str(entry.get("entry_id", "")).strip()
        read_entry_ids.append(entry_id)
        return f"content {entry_id}"

    app._transcript_entry_content = content_for  # type: ignore[method-assign]

    async with app.run_test() as pilot:
        await pilot.pause()
        rendered = [widget._markdown for widget in app.query(Markdown)]

    expected_entry_ids = [
        f"a-{index}"
        for index in range(ChatApp.TRANSCRIPT_REPLAY_LIMIT + 4, 4, -1)
    ]
    assert read_entry_ids == expected_entry_ids
    assert rendered == [f"content a-{index}" for index in range(5, 55)]
    assert "a-0" in app._displayed_transcript_entry_ids


@pytest.mark.asyncio
async def test_chat_app_mount_backfills_unreadable_recent_replay_candidates(
    tmp_path,
) -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        data_dir=tmp_path,
        user_id="ops",
        workspace_id="default",
        session_id="sess-1",
    )
    fake_client = AsyncMock()
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]
    transcript_dir = tmp_path / "sessions" / "transcripts"
    transcript_dir.mkdir(parents=True)
    transcript_path = transcript_dir / "sess-1.jsonl"
    transcript_path.write_text(
        "\n".join(
            json.dumps(
                {
                    "entry_id": f"a-{index}",
                    "role": "assistant",
                    "content_preview": f"preview {index}",
                    "metadata": {"channel": "cli"},
                }
            )
            for index in range(ChatApp.TRANSCRIPT_REPLAY_LIMIT + 5)
        )
        + "\n",
        encoding="utf-8",
    )
    read_entry_ids: list[str] = []

    def content_for(entry: object) -> str:
        assert isinstance(entry, dict)
        entry_id = str(entry.get("entry_id", "")).strip()
        read_entry_ids.append(entry_id)
        if entry_id in {"a-52", "a-53", "a-54"}:
            return ""
        return f"content {entry_id}"

    app._transcript_entry_content = content_for  # type: ignore[method-assign]

    async with app.run_test() as pilot:
        await pilot.pause()
        rendered = [widget._markdown for widget in app.query(Markdown)]

    expected_entry_ids = [f"a-{index}" for index in range(54, 1, -1)]
    assert read_entry_ids == expected_entry_ids
    assert rendered == [f"content a-{index}" for index in range(2, 52)]
    assert "a-1" in app._displayed_transcript_entry_ids
    assert "a-54" in app._displayed_transcript_entry_ids


@pytest.mark.asyncio
async def test_chat_app_mount_preserves_unreadable_async_blob_for_poll_retry(
    tmp_path,
) -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        data_dir=tmp_path,
        user_id="ops",
        workspace_id="default",
        session_id="sess-1",
    )
    fake_client = AsyncMock()
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]
    transcript_dir = tmp_path / "sessions" / "transcripts"
    blob_dir = tmp_path / "sessions" / "blobs"
    transcript_dir.mkdir(parents=True)
    blob_dir.mkdir(parents=True)
    transcript_path = transcript_dir / "sess-1.jsonl"
    transcript_path.write_text(
        json.dumps(
            {
                "entry_id": "r-blob",
                "role": "assistant",
                "blob_ref": "blob-1",
                "content_preview": "Reminder: truncated preview",
                "metadata": {
                    "channel": "session",
                    "delivered_by": "scheduler",
                    "delivery_target": {"recipient": "sess-1"},
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    async with app.run_test() as pilot:
        await pilot.pause()
        assert list(app.query(Markdown)) == []
        assert "r-blob" not in app._displayed_transcript_entry_ids

        (blob_dir / "blob-1.txt").write_text("Reminder: delayed blob", encoding="utf-8")
        app._poll_transcript_for_async_messages()
        await pilot.pause()
        rendered = [widget._markdown for widget in app.query(Markdown)]

    assert rendered == ["Reminder: delayed blob"]
    assert "r-blob" in app._displayed_transcript_entry_ids


@pytest.mark.asyncio
async def test_chat_app_mount_marks_readable_async_rows_outside_replay_window_displayed(
    tmp_path,
) -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        data_dir=tmp_path,
        user_id="ops",
        workspace_id="default",
        session_id="sess-1",
    )
    fake_client = AsyncMock()
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]
    transcript_dir = tmp_path / "sessions" / "transcripts"
    transcript_dir.mkdir(parents=True)
    transcript_path = transcript_dir / "sess-1.jsonl"
    rows = [
        {
            "entry_id": "r-old",
            "role": "assistant",
            "content_preview": "Reminder: older async delivery",
            "metadata": {
                "channel": "session",
                "delivered_by": "scheduler",
                "delivery_target": {"recipient": "sess-1"},
            },
        }
    ]
    rows.extend(
        {
            "entry_id": f"a-{index}",
            "role": "assistant",
            "content_preview": f"normal response {index}",
            "metadata": {"channel": "cli"},
        }
        for index in range(1, ChatApp.TRANSCRIPT_REPLAY_LIMIT + 5)
    )
    transcript_path.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n",
        encoding="utf-8",
    )

    async with app.run_test() as pilot:
        await pilot.pause()
        app._poll_transcript_for_async_messages()
        await pilot.pause()
        rendered = [widget._markdown for widget in app.query(Markdown)]

    assert "r-old" in app._displayed_transcript_entry_ids
    assert "Reminder: older async delivery" not in rendered
    assert rendered == [f"normal response {index}" for index in range(5, 55)]


@pytest.mark.asyncio
async def test_chat_app_mount_marks_old_async_blob_rows_without_reading_content(
    tmp_path,
) -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        data_dir=tmp_path,
        user_id="ops",
        workspace_id="default",
        session_id="sess-1",
    )
    fake_client = AsyncMock()
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]
    transcript_dir = tmp_path / "sessions" / "transcripts"
    blob_dir = tmp_path / "sessions" / "blobs"
    transcript_dir.mkdir(parents=True)
    blob_dir.mkdir(parents=True)
    transcript_path = transcript_dir / "sess-1.jsonl"
    rows = [
        {
            "entry_id": f"r-old-{index}",
            "role": "assistant",
            "blob_ref": f"old-blob-{index}",
            "content_preview": "Reminder: older async delivery",
            "metadata": {
                "channel": "session",
                "delivered_by": "scheduler",
                "delivery_target": {"recipient": "sess-1"},
            },
        }
        for index in range(5)
    ]
    for index in range(5):
        (blob_dir / f"old-blob-{index}.txt").write_text(
            f"Reminder: old async blob {index}",
            encoding="utf-8",
        )
    rows.extend(
        {
            "entry_id": f"a-{index}",
            "role": "assistant",
            "content_preview": f"normal response {index}",
            "metadata": {"channel": "cli"},
        }
        for index in range(ChatApp.TRANSCRIPT_REPLAY_LIMIT)
    )
    transcript_path.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n",
        encoding="utf-8",
    )
    read_entry_ids: list[str] = []

    def content_for(entry: object) -> str:
        assert isinstance(entry, dict)
        entry_id = str(entry.get("entry_id", "")).strip()
        read_entry_ids.append(entry_id)
        return f"content {entry_id}"

    app._transcript_entry_content = content_for  # type: ignore[method-assign]

    async with app.run_test() as pilot:
        await pilot.pause()
        app._poll_transcript_for_async_messages()
        await pilot.pause()
        rendered = [widget._markdown for widget in app.query(Markdown)]

    assert all(f"r-old-{index}" in app._displayed_transcript_entry_ids for index in range(5))
    assert all(entry_id.startswith("a-") for entry_id in read_entry_ids)
    assert rendered == [f"content a-{index}" for index in range(ChatApp.TRANSCRIPT_REPLAY_LIMIT)]


@pytest.mark.asyncio
async def test_chat_app_mount_preserves_pending_confirmation_transcript_preview(
    tmp_path,
) -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        data_dir=tmp_path,
        user_id="ops",
        workspace_id="default",
        session_id="sess-1",
    )
    fake_client = AsyncMock()
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]
    transcript_dir = tmp_path / "sessions" / "transcripts"
    transcript_dir.mkdir(parents=True)
    transcript_path = transcript_dir / "sess-1.jsonl"
    transcript_path.write_text(
        json.dumps(
            {
                "entry_id": "pending-1",
                "role": "assistant",
                "content_preview": (
                    "[PENDING CONFIRMATIONS]\n"
                    "Queued for your approval:\n"
                    "1. c-1\n"
                    "   Preview:\n"
                    "     body: line1\\nline2\n\n"
                    "Review all pending: shisad action list"
                ),
                "metadata": {
                    "channel": "cli",
                    "system_generated_pending_confirmations": True,
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    async with app.run_test() as pilot:
        await pilot.pause()
        rendered = [widget._markdown for widget in app.query(Markdown)]

    assert len(rendered) == 1
    assert "body: line1\\nline2" in rendered[0]
    assert "body: line1\nline2" not in rendered[0]


@pytest.mark.asyncio
async def test_chat_app_mount_replays_existing_async_delivery_without_duplicate(tmp_path) -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        data_dir=tmp_path,
        user_id="ops",
        workspace_id="default",
        session_id="sess-1",
    )
    fake_client = AsyncMock()
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]
    transcript_dir = tmp_path / "sessions" / "transcripts"
    transcript_dir.mkdir(parents=True)
    transcript_path = transcript_dir / "sess-1.jsonl"
    transcript_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "role": "assistant",
                        "content_hash": "old123",
                        "timestamp": "2026-06-18T00:00:00+00:00",
                        "content_preview": "previous normal answer",
                        "metadata": {"channel": "cli"},
                    }
                ),
                json.dumps(
                    {
                        "role": "assistant",
                        "content_hash": "abc123",
                        "timestamp": "2026-06-19T00:00:00+00:00",
                        "content_preview": "Reminder: arrived during startup",
                        "metadata": {
                            "channel": "session",
                            "delivered_by": "scheduler",
                            "delivery_target": {"recipient": "sess-1"},
                        },
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    async with app.run_test() as pilot:
        await pilot.pause()
        app._poll_transcript_for_async_messages()
        await pilot.pause()
        rendered = [widget._markdown for widget in app.query(Markdown)]

    assert rendered == ["previous normal answer", "Reminder: arrived during startup"]
    tx_entry_ids = {
        entry_id
        for entry_id in app._displayed_transcript_entry_ids
        if entry_id.startswith("tx-")
    }
    assert len(tx_entry_ids) == 2


@pytest.mark.asyncio
async def test_chat_app_transcript_poll_preserves_pending_confirmation_preview(
    tmp_path,
) -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        data_dir=tmp_path,
        user_id="ops",
        workspace_id="default",
        session_id="sess-1",
    )
    fake_client = AsyncMock()
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]
    transcript_dir = tmp_path / "sessions" / "transcripts"
    transcript_dir.mkdir(parents=True)
    transcript_path = transcript_dir / "sess-1.jsonl"
    transcript_path.write_text("", encoding="utf-8")

    async with app.run_test() as pilot:
        await pilot.pause()
        transcript_path.write_text(
            json.dumps(
                {
                    "entry_id": "pending-async",
                    "role": "assistant",
                    "content_preview": (
                        "[PENDING CONFIRMATIONS]\n"
                        "Queued for your approval:\n"
                        "1. c-1\n"
                        "   Preview:\n"
                        "     body: line1\\nline2\n\n"
                        "Review all pending: shisad action list"
                    ),
                    "metadata": {
                        "channel": "session",
                        "delivered_by": "scheduler",
                        "delivery_target": {"recipient": "sess-1"},
                        "pending_confirmation_bridge": True,
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        app._poll_transcript_for_async_messages()
        await pilot.pause()
        rendered = [widget._markdown for widget in app.query(Markdown)]

    assert len(rendered) == 1
    assert "body: line1\\nline2" in rendered[0]
    assert "body: line1\nline2" not in rendered[0]


@pytest.mark.asyncio
async def test_chat_app_transcript_poll_skips_ephemeral_evidence_read_rows(
    tmp_path,
) -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        data_dir=tmp_path,
        user_id="ops",
        workspace_id="default",
        session_id="sess-1",
    )
    fake_client = AsyncMock()
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]
    transcript_dir = tmp_path / "sessions" / "transcripts"
    transcript_dir.mkdir(parents=True)
    transcript_path = transcript_dir / "sess-1.jsonl"
    transcript_path.write_text("", encoding="utf-8")

    async with app.run_test() as pilot:
        await pilot.pause()
        transcript_path.write_text(
            json.dumps(
                {
                    "entry_id": "ev-async",
                    "role": "assistant",
                    "content_preview": "raw async evidence read content",
                    "metadata": {
                        "channel": "session",
                        "delivered_by": "scheduler",
                        "delivery_target": {"recipient": "sess-1"},
                        "ephemeral_evidence_read": True,
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        app._poll_transcript_for_async_messages()
        await pilot.pause()
        rendered = [widget._markdown for widget in app.query(Markdown)]

    assert rendered == []
    assert "ev-async" in app._displayed_transcript_entry_ids


@pytest.mark.asyncio
async def test_chat_app_transcript_poll_drains_multiple_async_deliveries(tmp_path) -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        data_dir=tmp_path,
        user_id="ops",
        workspace_id="default",
        session_id="sess-1",
    )
    fake_client = AsyncMock()
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]
    transcript_dir = tmp_path / "sessions" / "transcripts"
    transcript_dir.mkdir(parents=True)
    transcript_path = transcript_dir / "sess-1.jsonl"
    old_rows = [
        {
            "entry_id": "u-1",
            "role": "user",
            "content_preview": "intervening question",
            "metadata": {"channel": "cli"},
        },
        {
            "entry_id": "a-1",
            "role": "assistant",
            "content_preview": "normal response",
            "metadata": {"channel": "cli"},
        },
    ]
    async_rows = [
        {
            "entry_id": "r-1",
            "role": "assistant",
            "content_preview": "Reminder: first",
            "metadata": {
                "channel": "session",
                "delivered_by": "scheduler",
                "delivery_target": {"recipient": "sess-1"},
            },
        },
        {
            "entry_id": "r-2",
            "role": "assistant",
            "content_preview": "Reminder: second",
            "metadata": {
                "channel": "session",
                "delivered_by": "scheduler",
                "delivery_target": {"recipient": "sess-1"},
            },
        },
    ]
    transcript_path.write_text(
        "\n".join(json.dumps(row) for row in old_rows) + "\n",
        encoding="utf-8",
    )

    async with app.run_test() as pilot:
        await pilot.pause()
        with transcript_path.open("a", encoding="utf-8") as handle:
            for row in async_rows:
                handle.write(json.dumps(row) + "\n")
        app._poll_transcript_for_async_messages()
        await pilot.pause()
        app._poll_transcript_for_async_messages()
        await pilot.pause()

        rendered = [widget._markdown for widget in app.query(Markdown)]

    assert rendered == ["normal response", "Reminder: first", "Reminder: second"]


@pytest.mark.asyncio
async def test_chat_app_transcript_poll_retries_async_blob_until_readable(tmp_path) -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        data_dir=tmp_path,
        user_id="ops",
        workspace_id="default",
        session_id="sess-1",
    )
    fake_client = AsyncMock()
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]
    transcript_dir = tmp_path / "sessions" / "transcripts"
    blob_dir = tmp_path / "sessions" / "blobs"
    transcript_dir.mkdir(parents=True)
    blob_dir.mkdir(parents=True)
    transcript_path = transcript_dir / "sess-1.jsonl"
    transcript_path.write_text("", encoding="utf-8")

    async with app.run_test() as pilot:
        await pilot.pause()
        transcript_path.write_text(
            json.dumps(
                {
                    "entry_id": "r-blob",
                    "role": "assistant",
                    "blob_ref": "blob-1",
                    "content_preview": "Reminder: truncated preview",
                    "metadata": {
                        "channel": "session",
                        "delivered_by": "scheduler",
                        "delivery_target": {"recipient": "sess-1"},
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        app._poll_transcript_for_async_messages()
        await pilot.pause()
        assert list(app.query(Markdown)) == []

        (blob_dir / "blob-1.txt").write_text("Reminder: delayed blob", encoding="utf-8")
        app._poll_transcript_for_async_messages()
        await pilot.pause()
        rendered = [widget._markdown for widget in app.query(Markdown)]

    assert rendered == ["Reminder: delayed blob"]


@pytest.mark.asyncio
async def test_chat_app_transcript_poll_skips_partial_jsonl_rows(tmp_path) -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        data_dir=tmp_path,
        user_id="ops",
        workspace_id="default",
        session_id="sess-1",
    )
    fake_client = AsyncMock()
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]
    transcript_dir = tmp_path / "sessions" / "transcripts"
    transcript_dir.mkdir(parents=True)
    transcript_path = transcript_dir / "sess-1.jsonl"
    transcript_path.write_text('{"entry_id": "partial", "role": "assistant"\n', encoding="utf-8")

    async with app.run_test() as pilot:
        await pilot.pause()
        with transcript_path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {
                        "entry_id": "r-valid",
                        "role": "assistant",
                        "content_preview": "Reminder: valid row",
                        "metadata": {
                            "channel": "session",
                            "delivered_by": "scheduler",
                            "delivery_target": {"recipient": "sess-1"},
                        },
                    }
                )
                + "\n"
            )
        app._poll_transcript_for_async_messages()
        await pilot.pause()
        rendered = [widget._markdown for widget in app.query(Markdown)]

    assert rendered == ["Reminder: valid row"]
    assert "partial" not in app._displayed_transcript_entry_ids


@pytest.mark.asyncio
async def test_chat_app_prompt_box_expands_and_collapses_after_submit() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="default",
        session_id="sess-1",
    )
    fake_client = AsyncMock()
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]
    app._send_message = AsyncMock(return_value={"response": "ok"})  # type: ignore[method-assign]
    transcript_polls: list[str] = []
    app._poll_transcript_for_async_messages = lambda: transcript_polls.append("poll")  # type: ignore[method-assign]

    async with app.run_test() as pilot:
        await pilot.pause()
        transcript_polls.clear()
        prompt = app.query_one("#chat-input", TextArea)
        prompt.load_text("please summarize " + ("this long prompt " * 20))
        app._resize_prompt_input(prompt)
        expanded_height = prompt.styles.height.value

        await pilot.press("enter")
        await pilot.pause()

        assert expanded_height is not None
        assert expanded_height > app.PROMPT_INPUT_MIN_HEIGHT
        assert prompt.text == ""
        assert prompt.styles.height.value == app.PROMPT_INPUT_MIN_HEIGHT

    app._send_message.assert_awaited_once()
    assert transcript_polls == ["poll"]
