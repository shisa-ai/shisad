"""Tests for shisad.ui.chat — interactive chat TUI."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from textual.widgets import Markdown, Static, TextArea

from shisad import __version__
from shisad.core.api.transport import JsonRpcCallError
from shisad.ui import theme as theme_module
from shisad.ui.chat import ChatApp, format_assistant_message, format_user_message


def _rendered_static_texts(app: ChatApp, selector: str) -> list[str]:
    return [
        str(widget.renderable) for widget in app.query(selector) if hasattr(widget, "renderable")
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


def test_f6_chat_app_uses_runtime_theme_and_motion_posture() -> None:
    posture = theme_module.resolve_ui_posture(
        theme_name="shisa-light",
        reduce_motion=True,
        environ={"TERM": "xterm-256color", "LANG": "C.UTF-8"},
        isatty=True,
    )

    app = ChatApp(socket_path=Path("/tmp/test.sock"), ui_posture=posture)

    assert app.ui_posture is posture
    assert posture.palette.semantic["background"] in app.CSS
    assert app._terminal_capabilities.reduce_motion is True


def test_format_assistant_message_renders_literal_newline_escapes() -> None:
    result = format_assistant_message("1. first\\n2. second")

    assert result == "shisad: 1. first\n2. second"
    assert "\\n" not in result


def test_format_assistant_message_promotes_inline_bullets_to_markdown_list() -> None:
    result = format_assistant_message("I can help with: - Read files - Search the web")

    assert result == "shisad: I can help with:\n\n- Read files\n- Search the web"


def test_format_assistant_message_promotes_inline_unicode_bullets_to_markdown_list() -> None:
    result = format_assistant_message("Demo list: ● Who are you ● Ledger approval")

    assert result == "shisad: Demo list:\n\n- Who are you\n- Ledger approval"


def test_format_assistant_message_separates_unicode_bullet_list_from_trailing_prose() -> None:
    result = format_assistant_message(
        "Demo list:\n"
        "● Who are you\n"
        "● Ledger approval\n"
        "If you want, I can also turn that into a cleaner checklist format."
    )

    assert result == (
        "shisad: Demo list:\n\n"
        "- Who are you\n"
        "- Ledger approval\n\n"
        "If you want, I can also turn that into a cleaner checklist format."
    )


def test_format_assistant_message_promotes_inline_dot_bullets_to_markdown_list() -> None:
    result = format_assistant_message("Checklist: • Alpha • Beta\nDone.")

    assert result == "shisad: Checklist:\n\n- Alpha\n- Beta\n\nDone."


def test_format_assistant_message_keeps_non_list_hyphens_inline() -> None:
    result = format_assistant_message("Range: 1 - 2 and alpha - beta")

    assert result == "shisad: Range: 1 - 2 and alpha - beta"


def test_format_assistant_message_does_not_split_year_in_list_item() -> None:
    result = format_assistant_message("Highlights: - Released in 2024. It supports X - Next item")

    assert "2024. It supports X" in result
    assert result == "shisad: Highlights:\n\n- Released in 2024. It supports X\n- Next item"


def test_format_assistant_message_does_not_split_digit_hyphen_range_in_item() -> None:
    result = format_assistant_message(
        "Options: - Range is 1 - 10 for this setting - Another option"
    )

    assert "1 - 10" in result
    assert result == ("shisad: Options:\n\n- Range is 1 - 10 for this setting\n- Another option")


def test_format_assistant_message_does_not_rewrite_fenced_code() -> None:
    result = format_assistant_message("```\nItems: - one - two\n```")

    assert result == "shisad: ```\nItems: - one - two\n```"


def test_format_assistant_message_does_not_rewrite_fenced_unicode_bullets() -> None:
    result = format_assistant_message("```\nItems: ● one ● two\n```")

    assert result == "shisad: ```\nItems: ● one ● two\n```"


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
    result = format_assistant_message("Intro paragraph.\n\n## Already separate\nBody text.")

    assert result == "shisad: Intro paragraph.\n\n## Already separate\nBody text."


def test_format_assistant_message_does_not_rewrite_fenced_code_headings() -> None:
    result = format_assistant_message(
        "Example:\n```\nvalue\n## Not a markdown heading here\n```\nDone.\n## Real heading"
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
    assert app._startup_hint is None


@pytest.mark.asyncio
async def test_o3b_chat_tour_suggestion_is_display_only() -> None:
    suggestion = "Try asking shisad to read a file in your workspace."
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="default",
        startup_hint=suggestion,
    )
    fake_client = AsyncMock()
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]

    async with app.run_test() as pilot:
        await pilot.pause()
        status_messages = _rendered_static_texts(app, ".status-message")

    assert status_messages.count(f"Tour suggestion (not sent): {suggestion}") == 1
    fake_client.call.assert_not_awaited()


@pytest.mark.asyncio
async def test_o3b_chat_handoff_reports_missing_daemon_actionably() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/missing-test.sock"),
        startup_hint="Try asking shisad to read a file in your workspace.",
    )
    app._connect = AsyncMock(side_effect=OSError("offline"))  # type: ignore[method-assign]

    async with app.run_test() as pilot:
        await pilot.pause()
        status_messages = _rendered_static_texts(app, ".status-message")

    assert any("Could not connect to daemon" in message for message in status_messages)
    assert "Is the daemon running? Try: shisad start --foreground" in status_messages


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


def test_u2_chat_status_bar_formats_structured_state() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="alice",
        workspace_id="prod",
        session_id="sess-structured",
    )
    app._connection_state = "connected"
    app._channel = "cli"
    app._lockdown_level = "caution"

    assert app._format_status_bar() == (
        f"shisad {__version__} | connection=connected | session=sess-structured | "
        "channel=cli | lockdown=caution | user=alice | workspace=prod | "
        "keys=Ctrl+N New | Ctrl+C Quit"
    )


@pytest.mark.asyncio
async def test_u2_chat_mount_renders_structured_status_and_theme_classes() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="prod",
    )
    fake_client = AsyncMock()
    fake_client.call = AsyncMock(
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
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]

    async with app.run_test() as pilot:
        await pilot.pause()
        status_bar = app.query_one("#chat-status", Static)
        chat_log = app.query_one("#chat-log")
        chat_input = app.query_one("#chat-input")

    assert str(status_bar.renderable) == (
        f"shisad {__version__} | connection=connected | session=active-sid | "
        "channel=cli | lockdown=caution | user=ops | workspace=prod | "
        "keys=Ctrl+N New | Ctrl+C Quit"
    )
    assert chat_log.has_class("shisa-panel")
    assert chat_input.has_class("shisa-panel")


@pytest.mark.asyncio
async def test_u2_chat_turns_render_role_labels_and_muted_timestamps() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="default",
        session_id="sess-1",
    )
    fake_client = AsyncMock()
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]
    app._turn_timestamp = lambda: "12:34:56Z"  # type: ignore[method-assign]

    async with app.run_test() as pilot:
        await pilot.pause()
        app._append_user_message("hello")
        app._append_assistant_message("hi")
        await pilot.pause()
        user_labels = _rendered_static_texts(app, ".user-meta")
        assistant_labels = _rendered_static_texts(app, ".assistant-meta")

    assert user_labels[-1] == "you | 12:34:56Z"
    assert assistant_labels[-1] == "shisad | 12:34:56Z"


@pytest.mark.asyncio
async def test_u2_chat_evidence_refs_get_semantic_message_class() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="default",
        session_id="sess-1",
    )
    fake_client = AsyncMock()
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]

    async with app.run_test() as pilot:
        await pilot.pause()
        app._append_assistant_message(
            "[EVIDENCE ref=ev-61f3d4c48f54ff92 source=web.fetch:example.com "
            'taint=UNTRUSTED size=88 summary="Example Domain" '
            'Use evidence.read("ev-61f3d4c48f54ff92") for full content, or '
            'evidence.promote("ev-61f3d4c48f54ff92") to add it to the conversation.]'
        )
        await pilot.pause()
        rendered_markdown = list(app.query(Markdown))[-1]

    assert rendered_markdown.has_class("evidence-message")
    assert "[Evidence ev-61f3d4c48f54ff92]" in rendered_markdown._markdown


@pytest.mark.asyncio
async def test_u2_chat_happy_path_submits_prompt_and_renders_response() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="default",
        session_id="sess-1",
    )
    fake_client = AsyncMock()
    fake_client.call = AsyncMock(return_value={"response": "Hello from shisad!"})
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]

    async with app.run_test() as pilot:
        await pilot.pause()
        input_widget = app.query_one("#chat-input", TextArea)
        input_widget.focus()
        input_widget.load_text("hello")
        await app.action_submit_prompt()
        await pilot.pause()
        user_messages = _rendered_static_texts(app, ".user-message")
        assistant_messages = [widget._markdown for widget in app.query(Markdown)]

    fake_client.call.assert_awaited_once_with(
        "session.message",
        params={"session_id": "sess-1", "content": "hello"},
    )
    assert user_messages[-1] == "you: hello"
    assert assistant_messages[-1] == "Hello from shisad!"


@pytest.mark.asyncio
async def test_u2_chat_submit_refreshes_lockdown_status_from_response() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="default",
        session_id="sess-1",
    )
    fake_client = AsyncMock()
    fake_client.call = AsyncMock(
        return_value={
            "session_id": "sess-1",
            "response": "Caution state is now active.",
            "lockdown_level": "caution",
        }
    )
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]

    async with app.run_test() as pilot:
        await pilot.pause()
        input_widget = app.query_one("#chat-input", TextArea)
        input_widget.focus()
        input_widget.load_text("hello")
        await app.action_submit_prompt()
        await pilot.pause()
        status_bar = app.query_one("#chat-status", Static)

    assert "lockdown=caution" in str(status_bar.renderable)


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
    """When session_id is provided, _ensure_session should refresh metadata but not create."""
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="prod",
        session_id="existing-id",
    )

    mock_client = AsyncMock()
    mock_client.call = AsyncMock(
        return_value={
            "sessions": [
                {
                    "id": "existing-id",
                    "state": "active",
                    "channel": "discord",
                    "user_id": "alice",
                    "workspace_id": "ws1",
                    "lockdown_level": "quarantine",
                }
            ]
        }
    )
    await app._ensure_session(mock_client)

    mock_client.call.assert_awaited_once_with("session.list", params={})
    assert app._session_id == "existing-id"
    assert app._channel == "discord"
    assert app._lockdown_level == "quarantine"
    assert app._user_id == "alice"
    assert app._workspace_id == "ws1"


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
async def test_o3c_pending_panel_queries_exact_session_and_filters_terminal_rows() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="default",
        session_id="sess-current",
    )
    fake_client = AsyncMock()
    fake_client.call = AsyncMock(
        return_value={
            "actions": [
                {
                    "confirmation_id": "confirm-current",
                    "session_id": "sess-current",
                    "status": "pending",
                    "lifecycle_state": "pending",
                    "tool_name": "fs.write",
                    "risk_level": "high",
                    "required_level": "software",
                    "arguments": {"content": "raw-secret-must-not-render"},
                    "approval_url": "https://secret.example/approval",
                },
                {
                    "confirmation_id": "confirm-terminal",
                    "session_id": "sess-current",
                    "status": "rejected",
                    "lifecycle_state": "rejected",
                    "tool_name": "terminal-secret-tool",
                },
                {
                    "confirmation_id": "confirm-other",
                    "session_id": "sess-other",
                    "status": "pending",
                    "lifecycle_state": "pending",
                    "tool_name": "cross-session-secret-tool",
                },
            ],
            "count": 3,
        }
    )
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]
    app._start_pending_polling = lambda: None  # type: ignore[method-assign]

    async with app.run_test() as pilot:
        await pilot.pause()
        await app._refresh_pending_panel()
        await pilot.pause()
        panel = app.query_one("#chat-pending", Static)
        rendered = str(panel.renderable)
        app._refresh_status_from_message_result({"session_id": "sess-replaced"})
        assert "confirm-current" not in str(panel.renderable)

    fake_client.call.assert_awaited_once_with(
        "action.pending",
        params={
            "session_id": "sess-current",
            "status": "pending",
            "limit": ChatApp.PENDING_QUERY_LIMIT,
            "include_ui": False,
        },
    )
    assert "confirm-current" in rendered
    assert "fs.write" in rendered
    assert "risk=high" in rendered
    assert "approval=software" in rendered
    assert "confirm-terminal" not in rendered
    assert "terminal-secret-tool" not in rendered
    assert "confirm-other" not in rendered
    assert "cross-session-secret-tool" not in rendered
    assert "raw-secret-must-not-render" not in rendered
    assert "secret.example" not in rendered


@pytest.mark.asyncio
async def test_o3c_pending_poll_recovers_after_mount_time_daemon_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ChatApp, "PENDING_POLL_SECONDS", 0.01, raising=False)
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="default",
    )
    fake_client = AsyncMock()

    async def connect_after_mount_failure() -> object:
        if app._connect.await_count == 1:  # type: ignore[attr-defined]
            raise OSError("daemon starting")
        return fake_client

    async def ensure_recovered_session(_client: object) -> None:
        app._session_id = "sess-recovered"

    async def call(method: str, *, params: object) -> object:
        assert isinstance(params, dict)
        if method == "session.message":
            return {"session_id": "sess-recovered", "response": "chat recovered"}
        assert method == "action.pending"
        return {
            "actions": [
                {
                    "confirmation_id": "confirm-after-startup",
                    "session_id": "sess-recovered",
                    "status": "pending",
                    "tool_name": "fs.write",
                }
            ],
            "count": 1,
        }

    app._connect = AsyncMock(side_effect=connect_after_mount_failure)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock(side_effect=ensure_recovered_session)  # type: ignore[method-assign]
    fake_client.call = AsyncMock(side_effect=call)

    async with app.run_test() as pilot:
        await pilot.pause()
        assert app._pending_poll_task is not None

        input_widget = app.query_one("#chat-input", TextArea)
        input_widget.focus()
        input_widget.load_text("hello after startup")
        await app.action_submit_prompt()

        panel = app.query_one("#chat-pending", Static)
        for _ in range(100):
            await pilot.pause(0.01)
            if "confirm-after-startup" in str(panel.renderable):
                break
        else:
            pytest.fail("pending polling did not recover after mount-time daemon failure")

        assistant_messages = [widget._markdown for widget in app.query(Markdown)]
        assert assistant_messages[-1] == "chat recovered"


@pytest.mark.asyncio
@pytest.mark.parametrize("hung_stage", ["connect", "call", "close"])
async def test_o3c_pending_refresh_bounds_every_rpc_stage(
    monkeypatch: pytest.MonkeyPatch,
    hung_stage: str,
) -> None:
    monkeypatch.setattr(ChatApp, "PENDING_RPC_TIMEOUT_SECONDS", 0.01, raising=False)
    monkeypatch.setattr(ChatApp, "PENDING_CLOSE_TIMEOUT_SECONDS", 0.01, raising=False)
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="default",
        session_id="sess-current",
    )
    fake_client = AsyncMock()
    fake_client.call = AsyncMock(return_value={"actions": [], "count": 0})
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]
    app._start_pending_polling = lambda: None  # type: ignore[method-assign]

    async def never_returns(*_args: object, **_kwargs: object) -> object:
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    async with app.run_test() as pilot:
        await pilot.pause()
        if hung_stage == "connect":
            app._connect = AsyncMock(side_effect=never_returns)  # type: ignore[method-assign]
        elif hung_stage == "call":
            fake_client.call = AsyncMock(side_effect=never_returns)
        else:
            fake_client.close = AsyncMock(side_effect=never_returns)

        await asyncio.wait_for(app._refresh_pending_panel(), timeout=0.2)
        panel = app.query_one("#chat-pending", Static)
        rendered = str(panel.renderable)

    if hung_stage == "close":
        assert rendered == "No pending confirmations."
    else:
        assert rendered == ("Pending confirmations unavailable; chat remains usable. Retrying.")


@pytest.mark.asyncio
async def test_o3c_pending_panel_refreshes_without_prompt_and_cancels_serially(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ChatApp, "PENDING_POLL_SECONDS", 0.01, raising=False)
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="default",
        session_id="sess-current",
    )
    fake_client = AsyncMock()
    second_refresh = asyncio.Event()
    call_count = 0
    active_calls = 0
    max_active_calls = 0

    async def pending_call(method: str, *, params: object) -> object:
        nonlocal active_calls, call_count, max_active_calls
        assert method == "action.pending"
        assert isinstance(params, dict)
        call_count += 1
        active_calls += 1
        max_active_calls = max(max_active_calls, active_calls)
        try:
            if call_count == 1:
                return {
                    "actions": [
                        {
                            "confirmation_id": "confirm-refresh",
                            "session_id": "sess-current",
                            "status": "pending",
                            "tool_name": "fs.read",
                        }
                    ],
                    "count": 1,
                }
            await second_refresh.wait()
            return {"actions": [], "count": 0}
        finally:
            active_calls -= 1

    fake_client.call = AsyncMock(side_effect=pending_call)
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]

    async with app.run_test() as pilot:
        for _ in range(100):
            await pilot.pause(0.01)
            panel = app.query_one("#chat-pending", Static)
            if "confirm-refresh" in str(panel.renderable):
                break
        else:
            pytest.fail("pending panel did not refresh without a prompt")

        second_refresh.set()
        for _ in range(100):
            await pilot.pause(0.01)
            if "No pending confirmations" in str(panel.renderable):
                break
        else:
            pytest.fail("terminal pending row did not disappear on refresh")

        assert max_active_calls == 1
        assert app._pending_poll_task is not None
        pending_task = app._pending_poll_task
        app._start_pending_polling()
        assert app._pending_poll_task is pending_task

    assert app._pending_poll_task is None


@pytest.mark.asyncio
async def test_o3c_pending_panel_failure_is_bounded_and_chat_remains_usable() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="default",
        session_id="sess-current",
    )
    fake_client = AsyncMock()
    fake_client.call = AsyncMock(return_value={"actions": "malformed"})
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]
    app._start_pending_polling = lambda: None  # type: ignore[method-assign]

    async with app.run_test() as pilot:
        await pilot.pause()
        transcript_before = _rendered_static_texts(app, ".status-message")
        await app._refresh_pending_panel()
        await pilot.pause()
        panel = app.query_one("#chat-pending", Static)

        assert str(panel.renderable) == (
            "Pending confirmations unavailable; chat remains usable. Retrying."
        )
        assert _rendered_static_texts(app, ".status-message") == transcript_before

        fake_client.call = AsyncMock(
            return_value={
                "actions": [],
                "count": 0,
                "persistence_status": "degraded",
                "persistence_reason": "must-not-render",
            }
        )
        await app._refresh_pending_panel()
        assert str(panel.renderable) == (
            "Pending confirmations unavailable; chat remains usable. Retrying."
        )
        assert "must-not-render" not in str(panel.renderable)

        fake_client.call = AsyncMock(
            return_value={
                "actions": [
                    {
                        "confirmation_id": "confirm-recovered",
                        "session_id": "sess-current",
                        "status": "pending",
                        "tool_name": "fs.read",
                    }
                ],
                "count": 1,
            }
        )
        await app._refresh_pending_panel()
        assert "confirm-recovered" in str(panel.renderable)
        assert "unavailable" not in str(panel.renderable).lower()

        fake_client.call = AsyncMock(return_value={"response": "chat still works"})
        input_widget = app.query_one("#chat-input", TextArea)
        input_widget.focus()
        input_widget.load_text("hello after pending failure")
        await app.action_submit_prompt()
        await pilot.pause()
        assistant_messages = [widget._markdown for widget in app.query(Markdown)]

    assert assistant_messages[-1] == "chat still works"


@pytest.mark.asyncio
async def test_o3c_new_session_clears_panel_before_query_and_ignores_stale_refresh() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="default",
        session_id="sess-old",
    )
    fake_client = AsyncMock()
    old_query_started = asyncio.Event()
    release_old_query = asyncio.Event()
    create_started = asyncio.Event()
    release_create = asyncio.Event()

    async def call(method: str, *, params: object) -> object:
        assert isinstance(params, dict)
        if method == "action.pending":
            old_query_started.set()
            await release_old_query.wait()
            return {
                "actions": [
                    {
                        "confirmation_id": "confirm-old",
                        "session_id": "sess-old",
                        "status": "pending",
                        "tool_name": "fs.write",
                    }
                ],
                "count": 1,
            }
        assert method == "session.create"
        create_started.set()
        await release_create.wait()
        return {"session_id": "sess-new"}

    fake_client.call = AsyncMock(side_effect=call)
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]
    app._start_pending_polling = lambda: None  # type: ignore[method-assign]

    async with app.run_test() as pilot:
        await pilot.pause()
        stale_refresh = asyncio.create_task(app._refresh_pending_panel())
        await old_query_started.wait()
        new_session = asyncio.create_task(app.action_new_session())
        await create_started.wait()
        panel = app.query_one("#chat-pending", Static)
        assert "confirm-old" not in str(panel.renderable)

        release_create.set()
        await new_session
        release_old_query.set()
        await stale_refresh
        await pilot.pause()

        assert app._session_id == "sess-new"
        assert "confirm-old" not in str(panel.renderable)


@pytest.mark.asyncio
async def test_o3c_new_session_failure_restores_session_with_retrying_panel() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="default",
        session_id="sess-old",
    )
    fake_client = AsyncMock()
    fake_client.call = AsyncMock(side_effect=OSError("daemon unavailable"))
    app._connect = AsyncMock(return_value=fake_client)  # type: ignore[method-assign]
    app._ensure_session = AsyncMock()  # type: ignore[method-assign]
    app._start_pending_polling = lambda: None  # type: ignore[method-assign]

    async with app.run_test() as pilot:
        await pilot.pause()
        await app.action_new_session()
        await pilot.pause()
        panel = app.query_one("#chat-pending", Static)

    assert app._session_id == "sess-old"
    assert str(panel.renderable) == (
        "Pending confirmations unavailable; chat remains usable. Retrying."
    )


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
        f"a-{index}" for index in range(ChatApp.TRANSCRIPT_REPLAY_LIMIT + 4, 4, -1)
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
        entry_id for entry_id in app._displayed_transcript_entry_ids if entry_id.startswith("tx-")
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
