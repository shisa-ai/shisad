"""Tests for shisad.ui.chat — interactive chat TUI."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from shisad.ui.chat import ChatApp, format_assistant_message, format_user_message

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
        app._recall_prompt_history(direction=-1, current_value="draft message")
        == "second prompt"
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
    """_send_message should call session.message and return the response."""
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
    assert result == "Hello from shisad!"


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

    result = await app._send_message(mock_client, "hello")

    assert result == "Hello!"
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
    assert result == "Recovered"
    assert app._session_id == "new-id"
    assert app._reconnected is True


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
