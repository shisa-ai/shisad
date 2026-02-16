"""Tests for shisad.ui.chat — interactive chat TUI."""

from __future__ import annotations

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


def test_chat_app_with_existing_session() -> None:
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="default",
        session_id="abc123",
    )
    assert app._session_id == "abc123"


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
    mock_client.call = AsyncMock(return_value={"session_id": "new-session-id"})

    await app._ensure_session(mock_client)

    mock_client.call.assert_called_once_with(
        "session.create",
        params={"user_id": "ops", "workspace_id": "prod"},
    )
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
    """If the RPC response lacks 'response', return a fallback."""
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="prod",
        session_id="sess-1",
    )

    mock_client = AsyncMock()
    mock_client.call = AsyncMock(return_value={"unexpected": "data"})

    result = await app._send_message(mock_client, "hello")
    assert isinstance(result, str)
    assert len(result) > 0


@pytest.mark.asyncio
async def test_chat_app_send_message_handles_rpc_error() -> None:
    """RPC errors should be caught and returned as error text."""
    app = ChatApp(
        socket_path=Path("/tmp/test.sock"),
        user_id="ops",
        workspace_id="prod",
        session_id="sess-1",
    )

    mock_client = AsyncMock()
    mock_client.call = AsyncMock(side_effect=OSError("connection refused"))

    result = await app._send_message(mock_client, "hello")
    assert "error" in result.lower() or "connection" in result.lower()
