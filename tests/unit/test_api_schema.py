"""M0.T1: Schema validation rejects malformed control API requests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from shisad.core.api.schema import (
    JsonRpcRequest,
    SessionCreateParams,
    SessionMessageParams,
    ToolExecuteParams,
)


class TestApiSchemaValidation:
    """M0.T1: schema validation rejects malformed control API requests."""

    def test_valid_request(self) -> None:
        req = JsonRpcRequest(method="session.create", params={"user_id": "alice"}, id=1)
        assert req.method == "session.create"
        assert req.id == 1

    def test_missing_method_rejected(self) -> None:
        with pytest.raises(ValidationError):
            JsonRpcRequest.model_validate({"jsonrpc": "2.0", "id": 1})

    def test_session_message_missing_content(self) -> None:
        with pytest.raises(ValidationError):
            SessionMessageParams.model_validate({"session_id": "abc"})

    def test_session_create_defaults(self) -> None:
        params = SessionCreateParams()
        assert params.user_id == ""
        assert params.workspace_id == ""

    def test_tool_execute_rejects_empty_command(self) -> None:
        with pytest.raises(ValidationError):
            ToolExecuteParams.model_validate(
                {
                    "session_id": "s1",
                    "tool_name": "shell_exec",
                    "command": [],
                }
            )
