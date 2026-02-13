"""M0.T1: Schema validation rejects malformed control API requests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from shisad.core.api.schema import (
    ActionConfirmResult,
    ActionPendingResult,
    ActionRejectResult,
    ConfirmationMetricsResult,
    JsonRpcRequest,
    SessionCreateParams,
    SessionGrantCapabilitiesResult,
    SessionMessageParams,
    SessionRollbackResult,
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

    def test_session_rollback_result_validation(self) -> None:
        result = SessionRollbackResult.model_validate(
            {
                "rolled_back": True,
                "checkpoint_id": "cp-1",
                "session_id": "s1",
                "files_restored": 2,
                "files_deleted": 1,
                "restore_errors": [],
            }
        )
        assert result.rolled_back is True

    def test_session_grant_capabilities_result_defaults(self) -> None:
        result = SessionGrantCapabilitiesResult.model_validate(
            {"session_id": "s1", "granted": True}
        )
        assert result.capabilities == []

    def test_confirmation_result_models_accept_runtime_shapes(self) -> None:
        pending = ActionPendingResult.model_validate({"actions": [{"id": "x"}], "count": 1})
        confirm = ActionConfirmResult.model_validate(
            {
                "confirmed": False,
                "confirmation_id": "c1",
                "reason": "cooldown_active",
                "retry_after_seconds": 0.5,
            }
        )
        reject = ActionRejectResult.model_validate(
            {"rejected": True, "confirmation_id": "c2", "status": "rejected"}
        )
        metrics = ConfirmationMetricsResult.model_validate(
            {"metrics": [{"user_id": "alice"}], "count": 1}
        )
        assert pending.count == 1
        assert confirm.retry_after_seconds == 0.5
        assert reject.status == "rejected"
        assert metrics.count == 1
