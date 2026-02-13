"""M0.T1: Schema validation rejects malformed control API requests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from shisad.core.api.schema import (
    ActionConfirmResult,
    ActionPendingResult,
    ActionRejectResult,
    ChannelIngestResult,
    ConfirmationMetricsResult,
    DaemonShutdownResult,
    DaemonStatusResult,
    DashboardMarkFalsePositiveResult,
    DashboardQueryResult,
    JsonRpcRequest,
    LockdownSetResult,
    MemoryDeleteResult,
    MemoryExportResult,
    MemoryGetResult,
    MemoryIngestResult,
    MemoryListResult,
    MemoryRetrieveResult,
    MemoryRotateKeyResult,
    MemoryVerifyResult,
    MemoryWriteResult,
    PolicyExplainResult,
    SessionCreateParams,
    SessionGrantCapabilitiesResult,
    SessionMessageParams,
    SessionRollbackResult,
    SkillInstallResult,
    SkillListResult,
    SkillProfileResult,
    SkillReviewResult,
    SkillRevokeResult,
    TaskCreateResult,
    TaskDisableResult,
    TaskListResult,
    TaskPendingConfirmationsResult,
    TaskTriggerEventResult,
    ToolExecuteParams,
    ToolExecuteResult,
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

    def test_tool_execute_result_preserves_confirmation_fields(self) -> None:
        result = ToolExecuteResult.model_validate(
            {
                "allowed": False,
                "reason": "control_plane_confirmation_required",
                "confirmation_required": True,
                "confirmation_id": "confirm-1",
                "decision_nonce": "nonce-1",
            }
        )
        dumped = result.model_dump(mode="json", exclude_unset=True)
        assert dumped["confirmation_required"] is True
        assert dumped["confirmation_id"] == "confirm-1"

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

    def test_m1_additional_result_models_accept_runtime_shapes(self) -> None:
        memory_ingest = MemoryIngestResult.model_validate({"id": "m1"})
        memory_retrieve = MemoryRetrieveResult.model_validate(
            {"results": [{"id": "e1"}], "count": 1}
        )
        memory_write = MemoryWriteResult.model_validate({"written": True})
        memory_list = MemoryListResult.model_validate({"entries": [], "count": 0})
        memory_get = MemoryGetResult.model_validate({"entry": {"id": "e1"}})
        memory_delete = MemoryDeleteResult.model_validate({"deleted": True, "entry_id": "e1"})
        memory_export = MemoryExportResult.model_validate({"format": "json", "data": {}})
        memory_verify = MemoryVerifyResult.model_validate({"verified": True, "entry_id": "e1"})
        memory_rotate = MemoryRotateKeyResult.model_validate(
            {"rotated": True, "active_key_id": "k1", "reencrypt_existing": False}
        )
        skill_list = SkillListResult.model_validate({"skills": [], "count": 0})
        skill_review = SkillReviewResult.model_validate({"allowed": True})
        skill_install = SkillInstallResult.model_validate({"status": "installed"})
        skill_profile = SkillProfileResult.model_validate({"network": []})
        skill_revoke = SkillRevokeResult.model_validate(
            {"revoked": True, "skill_name": "s1", "reason": "manual"}
        )
        task_create = TaskCreateResult.model_validate({"id": "t1"})
        task_list = TaskListResult.model_validate({"tasks": [], "count": 0})
        task_disable = TaskDisableResult.model_validate({"disabled": True, "task_id": "t1"})
        task_trigger = TaskTriggerEventResult.model_validate({"runs": [], "count": 0})
        task_pending = TaskPendingConfirmationsResult.model_validate(
            {"task_id": "t1", "pending": [], "count": 0}
        )
        dashboard = DashboardQueryResult.model_validate({"count": 0})
        dashboard_marked = DashboardMarkFalsePositiveResult.model_validate(
            {"marked": True, "event_id": "evt", "reason": "manual"}
        )
        daemon_status = DaemonStatusResult.model_validate({"status": "running"})
        daemon_shutdown = DaemonShutdownResult.model_validate({"status": "shutting_down"})
        policy_explain = PolicyExplainResult.model_validate(
            {
                "session_id": "s1",
                "tool_name": "shell_exec",
                "action": "run",
                "effective_policy": {},
                "control_plane": {},
                "contributors": {},
            }
        )
        lockdown = LockdownSetResult.model_validate(
            {"session_id": "s1", "level": "caution", "reason": "manual"}
        )
        ingest = ChannelIngestResult.model_validate(
            {"session_id": "s1", "response": "ok", "ingress_risk": 0.1}
        )
        assert memory_ingest.model_dump(mode="json")["id"] == "m1"
        assert memory_retrieve.count == 1
        assert memory_write.model_dump(mode="json")["written"] is True
        assert memory_list.count == 0
        assert memory_get.entry == {"id": "e1"}
        assert memory_delete.deleted is True
        assert memory_export.format == "json"
        assert memory_verify.verified is True
        assert memory_rotate.active_key_id == "k1"
        assert skill_list.count == 0
        assert skill_review.model_dump(mode="json")["allowed"] is True
        assert skill_install.model_dump(mode="json")["status"] == "installed"
        assert skill_profile.model_dump(mode="json")["network"] == []
        assert skill_revoke.revoked is True
        assert task_create.model_dump(mode="json")["id"] == "t1"
        assert task_list.count == 0
        assert task_disable.disabled is True
        assert task_trigger.count == 0
        assert task_pending.task_id == "t1"
        assert dashboard.model_dump(mode="json")["count"] == 0
        assert dashboard_marked.marked is True
        assert daemon_status.status == "running"
        assert daemon_shutdown.status == "shutting_down"
        assert policy_explain.tool_name == "shell_exec"
        assert lockdown.level == "caution"
        assert ingest.ingress_risk == 0.1
