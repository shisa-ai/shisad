"""M0.T1: Schema validation rejects malformed control API requests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from shisad.core.api.schema import (
    ActionConfirmResult,
    ActionPendingResult,
    ActionRejectResult,
    ChannelIngestResult,
    ChannelPairingProposalResult,
    ConfirmationMetricsResult,
    DaemonShutdownResult,
    DaemonStatusResult,
    DashboardMarkFalsePositiveResult,
    DashboardQueryResult,
    DoctorCheckResult,
    JsonRpcRequest,
    LockdownSetResult,
    MemoryDeleteResult,
    MemoryEntryParams,
    MemoryExportResult,
    MemoryGetResult,
    MemoryIngestParams,
    MemoryIngestResult,
    MemoryLifecycleParams,
    MemoryListParams,
    MemoryListResult,
    MemoryRetrieveResult,
    MemoryRotateKeyResult,
    MemorySupersedeParams,
    MemoryVerifyResult,
    MemoryWorkflowStateParams,
    MemoryWriteParams,
    MemoryWriteResult,
    NoteCreateParams,
    PolicyExplainResult,
    RealityCheckReadResult,
    RealityCheckSearchResult,
    SessionCreateParams,
    SessionGrantCapabilitiesResult,
    SessionListResult,
    SessionMessageParams,
    SessionRollbackResult,
    SessionSetModeResult,
    SkillInstallResult,
    SkillListResult,
    SkillProfileResult,
    SkillReviewResult,
    SkillRevokeResult,
    TaskCreateParams,
    TaskCreateResult,
    TaskDisableResult,
    TaskListResult,
    TaskPendingConfirmationsResult,
    TaskTriggerEventResult,
    TodoCreateParams,
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
        assert params.tone is None

    def test_session_create_tone_accepts_known_values(self) -> None:
        params = SessionCreateParams(tone="friendly")
        assert params.tone == "friendly"

    def test_session_create_tone_rejects_unknown_values(self) -> None:
        with pytest.raises(ValidationError):
            SessionCreateParams(tone="casual")

    def test_task_create_requires_workspace_id(self) -> None:
        with pytest.raises(ValidationError):
            TaskCreateParams(
                schedule={"kind": "event", "expression": "message.received"},
                name="scan",
                goal="scan logs",
                policy_snapshot_ref="policy-1",
                created_by="alice",
            )

    def test_tool_execute_rejects_empty_command(self) -> None:
        with pytest.raises(ValidationError):
            ToolExecuteParams.model_validate(
                {
                    "session_id": "s1",
                    "tool_name": "shell_exec",
                    "command": [],
                }
            )

    def test_tool_execute_accepts_structured_arguments_map(self) -> None:
        params = ToolExecuteParams.model_validate(
            {
                "session_id": "s1",
                "tool_name": "retrieve_rag",
                "command": ["python", "-c", "print('ok')"],
                "arguments": {"query": "roadmap", "limit": 3},
            }
        )
        assert params.arguments == {"query": "roadmap", "limit": 3}

    def test_tool_execute_rejects_non_mapping_arguments(self) -> None:
        with pytest.raises(ValidationError):
            ToolExecuteParams.model_validate(
                {
                    "session_id": "s1",
                    "tool_name": "retrieve_rag",
                    "command": ["python", "-c", "print('ok')"],
                    "arguments": ["query", "roadmap"],
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
        memory_ingest = MemoryIngestResult.model_validate(
            {
                "chunk_id": "m1",
                "source_id": "src-1",
                "source_type": "user",
                "collection": "user_curated",
                "created_at": "2026-02-13T00:00:00+00:00",
                "content_sanitized": "safe",
                "risk_score": 0.1,
                "original_hash": "h1",
            }
        )
        memory_retrieve = MemoryRetrieveResult.model_validate(
            {
                "results": [
                    {
                        "chunk_id": "m1",
                        "source_id": "src-1",
                        "source_type": "user",
                        "collection": "user_curated",
                        "created_at": "2026-02-13T00:00:00+00:00",
                        "content_sanitized": "safe",
                        "risk_score": 0.1,
                        "original_hash": "h1",
                    }
                ],
                "count": 1,
            }
        )
        memory_write = MemoryWriteResult.model_validate({"kind": "allow", "entry": {"id": "e1"}})
        memory_list = MemoryListResult.model_validate(
            {"entries": [{"id": "e1", "entry_type": "fact", "key": "k1"}], "count": 1}
        )
        memory_get = MemoryGetResult.model_validate({"entry": {"id": "e1"}})
        memory_delete = MemoryDeleteResult.model_validate({"deleted": True, "entry_id": "e1"})
        memory_export = MemoryExportResult.model_validate({"format": "json", "data": {}})
        memory_verify = MemoryVerifyResult.model_validate({"verified": True, "entry_id": "e1"})
        memory_rotate = MemoryRotateKeyResult.model_validate(
            {"rotated": True, "active_key_id": "k1", "reencrypt_existing": False}
        )
        skill_list = SkillListResult.model_validate({"skills": [], "count": 0})
        skill_review = SkillReviewResult.model_validate({"signature": "trusted"})
        skill_install = SkillInstallResult.model_validate({"allowed": True, "status": "installed"})
        skill_profile = SkillProfileResult.model_validate({"network_domains": []})
        skill_revoke = SkillRevokeResult.model_validate(
            {"revoked": True, "skill_name": "s1", "reason": "manual"}
        )
        task_create = TaskCreateResult.model_validate({"id": "t1"})
        task_list = TaskListResult.model_validate(
            {"tasks": [{"id": "t1", "name": "demo", "enabled": True}], "count": 1}
        )
        session_list = SessionListResult.model_validate(
            {"sessions": [{"id": "s1", "state": "active", "user_id": "alice"}]}
        )
        task_disable = TaskDisableResult.model_validate({"disabled": True, "task_id": "t1"})
        task_trigger = TaskTriggerEventResult.model_validate({"runs": [], "count": 0})
        task_pending = TaskPendingConfirmationsResult.model_validate(
            {"task_id": "t1", "pending": [], "count": 0}
        )
        dashboard = DashboardQueryResult.model_validate(
            {
                "count": 1,
                "events": [{"event_type": "SessionCreated", "session_id": "s1"}],
                "alerts": [{"event_id": "evt", "event_type": "AlertRaised"}],
                "timeline": [{"skill_name": "demo", "versions": ["1.0.0"]}],
            }
        )
        dashboard_marked = DashboardMarkFalsePositiveResult.model_validate(
            {"marked": True, "event_id": "evt", "reason": "manual"}
        )
        daemon_status = DaemonStatusResult.model_validate({"status": "running"})
        realitycheck_search = RealityCheckSearchResult.model_validate(
            {
                "ok": True,
                "query": "roadmap",
                "mode": "local",
                "results": [],
            }
        )
        realitycheck_read = RealityCheckReadResult.model_validate(
            {
                "ok": True,
                "path": "/tmp/source.md",
                "content": "hello",
                "sha256": "abc123",
            }
        )
        doctor = DoctorCheckResult.model_validate(
            {
                "status": "ok",
                "component": "realitycheck",
                "checks": {"realitycheck": {"status": "ok"}},
            }
        )
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
        risk = ToolExecuteResult.model_validate(
            {"allowed": True, "exit_code": 0, "confirmation_required": False}
        )
        ingest = ChannelIngestResult.model_validate(
            {"session_id": "s1", "response": "ok", "ingress_risk": 0.1}
        )
        set_mode = SessionSetModeResult.model_validate(
            {"session_id": "s1", "mode": "admin_cleanroom", "changed": True}
        )
        pairing = ChannelPairingProposalResult.model_validate(
            {
                "proposal_id": "p1",
                "proposal_path": "/tmp/p1.json",
                "generated_at": "2026-02-15T00:00:00+00:00",
                "entries": [],
                "count": 0,
                "config_patch": {},
                "applied": False,
            }
        )
        assert memory_ingest.chunk_id == "m1"
        assert memory_retrieve.count == 1
        assert memory_write.kind == "allow"
        assert memory_list.count == 1
        assert memory_list.entries[0].id == "e1"
        assert memory_get.entry == {"id": "e1"}
        assert memory_delete.deleted is True
        assert memory_export.format == "json"
        assert memory_verify.verified is True
        assert memory_rotate.active_key_id == "k1"
        assert skill_list.count == 0
        assert skill_review.signature == "trusted"
        assert skill_install.model_dump(mode="json")["status"] == "installed"
        assert skill_profile.network_domains == []
        assert skill_revoke.revoked is True
        assert task_create.model_dump(mode="json")["id"] == "t1"
        assert task_list.count == 1
        assert task_list.tasks[0].id == "t1"
        assert session_list.sessions[0].id == "s1"
        assert task_disable.disabled is True
        assert task_trigger.count == 0
        assert task_pending.task_id == "t1"
        assert dashboard.model_dump(mode="json")["count"] == 1
        assert dashboard.events[0].session_id == "s1"
        assert dashboard_marked.marked is True
        assert daemon_status.status == "running"
        assert daemon_status.delivery == {}
        assert daemon_status.realitycheck == {}
        assert realitycheck_search.mode == "local"
        assert realitycheck_read.path == "/tmp/source.md"
        assert doctor.component == "realitycheck"
        assert daemon_shutdown.status == "shutting_down"
        assert policy_explain.tool_name == "shell_exec"
        assert lockdown.level == "caution"
        assert risk.allowed is True
        assert ingest.ingress_risk == 0.1
        assert set_mode.mode == "admin_cleanroom"
        assert pairing.proposal_id == "p1"

    def test_m1_memory_write_params_accept_ingress_context_shape(self) -> None:
        params = MemoryWriteParams.model_validate(
            {
                "ingress_context": "handle-1",
                "entry_type": "fact",
                "key": "profile.name",
                "value": "alice",
            }
        )

        assert params.ingress_context == "handle-1"
        assert params.derivation_path == "direct"

    def test_m1_memory_ingest_params_accept_handle_bound_shape(self) -> None:
        params = MemoryIngestParams.model_validate(
            {
                "ingress_context": "handle-1",
                "content": "remember this",
                "content_digest": "sha256:abc",
                "derivation_path": "summary",
                "parent_digest": "sha256:parent",
            }
        )

        assert params.ingress_context == "handle-1"
        assert params.source_id is None

    def test_m1_memory_ingest_params_reject_missing_source_and_orphaned_binding_fields(
        self,
    ) -> None:
        with pytest.raises(ValidationError):
            MemoryIngestParams.model_validate({"content": "hello"})

        with pytest.raises(ValidationError):
            MemoryIngestParams.model_validate(
                {
                    "source_id": "src-1",
                    "content": "hello",
                    "content_digest": "sha256:abc",
                }
            )

    def test_m1_memory_write_params_accept_direct_control_shape_without_ingress(self) -> None:
        params = MemoryWriteParams.model_validate(
            {
                "entry_type": "fact",
                "key": "profile.name",
                "value": "alice",
            }
        )

        assert params.ingress_context is None
        assert params.derivation_path == "direct"

    def test_m1_memory_write_params_accept_canonical_and_legacy_entry_type_aliases(self) -> None:
        canonical = MemoryWriteParams.model_validate(
            {
                "entry_type": "soft_constraint",
                "key": "behavior.reply_style",
                "value": "keep replies short",
            }
        )
        legacy = MemoryWriteParams.model_validate(
            {
                "entry_type": "context",
                "key": "legacy.context",
                "value": "remember this",
            }
        )

        assert canonical.entry_type == "soft_constraint"
        assert legacy.entry_type == "context"

    def test_m1_memory_write_params_reject_legacy_source_and_orphaned_binding_fields(self) -> None:
        with pytest.raises(ValidationError):
            MemoryWriteParams.model_validate(
                {
                    "entry_type": "fact",
                    "key": "profile.name",
                    "value": "alice",
                    "source": {
                        "origin": "user",
                        "source_id": "msg-1",
                        "extraction_method": "cli",
                    },
                }
            )

        with pytest.raises(ValidationError):
            MemoryWriteParams.model_validate(
                {
                    "entry_type": "fact",
                    "key": "profile.name",
                    "value": "alice",
                    "content_digest": "sha256:abc",
                }
            )

    def test_m1_memory_supersede_params_require_non_empty_target(self) -> None:
        params = MemorySupersedeParams.model_validate(
            {
                "entry_type": "note",
                "key": "note:chain",
                "value": "updated",
                "supersedes": "entry-1",
            }
        )

        assert params.supersedes == "entry-1"

        with pytest.raises(ValidationError):
            MemorySupersedeParams.model_validate(
                {
                    "entry_type": "note",
                    "key": "note:chain",
                    "value": "updated",
                    "supersedes": "",
                }
            )

    def test_m1_note_and_todo_params_reject_legacy_trust_fields(self) -> None:
        with pytest.raises(ValidationError):
            NoteCreateParams.model_validate(
                {
                    "key": "note:1",
                    "content": "hello",
                    "origin": "external",
                }
            )

        with pytest.raises(ValidationError):
            TodoCreateParams.model_validate(
                {
                    "title": "task",
                    "origin": "external",
                }
            )

        note = NoteCreateParams.model_validate(
            {
                "key": "note:2",
                "content": "hello",
                "ingress_context": "handle-2",
                "content_digest": "sha256:def",
                "derivation_path": "extracted",
                "parent_digest": "sha256:parent",
            }
        )
        todo = TodoCreateParams.model_validate(
            {
                "title": "task",
                "ingress_context": "handle-3",
                "content_digest": "sha256:ghi",
                "derivation_path": "summary",
                "parent_digest": "sha256:parent",
            }
        )

        assert note.ingress_context == "handle-2"
        assert todo.ingress_context == "handle-3"

    def test_m1_memory_lifecycle_params_require_reason_and_valid_workflow_state(self) -> None:
        params = MemoryLifecycleParams.model_validate(
            {
                "entry_id": "entry-1",
                "reason": "manual-review",
            }
        )
        workflow = MemoryWorkflowStateParams.model_validate(
            {
                "entry_id": "entry-1",
                "workflow_state": "closed",
            }
        )

        assert params.reason == "manual-review"
        assert workflow.workflow_state == "closed"

        with pytest.raises(ValidationError):
            MemoryLifecycleParams.model_validate({"entry_id": "entry-1", "reason": ""})

    def test_m1_memory_list_params_gate_quarantined_reads_on_confirmation(self) -> None:
        with pytest.raises(ValidationError):
            MemoryListParams.model_validate({"include_quarantined": True})

        params = MemoryListParams.model_validate(
            {
                "include_quarantined": True,
                "confirmed": True,
                "limit": 5,
            }
        )
        assert params.include_quarantined is True
        assert params.confirmed is True

    def test_m1_memory_entry_params_gate_quarantined_reads_on_confirmation(self) -> None:
        with pytest.raises(ValidationError):
            MemoryEntryParams.model_validate(
                {
                    "entry_id": "e1",
                    "include_quarantined": True,
                }
            )

        params = MemoryEntryParams.model_validate(
            {
                "entry_id": "e1",
                "include_quarantined": True,
                "confirmed": True,
            }
        )
        assert params.include_quarantined is True
        assert params.confirmed is True

    def test_m4_list_entry_models_preserve_additional_payload_fields(self) -> None:
        memory_list = MemoryListResult.model_validate(
            {
                "entries": [
                    {
                        "entry_id": "e1",
                        "entry_type": "fact",
                        "key": "favorite_color",
                        "value": "blue",
                        "created_at": "2026-02-13T00:00:00+00:00",
                    }
                ],
                "count": 1,
            }
        )
        action_pending = ActionPendingResult.model_validate(
            {
                "actions": [
                    {
                        "confirmation_id": "c1",
                        "status": "pending",
                        "tool_name": "http_request",
                        "extra_runtime_field": "kept",
                    }
                ],
                "count": 1,
            }
        )

        memory_dump = memory_list.model_dump(mode="json")
        action_dump = action_pending.model_dump(mode="json")
        assert memory_dump["entries"][0]["value"] == "blue"
        assert action_dump["actions"][0]["extra_runtime_field"] == "kept"
