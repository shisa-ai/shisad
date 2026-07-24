"""Restart recovery for durably unresolved approved-action attempts."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from shisad.channels.base import DeliveryTarget
from shisad.core.api.schema import SessionCreateParams
from shisad.core.approval import (
    approval_envelope_hash,
    canonical_sha256,
    legacy_software_confirmation_requirement,
)
from shisad.core.atomic_state import AtomicWriteError, AtomicWriteStage
from shisad.core.config import DaemonConfig
from shisad.core.events import ToolRejected
from shisad.core.request_context import RequestContext
from shisad.core.tools.schema import (
    StableIdempotencyAdapter,
    ToolDefinition,
    ToolParameter,
    ToolRetryClass,
)
from shisad.core.types import Capability, EventId, SessionId, ToolName
from shisad.daemon.control_handlers import DaemonControlHandlers
from shisad.daemon.handlers._impl import ApprovedToolExecutionResult
from shisad.daemon.services import DaemonServices
from shisad.scheduler.manager import SchedulerManager
from shisad.scheduler.schema import Schedule
from shisad.security.control_plane.schema import Origin, build_action
from shisad.security.lockdown import LockdownLevel


def _configure_model_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")


def _config(tmp_path: Path) -> DaemonConfig:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text('version: "1"\ndefault_require_confirmation: false\n', encoding="utf-8")
    return DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        assistant_fs_roots=[tmp_path],
        log_level="INFO",
    )


async def _session_and_impl(
    services: DaemonServices,
) -> tuple[SessionId, object]:
    handlers = DaemonControlHandlers(services=services)
    created = await handlers.handle_session_create(
        SessionCreateParams(channel="cli", user_id="alice", workspace_id="ws1"),
        RequestContext(),
    )
    return SessionId(created.session_id), handlers._impl


def _audit_rows(config: DaemonConfig) -> list[dict[str, object]]:
    path = config.data_dir / "audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _control_plane_history_rows(config: DaemonConfig) -> list[dict[str, object]]:
    path = config.data_dir / "control_plane" / "history.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _replace_with_self_asserted_fabricated_evidence(row: dict[str, object]) -> None:
    evidence = row["confirmation_evidence"]
    assert isinstance(evidence, dict)
    payload = evidence["evidence_payload"]
    assert isinstance(payload, dict)
    fabricated_payload = dict(payload)
    fabricated_payload["backend_id"] = "fabricated.backend"
    fabricated_hash = canonical_sha256(fabricated_payload)
    evidence["backend_id"] = "fabricated.backend"
    evidence["evidence_payload"] = fabricated_payload
    evidence["evidence_hash"] = fabricated_hash
    row["approval_evidence_hash"] = fabricated_hash


async def _wait_for_recovery_accounting(impl: object) -> None:
    while tasks := list(getattr(impl, "_recovery_accounting_tasks", ())):
        await asyncio.gather(*tasks)
        await asyncio.sleep(0)


async def _seed_unresolved_scheduled_time_attempt(
    config: DaemonConfig,
    *,
    bind_preflight_action: bool = False,
    lockdown_before_shutdown: bool = False,
) -> tuple[str, str]:
    services = await DaemonServices.build(config)
    try:
        session_id, raw_impl = await _session_and_impl(services)
        impl = raw_impl
        session = services.session_manager.get(session_id)
        assert session is not None
        task = services.scheduler.create_task(
            name="recovery-accounting-fault",
            goal="Recover one structural clock read",
            schedule=Schedule.from_event("message.received"),
            capability_snapshot=set(),
            policy_snapshot_ref="recovery-accounting-fault",
            created_by=session.user_id,
            workspace_id=session.workspace_id,
            max_runs=1,
        )
        preflight_action = (
            build_action(
                tool_name="time.now",
                arguments={"timezone": "UTC"},
                origin=Origin(
                    session_id=str(session_id),
                    user_id=str(session.user_id),
                    workspace_id=str(session.workspace_id),
                    task_id=task.id,
                    actor="planner",
                    channel="cli",
                ),
                workspace_roots=list(config.assistant_fs_roots),
            )
            if bind_preflight_action
            else None
        )
        pending = impl._queue_pending_action(
            session_id=session_id,
            user_id=session.user_id,
            workspace_id=session.workspace_id,
            tool_name=ToolName("time.now"),
            arguments={"timezone": "UTC"},
            reason="recovery-accounting-fault",
            capabilities=set(),
            confirmation_requirement=legacy_software_confirmation_requirement(),
            origin_turn_id="turn-recovery-accounting-fault",
            task_id=task.id,
            preflight_action=preflight_action,
        )
        services.scheduler.queue_confirmation(
            task.id,
            impl._pending_to_dict(pending, public=True),
        )
        publication = 0

        def _fail_terminal_write(stage: AtomicWriteStage) -> None:
            nonlocal publication
            if stage == AtomicWriteStage.TEMP_OPEN:
                publication += 1
            if publication == 2 and stage == AtomicWriteStage.FILE_FSYNC:
                raise OSError("crash after clock effect before terminal publication")

        impl._pending_state_fault_injector = _fail_terminal_write
        with pytest.raises(AtomicWriteError):
            await impl.do_action_confirm(
                {
                    "confirmation_id": pending.confirmation_id,
                    "decision_nonce": pending.decision_nonce,
                }
            )
        if lockdown_before_shutdown:
            impl._lockdown_manager.set_level(
                session_id,
                level=LockdownLevel.FULL_LOCKDOWN,
                reason="recovery test lockdown",
                trigger="test_recovery_lockdown",
            )
            assert impl._lockdown_manager.should_block_all_actions(session_id)
        return pending.confirmation_id, task.id
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_initial_stable_key_execution_rejects_adapter_guarantee_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    tool_name = ToolName("test.keyed-initial-drift")
    tool_definition = ToolDefinition(
        name=tool_name,
        description="Reject a stable-key execution after its provider guarantee changes.",
        parameters=[ToolParameter(name="value", type="string")],
        retry_class=ToolRetryClass.STABLE_IDEMPOTENCY_KEY,
    )
    calls: list[str] = []

    def _adapter(
        _arguments: dict[str, object],
        stable_idempotency_key: str,
    ) -> dict[str, object]:
        calls.append(stable_idempotency_key)
        return {"ok": True, "provider_operation_id": "must-not-run"}

    services = await DaemonServices.build(config)
    try:
        services.registry.register(tool_definition)
        services.idempotent_recovery_adapters[str(tool_name)] = StableIdempotencyAdapter(
            guarantee_id="test.keyed-initial-drift/provider-v1",
            operation=_adapter,
        )
        session_id, raw_impl = await _session_and_impl(services)
        impl = raw_impl
        session = services.session_manager.get(session_id)
        assert session is not None
        task = services.scheduler.create_task(
            name="initial-adapter-guarantee-drift",
            goal="Do not invoke a replacement stable-key adapter",
            schedule=Schedule.from_event("message.received"),
            capability_snapshot=set(),
            policy_snapshot_ref="adapter-guarantee-drift",
            created_by=session.user_id,
            workspace_id=session.workspace_id,
            max_runs=1,
        )
        pending = impl._queue_pending_action(
            session_id=session_id,
            user_id=session.user_id,
            workspace_id=session.workspace_id,
            tool_name=tool_name,
            arguments={"value": "create-once"},
            reason="adapter-guarantee-drift",
            capabilities=set(),
            confirmation_requirement=legacy_software_confirmation_requirement(),
            origin_turn_id="turn-adapter-guarantee-drift",
            task_id=task.id,
        )
        services.scheduler.queue_confirmation(
            task.id,
            impl._pending_to_dict(pending, public=True),
        )
        assert pending.retry_descriptor is not None
        assert (
            pending.retry_descriptor.stable_adapter_guarantee_id
            == "test.keyed-initial-drift/provider-v1"
        )

        services.idempotent_recovery_adapters[str(tool_name)] = StableIdempotencyAdapter(
            guarantee_id="test.keyed-initial-drift/provider-v2",
            operation=_adapter,
        )
        result = await impl.do_action_confirm(
            {
                "confirmation_id": pending.confirmation_id,
                "decision_nonce": pending.decision_nonce,
            }
        )

        assert result["confirmed"] is False
        assert pending.status == "failed"
        assert pending.status_reason == "approval_contract_mismatch"
        assert pending.retry_generation == 0
        assert calls == []
    finally:
        await services.shutdown()


@pytest.mark.parametrize(
    "approval_actor",
    ["control_api", "policy_loop", "daemon_recovery"],
)
@pytest.mark.asyncio
async def test_initial_stable_key_invocation_guard_rejects_post_queue_adapter_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    approval_actor: str,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    tool_name = ToolName("test.keyed-invocation-drift")
    tool_definition = ToolDefinition(
        name=tool_name,
        description="Reject replacement adapters at the initial invocation boundary.",
        parameters=[ToolParameter(name="value", type="string")],
        retry_class=ToolRetryClass.STABLE_IDEMPOTENCY_KEY,
    )
    initial_calls: list[str] = []
    replacement_calls: list[str] = []

    def _initial_adapter(
        _arguments: dict[str, object],
        stable_idempotency_key: str,
    ) -> dict[str, object]:
        initial_calls.append(stable_idempotency_key)
        return {"ok": True, "provider_operation_id": "initial-must-not-run"}

    def _replacement_adapter(
        _arguments: dict[str, object],
        stable_idempotency_key: str,
    ) -> dict[str, object]:
        replacement_calls.append(stable_idempotency_key)
        return {"ok": True, "provider_operation_id": "replacement-must-not-run"}

    services = await DaemonServices.build(config)
    try:
        services.registry.register(tool_definition)
        services.idempotent_recovery_adapters[str(tool_name)] = StableIdempotencyAdapter(
            guarantee_id="test.keyed-invocation-drift/provider-v1",
            operation=_initial_adapter,
        )
        session_id, raw_impl = await _session_and_impl(services)
        impl = raw_impl
        session = services.session_manager.get(session_id)
        assert session is not None
        action = build_action(
            tool_name=str(tool_name),
            arguments={"value": "create-once"},
            origin=Origin(
                session_id=str(session_id),
                user_id=str(session.user_id),
                workspace_id=str(session.workspace_id),
                actor=approval_actor,
                channel="cli",
            ),
            workspace_roots=list(config.assistant_fs_roots),
        )
        queued: list[object] = []
        queue_pending_action = impl._queue_pending_action

        def _queue_then_replace(**kwargs: object) -> object:
            pending = queue_pending_action(**kwargs)
            queued.append(pending)
            services.idempotent_recovery_adapters[str(tool_name)] = StableIdempotencyAdapter(
                guarantee_id="test.keyed-invocation-drift/provider-v2",
                operation=_replacement_adapter,
            )
            return pending

        monkeypatch.setattr(impl, "_queue_pending_action", _queue_then_replace)
        result = await impl._execute_approved_action(
            sid=session_id,
            user_id=session.user_id,
            workspace_id=session.workspace_id,
            tool_name=tool_name,
            arguments={"value": "create-once"},
            capabilities=set(),
            approval_actor=approval_actor,
            execution_action=action,
            persist_attempt_before_effect=True,
        )

        assert result.success is False
        assert result.outcome_unknown is False
        assert result.error == "idempotent_adapter_identity_mismatch"
        assert len(queued) == 1
        pending = queued[0]
        assert pending.status == "failed"
        assert pending.status_reason == "idempotent_adapter_identity_mismatch"
        assert pending.retry_descriptor is not None
        assert (
            pending.retry_descriptor.stable_adapter_guarantee_id
            == "test.keyed-invocation-drift/provider-v1"
        )
        assert initial_calls == []
        assert replacement_calls == []
    finally:
        await services.shutdown()


@pytest.mark.parametrize(
    ("mutation_phase", "surface"),
    [
        ("durable", "preflight"),
        ("durable", "evidence"),
        ("durable", "delivery-target"),
        ("durable", "task-envelope"),
        ("durable", "origin-turn"),
        ("durable", "result-id"),
        ("durable", "marker-timestamp"),
        ("loaded", "preflight"),
        ("loaded", "evidence"),
        ("loaded", "delivery-target"),
        ("loaded", "task-envelope"),
        ("loaded", "origin-turn"),
        ("loaded", "result-id"),
        ("loaded", "marker-timestamp"),
    ],
)
@pytest.mark.asyncio
async def test_terminal_recovery_accounting_rejects_coherent_authority_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation_phase: str,
    surface: str,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    confirmation_id, task_id = await _seed_unresolved_scheduled_time_attempt(
        config,
        bind_preflight_action=True,
    )
    pending_path = config.data_dir / "pending_actions.json"

    restarted = await DaemonServices.build(config)
    try:
        handlers = DaemonControlHandlers(services=restarted)
        impl = handlers._impl
        accounting_tasks = list(impl._recovery_accounting_tasks)
        assert len(accounting_tasks) == 1
        for task in accounting_tasks:
            task.cancel()
        await asyncio.gather(*accounting_tasks, return_exceptions=True)
        recovered = impl._pending_actions[confirmation_id]
        assert recovered.status == "approved"
        assert recovered.recovery_effect_invoked is True
        assert recovered.recovery_accounting_pending is True
        assert recovered.preflight_action is not None
        assert recovered.confirmation_evidence is not None

        if mutation_phase == "loaded":
            if surface == "preflight":
                recovered.preflight_action = recovered.preflight_action.model_copy(
                    update={"resource_ids": ["forged://resource"]}
                )
            else:
                if surface == "evidence":
                    recovered.confirmation_evidence = recovered.confirmation_evidence.model_copy(
                        update={"approver_principal_id": "mallory"}
                    )
                elif surface == "delivery-target":
                    recovered.delivery_target = DeliveryTarget(
                        channel="matrix",
                        recipient="mallory-room",
                    )
                elif surface == "task-envelope":
                    recovered.approval_task_envelope_id = "forged-task-envelope"
                elif surface == "origin-turn":
                    recovered.origin_turn_id = "forged-origin-turn"
                elif surface == "result-id":
                    recovered.result_id = "result-forged"
                else:
                    recovered.recovery_event_identity_untrusted = True
                    recovered.recovery_event_identity_untrusted_at = datetime.fromisoformat(
                        "2000-01-01T00:00:00+00:00"
                    )
            await impl._account_recovered_attempt(confirmation_id)
            terminal = impl._pending_actions[confirmation_id]
            assert terminal.status == "outcome_unknown"
            assert terminal.status_reason == "uncertain_effect_requires_fresh_approval"
            assert terminal.recovery_accounting_pending is False
    finally:
        await restarted.shutdown()

    if mutation_phase == "durable":
        durable_rows = json.loads(pending_path.read_text(encoding="utf-8"))
        durable = next(row for row in durable_rows if row["confirmation_id"] == confirmation_id)
        if surface == "preflight":
            durable["preflight_action"]["resource_ids"] = ["forged://resource"]
        elif surface == "evidence":
            durable["confirmation_evidence"]["approver_principal_id"] = "mallory"
        elif surface == "delivery-target":
            durable["delivery_target"] = {
                "channel": "matrix",
                "recipient": "mallory-room",
                "workspace_hint": "",
                "thread_id": "",
            }
        elif surface == "task-envelope":
            durable["approval_task_envelope_id"] = "forged-task-envelope"
        elif surface == "origin-turn":
            durable["origin_turn_id"] = "forged-origin-turn"
        elif surface == "result-id":
            durable["result_id"] = "result-forged"
        else:
            durable["recovery_event_identity_untrusted"] = True
            durable["recovery_event_identity_untrusted_at"] = "2000-01-01T00:00:00+00:00"
        pending_path.write_text(json.dumps(durable_rows, indent=2), encoding="utf-8")

        replayed = await DaemonServices.build(config)
        try:
            replayed_handlers = DaemonControlHandlers(services=replayed)
            await _wait_for_recovery_accounting(replayed_handlers._impl)
            terminal = replayed_handlers._impl._pending_actions[confirmation_id]
            assert terminal.status == "outcome_unknown"
            assert terminal.status_reason == "uncertain_effect_requires_fresh_approval"
            assert terminal.recovery_accounting_pending is False
        finally:
            await replayed.shutdown()

    assert terminal.approval_evidence_hash == ""
    assert terminal.execution_authorization_kind == ""
    assert terminal.confirmation_evidence is None
    assert terminal.preflight_action is None
    assert terminal.merged_policy is None
    assert terminal.pep_context is None
    assert terminal.pep_elevation is None
    assert terminal.retry_descriptor is None
    assert terminal.provider_operation_id == ""
    assert terminal.recovery_result == {}
    assert terminal.recovery_effect_invoked is False

    recovery_events = [row for row in _audit_rows(config) if row.get("actor") == "recovery"]
    assert [row.get("event_type") for row in recovery_events] == ["ToolRejected"]
    assert all(
        row.get("data", {}).get("approval_approver_principal_id") != "mallory"
        for row in recovery_events
    )
    for row in recovery_events:
        assert row.get("timestamp") != "2000-01-01T00:00:00+00:00"
        assert row.get("session_id") is None
        event_data = row.get("data")
        assert isinstance(event_data, dict)
        assert event_data.get("session_id") is None
        assert event_data.get("tool_name") == ""
        assert event_data.get("delivery_target") is None
        for identity_field in (
            "action_id",
            "origin_turn_id",
            "user_id",
            "workspace_id",
            "task_id",
            "execution_attempt_id",
            "result_id",
            "followup_id",
            "approval_session_id",
            "approval_task_envelope_id",
            "approval_confirmation_id",
        ):
            assert event_data.get(identity_field) == ""
        assert event_data.get("approval_decision_nonce") == ""
        assert event_data.get("approval_timestamp") == ""
        assert event_data.get("approval_evidence_hash") == ""
    recovered_task = (
        replayed.scheduler.get_task(task_id)
        if mutation_phase == "durable"
        else restarted.scheduler.get_task(task_id)
    )
    assert recovered_task is not None
    assert recovered_task.success_count == 1
    assert recovered_task.failure_count == 0
    assert recovered_task.enabled is False


@pytest.mark.asyncio
async def test_invalid_recovery_identity_cannot_select_existing_audit_event_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    confirmation_id, _task_id = await _seed_unresolved_scheduled_time_attempt(config)

    restarted = await DaemonServices.build(config)
    try:
        handlers = DaemonControlHandlers(services=restarted)
        impl = handlers._impl
        accounting_tasks = list(impl._recovery_accounting_tasks)
        assert len(accounting_tasks) == 1
        for task in accounting_tasks:
            task.cancel()
        await asyncio.gather(*accounting_tasks, return_exceptions=True)
        recovered = impl._pending_actions[confirmation_id]
        recovered.origin_turn_id = "forged-origin-turn"
        recovered.recovery_effect_invoked = False
        forged_identity_event_id = EventId(
            impl._recovery_accounting_key(recovered, "audit:ToolRejected")
        )
        await impl._event_bus.publish(
            ToolRejected(
                event_id=forged_identity_event_id,
                timestamp=datetime(2000, 1, 1, tzinfo=UTC),
                session_id=None,
                actor="recovery",
                tool_name=ToolName(""),
                reason="preexisting-forged-identity-correlation",
            )
        )

        await impl._account_recovered_attempt(confirmation_id)

        terminal = impl._pending_actions[confirmation_id]
        assert terminal.recovery_accounting_pending is False
        recovery_rejections = [
            row
            for row in _audit_rows(config)
            if row.get("event_type") == "ToolRejected" and row.get("actor") == "recovery"
        ]
        assert len(recovery_rejections) == 2
        assert len({row.get("event_id") for row in recovery_rejections}) == 2

        terminal.recovery_event_identity_untrusted_at = datetime.fromisoformat(
            "2001-01-01T00:00:00+00:00"
        )
        terminal.recovery_anonymous_accounting_id = "forged-after-anonymous-accounting"
        lifecycle = impl._pending_action_lifecycle_authority()
        lifecycle.persist_adopted(persist=impl._persist_pending_actions)
        assert terminal.recovery_event_identity_untrusted is True
        assert terminal.recovery_event_identity_untrusted_at != datetime.fromisoformat(
            "2001-01-01T00:00:00+00:00"
        )
        assert terminal.recovery_anonymous_accounting_id != "forged-after-anonymous-accounting"
        terminal.recovery_event_identity_untrusted = False
        lifecycle.persist_adopted(persist=impl._persist_pending_actions)
        assert terminal.recovery_event_identity_untrusted is True
    finally:
        await restarted.shutdown()


@pytest.mark.asyncio
async def test_terminal_purge_waits_for_recovery_accounting_convergence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    confirmation_id, _task_id = await _seed_unresolved_scheduled_time_attempt(config)

    restarted = await DaemonServices.build(config)
    try:
        handlers = DaemonControlHandlers(services=restarted)
        impl = handlers._impl
        accounting_tasks = list(impl._recovery_accounting_tasks)
        assert len(accounting_tasks) == 1
        for task in accounting_tasks:
            task.cancel()
        await asyncio.gather(*accounting_tasks, return_exceptions=True)
        recovered = impl._pending_actions[confirmation_id]
        assert recovered.recovery_accounting_pending is True

        blocked_purge = await impl.do_action_purge({"status": "terminal", "limit": 20})

        assert blocked_purge["purged"] == 0
        assert blocked_purge["confirmation_ids"] == []
        assert impl._pending_actions.get(confirmation_id) is recovered
        durable_rows = json.loads(
            (config.data_dir / "pending_actions.json").read_text(encoding="utf-8")
        )
        durable = next(row for row in durable_rows if row["confirmation_id"] == confirmation_id)
        assert durable["recovery_accounting_pending"] is True

        await impl._account_recovered_attempt(confirmation_id)
        assert recovered.recovery_accounting_pending is False
        completed_purge = await impl.do_action_purge({"status": "terminal", "limit": 20})
        assert completed_purge["purged"] == 1
        assert completed_purge["confirmation_ids"] == [confirmation_id]
        assert confirmation_id not in impl._pending_actions
    finally:
        await restarted.shutdown()


@pytest.mark.asyncio
async def test_unsigned_predecision_recovery_marker_cannot_be_trust_laundered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    services = await DaemonServices.build(config)
    try:
        session_id, raw_impl = await _session_and_impl(services)
        impl = raw_impl
        session = services.session_manager.get(session_id)
        assert session is not None
        pending = impl._queue_pending_action(
            session_id=session_id,
            user_id=session.user_id,
            workspace_id=session.workspace_id,
            tool_name=ToolName("time.now"),
            arguments={"timezone": "UTC"},
            reason="unsigned-predecision-recovery-marker",
            capabilities=set(),
            confirmation_requirement=legacy_software_confirmation_requirement(),
            origin_turn_id="turn-unsigned-predecision-recovery-marker",
        )
        confirmation_id = pending.confirmation_id
    finally:
        await services.shutdown()

    pending_path = config.data_dir / "pending_actions.json"
    durable_rows = json.loads(pending_path.read_text(encoding="utf-8"))
    durable = next(row for row in durable_rows if row["confirmation_id"] == confirmation_id)
    durable["recovery_event_identity_untrusted"] = True
    durable["recovery_event_identity_untrusted_at"] = "2000-01-01T00:00:00+00:00"
    durable["recovery_anonymous_accounting_id"] = "forged-anonymous-accounting-id"
    pending_path.write_text(json.dumps(durable_rows, indent=2), encoding="utf-8")

    restarted = await DaemonServices.build(config)
    try:
        handlers = DaemonControlHandlers(services=restarted)
        impl = handlers._impl
        recovered = impl._pending_actions[confirmation_id]
        assert recovered.status == "pending"
        assert recovered.recovery_event_identity_untrusted is False
        assert recovered.recovery_event_identity_untrusted_at is None
        assert recovered.recovery_anonymous_accounting_id == ""

        publication = 0

        def _fail_terminal_write(stage: AtomicWriteStage) -> None:
            nonlocal publication
            if stage == AtomicWriteStage.TEMP_OPEN:
                publication += 1
            if publication == 2 and stage == AtomicWriteStage.FILE_FSYNC:
                raise OSError("crash after sanitized-marker effect invocation")

        impl._pending_state_fault_injector = _fail_terminal_write
        with pytest.raises(AtomicWriteError):
            await impl.do_action_confirm(
                {
                    "confirmation_id": confirmation_id,
                    "decision_nonce": recovered.decision_nonce,
                }
            )
    finally:
        await restarted.shutdown()

    replayed = await DaemonServices.build(config)
    try:
        replayed_handlers = DaemonControlHandlers(services=replayed)
        await _wait_for_recovery_accounting(replayed_handlers._impl)
        recovery_events = [row for row in _audit_rows(config) if row.get("actor") == "recovery"]
        assert [row.get("event_type") for row in recovery_events] == ["ToolExecuted"]
        assert recovery_events[0].get("timestamp") != "2000-01-01T00:00:00+00:00"
        assert recovery_events[0].get("data", {}).get("approval_confirmation_id") == confirmation_id
    finally:
        await replayed.shutdown()


@pytest.mark.parametrize(
    "live_drift",
    ["human-backend", "human-tool-schema", "policy-stable-adapter"],
)
@pytest.mark.asyncio
async def test_terminal_recovery_accounting_preserves_authenticated_result_across_live_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    live_drift: str,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    adapter_calls: list[str] = []
    stable_tool_name = ToolName("test.terminal-accounting-stable")
    stable_tool_definition = ToolDefinition(
        name=stable_tool_name,
        description="Persist one stable-key recovery result before accounting.",
        parameters=[ToolParameter(name="value", type="string")],
        retry_class=ToolRetryClass.STABLE_IDEMPOTENCY_KEY,
    )

    def _stable_adapter(
        _arguments: dict[str, object],
        stable_idempotency_key: str,
    ) -> dict[str, object]:
        adapter_calls.append(stable_idempotency_key)
        return {
            "ok": True,
            "provider_operation_id": "terminal-accounting-provider-operation",
        }

    task_id = ""
    if live_drift == "policy-stable-adapter":

        class _ProcessStopped(BaseException):
            pass

        seeded = await DaemonServices.build(config)
        try:
            seeded.registry.register(stable_tool_definition)
            seeded.idempotent_recovery_adapters[str(stable_tool_name)] = StableIdempotencyAdapter(
                guarantee_id="test.terminal-accounting-stable/provider-v1",
                operation=_stable_adapter,
            )
            session_id, raw_impl = await _session_and_impl(seeded)
            impl = raw_impl
            session = seeded.session_manager.get(session_id)
            assert session is not None
            action = build_action(
                tool_name=str(stable_tool_name),
                arguments={"value": "create-once"},
                origin=Origin(
                    session_id=str(session_id),
                    user_id=str(session.user_id),
                    workspace_id=str(session.workspace_id),
                    actor="policy_loop",
                    channel="cli",
                ),
                workspace_roots=list(config.assistant_fs_roots),
            )

            def _stop_before_effect(**_kwargs: object) -> None:
                raise _ProcessStopped

            monkeypatch.setattr(impl._rate_limiter, "consume", _stop_before_effect)
            with pytest.raises(_ProcessStopped):
                await impl._execute_approved_action(
                    sid=session_id,
                    user_id=session.user_id,
                    workspace_id=session.workspace_id,
                    tool_name=stable_tool_name,
                    arguments={"value": "create-once"},
                    capabilities=set(),
                    approval_actor="policy_loop",
                    execution_action=action,
                    persist_attempt_before_effect=True,
                )
            seeded_pending = next(iter(impl._pending_actions.values()))
            confirmation_id = seeded_pending.confirmation_id
            assert seeded_pending.status == "executing"
            assert seeded_pending.execution_authorization_kind == "policy_allow"
        finally:
            await seeded.shutdown()
    else:
        confirmation_id, task_id = await _seed_unresolved_scheduled_time_attempt(
            config,
            bind_preflight_action=True,
        )

    recovered_services = await DaemonServices.build(config)
    try:
        if live_drift == "policy-stable-adapter":
            recovered_services.registry.register(stable_tool_definition)
            recovered_services.idempotent_recovery_adapters[str(stable_tool_name)] = (
                StableIdempotencyAdapter(
                    guarantee_id="test.terminal-accounting-stable/provider-v1",
                    operation=_stable_adapter,
                )
            )
        recovered_handlers = DaemonControlHandlers(services=recovered_services)
        recovered_impl = recovered_handlers._impl
        accounting_tasks = list(recovered_impl._recovery_accounting_tasks)
        assert len(accounting_tasks) == 1
        for task in accounting_tasks:
            task.cancel()
        await asyncio.gather(*accounting_tasks, return_exceptions=True)
        recovered = recovered_impl._pending_actions[confirmation_id]
        assert recovered.status == "approved"
        assert recovered.recovery_effect_invoked is True
        assert recovered.recovery_accounting_pending is True
        assert recovered.recovery_authority_mac.startswith("hmac-sha256:")
        authenticated_result = dict(recovered.recovery_result)
        authenticated_provider_operation_id = recovered.provider_operation_id
    finally:
        await recovered_services.shutdown()

    replayed = await DaemonServices.build(config)
    try:
        if live_drift == "human-tool-schema":
            time_definition = replayed.registry.get_tool(ToolName("time.now"))
            assert time_definition is not None
            replayed.registry._tools[time_definition.name] = time_definition.model_copy(
                update={"description": "Drifted after terminal recovery publication."}
            )
        elif live_drift == "policy-stable-adapter":
            replayed.registry.register(stable_tool_definition)
            replayed.idempotent_recovery_adapters[str(stable_tool_name)] = StableIdempotencyAdapter(
                guarantee_id="test.terminal-accounting-stable/provider-v2",
                operation=_stable_adapter,
            )
        replayed_handlers = DaemonControlHandlers(services=replayed)
        if live_drift == "human-backend":
            replayed_handlers._impl._confirmation_backend_registry._backends.pop("software.default")
        await _wait_for_recovery_accounting(replayed_handlers._impl)
        terminal = replayed_handlers._impl._pending_actions[confirmation_id]
        assert terminal.status == "approved"
        assert terminal.status_reason in {
            "recovered_structural_read",
            "recovered_stable_idempotency_key",
        }
        assert terminal.recovery_result == authenticated_result
        assert terminal.provider_operation_id == authenticated_provider_operation_id
        assert terminal.recovery_effect_invoked is True
        assert terminal.recovery_accounting_pending is False
        assert terminal.recovery_authority_mac.startswith("hmac-sha256:")
        if live_drift == "policy-stable-adapter":
            assert len(adapter_calls) == 1
        if task_id:
            recovered_task = replayed.scheduler.get_task(task_id)
            assert recovered_task is not None
            assert recovered_task.success_count == 1
            assert recovered_task.failure_count == 0
    finally:
        await replayed.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cancel_execution",
    [False, True],
    ids=["ordinary-exception", "task-cancellation"],
)
async def test_direct_scheduled_effect_has_durable_attempt_before_delivery_and_contains_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cancel_execution: bool,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    pending_path = config.data_dir / "pending_actions.json"
    durable_before_effect: list[dict[str, object]] = []
    effect_calls = 0
    effect_started = asyncio.Event()

    class _CrashAfterEffect(RuntimeError):
        pass

    services = await DaemonServices.build(config)
    try:
        session_id, raw_impl = await _session_and_impl(services)
        impl = raw_impl
        session = services.session_manager.get(session_id)
        assert session is not None
        task = services.scheduler.create_task(
            name="direct-scheduler-crash",
            goal="Deliver this reminder once",
            schedule=Schedule(kind="interval", expression="1s"),
            capability_snapshot={Capability.MESSAGE_SEND},
            policy_snapshot_ref="direct-scheduler-crash",
            created_by=session.user_id,
            workspace_id=session.workspace_id,
            allowed_recipients=["ops-room"],
            delivery_target={"channel": "discord", "recipient": "ops-room"},
            max_runs=3,
        )
        runs = services.scheduler.trigger_due(
            now=task.created_at + timedelta(seconds=2),
        )
        assert len(runs) == 1

        async def _crash_after_effect(**_kwargs: object) -> object:
            nonlocal effect_calls
            if pending_path.exists():
                durable_before_effect.extend(json.loads(pending_path.read_text(encoding="utf-8")))
            effect_calls += 1
            effect_started.set()
            if cancel_execution:
                await asyncio.Future()
            raise _CrashAfterEffect("process stopped after provider accepted delivery")

        monkeypatch.setattr(impl, "_execute_approved_action", _crash_after_effect)
        execution_task = asyncio.create_task(
            impl._execute_task_run(
                runs[0],
                event_type="scheduler.due",
                due_run=True,
            )
        )
        if cancel_execution:
            await asyncio.wait_for(effect_started.wait(), timeout=1.0)
            execution_task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await execution_task
        else:
            with pytest.raises(_CrashAfterEffect):
                await execution_task

        matching = [row for row in durable_before_effect if str(row.get("task_id", "")) == task.id]
        assert len(matching) == 1
        assert matching[0]["status"] == "executing"
        assert str(matching[0].get("execution_attempt_id", "")).startswith("attempt-")
        assert str(matching[0].get("result_id", "")).startswith("result-")
        assert effect_calls == 1
        contained_task = services.scheduler.get_task(task.id)
        assert contained_task is not None
        assert contained_task.failure_count == 1
        assert contained_task.enabled is False
        assert (
            services.scheduler.trigger_due(
                now=task.created_at + timedelta(seconds=3),
            )
            == []
        )
        live_pending = next(
            candidate
            for candidate in impl._pending_actions.values()
            if candidate.task_id == task.id
        )
        assert live_pending.recovery_effect_invoked is True
        await _wait_for_recovery_accounting(impl)
        execution_rows = [
            row
            for row in _control_plane_history_rows(config)
            if row.get("execution_status") == "outcome_unknown"
        ]
        assert len(execution_rows) == 1
        plans = json.loads(
            (config.data_dir / "control_plane" / "plans.json").read_text(encoding="utf-8")
        )
        assert plans[str(execution_rows[0]["session_id"])]["executed_actions"] == 1
        recovery_audits = [
            row
            for row in _audit_rows(config)
            if row.get("event_type") == "ToolExecuted"
            and row.get("actor") == "recovery"
            and row.get("data", {}).get("approval_confirmation_id") == live_pending.confirmation_id
        ]
        assert len(recovery_audits) == 1
        assert recovery_audits[0].get("data", {}).get("details", {}).get("outcome_unknown") is True
    finally:
        await services.shutdown()

    restarted = await DaemonServices.build(config)
    try:
        restarted_handlers = DaemonControlHandlers(services=restarted)
        await _wait_for_recovery_accounting(restarted_handlers._impl)
        recovered = next(
            pending
            for pending in restarted_handlers._impl._pending_actions.values()
            if pending.task_id == task.id
        )
        assert recovered.status == "outcome_unknown"
        assert recovered.status_reason == "uncertain_effect_requires_fresh_approval"
        recovered_task = restarted.scheduler.get_task(task.id)
        assert recovered_task is not None
        assert recovered_task.success_count == 0
        assert recovered_task.failure_count == 1
        assert recovered_task.enabled is False
        assert (
            restarted.scheduler.trigger_due(
                now=task.created_at + timedelta(seconds=4),
            )
            == []
        )
        assert effect_calls == 1
    finally:
        await restarted.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "approval_actor",
    ["control_api", "policy_loop", "daemon_recovery"],
)
@pytest.mark.parametrize(
    "cancel_execution",
    [False, True],
    ids=["ordinary-exception", "task-cancellation"],
)
async def test_allowed_immediate_effect_has_durable_attempt_before_delivery_and_contains_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    approval_actor: str,
    cancel_execution: bool,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    pending_path = config.data_dir / "pending_actions.json"
    durable_before_effect: list[dict[str, object]] = []
    effect_started = asyncio.Event()

    class _CrashAfterEffect(RuntimeError):
        pass

    class _EffectDelivery:
        async def send(self, **_kwargs: object) -> object:
            durable_before_effect.extend(json.loads(pending_path.read_text(encoding="utf-8")))
            effect_started.set()
            if cancel_execution:
                await asyncio.Future()
            raise _CrashAfterEffect("provider accepted delivery before response loss")

    services = await DaemonServices.build(config)
    try:
        session_id, raw_impl = await _session_and_impl(services)
        impl = raw_impl
        session = services.session_manager.get(session_id)
        assert session is not None
        impl._delivery = _EffectDelivery()
        impl._schedule_recovery_accounting = lambda _pending: None
        action = build_action(
            tool_name="message.send",
            arguments={
                "channel": "discord",
                "recipient": "ops-room",
                "message": "one durable delivery",
            },
            origin=Origin(
                session_id=str(session_id),
                user_id=str(session.user_id),
                workspace_id=str(session.workspace_id),
                actor=approval_actor,
                channel="cli",
            ),
            workspace_roots=list(config.assistant_fs_roots),
        )
        execution_task = asyncio.create_task(
            impl._execute_approved_action(
                sid=session_id,
                user_id=session.user_id,
                workspace_id=session.workspace_id,
                tool_name=ToolName("message.send"),
                arguments={
                    "channel": "discord",
                    "recipient": "ops-room",
                    "message": "one durable delivery",
                },
                capabilities={Capability.MESSAGE_SEND},
                approval_actor=approval_actor,
                execution_action=action,
                persist_attempt_before_effect=True,
            )
        )
        await asyncio.wait_for(effect_started.wait(), timeout=1.0)
        if cancel_execution:
            execution_task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await execution_task
        else:
            with pytest.raises(_CrashAfterEffect):
                await execution_task

        assert len(durable_before_effect) == 1
        durable_attempt = durable_before_effect[0]
        assert durable_attempt["status"] == "executing"
        assert durable_attempt["status_reason"] == f"{approval_actor}_execution_started"
        assert durable_attempt["execution_authorization_kind"] == "policy_allow"
        assert str(durable_attempt.get("execution_attempt_id", "")).startswith("attempt-")
        assert str(durable_attempt.get("result_id", "")).startswith("result-")
        pending = impl._pending_actions[str(durable_attempt["confirmation_id"])]
        assert "execution_authorization_kind" not in impl._pending_to_dict(
            pending,
            public=True,
        )
        assert pending.status == "outcome_unknown"
        assert pending.status_reason == "uncertain_effect_requires_fresh_approval"
        assert pending.recovery_effect_invoked is True
        assert pending.recovery_accounting_pending is True
        durable_after_containment = json.loads(pending_path.read_text(encoding="utf-8"))
        assert durable_after_containment[0]["status"] == "outcome_unknown"
    finally:
        await services.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "approval_actor",
    ["control_api", "policy_loop", "daemon_recovery"],
)
async def test_allowed_immediate_structural_read_recovers_authenticated_policy_allow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    approval_actor: str,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    from shisad.daemon.handlers import _impl as impl_module

    real_clock = impl_module.current_time_payload
    clock_calls: list[dict[str, object]] = []

    def _recording_clock(**kwargs: object) -> dict[str, object]:
        result = real_clock(**kwargs)
        clock_calls.append(dict(result))
        return result

    class _SimulatedProcessLoss(BaseException):
        pass

    monkeypatch.setattr(impl_module, "current_time_payload", _recording_clock)
    monkeypatch.setattr(impl_module, "_sleep", lambda _seconds: None)
    services = await DaemonServices.build(config)
    try:
        session_id, raw_impl = await _session_and_impl(services)
        impl = raw_impl
        session = services.session_manager.get(session_id)
        assert session is not None
        action = build_action(
            tool_name="time.now",
            arguments={"timezone": "UTC"},
            origin=Origin(
                session_id=str(session_id),
                user_id=str(session.user_id),
                workspace_id=str(session.workspace_id),
                actor=approval_actor,
                channel="cli",
            ),
            workspace_roots=list(config.assistant_fs_roots),
        )

        def _lose_process_before_effect(**_kwargs: object) -> None:
            raise _SimulatedProcessLoss

        monkeypatch.setattr(impl._rate_limiter, "consume", _lose_process_before_effect)
        with pytest.raises(_SimulatedProcessLoss):
            await impl._execute_approved_action(
                sid=session_id,
                user_id=session.user_id,
                workspace_id=session.workspace_id,
                tool_name=ToolName("time.now"),
                arguments={"timezone": "UTC"},
                capabilities=set(),
                approval_actor=approval_actor,
                execution_action=action,
                persist_attempt_before_effect=True,
            )

        durable = json.loads(
            (config.data_dir / "pending_actions.json").read_text(encoding="utf-8")
        )[0]
        confirmation_id = str(durable["confirmation_id"])
        assert durable["status"] == "executing"
        assert durable["status_reason"] == f"{approval_actor}_execution_started"
        assert durable["execution_authorization_kind"] == "policy_allow"
        assert "confirmation_evidence" not in durable
        assert durable["approval_evidence_hash"] == ""
        assert clock_calls == []
    finally:
        await services.shutdown()

    restarted = await DaemonServices.build(config)
    try:
        restarted_handlers = DaemonControlHandlers(services=restarted)
        recovered = restarted_handlers._impl._pending_actions[confirmation_id]
        assert recovered.status == "approved"
        assert recovered.status_reason == "recovered_structural_read"
        assert recovered.execution_authorization_kind == "policy_allow"
        assert recovered.retry_generation == 1
        assert recovered.recovery_result["ok"] is True
        assert clock_calls == [recovered.recovery_result]
        await _wait_for_recovery_accounting(restarted_handlers._impl)
        policy_metrics = restarted_handlers._impl._confirmation_analytics.metrics(
            user_id=str(recovered.user_id),
            window_seconds=3600,
        )
        assert policy_metrics["decisions"] == 0
        assert policy_metrics["approve_rate"] == 0.0
    finally:
        await restarted.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "restart_posture",
    ["authenticated", "tampered", "lockdown"],
)
async def test_allowed_immediate_stable_key_recovers_authenticated_policy_allow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    restart_posture: str,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    from shisad.daemon.handlers import _impl as impl_module

    monkeypatch.setattr(impl_module, "_sleep", lambda _seconds: None)
    tool_name = ToolName("test.allowed-stable-retry")
    tool_definition = ToolDefinition(
        name=tool_name,
        description="Create one effect under a stable provider key.",
        parameters=[ToolParameter(name="value", type="string")],
        retry_class=ToolRetryClass.STABLE_IDEMPOTENCY_KEY,
    )
    calls: list[str] = []

    def _deduplicating_adapter(
        arguments: dict[str, object],
        stable_idempotency_key: str,
    ) -> dict[str, object]:
        calls.append(stable_idempotency_key)
        return {
            "ok": True,
            "provider_operation_id": "allowed-provider-operation-1",
            "value": str(arguments.get("value", "")),
        }

    class _SimulatedProcessLoss(BaseException):
        pass

    services = await DaemonServices.build(config)
    try:
        services.registry.register(tool_definition)
        services.idempotent_recovery_adapters[str(tool_name)] = StableIdempotencyAdapter(
            guarantee_id="test.allowed-stable-retry/provider-v1",
            operation=_deduplicating_adapter,
        )
        session_id, raw_impl = await _session_and_impl(services)
        impl = raw_impl
        session = services.session_manager.get(session_id)
        assert session is not None
        action = build_action(
            tool_name=str(tool_name),
            arguments={"value": "create-once"},
            origin=Origin(
                session_id=str(session_id),
                user_id=str(session.user_id),
                workspace_id=str(session.workspace_id),
                actor="policy_loop",
                channel="cli",
            ),
            workspace_roots=list(config.assistant_fs_roots),
        )

        def _lose_process_before_effect(**_kwargs: object) -> None:
            raise _SimulatedProcessLoss

        monkeypatch.setattr(impl._rate_limiter, "consume", _lose_process_before_effect)
        with pytest.raises(_SimulatedProcessLoss):
            await impl._execute_approved_action(
                sid=session_id,
                user_id=session.user_id,
                workspace_id=session.workspace_id,
                tool_name=tool_name,
                arguments={"value": "create-once"},
                capabilities=set(),
                approval_actor="policy_loop",
                execution_action=action,
                persist_attempt_before_effect=True,
            )

        durable = json.loads(
            (config.data_dir / "pending_actions.json").read_text(encoding="utf-8")
        )[0]
        confirmation_id = str(durable["confirmation_id"])
        stable_key = str(durable["stable_idempotency_key"])
        assert durable["status"] == "executing"
        assert durable["execution_authorization_kind"] == "policy_allow"
        assert stable_key.startswith("shisad-")
        assert calls == []
        if restart_posture == "lockdown":
            impl._lockdown_manager.set_level(
                session_id,
                level=LockdownLevel.FULL_LOCKDOWN,
                reason="recovery test lockdown",
                trigger="test_recovery_lockdown",
            )
            assert impl._lockdown_manager.should_block_all_actions(session_id)
    finally:
        await services.shutdown()

    if restart_posture == "tampered":
        pending_path = config.data_dir / "pending_actions.json"
        durable_rows = json.loads(pending_path.read_text(encoding="utf-8"))
        durable_rows[0]["execution_authorization_kind"] = ""
        pending_path.write_text(json.dumps(durable_rows, indent=2), encoding="utf-8")

    restarted = await DaemonServices.build(config)
    try:
        restarted.registry.register(tool_definition)
        restarted.idempotent_recovery_adapters[str(tool_name)] = StableIdempotencyAdapter(
            guarantee_id="test.allowed-stable-retry/provider-v1",
            operation=_deduplicating_adapter,
        )
        restarted_handlers = DaemonControlHandlers(services=restarted)
        recovered = restarted_handlers._impl._pending_actions[confirmation_id]
        if restart_posture == "lockdown":
            assert restarted.lockdown_manager.should_block_all_actions(recovered.session_id)
        await _wait_for_recovery_accounting(restarted_handlers._impl)
        if restart_posture != "authenticated":
            assert recovered.status == "outcome_unknown"
            assert recovered.status_reason == "uncertain_effect_requires_fresh_approval"
            assert recovered.execution_authorization_kind == (
                "" if restart_posture == "tampered" else "policy_allow"
            )
            assert recovered.retry_generation == 0
            assert recovered.provider_operation_id == ""
            assert calls == []
        else:
            assert recovered.status == "approved"
            assert recovered.status_reason == "recovered_stable_idempotency_key"
            assert recovered.execution_authorization_kind == "policy_allow"
            assert recovered.retry_generation == 1
            assert recovered.provider_operation_id == "allowed-provider-operation-1"
            assert calls == [stable_key]
        policy_metrics = restarted_handlers._impl._confirmation_analytics.metrics(
            user_id=str(recovered.user_id),
            window_seconds=3600,
        )
        assert policy_metrics["decisions"] == 0
    finally:
        await restarted.shutdown()


@pytest.mark.asyncio
async def test_confirmed_post_effect_exception_accounts_uncertain_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    effect_calls = 0
    services = await DaemonServices.build(config)
    try:
        session_id, raw_impl = await _session_and_impl(services)
        impl = raw_impl
        session = services.session_manager.get(session_id)
        assert session is not None
        await services.control_plane.begin_precontent_plan(
            session_id=str(session_id),
            goal="Account one uncertain confirmed clock effect",
            origin=Origin(
                session_id=str(session_id),
                user_id=str(session.user_id),
                workspace_id=str(session.workspace_id),
                actor="planner",
                channel="cli",
            ),
            ttl_seconds=600,
            max_actions=1,
        )
        pending = impl._queue_pending_action(
            session_id=session_id,
            user_id=session.user_id,
            workspace_id=session.workspace_id,
            tool_name=ToolName("time.now"),
            arguments={"timezone": "UTC"},
            reason="confirmed-post-effect-exception-accounting",
            capabilities=set(),
            confirmation_requirement=legacy_software_confirmation_requirement(),
            origin_turn_id="turn-confirmed-post-effect-exception-accounting",
        )

        async def _raise_after_possible_effect(**_kwargs: object) -> object:
            nonlocal effect_calls
            effect_calls += 1
            raise RuntimeError("provider failed after possible clock effect")

        monkeypatch.setattr(impl, "_execute_approved_action", _raise_after_possible_effect)
        with pytest.raises(RuntimeError, match="possible clock effect"):
            await impl.do_action_confirm(
                {
                    "confirmation_id": pending.confirmation_id,
                    "decision_nonce": pending.decision_nonce,
                }
            )

        assert effect_calls == 1
        assert pending.status == "outcome_unknown"
        assert pending.recovery_effect_invoked is True
        await _wait_for_recovery_accounting(impl)
        assert pending.recovery_accounting_pending is False
        execution_rows = [
            row for row in _control_plane_history_rows(config) if row.get("tool_name") == "time.now"
        ]
        assert len(execution_rows) == 1
        assert execution_rows[0]["execution_status"] == "outcome_unknown"
        plans = json.loads(
            (config.data_dir / "control_plane" / "plans.json").read_text(encoding="utf-8")
        )
        assert plans[str(session_id)]["executed_actions"] == 1
        recovery_audits = [
            row
            for row in _audit_rows(config)
            if row.get("event_type") == "ToolExecuted"
            and row.get("actor") == "recovery"
            and row.get("data", {}).get("approval_confirmation_id") == pending.confirmation_id
        ]
        assert len(recovery_audits) == 1
        assert recovery_audits[0].get("data", {}).get("details", {}).get("outcome_unknown") is True
    finally:
        await services.shutdown()


@pytest.mark.parametrize(
    ("crash_publication", "authority_tamper"),
    [
        pytest.param(2, "none", id="before-terminal-publication"),
        pytest.param(3, "missing_mac", id="after-accounting-missing-mac"),
        pytest.param(3, "mismatched_mac", id="after-accounting-mismatched-mac"),
    ],
)
@pytest.mark.asyncio
async def test_direct_scheduled_terminal_write_failure_disables_before_pump_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    crash_publication: int,
    authority_tamper: str,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    effect_calls = 0

    services = await DaemonServices.build(config)
    try:
        session_id, raw_impl = await _session_and_impl(services)
        impl = raw_impl
        session = services.session_manager.get(session_id)
        assert session is not None
        task = services.scheduler.create_task(
            name="direct-terminal-write-crash",
            goal="Deliver this reminder once",
            schedule=Schedule(kind="interval", expression="1s"),
            capability_snapshot={Capability.MESSAGE_SEND},
            policy_snapshot_ref="direct-terminal-write-crash",
            created_by=session.user_id,
            workspace_id=session.workspace_id,
            allowed_recipients=["ops-room"],
            delivery_target={"channel": "discord", "recipient": "ops-room"},
            max_runs=3,
        )
        runs = services.scheduler.trigger_due(
            now=task.created_at + timedelta(seconds=2),
        )
        assert len(runs) == 1

        async def _successful_effect(**_kwargs: object) -> ApprovedToolExecutionResult:
            nonlocal effect_calls
            effect_calls += 1
            return ApprovedToolExecutionResult(success=True)

        publication = 0

        def _fail_terminal_write(stage: AtomicWriteStage) -> None:
            nonlocal publication
            if stage == AtomicWriteStage.TEMP_OPEN:
                publication += 1
            if publication == crash_publication and stage == AtomicWriteStage.FILE_FSYNC:
                raise OSError("process stopped during direct terminal accounting")

        monkeypatch.setattr(impl, "_execute_approved_action", _successful_effect)
        impl._pending_state_fault_injector = _fail_terminal_write
        with pytest.raises(AtomicWriteError):
            await impl._execute_task_run(
                runs[0],
                event_type="scheduler.due",
                due_run=True,
            )

        durable = next(
            row
            for row in json.loads(
                (config.data_dir / "pending_actions.json").read_text(encoding="utf-8")
            )
            if row["task_id"] == task.id
        )
        assert durable["status"] == ("executing" if crash_publication == 2 else "approved")
        assert durable["scheduler_accounting_pending"] is (crash_publication == 3)
        contained_task = services.scheduler.get_task(task.id)
        assert contained_task is not None
        assert contained_task.success_count == (1 if crash_publication == 3 else 0)
        assert contained_task.failure_count == 0
        assert contained_task.enabled is False
        assert (
            services.scheduler.trigger_due(
                now=task.created_at + timedelta(seconds=3),
            )
            == []
        )
        assert effect_calls == 1
    finally:
        await services.shutdown()

    if authority_tamper != "none":
        pending_path = config.data_dir / "pending_actions.json"
        durable_rows = json.loads(pending_path.read_text(encoding="utf-8"))
        durable = next(row for row in durable_rows if row["task_id"] == task.id)
        durable["recovery_authority_mac"] = (
            "" if authority_tamper == "missing_mac" else "sha256:" + ("0" * 64)
        )
        pending_path.write_text(json.dumps(durable_rows, indent=2), encoding="utf-8")

    restarted = await DaemonServices.build(config)
    try:
        restarted_handlers = DaemonControlHandlers(services=restarted)
        await _wait_for_recovery_accounting(restarted_handlers._impl)
        recovered = next(
            pending
            for pending in restarted_handlers._impl._pending_actions.values()
            if pending.task_id == task.id
        )
        assert recovered.status == "outcome_unknown"
        recovered_task = restarted.scheduler.get_task(task.id)
        assert recovered_task is not None
        assert recovered_task.success_count == (1 if crash_publication == 3 else 0)
        assert recovered_task.failure_count == (1 if crash_publication == 2 else 0)
        assert recovered_task.enabled is False
        assert effect_calls == 1
    finally:
        await restarted.shutdown()


@pytest.mark.parametrize(
    ("crash_point", "authority_tamper", "fail_first_recovery_cancellation"),
    [
        pytest.param("before_accounting", "none", False, id="before-accounting"),
        pytest.param("after_accounting", "none", False, id="after-accounting"),
        pytest.param(
            "after_accounting",
            "missing_mac",
            False,
            id="after-accounting-missing-mac",
        ),
        pytest.param(
            "after_accounting",
            "mismatched_mac",
            False,
            id="after-accounting-mismatched-mac",
        ),
        pytest.param(
            "after_accounting",
            "none",
            True,
            id="after-accounting-cancellation-second-restart",
        ),
    ],
)
@pytest.mark.asyncio
async def test_confirmed_scheduled_terminal_state_reconciles_run_accounting_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    crash_point: str,
    authority_tamper: str,
    fail_first_recovery_cancellation: bool,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)

    class _CrashBeforeAccounting(RuntimeError):
        pass

    services = await DaemonServices.build(config)
    try:
        session_id, raw_impl = await _session_and_impl(services)
        impl = raw_impl
        session = services.session_manager.get(session_id)
        assert session is not None
        task = services.scheduler.create_task(
            name=f"confirmed-accounting-{crash_point}",
            goal="Record one confirmed scheduled run",
            schedule=Schedule.from_event("message.received"),
            capability_snapshot=set(),
            policy_snapshot_ref="confirmed-accounting-crash",
            created_by=session.user_id,
            workspace_id=session.workspace_id,
            max_runs=1,
        )
        pending = impl._queue_pending_action(
            session_id=session_id,
            user_id=session.user_id,
            workspace_id=session.workspace_id,
            tool_name=ToolName("time.now"),
            arguments={"timezone": "UTC"},
            reason="confirmed-accounting-crash",
            capabilities=set(),
            confirmation_requirement=legacy_software_confirmation_requirement(),
            origin_turn_id=f"turn-confirmed-accounting-{crash_point}",
            task_id=task.id,
        )
        services.scheduler.queue_confirmation(
            task.id,
            impl._pending_to_dict(pending, public=True),
        )
        sibling = impl._queue_pending_action(
            session_id=session_id,
            user_id=session.user_id,
            workspace_id=session.workspace_id,
            tool_name=ToolName("time.now"),
            arguments={"timezone": "UTC"},
            reason="confirmed-accounting-sibling",
            capabilities=set(),
            confirmation_requirement=legacy_software_confirmation_requirement(),
            origin_turn_id=f"turn-confirmed-accounting-sibling-{crash_point}",
            task_id=task.id,
        )
        services.scheduler.queue_confirmation(
            task.id,
            impl._pending_to_dict(sibling, public=True),
        )

        if crash_point == "before_accounting":

            def _crash_before_accounting(
                _task_id: str,
                *,
                confirmation_id: str,
                success: bool,
            ) -> bool:
                _ = confirmation_id, success
                raise _CrashBeforeAccounting("process stopped before scheduler accounting")

            monkeypatch.setattr(
                services.scheduler,
                "record_confirmation_outcome",
                _crash_before_accounting,
            )
            expected_error: type[BaseException] = _CrashBeforeAccounting
        else:
            publication = 0

            def _crash_after_accounting(stage: AtomicWriteStage) -> None:
                nonlocal publication
                if stage == AtomicWriteStage.TEMP_OPEN:
                    publication += 1
                if publication == 3 and stage == AtomicWriteStage.FILE_FSYNC:
                    raise OSError("process stopped before scheduler marker clear")

            impl._pending_state_fault_injector = _crash_after_accounting
            expected_error = AtomicWriteError

        with pytest.raises(expected_error):
            await impl.do_action_confirm(
                {
                    "confirmation_id": pending.confirmation_id,
                    "decision_nonce": pending.decision_nonce,
                }
            )

        durable = next(
            row
            for row in json.loads(
                (config.data_dir / "pending_actions.json").read_text(encoding="utf-8")
            )
            if row["confirmation_id"] == pending.confirmation_id
        )
        assert durable["status"] == "approved"
        assert durable["scheduler_accounting_pending"] is True
        contained_task = services.scheduler.get_task(task.id)
        assert contained_task is not None
        assert contained_task.enabled is False
    finally:
        await services.shutdown()

    if authority_tamper != "none":
        pending_path = config.data_dir / "pending_actions.json"
        durable_rows = json.loads(pending_path.read_text(encoding="utf-8"))
        durable = next(
            row for row in durable_rows if row["confirmation_id"] == pending.confirmation_id
        )
        durable["recovery_authority_mac"] = (
            "" if authority_tamper == "missing_mac" else "sha256:" + ("0" * 64)
        )
        pending_path.write_text(json.dumps(durable_rows, indent=2), encoding="utf-8")

    recovery_attempts = 2 if fail_first_recovery_cancellation else 1
    for recovery_attempt in range(recovery_attempts):
        restarted = await DaemonServices.build(config)
        try:
            restarted_handlers = DaemonControlHandlers(services=restarted)
            recovered_impl = restarted_handlers._impl
            if fail_first_recovery_cancellation and recovery_attempt == 0:

                def _fail_sibling_cancellation(stage: AtomicWriteStage) -> None:
                    if stage == AtomicWriteStage.FILE_FSYNC:
                        raise OSError("process stopped during sibling cancellation")

                recovered_impl._pending_state_fault_injector = _fail_sibling_cancellation
                cancellation_tasks = [
                    recovery_task
                    for recovery_task in recovered_impl._recovery_accounting_tasks
                    if recovery_task.get_name().startswith("shisad-recovery-task-cancel-")
                ]
                assert len(cancellation_tasks) == 1
                with pytest.raises(AtomicWriteError):
                    await asyncio.gather(*cancellation_tasks)
                durable_rows = json.loads(
                    (config.data_dir / "pending_actions.json").read_text(encoding="utf-8")
                )
                durable_recovered = next(
                    row for row in durable_rows if row["confirmation_id"] == pending.confirmation_id
                )
                durable_sibling = next(
                    row for row in durable_rows if row["confirmation_id"] == sibling.confirmation_id
                )
                assert durable_recovered["scheduler_accounting_pending"] is True
                assert durable_sibling["status"] == "pending"
                continue

            await _wait_for_recovery_accounting(recovered_impl)
            recovered = recovered_impl._pending_actions[pending.confirmation_id]
            assert recovered.status == (
                "approved" if authority_tamper == "none" else "outcome_unknown"
            )
            recovered_sibling = recovered_impl._pending_actions[sibling.confirmation_id]
            assert recovered_sibling.status == "cancelled"
            assert recovered_sibling.status_reason == (
                "max_runs_reached" if authority_tamper == "none" else "outcome_unknown"
            )
            reconciled_task = restarted.scheduler.get_task(task.id)
            assert reconciled_task is not None
            assert reconciled_task.success_count == 1
            assert reconciled_task.failure_count == 0
            assert reconciled_task.enabled is False
            rows = restarted.scheduler._pending_confirmations[task.id]
            scheduler_row = next(
                row for row in rows if row["confirmation_id"] == pending.confirmation_id
            )
            assert scheduler_row["run_outcome_recorded"] is True
            assert scheduler_row["run_outcome_success"] is True
            durable = next(
                row
                for row in json.loads(
                    (config.data_dir / "pending_actions.json").read_text(encoding="utf-8")
                )
                if row["confirmation_id"] == pending.confirmation_id
            )
            assert durable["scheduler_accounting_pending"] is False
        finally:
            await restarted.shutdown()


@pytest.mark.parametrize("producer", ["direct", "confirmed"])
@pytest.mark.parametrize(
    "corruption",
    [
        "unrelated_metadata",
        "marker",
        "marker_false",
        "marker_missing",
        "marker_false+attempt_both_missing",
        "marker_missing+attempt_both_missing",
        "marker_false+attempt_both_malformed",
        "marker_missing+attempt_both_malformed",
        "marker_false+result_both_missing",
        "marker_missing+result_both_missing",
        "marker_false+result_both_malformed",
        "marker_missing+result_both_malformed",
        "marker_false+attempt_both_missing+status_pending",
        "marker_missing+result_both_malformed+status_pending",
        "marker_false+identity_missing+task_missing",
        "marker_missing+identity_missing+task_missing",
        "marker_false+identity_malformed",
        "marker_missing+identity_malformed",
        "marker_false+confirmation_mismatch",
        "marker_missing+confirmation_mismatch",
        "marker_false+task_mismatch",
        "marker_missing+task_mismatch",
        "marker_false+attempt_mismatch",
        "marker_missing+attempt_mismatch",
        "marker_false+result_mismatch",
        "marker_missing+result_mismatch",
        "marker_and_identity",
        "identity_missing",
        "identity_malformed",
        "confirmation_missing",
        "confirmation_both_missing",
        "confirmation_malformed",
        "confirmation_mismatch",
        "task_missing",
        "task_both_missing",
        "task_malformed",
        "task_mismatch",
        "attempt_missing",
        "attempt_both_missing",
        "attempt_malformed",
        "attempt_mismatch",
        "result_missing",
        "result_both_missing",
        "result_malformed",
        "result_mismatch",
        "status_pending",
    ],
)
@pytest.mark.asyncio
async def test_scheduled_terminal_accounting_intent_survives_corrupt_recovery_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    producer: str,
    corruption: str,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    corruption_parts = set(corruption.split("+"))

    class _ProcessStopped(BaseException):
        pass

    decoy_task_id = ""
    services = await DaemonServices.build(config)
    try:
        session_id, raw_impl = await _session_and_impl(services)
        impl = raw_impl
        session = services.session_manager.get(session_id)
        assert session is not None
        task = services.scheduler.create_task(
            name=f"terminal-corruption-{producer}-{corruption}",
            goal="Account one scheduled effect",
            schedule=Schedule(kind="interval", expression="1s"),
            capability_snapshot=({Capability.MESSAGE_SEND} if producer == "direct" else set()),
            policy_snapshot_ref="terminal-corruption-recovery",
            created_by=session.user_id,
            workspace_id=session.workspace_id,
            allowed_recipients=["ops-room"] if producer == "direct" else [],
            delivery_target=(
                {"channel": "discord", "recipient": "ops-room"} if producer == "direct" else {}
            ),
            max_runs=1,
        )
        if "task_mismatch" in corruption_parts:
            decoy = services.scheduler.create_task(
                name=f"terminal-corruption-decoy-{producer}",
                goal="Do not account the original effect here",
                schedule=Schedule(kind="interval", expression="1s"),
                capability_snapshot=set(task.capability_snapshot),
                policy_snapshot_ref="terminal-corruption-decoy",
                created_by=session.user_id,
                workspace_id=session.workspace_id,
                max_runs=1,
            )
            decoy_task_id = decoy.id

        def _stop_before_accounting(
            _task_id: str,
            *,
            confirmation_id: str,
            success: bool,
        ) -> bool:
            _ = confirmation_id, success
            raise _ProcessStopped("process stopped before scheduler accounting")

        monkeypatch.setattr(
            services.scheduler,
            "record_confirmation_outcome",
            _stop_before_accounting,
        )

        if producer == "direct":
            runs = services.scheduler.trigger_due(
                now=task.created_at + timedelta(seconds=2),
            )
            matching_runs = [run for run in runs if run.task_id == task.id]
            assert len(matching_runs) == 1

            async def _successful_effect(
                **_kwargs: object,
            ) -> ApprovedToolExecutionResult:
                return ApprovedToolExecutionResult(success=True)

            monkeypatch.setattr(impl, "_execute_approved_action", _successful_effect)
            with pytest.raises(_ProcessStopped):
                await impl._execute_task_run(
                    matching_runs[0],
                    event_type="scheduler.due",
                    due_run=True,
                )
            pending = next(
                item for item in impl._pending_actions.values() if item.task_id == task.id
            )
        else:
            pending = impl._queue_pending_action(
                session_id=session_id,
                user_id=session.user_id,
                workspace_id=session.workspace_id,
                tool_name=ToolName("time.now"),
                arguments={"timezone": "UTC"},
                reason="terminal-corruption-recovery",
                capabilities=set(),
                confirmation_requirement=legacy_software_confirmation_requirement(),
                origin_turn_id=f"turn-terminal-corruption-{corruption}",
                task_id=task.id,
            )
            services.scheduler.queue_confirmation(
                task.id,
                impl._pending_to_dict(pending, public=True),
            )
            with pytest.raises(_ProcessStopped):
                await impl.do_action_confirm(
                    {
                        "confirmation_id": pending.confirmation_id,
                        "decision_nonce": pending.decision_nonce,
                    }
                )

        durable = next(
            row
            for row in json.loads(
                (config.data_dir / "pending_actions.json").read_text(encoding="utf-8")
            )
            if row["confirmation_id"] == pending.confirmation_id
        )
        assert durable["status"] == "approved"
        assert durable["scheduler_accounting_pending"] is True
        interrupted_task = services.scheduler.get_task(task.id)
        assert interrupted_task is not None
        assert interrupted_task.success_count == 0
        assert interrupted_task.enabled is True
    finally:
        await services.shutdown()

    pending_path = config.data_dir / "pending_actions.json"
    durable_rows = json.loads(pending_path.read_text(encoding="utf-8"))
    durable = next(row for row in durable_rows if row["confirmation_id"] == pending.confirmation_id)
    if corruption_parts & {"marker", "marker_and_identity"}:
        durable["scheduler_accounting_pending"] = "not-a-boolean"
    elif "marker_false" in corruption_parts:
        durable["scheduler_accounting_pending"] = False
    elif "marker_missing" in corruption_parts:
        durable.pop("scheduler_accounting_pending")
    if "marker_and_identity" in corruption_parts:
        durable["execution_attempt_id"] = ["not", "text"]
        durable["result_id"] = ["not", "text"]
        durable["identity"]["execution_attempt_id"] = ["not", "text"]
        durable["identity"]["result_id"] = ["not", "text"]
    elif "identity_missing" in corruption_parts:
        durable.pop("identity")
    elif "identity_malformed" in corruption_parts:
        durable["identity"] = ["not", "a", "mapping"]
    elif corruption == "unrelated_metadata" and producer == "direct":
        durable["preflight_action"] = "not-a-mapping"
    elif corruption == "unrelated_metadata":
        durable["confirmation_evidence"]["level"] = "not-a-confirmation-level"
    elif corruption == "confirmation_missing":
        durable["confirmation_id"] = ""
    elif corruption == "confirmation_both_missing":
        durable["confirmation_id"] = ""
        durable["identity"]["confirmation_id"] = ""
    elif corruption == "confirmation_malformed":
        durable["confirmation_id"] = ["not", "text"]
    elif "confirmation_mismatch" in corruption_parts:
        durable["confirmation_id"] = "different-confirmation"
    elif corruption == "task_missing":
        durable["task_id"] = ""
    elif corruption == "task_both_missing":
        durable["task_id"] = ""
        durable["identity"]["task_id"] = ""
    elif corruption == "task_malformed":
        durable["task_id"] = ["not", "text"]
    elif "task_mismatch" in corruption_parts:
        durable["task_id"] = decoy_task_id
    elif corruption == "attempt_missing":
        durable["execution_attempt_id"] = ""
    elif "attempt_both_missing" in corruption_parts:
        durable["execution_attempt_id"] = ""
        durable["identity"]["execution_attempt_id"] = ""
    elif "attempt_both_malformed" in corruption_parts:
        durable["execution_attempt_id"] = ["not", "text"]
        durable["identity"]["execution_attempt_id"] = ["not", "text"]
    elif corruption == "attempt_malformed":
        durable["execution_attempt_id"] = ["not", "text"]
    elif "attempt_mismatch" in corruption_parts:
        durable["execution_attempt_id"] = "attempt-mismatch"
    elif corruption == "result_missing":
        durable["result_id"] = ""
    elif "result_both_missing" in corruption_parts:
        durable["result_id"] = ""
        durable["identity"]["result_id"] = ""
    elif "result_both_malformed" in corruption_parts:
        durable["result_id"] = ["not", "text"]
        durable["identity"]["result_id"] = ["not", "text"]
    elif corruption == "result_malformed":
        durable["result_id"] = ["not", "text"]
    elif "result_mismatch" in corruption_parts:
        durable["result_id"] = "result-mismatch"
    if "identity_missing" in corruption_parts and "task_missing" in corruption_parts:
        durable["task_id"] = ""
    if "status_pending" in corruption_parts:
        durable["status"] = "pending"
        durable["status_reason"] = ""
    pending_path.write_text(json.dumps(durable_rows, indent=2), encoding="utf-8")

    restarted = await DaemonServices.build(config)
    try:
        restarted_handlers = DaemonControlHandlers(services=restarted)
        await _wait_for_recovery_accounting(restarted_handlers._impl)
        reconciled_task = restarted.scheduler.get_task(task.id)
        assert reconciled_task is not None
        unrecoverable_confirmation = corruption == "confirmation_both_missing"
        assert reconciled_task.success_count == 0
        assert reconciled_task.failure_count == 0
        assert reconciled_task.enabled is False
        if not unrecoverable_confirmation:
            durable = next(
                row
                for row in json.loads(pending_path.read_text(encoding="utf-8"))
                if row["confirmation_id"] == pending.confirmation_id
            )
            assert durable["scheduler_accounting_pending"] is False
            assert durable["scheduler_accounting_mode"] == "ambiguous"
            assert durable["status"] == "outcome_unknown"
            assert durable["status_reason"] == "uncertain_effect_requires_fresh_approval"
            assert durable["decision_nonce"] == ""
        if decoy_task_id:
            decoy_task = restarted.scheduler.get_task(decoy_task_id)
            assert decoy_task is not None
            assert decoy_task.success_count == 0
            assert decoy_task.failure_count == 0
            assert decoy_task.enabled is True
    finally:
        await restarted.shutdown()


@pytest.mark.parametrize("recorded_outcome", [None, True, False])
@pytest.mark.asyncio
async def test_terminal_scheduler_shadow_blocks_preconfirmation_row_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    recorded_outcome: bool | None,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)

    class _ProcessStopped(BaseException):
        pass

    effect_calls = 0
    services = await DaemonServices.build(config)
    try:
        session_id, raw_impl = await _session_and_impl(services)
        impl = raw_impl
        session = services.session_manager.get(session_id)
        assert session is not None
        task = services.scheduler.create_task(
            name="confirmed-preconfirmation-row-rollback",
            goal="Do not repeat a confirmed effect after cross-store rollback",
            schedule=Schedule.from_event("message.received"),
            capability_snapshot=set(),
            policy_snapshot_ref="confirmed-preconfirmation-row-rollback",
            created_by=session.user_id,
            workspace_id=session.workspace_id,
            max_runs=3,
        )
        pending = impl._queue_pending_action(
            session_id=session_id,
            user_id=session.user_id,
            workspace_id=session.workspace_id,
            tool_name=ToolName("time.now"),
            arguments={"timezone": "UTC"},
            reason="confirmed-preconfirmation-row-rollback",
            capabilities=set(),
            confirmation_requirement=legacy_software_confirmation_requirement(),
            origin_turn_id="turn-confirmed-preconfirmation-row-rollback",
            task_id=task.id,
        )
        services.scheduler.queue_confirmation(
            task.id,
            impl._pending_to_dict(pending, public=True),
        )
        pending_path = config.data_dir / "pending_actions.json"
        preconfirmation_rows = pending_path.read_text(encoding="utf-8")
        original_nonce = pending.decision_nonce

        async def _successful_effect(**_kwargs: object) -> ApprovedToolExecutionResult:
            nonlocal effect_calls
            effect_calls += 1
            return ApprovedToolExecutionResult(success=True)

        monkeypatch.setattr(impl, "_execute_approved_action", _successful_effect)

        def _stop_before_accounting(
            _task_id: str,
            *,
            confirmation_id: str,
            success: bool,
        ) -> bool:
            _ = confirmation_id, success
            raise _ProcessStopped("process stopped before scheduler accounting")

        monkeypatch.setattr(
            services.scheduler,
            "record_confirmation_outcome",
            _stop_before_accounting,
        )
        with pytest.raises(_ProcessStopped):
            await impl.do_action_confirm(
                {
                    "confirmation_id": pending.confirmation_id,
                    "decision_nonce": original_nonce,
                }
            )
        assert effect_calls == 1
        shadow = services.scheduler._pending_confirmations[task.id][0]
        assert shadow["status"] == "approved"
        assert shadow["run_outcome_recorded"] is False
        if recorded_outcome is not None:
            assert SchedulerManager.record_confirmation_outcome(
                services.scheduler,
                task.id,
                confirmation_id=pending.confirmation_id,
                success=recorded_outcome,
            )
            assert shadow["run_outcome_recorded"] is True
            assert shadow["run_outcome_success"] is recorded_outcome
    finally:
        await services.shutdown()

    pending_path.write_text(preconfirmation_rows, encoding="utf-8")
    restarted = await DaemonServices.build(config)
    try:
        restarted_handlers = DaemonControlHandlers(services=restarted)
        restarted_impl = restarted_handlers._impl
        await _wait_for_recovery_accounting(restarted_impl)
        monkeypatch.setattr(
            restarted_impl,
            "_execute_approved_action",
            _successful_effect,
        )
        result = await restarted_impl.do_action_confirm(
            {
                "confirmation_id": pending.confirmation_id,
                "decision_nonce": original_nonce,
            }
        )
        assert result["confirmed"] is False
        assert effect_calls == 1
        recovered = restarted_impl._pending_actions[pending.confirmation_id]
        assert recovered.status == "outcome_unknown"
        assert recovered.status_reason == "uncertain_effect_requires_fresh_approval"
        assert recovered.decision_nonce == ""
        assert recovered.scheduler_accounting_mode == "ambiguous"
        recovered_task = restarted.scheduler.get_task(task.id)
        assert recovered_task is not None
        assert recovered_task.success_count == int(recorded_outcome is True)
        assert recovered_task.failure_count == int(recorded_outcome is False)
        assert recovered_task.enabled is False
    finally:
        await restarted.shutdown()

    converged = await DaemonServices.build(config)
    try:
        converged_handlers = DaemonControlHandlers(services=converged)
        await _wait_for_recovery_accounting(converged_handlers._impl)
        recovered = converged_handlers._impl._pending_actions[pending.confirmation_id]
        assert recovered.status == "outcome_unknown"
        assert recovered.decision_nonce == ""
        converged_task = converged.scheduler.get_task(task.id)
        assert converged_task is not None
        assert converged_task.success_count == int(recorded_outcome is True)
        assert converged_task.failure_count == int(recorded_outcome is False)
        assert converged_task.enabled is False
        assert effect_calls == 1
    finally:
        await converged.shutdown()


@pytest.mark.asyncio
async def test_corrupt_confirmation_evidence_recovery_replay_uses_trusted_marker_timestamp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    confirmation_id, _task_id = await _seed_unresolved_scheduled_time_attempt(config)
    pending_path = config.data_dir / "pending_actions.json"
    durable_rows = json.loads(pending_path.read_text(encoding="utf-8"))
    durable = next(row for row in durable_rows if row["confirmation_id"] == confirmation_id)
    durable["confirmation_evidence"]["level"] = "not-a-confirmation-level"
    pending_path.write_text(json.dumps(durable_rows, indent=2), encoding="utf-8")

    restarted = await DaemonServices.build(config)
    try:
        handlers = DaemonControlHandlers(services=restarted)
        impl = handlers._impl

        def _fail_marker_clear(stage: AtomicWriteStage) -> None:
            if stage == AtomicWriteStage.FILE_FSYNC:
                raise OSError("process stopped before corrupt-evidence marker clear")

        impl._pending_state_fault_injector = _fail_marker_clear
        accounting_tasks = [
            task
            for task in impl._recovery_accounting_tasks
            if task.get_name().startswith("shisad-recovery-accounting-")
        ]
        assert len(accounting_tasks) == 1
        with pytest.raises(AtomicWriteError):
            await asyncio.gather(*accounting_tasks)
        recovery_rejections = [
            row
            for row in _audit_rows(config)
            if row.get("event_type") == "ToolRejected" and row.get("actor") == "recovery"
        ]
        assert len(recovery_rejections) == 1
        durable = next(
            row
            for row in json.loads(pending_path.read_text(encoding="utf-8"))
            if row["confirmation_id"] == confirmation_id
        )
        trusted_marker_timestamp = str(durable["recovery_event_identity_untrusted_at"])
        assert trusted_marker_timestamp
        assert recovery_rejections[0].get("timestamp") == trusted_marker_timestamp
        assert recovery_rejections[0].get("data", {}).get("approval_timestamp") == ""
        assert recovery_rejections[0].get("data", {}).get("approval_confirmation_id") == ""
    finally:
        await restarted.shutdown()

    await asyncio.sleep(0.01)
    replayed = await DaemonServices.build(config)
    try:
        replayed_handlers = DaemonControlHandlers(services=replayed)
        await _wait_for_recovery_accounting(replayed_handlers._impl)
        recovery_rejections = [
            row
            for row in _audit_rows(config)
            if row.get("event_type") == "ToolRejected" and row.get("actor") == "recovery"
        ]
        assert len(recovery_rejections) == 1
        assert recovery_rejections[0].get("timestamp") == trusted_marker_timestamp
        assert recovery_rejections[0].get("data", {}).get("approval_timestamp") == ""
        assert recovery_rejections[0].get("data", {}).get("approval_confirmation_id") == ""
        durable = next(
            row
            for row in json.loads(pending_path.read_text(encoding="utf-8"))
            if row["confirmation_id"] == confirmation_id
        )
        assert durable["recovery_accounting_pending"] is False
    finally:
        await replayed.shutdown()


@pytest.mark.asyncio
async def test_time_now_structural_read_unresolved_attempt_retries_automatically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    from shisad.daemon.handlers import _impl as impl_module

    real_clock = impl_module.current_time_payload
    clock_calls: list[dict[str, object]] = []
    recovery_backoffs: list[float] = []

    def _recording_clock(**kwargs: object) -> dict[str, object]:
        result = real_clock(**kwargs)
        clock_calls.append(dict(result))
        return result

    monkeypatch.setattr(impl_module, "current_time_payload", _recording_clock)
    monkeypatch.setattr(
        impl_module,
        "_sleep",
        lambda seconds: recovery_backoffs.append(float(seconds)),
    )
    services = await DaemonServices.build(config)
    try:
        session_id, raw_impl = await _session_and_impl(services)
        impl = raw_impl
        session = services.session_manager.get(session_id)
        assert session is not None
        task = services.scheduler.create_task(
            name="recovery-clock",
            goal="Recover one structural clock read",
            schedule=Schedule.from_event("message.received"),
            capability_snapshot=set(),
            policy_snapshot_ref="recovery-test",
            created_by=session.user_id,
            workspace_id=session.workspace_id,
            max_runs=1,
        )
        pending = impl._queue_pending_action(
            session_id=session_id,
            user_id=session.user_id,
            workspace_id=session.workspace_id,
            tool_name=ToolName("time.now"),
            arguments={"timezone": "UTC"},
            reason="recovery-test-confirmation",
            capabilities=set(),
            confirmation_requirement=legacy_software_confirmation_requirement(),
            origin_turn_id="turn-time-recovery",
            task_id=task.id,
        )
        services.scheduler.queue_confirmation(
            task.id,
            impl._pending_to_dict(pending, public=True),
        )
        publication = 0

        def _fail_terminal_write(stage: AtomicWriteStage) -> None:
            nonlocal publication
            if stage == AtomicWriteStage.TEMP_OPEN:
                publication += 1
            if publication == 2 and stage == AtomicWriteStage.FILE_FSYNC:
                raise OSError("crash after clock effect before terminal publication")

        impl._pending_state_fault_injector = _fail_terminal_write

        with pytest.raises(AtomicWriteError):
            await impl.do_action_confirm(
                {
                    "confirmation_id": pending.confirmation_id,
                    "decision_nonce": pending.decision_nonce,
                }
            )

        durable = json.loads(
            (config.data_dir / "pending_actions.json").read_text(encoding="utf-8")
        )[0]
        assert durable["status"] == "executing"
        assert len(clock_calls) == 1
    finally:
        await services.shutdown()

    restarted = await DaemonServices.build(config)
    try:
        restarted_handlers = DaemonControlHandlers(services=restarted)
        recovered = restarted_handlers._impl._pending_actions[pending.confirmation_id]
        assert recovered.status == "approved"
        assert recovered.status_reason == "recovered_structural_read"
        assert recovered.retry_generation == 1
        assert recovered.recovery_result["ok"] is True
        assert recovered.recovery_result["source"] == "daemon_clock"
        assert len(clock_calls) == 2
        assert len(recovery_backoffs) == 1
        assert 0 < recovery_backoffs[0] <= 0.1
        await _wait_for_recovery_accounting(restarted_handlers._impl)
        confirmation_metrics = restarted_handlers._impl._confirmation_analytics.metrics(
            user_id=str(recovered.user_id),
            window_seconds=3600,
        )
        assert confirmation_metrics["decisions"] == 1
        assert confirmation_metrics["approve_rate"] == 1.0
        recovered_task = restarted.scheduler.get_task(task.id)
        assert recovered_task is not None
        assert recovered_task.success_count == 1
        assert recovered_task.failure_count == 0
        assert recovered_task.enabled is False
        confirmation_rows = restarted.scheduler._pending_confirmations[task.id]
        recovered_row = next(
            row for row in confirmation_rows if row["confirmation_id"] == pending.confirmation_id
        )
        assert recovered_row["run_outcome_recorded"] is True
        assert recovered_row["run_outcome_success"] is True
        recovery_events = [
            row
            for row in _audit_rows(config)
            if row.get("event_type") == "ToolExecuted"
            and row.get("actor") == "recovery"
            and row.get("data", {}).get("approval_confirmation_id") == pending.confirmation_id
        ]
        assert len(recovery_events) == 1
        recovery_execution_records = [
            row
            for row in _control_plane_history_rows(config)
            if row.get("tool_name") == "time.now"
            and row.get("execution_status") == "success"
            and row.get("origin", {}).get("actor") == "recovery"
        ]
        assert recovery_execution_records == []
        all_execution_records = [
            row
            for row in _control_plane_history_rows(config)
            if row.get("tool_name") == "time.now" and row.get("execution_status") == "success"
        ]
        assert len(all_execution_records) == 1
    finally:
        await restarted.shutdown()

    second_restart = await DaemonServices.build(config)
    try:
        second_handlers = DaemonControlHandlers(services=second_restart)
        terminal = second_handlers._impl._pending_actions[pending.confirmation_id]
        assert terminal.status == "approved"
        assert terminal.retry_generation == 1
        assert len(clock_calls) == 2
        assert len(recovery_backoffs) == 1
    finally:
        await second_restart.shutdown()


@pytest.mark.asyncio
async def test_human_confirmed_structural_recovery_respects_restored_lockdown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    from shisad.daemon.handlers import _impl as impl_module

    real_clock = impl_module.current_time_payload
    clock_calls = 0

    def _recording_clock(**kwargs: object) -> dict[str, object]:
        nonlocal clock_calls
        clock_calls += 1
        return dict(real_clock(**kwargs))

    monkeypatch.setattr(impl_module, "current_time_payload", _recording_clock)
    confirmation_id, _task_id = await _seed_unresolved_scheduled_time_attempt(
        config,
        lockdown_before_shutdown=True,
    )
    assert clock_calls == 1

    restarted = await DaemonServices.build(config)
    try:
        handlers = DaemonControlHandlers(services=restarted)
        recovered = handlers._impl._pending_actions[confirmation_id]
        assert restarted.lockdown_manager.should_block_all_actions(recovered.session_id)
        assert recovered.status == "outcome_unknown"
        assert recovered.status_reason == "uncertain_effect_requires_fresh_approval"
        assert recovered.retry_generation == 0
        assert clock_calls == 1
        await _wait_for_recovery_accounting(handlers._impl)
        metrics = handlers._impl._confirmation_analytics.metrics(
            user_id=str(recovered.user_id),
            window_seconds=3600,
        )
        assert metrics["decisions"] == 1
        assert metrics["approve_rate"] == 1.0
    finally:
        await restarted.shutdown()


@pytest.mark.asyncio
async def test_failed_human_confirmed_recovery_records_reject_analytics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    from shisad.daemon.handlers import _impl as impl_module

    clock_calls = 0

    def _failing_recovery_clock(**kwargs: object) -> dict[str, object]:
        nonlocal clock_calls
        clock_calls += 1
        return {"ok": False, "error": "clock_unavailable"}

    monkeypatch.setattr(impl_module, "current_time_payload", _failing_recovery_clock)
    confirmation_id, _task_id = await _seed_unresolved_scheduled_time_attempt(config)

    restarted = await DaemonServices.build(config)
    try:
        handlers = DaemonControlHandlers(services=restarted)
        recovered = handlers._impl._pending_actions[confirmation_id]
        assert recovered.status == "failed"
        assert recovered.status_reason == "structural_read_failed:clock_unavailable"
        assert recovered.retry_generation == 1
        assert clock_calls == 2
        await _wait_for_recovery_accounting(handlers._impl)
        assert recovered.status == "failed"
        metrics = handlers._impl._confirmation_analytics.metrics(
            user_id=str(recovered.user_id),
            window_seconds=3600,
        )
        assert metrics["decisions"] == 1
        assert metrics["approve_rate"] == 0.0
    finally:
        await restarted.shutdown()


@pytest.mark.parametrize(
    "accounting_failure",
    ["audit", "control_plane", "marker_persist"],
)
@pytest.mark.asyncio
async def test_recovery_accounting_replay_is_idempotent_and_task_is_precontained(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    accounting_failure: str,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    confirmation_id, task_id = await _seed_unresolved_scheduled_time_attempt(config)

    restarted = await DaemonServices.build(config)
    try:
        handlers = DaemonControlHandlers(services=restarted)
        impl = handlers._impl
        contained_task = restarted.scheduler.get_task(task_id)
        assert contained_task is not None
        assert contained_task.success_count == 1
        assert contained_task.failure_count == 0
        assert contained_task.enabled is False

        if accounting_failure == "audit":

            async def _fail_audit(_event: object) -> None:
                raise OSError("recovery audit unavailable")

            monkeypatch.setattr(impl._event_bus, "publish", _fail_audit)
            expected_error: type[BaseException] = OSError
        elif accounting_failure == "control_plane":

            async def _fail_control_plane(**_kwargs: object) -> None:
                raise OSError("recovery control plane unavailable")

            monkeypatch.setattr(
                impl._control_plane,
                "record_execution",
                _fail_control_plane,
            )
            expected_error = OSError
        else:

            def _fail_marker_clear(stage: AtomicWriteStage) -> None:
                if stage == AtomicWriteStage.FILE_FSYNC:
                    raise OSError("crash before recovery accounting marker clear")

            impl._pending_state_fault_injector = _fail_marker_clear
            expected_error = AtomicWriteError

        accounting_tasks = list(impl._recovery_accounting_tasks)
        assert len(accounting_tasks) == 1
        with pytest.raises(expected_error):
            await asyncio.gather(*accounting_tasks)

        durable = json.loads(
            (config.data_dir / "pending_actions.json").read_text(encoding="utf-8")
        )[0]
        assert durable["recovery_accounting_pending"] is True
        first_recovery_audit = [
            row
            for row in _audit_rows(config)
            if row.get("event_type") == "ToolExecuted"
            and row.get("actor") == "recovery"
            and row.get("data", {}).get("approval_confirmation_id") == confirmation_id
        ]
        first_recovery_control = [
            row
            for row in _control_plane_history_rows(config)
            if row.get("origin", {}).get("actor") == "recovery"
            and row.get("tool_name") == "time.now"
        ]
        expected_first_audit = 0 if accounting_failure == "audit" else 1
        expected_first_control = 0
        assert len(first_recovery_audit) == expected_first_audit
        assert len(first_recovery_control) == expected_first_control
        first_control = [
            row
            for row in _control_plane_history_rows(config)
            if row.get("tool_name") == "time.now" and row.get("execution_status") == "success"
        ]
        assert len(first_control) == 1
    finally:
        await restarted.shutdown()

    replayed = await DaemonServices.build(config)
    try:
        replayed_handlers = DaemonControlHandlers(services=replayed)
        await _wait_for_recovery_accounting(replayed_handlers._impl)
        replayed_task = replayed.scheduler.get_task(task_id)
        assert replayed_task is not None
        assert replayed_task.success_count == 1
        assert replayed_task.failure_count == 0
        assert replayed_task.enabled is False
        recovery_audit = [
            row
            for row in _audit_rows(config)
            if row.get("event_type") == "ToolExecuted"
            and row.get("actor") == "recovery"
            and row.get("data", {}).get("approval_confirmation_id") == confirmation_id
        ]
        recovery_control = [
            row
            for row in _control_plane_history_rows(config)
            if row.get("origin", {}).get("actor") == "recovery"
            and row.get("tool_name") == "time.now"
        ]
        assert len(recovery_audit) == 1
        assert len({row["event_id"] for row in recovery_audit}) == 1
        assert recovery_control == []
        total_control = [
            row
            for row in _control_plane_history_rows(config)
            if row.get("tool_name") == "time.now" and row.get("execution_status") == "success"
        ]
        assert len(total_control) == 1
        assert len({row["idempotency_key"] for row in total_control}) == 1
        durable = json.loads(
            (config.data_dir / "pending_actions.json").read_text(encoding="utf-8")
        )[0]
        assert durable["recovery_accounting_pending"] is False
    finally:
        await replayed.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scenario", "arguments"),
    [
        ("mutating_get", {"url": "https://mutating-get.example.test"}),
        (
            "single_use_get",
            {"url": "https://single-use.example.test", "snapshot": False},
        ),
        (
            "redirect_get",
            {"url": "https://redirect.example.test/start", "snapshot": False},
        ),
        (
            "snapshot_write",
            {"url": "https://snapshot.example.test", "snapshot": True},
        ),
        (
            "malformed_snapshot",
            {"url": "https://malformed.example.test", "snapshot": "not-a-boolean"},
        ),
    ],
)
async def test_arbitrary_web_fetch_crash_never_auto_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario: str,
    arguments: dict[str, object],
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    from shisad.assistant.web import WebToolkit

    fetch_calls = 0
    initial_effect_calls = 0

    class _ProcessStopped(BaseException):
        pass

    def _unexpected_fetch(
        _toolkit: WebToolkit,
        *,
        url: str,
        snapshot: bool = False,
        max_bytes: int | None = None,
    ) -> dict[str, object]:
        nonlocal fetch_calls
        fetch_calls += 1
        return {"ok": True, "url": url, "snapshot": snapshot, "max_bytes": max_bytes}

    monkeypatch.setattr(WebToolkit, "fetch", _unexpected_fetch)
    services = await DaemonServices.build(config)
    try:
        session_id, raw_impl = await _session_and_impl(services)
        impl = raw_impl
        session = services.session_manager.get(session_id)
        assert session is not None
        await services.control_plane.begin_precontent_plan(
            session_id=str(session_id),
            goal="Account one uncertain no-auto web effect",
            origin=Origin(
                session_id=str(session_id),
                user_id=str(session.user_id),
                workspace_id=str(session.workspace_id),
                actor="planner",
                channel="cli",
            ),
            ttl_seconds=600,
            max_actions=1,
        )
        pending = impl._queue_pending_action(
            session_id=session_id,
            user_id=session.user_id,
            workspace_id=session.workspace_id,
            tool_name=ToolName("web.fetch"),
            arguments=arguments,
            reason="recovery-test-confirmation",
            capabilities={Capability.HTTP_REQUEST},
            confirmation_requirement=legacy_software_confirmation_requirement(),
            origin_turn_id="turn-web-fetch-recovery",
        )

        async def _stop_after_possible_effect(**_kwargs: object) -> object:
            nonlocal initial_effect_calls
            initial_effect_calls += 1
            raise _ProcessStopped

        monkeypatch.setattr(impl, "_execute_approved_action", _stop_after_possible_effect)
        with pytest.raises(_ProcessStopped):
            await impl.do_action_confirm(
                {
                    "confirmation_id": pending.confirmation_id,
                    "decision_nonce": pending.decision_nonce,
                }
            )
        execution_attempt_id = pending.execution_attempt_id
        assert execution_attempt_id.startswith("attempt-")
        assert initial_effect_calls == 1
    finally:
        await services.shutdown()

    restarted = await DaemonServices.build(config)
    try:
        restarted_handlers = DaemonControlHandlers(services=restarted)
        await _wait_for_recovery_accounting(restarted_handlers._impl)
        recovered = restarted_handlers._impl._pending_actions[pending.confirmation_id]
        assert recovered.status == "outcome_unknown"
        assert recovered.status_reason == "uncertain_effect_requires_fresh_approval"
        assert recovered.decision_nonce == ""
        assert recovered.recovery_effect_invoked is True
        assert recovered.recovery_accounting_pending is False
        assert recovered.retry_generation == 0
        assert fetch_calls == 0
        public = restarted_handlers._impl._pending_to_dict(recovered, public=True)
        assert public["uncertainty_evidence"]["execution_attempt_id"] == execution_attempt_id
        assert public["manual_retry"]["requires_fresh_approval"] is True
        assert public["manual_retry"]["reuse_confirmation_id"] is False
        durable = json.loads(
            (config.data_dir / "pending_actions.json").read_text(encoding="utf-8")
        )[0]
        assert durable["status"] == "outcome_unknown"
        assert durable["execution_attempt_id"] == execution_attempt_id
        execution_rows = [
            row
            for row in _control_plane_history_rows(config)
            if row.get("tool_name") == "web.fetch"
        ]
        assert len(execution_rows) == 1
        assert execution_rows[0]["execution_status"] == "outcome_unknown"
        plans = json.loads(
            (config.data_dir / "control_plane" / "plans.json").read_text(encoding="utf-8")
        )
        assert plans[str(session_id)]["executed_actions"] == 1
        recovery_audits = [
            row
            for row in _audit_rows(config)
            if row.get("event_type") == "ToolExecuted"
            and row.get("actor") == "recovery"
            and row.get("data", {}).get("approval_confirmation_id") == pending.confirmation_id
        ]
        assert len(recovery_audits) == 1
        assert recovery_audits[0].get("data", {}).get("details", {}).get("outcome_unknown") is True
        if scenario == "mutating_get":
            fresh = restarted_handlers._impl._queue_pending_action(
                session_id=recovered.session_id,
                user_id=recovered.user_id,
                workspace_id=recovered.workspace_id,
                tool_name=recovered.tool_name,
                arguments=dict(recovered.arguments),
                reason="informed-manual-retry",
                capabilities=set(recovered.capabilities),
                confirmation_requirement=legacy_software_confirmation_requirement(),
                origin_turn_id="turn-web-fetch-fresh-manual-retry",
            )
            assert fresh.status == "pending"
            assert fresh.decision_nonce
            assert fresh.confirmation_id != recovered.confirmation_id
            assert fresh.action_id != recovered.action_id
            assert fresh.execution_attempt_id == ""
            assert recovered.status == "outcome_unknown"
            assert recovered.decision_nonce == ""
    finally:
        await restarted.shutdown()


@pytest.mark.parametrize("recovery_drift", ["adapter-missing", "schema-hash"])
@pytest.mark.asyncio
async def test_authenticated_stable_retry_drift_accounts_uncertain_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    recovery_drift: str,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    tool_name = ToolName("test.stable-retry-drift")
    tool_definition = ToolDefinition(
        name=tool_name,
        description="Create one effect under a stable provider key.",
        parameters=[ToolParameter(name="value", type="string")],
        retry_class=ToolRetryClass.STABLE_IDEMPOTENCY_KEY,
    )
    drifted_definition = ToolDefinition(
        name=tool_name,
        description="Create one effect under a changed provider contract.",
        parameters=[
            ToolParameter(name="value", type="string"),
            ToolParameter(name="revision", type="string", required=False),
        ],
        retry_class=ToolRetryClass.STABLE_IDEMPOTENCY_KEY,
    )

    class _ProcessStopped(BaseException):
        pass

    adapter_calls = 0

    def _unexpected_adapter(
        _arguments: dict[str, object],
        _stable_idempotency_key: str,
    ) -> dict[str, object]:
        nonlocal adapter_calls
        adapter_calls += 1
        return {"ok": True}

    services = await DaemonServices.build(config)
    try:
        services.registry.register(tool_definition)
        services.idempotent_recovery_adapters[str(tool_name)] = StableIdempotencyAdapter(
            guarantee_id="test.stable-retry-drift/provider-v1",
            operation=_unexpected_adapter,
        )
        session_id, raw_impl = await _session_and_impl(services)
        impl = raw_impl
        session = services.session_manager.get(session_id)
        assert session is not None
        await services.control_plane.begin_precontent_plan(
            session_id=str(session_id),
            goal="Account one uncertain stable-key effect after recovery drift",
            origin=Origin(
                session_id=str(session_id),
                user_id=str(session.user_id),
                workspace_id=str(session.workspace_id),
                actor="planner",
                channel="cli",
            ),
            ttl_seconds=600,
            max_actions=1,
        )
        pending = impl._queue_pending_action(
            session_id=session_id,
            user_id=session.user_id,
            workspace_id=session.workspace_id,
            tool_name=tool_name,
            arguments={"value": "create-once"},
            reason="authenticated-stable-retry-drift-accounting",
            capabilities=set(),
            confirmation_requirement=legacy_software_confirmation_requirement(),
            origin_turn_id="turn-authenticated-stable-retry-drift-accounting",
        )
        assert pending.retry_descriptor is not None

        async def _stop_after_possible_effect(**_kwargs: object) -> object:
            raise _ProcessStopped

        monkeypatch.setattr(impl, "_execute_approved_action", _stop_after_possible_effect)
        with pytest.raises(_ProcessStopped):
            await impl.do_action_confirm(
                {
                    "confirmation_id": pending.confirmation_id,
                    "decision_nonce": pending.decision_nonce,
                }
            )
        assert pending.execution_attempt_id.startswith("attempt-")
    finally:
        await services.shutdown()

    restarted = await DaemonServices.build(config)
    try:
        restarted.registry.register(
            drifted_definition if recovery_drift == "schema-hash" else tool_definition
        )
        if recovery_drift == "schema-hash":
            restarted.idempotent_recovery_adapters[str(tool_name)] = StableIdempotencyAdapter(
                guarantee_id="test.stable-retry-drift/provider-v1",
                operation=_unexpected_adapter,
            )
        restarted_handlers = DaemonControlHandlers(services=restarted)
        await _wait_for_recovery_accounting(restarted_handlers._impl)
        recovered = restarted_handlers._impl._pending_actions[pending.confirmation_id]
        assert recovered.status == "outcome_unknown"
        assert recovered.status_reason == "uncertain_effect_requires_fresh_approval"
        assert recovered.recovery_effect_invoked is True
        assert recovered.recovery_accounting_pending is False
        assert recovered.retry_generation == 0
        assert adapter_calls == 0
        execution_rows = [
            row
            for row in _control_plane_history_rows(config)
            if row.get("tool_name") == str(tool_name)
        ]
        assert len(execution_rows) == 1
        assert execution_rows[0]["execution_status"] == "outcome_unknown"
        plans = json.loads(
            (config.data_dir / "control_plane" / "plans.json").read_text(encoding="utf-8")
        )
        assert plans[str(session_id)]["executed_actions"] == 1
        recovery_audits = [
            row
            for row in _audit_rows(config)
            if row.get("event_type") == "ToolExecuted"
            and row.get("actor") == "recovery"
            and row.get("data", {}).get("approval_confirmation_id") == pending.confirmation_id
        ]
        assert len(recovery_audits) == 1
        assert recovery_audits[0].get("data", {}).get("details", {}).get("outcome_unknown") is True
    finally:
        await restarted.shutdown()


@pytest.mark.asyncio
async def test_nonidempotent_crash_window_recovers_outcome_unknown_without_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await test_arbitrary_web_fetch_crash_never_auto_retries(
        tmp_path,
        monkeypatch,
        "post_effect_crash",
        {"url": "https://uncertain-effect.example.test", "snapshot": True},
    )


@pytest.mark.parametrize(
    "tamper",
    [
        "descriptor_schema_hash",
        "missing_descriptor",
        "corrupt_recovery_started_at",
        "corrupt_approval_envelope",
        "corrupt_confirmation_evidence",
        "top_level_created_at",
        "top_level_arguments",
        "arguments_lone_surrogate",
        "arguments_non_finite",
        "recovery_result_lone_surrogate",
        "recovery_result_non_finite",
        "confirmation_evidence_lone_surrogate",
        "execution_identity_lone_surrogate",
        "top_level_capabilities",
        "top_level_required_level",
        "top_level_required_capabilities",
        "top_level_fallback",
        "top_level_leak_check",
        "top_level_identity",
        "top_level_required_methods",
        "top_level_status",
        "top_level_delivery_target",
        "top_level_preflight_action",
        "top_level_merged_policy",
        "top_level_pep_context",
        "top_level_pep_elevation",
        "top_level_retry_descriptor",
        "coherent_origin_identity_drift",
        "coherent_execution_identity_drift",
        "terminal_status_approved",
        "terminal_status_failed",
        "terminal_status_missing_mac",
        "top_level_expiry_extension",
        "valid_backend_method_drift",
        "valid_fallback_drift",
        "fabricated_confirmation_evidence",
        "non_ascii_evidence_hash",
        "non_ascii_contract_hash",
        "action_digest_mismatch",
        "retry_generation_exhausted",
        "principal_mismatch",
        "delivery_target_present",
        "policy_reject",
    ],
)
@pytest.mark.asyncio
async def test_time_now_recovery_rejects_drift_exhaustion_and_principal_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    from shisad.daemon.handlers import _impl as impl_module

    real_clock = impl_module.current_time_payload
    clock_calls = 0

    def _recording_clock(**kwargs: object) -> dict[str, object]:
        nonlocal clock_calls
        clock_calls += 1
        return dict(real_clock(**kwargs))

    monkeypatch.setattr(impl_module, "current_time_payload", _recording_clock)
    services = await DaemonServices.build(config)
    try:
        session_id, raw_impl = await _session_and_impl(services)
        impl = raw_impl
        session = services.session_manager.get(session_id)
        assert session is not None
        scheduled_task = None
        if tamper in {
            "top_level_status",
            "terminal_status_approved",
            "terminal_status_failed",
            "terminal_status_missing_mac",
        }:
            scheduled_task = services.scheduler.create_task(
                name="corrupt-status-recovery",
                goal="Contain a corrupt scheduled attempt",
                schedule=Schedule.from_event("message.received"),
                capability_snapshot=set(),
                policy_snapshot_ref="corrupt-status-recovery",
                created_by=session.user_id,
                workspace_id=session.workspace_id,
                max_runs=3,
            )
        pending = impl._queue_pending_action(
            session_id=session_id,
            user_id=session.user_id,
            workspace_id=session.workspace_id,
            tool_name=ToolName("time.now"),
            arguments={"timezone": "UTC"},
            reason="negative-recovery-test-confirmation",
            capabilities=set(),
            confirmation_requirement=legacy_software_confirmation_requirement(),
            origin_turn_id=f"turn-time-{tamper}",
            task_id=scheduled_task.id if scheduled_task is not None else "",
        )
        if scheduled_task is not None:
            services.scheduler.queue_confirmation(
                scheduled_task.id,
                impl._pending_to_dict(pending, public=True),
            )
        publication = 0

        def _fail_terminal_write(stage: AtomicWriteStage) -> None:
            nonlocal publication
            if stage == AtomicWriteStage.TEMP_OPEN:
                publication += 1
            if publication == 2 and stage == AtomicWriteStage.FILE_FSYNC:
                raise OSError("crash after clock effect before terminal publication")

        impl._pending_state_fault_injector = _fail_terminal_write
        with pytest.raises(AtomicWriteError):
            await impl.do_action_confirm(
                {
                    "confirmation_id": pending.confirmation_id,
                    "decision_nonce": pending.decision_nonce,
                }
            )
    finally:
        await services.shutdown()

    pending_path = config.data_dir / "pending_actions.json"
    durable_rows = json.loads(pending_path.read_text(encoding="utf-8"))
    if tamper == "descriptor_schema_hash":
        durable_rows[0]["retry_descriptor"]["tool_schema_hash"] = "sha256:" + ("0" * 64)
    elif tamper == "missing_descriptor":
        durable_rows[0]["retry_descriptor"] = None
    elif tamper == "corrupt_recovery_started_at":
        durable_rows[0]["recovery_started_at"] = "not-a-timestamp"
    elif tamper == "corrupt_approval_envelope":
        durable_rows[0]["approval_envelope"]["required_level"] = "not-a-level"
    elif tamper == "corrupt_confirmation_evidence":
        durable_rows[0]["confirmation_evidence"]["level"] = "not-a-level"
    elif tamper == "top_level_created_at":
        durable_rows[0]["created_at"] = "not-a-timestamp"
    elif tamper == "top_level_arguments":
        durable_rows[0]["arguments"] = "not-a-mapping"
    elif tamper == "arguments_lone_surrogate":
        durable_rows[0]["arguments"] = {"timezone": "\ud800"}
    elif tamper == "arguments_non_finite":
        durable_rows[0]["arguments"] = {"timezone": float("nan")}
    elif tamper == "recovery_result_lone_surrogate":
        durable_rows[0]["recovery_result"] = {"ok": True, "value": "\ud800"}
    elif tamper == "recovery_result_non_finite":
        durable_rows[0]["recovery_result"] = {"ok": True, "value": float("nan")}
    elif tamper == "confirmation_evidence_lone_surrogate":
        durable_rows[0]["confirmation_evidence"]["approver_principal_id"] = "\ud800"
    elif tamper == "execution_identity_lone_surrogate":
        durable_rows[0]["execution_attempt_id"] = "\ud800"
        durable_rows[0]["identity"]["execution_attempt_id"] = "\ud800"
    elif tamper == "top_level_capabilities":
        durable_rows[0]["capabilities"] = ["not-a-capability"]
    elif tamper == "top_level_required_level":
        durable_rows[0]["required_level"] = "not-a-level"
    elif tamper == "top_level_required_capabilities":
        durable_rows[0]["required_capabilities"] = "not-a-mapping"
    elif tamper == "top_level_fallback":
        durable_rows[0]["fallback"] = "not-a-mapping"
    elif tamper == "top_level_leak_check":
        durable_rows[0]["leak_check"] = "not-a-mapping"
    elif tamper == "top_level_identity":
        durable_rows[0]["identity"] = "not-a-mapping"
    elif tamper == "top_level_required_methods":
        durable_rows[0]["required_methods"] = "software"
    elif tamper == "top_level_status":
        durable_rows[0]["status"] = ["executing"]
    elif tamper == "top_level_delivery_target":
        durable_rows[0]["delivery_target"] = "discord:channel-1"
    elif tamper == "top_level_preflight_action":
        durable_rows[0]["preflight_action"] = "not-a-mapping"
    elif tamper == "top_level_merged_policy":
        durable_rows[0]["merged_policy"] = "not-a-mapping"
    elif tamper == "top_level_pep_context":
        durable_rows[0]["pep_context"] = "not-a-mapping"
    elif tamper == "top_level_pep_elevation":
        durable_rows[0]["pep_elevation"] = "not-a-mapping"
    elif tamper == "top_level_retry_descriptor":
        durable_rows[0]["retry_descriptor"] = "not-a-mapping"
    elif tamper == "coherent_origin_identity_drift":
        durable_rows[0]["origin_turn_id"] = "different-origin-turn"
        durable_rows[0]["identity"]["origin_turn_id"] = "different-origin-turn"
    elif tamper == "coherent_execution_identity_drift":
        durable_rows[0]["execution_attempt_id"] = "attempt-tampered"
        durable_rows[0]["identity"]["execution_attempt_id"] = "attempt-tampered"
    elif tamper == "terminal_status_approved":
        durable_rows[0]["status"] = "approved"
    elif tamper == "terminal_status_failed":
        durable_rows[0]["status"] = "failed"
    elif tamper == "terminal_status_missing_mac":
        durable_rows[0]["status"] = "approved"
        durable_rows[0]["recovery_authority_mac"] = ""
    elif tamper == "top_level_expiry_extension":
        durable_rows[0]["expires_at"] = (datetime.now(UTC) + timedelta(days=7)).isoformat()
    elif tamper == "valid_backend_method_drift":
        durable_rows[0]["selected_backend_method"] = "totp"
    elif tamper == "valid_fallback_drift":
        durable_rows[0]["fallback"] = {
            "mode": "allow_levels",
            "allow_levels": ["software"],
        }
    elif tamper == "fabricated_confirmation_evidence":
        _replace_with_self_asserted_fabricated_evidence(durable_rows[0])
    elif tamper == "non_ascii_evidence_hash":
        durable_rows[0]["confirmation_evidence"]["evidence_hash"] = "sha256:☃"
        durable_rows[0]["approval_evidence_hash"] = "sha256:☃"
    elif tamper == "non_ascii_contract_hash":
        durable_rows[0]["approval_envelope"]["approval_contract_hash"] = "sha256:☃"
        durable_rows[0]["approval_envelope_hash"] = approval_envelope_hash(
            durable_rows[0]["approval_envelope"]
        )
    elif tamper == "action_digest_mismatch":
        durable_rows[0]["action_digest"] = "sha256:" + ("f" * 64)
    elif tamper == "retry_generation_exhausted":
        durable_rows[0]["retry_generation"] = 1
    elif tamper == "principal_mismatch":
        durable_rows[0]["user_id"] = "mallory"
    elif tamper == "delivery_target_present":
        durable_rows[0]["delivery_target"] = {
            "channel": "discord",
            "recipient": "channel-1",
            "thread_id": "",
            "workspace_hint": "",
        }
    pending_path.write_text(json.dumps(durable_rows, indent=2), encoding="utf-8")
    if tamper == "policy_reject":
        config.policy_path.write_text(
            """version: "1"
default_deny: true
default_require_confirmation: false
tools:
  other.tool:
    capabilities_required: []
""",
            encoding="utf-8",
        )

    restarted = await DaemonServices.build(config)
    try:
        restarted_handlers = DaemonControlHandlers(services=restarted)
        recovered = restarted_handlers._impl._pending_actions[pending.confirmation_id]
        assert recovered.status == "outcome_unknown"
        assert recovered.status_reason == "uncertain_effect_requires_fresh_approval"
        assert recovered.decision_nonce == ""
        assert clock_calls == 1
        if scheduled_task is not None:
            contained_task = restarted.scheduler.get_task(scheduled_task.id)
            assert contained_task is not None
            assert contained_task.success_count == 0
            assert contained_task.failure_count == 0
            assert contained_task.enabled is False
            assert recovered.scheduler_accounting_mode == "ambiguous"
    finally:
        await restarted.shutdown()


@pytest.mark.parametrize(
    (
        "recovery_case",
        "max_runs",
        "disable_before_restart",
        "expected_task_enabled",
    ),
    [
        pytest.param("exact-key", 1, False, False, id="exact-key-max-runs"),
        pytest.param("changed-key", 1, False, False, id="changed-key"),
        pytest.param(
            "changed-adapter-guarantee",
            1,
            False,
            False,
            id="changed-adapter-guarantee",
        ),
        pytest.param("fabricated-evidence", 1, False, False, id="fabricated-evidence"),
        pytest.param("adapter-error", 1, False, False, id="adapter-error"),
        pytest.param("adapter-non-finite", 1, False, False, id="adapter-non-finite"),
        pytest.param("adapter-lone-surrogate", 1, False, False, id="adapter-lone-surrogate"),
        pytest.param("adapter-pathlike", 1, False, False, id="adapter-pathlike"),
        pytest.param("success-then-failure", 1, False, False, id="success-then-failure"),
        pytest.param("failure-then-success", 1, False, False, id="failure-then-success"),
        pytest.param("exact-key", 0, False, True, id="exact-key-unlimited"),
        pytest.param("exact-key", 3, False, True, id="exact-key-runs-remaining"),
        pytest.param("exact-key", 3, True, False, id="exact-key-pre-disabled"),
    ],
)
@pytest.mark.asyncio
async def test_stable_idempotency_key_recovery_reuses_key_without_duplicate_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    recovery_case: str,
    max_runs: int,
    disable_before_restart: bool,
    expected_task_enabled: bool,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    tool_name = ToolName("test.keyed-effect")
    tool_definition = ToolDefinition(
        name=tool_name,
        description="Create one fixture effect under a stable provider key.",
        parameters=[ToolParameter(name="value", type="string")],
        retry_class=ToolRetryClass.STABLE_IDEMPOTENCY_KEY,
    )
    calls: list[str] = []
    logical_effects: dict[str, dict[str, object]] = {}

    def _deduplicating_adapter(
        arguments: dict[str, object],
        stable_idempotency_key: str,
    ) -> dict[str, object]:
        calls.append(stable_idempotency_key)
        if recovery_case == "success-then-failure" and len(calls) > 1:
            return {
                "ok": False,
                "error": "provider_contradicted_initial_success",
            }
        if recovery_case == "failure-then-success":
            if len(calls) == 1:
                logical_effects.setdefault(
                    stable_idempotency_key,
                    {"ok": False, "error": "provider_initial_failure"},
                )
                return {"ok": False, "error": "provider_initial_failure"}
            return {
                "ok": True,
                "provider_operation_id": "provider-operation-contradiction",
                "value": str(arguments.get("value", "")),
            }
        result = logical_effects.setdefault(
            stable_idempotency_key,
            {
                "ok": True,
                "provider_operation_id": "provider-operation-1",
                "value": str(arguments.get("value", "")),
            },
        )
        if recovery_case == "adapter-error" and len(calls) > 1:
            raise RuntimeError("provider accepted keyed operation before transport failure")
        if recovery_case == "adapter-non-finite" and len(calls) > 1:
            return {"ok": True, "value": float("nan")}
        if recovery_case == "adapter-lone-surrogate" and len(calls) > 1:
            return {"ok": True, "value": "\ud800"}
        if recovery_case == "adapter-pathlike" and len(calls) > 1:
            return {"ok": True, "value": Path("/tmp/provider-value")}
        return result

    services = await DaemonServices.build(config)
    try:
        services.registry.register(tool_definition)
        services.idempotent_recovery_adapters[str(tool_name)] = StableIdempotencyAdapter(
            guarantee_id="test.keyed-effect/provider-v1",
            operation=_deduplicating_adapter,
        )
        session_id, raw_impl = await _session_and_impl(services)
        impl = raw_impl
        session = services.session_manager.get(session_id)
        assert session is not None
        await services.control_plane.begin_precontent_plan(
            session_id=str(session_id),
            goal="Run one keyed fixture effect",
            origin=Origin(
                session_id=str(session_id),
                user_id=str(session.user_id),
                workspace_id=str(session.workspace_id),
                actor="planner",
                channel="cli",
            ),
            ttl_seconds=600,
            max_actions=1,
        )
        task = services.scheduler.create_task(
            name=f"keyed-recovery-{recovery_case}",
            goal="Recover one keyed fixture effect",
            schedule=Schedule.from_event("message.received"),
            capability_snapshot=set(),
            policy_snapshot_ref="keyed-recovery-test",
            created_by=session.user_id,
            workspace_id=session.workspace_id,
            max_runs=max_runs,
        )
        pending = impl._queue_pending_action(
            session_id=session_id,
            user_id=session.user_id,
            workspace_id=session.workspace_id,
            tool_name=tool_name,
            arguments={"value": "create-once"},
            reason="keyed-recovery-test-confirmation",
            capabilities=set(),
            confirmation_requirement=legacy_software_confirmation_requirement(),
            origin_turn_id="turn-keyed-recovery",
            task_id=task.id,
        )
        services.scheduler.queue_confirmation(
            task.id,
            impl._pending_to_dict(pending, public=True),
        )
        publication = 0

        def _fail_terminal_write(stage: AtomicWriteStage) -> None:
            nonlocal publication
            if stage == AtomicWriteStage.TEMP_OPEN:
                publication += 1
            if publication == 2 and stage == AtomicWriteStage.FILE_FSYNC:
                raise OSError("crash after keyed effect before terminal publication")

        impl._pending_state_fault_injector = _fail_terminal_write

        with pytest.raises(AtomicWriteError):
            await impl.do_action_confirm(
                {
                    "confirmation_id": pending.confirmation_id,
                    "decision_nonce": pending.decision_nonce,
                }
            )

        durable = json.loads(
            (config.data_dir / "pending_actions.json").read_text(encoding="utf-8")
        )[0]
        stable_key = str(durable["stable_idempotency_key"])
        assert durable["status"] == "executing"
        assert stable_key.startswith("shisad-")
        assert (
            durable["retry_descriptor"]["stable_adapter_guarantee_id"]
            == "test.keyed-effect/provider-v1"
        )
        assert calls == [stable_key]
        assert len(logical_effects) == 1
        if disable_before_restart:
            assert services.scheduler.disable_task(task.id) is True
    finally:
        await services.shutdown()

    if recovery_case in {"changed-key", "fabricated-evidence"}:
        pending_path = config.data_dir / "pending_actions.json"
        durable_rows = json.loads(pending_path.read_text(encoding="utf-8"))
        if recovery_case == "changed-key":
            durable_rows[0]["stable_idempotency_key"] = stable_key + "-changed"
        else:
            _replace_with_self_asserted_fabricated_evidence(durable_rows[0])
        pending_path.write_text(json.dumps(durable_rows, indent=2), encoding="utf-8")

    restarted = await DaemonServices.build(config)
    try:
        restarted.registry.register(tool_definition)
        restarted.idempotent_recovery_adapters[str(tool_name)] = StableIdempotencyAdapter(
            guarantee_id=(
                "test.keyed-effect/provider-v2"
                if recovery_case == "changed-adapter-guarantee"
                else "test.keyed-effect/provider-v1"
            ),
            operation=_deduplicating_adapter,
        )
        loaded_task = restarted.scheduler.get_task(task.id)
        assert loaded_task is not None
        assert loaded_task.enabled is False
        assert bool(loaded_task.recovery_containment_token) is (not disable_before_restart)
        restarted_handlers = DaemonControlHandlers(services=restarted)
        recovered = restarted_handlers._impl._pending_actions[pending.confirmation_id]
        if recovery_case not in {"changed-key", "fabricated-evidence"}:
            precontained_task = restarted.scheduler.get_task(task.id)
            assert precontained_task is not None
            assert precontained_task.enabled is False
            assert recovered.recovery_scheduler_posture_captured is True
            assert recovered.recovery_scheduler_restore_enabled is (not disable_before_restart)
            public = restarted_handlers._impl._pending_to_dict(recovered, public=True)
            assert "recovery_scheduler_posture_captured" not in public
            assert "recovery_scheduler_restore_enabled" not in public
            precontained_rows = json.loads(
                (config.data_dir / "pending_actions.json").read_text(encoding="utf-8")
            )
            assert precontained_rows[0]["recovery_scheduler_posture_captured"] is True
            assert precontained_rows[0]["recovery_scheduler_restore_enabled"] is (
                not disable_before_restart
            )
        await _wait_for_recovery_accounting(restarted_handlers._impl)
        if recovery_case in {
            "changed-key",
            "changed-adapter-guarantee",
            "fabricated-evidence",
        }:
            assert recovered.status == "outcome_unknown"
            assert recovered.status_reason == "uncertain_effect_requires_fresh_approval"
            assert recovered.retry_generation == 0
            assert recovered.provider_operation_id == ""
            assert recovered.recovery_result == {}
            assert calls == [stable_key]
        elif recovery_case in {
            "adapter-error",
            "adapter-non-finite",
            "adapter-lone-surrogate",
            "adapter-pathlike",
            "success-then-failure",
            "failure-then-success",
        }:
            assert recovered.status == "outcome_unknown"
            assert recovered.status_reason == (
                "idempotent_adapter_outcome_unknown"
                if recovery_case
                in {
                    "adapter-error",
                    "adapter-non-finite",
                    "adapter-lone-surrogate",
                    "adapter-pathlike",
                }
                else "idempotent_adapter_outcome_conflict"
            )
            assert recovered.retry_generation == 1
            assert recovered.provider_operation_id == (
                "provider-operation-contradiction"
                if recovery_case == "failure-then-success"
                else ""
            )
            assert recovered.recovery_result["ok"] is (recovery_case == "failure-then-success")
            assert calls == [stable_key, stable_key]
        else:
            assert recovered.status == "approved"
            assert recovered.status_reason == "recovered_stable_idempotency_key"
            assert recovered.retry_generation == 1
            assert recovered.provider_operation_id == "provider-operation-1"
            assert recovered.recovery_result["ok"] is True
            assert calls == [stable_key, stable_key]
        assert len(logical_effects) == 1
        recovered_task = restarted.scheduler.get_task(task.id)
        assert recovered_task is not None
        assert recovered_task.success_count == (1 if recovery_case == "exact-key" else 0)
        assert recovered_task.failure_count == (
            0 if recovery_case in {"exact-key", "changed-key", "fabricated-evidence"} else 1
        )
        if recovery_case in {"changed-key", "fabricated-evidence"}:
            assert recovered.scheduler_accounting_mode == "ambiguous"
        assert recovered_task.enabled is expected_task_enabled
        all_recovery_events = [row for row in _audit_rows(config) if row.get("actor") == "recovery"]
        recovery_events = (
            all_recovery_events
            if recovery_case in {"changed-key", "fabricated-evidence"}
            else [
                row
                for row in all_recovery_events
                if row.get("data", {}).get("approval_confirmation_id") == pending.confirmation_id
            ]
        )
        executed_events = [
            row for row in recovery_events if row.get("event_type") == "ToolExecuted"
        ]
        rejected_events = [
            row for row in recovery_events if row.get("event_type") == "ToolRejected"
        ]
        recovery_execution_records = [
            row
            for row in _control_plane_history_rows(config)
            if row.get("tool_name") == str(tool_name)
            and row.get("origin", {}).get("actor") == "recovery"
        ]
        all_execution_records = [
            row
            for row in _control_plane_history_rows(config)
            if row.get("tool_name") == str(tool_name)
        ]
        assert len(all_execution_records) == 1
        expected_initial_status = "failed" if recovery_case == "failure-then-success" else "success"
        assert all_execution_records[0].get("execution_status") == expected_initial_status
        plans = json.loads(
            (config.data_dir / "control_plane" / "plans.json").read_text(encoding="utf-8")
        )
        assert plans[str(recovered.session_id)]["executed_actions"] == (
            0 if expected_initial_status == "failed" else 1
        )
        if recovery_case == "exact-key":
            assert len(executed_events) == 1
            assert rejected_events == []
            assert recovery_execution_records == []
        elif recovery_case in {
            "changed-adapter-guarantee",
            "adapter-error",
            "adapter-non-finite",
            "adapter-lone-surrogate",
            "adapter-pathlike",
            "success-then-failure",
            "failure-then-success",
        }:
            assert len(executed_events) == 1
            assert len(rejected_events) == 1
            assert recovery_execution_records == []
        else:
            assert executed_events == []
            assert len(rejected_events) == 1
            assert recovery_execution_records == []
            rejected_data = rejected_events[0].get("data")
            assert isinstance(rejected_data, dict)
            assert rejected_events[0].get("session_id") is None
            assert rejected_data.get("session_id") is None
            assert rejected_data.get("tool_name") == ""
            assert rejected_data.get("approval_confirmation_id") == ""
            assert rejected_data.get("approval_session_id") == ""
    finally:
        await restarted.shutdown()

    if recovery_case in {
        "adapter-non-finite",
        "adapter-lone-surrogate",
        "adapter-pathlike",
    }:
        second_restart = await DaemonServices.build(config)
        try:
            second_restart.registry.register(tool_definition)
            second_restart.idempotent_recovery_adapters[str(tool_name)] = StableIdempotencyAdapter(
                guarantee_id="test.keyed-effect/provider-v1",
                operation=_deduplicating_adapter,
            )
            second_handlers = DaemonControlHandlers(services=second_restart)
            await _wait_for_recovery_accounting(second_handlers._impl)
            terminal = second_handlers._impl._pending_actions[pending.confirmation_id]
            assert terminal.status == "outcome_unknown"
            assert terminal.status_reason == "idempotent_adapter_outcome_unknown"
            assert terminal.recovery_accounting_pending is False
            assert terminal.recovery_authority_mac.startswith("hmac-sha256:")
            assert calls == [stable_key, stable_key]
        finally:
            await second_restart.shutdown()


@pytest.mark.parametrize(
    "adapter_outcome",
    ["exception", "non-finite", "lone-surrogate", "pathlike"],
)
@pytest.mark.asyncio
async def test_initial_stable_key_adapter_exception_preserves_outcome_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    adapter_outcome: str,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    tool_name = ToolName("test.keyed-ambiguous")
    tool_definition = ToolDefinition(
        name=tool_name,
        description="Create one fixture effect before a transport exception.",
        parameters=[ToolParameter(name="value", type="string")],
        retry_class=ToolRetryClass.STABLE_IDEMPOTENCY_KEY,
    )
    calls: list[str] = []
    logical_effects: set[str] = set()

    def _ambiguous_adapter(
        _arguments: dict[str, object],
        stable_idempotency_key: str,
    ) -> dict[str, object]:
        calls.append(stable_idempotency_key)
        logical_effects.add(stable_idempotency_key)
        if adapter_outcome == "exception":
            raise RuntimeError("provider accepted keyed operation before transport failure")
        if adapter_outcome == "non-finite":
            return {"ok": True, "value": float("nan")}
        if adapter_outcome == "lone-surrogate":
            return {"ok": True, "value": "\ud800"}
        return {"ok": True, "value": Path("/tmp/provider-value")}

    services = await DaemonServices.build(config)
    try:
        services.registry.register(tool_definition)
        services.idempotent_recovery_adapters[str(tool_name)] = StableIdempotencyAdapter(
            guarantee_id="test.keyed-ambiguous/provider-v1",
            operation=_ambiguous_adapter,
        )
        session_id, raw_impl = await _session_and_impl(services)
        impl = raw_impl
        session = services.session_manager.get(session_id)
        assert session is not None
        await services.control_plane.begin_precontent_plan(
            session_id=str(session_id),
            goal="Account one ambiguous keyed fixture effect",
            origin=Origin(
                session_id=str(session_id),
                user_id=str(session.user_id),
                workspace_id=str(session.workspace_id),
                actor="planner",
                channel="cli",
            ),
            ttl_seconds=600,
            max_actions=1,
        )
        task = services.scheduler.create_task(
            name="initial-keyed-ambiguity",
            goal="Do not repeat an uncertain keyed fixture effect",
            schedule=Schedule.from_event("message.received"),
            capability_snapshot=set(),
            policy_snapshot_ref="keyed-ambiguity-test",
            created_by=session.user_id,
            workspace_id=session.workspace_id,
            max_runs=3,
        )
        pending = impl._queue_pending_action(
            session_id=session_id,
            user_id=session.user_id,
            workspace_id=session.workspace_id,
            tool_name=tool_name,
            arguments={"value": "create-once"},
            reason="keyed-ambiguous-test-confirmation",
            capabilities=set(),
            confirmation_requirement=legacy_software_confirmation_requirement(),
            origin_turn_id="turn-keyed-ambiguous",
            task_id=task.id,
        )
        services.scheduler.queue_confirmation(
            task.id,
            impl._pending_to_dict(pending, public=True),
        )

        result = await impl.do_action_confirm(
            {
                "confirmation_id": pending.confirmation_id,
                "decision_nonce": pending.decision_nonce,
            }
        )

        assert result["confirmed"] is False
        assert pending.status == "outcome_unknown"
        assert pending.status_reason == "idempotent_adapter_outcome_unknown"
        assert pending.decision_nonce == ""
        assert len(calls) == 1
        assert logical_effects == {calls[0]}
        durable = json.loads(
            (config.data_dir / "pending_actions.json").read_text(encoding="utf-8")
        )[0]
        assert durable["status"] == "outcome_unknown"
        public = impl._pending_to_dict(pending, public=True)
        assert public["manual_retry"]["requires_fresh_approval"] is True
        assert public["stable_idempotency_key_present"] is True
        assert calls[0] not in json.dumps(public, sort_keys=True)
        uncertain_task = services.scheduler.get_task(task.id)
        assert uncertain_task is not None
        assert uncertain_task.success_count == 0
        assert uncertain_task.failure_count == 1
        assert uncertain_task.enabled is False
        execution_rows = [
            row
            for row in _control_plane_history_rows(config)
            if row.get("tool_name") == str(tool_name)
        ]
        assert len(execution_rows) == 1
        assert execution_rows[0]["execution_status"] == "outcome_unknown"
        plans = json.loads(
            (config.data_dir / "control_plane" / "plans.json").read_text(encoding="utf-8")
        )
        assert plans[str(session_id)]["executed_actions"] == 1
        executed_audits = [
            row
            for row in _audit_rows(config)
            if row.get("event_type") == "ToolExecuted"
            and row.get("data", {}).get("tool_name") == str(tool_name)
        ]
        assert len(executed_audits) == 1
        assert executed_audits[0].get("data", {}).get("details", {}).get("outcome_unknown") is True
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_recovered_stable_key_ambiguity_without_prior_status_consumes_trace_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    tool_name = ToolName("test.keyed-recovery-ambiguous")
    tool_definition = ToolDefinition(
        name=tool_name,
        description="Create one fixture effect across a simulated process crash.",
        parameters=[ToolParameter(name="value", type="string")],
        retry_class=ToolRetryClass.STABLE_IDEMPOTENCY_KEY,
    )
    calls: list[str] = []
    logical_effects: set[str] = set()

    class _SimulatedProcessCrash(BaseException):
        pass

    def _ambiguous_adapter(
        _arguments: dict[str, object],
        stable_idempotency_key: str,
    ) -> dict[str, object]:
        calls.append(stable_idempotency_key)
        logical_effects.add(stable_idempotency_key)
        if len(calls) == 1:
            raise _SimulatedProcessCrash("process stopped after provider acceptance")
        raise RuntimeError("provider deduplicated the retry but response was lost")

    services = await DaemonServices.build(config)
    try:
        services.registry.register(tool_definition)
        services.idempotent_recovery_adapters[str(tool_name)] = StableIdempotencyAdapter(
            guarantee_id="test.keyed-recovery-ambiguous/provider-v1",
            operation=_ambiguous_adapter,
        )
        session_id, raw_impl = await _session_and_impl(services)
        impl = raw_impl
        session = services.session_manager.get(session_id)
        assert session is not None
        await services.control_plane.begin_precontent_plan(
            session_id=str(session_id),
            goal="Account one recovered ambiguous keyed effect",
            origin=Origin(
                session_id=str(session_id),
                user_id=str(session.user_id),
                workspace_id=str(session.workspace_id),
                actor="planner",
                channel="cli",
            ),
            ttl_seconds=600,
            max_actions=1,
        )
        task = services.scheduler.create_task(
            name="recovered-keyed-ambiguity",
            goal="Do not repeat an ambiguous keyed fixture effect",
            schedule=Schedule.from_event("message.received"),
            capability_snapshot=set(),
            policy_snapshot_ref="keyed-recovery-ambiguity-test",
            created_by=session.user_id,
            workspace_id=session.workspace_id,
            max_runs=3,
        )
        pending = impl._queue_pending_action(
            session_id=session_id,
            user_id=session.user_id,
            workspace_id=session.workspace_id,
            tool_name=tool_name,
            arguments={"value": "create-once"},
            reason="keyed-recovery-ambiguous-test-confirmation",
            capabilities=set(),
            confirmation_requirement=legacy_software_confirmation_requirement(),
            origin_turn_id="turn-keyed-recovery-ambiguous",
            task_id=task.id,
        )
        services.scheduler.queue_confirmation(
            task.id,
            impl._pending_to_dict(pending, public=True),
        )

        with pytest.raises(_SimulatedProcessCrash):
            await impl.do_action_confirm(
                {
                    "confirmation_id": pending.confirmation_id,
                    "decision_nonce": pending.decision_nonce,
                }
            )

        durable = json.loads(
            (config.data_dir / "pending_actions.json").read_text(encoding="utf-8")
        )[0]
        assert durable["status"] == "executing"
        assert _control_plane_history_rows(config) == []
        plans = json.loads(
            (config.data_dir / "control_plane" / "plans.json").read_text(encoding="utf-8")
        )
        assert plans[str(session_id)]["executed_actions"] == 0
        assert len(calls) == 1
        assert len(logical_effects) == 1
    finally:
        await services.shutdown()

    restarted = await DaemonServices.build(config)
    try:
        restarted.registry.register(tool_definition)
        restarted.idempotent_recovery_adapters[str(tool_name)] = StableIdempotencyAdapter(
            guarantee_id="test.keyed-recovery-ambiguous/provider-v1",
            operation=_ambiguous_adapter,
        )
        handlers = DaemonControlHandlers(services=restarted)
        await _wait_for_recovery_accounting(handlers._impl)
        recovered = handlers._impl._pending_actions[pending.confirmation_id]
        assert recovered.status == "outcome_unknown"
        assert recovered.status_reason == "idempotent_adapter_outcome_unknown"
        assert recovered.recovery_accounting_pending is False
        execution_rows = [
            row
            for row in _control_plane_history_rows(config)
            if row.get("tool_name") == str(tool_name)
        ]
        assert len(execution_rows) == 1
        assert execution_rows[0]["execution_status"] == "outcome_unknown"
        plans = json.loads(
            (config.data_dir / "control_plane" / "plans.json").read_text(encoding="utf-8")
        )
        assert plans[str(recovered.session_id)]["executed_actions"] == 1
        recovery_audits = [
            row
            for row in _audit_rows(config)
            if row.get("event_type") == "ToolExecuted"
            and row.get("actor") == "recovery"
            and row.get("data", {}).get("approval_confirmation_id") == pending.confirmation_id
        ]
        assert len(recovery_audits) == 1
        assert recovery_audits[0].get("data", {}).get("details", {}).get("outcome_unknown") is True
        recovered_task = restarted.scheduler.get_task(task.id)
        assert recovered_task is not None
        assert recovered_task.success_count == 0
        assert recovered_task.failure_count == 1
        assert recovered_task.enabled is False
        assert calls == [calls[0], calls[0]]
        assert len(logical_effects) == 1
    finally:
        await restarted.shutdown()

    second_restart = await DaemonServices.build(config)
    try:
        second_restart.registry.register(tool_definition)
        second_restart.idempotent_recovery_adapters[str(tool_name)] = StableIdempotencyAdapter(
            guarantee_id="test.keyed-recovery-ambiguous/provider-v1",
            operation=_ambiguous_adapter,
        )
        second_handlers = DaemonControlHandlers(services=second_restart)
        await _wait_for_recovery_accounting(second_handlers._impl)
        assert (
            len(
                [
                    row
                    for row in _control_plane_history_rows(config)
                    if row.get("tool_name") == str(tool_name)
                ]
            )
            == 1
        )
        plans = json.loads(
            (config.data_dir / "control_plane" / "plans.json").read_text(encoding="utf-8")
        )
        assert plans[str(pending.session_id)]["executed_actions"] == 1
        assert len(calls) == 2
    finally:
        await second_restart.shutdown()
