"""Restart recovery for durably unresolved approved-action attempts."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from shisad.core.api.schema import SessionCreateParams
from shisad.core.approval import (
    approval_envelope_hash,
    canonical_sha256,
    legacy_software_confirmation_requirement,
)
from shisad.core.atomic_state import AtomicWriteError, AtomicWriteStage
from shisad.core.config import DaemonConfig
from shisad.core.request_context import RequestContext
from shisad.core.tools.schema import (
    ToolDefinition,
    ToolParameter,
    ToolRetryClass,
)
from shisad.core.types import Capability, SessionId, ToolName
from shisad.daemon.control_handlers import DaemonControlHandlers
from shisad.daemon.handlers._impl import ApprovedToolExecutionResult
from shisad.daemon.services import DaemonServices
from shisad.scheduler.schema import Schedule
from shisad.security.control_plane.schema import Origin


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
    tasks = list(getattr(impl, "_recovery_accounting_tasks", ()))
    if tasks:
        await asyncio.gather(*tasks)


async def _seed_unresolved_scheduled_time_attempt(
    config: DaemonConfig,
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
        return pending.confirmation_id, task.id
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_direct_scheduled_effect_has_durable_attempt_before_delivery_and_contains_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    pending_path = config.data_dir / "pending_actions.json"
    durable_before_effect: list[dict[str, object]] = []
    effect_calls = 0

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
            raise _CrashAfterEffect("process stopped after provider accepted delivery")

        monkeypatch.setattr(impl, "_execute_approved_action", _crash_after_effect)
        with pytest.raises(_CrashAfterEffect):
            await impl._execute_task_run(
                runs[0],
                event_type="scheduler.due",
                due_run=True,
            )

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
async def test_direct_scheduled_terminal_write_failure_disables_before_pump_retry(
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
            if publication == 2 and stage == AtomicWriteStage.FILE_FSYNC:
                raise OSError("process stopped before direct terminal publication")

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
        assert durable["status"] == "executing"
        contained_task = services.scheduler.get_task(task.id)
        assert contained_task is not None
        assert contained_task.success_count == 0
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
        assert recovered_task.success_count == 0
        assert recovered_task.failure_count == 1
        assert recovered_task.enabled is False
        assert effect_calls == 1
    finally:
        await restarted.shutdown()


@pytest.mark.parametrize("crash_point", ["before_accounting", "after_accounting"])
@pytest.mark.asyncio
async def test_confirmed_scheduled_terminal_state_reconciles_run_accounting_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    crash_point: str,
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

    restarted = await DaemonServices.build(config)
    try:
        restarted_handlers = DaemonControlHandlers(services=restarted)
        await _wait_for_recovery_accounting(restarted_handlers._impl)
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
        if corruption == "task_mismatch":
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
    if corruption in {"marker", "marker_and_identity"}:
        durable["scheduler_accounting_pending"] = "not-a-boolean"
    if corruption == "marker_and_identity":
        durable["execution_attempt_id"] = ["not", "text"]
        durable["result_id"] = ["not", "text"]
        durable["identity"]["execution_attempt_id"] = ["not", "text"]
        durable["identity"]["result_id"] = ["not", "text"]
    elif corruption == "identity_missing":
        durable.pop("identity")
    elif corruption == "identity_malformed":
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
    elif corruption == "confirmation_mismatch":
        durable["confirmation_id"] = "different-confirmation"
    elif corruption == "task_missing":
        durable["task_id"] = ""
    elif corruption == "task_both_missing":
        durable["task_id"] = ""
        durable["identity"]["task_id"] = ""
    elif corruption == "task_malformed":
        durable["task_id"] = ["not", "text"]
    elif corruption == "task_mismatch":
        durable["task_id"] = decoy_task_id
    elif corruption == "attempt_missing":
        durable["execution_attempt_id"] = ""
    elif corruption == "attempt_both_missing":
        durable["execution_attempt_id"] = ""
        durable["identity"]["execution_attempt_id"] = ""
    elif corruption == "attempt_malformed":
        durable["execution_attempt_id"] = ["not", "text"]
    elif corruption == "attempt_mismatch":
        durable["execution_attempt_id"] = "attempt-mismatch"
    elif corruption == "result_missing":
        durable["result_id"] = ""
    elif corruption == "result_both_missing":
        durable["result_id"] = ""
        durable["identity"]["result_id"] = ""
    elif corruption == "result_malformed":
        durable["result_id"] = ["not", "text"]
    elif corruption == "result_mismatch":
        durable["result_id"] = "result-mismatch"
    elif corruption == "status_pending":
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
        if unrecoverable_confirmation:
            assert reconciled_task.success_count == 0
            assert reconciled_task.failure_count == 0
        else:
            assert reconciled_task.success_count == 0
            assert reconciled_task.failure_count == 1
        assert reconciled_task.enabled is False
        if not unrecoverable_confirmation:
            durable = next(
                row
                for row in json.loads(pending_path.read_text(encoding="utf-8"))
                if row["confirmation_id"] == pending.confirmation_id
            )
            assert durable["scheduler_accounting_pending"] is False
            if corruption == "status_pending":
                assert durable["status"] == "outcome_unknown"
                assert durable["decision_nonce"] == ""
        if decoy_task_id:
            decoy_task = restarted.scheduler.get_task(decoy_task_id)
            assert decoy_task is not None
            assert decoy_task.success_count == 0
            assert decoy_task.failure_count == 0
            assert decoy_task.enabled is True
    finally:
        await restarted.shutdown()


@pytest.mark.asyncio
async def test_corrupt_confirmation_evidence_recovery_replay_uses_persisted_timestamp(
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
    persisted_created_at = str(durable["created_at"])
    pending_path.write_text(json.dumps(durable_rows, indent=2), encoding="utf-8")

    restarted = await DaemonServices.build(config)
    try:
        handlers = DaemonControlHandlers(services=restarted)
        impl = handlers._impl

        def _fail_marker_clear(stage: AtomicWriteStage) -> None:
            if stage == AtomicWriteStage.FILE_FSYNC:
                raise OSError("process stopped before corrupt-evidence marker clear")

        impl._pending_state_fault_injector = _fail_marker_clear
        accounting_tasks = list(impl._recovery_accounting_tasks)
        assert len(accounting_tasks) == 1
        with pytest.raises(AtomicWriteError):
            await asyncio.gather(*accounting_tasks)
        recovery_rejections = [
            row
            for row in _audit_rows(config)
            if row.get("event_type") == "ToolRejected"
            and row.get("actor") == "recovery"
            and row.get("data", {}).get("approval_confirmation_id") == confirmation_id
        ]
        assert len(recovery_rejections) == 1
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
            if row.get("event_type") == "ToolRejected"
            and row.get("actor") == "recovery"
            and row.get("data", {}).get("approval_confirmation_id") == confirmation_id
        ]
        assert len(recovery_rejections) == 1
        assert (
            recovery_rejections[0].get("data", {}).get("approval_timestamp") == persisted_created_at
        )
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
        pending.execution_attempt_id = f"attempt-web-fetch-{scenario}"
        pending.result_id = f"result-web-fetch-{scenario}"
        pending.status = "executing"
        pending.status_reason = "confirmation_execution_started"
        pending.approval_evidence_hash = "sha256:" + ("a" * 64)
        impl._persist_pending_actions()
    finally:
        await services.shutdown()

    restarted = await DaemonServices.build(config)
    try:
        restarted_handlers = DaemonControlHandlers(services=restarted)
        recovered = restarted_handlers._impl._pending_actions[pending.confirmation_id]
        assert recovered.status == "outcome_unknown"
        assert recovered.status_reason == "uncertain_effect_requires_fresh_approval"
        assert recovered.decision_nonce == ""
        assert recovered.retry_generation == 0
        assert fetch_calls == 0
        public = restarted_handlers._impl._pending_to_dict(recovered, public=True)
        assert public["uncertainty_evidence"]["execution_attempt_id"] == (
            f"attempt-web-fetch-{scenario}"
        )
        assert public["manual_retry"]["requires_fresh_approval"] is True
        assert public["manual_retry"]["reuse_confirmation_id"] is False
        durable = json.loads(
            (config.data_dir / "pending_actions.json").read_text(encoding="utf-8")
        )[0]
        assert durable["status"] == "outcome_unknown"
        assert durable["execution_attempt_id"] == f"attempt-web-fetch-{scenario}"
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
            assert contained_task.failure_count == 1
            assert contained_task.enabled is False
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
        pytest.param("fabricated-evidence", 1, False, False, id="fabricated-evidence"),
        pytest.param("adapter-error", 1, False, False, id="adapter-error"),
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
        return result

    services = await DaemonServices.build(config)
    try:
        services.registry.register(tool_definition)
        services.idempotent_recovery_adapters[str(tool_name)] = _deduplicating_adapter
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
        restarted.idempotent_recovery_adapters[str(tool_name)] = _deduplicating_adapter
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
            precontained_rows = json.loads(
                (config.data_dir / "pending_actions.json").read_text(encoding="utf-8")
            )
            assert precontained_rows[0]["recovery_scheduler_posture_captured"] is True
            assert precontained_rows[0]["recovery_scheduler_restore_enabled"] is (
                not disable_before_restart
            )
        await _wait_for_recovery_accounting(restarted_handlers._impl)
        if recovery_case in {"changed-key", "fabricated-evidence"}:
            assert recovered.status == "outcome_unknown"
            assert recovered.status_reason == "uncertain_effect_requires_fresh_approval"
            assert recovered.retry_generation == 0
            assert recovered.provider_operation_id == ""
            assert recovered.recovery_result == {}
            assert calls == [stable_key]
        elif recovery_case in {
            "adapter-error",
            "success-then-failure",
            "failure-then-success",
        }:
            assert recovered.status == "outcome_unknown"
            assert recovered.status_reason == (
                "idempotent_adapter_outcome_unknown"
                if recovery_case == "adapter-error"
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
        assert recovered_task.failure_count == (0 if recovery_case == "exact-key" else 1)
        assert recovered_task.enabled is expected_task_enabled
        recovery_events = [
            row
            for row in _audit_rows(config)
            if row.get("actor") == "recovery"
            and row.get("data", {}).get("approval_confirmation_id") == pending.confirmation_id
        ]
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
            "adapter-error",
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
    finally:
        await restarted.shutdown()


@pytest.mark.asyncio
async def test_initial_stable_key_adapter_exception_preserves_outcome_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
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
        raise RuntimeError("provider accepted keyed operation before transport failure")

    services = await DaemonServices.build(config)
    try:
        services.registry.register(tool_definition)
        services.idempotent_recovery_adapters[str(tool_name)] = _ambiguous_adapter
        session_id, raw_impl = await _session_and_impl(services)
        impl = raw_impl
        session = services.session_manager.get(session_id)
        assert session is not None
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
    finally:
        await services.shutdown()
