"""Restart recovery for durably unresolved approved-action attempts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shisad.core.api.schema import SessionCreateParams
from shisad.core.approval import legacy_software_confirmation_requirement
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
from shisad.daemon.services import DaemonServices


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
        "action_digest_mismatch",
        "retry_generation_exhausted",
        "principal_mismatch",
        "delivery_target_mismatch",
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
    elif tamper == "action_digest_mismatch":
        durable_rows[0]["action_digest"] = "sha256:" + ("f" * 64)
    elif tamper == "retry_generation_exhausted":
        durable_rows[0]["retry_generation"] = 1
    elif tamper == "principal_mismatch":
        durable_rows[0]["user_id"] = "mallory"
    elif tamper == "delivery_target_mismatch":
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
    finally:
        await restarted.shutdown()


@pytest.mark.parametrize("change_persisted_key", [False, True], ids=["exact-key", "changed-key"])
@pytest.mark.asyncio
async def test_stable_idempotency_key_recovery_reuses_key_without_duplicate_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    change_persisted_key: bool,
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
        return logical_effects.setdefault(
            stable_idempotency_key,
            {
                "ok": True,
                "provider_operation_id": "provider-operation-1",
                "value": str(arguments.get("value", "")),
            },
        )

    services = await DaemonServices.build(config)
    try:
        services.registry.register(tool_definition)
        services.idempotent_recovery_adapters[str(tool_name)] = _deduplicating_adapter
        session_id, raw_impl = await _session_and_impl(services)
        impl = raw_impl
        session = services.session_manager.get(session_id)
        assert session is not None
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
    finally:
        await services.shutdown()

    if change_persisted_key:
        pending_path = config.data_dir / "pending_actions.json"
        durable_rows = json.loads(pending_path.read_text(encoding="utf-8"))
        durable_rows[0]["stable_idempotency_key"] = stable_key + "-changed"
        pending_path.write_text(json.dumps(durable_rows, indent=2), encoding="utf-8")

    restarted = await DaemonServices.build(config)
    try:
        restarted.registry.register(tool_definition)
        restarted.idempotent_recovery_adapters[str(tool_name)] = _deduplicating_adapter
        restarted_handlers = DaemonControlHandlers(services=restarted)
        recovered = restarted_handlers._impl._pending_actions[pending.confirmation_id]
        if change_persisted_key:
            assert recovered.status == "outcome_unknown"
            assert recovered.status_reason == "uncertain_effect_requires_fresh_approval"
            assert recovered.retry_generation == 0
            assert recovered.provider_operation_id == ""
            assert recovered.recovery_result == {}
            assert calls == [stable_key]
        else:
            assert recovered.status == "approved"
            assert recovered.status_reason == "recovered_stable_idempotency_key"
            assert recovered.retry_generation == 1
            assert recovered.provider_operation_id == "provider-operation-1"
            assert recovered.recovery_result["ok"] is True
            assert calls == [stable_key, stable_key]
        assert len(logical_effects) == 1
    finally:
        await restarted.shutdown()
