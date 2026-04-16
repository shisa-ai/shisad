"""M2 daemon services extraction coverage."""

from __future__ import annotations

import subprocess
import sys
import textwrap
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from shisad.core.config import DaemonConfig, ModelConfig
from shisad.core.events import EventBus, SessionCreated
from shisad.core.providers.local_planner import LocalPlannerProvider
from shisad.core.providers.routed_openai import RoutedOpenAIProvider
from shisad.core.providers.routing import ModelRouter
from shisad.core.trace import TraceTurn
from shisad.core.types import Capability, CredentialRef, SessionId, ToolName, UserId, WorkspaceId
from shisad.daemon.handlers._impl import HandlerImplementation, PendingAction
from shisad.daemon.services import (
    DaemonServices,
    _build_provider_diagnostics,
    _build_tool_registry,
    _key_gated_acceptance_matrix,
    _log_provider_route_summary,
    _normalize_tool_destination,
    _register_route_credentials,
    _validate_security_route_pins,
    _warn_on_evidence_kms_endpoint_config,
    _warn_on_provider_route_gaps,
)
from shisad.memory.schema import MemorySource
from shisad.scheduler.schema import Schedule
from shisad.security.control_plane.sidecar import ControlPlaneUnavailableError
from shisad.security.credentials import (
    ApprovalFactorRecord,
    CredentialConfig,
    InMemoryCredentialStore,
    SignerKeyRecord,
)
from shisad.security.lockdown import LockdownLevel
from shisad.security.risk import RiskObservation, RiskPolicyVersion
from shisad.skills.artifacts import ArtifactState
from shisad.skills.manager import InstalledSkill


def test_u8_daemon_runner_import_defers_disabled_backend_modules() -> None:
    code = textwrap.dedent(
        """
        import sys

        import shisad.daemon.runner

        eager_modules = [
            "shisad.assistant.realitycheck",
            "shisad.channels.discord",
            "shisad.channels.matrix",
            "shisad.channels.slack",
            "shisad.channels.telegram",
            "shisad.executors.browser",
        ]
        for name in eager_modules:
            if name in sys.modules:
                print(name)
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        text=True,
        capture_output=True,
    )
    assert result.stdout.strip() == ""


def _clear_remote_provider_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for env_var in (
        "SHISA_API_KEY",
        "SHISAD_MODEL_API_KEY",
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "OPENROUTER_API_KEY",
        "ANTHROPIC_API_KEY",
        "SHISAD_MODEL_PLANNER_PROVIDER_PRESET",
        "SHISAD_MODEL_PLANNER_BASE_URL",
        "SHISAD_MODEL_PLANNER_REMOTE_ENABLED",
        "SHISAD_MODEL_PLANNER_API_KEY",
        "SHISAD_MODEL_PLANNER_AUTH_MODE",
        "SHISAD_MODEL_EMBEDDINGS_PROVIDER_PRESET",
        "SHISAD_MODEL_EMBEDDINGS_BASE_URL",
        "SHISAD_MODEL_EMBEDDINGS_REMOTE_ENABLED",
        "SHISAD_MODEL_EMBEDDINGS_API_KEY",
        "SHISAD_MODEL_EMBEDDINGS_AUTH_MODE",
        "SHISAD_MODEL_MONITOR_PROVIDER_PRESET",
        "SHISAD_MODEL_MONITOR_BASE_URL",
        "SHISAD_MODEL_MONITOR_REMOTE_ENABLED",
        "SHISAD_MODEL_MONITOR_API_KEY",
        "SHISAD_MODEL_MONITOR_AUTH_MODE",
    ):
        monkeypatch.delenv(env_var, raising=False)
    monkeypatch.setenv("SHISAD_MODEL_REMOTE_ENABLED", "false")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_REMOTE_ENABLED", "false")


@pytest.mark.asyncio
async def test_daemon_services_builds_with_local_provider(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Explicitly clear API key overrides to force local provider path.
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    services = await DaemonServices.build(config)
    try:
        assert isinstance(services.provider, LocalPlannerProvider)
        assert services.matrix_channel is None
        assert services.server is not None
        assert services.internal_ingress_marker is not None
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_h2_daemon_services_reuses_firewall_for_ingestion_pipeline(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    services = await DaemonServices.build(config)
    try:
        assert services.ingestion._firewall is services.firewall
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_h1_daemon_services_builds_with_supervised_control_plane_sidecar(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    services = await DaemonServices.build(config)
    sidecar = services.control_plane_sidecar
    assert sidecar is not None
    assert sidecar.process.returncode is None
    assert await services.control_plane.ping() is True

    await services.shutdown()

    assert sidecar.process.returncode is not None
    assert not sidecar.socket_path.exists()


@pytest.mark.asyncio
async def test_h1_daemon_services_build_fails_closed_when_control_plane_sidecar_unavailable(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _raise_sidecar(  # type: ignore[no-untyped-def]
        *,
        data_dir,
        policy_path,
        assistant_fs_roots,
        startup_timeout_seconds,
    ):
        _ = (data_dir, policy_path, assistant_fs_roots, startup_timeout_seconds)
        raise ControlPlaneUnavailableError(reason_code="control_plane.startup_failed")

    monkeypatch.setattr("shisad.daemon.services.start_control_plane_sidecar", _raise_sidecar)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )

    with pytest.raises(ControlPlaneUnavailableError, match="Control-plane sidecar unavailable"):
        await DaemonServices.build(config)


@pytest.mark.asyncio
async def test_h1_daemon_services_closes_started_sidecar_on_late_build_failure(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[bool] = []

    class _FakeSidecar:
        def __init__(self) -> None:
            self.client = SimpleNamespace(ping=self._ping)
            self.process = SimpleNamespace(returncode=None)
            self.socket_path = tmp_path / "data" / "control_plane" / "fake.sock"

        async def _ping(self) -> bool:
            return True

        async def close(self) -> None:
            closed.append(True)

    async def _fake_start(  # type: ignore[no-untyped-def]
        *,
        data_dir,
        policy_path,
        assistant_fs_roots,
        startup_timeout_seconds,
    ):
        _ = (data_dir, policy_path, assistant_fs_roots, startup_timeout_seconds)
        return _FakeSidecar()

    monkeypatch.setattr("shisad.daemon.services.start_control_plane_sidecar", _fake_start)
    monkeypatch.setattr(
        "shisad.daemon.services._build_tool_registry",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )

    with pytest.raises(RuntimeError, match="boom"):
        await DaemonServices.build(config)

    assert closed == [True]


@pytest.mark.asyncio
async def test_daemon_services_threads_control_plane_startup_timeout(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    captured: dict[str, float] = {}

    class _FakeSidecar:
        def __init__(self) -> None:
            self.client = SimpleNamespace(ping=self._ping)
            self.process = SimpleNamespace(returncode=None)
            self.socket_path = tmp_path / "data" / "control_plane" / "fake.sock"

        async def _ping(self) -> bool:
            return True

        async def close(self) -> None:
            return None

    async def _fake_start(  # type: ignore[no-untyped-def]
        *,
        data_dir,
        policy_path,
        assistant_fs_roots,
        startup_timeout_seconds,
    ):
        _ = (data_dir, policy_path, assistant_fs_roots)
        captured["startup_timeout_seconds"] = float(startup_timeout_seconds)
        return _FakeSidecar()

    monkeypatch.setattr("shisad.daemon.services.start_control_plane_sidecar", _fake_start)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        control_plane_startup_timeout_seconds=12.5,
    )
    services = await DaemonServices.build(config)
    try:
        assert captured["startup_timeout_seconds"] == pytest.approx(12.5)
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_daemon_services_uses_default_control_plane_startup_timeout(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    captured: dict[str, float] = {}

    class _FakeSidecar:
        def __init__(self) -> None:
            self.client = SimpleNamespace(ping=self._ping)
            self.process = SimpleNamespace(returncode=None)
            self.socket_path = tmp_path / "data" / "control_plane" / "fake.sock"

        async def _ping(self) -> bool:
            return True

        async def close(self) -> None:
            return None

    async def _fake_start(  # type: ignore[no-untyped-def]
        *,
        data_dir,
        policy_path,
        assistant_fs_roots,
        startup_timeout_seconds,
    ):
        _ = (data_dir, policy_path, assistant_fs_roots)
        captured["startup_timeout_seconds"] = float(startup_timeout_seconds)
        return _FakeSidecar()

    monkeypatch.setattr("shisad.daemon.services.start_control_plane_sidecar", _fake_start)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    services = await DaemonServices.build(config)
    try:
        assert captured["startup_timeout_seconds"] == pytest.approx(15.0)
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_daemon_services_reset_test_state_clears_documented_subsystems(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        trace_enabled=True,
        test_mode=True,
        channel_identity_allowlist={"matrix": ["trusted-alice"]},
    )
    services = await DaemonServices.build(config)
    try:
        static_credential = CredentialRef("static-route-test")
        services.credential_store.register(
            static_credential,
            "super-secret",
            CredentialConfig(allowed_hosts=["example.com"]),
        )
        event_handler_count = sum(
            len(items) for items in services.event_bus._handlers.values()
        ) + len(services.event_bus._global_handlers)

        session = services.session_manager.create(
            channel="cli",
            user_id=UserId("alice"),
            workspace_id=WorkspaceId("ws1"),
        )
        task = services.scheduler.create_task(
            name="daily-summary",
            goal="summarize updates",
            schedule=Schedule.from_event("message.received"),
            capability_snapshot={Capability.MESSAGE_SEND},
            policy_snapshot_ref="policy-1",
            created_by=UserId("alice"),
            workspace_id=WorkspaceId("ws1"),
        )
        services.scheduler.queue_confirmation(
            task.id,
            {"confirmation_id": "sched-pending-1", "status": "pending"},
        )

        decision = services.memory_manager.write(
            entry_type="note",
            key="note-1",
            value="remember this",
            source=MemorySource(
                origin="user",
                source_id=str(session.id),
                extraction_method="note.create",
            ),
            user_confirmed=True,
        )
        assert decision.kind == "allow"
        assert decision.entry is not None

        services.lockdown_manager.set_level(
            session.id,
            level=LockdownLevel.CAUTION,
            reason="unit-test",
        )
        services.rate_limiter.consume(
            session_id=str(session.id),
            user_id="alice",
            tool_name="note.create",
        )
        services.checkpoint_store.create(session)
        services.channel_state_store.mark_seen(channel="matrix", message_id="msg-1")
        services.evidence_store.store(
            session.id,
            "evidence payload",
            taint_labels=set(),
            source="unit-test",
            summary="evidence summary",
        )
        services.ingestion.ingest(
            source_id="source-1",
            source_type="tool",
            content="retrieval payload",
        )

        inventory_type = services.selfmod_manager._inventory.__class__
        services.selfmod_manager._inventory = inventory_type.model_validate(
            {
                "skills": {"demo": {"enabled": True, "active_version": "1.0.0"}},
                "behavior_packs": {"persona": {"enabled": True, "active_version": "2.0.0"}},
            }
        )
        services.selfmod_manager._persist_inventory()
        (services.selfmod_manager._proposal_dir / "proposal.json").write_text(
            "{}",
            encoding="utf-8",
        )
        (services.selfmod_manager._change_dir / "change.json").write_text(
            "{}",
            encoding="utf-8",
        )
        (services.selfmod_manager._artifact_root / "artifact.txt").write_text(
            "artifact",
            encoding="utf-8",
        )
        services.selfmod_manager._incident_path.write_text(
            '{"reason": "unit-test"}',
            encoding="utf-8",
        )

        services.skill_manager._inventory["demo"] = InstalledSkill(
            name="demo",
            version="1.0.0",
            path=str(tmp_path / "demo-skill"),
            manifest_hash="abc123",
            state=ArtifactState.PUBLISHED,
            author="unit-test",
            tool_schema_hashes={},
        )
        services.skill_manager._skill_tool_map["demo"] = [ToolName("demo.tool")]
        services.skill_manager._pending_registration_events.append(object())  # type: ignore[arg-type]
        services.skill_manager._persist_inventory()

        services.credential_store.register_approval_factor(
            ApprovalFactorRecord(
                credential_id="totp-1",
                user_id="alice",
                method="totp",
                principal_id="alice",
                secret_b32="JBSWY3DPEHPK3PXP",
            )
        )
        services.credential_store.register_signer_key(
            SignerKeyRecord(
                credential_id="signer-1",
                user_id="alice",
                backend="kms",
                principal_id="alice",
                algorithm="ed25519",
                device_type="ledger-enterprise",
                public_key_pem="-----BEGIN PUBLIC KEY-----\nQUFB\n-----END PUBLIC KEY-----",
            )
        )
        assert services.credential_store.get_or_create_local_fido2_realm_id(seed="realm") == "realm"

        services.identity_map.configure_channel_trust(channel="matrix", trust_level="trusted")
        services.identity_map.allow_identity(channel="matrix", external_user_id="extra-user")
        services.identity_map.bind(
            channel="matrix",
            external_user_id="extra-user",
            user_id=UserId("extra"),
            workspace_id=WorkspaceId("ws-extra"),
        )
        services.identity_map.record_pairing_request(
            channel="matrix",
            external_user_id="pending-user",
            workspace_hint="!room:example.org",
        )

        services.transcript_store.append(
            session.id,
            role="user",
            content="x" * 5000,
        )
        assert services.trace_recorder is not None
        services.trace_recorder.record(
            TraceTurn(
                session_id=str(session.id),
                user_content="trace me",
            )
        )
        await services.audit_log.persist(
            SessionCreated(
                session_id=session.id,
                actor="unit-test",
                user_id=UserId("alice"),
                workspace_id="ws1",
            )
        )
        archive_dir = config.data_dir / "session_archives"
        archive_dir.mkdir(parents=True, exist_ok=True)
        (archive_dir / "archive.zip").write_text("archive", encoding="utf-8")

        services.risk_calibrator.record(
            RiskObservation(
                session_id=str(session.id),
                user_id="alice",
                tool_name="note.create",
                outcome="allowed",
                risk_score=0.4,
            )
        )
        services.risk_calibrator.save_policy(RiskPolicyVersion(version="v99"))

        result = await services.reset_test_state()

        assert result["status"] == "reset"
        assert result["cleared"]["sessions"] == 1
        assert result["cleared"]["scheduler_tasks"] == 1
        assert result["cleared"]["scheduler_pending_confirmations"] == 1
        assert result["cleared"]["memory_entries"] == 1
        assert result["cleared"]["lockdown_states"] == 1
        assert result["cleared"]["rate_limiter_windows"] >= 4
        assert result["cleared"]["audit_entries"] >= 1
        assert result["cleared"]["checkpoints"] == 1
        assert result["cleared"]["channel_state_files"] == 1
        assert result["cleared"]["channel_state_channels"] == 1
        assert result["cleared"]["evidence_refs"] == 1
        assert result["cleared"]["ingestion_records"] == 1
        assert result["cleared"]["selfmod_entries"] == 2
        assert result["cleared"]["skill_entries"] == 1
        assert result["cleared"]["approval_factors"] == 1
        assert result["cleared"]["signer_keys"] == 1
        assert result["cleared"]["identity_bindings"] == 1
        assert result["cleared"]["identity_pairing_requests"] == 1
        assert result["cleared"]["transcripts"] >= 2
        assert result["cleared"]["trace_files"] == 1
        assert result["cleared"]["session_archives"] == 1
        assert result["cleared"]["risk_observations"] == 1
        assert result["cleared"]["risk_policies"] == 1

        assert services.session_manager.list_active() == []
        assert services.scheduler.list_tasks() == []
        assert services.scheduler.pending_confirmations(task.id) == []
        assert services.memory_manager.list_entries(limit=10) == []
        assert services.lockdown_manager._states == {}
        assert services.rate_limiter._by_tool == {}
        assert services.rate_limiter._by_user == {}
        assert services.rate_limiter._by_session == {}
        assert services.rate_limiter._by_tool_burst == {}
        assert services.audit_log.entry_count == 0
        assert list(services.checkpoint_store._dir.iterdir()) == []
        assert services.channel_state_store.snapshot("matrix")["seen_count"] == 0
        assert services.evidence_store._refs == {}
        assert services.ingestion._records == {}
        assert services.ingestion._vectors == {}
        assert services.ingestion._active_key_id
        assert services.selfmod_manager._inventory.skills == {}
        assert services.selfmod_manager._inventory.behavior_packs == {}
        assert services.skill_manager.list_installed() == []
        assert services.skill_manager._skill_tool_map == {}
        assert services.credential_store.has_credential(static_credential) is True
        assert services.credential_store.list_approval_factors() == []
        assert services.credential_store.list_signer_keys(include_revoked=True) == []
        assert services.identity_map.is_allowed(channel="matrix", external_user_id="trusted-alice")
        assert not services.identity_map.is_allowed(channel="matrix", external_user_id="extra-user")
        assert (
            services.identity_map.resolve(channel="matrix", external_user_id="extra-user") is None
        )
        assert services.identity_map.trust_for_channel("matrix") == "untrusted"
        assert services.transcript_store.list_entries(session.id) == []
        assert services.trace_recorder.read_turns(str(session.id)) == []
        assert not any(archive_dir.iterdir())
        assert not services.risk_calibrator.observations_path.exists()
        assert not services.risk_calibrator.policy_path.exists()
        post_reset_handler_count = sum(
            len(items) for items in services.event_bus._handlers.values()
        ) + len(services.event_bus._global_handlers)
        assert post_reset_handler_count == event_handler_count

        second_ingest = services.ingestion.ingest(
            source_id="source-2",
            source_type="tool",
            content="fresh payload",
        )
        assert second_ingest.chunk_id
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_daemon_services_reset_test_state_requires_explicit_test_mode(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        test_mode=False,
    )
    services = await DaemonServices.build(config)
    try:
        with pytest.raises(RuntimeError, match="outside explicit test mode"):
            await services.reset_test_state()
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_handler_daemon_reset_clears_handler_state_and_marks_non_quiescent_reset(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        test_mode=True,
    )
    services = await DaemonServices.build(config)
    impl = HandlerImplementation(services=services)
    try:
        session = services.session_manager.create(
            channel="cli",
            user_id=UserId("alice"),
            workspace_id=WorkspaceId("ws1"),
        )
        task = services.scheduler.create_task(
            name="approval-task",
            goal="needs confirmation",
            schedule=Schedule.from_event("message.received"),
            capability_snapshot={Capability.MESSAGE_SEND},
            policy_snapshot_ref="policy-1",
            created_by=UserId("alice"),
            workspace_id=WorkspaceId("ws1"),
        )
        services.scheduler.queue_confirmation(
            task.id,
            {"confirmation_id": "task-confirm-1", "status": "pending"},
        )

        started = await impl.do_two_factor_register_begin(
            {"method": "totp", "user_id": "alice", "name": "ops-laptop"}
        )
        enrollment_id = str(started["enrollment_id"])
        assert enrollment_id

        pending = PendingAction(
            confirmation_id="confirm-1",
            decision_nonce="nonce-1",
            session_id=SessionId(str(session.id)),
            user_id=UserId("alice"),
            workspace_id=WorkspaceId("ws1"),
            tool_name=ToolName("note.create"),
            arguments={"key": "reset"},
            reason="unit-test",
            capabilities={Capability.MEMORY_WRITE},
            created_at=datetime.now(UTC),
        )
        impl._pending_actions[pending.confirmation_id] = pending
        impl._pending_by_session[session.id] = [pending.confirmation_id]
        impl._persist_pending_actions()
        impl._monitor_reject_counts[session.id] = 2
        impl._plan_violation_counts[session.id] = 3
        impl._confirmation_alerted_at[pending.confirmation_id] = datetime.now(UTC)
        impl._confirmation_failure_tracker.record_failure(user_id="alice", method="totp")
        impl._identity_map.record_pairing_request(
            channel="matrix",
            external_user_id="mallory",
            workspace_hint="!room:example.org",
        )
        impl._record_pairing_request_artifact(
            channel="matrix",
            external_user_id="mallory",
            workspace_hint="!room:example.org",
            reason="identity_not_allowlisted",
        )

        result = await impl.do_daemon_reset({})

        assert result["status"] == "reset"
        assert result["quiescent"] is False
        assert all(result["invariants"].values())
        assert result["cleared"]["scheduler_pending_confirmations"] == 1
        assert result["cleared"]["pending_actions"] == 1
        assert result["cleared"]["pending_action_sessions"] == 1
        assert result["cleared"]["pending_two_factor_enrollments"] == 1
        assert result["cleared"]["monitor_reject_counts"] == 1
        assert result["cleared"]["plan_violation_counts"] == 1
        assert result["cleared"]["confirmation_alerts"] == 1
        assert result["cleared"]["confirmation_lockouts"] == 1
        assert result["cleared"]["pairing_requests"] == 1
        assert result["cleared"]["pairing_request_artifacts"] == 1

        assert impl._pending_actions == {}
        assert impl._pending_by_session == {}
        assert impl._pending_two_factor_enrollments == {}
        assert impl._monitor_reject_counts == {}
        assert impl._plan_violation_counts == {}
        assert impl._confirmation_alerted_at == {}
        assert impl._confirmation_failure_tracker._state == {}
        assert impl._identity_map.list_pairing_requests() == []
        assert not impl._pending_actions_file.exists()
        assert not impl._pairing_requests_file.exists()
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_handler_daemon_reset_rejects_concurrent_reset_attempts(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        test_mode=True,
    )
    services = await DaemonServices.build(config)
    impl = HandlerImplementation(services=services)
    try:
        services.reset_in_progress = True
        with pytest.raises(RuntimeError, match="already in progress"):
            await impl.do_daemon_reset({})
    finally:
        services.reset_in_progress = False
        await services.shutdown()


@pytest.mark.asyncio
async def test_daemon_services_builds_with_remote_provider_when_enabled(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISA_API_KEY", "test-token")
    monkeypatch.setenv("SHISAD_MODEL_REMOTE_ENABLED", "true")
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    services = await DaemonServices.build(config)
    try:
        assert isinstance(services.provider, RoutedOpenAIProvider)
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_s0_daemon_services_supports_remote_route_with_auth_none(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SHISA_API_KEY", raising=False)
    monkeypatch.delenv("SHISAD_MODEL_API_KEY", raising=False)
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_PROVIDER_PRESET", "vllm_local_default")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "http://127.0.0.1:8000/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_REMOTE_ENABLED", "true")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_AUTH_MODE", "none")

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    services = await DaemonServices.build(config)
    try:
        assert isinstance(services.provider, RoutedOpenAIProvider)
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_s0_daemon_services_registers_credentials_per_route_host(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_REMOTE_ENABLED", "true")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_PROVIDER_PRESET", "openai_default")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_API_KEY", "planner-key")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_PROVIDER_PRESET", "openrouter_default")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_API_KEY", "monitor-key")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_REMOTE_ENABLED", "true")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_PROVIDER_PRESET", "vllm_local_default")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_REMOTE_ENABLED", "true")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_AUTH_MODE", "none")

    captured: list[tuple[str, str, tuple[str, ...], str, str]] = []

    class _CapturingCredentialStore(InMemoryCredentialStore):
        def register(self, ref, value, config):  # type: ignore[no-untyped-def]
            captured.append(
                (
                    str(ref),
                    value,
                    tuple(config.allowed_hosts),
                    config.header_name,
                    config.header_prefix,
                )
            )
            super().register(ref, value, config)

    monkeypatch.setattr("shisad.daemon.services.InMemoryCredentialStore", _CapturingCredentialStore)

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    services = await DaemonServices.build(config)
    try:
        hosts = {entry[2][0] for entry in captured}
        assert "api.openai.com" in hosts
        assert "openrouter.ai" in hosts
        assert "api.shisa.ai" not in hosts
        assert all(prefix == "Bearer " for *_rest, prefix in captured)
    finally:
        await services.shutdown()


def test_s0_register_route_credentials_coalesces_duplicate_signatures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SHISA_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("SHISAD_MODEL_API_KEY", raising=False)

    captured: list[tuple[str, str, tuple[str, ...], str, str]] = []

    class _CapturingCredentialStore(InMemoryCredentialStore):
        def register(self, ref, value, config):  # type: ignore[no-untyped-def]
            captured.append(
                (
                    str(ref),
                    value,
                    tuple(config.allowed_hosts),
                    config.header_name,
                    config.header_prefix,
                )
            )
            super().register(ref, value, config)

    router = ModelRouter(
        ModelConfig(
            remote_enabled=True,
            planner_provider_preset="openai_default",
            monitor_provider_preset="openai_default",
            planner_api_key="shared-key",
            monitor_api_key="shared-key",
            embeddings_remote_enabled=False,
        )
    )
    store = _CapturingCredentialStore()
    _register_route_credentials(credential_store=store, router=router)

    assert len(captured) == 1
    assert captured[0][1] == "shared-key"
    assert captured[0][2] == ("api.openai.com",)
    assert captured[0][3] == "Authorization"
    assert captured[0][4] == "Bearer "


def test_s0_register_route_credentials_skips_local_only_routes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SHISA_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("SHISAD_MODEL_API_KEY", raising=False)

    captured: list[str] = []

    class _CapturingCredentialStore(InMemoryCredentialStore):
        def register(self, ref, value, config):  # type: ignore[no-untyped-def]
            _ = (ref, value, config)
            captured.append("registered")
            super().register(ref, value, config)

    router = ModelRouter(
        ModelConfig(
            planner_provider_preset="openai_default",
            planner_api_key="planner-key",
            planner_remote_enabled=False,
            monitor_remote_enabled=False,
            embeddings_remote_enabled=False,
        )
    )
    store = _CapturingCredentialStore()
    _register_route_credentials(credential_store=store, router=router)

    assert captured == []


def test_s0_key_gated_acceptance_reports_env_eligibility_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "openai-key")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("SHISA_API_KEY", raising=False)

    matrix = _key_gated_acceptance_matrix()

    assert matrix["openai"]["status"] == "eligible (key env present)"
    assert matrix["openai"]["evidence"] == "env_presence_only"
    assert matrix["openai"]["scope"] == "route_configurable"
    assert matrix["openrouter"]["status"] == "N/A (key missing)"
    assert matrix["shisa_default"]["scope"] == "planner_only"
    assert "planner route only" in matrix["shisa_default"]["note"]


@pytest.mark.asyncio
async def test_daemon_services_matrix_missing_config_raises(tmp_path) -> None:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        matrix_enabled=True,
    )
    with pytest.raises(ValueError, match="Matrix channel is enabled but missing required config"):
        await DaemonServices.build(config)


@pytest.mark.asyncio
async def test_daemon_services_discord_missing_config_raises(tmp_path) -> None:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        discord_enabled=True,
    )
    with pytest.raises(ValueError, match="Discord channel is enabled but missing required config"):
        await DaemonServices.build(config)


@pytest.mark.asyncio
async def test_daemon_services_telegram_missing_config_raises(tmp_path) -> None:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        telegram_enabled=True,
    )
    with pytest.raises(ValueError, match="Telegram channel is enabled but missing required config"):
        await DaemonServices.build(config)


@pytest.mark.asyncio
async def test_daemon_services_slack_missing_config_raises(tmp_path) -> None:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        slack_enabled=True,
    )
    with pytest.raises(ValueError, match="Slack channel is enabled but missing required config"):
        await DaemonServices.build(config)


@pytest.mark.asyncio
async def test_daemon_services_build_rolls_back_connected_matrix_on_failure(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    disconnected = False

    class _MatrixStub:
        async def disconnect(self) -> None:
            nonlocal disconnected
            disconnected = True

    async def _fake_build_matrix_channel(config: DaemonConfig):  # type: ignore[no-untyped-def]
        _ = config
        return _MatrixStub()

    class _ExplodingCredentialStore:
        def __init__(self) -> None:
            raise RuntimeError("credential store exploded")

    monkeypatch.setattr(
        "shisad.daemon.services._build_matrix_channel",
        _fake_build_matrix_channel,
    )
    monkeypatch.setattr(
        "shisad.daemon.services.InMemoryCredentialStore",
        _ExplodingCredentialStore,
    )
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    with pytest.raises(RuntimeError, match="credential store exploded"):
        await DaemonServices.build(config)
    assert disconnected is True


@pytest.mark.asyncio
async def test_daemon_services_build_rolls_back_connected_matrix_on_unexpected_failure(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    disconnected = False

    class _MatrixStub:
        async def disconnect(self) -> None:
            nonlocal disconnected
            disconnected = True

    async def _fake_build_matrix_channel(config: DaemonConfig):  # type: ignore[no-untyped-def]
        _ = config
        return _MatrixStub()

    class _ExplodingCredentialStore:
        def __init__(self) -> None:
            raise KeyError("credential store exploded")

    monkeypatch.setattr(
        "shisad.daemon.services._build_matrix_channel",
        _fake_build_matrix_channel,
    )
    monkeypatch.setattr(
        "shisad.daemon.services.InMemoryCredentialStore",
        _ExplodingCredentialStore,
    )
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    with pytest.raises(KeyError, match="credential store exploded"):
        await DaemonServices.build(config)
    assert disconnected is True


@pytest.mark.asyncio
async def test_daemon_services_build_rolls_back_when_container_construction_fails(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    disconnected = False

    class _MatrixStub:
        async def disconnect(self) -> None:
            nonlocal disconnected
            disconnected = True

    async def _fake_build_matrix_channel(config: DaemonConfig):  # type: ignore[no-untyped-def]
        _ = config
        return _MatrixStub()

    class _ExplodingServices(DaemonServices):
        def __init__(self, *args: object, **kwargs: object) -> None:
            _ = args, kwargs
            raise RuntimeError("services construction exploded")

    monkeypatch.setattr(
        "shisad.daemon.services._build_matrix_channel",
        _fake_build_matrix_channel,
    )
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    with pytest.raises(RuntimeError, match="services construction exploded"):
        await _ExplodingServices.build(config)
    assert disconnected is True


@pytest.mark.asyncio
async def test_daemon_services_shutdown_continues_after_disconnect_error() -> None:
    calls: list[str] = []

    class _EmbeddingsAdapterStub:
        def close(self, *, wait: bool = True) -> None:
            calls.append(f"embed:{wait}")

    class _MatrixStub:
        async def disconnect(self) -> None:
            calls.append("matrix")
            raise RuntimeError("disconnect failed")

    class _ServerStub:
        async def stop(self) -> None:
            calls.append("server")

    # HDL-M1: construct a minimal DaemonServices via object.__new__ so this
    # test can pin the shutdown ordering (embeddings → matrix → server) and
    # the continue-past-disconnect-error invariant without standing up the
    # full services container. If DaemonServices.shutdown starts touching a
    # new attribute this test will raise AttributeError inside the call below
    # — that is the intended drift signal. A deeper cleanup would split
    # shutdown logic into a pure function; tracked as a follow-up.
    services = object.__new__(DaemonServices)
    services.embeddings_adapter = _EmbeddingsAdapterStub()  # type: ignore[assignment]
    services.matrix_channel = _MatrixStub()  # type: ignore[assignment]
    services.server = _ServerStub()  # type: ignore[assignment]

    await DaemonServices.shutdown(services)
    assert calls[0] == "embed:True"
    assert "matrix" in calls
    assert calls[-1] == "server"


def test_m3_normalize_tool_destination_preserves_scheme_and_port() -> None:
    assert _normalize_tool_destination("https://search.example") == "https://search.example:443"
    assert (
        _normalize_tool_destination("http://search.example:8080/api?q=1")
        == "http://search.example:8080"
    )
    assert _normalize_tool_destination("search.example") == "search.example"


def test_m6_normalize_tool_destination_rejects_invalid_port() -> None:
    assert _normalize_tool_destination("https://search.example:99999") == ""


def test_evidence_kms_bearer_over_non_loopback_http_logs_warning(
    tmp_path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        evidence_kms_url="http://10.0.0.5:8080/artifacts",
        evidence_kms_bearer_token="secret",
    )

    with caplog.at_level("WARNING"):
        _warn_on_evidence_kms_endpoint_config(config)

    assert "without TLS protection" in caplog.text


def test_evidence_kms_invalid_url_logs_warning(
    tmp_path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        evidence_kms_url="not-a-url",
    )

    with caplog.at_level("WARNING"):
        _warn_on_evidence_kms_endpoint_config(config)

    assert "may be misconfigured" in caplog.text


def test_m3_tool_registry_omits_realitycheck_tools_when_surface_disabled() -> None:
    registry, _alarm = _build_tool_registry(
        EventBus(),
        realitycheck_surface_enabled=False,
    )
    names = {str(item.name) for item in registry.list_tools()}
    assert "realitycheck.search" not in names
    assert "realitycheck.read" not in names


def test_s9_tool_registry_uses_dotted_canonical_runtime_ids_only() -> None:
    registry, _alarm = _build_tool_registry(
        EventBus(),
        realitycheck_surface_enabled=False,
    )
    names = {str(item.name) for item in registry.list_tools()}
    assert {"shell.exec", "http.request", "web.search", "web.fetch"} <= names
    assert "shell_exec" not in names
    assert "http_request" not in names
    assert "web_search" not in names
    assert "web_fetch" not in names


def test_m3_tool_registry_registers_realitycheck_tools_with_endpoint_caps() -> None:
    registry, _alarm = _build_tool_registry(
        EventBus(),
        realitycheck_surface_enabled=True,
        realitycheck_endpoint_enabled=True,
        realitycheck_endpoint_host="realitycheck.example",
    )
    search_tool = registry.get_tool(ToolName("realitycheck.search"))
    read_tool = registry.get_tool(ToolName("realitycheck.read"))
    assert search_tool is not None
    assert read_tool is not None
    assert set(search_tool.capabilities_required) == {Capability.FILE_READ, Capability.HTTP_REQUEST}
    assert search_tool.destinations == ["realitycheck.example"]
    assert set(read_tool.capabilities_required) == {Capability.FILE_READ}


def test_m6_tool_registry_registers_browser_scope_destinations() -> None:
    registry, _alarm = _build_tool_registry(
        EventBus(),
        browser_surface_enabled=True,
        browser_destinations=["localhost", "127.0.0.1"],
    )
    navigate_tool = registry.get_tool(ToolName("browser.navigate"))
    click_tool = registry.get_tool(ToolName("browser.click"))
    assert navigate_tool is not None
    assert click_tool is not None
    assert navigate_tool.destinations == ["localhost", "127.0.0.1"]
    assert click_tool.destinations == ["localhost", "127.0.0.1"]
    assert any(param.name == "destination" for param in click_tool.parameters)


@pytest.mark.parametrize(
    ("browser_allowed_domains", "web_allowed_domains"),
    [
        (["*.browser.example"], []),
        ([], ["*.browser.example"]),
    ],
)
def test_m6_daemon_config_rejects_wildcard_browser_scope_under_hardened_isolation(
    tmp_path,
    browser_allowed_domains: list[str],
    web_allowed_domains: list[str],
) -> None:
    with pytest.raises(ValidationError, match="wildcard browser scope"):
        DaemonConfig(
            data_dir=tmp_path / "data",
            socket_path=tmp_path / "control.sock",
            policy_path=tmp_path / "policy.yaml",
            browser_enabled=True,
            browser_require_hardened_isolation=True,
            browser_allowed_domains=browser_allowed_domains,
            web_allowed_domains=web_allowed_domains,
        )


def test_daemon_config_canonicalizes_default_port_approval_origin(tmp_path) -> None:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        approval_origin="https://approve.example.com:443",
    )

    assert config.approval_origin == "https://approve.example.com"
    assert config.approval_rp_id == "approve.example.com"
    assert config.approval_bind_host == "127.0.0.1"


def test_daemon_config_preserves_ipv6_loopback_approval_origin(tmp_path) -> None:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        approval_origin="http://[::1]:8787",
    )

    assert config.approval_origin == "http://[::1]:8787"
    assert config.approval_rp_id == "::1"
    assert config.approval_bind_host == "::1"
    assert config.approval_bind_port == 8787


@pytest.mark.asyncio
async def test_m6_daemon_services_browser_registry_falls_back_to_web_allowlist(
    tmp_path,
) -> None:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        browser_enabled=True,
        web_allowed_domains=["localhost"],
        browser_allowed_domains=[],
    )
    services = await DaemonServices.build(config)
    try:
        navigate_tool = services.registry.get_tool(ToolName("browser.navigate"))
        assert navigate_tool is not None
        assert navigate_tool.destinations == ["localhost"]
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_m3_daemon_services_fail_closed_when_realitycheck_disabled(tmp_path) -> None:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        realitycheck_enabled=False,
    )
    services = await DaemonServices.build(config)
    try:
        assert services.realitycheck_status["status"] == "disabled"
        assert services.registry.get_tool(ToolName("realitycheck.search")) is None
        assert services.registry.get_tool(ToolName("realitycheck.read")) is None
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_m3_daemon_services_enable_realitycheck_surface_when_config_valid(tmp_path) -> None:
    repo_root = tmp_path / "realitycheck"
    data_root = tmp_path / "realitycheck-data"
    repo_root.mkdir(parents=True)
    data_root.mkdir(parents=True)

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        realitycheck_enabled=True,
        realitycheck_repo_root=repo_root,
        realitycheck_data_roots=[data_root],
        realitycheck_endpoint_enabled=False,
    )
    services = await DaemonServices.build(config)
    try:
        assert services.realitycheck_status["status"] == "ok"
        assert services.registry.get_tool(ToolName("realitycheck.search")) is not None
        assert services.registry.get_tool(ToolName("realitycheck.read")) is not None
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_m3_daemon_services_fail_closed_on_invalid_endpoint_port(tmp_path) -> None:
    repo_root = tmp_path / "realitycheck"
    data_root = tmp_path / "realitycheck-data"
    repo_root.mkdir(parents=True)
    data_root.mkdir(parents=True)

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        realitycheck_enabled=True,
        realitycheck_repo_root=repo_root,
        realitycheck_data_roots=[data_root],
        realitycheck_endpoint_enabled=True,
        realitycheck_endpoint_url="https://allowed.example:abc/search",
        realitycheck_allowed_domains=["allowed.example"],
    )
    services = await DaemonServices.build(config)
    try:
        assert services.realitycheck_status["status"] == "misconfigured"
        assert "endpoint_port_invalid" in services.realitycheck_status["problems"]
        assert services.registry.get_tool(ToolName("realitycheck.search")) is None
        assert services.registry.get_tool(ToolName("realitycheck.read")) is None
    finally:
        await services.shutdown()


def test_m1_pf11_model_route_pinning_rejects_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_REMOTE_ENABLED", "true")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_MODEL", "monitor-live")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_MODEL", "planner-live")
    monkeypatch.setenv("SHISAD_MODEL_ENFORCE_SECURITY_ROUTE_PINNING", "true")
    monkeypatch.setenv("SHISAD_MODEL_PINNED_MONITOR_MODEL_ID", "monitor-pinned")
    monkeypatch.setenv("SHISAD_MODEL_PINNED_PLANNER_MODEL_ID", "planner-live")
    model = ModelConfig()
    router = ModelRouter(model)
    with pytest.raises(ValueError, match="Security monitor route model id mismatch"):
        _validate_security_route_pins(model, router)


def test_m1_pf11_model_route_pinning_disabled_allows_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_REMOTE_ENABLED", "true")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_MODEL", "monitor-live")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_MODEL", "planner-live")
    monkeypatch.setenv("SHISAD_MODEL_ENFORCE_SECURITY_ROUTE_PINNING", "false")
    monkeypatch.setenv("SHISAD_MODEL_PINNED_MONITOR_MODEL_ID", "monitor-pinned")
    monkeypatch.setenv("SHISAD_MODEL_PINNED_PLANNER_MODEL_ID", "planner-pinned")
    model = ModelConfig()
    router = ModelRouter(model)
    _validate_security_route_pins(model, router)


def test_m1_pf11_model_route_pinning_default_allows_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SHISAD_MODEL_ENFORCE_SECURITY_ROUTE_PINNING", raising=False)
    monkeypatch.setenv("SHISAD_MODEL_PINNED_MONITOR_MODEL_ID", "monitor-pinned")
    monkeypatch.setenv("SHISAD_MODEL_PINNED_PLANNER_MODEL_ID", "planner-pinned")
    model = ModelConfig()
    router = ModelRouter(model)
    _validate_security_route_pins(model, router)


def test_u4_provider_diagnostics_marks_custom_preset_label_for_global_base_url_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = ModelConfig(base_url="https://proxy.example.com/v1")

    diagnostics = _build_provider_diagnostics(ModelRouter(config))

    planner_route = diagnostics["routes"]["planner"]
    assert planner_route["preset"] == "shisa_default"
    assert planner_route["preset_label"] == "custom"


def test_u4_log_provider_route_summary_marks_route_override_as_overridden(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = ModelConfig(
        planner_provider_preset="openai_default",
        planner_base_url="https://proxy.example.com/v1",
    )

    with caplog.at_level("INFO"):
        _log_provider_route_summary(ModelRouter(config))

    assert "component=planner preset=openai_default (overridden)" in caplog.text


def test_u4_warn_on_provider_route_gaps_flags_missing_embeddings_route(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _clear_remote_provider_env(monkeypatch)

    with caplog.at_level("WARNING"):
        _warn_on_provider_route_gaps(ModelRouter(ModelConfig()))

    assert (
        "Embeddings route not configured - semantic retrieval will degrade to "
        "deterministic local fallback embeddings."
    ) in caplog.text


def test_u4_warn_on_provider_route_gaps_skips_warning_when_embeddings_route_enabled(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_PROVIDER_PRESET", "vllm_local_default")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "http://127.0.0.1:8000/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_REMOTE_ENABLED", "true")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_AUTH_MODE", "none")

    with caplog.at_level("WARNING"):
        _warn_on_provider_route_gaps(ModelRouter(ModelConfig()))

    assert "Embeddings route not configured" not in caplog.text
