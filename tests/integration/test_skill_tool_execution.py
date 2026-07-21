"""Dynamic-skill retry posture across install, reload, and self-modification."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
import yaml

from shisad.core.api.schema import SessionCreateParams
from shisad.core.approval import legacy_software_confirmation_requirement
from shisad.core.config import DaemonConfig
from shisad.core.request_context import RequestContext
from shisad.core.tools.schema import ToolRetryClass
from shisad.core.types import SessionId, ToolName
from shisad.daemon.control_handlers import DaemonControlHandlers
from shisad.daemon.services import DaemonServices
from shisad.executors.sandbox import DegradedModePolicy, SandboxResult
from shisad.executors.sandbox.models import ContainmentProfile


def _configure_model_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")


def _config(
    tmp_path: Path,
    *,
    containment_profile: str = "supported",
) -> DaemonConfig:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        'version: "1"\ndefault_require_confirmation: false\n'
        f"sandbox:\n  containment_profile: {containment_profile}\n",
        encoding="utf-8",
    )
    return DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        assistant_fs_roots=[tmp_path],
        log_level="INFO",
    )


def _write_skill(path: Path, *, description: str) -> None:
    path.mkdir(parents=True, exist_ok=True)
    manifest = {
        "manifest_version": "1.0.0",
        "name": "fixture",
        "version": "1.0.0",
        "author": "fixture-author",
        "signature": "",
        "source_repo": "https://example.test/fixture",
        "description": "dynamic retry fixture",
        "capabilities": {
            "network": [],
            "filesystem": [],
            "shell": [],
            "environment": [],
        },
        "dependencies": [],
        "tools": [
            {
                "name": "dynamic-effect",
                "description": description,
                "parameters": [{"name": "value", "type": "string", "required": True}],
                "destinations": [],
                "require_confirmation": True,
            }
        ],
    }
    (path / "skill.manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False),
        encoding="utf-8",
    )
    (path / "SKILL.md").write_text("Dynamic fixture skill.\n", encoding="utf-8")


def _write_command_skill(path: Path, *, shell_command: str = "echo") -> None:
    path.mkdir(parents=True, exist_ok=True)
    manifest = {
        "manifest_version": "1.0.0",
        "name": "command-fixture",
        "version": "1.0.0",
        "author": "fixture-author",
        "signature": "",
        "source_repo": "https://example.test/command-fixture",
        "description": "dynamic command fixture",
        "capabilities": {
            "network": [],
            "filesystem": [],
            "shell": [{"command": shell_command, "reason": "fixture output"}],
            "environment": [],
        },
        "dependencies": [],
        "tools": [
            {
                "name": "run",
                "description": "Run the declared fixture command.",
                "parameters": [
                    {
                        "name": "command",
                        "type": "array",
                        "items_type": "string",
                        "required": True,
                    }
                ],
                "destinations": [],
                "require_confirmation": False,
            }
        ],
    }
    (path / "skill.manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False),
        encoding="utf-8",
    )
    (path / "SKILL.md").write_text("Command fixture skill.\n", encoding="utf-8")


@pytest.mark.parametrize(
    "persist_attempt_before_effect",
    [False, True],
    ids=["planner", "persisted-confirmation"],
)
@pytest.mark.parametrize(
    ("caller_skill_name", "expected_error"),
    [("", "skill_bundle_drift"), ("forged-skill", "skill_identity_mismatch")],
    ids=["omitted-identity", "forged-identity"],
)
@pytest.mark.asyncio
async def test_f4b_registered_skill_identity_authorizes_at_effect_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    persist_attempt_before_effect: bool,
    caller_skill_name: str,
    expected_error: str,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    skill_path = tmp_path / "command-skill"
    _write_command_skill(skill_path)
    tool_name = ToolName("skill.command-fixture.run")

    services = await DaemonServices.build(config)
    try:
        services.skill_manager.activate_bundle(skill_path)
        registered = services.registry.get_tool(tool_name)
        assert registered is not None
        assert registered.registration_source == "skill"
        assert registered.registration_source_id == "command-fixture"
        assert registered.sandbox_type == "nsjail"
        handlers = DaemonControlHandlers(services=services)
        absent_source = registered.model_copy(
            update={"registration_source": "local", "registration_source_id": ""}
        )
        forged_source = registered.model_copy(update={"registration_source_id": "other-skill"})
        noncanonical_upstream = registered.model_copy(update={"upstream_tool_name": "RUN"})
        assert handlers._impl._registered_skill_identity(tool=absent_source, arguments={}) == (
            "",
            "skill_source_metadata_invalid",
        )
        assert handlers._impl._registered_skill_identity(tool=forged_source, arguments={}) == (
            "",
            "skill_source_metadata_invalid",
        )
        assert handlers._impl._registered_skill_identity(
            tool=noncanonical_upstream,
            arguments={},
        ) == ("", "skill_source_metadata_invalid")
        assert handlers._impl._registered_skill_identity(
            tool=registered,
            arguments={"skill_name": "COMMAND-FIXTURE"},
        ) == ("command-fixture", "")
        created = await handlers.handle_session_create(
            SessionCreateParams(channel="cli", user_id="alice", workspace_id="ws1"),
            RequestContext(),
        )
        session_id = SessionId(created.session_id)
        session = services.session_manager.get(session_id)
        assert session is not None

        (skill_path / "SKILL.md").write_text("drifted after approval\n", encoding="utf-8")
        arguments: dict[str, Any] = {"command": ["echo", "must-not-run"]}
        if caller_skill_name:
            arguments["skill_name"] = caller_skill_name
        result = await handlers._impl._execute_approved_action(
            sid=session_id,
            user_id=session.user_id,
            tool_name=tool_name,
            arguments=arguments,
            capabilities=set(session.capabilities),
            approval_actor="planner",
            persist_attempt_before_effect=persist_attempt_before_effect,
        )

        assert result.success is False
        assert result.error == expected_error
    finally:
        await services.shutdown()


@pytest.mark.parametrize(
    "command",
    [
        ["echo", "evil.example"],
        ["echo", "--url=https://evil.example/path"],
        ["echo", "endpoint=https://evil.example/path"],
    ],
    ids=["bare-domain", "url-flag", "url-assignment"],
)
@pytest.mark.asyncio
async def test_f4b_skill_authorization_uses_sandbox_network_target_surface(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: list[str],
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    skill_path = tmp_path / "network-target-skill"
    _write_command_skill(skill_path)
    services = await DaemonServices.build(config)
    try:
        services.skill_manager.activate_bundle(skill_path)
        handlers = DaemonControlHandlers(services=services)
        created = await handlers.handle_session_create(
            SessionCreateParams(channel="cli", user_id="alice", workspace_id="ws1"),
            RequestContext(),
        )
        session_id = SessionId(created.session_id)
        session = services.session_manager.get(session_id)
        assert session is not None

        result = await handlers._impl._execute_approved_action(
            sid=session_id,
            user_id=session.user_id,
            tool_name=ToolName("skill.command-fixture.run"),
            arguments={"command": command},
            capabilities=set(session.capabilities),
            approval_actor="planner",
        )

        assert result.success is False
        assert result.error == "undeclared_capability:undeclared_network:evil.example"
        assert result.sandbox_result is None
    finally:
        await services.shutdown()


@pytest.mark.parametrize("implicit_surface", ["absolute-argv", "cwd"])
@pytest.mark.asyncio
async def test_u42r_skill_authorization_covers_implicit_sandbox_filesystem_surface(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    implicit_surface: str,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    skill_path = tmp_path / "filesystem-target-skill"
    _write_command_skill(skill_path, shell_command="cat")
    secret_dir = tmp_path / "outside-skill"
    secret_dir.mkdir()
    secret = secret_dir / "secret"
    secret.write_text("must-not-read", encoding="utf-8")
    services = await DaemonServices.build(config)
    try:
        services.skill_manager.activate_bundle(skill_path)
        handlers = DaemonControlHandlers(services=services)
        created = await handlers.handle_session_create(
            SessionCreateParams(channel="cli", user_id="alice", workspace_id="ws1"),
            RequestContext(),
        )
        session_id = SessionId(created.session_id)
        session = services.session_manager.get(session_id)
        assert session is not None
        arguments: dict[str, Any]
        expected_path: Path
        if implicit_surface == "absolute-argv":
            arguments = {"command": ["cat", str(secret)]}
            expected_path = secret_dir
        else:
            arguments = {"command": ["cat", "secret"], "cwd": str(secret_dir)}
            expected_path = secret_dir

        result = await handlers._impl._execute_approved_action(
            sid=session_id,
            user_id=session.user_id,
            tool_name=ToolName("skill.command-fixture.run"),
            arguments=arguments,
            capabilities=set(session.capabilities),
            approval_actor="planner",
        )

        assert result.success is False
        assert result.error == (
            "undeclared_capability:undeclared_filesystem:" + str(expected_path.resolve())
        )
        assert result.sandbox_result is None
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_u42r_persisted_expert_policy_cannot_outlive_current_supported_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_model_env(monkeypatch)
    services = await DaemonServices.build(
        _config(tmp_path, containment_profile="expert_host_fallback")
    )
    try:
        handlers = DaemonControlHandlers(services=services)
        created = await handlers.handle_session_create(
            SessionCreateParams(channel="cli", user_id="alice", workspace_id="ws1"),
            RequestContext(),
        )
        session_id = SessionId(created.session_id)
        session = services.session_manager.get(session_id)
        assert session is not None
        tool_name = ToolName("shell.exec")
        tool = services.registry.get_tool(tool_name)
        assert tool is not None
        persisted = handlers._impl._build_merged_policy(
            tool_name=tool_name,
            arguments={"command": ["echo", "ok"]},
            tool_definition=tool,
        )
        assert persisted.containment_profile == ContainmentProfile.EXPERT_HOST_FALLBACK
        services.policy_loader.policy.sandbox.containment_profile = "supported"
        captured = []

        async def _capture(config, *, session=None):  # type: ignore[no-untyped-def]
            _ = session
            captured.append(config)
            return SandboxResult(allowed=True, exit_code=0, reason="allowed")

        monkeypatch.setattr(services.sandbox, "execute_async", _capture)

        result = await handlers._impl._execute_via_sandbox(
            sid=session_id,
            session=session,
            tool=tool,
            arguments={"command": ["echo", "ok"]},
            origin=handlers._impl._origin_for(session=session, actor="human_confirmation"),
            approved_by_pep=True,
            merged_policy=persisted,
        )

        assert result.allowed is True
        assert len(captured) == 1
        assert captured[0].containment_profile == ContainmentProfile.SUPPORTED
        assert captured[0].degraded_mode == DegradedModePolicy.FAIL_CLOSED
        assert captured[0].security_critical is True
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_u42r_supported_doctor_marks_missing_connect_path_misconfigured(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_model_env(monkeypatch)
    services = await DaemonServices.build(_config(tmp_path))
    try:
        sandbox_policy = services.policy_loader.policy.sandbox
        monkeypatch.setattr(
            services.sandbox,
            "connect_path_status",
            lambda: {
                "method": "none",
                "available": False,
                "engaged": False,
                "cap_net_admin_available": False,
            },
        )
        monkeypatch.setattr(
            services.sandbox,
            "backend_status",
            lambda: {
                sandbox_policy.default_backend: {
                    "available": True,
                    "network_available": True,
                },
                sandbox_policy.network_backend: {
                    "available": True,
                    "network_available": True,
                },
            },
        )

        status = DaemonControlHandlers(services=services)._impl._doctor_sandbox_status()

        assert status["status"] == "misconfigured"
        assert status["problems"] == ["connect_path_unavailable"]
    finally:
        await services.shutdown()


@pytest.mark.parametrize(
    "self_modified",
    [False, True],
    ids=["retry-reloaded", "retry-self-modified"],
)
@pytest.mark.asyncio
async def test_dynamic_skill_operation_defaults_unknown_and_never_auto_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    self_modified: bool,
) -> None:
    _configure_model_env(monkeypatch)
    config = _config(tmp_path)
    skill_path = tmp_path / "dynamic-skill"
    _write_skill(
        skill_path,
        description="Untrusted prose claims this operation is perfectly idempotent.",
    )
    tool_name = ToolName("skill.fixture.dynamic-effect")

    services = await DaemonServices.build(config)
    try:
        installed = services.skill_manager.activate_bundle(skill_path)
        assert installed is not None
        registered = services.registry.get_tool(tool_name)
        assert registered is not None
        assert registered.registration_source == "skill"
        assert registered.registration_source_id == "fixture"
        assert registered.sandbox_type == "nsjail"
        assert registered.upstream_tool_name == "dynamic-effect"
        assert registered.retry_class == ToolRetryClass.UNKNOWN

        handlers = DaemonControlHandlers(services=services)
        created = await handlers.handle_session_create(
            SessionCreateParams(channel="cli", user_id="alice", workspace_id="ws1"),
            RequestContext(),
        )
        session_id = SessionId(created.session_id)
        session = services.session_manager.get(session_id)
        assert session is not None
        pending = handlers._impl._queue_pending_action(
            session_id=session_id,
            user_id=session.user_id,
            workspace_id=session.workspace_id,
            tool_name=tool_name,
            arguments={"value": "uncertain"},
            reason="dynamic-skill-recovery-test",
            capabilities=set(),
            confirmation_requirement=legacy_software_confirmation_requirement(),
            origin_turn_id="turn-dynamic-skill-recovery",
        )
        assert pending.retry_descriptor is not None
        assert pending.retry_descriptor.retry_class == ToolRetryClass.UNKNOWN
        assert pending.retry_descriptor.registration_source == "skill"
        pending.execution_attempt_id = "attempt-dynamic-skill-uncertain"
        pending.result_id = "result-dynamic-skill-uncertain"
        pending.status = "executing"
        pending.status_reason = "confirmation_execution_started"
        handlers._impl._persist_pending_actions()
    finally:
        await services.shutdown()

    if self_modified:
        _write_skill(
            skill_path,
            description="Self-modified prose now claims an even stronger retry guarantee.",
        )

    unexpected_calls = 0

    def _malicious_adapter(
        _arguments: Mapping[str, object],
        _stable_idempotency_key: str,
    ) -> dict[str, object]:
        nonlocal unexpected_calls
        unexpected_calls += 1
        return {"ok": True}

    restarted = await DaemonServices.build(config)
    try:
        if self_modified:
            assert restarted.registry.get_tool(tool_name) is None
        else:
            restored_tool = restarted.registry.get_tool(tool_name)
            assert restored_tool is not None
            assert restored_tool.retry_class == ToolRetryClass.UNKNOWN
        restarted.idempotent_recovery_adapters[str(tool_name)] = _malicious_adapter
        restarted_handlers = DaemonControlHandlers(services=restarted)
        recovered = restarted_handlers._impl._pending_actions[pending.confirmation_id]
        assert recovered.status == "outcome_unknown"
        assert recovered.status_reason == "uncertain_effect_requires_fresh_approval"
        assert recovered.decision_nonce == ""
        assert recovered.retry_generation == 0
        assert unexpected_calls == 0
    finally:
        await restarted.shutdown()
