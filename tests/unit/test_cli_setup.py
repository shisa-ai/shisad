"""O2B provider and policy setup contracts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from shisad.channels.setup import ChannelSetupOutcome
from shisad.cli import setup as cli_setup
from shisad.cli.main import cli
from shisad.core.providers.capabilities import AuthMode, ProviderPreset
from shisad.core.providers.routing import ModelComponent
from shisad.core.readiness import failed_probe_readiness, verified_probe_readiness
from shisad.core.types import Capability
from shisad.security.credential_refs import CredentialReferenceError


class _CredentialStore:
    def __init__(self, value: str = "setup-secret") -> None:
        self.value = value
        self.resolved: list[str] = []

    def resolve(self, name: str) -> str:
        self.resolved.append(name)
        return self.value


def test_o2b_explicit_preset_ignores_unrelated_ambient_provider_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ambient_secret = "ambient-must-not-select-any-route"
    for variable in (
        "SHISA_API_KEY",
        "OPENAI_API_KEY",
        "OPENROUTER_API_KEY",
        "GEMINI_API_KEY",
        "ANTHROPIC_API_KEY",
    ):
        monkeypatch.setenv(variable, ambient_secret)
    selection = cli_setup.ProviderSetupSelection(
        preset=ProviderPreset.SHISA_DEFAULT.value,
        credential_ref="model.primary",
    )

    model_config, fragment = cli_setup.build_provider_setup_config(selection)

    assert model_config.planner_provider_preset is ProviderPreset.SHISA_DEFAULT
    assert model_config.planner_api_key_ref == "model.primary"
    assert fragment == {
        "planner_provider_preset": "shisa_default",
        "planner_model_id": "shisa-ai/shisa-v2.1-unphi4-14b",
        "planner_api_key_ref": "model.primary",
        "planner_remote_enabled": True,
    }
    assert ambient_secret not in json.dumps(fragment)
    router = cli_setup.ModelRouter(model_config)
    planner = router.route_for(ModelComponent.PLANNER)
    assert planner.api_key is None
    assert planner.api_key_source == "route:planner_api_key_ref_unavailable"
    for component in (ModelComponent.EMBEDDINGS, ModelComponent.MONITOR):
        route = router.route_for(component)
        assert route.provider_preset is ProviderPreset.VLLM_LOCAL_DEFAULT
        assert route.remote_enabled is False
        assert route.api_key is None
        assert route.api_key_source == "missing"


@pytest.mark.parametrize(
    "preset",
    [preset for preset in ProviderPreset if preset is not ProviderPreset.VLLM_LOCAL_DEFAULT],
)
def test_o2b_authenticated_maintained_preset_requires_explicit_reference(
    preset: ProviderPreset,
) -> None:
    with pytest.raises(ValueError, match="credential reference is required"):
        cli_setup.ProviderSetupSelection(preset=preset.value)


@pytest.mark.parametrize("preset", list(ProviderPreset))
def test_o2b_every_maintained_provider_preset_resolves_through_router(
    preset: ProviderPreset,
) -> None:
    selection = cli_setup.ProviderSetupSelection(
        preset=preset.value,
        credential_ref=("" if preset is ProviderPreset.VLLM_LOCAL_DEFAULT else "model.primary"),
    )

    model_config, fragment = cli_setup.build_provider_setup_config(selection)

    assert model_config.planner_provider_preset is preset
    assert fragment["planner_provider_preset"] == preset.value
    assert fragment["planner_model_id"]
    assert "planner_base_url" not in fragment


def test_o2b_valid_custom_provider_emits_explicit_safe_fragment() -> None:
    selection = cli_setup.ProviderSetupSelection(
        preset="custom",
        model_id="model-1",
        base_url="https://models.example/v1",
        auth_mode="bearer",
        credential_ref="model.primary",
    )

    _config, fragment = cli_setup.build_provider_setup_config(selection)

    assert fragment == {
        "planner_provider_preset": "shisa_default",
        "planner_model_id": "model-1",
        "planner_remote_enabled": True,
        "planner_base_url": "https://models.example/v1",
        "planner_auth_mode": "bearer",
        "planner_api_key_ref": "model.primary",
    }


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"preset": "custom", "base_url": "https://models.example/v1"}, "model"),
        ({"preset": "custom", "model_id": "model-1"}, "base URL"),
        (
            {
                "preset": "custom",
                "model_id": "model-1",
                "base_url": "https://models.example/v1",
                "auth_mode": "bearer",
            },
            "credential reference",
        ),
        (
            {
                "preset": "custom",
                "model_id": "model-1",
                "base_url": "https://models.example/v1",
                "auth_mode": "none",
                "credential_ref": "model.primary",
            },
            "does not accept",
        ),
        (
            {
                "preset": "custom",
                "model_id": "bad\nmodel",
                "base_url": "https://models.example/v1",
                "auth_mode": "none",
            },
            "terminal-safe",
        ),
        (
            {
                "preset": "custom",
                "model_id": "model-1",
                "base_url": "https://models.example/v1",
                "auth_mode": AuthMode.HEADER,
            },
            "authentication mode",
        ),
    ],
)
def test_o2b_custom_provider_requires_complete_bounded_explicit_input(
    kwargs: dict[str, str],
    match: str,
) -> None:
    with pytest.raises(ValueError, match=match):
        cli_setup.ProviderSetupSelection(**kwargs)


def test_o2b_custom_provider_uses_services_endpoint_validator() -> None:
    selection = cli_setup.ProviderSetupSelection(
        preset="custom",
        model_id="local-model",
        base_url="http://example.com/v1",
        auth_mode="none",
    )

    with pytest.raises(ValueError, match="Invalid planner model endpoint"):
        cli_setup.build_provider_setup_config(selection)


@pytest.mark.parametrize(
    ("base_url", "match"),
    [
        ("https://user:secret@models.example/v1", "cannot contain credentials"),
        ("https://user:sec%72et@models.example/v1", "base URL is malformed"),
        ("https://models.example/v1?api_key=secret", "cannot contain credentials"),
        ("https://models.example/v1#secret", "cannot contain credentials"),
    ],
)
def test_o2b_custom_provider_rejects_secret_bearing_endpoint_shapes(
    base_url: str,
    match: str,
) -> None:
    selection = cli_setup.ProviderSetupSelection(
        preset="custom",
        model_id="local-model",
        base_url=base_url,
        auth_mode="none",
    )

    with pytest.raises(ValueError, match=match) as exc:
        cli_setup.build_provider_setup_config(selection)

    assert base_url not in str(exc.value)


def test_o2b_malformed_custom_provider_url_never_echoes_embedded_secret() -> None:
    secret = "malformed-secret-must-not-echo"
    selection = cli_setup.ProviderSetupSelection(
        preset="custom",
        model_id="local-model",
        base_url=f"https://user:{secret}@[::1",
        auth_mode="none",
    )

    with pytest.raises(ValueError) as exc:
        cli_setup.build_provider_setup_config(selection)

    assert str(exc.value) == "custom provider base URL is malformed"
    assert secret not in str(exc.value)


def test_o2c_channel_cli_is_explicit_reference_only_and_json_redacted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "channel-secret-must-not-print"
    captured: list[cli_setup.ChannelSetupSelection] = []

    monkeypatch.setattr(
        cli_setup,
        "_channel_setup_context",
        lambda _ctx: (_CredentialStore(secret), cli_setup.DaemonConfig(data_dir=tmp_path)),
    )

    async def _evaluate(selection, **kwargs):
        captured.append(selection)
        return cli_setup.ChannelSetupResult(
            outcome=ChannelSetupOutcome.SKIPPED,
            channel=selection.channel,
            probe=cli_setup.ReadinessStatus(
                state=cli_setup.ReadinessState.CONFIGURED,
                configured=True,
                evidence="not_run",
                reason="probe_skipped",
                next_action="rerun without --skip-probe",
                source="explicit_setup_skip",
            ),
            identity_ready=True,
            identity_next_action="none",
            config_fragment={
                "discord_enabled": True,
                "discord_bot_token_ref": "channel.discord",
                "discord_trusted_users": ["123"],
            },
            retry_allowed=True,
            exit_code=0,
        )

    monkeypatch.setattr(cli_setup, "evaluate_channel_setup", _evaluate)

    result = CliRunner().invoke(
        cli,
        [
            "setup",
            "channel",
            "--channel",
            "discord",
            "--bot-token-ref",
            "channel.discord",
            "--trusted-user",
            "123",
            "--skip-probe",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert secret not in result.output
    payload = json.loads(result.output)
    assert payload["outcome"] == "skipped"
    assert payload["identity_ready"] is True
    assert payload["config_fragment"]["discord_bot_token_ref"] == "channel.discord"
    assert len(captured) == 1
    assert captured[0].run_test is False


def test_o2c_channel_cli_has_no_raw_token_or_arbitrary_message_option() -> None:
    result = CliRunner().invoke(cli, ["setup", "channel", "--help"])

    assert result.exit_code == 0
    assert "--bot-token-ref" in result.output
    assert "--access-token-ref" in result.output
    assert "--app-token-ref" in result.output
    assert "--token " not in result.output
    assert "--message" not in result.output


def test_o2c_missing_channel_uses_shared_json_error_without_loading_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli_setup,
        "_channel_setup_context",
        lambda _ctx: pytest.fail("invalid selection must fail before setup state loads"),
    )

    result = CliRunner().invoke(cli, ["setup", "channel", "--format", "json"])

    assert result.exit_code == 3
    payload = json.loads(result.output)
    assert payload["error_type"] == "setup"
    assert payload["exit_code"] == 3
    assert "channel" in payload["likely_cause"]


def test_o2c_channel_cli_threads_timeout_and_prints_recovery_posture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[float] = []
    monkeypatch.setattr(
        cli_setup,
        "_channel_setup_context",
        lambda _ctx: (_CredentialStore("unused"), cli_setup.DaemonConfig(data_dir=tmp_path)),
    )

    async def _evaluate(selection, *, timeout_seconds: float, **kwargs):
        _ = kwargs
        captured.append(timeout_seconds)
        return cli_setup.ChannelSetupResult(
            outcome=ChannelSetupOutcome.DEGRADED,
            channel=selection.channel,
            probe=cli_setup.ReadinessStatus(
                state=cli_setup.ReadinessState.DEGRADED,
                configured=True,
                evidence="live_test_delivery",
                reason="channel_test_outcome_unknown",
                next_action="inspect the explicit target before deciding whether to retry",
                source="channel_setup_delivery",
            ),
            identity_ready=True,
            identity_next_action="none",
            config_fragment={
                "discord_enabled": True,
                "discord_bot_token_ref": "channel.discord",
            },
            retry_allowed=False,
            exit_code=2,
        )

    monkeypatch.setattr(cli_setup, "evaluate_channel_setup", _evaluate)

    result = CliRunner().invoke(
        cli,
        [
            "setup",
            "channel",
            "--channel",
            "discord",
            "--bot-token-ref",
            "channel.discord",
            "--timeout",
            "1.25",
        ],
    )

    assert result.exit_code == 2
    assert captured == [1.25]
    assert "Next: inspect the explicit target" in result.output
    assert "Retry allowed: no" in result.output


async def test_o2b_provider_probe_resolves_once_and_discards_secret_and_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selection = cli_setup.ProviderSetupSelection(
        preset=ProviderPreset.OPENAI_DEFAULT.value,
        credential_ref="model.primary",
    )
    store = _CredentialStore("never-project-this-secret")
    calls: list[float] = []

    async def _verified(_provider, *, timeout_seconds: float):
        calls.append(timeout_seconds)
        return verified_probe_readiness()

    monkeypatch.setattr(cli_setup.RoutedOpenAIProvider, "probe_planner", _verified)

    result = await cli_setup.evaluate_provider_setup(
        selection,
        credential_store=store,
        timeout_seconds=1.25,
    )

    assert result.outcome is cli_setup.ProviderSetupOutcome.VERIFIED
    assert result.exit_code == 0
    assert result.retry_allowed is False
    assert store.resolved == ["model.primary"]
    assert calls == [1.25]
    assert result.config_fragment["planner_api_key_ref"] == "model.primary"
    assert "never-project-this-secret" not in result.model_dump_json()


async def test_o2b_provider_skip_performs_no_network_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selection = cli_setup.ProviderSetupSelection(
        preset=ProviderPreset.OPENAI_DEFAULT.value,
        credential_ref="model.primary",
    )
    store = _CredentialStore()

    async def _unexpected_probe(_provider, *, timeout_seconds: float):
        raise AssertionError(f"unexpected probe with timeout {timeout_seconds}")

    monkeypatch.setattr(cli_setup.RoutedOpenAIProvider, "probe_planner", _unexpected_probe)

    result = await cli_setup.evaluate_provider_setup(
        selection,
        credential_store=store,
        timeout_seconds=2.0,
        skip_probe=True,
    )

    assert result.outcome is cli_setup.ProviderSetupOutcome.SKIPPED
    assert result.exit_code == 0
    assert result.probe.verified is False
    assert result.probe.evidence == "not_run"
    assert store.resolved == ["model.primary"]


async def test_o2b_unavailable_reference_blocks_without_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selection = cli_setup.ProviderSetupSelection(
        preset=ProviderPreset.OPENAI_DEFAULT.value,
        credential_ref="model.primary",
    )

    class _UnavailableStore(_CredentialStore):
        def resolve(self, name: str) -> str:
            self.resolved.append(name)
            raise CredentialReferenceError("credential_value_unavailable")

    async def _unexpected_probe(_provider, *, timeout_seconds: float):
        raise AssertionError(f"unexpected probe with timeout {timeout_seconds}")

    monkeypatch.setattr(cli_setup.RoutedOpenAIProvider, "probe_planner", _unexpected_probe)
    store = _UnavailableStore()

    result = await cli_setup.evaluate_provider_setup(selection, credential_store=store)

    assert result.outcome is cli_setup.ProviderSetupOutcome.BLOCKED
    assert result.exit_code == 3
    assert result.probe.reason == "missing_api_key"
    assert result.retry_allowed is True
    assert store.resolved == ["model.primary"]


async def test_o2b_failed_probe_is_bounded_and_never_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selection = cli_setup.ProviderSetupSelection(
        preset=ProviderPreset.OPENAI_DEFAULT.value,
        credential_ref="model.primary",
    )
    calls = 0

    async def _failed(_provider, *, timeout_seconds: float):
        nonlocal calls
        calls += 1
        assert timeout_seconds == 3.0
        return failed_probe_readiness("Provider HTTP error 401: response-body-never-project-this")

    monkeypatch.setattr(cli_setup.RoutedOpenAIProvider, "probe_planner", _failed)

    result = await cli_setup.evaluate_provider_setup(
        selection,
        credential_store=_CredentialStore(),
    )

    assert calls == 1
    assert result.outcome is cli_setup.ProviderSetupOutcome.BLOCKED
    assert result.exit_code == 2
    assert result.retry_allowed is True
    assert result.probe.reason == "authentication_failed"
    assert "response-body-never-project-this" not in result.model_dump_json()


def test_o2b_maintained_policy_profiles_preserve_capabilities() -> None:
    recommended = cli_setup.generate_policy_profile(cli_setup.PolicyProfile.RECOMMENDED)
    strict = cli_setup.generate_policy_profile(cli_setup.PolicyProfile.STRICT)

    assert recommended.default_deny is False
    assert recommended.default_require_confirmation is False
    assert recommended.content_firewall.semantic_classifier.posture == "best_effort"
    assert recommended.yara_required is False
    assert set(recommended.default_capabilities) == set(Capability)

    assert strict.default_deny is False
    assert strict.default_require_confirmation is True
    assert strict.content_firewall.semantic_classifier.posture == "required"
    assert strict.yara_required is True
    assert strict.sandbox.containment_profile == "supported"
    assert set(strict.default_capabilities) == set(Capability)


def test_o2b_custom_policy_requires_all_finite_choices() -> None:
    with pytest.raises(ValueError, match="custom policy choices are required"):
        cli_setup.generate_policy_profile(cli_setup.PolicyProfile.CUSTOM)


@pytest.mark.parametrize("confirmation", ["auto", "always"])
@pytest.mark.parametrize("semantic_classifier", ["off", "best_effort", "required"])
@pytest.mark.parametrize("yara", ["optional", "required"])
def test_o2b_every_finite_custom_policy_choice_validates(
    confirmation: str,
    semantic_classifier: str,
    yara: str,
) -> None:
    custom = cli_setup.generate_policy_profile(
        cli_setup.PolicyProfile.CUSTOM,
        custom=cli_setup.CustomPolicyChoices(
            confirmation=confirmation,
            semantic_classifier=semantic_classifier,
            yara=yara,
        ),
    )

    assert custom.default_deny is False
    assert custom.default_require_confirmation is (confirmation == "always")
    assert custom.content_firewall.semantic_classifier.posture == semantic_classifier
    assert custom.yara_required is (yara == "required")
    assert custom.sandbox.containment_profile == "supported"
    assert set(custom.default_capabilities) == set(Capability)


def test_o2b_policy_cli_emits_deterministic_valid_json() -> None:
    result = CliRunner().invoke(
        cli,
        ["setup", "policy", "--profile", "strict", "--format", "json"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["profile"] == "strict"
    assert payload["policy"]["default_deny"] is False
    assert payload["policy"]["default_require_confirmation"] is True
    assert payload["requirements"] == {
        "semantic_classifier": "required",
        "yara": "required",
    }


def test_o2b_policy_cli_rejects_incomplete_custom_profile_without_traceback() -> None:
    result = CliRunner().invoke(
        cli,
        ["setup", "policy", "--profile", "custom", "--format", "json"],
    )

    assert result.exit_code == 3
    payload = json.loads(result.output)
    assert payload["error_type"] == "setup"
    assert payload["exit_code"] == 3
    assert "requires" in payload["likely_cause"]
    assert "Traceback" not in result.output


def _setup_cli_env(tmp_path: Path) -> dict[str, str]:
    return {
        "XDG_CONFIG_HOME": str(tmp_path / "config"),
        "SHISAD_DATA_DIR": str(tmp_path / "data"),
        "NO_COLOR": "1",
    }


@pytest.mark.parametrize(
    "arguments",
    [
        ["setup", "provider", "--format", "json"],
        ["setup", "provider", "--preset", "unknown", "--format", "json"],
        [
            "setup",
            "provider",
            "--preset",
            "custom",
            "--model-id",
            "model-1",
            "--base-url",
            "https://models.example/v1",
            "--auth",
            "header",
            "--format",
            "json",
        ],
        [
            "setup",
            "provider",
            "--preset",
            "vllm_local_default",
            "--timeout",
            "forever",
            "--format",
            "json",
        ],
        ["setup", "policy", "--format", "json"],
        ["setup", "policy", "--profile", "unknown", "--format", "json"],
        [
            "setup",
            "policy",
            "--profile",
            "custom",
            "--confirmation",
            "sometimes",
            "--semantic-classifier",
            "off",
            "--yara",
            "optional",
            "--format",
            "json",
        ],
    ],
)
def test_o2b_cli_selection_errors_use_setup_json_envelope(
    tmp_path: Path,
    arguments: list[str],
) -> None:
    result = CliRunner().invoke(cli, arguments, env=_setup_cli_env(tmp_path))

    assert result.exit_code == 3, result.output
    payload = json.loads(result.output)
    assert payload["error_type"] == "setup"
    assert payload["exit_code"] == 3
    assert "Usage:" not in result.output
    assert "Traceback" not in result.output


def test_o2b_cli_malformed_custom_url_json_never_echoes_embedded_secret(
    tmp_path: Path,
) -> None:
    secret = "cli-malformed-secret-must-not-echo"
    result = CliRunner().invoke(
        cli,
        [
            "setup",
            "provider",
            "--preset",
            "custom",
            "--model-id",
            "model-1",
            "--base-url",
            f"https://user:{secret}@[::1",
            "--auth",
            "none",
            "--format",
            "json",
        ],
        env=_setup_cli_env(tmp_path),
    )

    assert result.exit_code == 3
    payload = json.loads(result.output)
    assert payload["error_type"] == "setup"
    assert payload["likely_cause"] == "custom provider base URL is malformed"
    assert secret not in result.output


def test_o2b_cli_unavailable_reference_uses_setup_error_envelope(tmp_path: Path) -> None:
    runner = CliRunner()
    env = {**_setup_cli_env(tmp_path), "OPENAI_API_KEY": ""}
    enrolled = runner.invoke(
        cli,
        [
            "credential",
            "set",
            "model.primary",
            "--backend",
            "env",
            "--locator",
            "OPENAI_API_KEY",
        ],
        env=env,
    )
    assert enrolled.exit_code == 0, enrolled.output

    result = runner.invoke(
        cli,
        [
            "setup",
            "provider",
            "--preset",
            "openai_default",
            "--credential-ref",
            "model.primary",
            "--skip-probe",
            "--format",
            "json",
        ],
        env=env,
    )

    assert result.exit_code == 3, result.output
    payload = json.loads(result.output)
    assert payload["error_type"] == "setup"
    assert payload["likely_cause"] == "missing_api_key"
    assert "config_fragment" not in payload


def test_o2b_provider_and_policy_human_output_is_bounded(tmp_path: Path) -> None:
    runner = CliRunner()
    env = _setup_cli_env(tmp_path)
    provider = runner.invoke(
        cli,
        [
            "setup",
            "provider",
            "--preset",
            "vllm_local_default",
            "--skip-probe",
        ],
        env=env,
    )
    policy = runner.invoke(
        cli,
        ["setup", "policy", "--profile", "recommended"],
        env=env,
    )

    assert provider.exit_code == 0, provider.output
    assert "Provider setup: skipped" in provider.output
    assert "Probe: probe_skipped" in provider.output
    assert "Config fragment:" in provider.output
    assert policy.exit_code == 0, policy.output
    assert "Policy profile: recommended" in policy.output
    assert "Generated only; no active policy file was changed." in policy.output
    assert "\x1b[" not in provider.output + policy.output


def _o2d_selection_payload(
    *,
    preset: str = "vllm_local_default",
    model_id: str = "local/setup-model",
    channels: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "provider": {
            "preset": preset,
            "model_id": model_id,
            "credential_ref": "model.primary" if preset != "vllm_local_default" else "",
        },
        "policy": {"profile": "recommended"},
        "channels": channels or [],
    }


@pytest.mark.parametrize(
    ("preset", "credential_ref"),
    [
        ("openrouter_default", "model.primary"),
        ("vllm_local_default", ""),
    ],
)
def test_o2d_final_publication_requires_explicit_openrouter_and_vllm_model(
    preset: str,
    credential_ref: str,
) -> None:
    payload = _o2d_selection_payload(preset=preset, model_id="")
    provider = payload["provider"]
    assert isinstance(provider, dict)
    provider["credential_ref"] = credential_ref

    with pytest.raises(ValueError, match="explicit model ID"):
        cli_setup.CombinedSetupSelection.model_validate(payload)


def test_o2d_combined_selection_rejects_duplicate_channels() -> None:
    payload = _o2d_selection_payload(
        channels=[
            {"channel": "discord", "bot_token_ref": "channel.discord"},
            {"channel": "discord", "bot_token_ref": "channel.discord.other"},
        ]
    )

    with pytest.raises(ValueError, match="selected only once"):
        cli_setup.CombinedSetupSelection.model_validate(payload)


def test_o2d_selection_file_is_bounded_forbids_unknown_fields_and_redacts_failure(
    tmp_path: Path,
) -> None:
    secret = "selection-secret-must-not-print"
    selection_path = tmp_path / "selection.yaml"
    selection_path.write_text(
        yaml.safe_dump({**_o2d_selection_payload(), "raw_api_key": secret}),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        ["setup", "apply", "--selection", str(selection_path), "--format", "json"],
    )

    assert result.exit_code == 3
    payload = json.loads(result.output)
    assert payload["error_type"] == "setup"
    assert secret not in result.output
    assert "raw_api_key" not in result.output


def test_o2d_managed_apply_is_dry_run_without_explicit_write(tmp_path: Path) -> None:
    selection_path = tmp_path / "selection.yaml"
    selection_path.write_text(yaml.safe_dump(_o2d_selection_payload()), encoding="utf-8")
    config_path = tmp_path / "config.toml"

    result = CliRunner().invoke(
        cli,
        [
            "--config",
            str(config_path),
            "setup",
            "apply",
            "--selection",
            str(selection_path),
            "--skip-probes",
            "--format",
            "json",
        ],
        env={"SHISAD_MANAGED": "1", "SHISAD_DATA_DIR": str(tmp_path / "data")},
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["outcome"] == "ready"
    assert payload["persisted"] is False
    assert payload["provider"]["outcome"] == "skipped"
    assert not config_path.exists()
    assert not (tmp_path / "policy.yaml").exists()
    assert "Write" not in result.output


def test_o2d_wizard_refuses_noninteractive_and_managed_posture_before_prompt_or_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "config.toml"
    invoked: list[str] = []

    async def _unexpected_provider(*args, **kwargs):
        invoked.append("provider")
        pytest.fail("wizard must not probe in a refused posture")

    monkeypatch.setattr(cli_setup, "evaluate_provider_setup", _unexpected_provider)
    runner = CliRunner()
    noninteractive = runner.invoke(
        cli,
        ["--config", str(config_path), "setup", "wizard", "--format", "json"],
    )
    monkeypatch.setattr(cli_setup, "_interactive_terminal", lambda: True)
    managed = runner.invoke(
        cli,
        ["--config", str(config_path), "setup", "wizard", "--format", "json"],
        env={"SHISAD_MANAGED": "true"},
    )

    for result in (noninteractive, managed):
        assert result.exit_code == 3
        payload = json.loads(result.output)
        assert payload["error_type"] == "setup"
        assert "setup apply" in payload["next_action"]
    assert invoked == []
    assert not config_path.exists()


def test_o2d_interactive_decline_after_multiselect_summary_writes_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_setup, "_interactive_terminal", lambda: True)
    config_path = tmp_path / "config.toml"

    result = CliRunner().invoke(
        cli,
        ["--config", str(config_path), "setup", "wizard"],
        input=("vllm_local_default\nlocal/setup-model\nn\nrecommended\n\nn\n"),
        env={"SHISAD_DATA_DIR": str(tmp_path / "data"), "NO_COLOR": "1"},
    )

    assert result.exit_code == 0, result.output
    assert "Provider: skipped" in result.output
    assert "Provider readiness: probe_skipped" in result.output
    assert "Provider retry allowed: yes" in result.output
    assert "Policy: recommended" in result.output
    assert "Policy confirmation: auto" in result.output
    assert "Policy semantic classifier: best_effort" in result.output
    assert "Policy YARA: optional" in result.output
    assert "Channels: none" in result.output
    assert "Setup publication: skipped" in result.output
    assert not config_path.exists()
    assert not (tmp_path / "policy.yaml").exists()
    assert "\x1b[" not in result.output


def test_o2d_interactive_multiselect_collects_each_channel_reference_and_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_setup, "_interactive_terminal", lambda: True)
    captured: list[cli_setup.CombinedSetupSelection] = []

    async def _evaluate(selection, *, config_path: Path, **kwargs):
        _ = kwargs
        captured.append(selection)
        probe = cli_setup.ReadinessStatus(
            state=cli_setup.ReadinessState.CONFIGURED,
            configured=True,
            evidence="not_run",
            reason="probe_skipped",
            next_action="rerun without skipping probes",
            source="explicit_setup_skip",
        )
        provider = cli_setup.ProviderSetupResult(
            outcome=cli_setup.ProviderSetupOutcome.SKIPPED,
            preset=selection.provider.preset,
            model_id=selection.provider.model_id,
            base_url="http://127.0.0.1:8000/v1",
            probe=probe,
            config_fragment={
                "planner_provider_preset": "vllm_local_default",
                "planner_model_id": selection.provider.model_id,
                "planner_remote_enabled": True,
            },
            retry_allowed=True,
            exit_code=0,
        )
        channels = [
            cli_setup.ChannelSetupResult(
                outcome=ChannelSetupOutcome.SKIPPED,
                channel=item.channel,
                probe=probe,
                identity_ready=True,
                identity_next_action="none",
                config_fragment={},
                retry_allowed=True,
                exit_code=0,
            )
            for item in selection.channels
        ]
        return (
            cli_setup.CombinedSetupResult(
                outcome=cli_setup.CombinedSetupOutcome.READY,
                provider=provider,
                policy_profile=selection.policy.profile,
                policy_requirements={
                    "semantic_classifier": "best_effort",
                    "yara": "optional",
                },
                channels=channels,
                config_path=str(config_path),
                policy_path=str(config_path.with_name("policy.yaml")),
                persisted=False,
                next_actions=["rerun with --write"],
                exit_code=0,
            ),
            cli_setup.generate_policy_profile(selection.policy.profile),
        )

    monkeypatch.setattr(cli_setup, "evaluate_combined_setup", _evaluate)
    config_path = tmp_path / "config.toml"
    result = CliRunner().invoke(
        cli,
        ["--config", str(config_path), "setup", "wizard"],
        input=(
            "vllm_local_default\n"
            "local/setup-model\n"
            "n\n"
            "recommended\n"
            "discord,telegram\n"
            "channel.discord\n"
            "discord-room\n"
            "discord-user\n"
            "channel.telegram\n"
            "telegram-chat\n"
            "telegram-user-1,telegram-user-2\n"
            "n\n"
        ),
        env={"SHISAD_DATA_DIR": str(tmp_path / "data"), "NO_COLOR": "1"},
    )

    assert result.exit_code == 0, result.output
    assert len(captured) == 1
    selected = captured[0]
    assert [item.channel.value for item in selected.channels] == ["discord", "telegram"]
    assert selected.channels[0].bot_token_ref == "channel.discord"
    assert selected.channels[0].trusted_users == ["discord-user"]
    assert selected.channels[1].bot_token_ref == "channel.telegram"
    assert selected.channels[1].trusted_users == ["telegram-user-1", "telegram-user-2"]
    assert "- discord: skipped" in result.output
    assert "Readiness: probe_skipped" in result.output
    assert "Retry allowed: yes" in result.output
    assert "Ingress identity ready: yes" in result.output
    assert "Identity next: none" in result.output
    assert not config_path.exists()


def test_o2d_wizard_cancellation_before_selection_is_typed_json_skip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_setup, "_interactive_terminal", lambda: True)

    def _cancel_selection(*args, **kwargs):
        _ = args, kwargs
        raise cli_setup.click.Abort()

    monkeypatch.setattr(cli_setup, "_prompt_combined_setup_selection", _cancel_selection)
    config_path = tmp_path / "config.toml"
    result = CliRunner().invoke(
        cli,
        ["--config", str(config_path), "setup", "wizard", "--format", "json"],
        env={"SHISAD_DATA_DIR": str(tmp_path / "data")},
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload == {
        "next_actions": ["rerun setup wizard when ready to continue"],
        "outcome": "skipped",
        "persisted": False,
    }
    assert not config_path.exists()
    assert not (tmp_path / "policy.yaml").exists()


def test_o2d_wizard_final_confirmation_cancellation_keeps_json_stdout_parseable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_setup, "_interactive_terminal", lambda: True)
    config_path = tmp_path / "config.toml"
    result = CliRunner().invoke(
        cli,
        ["--config", str(config_path), "setup", "wizard", "--format", "json"],
        input="vllm_local_default\nlocal/setup-model\nn\nrecommended\n\n",
        env={"SHISAD_DATA_DIR": str(tmp_path / "data")},
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["outcome"] == "skipped"
    assert payload["persisted"] is False
    assert payload["policy_requirements"]["confirmation"] == "auto"
    assert "confirm publication below" in result.stderr
    assert "rerun with --write" not in result.stderr
    assert not config_path.exists()
    assert not (tmp_path / "policy.yaml").exists()


def test_o2d_wizard_blocked_result_preserves_actionable_stdout_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_setup, "_interactive_terminal", lambda: True)
    selection = cli_setup.CombinedSetupSelection.model_validate(_o2d_selection_payload())
    monkeypatch.setattr(
        cli_setup,
        "_prompt_combined_setup_selection",
        lambda **_kwargs: (selection, True),
    )

    async def _blocked(*args, config_path: Path, **kwargs):
        _ = args, kwargs
        probe = cli_setup.ReadinessStatus(
            state=cli_setup.ReadinessState.BLOCKED,
            configured=False,
            reason="provider_unavailable",
            next_action="repair the selected provider reference",
            source="provider_setup_probe",
        )
        provider = cli_setup.ProviderSetupResult(
            outcome=cli_setup.ProviderSetupOutcome.BLOCKED,
            preset="vllm_local_default",
            model_id="local/setup-model",
            base_url="http://127.0.0.1:8000/v1",
            probe=probe,
            config_fragment={},
            retry_allowed=True,
            exit_code=3,
        )
        return (
            cli_setup.CombinedSetupResult(
                outcome=cli_setup.CombinedSetupOutcome.BLOCKED,
                provider=provider,
                policy_profile=cli_setup.PolicyProfile.RECOMMENDED,
                policy_requirements={
                    "confirmation": "auto",
                    "semantic_classifier": "best_effort",
                    "yara": "optional",
                },
                channels=[],
                config_path=str(config_path),
                policy_path=str(config_path.with_name("policy.yaml")),
                persisted=False,
                next_actions=["follow the component next actions, then rerun setup"],
                exit_code=3,
            ),
            cli_setup.generate_policy_profile(cli_setup.PolicyProfile.RECOMMENDED),
        )

    monkeypatch.setattr(cli_setup, "evaluate_combined_setup", _blocked)
    config_path = tmp_path / "config.toml"
    result = CliRunner().invoke(
        cli,
        ["--config", str(config_path), "setup", "wizard", "--format", "json"],
        env={"SHISAD_DATA_DIR": str(tmp_path / "data")},
    )

    assert result.exit_code == 3, result.output
    payload = json.loads(result.stdout)
    assert payload["outcome"] == "blocked"
    assert payload["next_actions"] == ["follow the component next actions, then rerun setup"]
    assert "confirm publication below" not in result.output
    assert not config_path.exists()
    assert not (tmp_path / "policy.yaml").exists()


def test_o2d_policy_residue_is_reported_when_config_publication_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selection_path = tmp_path / "selection.yaml"
    selection_path.write_text(yaml.safe_dump(_o2d_selection_payload()), encoding="utf-8")
    config_path = tmp_path / "config.toml"

    def _fail_config(*args, **kwargs):
        raise cli_setup.ConfigFileError("simulated config publication failure")

    monkeypatch.setattr(cli_setup, "initialize_config_file", _fail_config)
    result = CliRunner().invoke(
        cli,
        [
            "--config",
            str(config_path),
            "setup",
            "apply",
            "--selection",
            str(selection_path),
            "--skip-probes",
            "--write",
            "--format",
            "json",
        ],
        env={"SHISAD_DATA_DIR": str(tmp_path / "data")},
    )

    assert result.exit_code == 3
    payload = json.loads(result.output)
    policy_path = tmp_path / "policy.yaml"
    assert policy_path.exists()
    assert policy_path.stat().st_mode & 0o777 == 0o600
    assert str(policy_path) in payload["next_action"]
    assert "inert" in payload["likely_cause"]
    assert not config_path.exists()


@pytest.mark.parametrize("occupied", ["config", "policy", "config_symlink", "policy_symlink"])
def test_o2d_publication_preflight_rejects_existing_or_symlink_artifacts_before_write(
    tmp_path: Path,
    occupied: str,
) -> None:
    selection_path = tmp_path / "selection.yaml"
    selection_path.write_text(yaml.safe_dump(_o2d_selection_payload()), encoding="utf-8")
    config_path = tmp_path / "config.toml"
    policy_path = tmp_path / "policy.yaml"
    if occupied == "config":
        config_path.write_text("schema_version = 1\n", encoding="utf-8")
    elif occupied == "policy":
        policy_path.write_text("do not replace\n", encoding="utf-8")
    else:
        destination = config_path if occupied == "config_symlink" else policy_path
        target = tmp_path / f"{occupied}-target.yaml"
        target.write_text("do not replace\n", encoding="utf-8")
        destination.symlink_to(target)

    result = CliRunner().invoke(
        cli,
        [
            "--config",
            str(config_path),
            "setup",
            "apply",
            "--selection",
            str(selection_path),
            "--skip-probes",
            "--write",
            "--format",
            "json",
        ],
        env={"SHISAD_DATA_DIR": str(tmp_path / "data")},
    )

    assert result.exit_code == 3
    payload = json.loads(result.output)
    assert payload["error_type"] == "setup"
    if occupied == "config":
        assert config_path.read_text(encoding="utf-8") == "schema_version = 1\n"
        assert not policy_path.exists()
    elif occupied == "config_symlink":
        assert config_path.is_symlink()
        assert target.read_text(encoding="utf-8") == "do not replace\n"
        assert not policy_path.exists()
    else:
        assert not config_path.exists()
        assert policy_path.exists() or policy_path.is_symlink()


def test_o2d_publication_rejects_identical_artifact_paths_before_write(tmp_path: Path) -> None:
    selection_path = tmp_path / "selection.yaml"
    selection_path.write_text(yaml.safe_dump(_o2d_selection_payload()), encoding="utf-8")
    shared_path = tmp_path / "policy.yaml"

    result = CliRunner().invoke(
        cli,
        [
            "--config",
            str(shared_path),
            "setup",
            "apply",
            "--selection",
            str(selection_path),
            "--skip-probes",
            "--write",
            "--format",
            "json",
        ],
        env={"SHISAD_DATA_DIR": str(tmp_path / "data")},
    )

    assert result.exit_code == 3
    assert "must be different" in json.loads(result.output)["likely_cause"]
    assert not shared_path.exists()


async def test_o2d_known_config_representation_failure_precedes_policy_write(
    tmp_path: Path,
) -> None:
    selection = cli_setup.CombinedSetupSelection.model_validate(_o2d_selection_payload())
    result, policy = await cli_setup.evaluate_combined_setup(
        selection,
        credential_store=_CredentialStore(),
        daemon_config=cli_setup.DaemonConfig(data_dir=tmp_path / "data"),
        model_config=cli_setup.ModelConfig(),
        config_path=tmp_path / "config.toml",
        skip_probes=True,
    )
    provider = result.provider.model_copy(
        update={"config_fragment": {"not_a_live_model_field": True}}
    )

    with pytest.raises(cli_setup.ConfigFileError, match="unknown model field"):
        cli_setup.publish_combined_setup(
            result.model_copy(update={"provider": provider}),
            policy,
            output_format="json",
        )

    assert not (tmp_path / "policy.yaml").exists()


def test_o2d_unsuccessful_provider_result_cannot_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selection_path = tmp_path / "selection.yaml"
    selection_path.write_text(yaml.safe_dump(_o2d_selection_payload()), encoding="utf-8")
    config_path = tmp_path / "config.toml"

    async def _degraded_provider(selection, **kwargs):
        _ = kwargs
        return cli_setup.ProviderSetupResult(
            outcome=cli_setup.ProviderSetupOutcome.DEGRADED,
            preset=selection.preset,
            model_id=selection.model_id,
            base_url="http://127.0.0.1:8000/v1",
            probe=cli_setup.ReadinessStatus(
                state=cli_setup.ReadinessState.DEGRADED,
                configured=True,
                evidence="live_probe",
                reason="provider_unreachable",
                next_action="inspect the configured provider",
                source="provider_setup_probe",
            ),
            config_fragment={
                "planner_provider_preset": "vllm_local_default",
                "planner_model_id": "local/setup-model",
                "planner_remote_enabled": True,
            },
            retry_allowed=True,
            exit_code=2,
        )

    monkeypatch.setattr(cli_setup, "evaluate_provider_setup", _degraded_provider)
    result = CliRunner().invoke(
        cli,
        [
            "--config",
            str(config_path),
            "setup",
            "apply",
            "--selection",
            str(selection_path),
            "--write",
            "--format",
            "json",
        ],
        env={"SHISAD_DATA_DIR": str(tmp_path / "data")},
    )

    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert payload["outcome"] == "blocked"
    assert payload["provider"]["outcome"] == "degraded"
    assert not config_path.exists()
    assert not (tmp_path / "policy.yaml").exists()
