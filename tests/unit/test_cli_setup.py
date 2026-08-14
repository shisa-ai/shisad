"""O2B provider and policy setup contracts."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from shisad.cli import setup as cli_setup
from shisad.cli.main import cli
from shisad.core.providers.capabilities import ProviderPreset
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
    monkeypatch.setenv("OPENAI_API_KEY", "ambient-must-not-select-openai")
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
    assert "ambient-must-not-select-openai" not in json.dumps(fragment)


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
    "base_url",
    [
        "https://user:secret@models.example/v1",
        "https://models.example/v1?api_key=secret",
        "https://models.example/v1#secret",
    ],
)
def test_o2b_custom_provider_rejects_secret_bearing_endpoint_shapes(base_url: str) -> None:
    selection = cli_setup.ProviderSetupSelection(
        preset="custom",
        model_id="local-model",
        base_url=base_url,
        auth_mode="none",
    )

    with pytest.raises(ValueError, match="cannot contain credentials"):
        cli_setup.build_provider_setup_config(selection)


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
