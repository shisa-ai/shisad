"""Bounded provider, policy, and channel preparation for setup."""

from __future__ import annotations

import asyncio
import json
import os
from enum import StrEnum
from pathlib import Path
from typing import Literal

import click
import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from shisad.channels.setup import (
    ChannelName,
    ChannelSetupResult,
    ChannelSetupSelection,
    evaluate_channel_setup,
)
from shisad.cli.presentation import CliErrorEnvelope, StructuredCliError, safe_cli_text
from shisad.core.config import (
    DaemonConfig,
    ModelConfig,
    effective_credential_reference_paths,
    validate_credential_reference_name,
)
from shisad.core.config_file import ConfigFileError, load_effective_config
from shisad.core.providers.capabilities import AuthMode, ProviderPreset
from shisad.core.providers.routed_openai import RoutedOpenAIProvider
from shisad.core.providers.routing import ModelComponent, ModelRouter
from shisad.core.readiness import ReadinessState, ReadinessStatus, configured_route_readiness
from shisad.core.url_parsing import safe_url_destination
from shisad.daemon.services import (
    _resolve_model_credential_references,
    validate_model_endpoints,
)
from shisad.security.credential_refs import CredentialReferenceStore
from shisad.security.policy import PolicyBundle


class ProviderSetupOutcome(StrEnum):
    """Finite provider setup outcomes."""

    VERIFIED = "verified"
    SKIPPED = "skipped"
    DEGRADED = "degraded"
    BLOCKED = "blocked"


class PolicyProfile(StrEnum):
    """Maintained setup policy profiles."""

    RECOMMENDED = "recommended"
    STRICT = "strict"
    CUSTOM = "custom"


class CustomPolicyChoices(BaseModel):
    """Finite custom-policy choices; free-form rule editing stays external."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    confirmation: Literal["auto", "always"]
    semantic_classifier: Literal["off", "best_effort", "required"]
    yara: Literal["optional", "required"]


class ProviderSetupSelection(BaseModel):
    """Explicit provider inputs, isolated from ambient provider selection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    preset: str
    model_id: str = Field(default="", max_length=256)
    base_url: str = ""
    credential_ref: str = ""
    auth_mode: AuthMode | None = None
    allow_http_localhost: bool = True
    block_private_ranges: bool = True
    endpoint_allowlist: list[str] = Field(default_factory=list)

    @field_validator("preset")
    @classmethod
    def _validate_preset(cls, value: str) -> str:
        selected = value.strip().lower()
        if selected == "custom":
            return selected
        try:
            return ProviderPreset(selected).value
        except ValueError:
            choices = ", ".join([preset.value for preset in ProviderPreset] + ["custom"])
            raise ValueError(f"provider preset must be one of: {choices}") from None

    @field_validator("model_id")
    @classmethod
    def _validate_model_id(cls, value: str) -> str:
        selected = value.strip()
        if any(ord(char) < 32 or ord(char) == 127 for char in selected):
            raise ValueError("model ID must be terminal-safe")
        return selected

    @field_validator("base_url")
    @classmethod
    def _normalize_base_url(cls, value: str) -> str:
        return value.strip()

    @field_validator("credential_ref")
    @classmethod
    def _validate_credential_ref(cls, value: str) -> str:
        selected = value.strip()
        return validate_credential_reference_name(selected) if selected else ""

    @model_validator(mode="after")
    def _validate_selection_shape(self) -> ProviderSetupSelection:
        if self.preset != "custom":
            if self.base_url:
                raise ValueError("maintained provider presets do not accept a base URL override")
            if self.auth_mode is not None:
                raise ValueError("maintained provider presets own their authentication mode")
            if self.preset == ProviderPreset.VLLM_LOCAL_DEFAULT.value and self.credential_ref:
                raise ValueError("the unauthenticated local provider does not accept a credential")
            if self.preset != ProviderPreset.VLLM_LOCAL_DEFAULT.value and not self.credential_ref:
                raise ValueError(
                    "maintained authenticated provider credential reference is required"
                )
            return self
        if not self.model_id:
            raise ValueError("custom provider model ID is required")
        if not self.base_url:
            raise ValueError("custom provider base URL is required")
        if self.auth_mode is None:
            raise ValueError("custom provider authentication mode is required")
        if self.auth_mode not in {AuthMode.BEARER, AuthMode.NONE}:
            raise ValueError("custom provider authentication mode must be bearer or none")
        if self.auth_mode is AuthMode.BEARER and not self.credential_ref:
            raise ValueError("custom bearer provider credential reference is required")
        if self.auth_mode is AuthMode.NONE and self.credential_ref:
            raise ValueError(
                "custom unauthenticated provider does not accept a credential reference"
            )
        return self


class ProviderSetupResult(BaseModel):
    """Redacted provider setup result and reusable configuration fragment."""

    model_config = ConfigDict(frozen=True)

    outcome: ProviderSetupOutcome
    preset: str
    model_id: str
    base_url: str
    probe: ReadinessStatus
    config_fragment: dict[str, object]
    retry_allowed: bool
    exit_code: int


class SetupCliError(StructuredCliError):
    """Expected setup selection/configuration failure."""

    exit_code = 3

    def __init__(self, reason: str, *, output_format: str) -> None:
        super().__init__(
            CliErrorEnvelope(
                error_type="setup",
                exit_code=self.exit_code,
                what_failed="Could not prepare the requested setup selection.",
                what_still_works="help, credential status, diagnostics, and local features.",
                likely_cause=safe_cli_text(reason, limit=256),
                next_action="correct the explicit setup values, then rerun the command",
                technical_details=safe_cli_text(reason, limit=256),
            ),
            output_format=output_format,
        )


def build_provider_setup_config(
    selection: ProviderSetupSelection,
) -> tuple[ModelConfig, dict[str, object]]:
    """Build and endpoint-validate an explicit secret-free planner fragment."""

    payload: dict[str, object] = {
        "planner_provider_preset": (
            ProviderPreset.SHISA_DEFAULT if selection.preset == "custom" else selection.preset
        ),
        "planner_remote_enabled": True,
        "embeddings_provider_preset": ProviderPreset.VLLM_LOCAL_DEFAULT,
        "embeddings_remote_enabled": False,
        "monitor_provider_preset": ProviderPreset.VLLM_LOCAL_DEFAULT,
        "monitor_remote_enabled": False,
        "allow_http_localhost": selection.allow_http_localhost,
        "block_private_ranges": selection.block_private_ranges,
        "endpoint_allowlist": list(selection.endpoint_allowlist),
    }
    if selection.model_id:
        payload["planner_model_id"] = selection.model_id
    if selection.credential_ref:
        payload["planner_api_key_ref"] = selection.credential_ref
    if selection.preset == "custom":
        destination = safe_url_destination(selection.base_url)
        if destination is None:
            raise ValueError("custom provider base URL is malformed")
        if destination.has_userinfo or destination.parsed.query or destination.parsed.fragment:
            raise ValueError(
                "custom provider base URL cannot contain credentials, a query, or a fragment"
            )
        payload["planner_base_url"] = selection.base_url
        payload["planner_auth_mode"] = selection.auth_mode

    model_config = ModelConfig.model_validate(payload)
    router = ModelRouter(model_config)
    validate_model_endpoints(
        model_config,
        router,
        components=(ModelComponent.PLANNER,),
    )
    route = router.route_for(ModelComponent.PLANNER)
    fragment: dict[str, object] = {
        "planner_provider_preset": route.provider_preset.value,
        "planner_model_id": route.model_id,
        "planner_remote_enabled": True,
    }
    if selection.preset == "custom":
        fragment["planner_base_url"] = route.base_url
        fragment["planner_auth_mode"] = route.auth_mode.value
    if selection.credential_ref:
        fragment["planner_api_key_ref"] = selection.credential_ref
    return model_config, fragment


async def evaluate_provider_setup(
    selection: ProviderSetupSelection,
    *,
    credential_store: CredentialReferenceStore,
    timeout_seconds: float = 3.0,
    skip_probe: bool = False,
) -> ProviderSetupResult:
    """Resolve locally and run zero or one existing bounded planner probe."""

    if not 0.1 <= timeout_seconds <= 30.0:
        raise ValueError("provider probe timeout must be between 0.1 and 30 seconds")
    model_config, fragment = build_provider_setup_config(selection)
    resolved = _resolve_model_credential_references(model_config, store=credential_store)
    router = ModelRouter(resolved)
    route = router.route_for(ModelComponent.PLANNER)
    configured = configured_route_readiness(route)
    if not configured.configured:
        return ProviderSetupResult(
            outcome=ProviderSetupOutcome.BLOCKED,
            preset=selection.preset,
            model_id=route.model_id,
            base_url=route.base_url,
            probe=configured,
            config_fragment=fragment,
            retry_allowed=True,
            exit_code=3,
        )
    if skip_probe:
        skipped = ReadinessStatus(
            state=ReadinessState.CONFIGURED,
            configured=True,
            evidence="not_run",
            reason="probe_skipped",
            next_action="rerun setup provider without --skip-probe to verify the route",
            source="explicit_setup_skip",
        )
        return ProviderSetupResult(
            outcome=ProviderSetupOutcome.SKIPPED,
            preset=selection.preset,
            model_id=route.model_id,
            base_url=route.base_url,
            probe=skipped,
            config_fragment=fragment,
            retry_allowed=True,
            exit_code=0,
        )

    provider = RoutedOpenAIProvider(
        router=router,
        allow_http_localhost=resolved.allow_http_localhost,
        block_private_ranges=resolved.block_private_ranges,
        endpoint_allowlist=resolved.endpoint_allowlist,
    )
    probe = await provider.probe_planner(timeout_seconds=timeout_seconds)
    outcome = (
        ProviderSetupOutcome.VERIFIED
        if probe.verified
        else ProviderSetupOutcome.BLOCKED
        if probe.state is ReadinessState.BLOCKED
        else ProviderSetupOutcome.DEGRADED
    )
    return ProviderSetupResult(
        outcome=outcome,
        preset=selection.preset,
        model_id=route.model_id,
        base_url=route.base_url,
        probe=probe,
        config_fragment=fragment,
        retry_allowed=not probe.verified,
        exit_code=0 if probe.verified else 2,
    )


def generate_policy_profile(
    profile: PolicyProfile | str,
    *,
    custom: CustomPolicyChoices | None = None,
) -> PolicyBundle:
    """Generate one validated capability-preserving maintained policy."""

    selected = PolicyProfile(profile)
    if selected is PolicyProfile.CUSTOM:
        if custom is None:
            raise ValueError("custom policy choices are required")
        confirmation = custom.confirmation
        semantic_classifier = custom.semantic_classifier
        yara = custom.yara
    else:
        if custom is not None:
            raise ValueError("custom policy choices are only valid with profile=custom")
        confirmation = "always" if selected is PolicyProfile.STRICT else "auto"
        semantic_classifier = "required" if selected is PolicyProfile.STRICT else "best_effort"
        yara = "required" if selected is PolicyProfile.STRICT else "optional"

    payload = PolicyBundle().model_dump(mode="json")
    payload["default_deny"] = False
    payload["default_require_confirmation"] = confirmation == "always"
    payload["yara_required"] = yara == "required"
    payload["sandbox"]["containment_profile"] = "supported"
    payload["content_firewall"]["semantic_classifier"]["posture"] = semantic_classifier
    return PolicyBundle.model_validate(payload)


def _credential_store(ctx: click.Context) -> tuple[CredentialReferenceStore, ModelConfig]:
    root = ctx.find_root()
    selected = (root.obj or {}).get("config_path")
    config_path = selected if isinstance(selected, Path) else None
    loaded = load_effective_config(config_path, environ=os.environ)
    registry_path, secret_root = effective_credential_reference_paths(
        data_dir=loaded.daemon.data_dir,
        configured_store_path=loaded.security.credential_reference_store_path,
        configured_secret_dir=loaded.security.credential_secret_dir,
    )
    return (
        CredentialReferenceStore(
            registry_path=registry_path,
            secret_root=secret_root,
            environ=os.environ,
        ),
        loaded.model,
    )


def _channel_setup_context(
    ctx: click.Context,
) -> tuple[CredentialReferenceStore, DaemonConfig]:
    root = ctx.find_root()
    selected = (root.obj or {}).get("config_path")
    config_path = selected if isinstance(selected, Path) else None
    loaded = load_effective_config(config_path, environ=os.environ)
    registry_path, secret_root = effective_credential_reference_paths(
        data_dir=loaded.daemon.data_dir,
        configured_store_path=loaded.security.credential_reference_store_path,
        configured_secret_dir=loaded.security.credential_secret_dir,
    )
    return (
        CredentialReferenceStore(
            registry_path=registry_path,
            secret_root=secret_root,
            environ=os.environ,
        ),
        loaded.daemon,
    )


def _emit_provider_result(result: ProviderSetupResult, *, output_format: str) -> None:
    if output_format == "json":
        click.echo(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))
        return
    click.echo(f"Provider setup: {result.outcome.value}")
    click.echo(f"Preset: {safe_cli_text(result.preset, limit=64)}")
    click.echo(f"Model: {safe_cli_text(result.model_id, limit=256)}")
    click.echo(f"Endpoint: {safe_cli_text(result.base_url, limit=512)}")
    click.echo(f"Probe: {result.probe.reason}")
    click.echo(f"Next: {result.probe.next_action}")
    click.echo("Config fragment:")
    click.echo(yaml.safe_dump(result.config_fragment, sort_keys=True).rstrip())


def _emit_channel_result(result: ChannelSetupResult, *, output_format: str) -> None:
    if output_format == "json":
        click.echo(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))
        return
    click.echo(f"Channel setup: {result.outcome.value}")
    click.echo(f"Channel: {result.channel.value}")
    click.echo(f"Probe: {result.probe.reason}")
    click.echo(f"Ingress identity ready: {'yes' if result.identity_ready else 'no'}")
    click.echo(f"Identity next: {result.identity_next_action}")
    if result.test_delivery is not None:
        click.echo(f"Test delivery: {result.test_delivery.state}")
        click.echo(f"Test target: {safe_cli_text(result.test_delivery.target, limit=512)}")
    click.echo("Config fragment:")
    click.echo(yaml.safe_dump(result.config_fragment, sort_keys=True).rstrip())


@click.group("setup")
def setup() -> None:
    """Prepare provider, policy, and channel choices without publishing files."""


@setup.command("provider")
@click.option(
    "--preset",
    default="",
    help="Maintained provider preset or custom.",
)
@click.option("--model-id", default="", help="Explicit planner model ID.")
@click.option("--base-url", default="", help="Explicit custom OpenAI-compatible endpoint.")
@click.option("--credential-ref", default="", help="Logical O2A credential reference.")
@click.option("--auth", "auth_mode", default=None, help="Custom auth: bearer or none.")
@click.option("--timeout", "timeout_value", default="3.0", help="Probe timeout in seconds.")
@click.option("--skip-probe", is_flag=True, help="Generate an explicitly unverified result.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["human", "json"]),
    default="human",
    show_default=True,
)
@click.pass_context
def setup_provider(
    ctx: click.Context,
    preset: str,
    model_id: str,
    base_url: str,
    credential_ref: str,
    auth_mode: str | None,
    timeout_value: str,
    skip_probe: bool,
    output_format: str,
) -> None:
    """Select and verify one planner provider without writing configuration."""

    try:
        try:
            timeout_seconds = float(timeout_value)
        except (TypeError, ValueError):
            raise ValueError("provider probe timeout must be a number") from None
        if not 0.1 <= timeout_seconds <= 30.0:
            raise ValueError("provider probe timeout must be between 0.1 and 30 seconds")
        store, current_model = _credential_store(ctx)
        selection = ProviderSetupSelection(
            preset=preset,
            model_id=model_id,
            base_url=base_url,
            credential_ref=credential_ref,
            auth_mode=auth_mode,
            allow_http_localhost=current_model.allow_http_localhost,
            block_private_ranges=current_model.block_private_ranges,
            endpoint_allowlist=current_model.endpoint_allowlist,
        )
        result = asyncio.run(
            evaluate_provider_setup(
                selection,
                credential_store=store,
                timeout_seconds=timeout_seconds,
                skip_probe=skip_probe,
            )
        )
    except (ConfigFileError, ValueError) as exc:
        raise SetupCliError(str(exc), output_format=output_format) from exc
    if result.exit_code == 3:
        raise SetupCliError(result.probe.reason, output_format=output_format)
    _emit_provider_result(result, output_format=output_format)
    if result.exit_code:
        ctx.exit(result.exit_code)


@setup.command("policy")
@click.option("--profile", default="", help="Policy profile: recommended, strict, or custom.")
@click.option("--confirmation", default=None, help="Custom confirmation: auto or always.")
@click.option(
    "--semantic-classifier",
    default=None,
    help="Custom classifier posture: off, best_effort, or required.",
)
@click.option("--yara", default=None, help="Custom YARA posture: optional or required.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["human", "json"]),
    default="human",
    show_default=True,
)
def setup_policy(
    profile: str,
    confirmation: str | None,
    semantic_classifier: str | None,
    yara: str | None,
    output_format: str,
) -> None:
    """Generate a validated policy profile without writing an active policy."""

    try:
        selected = PolicyProfile(profile)
        if selected is PolicyProfile.CUSTOM:
            if confirmation is None or semantic_classifier is None or yara is None:
                raise ValueError(
                    "custom profile requires --confirmation, --semantic-classifier, and --yara"
                )
            custom = CustomPolicyChoices(
                confirmation=confirmation,
                semantic_classifier=semantic_classifier,
                yara=yara,
            )
        else:
            if any(value is not None for value in (confirmation, semantic_classifier, yara)):
                raise ValueError("custom policy choices require --profile custom")
            custom = None
        policy = generate_policy_profile(selected, custom=custom)
    except ValueError as exc:
        raise SetupCliError(str(exc), output_format=output_format) from exc

    policy_payload = policy.model_dump(mode="json")
    requirements = {
        "semantic_classifier": policy.content_firewall.semantic_classifier.posture,
        "yara": "required" if policy.yara_required else "optional",
    }
    payload = {
        "profile": selected.value,
        "policy": policy_payload,
        "requirements": requirements,
        "persisted": False,
    }
    if output_format == "json":
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    click.echo(f"Policy profile: {selected.value}")
    click.echo("Generated only; no active policy file was changed.")
    click.echo(yaml.safe_dump(policy_payload, sort_keys=False).rstrip())


@setup.command("channel")
@click.option(
    "--channel",
    "channel_name",
    type=click.Choice([channel.value for channel in ChannelName]),
    default="",
    help="One maintained channel to prepare.",
)
@click.option("--access-token-ref", default="", help="Logical Matrix access-token ref.")
@click.option("--bot-token-ref", default="", help="Logical bot-token credential ref.")
@click.option("--app-token-ref", default="", help="Logical Slack app-token ref.")
@click.option("--homeserver", default="", help="Matrix homeserver URL.")
@click.option("--user-id", default="", help="Matrix bot user ID.")
@click.option("--room-id", default="", help="Matrix default room ID.")
@click.option("--default-target", default="", help="Optional default outbound target.")
@click.option("--trusted-user", "trusted_users", multiple=True, help="Explicit ingress user ID.")
@click.option("--send-test", is_flag=True, help="Send one fixed setup notice.")
@click.option("--test-target", default="", help="Explicit target for --send-test.")
@click.option("--timeout", "timeout_value", default="3.0", help="Probe timeout in seconds.")
@click.option("--skip-probe", is_flag=True, help="Generate an explicitly unverified result.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["human", "json"]),
    default="human",
    show_default=True,
)
@click.pass_context
def setup_channel(
    ctx: click.Context,
    channel_name: str,
    access_token_ref: str,
    bot_token_ref: str,
    app_token_ref: str,
    homeserver: str,
    user_id: str,
    room_id: str,
    default_target: str,
    trusted_users: tuple[str, ...],
    send_test: bool,
    test_target: str,
    timeout_value: str,
    skip_probe: bool,
    output_format: str,
) -> None:
    """Prepare one channel without publishing final configuration."""

    try:
        try:
            timeout_seconds = float(timeout_value)
        except (TypeError, ValueError):
            raise ValueError("channel probe timeout must be a number") from None
        store, daemon_config = _channel_setup_context(ctx)
        selection = ChannelSetupSelection(
            channel=channel_name,
            access_token_ref=access_token_ref,
            bot_token_ref=bot_token_ref,
            app_token_ref=app_token_ref,
            homeserver=homeserver,
            user_id=user_id,
            room_id=room_id,
            default_target=default_target,
            trusted_users=list(trusted_users),
            run_test=send_test,
            test_target=test_target,
        )
        result = asyncio.run(
            evaluate_channel_setup(
                selection,
                credential_store=store,
                state_root=daemon_config.data_dir / "channels",
                timeout_seconds=timeout_seconds,
                skip_probe=skip_probe,
            )
        )
    except (ConfigFileError, ValueError) as exc:
        raise SetupCliError(str(exc), output_format=output_format) from exc
    _emit_channel_result(result, output_format=output_format)
    if result.exit_code:
        ctx.exit(result.exit_code)
