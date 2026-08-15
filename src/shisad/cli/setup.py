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
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from pydantic_core import PydanticCustomError

from shisad.channels.setup import (
    ChannelName,
    ChannelSetupResult,
    ChannelSetupSelection,
    evaluate_channel_setup,
)
from shisad.cli.onboarding import EnvironmentDetectionError, parse_managed_posture
from shisad.cli.presentation import CliErrorEnvelope, StructuredCliError, safe_cli_text
from shisad.core.config import (
    DaemonConfig,
    ModelConfig,
    effective_credential_reference_paths,
    validate_credential_reference_name,
)
from shisad.core.config_file import (
    ConfigFileError,
    _initialize_owner_only_generated_file,
    _validate_owner_only_generated_path,
    initialize_config_file,
    load_effective_config,
    render_config_template,
    selected_config_path,
)
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


class SetupPolicySelection(BaseModel):
    """One finite generated policy choice for combined setup."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    profile: PolicyProfile
    custom: CustomPolicyChoices | None = None

    @model_validator(mode="after")
    def _validate_custom_shape(self) -> SetupPolicySelection:
        if self.profile is PolicyProfile.CUSTOM and self.custom is None:
            raise ValueError("custom policy choices are required")
        if self.profile is not PolicyProfile.CUSTOM and self.custom is not None:
            raise ValueError("custom policy choices require profile=custom")
        return self


class CombinedSetupSelection(BaseModel):
    """Secret-free provider, policy, and zero-or-more channel selections."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: ProviderSetupSelection
    policy: SetupPolicySelection
    channels: list[ChannelSetupSelection] = Field(default_factory=list, max_length=4)

    @model_validator(mode="after")
    def _validate_combined_shape(self) -> CombinedSetupSelection:
        if (
            self.provider.preset
            in {
                ProviderPreset.OPENROUTER_DEFAULT.value,
                ProviderPreset.VLLM_LOCAL_DEFAULT.value,
            }
            and not self.provider.model_id
        ):
            raise PydanticCustomError(
                "explicit_model_required",
                "{preset} requires an explicit model ID for final publication",
                {"preset": self.provider.preset},
            )
        selected = [item.channel for item in self.channels]
        if len(set(selected)) != len(selected):
            raise ValueError("each channel may be selected only once")
        return self


class CombinedSetupOutcome(StrEnum):
    READY = "ready"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class CombinedSetupResult(BaseModel):
    """Redacted composition of existing typed setup results."""

    model_config = ConfigDict(frozen=True)

    outcome: CombinedSetupOutcome
    provider: ProviderSetupResult
    policy_profile: PolicyProfile
    policy_requirements: dict[str, str]
    channels: list[ChannelSetupResult]
    config_path: str
    policy_path: str
    persisted: bool
    next_actions: list[str]
    exit_code: int


class SetupWizardSkippedResult(BaseModel):
    """Typed result for cancellation before a combined selection exists."""

    model_config = ConfigDict(frozen=True)

    outcome: Literal["skipped"] = "skipped"
    persisted: Literal[False] = False
    next_actions: list[str] = Field(
        default_factory=lambda: ["rerun setup wizard when ready to continue"]
    )


class SetupSelectionValidationError(ValueError):
    """Secret-free actionable projection of a selection validation failure."""

    def __init__(self, reason: str, *, next_action: str, technical_details: str) -> None:
        super().__init__(reason)
        self.next_action = next_action
        self.technical_details = technical_details


class SetupCliError(StructuredCliError):
    """Expected setup selection/configuration failure."""

    exit_code = 3

    def __init__(
        self,
        reason: str,
        *,
        output_format: str,
        next_action: str = "correct the explicit setup values, then rerun the command",
        technical_details: str | None = None,
    ) -> None:
        super().__init__(
            CliErrorEnvelope(
                error_type="setup",
                exit_code=self.exit_code,
                what_failed="Could not prepare the requested setup selection.",
                what_still_works="help, credential status, diagnostics, and local features.",
                likely_cause=safe_cli_text(reason, limit=256),
                next_action=safe_cli_text(next_action, limit=256),
                technical_details=safe_cli_text(technical_details or reason, limit=256),
            ),
            output_format=output_format,
        )


class SetupPostureError(StructuredCliError):
    """Interactive setup cannot safely run in the current posture."""

    exit_code = 3

    def __init__(self, reason: str, *, output_format: str) -> None:
        super().__init__(
            CliErrorEnvelope(
                error_type="setup",
                exit_code=self.exit_code,
                what_failed="Could not start interactive setup.",
                what_still_works="deterministic setup apply and explicit init commands.",
                likely_cause=safe_cli_text(reason, limit=256),
                next_action="use setup apply --selection FILE; add --write only to publish",
                technical_details=safe_cli_text(reason, limit=256),
            ),
            output_format=output_format,
        )


class SetupPublicationError(StructuredCliError):
    """Policy completed but final config publication did not."""

    exit_code = 3

    def __init__(self, policy_path: Path, reason: str, *, output_format: str) -> None:
        safe_path = safe_cli_text(str(policy_path), limit=512)
        super().__init__(
            CliErrorEnvelope(
                error_type="setup",
                exit_code=self.exit_code,
                what_failed="Could not finish setup artifact publication.",
                what_still_works=(
                    "the generated policy remains inactive until a config references it."
                ),
                likely_cause="an inert owner-only policy remains after config publication failed",
                next_action=f"inspect or remove the inert policy at {safe_path}, then retry setup",
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


_MAX_SELECTION_BYTES = 65_536


def _safe_selection_validation_error(exc: ValidationError) -> SetupSelectionValidationError:
    """Project only finite machine-owned validation codes into CLI guidance."""

    for error in exc.errors(include_input=False, include_url=False):
        if error.get("type") != "explicit_model_required":
            continue
        context = error.get("ctx")
        preset = context.get("preset") if isinstance(context, dict) else None
        if preset not in {
            ProviderPreset.OPENROUTER_DEFAULT.value,
            ProviderPreset.VLLM_LOCAL_DEFAULT.value,
        }:
            continue
        return SetupSelectionValidationError(
            f"{preset} requires an explicit model ID for final publication",
            next_action=f"set provider.model_id for {preset}, then rerun setup apply",
            technical_details=(f"provider.model_id is required when provider.preset is {preset}"),
        )
    reason = "setup selection document does not match the supported schema"
    return SetupSelectionValidationError(
        reason,
        next_action="correct the explicit setup values, then rerun the command",
        technical_details=reason,
    )


def load_combined_setup_selection(path: Path) -> CombinedSetupSelection:
    """Load one bounded secret-free YAML/JSON selection without echoing its content."""

    try:
        if path.stat().st_size > _MAX_SELECTION_BYTES:
            raise ValueError("setup selection file exceeds 65536 bytes")
        raw = path.read_bytes()
    except FileNotFoundError:
        raise ValueError("setup selection file does not exist") from None
    except OSError as exc:
        raise ValueError(f"setup selection file cannot be read: {exc.__class__.__name__}") from exc
    if len(raw) > _MAX_SELECTION_BYTES:
        raise ValueError("setup selection file exceeds 65536 bytes")
    try:
        payload = yaml.safe_load(raw)
        if not isinstance(payload, dict):
            raise ValueError("selection root must be a mapping")
        return CombinedSetupSelection.model_validate(payload)
    except ValidationError as exc:
        raise _safe_selection_validation_error(exc) from exc
    except (UnicodeDecodeError, yaml.YAMLError, ValueError) as exc:
        if isinstance(exc, ValueError) and str(exc).startswith("setup selection file exceeds"):
            raise
        raise ValueError("setup selection document does not match the supported schema") from exc


def _combined_setup_context(
    ctx: click.Context,
) -> tuple[CredentialReferenceStore, DaemonConfig, ModelConfig, Path]:
    root = ctx.find_root()
    selected = (root.obj or {}).get("config_path")
    explicit_path = selected if isinstance(selected, Path) else None
    destination = selected_config_path(explicit_path, environ=os.environ)
    if destination.exists():
        loaded = load_effective_config(explicit_path, environ=os.environ)
    else:
        baseline_env = dict(os.environ)
        baseline_env.pop("SHISAD_CONFIG_PATH", None)
        loaded = load_effective_config(None, environ=baseline_env)
    registry_path, secret_root = effective_credential_reference_paths(
        data_dir=loaded.daemon.data_dir,
        configured_store_path=loaded.security.credential_reference_store_path,
        configured_secret_dir=loaded.security.credential_secret_dir,
    )
    store = CredentialReferenceStore(
        registry_path=registry_path,
        secret_root=secret_root,
        environ=os.environ,
    )
    return store, loaded.daemon, loaded.model, destination


async def evaluate_combined_setup(
    selection: CombinedSetupSelection,
    *,
    credential_store: CredentialReferenceStore,
    daemon_config: DaemonConfig,
    model_config: ModelConfig,
    config_path: Path,
    skip_probes: bool,
    timeout_seconds: float = 3.0,
) -> tuple[CombinedSetupResult, PolicyBundle]:
    """Serially compose the existing provider, policy, and channel setup owners."""

    provider_selection = selection.provider.model_copy(
        update={
            "allow_http_localhost": model_config.allow_http_localhost,
            "block_private_ranges": model_config.block_private_ranges,
            "endpoint_allowlist": list(model_config.endpoint_allowlist),
        }
    )
    provider = await evaluate_provider_setup(
        provider_selection,
        credential_store=credential_store,
        timeout_seconds=timeout_seconds,
        skip_probe=skip_probes,
    )
    policy = generate_policy_profile(
        selection.policy.profile,
        custom=selection.policy.custom,
    )
    channels: list[ChannelSetupResult] = []
    for channel_selection in selection.channels:
        channels.append(
            await evaluate_channel_setup(
                channel_selection,
                credential_store=credential_store,
                state_root=daemon_config.data_dir / "channels",
                timeout_seconds=timeout_seconds,
                skip_probe=skip_probes,
            )
        )

    exit_codes = [provider.exit_code, *(item.exit_code for item in channels)]
    exit_code = 3 if 3 in exit_codes else 2 if 2 in exit_codes else 0
    policy_path = config_path.with_name("policy.yaml")
    requirements = {
        "confirmation": "always" if policy.default_require_confirmation else "auto",
        "semantic_classifier": policy.content_firewall.semantic_classifier.posture,
        "yara": "required" if policy.yara_required else "optional",
    }
    result = CombinedSetupResult(
        outcome=CombinedSetupOutcome.READY if exit_code == 0 else CombinedSetupOutcome.BLOCKED,
        provider=provider,
        policy_profile=selection.policy.profile,
        policy_requirements=requirements,
        channels=channels,
        config_path=str(config_path),
        policy_path=str(policy_path),
        persisted=False,
        next_actions=(
            ["rerun with --write to publish the displayed selection"]
            if exit_code == 0
            else ["follow the component next actions, then rerun setup"]
        ),
        exit_code=exit_code,
    )
    return result, policy


def publish_combined_setup(
    result: CombinedSetupResult,
    policy: PolicyBundle,
    *,
    output_format: str,
) -> CombinedSetupResult:
    """Publish policy then config as independent exclusive owner-only artifacts."""

    if result.exit_code != 0:
        raise ValueError("blocked setup results cannot be published")
    config_path = Path(result.config_path)
    policy_path = Path(result.policy_path)
    if config_path == policy_path:
        raise ConfigFileError("selected config and policy paths must be different")
    _validate_owner_only_generated_path(config_path, environ=os.environ, label="config")
    _validate_owner_only_generated_path(policy_path, environ=os.environ, label="policy")

    daemon_values: dict[str, object] = {"policy_path": policy_path}
    for channel in result.channels:
        daemon_values.update(channel.config_fragment)
    section_overrides = {
        "daemon": daemon_values,
        "model": result.provider.config_fragment,
    }
    render_config_template(section_overrides=section_overrides)

    policy_payload = yaml.safe_dump(
        policy.model_dump(mode="json"),
        sort_keys=False,
    ).encode("utf-8")
    _initialize_owner_only_generated_file(
        policy_path,
        policy_payload,
        environ=os.environ,
        label="policy",
    )

    try:
        initialize_config_file(
            config_path,
            environ=os.environ,
            section_overrides=section_overrides,
        )
    except ConfigFileError as exc:
        raise SetupPublicationError(
            policy_path,
            str(exc),
            output_format=output_format,
        ) from exc

    return result.model_copy(
        update={
            "outcome": CombinedSetupOutcome.COMPLETED,
            "persisted": True,
            "next_actions": [
                "shisad config validate",
                "shisad config show --format human",
                "shisad start --foreground",
            ],
        }
    )


def _interactive_terminal() -> bool:
    stdin = click.get_text_stream("stdin")
    stdout = click.get_text_stream("stdout")
    return bool(
        getattr(stdin, "isatty", lambda: False)() and getattr(stdout, "isatty", lambda: False)()
    )


def _comma_separated_values(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _prompt_channel_selection(
    channel: ChannelName,
    *,
    allow_test: bool,
    err: bool = False,
) -> ChannelSetupSelection:
    values: dict[str, object] = {"channel": channel}
    if channel is ChannelName.MATRIX:
        values.update(
            access_token_ref=click.prompt("Matrix access-token reference", err=err).strip(),
            homeserver=click.prompt("Matrix homeserver URL", err=err).strip(),
            user_id=click.prompt("Matrix bot user ID", err=err).strip(),
            room_id=click.prompt(
                "Matrix default room ID", default="", show_default=False, err=err
            ).strip(),
        )
    else:
        label = channel.value.capitalize()
        values["bot_token_ref"] = click.prompt(f"{label} bot-token reference", err=err).strip()
        if channel is ChannelName.SLACK:
            values["app_token_ref"] = click.prompt("Slack app-token reference", err=err).strip()
        values["default_target"] = click.prompt(
            f"{label} default outbound target",
            default="",
            show_default=False,
            err=err,
        ).strip()
    values["trusted_users"] = _comma_separated_values(
        click.prompt(
            f"{channel.value.capitalize()} trusted user IDs (comma-separated)",
            default="",
            show_default=False,
            err=err,
        )
    )
    run_test = allow_test and click.confirm(
        f"Send the fixed {channel.value} setup test notice?",
        default=False,
        err=err,
    )
    values["run_test"] = run_test
    if run_test:
        values["test_target"] = click.prompt("Explicit test target", err=err).strip()
    return ChannelSetupSelection.model_validate(values)


def _prompt_combined_setup_selection(*, err: bool = False) -> tuple[CombinedSetupSelection, bool]:
    presets = [preset.value for preset in ProviderPreset] + ["custom"]
    preset = click.prompt("Provider preset", type=click.Choice(presets), err=err).strip()
    model_id = click.prompt("Planner model ID", default="", show_default=False, err=err).strip()
    provider_values: dict[str, object] = {"preset": preset, "model_id": model_id}
    if preset == "custom":
        provider_values["base_url"] = click.prompt("Provider base URL", err=err).strip()
        provider_values["auth_mode"] = click.prompt(
            "Provider authentication",
            type=click.Choice([AuthMode.BEARER.value, AuthMode.NONE.value]),
            err=err,
        )
    auth_required = preset != ProviderPreset.VLLM_LOCAL_DEFAULT.value and (
        preset != "custom" or provider_values.get("auth_mode") == AuthMode.BEARER.value
    )
    if auth_required:
        provider_values["credential_ref"] = click.prompt(
            "Logical provider credential reference", err=err
        ).strip()
    run_probes = click.confirm("Run live provider and channel probes now?", default=True, err=err)

    profile = PolicyProfile(
        click.prompt(
            "Policy profile",
            type=click.Choice([item.value for item in PolicyProfile]),
            err=err,
        )
    )
    custom = None
    if profile is PolicyProfile.CUSTOM:
        custom = CustomPolicyChoices(
            confirmation=click.prompt(
                "Confirmation posture",
                type=click.Choice(["auto", "always"]),
                err=err,
            ),
            semantic_classifier=click.prompt(
                "Semantic classifier posture",
                type=click.Choice(["off", "best_effort", "required"]),
                err=err,
            ),
            yara=click.prompt("YARA posture", type=click.Choice(["optional", "required"]), err=err),
        )

    channel_text = click.prompt(
        "Channels (comma-separated matrix, discord, telegram, slack; blank for none)",
        default="",
        show_default=False,
        err=err,
    )
    channel_names = _comma_separated_values(channel_text)
    try:
        selected_channels = [ChannelName(item.lower()) for item in channel_names]
    except ValueError:
        raise ValueError("channel selection must use matrix, discord, telegram, or slack") from None
    if len(set(selected_channels)) != len(selected_channels):
        raise ValueError("each channel may be selected only once")
    channels = [
        _prompt_channel_selection(channel, allow_test=run_probes, err=err)
        for channel in selected_channels
    ]
    try:
        selection = CombinedSetupSelection(
            provider=ProviderSetupSelection.model_validate(provider_values),
            policy=SetupPolicySelection(profile=profile, custom=custom),
            channels=channels,
        )
    except ValidationError as exc:
        raise _safe_selection_validation_error(exc) from exc
    return selection, not run_probes


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
    click.echo(f"Next: {result.probe.next_action}")
    click.echo(f"Retry allowed: {'yes' if result.retry_allowed else 'no'}")
    click.echo(f"Ingress identity ready: {'yes' if result.identity_ready else 'no'}")
    click.echo(f"Identity next: {result.identity_next_action}")
    if result.test_delivery is not None:
        click.echo(f"Test delivery: {result.test_delivery.state}")
        click.echo(f"Test target: {safe_cli_text(result.test_delivery.target, limit=512)}")
    click.echo("Config fragment:")
    click.echo(yaml.safe_dump(result.config_fragment, sort_keys=True).rstrip())


def _emit_combined_result(
    result: CombinedSetupResult,
    *,
    output_format: str,
    err: bool = False,
) -> None:
    if output_format == "json":
        click.echo(
            json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True),
            err=err,
        )
        return
    click.echo(f"Provider: {result.provider.outcome.value}", err=err)
    click.echo(f"Provider readiness: {result.provider.probe.reason}", err=err)
    click.echo(f"Provider next: {result.provider.probe.next_action}", err=err)
    click.echo(
        f"Provider retry allowed: {'yes' if result.provider.retry_allowed else 'no'}",
        err=err,
    )
    click.echo(f"Policy: {result.policy_profile.value}", err=err)
    click.echo(
        f"Policy confirmation: {result.policy_requirements.get('confirmation', 'unspecified')}",
        err=err,
    )
    click.echo(
        "Policy semantic classifier: "
        f"{result.policy_requirements.get('semantic_classifier', 'unspecified')}",
        err=err,
    )
    click.echo(
        f"Policy YARA: {result.policy_requirements.get('yara', 'unspecified')}",
        err=err,
    )
    if result.channels:
        click.echo("Channels:", err=err)
        for channel in result.channels:
            click.echo(
                f"- {channel.channel.value}: {channel.outcome.value}\n"
                f"  Readiness: {channel.probe.reason}\n"
                f"  Next: {channel.probe.next_action}\n"
                f"  Retry allowed: {'yes' if channel.retry_allowed else 'no'}\n"
                f"  Ingress identity ready: {'yes' if channel.identity_ready else 'no'}\n"
                f"  Identity next: {channel.identity_next_action}",
                err=err,
            )
    else:
        click.echo("Channels: none", err=err)
    click.echo(f"Config path: {safe_cli_text(result.config_path, limit=512)}", err=err)
    click.echo(f"Policy path: {safe_cli_text(result.policy_path, limit=512)}", err=err)
    click.echo(f"Setup publication: {result.outcome.value}", err=err)
    for action in result.next_actions:
        click.echo(f"Next: {safe_cli_text(action, limit=512)}", err=err)


def _emit_wizard_skipped(*, output_format: str) -> None:
    result = SetupWizardSkippedResult()
    if output_format == "json":
        click.echo(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))
        return
    click.echo("Setup publication: skipped")
    click.echo(f"Next: {result.next_actions[0]}")


@click.group("setup")
def setup() -> None:
    """Prepare, verify, and explicitly publish setup choices."""


@setup.command("apply")
@click.option(
    "--selection",
    "selection_path",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Bounded secret-free YAML/JSON setup selection.",
)
@click.option("--skip-probes", is_flag=True, help="Publish explicitly unverified results.")
@click.option("--write", is_flag=True, help="Explicitly publish config and policy artifacts.")
@click.option("--timeout", "timeout_value", default="3.0", help="Probe timeout in seconds.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["human", "json"]),
    default="human",
    show_default=True,
)
@click.pass_context
def setup_apply(
    ctx: click.Context,
    selection_path: Path,
    skip_probes: bool,
    write: bool,
    timeout_value: str,
    output_format: str,
) -> None:
    """Evaluate one deterministic selection; write only with --write."""

    try:
        parse_managed_posture(os.environ)
        try:
            timeout_seconds = float(timeout_value)
        except (TypeError, ValueError):
            raise ValueError("setup probe timeout must be a number") from None
        if not 0.1 <= timeout_seconds <= 30.0:
            raise ValueError("setup probe timeout must be between 0.1 and 30 seconds")
        selection = load_combined_setup_selection(selection_path)
        store, daemon_config, model_config, config_path = _combined_setup_context(ctx)
        result, policy = asyncio.run(
            evaluate_combined_setup(
                selection,
                credential_store=store,
                daemon_config=daemon_config,
                model_config=model_config,
                config_path=config_path,
                skip_probes=skip_probes,
                timeout_seconds=timeout_seconds,
            )
        )
        if write and result.exit_code == 0:
            result = publish_combined_setup(
                result,
                policy,
                output_format=output_format,
            )
    except SetupPublicationError:
        raise
    except SetupSelectionValidationError as exc:
        raise SetupCliError(
            str(exc),
            output_format=output_format,
            next_action=exc.next_action,
            technical_details=exc.technical_details,
        ) from exc
    except (ConfigFileError, EnvironmentDetectionError, ValueError) as exc:
        raise SetupCliError(str(exc), output_format=output_format) from exc

    _emit_combined_result(result, output_format=output_format)
    if result.exit_code:
        ctx.exit(result.exit_code)


@setup.command("wizard")
@click.option("--timeout", "timeout_value", default="3.0", help="Probe timeout in seconds.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["human", "json"]),
    default="human",
    show_default=True,
)
@click.pass_context
def setup_wizard(ctx: click.Context, timeout_value: str, output_format: str) -> None:
    """Interactively compose setup and require final default-no write consent."""

    result: CombinedSetupResult | None = None
    try:
        managed = parse_managed_posture(os.environ)
        if managed:
            raise SetupPostureError(
                "managed posture does not permit interactive prompts",
                output_format=output_format,
            )
        if not _interactive_terminal():
            raise SetupPostureError(
                "stdin and stdout must both be interactive terminals",
                output_format=output_format,
            )
        try:
            timeout_seconds = float(timeout_value)
        except (TypeError, ValueError):
            raise ValueError("setup probe timeout must be a number") from None
        if not 0.1 <= timeout_seconds <= 30.0:
            raise ValueError("setup probe timeout must be between 0.1 and 30 seconds")
        json_output = output_format == "json"
        selection, skip_probes = _prompt_combined_setup_selection(err=json_output)
        store, daemon_config, model_config, config_path = _combined_setup_context(ctx)
        result, policy = asyncio.run(
            evaluate_combined_setup(
                selection,
                credential_store=store,
                daemon_config=daemon_config,
                model_config=model_config,
                config_path=config_path,
                skip_probes=skip_probes,
                timeout_seconds=timeout_seconds,
            )
        )
        if result.exit_code:
            _emit_combined_result(result, output_format=output_format)
            ctx.exit(result.exit_code)
        result = result.model_copy(
            update={
                "next_actions": [
                    "confirm publication below or decline to keep the filesystem unchanged"
                ]
            }
        )
        _emit_combined_result(result, output_format=output_format, err=json_output)
        if not click.confirm(
            "Publish the displayed config and policy?",
            default=False,
            err=json_output,
        ):
            declined = result.model_copy(
                update={
                    "outcome": CombinedSetupOutcome.SKIPPED,
                    "next_actions": ["rerun setup wizard when ready to publish"],
                }
            )
            _emit_combined_result(declined, output_format=output_format)
            return
        result = publish_combined_setup(
            result,
            policy,
            output_format=output_format,
        )
    except click.Abort:
        if result is None:
            _emit_wizard_skipped(output_format=output_format)
        else:
            cancelled = result.model_copy(
                update={
                    "outcome": CombinedSetupOutcome.SKIPPED,
                    "persisted": False,
                    "next_actions": ["rerun setup wizard when ready to publish"],
                }
            )
            _emit_combined_result(cancelled, output_format=output_format)
        return
    except (SetupPostureError, SetupPublicationError):
        raise
    except SetupSelectionValidationError as exc:
        raise SetupCliError(
            str(exc),
            output_format=output_format,
            next_action=exc.next_action,
            technical_details=exc.technical_details,
        ) from exc
    except (ConfigFileError, EnvironmentDetectionError, ValueError) as exc:
        raise SetupCliError(str(exc), output_format=output_format) from exc

    _emit_combined_result(result, output_format=output_format)


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
    default="",
    help="One maintained channel to prepare: matrix, discord, telegram, or slack.",
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
        try:
            selected_channel = ChannelName(channel_name.strip().lower())
        except ValueError:
            raise ValueError("channel must be one of: matrix, discord, telegram, slack") from None
        selection = ChannelSetupSelection(
            channel=selected_channel,
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
        store, daemon_config = _channel_setup_context(ctx)
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
