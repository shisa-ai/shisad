"""Provider-agnostic setup and readiness for shipped runtime channels."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from shisad.channels.base import Channel, DeliveryTarget
from shisad.channels.delivery import ChannelDeliveryService, DeliveryIntent, DeliveryResult
from shisad.channels.state import ChannelStateStore
from shisad.core.config import DaemonConfig, validate_credential_reference_name
from shisad.core.readiness import ReadinessState, ReadinessStatus
from shisad.daemon.services import (
    _build_discord_channel,
    _build_matrix_channel,
    _build_slack_channel,
    _build_telegram_channel,
    _resolve_channel_credential_references,
    _start_channel,
)
from shisad.security.credential_refs import CredentialReferenceError, CredentialReferenceStore

CHANNEL_SETUP_TEST_MESSAGE = "shisad setup test: outbound delivery works; no reply is required."
_MAX_SETUP_VALUE_LENGTH = 512


class ChannelName(StrEnum):
    MATRIX = "matrix"
    DISCORD = "discord"
    TELEGRAM = "telegram"
    SLACK = "slack"


class ChannelSetupOutcome(StrEnum):
    VERIFIED = "verified"
    CONFIGURED = "configured"
    SKIPPED = "skipped"
    DEGRADED = "degraded"
    BLOCKED = "blocked"


class ChannelSetupSelection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    channel: ChannelName
    access_token_ref: str = ""
    bot_token_ref: str = ""
    app_token_ref: str = ""
    homeserver: str = ""
    user_id: str = ""
    room_id: str = ""
    default_target: str = ""
    trusted_users: list[str] = Field(default_factory=list, max_length=64)
    run_test: bool = False
    test_target: str = ""

    @field_validator("access_token_ref", "bot_token_ref", "app_token_ref", mode="before")
    @classmethod
    def _validate_reference(cls, value: object) -> str:
        if not isinstance(value, str):
            raise ValueError("credential reference name must be a string")
        selected = value.strip()
        return validate_credential_reference_name(selected) if selected else ""

    @field_validator(
        "homeserver",
        "user_id",
        "room_id",
        "default_target",
        "test_target",
        mode="before",
    )
    @classmethod
    def _validate_bounded_value(cls, value: object) -> str:
        if not isinstance(value, str):
            raise ValueError("channel setup values must be strings")
        selected = value.strip()
        if len(selected) > _MAX_SETUP_VALUE_LENGTH or any(
            ord(char) < 32 or ord(char) == 127 for char in selected
        ):
            raise ValueError("channel setup value must be bounded and terminal-safe")
        return selected

    @field_validator("trusted_users", mode="before")
    @classmethod
    def _validate_trusted_users(cls, value: object) -> list[str]:
        if not isinstance(value, (list, tuple)):
            raise ValueError("trusted users must be a list")
        normalized: list[str] = []
        seen: set[str] = set()
        for raw in value:
            selected = str(raw).strip()
            if (
                not selected
                or len(selected) > 256
                or any(ord(char) < 32 or ord(char) == 127 for char in selected)
            ):
                raise ValueError("trusted user ids must be bounded and terminal-safe")
            if selected in seen:
                continue
            seen.add(selected)
            normalized.append(selected)
        return normalized

    @model_validator(mode="after")
    def _validate_channel_shape(self) -> ChannelSetupSelection:
        matrix_values = bool(self.homeserver or self.user_id or self.room_id)
        if self.channel is ChannelName.MATRIX:
            missing = [
                label
                for label, value in (
                    ("homeserver", self.homeserver),
                    ("user id", self.user_id),
                    ("room id", self.room_id),
                    ("access-token reference", self.access_token_ref),
                )
                if not value
            ]
            if missing:
                raise ValueError("Matrix setup requires " + ", ".join(missing))
            if self.bot_token_ref or self.app_token_ref or self.default_target:
                raise ValueError("Matrix setup does not accept bot/app refs or a default target")
        else:
            if self.access_token_ref or matrix_values:
                raise ValueError(f"{self.channel.value} setup does not accept Matrix options")
            if not self.bot_token_ref:
                raise ValueError(f"{self.channel.value} setup requires a bot-token reference")
            if self.channel is ChannelName.SLACK:
                if not self.app_token_ref:
                    raise ValueError("Slack setup requires an app-token reference")
            elif self.app_token_ref:
                raise ValueError(f"{self.channel.value} setup does not accept an app-token ref")
        if self.run_test and not self.test_target:
            raise ValueError("test delivery requires an explicit test target")
        if self.test_target and not self.run_test:
            raise ValueError("an explicit test target requires --send-test")
        return self


class ChannelTestDelivery(BaseModel):
    model_config = ConfigDict(frozen=True)

    attempted: bool
    sent: bool
    state: str
    outcome_unknown: bool
    reason: str
    delivery_id: str = ""
    target: str


class ChannelSetupResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    outcome: ChannelSetupOutcome
    channel: ChannelName
    probe: ReadinessStatus
    identity_ready: bool
    identity_next_action: str
    config_fragment: dict[str, object]
    test_delivery: ChannelTestDelivery | None = None
    retry_allowed: bool
    exit_code: int


def build_channel_setup_config(
    selection: ChannelSetupSelection,
) -> tuple[DaemonConfig, dict[str, object]]:
    trusted = list(selection.trusted_users)
    if selection.channel is ChannelName.MATRIX:
        fragment: dict[str, object] = {
            "matrix_enabled": True,
            "matrix_homeserver": selection.homeserver,
            "matrix_user_id": selection.user_id,
            "matrix_access_token_ref": selection.access_token_ref,
            "matrix_room_id": selection.room_id,
            "matrix_e2ee": True,
            "matrix_trusted_users": trusted,
        }
    elif selection.channel is ChannelName.DISCORD:
        fragment = {
            "discord_enabled": True,
            "discord_bot_token_ref": selection.bot_token_ref,
            "discord_default_channel_id": selection.default_target,
            "discord_trusted_users": trusted,
        }
    elif selection.channel is ChannelName.TELEGRAM:
        fragment = {
            "telegram_enabled": True,
            "telegram_bot_token_ref": selection.bot_token_ref,
            "telegram_default_chat_id": selection.default_target,
            "telegram_trusted_users": trusted,
        }
    else:
        fragment = {
            "slack_enabled": True,
            "slack_bot_token_ref": selection.bot_token_ref,
            "slack_app_token_ref": selection.app_token_ref,
            "slack_default_channel_id": selection.default_target,
            "slack_trusted_users": trusted,
        }
    return DaemonConfig.model_validate(fragment), fragment


def _build_setup_channel(
    selection: ChannelSetupSelection,
    *,
    credential_store: CredentialReferenceStore,
    state_root: Path,
) -> Channel:
    config, _fragment = build_channel_setup_config(selection)
    credentials, diagnostics = _resolve_channel_credential_references(
        config,
        store=credential_store,
    )
    if diagnostics:
        raise CredentialReferenceError("credential_value_unavailable")
    selected = credentials.get(selection.channel.value)
    channel: Channel | None
    if selection.channel is ChannelName.MATRIX:
        channel = _build_matrix_channel(config, credentials=selected)
    elif selection.channel is ChannelName.DISCORD:
        channel = _build_discord_channel(
            config,
            replay_state_store=ChannelStateStore(state_root / "state"),
            credentials=selected,
        )
    elif selection.channel is ChannelName.TELEGRAM:
        channel = _build_telegram_channel(config, credentials=selected)
    else:
        channel = _build_slack_channel(config, credentials=selected)
    if channel is None:  # pragma: no cover - validated enabled fragment invariant.
        raise CredentialReferenceError("channel_configuration_incomplete")
    return channel


def adapter_setup_readiness(
    channel_name: ChannelName,
    channel: Channel,
) -> ReadinessStatus:
    custom = getattr(channel, "setup_readiness", None)
    if callable(custom):
        status = custom()
        if isinstance(status, ReadinessStatus):
            return status
    if not getattr(channel, "available", False):
        return ReadinessStatus(
            state=ReadinessState.ABSENT,
            installed=False,
            configured=True,
            reason="channel_dependency_unavailable",
            next_action=f"install shisad[assistant] or the {channel_name.value} runtime extra",
            source="channel_setup_probe",
        )
    health = channel.health_status()
    if not bool(health.get("connected")):
        return ReadinessStatus(
            state=ReadinessState.CONFIGURED,
            configured=True,
            reason="channel_probe_not_run",
            next_action=f"run the bounded {channel_name.value} setup probe",
            source="channel_setup_config",
        )
    active = {
        ChannelName.MATRIX: bool(health.get("sync_task_running")),
        ChannelName.DISCORD: bool(health.get("client_active")),
        ChannelName.TELEGRAM: bool(health.get("app_active")),
        ChannelName.SLACK: bool(health.get("socket_mode") and health.get("socket_task_running")),
    }[channel_name]
    return ReadinessStatus(
        state=ReadinessState.CONFIGURED if active else ReadinessState.DEGRADED,
        configured=True,
        evidence="live_probe",
        reason=(
            "channel_transport_started_not_verified" if active else "channel_transport_unavailable"
        ),
        next_action=(
            f"send an explicit test message to verify outbound {channel_name.value} delivery"
            if active
            else f"check the {channel_name.value} credential and installed client runtime"
        ),
        source="channel_setup_probe",
    )


def _blocked_result(
    selection: ChannelSetupSelection,
    fragment: dict[str, object],
    *,
    reason: str,
    next_action: str,
    identity_ready: bool,
    identity_next_action: str,
) -> ChannelSetupResult:
    return ChannelSetupResult(
        outcome=ChannelSetupOutcome.BLOCKED,
        channel=selection.channel,
        probe=ReadinessStatus(
            state=ReadinessState.BLOCKED,
            configured=False,
            reason=reason,
            next_action=next_action,
            source="channel_setup_config",
        ),
        identity_ready=identity_ready,
        identity_next_action=identity_next_action,
        config_fragment=fragment,
        retry_allowed=True,
        exit_code=3,
    )


def _delivery_projection(result: DeliveryResult, *, target: str) -> ChannelTestDelivery:
    return ChannelTestDelivery(
        attempted=result.attempted,
        sent=result.sent,
        state=result.state,
        outcome_unknown=result.outcome_unknown,
        reason=result.reason,
        delivery_id=result.delivery_id,
        target=target,
    )


async def _disconnect_setup_channel(
    channel: Channel,
    *,
    timeout_seconds: float,
) -> str:
    disconnect = getattr(channel, "disconnect_strict", channel.disconnect)
    try:
        await asyncio.wait_for(disconnect(), timeout=timeout_seconds)
    except TimeoutError:
        return "channel_probe_cleanup_timeout"
    except Exception:
        return "channel_probe_cleanup_failed"
    return ""


class _SetupCleanupError(RuntimeError): ...


@asynccontextmanager
async def _cleanup_started_channel(
    channel: Channel,
    *,
    timeout_seconds: float,
) -> AsyncIterator[None]:
    try:
        yield
    finally:
        reason = await _disconnect_setup_channel(channel, timeout_seconds=timeout_seconds)
        if reason:
            raise _SetupCleanupError(reason)


async def evaluate_channel_setup(
    selection: ChannelSetupSelection,
    *,
    credential_store: CredentialReferenceStore,
    state_root: Path,
    timeout_seconds: float = 3.0,
    skip_probe: bool = False,
) -> ChannelSetupResult:
    if not 0.1 <= timeout_seconds <= 30.0:
        raise ValueError("channel probe timeout must be between 0.1 and 30 seconds")
    if skip_probe and selection.run_test:
        raise ValueError("test delivery cannot be combined with --skip-probe")
    _config, fragment = build_channel_setup_config(selection)
    identity_ready = bool(selection.trusted_users)
    identity_next_action = (
        "none"
        if identity_ready
        else f"add an explicit {selection.channel.value} trusted user before ingress use"
    )
    try:
        channel = _build_setup_channel(
            selection,
            credential_store=credential_store,
            state_root=state_root,
        )
    except CredentialReferenceError:
        return _blocked_result(
            selection,
            fragment,
            reason="channel_credential_unavailable",
            next_action="enroll or repair the selected logical credential reference",
            identity_ready=identity_ready,
            identity_next_action=identity_next_action,
        )

    if skip_probe:
        configured = adapter_setup_readiness(selection.channel, channel)
        probe = configured.model_copy(
            update={
                "evidence": "not_run",
                "verified": False,
                "reachable": False,
                "authenticated": False,
                "reason": (
                    "channel_dependency_unavailable"
                    if not configured.installed
                    else "probe_skipped"
                ),
                "next_action": (
                    configured.next_action
                    if not configured.installed
                    else "rerun setup channel without --skip-probe"
                ),
                "source": "explicit_setup_skip",
            }
        )
        return ChannelSetupResult(
            outcome=ChannelSetupOutcome.SKIPPED,
            channel=selection.channel,
            probe=probe,
            identity_ready=identity_ready,
            identity_next_action=identity_next_action,
            config_fragment=fragment,
            retry_allowed=True,
            exit_code=0,
        )

    try:
        startup = await _start_channel(
            name=selection.channel.value,
            channel=channel,
            timeout_seconds=timeout_seconds,
        )
    except RuntimeError:
        return _blocked_result(
            selection,
            fragment,
            reason="channel_probe_cleanup_failed",
            next_action="stop and inspect connector cleanup before retrying setup",
            identity_ready=identity_ready,
            identity_next_action=identity_next_action,
        )
    if not startup.active:
        configured = adapter_setup_readiness(selection.channel, channel)
        if startup.diagnostic["reason_code"] == "channel.dependency_unavailable":
            probe = configured
        else:
            probe = ReadinessStatus(
                state=ReadinessState.DEGRADED,
                configured=True,
                evidence="live_probe",
                reason=str(startup.diagnostic["reason_code"]).replace(".", "_"),
                next_action="check the selected channel configuration and retry explicitly",
                source="channel_setup_probe",
            )
        return ChannelSetupResult(
            outcome=ChannelSetupOutcome.DEGRADED,
            channel=selection.channel,
            probe=probe,
            identity_ready=identity_ready,
            identity_next_action=identity_next_action,
            config_fragment=fragment,
            retry_allowed=True,
            exit_code=2,
        )

    test_delivery: ChannelTestDelivery | None = None
    try:
        async with _cleanup_started_channel(channel, timeout_seconds=timeout_seconds):
            probe = adapter_setup_readiness(selection.channel, channel)
            retry_allowed = True
            if probe.state is ReadinessState.DEGRADED:
                outcome = ChannelSetupOutcome.DEGRADED
                exit_code = 2
            elif not selection.run_test:
                outcome = ChannelSetupOutcome.CONFIGURED
                exit_code = 0
            else:
                delivery = ChannelDeliveryService(
                    {selection.channel.value: channel},
                    state_root=state_root / "delivery",
                )
                try:
                    intent = DeliveryIntent(
                        source_id=f"setup:{selection.channel.value}:{uuid.uuid4().hex}",
                        kind="message_send",
                        target=DeliveryTarget(
                            channel=selection.channel.value,
                            recipient=selection.test_target,
                        ),
                    )
                    try:
                        delivery_result = await asyncio.wait_for(
                            delivery.send(
                                intent=intent,
                                message=CHANNEL_SETUP_TEST_MESSAGE,
                                metadata={"setup_test": True},
                            ),
                            timeout=timeout_seconds,
                        )
                        test_delivery = _delivery_projection(
                            delivery_result,
                            target=selection.test_target,
                        )
                    except TimeoutError:
                        test_delivery = ChannelTestDelivery(
                            attempted=True,
                            sent=False,
                            state="outcome_unknown",
                            outcome_unknown=True,
                            reason="channel_test_timeout",
                            target=selection.test_target,
                        )
                finally:
                    delivery.close()
                if test_delivery.sent:
                    probe = ReadinessStatus(
                        state=ReadinessState.VERIFIED,
                        configured=True,
                        reachable=True,
                        authenticated=True,
                        verified=True,
                        evidence="live_test_delivery",
                        reason="channel_test_delivered",
                        next_action="none",
                        source="channel_setup_delivery",
                    )
                    outcome = ChannelSetupOutcome.VERIFIED
                    retry_allowed = False
                    exit_code = 0
                else:
                    probe = ReadinessStatus(
                        state=ReadinessState.DEGRADED,
                        configured=True,
                        evidence="live_test_delivery",
                        reason=(
                            "channel_test_outcome_unknown"
                            if test_delivery.outcome_unknown
                            else "channel_test_failed_before_effect"
                        ),
                        next_action=(
                            "inspect the explicit target before deciding whether to retry"
                            if test_delivery.outcome_unknown
                            else "correct the delivery target or channel configuration and retry"
                        ),
                        source="channel_setup_delivery",
                    )
                    outcome = ChannelSetupOutcome.DEGRADED
                    retry_allowed = not test_delivery.outcome_unknown
                    exit_code = 2

            if (
                outcome
                in {
                    ChannelSetupOutcome.CONFIGURED,
                    ChannelSetupOutcome.VERIFIED,
                }
                and not identity_ready
            ):
                outcome = ChannelSetupOutcome.DEGRADED
                retry_allowed = True
                exit_code = 2
            return ChannelSetupResult(
                outcome=outcome,
                channel=selection.channel,
                probe=probe,
                identity_ready=identity_ready,
                identity_next_action=identity_next_action,
                config_fragment=fragment,
                test_delivery=test_delivery,
                retry_allowed=retry_allowed,
                exit_code=exit_code,
            )
    except _SetupCleanupError as exc:
        return ChannelSetupResult(
            outcome=ChannelSetupOutcome.BLOCKED,
            channel=selection.channel,
            probe=ReadinessStatus(
                state=ReadinessState.BLOCKED,
                configured=True,
                evidence="live_probe",
                reason=str(exc),
                next_action="stop and inspect connector cleanup before retrying setup",
                source="channel_setup_probe",
            ),
            identity_ready=identity_ready,
            identity_next_action=identity_next_action,
            config_fragment=fragment,
            test_delivery=test_delivery,
            retry_allowed=False,
            exit_code=3,
        )
