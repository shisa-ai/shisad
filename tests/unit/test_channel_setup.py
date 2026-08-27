"""O2C channel setup, readiness, identity, and test-delivery contracts."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from shisad.channels import setup as channel_setup
from shisad.channels.base import DeliveryTarget, InMemoryChannel
from shisad.core.readiness import ReadinessState, ReadinessStatus
from shisad.security.credential_refs import CredentialReferenceError


class _CredentialStore:
    def __init__(self, values: dict[str, str] | None = None) -> None:
        self.values = (
            values
            if values is not None
            else {
                "channel.matrix": "matrix-secret",
                "channel.discord": "discord-secret",
                "channel.telegram": "telegram-secret",
                "channel.slack.bot": "slack-bot-secret",
                "channel.slack.app": "slack-app-secret",
            }
        )
        self.resolved: list[str] = []

    def resolve(self, name: str) -> str:
        self.resolved.append(name)
        try:
            return self.values[name]
        except KeyError:
            raise CredentialReferenceError("credential_value_unavailable") from None


class _SetupChannel(InMemoryChannel):
    def __init__(self, name: str, *, available: bool = True) -> None:
        super().__init__(name)
        self.available = available
        self.connect_calls = 0
        self.disconnect_calls = 0
        self.send_calls = 0
        self.sent_payloads: list[tuple[str, DeliveryTarget | None]] = []

    async def connect(self) -> None:
        self.connect_calls += 1
        await super().connect()

    async def disconnect(self) -> None:
        self.disconnect_calls += 1
        await super().disconnect()

    async def disconnect_strict(self) -> None:
        await self.disconnect()

    async def send(
        self,
        message: str,
        *,
        target: DeliveryTarget | None = None,
        metadata: dict[str, object] | None = None,
    ):
        self.send_calls += 1
        self.sent_payloads.append((message, target))
        return await super().send(message, target=target, metadata=metadata)

    def setup_readiness(self) -> ReadinessStatus:
        if not self.available:
            return ReadinessStatus(
                state=ReadinessState.ABSENT,
                installed=False,
                configured=True,
                reason="channel_dependency_unavailable",
                next_action="install the optional channel runtime",
                source="channel_setup_probe",
            )
        if not self.connected:
            return ReadinessStatus(
                state=ReadinessState.CONFIGURED,
                configured=True,
                reason="channel_probe_not_run",
                next_action="run the bounded channel probe",
                source="channel_setup_config",
            )
        return ReadinessStatus(
            state=ReadinessState.CONFIGURED,
            configured=True,
            evidence="live_probe",
            reason="channel_transport_started_not_verified",
            next_action="send an explicit test message to verify outbound delivery",
            source="channel_setup_probe",
        )


def _selection(channel: str, *, trusted: bool = True, run_test: bool = False):
    common: dict[str, object] = {
        "channel": channel,
        "trusted_users": ["trusted-user"] if trusted else [],
        "run_test": run_test,
        "test_target": "explicit-target" if run_test else "",
    }
    if channel == "matrix":
        common.update(
            homeserver="https://matrix.example",
            user_id="@bot:example",
            room_id="!room:example",
            access_token_ref="channel.matrix",
        )
    elif channel == "discord":
        common.update(bot_token_ref="channel.discord", default_target="1234")
    elif channel == "telegram":
        common.update(bot_token_ref="channel.telegram", default_target="5678")
    elif channel == "slack":
        common.update(
            bot_token_ref="channel.slack.bot",
            app_token_ref="channel.slack.app",
            default_target="C1234",
        )
    return channel_setup.ChannelSetupSelection(**common)


@pytest.mark.parametrize(
    ("channel", "expected"),
    [
        (
            "matrix",
            {
                "matrix_enabled": True,
                "matrix_homeserver": "https://matrix.example",
                "matrix_user_id": "@bot:example",
                "matrix_access_token_ref": "channel.matrix",
                "matrix_room_id": "!room:example",
                "matrix_e2ee": True,
                "matrix_trusted_users": ["trusted-user"],
            },
        ),
        (
            "discord",
            {
                "discord_enabled": True,
                "discord_bot_token_ref": "channel.discord",
                "discord_default_channel_id": "1234",
                "discord_trusted_users": ["trusted-user"],
            },
        ),
        (
            "telegram",
            {
                "telegram_enabled": True,
                "telegram_bot_token_ref": "channel.telegram",
                "telegram_default_chat_id": "5678",
                "telegram_trusted_users": ["trusted-user"],
            },
        ),
        (
            "slack",
            {
                "slack_enabled": True,
                "slack_bot_token_ref": "channel.slack.bot",
                "slack_app_token_ref": "channel.slack.app",
                "slack_default_channel_id": "C1234",
                "slack_trusted_users": ["trusted-user"],
            },
        ),
    ],
)
def test_o2c_four_channel_selections_emit_exact_secret_free_fragments(
    channel: str,
    expected: dict[str, object],
) -> None:
    config, fragment = channel_setup.build_channel_setup_config(_selection(channel))

    assert fragment == expected
    assert config.model_dump(include=set(expected)) == expected
    serialized = json.dumps(fragment)
    for secret in _CredentialStore().values.values():
        assert secret not in serialized


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"channel": "matrix", "access_token_ref": "channel.matrix"}, "homeserver"),
        ({"channel": "discord"}, "bot-token reference"),
        (
            {
                "channel": "telegram",
                "bot_token_ref": "channel.telegram",
                "app_token_ref": "channel.slack.app",
            },
            "does not accept",
        ),
        ({"channel": "slack", "bot_token_ref": "channel.slack.bot"}, "app-token"),
        (
            {
                "channel": "discord",
                "bot_token_ref": "channel.discord",
                "run_test": True,
            },
            "explicit test target",
        ),
        (
            {
                "channel": "discord",
                "bot_token_ref": "channel.discord",
                "test_target": "1234",
            },
            "requires --send-test",
        ),
        (
            {
                "channel": "discord",
                "bot_token_ref": "bad/ref",
            },
            "credential reference name",
        ),
        (
            {
                "channel": "slack",
                "bot_token_ref": "channel.slack.same",
                "app_token_ref": "channel.slack.same",
            },
            "distinct",
        ),
        (
            {
                "channel": "matrix",
                "homeserver": "https://user:secret@matrix.example",
                "user_id": "@bot:example",
                "room_id": "!room:example",
                "access_token_ref": "channel.matrix",
            },
            "cannot contain credentials",
        ),
    ],
)
def test_o2c_selection_rejects_missing_cross_channel_or_implicit_effect_input(
    kwargs: dict[str, object],
    match: str,
) -> None:
    with pytest.raises(ValueError, match=match):
        channel_setup.ChannelSetupSelection(**kwargs)


def test_o2c_fragment_validation_ignores_ambient_channel_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_DISCORD_BOT_TOKEN", "ambient-raw-secret")
    monkeypatch.setenv("SHISAD_TELEGRAM_ENABLED", "true")
    monkeypatch.setenv("SHISAD_TELEGRAM_BOT_TOKEN_REF", "channel.telegram.ambient")
    store = _CredentialStore()

    config, fragment = channel_setup.build_channel_setup_config(_selection("discord"))
    channel_setup._build_setup_channel(
        _selection("discord"),
        credential_store=store,
        state_root=tmp_path,
    )

    assert config.discord_bot_token == ""
    assert config.discord_bot_token_ref == "channel.discord"
    assert config.telegram_enabled is False
    assert fragment["discord_bot_token_ref"] == "channel.discord"
    assert store.resolved == ["channel.discord"]


@pytest.mark.parametrize(
    ("channel", "resolved"),
    [
        ("matrix", ["channel.matrix"]),
        ("discord", ["channel.discord"]),
        ("telegram", ["channel.telegram"]),
        ("slack", ["channel.slack.bot", "channel.slack.app"]),
    ],
)
def test_o2c_adapter_construction_resolves_only_selected_references(
    tmp_path: Path,
    channel: str,
    resolved: list[str],
) -> None:
    store = _CredentialStore()

    adapter = channel_setup._build_setup_channel(
        _selection(channel),
        credential_store=store,
        state_root=tmp_path,
    )

    assert store.resolved == resolved
    assert adapter is not None


@pytest.mark.asyncio
async def test_o2c_skip_resolves_config_but_performs_no_connector_or_delivery_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _SetupChannel("discord")
    monkeypatch.setattr(channel_setup, "_build_setup_channel", lambda *args, **kwargs: fake)

    result = await channel_setup.evaluate_channel_setup(
        _selection("discord"),
        credential_store=_CredentialStore(),
        state_root=tmp_path,
        skip_probe=True,
    )

    assert result.outcome is channel_setup.ChannelSetupOutcome.SKIPPED
    assert result.probe.evidence == "not_run"
    assert result.probe.verified is False
    assert fake.connect_calls == 0
    assert fake.send_calls == 0


@pytest.mark.asyncio
async def test_o2c_connector_start_is_configured_not_verified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _SetupChannel("telegram")
    monkeypatch.setattr(channel_setup, "_build_setup_channel", lambda *args, **kwargs: fake)

    result = await channel_setup.evaluate_channel_setup(
        _selection("telegram"),
        credential_store=_CredentialStore(),
        state_root=tmp_path,
    )

    assert result.outcome is channel_setup.ChannelSetupOutcome.CONFIGURED
    assert result.probe.state is ReadinessState.CONFIGURED
    assert result.probe.authenticated is False
    assert result.probe.verified is False
    assert fake.connect_calls == 1
    assert fake.disconnect_calls == 1


@pytest.mark.asyncio
async def test_o2c_empty_allowlist_remains_default_deny_and_non_green(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _SetupChannel("discord")
    monkeypatch.setattr(channel_setup, "_build_setup_channel", lambda *args, **kwargs: fake)

    result = await channel_setup.evaluate_channel_setup(
        _selection("discord", trusted=False),
        credential_store=_CredentialStore(),
        state_root=tmp_path,
    )

    assert result.outcome is channel_setup.ChannelSetupOutcome.DEGRADED
    assert result.identity_ready is False
    assert "trusted" in result.identity_next_action
    assert result.config_fragment["discord_trusted_users"] == []


@pytest.mark.asyncio
async def test_o2c_delivered_test_with_empty_allowlist_is_not_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _SetupChannel("discord")
    monkeypatch.setattr(channel_setup, "_build_setup_channel", lambda *args, **kwargs: fake)

    result = await channel_setup.evaluate_channel_setup(
        _selection("discord", trusted=False, run_test=True),
        credential_store=_CredentialStore(),
        state_root=tmp_path,
    )

    assert result.outcome is channel_setup.ChannelSetupOutcome.DEGRADED
    assert result.test_delivery is not None
    assert result.test_delivery.sent is True
    assert result.retry_allowed is False


@pytest.mark.asyncio
async def test_o2c_explicit_test_delivery_uses_one_normal_attempt_and_fixed_notice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _SetupChannel("slack")
    monkeypatch.setattr(channel_setup, "_build_setup_channel", lambda *args, **kwargs: fake)

    result = await channel_setup.evaluate_channel_setup(
        _selection("slack", run_test=True),
        credential_store=_CredentialStore(),
        state_root=tmp_path,
    )

    assert result.outcome is channel_setup.ChannelSetupOutcome.VERIFIED
    assert result.probe.state is ReadinessState.VERIFIED
    assert result.test_delivery is not None
    assert result.test_delivery.sent is True
    assert result.test_delivery.target == "explicit-target"
    assert fake.send_calls == 1
    assert fake.sent_payloads[0][0] == channel_setup.CHANNEL_SETUP_TEST_MESSAGE
    assert fake.sent_payloads[0][1] is not None
    assert fake.sent_payloads[0][1].recipient == "explicit-target"
    assert fake.disconnect_calls == 1
    assert not (tmp_path / "delivery").exists()
    assert (tmp_path / "setup-delivery").is_dir()


@pytest.mark.asyncio
async def test_o2c_uncertain_test_effect_is_never_automatically_retried(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _UncertainChannel(_SetupChannel):
        async def send(self, message: str, **kwargs):
            self.send_calls += 1
            raise RuntimeError("provider detail must not escape")

    fake = _UncertainChannel("matrix")
    monkeypatch.setattr(channel_setup, "_build_setup_channel", lambda *args, **kwargs: fake)

    result = await channel_setup.evaluate_channel_setup(
        _selection("matrix", run_test=True),
        credential_store=_CredentialStore(),
        state_root=tmp_path,
    )

    assert result.outcome is channel_setup.ChannelSetupOutcome.DEGRADED
    assert result.test_delivery is not None
    assert result.test_delivery.outcome_unknown is True
    assert result.test_delivery.state == "outcome_unknown"
    assert result.retry_allowed is False
    assert fake.send_calls == 1
    assert "provider detail" not in result.model_dump_json()


@pytest.mark.asyncio
async def test_o2c_pre_effect_test_failure_is_explicitly_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _DisconnectedBeforeEffectChannel(_SetupChannel):
        def health_status(self) -> dict[str, object]:
            status = super().health_status()
            status["connected"] = False
            return status

    fake = _DisconnectedBeforeEffectChannel("discord")
    monkeypatch.setattr(channel_setup, "_build_setup_channel", lambda *args, **kwargs: fake)

    result = await channel_setup.evaluate_channel_setup(
        _selection("discord", run_test=True),
        credential_store=_CredentialStore(),
        state_root=tmp_path,
    )

    assert result.outcome is channel_setup.ChannelSetupOutcome.DEGRADED
    assert result.test_delivery is not None
    assert result.test_delivery.attempted is False
    assert result.test_delivery.state == "failed_pre_effect"
    assert result.test_delivery.outcome_unknown is False
    assert result.retry_allowed is True
    assert fake.send_calls == 0
    assert fake.disconnect_calls == 1


@pytest.mark.asyncio
async def test_o2c_cleanup_failure_is_blocked_and_not_safe_to_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _CleanupFailureChannel(_SetupChannel):
        async def disconnect_strict(self) -> None:
            raise RuntimeError("provider cleanup detail must not escape")

    fake = _CleanupFailureChannel("slack")
    monkeypatch.setattr(channel_setup, "_build_setup_channel", lambda *args, **kwargs: fake)

    result = await channel_setup.evaluate_channel_setup(
        _selection("slack", run_test=True),
        credential_store=_CredentialStore(),
        state_root=tmp_path,
    )

    assert result.outcome is channel_setup.ChannelSetupOutcome.BLOCKED
    assert result.probe.reason == "channel_probe_cleanup_failed"
    assert result.test_delivery is not None
    assert result.test_delivery.sent is True
    assert result.retry_allowed is False
    assert "provider cleanup detail" not in result.model_dump_json()


@pytest.mark.asyncio
async def test_o2c_startup_cleanup_failure_is_blocked_and_not_safe_to_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _startup_cleanup_failed(**kwargs):
        _ = kwargs
        raise RuntimeError("provider startup cleanup detail must not escape")

    monkeypatch.setattr(channel_setup, "_start_channel", _startup_cleanup_failed)

    result = await channel_setup.evaluate_channel_setup(
        _selection("telegram"),
        credential_store=_CredentialStore(),
        state_root=tmp_path,
    )

    assert result.outcome is channel_setup.ChannelSetupOutcome.BLOCKED
    assert result.probe.reason == "channel_probe_cleanup_failed"
    assert result.retry_allowed is False
    assert "provider startup cleanup detail" not in result.model_dump_json()


@pytest.mark.asyncio
async def test_o2c_delivery_timeout_is_unknown_and_requires_target_inspection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _TimeoutChannel(_SetupChannel):
        async def send(self, message: str, **kwargs):
            self.send_calls += 1
            await asyncio.Event().wait()

    fake = _TimeoutChannel("matrix")
    monkeypatch.setattr(channel_setup, "_build_setup_channel", lambda *args, **kwargs: fake)

    result = await channel_setup.evaluate_channel_setup(
        _selection("matrix", run_test=True),
        credential_store=_CredentialStore(),
        state_root=tmp_path,
        timeout_seconds=0.1,
    )

    assert result.test_delivery is not None
    assert result.test_delivery.reason == "channel_test_timeout"
    assert result.test_delivery.outcome_unknown is True
    assert result.retry_allowed is False
    assert "inspect" in result.probe.next_action
    assert fake.send_calls == 1
    assert fake.disconnect_calls == 1


@pytest.mark.asyncio
async def test_o2c_non_dependency_startup_failure_is_degraded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _startup_failed(**kwargs):
        _ = kwargs
        return SimpleNamespace(
            active=False,
            diagnostic={"reason_code": "channel.startup_error"},
        )

    monkeypatch.setattr(channel_setup, "_start_channel", _startup_failed)

    result = await channel_setup.evaluate_channel_setup(
        _selection("telegram"),
        credential_store=_CredentialStore(),
        state_root=tmp_path,
    )

    assert result.outcome is channel_setup.ChannelSetupOutcome.DEGRADED
    assert result.probe.reason == "channel_startup_error"
    assert result.retry_allowed is True


@pytest.mark.asyncio
async def test_o2c_external_test_cancellation_still_cleans_started_connector(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    send_started = asyncio.Event()

    class _CancelledChannel(_SetupChannel):
        async def send(self, message: str, **kwargs):
            self.send_calls += 1
            send_started.set()
            await asyncio.Event().wait()

    fake = _CancelledChannel("telegram")
    monkeypatch.setattr(channel_setup, "_build_setup_channel", lambda *args, **kwargs: fake)
    task = asyncio.create_task(
        channel_setup.evaluate_channel_setup(
            _selection("telegram", run_test=True),
            credential_store=_CredentialStore(),
            state_root=tmp_path,
        )
    )
    await send_started.wait()
    task.cancel()

    result = await task

    assert result.outcome is channel_setup.ChannelSetupOutcome.DEGRADED
    assert result.test_delivery is not None
    assert result.test_delivery.reason == "channel_test_cancelled"
    assert result.test_delivery.outcome_unknown is True
    assert result.retry_allowed is False
    assert "inspect" in result.probe.next_action
    assert fake.send_calls == 1
    assert fake.disconnect_calls == 1


@pytest.mark.asyncio
async def test_o2c_unavailable_reference_blocks_before_connector_activity(
    tmp_path: Path,
) -> None:
    store = _CredentialStore(values={})

    result = await channel_setup.evaluate_channel_setup(
        _selection("discord"),
        credential_store=store,
        state_root=tmp_path,
    )

    assert result.outcome is channel_setup.ChannelSetupOutcome.BLOCKED
    assert result.probe.reason == "channel_credential_unavailable"
    assert result.exit_code == 3
    assert store.resolved == ["channel.discord"]


@pytest.mark.parametrize("timeout_seconds", [0.09, 30.01, float("nan")])
@pytest.mark.asyncio
async def test_o2c_probe_timeout_is_finitely_bounded(
    tmp_path: Path,
    timeout_seconds: float,
) -> None:
    with pytest.raises(ValueError, match=r"between 0\.1 and 30"):
        await channel_setup.evaluate_channel_setup(
            _selection("discord"),
            credential_store=_CredentialStore(),
            state_root=tmp_path,
            timeout_seconds=timeout_seconds,
        )


@pytest.mark.asyncio
async def test_o2c_skip_cannot_be_combined_with_test_delivery(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="cannot be combined"):
        await channel_setup.evaluate_channel_setup(
            _selection("discord", run_test=True),
            credential_store=_CredentialStore(),
            state_root=tmp_path,
            skip_probe=True,
        )
