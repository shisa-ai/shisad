from __future__ import annotations

from shisad.channels.base import DeliveryTarget
from shisad.memory.context_defaults import resolve_active_attention_defaults


def test_m3_cli_active_attention_defaults_match_scope_contract() -> None:
    defaults = resolve_active_attention_defaults(channel="cli")

    assert defaults is not None
    assert defaults.scope_filter == {"session", "project", "user", "channel"}
    assert defaults.allowed_channel_trusts == {"command", "owner_observed"}
    assert defaults.channel_binding is None


def test_m3_discord_channel_active_attention_defaults_bind_current_channel() -> None:
    defaults = resolve_active_attention_defaults(
        channel="discord",
        delivery_target=DeliveryTarget(
            channel="discord",
            recipient="general",
            workspace_hint="guild-1",
        ),
    )

    assert defaults is not None
    assert defaults.scope_filter == {"session", "user", "channel"}
    assert defaults.allowed_channel_trusts is None
    assert defaults.channel_binding == "general"


def test_m3_discord_dm_active_attention_defaults_use_owner_observed_channels() -> None:
    defaults = resolve_active_attention_defaults(
        channel="discord",
        delivery_target=DeliveryTarget(
            channel="discord",
            recipient="dm-1",
            workspace_hint="discord",
        ),
    )

    assert defaults is not None
    assert defaults.scope_filter == {"session", "user", "channel"}
    assert defaults.allowed_channel_trusts == {"owner_observed"}
    assert defaults.channel_binding is None


def test_m3_unknown_non_cli_active_attention_defaults_remain_unwired() -> None:
    assert resolve_active_attention_defaults(channel="a2a") is None
