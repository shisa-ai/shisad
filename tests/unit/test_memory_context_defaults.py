from __future__ import annotations

from shisad.memory.context_defaults import resolve_active_attention_defaults


def test_m3_cli_active_attention_defaults_match_scope_contract() -> None:
    defaults = resolve_active_attention_defaults(channel="cli")

    assert defaults is not None
    assert defaults.scope_filter == {"session", "project", "user", "channel"}
    assert defaults.allowed_channel_trusts == {"command", "owner_observed"}


def test_m3_non_cli_active_attention_defaults_are_explicitly_unwired() -> None:
    assert resolve_active_attention_defaults(channel="discord") is None
