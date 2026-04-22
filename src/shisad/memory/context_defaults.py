"""Context-default memory selection policies for M3 surfaces."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ActiveAttentionDefaults:
    """Default Active Attention filters for a session context."""

    scope_filter: frozenset[str]
    allowed_channel_trusts: frozenset[str]


_CLI_ACTIVE_ATTENTION_DEFAULTS = ActiveAttentionDefaults(
    scope_filter=frozenset({"session", "project", "user", "channel"}),
    allowed_channel_trusts=frozenset({"command", "owner_observed"}),
)


def resolve_active_attention_defaults(*, channel: str) -> ActiveAttentionDefaults | None:
    """Return the current default Active Attention policy for *channel*."""

    normalized = channel.strip().lower()
    if normalized == "cli":
        return _CLI_ACTIVE_ATTENTION_DEFAULTS
    return None
