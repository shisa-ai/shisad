"""Context-default memory selection policies for M3 surfaces."""

from __future__ import annotations

from dataclasses import dataclass

from shisad.channels.base import DeliveryTarget
from shisad.memory.participation import compose_channel_binding


@dataclass(frozen=True, slots=True)
class ActiveAttentionDefaults:
    """Default Active Attention filters for a session context."""

    scope_filter: frozenset[str]
    allowed_channel_trusts: frozenset[str] | None = None
    channel_binding: str | None = None


_CLI_ACTIVE_ATTENTION_DEFAULTS = ActiveAttentionDefaults(
    scope_filter=frozenset({"session", "project", "user", "channel"}),
    allowed_channel_trusts=frozenset({"command", "owner_observed"}),
)
_CONNECTOR_ACTIVE_ATTENTION_SCOPE_FILTER = frozenset({"session", "user", "channel"})
_OWNER_OBSERVED_CHANNEL_TRUSTS = frozenset({"owner_observed"})


def resolve_active_attention_defaults(
    *,
    channel: str,
    delivery_target: DeliveryTarget | None = None,
) -> ActiveAttentionDefaults | None:
    """Return the current default Active Attention policy for *channel*."""

    normalized = channel.strip().lower()
    if normalized == "cli":
        return _CLI_ACTIVE_ATTENTION_DEFAULTS
    if normalized in {"discord", "slack"} and delivery_target is not None:
        return _resolve_connector_active_attention_defaults(
            channel=normalized,
            delivery_target=delivery_target,
        )
    return None


def _resolve_connector_active_attention_defaults(
    *,
    channel: str,
    delivery_target: DeliveryTarget,
) -> ActiveAttentionDefaults | None:
    recipient = delivery_target.recipient.strip()
    if _looks_like_owner_dm(channel=channel, delivery_target=delivery_target):
        return ActiveAttentionDefaults(
            scope_filter=_CONNECTOR_ACTIVE_ATTENTION_SCOPE_FILTER,
            allowed_channel_trusts=_OWNER_OBSERVED_CHANNEL_TRUSTS,
        )
    if recipient:
        return ActiveAttentionDefaults(
            scope_filter=_CONNECTOR_ACTIVE_ATTENTION_SCOPE_FILTER,
            channel_binding=compose_channel_binding(
                channel=channel,
                workspace_hint=delivery_target.workspace_hint,
                channel_id=recipient,
            ),
        )
    return None


def _looks_like_owner_dm(*, channel: str, delivery_target: DeliveryTarget) -> bool:
    workspace_hint = delivery_target.workspace_hint.strip().lower()
    recipient = delivery_target.recipient.strip()
    if channel == "discord":
        return workspace_hint == "discord"
    if channel == "slack":
        return recipient.upper().startswith("D")
    return False
