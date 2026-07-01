"""Lightweight Discord approval component helpers.

This module intentionally avoids importing the optional Discord runtime so
daemon handlers can build pending-approval metadata without loading discord.py.
"""

from __future__ import annotations

from dataclasses import dataclass

_DISCORD_APPROVAL_CUSTOM_ID_PREFIX = "shisad:approval:v1"
_DISCORD_APPROVAL_ACTIONS = {"confirm", "reject", "totp", "totp_submit"}

DISCORD_VIEW_COMPONENT_LIMIT = 25


@dataclass(frozen=True, slots=True)
class DiscordApprovalInteraction:
    action: str
    confirmation_id: str
    decision_nonce: str


def discord_approval_custom_id(
    *,
    action: str,
    confirmation_id: str,
    decision_nonce: str,
) -> str:
    normalized_action = action.strip().lower()
    normalized_confirmation_id = confirmation_id.strip()
    normalized_nonce = decision_nonce.strip()
    if normalized_action not in _DISCORD_APPROVAL_ACTIONS:
        raise ValueError("unsupported Discord approval action")
    if (
        not normalized_confirmation_id
        or not normalized_nonce
        or ":" in normalized_confirmation_id
        or ":" in normalized_nonce
    ):
        raise ValueError("Discord approval custom id requires id and nonce")
    return (
        f"{_DISCORD_APPROVAL_CUSTOM_ID_PREFIX}:"
        f"{normalized_action}:{normalized_confirmation_id}:{normalized_nonce}"
    )


def parse_discord_approval_custom_id(custom_id: str) -> DiscordApprovalInteraction | None:
    parts = custom_id.strip().split(":")
    prefix_parts = _DISCORD_APPROVAL_CUSTOM_ID_PREFIX.split(":")
    if len(parts) != len(prefix_parts) + 3:
        return None
    if parts[: len(prefix_parts)] != prefix_parts:
        return None
    action = parts[len(prefix_parts)].strip().lower()
    confirmation_id = parts[len(prefix_parts) + 1].strip()
    decision_nonce = parts[len(prefix_parts) + 2].strip()
    if action not in _DISCORD_APPROVAL_ACTIONS or not confirmation_id or not decision_nonce:
        return None
    return DiscordApprovalInteraction(
        action=action,
        confirmation_id=confirmation_id,
        decision_nonce=decision_nonce,
    )
