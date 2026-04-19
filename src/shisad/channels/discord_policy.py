"""Discord public-channel policy resolution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from shisad.core.tools.names import canonical_tool_name

DiscordEngagementMode = Literal["mention-only", "read-along", "passive-observe"]

_VALID_MODES = {"mention-only", "read-along", "passive-observe"}


def _normalize_text(value: object) -> str:
    return str(value or "").strip()


def _normalize_list(values: object) -> list[str]:
    if isinstance(values, str):
        return [item.strip() for item in values.split(",") if item.strip()]
    if isinstance(values, list):
        return [str(item).strip() for item in values if str(item).strip()]
    if isinstance(values, tuple | set):
        return [str(item).strip() for item in values if str(item).strip()]
    return []


def _normalize_tools(values: object) -> list[str]:
    normalized = _normalize_list(values)
    canonical: list[str] = []
    seen: set[str] = set()
    for item in normalized:
        tool = canonical_tool_name(str(item))
        if not tool or tool in seen:
            continue
        seen.add(tool)
        canonical.append(tool)
    return sorted(canonical)


class DiscordChannelRule(BaseModel):
    """Operator-configured Discord server/channel rule.

    Empty ``channels`` means every channel in the guild except explicit
    ``exclude_channels`` entries. Explicit channel/user denies win before
    public/trusted-guest grants are considered.
    """

    guild_id: str = "*"
    channels: list[str] = Field(default_factory=list)
    exclude_channels: list[str] = Field(default_factory=list)
    mode: DiscordEngagementMode = "mention-only"
    public_enabled: bool = False
    public_tools: list[str] = Field(default_factory=list)
    trusted_guest_users: list[str] = Field(default_factory=list)
    trusted_guest_tools: list[str] = Field(default_factory=list)
    denied_users: list[str] = Field(default_factory=list)
    relevance_keywords: list[str] = Field(default_factory=list)
    cooldown_seconds: float = Field(default=60.0, ge=0.0)
    proactive_marker: str = "[proactive]"

    @field_validator("guild_id", "mode", "proactive_marker", mode="before")
    @classmethod
    def _normalize_scalar(cls, value: object) -> object:
        return _normalize_text(value)

    @field_validator(
        "channels",
        "exclude_channels",
        "trusted_guest_users",
        "denied_users",
        "relevance_keywords",
        mode="before",
    )
    @classmethod
    def _normalize_string_list(cls, value: object) -> object:
        return _normalize_list(value)

    @field_validator("public_tools", "trusted_guest_tools", mode="before")
    @classmethod
    def _normalize_tool_list(cls, value: object) -> object:
        return _normalize_tools(value)

    @field_validator("mode")
    @classmethod
    def _validate_mode(cls, value: str) -> DiscordEngagementMode:
        candidate = value.strip().lower()
        if candidate not in _VALID_MODES:
            raise ValueError(f"unsupported Discord engagement mode: {value}")
        return candidate  # type: ignore[return-value]

    @field_validator("guild_id")
    @classmethod
    def _default_guild(cls, value: str) -> str:
        return value or "*"

    @field_validator("proactive_marker")
    @classmethod
    def _default_marker(cls, value: str) -> str:
        return value or "[proactive]"

    def guild_matches(self, guild_id: str) -> bool:
        rule_guild = self.guild_id.strip()
        return rule_guild == "*" or rule_guild == guild_id.strip()

    def channel_matches(self, channel_id: str) -> bool:
        channel = channel_id.strip()
        if channel in set(self.exclude_channels):
            return False
        includes = {item.strip() for item in self.channels if item.strip()}
        return not includes or channel in includes

    def denies_channel(self, channel_id: str) -> bool:
        excluded = {item.strip() for item in self.exclude_channels if item.strip()}
        return channel_id.strip() in excluded

    def denies_user(self, external_user_id: str) -> bool:
        return external_user_id.strip() in {
            item.strip() for item in self.denied_users if item.strip()
        }

    def specificity(self, *, guild_id: str, channel_id: str) -> tuple[int, int]:
        guild_score = 2 if self.guild_id.strip() == guild_id.strip() else 1
        channel_score = 2 if channel_id.strip() in set(self.channels) else 1
        return guild_score, channel_score


@dataclass(frozen=True, slots=True)
class DiscordRelevanceDecision:
    relevant: bool
    matched_keywords: tuple[str, ...] = ()
    reason: str = ""


@dataclass(frozen=True, slots=True)
class DiscordChannelPolicyDecision:
    engagement_mode: str = "mention-only"
    public_access: bool = False
    trust_level: str = "untrusted"
    allowed_tools: tuple[str, ...] = ()
    denied: bool = False
    reason: str = "no_matching_rule"
    cooldown_seconds: float = 60.0
    relevance_keywords: tuple[str, ...] = ()
    proactive_marker: str = "[proactive]"

    def relevance_for(self, content: str) -> DiscordRelevanceDecision:
        if self.engagement_mode != "read-along":
            return DiscordRelevanceDecision(False, reason="not_read_along")
        lowered = content.casefold()
        matches = tuple(
            keyword
            for keyword in self.relevance_keywords
            if keyword and keyword.casefold() in lowered
        )
        if not matches:
            return DiscordRelevanceDecision(False, reason="read_along_not_relevant")
        return DiscordRelevanceDecision(True, matched_keywords=matches, reason="keyword_match")


class DiscordChannelPolicy:
    """Resolve Discord guild/channel rules into runtime ingress decisions."""

    def __init__(self, rules: list[DiscordChannelRule] | tuple[DiscordChannelRule, ...]) -> None:
        self._rules = tuple(DiscordChannelRule.model_validate(rule) for rule in rules)

    def resolve(
        self,
        *,
        guild_id: str,
        channel_id: str,
        external_user_id: str,
    ) -> DiscordChannelPolicyDecision:
        guild = guild_id.strip()
        channel = channel_id.strip()
        user = external_user_id.strip()
        if not guild or not channel:
            return DiscordChannelPolicyDecision()
        guild_rules = [rule for rule in self._rules if rule.guild_matches(guild)]
        if not guild_rules:
            return DiscordChannelPolicyDecision()

        for rule in guild_rules:
            if rule.denies_channel(channel) or (
                rule.channel_matches(channel) and rule.denies_user(user)
            ):
                return DiscordChannelPolicyDecision(
                    engagement_mode=rule.mode,
                    denied=True,
                    reason="channel_policy_denied",
                    cooldown_seconds=float(rule.cooldown_seconds),
                    relevance_keywords=tuple(sorted(set(rule.relevance_keywords))),
                    proactive_marker=rule.proactive_marker,
                )

        matching = [rule for rule in guild_rules if rule.channel_matches(channel)]
        if not matching:
            return DiscordChannelPolicyDecision()

        selected = sorted(
            enumerate(matching),
            key=lambda item: (
                item[1].specificity(guild_id=guild, channel_id=channel),
                -item[0],
            ),
            reverse=True,
        )[0][1]

        trusted_guests = {item.strip() for item in selected.trusted_guest_users if item.strip()}
        if user in trusted_guests:
            return DiscordChannelPolicyDecision(
                engagement_mode=selected.mode,
                public_access=True,
                trust_level="trusted_guest",
                allowed_tools=tuple(sorted(set(selected.trusted_guest_tools))),
                reason="trusted_guest_grant",
                cooldown_seconds=float(selected.cooldown_seconds),
                relevance_keywords=tuple(sorted(set(selected.relevance_keywords))),
                proactive_marker=selected.proactive_marker,
            )

        public_access = bool(selected.public_enabled)
        return DiscordChannelPolicyDecision(
            engagement_mode=selected.mode,
            public_access=public_access,
            trust_level="public" if public_access else "untrusted",
            allowed_tools=tuple(sorted(set(selected.public_tools))) if public_access else (),
            reason="public_grant" if public_access else "rule_without_public_grant",
            cooldown_seconds=float(selected.cooldown_seconds),
            relevance_keywords=tuple(sorted(set(selected.relevance_keywords))),
            proactive_marker=selected.proactive_marker,
        )
