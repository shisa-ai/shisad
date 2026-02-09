"""Channel identity mapping primitives."""

from __future__ import annotations

from dataclasses import dataclass

from shisad.core.types import UserId, WorkspaceId


@dataclass(frozen=True)
class ChannelIdentity:
    user_id: UserId
    workspace_id: WorkspaceId
    trust_level: str = "untrusted"


class ChannelIdentityMap:
    """Maps channel identities into shisad user/workspace scope."""

    def __init__(self, *, default_trust: dict[str, str] | None = None) -> None:
        self._map: dict[tuple[str, str], ChannelIdentity] = {}
        self._default_trust = default_trust or {}

    def bind(
        self,
        *,
        channel: str,
        external_user_id: str,
        user_id: UserId,
        workspace_id: WorkspaceId,
        trust_level: str | None = None,
    ) -> None:
        resolved_trust = trust_level or self.trust_for_channel(channel)
        self._map[(channel, external_user_id)] = ChannelIdentity(
            user_id=user_id,
            workspace_id=workspace_id,
            trust_level=resolved_trust,
        )

    def resolve(self, *, channel: str, external_user_id: str) -> ChannelIdentity | None:
        return self._map.get((channel, external_user_id))

    def trust_for_channel(self, channel: str) -> str:
        return self._default_trust.get(channel, "untrusted")

    def configure_channel_trust(self, *, channel: str, trust_level: str) -> None:
        self._default_trust[channel] = trust_level
