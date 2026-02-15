"""Channel identity mapping primitives."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from shisad.core.types import UserId, WorkspaceId


@dataclass(frozen=True)
class ChannelIdentity:
    user_id: UserId
    workspace_id: WorkspaceId
    trust_level: str = "untrusted"


@dataclass(frozen=True)
class ChannelPairingRequest:
    channel: str
    external_user_id: str
    workspace_hint: str = ""
    reason: str = "identity_not_allowlisted"
    requested_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class ChannelIdentityMap:
    """Maps channel identities into shisad user/workspace scope."""

    def __init__(
        self,
        *,
        default_trust: dict[str, str] | None = None,
        allowlists: dict[str, set[str]] | None = None,
    ) -> None:
        self._map: dict[tuple[str, str], ChannelIdentity] = {}
        self._default_trust = default_trust or {}
        self._allowlists = allowlists or {}
        self._pairing_requests: dict[tuple[str, str], ChannelPairingRequest] = {}

    def bind(
        self,
        *,
        channel: str,
        external_user_id: str,
        user_id: UserId,
        workspace_id: WorkspaceId,
        trust_level: str | None = None,
    ) -> None:
        normalized_external_user_id = external_user_id.strip()
        resolved_trust = trust_level or self.trust_for_channel(channel)
        self._map[(channel, normalized_external_user_id)] = ChannelIdentity(
            user_id=user_id,
            workspace_id=workspace_id,
            trust_level=resolved_trust,
        )

    def resolve(self, *, channel: str, external_user_id: str) -> ChannelIdentity | None:
        return self._map.get((channel, external_user_id.strip()))

    def trust_for_channel(self, channel: str) -> str:
        return self._default_trust.get(channel, "untrusted")

    def configure_channel_trust(self, *, channel: str, trust_level: str) -> None:
        self._default_trust[channel] = trust_level

    def configure_allowlist(self, *, channel: str, external_user_ids: set[str]) -> None:
        self._allowlists[channel] = {item.strip() for item in external_user_ids if item.strip()}

    def allow_identity(self, *, channel: str, external_user_id: str) -> None:
        current = set(self._allowlists.get(channel, set()))
        candidate = external_user_id.strip()
        if candidate:
            current.add(candidate)
        self._allowlists[channel] = current

    def is_allowed(self, *, channel: str, external_user_id: str) -> bool:
        allowed = self._allowlists.get(channel, set())
        return external_user_id.strip() in allowed

    def record_pairing_request(
        self,
        *,
        channel: str,
        external_user_id: str,
        workspace_hint: str = "",
        reason: str = "identity_not_allowlisted",
    ) -> tuple[ChannelPairingRequest, bool]:
        normalized_external_user_id = external_user_id.strip()
        key = (channel, normalized_external_user_id)
        existing = self._pairing_requests.get(key)
        if existing is not None:
            return existing, False
        request = ChannelPairingRequest(
            channel=channel,
            external_user_id=normalized_external_user_id,
            workspace_hint=workspace_hint,
            reason=reason,
            requested_at=datetime.now(UTC),
        )
        self._pairing_requests[key] = request
        return request, True

    def list_pairing_requests(self, *, limit: int = 100) -> list[ChannelPairingRequest]:
        items = list(self._pairing_requests.values())
        items.sort(key=lambda item: item.requested_at, reverse=True)
        return items[: max(limit, 1)]
