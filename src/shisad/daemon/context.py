"""Request-scoped adapter context for control handler dispatch."""

from __future__ import annotations

from dataclasses import dataclass

from shisad.security.firewall import FirewallResult


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Adapter-only runtime context passed alongside validated params."""

    rpc_peer: dict[str, int | None] | None = None
    is_internal_ingress: bool = False
    trust_level_override: str | None = None
    firewall_result: FirewallResult | None = None

