"""Egress proxy policy and credential placeholder injection."""

from __future__ import annotations

import fnmatch
import ipaddress
import math
import re
import socket
from collections.abc import Callable
from typing import Protocol
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from shisad.security.credentials import CredentialStore, is_placeholder

_PLACEHOLDER_RE = re.compile(r"SHISAD_SECRET_PLACEHOLDER_[A-Fa-f0-9]{32}")

_PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


class DnsResolver(Protocol):
    """Protocol for DNS resolution injection (testability)."""

    def __call__(self, hostname: str) -> list[str]: ...


class NetworkPolicy(BaseModel):
    """Per-tool network policy."""

    allow_network: bool = False
    allowed_domains: list[str] = Field(default_factory=list)
    deny_private_ranges: bool = True
    deny_ip_literals: bool = True


class ProxyDecision(BaseModel):
    """Outcome of egress proxy evaluation."""

    allowed: bool
    reason: str = ""
    destination_host: str = ""
    destination_port: int | None = None
    protocol: str = "https"
    request_size: int = 0
    resolved_addresses: list[str] = Field(default_factory=list)
    injected_headers: dict[str, str] = Field(default_factory=dict)
    used_placeholders: list[str] = Field(default_factory=list)
    alert: bool = False


class EgressProxy:
    """Policy chokepoint for outbound network requests."""

    def __init__(
        self,
        *,
        credential_store: CredentialStore | None = None,
        audit_hook: Callable[[dict[str, object]], None] | None = None,
        resolver: DnsResolver | None = None,
    ) -> None:
        self._credential_store = credential_store
        self._audit_hook = audit_hook
        self._resolver = resolver or self._default_resolver

    def authorize_request(
        self,
        *,
        tool_name: str,
        url: str,
        policy: NetworkPolicy,
        headers: dict[str, str] | None = None,
        body: str = "",
        approved_by_pep: bool = False,
        expected_addresses: list[str] | None = None,
    ) -> ProxyDecision:
        """Authorize a request and inject credentials if allowed."""
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80

        decision = ProxyDecision(
            allowed=False,
            reason="",
            destination_host=host,
            destination_port=port,
            protocol=(parsed.scheme or "").lower(),
            request_size=len(body.encode("utf-8")),
        )

        if not policy.allow_network:
            decision.reason = "network_disabled"
            self._audit(tool_name=tool_name, url=url, decision=decision, body=body)
            return decision
        if parsed.scheme not in {"http", "https"} or not host:
            decision.reason = "malformed_destination"
            self._audit(tool_name=tool_name, url=url, decision=decision, body=body)
            return decision

        if policy.deny_ip_literals and self._is_ip_literal(host):
            decision.reason = "ip_literal_blocked"
            self._audit(tool_name=tool_name, url=url, decision=decision, body=body)
            return decision
        if not self._host_allowed(host, policy.allowed_domains):
            decision.reason = "host_not_allowlisted"
            decision.alert = bool(_PLACEHOLDER_RE.search(body))
            self._audit(tool_name=tool_name, url=url, decision=decision, body=body)
            return decision
        if self._looks_like_dns_exfil(host):
            decision.reason = "dns_exfil_suspected"
            decision.alert = True
            self._audit(tool_name=tool_name, url=url, decision=decision, body=body)
            return decision

        resolved = self._resolver(host)
        decision.resolved_addresses = list(resolved)
        if not resolved:
            decision.reason = "dns_resolution_failed"
            decision.alert = True
            self._audit(tool_name=tool_name, url=url, decision=decision, body=body)
            return decision
        if expected_addresses and set(expected_addresses) != set(resolved):
            decision.reason = "dns_rebinding_blocked"
            decision.alert = True
            self._audit(tool_name=tool_name, url=url, decision=decision, body=body)
            return decision
        if policy.deny_private_ranges:
            for addr in resolved:
                if self._is_private(addr):
                    decision.reason = "private_range_blocked"
                    self._audit(tool_name=tool_name, url=url, decision=decision, body=body)
                    return decision

        injected_headers = dict(headers or {})
        placeholders_used: list[str] = []
        for key, value in list(injected_headers.items()):
            if not is_placeholder(value):
                continue
            placeholders_used.append(value)
            if not approved_by_pep:
                decision.reason = "pep_not_approved"
                decision.alert = True
                decision.used_placeholders = placeholders_used
                self._audit(tool_name=tool_name, url=url, decision=decision, body=body)
                return decision
            resolved_secret = self._resolve_placeholder(value, host)
            if resolved_secret is None:
                decision.reason = "credential_host_mismatch"
                decision.alert = True
                decision.used_placeholders = placeholders_used
                self._audit(tool_name=tool_name, url=url, decision=decision, body=body)
                return decision
            injected_headers[key] = resolved_secret

        if _PLACEHOLDER_RE.search(body):
            for placeholder in _PLACEHOLDER_RE.findall(body):
                placeholders_used.append(placeholder)
                if not approved_by_pep:
                    decision.reason = "placeholder_exfiltration_blocked"
                    decision.alert = True
                    decision.used_placeholders = placeholders_used
                    self._audit(tool_name=tool_name, url=url, decision=decision, body=body)
                    return decision
                resolved_secret = self._resolve_placeholder(placeholder, host)
                if resolved_secret is None:
                    decision.reason = "placeholder_exfiltration_blocked"
                    decision.alert = True
                    decision.used_placeholders = placeholders_used
                    self._audit(tool_name=tool_name, url=url, decision=decision, body=body)
                    return decision

        decision.allowed = True
        decision.reason = "allowed"
        decision.injected_headers = injected_headers
        decision.used_placeholders = placeholders_used
        self._audit(tool_name=tool_name, url=url, decision=decision, body=body)
        return decision

    def _resolve_placeholder(self, placeholder: str, host: str) -> str | None:
        if self._credential_store is None:
            return None
        return self._credential_store.resolve(placeholder, host)

    def _audit(self, *, tool_name: str, url: str, decision: ProxyDecision, body: str) -> None:
        if self._audit_hook is None:
            return
        self._audit_hook(
            {
                "tool_name": tool_name,
                "url": url,
                "destination_host": decision.destination_host,
                "destination_port": decision.destination_port,
                "allowed": decision.allowed,
                "reason": decision.reason,
                "credential_placeholders": list(decision.used_placeholders),
                "request_size": len(body.encode("utf-8")),
                "alert": decision.alert,
            }
        )

    @staticmethod
    def _host_allowed(host: str, allowed_domains: list[str]) -> bool:
        if not allowed_domains:
            return False
        for raw in allowed_domains:
            value = raw.strip().lower()
            if not value:
                continue
            if fnmatch.fnmatch(host, value):
                return True
        return False

    @staticmethod
    def _is_ip_literal(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return False
        return True

    @staticmethod
    def _is_private(addr: str) -> bool:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        return any(ip in network for network in _PRIVATE_NETWORKS)

    @staticmethod
    def _default_resolver(hostname: str) -> list[str]:
        resolved: list[str] = []
        try:
            infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        except OSError:
            return resolved
        for info in infos:
            sockaddr = info[4]
            if isinstance(sockaddr, tuple) and sockaddr:
                candidate = str(sockaddr[0])
                if candidate not in resolved:
                    resolved.append(candidate)
        return resolved

    def resolve_placeholder(
        self,
        *,
        placeholder: str,
        host: str,
        approved_by_pep: bool,
    ) -> str | None:
        if not approved_by_pep:
            return None
        return self._resolve_placeholder(placeholder, host)

    @classmethod
    def _looks_like_dns_exfil(cls, host: str) -> bool:
        labels = [label for label in host.split(".") if label]
        return any(
            len(label) >= 64 or (len(label) >= 48 and cls._entropy(label) >= 3.8)
            for label in labels
        )

    @staticmethod
    def _entropy(value: str) -> float:
        if not value:
            return 0.0
        counts: dict[str, int] = {}
        for char in value:
            counts[char] = counts.get(char, 0) + 1
        size = len(value)
        entropy = 0.0
        for count in counts.values():
            p = count / size
            entropy -= p * math.log2(p)
        return entropy
