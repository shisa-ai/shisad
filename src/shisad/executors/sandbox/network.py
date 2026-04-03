"""Sandbox network decision and credential injection components."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Protocol
from urllib.parse import urlparse

from shisad.executors.proxy import EgressProxy, NetworkPolicy, ProxyDecision
from shisad.security.credentials import is_placeholder

_NETWORK_EXECUTABLES = {
    "curl",
    "wget",
    "nc",
    "ncat",
    "telnet",
    "ping",
    "nslookup",
    "dig",
    "host",
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "ftp",
    "socat",
}
_DOMAIN_TOKEN_RE = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?::\d+)?$")
_PLACEHOLDER_RE = re.compile(r"SHISAD_SECRET_PLACEHOLDER_[A-Fa-f0-9]{32}")
_WILDCARD_TOKENS = {"*", "?", "[", "]"}


class SandboxNetworkComponent(Protocol):
    """Protocol for sandbox network policy component."""

    def extract_network_targets(self, command: list[str]) -> list[str]: ...

    def command_attempts_network(self, command: list[str]) -> bool: ...

    def authorize_requests(
        self,
        *,
        tool_name: str,
        urls: list[str],
        policy: NetworkPolicy,
        request_headers: dict[str, str],
        request_body: str,
        approved_by_pep: bool,
    ) -> tuple[list[ProxyDecision], str | None]: ...

    def revalidate_requests(
        self,
        *,
        tool_name: str,
        urls: list[str],
        policy: NetworkPolicy,
        prior_decisions: list[ProxyDecision],
        approved_by_pep: bool,
    ) -> str | None: ...

    def resolve_connect_path_scope_addresses(
        self,
        *,
        policy: NetworkPolicy,
    ) -> list[str]: ...

    def inject_credentials(
        self,
        *,
        command: list[str],
        env: dict[str, str],
        network_decisions: list[ProxyDecision],
        approved_by_pep: bool,
    ) -> tuple[list[str], dict[str, str], str | None]: ...


class SandboxNetworkManager:
    """Default network policy manager used by sandbox orchestrator."""

    def __init__(self, proxy: EgressProxy) -> None:
        self._proxy = proxy

    def extract_network_targets(self, command: list[str]) -> list[str]:
        targets: list[str] = []
        for token in command:
            if token.startswith(("http://", "https://")):
                targets.append(token)
                continue
            if token.startswith("--url="):
                targets.append(token.split("=", 1)[1])
                continue
            if token.startswith(("ftp://", "ftps://")):
                targets.append(token.replace("ftp://", "https://", 1))
                continue
            if "=" in token:
                _, rhs = token.split("=", 1)
                if rhs.startswith(("http://", "https://")):
                    targets.append(rhs)
                    continue
            if _DOMAIN_TOKEN_RE.match(token):
                host = token
                if "://" in host:
                    parsed = urlparse(host)
                    host = parsed.hostname or ""
                if host:
                    targets.append(f"https://{host}/")
        if command and Path(command[0]).name in {"nslookup", "dig", "host"} and len(command) >= 2:
            host = command[-1].strip()
            if host and "://" not in host:
                targets.append(f"https://{host}/")
        deduped: list[str] = []
        seen: set[str] = set()
        for target in targets:
            if target not in seen:
                deduped.append(target)
                seen.add(target)
        return deduped

    def command_attempts_network(self, command: list[str]) -> bool:
        if not command:
            return False
        executable = Path(command[0]).name
        if executable in _NETWORK_EXECUTABLES:
            return True
        return any(
            token.startswith(("http://", "https://", "ftp://", "ftps://"))
            or _DOMAIN_TOKEN_RE.match(token)
            for token in command[1:]
        )

    def authorize_requests(
        self,
        *,
        tool_name: str,
        urls: list[str],
        policy: NetworkPolicy,
        request_headers: dict[str, str],
        request_body: str,
        approved_by_pep: bool,
    ) -> tuple[list[ProxyDecision], str | None]:
        decisions: list[ProxyDecision] = []
        for url in urls:
            decision = self._proxy.authorize_request(
                tool_name=tool_name,
                url=url,
                policy=policy,
                headers=request_headers,
                body=request_body,
                approved_by_pep=approved_by_pep,
            )
            decisions.append(decision)
            if not decision.allowed:
                return decisions, decision.reason
        return decisions, None

    def revalidate_requests(
        self,
        *,
        tool_name: str,
        urls: list[str],
        policy: NetworkPolicy,
        prior_decisions: list[ProxyDecision],
        approved_by_pep: bool,
    ) -> str | None:
        if len(urls) != len(prior_decisions):
            return "revalidation_decision_mismatch"
        for url, prior in zip(urls, prior_decisions, strict=True):
            revalidated = self._proxy.authorize_request(
                tool_name=tool_name,
                url=url,
                policy=policy,
                approved_by_pep=approved_by_pep,
                expected_addresses=list(prior.resolved_addresses),
            )
            if not revalidated.allowed:
                return revalidated.reason
        return None

    def resolve_connect_path_scope_addresses(
        self,
        *,
        policy: NetworkPolicy,
    ) -> list[str]:
        addresses: list[str] = []
        seen: set[str] = set()
        for raw_scope in policy.allowed_domains:
            probe_url = self._connect_path_probe_url(raw_scope)
            if not probe_url:
                continue
            for address in self._proxy.resolve_scope_addresses(url=probe_url, policy=policy):
                if address in seen:
                    continue
                addresses.append(address)
                seen.add(address)
        return addresses

    def inject_credentials(
        self,
        *,
        command: list[str],
        env: dict[str, str],
        network_decisions: list[ProxyDecision],
        approved_by_pep: bool,
    ) -> tuple[list[str], dict[str, str], str | None]:
        hosts = [d.destination_host for d in network_decisions if d.allowed and d.destination_host]
        if not hosts:
            return list(command), dict(env), None

        resolved_cache: dict[str, str] = {}

        def _resolve_placeholder(value: str) -> tuple[str | None, str | None]:
            if value in resolved_cache:
                return resolved_cache[value], None
            if not is_placeholder(value):
                return None, None
            if not approved_by_pep:
                return None, "pep_not_approved"
            for host in hosts:
                resolved = self._proxy.resolve_placeholder(
                    placeholder=value,
                    host=host,
                    approved_by_pep=approved_by_pep,
                )
                if resolved is not None:
                    resolved_cache[value] = resolved
                    return resolved, None
            return None, "credential_host_mismatch"

        transformed_command: list[str] = []
        for token in command:
            replaced = token
            if is_placeholder(token):
                resolved, reason = _resolve_placeholder(token)
                if resolved is None:
                    return [], {}, reason or "credential_host_mismatch"
                replaced = resolved
            else:
                for placeholder in _PLACEHOLDER_RE.findall(token):
                    resolved, reason = _resolve_placeholder(placeholder)
                    if resolved is None:
                        return [], {}, reason or "credential_host_mismatch"
                    replaced = replaced.replace(placeholder, resolved)
            transformed_command.append(replaced)

        transformed_env: dict[str, str] = {}
        for key, value in env.items():
            replaced = value
            if is_placeholder(value):
                resolved, reason = _resolve_placeholder(value)
                if resolved is None:
                    return [], {}, reason or "credential_host_mismatch"
                replaced = resolved
            else:
                for placeholder in _PLACEHOLDER_RE.findall(value):
                    resolved, reason = _resolve_placeholder(placeholder)
                    if resolved is None:
                        return [], {}, reason or "credential_host_mismatch"
                    replaced = replaced.replace(placeholder, resolved)
            transformed_env[key] = replaced
        return transformed_command, transformed_env, None

    @staticmethod
    def _connect_path_probe_url(raw_scope: str) -> str:
        normalized = str(raw_scope).strip().lower()
        if not normalized:
            return ""
        parsed = urlparse(normalized if "://" in normalized else f"https://{normalized}")
        scheme = (parsed.scheme or "https").lower()
        if scheme not in {"http", "https"}:
            return ""
        try:
            host = (parsed.hostname or "").lower()
            port = parsed.port
        except ValueError:
            return ""
        if not host or any(token in host for token in _WILDCARD_TOKENS):
            return ""
        if port is None:
            port = 80 if scheme == "http" else 443
        return f"{scheme}://{host}:{port}/"


__all__ = ["SandboxNetworkComponent", "SandboxNetworkManager"]
