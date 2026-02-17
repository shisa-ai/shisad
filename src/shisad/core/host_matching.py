"""Shared host allowlist matching utilities."""

from __future__ import annotations


def host_matches(host: str, rule: str) -> bool:
    candidate = rule.strip().lower()
    if not candidate:
        return False
    value = host.strip().lower()
    if not value:
        return False
    if candidate.startswith("*."):
        return value.endswith(candidate[1:])
    return value == candidate
