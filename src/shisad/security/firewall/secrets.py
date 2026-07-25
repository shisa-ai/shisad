"""Ingress secret detection and redaction."""

from __future__ import annotations

from typing import NamedTuple

from shisad.security.secret_patterns import SECRET_PATTERNS, SecretPattern

__all__ = [
    "SECRET_PATTERNS",
    "SecretFinding",
    "SecretPattern",
    "detect_ingress_secrets",
    "redact_ingress_secrets",
]


class SecretFinding(NamedTuple):
    kind: str
    value: str
    start: int
    end: int


def detect_ingress_secrets(text: str) -> list[SecretFinding]:
    """Detect likely credential material in untrusted text."""
    findings: list[SecretFinding] = []
    for pattern in SECRET_PATTERNS:
        for match in pattern.regex.finditer(text):
            findings.append(
                SecretFinding(
                    kind=pattern.kind,
                    value=match.group(0),
                    start=match.start(),
                    end=match.end(),
                )
            )
    return findings


def redact_ingress_secrets(text: str) -> tuple[str, list[SecretFinding]]:
    """Redact detected credential-like values from text."""
    findings = detect_ingress_secrets(text)
    if not findings:
        return text, []

    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.regex.sub(f"[REDACTED:{pattern.kind}]", redacted)
    return redacted, findings
