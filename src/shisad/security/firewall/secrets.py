"""Ingress secret detection and redaction."""

from __future__ import annotations

import re
from typing import NamedTuple


class SecretPattern(NamedTuple):
    kind: str
    regex: re.Pattern[str]


SECRET_PATTERNS: list[SecretPattern] = [
    SecretPattern("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    SecretPattern("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    SecretPattern("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    SecretPattern("oauth_access_token", re.compile(r"\bya29\.[A-Za-z0-9._-]{20,}\b")),
    SecretPattern(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+\b"),
    ),
    SecretPattern(
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----[\s\S]+?"
            r"-----END (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----"
        ),
    ),
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
