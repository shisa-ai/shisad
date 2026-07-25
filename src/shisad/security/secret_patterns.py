"""Canonical finite secret-token signatures shared by security consumers."""

from __future__ import annotations

import re
from typing import Final, Literal, NamedTuple

SecretKind = Literal[
    "anthropic_key",
    "openai_key",
    "github_token",
    "aws_access_key",
    "oauth_access_token",
    "jwt",
    "private_key",
]


class SecretPattern(NamedTuple):
    """One typed credential-family signature."""

    kind: SecretKind
    regex: re.Pattern[str]


SECRET_PATTERNS: Final[tuple[SecretPattern, ...]] = (
    SecretPattern("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b")),
    SecretPattern("openai_key", re.compile(r"\bsk-(?!ant-)[A-Za-z0-9_-]{16,}\b")),
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
)
