"""PII detection/redaction utilities for outbound and memory paths."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar


@dataclass(slots=True, frozen=True)
class PIIFinding:
    kind: str
    value: str


class PIIDetector:
    """Regex-driven PII detector suitable for local deterministic scanning."""

    _PATTERNS: ClassVar[list[tuple[str, re.Pattern[str]]]] = [
        ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
        ("credit_card", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
        ("phone", re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")),
        ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
        (
            "dob",
            re.compile(r"\b(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}\b"),
        ),
    ]

    def inspect(self, text: str) -> list[PIIFinding]:
        findings: list[PIIFinding] = []
        for kind, pattern in self._PATTERNS:
            for match in pattern.findall(text):
                findings.append(PIIFinding(kind=kind, value=str(match)))
        return findings

    def redact(self, text: str) -> tuple[str, list[PIIFinding]]:
        findings = self.inspect(text)
        redacted = text
        for finding in sorted(findings, key=lambda item: len(item.value), reverse=True):
            redacted = redacted.replace(finding.value, f"[REDACTED:{finding.kind}]")
        deduped: dict[tuple[str, str], PIIFinding] = {}
        for finding in findings:
            deduped[(finding.kind, finding.value)] = finding
        return redacted, list(deduped.values())
