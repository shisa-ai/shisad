"""PII detection/redaction utilities for outbound and memory paths."""

from __future__ import annotations

import re
from collections.abc import Iterator
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
        ("credit_card", re.compile(r"\b\d(?:[ -]?\d){12,18}\b")),
        ("phone", re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")),
        ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
        (
            "dob",
            re.compile(r"\b(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}\b"),
        ),
    ]

    def inspect(self, text: str) -> list[PIIFinding]:
        return [PIIFinding(kind=kind, value=match.group(0)) for kind, match in self._matches(text)]

    def _matches(self, text: str) -> Iterator[tuple[str, re.Match[str]]]:
        for kind, pattern in self._PATTERNS:
            for match in pattern.finditer(text):
                if kind == "credit_card" and not self._valid_card_checksum(match.group(0)):
                    continue
                yield kind, match

    @staticmethod
    def _valid_card_checksum(value: str) -> bool:
        """Validate the Luhn checksum of a structurally matched card candidate."""
        digits = [int(char) for char in value if char.isdecimal()]
        total = 0
        for index, digit in enumerate(reversed(digits)):
            if index % 2:
                digit *= 2
                if digit > 9:
                    digit -= 9
            total += digit
        return total % 10 == 0

    def redact(self, text: str) -> tuple[str, list[PIIFinding]]:
        findings: list[PIIFinding] = []
        replacements: list[tuple[int, int, str]] = []
        for kind, match in self._matches(text):
            value = match.group(0)
            findings.append(PIIFinding(kind=kind, value=value))
            replacements.append((match.start(), match.end(), f"[REDACTED:{kind}]"))
        redacted = self._replace_spans(text, replacements) if replacements else text
        deduped: dict[tuple[str, str], PIIFinding] = {}
        for finding in findings:
            deduped[(finding.kind, finding.value)] = finding
        return redacted, list(deduped.values())

    @staticmethod
    def _replace_spans(text: str, replacements: list[tuple[int, int, str]]) -> str:
        parts: list[str] = []
        last_end = 0
        for start, end, replacement in sorted(replacements, key=lambda item: item[0]):
            if start < last_end:
                continue
            parts.append(text[last_end:start])
            parts.append(replacement)
            last_end = end
        parts.append(text[last_end:])
        return "".join(parts)
