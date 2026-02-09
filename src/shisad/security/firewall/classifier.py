"""Prompt injection classifier (pattern fast-path + semantic stub hook)."""

from __future__ import annotations

import base64
import re
from pathlib import Path
from typing import Any, ClassVar, Protocol

from pydantic import BaseModel, Field


class InjectionClassification(BaseModel):
    """Classification result for potentially malicious text."""

    risk_score: float = 0.0
    risk_factors: list[str] = Field(default_factory=list)
    matched_patterns: list[str] = Field(default_factory=list)


class SemanticClassifier(Protocol):
    """Optional semantic classifier integration point."""

    def classify(self, text: str) -> InjectionClassification: ...


class PatternInjectionClassifier:
    """Deterministic prompt-injection detector."""

    _BASE_PATTERNS: ClassVar[list[tuple[str, re.Pattern[str], float]]] = [
        (
            "instruction_override",
            re.compile(
                r"\b(ignore|disregard|bypass)\b.{0,40}\b(instruction|policy|rule)s?\b",
                re.IGNORECASE,
            ),
            0.35,
        ),
        (
            "prompt_leak_request",
            re.compile(r"\b(system prompt|developer message|hidden prompt)\b", re.IGNORECASE),
            0.35,
        ),
        (
            "credential_harvest",
            re.compile(
                r"\b(api key|token|password|secret)\b.{0,24}\b(send|exfiltrate|share)\b",
                re.IGNORECASE,
            ),
            0.45,
        ),
        (
            "tool_spoofing_tag",
            re.compile(r"<\s*(use_tool|tool_call|function_call)[^>]*>", re.IGNORECASE),
            0.35,
        ),
        (
            "role_impersonation",
            re.compile(r"\b(as system|i am the system|as developer)\b", re.IGNORECASE),
            0.25,
        ),
        (
            "command_chain",
            re.compile(r"\b(curl|wget|bash -c|python -c|powershell)\b", re.IGNORECASE),
            0.2,
        ),
        (
            "egress_lure",
            re.compile(r"\b(send email|post to webhook|upload to)\b", re.IGNORECASE),
            0.2,
        ),
    ]
    _BASE64_DIRECT_RE: ClassVar[re.Pattern[str]] = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
    _BASE64_SPLIT_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:[A-Za-z0-9+/]{8,}={0,2}(?:[\s\"'`:,;|\\/-]+|$)){3,}"
    )
    _ENCODED_SIGNAL_TOKENS: ClassVar[tuple[str, ...]] = (
        "ignore previous",
        "disregard instructions",
        "system prompt",
        "curl ",
        "wget ",
        "http://",
        "https://",
        "exfiltrate",
        "token",
        "secret",
    )

    def __init__(
        self,
        *,
        semantic_classifier: SemanticClassifier | None = None,
        yara_rules_dir: Path | None = None,
    ) -> None:
        self._semantic_classifier = semantic_classifier
        self._yara_rules = self._compile_yara_rules(yara_rules_dir)
        self._extra_patterns = self._load_fallback_patterns(yara_rules_dir)

    @property
    def mode(self) -> str:
        if self._yara_rules is not None:
            return "yara"
        if self._extra_patterns:
            return "fallback_regex"
        return "base_patterns"

    def classify(self, text: str) -> InjectionClassification:
        """Classify text for likely injection indicators."""
        score = 0.0
        factors: list[str] = []
        matches: list[str] = []

        for name, pattern, weight in [*self._BASE_PATTERNS, *self._extra_patterns]:
            if pattern.search(text):
                factors.append(name)
                matches.append(pattern.pattern)
                score += weight

        if self._yara_rules is not None:
            for match in self._yara_rules.match(data=text):
                factors.append(f"yara:{match.rule}")
                score += 0.15

        # Base64 payloads with executable-looking text are suspicious.
        if self._looks_like_encoded_payload(text):
            factors.append("encoded_payload")
            score += 0.25

        if self._semantic_classifier is not None:
            semantic = self._semantic_classifier.classify(text)
            factors.extend(semantic.risk_factors)
            matches.extend(semantic.matched_patterns)
            score = max(score, semantic.risk_score)

        return InjectionClassification(
            risk_score=min(score, 1.0),
            risk_factors=sorted(set(factors)),
            matched_patterns=sorted(set(matches)),
        )

    @classmethod
    def _looks_like_encoded_payload(cls, text: str) -> bool:
        candidates = set(cls._BASE64_DIRECT_RE.findall(text))
        for blob in cls._BASE64_SPLIT_RE.findall(text):
            collapsed = re.sub(r"[\s\"'`:,;|\\/-]+", "", blob)
            if len(collapsed) >= 40:
                candidates.add(collapsed)

        for chunk in sorted(candidates, key=len, reverse=True):
            if cls._contains_encoded_signal(chunk):
                return True
        return False

    @classmethod
    def _contains_encoded_signal(cls, chunk: str) -> bool:
        current = chunk.strip()
        for _ in range(2):
            padding = "=" * ((4 - (len(current) % 4)) % 4)
            try:
                decoded = base64.b64decode(current + padding, validate=True)
            except Exception:
                return False
            decoded_text = decoded.decode("utf-8", errors="ignore")
            lowered = decoded_text.lower()
            if any(token in lowered for token in cls._ENCODED_SIGNAL_TOKENS):
                return True

            next_candidate = re.sub(r"\s+", "", decoded_text)
            if not re.fullmatch(r"[A-Za-z0-9+/=]{24,}", next_candidate or ""):
                return False
            current = next_candidate
        return False

    @staticmethod
    def _compile_yara_rules(rules_dir: Path | None) -> Any:
        """Compile YARA rules if yara-python is available."""
        if rules_dir is None or not rules_dir.exists():
            return None
        try:
            import yara  # type: ignore
        except Exception:
            return None

        filepaths = {path.stem: str(path) for path in sorted(rules_dir.glob("*.yara"))}
        if not filepaths:
            return None
        try:
            return yara.compile(filepaths=filepaths)
        except Exception:
            return None

    @staticmethod
    def _load_fallback_patterns(
        rules_dir: Path | None,
    ) -> list[tuple[str, re.Pattern[str], float]]:
        """Load fallback regex markers from YARA files when yara-python is unavailable."""
        if rules_dir is None or not rules_dir.exists():
            return []

        patterns: list[tuple[str, re.Pattern[str], float]] = []
        for path in sorted(rules_dir.glob("*.yara")):
            for line in path.read_text(encoding="utf-8").splitlines():
                marker = "="
                if marker not in line or "/" not in line:
                    continue
                # Parse lines like: $a = /.../i
                lhs, rhs = line.split(marker, 1)
                if "$" not in lhs:
                    continue
                rhs = rhs.strip()
                if not rhs.startswith("/"):
                    continue
                raw = rhs.strip().removeprefix("/")
                if raw.endswith("/i"):
                    raw = raw[:-2]
                elif raw.endswith("/"):
                    raw = raw[:-1]
                if not raw:
                    continue
                try:
                    patterns.append((path.stem, re.compile(raw, re.IGNORECASE), 0.15))
                except re.error:
                    continue
        return patterns
