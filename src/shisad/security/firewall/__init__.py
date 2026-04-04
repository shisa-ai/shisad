"""Content Firewall pipeline."""

from __future__ import annotations

import hashlib
import re
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from shisad.core.types import TaintLabel
from shisad.security.firewall.classifier import (
    PatternInjectionClassifier,
    PromptGuardRuntimeStatus,
    SemanticClassifier,
)
from shisad.security.firewall.normalize import decode_text_layers, normalize_text
from shisad.security.firewall.secrets import SecretFinding, redact_ingress_secrets


class SanitizationMode(StrEnum):
    REWRITE = "rewrite"
    EXTRACT_FACTS = "extract_facts"


class FirewallResult(BaseModel):
    """Result of content firewall processing."""

    sanitized_text: str
    extracted_facts: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    risk_factors: list[str] = Field(default_factory=list)
    original_hash: str
    taint_labels: list[TaintLabel] = Field(default_factory=list)
    secret_findings: list[str] = Field(default_factory=list)
    decode_depth: int = 0
    decode_reason_codes: list[str] = Field(default_factory=list)
    semantic_risk_score: float = 0.0
    semantic_risk_tier: str = "none"
    semantic_classifier_id: str = ""


class ContentFirewall:
    """Normalizes, classifies, and sanitizes untrusted content."""

    def __init__(
        self,
        *,
        semantic_classifier: SemanticClassifier | None = None,
        semantic_classifier_status: PromptGuardRuntimeStatus | None = None,
    ) -> None:
        self._semantic_classifier = semantic_classifier
        rules_dir = Path(__file__).resolve().parent.parent / "rules" / "yara"
        self._classifier = PatternInjectionClassifier(
            semantic_classifier=semantic_classifier,
            yara_rules_dir=rules_dir,
        )
        self._semantic_classifier_status = semantic_classifier_status or PromptGuardRuntimeStatus(
            posture="best_effort" if semantic_classifier is not None else "off",
            status="active" if semantic_classifier is not None else "disabled",
        )

    @property
    def classifier_mode(self) -> str:
        return self._classifier.mode

    def status_snapshot(self) -> dict[str, Any]:
        semantic_status = self._semantic_classifier_status
        runtime_status = getattr(self._semantic_classifier, "runtime_status", None)
        if callable(runtime_status):
            try:
                observed = runtime_status()
                if isinstance(observed, PromptGuardRuntimeStatus):
                    semantic_status = observed
            except Exception:
                pass
        return {
            "pattern_mode": self.classifier_mode,
            "semantic_classifier": semantic_status.as_dict(),
        }

    def inspect(
        self,
        text: str,
        *,
        mode: SanitizationMode = SanitizationMode.REWRITE,
        trusted_input: bool = False,
    ) -> FirewallResult:
        """Process untrusted input and return sanitized content + metadata."""
        original_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        normalized = normalize_text(text)
        decoded = decode_text_layers(normalized)
        redacted, secret_findings = redact_ingress_secrets(decoded.text)
        classification = self._classifier.classify(
            redacted,
            context_factors=decoded.reason_codes,
        )

        sanitized = redacted
        extracted_facts: list[str] = []

        if mode == SanitizationMode.REWRITE:
            sanitized = self._rewrite_suspicious(redacted)
        else:
            extracted_facts = self._extract_facts(redacted)

        taints: set[TaintLabel] = set() if trusted_input else {TaintLabel.UNTRUSTED}
        if secret_findings:
            taints.add(TaintLabel.USER_CREDENTIALS)

        return FirewallResult(
            sanitized_text=sanitized,
            extracted_facts=extracted_facts,
            risk_score=classification.risk_score,
            risk_factors=classification.risk_factors,
            original_hash=original_hash,
            taint_labels=sorted(taints),
            secret_findings=[f.kind for f in secret_findings],
            decode_depth=decoded.decode_depth,
            decode_reason_codes=list(decoded.reason_codes),
            semantic_risk_score=classification.semantic_risk_score,
            semantic_risk_tier=classification.semantic_risk_tier,
            semantic_classifier_id=classification.semantic_classifier_id,
        )

    @staticmethod
    def _rewrite_suspicious(text: str) -> str:
        """Rewrite obvious adversarial instruction fragments out of content."""
        rewrite_patterns = [
            r"ignore previous instructions",
            r"disregard .*? policy",
            r"as system",
            r"<\s*(use_tool|tool_call|function_call)[^>]*>",
        ]
        rewritten = text
        for pattern in rewrite_patterns:
            rewritten = re.sub(pattern, "[REMOVED_SUSPICIOUS_TEXT]", rewritten, flags=re.IGNORECASE)
        return rewritten

    @staticmethod
    def _extract_facts(text: str) -> list[str]:
        """Extract coarse factual lines while discarding imperative instructions."""
        facts: list[str] = []
        for chunk in re.split(r"[\n\.]+", text):
            candidate = chunk.strip()
            if not candidate:
                continue
            lower = candidate.lower()
            if any(
                token in lower
                for token in (
                    "ignore",
                    "execute",
                    "send",
                    "run",
                    "tool_call",
                    "instruction",
                )
            ):
                continue
            facts.append(candidate)
        return facts


def redact_findings(findings: list[SecretFinding]) -> list[str]:
    """Helper for serializing secret findings."""
    return [f.kind for f in findings]
