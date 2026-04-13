"""Content Firewall pipeline."""

from __future__ import annotations

import hashlib
import re
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field
from textguard import TextGuard

from shisad.core.types import TaintLabel
from shisad.security.firewall.classifier import (
    TEXTGUARD_MODE as _TEXTGUARD_MODE,
)
from shisad.security.firewall.classifier import (
    InjectionClassification,
    PromptGuardRuntimeStatus,
    SemanticClassifier,
)
from shisad.security.firewall.classifier import (
    classify_textguard_findings as _classify_textguard_findings,
)
from shisad.security.firewall.classifier import (
    detect_split_base64_payload_finding as _detect_split_base64_payload_finding,
)
from shisad.security.firewall.classifier import (
    legacy_skill_review_findings as _legacy_skill_review_findings,
)
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
        self._guard = TextGuard(
            confusables="trimmed",
            preset="default",
            promptguard_model_path="",
            split_tokens=False,
            yara_bundled=True,
            yara_rules_dir="",
        )
        self._semantic_classifier_status = semantic_classifier_status or PromptGuardRuntimeStatus(
            posture="best_effort" if semantic_classifier is not None else "off",
            status="active" if semantic_classifier is not None else "disabled",
        )

    @property
    def classifier_mode(self) -> str:
        return _TEXTGUARD_MODE

    def validate_yara_backend(self) -> None:
        self._guard.match_yara("")

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
        scan_result = self._guard.scan(text)
        findings = list(scan_result.findings)
        split_base64_finding = _detect_split_base64_payload_finding(
            text,
            scan_result.decoded_text,
        )
        if split_base64_finding is not None:
            findings.append(split_base64_finding)
        for candidate_text in {text, scan_result.decoded_text}:
            findings.extend(_legacy_skill_review_findings(candidate_text))
        redacted, secret_findings = redact_ingress_secrets(scan_result.decoded_text)
        classification = _classify_textguard_findings(
            findings,
            decode_reason_codes=scan_result.decode_reason_codes,
        )
        classification = self._classify_semantic(
            classification,
            redacted,
            skip_semantic=trusted_input,
            decode_reason_codes=scan_result.decode_reason_codes,
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
            decode_depth=scan_result.decode_depth,
            decode_reason_codes=list(scan_result.decode_reason_codes),
            semantic_risk_score=classification.semantic_risk_score,
            semantic_risk_tier=classification.semantic_risk_tier,
            semantic_classifier_id=classification.semantic_classifier_id,
        )

    def _classify_semantic(
        self,
        classification: InjectionClassification,
        text: str,
        *,
        skip_semantic: bool,
        decode_reason_codes: list[str],
    ) -> InjectionClassification:
        if self._semantic_classifier is None or skip_semantic:
            return classification

        semantic = self._semantic_classifier.classify(text)
        risk_factors = {*classification.risk_factors, *semantic.risk_factors}
        if risk_factors:
            risk_factors.update(str(item) for item in decode_reason_codes)
        return InjectionClassification(
            risk_score=min(max(classification.risk_score, semantic.risk_score), 1.0),
            risk_factors=sorted(risk_factors),
            matched_patterns=sorted({*classification.matched_patterns, *semantic.matched_patterns}),
            semantic_risk_score=min(max(semantic.semantic_risk_score, 0.0), 1.0),
            semantic_risk_tier=semantic.semantic_risk_tier,
            semantic_classifier_id=semantic.semantic_classifier_id,
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
