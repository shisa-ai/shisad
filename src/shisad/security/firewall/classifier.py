"""Prompt injection classifier primitives."""

from __future__ import annotations

import base64
import binascii
import logging
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, ClassVar, Protocol

from pydantic import BaseModel, Field
from textguard.backends.promptguard import load_promptguard_backend

logger = logging.getLogger(__name__)
_REMOTE_PATH_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")


class InjectionClassification(BaseModel):
    """Classification result for potentially malicious text."""

    risk_score: float = 0.0
    risk_factors: list[str] = Field(default_factory=list)
    matched_patterns: list[str] = Field(default_factory=list)
    semantic_risk_score: float = 0.0
    semantic_risk_tier: str = "none"
    semantic_classifier_id: str = ""


class SemanticClassifier(Protocol):
    """Optional semantic classifier integration point."""

    def classify(self, text: str) -> InjectionClassification: ...


class PromptGuardBackend(Protocol):
    """Backend that returns PromptGuard maliciousness scores per chunk."""

    model_source: str

    def score_text(self, text: str) -> list[float]: ...


class SemanticRiskTier(StrEnum):
    NONE = "none"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(slots=True, frozen=True)
class PromptGuardThresholds:
    medium: float = 0.35
    high: float = 0.7
    critical: float = 0.9

    def __post_init__(self) -> None:
        values = (self.medium, self.high, self.critical)
        if any(item < 0.0 or item > 1.0 for item in values):
            raise ValueError("PromptGuard thresholds must stay within [0.0, 1.0]")
        if not self.medium < self.high < self.critical:
            raise ValueError("PromptGuard thresholds must be strictly increasing")

    def tier_for(self, score: float) -> SemanticRiskTier:
        normalized = min(max(float(score), 0.0), 1.0)
        if normalized >= self.critical:
            return SemanticRiskTier.CRITICAL
        if normalized >= self.high:
            return SemanticRiskTier.HIGH
        if normalized >= self.medium:
            return SemanticRiskTier.MEDIUM
        return SemanticRiskTier.NONE

    def as_dict(self) -> dict[str, float]:
        return {
            "medium": self.medium,
            "high": self.high,
            "critical": self.critical,
        }


@dataclass(slots=True, frozen=True)
class PromptGuardSettings:
    posture: str = "best_effort"
    model_path: str = ""
    allowed_signers_path: str = ""
    thresholds: PromptGuardThresholds = field(default_factory=PromptGuardThresholds)

    def __post_init__(self) -> None:
        if self.posture not in {"off", "best_effort", "required"}:
            raise ValueError(f"Unsupported PromptGuard posture: {self.posture}")


@dataclass(slots=True, frozen=True)
class PromptGuardRuntimeStatus:
    posture: str
    status: str
    reason: str = ""
    classifier_id: str = "promptguard-v2"
    thresholds: dict[str, float] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "posture": self.posture,
            "status": self.status,
            "reason": self.reason,
            "classifier_id": self.classifier_id,
            "thresholds": dict(self.thresholds),
        }


@dataclass(slots=True, frozen=True)
class PromptGuardComparisonCase:
    label: str
    text: str


@dataclass(slots=True, frozen=True)
class PromptGuardComparisonResult:
    artifact_label: str
    artifact_path: str
    sample_label: str
    elapsed_ms: float
    semantic_risk_score: float
    semantic_risk_tier: str
    semantic_classifier_id: str

    def as_dict(self) -> dict[str, str | float]:
        return {
            "artifact_label": self.artifact_label,
            "artifact_path": self.artifact_path,
            "sample_label": self.sample_label,
            "elapsed_ms": self.elapsed_ms,
            "semantic_risk_score": self.semantic_risk_score,
            "semantic_risk_tier": self.semantic_risk_tier,
            "semantic_classifier_id": self.semantic_classifier_id,
        }


class PromptGuardLoadError(RuntimeError):
    """PromptGuard loader or inference failure with machine-readable reason."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class PromptGuardSemanticClassifier:
    """PromptGuard 2 wrapper behind the semantic-classifier protocol."""

    classifier_id = "promptguard-v2"

    def __init__(
        self,
        *,
        backend: PromptGuardBackend,
        thresholds: PromptGuardThresholds,
        posture: str = "best_effort",
    ) -> None:
        self._backend = backend
        self._thresholds = thresholds
        self._posture = posture
        self._status = PromptGuardRuntimeStatus(
            posture=posture,
            status="active",
            thresholds=thresholds.as_dict(),
        )

    def runtime_status(self) -> PromptGuardRuntimeStatus:
        return self._status

    def classify(self, text: str) -> InjectionClassification:
        try:
            scores = self._backend.score_text(text)
        except PromptGuardLoadError as exc:
            self._status = PromptGuardRuntimeStatus(
                posture=self._posture,
                status="degraded",
                reason=exc.reason,
                thresholds=self._thresholds.as_dict(),
            )
            if self._posture == "required":
                raise
            logger.warning(
                "PromptGuard degraded; reason_code=%s",
                exc.reason,
                exc_info=True,
            )
            return InjectionClassification(semantic_classifier_id=self.classifier_id)
        except RuntimeError as exc:
            reason = _promptguard_runtime_reason(exc)
            self._status = PromptGuardRuntimeStatus(
                posture=self._posture,
                status="degraded",
                reason=reason,
                thresholds=self._thresholds.as_dict(),
            )
            if self._posture == "required":
                raise PromptGuardLoadError(reason) from exc
            logger.warning(
                "PromptGuard degraded; reason_code=%s",
                reason,
                exc_info=True,
            )
            return InjectionClassification(semantic_classifier_id=self.classifier_id)
        except Exception as exc:
            reason = "promptguard_unexpected_error"
            self._status = PromptGuardRuntimeStatus(
                posture=self._posture,
                status="degraded",
                reason=reason,
                thresholds=self._thresholds.as_dict(),
            )
            if self._posture == "required":
                raise PromptGuardLoadError(reason) from exc
            logger.warning(
                "PromptGuard degraded; reason_code=%s",
                reason,
                exc_info=True,
            )
            return InjectionClassification(semantic_classifier_id=self.classifier_id)

        self._status = PromptGuardRuntimeStatus(
            posture=self._posture,
            status="active",
            thresholds=self._thresholds.as_dict(),
        )
        score = max((float(item) for item in scores), default=0.0)
        tier = self._thresholds.tier_for(score)
        risk_factors = [] if tier is SemanticRiskTier.NONE else [f"promptguard:{tier.value}"]
        return InjectionClassification(
            risk_score=score,
            risk_factors=risk_factors,
            semantic_risk_score=score,
            semantic_risk_tier=tier.value,
            semantic_classifier_id=self.classifier_id,
        )


def build_promptguard_classifier(
    settings: PromptGuardSettings,
) -> tuple[PromptGuardSemanticClassifier | None, PromptGuardRuntimeStatus]:
    thresholds = settings.thresholds.as_dict()
    if settings.posture == "off":
        return None, PromptGuardRuntimeStatus(
            posture="off",
            status="disabled",
            thresholds=thresholds,
        )

    raw_model_path = settings.model_path.strip()
    if not raw_model_path:
        reason = "model_path_unconfigured"
        return _promptguard_unavailable(settings=settings, reason=reason)
    if not _looks_like_local_path(raw_model_path):
        reason = "model_path_must_be_local"
        return _promptguard_unavailable(settings=settings, reason=reason)

    try:
        model_path = _expand_local_path(
            raw_model_path,
            reason="model_path_expanduser_failed",
        )
    except PromptGuardLoadError as exc:
        return _promptguard_unavailable(settings=settings, reason=exc.reason)
    if not model_path.exists():
        reason = "model_path_missing"
        return _promptguard_unavailable(settings=settings, reason=reason)
    if not model_path.is_dir():
        reason = "model_path_not_directory"
        return _promptguard_unavailable(settings=settings, reason=reason)

    allowed_signers_path = None
    raw_allowed_signers_path = settings.allowed_signers_path.strip()
    if raw_allowed_signers_path:
        try:
            allowed_signers_path = _expand_local_path(
                raw_allowed_signers_path,
                reason="promptguard_pack_trust_store_path_invalid",
            )
        except PromptGuardLoadError as exc:
            return _promptguard_unavailable(settings=settings, reason=exc.reason)

    try:
        backend = load_promptguard_backend(model_path, allowed_signers_path=allowed_signers_path)
    except RuntimeError as exc:
        return _promptguard_unavailable(settings=settings, reason=_promptguard_load_reason(exc))
    classifier = PromptGuardSemanticClassifier(
        backend=backend,
        thresholds=settings.thresholds,
        posture=settings.posture,
    )
    return classifier, PromptGuardRuntimeStatus(
        posture=settings.posture,
        status="active",
        thresholds=thresholds,
    )


def _looks_like_local_path(candidate: str) -> bool:
    return not _REMOTE_PATH_RE.match(candidate.strip())


def _expand_local_path(raw_path: str, *, reason: str) -> Path:
    try:
        return Path(raw_path).expanduser()
    except RuntimeError as exc:
        raise PromptGuardLoadError(reason) from exc


def _promptguard_load_reason(exc: RuntimeError) -> str:
    return _promptguard_reason_from_message(str(exc), default="promptguard_model_load_failed")


def _promptguard_runtime_reason(exc: RuntimeError) -> str:
    return _promptguard_reason_from_message(str(exc), default="promptguard_unexpected_error")


def _promptguard_reason_from_message(message: str, *, default: str) -> str:
    lowered = message.lower()
    if "model pack verification failed:" in lowered:
        return message.rsplit(":", 1)[-1].strip() or default
    if "onnx model is missing" in lowered:
        return "promptguard_onnx_model_missing"
    if "optional dependencies" in lowered or "install hint: textguard[promptguard]" in lowered:
        return "promptguard_runtime_missing"
    if "cpuexecutionprovider" in lowered:
        return "promptguard_cpu_provider_unavailable"
    if "model load failed" in lowered:
        return "promptguard_model_load_failed"
    if "tokenization failed" in lowered:
        return "promptguard_tokenization_failed"
    if "inference failed" in lowered:
        return "promptguard_inference_failed"
    return default


def _promptguard_unavailable(
    *,
    settings: PromptGuardSettings,
    reason: str,
) -> tuple[PromptGuardSemanticClassifier | None, PromptGuardRuntimeStatus]:
    status = PromptGuardRuntimeStatus(
        posture=settings.posture,
        status="unavailable",
        reason=reason,
        thresholds=settings.thresholds.as_dict(),
    )
    if settings.posture == "required":
        raise ValueError(
            f"PromptGuard semantic classifier is required but unavailable: {status.reason}"
        )
    return None, status


def compare_promptguard_artifacts(
    artifacts: Mapping[str, Path],
    samples: Sequence[PromptGuardComparisonCase],
    *,
    allowed_signers_path: Path | None = None,
    timer: Callable[[], float] = time.perf_counter,
) -> list[PromptGuardComparisonResult]:
    if not artifacts:
        raise ValueError("At least one PromptGuard artifact is required for comparison")
    if not samples:
        raise ValueError("At least one PromptGuard sample is required for comparison")

    reports: list[PromptGuardComparisonResult] = []
    for artifact_label, artifact_path in artifacts.items():
        classifier, status = build_promptguard_classifier(
            PromptGuardSettings(
                posture="required",
                model_path=str(artifact_path),
                allowed_signers_path=str(allowed_signers_path) if allowed_signers_path else "",
            )
        )
        if classifier is None or status.status != "active":
            raise ValueError(
                "PromptGuard artifact is unavailable for comparison: "
                f"{artifact_label} ({artifact_path})"
            )
        for sample in samples:
            started = timer()
            result = classifier.classify(sample.text)
            elapsed_ms = (timer() - started) * 1000.0
            reports.append(
                PromptGuardComparisonResult(
                    artifact_label=artifact_label,
                    artifact_path=str(artifact_path),
                    sample_label=sample.label,
                    elapsed_ms=elapsed_ms,
                    semantic_risk_score=result.semantic_risk_score,
                    semantic_risk_tier=result.semantic_risk_tier,
                    semantic_classifier_id=result.semantic_classifier_id,
                )
            )
    return reports


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

    def classify(
        self,
        text: str,
        *,
        context_factors: list[str] | tuple[str, ...] | None = None,
        skip_semantic: bool = False,
    ) -> InjectionClassification:
        """Classify text for likely injection indicators.

        When *skip_semantic* is True the PromptGuard neural-net classifier is
        not invoked.  Pattern/YARA scoring still runs (cheap, deterministic).
        This is the correct mode for trusted operator input — the operator is
        the trust root, so asking a neural net "did they inject themselves?"
        only adds latency and false-positive risk scores.
        """
        score = 0.0
        factors: list[str] = []
        matches: list[str] = []
        semantic_risk_score = 0.0
        semantic_risk_tier = SemanticRiskTier.NONE.value
        semantic_classifier_id = ""

        for name, pattern, weight in [*self._BASE_PATTERNS, *self._extra_patterns]:
            if pattern.search(text):
                factors.append(name)
                matches.append(pattern.pattern)
                score += weight

        if self._yara_rules is not None:
            for match in self._yara_rules.match(data=text):
                factors.append(f"yara:{match.rule}")
                score += 0.15

        if self._looks_like_encoded_payload(text):
            factors.append("encoded_payload")
            score += 0.25

        if self._semantic_classifier is not None and not skip_semantic:
            semantic = self._semantic_classifier.classify(text)
            factors.extend(semantic.risk_factors)
            matches.extend(semantic.matched_patterns)
            score = max(score, semantic.risk_score)
            semantic_risk_score = semantic.semantic_risk_score
            semantic_risk_tier = semantic.semantic_risk_tier
            semantic_classifier_id = semantic.semantic_classifier_id

        if context_factors and score > 0.0:
            factors.extend(str(item) for item in context_factors)

        return InjectionClassification(
            risk_score=min(score, 1.0),
            risk_factors=sorted(set(factors)),
            matched_patterns=sorted(set(matches)),
            semantic_risk_score=min(max(semantic_risk_score, 0.0), 1.0),
            semantic_risk_tier=semantic_risk_tier,
            semantic_classifier_id=semantic_classifier_id,
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
            except (ValueError, binascii.Error):
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
        except ImportError:
            return None

        filepaths = {path.stem: str(path) for path in sorted(rules_dir.glob("*.yara"))}
        if not filepaths:
            return None
        try:
            return yara.compile(filepaths=filepaths)
        except Exception:
            logger.warning(
                "YARA compile failed; reason_code=firewall.yara_compile_failed",
                exc_info=True,
            )
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
