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
from typing import Any, ClassVar, Protocol, cast

from pydantic import BaseModel, Field

from shisad.security.firewall.promptguard_pack import inspect_promptguard_model_pack

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


class OnnxPromptGuardBackend:
    """Local-only PromptGuard 2 backend using Transformers tokenizer + ONNX Runtime."""

    def __init__(
        self,
        *,
        model_source: str,
        tokenizer: Any,
        config: Any,
        session: Any,
        numpy_module: Any,
        max_length: int = 512,
        stride: int = 64,
        max_segments: int = 8,
    ) -> None:
        self.model_source = model_source
        self._tokenizer = tokenizer
        self._config = config
        self._session = session
        self._np = numpy_module
        self._max_length = max_length
        self._stride = stride
        self._max_segments = max_segments
        self._input_names = tuple(item.name for item in self._session.get_inputs())
        outputs = self._session.get_outputs()
        self._output_name = outputs[0].name if outputs else "logits"

    @classmethod
    def from_local_path(cls, model_path: Path) -> OnnxPromptGuardBackend:
        onnx_path = _resolve_promptguard_onnx_path(model_path)
        if onnx_path is None:
            raise PromptGuardLoadError("promptguard_onnx_model_missing")

        try:
            import numpy as np
            import onnxruntime as ort  # type: ignore[import-untyped]
            from transformers import AutoConfig, AutoTokenizer
        except ImportError as exc:  # pragma: no cover - exercised via loader surface
            raise PromptGuardLoadError("promptguard_runtime_missing") from exc

        if "CPUExecutionProvider" not in ort.get_available_providers():
            raise PromptGuardLoadError("promptguard_cpu_provider_unavailable")

        try:
            tokenizer_loader = cast(Any, AutoTokenizer)
            config_loader = cast(Any, AutoConfig)
            tokenizer = tokenizer_loader.from_pretrained(
                str(model_path),
                local_files_only=True,
                trust_remote_code=False,
            )
            config = config_loader.from_pretrained(
                str(model_path),
                local_files_only=True,
                trust_remote_code=False,
            )
            session = ort.InferenceSession(
                str(onnx_path),
                providers=["CPUExecutionProvider"],
            )
        except Exception as exc:  # pragma: no cover - exercised via loader surface
            raise PromptGuardLoadError("promptguard_model_load_failed") from exc

        return cls(
            model_source=str(model_path),
            tokenizer=tokenizer,
            config=config,
            session=session,
            numpy_module=np,
        )

    def score_text(self, text: str) -> list[float]:
        try:
            batch = self._tokenizer(
                text,
                return_tensors="np",
                truncation=True,
                padding=True,
                max_length=self._max_length,
                stride=self._stride,
                return_overflowing_tokens=True,
            )
        except Exception as exc:
            raise PromptGuardLoadError("promptguard_tokenization_failed") from exc

        payload = dict(batch)
        payload.pop("overflow_to_sample_mapping", None)
        segment_count = self._segment_count(payload)
        if segment_count > self._max_segments:
            logger.debug(
                "PromptGuard scoring long input in %s batches (%s segments total)",
                ((segment_count - 1) // self._max_segments) + 1,
                segment_count,
            )

        all_scores: list[float] = []
        for model_inputs in self._iter_model_batches(payload):
            input_feed = {
                key: value for key, value in model_inputs.items() if key in self._input_names
            }

            try:
                logits = self._session.run([self._output_name], input_feed)[0]
                probabilities = self._softmax(logits)
            except Exception as exc:
                raise PromptGuardLoadError("promptguard_inference_failed") from exc

            label_count = int(getattr(probabilities, "shape", [0, 0])[-1])
            malicious_index = self._malicious_index(label_count)
            score_tensor = probabilities[:, malicious_index]
            raw_scores = (
                score_tensor.tolist() if hasattr(score_tensor, "tolist") else [score_tensor]
            )
            all_scores.extend(min(max(float(item), 0.0), 1.0) for item in raw_scores)
        return all_scores

    def _iter_model_batches(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        segment_count = self._segment_count(payload)
        if segment_count <= 0 or segment_count <= self._max_segments:
            return [payload]
        return [
            self._slice_batch(payload, start, start + self._max_segments)
            for start in range(0, segment_count, self._max_segments)
        ]

    def _segment_count(self, payload: dict[str, Any]) -> int:
        for value in payload.values():
            shape = getattr(value, "shape", None)
            if shape:
                try:
                    return int(shape[0])
                except (TypeError, ValueError):
                    pass
            if hasattr(value, "__len__") and hasattr(value, "__getitem__"):
                try:
                    return len(value)
                except (TypeError, ValueError):
                    pass
        return 0

    def _slice_batch(self, payload: dict[str, Any], start: int, stop: int) -> dict[str, Any]:
        truncated: dict[str, Any] = {}
        for key, value in payload.items():
            if hasattr(value, "__getitem__"):
                try:
                    truncated[key] = value[start:stop]
                    continue
                except Exception:
                    pass
            truncated[key] = value
        return truncated

    def _malicious_index(self, label_count: int) -> int:
        id2label = getattr(self._config, "id2label", {}) if self._config is not None else {}
        if isinstance(id2label, dict):
            benign_indices: set[int] = set()
            for raw_index, raw_label in id2label.items():
                index = _coerce_promptguard_label_index(raw_index)
                if index is None:
                    continue
                label = str(raw_label).strip().lower()
                if label == "malicious":
                    return index
                if label == "benign":
                    benign_indices.add(index)
            if label_count == 2 and benign_indices == {0}:
                return 1
        if label_count <= 1:
            return 0
        return 1

    def _softmax(self, logits: Any) -> Any:
        array = self._np.asarray(logits, dtype="float32")
        shifted = array - array.max(axis=-1, keepdims=True)
        exponents = self._np.exp(shifted)
        return exponents / exponents.sum(axis=-1, keepdims=True)


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

    runtime_model_path = model_path
    if (model_path / "manifest.json").is_file():
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
        inspection = inspect_promptguard_model_pack(
            model_path,
            allowed_signers_path=allowed_signers_path,
        )
        if not inspection.valid or inspection.payload_dir is None:
            return _promptguard_unavailable(settings=settings, reason=inspection.reason)
        runtime_model_path = inspection.payload_dir

    try:
        backend = OnnxPromptGuardBackend.from_local_path(runtime_model_path)
    except PromptGuardLoadError as exc:
        return _promptguard_unavailable(settings=settings, reason=exc.reason)
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


def _coerce_promptguard_label_index(raw_index: object) -> int | None:
    if isinstance(raw_index, int):
        return raw_index
    if isinstance(raw_index, str):
        try:
            return int(raw_index)
        except ValueError:
            return None
    return None


def _resolve_promptguard_onnx_path(model_path: Path) -> Path | None:
    candidates = (
        model_path / "model.onnx",
        model_path / "onnx" / "model.onnx",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    root_matches = sorted(model_path.glob("*.onnx"))
    if len(root_matches) == 1:
        return root_matches[0]
    nested_dir = model_path / "onnx"
    nested_matches = sorted(nested_dir.glob("*.onnx")) if nested_dir.is_dir() else []
    if len(nested_matches) == 1:
        return nested_matches[0]
    return None


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
