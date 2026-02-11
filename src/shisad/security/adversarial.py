"""Adversarial-evaluation metrics and CI gate helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True, frozen=True)
class AdversarialMetrics:
    attack_success_rate: float
    utility_retention: float
    false_positive_rate: float
    detection_latency_ms: float
    memory_usage_mb: float = 0.0


@dataclass(slots=True, frozen=True)
class GateDecision:
    allowed: bool
    reason: str
    details: dict[str, Any]


def ci_gate(
    metrics: AdversarialMetrics,
    *,
    max_attack_success_rate: float = 0.05,
    min_utility_retention: float = 0.95,
    max_false_positive_rate: float = 0.02,
) -> GateDecision:
    failures: list[str] = []
    details = {
        "attack_success_rate": metrics.attack_success_rate,
        "utility_retention": metrics.utility_retention,
        "false_positive_rate": metrics.false_positive_rate,
    }
    if metrics.attack_success_rate > max_attack_success_rate:
        failures.append("asr")
    if metrics.utility_retention < min_utility_retention:
        failures.append("utility")
    if metrics.false_positive_rate > max_false_positive_rate:
        failures.append("fpr")
    if failures:
        return GateDecision(
            allowed=False,
            reason="threshold_violation:" + ",".join(failures),
            details=details,
        )
    return GateDecision(allowed=True, reason="pass", details=details)


def detect_regression(
    *,
    baseline: AdversarialMetrics,
    current: AdversarialMetrics,
    asr_tolerance: float = 0.005,
    utility_tolerance: float = 0.01,
    fpr_tolerance: float = 0.005,
) -> list[str]:
    findings: list[str] = []
    if current.attack_success_rate > baseline.attack_success_rate + asr_tolerance:
        findings.append("asr_regression")
    if current.utility_retention + utility_tolerance < baseline.utility_retention:
        findings.append("utility_regression")
    if current.false_positive_rate > baseline.false_positive_rate + fpr_tolerance:
        findings.append("fpr_regression")
    if current.detection_latency_ms > baseline.detection_latency_ms * 1.25:
        findings.append("latency_regression")
    return findings


def performance_gate(
    metrics: AdversarialMetrics,
    *,
    max_latency_ms: float = 100.0,
    max_memory_mb: float = 1024.0,
) -> GateDecision:
    failures: list[str] = []
    details = {
        "detection_latency_ms": metrics.detection_latency_ms,
        "memory_usage_mb": metrics.memory_usage_mb,
    }
    if metrics.detection_latency_ms > max_latency_ms:
        failures.append("latency")
    if metrics.memory_usage_mb > max_memory_mb:
        failures.append("memory")
    if failures:
        return GateDecision(
            allowed=False,
            reason="performance_violation:" + ",".join(failures),
            details=details,
        )
    return GateDecision(allowed=True, reason="pass", details=details)
