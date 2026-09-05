"""M6 adversarial CI/regression/performance gate coverage."""

from __future__ import annotations

import pytest

from shisad.security.adversarial import (
    AdversarialMetrics,
    ci_gate,
    detect_regression,
    performance_gate,
)


@pytest.mark.parametrize(
    ("asr", "utility", "false_positives", "reason"),
    [
        (0.05, 0.95, 0.02, "pass"),
        (0.051, 0.95, 0.02, "threshold_violation:asr"),
        (0.05, 0.949, 0.02, "threshold_violation:utility"),
        (0.05, 0.95, 0.021, "threshold_violation:fpr"),
    ],
)
def test_ci_gate_thresholds(
    asr: float, utility: float, false_positives: float, reason: str
) -> None:
    decision = ci_gate(
        AdversarialMetrics(
            attack_success_rate=asr,
            utility_retention=utility,
            false_positive_rate=false_positives,
            detection_latency_ms=35,
        )
    )
    assert decision.allowed is (reason == "pass")
    assert decision.reason == reason


def test_m6_regression_detection_flags_metric_drift() -> None:
    baseline = AdversarialMetrics(
        attack_success_rate=0.03,
        utility_retention=0.98,
        false_positive_rate=0.01,
        detection_latency_ms=70,
    )
    current = AdversarialMetrics(
        attack_success_rate=0.05,
        utility_retention=0.94,
        false_positive_rate=0.02,
        detection_latency_ms=95,
    )
    findings = detect_regression(baseline=baseline, current=current)
    assert "asr_regression" in findings
    assert "utility_regression" in findings
    assert "fpr_regression" in findings
    assert "latency_regression" in findings


def test_m6_performance_gate_blocks_latency_and_memory_overrun() -> None:
    decision = performance_gate(
        AdversarialMetrics(
            attack_success_rate=0.01,
            utility_retention=0.99,
            false_positive_rate=0.005,
            detection_latency_ms=140,
            memory_usage_mb=1200,
        )
    )
    assert decision.allowed is False
    assert "latency" in decision.reason
    assert "memory" in decision.reason
