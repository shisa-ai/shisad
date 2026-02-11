"""M6 adversarial CI/regression/performance gate coverage."""

from __future__ import annotations

from shisad.security.adversarial import (
    AdversarialMetrics,
    ci_gate,
    detect_regression,
    performance_gate,
)


def test_m6_t8_ci_gate_blocks_high_asr() -> None:
    decision = ci_gate(
        AdversarialMetrics(
            attack_success_rate=0.09,
            utility_retention=0.97,
            false_positive_rate=0.01,
            detection_latency_ms=80,
        )
    )
    assert decision.allowed is False
    assert "asr" in decision.reason


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
