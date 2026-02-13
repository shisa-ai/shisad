"""M6 coverage tests for differential execution analyzer."""

from __future__ import annotations

from shisad.security.control_plane.differential import DifferentialExecutionAnalyzer


def test_m6_differential_empty_outputs_are_stable() -> None:
    analyzer = DifferentialExecutionAnalyzer()
    signal = analyzer.compute(strict_output={}, relaxed_output={})
    assert signal.divergence_score == 0.0
    assert signal.reason == "differential:empty"


def test_m6_differential_identical_outputs_are_stable() -> None:
    analyzer = DifferentialExecutionAnalyzer()
    signal = analyzer.compute(
        strict_output={"tool": "http_request", "status": "allow"},
        relaxed_output={"tool": "http_request", "status": "allow"},
    )
    assert signal.divergence_score == 0.0
    assert signal.reason == "differential:stable"


def test_m6_differential_moderate_divergence_threshold() -> None:
    analyzer = DifferentialExecutionAnalyzer()
    signal = analyzer.compute(
        strict_output={"tool": "http_request", "status": "allow"},
        relaxed_output={"tool": "shell.exec", "status": "allow", "extra": "x"},
    )
    assert 0.4 <= signal.divergence_score < 0.7
    assert signal.reason == "differential:moderate_divergence"


def test_m6_differential_high_divergence_threshold() -> None:
    analyzer = DifferentialExecutionAnalyzer()
    signal = analyzer.compute(
        strict_output={"tool": "http_request", "status": "allow"},
        relaxed_output={"tool": "shell.exec", "mode": "raw"},
    )
    assert signal.divergence_score >= 0.7
    assert signal.reason == "differential:high_divergence"
