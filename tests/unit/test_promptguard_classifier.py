"""H2 PromptGuard 2 classifier contract tests."""

from __future__ import annotations

import pytest

from shisad.core.types import TaintLabel
from shisad.security.firewall import ContentFirewall
from shisad.security.firewall.classifier import (
    PromptGuardSemanticClassifier,
    PromptGuardSettings,
    PromptGuardThresholds,
    build_promptguard_classifier,
)


class _FakePromptGuardBackend:
    model_source = "/opt/shisad/promptguard"

    def __init__(self, scores: list[float]) -> None:
        self._scores = list(scores)

    def score_text(self, text: str) -> list[float]:
        assert text
        return list(self._scores)


def test_h2_promptguard_best_effort_without_model_path_reports_unavailable() -> None:
    classifier, status = build_promptguard_classifier(
        PromptGuardSettings(posture="best_effort", model_path="")
    )

    assert classifier is None
    assert status.posture == "best_effort"
    assert status.status == "unavailable"
    assert status.reason == "model_path_unconfigured"


def test_h2_promptguard_required_without_model_path_fails_closed() -> None:
    with pytest.raises(ValueError, match="model_path_unconfigured"):
        build_promptguard_classifier(PromptGuardSettings(posture="required", model_path=""))


def test_h2_promptguard_rejects_non_local_model_refs() -> None:
    classifier, status = build_promptguard_classifier(
        PromptGuardSettings(
            posture="best_effort",
            model_path="meta-llama/Llama-Prompt-Guard-2-22M",
        )
    )

    assert classifier is None
    assert status.status == "unavailable"
    assert status.reason == "model_path_must_be_local"


def test_h2_promptguard_classifier_maps_backend_scores_to_risk_tiers() -> None:
    classifier = PromptGuardSemanticClassifier(
        backend=_FakePromptGuardBackend([0.74]),
        thresholds=PromptGuardThresholds(medium=0.35, high=0.7, critical=0.9),
    )

    result = classifier.classify("Quarterly planning notes")

    assert result.risk_score == pytest.approx(0.74)
    assert result.semantic_risk_score == pytest.approx(0.74)
    assert result.semantic_risk_tier == "high"
    assert result.semantic_classifier_id == "promptguard-v2"
    assert "promptguard:high" in result.risk_factors


def test_h2_content_firewall_surfaces_promptguard_metadata() -> None:
    firewall = ContentFirewall(
        semantic_classifier=PromptGuardSemanticClassifier(
            backend=_FakePromptGuardBackend([0.93]),
            thresholds=PromptGuardThresholds(medium=0.35, high=0.7, critical=0.9),
        )
    )

    result = firewall.inspect("Routine status update")

    assert result.risk_score == pytest.approx(0.93)
    assert result.semantic_risk_score == pytest.approx(0.93)
    assert result.semantic_risk_tier == "critical"
    assert result.semantic_classifier_id == "promptguard-v2"
    assert TaintLabel.UNTRUSTED in result.taint_labels
