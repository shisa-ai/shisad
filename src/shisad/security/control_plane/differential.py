"""Optional differential execution signal for control-plane analysis."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DifferentialSignal:
    divergence_score: float
    reason: str


class DifferentialExecutionAnalyzer:
    """Compares structured outputs from two sanitization regimes."""

    def compute(
        self,
        *,
        strict_output: dict[str, object],
        relaxed_output: dict[str, object],
    ) -> DifferentialSignal:
        strict_keys = set(strict_output.keys())
        relaxed_keys = set(relaxed_output.keys())
        union = strict_keys | relaxed_keys
        if not union:
            return DifferentialSignal(divergence_score=0.0, reason="differential:empty")
        intersection = strict_keys & relaxed_keys
        key_divergence = 1.0 - (len(intersection) / len(union))

        differing_values = 0
        for key in intersection:
            if strict_output.get(key) != relaxed_output.get(key):
                differing_values += 1
        value_divergence = differing_values / max(len(intersection), 1)
        divergence = min(1.0, (key_divergence + value_divergence) / 2.0)

        reason = "differential:stable"
        if divergence >= 0.7:
            reason = "differential:high_divergence"
        elif divergence >= 0.4:
            reason = "differential:moderate_divergence"
        return DifferentialSignal(divergence_score=divergence, reason=reason)
