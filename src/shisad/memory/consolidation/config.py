"""Tunables for memory consolidation."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ConsolidationConfig:
    """Workspace-tunable consolidation defaults."""

    delta_corroborate: float = 0.05
    delta_contradict: float = 0.15
    delta_reverify: float = 0.10
    identity_candidate_threshold: int = 3
    surface_limit: int = 2
    candidate_ttl_activity_days: int = 30
    archive_threshold: float = 0.05
    max_unused_days: int = 180
    strong_invalidation_patterns: tuple[str, ...] = (
        "no longer",
        "used to",
        "anymore",
        "these days",
        "broke up with",
        "got dumped",
        "got engaged",
        "got married",
        "got divorced",
        "moved from",
        "moved to",
        "left ",
        "quit ",
        "got laid off",
        "fired",
        "started at",
        "joined",
        "changed my mind",
        "turns out i don't",
        "actually i prefer",
    )
    per_pattern_candidate_thresholds: dict[str, int] = field(
        default_factory=lambda: {"dietary": 2, "medical": 2}
    )
