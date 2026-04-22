"""Pattern-based identity observation detection for M3 candidate flow."""

from __future__ import annotations

import re
from dataclasses import dataclass

from shisad.memory.remap import digest_memory_value


@dataclass(frozen=True, slots=True)
class IdentityObservation:
    """A low-confidence owner-observed signal that may later become Identity."""

    category: str
    pattern_id: str
    confidence: float = 0.30


_PATTERN_RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "preference",
        "preference_like",
        re.compile(r"\bi\s+(?:really\s+)?(?:like|love|enjoy|prefer)\b", re.IGNORECASE),
    ),
    (
        "preference",
        "preference_dislike",
        re.compile(r"\bi\s+(?:really\s+)?(?:hate|dislike|avoid)\b", re.IGNORECASE),
    ),
    (
        "persona_fact",
        "habitual_schedule",
        re.compile(r"\bi\s+(?:usually|always|tend to)\b", re.IGNORECASE),
    ),
)


def detect_identity_observation(text: str) -> IdentityObservation | None:
    """Return a detected observation candidate for sanitized owner-observed text."""

    normalized = text.strip()
    if not normalized:
        return None
    for category, pattern_id, pattern in _PATTERN_RULES:
        if pattern.search(normalized) is not None:
            return IdentityObservation(category=category, pattern_id=pattern_id)
    return None


def build_identity_observation_key(
    *,
    observation: IdentityObservation,
    source_id: str,
    text: str,
) -> str:
    """Return a deterministic memory key for one observed identity signal."""

    digest = digest_memory_value(text)[:16]
    return f"identity-observation:{observation.category}:{source_id}:{digest}"
