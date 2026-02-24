"""v0.3.4 context scaffold stubs and delegation hooks."""

from __future__ import annotations

import pytest

from shisad.core.context import ContextScaffold, ConversationEpisode, EpisodeSummary
from shisad.security import spotlight


def test_m1_h3_context_scaffold_models_validate() -> None:
    scaffold = ContextScaffold(
        session_id="s-1",
        episodes=[
            ConversationEpisode(
                episode_id="ep-1",
                summary=EpisodeSummary(text="first summary"),
            )
        ],
    )
    assert scaffold.session_id == "s-1"
    assert scaffold.episodes[0].episode_id == "ep-1"
    assert scaffold.episodes[0].summary is not None


def test_m1_h4_build_planner_input_v2_delegates_to_v1(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixed = spotlight.Delimiters(
        evidence_start="E1",
        evidence_end="E2",
        system_start="S1",
        user_goal="U1",
    )
    monkeypatch.setattr(spotlight, "generate_delimiters", lambda: fixed)
    base = spotlight.build_planner_input(
        trusted_instructions="trusted",
        user_goal="goal",
        untrusted_content="payload",
        untrusted_context="history",
    )
    v2 = spotlight.build_planner_input_v2(
        trusted_instructions="trusted",
        user_goal="goal",
        untrusted_content="payload",
        untrusted_context="history",
    )
    assert v2 == base
