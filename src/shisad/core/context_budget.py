"""Deterministic planner request capacity assessment and context compaction."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from shisad.core.context import ContextScaffold, ContextScaffoldEntry
from shisad.core.providers.base import Message

_BASELINE_TOKEN_NUMERATOR = 4
_BASELINE_TOKEN_DENOMINATOR = 11
_OPAQUE_ALNUM_RUN_MIN_BYTES = 24
_OPAQUE_PUNCTUATION_RUN_MIN_BYTES = 8
_REQUEST_FRAMING_TOKENS = 8
_MESSAGE_FRAMING_TOKENS = 6
_TOOL_FRAMING_TOKENS = 8
_CAPACITY_METADATA_PREFIX = "context_capacity_"

_COMPACTION_ORDER: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("history", ("conversation_context", "episode:")),
    ("thread_attention", ("thread_resume_context", "active_attention_context")),
    ("retrieved_memory", ("memory_context",)),
    ("remaining_optional", ("same_scope_memory_context", "task:", "task-title:")),
)


@dataclass(frozen=True)
class RequestCapacityAssessment:
    """Deterministic estimate of whether one outbound request fits its route."""

    context_window_tokens: int | None
    output_reserve_tokens: int
    estimated_input_tokens: int
    input_token_limit: int | None
    fits: bool


@dataclass(frozen=True)
class ContextCompactionResult:
    """Rendered scaffold after bounded whole-entry compaction."""

    scaffold: ContextScaffold
    planner_input: str
    omitted_categories: tuple[str, ...]
    assessment: RequestCapacityAssessment


def _serialized_messages(messages: Sequence[Message]) -> list[dict[str, object]]:
    payload: list[dict[str, object]] = []
    for message in messages:
        item: dict[str, object] = {
            "role": message.role,
            "content": message.content,
        }
        if message.tool_calls:
            item["tool_calls"] = message.tool_calls
        if message.tool_call_id is not None:
            item["tool_call_id"] = message.tool_call_id
        payload.append(item)
    return payload


def _estimate_serialized_tokens(serialized: str) -> int:
    """Return an upper-biased estimate for ordinary and byte-fallback text."""

    encoded_bytes = len(serialized.encode("utf-8"))
    baseline = (
        encoded_bytes * _BASELINE_TOKEN_NUMERATOR + _BASELINE_TOKEN_DENOMINATOR - 1
    ) // _BASELINE_TOKEN_DENOMINATOR
    risky_bytes = 0
    risky_tokens = 0
    index = 0
    while index < len(serialized):
        character = serialized[index]
        if not character.isascii():
            byte_count = len(character.encode("utf-8"))
            risky_bytes += byte_count
            risky_tokens += byte_count
            index += 1
            continue
        if character.isalnum():
            end = index + 1
            while end < len(serialized):
                candidate = serialized[end]
                if not candidate.isascii() or not candidate.isalnum():
                    break
                end += 1
            run_length = end - index
            if run_length >= _OPAQUE_ALNUM_RUN_MIN_BYTES:
                risky_bytes += run_length
                risky_tokens += run_length
            index = end
            continue
        if not character.isspace():
            end = index + 1
            while end < len(serialized):
                candidate = serialized[end]
                if not candidate.isascii() or candidate.isalnum() or candidate.isspace():
                    break
                end += 1
            run_length = end - index
            if run_length >= _OPAQUE_PUNCTUATION_RUN_MIN_BYTES:
                risky_bytes += run_length
                risky_tokens += run_length
            index = end
            continue
        index += 1

    ordinary_bytes = max(0, encoded_bytes - risky_bytes)
    risk_adjusted = risky_tokens + (
        ordinary_bytes * _BASELINE_TOKEN_NUMERATOR + _BASELINE_TOKEN_DENOMINATOR - 1
    ) // _BASELINE_TOKEN_DENOMINATOR
    return max(1, baseline, risk_adjusted)


def estimate_request_tokens(
    *,
    messages: Sequence[Message],
    tools: Sequence[dict[str, Any]] | None,
) -> int:
    """Estimate input tokens conservatively without claiming tokenizer parity."""

    message_payload = json.dumps(
        _serialized_messages(messages),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    tool_payload = json.dumps(
        list(tools or ()),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    payload_estimate = _estimate_serialized_tokens(
        message_payload
    ) + _estimate_serialized_tokens(tool_payload)
    framing = (
        _REQUEST_FRAMING_TOKENS
        + len(messages) * _MESSAGE_FRAMING_TOKENS
        + len(tools or ()) * _TOOL_FRAMING_TOKENS
    )
    return max(1, payload_estimate + framing)


def assess_request_capacity(
    *,
    messages: Sequence[Message],
    tools: Sequence[dict[str, Any]] | None,
    context_window_tokens: int | None,
    output_reserve_tokens: int,
) -> RequestCapacityAssessment:
    """Assess a full request, including tools and reserved output capacity."""

    reserve = max(0, int(output_reserve_tokens))
    estimated = estimate_request_tokens(messages=messages, tools=tools)
    if context_window_tokens is None:
        return RequestCapacityAssessment(
            context_window_tokens=None,
            output_reserve_tokens=reserve,
            estimated_input_tokens=estimated,
            input_token_limit=None,
            fits=True,
        )
    window = max(0, int(context_window_tokens))
    input_limit = max(0, window - reserve)
    return RequestCapacityAssessment(
        context_window_tokens=window,
        output_reserve_tokens=reserve,
        estimated_input_tokens=estimated,
        input_token_limit=input_limit,
        fits=estimated <= input_limit,
    )


def _entry_matches(entry: ContextScaffoldEntry, prefixes: tuple[str, ...]) -> bool:
    entry_id = entry.entry_id.strip()
    return any(
        entry_id.startswith(prefix) if prefix.endswith(":") else entry_id == prefix
        for prefix in prefixes
    )


def _without_category(
    scaffold: ContextScaffold,
    *,
    category: str,
    prefixes: tuple[str, ...],
) -> tuple[ContextScaffold, bool]:
    internal = [
        entry for entry in scaffold.internal_entries if not _entry_matches(entry, prefixes)
    ]
    untrusted = [
        entry for entry in scaffold.untrusted_entries if not _entry_matches(entry, prefixes)
    ]
    episodes = [] if category == "history" else list(scaffold.episodes)
    changed = (
        len(internal) != len(scaffold.internal_entries)
        or len(untrusted) != len(scaffold.untrusted_entries)
        or len(episodes) != len(scaffold.episodes)
    )
    return (
        scaffold.model_copy(
            update={
                "internal_entries": internal,
                "untrusted_entries": untrusted,
                "episodes": episodes,
            },
            deep=True,
        ),
        changed,
    )


def _with_omission_metadata(
    scaffold: ContextScaffold,
    omitted_categories: Sequence[str],
) -> ContextScaffold:
    retained_lines = [
        line
        for line in scaffold.trusted_frontmatter.splitlines()
        if not line.strip().startswith(_CAPACITY_METADATA_PREFIX)
    ]
    if omitted_categories:
        retained_lines.extend(
            (
                "context_capacity_compacted=true",
                f"context_capacity_omitted={','.join(omitted_categories)}",
            )
        )
    return scaffold.model_copy(
        update={"trusted_frontmatter": "\n".join(retained_lines).strip()},
        deep=True,
    )


def compact_context_scaffold(
    scaffold: ContextScaffold,
    *,
    render: Callable[[ContextScaffold], str],
    assess: Callable[[str], RequestCapacityAssessment],
) -> ContextCompactionResult:
    """Remove bounded optional entry categories until a known request fits."""

    working = _with_omission_metadata(scaffold.model_copy(deep=True), ())
    planner_input = render(working)
    assessment = assess(planner_input)
    if assessment.context_window_tokens is None or assessment.fits:
        return ContextCompactionResult(
            scaffold=working,
            planner_input=planner_input,
            omitted_categories=(),
            assessment=assessment,
        )

    omitted: list[str] = []
    for category, prefixes in _COMPACTION_ORDER:
        compacted, changed = _without_category(
            working,
            category=category,
            prefixes=prefixes,
        )
        if not changed:
            continue
        omitted.append(category)
        working = _with_omission_metadata(compacted, omitted)
        planner_input = render(working)
        assessment = assess(planner_input)
        if assessment.fits:
            break

    return ContextCompactionResult(
        scaffold=working,
        planner_input=planner_input,
        omitted_categories=tuple(omitted),
        assessment=assessment,
    )
