"""Shared helpers for strict user-intent matching in deterministic paths."""

from __future__ import annotations

import re

_FOLLOW_ON_COMMAND_FRAGMENT = (
    r"(?:(?:list|show)\s+(?:my\s+)?(?:notes|todos|tasks|reminders)\b"
    r"|search\s+(?:my\s+)?notes\b"
    r"|(?:add|save)\s+(?:a\s+)?note:"
    r"|(?:add|create)\s+(?:a\s+)?(?:todo|task):"
    r"|(?:mark|complete|finish)\b"
    r"|remind me\b)"
)
_PUNCTUATION_FOLLOW_ON_VERB_FRAGMENT = (
    r"(?:(?:please\s+)?(?:add|create|read|open|view|list|show|check|inspect|search|"
    r"find|fetch|get|look\s+up|browse|visit|write|send|message|email|run|execute|"
    r"edit|update|delete|remove|summarize|explain)\b)"
)


def normalize_intent_text(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip()


def strip_optional_greeting_prefix(text: str) -> str:
    normalized = normalize_intent_text(text)
    match = re.match(
        r"^(?:hello|hi|hey)(?: there)?(?:[,!:.]+)?\s+(.+)$",
        normalized,
        flags=re.IGNORECASE,
    )
    if match is None:
        return normalized
    return match.group(1).strip()


def has_follow_on_command(text: str) -> bool:
    normalized = normalize_intent_text(text)
    return (
        re.search(
            (
                rf"\b(?:and|then|also)\s+(?:{_FOLLOW_ON_COMMAND_FRAGMENT})"
                rf"|[;,]\s+(?:{_FOLLOW_ON_COMMAND_FRAGMENT}|{_PUNCTUATION_FOLLOW_ON_VERB_FRAGMENT})"
            ),
            normalized,
            flags=re.IGNORECASE,
        )
        is not None
    )


def has_follow_on_command_verb(text: str) -> bool:
    normalized = normalize_intent_text(text)
    return (
        re.search(
            rf"(?<!the )\b(?:{_PUNCTUATION_FOLLOW_ON_VERB_FRAGMENT})",
            normalized,
            flags=re.IGNORECASE,
        )
        is not None
    )
