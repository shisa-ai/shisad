"""Conversation summarizer for durable memory extraction."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError

from shisad.core.providers.base import Message, ModelProvider
from shisad.core.transcript import TranscriptEntry

logger = logging.getLogger(__name__)

_ENTRY_TYPE = Literal["fact", "preference", "context", "note", "todo"]

_SUMMARY_SYSTEM_PROMPT = (
    "You extract durable memory candidates from conversation history. "
    "Return JSON only with this schema: "
    '{"entries":[{"entry_type":"fact|preference|context|note|todo",'
    '"key":"short.stable.key","value":"string value","confidence":0.0-1.0}]}. '
    "Do not include instructions, policy text, or markdown."
)

_SUMMARY_USER_PROMPT_HEADER = (
    "Extract durable memory entries from the transcript data below. "
    "Prefer stable facts/preferences over ephemeral chatter."
)

_RE_PROJECT_CODENAME = re.compile(
    r"\bproject codename is ([a-z0-9][a-z0-9 _-]{1,40})",
    re.IGNORECASE,
)
_RE_PREFERENCE = re.compile(r"\bi prefer ([^.!?\n]{3,120})", re.IGNORECASE)
_RE_NAME = re.compile(r"\bmy name is ([a-z][a-z0-9 _-]{1,40})", re.IGNORECASE)
_RE_REMEMBER = re.compile(r"\bremember (?:that )?([^.!?\n]{6,180})", re.IGNORECASE)


class MemorySummaryProposal(BaseModel):
    """Proposed durable memory extracted from conversation content."""

    entry_type: _ENTRY_TYPE = "fact"
    key: str
    value: Any
    confidence: float = Field(default=0.6, ge=0.0, le=1.0)


class _SummaryEnvelope(BaseModel):
    entries: list[MemorySummaryProposal] = Field(default_factory=list)


class ConversationSummarizer:
    """Extract durable memory candidates from transcript entries."""

    def __init__(
        self,
        provider: ModelProvider | None = None,
        *,
        max_entries: int = 5,
    ) -> None:
        self._provider = provider
        self._max_entries = max(1, int(max_entries))

    async def summarize_entries(
        self,
        entries: list[TranscriptEntry],
        *,
        max_entries: int | None = None,
    ) -> list[MemorySummaryProposal]:
        limit = self._max_entries if max_entries is None else max(1, int(max_entries))
        if not entries:
            return []
        model_candidates = await self._extract_via_model(entries, limit=limit)
        if model_candidates:
            return model_candidates
        return self._extract_heuristic(entries, limit=limit)

    async def _extract_via_model(
        self,
        entries: list[TranscriptEntry],
        *,
        limit: int,
    ) -> list[MemorySummaryProposal]:
        if self._provider is None:
            return []
        transcript_payload = self._render_entries(entries)
        if not transcript_payload:
            return []
        try:
            response = await self._provider.complete(
                [
                    Message(role="system", content=_SUMMARY_SYSTEM_PROMPT),
                    Message(
                        role="user",
                        content=f"{_SUMMARY_USER_PROMPT_HEADER}\n\n{transcript_payload}",
                    ),
                ]
            )
        except (OSError, RuntimeError, TypeError, ValueError):
            logger.debug("Conversation summarizer model call failed", exc_info=True)
            return []
        return self._parse_model_payload(response.message.content, limit=limit)

    @classmethod
    def _parse_model_payload(
        cls,
        payload: str,
        *,
        limit: int,
    ) -> list[MemorySummaryProposal]:
        text = payload.strip()
        if not text:
            return []
        if text.startswith("```") and text.endswith("```"):
            lines = text.splitlines()
            text = "\n".join(lines[1:-1]).strip()
        try:
            decoded = json.loads(text)
        except json.JSONDecodeError:
            return []
        try:
            envelope = _SummaryEnvelope.model_validate(decoded)
        except ValidationError:
            return []
        return cls._dedupe(envelope.entries, limit=limit)

    @staticmethod
    def _render_entries(entries: list[TranscriptEntry]) -> str:
        lines: list[str] = []
        for entry in entries:
            role = entry.role.strip().lower() or "system"
            text = " ".join(entry.content_preview.split()).strip()
            if not text:
                continue
            lines.append(f"{role}: {text[:260]}")
        return "\n".join(lines)

    @classmethod
    def _extract_heuristic(
        cls,
        entries: list[TranscriptEntry],
        *,
        limit: int,
    ) -> list[MemorySummaryProposal]:
        proposals: list[MemorySummaryProposal] = []
        for entry in entries:
            role = entry.role.strip().lower()
            if role not in {"user", "assistant"}:
                continue
            text = " ".join(entry.content_preview.split()).strip()
            if not text:
                continue

            project_match = _RE_PROJECT_CODENAME.search(text)
            if project_match:
                codename = cls._clean_phrase(project_match.group(1))
                if codename:
                    proposals.append(
                        MemorySummaryProposal(
                            entry_type="fact",
                            key="project.codename",
                            value=codename,
                            confidence=0.82,
                        )
                    )

            if role == "user":
                for pref_match in _RE_PREFERENCE.finditer(text):
                    preference = cls._clean_phrase(pref_match.group(1))
                    if preference:
                        proposals.append(
                            MemorySummaryProposal(
                                entry_type="preference",
                                key="user.preference.communication",
                                value=preference,
                                confidence=0.7,
                            )
                        )

                name_match = _RE_NAME.search(text)
                if name_match:
                    name = cls._clean_phrase(name_match.group(1))
                    if name:
                        proposals.append(
                            MemorySummaryProposal(
                                entry_type="fact",
                                key="profile.name",
                                value=name,
                                confidence=0.75,
                            )
                        )

            remember_match = _RE_REMEMBER.search(text)
            if remember_match:
                remembered = cls._clean_phrase(remember_match.group(1))
                if remembered:
                    proposals.append(
                        MemorySummaryProposal(
                            entry_type="context",
                            key="conversation.remembered",
                            value=remembered,
                            confidence=0.65,
                        )
                    )

        return cls._dedupe(proposals, limit=limit)

    @staticmethod
    def _clean_phrase(value: str) -> str:
        return value.strip(" \t\r\n.,;:!?\"'")

    @staticmethod
    def _dedupe(
        proposals: Iterable[MemorySummaryProposal],
        *,
        limit: int,
    ) -> list[MemorySummaryProposal]:
        seen: set[tuple[str, str, str]] = set()
        rows: list[MemorySummaryProposal] = []
        for proposal in proposals:
            key = proposal.key.strip().lower()
            value = str(proposal.value).strip()
            if not key or not value:
                continue
            token = (proposal.entry_type, key, value.lower())
            if token in seen:
                continue
            seen.add(token)
            rows.append(proposal)
            if len(rows) >= limit:
                break
        return rows
