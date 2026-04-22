"""Recall/MemoryPack surface helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shisad.memory.ingestion import RetrievalResult


@dataclass(slots=True)
class RecallPack:
    """Internal Recall surface result used by M2 rewiring."""

    query: str
    results: list[RetrievalResult]
    count: int
    max_tokens: int | None = None
    as_of: datetime | None = None
    include_archived: bool = False

    def legacy_payload(self) -> dict[str, Any]:
        """Return the current public `memory.retrieve` response shape."""
        return {
            "results": [item.model_dump(mode="json") for item in self.results],
            "count": self.count,
        }


def build_recall_pack(
    *,
    query: str,
    results: list[RetrievalResult],
    max_tokens: int | None = None,
    as_of: datetime | None = None,
    include_archived: bool = False,
) -> RecallPack:
    """Wrap scored retrieval results in the emerging Recall surface shape."""

    return RecallPack(
        query=query,
        results=results,
        count=len(results),
        max_tokens=max_tokens,
        as_of=as_of,
        include_archived=include_archived,
    )
