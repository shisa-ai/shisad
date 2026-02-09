"""Retrieval ingestion foundation for M1."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol

from pydantic import BaseModel, Field

from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, ToolName
from shisad.security.firewall import ContentFirewall, SanitizationMode


class Fact(BaseModel):
    """Extracted fact from sanitized content."""

    text: str
    confidence: float = 0.5


class RetrievalResult(BaseModel):
    """Structured retrieval result for planner consumption."""

    chunk_id: str
    source_id: str
    source_type: Literal["user", "external", "tool"]
    created_at: datetime
    content_sanitized: str
    extracted_facts: list[Fact] = Field(default_factory=list)
    risk_score: float
    original_hash: str


class EmbeddingsProvider(Protocol):
    """Embeddings provider abstraction."""

    async def embed(self, input_texts: list[str]) -> list[list[float]]: ...


class EmbeddingFingerprint(BaseModel):
    """Captures embedding pipeline identity for reindex checks."""

    model_id: str
    base_url: str
    chunk_size: int = 1024

    def stable_hash(self) -> str:
        payload = f"{self.model_id}|{self.base_url}|{self.chunk_size}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class IngestionPipeline:
    """Ingests content through firewall and stores retrieval records."""

    def __init__(
        self,
        storage_dir: Path,
        *,
        firewall: ContentFirewall | None = None,
        embedding_fingerprint: EmbeddingFingerprint | None = None,
        encryption_key: str = "shisad-m1-default-key",
    ) -> None:
        self._storage_dir = storage_dir
        self._records: dict[str, RetrievalResult] = {}
        self._firewall = firewall or ContentFirewall()
        self._embedding_fingerprint = embedding_fingerprint or EmbeddingFingerprint(
            model_id="text-embedding-3-small",
            base_url="https://api.openai.com/v1",
            chunk_size=1024,
        )
        self._key_material = hashlib.sha256(encryption_key.encode("utf-8")).digest()

        self._sanitized_dir = self._storage_dir / "sanitized"
        self._original_dir = self._storage_dir / "original_encrypted"
        self._sanitized_dir.mkdir(parents=True, exist_ok=True)
        self._original_dir.mkdir(parents=True, exist_ok=True)

    @property
    def embedding_fingerprint(self) -> EmbeddingFingerprint:
        return self._embedding_fingerprint

    def reindex_required(self, new_fingerprint: EmbeddingFingerprint) -> bool:
        """Whether index should be rebuilt due to embedding config change."""
        return new_fingerprint.stable_hash() != self._embedding_fingerprint.stable_hash()

    def ingest(
        self,
        *,
        source_id: str,
        source_type: Literal["user", "external", "tool"],
        content: str,
    ) -> RetrievalResult:
        """Process content through firewall and store retrieval record."""
        inspection = self._firewall.inspect(content, mode=SanitizationMode.EXTRACT_FACTS)
        chunk_id = uuid.uuid4().hex

        result = RetrievalResult(
            chunk_id=chunk_id,
            source_id=source_id,
            source_type=source_type,
            created_at=datetime.now(UTC),
            content_sanitized=inspection.sanitized_text,
            extracted_facts=[
                Fact(text=fact, confidence=0.6)
                for fact in inspection.extracted_facts
            ],
            risk_score=inspection.risk_score,
            original_hash=inspection.original_hash,
        )

        self._records[chunk_id] = result
        (self._sanitized_dir / f"{chunk_id}.json").write_text(result.model_dump_json(indent=2))
        (self._original_dir / f"{chunk_id}.bin").write_bytes(
            self._xor_encrypt(content.encode("utf-8"))
        )
        return result

    def retrieve(self, query: str, *, limit: int = 5) -> list[RetrievalResult]:
        """Naive retrieval over sanitized content."""
        if not self._records:
            return []

        terms = [term for term in query.lower().split() if term]
        scored: list[tuple[int, RetrievalResult]] = []
        for record in self._records.values():
            text = record.content_sanitized.lower()
            score = sum(text.count(term) for term in terms)
            scored.append((score, record))

        scored.sort(key=lambda item: item[0], reverse=True)
        return [record for score, record in scored if score > 0][:limit] or [
            record for _, record in scored[:limit]
        ]

    def read_original(self, chunk_id: str) -> str | None:
        """Return decrypted original content for explicit user inspection."""
        path = self._original_dir / f"{chunk_id}.bin"
        if not path.exists():
            return None
        decrypted = self._xor_encrypt(path.read_bytes())
        return decrypted.decode("utf-8", errors="replace")

    def _xor_encrypt(self, payload: bytes) -> bytes:
        """Symmetric XOR helper for encrypted-at-rest storage in MVP."""
        key = self._key_material
        return bytes(payload[i] ^ key[i % len(key)] for i in range(len(payload)))


class RetrieveRagTool:
    """PEP-gated retrieval tool facade."""

    name = ToolName("retrieve_rag")

    def __init__(self, ingestion: IngestionPipeline) -> None:
        self._ingestion = ingestion

    @staticmethod
    def tool_definition() -> ToolDefinition:
        return ToolDefinition(
            name=ToolName("retrieve_rag"),
            description="Retrieve sanitized evidence from indexed content",
            parameters=[
                ToolParameter(name="query", type="string", required=True),
                ToolParameter(name="limit", type="integer", required=False),
            ],
            capabilities_required=[Capability.MEMORY_READ],
            require_confirmation=False,
        )

    def execute(self, *, query: str, limit: int = 5) -> list[RetrievalResult]:
        return self._ingestion.retrieve(query, limit=limit)
