"""Retrieval ingestion and trust-aware hybrid ranking."""

from __future__ import annotations

import hashlib
import math
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, Field

from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, ToolName
from shisad.security.firewall import ContentFirewall, SanitizationMode

RetrievalCollection = Literal["user_curated", "project_docs", "external_web", "tool_outputs"]

_TRUST_PRIOR: dict[RetrievalCollection, float] = {
    "user_curated": 1.0,
    "project_docs": 0.8,
    "tool_outputs": 0.6,
    "external_web": 0.35,
}

_SIDE_EFFECT_CAPABILITIES = {
    Capability.EMAIL_SEND,
    Capability.FILE_WRITE,
    Capability.HTTP_REQUEST,
    Capability.MESSAGE_SEND,
}


class Fact(BaseModel):
    """Extracted fact from sanitized content."""

    text: str
    confidence: float = 0.5


class RetrievalResult(BaseModel):
    """Structured retrieval result for planner consumption."""

    chunk_id: str
    source_id: str
    source_type: Literal["user", "external", "tool"]
    collection: RetrievalCollection
    created_at: datetime
    content_sanitized: str
    extracted_facts: list[Fact] = Field(default_factory=list)
    risk_score: float
    original_hash: str
    quarantined: bool = False
    lexical_score: float = 0.0
    semantic_score: float = 0.0
    blended_score: float = 0.0
    corroborated: bool = False


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
        encryption_key: str | None = None,
        quarantine_threshold: float = 0.75,
    ) -> None:
        self._storage_dir = storage_dir
        self._records: dict[str, RetrievalResult] = {}
        self._vectors: dict[str, list[float]] = {}
        self._firewall = firewall or ContentFirewall()
        self._embedding_fingerprint = embedding_fingerprint or EmbeddingFingerprint(
            model_id="text-embedding-3-small",
            base_url="https://api.openai.com/v1",
            chunk_size=1024,
        )
        self._quarantine_threshold = quarantine_threshold

        self._sanitized_dir = self._storage_dir / "sanitized"
        self._original_dir = self._storage_dir / "original_encrypted"
        self._key_file = self._storage_dir / "key.bin"
        self._sanitized_dir.mkdir(parents=True, exist_ok=True)
        self._original_dir.mkdir(parents=True, exist_ok=True)
        self._key_material = self._load_key(encryption_key)

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
        collection: RetrievalCollection | None = None,
    ) -> RetrievalResult:
        """Process content through firewall and store retrieval record."""
        inspection = self._firewall.inspect(content, mode=SanitizationMode.EXTRACT_FACTS)
        chunk_id = uuid.uuid4().hex
        resolved_collection = collection or self._default_collection(source_type)
        quarantined = inspection.risk_score >= self._quarantine_threshold

        result = RetrievalResult(
            chunk_id=chunk_id,
            source_id=source_id,
            source_type=source_type,
            collection=resolved_collection,
            created_at=datetime.now(UTC),
            content_sanitized=inspection.sanitized_text,
            extracted_facts=[
                Fact(text=fact, confidence=0.6) for fact in inspection.extracted_facts
            ],
            risk_score=inspection.risk_score,
            original_hash=inspection.original_hash,
            quarantined=quarantined,
        )

        self._records[chunk_id] = result
        self._vectors[chunk_id] = self._embed_text(result.content_sanitized)

        (self._sanitized_dir / f"{chunk_id}.json").write_text(result.model_dump_json(indent=2))
        (self._original_dir / f"{chunk_id}.bin").write_bytes(
            self._encrypt_payload(content.encode("utf-8"))
        )
        return result

    def retrieve(
        self,
        query: str,
        *,
        limit: int = 5,
        capabilities: set[Capability] | None = None,
        allowed_collections: set[RetrievalCollection] | None = None,
        include_quarantined: bool = False,
        require_corroboration: bool = False,
    ) -> list[RetrievalResult]:
        """Hybrid retrieval over lexical + semantic + trust prior."""
        if not self._records:
            return []

        collections = (
            set(allowed_collections) if allowed_collections is not None else set(_TRUST_PRIOR)
        )
        if capabilities is not None and capabilities & _SIDE_EFFECT_CAPABILITIES:
            collections.discard("external_web")

        terms = [term for term in query.lower().split() if term]
        query_vector = self._embed_text(query)
        scored: list[tuple[float, RetrievalResult]] = []

        for chunk_id, record in self._records.items():
            if record.collection not in collections:
                continue
            if record.quarantined and not include_quarantined:
                continue

            text = record.content_sanitized.lower()
            lexical = float(sum(text.count(term) for term in terms))
            semantic = self._cosine_similarity(query_vector, self._vectors.get(chunk_id, []))
            trust = _TRUST_PRIOR[record.collection]
            blended = (0.45 * lexical) + (0.45 * semantic) + (0.10 * trust)
            scored.append(
                (
                    blended,
                    record.model_copy(
                        update={
                            "lexical_score": lexical,
                            "semantic_score": semantic,
                            "blended_score": blended,
                        }
                    ),
                )
            )

        scored.sort(key=lambda item: item[0], reverse=True)
        top = [record for _, record in scored[:limit]]
        if not top:
            return []
        if require_corroboration:
            source_ids = {record.source_id for record in top}
            tiers = {record.collection for record in top}
            corroborated = len(source_ids) >= 2 and len(tiers) >= 2
            top = [record.model_copy(update={"corroborated": corroborated}) for record in top]
        return top

    def read_original(self, chunk_id: str) -> str | None:
        """Return decrypted original content for explicit user inspection."""
        path = self._original_dir / f"{chunk_id}.bin"
        if not path.exists():
            return None
        try:
            decrypted = self._decrypt_payload(path.read_bytes())
        except Exception:
            return None
        return decrypted.decode("utf-8", errors="replace")

    def quarantine_source(self, source_id: str, *, reason: str = "") -> int:
        """Quarantine all chunks from a suspicious source."""
        count = 0
        for chunk_id, record in list(self._records.items()):
            if record.source_id != source_id:
                continue
            if record.quarantined:
                continue
            self._records[chunk_id] = record.model_copy(update={"quarantined": True})
            (self._sanitized_dir / f"{chunk_id}.json").write_text(
                self._records[chunk_id].model_dump_json(indent=2)
            )
            count += 1
        _ = reason
        return count

    def collections_for_capabilities(
        self,
        capabilities: set[Capability],
    ) -> set[RetrievalCollection]:
        collections: set[RetrievalCollection] = set(_TRUST_PRIOR)
        if capabilities & _SIDE_EFFECT_CAPABILITIES:
            collections.discard("external_web")
        return collections

    def _load_key(self, encryption_key: str | None) -> bytes:
        if encryption_key:
            return hashlib.sha256(encryption_key.encode("utf-8")).digest()

        if self._key_file.exists():
            key = self._key_file.read_bytes()
            if len(key) != 32:
                raise ValueError("Invalid key length in key file")
            return key

        key = os.urandom(32)
        self._key_file.parent.mkdir(parents=True, exist_ok=True)
        self._key_file.write_bytes(key)
        os.chmod(self._key_file, 0o600)
        return key

    def _encrypt_payload(self, payload: bytes) -> bytes:
        nonce = os.urandom(12)
        ciphertext = AESGCM(self._key_material).encrypt(nonce, payload, associated_data=None)
        return nonce + ciphertext

    def _decrypt_payload(self, payload: bytes) -> bytes:
        if len(payload) < 13:
            raise ValueError("ciphertext too short")
        nonce = payload[:12]
        ciphertext = payload[12:]
        return AESGCM(self._key_material).decrypt(nonce, ciphertext, associated_data=None)

    @staticmethod
    def _default_collection(
        source_type: Literal["user", "external", "tool"],
    ) -> RetrievalCollection:
        mapping: dict[str, RetrievalCollection] = {
            "user": "user_curated",
            "external": "external_web",
            "tool": "tool_outputs",
        }
        return mapping[source_type]

    @staticmethod
    def _embed_text(text: str) -> list[float]:
        # Deterministic local embedding approximation for M2 hybrid ranking.
        if not text:
            return [0.0] * 12
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        values = [digest[i] / 255.0 for i in range(12)]
        norm = math.sqrt(sum(v * v for v in values)) or 1.0
        return [v / norm for v in values]

    @staticmethod
    def _cosine_similarity(a: list[float], b: list[float]) -> float:
        if not a or not b or len(a) != len(b):
            return 0.0
        dot = sum(x * y for x, y in zip(a, b, strict=True))
        return max(0.0, min(dot, 1.0))


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

    def execute(
        self,
        *,
        query: str,
        limit: int = 5,
        capabilities: set[Capability] | None = None,
    ) -> list[RetrievalResult]:
        return self._ingestion.retrieve(query, limit=limit, capabilities=capabilities)
