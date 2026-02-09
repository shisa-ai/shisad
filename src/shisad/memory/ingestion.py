"""Retrieval ingestion and trust-aware hybrid ranking."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
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

    def embed(self, input_texts: list[str]) -> list[list[float]]: ...


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
        embeddings_provider: EmbeddingsProvider | None = None,
        encryption_key: str | None = None,
        quarantine_threshold: float = 0.75,
        audit_hook: Callable[[str, dict[str, Any]], None] | None = None,
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
        self._embeddings_provider = embeddings_provider
        self._quarantine_threshold = quarantine_threshold
        self._audit_hook = audit_hook

        self._sanitized_dir = self._storage_dir / "sanitized"
        self._original_dir = self._storage_dir / "original_encrypted"
        self._legacy_key_file = self._storage_dir / "key.bin"
        self._key_manifest_file = self._storage_dir / "keys.json"
        self._master_salt_file = self._storage_dir / "master_salt.bin"
        self._sanitized_dir.mkdir(parents=True, exist_ok=True)
        self._original_dir.mkdir(parents=True, exist_ok=True)
        self._master_secret = self._resolve_master_secret(encryption_key)
        self._key_material_by_id: dict[str, bytes] = {}
        self._key_metadata_by_id: dict[str, dict[str, str]] = {}
        self._active_key_id = ""
        self._load_or_create_keys()

    @property
    def embedding_fingerprint(self) -> EmbeddingFingerprint:
        return self._embedding_fingerprint

    @property
    def active_key_id(self) -> str:
        return self._active_key_id

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
            self._encrypt_payload(content.encode("utf-8"), chunk_id=chunk_id)
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
            decrypted = self._decrypt_payload(path.read_bytes(), chunk_id=chunk_id)
        except Exception:
            self._audit(
                "memory.original_read_failed",
                {"chunk_id": chunk_id, "reason": "decrypt_failed"},
            )
            return None
        return decrypted.decode("utf-8", errors="replace")

    def rotate_data_key(self, *, reencrypt_existing: bool = True) -> str:
        """Rotate active data key; optionally re-encrypt existing original payloads."""
        new_key_id = self._add_data_key()
        self._active_key_id = new_key_id
        self._persist_key_manifest()
        if reencrypt_existing:
            for path in sorted(self._original_dir.glob("*.bin")):
                chunk_id = path.stem
                plaintext = self._decrypt_payload(path.read_bytes(), chunk_id=chunk_id)
                path.write_bytes(self._encrypt_payload(plaintext, chunk_id=chunk_id))
        self._audit(
            "memory.key_rotated",
            {"active_key_id": self._active_key_id, "reencrypt_existing": reencrypt_existing},
        )
        return self._active_key_id

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

    def _resolve_master_secret(self, encryption_key: str | None) -> bytes:
        if encryption_key:
            return self._derive_password_secret(encryption_key.encode("utf-8"))
        env_secret = os.getenv("SHISAD_MEMORY_MASTER_KEY", "").strip()
        if env_secret:
            return self._derive_password_secret(env_secret.encode("utf-8"))
        machine_id = ""
        for candidate in (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")):
            if candidate.exists():
                machine_id = candidate.read_text(encoding="utf-8").strip()
                break
        basis = f"{os.getuid()}|{machine_id}|{self._storage_dir.resolve()}"
        return self._derive_password_secret(basis.encode("utf-8"))

    def _derive_password_secret(self, secret: bytes) -> bytes:
        salt = self._load_master_salt()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=300_000,
        )
        return kdf.derive(secret)

    def _load_master_salt(self) -> bytes:
        if self._master_salt_file.exists():
            salt = self._master_salt_file.read_bytes()
            if len(salt) != 16:
                raise ValueError("Invalid master salt length")
            return salt
        salt = os.urandom(16)
        self._master_salt_file.parent.mkdir(parents=True, exist_ok=True)
        self._master_salt_file.write_bytes(salt)
        os.chmod(self._master_salt_file, 0o600)
        return salt

    def _derive_kek(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=200_000,
        )
        return kdf.derive(self._master_secret)

    @staticmethod
    def _b64(data: bytes) -> str:
        return base64.b64encode(data).decode("utf-8")

    @staticmethod
    def _unb64(data: str) -> bytes:
        return base64.b64decode(data.encode("utf-8"))

    def _wrap_data_key(self, key_material: bytes) -> tuple[str, str, str]:
        salt = os.urandom(16)
        nonce = os.urandom(12)
        kek = self._derive_kek(salt)
        wrapped = AESGCM(kek).encrypt(nonce, key_material, associated_data=None)
        return self._b64(salt), self._b64(nonce), self._b64(wrapped)

    def _unwrap_data_key(self, *, salt_b64: str, nonce_b64: str, wrapped_key_b64: str) -> bytes:
        salt = self._unb64(salt_b64)
        nonce = self._unb64(nonce_b64)
        wrapped = self._unb64(wrapped_key_b64)
        kek = self._derive_kek(salt)
        return AESGCM(kek).decrypt(nonce, wrapped, associated_data=None)

    def _load_or_create_keys(self) -> None:
        if self._key_manifest_file.exists():
            raw = json.loads(self._key_manifest_file.read_text(encoding="utf-8"))
            keys = raw.get("keys", [])
            active = str(raw.get("active_key_id", "")).strip()
            if not isinstance(keys, list) or not keys:
                raise ValueError("Invalid key manifest: keys missing")
            for entry in keys:
                key_id = str(entry["key_id"])
                key_material = self._unwrap_data_key(
                    salt_b64=str(entry["salt_b64"]),
                    nonce_b64=str(entry["nonce_b64"]),
                    wrapped_key_b64=str(entry["wrapped_key_b64"]),
                )
                self._key_material_by_id[key_id] = key_material
                self._key_metadata_by_id[key_id] = {
                    "key_id": key_id,
                    "created_at": str(entry.get("created_at", "")),
                    "salt_b64": str(entry["salt_b64"]),
                    "nonce_b64": str(entry["nonce_b64"]),
                    "wrapped_key_b64": str(entry["wrapped_key_b64"]),
                }
            self._active_key_id = active or next(iter(self._key_material_by_id))
            return

        # Migrate legacy plaintext key file to wrapped manifest if present.
        if self._legacy_key_file.exists():
            legacy = self._legacy_key_file.read_bytes()
            if len(legacy) != 32:
                raise ValueError("Invalid legacy key length")
            key_id = self._register_data_key(legacy)
            self._active_key_id = key_id
            self._persist_key_manifest()
            self._legacy_key_file.unlink(missing_ok=True)
            return

        # First-run key bootstrap.
        self._active_key_id = self._add_data_key()
        self._persist_key_manifest()

    def _register_data_key(self, key_material: bytes) -> str:
        key_id = uuid.uuid4().hex
        salt_b64, nonce_b64, wrapped_key_b64 = self._wrap_data_key(key_material)
        self._key_material_by_id[key_id] = key_material
        self._key_metadata_by_id[key_id] = {
            "key_id": key_id,
            "created_at": datetime.now(UTC).isoformat(),
            "salt_b64": salt_b64,
            "nonce_b64": nonce_b64,
            "wrapped_key_b64": wrapped_key_b64,
        }
        return key_id

    def _add_data_key(self) -> str:
        return self._register_data_key(os.urandom(32))

    def _persist_key_manifest(self) -> None:
        payload = {
            "version": 1,
            "active_key_id": self._active_key_id,
            "keys": [
                self._key_metadata_by_id[key_id]
                for key_id in sorted(self._key_metadata_by_id)
            ],
        }
        self._key_manifest_file.parent.mkdir(parents=True, exist_ok=True)
        self._key_manifest_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.chmod(self._key_manifest_file, 0o600)

    def _encrypt_payload(self, payload: bytes, *, chunk_id: str | None = None) -> bytes:
        key = self._key_material_by_id[self._active_key_id]
        nonce = os.urandom(12)
        aad = self._aad(self._active_key_id, chunk_id)
        ciphertext = AESGCM(key).encrypt(nonce, payload, associated_data=aad)
        envelope = {
            "v": 3,
            "kid": self._active_key_id,
            "chunk_id": chunk_id or "",
            "nonce_b64": self._b64(nonce),
            "ciphertext_b64": self._b64(ciphertext),
        }
        return json.dumps(envelope, separators=(",", ":")).encode("utf-8")

    def _decrypt_payload(self, payload: bytes, *, chunk_id: str | None = None) -> bytes:
        envelope: Any | None = None
        try:
            envelope = json.loads(payload.decode("utf-8"))
        except Exception:
            envelope = None

        if isinstance(envelope, dict) and envelope.get("v") in {2, 3}:
            key_id = str(envelope["kid"])
            key = self._key_material_by_id[key_id]
            bound_chunk = str(envelope.get("chunk_id", "")).strip() or None
            if chunk_id and bound_chunk and chunk_id != bound_chunk:
                raise ValueError("chunk_id binding mismatch")
            nonce = self._unb64(str(envelope["nonce_b64"]))
            ciphertext = self._unb64(str(envelope["ciphertext_b64"]))
            if envelope.get("v") == 2 and "chunk_id" not in envelope:
                return AESGCM(key).decrypt(nonce, ciphertext, associated_data=None)
            aad = self._aad(key_id, bound_chunk)
            return AESGCM(key).decrypt(nonce, ciphertext, associated_data=aad)

        # Legacy payload format fallback: nonce + ciphertext.
        if len(payload) < 13:
            raise ValueError("ciphertext too short")
        key = self._key_material_by_id[self._active_key_id]
        nonce = payload[:12]
        ciphertext = payload[12:]
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data=None)

    @staticmethod
    def _aad(key_id: str, chunk_id: str | None) -> bytes:
        return f"shisad:v2|kid={key_id}|chunk={chunk_id or ''}".encode()

    def _audit(self, action: str, payload: dict[str, Any]) -> None:
        if self._audit_hook is not None:
            self._audit_hook(action, payload)

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

    def _embed_text(self, text: str) -> list[float]:
        # Provider-backed semantic vectors with deterministic local fallback.
        if self._embeddings_provider is not None:
            try:
                vectors = self._embeddings_provider.embed([text])
                if vectors and vectors[0]:
                    values = [float(v) for v in vectors[0]]
                    norm = math.sqrt(sum(v * v for v in values)) or 1.0
                    return [v / norm for v in values]
            except Exception:
                # Fail closed to deterministic local fallback.
                pass

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
