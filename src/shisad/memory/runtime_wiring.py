"""Shared memory component construction for daemon and eval SUT paths."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shisad.memory.ingestion import EmbeddingFingerprint, IngestionPipeline, SyncEmbeddingsProvider
from shisad.memory.manager import MemoryManager
from shisad.security.firewall import ContentFirewall


@dataclass(frozen=True)
class MemoryRuntimeComponents:
    """Memory components plus the storage paths used to build them."""

    storage_root: Path
    legacy_storage_dir: Path
    ingestion: IngestionPipeline
    memory_manager: MemoryManager


def deterministic_embedding_fingerprint() -> EmbeddingFingerprint:
    """Fingerprint used when the local deterministic fallback is intentional."""

    return EmbeddingFingerprint(
        model_id="shisad-deterministic-sha256",
        base_url="local://sha256",
    )


def build_memory_runtime_components(
    data_dir: Path,
    *,
    firewall: ContentFirewall | None = None,
    embedding_fingerprint: EmbeddingFingerprint | None = None,
    embeddings_provider: SyncEmbeddingsProvider | None = None,
    audit_hook: Callable[[str, dict[str, Any]], None] | None = None,
) -> MemoryRuntimeComponents:
    """Build the memory substrate using the daemon's canonical path layout."""

    storage_root = data_dir / "memory_entries"
    legacy_storage_dir = data_dir / "memory"
    return MemoryRuntimeComponents(
        storage_root=storage_root,
        legacy_storage_dir=legacy_storage_dir,
        ingestion=IngestionPipeline(
            storage_root,
            firewall=firewall,
            embedding_fingerprint=embedding_fingerprint or deterministic_embedding_fingerprint(),
            embeddings_provider=embeddings_provider,
            legacy_storage_dir=legacy_storage_dir,
            audit_hook=audit_hook,
        ),
        memory_manager=MemoryManager(
            storage_root,
            audit_hook=audit_hook,
        ),
    )
