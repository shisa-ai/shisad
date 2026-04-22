"""SQLite-backed retrieval storage and search primitives."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(slots=True)
class RetrievalBackendRow:
    """Backend row hydrated from SQLite retrieval storage."""

    chunk_id: str
    source_id: str
    source_type: str
    collection: str
    created_at: str
    content_sanitized: str
    extracted_facts_json: str
    risk_score: float
    original_hash: str
    taint_labels_json: str
    quarantined: bool
    citation_count: int
    last_cited_at: str | None
    embedding: list[float]


class RetrievalBackend(Protocol):
    """Stable retrieval backend contract for ingestion/search."""

    def upsert_record(
        self,
        *,
        row: RetrievalBackendRow,
        original_payload: bytes,
    ) -> None: ...

    def list_records(
        self,
        *,
        collections: set[str] | None = None,
        include_quarantined: bool = False,
    ) -> list[RetrievalBackendRow]: ...

    def lexical_match_ids(
        self,
        query: str,
        *,
        collections: set[str] | None = None,
        include_quarantined: bool = False,
    ) -> set[str]: ...

    def read_original_payload(self, chunk_id: str) -> bytes | None: ...

    def iter_original_payloads(self) -> list[tuple[str, bytes]]: ...

    def replace_original_payload(self, *, chunk_id: str, original_payload: bytes) -> None: ...

    def quarantine_source(self, source_id: str) -> int: ...

    def record_citations(
        self,
        chunk_ids: list[str],
        *,
        cited_at: str,
    ) -> int: ...

    def count_records(self) -> int: ...

    def count_vectors(self) -> int: ...

    def clear_records(self) -> None: ...

    def backfill_search_index(
        self,
        *,
        embed_text: Callable[[str], list[float]],
    ) -> int: ...


_FTS_TOKEN = re.compile(r"[A-Za-z0-9_]+")


class SQLiteRetrievalBackend:
    """SQLite implementation of the retrieval backend contract."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            self._ensure_schema(conn)

    def upsert_record(
        self,
        *,
        row: RetrievalBackendRow,
        original_payload: bytes,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO retrieval_records (
                    chunk_id,
                    source_id,
                    source_type,
                    collection,
                    created_at,
                    content_sanitized,
                    extracted_facts_json,
                    risk_score,
                    original_hash,
                    taint_labels_json,
                    quarantined,
                    citation_count,
                    last_cited_at,
                    original_payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row.chunk_id,
                    row.source_id,
                    row.source_type,
                    row.collection,
                    row.created_at,
                    row.content_sanitized,
                    row.extracted_facts_json,
                    row.risk_score,
                    row.original_hash,
                    row.taint_labels_json,
                    int(row.quarantined),
                    row.citation_count,
                    row.last_cited_at,
                    original_payload,
                ),
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO retrieval_vectors (
                    chunk_id,
                    embedding_json
                ) VALUES (?, ?)
                """,
                (row.chunk_id, json.dumps(row.embedding, separators=(",", ":"))),
            )
            conn.execute("DELETE FROM retrieval_fts WHERE chunk_id = ?", (row.chunk_id,))
            conn.execute(
                """
                INSERT INTO retrieval_fts (
                    chunk_id,
                    content_sanitized
                ) VALUES (?, ?)
                """,
                (row.chunk_id, row.content_sanitized),
            )

    def list_records(
        self,
        *,
        collections: set[str] | None = None,
        include_quarantined: bool = False,
    ) -> list[RetrievalBackendRow]:
        if collections is not None and not collections:
            return []
        query = """
            SELECT
                r.chunk_id,
                r.source_id,
                r.source_type,
                r.collection,
                r.created_at,
                r.content_sanitized,
                r.extracted_facts_json,
                r.risk_score,
                r.original_hash,
                r.taint_labels_json,
                r.quarantined,
                r.citation_count,
                r.last_cited_at,
                v.embedding_json
            FROM retrieval_records r
            LEFT JOIN retrieval_vectors v ON v.chunk_id = r.chunk_id
        """
        predicates: list[str] = []
        params: list[object] = []
        if collections:
            placeholders = ", ".join("?" for _ in collections)
            predicates.append(f"r.collection IN ({placeholders})")
            params.extend(sorted(collections))
        if not include_quarantined:
            predicates.append("r.quarantined = 0")
        if predicates:
            query += " WHERE " + " AND ".join(predicates)
        query += " ORDER BY r.created_at ASC, r.chunk_id ASC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        hydrated: list[RetrievalBackendRow] = []
        for row in rows:
            try:
                embedding_json = row["embedding_json"]
                if embedding_json is None:
                    continue
                hydrated.append(
                    RetrievalBackendRow(
                        chunk_id=str(row["chunk_id"]),
                        source_id=str(row["source_id"]),
                        source_type=str(row["source_type"]),
                        collection=str(row["collection"]),
                        created_at=str(row["created_at"]),
                        content_sanitized=str(row["content_sanitized"]),
                        extracted_facts_json=str(row["extracted_facts_json"]),
                        risk_score=float(row["risk_score"]),
                        original_hash=str(row["original_hash"]),
                        taint_labels_json=str(row["taint_labels_json"]),
                        quarantined=bool(row["quarantined"]),
                        citation_count=int(row["citation_count"]),
                        last_cited_at=(
                            str(row["last_cited_at"]) if row["last_cited_at"] is not None else None
                        ),
                        embedding=[float(value) for value in json.loads(str(embedding_json))],
                    )
                )
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
        return hydrated

    def lexical_match_ids(
        self,
        query: str,
        *,
        collections: set[str] | None = None,
        include_quarantined: bool = False,
    ) -> set[str]:
        if collections is not None and not collections:
            return set()
        tokens = _FTS_TOKEN.findall(query)
        if not tokens:
            return set()
        match_query = " OR ".join(f'"{token}"' for token in tokens)
        sql = """
            SELECT DISTINCT f.chunk_id
            FROM retrieval_fts f
            JOIN retrieval_records r ON r.chunk_id = f.chunk_id
            WHERE retrieval_fts MATCH ?
        """
        params: list[object] = [match_query]
        if collections:
            placeholders = ", ".join("?" for _ in collections)
            sql += f" AND r.collection IN ({placeholders})"
            params.extend(sorted(collections))
        if not include_quarantined:
            sql += " AND r.quarantined = 0"
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return {str(row["chunk_id"]) for row in rows}

    def read_original_payload(self, chunk_id: str) -> bytes | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT original_payload FROM retrieval_records WHERE chunk_id = ?",
                (chunk_id,),
            ).fetchone()
        if row is None:
            return None
        return bytes(row["original_payload"])

    def iter_original_payloads(self) -> list[tuple[str, bytes]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT chunk_id, original_payload FROM retrieval_records ORDER BY chunk_id ASC"
            ).fetchall()
        return [(str(row["chunk_id"]), bytes(row["original_payload"])) for row in rows]

    def replace_original_payload(self, *, chunk_id: str, original_payload: bytes) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE retrieval_records SET original_payload = ? WHERE chunk_id = ?",
                (original_payload, chunk_id),
            )

    def quarantine_source(self, source_id: str) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE retrieval_records
                SET quarantined = 1
                WHERE source_id = ? AND quarantined = 0
                """,
                (source_id,),
            )
            return int(cursor.rowcount or 0)

    def record_citations(
        self,
        chunk_ids: list[str],
        *,
        cited_at: str,
    ) -> int:
        unique_chunk_ids = [chunk_id for chunk_id in dict.fromkeys(chunk_ids) if chunk_id]
        if not unique_chunk_ids:
            return 0
        with self._connect() as conn:
            cursor = conn.executemany(
                """
                UPDATE retrieval_records
                SET citation_count = citation_count + 1,
                    last_cited_at = ?
                WHERE chunk_id = ?
                """,
                [(cited_at, chunk_id) for chunk_id in unique_chunk_ids],
            )
        return int(cursor.rowcount or 0)

    def count_records(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) FROM retrieval_records").fetchone()
        return int(row[0]) if row is not None else 0

    def count_vectors(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) FROM retrieval_vectors").fetchone()
        return int(row[0]) if row is not None else 0

    def clear_records(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM retrieval_records")
            conn.execute("DELETE FROM retrieval_vectors")
            conn.execute("DELETE FROM retrieval_fts")

    def backfill_search_index(
        self,
        *,
        embed_text: Callable[[str], list[float]],
    ) -> int:
        with self._connect() as conn:
            record_rows = conn.execute(
                """
                SELECT chunk_id, content_sanitized
                FROM retrieval_records
                ORDER BY created_at ASC, chunk_id ASC
                """
            ).fetchall()
            vector_ids = {
                str(row["chunk_id"])
                for row in conn.execute("SELECT chunk_id FROM retrieval_vectors").fetchall()
            }
            fts_ids = {
                str(row["chunk_id"])
                for row in conn.execute("SELECT chunk_id FROM retrieval_fts").fetchall()
            }
            rebuilt = 0
            for row in record_rows:
                chunk_id = str(row["chunk_id"])
                content = str(row["content_sanitized"])
                if chunk_id not in vector_ids:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO retrieval_vectors (
                            chunk_id,
                            embedding_json
                        ) VALUES (?, ?)
                        """,
                        (
                            chunk_id,
                            json.dumps(embed_text(content), separators=(",", ":")),
                        ),
                    )
                    rebuilt += 1
                if chunk_id not in fts_ids:
                    conn.execute(
                        """
                        INSERT INTO retrieval_fts (
                            chunk_id,
                            content_sanitized
                        ) VALUES (?, ?)
                        """,
                        (chunk_id, content),
                    )
                    rebuilt += 1
        return rebuilt

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _ensure_schema(conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS retrieval_records (
                chunk_id TEXT PRIMARY KEY,
                source_id TEXT NOT NULL,
                source_type TEXT NOT NULL,
                collection TEXT NOT NULL,
                created_at TEXT NOT NULL,
                content_sanitized TEXT NOT NULL,
                extracted_facts_json TEXT NOT NULL,
                risk_score REAL NOT NULL,
                original_hash TEXT NOT NULL,
                taint_labels_json TEXT NOT NULL,
                quarantined INTEGER NOT NULL,
                citation_count INTEGER NOT NULL DEFAULT 0,
                last_cited_at TEXT,
                original_payload BLOB NOT NULL
            )
            """
        )
        columns = {
            str(row["name"])
            for row in conn.execute("PRAGMA table_info(retrieval_records)").fetchall()
        }
        if "citation_count" not in columns:
            conn.execute(
                """
                ALTER TABLE retrieval_records
                ADD COLUMN citation_count INTEGER NOT NULL DEFAULT 0
                """
            )
        if "last_cited_at" not in columns:
            conn.execute(
                """
                ALTER TABLE retrieval_records
                ADD COLUMN last_cited_at TEXT
                """
            )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS retrieval_vectors (
                chunk_id TEXT PRIMARY KEY,
                embedding_json TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS retrieval_fts
            USING fts5(chunk_id UNINDEXED, content_sanitized)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_retrieval_records_collection_created
            ON retrieval_records (collection, created_at)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_retrieval_records_source_created
            ON retrieval_records (source_id, created_at)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_retrieval_records_quarantined
            ON retrieval_records (quarantined, created_at)
            """
        )
