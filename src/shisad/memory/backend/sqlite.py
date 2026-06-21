"""SQLite-backed retrieval storage and search primitives."""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

logger = logging.getLogger(__name__)


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
    source_origin: str | None
    channel_trust: str | None
    confirmation_status: str | None
    scope: str | None
    taint_labels_json: str
    quarantined: bool
    citation_count: int
    last_cited_at: str | None
    embedding: list[float]
    # (user, workspace) ownership added in v0.7.1 C2 to close cross-session
    # recall leakage. NULL for pre-migration rows; new writes populate both.
    user_id: str | None = None
    workspace_id: str | None = None


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
_SearchIndexMode = Literal["fts5", "like"]
_SEARCH_INDEX_TABLES = ("retrieval_fts", "retrieval_lexical")


class SQLiteRetrievalBackend:
    """SQLite implementation of the retrieval backend contract."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._search_index_mode: _SearchIndexMode = "fts5"
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            self._search_index_mode = self._ensure_schema(conn)

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
                    source_origin,
                    channel_trust,
                    confirmation_status,
                    scope,
                    user_id,
                    workspace_id,
                    taint_labels_json,
                    quarantined,
                    citation_count,
                    last_cited_at,
                    original_payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    row.source_origin,
                    row.channel_trust,
                    row.confirmation_status,
                    row.scope,
                    row.user_id,
                    row.workspace_id,
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
            self._delete_search_index_row(conn, row.chunk_id)
            self._insert_search_index_row(conn, row.chunk_id, row.content_sanitized)

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
                r.source_origin,
                r.channel_trust,
                r.confirmation_status,
                r.scope,
                r.user_id,
                r.workspace_id,
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
                        source_origin=(
                            str(row["source_origin"]) if row["source_origin"] is not None else None
                        ),
                        channel_trust=(
                            str(row["channel_trust"]) if row["channel_trust"] is not None else None
                        ),
                        confirmation_status=(
                            str(row["confirmation_status"])
                            if row["confirmation_status"] is not None
                            else None
                        ),
                        scope=str(row["scope"]) if row["scope"] is not None else None,
                        user_id=(str(row["user_id"]) if row["user_id"] is not None else None),
                        workspace_id=(
                            str(row["workspace_id"]) if row["workspace_id"] is not None else None
                        ),
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
        if self._search_index_mode == "fts5":
            match_query = " OR ".join(f'"{token}"' for token in tokens)
            sql = """
                SELECT DISTINCT f.chunk_id
                FROM retrieval_fts f
                JOIN retrieval_records r ON r.chunk_id = f.chunk_id
                WHERE retrieval_fts MATCH ?
            """
            params: list[object] = [match_query]
        else:
            predicates = [
                "LOWER(f.content_sanitized) LIKE ? ESCAPE '\\'"
                for _ in tokens
            ]
            sql = f"""
                SELECT DISTINCT f.chunk_id
                FROM retrieval_lexical f
                JOIN retrieval_records r ON r.chunk_id = f.chunk_id
                WHERE ({" OR ".join(predicates)})
            """
            params = [
                f"%{self._escape_like_token(token.lower())}%"
                for token in tokens
            ]
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
            self._clear_search_index_tables(conn)

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
            record_ids = {str(row["chunk_id"]) for row in record_rows}
            self._remove_stale_search_index_rows(conn, valid_chunk_ids=record_ids)
            vector_ids = {
                str(row["chunk_id"])
                for row in conn.execute("SELECT chunk_id FROM retrieval_vectors").fetchall()
            }
            fts_ids = {
                str(row["chunk_id"])
                for row in conn.execute(
                    f"SELECT chunk_id FROM {self._search_index_table}"
                ).fetchall()
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
                    self._insert_search_index_row(conn, chunk_id, content)
                    rebuilt += 1
        return rebuilt

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    @property
    def _search_index_table(self) -> str:
        if self._search_index_mode == "fts5":
            return "retrieval_fts"
        return "retrieval_lexical"

    def _delete_search_index_row(self, conn: sqlite3.Connection, chunk_id: str) -> None:
        for table_name in self._existing_search_index_tables(conn):
            self._delete_from_search_index_table(
                conn,
                table_name=table_name,
                where_clause="chunk_id = ?",
                params=(chunk_id,),
                context=f"chunk {chunk_id}",
            )

    def _insert_search_index_row(
        self,
        conn: sqlite3.Connection,
        chunk_id: str,
        content_sanitized: str,
    ) -> None:
        conn.execute(
            f"""
            INSERT OR REPLACE INTO {self._search_index_table} (
                chunk_id,
                content_sanitized
            ) VALUES (?, ?)
            """,
            (chunk_id, content_sanitized),
        )

    def _clear_search_index_tables(self, conn: sqlite3.Connection) -> None:
        for table_name in self._existing_search_index_tables(conn):
            self._delete_from_search_index_table(
                conn,
                table_name=table_name,
                where_clause=None,
                params=(),
                context="all rows",
            )

    def _remove_stale_search_index_rows(
        self,
        conn: sqlite3.Connection,
        *,
        valid_chunk_ids: set[str],
    ) -> None:
        if not valid_chunk_ids:
            self._clear_search_index_tables(conn)
            return
        placeholders = ", ".join("?" for _ in valid_chunk_ids)
        params = tuple(sorted(valid_chunk_ids))
        for table_name in self._existing_search_index_tables(conn):
            self._delete_from_search_index_table(
                conn,
                table_name=table_name,
                where_clause=f"chunk_id NOT IN ({placeholders})",
                params=params,
                context="stale rows",
            )

    def _delete_from_search_index_table(
        self,
        conn: sqlite3.Connection,
        *,
        table_name: str,
        where_clause: str | None,
        params: tuple[object, ...],
        context: str,
    ) -> None:
        sql = f"DELETE FROM {table_name}"
        if where_clause is not None:
            sql += f" WHERE {where_clause}"
        try:
            conn.execute(sql, params)
        except sqlite3.OperationalError as exc:
            if table_name == "retrieval_fts" and self._is_missing_fts5_error(exc):
                logger.warning(
                    "Unable to purge inactive SQLite FTS5 search index table %s "
                    "for %s in %s because FTS5 is unavailable; rerun with a "
                    "Python sqlite3 build that has ENABLE_FTS5 to purge it.",
                    table_name,
                    context,
                    self._db_path,
                )
                return
            raise

    @staticmethod
    def _existing_search_index_tables(conn: sqlite3.Connection) -> list[str]:
        rows = conn.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name IN ('retrieval_fts', 'retrieval_lexical')
            """
        ).fetchall()
        found = {str(row["name"]) for row in rows}
        return [table_name for table_name in _SEARCH_INDEX_TABLES if table_name in found]

    def _ensure_schema(self, conn: sqlite3.Connection) -> _SearchIndexMode:
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
                source_origin TEXT,
                channel_trust TEXT,
                confirmation_status TEXT,
                scope TEXT,
                user_id TEXT,
                workspace_id TEXT,
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
        if "source_origin" not in columns:
            conn.execute(
                """
                ALTER TABLE retrieval_records
                ADD COLUMN source_origin TEXT
                """
            )
        if "channel_trust" not in columns:
            conn.execute(
                """
                ALTER TABLE retrieval_records
                ADD COLUMN channel_trust TEXT
                """
            )
        if "confirmation_status" not in columns:
            conn.execute(
                """
                ALTER TABLE retrieval_records
                ADD COLUMN confirmation_status TEXT
                """
            )
        if "scope" not in columns:
            conn.execute(
                """
                ALTER TABLE retrieval_records
                ADD COLUMN scope TEXT
                """
            )
        # v0.7.1 C2: (user, workspace) ownership migration. Pre-migration rows
        # retain NULL owner and are excluded from recall by default.
        if "user_id" not in columns:
            conn.execute(
                """
                ALTER TABLE retrieval_records
                ADD COLUMN user_id TEXT
                """
            )
        if "workspace_id" not in columns:
            conn.execute(
                """
                ALTER TABLE retrieval_records
                ADD COLUMN workspace_id TEXT
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
        search_index_mode = self._ensure_search_index(conn)
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
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_retrieval_records_owner
            ON retrieval_records (user_id, workspace_id, created_at)
            """
        )
        return search_index_mode

    def _ensure_search_index(self, conn: sqlite3.Connection) -> _SearchIndexMode:
        try:
            self._create_fts_index(conn)
            return "fts5"
        except sqlite3.OperationalError as exc:
            if not self._is_missing_fts5_error(exc):
                raise
        logger.warning(
            "SQLite FTS5 extension is unavailable for %s; memory retrieval is "
            "running in degraded LIKE lexical-index mode. Use a Python sqlite3 "
            "build with ENABLE_FTS5 for full FTS retrieval indexing.",
            self._db_path,
        )
        self._create_fallback_lexical_index(conn)
        return "like"

    @staticmethod
    def _create_fts_index(conn: sqlite3.Connection) -> None:
        conn.execute("CREATE VIRTUAL TABLE temp.__shisad_fts5_probe USING fts5(x)")
        conn.execute("DROP TABLE temp.__shisad_fts5_probe")
        conn.execute(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS retrieval_fts
            USING fts5(chunk_id UNINDEXED, content_sanitized)
            """
        )

    @staticmethod
    def _create_fallback_lexical_index(conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS retrieval_lexical (
                chunk_id TEXT PRIMARY KEY,
                content_sanitized TEXT NOT NULL
            )
            """
        )

    @staticmethod
    def _is_missing_fts5_error(exc: sqlite3.OperationalError) -> bool:
        return "no such module: fts5" in str(exc).lower()

    @staticmethod
    def _escape_like_token(token: str) -> str:
        return token.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
