"""SQLite runtime diagnostics for memory storage."""

from __future__ import annotations

import sqlite3
import sys
from collections.abc import Callable, Iterable
from typing import Any, Protocol, cast

SQLITE_FTS5_DOCS_PATH = "docs/runbooks/SQLITE.md#sqlite-fts5-runtime"


class _SQLiteConnection(Protocol):
    def __enter__(self) -> _SQLiteConnection: ...

    def __exit__(self, *_exc: object) -> object: ...

    def execute(self, sql: str, *args: object, **kwargs: object) -> Any: ...


def sqlite_runtime_status(
    *,
    connect: Callable[[str], _SQLiteConnection] | None = None,
) -> dict[str, Any]:
    """Return the Python sqlite3 runtime status without touching user data."""

    connector = cast(
        Callable[[str], _SQLiteConnection],
        sqlite3.connect if connect is None else connect,
    )
    compile_options, compile_options_error = _sqlite_compile_options(connect=connector)
    fts5_available, fts5_error = _sqlite_fts5_probe(connect=connector)
    problems: list[str] = []
    if not fts5_available:
        problems.append("sqlite_fts5_unavailable")
    status = "degraded" if problems else "ok"
    compile_option_reported = "ENABLE_FTS5" in compile_options
    hint = ""
    if not fts5_available:
        hint = (
            "Python sqlite3 is linked against SQLite without FTS5. shisad will "
            "fall back to degraded lexical retrieval; use a Python runtime linked "
            "against SQLite built with FTS5 for full retrieval indexing."
        )
    return {
        "status": status,
        "problems": sorted(set(problems)),
        "sqlite": {
            "python_module": "sqlite3",
            "python_executable": sys.executable,
            "library_version": sqlite3.sqlite_version,
            "library_version_info": list(sqlite3.sqlite_version_info),
            "fts5": {
                "available": fts5_available,
                "compile_option_reported": compile_option_reported,
                "probe_error": fts5_error,
            },
            "compile_options": compile_options,
            "compile_options_error": compile_options_error,
        },
        "docs": SQLITE_FTS5_DOCS_PATH,
        "hint": hint,
    }


def _sqlite_fts5_probe(
    *,
    connect: Callable[[str], _SQLiteConnection],
) -> tuple[bool, str]:
    try:
        with connect(":memory:") as conn:
            conn.execute(
                "CREATE VIRTUAL TABLE temp.shisad_fts5_probe USING fts5(content)"
            )
    except sqlite3.Error as exc:
        return False, f"{exc.__class__.__name__}: {exc}"
    return True, ""


def _sqlite_compile_options(
    *,
    connect: Callable[[str], _SQLiteConnection],
) -> tuple[list[str], str]:
    try:
        with connect(":memory:") as conn:
            rows = conn.execute("PRAGMA compile_options").fetchall()
    except sqlite3.Error as exc:
        return [], f"{exc.__class__.__name__}: {exc}"
    return sorted(set(_normalize_compile_options(rows))), ""


def _normalize_compile_options(rows: Iterable[object]) -> list[str]:
    options: list[str] = []
    for row in rows:
        value: object
        if isinstance(row, str):
            value = row
        elif isinstance(row, (tuple, list)) and row:
            value = row[0]
        else:
            value = row
        option = str(value).strip()
        if option:
            options.append(option)
    return options
