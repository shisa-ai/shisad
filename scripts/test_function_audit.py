#!/usr/bin/env python3
"""Fail if any pytest test file has zero collectable test functions."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path


def _count_test_functions(path: Path) -> int:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError):
        return 0

    count = 0
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith(
            "test_"
        ):
            count += 1
            continue
        if isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            for child in node.body:
                is_test_method = isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
                    child.name.startswith("test_")
                )
                if is_test_method:
                    count += 1
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tests-root", default="tests", help="Root directory for pytest files")
    args = parser.parse_args()

    root = Path(args.tests_root)
    if not root.exists():
        raise SystemExit(f"tests root missing: {root}")

    files = sorted(
        {
            path
            for pattern in ("test_*.py", "*_test.py")
            for path in root.rglob(pattern)
            if path.is_file()
        }
    )
    empty: list[str] = []
    for path in files:
        if _count_test_functions(path) == 0:
            empty.append(str(path))

    payload = {
        "checked_files": len(files),
        "empty_test_files": empty,
        "status": "ok" if not empty else "empty_files_found",
    }
    print(json.dumps(payload, indent=2))
    return 0 if not empty else 2


if __name__ == "__main__":
    raise SystemExit(main())
