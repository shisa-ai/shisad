"""Guard against untracked growth in test daemon startup/build sites."""

from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path
from typing import Final

_CALL_LABELS: Final[tuple[str, ...]] = ("run_daemon", "DaemonServices.build")


def _call_label(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name) and func.id == "run_daemon":
        return "run_daemon"
    if (
        isinstance(func, ast.Attribute)
        and func.attr == "build"
        and isinstance(func.value, ast.Name)
        and func.value.id == "DaemonServices"
    ):
        return "DaemonServices.build"
    return None


class _CallSiteCounter(ast.NodeVisitor):
    def __init__(self) -> None:
        self.counts: dict[str, int] = {label: 0 for label in _CALL_LABELS}

    def visit_Call(self, node: ast.Call) -> None:
        label = _call_label(node.func)
        if label is not None:
            self.counts[label] += 1
        self.generic_visit(node)


def _scan_test_file(path: Path) -> dict[str, int]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    counter = _CallSiteCounter()
    counter.visit(tree)
    return counter.counts


def _scan_tests(repo_root: Path, tests_root: Path) -> dict[str, object]:
    counts: dict[str, dict[str, int]] = {label: {} for label in _CALL_LABELS}
    for path in sorted(tests_root.rglob("*.py")):
        relative = path.relative_to(repo_root).as_posix()
        file_counts = _scan_test_file(path)
        for label in _CALL_LABELS:
            count = file_counts[label]
            if count > 0:
                counts[label][relative] = count

    totals = {label: sum(per_file.values()) for label, per_file in counts.items()}
    return {
        "tests_root": tests_root.relative_to(repo_root).as_posix(),
        "counts": counts,
        "totals": totals,
    }


def _write_baseline(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _compare_against_baseline(
    *,
    baseline: dict[str, object],
    current: dict[str, object],
) -> list[str]:
    failures: list[str] = []
    baseline_counts = baseline.get("counts", {})
    current_counts = current.get("counts", {})
    if not isinstance(baseline_counts, dict) or not isinstance(current_counts, dict):
        return ["baseline file is missing a top-level 'counts' mapping"]

    for label in _CALL_LABELS:
        baseline_per_file = baseline_counts.get(label, {})
        current_per_file = current_counts.get(label, {})
        if not isinstance(baseline_per_file, dict) or not isinstance(current_per_file, dict):
            failures.append(f"baseline entry for {label!r} is not a mapping")
            continue
        for relative_path, current_count in sorted(current_per_file.items()):
            if not isinstance(relative_path, str) or not isinstance(current_count, int):
                failures.append(f"current scan entry for {label!r} is malformed")
                continue
            allowed = baseline_per_file.get(relative_path, 0)
            if not isinstance(allowed, int):
                failures.append(f"baseline count for {label!r} {relative_path} is malformed")
                continue
            if current_count > allowed:
                failures.append(
                    f"{label} call sites increased in {relative_path}: "
                    f"{current_count} > baseline {allowed}"
                )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baseline",
        type=Path,
        required=True,
        help="Path to the committed baseline JSON file.",
    )
    parser.add_argument(
        "--tests-root",
        type=Path,
        default=Path("tests"),
        help="Root directory to scan for test files.",
    )
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="Overwrite the baseline file with the current scan output.",
    )
    args = parser.parse_args()

    repo_root = Path.cwd()
    tests_root = (repo_root / args.tests_root).resolve()
    if not tests_root.exists():
        parser.error(f"tests root does not exist: {tests_root}")

    current = _scan_tests(repo_root=repo_root, tests_root=tests_root)

    if args.write_baseline:
        _write_baseline(args.baseline, current)
        print(
            "Wrote daemon site baseline:",
            json.dumps(current["totals"], sort_keys=True),
        )
        return 0

    if not args.baseline.exists():
        parser.error(f"baseline file does not exist: {args.baseline}")

    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    failures = _compare_against_baseline(baseline=baseline, current=current)
    if failures:
        print("Daemon site guard failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        print(
            "Current totals:",
            json.dumps(current["totals"], sort_keys=True),
            file=sys.stderr,
        )
        return 1

    print("Daemon site guard passed:", json.dumps(current["totals"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
