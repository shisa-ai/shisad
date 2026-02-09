#!/usr/bin/env python3
"""Validate coverage report against baseline metadata."""

from __future__ import annotations

import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path


def _read_coverage(xml_path: Path) -> float:
    root = ET.fromstring(xml_path.read_text())
    rate = float(root.attrib.get("line-rate", "0.0"))
    return round(rate * 100.0, 2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xml", required=True, help="Path to coverage.xml")
    parser.add_argument(
        "--baseline",
        default="docs/coverage-baseline.json",
        help="Coverage baseline metadata JSON",
    )
    args = parser.parse_args()

    xml_path = Path(args.xml)
    baseline_path = Path(args.baseline)
    if not xml_path.exists():
        raise SystemExit(f"coverage xml missing: {xml_path}")
    if not baseline_path.exists():
        raise SystemExit(f"baseline missing: {baseline_path}")

    total = _read_coverage(xml_path)
    baseline = json.loads(baseline_path.read_text())
    floor = float(baseline.get("floor_percent", 0.0))
    status = {
        "total_percent": total,
        "floor_percent": floor,
        "status": "ok" if total >= floor else "below_floor",
    }
    print(json.dumps(status, indent=2))
    return 0 if total >= floor else 2


if __name__ == "__main__":
    raise SystemExit(main())

