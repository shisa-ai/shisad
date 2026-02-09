#!/usr/bin/env python3
"""Generate per-package coverage summary artifact from coverage.xml."""

from __future__ import annotations

import argparse
import json
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path


def _package_for_filename(filename: str) -> str:
    parts = Path(filename).parts
    if len(parts) >= 3 and parts[0] == "src" and parts[1] == "shisad":
        return parts[2]
    if len(parts) >= 2:
        return parts[0]
    return "root"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xml", required=True, help="Path to coverage.xml")
    parser.add_argument("--output", required=True, help="Output JSON path")
    args = parser.parse_args()

    xml_path = Path(args.xml)
    root = ET.fromstring(xml_path.read_text(encoding="utf-8"))
    totals: dict[str, dict[str, int]] = defaultdict(lambda: {"covered": 0, "total": 0})

    for class_node in root.findall(".//class"):
        filename = class_node.attrib.get("filename", "")
        package = _package_for_filename(filename)
        for line in class_node.findall("./lines/line"):
            totals[package]["total"] += 1
            if int(line.attrib.get("hits", "0")) > 0:
                totals[package]["covered"] += 1

    packages: list[dict[str, object]] = []
    for package, values in sorted(totals.items()):
        total = values["total"]
        covered = values["covered"]
        percent = round((covered / total) * 100.0, 2) if total else 100.0
        packages.append(
            {
                "package": package,
                "covered_lines": covered,
                "total_lines": total,
                "coverage_percent": percent,
            }
        )

    payload = {"packages": packages}
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
