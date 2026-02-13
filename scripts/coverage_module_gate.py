#!/usr/bin/env python3
"""Enforce per-module coverage floors from coverage.xml."""

from __future__ import annotations

import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path


def _threshold_for(filename: str, *, critical_floor: float, module_floor: float) -> float | None:
    if filename.startswith("src/shisad/"):
        normalized = filename.removeprefix("src/")
    elif filename.startswith("shisad/"):
        normalized = filename
    else:
        return None
    if normalized.startswith("shisad/security/") or normalized.startswith("shisad/executors/"):
        return critical_floor
    return module_floor


def _percent_for(class_node: ET.Element) -> tuple[int, int, float]:
    total = 0
    covered = 0
    for line in class_node.findall("./lines/line"):
        total += 1
        if int(line.attrib.get("hits", "0")) > 0:
            covered += 1
    percent = round((covered / total) * 100.0, 2) if total else 100.0
    return covered, total, percent


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xml", required=True, help="Path to coverage.xml")
    parser.add_argument(
        "--critical-floor",
        type=float,
        default=80.0,
        help="Minimum percent for security/executors modules",
    )
    parser.add_argument(
        "--module-floor",
        type=float,
        default=60.0,
        help="Minimum percent for all other src/shisad modules",
    )
    args = parser.parse_args()

    xml_path = Path(args.xml)
    if not xml_path.exists():
        raise SystemExit(f"coverage xml missing: {xml_path}")

    root = ET.fromstring(xml_path.read_text(encoding="utf-8"))
    below: list[dict[str, float | str]] = []
    checked: list[dict[str, float | str]] = []

    for class_node in root.findall(".//class"):
        filename = class_node.attrib.get("filename", "")
        threshold = _threshold_for(
            filename,
            critical_floor=float(args.critical_floor),
            module_floor=float(args.module_floor),
        )
        if threshold is None:
            continue
        covered, total, percent = _percent_for(class_node)
        record: dict[str, float | str] = {
            "module": filename,
            "coverage_percent": percent,
            "threshold_percent": threshold,
            "covered_lines": float(covered),
            "total_lines": float(total),
        }
        checked.append(record)
        if percent < threshold:
            below.append(record)

    status = "ok"
    exit_code = 0
    if not checked:
        status = "no_modules_checked"
        exit_code = 2
    elif below:
        status = "below_floor"
        exit_code = 2

    payload = {
        "checked_modules": len(checked),
        "critical_floor_percent": float(args.critical_floor),
        "module_floor_percent": float(args.module_floor),
        "status": status,
        "below": sorted(below, key=lambda item: float(item["coverage_percent"])),
    }
    print(json.dumps(payload, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
