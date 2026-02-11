#!/usr/bin/env python3
"""Evaluate M6 adversarial metrics against CI and regression gates."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from shisad.security.adversarial import (
    AdversarialMetrics,
    ci_gate,
    detect_regression,
    performance_gate,
)


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected object payload at {path}")
    return payload


def _parse_metrics(payload: dict[str, Any]) -> AdversarialMetrics:
    metrics_payload = payload.get("metrics")
    if not isinstance(metrics_payload, dict):
        raise ValueError("metrics payload missing")
    return AdversarialMetrics(
        attack_success_rate=float(metrics_payload.get("attack_success_rate", 1.0)),
        utility_retention=float(metrics_payload.get("utility_retention", 0.0)),
        false_positive_rate=float(metrics_payload.get("false_positive_rate", 1.0)),
        detection_latency_ms=float(metrics_payload.get("detection_latency_ms", 10_000.0)),
        memory_usage_mb=float(metrics_payload.get("memory_usage_mb", 0.0)),
    )


def _select_baseline(payload: dict[str, Any], *, lane: str) -> AdversarialMetrics:
    lane_payload = payload.get(lane)
    if not isinstance(lane_payload, dict):
        raise ValueError(f"baseline lane '{lane}' missing")
    return AdversarialMetrics(
        attack_success_rate=float(lane_payload.get("attack_success_rate", 1.0)),
        utility_retention=float(lane_payload.get("utility_retention", 0.0)),
        false_positive_rate=float(lane_payload.get("false_positive_rate", 1.0)),
        detection_latency_ms=float(lane_payload.get("detection_latency_ms", 10_000.0)),
        memory_usage_mb=float(lane_payload.get("memory_usage_mb", 0.0)),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metrics", type=Path, required=True, help="Input metrics JSON path.")
    parser.add_argument("--baseline", type=Path, required=True, help="Baseline metrics JSON path.")
    parser.add_argument("--lane", choices=("core", "full"), required=True, help="Lane to evaluate.")
    parser.add_argument("--output", type=Path, required=True, help="Output report JSON path.")
    parser.add_argument(
        "--allow-regression",
        action="store_true",
        help="Allow regression findings without failing the job.",
    )
    args = parser.parse_args()

    metrics_payload = _load_json(args.metrics)
    baseline_payload = _load_json(args.baseline)
    metrics = _parse_metrics(metrics_payload)
    baseline = _select_baseline(baseline_payload, lane=args.lane)

    ci_decision = ci_gate(metrics)
    perf_decision = performance_gate(metrics)
    regressions = detect_regression(baseline=baseline, current=metrics)

    allowed = (
        ci_decision.allowed
        and perf_decision.allowed
        and (args.allow_regression or not regressions)
    )
    report = {
        "lane": args.lane,
        "metrics": asdict(metrics),
        "baseline": asdict(baseline),
        "ci_gate": {
            "allowed": ci_decision.allowed,
            "reason": ci_decision.reason,
            "details": ci_decision.details,
        },
        "performance_gate": {
            "allowed": perf_decision.allowed,
            "reason": perf_decision.reason,
            "details": perf_decision.details,
        },
        "regressions": regressions,
        "allow_regression_override": args.allow_regression,
        "allowed": allowed,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    if allowed:
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
