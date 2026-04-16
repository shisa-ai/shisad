"""Shared helpers for behavioral contract tests.

Previously both ``test_behavioral_contract.py`` and
``test_behavioral_contract_live_model.py`` carried near-identical copies of
``_extract_tool_outputs`` (plus closely-related stub-search handlers). Review
finding ADV-M2 called the duplication out because divergence in one copy
would silently invalidate the other file's assertions.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any


def extract_tool_outputs(
    payload: Mapping[str, Any] | str,
) -> dict[str, list[dict[str, Any]]]:
    """Parse structured ``tool_outputs``, falling back to legacy response markers.

    Behavioral contract tests historically relied on in-response string
    boundaries (``[[TOOL_OUTPUT_BEGIN tool=... ]] ... [[TOOL_OUTPUT_END]]``)
    to recover executed tool payloads. Modern responses instead expose a
    structured ``tool_outputs`` list. Accept both shapes so the same assertion
    works across transport/output-format changes.
    """

    if isinstance(payload, Mapping):
        raw_records = payload.get("tool_outputs")
        if isinstance(raw_records, list):
            structured_outputs: dict[str, list[dict[str, Any]]] = {}
            for record in raw_records:
                if not isinstance(record, dict):
                    continue
                tool_name = str(record.get("tool_name", "")).strip()
                data = record.get("payload")
                if tool_name and isinstance(data, dict):
                    structured_outputs.setdefault(tool_name, []).append(data)
            if structured_outputs:
                return structured_outputs
        response_text = str(payload.get("response", ""))
    else:
        response_text = str(payload)

    outputs: dict[str, list[dict[str, Any]]] = {}
    begin = "[[TOOL_OUTPUT_BEGIN"
    end = "[[TOOL_OUTPUT_END]]"
    cursor = 0
    while True:
        start = response_text.find(begin, cursor)
        if start < 0:
            break
        header_end = response_text.find("]]", start)
        if header_end < 0:
            raise AssertionError("Malformed tool boundary: missing closing brackets")
        header = response_text[start : header_end + 2]
        match = re.search(r"tool=([^\s]+)", header)
        if match is None:
            raise AssertionError(f"Malformed tool boundary: {header}")
        tool_name = match.group(1).strip()
        payload_start = header_end + 2
        payload_end = response_text.find(end, payload_start)
        if payload_end < 0:
            raise AssertionError(f"Malformed tool boundary: missing end marker for {tool_name}")
        raw_payload = response_text[payload_start:payload_end].strip()
        try:
            tool_payload = json.loads(raw_payload)
        except json.JSONDecodeError as exc:
            raise AssertionError(
                f"Tool payload is not JSON for {tool_name}: {raw_payload}"
            ) from exc
        outputs.setdefault(tool_name, []).append(tool_payload)
        cursor = payload_end + len(end)
    return outputs
