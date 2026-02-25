#!/usr/bin/env python3
"""Live daemon prompt/tool matrix probe with deterministic pass/fail output."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast

from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig

_DISABLED_REASONS: frozenset[str] = frozenset(
    {
        "web_search_disabled",
        "web_search_backend_unconfigured",
        "web_search_backend_not_allowlisted",
        "web_allowlist_unconfigured",
        "web_fetch_disabled",
        "destination_not_allowlisted",
        "realitycheck_disabled",
        "realitycheck_misconfigured",
        "endpoint_mode_disabled",
    }
)


@dataclass(slots=True)
class MatrixRow:
    name: str
    status: str
    detail: str


def _tool_payload_templates(repo_root: Path) -> dict[str, dict[str, Any]]:
    safe_command = [sys.executable, "-c", "print('live-tool-matrix-ok')"]
    write_target = repo_root / ".local" / "live-tool-matrix-tool-write.txt"
    return {
        "retrieve_rag": {
            "command": safe_command,
            "arguments": {"query": "README", "limit": 2},
        },
        "shell.exec": {
            "command": safe_command,
        },
        "http.request": {
            "command": safe_command,
            "network_urls": ["https://example.com"],
            "network": {
                "allow_network": True,
                "allowed_domains": ["example.com"],
                "deny_private_ranges": True,
                "deny_ip_literals": True,
            },
        },
        "file.read": {
            "command": safe_command,
            "read_paths": [str(repo_root / "README.md")],
        },
        "file.write": {
            "command": safe_command,
            "write_paths": [str(write_target)],
        },
        "web.search": {
            "command": safe_command,
            "arguments": {"query": "shisad", "limit": 2},
        },
        "web.fetch": {
            "command": safe_command,
            "arguments": {"url": "https://example.com", "snapshot": False, "max_bytes": 4096},
        },
        "fs.list": {
            "command": safe_command,
            "arguments": {"path": ".", "recursive": False, "limit": 20},
        },
        "fs.read": {
            "command": safe_command,
            "arguments": {"path": "README.md", "max_bytes": 4096},
        },
        "fs.write": {
            "command": safe_command,
            "arguments": {
                "path": ".local/live-tool-matrix-fs-write.txt",
                "content": "live matrix write",
                "confirm": True,
            },
        },
        "git.status": {
            "command": safe_command,
            "arguments": {"repo_path": "."},
        },
        "git.diff": {
            "command": safe_command,
            "arguments": {"repo_path": ".", "max_lines": 80},
        },
        "git.log": {
            "command": safe_command,
            "arguments": {"repo_path": ".", "limit": 5},
        },
        "report_anomaly": {
            "command": safe_command,
            "arguments": {
                "anomaly_type": "live_matrix_probe",
                "description": "live matrix probe validation",
                "recommended_action": "review",
                "confidence": 0.6,
            },
        },
        "realitycheck.search": {
            "command": safe_command,
            "arguments": {"query": "security", "limit": 2, "mode": "auto"},
        },
        "realitycheck.read": {
            "command": safe_command,
            "arguments": {"path": "README.md", "max_bytes": 2048},
        },
    }


def _structured_rpc_templates() -> dict[str, dict[str, Any]]:
    return {
        "web.search": {"query": "shisad", "limit": 2},
        "web.fetch": {"url": "https://example.com", "snapshot": False},
        "fs.list": {"path": ".", "recursive": False, "limit": 20},
        "fs.read": {"path": "README.md", "max_bytes": 4096},
        "fs.write": {
            "path": ".local/live-tool-matrix-fs-write.txt",
            "content": "live matrix write",
            "confirm": True,
        },
        "git.status": {"repo_path": "."},
        "git.diff": {"repo_path": ".", "max_lines": 80},
        "git.log": {"repo_path": ".", "limit": 5},
        "realitycheck.search": {"query": "security", "limit": 2, "mode": "auto"},
        "realitycheck.read": {"path": "README.md", "max_bytes": 2048},
    }


async def _confirm_if_required(
    client: ControlClient,
    result: dict[str, Any],
) -> dict[str, Any]:
    if result.get("confirmation_required") is not True:
        return result
    confirmation_id = str(result.get("confirmation_id", "")).strip()
    decision_nonce = str(result.get("decision_nonce", "")).strip()
    if not confirmation_id or not decision_nonce:
        return {
            "confirmed": False,
            "status_reason": "missing_confirmation_metadata",
        }
    confirmed = await client.call(
        "action.confirm",
        {
            "confirmation_id": confirmation_id,
            "decision_nonce": decision_nonce,
            "reason": "live_tool_matrix",
        },
    )
    return cast(dict[str, Any], confirmed)


def _is_policy_gate_reason(reason: str) -> bool:
    return (
        reason.startswith("consensus:veto:")
        or "trace:stage2_upgrade_required" in reason
        or reason.startswith("control_plane_")
        or reason.startswith("trace:")
        or reason.startswith("plan_amendment")
    )


def _classify_tool_result(
    *,
    tool_name: str,
    result: dict[str, Any],
    strict_disabled: bool,
) -> MatrixRow:
    if "confirmed" in result:
        confirmed = bool(result.get("confirmed"))
        if confirmed:
            return MatrixRow(tool_name, "pass", "confirmed")
        status_reason = str(result.get("status_reason") or result.get("reason") or "")
        if status_reason and status_reason != "missing_confirmation_metadata":
            return MatrixRow(tool_name, "pass_gated", status_reason)
        if _is_policy_gate_reason(status_reason):
            return MatrixRow(tool_name, "pass_gated", status_reason)
        return MatrixRow(tool_name, "fail", f"confirmation_denied:{status_reason}")

    allowed = bool(result.get("allowed"))
    if allowed:
        return MatrixRow(tool_name, "pass", "allowed")

    reason = str(result.get("reason", "")).strip()
    if reason in _DISABLED_REASONS:
        status = "fail" if strict_disabled else "pass_disabled"
        return MatrixRow(tool_name, status, reason)
    if _is_policy_gate_reason(reason):
        return MatrixRow(tool_name, "pass_gated", reason)
    if reason:
        return MatrixRow(tool_name, "fail", reason)
    return MatrixRow(tool_name, "fail", "unknown_failure")


def _classify_structured_rpc_result(
    *,
    method_name: str,
    result: dict[str, Any],
    strict_disabled: bool,
) -> MatrixRow:
    ok = bool(result.get("ok"))
    if ok:
        return MatrixRow(method_name, "pass", "ok")
    error = str(result.get("error", "")).strip()
    if error in _DISABLED_REASONS:
        status = "fail" if strict_disabled else "pass_disabled"
        return MatrixRow(method_name, status, error)
    if error:
        return MatrixRow(method_name, "fail", error)
    return MatrixRow(method_name, "fail", "unknown_failure")


async def _run_prompt_checks(
    *,
    client: ControlClient,
    session_id: str,
) -> list[MatrixRow]:
    prompts = [
        "hi, can you confirm you are online?",
        "what tools do you have available?",
        "in one short sentence, summarize what shisad is.",
    ]
    rows: list[MatrixRow] = []
    for idx, prompt in enumerate(prompts, start=1):
        name = f"prompt.{idx}"
        try:
            response = await client.call(
                "session.message",
                {"session_id": session_id, "content": prompt},
            )
        except Exception as exc:  # pragma: no cover - live path
            rows.append(MatrixRow(name, "fail", f"rpc_error:{exc}"))
            continue
        text = str(response.get("response", "")).strip()
        if not text:
            rows.append(MatrixRow(name, "fail", "empty_response"))
            continue
        if "[LOCKDOWN NOTICE]" in text:
            rows.append(MatrixRow(name, "fail", "lockdown_notice_in_response"))
            continue
        if "Response blocked by output policy." in text:
            rows.append(MatrixRow(name, "fail", "output_policy_block"))
            continue
        if text.startswith("Safe summary:"):
            rows.append(MatrixRow(name, "fail", "local_fallback_response"))
            continue
        lockdown = str(response.get("lockdown_level", "")).strip().lower()
        if lockdown and lockdown != "normal":
            rows.append(MatrixRow(name, "fail", f"lockdown_level:{lockdown}"))
            continue
        rows.append(MatrixRow(name, "pass", "response_ok"))
    return rows


async def _run_tool_checks(
    *,
    client: ControlClient,
    session_id: str,
    tools: list[str],
    execute_templates: dict[str, dict[str, Any]],
    structured_templates: dict[str, dict[str, Any]],
    strict_disabled: bool,
) -> list[MatrixRow]:
    rows: list[MatrixRow] = []
    structured_methods = set(structured_templates)
    ordered = [name for name in tools if name != "report_anomaly"] + [
        name for name in tools if name == "report_anomaly"
    ]
    for tool_name in ordered:
        if tool_name in structured_methods:
            try:
                structured_result = await client.call(
                    tool_name,
                    structured_templates[tool_name],
                )
            except Exception as exc:  # pragma: no cover - live path
                rows.append(MatrixRow(f"tool.{tool_name}", "fail", f"rpc_error:{exc}"))
                continue
            rows.append(
                _classify_structured_rpc_result(
                    method_name=f"tool.{tool_name}",
                    result=cast(dict[str, Any], structured_result),
                    strict_disabled=strict_disabled,
                )
            )
            continue

        payload_template = execute_templates.get(tool_name)
        if payload_template is None:
            rows.append(MatrixRow(f"tool.{tool_name}", "fail", "missing_payload_template"))
            continue
        payload = {
            "session_id": session_id,
            "tool_name": tool_name,
            "security_critical": False,
            "degraded_mode": "fail_open",
            **payload_template,
        }
        try:
            result = await client.call("tool.execute", payload)
        except Exception as exc:  # pragma: no cover - live path
            rows.append(MatrixRow(f"tool.{tool_name}", "fail", f"rpc_error:{exc}"))
            continue
        try:
            effective = await _confirm_if_required(client, cast(dict[str, Any], result))
        except Exception as exc:  # pragma: no cover - live path
            rows.append(MatrixRow(f"tool.{tool_name}", "fail", f"confirm_error:{exc}"))
            continue
        rows.append(
            _classify_tool_result(
                tool_name=f"tool.{tool_name}",
                result=effective,
                strict_disabled=strict_disabled,
            )
        )
    return rows


async def _run_matrix(*, strict_disabled: bool) -> int:
    config = DaemonConfig()
    client = ControlClient(config.socket_path)
    await client.connect()
    try:
        status = await client.call("daemon.status")
        tools = [str(item) for item in status.get("tools_registered", [])]
        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "live_matrix", "workspace_id": "local"},
        )
        session_id = str(created.get("session_id", "")).strip()
        if not session_id:
            print("FAIL: session.create returned empty session_id", file=sys.stderr)
            return 2

        repo_root = Path.cwd()
        execute_templates = _tool_payload_templates(repo_root)
        structured_templates = _structured_rpc_templates()
        prompt_rows = await _run_prompt_checks(client=client, session_id=session_id)
        tool_rows = await _run_tool_checks(
            client=client,
            session_id=session_id,
            tools=tools,
            execute_templates=execute_templates,
            structured_templates=structured_templates,
            strict_disabled=strict_disabled,
        )
    finally:
        await client.close()

    rows = prompt_rows + tool_rows
    passed = sum(1 for row in rows if row.status == "pass")
    disabled = sum(1 for row in rows if row.status == "pass_disabled")
    gated = sum(1 for row in rows if row.status == "pass_gated")
    failed = sum(1 for row in rows if row.status == "fail")

    print(json.dumps({"checks": [asdict(row) for row in rows]}, indent=2))
    print(
        "summary: "
        f"pass={passed} pass_disabled={disabled} pass_gated={gated} "
        f"fail={failed} total={len(rows)}"
    )
    return 0 if failed == 0 else 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--strict-disabled",
        action="store_true",
        help="Treat disabled-by-config tool results as failures.",
    )
    args = parser.parse_args()
    return asyncio.run(_run_matrix(strict_disabled=bool(args.strict_disabled)))


if __name__ == "__main__":
    raise SystemExit(main())
