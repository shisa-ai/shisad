#!/usr/bin/env python3
"""Live daemon prompt/tool matrix probe with deterministic pass/fail output."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import uuid
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
        "msgvault_disabled",
        "msgvault_command_not_found",
        "msgvault_account_required",
        "email_read_probe_message_id_unconfigured",
        "realitycheck_disabled",
        "realitycheck_misconfigured",
        "endpoint_mode_disabled",
        "no_evidence_ref_available",
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
    probe_suffix = uuid.uuid4().hex[:8]
    note_content = f"live tool matrix note {probe_suffix}"
    todo_title = f"live tool matrix todo {probe_suffix}"
    reminder_message = f"live tool matrix reminder {probe_suffix}"
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
        "note.create": {
            "command": safe_command,
            "arguments": {
                "content": note_content,
                "key": f"live-tool-matrix-note-{probe_suffix}",
            },
        },
        "note.list": {
            "command": safe_command,
            "arguments": {"limit": 5},
        },
        "note.search": {
            "command": safe_command,
            "arguments": {"query": note_content, "limit": 5},
        },
        "todo.create": {
            "command": safe_command,
            "arguments": {
                "title": todo_title,
                "details": "created by live tool matrix probe",
            },
        },
        "todo.list": {
            "command": safe_command,
            "arguments": {"limit": 5},
        },
        "todo.complete": {
            "command": safe_command,
            "arguments": {"selector": todo_title},
        },
        "reminder.create": {
            "command": safe_command,
            "arguments": {
                "message": reminder_message,
                "when": "in 1 hour",
                "name": f"live-tool-matrix-reminder-{probe_suffix}",
            },
        },
        "reminder.list": {
            "command": safe_command,
            "arguments": {"limit": 5},
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
    email_search_template: dict[str, Any] = {"query": "shisad", "limit": 2}
    email_account = os.environ.get("SHISAD_LIVE_TOOL_MATRIX_EMAIL_ACCOUNT", "").strip()
    if email_account:
        email_search_template["account"] = email_account
    templates: dict[str, dict[str, Any]] = {
        "web.search": {"query": "shisad", "limit": 2},
        "web.fetch": {"url": "https://example.com", "snapshot": False},
        "email.search": email_search_template,
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
    configured_email_read = _configured_email_read_template()
    if configured_email_read is not None:
        templates["email.read"] = configured_email_read
    return templates


def _configured_email_read_template() -> dict[str, Any] | None:
    message_id = os.environ.get("SHISAD_LIVE_TOOL_MATRIX_EMAIL_MESSAGE_ID", "").strip()
    if not message_id:
        return None
    template: dict[str, Any] = {"message_id": message_id}
    account = os.environ.get("SHISAD_LIVE_TOOL_MATRIX_EMAIL_ACCOUNT", "").strip()
    if account:
        template["account"] = account
    return template


def _email_read_template_from_search_result(result: dict[str, Any]) -> dict[str, Any] | None:
    messages = result.get("results")
    if not isinstance(messages, list):
        return None
    for message in messages:
        if not isinstance(message, dict):
            continue
        message_id = str(message.get("id") or message.get("source_message_id") or "").strip()
        if not message_id:
            continue
        template: dict[str, Any] = {"message_id": message_id}
        account = str(result.get("account") or "").strip()
        if account:
            template["account"] = account
        return template
    return None


def _message_send_template(
    status: dict[str, Any],
) -> tuple[dict[str, Any] | None, str | None]:
    channels = status.get("channels")
    if not isinstance(channels, dict):
        return None, "no_delivery_channels_configured"
    for channel_name, channel_status in channels.items():
        if not isinstance(channel_status, dict):
            continue
        if channel_status.get("enabled") is not True:
            continue
        return (
            {
                "command": [sys.executable, "-c", "print('live-tool-matrix-ok')"],
                "arguments": {
                    "channel": str(channel_name),
                    "recipient": "live-matrix",
                    "message": "live tool matrix probe",
                },
            },
            None,
        )
    return None, "no_delivery_channels_configured"


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
        if text.startswith("Safe summary:") or text.startswith("[PLANNER FALLBACK:"):
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
    disabled_tools: dict[str, str],
    structured_templates: dict[str, dict[str, Any]],
    strict_disabled: bool,
) -> list[MatrixRow]:
    rows: list[MatrixRow] = []
    structured_templates = dict(structured_templates)
    email_read_disabled_reason = disabled_tools.get("email.read", "").strip()
    ordered = [name for name in tools if name != "report_anomaly"] + [
        name for name in tools if name == "report_anomaly"
    ]
    for tool_name in ordered:
        if tool_name == "email.read" and tool_name not in structured_templates:
            disabled_tools["email.read"] = (
                email_read_disabled_reason or "email_read_probe_message_id_unconfigured"
            )
        if tool_name in structured_templates:
            try:
                structured_result = await client.call(
                    tool_name,
                    structured_templates[tool_name],
                )
            except Exception as exc:  # pragma: no cover - live path
                rows.append(MatrixRow(f"tool.{tool_name}", "fail", f"rpc_error:{exc}"))
                continue
            structured_payload = cast(dict[str, Any], structured_result)
            rows.append(
                _classify_structured_rpc_result(
                    method_name=f"tool.{tool_name}",
                    result=structured_payload,
                    strict_disabled=strict_disabled,
                )
            )
            if tool_name == "email.search":
                if bool(structured_payload.get("ok")):
                    email_read_template = _email_read_template_from_search_result(
                        structured_payload
                    )
                    if email_read_template is not None:
                        structured_templates.setdefault("email.read", email_read_template)
                else:
                    reason = str(structured_payload.get("error", "")).strip()
                    if reason in _DISABLED_REASONS:
                        email_read_disabled_reason = reason
            continue

        payload_template = execute_templates.get(tool_name)
        if payload_template is None:
            disabled_reason = disabled_tools.get(tool_name, "").strip()
            if disabled_reason:
                status = "fail" if strict_disabled else "pass_disabled"
                rows.append(MatrixRow(f"tool.{tool_name}", status, disabled_reason))
            else:
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


_STATUS_MAP: dict[str, str] = {
    "pass": "WORKS",
    "pass_disabled": "DISABLED",
    "pass_gated": "GATED",
    "fail": "BROKEN",
}


def _print_tool_status_markdown(rows: list[MatrixRow]) -> None:
    """Render a Markdown table of tool health status."""
    print("# Tool Status Report")
    print()
    print("*Generated by `scripts/live_tool_matrix.py --tool-status`*")
    print()
    print("| Tool | Status | Detail |")
    print("|------|--------|--------|")
    for row in rows:
        status = _STATUS_MAP.get(row.status, row.status.upper())
        print(f"| {row.name} | {status} | {row.detail} |")
    print()


async def _run_matrix(*, strict_disabled: bool, tool_status: bool = False) -> int:
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
        disabled_tools: dict[str, str] = {}
        message_send_template, message_send_disabled_reason = _message_send_template(
            cast(dict[str, Any], status)
        )
        if message_send_template is not None:
            execute_templates["message.send"] = message_send_template
        elif message_send_disabled_reason:
            disabled_tools["message.send"] = message_send_disabled_reason
        disabled_tools["evidence.read"] = "no_evidence_ref_available"
        disabled_tools["evidence.promote"] = "no_evidence_ref_available"
        structured_templates = _structured_rpc_templates()
        prompt_rows = await _run_prompt_checks(client=client, session_id=session_id)
        tool_rows = await _run_tool_checks(
            client=client,
            session_id=session_id,
            tools=tools,
            execute_templates=execute_templates,
            disabled_tools=disabled_tools,
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

    if tool_status:
        _print_tool_status_markdown(rows)
    else:
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
    parser.add_argument(
        "--tool-status",
        action="store_true",
        help="Output a Markdown table of tool health instead of JSON.",
    )
    args = parser.parse_args()
    return asyncio.run(
        _run_matrix(
            strict_disabled=bool(args.strict_disabled),
            tool_status=bool(args.tool_status),
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
