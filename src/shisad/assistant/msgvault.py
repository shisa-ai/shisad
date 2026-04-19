"""Local msgvault email connector facade."""

from __future__ import annotations

import hashlib
import json
import shlex
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_EMAIL_TAINT_LABELS = ["untrusted", "email"]
_MAX_CLI_OUTPUT_BYTES = 4 * 1024 * 1024
_MAX_TEXT_FIELD_BYTES = 8192
_MAX_LABELS = 50
_MAX_ATTACHMENTS = 50


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _string_value(value: Any, *, max_bytes: int = _MAX_TEXT_FIELD_BYTES) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    truncated, _did_truncate = _truncate_utf8(text, max_bytes=max_bytes)
    return truncated


def _bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return bool(value)


def _int_value(value: Any, *, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _truncate_utf8(text: str, *, max_bytes: int) -> tuple[str, bool]:
    limit = max(0, int(max_bytes))
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return text, False
    truncated = encoded[:limit].decode("utf-8", errors="ignore")
    return truncated, True


def _labels(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    labels: list[str] = []
    for item in value:
        label = _string_value(item, max_bytes=256)
        if label:
            labels.append(label)
        if len(labels) >= _MAX_LABELS:
            break
    return labels


def _address(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        return {
            "email": _string_value(value.get("email"), max_bytes=512),
            "name": _string_value(value.get("name"), max_bytes=512),
        }
    return {"email": _string_value(value, max_bytes=512), "name": ""}


def _address_list(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        value = [value] if value else []
    addresses: list[dict[str, str]] = []
    for item in value:
        address = _address(item)
        if address["email"] or address["name"]:
            addresses.append(address)
        if len(addresses) >= 100:
            break
    return addresses


def _attachments(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    rows: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "filename": _string_value(
                    item.get("filename") or item.get("name"),
                    max_bytes=512,
                ),
                "mime_type": _string_value(
                    item.get("mime_type") or item.get("content_type"),
                    max_bytes=256,
                ),
                "size": _int_value(item.get("size") or item.get("size_bytes")),
            }
        )
        if len(rows) >= _MAX_ATTACHMENTS:
            break
    return rows


@dataclass(slots=True)
class MsgvaultToolkit:
    """Read-only local msgvault integration.

    msgvault owns provider sync and raw provider credentials. shisad calls the
    local archive CLI with ``--local`` only, then bounds and taints returned
    email content before it crosses the tool-output boundary.
    """

    enabled: bool
    command: str
    home: Path | None
    timeout_seconds: float
    max_results: int
    max_body_bytes: int
    account_allowlist: list[str]

    def search(
        self,
        *,
        query: str,
        limit: int = 10,
        offset: int = 0,
        account: str = "",
    ) -> dict[str, Any]:
        normalized_query = query.strip()
        if not normalized_query:
            return self._error_payload(
                operation="email.search",
                reason="email_search_query_required",
                query=normalized_query,
                results=[],
                count=0,
            )
        account_result = self._resolve_account(account)
        if isinstance(account_result, dict):
            return self._error_payload(
                operation="email.search",
                reason=str(account_result["error"]),
                query=normalized_query,
                account=account,
                results=[],
                count=0,
            )
        resolved_account = account_result
        max_items = max(1, min(int(limit), int(self.max_results), 50))
        start_offset = max(0, int(offset))
        args = [
            "search",
            normalized_query,
            "--json",
            "--limit",
            str(max_items),
            "--offset",
            str(start_offset),
        ]
        if resolved_account:
            args.extend(["--account", resolved_account])
        result = self._run(args, operation="email.search")
        if isinstance(result, dict) and "error" in result:
            return self._search_error_payload(
                reason=str(result["error"]),
                query=normalized_query,
                account=resolved_account,
                details=result,
            )
        rows = self._search_rows(result)
        if rows is None:
            return self._search_error_payload(
                reason="msgvault_unexpected_json",
                query=normalized_query,
                account=resolved_account,
            )
        results = [self._normalize_search_row(item) for item in rows[:max_items]]
        return {
            "ok": True,
            "operation": "email.search",
            "query": normalized_query,
            "account": resolved_account,
            "limit": max_items,
            "offset": start_offset,
            "count": len(results),
            "results": results,
            "taint_labels": list(_EMAIL_TAINT_LABELS),
            "evidence": {
                "operation": "email.search",
                "query_hash": _sha256_text(normalized_query),
                "account_hash": _sha256_text(resolved_account) if resolved_account else "",
                "fetched_at": _now_iso(),
                "local_only": True,
                "result_count": len(results),
            },
            "error": "",
        }

    def read_message(self, *, message_id: str) -> dict[str, Any]:
        normalized_id = message_id.strip()
        if not normalized_id:
            return self._error_payload(
                operation="email.read",
                reason="email_message_id_required",
                message=None,
            )
        result = self._run(
            ["show-message", normalized_id, "--json"],
            operation="email.read",
        )
        if isinstance(result, dict) and "error" in result:
            return self._read_error_payload(
                reason=str(result["error"]),
                message_id=normalized_id,
                details=result,
            )
        if not isinstance(result, dict):
            return self._read_error_payload(
                reason="msgvault_unexpected_json",
                message_id=normalized_id,
            )
        message = self._normalize_message(result)
        return {
            "ok": True,
            "operation": "email.read",
            "message_id": normalized_id,
            "message": message,
            "taint_labels": list(_EMAIL_TAINT_LABELS),
            "evidence": {
                "operation": "email.read",
                "message_id_hash": _sha256_text(normalized_id),
                "source_message_id_hash": _sha256_text(message.get("source_message_id", "")),
                "fetched_at": _now_iso(),
                "local_only": True,
                "body_text_truncated": bool(message.get("body_text_truncated", False)),
                "body_html_omitted": bool(message.get("body_html_omitted", False)),
            },
            "error": "",
        }

    def _run(
        self,
        args: list[str],
        *,
        operation: str,
    ) -> Any | dict[str, Any]:
        preflight = self._preflight(operation=operation)
        if preflight is not None:
            return preflight
        command = shlex.split(self.command.strip())
        if not command:
            return {"error": "msgvault_command_required"}
        full_args = [*command, "--local"]
        if self.home is not None:
            full_args.extend(["--home", str(self.home)])
        full_args.extend(args)
        try:
            completed = subprocess.run(
                full_args,
                check=False,
                capture_output=True,
                text=True,
                timeout=max(0.1, float(self.timeout_seconds)),
            )
        except FileNotFoundError:
            return {"error": "msgvault_command_not_found"}
        except subprocess.TimeoutExpired:
            return {"error": "msgvault_timeout"}
        except OSError:
            return {"error": "msgvault_command_failed"}
        stdout = completed.stdout[:_MAX_CLI_OUTPUT_BYTES]
        if completed.returncode != 0:
            return {
                "error": "msgvault_failed",
                "exit_code": completed.returncode,
            }
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            return {"error": "msgvault_invalid_json"}

    def _preflight(self, *, operation: str) -> dict[str, Any] | None:
        _ = operation
        if not self.enabled:
            return {"error": "msgvault_disabled"}
        return None

    def _resolve_account(self, account: str) -> str | dict[str, str]:
        normalized = account.strip().lower()
        allowed = [item.strip().lower() for item in self.account_allowlist if item.strip()]
        if not allowed:
            return normalized
        if normalized:
            if normalized not in allowed:
                return {"error": "msgvault_account_not_allowed"}
            return normalized
        if len(allowed) == 1:
            return allowed[0]
        return {"error": "msgvault_account_required"}

    def _search_rows(self, payload: Any) -> list[Any] | None:
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("results", "messages"):
                rows = payload.get(key)
                if isinstance(rows, list):
                    return rows
        return None

    def _normalize_search_row(self, item: Any) -> dict[str, Any]:
        row = item if isinstance(item, dict) else {}
        return {
            "id": _string_value(row.get("id"), max_bytes=256),
            "source_message_id": _string_value(row.get("source_message_id"), max_bytes=512),
            "conversation_id": _string_value(row.get("conversation_id"), max_bytes=256),
            "source_conversation_id": _string_value(
                row.get("source_conversation_id"),
                max_bytes=512,
            ),
            "subject": _string_value(row.get("subject"), max_bytes=1024),
            "snippet": _string_value(row.get("snippet"), max_bytes=2048),
            "from_email": _string_value(row.get("from_email"), max_bytes=512),
            "from_name": _string_value(row.get("from_name"), max_bytes=512),
            "sent_at": _string_value(row.get("sent_at"), max_bytes=128),
            "size_estimate": _int_value(row.get("size_estimate")),
            "has_attachments": _bool_value(row.get("has_attachments")),
            "attachment_count": _int_value(row.get("attachment_count")),
            "bcc_count": 0,
            "labels": _labels(row.get("labels")),
        }

    def _normalize_message(self, row: dict[str, Any]) -> dict[str, Any]:
        body_text, body_truncated = _truncate_utf8(
            str(row.get("body_text") or ""),
            max_bytes=max(0, int(self.max_body_bytes)),
        )
        bcc = row.get("bcc")
        bcc_count = len(bcc) if isinstance(bcc, list) else 0
        body_html_present = bool(str(row.get("body_html") or "").strip())
        return {
            "id": _string_value(row.get("id"), max_bytes=256),
            "source_message_id": _string_value(row.get("source_message_id"), max_bytes=512),
            "conversation_id": _string_value(row.get("conversation_id"), max_bytes=256),
            "source_conversation_id": _string_value(
                row.get("source_conversation_id"),
                max_bytes=512,
            ),
            "subject": _string_value(row.get("subject"), max_bytes=1024),
            "snippet": _string_value(row.get("snippet"), max_bytes=2048),
            "sent_at": _string_value(row.get("sent_at"), max_bytes=128),
            "received_at": _string_value(row.get("received_at"), max_bytes=128),
            "from": _address(row.get("from")),
            "to": _address_list(row.get("to")),
            "cc": _address_list(row.get("cc")),
            "bcc_count": bcc_count,
            "labels": _labels(row.get("labels")),
            "attachments": _attachments(row.get("attachments")),
            "has_attachments": _bool_value(row.get("has_attachments"))
            or bool(row.get("attachments")),
            "body_text": body_text,
            "body_text_truncated": body_truncated,
            "body_html_omitted": body_html_present,
        }

    def _search_error_payload(
        self,
        *,
        reason: str,
        query: str,
        account: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._error_payload(
            operation="email.search",
            reason=reason,
            query=query,
            account=account,
            results=[],
            count=0,
            details=details,
        )

    def _read_error_payload(
        self,
        *,
        reason: str,
        message_id: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._error_payload(
            operation="email.read",
            reason=reason,
            message_id=message_id,
            message=None,
            details=details,
        )

    def _error_payload(
        self,
        *,
        operation: str,
        reason: str,
        details: dict[str, Any] | None = None,
        **extra: Any,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": False,
            "operation": operation,
            "error": reason,
            "actionable": _actionable_message(reason, operation=operation),
            "taint_labels": list(_EMAIL_TAINT_LABELS),
            "evidence": {
                "operation": operation,
                "fetched_at": _now_iso(),
                "local_only": True,
            },
        }
        payload.update(extra)
        if details:
            safe_details = {
                key: value
                for key, value in details.items()
                if key in {"error", "exit_code"}
            }
            payload["details"] = safe_details
        return payload


def _actionable_message(reason: str, *, operation: str) -> str:
    if reason == "msgvault_disabled":
        return (
            "Set SHISAD_MSGVAULT_ENABLED=true after installing msgvault and syncing "
            "the local archive."
        )
    if reason == "msgvault_command_required":
        return "Set SHISAD_MSGVAULT_COMMAND to the msgvault executable path."
    if reason == "msgvault_command_not_found":
        return "Install msgvault or set SHISAD_MSGVAULT_COMMAND to the executable path."
    if reason == "msgvault_timeout":
        return (
            "msgvault did not finish before SHISAD_MSGVAULT_TIMEOUT_SECONDS; "
            "check the local archive or increase the timeout."
        )
    if reason == "msgvault_failed":
        return "Run the equivalent msgvault command locally and check its stderr output."
    if reason == "msgvault_invalid_json":
        command = (
            "msgvault search --json"
            if operation == "email.search"
            else "msgvault show-message --json"
        )
        return f"Check that {command} returns valid JSON with the installed msgvault version."
    if reason == "msgvault_unexpected_json":
        return "The installed msgvault returned a JSON shape shisad does not understand."
    if reason == "msgvault_account_not_allowed":
        return "Use an account listed in SHISAD_MSGVAULT_ACCOUNT_ALLOWLIST."
    if reason == "msgvault_account_required":
        return "Specify an account from SHISAD_MSGVAULT_ACCOUNT_ALLOWLIST for this query."
    if reason in {"email_search_query_required", "email_message_id_required"}:
        return "Provide the required email search query or msgvault message id."
    return "Check local msgvault setup and retry the email connector operation."
