"""Local msgvault email connector facade."""

from __future__ import annotations

import hashlib
import json
import os
import selectors
import shlex
import sqlite3
import subprocess
import time
import tomllib
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_EMAIL_TAINT_LABELS = ["untrusted", "email"]
_MAX_CLI_OUTPUT_BYTES = 4 * 1024 * 1024
_MAX_CLI_STDERR_BYTES = 64 * 1024
_CLI_READ_CHUNK_BYTES = 64 * 1024
_MAX_TEXT_FIELD_BYTES = 8192
_MAX_QUERY_BYTES = 2048
_MAX_ACCOUNT_BYTES = 512
_MAX_MESSAGE_ID_BYTES = 512
_MAX_LABELS = 50
_MAX_ATTACHMENTS = 50
_CHILD_ENV_ALLOWLIST = frozenset(
    {
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LOGNAME",
        "PATH",
        "TMPDIR",
        "TZ",
        "USER",
    }
)


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


def _canonical_internal_message_id(value: str) -> int | None:
    text = value.strip()
    if not text or not text.isascii() or not text.isdigit():
        return None
    if len(text) > 1 and text.startswith("0"):
        return None
    try:
        return int(text)
    except ValueError:
        return None


def _resolve_config_path(value: str, *, base: Path) -> Path:
    path = Path(os.path.expanduser(value.strip()))
    if path.is_absolute():
        return path
    return base / path


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


def _msgvault_child_env() -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if key in _CHILD_ENV_ALLOWLIST and value
    }
    env.setdefault("PATH", os.defpath)
    return env


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
        normalized_query = _string_value(query, max_bytes=_MAX_QUERY_BYTES)
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
                account=_string_value(account, max_bytes=_MAX_ACCOUNT_BYTES),
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

    def read_message(self, *, message_id: str, account: str = "") -> dict[str, Any]:
        normalized_id = _string_value(message_id, max_bytes=_MAX_MESSAGE_ID_BYTES)
        if not normalized_id:
            return self._error_payload(
                operation="email.read",
                reason="email_message_id_required",
                message=None,
            )
        account_result = self._resolve_account(account)
        if isinstance(account_result, dict):
            return self._read_error_payload(
                reason=str(account_result["error"]),
                message_id=normalized_id,
                account=_string_value(account, max_bytes=_MAX_ACCOUNT_BYTES),
            )
        resolved_account = account_result
        read_id = normalized_id
        if resolved_account:
            scope_result = self._validate_read_account_scope(
                message_id=normalized_id,
                account=resolved_account,
            )
            if isinstance(scope_result, dict):
                return self._read_error_payload(
                    reason=str(scope_result["error"]),
                    message_id=normalized_id,
                    account=resolved_account,
                    details=scope_result,
                )
            read_id = scope_result
        result = self._run(
            ["show-message", read_id, "--json"],
            operation="email.read",
        )
        if isinstance(result, dict) and "error" in result:
            return self._read_error_payload(
                reason=str(result["error"]),
                message_id=normalized_id,
                account=resolved_account,
                details=result,
            )
        if not isinstance(result, dict):
            return self._read_error_payload(
                reason="msgvault_unexpected_json",
                message_id=normalized_id,
                account=resolved_account,
            )
        message = self._normalize_message(result)
        return {
            "ok": True,
            "operation": "email.read",
            "message_id": normalized_id,
            "account": resolved_account,
            "message": message,
            "taint_labels": list(_EMAIL_TAINT_LABELS),
            "evidence": {
                "operation": "email.read",
                "message_id_hash": _sha256_text(normalized_id),
                "account_hash": _sha256_text(resolved_account) if resolved_account else "",
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
            process = subprocess.Popen(
                full_args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_msgvault_child_env(),
            )
        except FileNotFoundError:
            return {"error": "msgvault_command_not_found"}
        except OSError:
            return {"error": "msgvault_command_failed"}
        completed = self._communicate_bounded(process)
        if isinstance(completed, dict):
            return completed
        returncode, stdout = completed
        if returncode != 0:
            return {
                "error": "msgvault_failed",
                "exit_code": returncode,
            }
        try:
            return json.loads(stdout.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return {"error": "msgvault_invalid_json"}

    def _communicate_bounded(
        self,
        process: subprocess.Popen[bytes],
    ) -> tuple[int, bytes] | dict[str, Any]:
        stdout = bytearray()
        stderr = bytearray()
        buffers = {"stdout": stdout, "stderr": stderr}
        limits = {
            "stdout": _MAX_CLI_OUTPUT_BYTES,
            "stderr": _MAX_CLI_STDERR_BYTES,
        }
        deadline = time.monotonic() + max(0.1, float(self.timeout_seconds))
        with selectors.DefaultSelector() as selector:
            if process.stdout is not None:
                selector.register(process.stdout.fileno(), selectors.EVENT_READ, "stdout")
            if process.stderr is not None:
                selector.register(process.stderr.fileno(), selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._kill_process(process)
                    return {"error": "msgvault_timeout"}
                events = selector.select(timeout=min(0.2, remaining))
                if not events:
                    continue
                for key, _mask in events:
                    stream_name = str(key.data)
                    data = os.read(int(key.fd), _CLI_READ_CHUNK_BYTES)
                    if not data:
                        selector.unregister(key.fd)
                        continue
                    buffer = buffers[stream_name]
                    if len(buffer) + len(data) > limits[stream_name]:
                        self._kill_process(process)
                        return {
                            "error": "msgvault_output_too_large",
                            "stream": stream_name,
                        }
                    buffer.extend(data)
        try:
            return process.wait(timeout=0.1), bytes(stdout)
        except subprocess.TimeoutExpired:
            self._kill_process(process)
            return {"error": "msgvault_timeout"}

    def _kill_process(self, process: subprocess.Popen[bytes]) -> None:
        with suppress(ProcessLookupError):
            process.kill()
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=1.0)

    def _preflight(self, *, operation: str) -> dict[str, Any] | None:
        _ = operation
        if not self.enabled:
            return {"error": "msgvault_disabled"}
        return None

    def _resolve_account(self, account: str) -> str | dict[str, str]:
        normalized = _string_value(account, max_bytes=_MAX_ACCOUNT_BYTES).lower()
        allowed = [
            _string_value(item, max_bytes=_MAX_ACCOUNT_BYTES).lower()
            for item in self.account_allowlist
            if _string_value(item, max_bytes=_MAX_ACCOUNT_BYTES)
        ]
        if not allowed:
            return normalized
        if normalized:
            if normalized not in allowed:
                return {"error": "msgvault_account_not_allowed"}
            return normalized
        if len(allowed) == 1:
            return allowed[0]
        return {"error": "msgvault_account_required"}

    def _validate_read_account_scope(
        self,
        *,
        message_id: str,
        account: str,
    ) -> str | dict[str, Any]:
        db_path = self._msgvault_database_path()
        if isinstance(db_path, dict):
            return db_path
        return self._lookup_scoped_internal_message_id(
            db_path=db_path,
            message_id=message_id,
            account=account,
        )

    def _msgvault_home_dir(self) -> Path:
        if self.home is not None:
            return self.home.expanduser()
        home = os.environ.get("HOME", "").strip()
        if home:
            return Path(home).expanduser() / ".msgvault"
        return Path.home() / ".msgvault"

    def _msgvault_database_path(self) -> Path | dict[str, str]:
        home = self._msgvault_home_dir()
        data_dir = home
        database_url = ""
        config_path = home / "config.toml"
        if config_path.is_file():
            try:
                with config_path.open("rb") as handle:
                    config = tomllib.load(handle)
            except (OSError, tomllib.TOMLDecodeError):
                return {"error": "msgvault_scope_lookup_unavailable"}
            data = config.get("data")
            if isinstance(data, dict):
                raw_database_url = _string_value(data.get("database_url"), max_bytes=4096)
                if raw_database_url:
                    database_url = raw_database_url
                raw_data_dir = _string_value(data.get("data_dir"), max_bytes=4096)
                if raw_data_dir:
                    data_dir = _resolve_config_path(raw_data_dir, base=home)
        if database_url:
            if "://" in database_url:
                return {"error": "msgvault_scope_lookup_unavailable"}
            db_path = _resolve_config_path(database_url, base=home)
        else:
            db_path = data_dir / "msgvault.db"
        if not db_path.is_file():
            return {"error": "msgvault_scope_lookup_unavailable"}
        return db_path

    def _lookup_scoped_internal_message_id(
        self,
        *,
        db_path: Path,
        message_id: str,
        account: str,
    ) -> str | dict[str, str]:
        timeout = max(0.1, min(float(self.timeout_seconds), 5.0))
        try:
            conn = sqlite3.connect(str(db_path), timeout=timeout)
        except (OSError, sqlite3.Error):
            return {"error": "msgvault_scope_lookup_unavailable"}
        try:
            conn.execute("PRAGMA query_only = ON")
            email_clause = self._email_message_type_clause(conn)
            internal_id = _canonical_internal_message_id(message_id)
            if internal_id is not None:
                row = conn.execute(
                    f"""
                    SELECT m.id
                    FROM messages m
                    JOIN sources s ON s.id = m.source_id
                    WHERE lower(COALESCE(s.identifier, '')) = ?
                      {email_clause}
                      AND m.id = ?
                    LIMIT 1
                    """,
                    (account, internal_id),
                ).fetchone()
                if row is not None:
                    return str(row[0])
            source_rows = conn.execute(
                f"""
                SELECT m.id
                FROM messages m
                JOIN sources s ON s.id = m.source_id
                WHERE lower(COALESCE(s.identifier, '')) = ?
                  {email_clause}
                  AND m.source_message_id = ?
                ORDER BY m.id
                LIMIT 2
                """,
                (account, message_id),
            ).fetchall()
        except sqlite3.Error:
            return {"error": "msgvault_scope_lookup_unavailable"}
        finally:
            conn.close()
        if len(source_rows) == 1:
            return str(source_rows[0][0])
        return {"error": "msgvault_message_not_in_account_scope"}

    def _email_message_type_clause(self, conn: sqlite3.Connection) -> str:
        columns = {
            str(row[1])
            for row in conn.execute("PRAGMA table_info(messages)").fetchall()
            if len(row) > 1
        }
        if "message_type" not in columns:
            return ""
        return "AND (m.message_type = 'email' OR m.message_type IS NULL OR m.message_type = '')"

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
        account: str = "",
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._error_payload(
            operation="email.read",
            reason=reason,
            message_id=message_id,
            account=account,
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
                if key in {"error", "exit_code", "stream"}
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
    if reason == "msgvault_output_too_large":
        return (
            "The local msgvault command returned more output than shisad will buffer; "
            "narrow the query or lower message size before retrying."
        )
    if reason == "msgvault_unexpected_json":
        return "The installed msgvault returned a JSON shape shisad does not understand."
    if reason == "msgvault_account_not_allowed":
        return "Use an account listed in SHISAD_MSGVAULT_ACCOUNT_ALLOWLIST."
    if reason == "msgvault_account_required":
        return "Specify an account from SHISAD_MSGVAULT_ACCOUNT_ALLOWLIST for this operation."
    if reason == "msgvault_message_not_in_account_scope":
        return (
            "The msgvault message id was not found in account-scoped archive metadata; "
            "use an id returned by email.search for the requested account."
        )
    if reason == "msgvault_scope_lookup_unavailable":
        return (
            "Account-scoped email.read could not inspect the local msgvault archive; "
            "check SHISAD_MSGVAULT_HOME, msgvault config.toml, and msgvault.db."
        )
    if reason in {"email_search_query_required", "email_message_id_required"}:
        return "Provide the required email search query or msgvault message id."
    return "Check local msgvault setup and retry the email connector operation."
