"""Control-plane metadata schema and action normalization."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from shisad.core.tools.names import canonical_tool_name
from shisad.core.types import Capability


class ActionKind(StrEnum):
    """Canonical action taxonomy for metadata-only control-plane decisions."""

    FS_READ = "FS_READ"
    FS_WRITE = "FS_WRITE"
    FS_LIST = "FS_LIST"
    EGRESS = "EGRESS"
    BROWSER_READ = "BROWSER_READ"
    BROWSER_WRITE = "BROWSER_WRITE"
    SHELL_EXEC = "SHELL_EXEC"
    ENV_ACCESS = "ENV_ACCESS"
    MEMORY_READ = "MEMORY_READ"
    MEMORY_WRITE = "MEMORY_WRITE"
    MESSAGE_READ = "MESSAGE_READ"
    MESSAGE_SEND = "MESSAGE_SEND"
    UNKNOWN = "UNKNOWN"


_CAPABILITY_TO_ACTION_KINDS: dict[Capability, set[ActionKind]] = {
    Capability.HTTP_REQUEST: {ActionKind.EGRESS, ActionKind.BROWSER_READ},
    Capability.FILE_WRITE: {ActionKind.FS_WRITE},
    Capability.FILE_READ: {ActionKind.FS_READ},
    Capability.MEMORY_WRITE: {ActionKind.MEMORY_WRITE},
    Capability.MEMORY_READ: {ActionKind.MEMORY_READ},
    Capability.MESSAGE_SEND: {ActionKind.MESSAGE_SEND},
    Capability.MESSAGE_READ: {ActionKind.MESSAGE_READ},
    Capability.SHELL_EXEC: {ActionKind.SHELL_EXEC},
    Capability.EMAIL_SEND: {ActionKind.MESSAGE_SEND},
    Capability.EMAIL_READ: {ActionKind.MESSAGE_READ},
    Capability.EMAIL_WRITE: {ActionKind.MESSAGE_SEND},
    Capability.CALENDAR_READ: {ActionKind.MEMORY_READ},
    Capability.CALENDAR_WRITE: {ActionKind.MEMORY_WRITE},
}


def action_kinds_for_capabilities(
    capabilities: set[Capability],
) -> set[ActionKind]:
    """Map session capabilities to allowed ActionKinds for stage1 plans."""
    result: set[ActionKind] = set()
    for cap in capabilities:
        kinds = _CAPABILITY_TO_ACTION_KINDS.get(cap)
        if kinds is not None:
            result.update(kinds)
    return result


class RiskTier(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ControlDecision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_CONFIRMATION = "require_confirmation"


class Origin(BaseModel, frozen=True):
    """Frozen origin metadata propagated across execution paths."""

    session_id: str = ""
    user_id: str = ""
    workspace_id: str = ""
    task_id: str = ""
    skill_name: str = ""
    actor: str = ""
    channel: str = ""
    trust_level: str = "untrusted"


class ControlPlaneAction(BaseModel, frozen=True):
    """Normalized metadata-only action envelope."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    origin: Origin = Field(default_factory=Origin)
    tool_name: str
    action_kind: ActionKind
    risk_tier: RiskTier = RiskTier.LOW
    resource_id: str = ""
    resource_ids: list[str] = Field(default_factory=list)
    network_hosts: list[str] = Field(default_factory=list)


_TOOL_KIND_MAP: dict[str, ActionKind] = {
    "retrieve_rag": ActionKind.MEMORY_READ,
    "memory.retrieve": ActionKind.MEMORY_READ,
    "memory.write": ActionKind.MEMORY_WRITE,
    "note.create": ActionKind.MEMORY_WRITE,
    "note.list": ActionKind.MEMORY_READ,
    "note.search": ActionKind.MEMORY_READ,
    "note.get": ActionKind.MEMORY_READ,
    "note.delete": ActionKind.MEMORY_WRITE,
    "note.verify": ActionKind.MEMORY_WRITE,
    "note.export": ActionKind.MEMORY_READ,
    "todo.create": ActionKind.MEMORY_WRITE,
    "todo.list": ActionKind.MEMORY_READ,
    "todo.complete": ActionKind.MEMORY_WRITE,
    "todo.get": ActionKind.MEMORY_READ,
    "todo.delete": ActionKind.MEMORY_WRITE,
    "todo.verify": ActionKind.MEMORY_WRITE,
    "todo.export": ActionKind.MEMORY_READ,
    "task.create": ActionKind.MEMORY_WRITE,
    "task.list": ActionKind.MEMORY_READ,
    "task.disable": ActionKind.MEMORY_WRITE,
    "reminder.create": ActionKind.MEMORY_WRITE,
    "reminder.list": ActionKind.MEMORY_READ,
    "evidence.read": ActionKind.MEMORY_READ,
    "evidence.promote": ActionKind.MEMORY_READ,
    "fs.list": ActionKind.FS_LIST,
    "fs.read": ActionKind.FS_READ,
    "fs.write": ActionKind.FS_WRITE,
    "git.status": ActionKind.FS_READ,
    "git.diff": ActionKind.FS_READ,
    "git.log": ActionKind.FS_READ,
    "file.read": ActionKind.FS_READ,
    "file.write": ActionKind.FS_WRITE,
    "shell.exec": ActionKind.SHELL_EXEC,
    "http.request": ActionKind.EGRESS,
    "web.search": ActionKind.EGRESS,
    "web.fetch": ActionKind.EGRESS,
    "email.search": ActionKind.MESSAGE_READ,
    "email.read": ActionKind.MESSAGE_READ,
    "attachment.ingest": ActionKind.FS_READ,
    "browser.navigate": ActionKind.BROWSER_READ,
    "browser.read_page": ActionKind.BROWSER_READ,
    "browser.screenshot": ActionKind.BROWSER_READ,
    "browser.click": ActionKind.BROWSER_WRITE,
    "browser.type_text": ActionKind.BROWSER_WRITE,
    "browser.end_session": ActionKind.BROWSER_READ,
    "send_email": ActionKind.MESSAGE_SEND,
    "message.send": ActionKind.MESSAGE_SEND,
    "session.message": ActionKind.MESSAGE_READ,
}

_NETWORK_COMMANDS = {
    "curl",
    "wget",
    "nc",
    "ncat",
    "telnet",
    "ftp",
    "sftp",
    "scp",
    "ssh",
    "dig",
    "host",
    "nslookup",
}

_ENV_COMMANDS = {
    "env",
    "printenv",
    "set",
}

_LIST_COMMANDS = {
    "ls",
    "find",
    "tree",
    "dir",
}

_READ_COMMAND_HINTS = {
    "cat",
    "head",
    "tail",
    "sed",
    "awk",
    "grep",
}

_WRITE_COMMAND_HINTS = {
    "tee",
    "cp",
    "mv",
    "touch",
    "mkdir",
    "rm",
}

_DOMAIN_TOKEN_RE = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?::\d+)?$")
_COMMAND_HOST_PREFIXES = (
    "--url=",
    "--uri=",
    "--endpoint=",
    "--destination=",
    "--host=",
    "url=",
    "uri=",
    "endpoint=",
    "destination=",
    "host=",
)
_LOCAL_FILE_EXTENSIONS = {
    ".txt",
    ".md",
    ".rst",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".conf",
    ".cfg",
    ".csv",
    ".tsv",
    ".log",
    ".xml",
    ".py",
    ".ts",
    ".js",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".sql",
}

_BANNED_TEXT_FIELDS = {
    "content",
    "raw_content",
    "raw_text",
    "raw_args",
    "payload",
    "body",
    "user_goal",
    "assistant_response",
    "request_body",
    "response_body",
    "reasoning",
    "prompt",
    "completion",
    "arguments",
    "tool_arguments",
    "headers",
    "request_headers",
}


class NormalizationResult(BaseModel, frozen=True):
    action: ControlPlaneAction


def risk_rank(value: RiskTier) -> int:
    return {
        RiskTier.LOW: 0,
        RiskTier.MEDIUM: 1,
        RiskTier.HIGH: 2,
        RiskTier.CRITICAL: 3,
    }[value]


def build_action(
    *,
    tool_name: str,
    arguments: dict[str, Any],
    origin: Origin,
    risk_tier: RiskTier = RiskTier.LOW,
    workspace_roots: list[Path] | None = None,
) -> ControlPlaneAction:
    canonical_tool = _canonical_tool_name(tool_name)
    action_kind = infer_action_kind(canonical_tool, arguments)
    resource_ids = normalize_resource_ids(
        action_kind=action_kind,
        tool_name=canonical_tool,
        arguments=arguments,
        workspace_roots=workspace_roots,
    )
    network_hosts = extract_network_hosts(arguments)
    primary_resource = (
        resource_ids[0] if resource_ids else (network_hosts[0] if network_hosts else "")
    )
    return ControlPlaneAction(
        origin=origin,
        tool_name=canonical_tool,
        action_kind=action_kind,
        risk_tier=risk_tier,
        resource_id=primary_resource,
        resource_ids=resource_ids,
        network_hosts=network_hosts,
    )


def _canonical_tool_name(tool_name: str) -> str:
    return canonical_tool_name(tool_name)


def infer_action_kind(tool_name: str, arguments: dict[str, Any]) -> ActionKind:
    tool_name = _canonical_tool_name(tool_name)
    kind = _TOOL_KIND_MAP.get(tool_name)
    if kind is not None:
        if tool_name == "shell.exec" and extract_network_hosts(arguments):
            return ActionKind.EGRESS
        return kind

    if extract_network_hosts(arguments):
        return ActionKind.EGRESS

    if any(key in arguments for key in ("read_paths", "path", "file_path")):
        return ActionKind.FS_READ
    if any(key in arguments for key in ("write_paths", "output_path", "target_path")):
        return ActionKind.FS_WRITE
    if "env" in arguments and isinstance(arguments.get("env"), dict):
        return ActionKind.ENV_ACCESS

    command = arguments.get("command")
    if isinstance(command, list) and command:
        executable = Path(str(command[0])).name.lower()
        if executable in _NETWORK_COMMANDS:
            return ActionKind.EGRESS
        if executable in _ENV_COMMANDS:
            return ActionKind.ENV_ACCESS
        if executable in _LIST_COMMANDS:
            return ActionKind.FS_LIST
        if executable in _READ_COMMAND_HINTS:
            return ActionKind.FS_READ
        if executable in _WRITE_COMMAND_HINTS:
            return ActionKind.FS_WRITE
        return ActionKind.SHELL_EXEC

    return ActionKind.UNKNOWN


def normalize_resource_ids(
    *,
    action_kind: ActionKind,
    tool_name: str = "",
    arguments: dict[str, Any],
    workspace_roots: list[Path] | None = None,
) -> list[str]:
    resources: list[str] = []
    if action_kind in {ActionKind.FS_READ, ActionKind.FS_WRITE, ActionKind.FS_LIST}:
        for key in ("read_paths", "write_paths"):
            value = arguments.get(key)
            if isinstance(value, list):
                for item in value:
                    normalized = normalize_workspace_path(
                        str(item),
                        workspace_roots=workspace_roots,
                    )
                    if normalized:
                        resources.append(normalized)
        for key in ("path", "file_path", "output_path", "target_path", "cwd", "repo_path"):
            value = arguments.get(key)
            if isinstance(value, str) and value.strip():
                normalized = normalize_workspace_path(
                    value,
                    workspace_roots=workspace_roots,
                )
                if normalized:
                    resources.append(normalized)
        if not resources:
            implicit_workspace_target = _implicit_workspace_target(
                action_kind=action_kind,
                tool_name=tool_name,
            )
            if implicit_workspace_target:
                normalized = normalize_workspace_path(
                    implicit_workspace_target,
                    workspace_roots=workspace_roots,
                )
                if normalized:
                    resources.append(normalized)
    elif action_kind in {ActionKind.EGRESS, ActionKind.BROWSER_READ, ActionKind.BROWSER_WRITE}:
        resources.extend(
            extract_tdg_resource_ids(
                action_kind=action_kind,
                tool_name=tool_name,
                arguments=arguments,
            )
        )
    elif action_kind == ActionKind.ENV_ACCESS:
        env_obj = arguments.get("env")
        if isinstance(env_obj, dict):
            resources.extend(str(key).strip().upper() for key in env_obj if str(key).strip())
    elif action_kind == ActionKind.MESSAGE_SEND:
        recipient = str(arguments.get("recipient", "")).strip()
        channel = str(arguments.get("channel", "")).strip()
        if channel and recipient:
            resources.append(f"{channel}:{recipient}")
        elif recipient:
            resources.append(recipient)
    elif action_kind in {ActionKind.MEMORY_READ, ActionKind.MEMORY_WRITE}:
        for key in ("key", "entry_id", "memory_id", "query", "selector", "task_id", "name"):
            value = arguments.get(key)
            if isinstance(value, str) and value.strip():
                resources.append(value.strip())

    deduped: list[str] = []
    seen: set[str] = set()
    for item in resources:
        if item and item not in seen:
            deduped.append(item)
            seen.add(item)
    return deduped


def extract_network_hosts(arguments: dict[str, Any]) -> list[str]:
    hosts: list[str] = []

    for key in ("url", "endpoint", "destination", "webhook_url", "source_url"):
        value = arguments.get(key)
        if isinstance(value, str):
            host = _host_from_token(value)
            if host:
                hosts.append(host)

    value = arguments.get("network_urls")
    if isinstance(value, list):
        for item in value:
            host = _host_from_token(str(item))
            if host:
                hosts.append(host)

    command = arguments.get("command")
    if isinstance(command, list):
        hosts.extend(_extract_hosts_from_command_tokens(command))

    deduped: list[str] = []
    seen: set[str] = set()
    for host in hosts:
        lowered = host.lower()
        if lowered not in seen:
            deduped.append(lowered)
            seen.add(lowered)
    return deduped


def extract_tdg_resource_ids(
    *,
    action_kind: ActionKind,
    tool_name: str,
    arguments: dict[str, Any],
) -> list[str]:
    resources: list[str] = []

    if action_kind == ActionKind.EGRESS:
        for key in ("url", "endpoint", "destination", "webhook_url"):
            value = arguments.get(key)
            if isinstance(value, str):
                host = _host_from_token(value)
                if host:
                    resources.append(host)
        value = arguments.get("network_urls")
        if isinstance(value, list):
            for item in value:
                host = _host_from_token(str(item))
                if host:
                    resources.append(host)
        command = arguments.get("command")
        if isinstance(command, list):
            resources.extend(_extract_hosts_from_command_tokens(command))
    elif action_kind in {ActionKind.BROWSER_READ, ActionKind.BROWSER_WRITE}:
        destination = _host_from_token(str(arguments.get("destination", "")))
        if destination:
            resources.append(destination)
        elif tool_name == "browser.navigate":
            host = _host_from_token(str(arguments.get("url", "")))
            if host:
                resources.append(host)
        elif action_kind == ActionKind.BROWSER_READ:
            source = _host_from_token(str(arguments.get("source_url", "")))
            if source:
                resources.append(source)

    deduped: list[str] = []
    seen: set[str] = set()
    for item in resources:
        lowered = item.strip().lower()
        if lowered and lowered not in seen:
            deduped.append(lowered)
            seen.add(lowered)
    return deduped


def extract_request_size_bytes(arguments: dict[str, Any]) -> int:
    for key in ("request_size", "request_bytes", "content_length"):
        value = arguments.get(key)
        parsed = _parse_size_value(value)
        if parsed is not None:
            return parsed

    headers = arguments.get("request_headers")
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).strip().lower() != "content-length":
                continue
            parsed = _parse_size_value(value)
            if parsed is not None:
                return parsed
    return 0


def contains_freeform_text(payload: Any) -> bool:
    if isinstance(payload, dict):
        for key, value in payload.items():
            lowered_key = str(key).lower().strip()
            if lowered_key in _BANNED_TEXT_FIELDS:
                return True
            if contains_freeform_text(value):
                return True
        return False
    if isinstance(payload, list):
        return any(contains_freeform_text(item) for item in payload)
    if isinstance(payload, str):
        # Long free-form text is disallowed in voter payloads.
        return len(payload) > 256 or ("\n" in payload and len(payload) > 64)
    return False


def sanitize_metadata_payload(payload: dict[str, Any]) -> dict[str, Any]:
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        lowered_key = str(key).lower().strip()
        if lowered_key in _BANNED_TEXT_FIELDS:
            continue
        if isinstance(value, dict):
            nested = sanitize_metadata_payload(value)
            cleaned[str(key)] = nested
            continue
        if isinstance(value, list):
            filtered: list[Any] = []
            for item in value:
                if isinstance(item, dict):
                    filtered.append(sanitize_metadata_payload(item))
                elif not isinstance(item, str) or len(item) <= 256:
                    filtered.append(item)
            cleaned[str(key)] = filtered
            continue
        if isinstance(value, str) and len(value) > 256:
            continue
        cleaned[str(key)] = value
    return cleaned


def normalize_workspace_path(value: str, *, workspace_roots: list[Path] | None = None) -> str:
    text = value.strip()
    if not text:
        return ""
    try:
        roots = _normalized_workspace_roots(workspace_roots)
        candidate = Path(text).expanduser()
        if not candidate.is_absolute():
            candidate = roots[0] / candidate
        return str(candidate.resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        return text


def _normalized_workspace_roots(workspace_roots: list[Path] | None) -> list[Path]:
    roots = [item.expanduser().resolve(strict=False) for item in (workspace_roots or [])]
    if roots:
        return roots
    return [Path.cwd().expanduser().resolve(strict=False)]


def _implicit_workspace_target(*, action_kind: ActionKind, tool_name: str) -> str:
    if action_kind == ActionKind.FS_LIST:
        return "."
    if tool_name in {"git.status", "git.diff", "git.log"}:
        return "."
    return ""


def _host_from_token(token: str) -> str:
    value = token.strip()
    if not value:
        return ""
    parsed = urlparse(value)
    if parsed.hostname:
        return parsed.hostname.lower()
    if _DOMAIN_TOKEN_RE.match(value):
        host = value.split(":", 1)[0]
        return host.lower()
    return ""


def _extract_hosts_from_command_tokens(command: list[Any]) -> list[str]:
    if not command:
        return []
    executable = Path(str(command[0])).name.lower()
    hosts: list[str] = []
    for raw_token in command[1:]:
        token = str(raw_token).strip()
        if not token:
            continue
        if "://" in token:
            host = _host_from_token(token)
            if host:
                hosts.append(host)
            continue

        lowered = token.lower()
        prefixed_host = ""
        for prefix in _COMMAND_HOST_PREFIXES:
            if not lowered.startswith(prefix):
                continue
            candidate = token[len(prefix) :].strip()
            prefixed_host = _host_from_token(candidate)
            break
        if prefixed_host:
            hosts.append(prefixed_host)
            continue

        if executable not in _NETWORK_COMMANDS:
            continue
        if _looks_like_local_path_token(token):
            continue
        host = _host_from_token(token)
        if host:
            hosts.append(host)
    return hosts


def _looks_like_local_path_token(token: str) -> bool:
    stripped = token.strip()
    if not stripped:
        return False
    if stripped.startswith(("/", "./", "../", "~/", ".\\", "..\\")):
        return True
    if "\\" in stripped or "/" in stripped:
        return True
    suffix = Path(stripped).suffix.lower()
    return suffix in _LOCAL_FILE_EXTENSIONS


def _parse_size_value(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, float):
        return max(0, int(value))
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return int(text)
    return None
