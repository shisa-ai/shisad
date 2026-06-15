"""Browser sandbox helpers and external browser toolkit wrapper."""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import ipaddress
import json
import math
import os
import re
import shlex
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import ParseResult, parse_qsl, urljoin

from pydantic import BaseModel, Field

from shisad.core.host_matching import host_matches
from shisad.core.session import Session
from shisad.core.types import TaintLabel
from shisad.core.url_parsing import safe_url_hostname, safe_urlparse
from shisad.executors.mounts import FilesystemPolicy
from shisad.executors.proxy import NetworkPolicy
from shisad.executors.sandbox import (
    DegradedModePolicy,
    EnvironmentPolicy,
    ResourceLimits,
    SandboxConfig,
    SandboxResult,
    SandboxType,
)
from shisad.security.firewall.output import OutputFirewall

_SNAPSHOT_ELEMENT_RE = re.compile(
    r'^\[(?P<ref>e\d+)\]\s+(?P<kind>\w+)\s+"(?P<label>[^"]*)"\s+selector="(?P<selector>[^"]*)"'
    r'(?:\s+href="(?P<href>[^"]*)")?'
    r'(?:\s+control_type="(?P<control_type>[^"]*)")?'
    r'(?:\s+form_action="(?P<form_action>[^"]*)")?'
    r'(?:\s+form_method="(?P<form_method>[^"]*)")?$'
)
_STRUCTURED_BROWSER_TARGET_RE = re.compile(r"^(?:e\d+|[#./\[].+)$")
_WILDCARD_SCOPE_TOKENS = {"*", "?", "[", "]"}
_PLAYWRIGHT_BROWSERS_PATH_ENV = "PLAYWRIGHT_BROWSERS_PATH"
_SHISAD_BROWSER_WRAPPER_VERSION = "shisad-browser-wrapper 2"
_SHISAD_BROWSER_WRAPPER_SENTINEL = "--shisad-browser-wrapper-version"
_SHISAD_BROWSER_WRAPPER_DOCTOR = "--shisad-browser-wrapper-doctor"
_BROWSER_NODE_VERSION_TOO_OLD = "browser_node_version_too_old"
_PATHLIKE_COMMAND_ARG_SUFFIXES = {
    ".cjs",
    ".js",
    ".json",
    ".jsx",
    ".mjs",
    ".py",
    ".sh",
    ".ts",
    ".tsx",
}
_NODE_NON_PATH_FLAGS = {"-e", "-p", "--eval", "--print"}
_PYTHON_NON_PATH_FLAGS = {"-c", "-m", "--module"}
_ENV_FLAGS_WITHOUT_VALUES = {
    "-0",
    "-i",
    "--debug",
    "--ignore-environment",
    "--null",
}
_ENV_FLAGS_WITH_VALUES = {
    "-a",
    "-C",
    "-u",
    "--argv0",
    "--chdir",
    "--unset",
}
_ENV_FLAGS_WITH_VALUE_PREFIXES = (
    "--argv0=",
    "--chdir=",
    "--unset=",
)
_ENV_LITERAL_VALUE_FLAGS = {"-a", "-u", "--argv0", "--unset"}
_ENV_LITERAL_VALUE_PREFIXES = ("--argv0=", "--unset=")
_ENV_SPLIT_FLAGS = {"-S", "--split-string"}
_ENV_SPLIT_FLAG_PREFIX = "--split-string="
_BROWSER_FAILURE_DETAIL_MAX_CHARS = 512
_BROWSER_FAILURE_SECRET_ASSIGNMENT_RE = re.compile(
    r"\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|ACCESS_KEY|KEY|CREDENTIAL)"
    r"[A-Z0-9_]*)=([^\s]+)",
    re.IGNORECASE,
)
_BROWSER_FAILURE_SECRET_TOKEN_RE = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{12,}|[A-Fa-f0-9]{32,})\b"
)
_BROWSER_FAILURE_FILE_URL_PATH_RE = re.compile(r"file://[^\r\n]+", re.IGNORECASE)
_BROWSER_FAILURE_WINDOWS_DRIVE_PATH_RE = re.compile(r"(?<![\w.-])[A-Za-z]:[\\/][^\r\n]+")
_BROWSER_FAILURE_UNC_PATH_RE = re.compile(r"\\\\[^\r\n]+")
_BROWSER_FAILURE_ABSOLUTE_PATH_RE = re.compile(r"(?<![/\w.-])/(?!/)[^\r\n]+")
_BROWSER_FAILURE_URL_TOKEN_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s]+")
_BROWSER_FAILURE_DRIVE_SCHEME_RE = re.compile(r"^[A-Za-z]://")
_BROWSER_FAILURE_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_BROWSER_SANDBOX_MEMORY_MB = 2048
_BROWSER_SANDBOX_PIDS = 4096
_BROWSER_BUTTON_NON_SUBMIT_TYPES = {"button", "reset"}
_BROWSER_FORM_METHODS = {"get", "post", "dialog"}
_BROWSER_INPUT_TYPES = {
    "button",
    "checkbox",
    "color",
    "date",
    "datetime-local",
    "email",
    "file",
    "hidden",
    "image",
    "month",
    "number",
    "password",
    "radio",
    "range",
    "reset",
    "search",
    "submit",
    "tel",
    "text",
    "time",
    "url",
    "week",
}
_BROWSER_IMPLICIT_ENTER_SUBMIT_INPUT_TYPES = {
    "date",
    "datetime-local",
    "email",
    "month",
    "number",
    "password",
    "search",
    "tel",
    "text",
    "time",
    "url",
    "week",
}
_TARGET_STOPWORDS = {
    "a",
    "an",
    "browser",
    "button",
    "control",
    "element",
    "field",
    "in",
    "input",
    "link",
    "of",
    "on",
    "page",
    "tab",
    "the",
    "to",
}


@dataclass(slots=True)
class BrowserSnapshotElement:
    ref: str
    kind: str
    label: str
    selector: str
    href: str = ""
    control_type: str = ""
    form_action: str = ""
    form_method: str = ""


@dataclass(slots=True)
class BrowserTargetResolution:
    requested_target: str
    resolved_target: str
    destination_url: str = ""
    binding_hash: str = ""


@dataclass(slots=True)
class BrowserBindingValidation:
    destination_url: str = ""
    allows_form_query: bool = False


@dataclass(slots=True)
class BrowserRuntimeSandbox:
    command: list[str]
    read_paths: list[Path]
    write_paths: list[Path]
    env: dict[str, str]
    error: str = ""
    details: dict[str, Any] | None = None


@dataclass(slots=True)
class BrowserCacheSandbox:
    write_paths: list[Path]
    env: dict[str, str]
    error: str = ""
    details: dict[str, Any] | None = None


class BrowserSandboxMode(StrEnum):
    CONTAINER_HARDENED = "container_hardened"
    VM = "vm"


class BrowserClipboardMode(StrEnum):
    DISABLED = "disabled"
    ENABLED = "enabled"


class BrowserDownloadsMode(StrEnum):
    DISABLED = "disabled"
    ENABLED = "enabled"


class BrowserLocalNetworkMode(StrEnum):
    BLOCKED = "blocked"
    ALLOWED = "allowed"


class BrowserCookiesMode(StrEnum):
    SESSION_ONLY = "session_only"
    PERSISTENT = "persistent"


class BrowserExtensionsMode(StrEnum):
    NONE = "none"
    ALLOWED = "allowed"


class BrowserSandboxPolicy(BaseModel):
    """Browser runtime policy."""

    sandbox: BrowserSandboxMode = BrowserSandboxMode.CONTAINER_HARDENED
    clipboard: BrowserClipboardMode = BrowserClipboardMode.DISABLED
    downloads: BrowserDownloadsMode = BrowserDownloadsMode.DISABLED
    local_network: BrowserLocalNetworkMode = BrowserLocalNetworkMode.BLOCKED
    cookies: BrowserCookiesMode = BrowserCookiesMode.SESSION_ONLY
    extensions: BrowserExtensionsMode = BrowserExtensionsMode.NONE
    max_screenshot_bytes: int = 5_000_000


class BrowserPasteResult(BaseModel):
    """Clipboard sink decision."""

    allowed: bool
    reason: str = ""
    sanitized_text: str = ""
    blocked: bool = False
    require_confirmation: bool = False
    reason_codes: list[str] = Field(default_factory=list)


class BrowserScreenshotResult(BaseModel):
    """Stored screenshot metadata."""

    screenshot_id: str
    path: str
    size_bytes: int
    taint_labels: list[str] = Field(default_factory=lambda: [TaintLabel.UNTRUSTED.value])
    ocr_text: str = ""
    ocr_taint: str = TaintLabel.UNTRUSTED.value


class BrowserSandbox:
    """Clipboard and screenshot controls for browser automation."""

    def __init__(
        self,
        *,
        output_firewall: OutputFirewall,
        screenshots_dir: Path,
        policy: BrowserSandboxPolicy | None = None,
    ) -> None:
        self._output_firewall = output_firewall
        self._screenshots_dir = screenshots_dir
        self._screenshots_dir.mkdir(parents=True, exist_ok=True)
        self._policy = policy or BrowserSandboxPolicy()

    @property
    def policy(self) -> BrowserSandboxPolicy:
        return self._policy

    def paste(
        self,
        text: str,
        *,
        taint_labels: set[TaintLabel] | None = None,
    ) -> BrowserPasteResult:
        labels = taint_labels or set()
        if self._policy.clipboard == BrowserClipboardMode.DISABLED:
            return BrowserPasteResult(allowed=False, blocked=True, reason="clipboard_disabled")
        if labels & {
            TaintLabel.SENSITIVE_FILE,
            TaintLabel.SENSITIVE_EMAIL,
            TaintLabel.SENSITIVE_CALENDAR,
            TaintLabel.USER_CREDENTIALS,
        }:
            return BrowserPasteResult(
                allowed=False,
                blocked=True,
                reason="sensitive_taint_clipboard",
            )

        result = self._output_firewall.inspect(text, context={"sink": "browser.clipboard"})
        return BrowserPasteResult(
            allowed=not (result.blocked or result.require_confirmation),
            reason="blocked_by_output_firewall" if result.blocked else "",
            sanitized_text=result.sanitized_text,
            blocked=result.blocked,
            require_confirmation=result.require_confirmation,
            reason_codes=list(result.reason_codes),
        )

    def store_screenshot(
        self,
        *,
        session_id: str,
        image_base64: str,
        ocr_text: str = "",
    ) -> BrowserScreenshotResult:
        try:
            payload = base64.b64decode(image_base64.encode("utf-8"), validate=True)
        except binascii.Error as exc:
            raise ValueError("invalid_screenshot_payload") from exc
        if len(payload) > self._policy.max_screenshot_bytes:
            raise ValueError("screenshot_too_large")
        digest = hashlib.sha256(payload).hexdigest()[:16]
        screenshot_id = f"{session_id}-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}-{digest}"
        path = self._screenshots_dir / f"{screenshot_id}.png"
        path.write_bytes(payload)

        return BrowserScreenshotResult(
            screenshot_id=screenshot_id,
            path=str(path),
            size_bytes=len(payload),
            ocr_text=ocr_text,
        )


class BrowserCommandRunner(Protocol):
    """Async command runner interface used by browser automation."""

    async def execute_async(
        self,
        config: SandboxConfig,
        *,
        session: Session | None = None,
    ) -> SandboxResult: ...


class BrowserToolkit:
    """Playwright-CLI style browser wrapper with sandboxed command execution."""

    def __init__(
        self,
        *,
        enabled: bool,
        command: list[str] | str,
        session_root: Path,
        allowed_domains: list[str],
        timeout_seconds: float,
        require_hardened_isolation: bool,
        max_read_bytes: int,
        sandbox_runner: BrowserCommandRunner,
        browser_sandbox: BrowserSandbox,
    ) -> None:
        if isinstance(command, str):
            command = shlex.split(command)
        self._enabled = enabled
        self._command = [str(token) for token in command if str(token).strip()]
        self._session_root = session_root
        self._session_root.mkdir(parents=True, exist_ok=True)
        self._allowed_domains = [item.strip().lower() for item in allowed_domains if item.strip()]
        self._timeout_seconds = max(1.0, float(timeout_seconds))
        self._require_hardened_isolation = bool(require_hardened_isolation)
        self._max_read_bytes = max(1024, int(max_read_bytes))
        self._sandbox_runner = sandbox_runner
        self._browser_sandbox = browser_sandbox

    async def prepare_action_arguments(
        self,
        *,
        session: Session,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> dict[str, Any]:
        prepared = dict(arguments)
        if tool_name == "browser.navigate":
            url = str(prepared.get("url", "")).strip()
            if url:
                prepared["url"] = url
            return prepared
        if tool_name not in {"browser.click", "browser.type_text"}:
            return prepared
        for runtime_field in (
            "resolved_target",
            "resolved_click_target",
            "destination",
            "source_url",
            "source_binding",
            "click_source_binding",
        ):
            prepared.pop(runtime_field, None)
        current_url = self._current_url(session)
        if not current_url:
            return prepared
        prepared["source_url"] = current_url
        resolution = await self._resolve_target_details(
            session=session,
            tool_name=tool_name,
            target=str(prepared.get("target", "")),
            current_url=current_url,
            submit=bool(prepared.get("submit", False)),
        )
        if resolution.resolved_target and resolution.resolved_target != resolution.requested_target:
            prepared["resolved_target"] = resolution.resolved_target
        if resolution.destination_url:
            prepared["destination"] = resolution.destination_url
        if resolution.binding_hash:
            prepared["source_binding"] = resolution.binding_hash
        if tool_name == "browser.type_text":
            click_target = str(prepared.get("click_target", "")).strip()
            if click_target:
                click_resolution = await self._resolve_target_details(
                    session=session,
                    tool_name="browser.click",
                    target=click_target,
                    current_url=current_url,
                    submit=False,
                )
                if (
                    click_resolution.resolved_target
                    and click_resolution.resolved_target != click_resolution.requested_target
                ):
                    prepared["resolved_click_target"] = click_resolution.resolved_target
                if click_resolution.destination_url:
                    prepared["destination"] = click_resolution.destination_url
                if click_resolution.binding_hash:
                    prepared["click_source_binding"] = click_resolution.binding_hash
        return prepared

    async def navigate(self, *, session: Session, url: str) -> dict[str, Any]:
        normalized_url = url.strip()
        if not normalized_url:
            return self._error_payload("url_required")
        availability = self._availability_error()
        if availability is not None:
            return availability
        if not safe_url_hostname(normalized_url):
            return self._error_payload("browser_url_invalid")
        opened = await self._ensure_session_open(session=session)
        if opened is not None:
            return opened
        result = await self._run_cli(
            session=session,
            tool_name="browser.navigate",
            args=["goto", normalized_url],
            network_urls=[normalized_url],
            allow_network=True,
        )
        if result is not None:
            return result
        return await self._capture_page_state(
            session=session,
            tool_name="browser.navigate",
            include_snapshot=True,
            fallback_url=normalized_url,
        )

    async def read_page(self, *, session: Session) -> dict[str, Any]:
        availability = self._availability_error()
        if availability is not None:
            return availability
        state = self._load_state(session)
        if not bool(state.get("opened")) or not str(state.get("current_url", "")).strip():
            return self._error_payload("browser_session_missing")
        return await self._capture_page_state(
            session=session,
            tool_name="browser.read_page",
            include_snapshot=True,
        )

    async def click(
        self,
        *,
        session: Session,
        target: str,
        description: str = "",
        resolved_target: str = "",
        destination: str = "",
        source_url: str = "",
        source_binding: str = "",
    ) -> dict[str, Any]:
        availability = self._availability_error()
        if availability is not None:
            return availability
        current_url = self._current_url(session)
        if not current_url:
            return self._error_payload("browser_session_missing")
        prepared_source_url = source_url.strip()
        if prepared_source_url and prepared_source_url != current_url:
            return self._error_payload("browser_confirmation_context_changed")
        requested_target = target.strip()
        concrete_target = resolved_target.strip() or await self._resolve_target(
            session=session,
            tool_name="browser.click",
            target=requested_target,
            current_url=current_url,
        )
        binding_validation = await self._validate_prepared_binding(
            session=session,
            tool_name="browser.click",
            current_url=current_url,
            binding_target=concrete_target,
            expected_binding=source_binding.strip(),
            expected_destination=destination.strip(),
            submit=False,
        )
        if isinstance(binding_validation, dict):
            return binding_validation
        destination_url = destination.strip()
        network_urls = self._merge_network_urls(current_url, prepared_source_url, destination_url)
        result = await self._run_cli(
            session=session,
            tool_name="browser.click",
            args=["click", concrete_target],
            network_urls=network_urls,
            allow_network=True,
        )
        if result is not None:
            return result
        payload = await self._capture_page_state(
            session=session,
            tool_name="browser.click",
            include_snapshot=True,
            additional_network_urls=network_urls,
        )
        if payload.get("ok") is True:
            if source_binding.strip() or destination_url:
                post_action_error = self._validate_post_action_destination(
                    source_url=current_url,
                    expected_destination=destination_url,
                    actual_url=str(payload.get("url", "")),
                    allow_query_extension=bool(
                        binding_validation and binding_validation.allows_form_query
                    ),
                )
                if post_action_error is not None:
                    self._invalidate_session_state(session)
                    return post_action_error
            payload["action"] = "click"
            payload["target"] = concrete_target
            payload["requested_target"] = requested_target
            payload["description"] = description.strip()
            if prepared_source_url:
                payload["source_url"] = prepared_source_url
            if destination_url:
                payload["destination"] = destination_url
        return payload

    async def type_text(
        self,
        *,
        session: Session,
        target: str,
        text: str,
        is_sensitive: bool = False,
        submit: bool = False,
        click_target: str = "",
        resolved_target: str = "",
        resolved_click_target: str = "",
        destination: str = "",
        source_url: str = "",
        source_binding: str = "",
        click_source_binding: str = "",
    ) -> dict[str, Any]:
        availability = self._availability_error()
        if availability is not None:
            return availability
        current_url = self._current_url(session)
        if not current_url:
            return self._error_payload("browser_session_missing")
        prepared_source_url = source_url.strip()
        if prepared_source_url and prepared_source_url != current_url:
            return self._error_payload("browser_confirmation_context_changed")
        requested_target = target.strip()
        concrete_target = resolved_target.strip() or await self._resolve_target(
            session=session,
            tool_name="browser.type_text",
            target=requested_target,
            current_url=current_url,
        )
        binding_validation = await self._validate_prepared_binding(
            session=session,
            tool_name="browser.type_text",
            current_url=current_url,
            binding_target=concrete_target,
            expected_binding=source_binding.strip(),
            expected_destination=destination.strip() if submit else "",
            submit=submit,
        )
        if isinstance(binding_validation, dict):
            return binding_validation
        requested_click_target = click_target.strip()
        concrete_click_target = ""
        click_binding_validation: BrowserBindingValidation | None = None
        if requested_click_target:
            if submit:
                return self._error_payload("browser_type_text_submit_or_click")
            concrete_click_target = resolved_click_target.strip() or await self._resolve_target(
                session=session,
                tool_name="browser.click",
                target=requested_click_target,
                current_url=current_url,
            )
            click_binding_result = await self._validate_prepared_binding(
                session=session,
                tool_name="browser.click",
                current_url=current_url,
                binding_target=concrete_click_target,
                expected_binding=click_source_binding.strip(),
                expected_destination=destination.strip(),
                submit=False,
            )
            if isinstance(click_binding_result, dict):
                return click_binding_result
            click_binding_validation = click_binding_result
        args = ["fill", concrete_target, text]
        if submit:
            args.append("--submit")
        if concrete_click_target:
            args.extend(["--click", concrete_click_target])
        if is_sensitive:
            args.append("--no-store")
        destination_url = destination.strip()
        network_urls = self._merge_network_urls(current_url, prepared_source_url, destination_url)
        result = await self._run_cli(
            session=session,
            tool_name="browser.type_text",
            args=args,
            network_urls=network_urls,
            allow_network=True,
        )
        if result is not None:
            return result
        payload = await self._capture_page_state(
            session=session,
            tool_name="browser.type_text",
            include_snapshot=False,
            additional_network_urls=network_urls,
        )
        if payload.get("ok") is True:
            if source_binding.strip() or click_source_binding.strip() or destination_url:
                post_action_error = self._validate_post_action_destination(
                    source_url=current_url,
                    expected_destination=destination_url,
                    actual_url=str(payload.get("url", "")),
                    allow_query_extension=bool(
                        (binding_validation and binding_validation.allows_form_query)
                        or (click_binding_validation and click_binding_validation.allows_form_query)
                        or (submit and not source_binding.strip())
                    ),
                )
                if post_action_error is not None:
                    self._invalidate_session_state(session)
                    return post_action_error
            payload["action"] = "type_text"
            payload["target"] = concrete_target
            payload["requested_target"] = requested_target
            payload["is_sensitive"] = bool(is_sensitive)
            if concrete_click_target:
                payload["click_target"] = concrete_click_target
                payload["requested_click_target"] = requested_click_target
            if prepared_source_url:
                payload["source_url"] = prepared_source_url
            if destination_url:
                payload["destination"] = destination_url
        return payload

    async def screenshot(self, *, session: Session) -> dict[str, Any]:
        availability = self._availability_error()
        if availability is not None:
            return availability
        current_url = self._current_url(session)
        if not current_url:
            return self._error_payload("browser_session_missing")
        session_dir = self._session_dir(session)
        raw_path = session_dir / "page.png"
        result = await self._run_cli(
            session=session,
            tool_name="browser.screenshot",
            args=["screenshot", "--filename", str(raw_path)],
            network_urls=[current_url],
            allow_network=True,
        )
        if result is not None:
            return result
        page_state = await self._capture_page_state(
            session=session,
            tool_name="browser.screenshot",
            include_snapshot=False,
        )
        if page_state.get("ok") is not True:
            return page_state
        if not raw_path.exists():
            return self._error_payload("browser_screenshot_missing")
        image_base64 = base64.b64encode(raw_path.read_bytes()).decode("ascii")
        stored = self._browser_sandbox.store_screenshot(
            session_id=str(session.id),
            image_base64=image_base64,
            ocr_text=str(page_state.get("content", "")),
        )
        with contextlib.suppress(OSError):
            raw_path.unlink()
        return {
            "ok": True,
            "url": page_state.get("url", ""),
            "title": page_state.get("title", ""),
            "screenshot_id": stored.screenshot_id,
            "path": stored.path,
            "size_bytes": stored.size_bytes,
            "ocr_text": stored.ocr_text,
            "taint_labels": list(stored.taint_labels),
            "error": "",
        }

    async def end_session(self, *, session: Session) -> dict[str, Any]:
        availability = self._availability_error()
        if availability is not None:
            return availability
        if not bool(self._load_state(session).get("opened")):
            return {"ok": True, "closed": False, "taint_labels": [], "error": ""}
        result = await self._run_cli(
            session=session,
            tool_name="browser.end_session",
            args=["close"],
            network_urls=[],
            allow_network=False,
        )
        session_dir = self._session_dir(session)
        try:
            state_path = self._state_path(session)
            if state_path.exists():
                state_path.unlink()
        except OSError:
            pass
        if result is not None:
            return result
        if session_dir.exists():
            for child in session_dir.iterdir():
                if child.is_file():
                    try:
                        child.unlink()
                    except OSError:
                        continue
        return {"ok": True, "closed": True, "taint_labels": [], "error": ""}

    def current_state(self, *, session: Session) -> dict[str, Any]:
        state = self._load_state(session)
        current_url = str(state.get("current_url", "")).strip()
        opened = bool(state.get("opened")) and bool(safe_url_hostname(current_url))
        return {
            "opened": opened,
            "current_url": current_url if opened else "",
        }

    async def doctor_status(self) -> dict[str, Any]:
        """Return operator-facing browser command readiness diagnostics."""
        command_display = shlex.join(self._command) if self._command else ""
        base_payload: dict[str, Any] = {
            "enabled": bool(self._enabled),
            "command": command_display,
            "allowed_domains": list(self._allowed_domains),
            "require_hardened_isolation": bool(self._require_hardened_isolation),
            "problems": [],
            "protocol": {"supported": False, "probe": "", "reason": ""},
        }
        if not self._enabled:
            return {**base_payload, "status": "disabled"}
        problems: list[str] = []
        if self._has_unsupported_hardened_wildcard_scope():
            problems.append("browser_hardened_wildcard_scope_unsupported")
        if not self._command:
            problems.append("browser_command_unconfigured")
        runtime_command: list[str] = []
        dependency_error = ""
        if self._command:
            runtime_command, _read_paths, dependency_error = self._browser_command_runtime()
            if dependency_error:
                problems.append(dependency_error)
        protocol: dict[str, Any] = {"supported": False, "probe": "", "reason": ""}
        if runtime_command and not dependency_error:
            cache = self._prepare_browser_cache_dir()
            if cache.error:
                problems.append(cache.error)
            protocol = await self._probe_browser_command_protocol(runtime_command)
            if not protocol["supported"]:
                problems.append(protocol["reason"])
        status = "ok" if not problems else "misconfigured"
        return {
            **base_payload,
            "status": status,
            "problems": sorted(set(problems)),
            "protocol": protocol,
        }

    def _availability_error(self) -> dict[str, Any] | None:
        if not self._enabled:
            return self._error_payload("browser_disabled")
        if self._has_unsupported_hardened_wildcard_scope():
            return self._error_payload("browser_hardened_wildcard_scope_unsupported")
        if not self._command:
            return self._error_payload(
                "browser_command_unconfigured",
                details=self._preflight_error_details("browser_command_unconfigured"),
            )
        _, error = self._browser_command_dependency_roots()
        if error:
            return self._error_payload(error, details=self._preflight_error_details(error))
        return None

    def _has_unsupported_hardened_wildcard_scope(self) -> bool:
        if not self._require_hardened_isolation:
            return False
        return any(self._scope_rule_has_wildcards(rule) for rule in self._allowed_domains)

    async def _ensure_session_open(self, *, session: Session) -> dict[str, Any] | None:
        state = self._load_state(session)
        if bool(state.get("opened")):
            return None
        result = await self._run_cli(
            session=session,
            tool_name="browser.navigate",
            args=["open"],
            network_urls=[],
            allow_network=False,
        )
        if result is not None:
            return result
        state["opened"] = True
        self._save_state(session, state)
        return None

    async def _capture_page_state(
        self,
        *,
        session: Session,
        tool_name: str,
        include_snapshot: bool,
        fallback_url: str = "",
        additional_network_urls: list[str] | None = None,
    ) -> dict[str, Any]:
        current_url = self._current_url(session) or fallback_url.strip()
        if not current_url:
            return self._error_payload("browser_session_missing")
        network_scope = self._merge_network_urls(
            current_url,
            fallback_url,
            *(additional_network_urls or []),
        )
        session_dir = self._session_dir(session)
        metadata_path = session_dir / "page.json"
        snapshot_path = session_dir / "snapshot.txt"
        metadata_error = await self._run_cli(
            session=session,
            tool_name=tool_name,
            args=[
                "eval",
                (
                    "() => JSON.stringify({url: location.href, title: document.title, "
                    "visible_text: document.body ? document.body.innerText : ''})"
                ),
                "--filename",
                str(metadata_path),
            ],
            network_urls=network_scope,
            allow_network=True,
        )
        if metadata_error is not None:
            return metadata_error
        try:
            payload = self._parse_page_metadata(metadata_path.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError):
            return self._error_payload("browser_eval_invalid")
        snapshot = ""
        if include_snapshot:
            snapshot_error = await self._run_cli(
                session=session,
                tool_name=tool_name,
                args=["snapshot", "--filename", str(snapshot_path)],
                network_urls=self._merge_network_urls(
                    current_url,
                    fallback_url,
                    str(payload.get("url", current_url)),
                    *(additional_network_urls or []),
                ),
                allow_network=True,
            )
            if snapshot_error is not None:
                return snapshot_error
            try:
                snapshot = self._truncate_text(snapshot_path.read_text(encoding="utf-8"))
            except OSError:
                snapshot = ""
        state = self._load_state(session)
        state["opened"] = True
        state["current_url"] = str(payload.get("url", current_url)).strip() or current_url
        self._save_state(session, state)
        return {
            "ok": True,
            "url": state["current_url"],
            "title": str(payload.get("title", "")).strip(),
            "content": self._truncate_text(str(payload.get("visible_text", ""))),
            "snapshot": snapshot,
            "taint_labels": [TaintLabel.UNTRUSTED.value],
            "error": "",
        }

    @staticmethod
    def _merge_network_urls(*urls: str) -> list[str]:
        merged: list[str] = []
        seen: set[str] = set()
        for raw_url in urls:
            normalized = str(raw_url).strip()
            if not normalized or normalized in seen:
                continue
            merged.append(normalized)
            seen.add(normalized)
        return merged

    async def _run_cli(
        self,
        *,
        session: Session,
        tool_name: str,
        args: list[str],
        network_urls: list[str],
        allow_network: bool,
    ) -> dict[str, Any] | None:
        session_dir = self._session_dir(session)
        session_dir.mkdir(parents=True, exist_ok=True)
        runtime = self._prepare_browser_runtime_sandbox()
        if runtime.error:
            return self._error_payload(runtime.error, details=runtime.details)
        read_paths = self._dedupe_paths([session_dir, *runtime.read_paths])
        write_paths = self._dedupe_paths([session_dir, *runtime.write_paths])
        filesystem = self._filesystem_policy(read_paths=read_paths, write_paths=write_paths)
        network_policy = self._network_policy(target_urls=network_urls, allow_network=allow_network)
        config = SandboxConfig(
            tool_name=tool_name,
            command=[*runtime.command, f"-s={self._session_alias(session)}", *args],
            sandbox_type=SandboxType.CONTAINER,
            session_id=str(session.id),
            cwd=str(session_dir),
            read_paths=[str(path) for path in read_paths],
            write_paths=[str(path) for path in write_paths],
            env=runtime.env,
            filesystem=filesystem,
            network_urls=network_urls,
            network=network_policy,
            environment=self._browser_environment_policy(),
            limits=ResourceLimits(
                memory_mb=_BROWSER_SANDBOX_MEMORY_MB,
                address_space_mb=0,
                timeout_seconds=max(1, math.ceil(self._timeout_seconds)),
                output_bytes=max(self._max_read_bytes * 2, 32_768),
                pids=_BROWSER_SANDBOX_PIDS,
            ),
            degraded_mode=(
                DegradedModePolicy.FAIL_CLOSED
                if self._require_hardened_isolation
                else DegradedModePolicy.FAIL_OPEN
            ),
            security_critical=self._require_hardened_isolation,
            approved_by_pep=True,
            origin={
                "actor": "browser_toolkit",
                "session_id": str(session.id),
                "channel": str(session.channel),
            },
        )
        result = await self._sandbox_runner.execute_async(config, session=session)
        if result.allowed and not result.timed_out and (result.exit_code or 0) == 0:
            return None
        reason = self._result_error_reason(result)
        return self._error_payload(reason, details=self._result_error_details(result, reason))

    def _prepare_browser_runtime_sandbox(self) -> BrowserRuntimeSandbox:
        command, read_paths, dependency_error = self._browser_command_runtime()
        if dependency_error:
            return BrowserRuntimeSandbox(
                command=[],
                read_paths=[],
                write_paths=[],
                env={},
                error=dependency_error,
                details=self._preflight_error_details(dependency_error),
            )
        cache = self._prepare_browser_cache_dir()
        if cache.error:
            return BrowserRuntimeSandbox(
                command=[],
                read_paths=[],
                write_paths=[],
                env={},
                error=cache.error,
                details=cache.details,
            )
        return BrowserRuntimeSandbox(
            command=command,
            read_paths=read_paths,
            write_paths=cache.write_paths,
            env=cache.env,
        )

    async def _probe_browser_command_protocol(self, command: list[str]) -> dict[str, Any]:
        sentinel = await self._run_browser_command_probe(
            command,
            [_SHISAD_BROWSER_WRAPPER_SENTINEL],
        )
        sentinel_output = self._probe_text(sentinel)
        if sentinel["exit_code"] == 0 and "shisad-browser-wrapper" in sentinel_output:
            version_supported = _SHISAD_BROWSER_WRAPPER_VERSION in sentinel_output
            readiness = await self._run_browser_command_probe(
                command,
                [_SHISAD_BROWSER_WRAPPER_DOCTOR],
            )
            readiness_output = self._probe_text(readiness)
            if (
                version_supported
                and readiness["exit_code"] == 0
                and "doctor ok" in readiness_output
            ):
                return {"supported": True, "probe": "sentinel,readiness", "reason": ""}
            reason = self._readiness_probe_reason(readiness)
            if readiness["exit_code"] == 0 and "doctor ok" in readiness_output:
                reason = "browser_command_protocol_incompatible"
            return {
                "supported": False,
                "probe": "sentinel,readiness",
                "reason": reason,
                "stderr": self._sanitize_browser_failure_text(readiness["stderr"]),
                "stdout": self._sanitize_browser_failure_text(readiness["stdout"]),
                "degraded_controls": sorted(readiness.get("degraded_controls", [])),
            }

        help_probe = await self._run_browser_command_probe(command, ["--help"])
        help_output = self._probe_text(help_probe)
        if help_probe["exit_code"] == 0 and (
            _SHISAD_BROWSER_WRAPPER_SENTINEL in help_output
            or ("-s=" in help_output and "shisad" in help_output.lower())
        ):
            return {
                "supported": False,
                "probe": "sentinel,help",
                "reason": "browser_command_protocol_incompatible",
                "stderr": self._sanitize_browser_failure_text(
                    sentinel["stderr"] or help_probe["stderr"]
                ),
                "stdout": self._sanitize_browser_failure_text(
                    sentinel["stdout"] or help_probe["stdout"]
                ),
                "degraded_controls": sorted(
                    {
                        *sentinel.get("degraded_controls", []),
                        *help_probe.get("degraded_controls", []),
                    }
                ),
            }

        probe_error = str(sentinel.get("error") or help_probe.get("error") or "")
        reason = "browser_command_protocol_incompatible"
        if probe_error:
            reason = probe_error
        elif sentinel["timed_out"] or help_probe["timed_out"]:
            reason = "browser_command_protocol_probe_timeout"
        return {
            "supported": False,
            "probe": "sentinel,help",
            "reason": reason,
            "stderr": self._sanitize_browser_failure_text(
                sentinel["stderr"] or help_probe["stderr"]
            ),
            "stdout": self._sanitize_browser_failure_text(
                sentinel["stdout"] or help_probe["stdout"]
            ),
            "degraded_controls": sorted(
                {
                    *sentinel.get("degraded_controls", []),
                    *help_probe.get("degraded_controls", []),
                }
            ),
        }

    async def _run_browser_command_probe(
        self,
        command: list[str],
        args: list[str],
    ) -> dict[str, Any]:
        probe_dir = self._session_root / "_doctor"
        probe_dir.mkdir(parents=True, exist_ok=True)
        read_paths = self._dedupe_paths([probe_dir, *self._browser_command_dependency_roots()[0]])
        config = SandboxConfig(
            tool_name="browser.doctor",
            command=[*command, *args],
            sandbox_type=SandboxType.CONTAINER,
            session_id="browser-doctor",
            cwd=str(probe_dir),
            read_paths=[str(path) for path in read_paths],
            write_paths=[str(probe_dir)],
            env={},
            filesystem=self._filesystem_policy(read_paths=read_paths, write_paths=[probe_dir]),
            network_urls=[],
            network=NetworkPolicy(allow_network=False, allowed_domains=[]),
            environment=self._browser_environment_policy(),
            limits=ResourceLimits(
                memory_mb=_BROWSER_SANDBOX_MEMORY_MB,
                address_space_mb=0,
                timeout_seconds=5,
                output_bytes=16_384,
                pids=_BROWSER_SANDBOX_PIDS,
            ),
            degraded_mode=(
                DegradedModePolicy.FAIL_CLOSED
                if self._require_hardened_isolation
                else DegradedModePolicy.FAIL_OPEN
            ),
            security_critical=self._require_hardened_isolation,
            approved_by_pep=True,
            origin={"actor": "browser_doctor"},
        )
        result = await self._sandbox_runner.execute_async(config, session=None)
        error = ""
        if not result.allowed or result.timed_out:
            error = self._result_error_reason(result)
        return {
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "timed_out": result.timed_out,
            "error": error,
            "degraded_controls": list(result.degraded_controls),
        }

    @staticmethod
    def _probe_text(probe: Mapping[str, Any]) -> str:
        return " ".join(str(probe.get(key, "")) for key in ("stdout", "stderr"))

    def _readiness_probe_reason(self, probe: Mapping[str, Any]) -> str:
        error = str(probe.get("error") or "")
        if error:
            return error
        if probe.get("timed_out"):
            return "browser_command_protocol_probe_timeout"
        text = self._probe_text(probe).lower()
        if _BROWSER_NODE_VERSION_TOO_OLD in text:
            return _BROWSER_NODE_VERSION_TOO_OLD
        if (
            "@playwright/test is not available" in text
            or "did not expose chromium.launchpersistentcontext" in text
        ):
            return "browser_dependency_unavailable"
        if _SHISAD_BROWSER_WRAPPER_DOCTOR in text and (
            "unsupported" in text or "unknown option" in text or "unknown command" in text
        ):
            return "browser_command_protocol_incompatible"
        return "browser_command_failed"

    def _browser_command_dependency_roots(self) -> tuple[list[Path], str]:
        _, read_paths, error = self._browser_command_runtime()
        return read_paths, error

    def _browser_command_runtime(self) -> tuple[list[str], list[Path], str]:
        executable_path, executable_error = self._resolve_browser_executable()
        if executable_error or executable_path is None:
            return [], [], executable_error or "browser_command_unavailable"
        roots: list[Path] = []
        executable_roots, dependency_error = self._runtime_read_paths_for_path(executable_path)
        if dependency_error:
            return [], [], dependency_error
        roots.extend(executable_roots)
        shebang_roots, dependency_error = self._shebang_dependency_roots(executable_path)
        if dependency_error:
            return [], [], dependency_error
        roots.extend(shebang_roots)
        (
            env_target_path,
            env_values,
            env_cwd,
            _env_target,
            env_target_index,
            dependency_error,
        ) = self._env_command_target_path(executable_path)
        if dependency_error:
            return [], [], dependency_error
        if env_target_path is not None:
            env_target_roots, dependency_error = self._runtime_read_paths_for_path(env_target_path)
            if dependency_error:
                return [], [], dependency_error
            roots.extend(env_target_roots)
            env_target_shebang_roots, dependency_error = self._shebang_dependency_roots(
                env_target_path,
                env_values=env_values,
                cwd=env_cwd,
            )
            if dependency_error:
                return [], [], dependency_error
            roots.extend(env_target_shebang_roots)
        command = [str(executable_path)]
        non_path_flags = self._non_path_flags_for_command(executable_path, env_target_path)
        env_prefix_active = "env" in self._executable_identity_names(executable_path)
        env_options_ended = False
        previous_token = ""
        previous_token_was_env_value = False
        for arg_index, token in enumerate(self._command[1:]):
            token_value = str(token)
            env_option_prefix_active = env_prefix_active and not env_options_ended
            previous_token_expects_env_value = (
                env_option_prefix_active
                and previous_token in _ENV_FLAGS_WITH_VALUES
                and not previous_token_was_env_value
            )
            if (
                env_option_prefix_active
                and previous_token in _ENV_SPLIT_FLAGS
                and not previous_token_was_env_value
            ):
                split_token, split_paths = self._normalize_env_split_argument(token_value)
                for split_path in split_paths:
                    split_roots, dependency_error = self._runtime_read_paths_for_path(split_path)
                    if dependency_error:
                        return [], [], dependency_error
                    roots.extend(split_roots)
                command.append(split_token)
                previous_token = token_value
                previous_token_was_env_value = False
                env_prefix_active = False
                continue
            if (
                env_option_prefix_active
                and not previous_token_expects_env_value
                and token_value == "--"
            ):
                command.append(token_value)
                previous_token = token_value
                previous_token_was_env_value = False
                env_options_ended = True
                continue
            if (
                env_option_prefix_active
                and not previous_token_expects_env_value
                and token_value.startswith(_ENV_SPLIT_FLAG_PREFIX)
            ):
                split_token, split_paths = self._normalize_env_split_argument(
                    token_value.split("=", 1)[1]
                )
                for split_path in split_paths:
                    split_roots, dependency_error = self._runtime_read_paths_for_path(split_path)
                    if dependency_error:
                        return [], [], dependency_error
                    roots.extend(split_roots)
                command.append(f"{_ENV_SPLIT_FLAG_PREFIX}{split_token}")
                previous_token = token_value
                previous_token_was_env_value = False
                env_prefix_active = False
                continue
            current_token_is_env_value = previous_token_expects_env_value
            helper_previous_token = "" if previous_token_was_env_value else previous_token
            resolved_token, token_path = self._resolve_existing_command_argument(
                token_value,
                previous_token=helper_previous_token,
                non_path_flags=non_path_flags,
                base_dir=env_cwd,
                env_prefix=env_option_prefix_active,
            )
            if token_path is None:
                command.append(resolved_token)
                if env_prefix_active and arg_index == env_target_index:
                    env_prefix_active = False
                previous_token = token_value
                previous_token_was_env_value = current_token_is_env_value
                continue
            token_roots, dependency_error = self._runtime_read_paths_for_path(token_path)
            if dependency_error:
                return [], [], dependency_error
            roots.extend(token_roots)
            command.append(resolved_token)
            if env_prefix_active and arg_index == env_target_index:
                env_prefix_active = False
            previous_token = token_value
            previous_token_was_env_value = current_token_is_env_value
        return command, self._dedupe_paths(roots), ""

    def _runtime_read_paths_for_path(self, path: Path) -> tuple[list[Path], str]:
        candidate = path.expanduser()
        dependency_roots, dependency_error = self._dependency_roots_for_path(candidate)
        if dependency_error:
            return [], dependency_error
        paths = [candidate]
        if candidate.is_symlink():
            try:
                paths.append(candidate.resolve(strict=True))
            except OSError:
                return [], "browser_dependency_unavailable"
        return self._dedupe_paths([*paths, *dependency_roots]), ""

    def _resolve_browser_executable(self) -> tuple[Path | None, str]:
        if not self._command:
            return None, "browser_command_unconfigured"
        return self._resolve_executable_token(self._command[0])

    def _resolve_executable_token(self, executable: str) -> tuple[Path | None, str]:
        explicit_path = Path(executable).expanduser()
        if explicit_path.is_absolute() or "/" in executable:
            candidate = self._absolute_path(explicit_path)
            if candidate.exists() or candidate.is_symlink():
                return candidate, ""
            return None, "browser_command_unavailable"
        resolved = shutil.which(executable)
        if not resolved:
            return None, "browser_command_unavailable"
        return Path(resolved), ""

    def _resolve_existing_command_argument(
        self,
        token: str,
        *,
        previous_token: str,
        non_path_flags: set[str],
        base_dir: Path | None,
        env_prefix: bool,
    ) -> tuple[str, Path | None]:
        if not token.strip():
            return token, None
        if env_prefix and previous_token in {"-C", "--chdir"}:
            chdir_path = self._env_chdir_path(token, None)
            return str(chdir_path), chdir_path
        if env_prefix and previous_token in _ENV_LITERAL_VALUE_FLAGS:
            return token, None
        if env_prefix and token.startswith("--chdir="):
            chdir_path = self._env_chdir_path(token.split("=", 1)[1], None)
            return f"--chdir={chdir_path}", chdir_path
        if env_prefix and token.startswith(_ENV_LITERAL_VALUE_PREFIXES):
            return token, None
        if env_prefix and token.startswith("PATH="):
            return f"PATH={self._normalize_env_path_value(token.split('=', 1)[1], base_dir)}", None
        if token.startswith("-"):
            if "=" not in token:
                return token, None
            flag, value = token.split("=", 1)
            value_path = self._resolve_existing_command_argument_path(
                value,
                previous_token=flag,
                non_path_flags=non_path_flags,
                base_dir=base_dir,
            )
            if value_path is None:
                return token, None
            return f"{flag}={value_path}", value_path
        token_path = self._resolve_existing_command_argument_path(
            token,
            previous_token=previous_token,
            non_path_flags=non_path_flags,
            base_dir=base_dir,
        )
        return (str(token_path), token_path) if token_path is not None else (token, None)

    def _resolve_existing_command_argument_path(
        self,
        token: str,
        *,
        previous_token: str,
        non_path_flags: set[str],
        base_dir: Path | None,
    ) -> Path | None:
        token_path = Path(token).expanduser()
        explicit_path_like = (
            token_path.is_absolute()
            or token.startswith((".", "~"))
            or "/" in token
            or "\\" in token
        )
        script_like = token_path.suffix.lower() in _PATHLIKE_COMMAND_ARG_SUFFIXES
        if previous_token in non_path_flags:
            return None
        if previous_token.startswith("-") and not explicit_path_like and not script_like:
            return None
        if not (explicit_path_like or script_like):
            return None
        candidate = self._absolute_path(token_path, base_dir=base_dir)
        if candidate.exists() or candidate.is_symlink():
            return candidate
        return None

    def _env_command_target_path(
        self,
        executable_path: Path,
    ) -> tuple[Path | None, dict[str, str], Path | None, str, int | None, str]:
        if "env" not in self._executable_identity_names(executable_path):
            return None, {}, None, "", None, ""
        env_target, env_values, env_cwd, env_target_index = self._env_invocation(
            [str(token) for token in self._command[1:]]
        )
        if not env_target:
            return None, env_values, env_cwd, "", env_target_index, ""
        env_target_path, dependency_error = self._resolve_env_target_token(
            env_target,
            env_values,
            cwd=env_cwd,
        )
        if dependency_error or env_target_path is None:
            return (
                None,
                env_values,
                env_cwd,
                env_target,
                env_target_index,
                "browser_dependency_unavailable",
            )
        return env_target_path, env_values, env_cwd, env_target, env_target_index, ""

    def _resolve_env_target_token(
        self,
        target: str,
        env_values: dict[str, str],
        *,
        cwd: Path | None,
    ) -> tuple[Path | None, str]:
        explicit_path = Path(target).expanduser()
        if explicit_path.is_absolute() or "/" in target:
            candidate = self._absolute_path(explicit_path, base_dir=cwd)
            if candidate.exists() or candidate.is_symlink():
                return candidate, ""
            return None, "browser_command_unavailable"
        configured_path = env_values.get("PATH")
        if configured_path is not None:
            resolved = shutil.which(
                target,
                path=self._normalize_env_path_value(configured_path, cwd),
            )
            if not resolved:
                return None, "browser_command_unavailable"
            return Path(resolved), ""
        return self._resolve_executable_token(target)

    def _non_path_flags_for_command(
        self,
        executable_path: Path,
        env_target_path: Path | None,
    ) -> set[str]:
        executable_names = self._executable_identity_names(executable_path)
        if env_target_path is not None:
            executable_names.update(self._executable_identity_names(env_target_path))
        if any(name.startswith("python") for name in executable_names):
            return set(_PYTHON_NON_PATH_FLAGS)
        if executable_names & {"node", "nodejs"}:
            return set(_NODE_NON_PATH_FLAGS)
        return set()

    @staticmethod
    def _executable_identity_names(executable_path: Path) -> set[str]:
        names = {executable_path.name.lower()}
        try:
            resolved = executable_path.resolve(strict=True)
        except OSError:
            return names
        names.add(resolved.name.lower())
        return names

    def _dependency_roots_for_path(self, path: Path) -> tuple[list[Path], str]:
        candidate = path.expanduser()
        if candidate.is_symlink():
            try:
                resolved = candidate.resolve(strict=True)
            except OSError:
                return [], "browser_dependency_unavailable"
            return self._dedupe_paths(
                [
                    self._browser_dependency_root(candidate),
                    self._browser_dependency_root(resolved),
                    *self._node_modules_dependency_roots(candidate),
                    *self._node_modules_dependency_roots(resolved),
                ]
            ), ""
        if not candidate.exists():
            return [], "browser_dependency_unavailable"
        return self._dedupe_paths(
            [
                self._browser_dependency_root(candidate),
                *self._node_modules_dependency_roots(candidate),
            ]
        ), ""

    @staticmethod
    def _node_modules_dependency_roots(path: Path) -> list[Path]:
        candidate = path if path.is_dir() else path.parent
        if "node_modules" in candidate.parts:
            return []
        roots: list[Path] = []
        for parent in (candidate, *candidate.parents):
            node_modules = parent / "node_modules"
            if node_modules.is_dir():
                roots.append(node_modules)
        return roots

    def _shebang_dependency_roots(
        self,
        path: Path,
        seen: set[Path] | None = None,
        env_values: dict[str, str] | None = None,
        cwd: Path | None = None,
    ) -> tuple[list[Path], str]:
        candidate = path.expanduser()
        try:
            script_path = candidate.resolve(strict=True)
        except OSError:
            return [], "browser_dependency_unavailable"
        visited = seen or set()
        if script_path in visited:
            return [], ""
        visited.add(script_path)
        if not script_path.is_file():
            return [], ""
        try:
            first_line = script_path.open("rb").readline(256).decode("utf-8", errors="ignore")
        except OSError:
            return [], "browser_dependency_unavailable"
        if not first_line.startswith("#!"):
            return [], ""
        try:
            shebang = shlex.split(first_line[2:].strip())
        except ValueError:
            return [], "browser_dependency_unavailable"
        if not shebang:
            return [], ""
        roots: list[Path] = []
        interpreter_path, dependency_error = self._resolve_executable_token(shebang[0])
        if dependency_error or interpreter_path is None:
            return [], "browser_dependency_unavailable"
        interpreter_roots, dependency_error = self._dependency_roots_for_path(interpreter_path)
        if dependency_error:
            return [], dependency_error
        roots.extend(interpreter_roots)
        if Path(shebang[0]).name == "env":
            env_target, shebang_env_values, shebang_cwd, _ = self._env_invocation(shebang[1:])
            if env_target:
                inherited_env_values = dict(env_values or {})
                inherited_env_values.update(shebang_env_values)
                effective_cwd = shebang_cwd or cwd
                env_target_path, dependency_error = self._resolve_env_target_token(
                    env_target,
                    inherited_env_values,
                    cwd=effective_cwd,
                )
                if dependency_error or env_target_path is None:
                    return [], "browser_dependency_unavailable"
                env_target_roots, dependency_error = self._dependency_roots_for_path(
                    env_target_path
                )
                if dependency_error:
                    return [], dependency_error
                roots.extend(env_target_roots)
                env_target_shebang_roots, dependency_error = self._shebang_dependency_roots(
                    env_target_path,
                    seen=visited,
                    env_values=inherited_env_values,
                    cwd=effective_cwd,
                )
                if dependency_error:
                    return [], dependency_error
                roots.extend(env_target_shebang_roots)
        return self._dedupe_paths(roots), ""

    @staticmethod
    def _env_shebang_target(args: list[str]) -> str:
        return BrowserToolkit._env_invocation(args)[0]

    @staticmethod
    def _env_invocation(args: list[str]) -> tuple[str, dict[str, str], Path | None, int | None]:
        env_values: dict[str, str] = {}
        cwd: Path | None = None
        index = 0
        while index < len(args):
            token = args[index]
            if token in _ENV_SPLIT_FLAGS:
                try:
                    split_args = shlex.split(" ".join(args[index + 1 :]))
                except ValueError:
                    return "", env_values, cwd, None
                split_target, split_env_values, split_cwd, _ = BrowserToolkit._env_invocation(
                    split_args
                )
                env_values.update(split_env_values)
                return split_target, env_values, split_cwd or cwd, index + 1
            if token.startswith(_ENV_SPLIT_FLAG_PREFIX):
                try:
                    split_args = shlex.split(token.split("=", 1)[1])
                except ValueError:
                    return "", env_values, cwd, None
                split_target, split_env_values, split_cwd, _ = BrowserToolkit._env_invocation(
                    split_args
                )
                env_values.update(split_env_values)
                return split_target, env_values, split_cwd or cwd, index
            if token == "--":
                if index + 1 < len(args):
                    return args[index + 1], env_values, cwd, index + 1
                return "", env_values, cwd, None
            if token in _ENV_FLAGS_WITHOUT_VALUES:
                index += 1
                continue
            if token in _ENV_FLAGS_WITH_VALUES:
                if token in {"-C", "--chdir"} and index + 1 < len(args):
                    cwd = BrowserToolkit._env_chdir_path(args[index + 1], cwd)
                index += 2
                continue
            if token.startswith("--chdir="):
                cwd = BrowserToolkit._env_chdir_path(token.split("=", 1)[1], cwd)
                index += 1
                continue
            if token.startswith(_ENV_FLAGS_WITH_VALUE_PREFIXES):
                index += 1
                continue
            if "=" in token and not token.startswith("="):
                key, value = token.split("=", 1)
                if key:
                    if key == "PATH":
                        value = BrowserToolkit._normalize_env_path_value(value, cwd)
                    env_values[key] = value
                index += 1
                continue
            if token.startswith("-"):
                index += 1
                continue
            return token, env_values, cwd, index
        return "", env_values, cwd, None

    @staticmethod
    def _env_chdir_path(raw_path: str, current_cwd: Path | None) -> Path:
        chdir_path = Path(raw_path).expanduser()
        if chdir_path.is_absolute():
            return chdir_path
        return (current_cwd or Path.cwd()) / chdir_path

    def _normalize_env_split_argument(self, raw_arg: str) -> tuple[str, list[Path]]:
        try:
            tokens = shlex.split(raw_arg)
        except ValueError:
            return raw_arg, []
        normalized: list[str] = []
        paths: list[Path] = []
        env_values: dict[str, str] = {}
        cwd: Path | None = None
        target_seen = False
        env_options_ended = False
        non_path_flags: set[str] = set()
        previous_token = ""
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if not target_seen:
                if not env_options_ended:
                    if token == "--":
                        normalized.append(token)
                        env_options_ended = True
                        index += 1
                        continue
                    if token in _ENV_FLAGS_WITHOUT_VALUES:
                        normalized.append(token)
                        index += 1
                        continue
                    if token in {"-C", "--chdir"} and index + 1 < len(tokens):
                        chdir_path = self._env_chdir_path(tokens[index + 1], cwd)
                        cwd = chdir_path
                        normalized.extend([token, str(chdir_path)])
                        paths.append(chdir_path)
                        index += 2
                        continue
                    if token in _ENV_FLAGS_WITH_VALUES and index + 1 < len(tokens):
                        normalized.extend([token, tokens[index + 1]])
                        index += 2
                        continue
                    if token.startswith("--chdir="):
                        chdir_path = self._env_chdir_path(token.split("=", 1)[1], cwd)
                        cwd = chdir_path
                        normalized.append(f"--chdir={chdir_path}")
                        paths.append(chdir_path)
                        index += 1
                        continue
                    if token.startswith(_ENV_FLAGS_WITH_VALUE_PREFIXES):
                        normalized.append(token)
                        index += 1
                        continue
                    if "=" in token and not token.startswith("="):
                        key, value = token.split("=", 1)
                        if key == "PATH":
                            value = self._normalize_env_path_value(value, cwd)
                        if key:
                            env_values[key] = value
                        normalized.append(f"{key}={value}")
                        index += 1
                        continue
                target_path, _ = self._resolve_env_target_token(
                    token,
                    env_values,
                    cwd=cwd,
                )
                if target_path is not None:
                    paths.append(target_path)
                    non_path_flags = self._non_path_flags_for_command(target_path, None)
                    target_token_path = Path(token).expanduser()
                    if target_token_path.is_absolute() or "/" in token or token.startswith("."):
                        token = str(target_path)
                normalized.append(token)
                target_seen = True
                previous_token = token
                index += 1
                continue
            resolved_token, token_path = self._resolve_existing_command_argument(
                token,
                previous_token=previous_token,
                non_path_flags=non_path_flags,
                base_dir=cwd,
                env_prefix=False,
            )
            if token_path is not None:
                paths.append(token_path)
            normalized.append(resolved_token)
            previous_token = token
            index += 1
        return shlex.join(normalized), paths

    @staticmethod
    def _normalize_env_path_value(raw_path: str, cwd: Path | None) -> str:
        base_dir = cwd or Path.cwd()
        normalized_entries: list[str] = []
        for entry in raw_path.split(os.pathsep):
            if not entry:
                normalized_entries.append(str(base_dir))
                continue
            entry_path = Path(entry).expanduser()
            normalized_entries.append(
                str(entry_path if entry_path.is_absolute() else base_dir / entry_path)
            )
        return os.pathsep.join(normalized_entries)

    @staticmethod
    def _absolute_path(path: Path, *, base_dir: Path | None = None) -> Path:
        return path if path.is_absolute() else (base_dir or Path.cwd()) / path

    @staticmethod
    def _browser_dependency_root(path: Path) -> Path:
        candidate = path if path.is_dir() else path.parent
        parts = candidate.parts
        if "node_modules" in parts:
            node_modules_index = parts.index("node_modules")
            return Path(*parts[: node_modules_index + 1])
        return candidate

    @staticmethod
    def _prepare_browser_cache_dir() -> BrowserCacheSandbox:
        configured = os.environ.get(_PLAYWRIGHT_BROWSERS_PATH_ENV, "").strip()
        if configured == "0":
            return BrowserCacheSandbox(
                write_paths=[],
                env={_PLAYWRIGHT_BROWSERS_PATH_ENV: "0"},
            )
        if configured:
            cache_dir = Path(configured).expanduser()
            if not cache_dir.is_absolute():
                cache_dir = cache_dir.resolve(strict=False)
        else:
            cache_dir = Path.home() / ".cache" / "ms-playwright"
        try:
            cache_dir.mkdir(parents=True, exist_ok=True)
            if not cache_dir.is_dir():
                return BrowserCacheSandbox(
                    write_paths=[],
                    env={},
                    error="browser_cache_not_writable",
                    details=BrowserToolkit._preflight_error_details("browser_cache_not_writable"),
                )
            probe = cache_dir / ".shisad-cache-write-test"
            probe.write_text("", encoding="utf-8")
            probe.unlink(missing_ok=True)
        except OSError:
            return BrowserCacheSandbox(
                write_paths=[],
                env={},
                error="browser_cache_not_writable",
                details=BrowserToolkit._preflight_error_details("browser_cache_not_writable"),
            )
        return BrowserCacheSandbox(
            write_paths=[cache_dir],
            env={_PLAYWRIGHT_BROWSERS_PATH_ENV: str(cache_dir)},
        )

    @staticmethod
    def _browser_environment_policy() -> EnvironmentPolicy:
        default_policy = EnvironmentPolicy()
        allowed_keys = list(default_policy.allowed_keys)
        if _PLAYWRIGHT_BROWSERS_PATH_ENV not in allowed_keys:
            allowed_keys.append(_PLAYWRIGHT_BROWSERS_PATH_ENV)
        return EnvironmentPolicy(
            allowed_keys=allowed_keys,
            denied_prefixes=list(default_policy.denied_prefixes),
            max_keys=default_policy.max_keys,
            max_total_bytes=default_policy.max_total_bytes,
        )

    @staticmethod
    def _filesystem_policy(*, read_paths: list[Path], write_paths: list[Path]) -> FilesystemPolicy:
        mounts: dict[str, str] = {}
        for path in read_paths:
            mounts.setdefault(str(path), "ro")
        for path in write_paths:
            mounts[str(path)] = "rw"
        ordered_mounts = sorted(mounts.items(), key=lambda item: len(item[0]), reverse=True)
        return FilesystemPolicy(
            mounts=[{"path": path, "mode": mode} for path, mode in ordered_mounts]
        )

    @staticmethod
    def _dedupe_paths(paths: list[Path]) -> list[Path]:
        deduped: list[Path] = []
        seen: set[str] = set()
        for path in paths:
            key = str(path)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(path)
        return deduped

    def _network_policy(self, *, target_urls: list[str], allow_network: bool) -> NetworkPolicy:
        if not allow_network:
            return NetworkPolicy(allow_network=False, allowed_domains=[])
        allow_private_targets = self._allows_private_network_target(target_urls)
        hosts = list(self._allowed_domains)
        for url in target_urls:
            host = safe_url_hostname(url)
            if host and host not in hosts:
                hosts.append(host)
        return NetworkPolicy(
            allow_network=True,
            allowed_domains=hosts,
            deny_private_ranges=not allow_private_targets,
            deny_ip_literals=not allow_private_targets,
        )

    def _allows_private_network_target(self, target_urls: list[str]) -> bool:
        if not target_urls:
            return False
        for url in target_urls:
            host = safe_url_hostname(url)
            if not self._is_private_network_host(host):
                continue
            if self._browser_sandbox.policy.local_network == BrowserLocalNetworkMode.ALLOWED or any(
                host_matches(host, rule) for rule in self._allowed_domains
            ):
                return True
        return False

    @staticmethod
    def _is_private_network_host(host: str) -> bool:
        if not host:
            return False
        if host == "localhost":
            return True
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return False
        return bool(address.is_private or address.is_loopback or address.is_link_local)

    @staticmethod
    def _preflight_error_details(reason: str) -> dict[str, Any]:
        stage = {
            "browser_command_unavailable": "command_preflight",
            "browser_command_unconfigured": "command_preflight",
            "browser_dependency_unavailable": "dependency_preflight",
            "browser_cache_not_writable": "cache_preflight",
            "browser_command_protocol_incompatible": "command_protocol",
            "browser_command_protocol_probe_failed": "command_protocol",
            "browser_command_protocol_probe_timeout": "command_protocol",
            "browser_runtime_isolation_unavailable": "runtime_isolation",
        }.get(reason, "preflight")
        return {"reason": reason, "stage": stage}

    def _result_error_reason(self, result: SandboxResult) -> str:
        if result.timed_out:
            return "browser_command_timeout"
        if result.reason in {
            "degraded_enforcement",
            "runtime_isolation_unavailable",
            "connect_path_unavailable",
        }:
            return "browser_runtime_isolation_unavailable"
        if "private_range_blocked" in result.reason or "ip_literal_blocked" in result.reason:
            return "browser_local_network_blocked"
        detail = " ".join(
            part for part in [result.reason, result.stderr, result.stdout] if part
        ).lower()
        if _BROWSER_NODE_VERSION_TOO_OLD in detail:
            return _BROWSER_NODE_VERSION_TOO_OLD
        if "unknown option" in detail and ("-s=" in detail or "shisad-browser-wrapper" in detail):
            return "browser_command_protocol_incompatible"
        if (
            "distribution" in detail
            or "install-browser" in detail
            or "playwright install" in detail
        ):
            return "browser_browser_not_installed"
        if result.reason in {
            "command_not_found",
            "command_unavailable",
            "browser_command_unavailable",
        }:
            return "browser_command_unavailable"
        if self._detail_suggests_cache_unwritable(detail):
            return "browser_cache_not_writable"
        if self._detail_suggests_dependency_unavailable(detail):
            return "browser_dependency_unavailable"
        if self._detail_suggests_command_unavailable(detail):
            return "browser_command_unavailable"
        return "browser_subprocess_failed"

    @staticmethod
    def _detail_suggests_command_unavailable(detail: str) -> bool:
        return "executable doesn't exist" in detail

    @staticmethod
    def _detail_suggests_dependency_unavailable(detail: str) -> bool:
        markers = (
            "error while loading shared libraries",
            "cannot open shared object file",
            "dyld: library not loaded",
            "bad interpreter",
            "cannot find module",
        )
        return any(marker in detail for marker in markers)

    @staticmethod
    def _detail_suggests_cache_unwritable(detail: str) -> bool:
        markers = (
            "read-only file system",
            "erofs",
            "cache write failed",
        )
        return any(marker in detail for marker in markers)

    def _result_error_details(self, result: SandboxResult, reason: str) -> dict[str, Any]:
        details: dict[str, Any] = {
            "reason": reason,
            "stage": "subprocess",
        }
        sandbox_reason = self._sanitize_browser_failure_text(result.reason)
        if sandbox_reason and sandbox_reason != "allowed":
            details["sandbox_reason"] = sandbox_reason
        if result.exit_code is not None:
            details["exit_code"] = result.exit_code
        if result.timed_out:
            details["timed_out"] = True
        if result.truncated:
            details["truncated"] = True
        stderr = self._sanitize_browser_failure_text(result.stderr)
        if stderr:
            details["stderr"] = stderr
        stdout = self._sanitize_browser_failure_text(result.stdout)
        if stdout:
            details["stdout"] = stdout
        return details

    @staticmethod
    def _sanitize_browser_failure_text(text: str) -> str:
        normalized = _BROWSER_FAILURE_CONTROL_RE.sub(" ", str(text))
        normalized = re.sub(r"\s+", " ", normalized).strip()
        if not normalized:
            return ""
        normalized = _BROWSER_FAILURE_SECRET_ASSIGNMENT_RE.sub(
            lambda match: f"{match.group(1)}=[redacted]",
            normalized,
        )
        normalized = _BROWSER_FAILURE_SECRET_TOKEN_RE.sub("[redacted]", normalized)
        normalized = _BROWSER_FAILURE_FILE_URL_PATH_RE.sub("file://[path]", normalized)
        url_tokens: list[str] = []

        def protect_url(match: re.Match[str]) -> str:
            token = match.group(0)
            if token.lower().startswith("file://") or _BROWSER_FAILURE_DRIVE_SCHEME_RE.match(token):
                return token
            url_tokens.append(token)
            return f"__shisad_browser_url_{len(url_tokens) - 1}__"

        normalized = _BROWSER_FAILURE_URL_TOKEN_RE.sub(protect_url, normalized)
        normalized = _BROWSER_FAILURE_WINDOWS_DRIVE_PATH_RE.sub("[path]", normalized)
        normalized = _BROWSER_FAILURE_UNC_PATH_RE.sub("[path]", normalized)
        normalized = _BROWSER_FAILURE_ABSOLUTE_PATH_RE.sub("[path]", normalized)
        for index, token in enumerate(url_tokens):
            normalized = normalized.replace(f"__shisad_browser_url_{index}__", token)
        if len(normalized) <= _BROWSER_FAILURE_DETAIL_MAX_CHARS:
            return normalized
        return f"{normalized[: _BROWSER_FAILURE_DETAIL_MAX_CHARS - 3].rstrip()}..."

    def _parse_page_metadata(self, raw: str) -> dict[str, Any]:
        text = raw.strip()
        if not text:
            raise ValueError("empty browser metadata")
        payload = json.loads(text)
        if isinstance(payload, str):
            payload = json.loads(payload)
        if not isinstance(payload, dict):
            raise ValueError("invalid browser metadata payload")
        return payload

    def _truncate_text(self, text: str) -> str:
        encoded = text.encode("utf-8")
        if len(encoded) <= self._max_read_bytes:
            return text.strip()
        return encoded[: self._max_read_bytes].decode("utf-8", errors="ignore").strip()

    async def _resolve_target(
        self,
        *,
        session: Session,
        tool_name: str,
        target: str,
        current_url: str,
    ) -> str:
        return (
            await self._resolve_target_details(
                session=session,
                tool_name=tool_name,
                target=target,
                current_url=current_url,
            )
        ).resolved_target

    async def _resolve_target_details(
        self,
        *,
        session: Session,
        tool_name: str,
        target: str,
        current_url: str,
        submit: bool = False,
    ) -> BrowserTargetResolution:
        candidate = target.strip()
        if not candidate:
            return BrowserTargetResolution(requested_target="", resolved_target="")
        elements = await self._load_interaction_snapshot(
            session=session,
            tool_name=tool_name,
            current_url=current_url,
        )
        if not elements:
            return BrowserTargetResolution(
                requested_target=candidate,
                resolved_target=candidate,
            )
        matched = self._match_snapshot_target(elements, candidate)
        if matched is None:
            return BrowserTargetResolution(
                requested_target=candidate,
                resolved_target=candidate,
            )
        resolved_target = matched.selector or matched.ref or candidate
        return BrowserTargetResolution(
            requested_target=candidate,
            resolved_target=resolved_target,
            destination_url=self._predict_destination_url(
                matched,
                current_url=current_url,
                submit=submit,
            ),
            binding_hash=self._binding_hash_for_element(
                matched,
                current_url=current_url,
                submit=submit,
            ),
        )

    async def _load_interaction_snapshot(
        self,
        *,
        session: Session,
        tool_name: str,
        current_url: str,
    ) -> list[BrowserSnapshotElement]:
        session_dir = self._session_dir(session)
        snapshot_path = session_dir / "interaction-targets.txt"
        snapshot_error = await self._run_cli(
            session=session,
            tool_name=tool_name,
            args=["snapshot", "--filename", str(snapshot_path)],
            network_urls=[current_url],
            allow_network=True,
        )
        if snapshot_error is not None:
            return []
        try:
            raw_snapshot = snapshot_path.read_text(encoding="utf-8")
        except OSError:
            return []
        return self._parse_snapshot_elements(raw_snapshot)

    @classmethod
    def _match_snapshot_target(
        cls,
        elements: list[BrowserSnapshotElement],
        target: str,
    ) -> BrowserSnapshotElement | None:
        exact = cls._find_exact_snapshot_target(elements, target)
        if exact is not None:
            return exact
        normalized_target = cls._normalize_target(target)
        target_tokens = cls._target_tokens(target)
        best_match: tuple[int, int, BrowserSnapshotElement] | None = None
        for element in elements:
            selector = element.selector.strip()
            ref = element.ref.strip()
            label = element.label.strip()
            kind = element.kind.strip()
            normalized_label = cls._normalize_target(label)
            if normalized_target and (
                normalized_target == normalized_label
                or normalized_target in normalized_label
                or normalized_label in normalized_target
            ):
                return element
            element_tokens = cls._target_tokens(" ".join([label, selector, ref, kind]))
            overlap = len(target_tokens & element_tokens)
            if overlap <= 0:
                continue
            score = (overlap, -len(target_tokens - element_tokens))
            if best_match is None or score > best_match[:2]:
                best_match = (*score, element)
        if best_match is None:
            return None
        return best_match[2]

    @staticmethod
    def _find_exact_snapshot_target(
        elements: list[BrowserSnapshotElement],
        target: str,
    ) -> BrowserSnapshotElement | None:
        candidate = target.strip()
        if not candidate:
            return None
        for element in elements:
            if candidate in {element.ref.strip(), element.selector.strip()}:
                return element
        return None

    @staticmethod
    def _parse_snapshot_elements(raw_snapshot: str) -> list[BrowserSnapshotElement]:
        elements: list[BrowserSnapshotElement] = []
        for line in raw_snapshot.splitlines():
            match = _SNAPSHOT_ELEMENT_RE.match(line.strip())
            if match is None:
                continue
            elements.append(
                BrowserSnapshotElement(
                    ref=match.group("ref").strip(),
                    kind=match.group("kind").strip(),
                    label=match.group("label").strip(),
                    selector=match.group("selector").strip(),
                    href=(match.group("href") or "").strip(),
                    control_type=(match.group("control_type") or "").strip(),
                    form_action=(match.group("form_action") or "").strip(),
                    form_method=(match.group("form_method") or "").strip(),
                )
            )
        return elements

    @classmethod
    def _predict_destination_url(
        cls,
        element: BrowserSnapshotElement,
        *,
        current_url: str,
        submit: bool,
    ) -> str:
        if element.kind == "link" and element.href:
            return cls._resolve_destination_url(element.href, current_url=current_url)
        if cls._is_form_submit_control(element, submit=submit):
            return cls._resolve_destination_url(
                element.form_action or current_url,
                current_url=current_url,
            )
        return ""

    @classmethod
    def _resolve_destination_url(cls, value: str, *, current_url: str) -> str:
        normalized = str(value or "").strip()
        if not normalized or cls._is_fragment_only_reference(normalized):
            return ""
        return urljoin(current_url, normalized)

    @classmethod
    def _binding_hash_for_element(
        cls,
        element: BrowserSnapshotElement,
        *,
        current_url: str,
        submit: bool,
    ) -> str:
        payload = {
            "kind": element.kind.strip(),
            "label": element.label.strip(),
            "selector": element.selector.strip(),
            "control_type": cls._normalized_control_type(element),
            "form_method": cls._normalized_form_method(element.form_method),
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, ensure_ascii=True).encode("utf-8")
        ).hexdigest()

    async def _validate_prepared_binding(
        self,
        *,
        session: Session,
        tool_name: str,
        current_url: str,
        binding_target: str,
        expected_binding: str,
        submit: bool,
        expected_destination: str = "",
    ) -> BrowserBindingValidation | dict[str, Any] | None:
        if not expected_binding:
            return None
        elements = await self._load_interaction_snapshot(
            session=session,
            tool_name=tool_name,
            current_url=current_url,
        )
        if not elements:
            return self._error_payload("browser_confirmation_context_changed")
        matched = self._find_exact_snapshot_target(elements, binding_target)
        if matched is None:
            return self._error_payload("browser_confirmation_context_changed")
        live_binding = self._binding_hash_for_element(
            matched,
            current_url=current_url,
            submit=submit,
        )
        if live_binding != expected_binding:
            return self._error_payload("browser_confirmation_context_changed")
        live_destination = self._normalize_confirmation_destination(
            self._predict_destination_url(matched, current_url=current_url, submit=submit),
            current_url=current_url,
        )
        approved_destination = self._normalize_confirmation_destination(
            expected_destination,
            current_url=current_url,
        )
        if bool(live_destination) != bool(approved_destination):
            return self._error_payload("browser_confirmation_context_changed")
        if live_destination and not self._destinations_match(
            approved_destination,
            live_destination,
            allow_query_extension=False,
        ):
            return self._error_payload("browser_confirmation_context_changed")
        return BrowserBindingValidation(
            destination_url=approved_destination,
            allows_form_query=self._allows_form_query_extension(matched, submit=submit),
        )

    @classmethod
    def _normalize_confirmation_destination(cls, value: str, *, current_url: str) -> str:
        normalized = str(value or "").strip()
        if not normalized:
            return ""
        if cls._is_fragment_only_reference(normalized):
            return ""
        resolved = urljoin(current_url, normalized)
        parsed = safe_urlparse(resolved)
        if parsed is None:
            return ""
        current_parsed = safe_urlparse(current_url)
        fragment_only = (
            (bool(parsed.fragment) or normalized.endswith("#"))
            and current_parsed is not None
            and cls._same_document_parts(parsed, current_parsed)
        )
        if fragment_only:
            return ""
        return resolved

    @staticmethod
    def _is_fragment_only_reference(value: str) -> bool:
        normalized = str(value or "").strip()
        return normalized.startswith("#")

    @classmethod
    def _allows_form_query_extension(
        cls,
        element: BrowserSnapshotElement,
        *,
        submit: bool,
    ) -> bool:
        method = cls._normalized_form_method(element.form_method)
        if method != "get":
            return False
        return cls._is_form_submit_control(element, submit=submit)

    @classmethod
    def _normalized_control_type(cls, element: BrowserSnapshotElement) -> str:
        control_type = element.control_type.strip().lower()
        kind = element.kind.strip().lower()
        if kind == "button":
            return control_type if control_type in _BROWSER_BUTTON_NON_SUBMIT_TYPES else "submit"
        if kind == "field" and control_type:
            return control_type if control_type in _BROWSER_INPUT_TYPES else "text"
        return control_type

    @staticmethod
    def _normalized_form_method(value: str) -> str:
        method = value.strip().lower()
        if not method:
            return ""
        return method if method in _BROWSER_FORM_METHODS else "get"

    @classmethod
    def _is_form_submit_control(
        cls,
        element: BrowserSnapshotElement,
        *,
        submit: bool,
    ) -> bool:
        method = cls._normalized_form_method(element.form_method)
        if not method or method == "dialog":
            return False
        kind = element.kind.strip().lower()
        control_type = cls._normalized_control_type(element)
        if kind == "button":
            return control_type == "submit"
        if kind == "field":
            if control_type in {"submit", "image"}:
                return True
            if submit:
                return control_type in _BROWSER_IMPLICIT_ENTER_SUBMIT_INPUT_TYPES
        return False

    def _validate_post_action_destination(
        self,
        *,
        source_url: str,
        expected_destination: str,
        actual_url: str,
        allow_query_extension: bool,
    ) -> dict[str, Any] | None:
        actual_destination = self._normalize_confirmation_destination(
            actual_url,
            current_url=source_url,
        )
        approved_destination = self._normalize_confirmation_destination(
            expected_destination,
            current_url=source_url,
        )
        if not actual_destination:
            if not approved_destination and self._is_same_document_url(
                actual_url,
                current_url=source_url,
            ):
                return None
            return self._error_payload("browser_confirmation_context_changed")
        if approved_destination:
            if self._destinations_match(
                approved_destination,
                actual_destination,
                allow_query_extension=allow_query_extension,
            ):
                return None
            return self._error_payload("browser_confirmation_context_changed")
        if self._destinations_match(
            source_url,
            actual_destination,
            allow_query_extension=allow_query_extension,
            allow_fragment_extension=allow_query_extension,
        ):
            return None
        return self._error_payload("browser_confirmation_context_changed")

    @classmethod
    def _destinations_match(
        cls,
        expected_url: str,
        actual_url: str,
        *,
        allow_query_extension: bool,
        allow_fragment_extension: bool = False,
    ) -> bool:
        if actual_url == expected_url:
            return True
        expected = safe_urlparse(expected_url)
        actual = safe_urlparse(actual_url)
        if expected is None or actual is None:
            return False
        if not cls._same_destination_base(expected, actual):
            return False
        query_matches = actual.query == expected.query
        if allow_query_extension:
            query_matches = cls._form_query_matches(expected.query, actual.query)
        if not query_matches:
            return False
        if actual.fragment == expected.fragment:
            return True
        return bool(allow_fragment_extension and not expected.fragment and actual.fragment)

    @staticmethod
    def _form_query_matches(expected_query: str, actual_query: str) -> bool:
        if not expected_query:
            return True
        expected_values: dict[str, list[str]] = {}
        for key, value in parse_qsl(expected_query, keep_blank_values=True):
            expected_values.setdefault(key, []).append(value)
        actual_values: dict[str, list[str]] = {}
        for key, value in parse_qsl(actual_query, keep_blank_values=True):
            actual_values.setdefault(key, []).append(value)
        return all(
            key not in actual_values or actual_values[key] == values
            for key, values in expected_values.items()
        )

    @classmethod
    def _is_same_document_url(cls, value: str, *, current_url: str) -> bool:
        normalized = str(value or "").strip()
        if not normalized:
            return False
        if cls._is_fragment_only_reference(normalized):
            return True
        resolved = urljoin(current_url, normalized)
        parsed = safe_urlparse(resolved)
        current = safe_urlparse(current_url)
        if parsed is None or current is None:
            return False
        return cls._same_document_parts(parsed, current) and (
            bool(parsed.fragment) or normalized.endswith("#")
        )

    @classmethod
    def _same_document_parts(cls, first: ParseResult, second: ParseResult) -> bool:
        return cls._same_destination_base(first, second) and first.query == second.query

    @classmethod
    def _same_destination_base(cls, first: ParseResult, second: ParseResult) -> bool:
        first_authority = cls._authority_key(first)
        second_authority = cls._authority_key(second)
        if first_authority is None or second_authority is None:
            return False
        return (
            first.scheme.lower() == second.scheme.lower()
            and first_authority == second_authority
            and cls._canonical_path(first) == cls._canonical_path(second)
        )

    @staticmethod
    def _authority_key(parsed: ParseResult) -> tuple[str, str, str, int | None] | None:
        try:
            host = parsed.hostname or ""
            port = parsed.port
            username = parsed.username or ""
            password = parsed.password or ""
        except ValueError:
            return None
        default_port = BrowserToolkit._default_port_for_scheme(parsed.scheme)
        if port == default_port:
            port = None
        return (username, password, host.lower(), port)

    @staticmethod
    def _default_port_for_scheme(scheme: str) -> int | None:
        normalized = scheme.lower()
        if normalized == "http":
            return 80
        if normalized == "https":
            return 443
        return None

    @staticmethod
    def _canonical_path(parsed: ParseResult) -> str:
        if parsed.scheme.lower() in {"http", "https"} and parsed.netloc and not parsed.path:
            return "/"
        return parsed.path

    @classmethod
    def _normalize_target(cls, value: str) -> str:
        tokens = cls._target_tokens(value)
        return " ".join(sorted(tokens))

    @staticmethod
    def _target_tokens(value: str) -> set[str]:
        return {
            token
            for token in re.findall(r"[a-z0-9]+", value.lower())
            if token and token not in _TARGET_STOPWORDS
        }

    @staticmethod
    def _scope_rule_has_wildcards(rule: str) -> bool:
        normalized = str(rule).strip().lower()
        if not normalized:
            return False
        host = safe_url_hostname(normalized if "://" in normalized else f"https://{normalized}")
        if not host:
            host = normalized
        return any(token in host for token in _WILDCARD_SCOPE_TOKENS)

    def _session_alias(self, session: Session) -> str:
        return f"shisad-{session.id}"

    def _session_dir(self, session: Session) -> Path:
        return self._session_root / str(session.id)

    def _state_path(self, session: Session) -> Path:
        return self._session_dir(session) / "state.json"

    def _load_state(self, session: Session) -> dict[str, Any]:
        path = self._state_path(session)
        if not path.exists():
            return {"opened": False, "current_url": ""}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"opened": False, "current_url": ""}
        if not isinstance(payload, dict):
            return {"opened": False, "current_url": ""}
        return {
            "opened": bool(payload.get("opened")),
            "current_url": str(payload.get("current_url", "")).strip(),
        }

    def _save_state(self, session: Session, state: dict[str, Any]) -> None:
        path = self._state_path(session)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(state, indent=2), encoding="utf-8")

    def _invalidate_session_state(self, session: Session) -> None:
        with contextlib.suppress(OSError):
            self._save_state(session, {"opened": False, "current_url": ""})

    def _current_url(self, session: Session) -> str:
        return str(self._load_state(session).get("current_url", "")).strip()

    @staticmethod
    def _error_payload(reason: str, *, details: dict[str, Any] | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"ok": False, "error": reason}
        if details:
            payload["details"] = details
        payload["taint_labels"] = []
        return payload
