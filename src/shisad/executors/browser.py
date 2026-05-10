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
from urllib.parse import urljoin

from pydantic import BaseModel, Field

from shisad.core.host_matching import host_matches
from shisad.core.session import Session
from shisad.core.types import TaintLabel
from shisad.core.url_parsing import safe_url_hostname
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
    r'(?:\s+form_action="(?P<form_action>[^"]*)")?'
    r'(?:\s+form_method="(?P<form_method>[^"]*)")?$'
)
_STRUCTURED_BROWSER_TARGET_RE = re.compile(r"^(?:e\d+|[#./\[].+)$")
_WILDCARD_SCOPE_TOKENS = {"*", "?", "[", "]"}
_PLAYWRIGHT_BROWSERS_PATH_ENV = "PLAYWRIGHT_BROWSERS_PATH"
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
    form_action: str = ""
    form_method: str = ""


@dataclass(slots=True)
class BrowserTargetResolution:
    requested_target: str
    resolved_target: str
    destination_url: str = ""
    binding_hash: str = ""


@dataclass(slots=True)
class BrowserRuntimeSandbox:
    command: list[str]
    read_paths: list[Path]
    write_paths: list[Path]
    env: dict[str, str]
    error: str = ""


@dataclass(slots=True)
class BrowserCacheSandbox:
    write_paths: list[Path]
    env: dict[str, str]
    error: str = ""


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
        binding_error = await self._validate_prepared_binding(
            session=session,
            tool_name="browser.click",
            current_url=current_url,
            binding_target=concrete_target,
            expected_binding=source_binding.strip(),
            submit=False,
        )
        if binding_error is not None:
            return binding_error
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
            tool_name="browser.type_text",
            target=requested_target,
            current_url=current_url,
        )
        binding_error = await self._validate_prepared_binding(
            session=session,
            tool_name="browser.type_text",
            current_url=current_url,
            binding_target=concrete_target,
            expected_binding=source_binding.strip(),
            submit=submit,
        )
        if binding_error is not None:
            return binding_error
        args = ["fill", concrete_target, text]
        if submit:
            args.append("--submit")
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
            payload["action"] = "type_text"
            payload["target"] = concrete_target
            payload["requested_target"] = requested_target
            payload["is_sensitive"] = bool(is_sensitive)
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

    def _availability_error(self) -> dict[str, Any] | None:
        if not self._enabled:
            return self._error_payload("browser_disabled")
        if self._has_unsupported_hardened_wildcard_scope():
            return self._error_payload("browser_hardened_wildcard_scope_unsupported")
        if not self._command:
            return self._error_payload("browser_command_unconfigured")
        _, error = self._browser_command_dependency_roots()
        if error:
            return self._error_payload(error)
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
            return self._error_payload(runtime.error)
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
                timeout_seconds=max(1, math.ceil(self._timeout_seconds)),
                output_bytes=max(self._max_read_bytes * 2, 32_768),
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
        return self._error_payload(self._result_error_reason(result))

    def _prepare_browser_runtime_sandbox(self) -> BrowserRuntimeSandbox:
        command, read_paths, dependency_error = self._browser_command_runtime()
        if dependency_error:
            return BrowserRuntimeSandbox(
                command=[],
                read_paths=[],
                write_paths=[],
                env={},
                error=dependency_error,
            )
        cache = self._prepare_browser_cache_dir()
        if cache.error:
            return BrowserRuntimeSandbox(
                command=[],
                read_paths=[],
                write_paths=[],
                env={},
                error=cache.error,
            )
        return BrowserRuntimeSandbox(
            command=command,
            read_paths=read_paths,
            write_paths=cache.write_paths,
            env=cache.env,
        )

    def _browser_command_dependency_roots(self) -> tuple[list[Path], str]:
        _, read_paths, error = self._browser_command_runtime()
        return read_paths, error

    def _browser_command_runtime(self) -> tuple[list[str], list[Path], str]:
        executable_path, executable_error = self._resolve_browser_executable()
        if executable_error or executable_path is None:
            return [], [], executable_error or "browser_command_unavailable"
        roots: list[Path] = []
        executable_roots, dependency_error = self._dependency_roots_for_path(executable_path)
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
            env_target_roots, dependency_error = self._dependency_roots_for_path(env_target_path)
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
        previous_token = ""
        for arg_index, token in enumerate(self._command[1:]):
            token_value = str(token)
            if env_prefix_active and previous_token in _ENV_SPLIT_FLAGS:
                split_token, split_paths = self._normalize_env_split_argument(token_value)
                for split_path in split_paths:
                    split_roots, dependency_error = self._dependency_roots_for_path(split_path)
                    if dependency_error:
                        return [], [], dependency_error
                    roots.extend(split_roots)
                command.append(split_token)
                previous_token = token_value
                env_prefix_active = False
                continue
            if env_prefix_active and token_value.startswith(_ENV_SPLIT_FLAG_PREFIX):
                split_token, split_paths = self._normalize_env_split_argument(
                    token_value.split("=", 1)[1]
                )
                for split_path in split_paths:
                    split_roots, dependency_error = self._dependency_roots_for_path(split_path)
                    if dependency_error:
                        return [], [], dependency_error
                    roots.extend(split_roots)
                command.append(f"{_ENV_SPLIT_FLAG_PREFIX}{split_token}")
                previous_token = token_value
                env_prefix_active = False
                continue
            resolved_token, token_path = self._resolve_existing_command_argument(
                token_value,
                previous_token=previous_token,
                non_path_flags=non_path_flags,
                base_dir=env_cwd,
                env_prefix=env_prefix_active,
            )
            if token_path is None:
                command.append(resolved_token)
                if env_prefix_active and arg_index == env_target_index:
                    env_prefix_active = False
                previous_token = token_value
                continue
            token_roots, dependency_error = self._dependency_roots_for_path(token_path)
            if dependency_error:
                return [], [], dependency_error
            roots.extend(token_roots)
            command.append(resolved_token)
            if env_prefix_active and arg_index == env_target_index:
                env_prefix_active = False
            previous_token = token_value
        return command, self._dedupe_paths(roots), ""

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
                ]
            ), ""
        if not candidate.exists():
            return [], "browser_dependency_unavailable"
        return [self._browser_dependency_root(candidate)], ""

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
        non_path_flags: set[str] = set()
        previous_token = ""
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if not target_seen:
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
                )
            probe = cache_dir / ".shisad-cache-write-test"
            probe.write_text("", encoding="utf-8")
            probe.unlink(missing_ok=True)
        except OSError:
            return BrowserCacheSandbox(write_paths=[], env={}, error="browser_cache_not_writable")
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
        if (
            "distribution" in detail
            or "install-browser" in detail
            or "playwright install" in detail
        ):
            return "browser_browser_not_installed"
        if "not found" in detail or "no such file" in detail:
            return "browser_command_unavailable"
        return "browser_command_failed"

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
                    form_action=(match.group("form_action") or "").strip(),
                    form_method=(match.group("form_method") or "").strip(),
                )
            )
        return elements

    @staticmethod
    def _predict_destination_url(
        element: BrowserSnapshotElement,
        *,
        current_url: str,
        submit: bool,
    ) -> str:
        if element.kind == "link" and element.href:
            return urljoin(current_url, element.href)
        if element.kind == "button":
            return urljoin(current_url, element.form_action or current_url)
        if submit and element.kind == "field":
            return urljoin(current_url, element.form_action or current_url)
        return ""

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
            "href": element.href.strip(),
            "form_action": element.form_action.strip(),
            "form_method": element.form_method.strip().lower(),
            "destination": cls._predict_destination_url(
                element,
                current_url=current_url,
                submit=submit,
            ),
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
    ) -> dict[str, Any] | None:
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
        return None

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

    def _current_url(self, session: Session) -> str:
        return str(self._load_state(session).get("current_url", "")).strip()

    @staticmethod
    def _error_payload(reason: str) -> dict[str, Any]:
        return {"ok": False, "error": reason, "taint_labels": []}
