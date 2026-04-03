"""Browser sandbox helpers and external browser toolkit wrapper."""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import ipaddress
import json
import math
import re
import shlex
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urljoin, urlparse

from pydantic import BaseModel, Field

from shisad.core.host_matching import host_matches
from shisad.core.session import Session
from shisad.core.types import TaintLabel
from shisad.executors.mounts import FilesystemPolicy
from shisad.executors.proxy import NetworkPolicy
from shisad.executors.sandbox import (
    DegradedModePolicy,
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
        return prepared

    async def navigate(self, *, session: Session, url: str) -> dict[str, Any]:
        normalized_url = url.strip()
        if not normalized_url:
            return self._error_payload("url_required")
        availability = self._availability_error()
        if availability is not None:
            return availability
        if not (urlparse(normalized_url).hostname or "").strip():
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

    def _availability_error(self) -> dict[str, Any] | None:
        if not self._enabled:
            return self._error_payload("browser_disabled")
        if not self._command:
            return self._error_payload("browser_command_unconfigured")
        executable = self._command[0]
        if Path(executable).exists() or shutil.which(executable):
            return None
        return self._error_payload("browser_command_unavailable")

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
        network_policy = self._network_policy(target_urls=network_urls, allow_network=allow_network)
        config = SandboxConfig(
            tool_name=tool_name,
            command=[*self._command, f"-s={self._session_alias(session)}", *args],
            sandbox_type=SandboxType.CONTAINER,
            session_id=str(session.id),
            cwd=str(session_dir),
            read_paths=[str(session_dir)],
            write_paths=[str(session_dir)],
            filesystem=FilesystemPolicy(mounts=[{"path": str(session_dir), "mode": "rw"}]),
            network_urls=network_urls,
            network=network_policy,
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

    def _network_policy(self, *, target_urls: list[str], allow_network: bool) -> NetworkPolicy:
        if not allow_network:
            return NetworkPolicy(allow_network=False, allowed_domains=[])
        allow_private_targets = self._allows_private_network_target(target_urls)
        hosts = list(self._allowed_domains)
        for url in target_urls:
            host = (urlparse(url).hostname or "").lower()
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
            host = (urlparse(url).hostname or "").lower()
            if not self._is_private_network_host(host):
                continue
            if (
                self._browser_sandbox.policy.local_network == BrowserLocalNetworkMode.ALLOWED
                or any(host_matches(host, rule) for rule in self._allowed_domains)
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
