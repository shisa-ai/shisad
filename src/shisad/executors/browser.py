"""Browser sandbox helpers (clipboard + screenshot handling)."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field

from shisad.core.types import TaintLabel
from shisad.security.firewall.output import OutputFirewall


class BrowserSandboxPolicy(BaseModel):
    """Browser runtime policy."""

    sandbox: str = "container_hardened"
    clipboard: str = "disabled"
    downloads: str = "disabled"
    local_network: str = "blocked"
    cookies: str = "session_only"
    extensions: str = "none"


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
        if self._policy.clipboard == "disabled":
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
        payload = base64.b64decode(image_base64.encode("utf-8"))
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
