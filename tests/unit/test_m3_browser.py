"""M3 browser sandbox checks."""

from __future__ import annotations

import base64
from pathlib import Path

from shisad.core.types import TaintLabel
from shisad.executors.browser import BrowserSandbox, BrowserSandboxPolicy
from shisad.security.firewall.output import OutputFirewall


def _browser(tmp_path: Path) -> BrowserSandbox:
    return BrowserSandbox(
        output_firewall=OutputFirewall(safe_domains=["api.good.com"]),
        screenshots_dir=tmp_path / "screenshots",
        policy=BrowserSandboxPolicy(clipboard="enabled"),
    )


def test_m3_browser_paste_blocks_sensitive_taint(tmp_path: Path) -> None:
    browser = _browser(tmp_path)
    result = browser.paste(
        "top secret data",
        taint_labels={TaintLabel.SENSITIVE_FILE},
    )
    assert result.allowed is False
    assert result.reason == "sensitive_taint_clipboard"


def test_m3_browser_paste_uses_output_firewall(tmp_path: Path) -> None:
    browser = _browser(tmp_path)
    result = browser.paste("click https://evil.com/pixel")
    assert result.allowed is False
    assert result.blocked is True
    assert "malicious_url" in result.reason_codes


def test_m3_browser_screenshot_storage_marks_untrusted(tmp_path: Path) -> None:
    browser = _browser(tmp_path)
    image_payload = base64.b64encode(b"\x89PNG\r\n\x1a\nfake").decode("utf-8")
    result = browser.store_screenshot(
        session_id="s1",
        image_base64=image_payload,
        ocr_text="hello from screenshot",
    )
    assert Path(result.path).exists()
    assert result.ocr_taint == TaintLabel.UNTRUSTED.value
