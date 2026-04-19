from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_live_tool_matrix_module():
    module_path = Path(__file__).resolve().parents[2] / "scripts" / "live_tool_matrix.py"
    spec = importlib.util.spec_from_file_location("live_tool_matrix", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_message_send_template_is_disabled_when_no_channels_enabled() -> None:
    module = _load_live_tool_matrix_module()

    template, reason = module._message_send_template(
        {
            "channels": {
                "discord": {"enabled": False, "available": False, "connected": False},
                "telegram": {"enabled": False, "available": False, "connected": False},
            }
        }
    )

    assert template is None
    assert reason == "no_delivery_channels_configured"


def test_message_send_template_uses_first_enabled_channel() -> None:
    module = _load_live_tool_matrix_module()

    template, reason = module._message_send_template(
        {
            "channels": {
                "discord": {"enabled": True, "available": True, "connected": True},
                "telegram": {"enabled": False, "available": False, "connected": False},
            }
        }
    )

    assert reason is None
    assert template is not None
    assert template["arguments"]["channel"] == "discord"
    assert template["arguments"]["recipient"] == "live-matrix"
    assert template["arguments"]["message"] == "live tool matrix probe"


def test_tool_payload_templates_cover_memory_and_reminder_tools() -> None:
    module = _load_live_tool_matrix_module()

    templates = module._tool_payload_templates(Path("/tmp/shisad-live-tool-matrix"))

    for tool_name in (
        "note.create",
        "note.list",
        "note.search",
        "todo.create",
        "todo.list",
        "todo.complete",
        "reminder.create",
        "reminder.list",
    ):
        assert tool_name in templates
        assert templates[tool_name]["arguments"]


def test_email_read_template_requires_configured_or_search_derived_id(monkeypatch) -> None:
    module = _load_live_tool_matrix_module()

    monkeypatch.delenv("SHISAD_LIVE_TOOL_MATRIX_EMAIL_MESSAGE_ID", raising=False)
    templates = module._structured_rpc_templates()

    assert "email.search" in templates
    assert "email.read" not in templates

    monkeypatch.setenv("SHISAD_LIVE_TOOL_MATRIX_EMAIL_MESSAGE_ID", "msg-101")
    monkeypatch.setenv("SHISAD_LIVE_TOOL_MATRIX_EMAIL_ACCOUNT", "me@example.com")
    configured_templates = module._structured_rpc_templates()

    assert configured_templates["email.read"] == {
        "message_id": "msg-101",
        "account": "me@example.com",
    }

    derived = module._email_read_template_from_search_result(
        {
            "ok": True,
            "account": "work@example.com",
            "results": [{"id": 202, "source_message_id": "source-202"}],
        }
    )

    assert derived == {"message_id": "202", "account": "work@example.com"}
