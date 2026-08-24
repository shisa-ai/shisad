"""M6.T1-T4 confirmation safety and analytics coverage."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from shisad.channels.base import DeliveryTarget
from shisad.core.approval import (
    ApprovalEnvelope,
    ConfirmationLevel,
    IntentAction,
    IntentEnvelope,
    IntentPolicyContext,
)
from shisad.core.types import Capability, SessionId, ToolName, UserId, WorkspaceId
from shisad.daemon.handlers._impl import HandlerImplementation, PendingAction
from shisad.ui.confirmation import (
    ConfirmationAnalytics,
    ConfirmationWarningGenerator,
    compact_confirmation_review,
    render_compact_confirmation_review,
    render_pending_action,
    render_structured_confirmation,
    safe_summary,
)
from shisad.ui.tui import _safe_pending_action_rows


def test_m6_t1_safe_summary_generator_escapes_user_content() -> None:
    summary = safe_summary(
        action="send_email",
        risk_level="medium",
        arguments={"body": "<script>alert(1)</script>\nhello", "to": "bob@example.com"},
    )
    body_row = dict(summary.parameters)["body"]
    assert "<script>" not in body_row
    assert "&lt;script&gt;" in body_row
    assert "\\n" in body_row


def test_m6_t2_structured_viewer_renders_action_correctly() -> None:
    summary = safe_summary(
        action="send_email",
        risk_level="medium",
        arguments={"to": "bob@example.com", "subject": "Meeting follow-up"},
    )
    rendered = render_structured_confirmation(
        summary,
        warnings=["First-time recipient/destination"],
    )
    assert "ACTION CONFIRMATION" in rendered
    assert "Action: send_email" in rendered
    assert "Risk Level: MEDIUM" in rendered
    assert "First-time recipient/destination" in rendered


def test_f7c_safe_summary_leads_with_action_specific_review_text() -> None:
    cases = (
        (
            "shell.exec",
            {"command": ["echo", "ok"]},
            "Review: Run command: echo ok",
        ),
        ("fs.read", {"path": "README.md"}, "Review: Read file: README.md"),
        ("file.read", {"path": "README.md"}, "Review: Read file: README.md"),
        ("file.write", {"path": "notes.txt"}, "Review: Write file: notes.txt"),
        ("fs.list", {"path": "docs"}, "Review: List files at: docs"),
        ("fs.delete", {"path": "scratch.txt"}, "Review: Delete file: scratch.txt"),
        (
            "web.fetch",
            {"url": "https://example.test/release"},
            "Review: Fetch URL: https://example.test/release",
        ),
        (
            "web.search",
            {"query": "shisad release notes"},
            "Review: Search the web for: shisad release notes",
        ),
        (
            "http.request",
            {"method": "post", "url": "https://example.test/hook"},
            "Review: Send POST request to: https://example.test/hook",
        ),
        (
            "message.send",
            {"channel": "slack", "recipient": "alice", "message": "hello"},
            "Review: Send message to alice on slack",
        ),
        (
            "reminder.create",
            {"message": "stretch", "when": "in 5 minutes"},
            "Review: Create reminder: stretch — in 5 minutes",
        ),
        (
            "browser.navigate",
            {"url": "https://example.test/settings"},
            "Review: Navigate browser to: https://example.test/settings",
        ),
        (
            "browser.click",
            {"description": "Save changes"},
            "Review: Click browser target: Save changes",
        ),
        (
            "browser.type_text",
            {"description": "Search field"},
            "Review: Type text into browser target: Search field",
        ),
        (
            "custom.tool",
            {"target": "record-1"},
            "Review: Run custom.tool",
        ),
    )

    for action, arguments, expected in cases:
        rendered = render_structured_confirmation(
            safe_summary(action=action, risk_level="medium", arguments=arguments)
        )
        assert expected in rendered


def test_i5a_compact_review_uses_only_closed_preview_labels() -> None:
    preview = (
        "ACTION CONFIRMATION\n"
        "Review: Search the web for: OpenClaw\n"
        "Action: web.search\n"
        "Risk Level: medium\n"
        "PARAMETERS:\n"
        "  query: OpenClaw\n"
        "  internal_secret: should-not-render"
    )

    compact = compact_confirmation_review(preview, fallback_action="web.search")

    assert compact.review == "Search the web for: OpenClaw"
    assert compact.risk_level == "MEDIUM"
    assert (
        render_compact_confirmation_review(
            preview,
            fallback_action="web.search",
        )
        == "Review: Search the web for: OpenClaw\nRisk Level: MEDIUM"
    )


def test_i5a_compact_review_does_not_echo_malformed_preview() -> None:
    compact = render_compact_confirmation_review(
        "Review: raw operator diagnostic with secret-token\nRisk Level: high",
        fallback_action="custom.tool",
    )

    assert compact == "Review: Run custom.tool\nRisk Level: UNKNOWN"
    assert "secret-token" not in compact


def test_f7c_action_review_preserves_literal_metacharacters() -> None:
    cases = (
        (
            "shell.exec",
            {"command": ["printf", "%s", "a&b<c>"]},
            "Review: Run command: printf %s 'a&b<c>'",
        ),
        (
            "fs.read",
            {"path": "notes/a&b<c>.txt"},
            "Review: Read file: notes/a&b<c>.txt",
        ),
        (
            "web.fetch",
            {"url": "https://example.test/?a=1&b=<two>"},
            "Review: Fetch URL: https://example.test/?a=1&b=<two>",
        ),
        (
            "message.send",
            {"channel": "slack&matrix", "recipient": "ops<primary>"},
            "Review: Send message to ops<primary> on slack&matrix",
        ),
        (
            "reminder.create",
            {"message": "review A&B", "when": "before <deploy>"},
            "Review: Create reminder: review A&B — before <deploy>",
        ),
        (
            "browser.click",
            {"description": "Save & <continue>"},
            "Review: Click browser target: Save & <continue>",
        ),
    )

    for action, arguments, expected in cases:
        summary = safe_summary(action=action, risk_level="medium", arguments=arguments)
        rendered = render_structured_confirmation(summary)
        assert expected in rendered
        assert "&amp;" not in summary.review
        assert "&lt;" not in summary.review

    shell_parameters = dict(
        safe_summary(
            action="shell.exec",
            risk_level="high",
            arguments={"command": ["printf", "%s", "a&b<c>"]},
        ).parameters
    )
    assert "a&amp;b&lt;c&gt;" in shell_parameters["command"]


def test_f7c_public_summary_structurally_excludes_internal_control_fields() -> None:
    arguments = {
        "command": ["echo", "ok"],
        "_rpc_peer": {"uid": 1000},
        "_internal_ingress_marker": "opaque",
        "session_id": "session-secret",
        "tool_name": "routing-duplicate",
        "limits": {"max_bytes": 4096},
        "degraded_mode": True,
        "security_critical": True,
        "command_intent": "execute",
    }

    summary = safe_summary(action="shell.exec", risk_level="high", arguments=arguments)
    rendered = render_structured_confirmation(summary)

    assert "Review: Run command: echo ok" in rendered
    for key in arguments.keys() - {"command"}:
        assert key not in dict(summary.parameters)
        assert key not in rendered


def test_f7c_channel_capability_matrix_is_explicit_for_supported_surfaces() -> None:
    for channel in ("discord", "slack", "telegram", "matrix"):
        pending = PendingAction(
            confirmation_id=f"c-{channel}",
            decision_nonce=f"nonce-{channel}",
            session_id=SessionId("s-1"),
            user_id=UserId("alice"),
            workspace_id=WorkspaceId("w-1"),
            tool_name=ToolName("fs.read"),
            arguments={"path": "README.md"},
            reason="requires_confirmation",
            capabilities={Capability.FILE_READ},
            created_at=datetime.now(UTC),
            delivery_target=DeliveryTarget(
                channel=channel,
                recipient="target-1",
                workspace_hint="provider-workspace-1",
            ),
            selected_backend_id="software.default",
            selected_backend_method="software",
        )

        public = HandlerImplementation._pending_to_dict(
            pending,
            public=True,
            selected_backend_available=True,
        )
        capability = public["channel_capability"]

        assert capability["surface"] == channel
        assert capability["interaction_mode"] == (
            "native_components_with_typed_fallback" if channel == "discord" else "typed_command"
        )
        assert capability["carried_methods"] == ["software", "totp"]
        assert capability["rejection_mode"] == (
            "native_component_with_typed_fallback" if channel == "discord" else "typed_command"
        )
        assert capability["approval_route"] == "channel_native"
        assert capability["can_collect_selected_method"] is True
        assert capability["can_carry"] is True


def test_f7c_recovery_code_is_not_claimed_as_channel_carried() -> None:
    pending = PendingAction(
        confirmation_id="c-recovery",
        decision_nonce="nonce-recovery",
        session_id=SessionId("s-1"),
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("web.fetch"),
        arguments={"url": "https://example.test"},
        reason="requires_confirmation",
        capabilities={Capability.HTTP_REQUEST},
        created_at=datetime.now(UTC),
        delivery_target=DeliveryTarget(
            channel="discord",
            recipient="target-1",
            workspace_hint="guild-1",
        ),
        required_level=ConfirmationLevel.REAUTHENTICATED,
        selected_backend_id="recovery.default",
        selected_backend_method="recovery_code",
    )

    public = HandlerImplementation._pending_to_dict(
        pending,
        public=True,
        selected_backend_available=True,
    )
    capability = public["channel_capability"]

    assert capability["approval_route"] == "host_cli"
    assert capability["can_collect_selected_method"] is False
    assert capability["can_carry"] is False
    assert capability["cannot_carry_reason"] == "selected_method_requires_host_cli"


def test_f7c_stronger_methods_name_exact_nonchannel_routes() -> None:
    routes = {
        "webauthn": "browser",
        "local_fido2": "local_helper",
        "kms": "external_signer",
        "ledger": "external_signer",
    }

    for channel in ("discord", "slack", "telegram", "matrix"):
        for method, route in routes.items():
            pending = PendingAction(
                confirmation_id=f"c-{channel}-{method}",
                decision_nonce=f"nonce-{channel}-{method}",
                session_id=SessionId("s-1"),
                user_id=UserId("alice"),
                workspace_id=WorkspaceId("w-1"),
                tool_name=ToolName("fs.write"),
                arguments={"path": "notes.txt", "content": "reviewed"},
                reason="requires_confirmation",
                capabilities={Capability.FILE_WRITE},
                created_at=datetime.now(UTC),
                delivery_target=DeliveryTarget(
                    channel=channel,
                    recipient="target-1",
                    workspace_hint="provider-workspace-1",
                ),
                required_level=ConfirmationLevel.BOUND_APPROVAL,
                selected_backend_id=f"{method}.default",
                selected_backend_method=method,
            )

            capability = HandlerImplementation._pending_to_dict(
                pending,
                public=True,
                selected_backend_available=True,
            )["channel_capability"]

            assert capability["approval_route"] == route
            assert capability["can_collect_selected_method"] is False
            assert capability["can_carry"] is False
            assert capability["cannot_carry_reason"] == (
                f"method_specific_approval_requires_{method}"
            )


def test_gh12_shell_exec_confirmation_preview_includes_literal_command() -> None:
    summary = safe_summary(
        action="shell.exec",
        risk_level="medium",
        arguments={
            "command": ["find", ".", "-maxdepth", "2", "-iname", "*install*log*"],
            "read_paths": ["."],
        },
    )
    rendered = render_structured_confirmation(summary)

    assert "command: find . -maxdepth 2 -iname '*install*log*'" in rendered
    assert "command: [6 items]" not in rendered


def test_gh55_shell_exec_confirmation_preview_hides_command_intent() -> None:
    summary = safe_summary(
        action="shell.exec",
        risk_level="medium",
        arguments={
            "command": ["echo", "ok"],
            "command_intent": "execute",
            "read_paths": ["."],
        },
    )
    rendered = render_structured_confirmation(summary)

    assert "command: echo ok" in rendered
    assert "command_intent" not in dict(summary.parameters)
    assert "command_intent" not in rendered


def test_gh55_shell_exec_pending_payload_hides_command_intent() -> None:
    arguments = {
        "command": ["echo", "ok"],
        "command_intent": "execute",
        "read_paths": ["."],
    }
    pending = PendingAction(
        confirmation_id="c-1",
        decision_nonce="nonce-1",
        session_id=SessionId("s-1"),
        user_id=UserId("u-1"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("shell.exec"),
        arguments=arguments,
        reason="requires_confirmation",
        capabilities={Capability.SHELL_EXEC},
        created_at=datetime.now(UTC),
        safe_preview=render_structured_confirmation(
            safe_summary(
                action="shell.exec",
                risk_level="medium",
                arguments={
                    "command": ["echo", "ok"],
                    "command_intent": "execute",
                    "read_paths": ["."],
                },
            )
        ),
        intent_envelope=IntentEnvelope(
            intent_id="c-1",
            agent_id="daemon-1",
            workspace_id="w-1",
            session_id="s-1",
            created_at=datetime.now(UTC),
            action=IntentAction(
                tool="shell.exec",
                display_summary="shell.exec: command=echo ok",
                parameters=dict(arguments),
                destinations=[],
            ),
            policy_context=IntentPolicyContext(
                required_level=ConfirmationLevel.SIGNED_AUTHORIZATION,
                confirmation_reason="requires_confirmation",
                matched_rule="shell.exec",
                action_digest="sha256:test",
            ),
            nonce="nonce-2",
        ),
    )

    payload = HandlerImplementation._pending_to_dict(pending, public=True)

    assert payload["arguments"] == {
        "command": ["echo", "ok"],
        "read_paths": ["."],
    }
    assert "command_intent" not in payload["safe_preview"]
    assert "command_intent" not in payload["intent_envelope"]["action"]["parameters"]
    assert "command_intent" not in str(payload)

    durable_payload = HandlerImplementation._pending_to_dict(pending)
    assert durable_payload["arguments"]["command_intent"] == "execute"
    assert durable_payload["intent_envelope"]["action"]["parameters"]["command_intent"] == "execute"


def test_gh55_legacy_shell_alias_pending_payload_hides_command_intent() -> None:
    pending = PendingAction(
        confirmation_id="c-1",
        decision_nonce="nonce-1",
        session_id=SessionId("s-1"),
        user_id=UserId("u-1"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("shell_exec"),
        arguments={
            "command": ["echo", "ok"],
            "command_intent": "execute",
        },
        reason="requires_confirmation",
        capabilities={Capability.SHELL_EXEC},
        created_at=datetime.now(UTC),
        safe_preview="ACTION CONFIRMATION\nPARAMETERS:\n  command_intent: execute",
        approval_envelope=ApprovalEnvelope(
            approval_id="c-1",
            pending_action_id="c-1",
            workspace_id="w-1",
            daemon_id="daemon-1",
            session_id="s-1",
            required_level=ConfirmationLevel.SIGNED_AUTHORIZATION,
            policy_reason="requires_confirmation",
            action_digest="sha256:test",
            nonce="nonce-3",
            intent_envelope_hash="sha256:intent",
            action_summary="shell_exec: command_intent=execute",
        ),
        intent_envelope=IntentEnvelope(
            intent_id="c-1",
            agent_id="daemon-1",
            workspace_id="w-1",
            session_id="s-1",
            created_at=datetime.now(UTC),
            action=IntentAction(
                tool="shell_exec",
                display_summary="shell_exec: command_intent=execute",
                parameters={
                    "command": ["echo", "ok"],
                    "command_intent": "execute",
                },
                destinations=[],
            ),
            policy_context=IntentPolicyContext(
                required_level=ConfirmationLevel.SIGNED_AUTHORIZATION,
                confirmation_reason="requires_confirmation",
                matched_rule="shell_exec",
                action_digest="sha256:test",
            ),
            nonce="nonce-2",
        ),
    )

    payload = HandlerImplementation._pending_to_dict(pending, public=True)

    assert "command_intent" not in payload["arguments"]
    assert "command_intent" not in payload["intent_envelope"]["action"]["parameters"]
    assert "command_intent" not in payload["safe_preview"]
    assert "command_intent" not in payload["approval_envelope"]["action_summary"]
    assert "command_intent" not in payload["intent_envelope"]["action"]["display_summary"]
    assert "command_intent" not in str(payload)
    assert "command: echo ok" in payload["safe_preview"]
    assert payload["approval_envelope"]["action_summary"] == "Run command: echo ok"
    assert payload["intent_envelope"]["action"]["display_summary"] == "Run command: echo ok"


def test_f7c_non_shell_pending_payload_hides_internal_intent_marker() -> None:
    pending = PendingAction(
        confirmation_id="c-1",
        decision_nonce="nonce-1",
        session_id=SessionId("s-1"),
        user_id=UserId("u-1"),
        workspace_id=WorkspaceId("w-1"),
        tool_name=ToolName("custom.tool"),
        arguments={
            "command": ["echo", "ok"],
            "command_intent": "execute",
        },
        reason="requires_confirmation",
        capabilities=set(),
        created_at=datetime.now(UTC),
        safe_preview="preview",
    )

    payload = HandlerImplementation._pending_to_dict(pending, public=True)

    assert payload["arguments"] == {"command": ["echo", "ok"]}
    assert "command_intent" not in str(payload)

    durable_payload = HandlerImplementation._pending_to_dict(pending)
    assert durable_payload["arguments"]["command_intent"] == "execute"


def test_m6_t3_warning_generator_detects_first_time_recipient() -> None:
    generator = ConfirmationWarningGenerator()
    warnings = generator.generate(
        user_id="u-1",
        tool_name="send_email",
        arguments={"to": "alice@external.example"},
        taint_labels=["untrusted"],
    )
    assert "First-time recipient/destination" in warnings
    assert "External destination" in warnings
    assert "Contains tainted data" in warnings
    assert "High-value action" in warnings


def test_pending_action_renderer_surfaces_warning_details_after_preview_truncation() -> None:
    safe_preview = "\n".join(
        [
            "ACTION CONFIRMATION",
            "Action: http_request",
            "PARAMETERS:",
            *[f"  param_{index}: value_{index}" for index in range(12)],
            "WARNINGS:",
            "  - Contains tainted data",
        ]
    )
    rendered = render_pending_action(
        {
            "confirmation_id": "c1",
            "tool_name": "http_request",
            "status": "pending",
            "risk_level": "high",
            "required_proof_tier": "T1_stepup",
            "selected_backend_method": "totp",
            "channel_capability": {
                "approval_route": "host_cli",
                "can_carry": True,
                "requires_second_factor": True,
            },
            "safe_preview": safe_preview,
            "warnings": ["Contains tainted data", "High-value action"],
        }
    )

    assert "warnings=2: Contains tainted data; High-value action" in rendered
    assert "approve: c c1 <totp-code>" in rendered


def test_f1_pending_action_renderer_uses_canonical_lifecycle_projection() -> None:
    rendered = render_pending_action(
        {
            "confirmation_id": "c1",
            "tool_name": "web.fetch",
            "status": "pending",
            "lifecycle_state": "superseded",
            "risk_level": "high",
            "required_proof_tier": "T0_identity",
            "selected_backend_method": "software",
            "channel_capability": {
                "approval_route": "host_cli",
                "can_carry": False,
                "can_reject": False,
                "cannot_carry_reason": "action_superseded",
            },
        }
    )

    assert "status=superseded" in rendered
    assert "status=pending" not in rendered


def test_f2_pending_action_renderer_surfaces_lifetime_and_origin() -> None:
    action = {
        "confirmation_id": "c1",
        "tool_name": "web.fetch",
        "status": "failed",
        "lifecycle_state": "expired",
        "status_reason": "approval_expired",
        "risk_level": "high",
        "required_proof_tier": "T0_identity",
        "selected_backend_method": "software",
        "created_at": "2026-07-12T10:00:00+00:00",
        "age_seconds": 90,
        "expires_at": "2026-07-12T11:00:00+00:00",
        "origin_turn_id": "turn-42",
        "channel_capability": {
            "approval_route": "host_cli",
            "can_carry": False,
            "can_reject": False,
            "cannot_carry_reason": "approval_expired",
        },
    }

    safe_row = _safe_pending_action_rows([action])[0]
    rendered = render_pending_action(safe_row)

    assert safe_row["age_seconds"] == 90
    assert safe_row["expires_at"] == "2026-07-12T11:00:00+00:00"
    assert safe_row["status_reason"] == "approval_expired"
    assert "age=90s" in rendered
    assert "expires_at=2026-07-12T11:00:00+00:00" in rendered
    assert "origin_turn=turn-42" in rendered
    assert "state_reason=approval_expired" in rendered


def test_pending_action_renderer_shows_selected_totp_collection_for_t0_fallback() -> None:
    rendered = render_pending_action(
        {
            "confirmation_id": "c1",
            "tool_name": "web.fetch",
            "status": "pending",
            "risk_level": "high",
            "required_proof_tier": "T0_identity",
            "selected_backend_method": "totp",
            "channel_capability": {
                "approval_route": "host_cli",
                "can_carry": False,
                "can_collect_selected_method": True,
                "can_carry_t1_stepup": True,
                "requires_second_factor": True,
                "cannot_carry_reason": "selected_method_requires_T1_stepup",
            },
        }
    )

    assert "risk=high proof=T0_identity method=totp route=host_cli" in rendered
    assert "approve: c c1 <totp-code>" in rendered
    assert "approve: cannot carry" not in rendered


def test_pending_action_renderer_basic_terminal_totp_fallback_is_plain_text() -> None:
    rendered = render_pending_action(
        {
            "confirmation_id": "c1",
            "tool_name": "web.fetch",
            "status": "pending",
            "risk_level": "high",
            "required_proof_tier": "T1_stepup",
            "selected_backend_method": "totp",
            "channel_capability": {
                "approval_route": "host_cli",
                "can_carry": True,
                "can_collect_selected_method": True,
                "requires_second_factor": True,
            },
            "safe_preview": "ACTION CONFIRMATION\nAction: web.fetch",
            "warnings": ["Contains tainted data"],
        }
    )

    assert "\x1b[" not in rendered
    assert rendered.isascii()
    assert "risk=high proof=T1_stepup method=totp route=host_cli" in rendered
    assert "approve: c c1 <totp-code>" in rendered
    assert "reject: x c1" in rendered
    assert "preview: ACTION CONFIRMATION | Action: web.fetch" in rendered
    assert "warnings=1: Contains tainted data" in rendered


def test_t2_pending_action_renderer_labels_recovery_code_truthfully() -> None:
    rendered = render_pending_action(
        {
            "confirmation_id": "c1",
            "tool_name": "web.fetch",
            "status": "pending",
            "risk_level": "high",
            "required_proof_tier": "T1_stepup",
            "selected_backend_method": "recovery_code",
            "channel_capability": {
                "approval_route": "host_cli",
                "can_carry": True,
                "can_collect_selected_method": True,
                "requires_second_factor": True,
            },
        }
    )

    assert "approve: c c1 <recovery-code>" in rendered
    assert "<totp-code>" not in rendered


def test_m6_t4_confirmation_analytics_detects_rubber_stamping() -> None:
    analytics = ConfirmationAnalytics()
    base = datetime.now(UTC) - timedelta(minutes=10)
    for index in range(12):
        created = base + timedelta(seconds=index * 30)
        decided = created + timedelta(seconds=max(1, 15 - index))
        analytics.record(
            user_id="u-1",
            decision="approve",
            created_at=created,
            decided_at=decided,
        )
    metrics = analytics.metrics(user_id="u-1", window_seconds=3600)
    assert metrics["decisions"] == 12
    assert metrics["rubber_stamping"] is True
    assert metrics["fatigue_detected"] is True


# SEC-LM3: boundary cases for the rubber-stamping thresholds.
#
# Production thresholds (shisad/ui/confirmation.py):
#   rubber_stamping: len(records) >= 10 and approve_rate >= 0.9
#   fatigue_detected: len(records) >= 6 and response-time slope <= -0.25
#
# The prior test pushed well past both thresholds, so threshold drift would
# have stayed invisible. These tests pin the exact boundary behavior in both
# directions so bumping either threshold breaks the test and forces a review.


def _record_decisions(
    analytics: ConfirmationAnalytics,
    *,
    user_id: str,
    decisions: list[str],
    base: datetime,
    response_seconds: float = 10.0,
) -> None:
    for index, decision in enumerate(decisions):
        created = base + timedelta(seconds=index * 30)
        decided = created + timedelta(seconds=response_seconds)
        analytics.record(
            user_id=user_id,
            decision=decision,
            created_at=created,
            decided_at=decided,
        )


def test_sec_lm3_rubber_stamping_fires_at_10_records_and_approve_rate_0_9() -> None:
    analytics = ConfirmationAnalytics()
    base = datetime.now(UTC) - timedelta(minutes=10)
    # Exactly 10 records, approve_rate = 0.9 (9 approve + 1 reject).
    _record_decisions(
        analytics,
        user_id="u-boundary",
        decisions=["approve"] * 9 + ["reject"],
        base=base,
    )

    metrics = analytics.metrics(user_id="u-boundary", window_seconds=3600)

    assert metrics["decisions"] == 10
    assert metrics["approve_rate"] == 0.9
    assert metrics["rubber_stamping"] is True


def test_sec_lm3_rubber_stamping_silent_at_9_records_even_when_all_approve() -> None:
    analytics = ConfirmationAnalytics()
    base = datetime.now(UTC) - timedelta(minutes=10)
    _record_decisions(
        analytics,
        user_id="u-too-few",
        decisions=["approve"] * 9,
        base=base,
    )

    metrics = analytics.metrics(user_id="u-too-few", window_seconds=3600)

    assert metrics["decisions"] == 9
    assert metrics["approve_rate"] == 1.0
    assert metrics["rubber_stamping"] is False


def test_sec_lm3_rubber_stamping_silent_at_10_records_with_approve_rate_just_below() -> None:
    analytics = ConfirmationAnalytics()
    base = datetime.now(UTC) - timedelta(minutes=10)
    # 10 records, approve_rate = 0.8 (8 approve + 2 reject) -> just below 0.9.
    _record_decisions(
        analytics,
        user_id="u-just-below",
        decisions=["approve"] * 8 + ["reject"] * 2,
        base=base,
    )

    metrics = analytics.metrics(user_id="u-just-below", window_seconds=3600)

    assert metrics["decisions"] == 10
    assert metrics["approve_rate"] == 0.8
    assert metrics["rubber_stamping"] is False


def test_sec_lm3_fatigue_silent_when_slope_is_flat() -> None:
    analytics = ConfirmationAnalytics()
    base = datetime.now(UTC) - timedelta(minutes=10)
    # 8 records with a flat response-time profile -> no slope -> no fatigue.
    for index in range(8):
        created = base + timedelta(seconds=index * 30)
        decided = created + timedelta(seconds=10)
        analytics.record(
            user_id="u-flat",
            decision="approve",
            created_at=created,
            decided_at=decided,
        )

    metrics = analytics.metrics(user_id="u-flat", window_seconds=3600)

    assert metrics["decisions"] == 8
    assert metrics["fatigue_detected"] is False


def test_sec_lm3_fatigue_silent_when_fewer_than_six_records() -> None:
    analytics = ConfirmationAnalytics()
    base = datetime.now(UTC) - timedelta(minutes=10)
    # 5 records with a steep negative slope still below the sample threshold.
    for index in range(5):
        created = base + timedelta(seconds=index * 30)
        decided = created + timedelta(seconds=max(1, 15 - index * 3))
        analytics.record(
            user_id="u-too-few-fatigue",
            decision="approve",
            created_at=created,
            decided_at=decided,
        )

    metrics = analytics.metrics(user_id="u-too-few-fatigue", window_seconds=3600)

    assert metrics["decisions"] == 5
    assert metrics["fatigue_detected"] is False
