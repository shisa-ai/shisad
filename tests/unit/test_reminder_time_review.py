"""Reminder semantics are model judgments with structural enforcement."""

import asyncio
import json

import pytest

from shisad.core.providers.base import Message, ProviderResponse
from shisad.core.reminder_time_review import ReminderTimeReviewer
from shisad.security.firewall import ContentFirewall


class Provider:
    def __init__(self, payload):
        self.payload = payload
        self.messages = []

    async def complete(self, messages, tools=None):
        assert tools is None
        self.messages = messages
        if isinstance(self.payload, Exception):
            raise self.payload
        return ProviderResponse(
            message=Message(role="assistant", content=json.dumps(self.payload)), usage={}
        )


def decision(status="specified", source="user_request", quote="ten minutes"):
    return {"status": status, "source": source, "quote": quote}


async def review(provider, **kwargs):
    return await ReminderTimeReviewer(provider=provider, firewall=ContentFirewall()).review(
        user_request=kwargs.get("user_request", "Remind me in ten minutes to check results"),
        user_context=kwargs.get("user_context", ""),
        arguments={"when": "in 10 minutes", "message": "check results"},
    )


@pytest.mark.asyncio
async def test_supported_time_requires_a_source_quote_and_fresh_tool_free_context():
    provider = Provider(decision())
    result = await review(provider)
    assert result.status == "specified"
    assert len(provider.messages) == 2
    assert provider.messages[0].role == "system"
    assert "Remind me" not in provider.messages[0].content
    assert "ten minutes" in provider.messages[1].content


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["missing", "ambiguous", "unresolved"])
async def test_non_specified_status_cannot_schedule(status):
    assert (await review(Provider(decision(status, "none", "")))).status == status


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {},
        decision(source="arguments"),
        decision(quote="in 10 minutes"),
        decision(quote=""),
        decision(source="none"),
        {**decision(), "extra": True},
        RuntimeError("secret provider error"),
    ],
)
async def test_invalid_or_ungrounded_response_is_unresolved(payload):
    assert (await review(Provider(payload))).status == "unresolved"


@pytest.mark.asyncio
async def test_explicit_default_can_be_grounded_in_prior_user_context():
    result = await review(
        Provider(decision(source="user_context", quote="later means ten minutes")),
        user_request="Remind me later to check results",
        user_context="For my reminders, later means ten minutes.",
    )
    assert result.status == "specified"


@pytest.mark.asyncio
async def test_missing_provider_and_oversized_packet_do_not_guess():
    assert (await review(None)).status == "unresolved"
    provider = Provider(decision())
    assert (await review(provider, user_context="x" * 100_000)).status == "unresolved"
    assert not provider.messages


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid", ["tool_call", "truncated", "oversized", "inconsistent"])
async def test_incomplete_or_inconsistent_completion_is_unresolved(invalid):
    class InvalidProvider(Provider):
        async def complete(self, messages, tools=None):
            response = await super().complete(messages, tools)
            if invalid == "tool_call":
                response.message.tool_calls = [{"name": "reminder.create"}]
            elif invalid == "truncated":
                response.finish_reason = "length"
            elif invalid == "oversized":
                response.message.content = "x" * 8001
            return response

    payload = decision("missing") if invalid == "inconsistent" else decision()
    assert (await review(InvalidProvider(payload))).status == "unresolved"


@pytest.mark.asyncio
async def test_timeout_returns_unresolved_without_propagating_provider_errors():
    class SlowProvider(Provider):
        async def complete(self, messages, tools=None):
            await asyncio.sleep(1)
            return await super().complete(messages, tools)

    result = await ReminderTimeReviewer(
        provider=SlowProvider(decision()),
        firewall=ContentFirewall(),
        timeout_seconds=0.001,
    ).review(user_request="in ten minutes", user_context="", arguments={})
    assert result.status == "unresolved"


@pytest.mark.asyncio
async def test_remote_packet_filters_secrets_and_keeps_proposal_out_of_system_prompt():
    provider = Provider(decision())
    secret = "sk-abc123def456ghi789"
    result = await review(provider, user_context="A token: " + secret)
    assert result.status == "specified"
    assert secret not in provider.messages[1].content
    assert "check results" not in provider.messages[0].content


@pytest.mark.asyncio
async def test_current_request_authority_requires_separate_exact_user_quote():
    provider = Provider(
        {
            **decision(),
            "current_request_authorized": True,
            "request_quote": "Remind me in ten minutes to check results",
        }
    )
    result = await review(provider)
    assert result.status == "specified"
    assert result.current_request_authorized is True
    assert result.request_quote == "Remind me in ten minutes to check results"
    assert "quoted" in provider.messages[0].content.lower()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {**decision(), "current_request_authorized": False, "request_quote": "Remind me"},
        {
            **decision(source="user_context", quote="prior instructions"),
            "current_request_authorized": True,
            "request_quote": "Remind me",
        },
        {**decision(), "current_request_authorized": True, "request_quote": ""},
        {**decision(), "current_request_authorized": True, "request_quote": "prior instructions"},
        {
            **decision("missing", "none", ""),
            "current_request_authorized": True,
            "request_quote": "Remind me",
        },
    ],
)
async def test_invalid_current_request_authority_is_unresolved(payload):
    result = await review(Provider(payload), user_context="prior instructions")
    assert result.status == "unresolved"
    assert result.current_request_authorized is False


@pytest.mark.asyncio
async def test_timing_alone_does_not_supply_action_authority():
    result = await review(Provider(decision()))
    assert result.status == "specified"
    assert result.current_request_authorized is False
